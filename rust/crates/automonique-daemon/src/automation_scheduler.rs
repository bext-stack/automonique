// SPDX-License-Identifier: Elastic-2.0

//! The automation scheduler worker: the one place a registered automation
//! becomes a run.
//!
//! Three durable stores meet here, and the worker owns a connection to each:
//!
//! - the **automation registry** (`automonique_store::automation_store`),
//!   which says what is registered, whether an operator has it in service,
//!   when it is next due, and which occurrence — at most one — is active;
//! - the **scheduler core** (`automonique_store::durable_scheduler`), which
//!   admits work under the generation fence, bounds how much of it runs at
//!   once, serializes it per scope, and remembers every identity it ever
//!   admitted so nothing starts twice;
//! - the **product store**'s durable synthetic lane, on which an occurrence is
//!   submitted as a normal inbox item under a stable idempotency key, claimed
//!   and completed by the daemon's existing controller tick, and committed
//!   with an outbox intent exactly as `automonique submit` work is.
//!
//! There is no second outbox and no second executor. What this module adds is
//! the *derivation* — from a schedule to an instant, from an instant to an
//! identity — and the bookkeeping that makes the derivation replayable.
//!
//! # The occurrence key
//!
//! An occurrence is identified by
//! [`AutomationOccurrenceKey`]: `automation:<automation_id>:<instant>`, the
//! scheduled instant rather than the instant it happened to be noticed. The
//! same key is the work identity in the scheduler core and the transport key
//! on the synthetic lane, and both dedupe on it. A replayed tick, a restarted
//! daemon or a re-elected generation derives the same bytes and is refused —
//! `duplicate_work` by the core, `duplicate: true` by the lane — rather than
//! firing again.
//!
//! # The fence
//!
//! Every tick is judged under the generation fence twice. The product store's
//! generation row is read first and must name this holder and epoch with a
//! live lease; a daemon that has lost its generation submits nothing, because
//! the successor is about to derive the same occurrences. The scheduler core
//! then checks the [`SchedulerFence`] installed at open on every operation,
//! and a stale one starts nothing — a stale tick is not a partial tick.
//!
//! # One tick
//!
//! 1. **Reconcile** every occurrence the registry records as active against
//!    the core and the lane. This is where a crash between any two of the
//!    durable writes below is repaired, and it runs first so a restart
//!    finishes what it was doing before it derives anything new.
//! 2. **Admit** every enabled automation whose next instant is due at the
//!    clock's `now`: submit its occurrence to the core (queued, nothing
//!    starts) and mark the registry row active at that instant.
//! 3. **Start** what the core's `tick` admits under the bound: submit the
//!    occurrence to the lane and advance the registry's next instant past it.
//!
//! Completion is noticed in step 1 of a later tick: when the lane reports the
//! key terminal, the core is told the slot is free and the registry records
//! the firing.
//!
//! # Pause, resume, archive
//!
//! A withdrawn automation derives no new occurrence — `due` answers only
//! enabled rows. One it had already admitted is handled by the core's own
//! verbs: queued work is cancelled and never starts, and the instant is
//! skipped rather than retried, because the core remembers the identity as
//! terminal and would refuse it again. Work the lane is already running is
//! left to finish — pause is not cancel — except that an archived automation,
//! which nothing can resume, requests a stop; custody stays with the core
//! until the lane's terminal commit lands, exactly as scheduler-core says. On
//! resume, a fixed interval continues from the first instant after `now`,
//! never with a burst of catch-up firings.
//!
//! # Restart
//!
//! Nothing here is in memory. A due-but-unfired occurrence is due again on the
//! first tick after restart and fires once; a running occurrence is found
//! active in the registry, running in the core and present on the lane, and
//! is waited on rather than resubmitted; a paused automation is still paused,
//! because the registry is what says so.
//!
//! # The clock
//!
//! `now` comes from an [`AutomationClock`] the worker is handed at open, the
//! way other workers take a lease-time source. Production hands it
//! [`SystemClock`]; a test hands it a fake and drives [`AutomationSchedulerWorker::tick_at`]
//! directly, without a thread.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_core::SchedulerFence;
use automonique_core::scheduler_conformance::{QueuedWork, ScopeId, WorkId, WorkState};
use automonique_protocol::automation_api::{
    AutomationId, AutomationOccurrenceKey, AutomationSchedule,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_store::automation_store::{
    AutomationRecord, AutomationSchedule as StoredSchedule, AutomationStore, AutomationStoreError,
};
use automonique_store::durable_scheduler::{DurableSchedulerError, DurableSchedulerStore};
use automonique_store::{InboxSubmission, LeaseTimeSource, Store, StoreError};

/// The transport an occurrence is submitted on: the daemon's durable synthetic
/// lane, the one `automonique submit` uses and the serve loop's controller
/// tick claims from.
pub const OCCURRENCE_TRANSPORT: &str = "local.synthetic";

/// Occurrences the scheduler core lets run at once, across every automation.
///
/// Within the conformance band the core is held to (`2..=1024`) and small on
/// purpose: an occurrence is a synthetic-lane item that completes within one
/// controller tick, so the bound is a ceiling on admission rather than a
/// throughput setting.
pub const AUTOMATION_PARALLELISM_LIMIT: u32 = 4;

/// Rows one tick reconciles or admits at most. Bounded because a tick runs on
/// a thread that has to notice a stop.
pub const OCCURRENCE_BATCH: usize = 64;

/// How long an idle worker sleeps before it looks again.
const IDLE_POLL: Duration = Duration::from_millis(250);

/// Where `now` comes from.
///
/// Injectable for the reason the other workers take a lease-time source: a
/// scheduler that read the wall clock itself could be tested only by waiting.
pub trait AutomationClock: Send + Sync {
    /// Unix milliseconds now, or a stable category when the clock cannot say.
    fn now_ms(&self) -> Result<i64, &'static str>;
}

/// The system wall clock.
pub struct SystemClock;

impl AutomationClock for SystemClock {
    fn now_ms(&self) -> Result<i64, &'static str> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock_before_epoch")?;
        i64::try_from(duration.as_millis()).map_err(|_| "clock_out_of_range")
    }
}

/// What the worker needs to open its three stores under one fence.
#[derive(Clone)]
pub struct AutomationSchedulerParams<'a> {
    /// The product store, for the synthetic lane and the generation row.
    pub database_path: &'a Path,
    /// The automation registry.
    pub registry_path: &'a Path,
    /// The scheduler core's own database.
    pub scheduler_path: &'a Path,
    /// The generation this worker serves.
    pub generation_id: &'a str,
    /// The holder of that generation's lease.
    pub holder_id: &'a str,
    /// The epoch of that lease.
    pub lease_epoch: u64,
    /// The core's parallelism bound.
    pub parallelism_limit: u32,
    /// The lease-time source the product store classifies leases with.
    pub lease_time_source: Arc<dyn LeaseTimeSource>,
    /// Where `now` comes from.
    pub clock: Arc<dyn AutomationClock>,
}

/// Why the worker could not open, or why one tick did not complete.
#[derive(Debug)]
pub enum AutomationSchedulerError {
    /// The product store refused. The payload is its stable category.
    Store(&'static str),
    /// The automation registry refused. The payload is its stable category.
    Registry(&'static str),
    /// The scheduler core refused. The payload is its stable category.
    Scheduler(&'static str),
    /// The clock could not say what time it is.
    Clock(&'static str),
    /// A store was busy or locked; a later tick may retry.
    Transient(&'static str),
    /// This holder and epoch no longer own the generation.
    StaleFence,
    /// The three stores disagree in a way no writer of this module could have
    /// produced.
    Corrupt(&'static str),
    /// The worker thread could not be spawned, or was asked to start twice
    /// without a composed worker.
    Thread,
}

impl AutomationSchedulerError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Store(category)
            | Self::Registry(category)
            | Self::Scheduler(category)
            | Self::Clock(category)
            | Self::Transient(category)
            | Self::Corrupt(category) => category,
            Self::StaleFence => "stale_fence",
            Self::Thread => "automation_scheduler_thread",
        }
    }

    /// Whether a later tick may reasonably succeed.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Transient(_) | Self::Clock(_))
    }
}

impl std::fmt::Display for AutomationSchedulerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(category) => write!(formatter, "product store refused: {category}"),
            Self::Registry(category) => {
                write!(formatter, "automation registry refused: {category}")
            }
            Self::Scheduler(category) => write!(formatter, "scheduler core refused: {category}"),
            Self::Clock(category) => write!(formatter, "clock failed: {category}"),
            Self::Transient(category) => write!(formatter, "transient store failure: {category}"),
            Self::StaleFence => formatter.write_str("the generation fence is stale"),
            Self::Corrupt(category) => {
                write!(formatter, "the automation stores disagree: {category}")
            }
            Self::Thread => formatter.write_str("the worker thread could not be started"),
        }
    }
}

impl std::error::Error for AutomationSchedulerError {}

fn sqlite_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

impl From<StoreError> for AutomationSchedulerError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::StaleEpoch | StoreError::LeaseHeld | StoreError::AuthorityLost => {
                Self::StaleFence
            }
            StoreError::Sqlite(ref inner) if sqlite_is_busy(inner) => {
                Self::Transient("sqlite_busy")
            }
            other => Self::Store(other.category()),
        }
    }
}

impl From<AutomationStoreError> for AutomationSchedulerError {
    fn from(error: AutomationStoreError) -> Self {
        match error {
            AutomationStoreError::Sqlite(ref inner) if sqlite_is_busy(inner) => {
                Self::Transient("sqlite_busy")
            }
            other => Self::Registry(other.category()),
        }
    }
}

impl From<DurableSchedulerError> for AutomationSchedulerError {
    fn from(error: DurableSchedulerError) -> Self {
        match error {
            DurableSchedulerError::StaleFence => Self::StaleFence,
            DurableSchedulerError::Sqlite(ref inner) if sqlite_is_busy(inner) => {
                Self::Transient("sqlite_busy")
            }
            other => Self::Scheduler(other.category()),
        }
    }
}

/// What one tick did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickReport {
    /// Occurrences newly admitted to the scheduler core.
    pub admitted: usize,
    /// Occurrences submitted to the synthetic lane.
    pub started: usize,
    /// Occurrences whose run the lane reported terminal, freed in the core and
    /// recorded in the registry.
    pub settled: usize,
    /// Occurrences cancelled before they started, because their automation was
    /// withdrawn while they were queued.
    pub cancelled: usize,
}

impl TickReport {
    /// Whether the tick changed nothing, so the worker may sleep.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.admitted == 0 && self.started == 0 && self.settled == 0 && self.cancelled == 0
    }
}

#[derive(Clone)]
struct OwnedParams {
    database_path: PathBuf,
    registry_path: PathBuf,
    scheduler_path: PathBuf,
    generation_id: String,
    holder_id: String,
    lease_epoch: u64,
    parallelism_limit: u32,
    lease_time_source: Arc<dyn LeaseTimeSource>,
    clock: Arc<dyn AutomationClock>,
}

/// The worker, drivable one tick at a time.
///
/// Public so a test can open it against real files, hand it a fake clock and
/// call [`Self::tick_at`] deterministically; the daemon puts it on a thread
/// through [`AutomationSchedulerHost`].
pub struct AutomationSchedulerWorker {
    params: OwnedParams,
    store: Store,
    registry: AutomationStore,
    scheduler: DurableSchedulerStore,
    fence: SchedulerFence,
}

/// One occurrence's coordinates, derived from a registry row.
struct Occurrence {
    automation_id: String,
    at: i64,
    key: AutomationOccurrenceKey,
    work_id: WorkId,
    scope: ScopeId,
    prompt: String,
    schedule: AutomationSchedule,
}

impl AutomationSchedulerWorker {
    /// Open the three stores and install this generation's fence on the core.
    ///
    /// # Errors
    ///
    /// Returns the first store's refusal, by its own category.
    pub fn open(params: &AutomationSchedulerParams<'_>) -> Result<Self, AutomationSchedulerError> {
        let owned = OwnedParams {
            database_path: params.database_path.to_path_buf(),
            registry_path: params.registry_path.to_path_buf(),
            scheduler_path: params.scheduler_path.to_path_buf(),
            generation_id: params.generation_id.to_owned(),
            holder_id: params.holder_id.to_owned(),
            lease_epoch: params.lease_epoch,
            parallelism_limit: params.parallelism_limit,
            lease_time_source: Arc::clone(&params.lease_time_source),
            clock: Arc::clone(&params.clock),
        };
        Self::open_owned(owned)
    }

    fn open_owned(params: OwnedParams) -> Result<Self, AutomationSchedulerError> {
        let fence = SchedulerFence::new(
            params.generation_id.as_str(),
            params.holder_id.as_str(),
            params.lease_epoch,
        )
        .map_err(|_| AutomationSchedulerError::Corrupt("scheduler_fence"))?;
        let store = Store::open_with_lease_time_source(
            &params.database_path,
            Arc::clone(&params.lease_time_source),
        )?;
        let registry = AutomationStore::open(&params.registry_path)?;
        let scheduler = DurableSchedulerStore::open(
            &params.scheduler_path,
            params.parallelism_limit,
            fence.clone(),
        )?;
        Ok(Self {
            params,
            store,
            registry,
            scheduler,
            fence,
        })
    }

    /// The fence every core operation is judged under.
    #[must_use]
    pub const fn fence(&self) -> &SchedulerFence {
        &self.fence
    }

    /// One tick at the clock's `now`.
    ///
    /// # Errors
    ///
    /// As [`Self::tick_at`], plus [`AutomationSchedulerError::Clock`].
    pub fn tick(&mut self) -> Result<TickReport, AutomationSchedulerError> {
        let now_ms = self
            .params
            .clock
            .now_ms()
            .map_err(AutomationSchedulerError::Clock)?;
        self.tick_at(now_ms)
    }

    /// One tick, judged at an explicit `now`.
    ///
    /// Reconciles what is active, admits what is due, and starts what the core
    /// admits, in that order and under the fence. Every step is a replayable
    /// durable write: a tick that fails halfway leaves state the next tick
    /// finishes rather than repeats.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationSchedulerError::StaleFence`] when this holder and
    /// epoch no longer own the generation — nothing was started —
    /// [`AutomationSchedulerError::Transient`] when a store was busy, and the
    /// refusing store's category otherwise.
    pub fn tick_at(&mut self, now_ms: i64) -> Result<TickReport, AutomationSchedulerError> {
        if now_ms < 0 {
            return Err(AutomationSchedulerError::Clock("clock_before_epoch"));
        }
        self.require_generation(now_ms)?;
        let mut report = TickReport::default();
        self.reconcile_active(now_ms, &mut report)?;
        self.admit_due(now_ms, &mut report)?;
        self.start_admitted(now_ms, &mut report)?;
        Ok(report)
    }

    /// The product store's generation row must name this holder and epoch
    /// with a live lease.
    fn require_generation(&mut self, now_ms: i64) -> Result<(), AutomationSchedulerError> {
        let snapshot = self
            .store
            .status_snapshot_at(&self.params.generation_id, now_ms)?;
        let generation = snapshot
            .generation()
            .ok_or(AutomationSchedulerError::StaleFence)?;
        if generation.holder_id() != self.params.holder_id
            || generation.lease_epoch() != self.params.lease_epoch
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(AutomationSchedulerError::StaleFence);
        }
        Ok(())
    }

    /// Step 1: every occurrence the registry records as active, read back
    /// against the core and the lane.
    fn reconcile_active(
        &mut self,
        now_ms: i64,
        report: &mut TickReport,
    ) -> Result<(), AutomationSchedulerError> {
        for record in self.registry.active_occurrences(OCCURRENCE_BATCH)? {
            let job = record
                .job
                .as_ref()
                .ok_or(AutomationSchedulerError::Corrupt("active_without_job"))?;
            let at = job
                .active_occurrence_ms
                .ok_or(AutomationSchedulerError::Corrupt("active_without_instant"))?;
            let occurrence = occurrence(&record, at)?;
            let enabled = record.enablement.admits_occurrence();
            let archived =
                record.enablement == automonique_store::automation_store::EnablementState::Archived;
            match self.scheduler.state(&occurrence.work_id)? {
                // The registry write follows the core's, so a row the core has
                // never seen is a core that lost it. Re-admit under the same
                // identity; both stores dedupe on it.
                None => {
                    self.scheduler.submit(&QueuedWork::new(
                        occurrence.work_id.clone(),
                        occurrence.scope.clone(),
                    ))?;
                }
                Some(WorkState::Queued) => {
                    if !enabled {
                        // Cancelling queued work: it never starts. The instant
                        // is skipped rather than retried — the core remembers
                        // the identity as terminal and would refuse it again.
                        self.scheduler.cancel(&occurrence.work_id)?;
                        self.skip_unstarted(&occurrence, now_ms)?;
                        report.cancelled += 1;
                    }
                }
                Some(WorkState::Running | WorkState::StopRequested) => {
                    match self
                        .store
                        .inbox_disposition(OCCURRENCE_TRANSPORT, occurrence.key.as_str())?
                    {
                        // Started by the core, never handed to the lane: a
                        // crash between the two, or a withdrawal that landed
                        // between a tick's start and this one.
                        None => {
                            if enabled {
                                self.submit_to_lane(&occurrence, now_ms)?;
                                report.started += 1;
                            } else {
                                self.cancel_unstarted(&occurrence, now_ms)?;
                                report.cancelled += 1;
                            }
                        }
                        Some(disposition) if disposition.state.is_terminal() => {
                            self.settle_fired(&occurrence, now_ms)?;
                            report.settled += 1;
                        }
                        // In flight on the lane. Pause is not cancel; archive
                        // requests a stop, and custody stays with the core until
                        // the lane's terminal commit lands.
                        Some(_) => {
                            if archived
                                && matches!(
                                    self.scheduler.state(&occurrence.work_id)?,
                                    Some(WorkState::Running)
                                )
                            {
                                self.scheduler.cancel(&occurrence.work_id)?;
                            }
                        }
                    }
                }
                // Terminal in the core with the registry still active: a crash
                // between the core's commit and the registry's settle. Whether
                // it fired is the lane's to say.
                Some(WorkState::Completed | WorkState::Cancelled) => {
                    let fired = self
                        .store
                        .inbox_disposition(OCCURRENCE_TRANSPORT, occurrence.key.as_str())?
                        .is_some();
                    self.advance(&occurrence, now_ms)?;
                    self.registry
                        .settle_occurrence(&occurrence.automation_id, at, fired)?;
                    report.settled += 1;
                }
            }
        }
        Ok(())
    }

    /// Step 2: admit every due occurrence to the core, and mark it active.
    fn admit_due(
        &mut self,
        now_ms: i64,
        report: &mut TickReport,
    ) -> Result<(), AutomationSchedulerError> {
        for record in self.registry.due(now_ms, OCCURRENCE_BATCH)? {
            let job = record
                .job
                .as_ref()
                .ok_or(AutomationSchedulerError::Corrupt("due_without_job"))?;
            let at = job
                .next_fire_at_ms
                .ok_or(AutomationSchedulerError::Corrupt("due_without_instant"))?;
            let occurrence = occurrence(&record, at)?;
            match self.scheduler.submit(&QueuedWork::new(
                occurrence.work_id.clone(),
                occurrence.scope.clone(),
            )) {
                // Already admitted — by a tick that crashed before the registry
                // write, or as a terminal identity the core still remembers.
                // Either way the registry's admission below is what decides.
                Ok(()) | Err(DurableSchedulerError::DuplicateWork) => {}
                Err(error) => return Err(error.into()),
            }
            match self
                .registry
                .admit_occurrence(&occurrence.automation_id, at)
            {
                Ok(()) => report.admitted += 1,
                // The row moved between the read and the write — a withdrawal
                // landed. Leave it; the next tick reads the row as it is.
                Err(AutomationStoreError::OccurrenceMismatch) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Step 3: start what the core admits under its bound.
    fn start_admitted(
        &mut self,
        now_ms: i64,
        report: &mut TickReport,
    ) -> Result<(), AutomationSchedulerError> {
        for work_id in self.scheduler.tick(&self.fence.clone())? {
            let (automation_id, at) = AutomationOccurrenceKey::parse(work_id.as_str())
                .map_err(|_| AutomationSchedulerError::Corrupt("occurrence_key"))?;
            let record = self.registry.entry(automation_id.as_str())?;
            let active = record
                .as_ref()
                .and_then(|record| record.job.as_ref().and_then(|job| job.active_occurrence_ms));
            match record {
                Some(record)
                    if active == Some(at.as_millis()) && record.enablement.admits_occurrence() =>
                {
                    let occurrence = occurrence(&record, at.as_millis())?;
                    self.submit_to_lane(&occurrence, now_ms)?;
                    report.started += 1;
                }
                // Admitted to the core but not, any longer, to the registry:
                // withdrawn since, or admitted by a tick whose registry write
                // lost a race. Nothing was handed to the lane, so nothing ran;
                // the core is told so and the identity stays terminal.
                Some(record) if active == Some(at.as_millis()) => {
                    let occurrence = occurrence(&record, at.as_millis())?;
                    self.cancel_unstarted(&occurrence, now_ms)?;
                    report.cancelled += 1;
                }
                _ => {
                    self.scheduler.cancel(&work_id)?;
                    self.scheduler.complete(&work_id)?;
                    report.cancelled += 1;
                }
            }
        }
        Ok(())
    }

    /// Submit the occurrence to the synthetic lane and advance the registry
    /// past its instant. Both are idempotent under the key.
    fn submit_to_lane(
        &mut self,
        occurrence: &Occurrence,
        now_ms: i64,
    ) -> Result<(), AutomationSchedulerError> {
        self.store.submit_inbox(InboxSubmission {
            transport: OCCURRENCE_TRANSPORT,
            transport_key: occurrence.key.as_str(),
            scope: occurrence.scope.as_str(),
            payload: occurrence.prompt.as_bytes(),
            received_ms: now_ms,
        })?;
        self.advance(occurrence, now_ms)
    }

    /// The lane reported the occurrence terminal: free the slot, record the
    /// firing.
    fn settle_fired(
        &mut self,
        occurrence: &Occurrence,
        now_ms: i64,
    ) -> Result<(), AutomationSchedulerError> {
        self.advance(occurrence, now_ms)?;
        self.scheduler.complete(&occurrence.work_id)?;
        self.registry
            .settle_occurrence(&occurrence.automation_id, occurrence.at, true)?;
        Ok(())
    }

    /// The core started an occurrence the registry no longer admits: cancel
    /// the start before anything reaches the lane, and skip the instant.
    fn cancel_unstarted(
        &mut self,
        occurrence: &Occurrence,
        now_ms: i64,
    ) -> Result<(), AutomationSchedulerError> {
        self.scheduler.cancel(&occurrence.work_id)?;
        self.scheduler.complete(&occurrence.work_id)?;
        self.skip_unstarted(occurrence, now_ms)
    }

    /// Skip an instant that will never fire: advance past it and settle it as
    /// not fired.
    fn skip_unstarted(
        &mut self,
        occurrence: &Occurrence,
        now_ms: i64,
    ) -> Result<(), AutomationSchedulerError> {
        self.advance(occurrence, now_ms)?;
        self.registry
            .settle_occurrence(&occurrence.automation_id, occurrence.at, false)?;
        Ok(())
    }

    /// Advance the registry's next instant past the occurrence, to the
    /// schedule's successor as judged now. A replay answers false and keeps
    /// the successor the first call wrote.
    fn advance(
        &mut self,
        occurrence: &Occurrence,
        now_ms: i64,
    ) -> Result<(), AutomationSchedulerError> {
        let next = occurrence
            .schedule
            .next_after(
                EpochMillis::from_millis(occurrence.at),
                EpochMillis::from_millis(now_ms),
            )
            .map(EpochMillis::as_millis);
        self.registry
            .advance_after_start(&occurrence.automation_id, occurrence.at, next)?;
        Ok(())
    }
}

/// Derive one occurrence's coordinates from a registry row and an instant.
fn occurrence(record: &AutomationRecord, at: i64) -> Result<Occurrence, AutomationSchedulerError> {
    let job = record
        .job
        .as_ref()
        .ok_or(AutomationSchedulerError::Corrupt("occurrence_without_job"))?;
    let automation_id = AutomationId::new(&record.automation_id)
        .map_err(|_| AutomationSchedulerError::Corrupt("automation_id"))?;
    let key = AutomationOccurrenceKey::derive(&automation_id, EpochMillis::from_millis(at))
        .map_err(|_| AutomationSchedulerError::Corrupt("occurrence_key"))?;
    let work_id =
        WorkId::new(key.as_str()).map_err(|_| AutomationSchedulerError::Corrupt("work_id"))?;
    let scope =
        ScopeId::new(job.scope.as_str()).map_err(|_| AutomationSchedulerError::Corrupt("scope"))?;
    let schedule = match job.schedule {
        StoredSchedule::Once { at_ms } => AutomationSchedule::once(EpochMillis::from_millis(at_ms)),
        StoredSchedule::Every { interval_ms } => AutomationSchedule::every(interval_ms),
    }
    .map_err(|_| AutomationSchedulerError::Corrupt("schedule"))?;
    Ok(Occurrence {
        automation_id: record.automation_id.clone(),
        at,
        key,
        work_id,
        scope,
        prompt: job.prompt.clone(),
        schedule,
    })
}

/// The worker on a thread, with the lifecycle every other daemon worker has.
///
/// `open` composes and dials nothing; `start` puts the worker on a thread;
/// `begin_shutdown` signals it and hands its join handle to the daemon's
/// labelled drain. A host opened in recovery mode is [`Self::disabled`]:
/// nothing composed, nothing to start, nothing to drain.
pub struct AutomationSchedulerHost {
    composed: Option<AutomationSchedulerWorker>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    fault: Arc<Mutex<Option<&'static str>>>,
}

impl AutomationSchedulerHost {
    /// A host with no worker: the recovery-mode shape.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            composed: None,
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
            fault: Arc::new(Mutex::new(None)),
        }
    }

    /// Open the worker's stores under the generation fence, starting nothing.
    ///
    /// # Errors
    ///
    /// As [`AutomationSchedulerWorker::open`].
    pub fn open(params: &AutomationSchedulerParams<'_>) -> Result<Self, AutomationSchedulerError> {
        Ok(Self {
            composed: Some(AutomationSchedulerWorker::open(params)?),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
            fault: Arc::new(Mutex::new(None)),
        })
    }

    /// Put the composed worker on its thread. A second call, or a call on a
    /// disabled host, is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationSchedulerError::Thread`] when the thread cannot be
    /// spawned.
    pub fn start(&mut self) -> Result<(), AutomationSchedulerError> {
        if self.worker.is_some() {
            return Ok(());
        }
        let Some(mut composed) = self.composed.take() else {
            return Ok(());
        };
        let stop = Arc::clone(&self.stop);
        let fault = Arc::clone(&self.fault);
        let worker = std::thread::Builder::new()
            .name("automonique-automation-scheduler".to_owned())
            .spawn(move || composed.run(&stop, &fault))
            .map_err(|_| AutomationSchedulerError::Thread)?;
        self.worker = Some(worker);
        Ok(())
    }

    /// The category the worker stopped on, if it stopped on its own.
    ///
    /// A worker that met a non-transient failure — a stale fence, corrupt
    /// state — stops rather than looping over it, and says why here.
    #[must_use]
    pub fn fault(&self) -> Option<&'static str> {
        self.fault.lock().map_or(None, |fault| *fault)
    }

    /// Whether a worker thread is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    /// Signal and join the worker.
    pub fn shutdown(&mut self) {
        if let Some(worker) = self.begin_shutdown() {
            let _ = worker.join();
        }
    }

    /// Signal the worker and return its join handle to an external drainer.
    ///
    /// The daemon uses this form so all workers can drain together while the
    /// serve thread keeps their shared generation lease renewed.
    pub(crate) fn begin_shutdown(&mut self) -> Option<JoinHandle<()>> {
        self.stop.store(true, Ordering::Release);
        self.worker.take()
    }
}

impl Drop for AutomationSchedulerHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl AutomationSchedulerWorker {
    fn run(&mut self, stop: &AtomicBool, fault: &Mutex<Option<&'static str>>) {
        while !stop.load(Ordering::Acquire) {
            match self.tick() {
                Ok(report) if !report.is_idle() => {}
                Ok(_) => std::thread::sleep(IDLE_POLL),
                Err(error) if error.is_transient() => std::thread::sleep(IDLE_POLL),
                Err(error) => {
                    if let Ok(mut slot) = fault.lock() {
                        *slot = Some(error.category());
                    }
                    return;
                }
            }
        }
    }
}
