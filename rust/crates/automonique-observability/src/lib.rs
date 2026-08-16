// SPDX-License-Identifier: Elastic-2.0

//! Bounded, low-cardinality operational projections.
//!
//! This crate deliberately has no free-form label or log-message API. Product
//! components report closed metric/event kinds and bounded numeric coordinates;
//! user content, credentials, paths, prompts, and provider output are not
//! representable. A snapshot is a validated data transfer object, not a health
//! authority: this crate deliberately exposes no `healthy` decision until
//! production components supply independently measured values.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use automonique_store::StatusSnapshot;

const MAX_GENERATION_ID_BYTES: usize = 128;

/// Closed metric vocabulary exported by the first operational projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricName {
    DaemonReady,
    IntakeEnabled,
    InboxPending,
    RunsRunning,
    ReconciliationPending,
    OutboxPending,
    OutboxOldestAgeMs,
    TelegramPollerOwned,
    TelegramOffsetLag,
    ProviderAvailable,
    SandboxLaunchRefusals,
    OutboxPendingReady,
    OutboxPendingDelayed,
    OutboxInFlightLive,
    OutboxInFlightAmbiguous,
    OutboxDelivered,
    OutboxDeadLettered,
    TelegramPollersLive,
    TelegramPollersExpired,
    /// Most bytes one live-progress subscriber's queue has ever held.
    ///
    /// The bound it is measured against is the fan-out's, not this crate's:
    /// what this reports is how close the busiest subscriber came to being
    /// disconnected for falling behind.
    ProgressQueueHighWaterBytes,
    /// Frames discarded from subscriber queues, cumulative.
    ProgressFramesDropped,
    /// Subscribers disconnected for falling behind, cumulative.
    ProgressLagDisconnects,
    /// Age of the oldest frame still retained for replay.
    ///
    /// The live window's depth in time. It is not a claim about the durable
    /// record, which retains everything and has no age.
    ProgressOldestRetainedAgeMs,
}

impl MetricName {
    pub const ALL: [Self; 23] = [
        Self::DaemonReady,
        Self::IntakeEnabled,
        Self::InboxPending,
        Self::RunsRunning,
        Self::ReconciliationPending,
        Self::OutboxPending,
        Self::OutboxOldestAgeMs,
        Self::TelegramPollerOwned,
        Self::TelegramOffsetLag,
        Self::ProviderAvailable,
        Self::SandboxLaunchRefusals,
        Self::OutboxPendingReady,
        Self::OutboxPendingDelayed,
        Self::OutboxInFlightLive,
        Self::OutboxInFlightAmbiguous,
        Self::OutboxDelivered,
        Self::OutboxDeadLettered,
        Self::TelegramPollersLive,
        Self::TelegramPollersExpired,
        Self::ProgressQueueHighWaterBytes,
        Self::ProgressFramesDropped,
        Self::ProgressLagDisconnects,
        Self::ProgressOldestRetainedAgeMs,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DaemonReady => "automonique_daemon_ready",
            Self::IntakeEnabled => "automonique_intake_enabled",
            Self::InboxPending => "automonique_inbox_pending",
            Self::RunsRunning => "automonique_runs_running",
            Self::ReconciliationPending => "automonique_reconciliation_pending",
            Self::OutboxPending => "automonique_outbox_pending",
            Self::OutboxOldestAgeMs => "automonique_outbox_oldest_age_ms",
            Self::TelegramPollerOwned => "automonique_telegram_poller_owned",
            Self::TelegramOffsetLag => "automonique_telegram_offset_lag",
            Self::ProviderAvailable => "automonique_provider_available",
            Self::SandboxLaunchRefusals => "automonique_sandbox_launch_refusals_total",
            Self::OutboxPendingReady => "automonique_outbox_pending_ready",
            Self::OutboxPendingDelayed => "automonique_outbox_pending_delayed",
            Self::OutboxInFlightLive => "automonique_outbox_in_flight_live",
            Self::OutboxInFlightAmbiguous => "automonique_outbox_in_flight_ambiguous",
            Self::OutboxDelivered => "automonique_outbox_delivered_total",
            Self::OutboxDeadLettered => "automonique_outbox_dead_lettered_total",
            Self::TelegramPollersLive => "automonique_telegram_pollers_live",
            Self::TelegramPollersExpired => "automonique_telegram_pollers_expired",
            Self::ProgressQueueHighWaterBytes => "automonique_progress_queue_high_water_bytes",
            Self::ProgressFramesDropped => "automonique_progress_frames_dropped_total",
            Self::ProgressLagDisconnects => "automonique_progress_lag_disconnects_total",
            Self::ProgressOldestRetainedAgeMs => "automonique_progress_oldest_retained_age_ms",
        }
    }

    const fn is_boolean(self) -> bool {
        matches!(
            self,
            Self::DaemonReady
                | Self::IntakeEnabled
                | Self::TelegramPollerOwned
                | Self::ProviderAvailable
        )
    }
}

/// Conservative assessment derived only from durable store evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreAssessment {
    /// No durable ambiguity is visible, but runtime/provider readiness is not integrated.
    Unknown,
    /// Durable expired work requires reconciliation.
    Degraded,
}

/// Metrics and assessment derived from one real SQLite status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreProjection {
    metrics: MetricsSnapshot,
    assessment: StoreAssessment,
}

impl StoreProjection {
    pub fn from_status(status: &StatusSnapshot) -> Result<Self, ObservabilityError> {
        let generation = status
            .generation()
            .ok_or(ObservabilityError::MissingGeneration)?;
        let observed_ms = u64::try_from(status.observed_ms())
            .map_err(|_| ObservabilityError::InvalidCoordinate)?;
        let reconciliation_pending = status
            .runs_reconciliation_pending()
            .checked_add(status.outbox_in_flight_ambiguous())
            .ok_or(ObservabilityError::MetricOverflow)?;
        let unavailable = |name| MetricSample::unavailable(name, UnavailableReason::NotIntegrated);
        let measured = |name, value| MetricSample::new(name, value);
        let samples = [
            unavailable(MetricName::DaemonReady),
            unavailable(MetricName::IntakeEnabled),
            measured(MetricName::InboxPending, status.inbox_pending())?,
            measured(MetricName::RunsRunning, status.runs_running())?,
            measured(MetricName::ReconciliationPending, reconciliation_pending)?,
            measured(MetricName::OutboxPending, status.outbox_pending())?,
            measured(
                MetricName::OutboxOldestAgeMs,
                status.outbox_oldest_ready_age_ms(),
            )?,
            measured(
                MetricName::TelegramPollerOwned,
                u64::from(status.telegram_pollers_live() > 0),
            )?,
            unavailable(MetricName::TelegramOffsetLag),
            unavailable(MetricName::ProviderAvailable),
            unavailable(MetricName::SandboxLaunchRefusals),
            measured(
                MetricName::OutboxPendingReady,
                status.outbox_pending_ready(),
            )?,
            measured(
                MetricName::OutboxPendingDelayed,
                status.outbox_pending_delayed(),
            )?,
            measured(
                MetricName::OutboxInFlightLive,
                status.outbox_in_flight_live(),
            )?,
            measured(
                MetricName::OutboxInFlightAmbiguous,
                status.outbox_in_flight_ambiguous(),
            )?,
            measured(MetricName::OutboxDelivered, status.outbox_delivered())?,
            measured(
                MetricName::OutboxDeadLettered,
                status.outbox_dead_lettered(),
            )?,
            measured(
                MetricName::TelegramPollersLive,
                status.telegram_pollers_live(),
            )?,
            measured(
                MetricName::TelegramPollersExpired,
                status.telegram_pollers_expired(),
            )?,
            // The live fan-out is in the daemon's memory, not in this database.
            // A store snapshot cannot see it, so it says so rather than
            // reporting four zeroes that would read as a quiet endpoint.
            // [`StoreProjection::with_progress`] is where a measurement arrives.
            unavailable(MetricName::ProgressQueueHighWaterBytes),
            unavailable(MetricName::ProgressFramesDropped),
            unavailable(MetricName::ProgressLagDisconnects),
            unavailable(MetricName::ProgressOldestRetainedAgeMs),
        ];
        let metrics = MetricsSnapshot::new(observed_ms, generation.generation_id(), samples)?;
        let assessment = if reconciliation_pending > 0 {
            StoreAssessment::Degraded
        } else {
            StoreAssessment::Unknown
        };
        Ok(Self {
            metrics,
            assessment,
        })
    }

    /// Attach what the live progress fan-out observed, replacing the four
    /// samples a store snapshot cannot measure.
    ///
    /// Additive and narrow by construction: it can only measure metrics that
    /// [`StoreProjection::from_status`] declared unavailable, so it cannot
    /// overwrite a durable reading with a memory one. The assessment is
    /// untouched — a busy fan-out is not evidence about the store, and this
    /// crate's whole discipline is that a projection reports what its source
    /// saw and nothing more.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityError::DuplicateMetric`] if one of the four was
    /// already measured, which would mean this projection was being assembled
    /// from two readings taken at different moments.
    pub fn with_progress(
        mut self,
        observation: ProgressObservation,
    ) -> Result<Self, ObservabilityError> {
        self.metrics.measure([
            (
                MetricName::ProgressQueueHighWaterBytes,
                observation.queue_high_water_bytes,
            ),
            (
                MetricName::ProgressFramesDropped,
                observation.frames_dropped,
            ),
            (
                MetricName::ProgressLagDisconnects,
                observation.lag_disconnects,
            ),
            (
                MetricName::ProgressOldestRetainedAgeMs,
                observation.oldest_retained_age_ms,
            ),
        ])?;
        Ok(self)
    }

    #[must_use]
    pub const fn metrics(&self) -> &MetricsSnapshot {
        &self.metrics
    }

    #[must_use]
    pub const fn assessment(&self) -> StoreAssessment {
        self.assessment
    }
}

/// What one live progress fan-out has observed since the process started.
///
/// Four numbers and no identifiers: which attempt a subscriber was watching,
/// which peer it was, and what it was shown are all things this crate refuses
/// to represent, and none of them is needed to answer the question these
/// metrics exist for — whether the live tier is keeping up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgressObservation {
    /// Most bytes one subscriber's queue has ever held.
    pub queue_high_water_bytes: u64,
    /// Frames discarded from subscriber queues, cumulative.
    pub frames_dropped: u64,
    /// Subscribers disconnected for falling behind, cumulative.
    pub lag_disconnects: u64,
    /// Age of the oldest frame still retained for replay.
    pub oldest_retained_age_ms: u64,
}

/// Closed reason why a value could not be measured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    NotIntegrated,
    CapabilityMissing,
    DependencyUnavailable,
    MeasurementFailed,
}

/// A measurement is never represented by an invented default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricValue {
    Measured(u64),
    Unavailable(UnavailableReason),
}

/// One exact metric sample or explicit missing measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricSample {
    name: MetricName,
    value: MetricValue,
}

impl MetricSample {
    pub fn new(name: MetricName, value: u64) -> Result<Self, ObservabilityError> {
        if name.is_boolean() && value > 1 {
            return Err(ObservabilityError::InvalidBooleanMetric(name));
        }
        Ok(Self {
            name,
            value: MetricValue::Measured(value),
        })
    }

    #[must_use]
    pub const fn unavailable(name: MetricName, reason: UnavailableReason) -> Self {
        Self {
            name,
            value: MetricValue::Unavailable(reason),
        }
    }

    #[must_use]
    pub const fn name(self) -> MetricName {
        self.name
    }

    #[must_use]
    pub const fn value(self) -> MetricValue {
        self.value
    }
}

/// Complete point-in-time operational projection for one generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricsSnapshot {
    observed_ms: u64,
    generation_id: String,
    values: BTreeMap<MetricName, MetricValue>,
}

impl MetricsSnapshot {
    pub fn new(
        observed_ms: u64,
        generation_id: impl Into<String>,
        samples: impl IntoIterator<Item = MetricSample>,
    ) -> Result<Self, ObservabilityError> {
        let generation_id = generation_id.into();
        if observed_ms == 0 || !valid_coordinate(&generation_id, MAX_GENERATION_ID_BYTES) {
            return Err(ObservabilityError::InvalidCoordinate);
        }
        let mut values = BTreeMap::new();
        for sample in samples {
            if values.insert(sample.name, sample.value).is_some() {
                return Err(ObservabilityError::DuplicateMetric(sample.name));
            }
        }
        if MetricName::ALL
            .iter()
            .any(|name| !values.contains_key(name))
        {
            return Err(ObservabilityError::IncompleteSnapshot);
        }
        Ok(Self {
            observed_ms,
            generation_id,
            values,
        })
    }

    #[must_use]
    pub const fn observed_ms(&self) -> u64 {
        self.observed_ms
    }

    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    #[must_use]
    pub fn value(&self, name: MetricName) -> MetricValue {
        self.values[&name]
    }

    /// Record a real measurement for a metric this snapshot declared missing.
    ///
    /// Private, and it stays that way: a snapshot is a point-in-time projection
    /// of one source, and a public setter would let a caller assemble one out of
    /// readings taken at different moments. The one composition this crate
    /// admits is [`StoreProjection::with_progress`], which is why the guard is
    /// exactly "the sample must currently be unavailable" — a durable reading
    /// can never be overwritten by a later one.
    fn measure(
        &mut self,
        samples: impl IntoIterator<Item = (MetricName, u64)>,
    ) -> Result<(), ObservabilityError> {
        for (name, value) in samples {
            let sample = MetricSample::new(name, value)?;
            match self.values.get(&name) {
                Some(MetricValue::Unavailable(_)) => {
                    self.values.insert(name, sample.value());
                }
                _ => return Err(ObservabilityError::DuplicateMetric(name)),
            }
        }
        Ok(())
    }

    /// Iterate in the closed canonical metric order.
    pub fn samples(&self) -> impl Iterator<Item = (MetricName, MetricValue)> + '_ {
        MetricName::ALL
            .into_iter()
            .map(|name| (name, self.values[&name]))
    }
}

/// Closed severity levels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Closed operational event vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalEventKind {
    LeaseAcquired,
    LeaseLost,
    IntakeChanged,
    ReconciliationRequired,
    ReconciliationResolved,
    OutboxClaimed,
    OutboxReconciled,
    TelegramBatchCommitted,
    ProviderRefused,
    SandboxLaunchRefused,
}

/// Closed, low-cardinality refusal and transition categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventCategory {
    ClaimedOutcomeUnknown,
    StaleEpoch,
    DependencyUnavailable,
    CapabilityMissing,
    PolicyRefused,
    InvalidAttestation,
}

impl EventCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimedOutcomeUnknown => "claimed_outcome_unknown",
            Self::StaleEpoch => "stale_epoch",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::CapabilityMissing => "capability_missing",
            Self::PolicyRefused => "policy_refused",
            Self::InvalidAttestation => "invalid_attestation",
        }
    }
}

/// Redacted event containing no arbitrary message or string labels.
#[derive(Clone, Eq, PartialEq)]
pub struct OperationalEvent {
    observed_ms: u64,
    kind: OperationalEventKind,
    severity: Severity,
    generation_id: String,
    run_id: Option<u64>,
    outbox_id: Option<u64>,
    category: Option<EventCategory>,
}

impl OperationalEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observed_ms: u64,
        kind: OperationalEventKind,
        severity: Severity,
        generation_id: impl Into<String>,
        run_id: Option<u64>,
        outbox_id: Option<u64>,
        category: Option<EventCategory>,
    ) -> Result<Self, ObservabilityError> {
        let generation_id = generation_id.into();
        if observed_ms == 0
            || !valid_coordinate(&generation_id, MAX_GENERATION_ID_BYTES)
            || run_id == Some(0)
            || outbox_id == Some(0)
        {
            return Err(ObservabilityError::InvalidCoordinate);
        }
        Ok(Self {
            observed_ms,
            kind,
            severity,
            generation_id,
            run_id,
            outbox_id,
            category,
        })
    }

    #[must_use]
    pub const fn observed_ms(&self) -> u64 {
        self.observed_ms
    }

    #[must_use]
    pub const fn kind(&self) -> OperationalEventKind {
        self.kind
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    #[must_use]
    pub const fn run_id(&self) -> Option<u64> {
        self.run_id
    }

    #[must_use]
    pub const fn outbox_id(&self) -> Option<u64> {
        self.outbox_id
    }

    #[must_use]
    pub const fn category(&self) -> Option<EventCategory> {
        self.category
    }
}

impl fmt::Debug for OperationalEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalEvent")
            .field("observed_ms", &self.observed_ms)
            .field("kind", &self.kind)
            .field("severity", &self.severity)
            .field("generation_id", &self.generation_id)
            .field("run_id", &self.run_id)
            .field("outbox_id", &self.outbox_id)
            .field("category", &self.category)
            .finish()
    }
}

/// Closed construction refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservabilityError {
    InvalidCoordinate,
    InvalidBooleanMetric(MetricName),
    DuplicateMetric(MetricName),
    IncompleteSnapshot,
    MissingGeneration,
    MetricOverflow,
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "observability projection refused: {self:?}")
    }
}

impl Error for ObservabilityError {}

fn valid_coordinate(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
