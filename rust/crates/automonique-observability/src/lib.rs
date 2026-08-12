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
}

impl MetricName {
    pub const ALL: [Self; 11] = [
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
