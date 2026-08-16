// SPDX-License-Identifier: Elastic-2.0

use automonique_observability::{
    EventCategory, MetricName, MetricSample, MetricValue, MetricsSnapshot, ObservabilityError,
    OperationalEvent, OperationalEventKind, Severity, StoreAssessment, StoreProjection,
    UnavailableReason, render_exposition,
};
use automonique_store::{
    InboxSubmission, LeaseRequest, OutboxClaimRequest, SchedulerClaim, Store,
    TelegramPollerLeaseIdentity, TelegramPollerLeaseRequest, TerminalRun, TerminalState,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn samples() -> Vec<MetricSample> {
    MetricName::ALL
        .into_iter()
        .map(|name| {
            let value = match name {
                MetricName::DaemonReady
                | MetricName::IntakeEnabled
                | MetricName::TelegramPollerOwned
                | MetricName::ProviderAvailable => 1,
                _ => 0,
            };
            MetricSample::new(name, value).expect("sample")
        })
        .collect()
}

#[test]
fn clean_released_poller_is_not_reconciliation_debt() {
    let directory = tempfile::tempdir().expect("directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let mut store = Store::open(directory.path().join("store.sqlite3")).expect("store");
    let generation = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("generation");
    let poller = store
        .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
            bot_id: 7,
            generation_id: "generation-a",
            holder_id: "holder-a",
            authority_lease_epoch: generation.epoch,
            now_ms: 2,
            ttl_ms: 20,
        })
        .expect("poller");
    store
        .release_telegram_poller_lease(TelegramPollerLeaseIdentity {
            bot_id: poller.bot_id,
            generation_id: &poller.generation_id,
            holder_id: &poller.holder_id,
            poller_epoch: poller.epoch,
            expected_expires_ms: poller.expires_ms,
            now_ms: 3,
        })
        .expect("release");
    let snapshot = store
        .status_snapshot_at("generation-a", 4)
        .expect("snapshot");
    let projection = StoreProjection::from_status(&snapshot).expect("projection");
    assert_eq!(projection.assessment(), StoreAssessment::Unknown);
    assert_eq!(
        projection
            .metrics()
            .value(MetricName::ReconciliationPending),
        MetricValue::Measured(0)
    );
}

#[test]
fn a_complete_low_cardinality_snapshot_preserves_exact_measurements() {
    let snapshot = MetricsSnapshot::new(1, "generation-a", samples()).expect("snapshot");
    assert_eq!(
        snapshot.value(MetricName::DaemonReady),
        MetricValue::Measured(1)
    );

    let mut degraded = samples();
    let intake = degraded
        .iter_mut()
        .find(|sample| sample.name() == MetricName::IntakeEnabled)
        .expect("intake");
    *intake = MetricSample::new(MetricName::IntakeEnabled, 0).expect("disabled");
    let snapshot = MetricsSnapshot::new(2, "generation-a", degraded).expect("snapshot");
    assert_eq!(
        snapshot.value(MetricName::IntakeEnabled),
        MetricValue::Measured(0)
    );
}

#[test]
fn unavailable_measurements_are_explicit_without_invented_defaults() {
    let mut values = samples();
    let provider = values
        .iter_mut()
        .find(|sample| sample.name() == MetricName::ProviderAvailable)
        .expect("provider");
    *provider = MetricSample::unavailable(
        MetricName::ProviderAvailable,
        UnavailableReason::NotIntegrated,
    );
    let snapshot = MetricsSnapshot::new(1, "generation-a", values).expect("snapshot");
    assert_eq!(
        snapshot.value(MetricName::ProviderAvailable),
        MetricValue::Unavailable(UnavailableReason::NotIntegrated)
    );
}

#[test]
fn missing_duplicate_and_non_boolean_values_refuse() {
    let mut missing = samples();
    missing.pop();
    assert_eq!(
        MetricsSnapshot::new(1, "generation-a", missing).expect_err("missing"),
        ObservabilityError::IncompleteSnapshot
    );
    let mut duplicate = samples();
    duplicate.push(MetricSample::new(MetricName::InboxPending, 1).expect("sample"));
    assert_eq!(
        MetricsSnapshot::new(1, "generation-a", duplicate).expect_err("duplicate"),
        ObservabilityError::DuplicateMetric(MetricName::InboxPending)
    );
    assert_eq!(
        MetricSample::new(MetricName::DaemonReady, 2).expect_err("boolean"),
        ObservabilityError::InvalidBooleanMetric(MetricName::DaemonReady)
    );
}

#[test]
fn events_have_no_free_form_message_or_labels() {
    let event = OperationalEvent::new(
        1,
        OperationalEventKind::ReconciliationRequired,
        Severity::Warning,
        "generation-a",
        Some(41),
        None,
        Some(EventCategory::ClaimedOutcomeUnknown),
    )
    .expect("event");
    assert_eq!(
        event.category().map(EventCategory::as_str),
        Some("claimed_outcome_unknown")
    );
    assert!(!format!("{event:?}").contains("prompt"));
    assert!(
        OperationalEvent::new(
            1,
            OperationalEventKind::ProviderRefused,
            Severity::Error,
            "generation-a",
            None,
            None,
            Some(EventCategory::PolicyRefused),
        )
        .is_ok()
    );
    assert!(MetricsSnapshot::new(1, "/home/customer/workspace", samples()).is_err());
}

#[test]
fn store_projection_uses_real_snapshot_and_never_invents_readiness() {
    let directory = tempfile::tempdir().expect("directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let path = directory.path().join("store.sqlite3");
    let mut store = Store::open(&path).expect("store");
    let generation = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("generation");
    let empty = store
        .status_snapshot_at("generation-a", 2)
        .expect("empty snapshot");
    let legacy = store
        .status_snapshot("generation-a")
        .expect("aggregate compatibility snapshot");
    assert_eq!(legacy.observed_ms(), 0);
    assert_eq!(
        StoreProjection::from_status(&legacy).expect_err("legacy snapshot is not projectable"),
        ObservabilityError::InvalidCoordinate
    );
    let projection = StoreProjection::from_status(&empty).expect("projection");
    assert_eq!(projection.assessment(), StoreAssessment::Unknown);
    assert_eq!(
        projection.metrics().value(MetricName::DaemonReady),
        MetricValue::Unavailable(UnavailableReason::NotIntegrated)
    );
    assert_eq!(
        projection.metrics().value(MetricName::OutboxPendingReady),
        MetricValue::Measured(0)
    );

    store
        .submit_inbox(InboxSubmission {
            transport: "test",
            transport_key: "observable-effect",
            scope: "scope:observable",
            payload: b"bounded",
            received_ms: 3,
        })
        .expect("inbox");
    let run = store
        .claim_next(SchedulerClaim {
            transport: "test",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: generation.epoch,
            now_ms: 4,
        })
        .expect("claim")
        .expect("run");
    store
        .finish_run(TerminalRun {
            run_id: run.run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: generation.epoch,
            expected_revision: 1,
            now_ms: 5,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"done",
            outbox_intent_key: "observable-intent",
            outbox_kind: "test.effect",
            outbox_payload: b"effect",
        })
        .expect("terminal");
    store
        .claim_outbox(OutboxClaimRequest {
            transport: "test",
            kind: "test.effect",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: generation.epoch,
            now_ms: 6,
            ttl_ms: 4,
        })
        .expect("outbox claim")
        .expect("outbox");
    drop(store);

    let mut reopened = Store::open(&path).expect("reopen");
    let ambiguous = reopened
        .status_snapshot_at("generation-a", 10)
        .expect("ambiguous snapshot");
    let degraded = StoreProjection::from_status(&ambiguous).expect("degraded projection");
    assert_eq!(degraded.assessment(), StoreAssessment::Degraded);
    assert_eq!(
        degraded
            .metrics()
            .value(MetricName::OutboxInFlightAmbiguous),
        MetricValue::Measured(1)
    );
    assert_eq!(
        degraded.metrics().value(MetricName::ProviderAvailable),
        MetricValue::Unavailable(UnavailableReason::NotIntegrated)
    );
}

/// The four live-progress metrics: absent from a store snapshot, and present
/// once the fan-out reports.
///
/// The pairing is the whole point. A database has never seen a subscriber
/// queue, so a store projection says `unavailable` rather than zero — because
/// zero drops and zero lag disconnects is a real reading an operator would act
/// on, and it is not the reading a database can take.
#[test]
fn progress_metrics_are_unavailable_until_the_fan_out_reports_them() {
    use automonique_observability::ProgressObservation;

    const PROGRESS: [MetricName; 4] = [
        MetricName::ProgressQueueHighWaterBytes,
        MetricName::ProgressFramesDropped,
        MetricName::ProgressLagDisconnects,
        MetricName::ProgressOldestRetainedAgeMs,
    ];

    let directory = tempfile::tempdir().expect("directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory");
    let mut store = Store::open(directory.path().join("store.sqlite3")).expect("store");
    store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("generation");
    let status = store
        .status_snapshot_at("generation-a", 2)
        .expect("status snapshot");

    let projection = StoreProjection::from_status(&status).expect("projection");
    for name in PROGRESS {
        assert_eq!(
            projection.metrics().value(name),
            MetricValue::Unavailable(UnavailableReason::NotIntegrated),
            "{} was answered from a source that cannot see it",
            name.as_str()
        );
    }

    let observed = projection
        .clone()
        .with_progress(ProgressObservation {
            queue_high_water_bytes: 4_096,
            frames_dropped: 17,
            lag_disconnects: 1,
            oldest_retained_age_ms: 250,
        })
        .expect("the fan-out's observation attaches");
    assert_eq!(
        observed
            .metrics()
            .value(MetricName::ProgressQueueHighWaterBytes),
        MetricValue::Measured(4_096)
    );
    assert_eq!(
        observed.metrics().value(MetricName::ProgressFramesDropped),
        MetricValue::Measured(17)
    );
    assert_eq!(
        observed.metrics().value(MetricName::ProgressLagDisconnects),
        MetricValue::Measured(1)
    );
    assert_eq!(
        observed
            .metrics()
            .value(MetricName::ProgressOldestRetainedAgeMs),
        MetricValue::Measured(250)
    );
    // The durable half is untouched: attaching a memory reading cannot
    // overwrite a reading of the store, and the assessment is still the store's.
    assert_eq!(
        observed.metrics().value(MetricName::InboxPending),
        projection.metrics().value(MetricName::InboxPending)
    );
    assert_eq!(observed.assessment(), projection.assessment());

    // And a second attachment is refused: a snapshot is one reading, not two
    // taken at different moments.
    assert_eq!(
        observed.with_progress(ProgressObservation::default()),
        Err(ObservabilityError::DuplicateMetric(
            MetricName::ProgressQueueHighWaterBytes
        ))
    );
}

/// The metric names are the exported strings, and they are all distinct.
#[test]
fn every_metric_name_is_exported_once() {
    let mut names: Vec<&str> = MetricName::ALL
        .into_iter()
        .map(MetricName::as_str)
        .collect();
    assert_eq!(names.len(), MetricName::ALL.len());
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        MetricName::ALL.len(),
        "two metrics export the same name"
    );
    assert!(
        MetricName::ALL
            .into_iter()
            .all(|name| name.as_str().starts_with("automonique_")),
        "a metric escaped the product's own namespace"
    );
}

#[test]
fn prometheus_exposition_is_complete_typed_and_never_invents_missing_values() {
    let mut values = samples();
    let provider = values
        .iter_mut()
        .find(|sample| sample.name() == MetricName::ProviderAvailable)
        .expect("provider metric");
    *provider = MetricSample::unavailable(
        MetricName::ProviderAvailable,
        UnavailableReason::DependencyUnavailable,
    );
    let snapshot = MetricsSnapshot::new(1, "generation-a", values).expect("snapshot");
    let rendered = render_exposition(&snapshot, "1.2\"edge\\build");

    assert!(rendered.starts_with("# HELP automonique_build_info"));
    assert!(rendered.contains("automonique_build_info{version=\"1.2\\\"edge\\\\build\"} 1\n"));
    for name in MetricName::ALL {
        assert_eq!(
            rendered
                .lines()
                .filter(|line| *line == format!("# HELP {} {}", name.as_str(), name.help()))
                .count(),
            1,
            "{} must have one HELP line",
            name.as_str()
        );
        assert!(rendered.contains(&format!(
            "# TYPE {} {}\n",
            name.as_str(),
            name.metric_type()
        )));
    }
    assert!(rendered.contains(
        "# automonique unavailable automonique_provider_available dependency_unavailable\n"
    ));
    assert!(!rendered.contains("automonique_provider_available 0\n"));
    assert!(rendered.ends_with('\n'));
}
