// SPDX-License-Identifier: Elastic-2.0

use automonique_observability::{
    EventCategory, MetricName, MetricSample, MetricValue, MetricsSnapshot, ObservabilityError,
    OperationalEvent, OperationalEventKind, Severity, StoreAssessment, StoreProjection,
    UnavailableReason,
};
use automonique_store::{
    InboxSubmission, LeaseRequest, OutboxClaimRequest, SchedulerClaim, Store, TerminalRun,
    TerminalState,
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
