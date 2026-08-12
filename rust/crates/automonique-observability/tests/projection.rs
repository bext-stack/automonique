// SPDX-License-Identifier: Elastic-2.0

use automonique_observability::{
    EventCategory, MetricName, MetricSample, MetricValue, MetricsSnapshot, ObservabilityError,
    OperationalEvent, OperationalEventKind, Severity, UnavailableReason,
};

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
