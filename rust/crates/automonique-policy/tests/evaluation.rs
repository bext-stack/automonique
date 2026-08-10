// SPDX-License-Identifier: Elastic-2.0

use automonique_policy::{Disposition, Health, Importance, Observation, Rule, summarize};

#[test]
fn required_missing_evidence_fails_closed() {
    let evaluation = Rule::new("runtime-directory", Importance::Required)
        .evaluate(Observation::Unavailable("not observed"));

    assert_eq!(evaluation.disposition(), Disposition::Fail);
    assert_eq!(evaluation.reason(), Some("not observed"));
    assert_eq!(summarize(&[evaluation]).health, Health::Unhealthy);
}

#[test]
fn advisory_failure_degrades_without_becoming_healthy() {
    let evaluation = Rule::new("optional-supervisor", Importance::Advisory)
        .evaluate(Observation::Unsupported("adapter not installed"));
    let summary = summarize(&[evaluation]);

    assert_eq!(evaluation.disposition(), Disposition::Degraded);
    assert_eq!(summary.health, Health::Degraded);
    assert_eq!(summary.degraded, 1);
    assert_eq!(summary.unsupported, 1);
}

#[test]
fn informational_findings_do_not_mask_required_success() {
    let evaluations = [
        Rule::new("release-manifest", Importance::Required).evaluate(Observation::Satisfied),
        Rule::new("kernel-detail", Importance::Informational)
            .evaluate(Observation::Violated("older than preferred")),
    ];
    let summary = summarize(&evaluations);

    assert_eq!(summary.health, Health::Healthy);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.informational, 1);
}

#[test]
fn worst_disposition_controls_aggregate_health() {
    let evaluations = [
        Rule::new("optional-supervisor", Importance::Advisory)
            .evaluate(Observation::Unavailable("not queried")),
        Rule::new("runtime-directory", Importance::Required)
            .evaluate(Observation::Violated("mode is too permissive")),
        Rule::new("release-manifest", Importance::Required).evaluate(Observation::Satisfied),
    ];
    let summary = summarize(&evaluations);

    assert_eq!(summary.health, Health::Unhealthy);
    assert_eq!(summary.total, 3);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.degraded, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.unavailable, 1);
}

#[test]
fn empty_evidence_is_unknown() {
    let summary = summarize(&[]);

    assert_eq!(summary.health, Health::Unknown);
    assert_eq!(summary.total, 0);
}
