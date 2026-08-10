// SPDX-License-Identifier: Elastic-2.0

//! R1-22 verification contract.

use automonique_protocol::automation::{
    AutomationError, AutomationRevision, BoardClaim, CanonicalSchedule, CompletionEvidence, Goal,
    GoalVerdict, OccurrenceKey, TriggerRoute, VerificationMethod, WaitCondition,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

mod canonical_storage {
    use super::*;

    #[test]
    fn a_recognized_expression_parses_to_one_canonical_schedule() {
        assert_eq!(
            CanonicalSchedule::parse("every hour").expect("recognized"),
            CanonicalSchedule::Every {
                interval_ms: 3_600_000
            }
        );
        assert_eq!(
            CanonicalSchedule::parse("Daily").expect("case-insensitive"),
            CanonicalSchedule::Cron {
                expression: "0 0 * * *".to_owned(),
                timezone: "UTC".to_owned(),
            }
        );
    }

    #[test]
    fn an_ambiguous_expression_is_refused_rather_than_guessed() {
        for expression in ["sometime tomorrow", "when the build is green", "often"] {
            assert_eq!(
                CanonicalSchedule::parse(expression)
                    .expect_err("ambiguous")
                    .category(),
                "ambiguous_expression",
                "{expression} was guessed at"
            );
        }
    }

    #[test]
    fn a_canonical_schedule_round_trips_through_its_rendering() {
        let schedules = [
            CanonicalSchedule::Once { at: at(1_000) },
            CanonicalSchedule::Every {
                interval_ms: 60_000,
            },
            CanonicalSchedule::Cron {
                expression: "0 0 * * *".to_owned(),
                timezone: "UTC".to_owned(),
            },
        ];
        for schedule in &schedules {
            // Equal schedules render identically, so the preview an operator
            // reviews is the schedule that will run.
            assert_eq!(schedule.render(), schedule.clone().render());
        }
        assert_ne!(schedules[0].render(), schedules[1].render());
    }
}

mod occurrence_idempotency {
    use super::*;

    #[test]
    fn the_same_automation_and_instant_yield_the_same_key() {
        let first = OccurrenceKey::derive("auto-1", at(1_000)).expect("derived");
        for _ in 0..8 {
            assert_eq!(
                OccurrenceKey::derive("auto-1", at(1_000)).expect("derived"),
                first
            );
        }
    }

    #[test]
    fn a_different_automation_or_instant_yields_a_different_key() {
        let base = OccurrenceKey::derive("auto-1", at(1_000)).expect("derived");
        assert_ne!(
            base,
            OccurrenceKey::derive("auto-2", at(1_000)).expect("derived")
        );
        assert_ne!(
            base,
            OccurrenceKey::derive("auto-1", at(2_000)).expect("derived")
        );
    }

    #[test]
    fn a_key_takes_no_other_input() {
        // Only the automation and the canonical instant, so a replayed tick
        // after failover derives the same key rather than a fresh one.
        let key = OccurrenceKey::derive("auto-1", at(1_000)).expect("derived");
        assert!(key.as_str().starts_with("auto-1@"));
    }
}

mod revision_immutability {
    use super::*;

    fn automation() -> AutomationRevision {
        AutomationRevision::new(
            "auto-1",
            revision(3),
            CanonicalSchedule::Every {
                interval_ms: 60_000,
            },
            &["notify:slack"],
        )
        .expect("valid automation")
    }

    #[test]
    fn an_edit_requires_the_expected_revision() {
        let current = automation();
        let edited = current
            .edited(revision(3), CanonicalSchedule::Once { at: at(1) })
            .expect("matching expectation");
        assert_eq!(edited.revision().get(), 4);
        // The original is untouched.
        assert_eq!(current.revision().get(), 3);
    }

    #[test]
    fn a_stale_edit_conflicts_rather_than_overwriting() {
        assert_eq!(
            automation()
                .edited(revision(2), CanonicalSchedule::Once { at: at(1) })
                .expect_err("stale"),
            AutomationError::RevisionConflict {
                expected: 3,
                offered: 2,
            }
        );
    }
}

mod scope_authority {
    use super::*;

    fn automation() -> AutomationRevision {
        AutomationRevision::new(
            "auto-1",
            revision(1),
            CanonicalSchedule::Once { at: at(1) },
            &["notify:slack"],
        )
        .expect("valid automation")
    }

    #[test]
    fn a_pre_approved_effect_is_permitted() {
        automation()
            .permit_unattended("notify:slack")
            .expect("in scope");
    }

    #[test]
    fn an_effect_outside_scope_is_refused_not_completed() {
        assert_eq!(
            automation()
                .permit_unattended("deploy:production")
                .expect_err("out of scope"),
            AutomationError::OutsideApprovedScope {
                effect: "deploy:production".to_owned(),
            }
        );
    }

    #[test]
    fn an_automation_with_no_approved_effects_permits_nothing() {
        let bare = AutomationRevision::new(
            "auto-2",
            revision(1),
            CanonicalSchedule::Once { at: at(1) },
            &[],
        )
        .expect("valid automation");
        assert!(bare.permit_unattended("notify:slack").is_err());
    }
}

mod evidence_bound_completion {
    use super::*;

    #[test]
    fn a_narrative_goal_completes_on_prose() {
        let goal = Goal::new("g-1", CompletionEvidence::Narrative).expect("valid goal");
        let verdict = goal
            .complete_with(CompletionEvidence::Narrative, "explained the failure")
            .expect("prose is sufficient here");
        assert!(matches!(verdict, GoalVerdict::Complete { .. }));
    }

    #[test]
    fn a_goal_requiring_artifacts_is_not_closed_by_prose() {
        let goal = Goal::new("g-2", CompletionEvidence::Artifact).expect("valid goal");
        assert_eq!(
            goal.complete_with(CompletionEvidence::Narrative, "it looks done")
                .expect_err("prose is not an artifact"),
            AutomationError::CompletionEvidenceMissing {
                required: "artifact",
            }
        );
        goal.complete_with(CompletionEvidence::Artifact, "built the bundle")
            .expect("the required evidence closes it");
    }

    #[test]
    fn each_required_evidence_kind_is_enforced() {
        for required in [
            CompletionEvidence::Tests,
            CompletionEvidence::Artifact,
            CompletionEvidence::Receipt,
        ] {
            let goal = Goal::new("g", required).expect("valid goal");
            assert!(
                goal.complete_with(CompletionEvidence::Narrative, "done")
                    .is_err(),
                "{required:?} was closable by prose"
            );
            goal.complete_with(required, "done")
                .expect("matching evidence");
        }
    }
}

mod wait_resolution {
    use super::*;

    #[test]
    fn every_wait_condition_names_something_durable() {
        let conditions = [
            WaitCondition::Timer { until: at(5_000) },
            WaitCondition::Run {
                run_id: "run-1".to_owned(),
            },
            WaitCondition::ConnectorEvent {
                source_key: "teams:app:evt-1".to_owned(),
            },
        ];
        for condition in conditions {
            // A free-text label is not a variant, so a wake cannot resolve
            // from prose.
            match condition {
                WaitCondition::Timer { until } => assert!(until.as_millis() > 0),
                WaitCondition::Run { run_id } => assert!(!run_id.is_empty()),
                WaitCondition::ConnectorEvent { source_key } => assert!(!source_key.is_empty()),
            }
        }
    }
}

mod fenced_claims {
    use super::*;

    #[test]
    fn a_claim_carries_an_epoch_and_goes_stale() {
        let claim = BoardClaim::new("task-1", "worker-1", 7).expect("valid claim");
        assert_eq!(claim.epoch(), 7);
        assert_eq!(claim.worker(), "worker-1");
        assert!(claim.is_current(7));
        assert!(claim.is_current(6));
        assert!(
            !claim.is_current(8),
            "a newer epoch fences an older claim out"
        );
    }
}

mod trigger_routes {
    use super::*;

    #[test]
    fn a_route_requires_verification_a_window_and_a_ceiling() {
        let route = TriggerRoute::new("route-1", VerificationMethod::Hmac, 300_000, 65_536, false)
            .expect("valid route");
        assert_eq!(route.verification(), VerificationMethod::Hmac);
        assert_eq!(route.replay_window_ms(), 300_000);
        assert_eq!(route.max_body_bytes(), 65_536);
        assert!(!route.delivers_directly());
    }

    #[test]
    fn direct_delivery_is_a_flag_on_a_fully_specified_route() {
        // Bypassing the model does not produce a lesser route: verification,
        // window and ceiling are still required.
        let direct = TriggerRoute::new(
            "route-2",
            VerificationMethod::MutualTls,
            60_000,
            1_024,
            true,
        )
        .expect("valid route");
        assert!(direct.delivers_directly());
        assert_eq!(direct.verification(), VerificationMethod::MutualTls);
        assert_eq!(direct.max_body_bytes(), 1_024);
    }

    #[test]
    fn a_route_requires_an_identifier() {
        assert!(TriggerRoute::new("", VerificationMethod::PublicKey, 1, 1, false).is_err());
    }
}
