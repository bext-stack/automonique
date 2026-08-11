// SPDX-License-Identifier: Elastic-2.0

//! R1-22 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-22.md`. The rows that require something to be
//! *unrepresentable* are proven by paired doc tests in the library, where a
//! `compile_fail` case executes; the modules here assert the runtime half and
//! name the doc test that carries the compile-time half.

use automonique_protocol::automation::{
    AnyCompletionEvidence, ArtifactEvidence, AuthorizedDestination, AutomationError, AutomationJob,
    AutomationRevision, BoardClaim, BoardClaimParts, CanonicalSchedule, ClaimLabel, ClaimState,
    CompletedEffect, CompletionEvidence, CompletionEvidenceKind, CronExpression, DeliveryMode,
    DstPolicy, DurableId, EventFilter, EventFilters, FailureLedger, FixedInterval, Goal,
    GoalOutcome, GoalVerdict, IdempotencySource, JobKind, JobObligations, NarrativeEvidence,
    OccurrenceKey, OutboxObligation, ReceiptEvidence, RouteTransform, Tenancy, TestEvidence,
    Timezone, TriggerRoute, TriggerRouteParts, UnattendedDecision, VerdictEvidence,
    VerificationMethod, WaitCondition, Wake, WakeContext,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn tenant(name: &str) -> Tenancy {
    Tenancy::new(name).expect("valid tenant")
}

fn durable(id: &str) -> DurableId {
    DurableId::new(id).expect("valid identity")
}

/// UTC instants at which a real zone changes offset.
///
/// The values are synthetic fixtures computed offline; nothing in the crate
/// reads a timezone database, so these exercise the *record* of a transition,
/// not arithmetic across one.
const DST_TRANSITIONS: [(&str, i64); 5] = [
    (
        "america/new_york spring forward 2026-03-08T07:00Z",
        1_772_953_200_000,
    ),
    (
        "america/new_york fall back 2026-11-01T06:00Z",
        1_793_512_800_000,
    ),
    (
        "europe/paris spring forward 2026-03-29T01:00Z",
        1_774_746_000_000,
    ),
    (
        "europe/paris fall back 2026-10-25T01:00Z",
        1_792_890_000_000,
    ),
    (
        "australia/lord_howe forward 2026-10-04T15:30Z",
        1_791_127_800_000,
    ),
];

const DST_ZONES: [&str; 5] = [
    "UTC",
    "America/New_York",
    "Europe/Paris",
    "Australia/Lord_Howe",
    "America/Argentina/Buenos_Aires",
];

const CRON_EXPRESSIONS: [&str; 3] = ["0 0 * * *", "*/5 * * * *", "30 2 * * SUN"];

/// Every canonical schedule the round-trip row is measured over.
fn corpus() -> Vec<CanonicalSchedule> {
    let mut schedules = vec![
        CanonicalSchedule::once(EpochMillis::EPOCH),
        CanonicalSchedule::once(at(-1_000)),
    ];
    for (_, millis) in DST_TRANSITIONS {
        schedules.push(CanonicalSchedule::once(at(millis)));
    }
    for interval in [1, 60_000, 3_600_000, 86_400_000] {
        schedules.push(CanonicalSchedule::every(interval).expect("positive interval"));
    }
    for expression in CRON_EXPRESSIONS {
        for zone in DST_ZONES {
            for policy in DstPolicy::ALL {
                schedules.push(
                    CanonicalSchedule::cron(expression, zone, policy).expect("canonical cron"),
                );
            }
        }
    }
    schedules
}

mod canonical_storage {
    use super::*;

    #[test]
    fn a_recognized_expression_parses_to_one_canonical_schedule() {
        assert_eq!(
            CanonicalSchedule::parse("every hour").expect("recognized"),
            CanonicalSchedule::every(3_600_000).expect("positive interval")
        );
        assert_eq!(
            CanonicalSchedule::parse("Daily").expect("case-insensitive"),
            CanonicalSchedule::cron("0 0 * * *", "UTC", DstPolicy::SkipMissingFireFirst)
                .expect("canonical cron")
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
    fn storage_reads_canonical_renderings_only_so_prose_has_no_way_in() {
        for prose in [
            "every hour",
            "daily",
            "sometime tomorrow",
            "when the build is green",
        ] {
            assert_eq!(
                CanonicalSchedule::from_rendering(prose)
                    .expect_err("prose is not canonical")
                    .category(),
                "not_canonical",
                "{prose} was storable"
            );
        }
    }

    #[test]
    fn the_canonical_form_is_exactly_three_shapes_and_none_of_them_is_prose() {
        // An exhaustive match with no wildcard arm: a prose variant added to
        // `CanonicalSchedule` would stop this test compiling.
        for schedule in corpus() {
            let rendered = schedule.render();
            match &schedule {
                CanonicalSchedule::Once { at } => {
                    assert_eq!(rendered, format!("once@{}", at.as_millis()));
                }
                CanonicalSchedule::Every { interval } => {
                    assert!(interval.as_millis() > 0);
                    assert_eq!(rendered, format!("every@{}", interval.as_millis()));
                }
                CanonicalSchedule::Cron {
                    expression,
                    timezone,
                    dst_policy,
                } => {
                    assert_eq!(expression.as_str().split(' ').count(), 5);
                    assert_eq!(
                        rendered,
                        format!(
                            "cron@{}@{}@{}",
                            expression.as_str(),
                            timezone.as_str(),
                            dst_policy.as_str()
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn a_component_that_is_not_canonical_is_refused_at_construction() {
        assert_eq!(
            CronExpression::new("when the build is green")
                .expect_err("not five fields")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            CronExpression::new("0 0 * *")
                .expect_err("four fields")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            CronExpression::new("0 0 * * * *")
                .expect_err("six fields")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            Timezone::new("Europe/Paris/Left Bank")
                .expect_err("not an IANA name")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            FixedInterval::new(0)
                .expect_err("an interval that never advances")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            FixedInterval::new(-1).expect_err("negative").category(),
            "not_canonical"
        );
    }
}

mod round_trip {
    use super::*;

    #[test]
    fn the_corpus_covers_every_dst_transition_and_both_policies() {
        // Guards the two property tests below: shrinking the corpus to make
        // them pass would fail here.
        let schedules = corpus();
        for (label, millis) in DST_TRANSITIONS {
            assert!(
                schedules.contains(&CanonicalSchedule::once(at(millis))),
                "{label} is missing from the corpus"
            );
        }
        for zone in DST_ZONES {
            for policy in DstPolicy::ALL {
                assert!(
                    schedules.contains(
                        &CanonicalSchedule::cron("0 0 * * *", zone, policy)
                            .expect("canonical cron")
                    ),
                    "{zone} under {} is missing from the corpus",
                    policy.as_str()
                );
            }
        }
        assert_eq!(schedules.len(), 2 + DST_TRANSITIONS.len() + 4 + 3 * 5 * 2);
    }

    #[test]
    fn parsing_a_canonical_rendering_yields_an_identical_schedule() {
        for schedule in corpus() {
            let rendered = schedule.render();
            assert_eq!(
                CanonicalSchedule::from_rendering(&rendered).expect("its own rendering"),
                schedule,
                "{rendered} did not read back"
            );
            assert_eq!(
                CanonicalSchedule::parse(&rendered).expect("its own rendering"),
                schedule,
                "{rendered} did not parse back"
            );
            // And the rendering is a fixed point: reading and re-rendering
            // produces the same bytes.
            assert_eq!(
                CanonicalSchedule::from_rendering(&rendered)
                    .expect("its own rendering")
                    .render(),
                rendered
            );
        }
    }

    #[test]
    fn equal_schedules_render_identically_and_unequal_ones_do_not() {
        let schedules = corpus();
        for left in &schedules {
            for right in &schedules {
                assert_eq!(
                    left == right,
                    left.render() == right.render(),
                    "{} and {} disagree about equality",
                    left.render(),
                    right.render()
                );
            }
        }
    }

    #[test]
    fn the_dst_policy_is_part_of_the_canonical_form() {
        let skip = CanonicalSchedule::cron(
            "0 2 * * *",
            "America/New_York",
            DstPolicy::SkipMissingFireFirst,
        )
        .expect("canonical cron");
        let shift = CanonicalSchedule::cron(
            "0 2 * * *",
            "America/New_York",
            DstPolicy::ShiftMissingFireSecond,
        )
        .expect("canonical cron");
        assert_ne!(skip, shift);
        assert_ne!(
            skip.render(),
            shift.render(),
            "two schedules that resolve a DST transition differently must not \
             render the same, or a review would not show which one runs"
        );
        assert_eq!(
            CanonicalSchedule::from_rendering(&shift.render()).expect("round trip"),
            shift
        );
    }

    #[test]
    fn a_rendering_that_is_not_canonical_is_refused_rather_than_normalized() {
        for rendered in [
            "once@007",
            "once@+5",
            "once@ 5",
            "once@",
            "every@0",
            "every@-60000",
            "cron@0 0 * * *@UTC",
            "cron@0 0 * * *@UTC@sometimes",
            "cron@0 0 * * *@UTC@skip_missing_fire_first@extra",
            "weekly@1",
        ] {
            assert_eq!(
                CanonicalSchedule::from_rendering(rendered)
                    .expect_err("not canonical")
                    .category(),
                "not_canonical",
                "{rendered} was accepted"
            );
        }
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
    fn no_two_distinct_firings_share_a_key() {
        // The collision property over a cross product, including identifiers
        // that contain the separator: the key is unambiguous because the
        // instant is a decimal integer and cannot contain one.
        let automations = ["auto-1", "auto-2", "auto-1@1", "a", "a@b@c"];
        let instants = [-1_000, 0, 1, 1_000, 1_772_953_200_000];
        let mut keys = Vec::new();
        for automation in automations {
            for millis in instants {
                keys.push((
                    automation,
                    millis,
                    OccurrenceKey::derive(automation, at(millis)).expect("derived"),
                ));
            }
        }
        for (left_id, left_at, left_key) in &keys {
            for (right_id, right_at, right_key) in &keys {
                assert_eq!(
                    (left_id, left_at) == (right_id, right_at),
                    left_key == right_key,
                    "{left_id}@{left_at} and {right_id}@{right_at} collide"
                );
            }
        }
    }

    #[test]
    fn a_key_takes_no_other_input() {
        // Only the automation and the canonical instant, so a replayed tick
        // after failover derives the same key rather than a fresh one.
        let key = OccurrenceKey::derive("auto-1", at(1_000)).expect("derived");
        assert!(key.as_str().starts_with("auto-1@"));
        assert_eq!(
            key,
            OccurrenceKey::derive("auto-1", at(1_000)).expect("derived")
        );
    }
}

mod revision_immutability {
    use super::*;

    fn automation() -> AutomationRevision {
        AutomationRevision::new(
            "auto-1",
            revision(3),
            CanonicalSchedule::every(60_000).expect("positive interval"),
            &["notify:slack"],
        )
        .expect("valid automation")
    }

    #[test]
    fn an_edit_requires_the_expected_revision() {
        let current = automation();
        let edited = current
            .edited(revision(3), CanonicalSchedule::once(at(1)))
            .expect("matching expectation");
        assert_eq!(edited.revision().get(), 4);
        // The original is untouched.
        assert_eq!(current.revision().get(), 3);
        assert_eq!(
            current.schedule(),
            &CanonicalSchedule::every(60_000).expect("positive interval")
        );
    }

    #[test]
    fn a_stale_edit_conflicts_rather_than_overwriting() {
        assert_eq!(
            automation()
                .edited(revision(2), CanonicalSchedule::once(at(1)))
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
            CanonicalSchedule::once(at(1)),
            &["notify:slack"],
        )
        .expect("valid automation")
    }

    #[test]
    fn a_pre_approved_effect_yields_the_token_a_completion_needs() {
        let automation = automation();
        let UnattendedDecision::PreApproved(approved) =
            automation.decide_unattended("notify:slack")
        else {
            panic!("a declared effect is pre-approved");
        };
        assert_eq!(approved.effect(), "notify:slack");
        assert_eq!(approved.automation_id(), "auto-1");
        let done = CompletedEffect::record(approved, "outbox:receipt-1").expect("valid receipt");
        assert_eq!(done.effect(), "notify:slack");
        assert_eq!(done.receipt(), "outbox:receipt-1");
        automation
            .permit_unattended("notify:slack")
            .expect("in scope");
    }

    #[test]
    fn an_effect_outside_scope_is_representable_only_as_an_approval_request() {
        // An exhaustive match with no wildcard: a third outcome added to
        // `UnattendedDecision` — a completed one, say — would stop this test
        // compiling. The compile-fail proof that an approval request cannot be
        // spent as an `ApprovedEffect` is a paired doc test in the library.
        match automation().decide_unattended("deploy:production") {
            UnattendedDecision::PreApproved(approved) => {
                panic!("undeclared effect was approved: {}", approved.effect())
            }
            UnattendedDecision::RequiresApproval(request) => {
                assert_eq!(request.effect(), "deploy:production");
                assert_eq!(request.automation_id(), "auto-1");
                assert_eq!(
                    request.refusal(),
                    AutomationError::OutsideApprovedScope {
                        effect: "deploy:production".to_owned(),
                    }
                );
            }
        }
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
    fn an_approval_becomes_authority_only_through_a_new_revision() {
        let current = automation();
        let UnattendedDecision::RequiresApproval(request) =
            current.decide_unattended("deploy:production")
        else {
            panic!("undeclared effect");
        };
        let approved_revision = current
            .approving(revision(1), &request)
            .expect("matching expectation");
        assert_eq!(approved_revision.revision().get(), 2);
        approved_revision
            .permit_unattended("deploy:production")
            .expect("declared by the new revision");
        // The revision that refused is unchanged and still refuses.
        assert_eq!(current.revision().get(), 1);
        assert_eq!(current.approved_effects(), ["notify:slack"]);
        assert!(current.permit_unattended("deploy:production").is_err());
    }

    #[test]
    fn an_approval_raised_by_another_automation_is_refused() {
        let other =
            AutomationRevision::new("auto-2", revision(1), CanonicalSchedule::once(at(1)), &[])
                .expect("valid automation");
        let UnattendedDecision::RequiresApproval(request) =
            other.decide_unattended("deploy:production")
        else {
            panic!("undeclared effect");
        };
        assert_eq!(
            automation()
                .approving(revision(1), &request)
                .expect_err("foreign approval"),
            AutomationError::ApprovalMismatch {
                automation_id: "auto-2".to_owned(),
            }
        );
    }

    #[test]
    fn a_stale_approval_conflicts_rather_than_overwriting() {
        let current = automation();
        let UnattendedDecision::RequiresApproval(request) =
            current.decide_unattended("deploy:production")
        else {
            panic!("undeclared effect");
        };
        assert_eq!(
            current
                .approving(revision(9), &request)
                .expect_err("stale expectation"),
            AutomationError::RevisionConflict {
                expected: 1,
                offered: 9,
            }
        );
    }

    #[test]
    fn an_automation_with_no_approved_effects_permits_nothing() {
        let bare =
            AutomationRevision::new("auto-2", revision(1), CanonicalSchedule::once(at(1)), &[])
                .expect("valid automation");
        for effect in ["notify:slack", "deploy:production", ""] {
            assert!(
                matches!(
                    bare.decide_unattended(effect),
                    UnattendedDecision::RequiresApproval(_)
                ),
                "{effect} was pre-approved by an automation that declared nothing"
            );
        }
    }
}

mod job_parity {
    use super::*;

    fn obligations() -> JobObligations {
        JobObligations::new(
            "auto-1",
            tenant("acme"),
            "workspace-offline",
            OutboxObligation::new(
                AuthorizedDestination::new("slack:C1", "grant:slack-post").expect("authorized"),
                "outbox:auto-1",
            )
            .expect("valid obligation"),
        )
        .expect("valid obligations")
    }

    #[test]
    fn both_kinds_carry_the_same_obligations_through_the_same_type() {
        let script = AutomationJob::declare(JobKind::Script, obligations());
        let agent = AutomationJob::declare(JobKind::Agent, obligations());
        assert_eq!(
            script.obligations(),
            agent.obligations(),
            "the job that skips the model owes less than the one that does not"
        );
        assert_ne!(script.kind(), agent.kind());
        assert_eq!(script.kind(), JobKind::Script);
        assert_eq!(agent.kind(), JobKind::Agent);
    }

    #[test]
    fn identity_sandbox_and_outbox_are_present_for_every_kind() {
        // An exhaustive iteration over the closed kind set: a third kind would
        // have to satisfy the same assertions.
        assert_eq!(JobKind::ALL.len(), 2);
        for kind in JobKind::ALL {
            let job = AutomationJob::declare(kind, obligations());
            let owed = job.obligations();
            assert_eq!(owed.automation_id(), "auto-1", "{} identity", kind.as_str());
            assert_eq!(owed.tenant(), &tenant("acme"), "{} tenant", kind.as_str());
            assert_eq!(
                owed.sandbox_profile(),
                "workspace-offline",
                "{} sandbox",
                kind.as_str()
            );
            assert_eq!(
                owed.outbox().destination().target(),
                "slack:C1",
                "{} destination",
                kind.as_str()
            );
            assert_eq!(
                owed.outbox().destination().authorization(),
                "grant:slack-post",
                "{} destination authorization",
                kind.as_str()
            );
            assert_eq!(
                owed.outbox().receipt_log(),
                "outbox:auto-1",
                "{} receipts",
                kind.as_str()
            );
        }
    }

    #[test]
    fn an_incomplete_obligation_is_refused_before_any_job_exists() {
        // The refusal is on the shared type, so it cannot be weaker for one
        // kind: there is no per-kind constructor to weaken.
        assert_eq!(
            JobObligations::new(
                "auto-1",
                tenant("acme"),
                "",
                OutboxObligation::new(
                    AuthorizedDestination::new("slack:C1", "grant:slack-post").expect("authorized"),
                    "outbox:auto-1",
                )
                .expect("valid obligation"),
            )
            .expect_err("no sandbox profile")
            .category(),
            "field_invalid"
        );
        assert_eq!(
            AuthorizedDestination::new("slack:C1", "")
                .expect_err("no authorization")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            OutboxObligation::new(
                AuthorizedDestination::new("slack:C1", "grant:slack-post").expect("authorized"),
                "",
            )
            .expect_err("nowhere to record receipts")
            .category(),
            "field_invalid"
        );
    }

    #[test]
    fn the_kind_spellings_are_distinct() {
        let mut spellings: Vec<&str> = JobKind::ALL.iter().map(|kind| kind.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod verdict_closure {
    use super::*;

    fn one_verdict_per_outcome() -> Vec<GoalVerdict> {
        let goal: Goal<ArtifactEvidence> = Goal::declare("g-1").expect("valid goal");
        vec![
            GoalVerdict::Continue {
                evidence: VerdictEvidence::new("two of five criteria met").expect("evidence"),
            },
            goal.complete_with(
                ArtifactEvidence::new("sha256:bundle", "built the bundle").expect("artifact"),
            ),
            GoalVerdict::Wait {
                condition: WaitCondition::Run {
                    run_id: durable("run-1"),
                },
                evidence: VerdictEvidence::new("blocked on run-1").expect("evidence"),
            },
            GoalVerdict::Blocked {
                evidence: VerdictEvidence::new("the connector is revoked").expect("evidence"),
            },
            GoalVerdict::BudgetExhausted {
                evidence: VerdictEvidence::new("budget of 60000 milliseconds spent")
                    .expect("evidence"),
            },
        ]
    }

    #[test]
    fn the_outcome_set_is_closed_and_exhaustively_covered() {
        assert_eq!(GoalOutcome::ALL.len(), 5);
        let verdicts = one_verdict_per_outcome();
        assert_eq!(verdicts.len(), GoalOutcome::ALL.len());
        // An exhaustive match with no wildcard arm: a sixth verdict variant
        // would stop this test compiling, which is what "closed" means here.
        let covered: Vec<GoalOutcome> = verdicts
            .iter()
            .map(|verdict| match verdict {
                GoalVerdict::Continue { .. } => GoalOutcome::Continue,
                GoalVerdict::Complete { .. } => GoalOutcome::Complete,
                GoalVerdict::Wait { .. } => GoalOutcome::Wait,
                GoalVerdict::Blocked { .. } => GoalOutcome::Blocked,
                GoalVerdict::BudgetExhausted { .. } => GoalOutcome::BudgetExhausted,
            })
            .collect();
        assert_eq!(covered, GoalOutcome::ALL.to_vec());
        for (verdict, outcome) in verdicts.iter().zip(GoalOutcome::ALL) {
            assert_eq!(verdict.outcome(), outcome);
        }
    }

    #[test]
    fn every_verdict_carries_evidence() {
        for verdict in one_verdict_per_outcome() {
            assert!(
                !verdict.evidence().as_str().is_empty(),
                "{} carried no evidence",
                verdict.outcome().as_str()
            );
        }
    }

    #[test]
    fn a_verdict_without_evidence_is_unrepresentable() {
        // Every variant's evidence is a `VerdictEvidence`, and that type
        // refuses emptiness, so there is no empty-evidence verdict to build.
        assert_eq!(
            VerdictEvidence::new("").expect_err("empty").category(),
            "field_invalid"
        );
        assert_eq!(
            VerdictEvidence::new("done\u{0}")
                .expect_err("control")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn the_outcome_spellings_are_distinct() {
        let mut spellings: Vec<&str> = GoalOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod evidence_bound_completion {
    use super::*;

    /// Prose supplied at runtime to a goal that demanded something durable.
    fn prose() -> AnyCompletionEvidence {
        AnyCompletionEvidence::Narrative(
            NarrativeEvidence::new("it looks done").expect("valid prose"),
        )
    }

    fn refuses_prose<E: CompletionEvidence>(goal: &Goal<E>, required: &'static str) {
        assert_eq!(
            goal.complete_from(prose())
                .expect_err("prose is not the required evidence"),
            AutomationError::CompletionEvidenceMissing { required },
            "{required} was closable by prose"
        );
    }

    #[test]
    fn a_narrative_goal_completes_on_prose() {
        let goal: Goal<NarrativeEvidence> = Goal::declare("g-1").expect("valid goal");
        assert_eq!(goal.required_evidence(), CompletionEvidenceKind::Narrative);
        let verdict =
            goal.complete_with(NarrativeEvidence::new("explained the failure").expect("prose"));
        let GoalVerdict::Complete { record } = verdict else {
            panic!("a completed goal");
        };
        assert_eq!(record.kind(), CompletionEvidenceKind::Narrative);
        assert_eq!(record.reference(), None);
        assert_eq!(record.statement().as_str(), "explained the failure");
    }

    #[test]
    fn a_goal_requiring_artifacts_is_not_closed_by_prose() {
        // The compile-time half — `complete_with` refusing prose for a
        // `Goal<ArtifactEvidence>` — is a paired doc test in the library. This
        // is the runtime half, for evidence whose kind is only known when it is
        // read back.
        let goal: Goal<ArtifactEvidence> = Goal::declare("g-2").expect("valid goal");
        refuses_prose(&goal, "artifact");
        let verdict = goal
            .complete_from(AnyCompletionEvidence::Artifact(
                ArtifactEvidence::new("sha256:bundle", "built the bundle").expect("artifact"),
            ))
            .expect("the required evidence closes it");
        let GoalVerdict::Complete { record } = verdict else {
            panic!("a completed goal");
        };
        assert_eq!(record.kind(), CompletionEvidenceKind::Artifact);
        assert_eq!(record.reference(), Some("sha256:bundle"));
    }

    #[test]
    fn each_required_evidence_kind_is_enforced() {
        let tests: Goal<TestEvidence> = Goal::declare("g-tests").expect("valid goal");
        refuses_prose(&tests, "tests");
        tests
            .complete_from(AnyCompletionEvidence::Tests(
                TestEvidence::new("run-1", "417 tests passed").expect("tests"),
            ))
            .expect("matching evidence");

        let artifact: Goal<ArtifactEvidence> = Goal::declare("g-artifact").expect("valid goal");
        refuses_prose(&artifact, "artifact");
        artifact
            .complete_from(AnyCompletionEvidence::Artifact(
                ArtifactEvidence::new("sha256:bundle", "built the bundle").expect("artifact"),
            ))
            .expect("matching evidence");

        let receipt: Goal<ReceiptEvidence> = Goal::declare("g-receipt").expect("valid goal");
        refuses_prose(&receipt, "receipt");
        receipt
            .complete_from(AnyCompletionEvidence::Receipt(
                ReceiptEvidence::new("receipt-1", "posted to slack:C1").expect("receipt"),
            ))
            .expect("matching evidence");
    }

    #[test]
    fn a_completion_record_names_the_kind_that_closed_the_goal() {
        for kind in CompletionEvidenceKind::ALL {
            assert!(!kind.as_str().is_empty());
        }
        let goal: Goal<ReceiptEvidence> = Goal::declare("g-3").expect("valid goal");
        let verdict =
            goal.complete_with(ReceiptEvidence::new("receipt-9", "posted").expect("receipt"));
        assert_eq!(verdict.outcome(), GoalOutcome::Complete);
        assert_eq!(verdict.evidence().as_str(), "posted");
    }

    #[test]
    fn evidence_that_names_nothing_durable_is_refused() {
        assert_eq!(
            ArtifactEvidence::new("the bundle I built", "done")
                .expect_err("prose is not a digest")
                .category(),
            "not_canonical"
        );
        assert_eq!(
            TestEvidence::new("run-1", "")
                .expect_err("no statement")
                .category(),
            "field_invalid"
        );
    }
}

mod wait_resolution {
    use super::*;

    #[test]
    fn every_wait_condition_names_something_durable() {
        let conditions = [
            WaitCondition::Timer { until: at(5_000) },
            WaitCondition::Run {
                run_id: durable("run-1"),
            },
            WaitCondition::ConnectorEvent {
                source_key: durable("teams:app:evt-1"),
            },
            WaitCondition::MonitoredPattern {
                monitor_id: durable("monitor-7"),
            },
        ];
        // An exhaustive match with no wildcard arm: a free-text variant added
        // to `WaitCondition` would stop this test compiling.
        for condition in conditions {
            match condition {
                WaitCondition::Timer { until } => assert!(until.as_millis() > 0),
                WaitCondition::Run { run_id } => assert!(!run_id.as_str().is_empty()),
                WaitCondition::ConnectorEvent { source_key } => {
                    assert!(!source_key.as_str().is_empty());
                }
                WaitCondition::MonitoredPattern { monitor_id } => {
                    assert!(!monitor_id.as_str().is_empty());
                }
            }
        }
    }

    #[test]
    fn a_free_text_label_cannot_occupy_an_identity_position() {
        for label in [
            "when the build is green",
            "the goal about the release",
            "run 1",
        ] {
            assert_eq!(
                DurableId::new(label)
                    .expect_err("prose is not an identity")
                    .category(),
                "not_canonical",
                "{label} was accepted as an identity"
            );
        }
        assert_eq!(
            DurableId::new("").expect_err("empty").category(),
            "field_invalid"
        );
    }

    #[test]
    fn a_wake_resolves_an_exact_context() {
        let condition = WaitCondition::Timer { until: at(5_000) };
        for context in [
            WakeContext::Goal(durable("g-1")),
            WakeContext::Job(durable("job-1")),
            WakeContext::Session(durable("session-1")),
        ] {
            let expected = context.id().to_owned();
            let wake = Wake::resolve(context, condition.clone());
            assert_eq!(wake.context_id(), expected);
            assert_eq!(wake.condition(), &condition);
        }
    }
}

mod trigger_routes {
    use super::*;

    fn outbox() -> OutboxObligation {
        OutboxObligation::new(
            AuthorizedDestination::new("https://example.test/hook", "grant:route-post")
                .expect("authorized"),
            "outbox:route-1",
        )
        .expect("valid obligation")
    }

    fn parts<'a>(id: &'a str, delivery: DeliveryMode) -> TriggerRouteParts<'a> {
        TriggerRouteParts {
            id,
            path: "/hooks/acme/build",
            tenant: tenant("acme"),
            service_actor: "svc:trigger-router",
            allowed_event_types: &["build.completed", "build.failed"],
            verification: VerificationMethod::Hmac,
            replay_window_ms: 300_000,
            max_body_bytes: 65_536,
            max_header_bytes: 8_192,
            filters: EventFilters::requiring_all(vec![
                EventFilter::requiring("repository", "acme/app").expect("valid filter"),
            ]),
            transform: RouteTransform::Sandboxed {
                profile: durable("workspace-offline"),
            },
            outbox: outbox(),
            idempotency: IdempotencySource::Header {
                name: durable("X-Delivery-Id"),
            },
            delivery,
        }
    }

    #[test]
    fn a_route_declares_every_required_element() {
        let route =
            TriggerRoute::declare(parts("route-1", DeliveryMode::ThroughModel)).expect("valid");
        assert_eq!(route.id(), "route-1");
        assert_eq!(route.path(), "/hooks/acme/build");
        assert_eq!(route.tenant(), &tenant("acme"));
        assert_eq!(route.service_actor(), "svc:trigger-router");
        assert_eq!(
            route.allowed_event_types(),
            ["build.completed", "build.failed"]
        );
        assert_eq!(route.verification(), VerificationMethod::Hmac);
        assert_eq!(route.replay_window_ms(), 300_000);
        assert_eq!(route.max_body_bytes(), 65_536);
        assert_eq!(route.max_header_bytes(), 8_192);
        assert_eq!(route.filters().as_slice().len(), 1);
        assert_eq!(route.filters().as_slice()[0].field(), "repository");
        assert_eq!(
            route.transform(),
            &RouteTransform::Sandboxed {
                profile: durable("workspace-offline"),
            }
        );
        assert_eq!(
            route.idempotency(),
            &IdempotencySource::Header {
                name: durable("X-Delivery-Id"),
            }
        );
        assert_eq!(
            route.outbox().destination().target(),
            "https://example.test/hook"
        );
        assert_eq!(
            route.outbox().destination().authorization(),
            "grant:route-post"
        );
        assert_eq!(route.outbox().receipt_log(), "outbox:route-1");
        // Every element above is a field of `TriggerRouteParts`; a literal that
        // omits one does not compile. The paired doc test that proves it lives
        // in the library.
    }

    #[test]
    fn direct_delivery_carries_the_same_destination_authorization_and_receipts() {
        assert_eq!(DeliveryMode::ALL.len(), 2);
        let through =
            TriggerRoute::declare(parts("route-1", DeliveryMode::ThroughModel)).expect("valid");
        let direct = TriggerRoute::declare(parts("route-1", DeliveryMode::Direct)).expect("valid");
        assert!(direct.delivers_directly());
        assert!(!through.delivers_directly());
        assert_eq!(
            direct.outbox(),
            through.outbox(),
            "bypassing the model must not bypass destination authorization or receipts"
        );
        assert_eq!(direct.verification(), through.verification());
        assert_eq!(direct.max_body_bytes(), through.max_body_bytes());
        assert_eq!(direct.max_header_bytes(), through.max_header_bytes());
        assert_eq!(direct.replay_window_ms(), through.replay_window_ms());
        assert_eq!(direct.filters(), through.filters());
    }

    #[test]
    fn a_route_missing_a_required_value_is_refused() {
        let cases: [(&str, TriggerRouteParts<'_>); 7] = [
            (
                "field_invalid",
                TriggerRouteParts {
                    id: "",
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "field_invalid",
                TriggerRouteParts {
                    service_actor: "",
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "not_canonical",
                TriggerRouteParts {
                    path: "hooks/acme/build",
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "not_canonical",
                TriggerRouteParts {
                    allowed_event_types: &[],
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "not_canonical",
                TriggerRouteParts {
                    replay_window_ms: 0,
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "not_canonical",
                TriggerRouteParts {
                    max_body_bytes: 0,
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
            (
                "not_canonical",
                TriggerRouteParts {
                    max_header_bytes: 0,
                    ..parts("route-1", DeliveryMode::Direct)
                },
            ),
        ];
        for (category, case) in cases {
            assert_eq!(
                TriggerRoute::declare(case)
                    .expect_err("incomplete route")
                    .category(),
                category
            );
        }
    }

    #[test]
    fn accepting_every_allowed_type_is_a_declared_decision() {
        let route = TriggerRoute::declare(TriggerRouteParts {
            filters: EventFilters::accept_all_allowed_types(),
            ..parts("route-2", DeliveryMode::Direct)
        })
        .expect("valid");
        assert!(route.filters().as_slice().is_empty());
        // The route still names the types it accepts, so "no filter" is not
        // "any event".
        assert_eq!(route.allowed_event_types().len(), 2);
    }
}

mod fenced_claims {
    use super::*;

    fn claim_parts<'a>(
        tenant_name: &str,
        epoch: u64,
        labels: Vec<ClaimLabel>,
    ) -> BoardClaimParts<'a> {
        BoardClaimParts {
            task: "task-1",
            worker: "worker-1",
            tenant: tenant(tenant_name),
            epoch,
            labels,
            failures: FailureLedger::declare(3).expect("positive threshold"),
        }
    }

    #[test]
    fn a_claim_carries_an_epoch_and_goes_stale() {
        let claim = BoardClaim::claim(claim_parts("acme", 7, Vec::new())).expect("valid claim");
        assert_eq!(claim.epoch(), 7);
        assert_eq!(claim.task(), "task-1");
        assert_eq!(claim.worker(), "worker-1");
        assert!(claim.is_current(7));
        assert!(claim.is_current(6));
        assert!(
            !claim.is_current(8),
            "a newer epoch fences an older claim out"
        );
        assert!(!claim.authorizes(&tenant("acme"), 8));
    }

    #[test]
    fn a_label_cannot_serve_as_a_tenancy_control() {
        let mislabelled = BoardClaim::claim(claim_parts(
            "acme",
            7,
            vec![
                ClaimLabel::new("tenant:globex").expect("valid label"),
                ClaimLabel::new("globex").expect("valid label"),
            ],
        ))
        .expect("valid claim");
        assert!(mislabelled.authorizes(&tenant("acme"), 7));
        assert!(
            !mislabelled.authorizes(&tenant("globex"), 7),
            "a label naming a tenant granted that tenant authority"
        );
        // The labels are still readable; they simply carry nothing.
        assert_eq!(mislabelled.labels().len(), 2);
        assert_eq!(mislabelled.tenant(), &tenant("acme"));
        // The compile-fail proof that a `ClaimLabel` cannot be passed where a
        // `Tenancy` is required is a paired doc test in the library.
    }

    #[test]
    fn a_declared_threshold_blocks_rather_than_retrying_unboundedly() {
        let mut claim = BoardClaim::claim(claim_parts("acme", 7, Vec::new())).expect("valid claim");
        assert_eq!(claim.state(), ClaimState::Retry { remaining: 3 });
        let mut blocked_from = None;
        for failure in 1..=10_u32 {
            claim = claim.after_failure();
            // An exhaustive match with no wildcard arm: a "retry forever"
            // variant added to `ClaimState` would stop this test compiling.
            match claim.state() {
                ClaimState::Retry { remaining } => {
                    assert!(failure < 3, "failure {failure} still retried");
                    assert_eq!(remaining, 3 - failure);
                    assert!(blocked_from.is_none(), "a blocked claim went back to retry");
                }
                ClaimState::Blocked { failures } => {
                    assert_eq!(failures, failure);
                    blocked_from.get_or_insert(failure);
                }
            }
        }
        assert_eq!(
            blocked_from,
            Some(3),
            "the claim did not block at its declared threshold"
        );
    }

    #[test]
    fn a_threshold_that_permits_no_attempt_is_refused() {
        assert_eq!(
            FailureLedger::declare(0)
                .expect_err("no attempt at all")
                .category(),
            "not_canonical"
        );
        let ledger = FailureLedger::declare(1).expect("positive threshold");
        assert_eq!(ledger.threshold(), 1);
        assert_eq!(ledger.failures(), 0);
        assert_eq!(ledger.state(), ClaimState::Retry { remaining: 1 });
        assert_eq!(
            ledger.after_failure().state(),
            ClaimState::Blocked { failures: 1 }
        );
    }
}
