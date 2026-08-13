// SPDX-License-Identifier: Elastic-2.0

//! R1-22 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-22.md`. The rows that require something to be
//! *unrepresentable* are proven by paired doc tests in the library, where a
//! `compile_fail` case executes; the modules here assert the runtime half and
//! name the doc test that carries the compile-time half.

use automonique_protocol::automation::{
    ActionBinding, ActionKind, AnyCompletionEvidence, ArtifactEvidence, AuthorizedDestination,
    AutomationAction, AutomationActor, AutomationEnablement, AutomationError, AutomationJob,
    AutomationRevision, BoardClaim, BoardClaimParts, BoundedPattern, CanonicalSchedule, ClaimLabel,
    ClaimState, CompletedEffect, CompletionEvidence, CompletionEvidenceKind, CronExpression,
    DeliveryMode, DstPolicy, DurableId, EnablementState, EventFilter, EventFilters, FailureLedger,
    FilterExpression, FilterField, FilterPredicate, FixedInterval, Goal, GoalOutcome, GoalVerdict,
    IdempotencySource, JobKind, JobObligations, MAX_FILTER_DEPTH, MAX_FILTER_FIELD_SEGMENTS,
    MAX_FILTER_NODES, MAX_FILTER_RENDERING_BYTES, MAX_MEMBERSHIP_VALUES, MAX_PATTERN_EXPANSION,
    NarrativeEvidence, OccurrenceKey, OutboxObligation, OverlapKind, OverlapPolicy, PauseCause,
    PredicateKind, ReceiptEvidence, RouteTransform, Tenancy, TestEvidence, Timezone, TriggerKind,
    TriggerRoute, TriggerRouteParts, TriggerSpec, UnattendedDecision, VerdictEvidence,
    VerificationMethod, WaitCondition, Wake, WakeContext, WatchedSource,
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
        // The edit applies: the successor carries the schedule the caller
        // asked for, so `edited` cannot pass by returning the receiver at a
        // higher revision.
        assert_eq!(edited.schedule(), &CanonicalSchedule::once(at(1)));
        // Everything the edit did not name is carried over rather than reset.
        assert_eq!(edited.id(), "auto-1");
        assert_eq!(edited.approved_effects(), ["notify:slack"]);
        // The original is untouched.
        assert_eq!(current.revision().get(), 3);
        assert_eq!(
            current.schedule(),
            &CanonicalSchedule::every(60_000).expect("positive interval")
        );
    }

    #[test]
    fn each_edit_applies_its_own_schedule() {
        // One schedule per canonical shape, so an `edited` that applied a
        // constant, or applied only some shapes, fails here.
        let cron = CanonicalSchedule::parse("daily").expect("recognized expression");
        for schedule in [
            CanonicalSchedule::once(at(1)),
            CanonicalSchedule::once(at(-1_000)),
            CanonicalSchedule::every(1).expect("positive interval"),
            CanonicalSchedule::every(86_400_000).expect("positive interval"),
            cron,
        ] {
            let current = automation();
            let edited = current
                .edited(revision(3), schedule.clone())
                .expect("matching expectation");
            assert_eq!(
                edited.schedule(),
                &schedule,
                "the edit did not apply {}",
                schedule.render()
            );
            assert_eq!(edited.revision().get(), 4);
        }
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

    /// Effects that are near misses of the declared `notify:slack`.
    ///
    /// Each rules out a comparison that is not equality: the declared effect
    /// carrying a suffix or a prefix rules out `contains`, `starts_with` and
    /// `ends_with`; a truncated or partial spelling rules out the same three
    /// applied the other way round; surrounding whitespace rules out a trimming
    /// comparison; and a different case rules out an ASCII-insensitive one.
    const NEAR_MISSES: [&str; 10] = [
        "notify:slack && rm -rf /",
        "notify:slack:production",
        "sudo notify:slack",
        "notify:slack ",
        " notify:slack",
        "notify:slack\n",
        "notify:slac",
        "notify:",
        "slack",
        "NOTIFY:SLACK",
    ];

    #[test]
    fn scope_membership_is_exact_rather_than_prefix_or_substring() {
        let automation = automation();
        assert_eq!(automation.approved_effects(), ["notify:slack"]);
        for effect in NEAR_MISSES {
            assert!(
                matches!(
                    automation.decide_unattended(effect),
                    UnattendedDecision::RequiresApproval(_)
                ),
                "{effect:?} was pre-approved by an automation that declared only notify:slack"
            );
            assert_eq!(
                automation
                    .permit_unattended(effect)
                    .expect_err("a near miss is not the declared effect"),
                AutomationError::OutsideApprovedScope {
                    effect: effect.to_owned(),
                },
                "{effect:?} was permitted by an automation that declared only notify:slack"
            );
        }
        // The exact spelling is still inside scope, so the assertions above
        // cannot be satisfied by refusing everything.
        automation
            .permit_unattended("notify:slack")
            .expect("the declared effect is exactly in scope");
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
        let GoalVerdict::Complete { record } = verdict else {
            panic!("a completed goal");
        };
        assert_eq!(record.goal_id(), "g-3");
        assert_eq!(record.kind(), CompletionEvidenceKind::Receipt);
        assert_eq!(record.reference(), Some("receipt-9"));
    }

    #[test]
    fn a_completion_record_names_the_goal_it_closed_by_either_route() {
        let statically: Goal<ArtifactEvidence> = Goal::declare("g-static").expect("valid goal");
        let GoalVerdict::Complete { record } = statically.complete_with(
            ArtifactEvidence::new("sha256:bundle", "built the bundle").expect("artifact"),
        ) else {
            panic!("a completed goal");
        };
        assert_eq!(record.goal_id(), "g-static");

        let dynamically: Goal<ArtifactEvidence> = Goal::declare("g-dynamic").expect("valid goal");
        let GoalVerdict::Complete { record } = dynamically
            .complete_from(AnyCompletionEvidence::Artifact(
                ArtifactEvidence::new("sha256:bundle", "built the bundle").expect("artifact"),
            ))
            .expect("the required evidence closes it")
        else {
            panic!("a completed goal");
        };
        assert_eq!(record.goal_id(), "g-dynamic");
    }

    /// The boundary of the type-level binding, asserted as it actually is.
    ///
    /// The binding between a goal's identity and its completion contract is
    /// carried by the `Goal` value's type parameter; nothing in this slice
    /// registers it. So a second goal declared with the same identity and a
    /// prose contract *is* constructible and *does* close on prose — this test
    /// says so rather than letting the module claim otherwise. What the record
    /// gives a consumer is the means to detect it: the verdict names the goal
    /// it closed and the kind that closed it, so a consumer holding the real
    /// contract for `g-2` can reject the prose completion.
    #[test]
    fn a_prose_twin_of_a_demanding_goal_is_detectable_from_the_verdict_alone() {
        let demanding: Goal<ArtifactEvidence> = Goal::declare("g-2").expect("valid goal");
        assert_eq!(
            demanding.required_evidence(),
            CompletionEvidenceKind::Artifact
        );

        let twin: Goal<NarrativeEvidence> = Goal::declare("g-2").expect("valid goal");
        let GoalVerdict::Complete { record } =
            twin.complete_with(NarrativeEvidence::new("it looks done").expect("prose"))
        else {
            panic!("a completed goal");
        };

        // The verdict is about the same identity as the demanding goal, so the
        // pairing a consumer holds cannot tell them apart.
        assert_eq!(record.goal_id(), demanding.id());
        // The record does say which contract closed it, and it is not the one
        // `g-2` demanded, so the consumer has the means to refuse it.
        assert_eq!(record.kind(), CompletionEvidenceKind::Narrative);
        assert_ne!(record.kind(), demanding.required_evidence());
        assert_eq!(record.reference(), None);
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

// ---------------------------------------------------------------------------
// Extension: the automation surface the R1-22 evidence recorded as not done.
//
// `plan/evidence/R1-22.json` states under "WHAT IS NOT DONE" that an
// `AutomationRevision` carries no enabled state and no concurrency or overlap
// policy, both of which `docs/product-plan/requirements/
// automation-goals-and-triggers.md` § Durable automations requires (lines 7 and
// 11). The same requirement's line 43 lists a filter vocabulary — equals,
// contains, existence, membership and bounded regex with all/any/not — of which
// only equality was modelled, and lines 11 and 50-52 name run-now and the
// registered watcher sources that no type spelled. The modules below close
// those, and each names the requirement line it answers to.
// ---------------------------------------------------------------------------

/// § Durable automations, lines 7 and 11: an automation revision stores its
/// enabled state, and the operation set includes pause, resume and archive.
mod enablement {
    use super::*;

    fn automation() -> AutomationRevision {
        AutomationRevision::new(
            "auto-1",
            Revision::FIRST,
            CanonicalSchedule::every(60_000).expect("positive interval"),
            &["notify:slack"],
        )
        .expect("valid automation")
    }

    fn cause() -> PauseCause {
        PauseCause::new("ada", "the upstream feed is replaying").expect("valid cause")
    }

    #[test]
    fn a_newly_declared_automation_is_enabled_and_names_no_resumer() {
        let automation = automation();
        assert_eq!(
            automation.enablement(),
            &AutomationEnablement::Enabled { resumed_by: None }
        );
        assert_eq!(automation.enablement().state(), EnablementState::Enabled);
        assert!(automation.enablement().admits_occurrence());
        assert_eq!(automation.enablement().cause(), None);
    }

    #[test]
    fn the_lifecycle_is_closed_and_every_state_is_reachable_or_refused() {
        // Exhaustive over the nine ordered pairs of the three states. The match
        // has no wildcard arm, so a fourth state would stop this compiling.
        let mut reached: Vec<EnablementState> = Vec::new();
        for state in EnablementState::ALL {
            let held = match state {
                EnablementState::Enabled => automation(),
                EnablementState::Paused => automation()
                    .paused(Revision::FIRST, cause())
                    .expect("enabled pauses"),
                EnablementState::Archived => automation()
                    .archived(Revision::FIRST, cause())
                    .expect("enabled archives"),
            };
            assert_eq!(held.enablement().state(), state);
            reached.push(state);

            let at = held.revision();
            for target in EnablementState::ALL {
                let attempt = match target {
                    EnablementState::Enabled => held.resumed(at, "grace"),
                    EnablementState::Paused => held.paused(at, cause()),
                    EnablementState::Archived => held.archived(at, cause()),
                };
                let permitted = matches!(
                    (state, target),
                    (EnablementState::Enabled, EnablementState::Paused)
                        | (EnablementState::Paused, EnablementState::Enabled)
                        | (
                            EnablementState::Enabled | EnablementState::Paused,
                            EnablementState::Archived
                        )
                );
                match attempt {
                    Ok(next) => {
                        assert!(
                            permitted,
                            "{} -> {} was accepted and should not be",
                            state.as_str(),
                            target.as_str()
                        );
                        assert_eq!(next.enablement().state(), target);
                        assert_eq!(next.revision().get(), at.get() + 1);
                    }
                    Err(error) => {
                        assert!(
                            !permitted,
                            "{} -> {} was refused and should not be",
                            state.as_str(),
                            target.as_str()
                        );
                        assert_eq!(error.category(), "invalid_transition");
                        assert_eq!(
                            error,
                            AutomationError::InvalidTransition {
                                from: state.as_str(),
                                to: target.as_str(),
                            }
                        );
                    }
                }
            }
        }
        assert_eq!(reached.len(), 3);
    }

    #[test]
    fn archived_is_terminal() {
        let archived = automation()
            .archived(Revision::FIRST, cause())
            .expect("enabled archives");
        let at = archived.revision();
        for attempt in [
            archived.resumed(at, "grace"),
            archived.paused(at, cause()),
            archived.archived(at, cause()),
        ] {
            assert_eq!(
                attempt.expect_err("archived is terminal").category(),
                "invalid_transition"
            );
        }
    }

    #[test]
    fn a_pause_names_who_and_why_and_a_resume_names_who() {
        let paused = automation()
            .paused(Revision::FIRST, cause())
            .expect("enabled pauses");
        let recorded = paused.enablement().cause().expect("a paused cause");
        assert_eq!(recorded.actor().as_str(), "ada");
        assert_eq!(recorded.reason(), "the upstream feed is replaying");

        let resumed = paused
            .resumed(paused.revision(), "grace")
            .expect("paused resumes");
        assert_eq!(
            resumed.enablement(),
            &AutomationEnablement::Enabled {
                resumed_by: Some(AutomationActor::new("grace").expect("valid actor")),
            }
        );
        // The resumer is carried, not dropped: the record says who reopened it.
        assert_eq!(resumed.enablement().cause(), None);

        // A pause with no stated cause is not constructible.
        for (actor, reason) in [("", "why"), ("ada", ""), ("ada", "a\u{7}b")] {
            assert_eq!(
                PauseCause::new(actor, reason)
                    .expect_err("a pause states who and why")
                    .category(),
                "field_invalid"
            );
        }
    }

    #[test]
    fn a_withdrawn_automation_produces_no_occurrence_key() {
        let automation = automation();
        assert_eq!(
            automation
                .occurrence_at(at(1_700_000_000_000))
                .expect("enabled fires")
                .as_str(),
            "auto-1@1700000000000"
        );

        for withdrawn in [
            automation.paused(Revision::FIRST, cause()).expect("pauses"),
            automation
                .archived(Revision::FIRST, cause())
                .expect("archives"),
        ] {
            let state = withdrawn.enablement().state();
            let refusal = withdrawn
                .occurrence_at(at(1_700_000_000_000))
                .expect_err("a withdrawn automation fires nothing");
            assert_eq!(refusal.category(), "not_enabled");
            assert_eq!(
                refusal,
                AutomationError::NotEnabled {
                    state: state.as_str(),
                }
            );
            assert!(!state.admits_occurrence());
        }
    }

    #[test]
    fn a_lifecycle_transition_requires_the_expected_revision() {
        let automation = automation();
        let stale = revision(9);
        assert_eq!(
            automation
                .paused(stale, cause())
                .expect_err("stale expectation")
                .category(),
            "revision_conflict"
        );
        // The receiver is unchanged by the refused edit.
        assert_eq!(automation.revision(), Revision::FIRST);
        assert_eq!(automation.enablement().state(), EnablementState::Enabled);
    }

    #[test]
    fn a_pause_carries_the_rest_of_the_revision_forward() {
        let paused = automation()
            .paused(Revision::FIRST, cause())
            .expect("enabled pauses");
        assert_eq!(paused.id(), "auto-1");
        assert_eq!(paused.approved_effects(), ["notify:slack"]);
        assert_eq!(
            paused.schedule(),
            &CanonicalSchedule::every(60_000).expect("positive interval")
        );
        assert_eq!(paused.overlap(), OverlapPolicy::Skip);
    }
}

/// § Durable automations, line 7: an automation revision stores a concurrency
/// or overlap policy.
mod overlap_policy {
    use super::*;

    #[test]
    fn the_policy_set_is_closed_and_every_kind_names_a_ceiling() {
        let mut seen: Vec<OverlapKind> = Vec::new();
        for kind in OverlapKind::ALL {
            // No wildcard arm: a fifth kind would stop this compiling.
            let policy = match kind {
                OverlapKind::Skip => OverlapPolicy::Skip,
                OverlapKind::Queue => OverlapPolicy::queue(4).expect("positive queue"),
                OverlapKind::CancelPrevious => OverlapPolicy::CancelPrevious,
                OverlapKind::Concurrent => OverlapPolicy::concurrent(3).expect("positive limit"),
            };
            assert_eq!(policy.kind(), kind);
            assert!(
                policy.live_ceiling() >= 1,
                "{} named no ceiling",
                kind.as_str()
            );
            seen.push(kind);
        }
        assert_eq!(seen.len(), 4);
        assert_eq!(OverlapPolicy::Skip.live_ceiling(), 1);
        assert_eq!(OverlapPolicy::CancelPrevious.live_ceiling(), 1);
        assert_eq!(
            OverlapPolicy::queue(4).expect("valid").live_ceiling(),
            5,
            "a queue of four plus the one running"
        );
        assert_eq!(
            OverlapPolicy::concurrent(3).expect("valid").live_ceiling(),
            3
        );
    }

    #[test]
    fn a_zero_ceiling_is_refused_rather_than_read_as_no_limit() {
        for refusal in [OverlapPolicy::queue(0), OverlapPolicy::concurrent(0)] {
            assert_eq!(
                refusal
                    .expect_err("a ceiling admits at least one")
                    .category(),
                "not_canonical"
            );
        }
        assert!(OverlapPolicy::queue(1).is_ok());
        assert!(OverlapPolicy::concurrent(1).is_ok());
    }

    #[test]
    fn the_policy_is_part_of_the_revision_and_edits_conflict() {
        let automation = AutomationRevision::new(
            "auto-1",
            Revision::FIRST,
            CanonicalSchedule::every(60_000).expect("positive interval"),
            &[],
        )
        .expect("valid automation");
        assert_eq!(automation.overlap(), OverlapPolicy::Skip);

        let policy = OverlapPolicy::concurrent(2).expect("positive limit");
        let next = automation
            .with_overlap(Revision::FIRST, policy)
            .expect("expected revision");
        assert_eq!(next.overlap(), policy);
        assert_eq!(next.revision().get(), 2);
        assert_eq!(
            automation.overlap(),
            OverlapPolicy::Skip,
            "the receiver was mutated"
        );
        assert_eq!(
            automation
                .with_overlap(revision(9), policy)
                .expect_err("stale expectation")
                .category(),
            "revision_conflict"
        );
    }
}

/// § Durable automations, line 11 (run-now) and § Hooks, watchers and wakeups,
/// lines 50-52 (the registered sources that can wake an automation).
mod trigger_vocabulary {
    use super::*;

    fn corpus() -> Vec<TriggerSpec> {
        let mut triggers = vec![
            TriggerSpec::schedule(CanonicalSchedule::once(at(0))),
            TriggerSpec::schedule(CanonicalSchedule::once(at(-1_000))),
            TriggerSpec::schedule(CanonicalSchedule::every(86_400_000).expect("positive")),
            TriggerSpec::schedule(
                CanonicalSchedule::cron(
                    "0 3 * * MON",
                    "Europe/Paris",
                    DstPolicy::ShiftMissingFireSecond,
                )
                .expect("valid cron"),
            ),
            TriggerSpec::inbound("route-1").expect("valid route"),
            TriggerSpec::inbound("route:with:colons").expect("valid route"),
            TriggerSpec::manual("ada").expect("valid actor"),
            TriggerSpec::manual("Ada Lovelace <ada@example.test>").expect("valid actor"),
        ];
        for source in WatchedSource::ALL {
            triggers.push(TriggerSpec::watch(source, "watcher-1").expect("valid watcher"));
        }
        triggers
    }

    #[test]
    fn the_trigger_set_is_closed_and_exhaustively_covered() {
        let mut seen: Vec<TriggerKind> = Vec::new();
        for kind in TriggerKind::ALL {
            // No wildcard arm: a fifth trigger kind would stop this compiling.
            let trigger = match kind {
                TriggerKind::Schedule => {
                    TriggerSpec::schedule(CanonicalSchedule::every(1).expect("positive"))
                }
                TriggerKind::Inbound => TriggerSpec::inbound("route-1").expect("valid"),
                TriggerKind::Watch => {
                    TriggerSpec::watch(WatchedSource::GitHub, "watcher-1").expect("valid")
                }
                TriggerKind::Manual => TriggerSpec::manual("ada").expect("valid"),
            };
            assert_eq!(trigger.kind(), kind);
            assert_eq!(trigger.is_unattended(), kind.is_unattended());
            seen.push(kind);
        }
        assert_eq!(seen.len(), 4);

        let spellings: Vec<&str> = TriggerKind::ALL.iter().map(|k| k.as_str()).collect();
        let mut sorted = spellings.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), spellings.len(), "two kinds share a spelling");
    }

    #[test]
    fn exactly_one_trigger_kind_is_attended() {
        let unattended: Vec<&str> = TriggerKind::ALL
            .iter()
            .filter(|kind| kind.is_unattended())
            .map(|kind| kind.as_str())
            .collect();
        assert_eq!(unattended, ["schedule", "inbound", "watch"]);
        assert!(!TriggerKind::Manual.is_unattended());
    }

    #[test]
    fn every_trigger_round_trips_through_its_canonical_rendering() {
        for trigger in corpus() {
            let rendered = trigger.render();
            let read = TriggerSpec::from_rendering(&rendered)
                .unwrap_or_else(|error| panic!("{rendered} did not read back: {error}"));
            assert_eq!(read, trigger);
            assert_eq!(read.render(), rendered, "re-rendering was not identical");
            assert!(
                rendered.starts_with(trigger.kind().as_str()),
                "{rendered} does not open with its kind"
            );
        }
    }

    #[test]
    fn equal_triggers_render_identically_and_unequal_ones_do_not() {
        let corpus = corpus();
        assert!(corpus.len() >= 16, "the corpus was shrunk");
        for left in &corpus {
            for right in &corpus {
                assert_eq!(
                    left == right,
                    left.render() == right.render(),
                    "{} and {} disagree",
                    left.render(),
                    right.render()
                );
            }
        }
    }

    #[test]
    fn the_watched_source_set_is_exactly_the_eight_the_requirement_names() {
        let spellings: Vec<&str> = WatchedSource::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            spellings,
            [
                "github",
                "ci",
                "monitoring",
                "filesystem",
                "rss",
                "calendar",
                "email",
                "platform"
            ]
        );
        for source in WatchedSource::ALL {
            assert_eq!(
                WatchedSource::from_name(source.as_str()).expect("declared source"),
                source
            );
        }
    }

    #[test]
    fn an_unknown_name_is_refused_rather_than_defaulted() {
        for (vocabulary, name) in [
            ("watched_source", "gitlab"),
            ("watched_source", "GitHub"),
            ("watched_source", "github "),
            ("watched_source", ""),
        ] {
            let refusal = WatchedSource::from_name(name).expect_err("not a declared source");
            assert_eq!(refusal.category(), "unknown_vocabulary");
            assert_eq!(
                refusal,
                AutomationError::UnknownVocabulary {
                    vocabulary,
                    requested: name.to_owned(),
                }
            );
        }
        for name in ["webhook", "cron", "Manual", "manual "] {
            assert_eq!(
                TriggerKind::from_name(name)
                    .expect_err("not a declared kind")
                    .category(),
                "unknown_vocabulary"
            );
        }
    }

    #[test]
    fn a_malformed_rendering_is_refused() {
        for rendered in [
            "manual",                 // no separator at all
            "webhook:route-1",        // unknown kind
            "watch:gitlab:watcher-1", // unknown source
            "watch:github",           // no watcher
            "schedule:weekly@1",      // not a canonical schedule
            "schedule:",              // empty schedule
            "inbound:",               // empty route
            "inbound:route 1",        // whitespace in an identity
            "manual:",                // anonymous run-now
        ] {
            let refusal = TriggerSpec::from_rendering(rendered)
                .expect_err("a malformed rendering was accepted");
            assert!(
                matches!(
                    refusal.category(),
                    "unknown_vocabulary" | "not_canonical" | "field_invalid"
                ),
                "{rendered} was refused as {}",
                refusal.category()
            );
        }
        // The paired accepting cases, differing only in the rejected thing.
        assert!(TriggerSpec::from_rendering("manual:ada").is_ok());
        assert!(TriggerSpec::from_rendering("watch:github:watcher-1").is_ok());
        assert!(TriggerSpec::from_rendering("schedule:every@1").is_ok());
        assert!(TriggerSpec::from_rendering("inbound:route-1").is_ok());
    }
}

/// § Durable automations, lines 13-22: what a job can do, and that creating a
/// schedule is never blanket authority for future arbitrary effects.
mod action_binding {
    use super::*;

    fn automation(effects: &[&str]) -> AutomationRevision {
        AutomationRevision::new(
            "auto-1",
            Revision::FIRST,
            CanonicalSchedule::every(60_000).expect("positive interval"),
            effects,
        )
        .expect("valid automation")
    }

    fn destination() -> AuthorizedDestination {
        AuthorizedDestination::new("slack:C1", "grant:slack-post").expect("authorized")
    }

    fn every_action() -> Vec<AutomationAction> {
        vec![
            AutomationAction::agent_turn("prompt-nightly").expect("valid prompt"),
            AutomationAction::script("workflow-backup").expect("valid workflow"),
            AutomationAction::command("pause_intake").expect("valid command"),
            AutomationAction::notify(destination()),
        ]
    }

    #[test]
    fn the_action_set_is_closed_and_exhaustively_covered() {
        let mut seen: Vec<ActionKind> = Vec::new();
        for kind in ActionKind::ALL {
            // No wildcard arm: a fifth action kind would stop this compiling.
            let action = match kind {
                ActionKind::AgentTurn => AutomationAction::agent_turn("p-1").expect("valid"),
                ActionKind::Script => AutomationAction::script("w-1").expect("valid"),
                ActionKind::Command => AutomationAction::command("status").expect("valid"),
                ActionKind::Notify => AutomationAction::notify(destination()),
            };
            assert_eq!(action.kind(), kind);
            assert_eq!(action.reaches_model(), kind.reaches_model());
            seen.push(kind);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn only_an_agent_turn_reaches_a_model_and_the_rest_are_script_jobs() {
        // Requirement line 20: a job may run notification-only with zero model
        // call. Requirement line 51 of the contract: skipping the model does
        // not buy weaker obligations, so every non-model action is a
        // `JobKind::Script` and carries the same `JobObligations`.
        for action in every_action() {
            let expected = matches!(action.kind(), ActionKind::AgentTurn);
            assert_eq!(action.reaches_model(), expected);
            assert_eq!(
                action.kind().job_kind(),
                if expected {
                    JobKind::Agent
                } else {
                    JobKind::Script
                }
            );
        }
        assert_eq!(
            ActionKind::ALL
                .iter()
                .filter(|kind| kind.reaches_model())
                .count(),
            1
        );
    }

    #[test]
    fn an_action_names_the_exact_effect_its_scope_must_contain() {
        let expected = [
            "agent_turn:prompt-nightly",
            "script:workflow-backup",
            "command:pause_intake",
            "notify:slack:C1",
        ];
        let effects: Vec<String> = every_action()
            .iter()
            .map(AutomationAction::required_effect)
            .collect();
        assert_eq!(effects, expected);

        // Deterministic: the same action yields the same effect every time.
        for action in every_action() {
            assert_eq!(action.required_effect(), action.required_effect());
        }

        // Distinct: two different actions never demand the same authority.
        let mut sorted = effects.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), effects.len());
    }

    #[test]
    fn an_action_inside_scope_binds_and_one_outside_it_can_only_be_asked_for() {
        let trigger = TriggerSpec::schedule(CanonicalSchedule::every(60_000).expect("positive"));
        for action in every_action() {
            let effect = action.required_effect();
            let declared = automation(&[effect.as_str()]);
            // No wildcard arm: a third binding outcome would stop this
            // compiling.
            match declared
                .bind(&trigger, action.clone())
                .expect("an enabled automation")
            {
                ActionBinding::Bound(bound) => {
                    assert_eq!(bound.automation_id(), "auto-1");
                    assert_eq!(bound.action(), &action);
                    assert_eq!(bound.trigger(), &trigger);
                    assert_eq!(bound.job_kind(), action.kind().job_kind());
                    // The binding is spendable exactly once, as the approval a
                    // completed effect requires.
                    let done = CompletedEffect::record(bound.into_approved(), "outbox:r-1")
                        .expect("valid receipt");
                    assert_eq!(done.effect(), effect);
                    assert_eq!(done.automation_id(), "auto-1");
                }
                ActionBinding::RequiresApproval(request) => {
                    panic!("{effect} was declared and still needed approval: {request:?}");
                }
            }

            let undeclared = automation(&["notify:somewhere-else"]);
            match undeclared
                .bind(&trigger, action.clone())
                .expect("an enabled automation")
            {
                ActionBinding::Bound(bound) => {
                    panic!("{effect} was not declared and still bound: {bound:?}");
                }
                ActionBinding::RequiresApproval(request) => {
                    assert_eq!(request.effect(), effect);
                    assert_eq!(request.automation_id(), "auto-1");
                    assert_eq!(
                        request.refusal(),
                        AutomationError::OutsideApprovedScope {
                            effect: effect.clone(),
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn a_manual_trigger_is_not_a_way_around_declared_scope() {
        // If run-now bypassed the scope check, "ask a person to press the
        // button" would be a privilege escalation. Every trigger kind gets the
        // same answer for the same action and the same declared scope.
        let action = AutomationAction::command("submit_run").expect("valid command");
        let undeclared = automation(&["command:status"]);
        let triggers = [
            TriggerSpec::manual("ada").expect("valid actor"),
            TriggerSpec::schedule(CanonicalSchedule::every(60_000).expect("positive")),
            TriggerSpec::inbound("route-1").expect("valid route"),
            TriggerSpec::watch(WatchedSource::GitHub, "watcher-1").expect("valid watcher"),
        ];
        for trigger in &triggers {
            let binding = undeclared
                .bind(trigger, action.clone())
                .expect("an enabled automation");
            assert!(
                matches!(binding, ActionBinding::RequiresApproval(_)),
                "{} bypassed the declared scope",
                trigger.kind().as_str()
            );
        }
        // And the paired case: declaring it makes every trigger bind, so the
        // test cannot be satisfied by refusing everything.
        let declared = automation(&["command:submit_run"]);
        for trigger in &triggers {
            assert!(matches!(
                declared
                    .bind(trigger, action.clone())
                    .expect("an enabled automation"),
                ActionBinding::Bound(_)
            ));
        }
    }

    #[test]
    fn a_withdrawn_automation_binds_nothing_however_it_is_triggered() {
        let cause = PauseCause::new("ada", "under investigation").expect("valid cause");
        let declared = automation(&["command:status"]);
        let action = AutomationAction::command("status").expect("valid command");
        for withdrawn in [
            declared
                .paused(Revision::FIRST, cause.clone())
                .expect("pauses"),
            declared.archived(Revision::FIRST, cause).expect("archives"),
        ] {
            for trigger in [
                TriggerSpec::manual("ada").expect("valid actor"),
                TriggerSpec::schedule(CanonicalSchedule::every(60_000).expect("positive")),
            ] {
                let refusal = withdrawn
                    .bind(&trigger, action.clone())
                    .expect_err("a withdrawn automation binds nothing");
                assert_eq!(refusal.category(), "not_enabled");
            }
        }
        // Paired: the same automation, enabled, binds the same action.
        assert!(matches!(
            declared
                .bind(&TriggerSpec::manual("ada").expect("valid actor"), action,)
                .expect("an enabled automation"),
            ActionBinding::Bound(_)
        ));
    }

    #[test]
    fn an_action_this_build_cannot_perform_is_refused_rather_than_dropped() {
        for name in ["deploy", "agent-turn", "AgentTurn", "shell", ""] {
            let refusal = ActionKind::from_name(name).expect_err("not a declared action");
            assert_eq!(refusal.category(), "unknown_vocabulary");
            assert_eq!(
                refusal,
                AutomationError::UnknownVocabulary {
                    vocabulary: "action_kind",
                    requested: name.to_owned(),
                }
            );
        }
        for kind in ActionKind::ALL {
            assert_eq!(
                ActionKind::from_name(kind.as_str()).expect("declared action"),
                kind
            );
        }
        // A command identifier outside the registry grammar is refused where it
        // is written, not carried forward as text for something else to parse.
        for spelling in ["Pause Intake", "pause intake", "", "pause..intake"] {
            assert_eq!(
                AutomationAction::command(spelling)
                    .expect_err("not a command identifier")
                    .category(),
                "unknown_vocabulary"
            );
        }
        assert!(AutomationAction::command("pause_intake").is_ok());
    }

    #[test]
    fn an_action_reference_cannot_be_prose() {
        for label in ["the nightly build", "prompt with spaces", ""] {
            assert!(
                AutomationAction::agent_turn(label).is_err(),
                "{label} was accepted as a prompt reference"
            );
            assert!(
                AutomationAction::script(label).is_err(),
                "{label} was accepted as a workflow reference"
            );
        }
        assert!(AutomationAction::agent_turn("prompt-nightly").is_ok());
        assert!(AutomationAction::script("workflow-backup").is_ok());
    }
}

/// § Inbound webhook subscriptions, line 43: declarative filters — `equals`,
/// `contains`, existence, membership and bounded regex with all/any/not.
mod condition_vocabulary {
    use super::*;

    fn eq(field: &str, value: &str) -> FilterExpression {
        FilterExpression::field(field, FilterPredicate::equals(value).expect("valid value"))
            .expect("valid field")
    }

    fn corpus() -> Vec<FilterExpression> {
        let leaves = vec![
            eq("repository", "acme/app"),
            eq("repository", "acme/other"),
            FilterExpression::field(
                "event.name",
                FilterPredicate::contains("completed").expect("valid substring"),
            )
            .expect("valid field"),
            FilterExpression::field("payload.head_sha", FilterPredicate::Exists)
                .expect("valid field"),
            FilterExpression::field(
                "branch",
                FilterPredicate::member_of(&["main", "release", "hotfix"]).expect("valid set"),
            )
            .expect("valid field"),
            FilterExpression::field(
                "tag",
                FilterPredicate::matches("v[0-9]{1,3}").expect("bounded pattern"),
            )
            .expect("valid field"),
            // Separators inside a literal are structure-free because the
            // rendering counts bytes rather than escaping them.
            eq("note", "a,b)c(d:e"),
            eq("note", "héllo — ünicode"),
        ];
        let mut all = leaves.clone();
        all.push(FilterExpression::all(leaves.clone()).expect("bounded"));
        all.push(FilterExpression::any(leaves.clone()).expect("bounded"));
        all.push(FilterExpression::negating(leaves[0].clone()).expect("bounded"));
        all.push(
            FilterExpression::all(vec![
                FilterExpression::negating(leaves[1].clone()).expect("bounded"),
                FilterExpression::any(vec![leaves[2].clone(), leaves[3].clone()]).expect("bounded"),
            ])
            .expect("bounded"),
        );
        // Order is part of the value, so both orders belong in the corpus.
        all.push(
            FilterExpression::all(vec![leaves[0].clone(), leaves[1].clone()]).expect("bounded"),
        );
        all.push(
            FilterExpression::all(vec![leaves[1].clone(), leaves[0].clone()]).expect("bounded"),
        );
        all
    }

    #[test]
    fn the_predicate_set_is_exactly_the_five_the_requirement_names() {
        let mut seen: Vec<PredicateKind> = Vec::new();
        for kind in PredicateKind::ALL {
            // No wildcard arm: a sixth predicate — an `Eval`, a `Script`, a
            // `Jq` — would stop this compiling.
            let predicate = match kind {
                PredicateKind::Equals => FilterPredicate::equals("x").expect("valid"),
                PredicateKind::Contains => FilterPredicate::contains("x").expect("valid"),
                PredicateKind::Exists => FilterPredicate::Exists,
                PredicateKind::MemberOf => FilterPredicate::member_of(&["x"]).expect("valid"),
                PredicateKind::Matches => FilterPredicate::matches("x{1,2}").expect("valid"),
            };
            assert_eq!(predicate.kind(), kind);
            seen.push(kind);
        }
        assert_eq!(seen.len(), 5);
        assert_eq!(
            PredicateKind::ALL.map(PredicateKind::as_str),
            ["eq", "contains", "exists", "in", "matches"]
        );
    }

    #[test]
    fn an_unbounded_quantifier_is_refused() {
        // This is the whole point of "bounded regex": a pattern whose matching
        // cost is not bounded by its own text does not become a stored filter.
        for pattern in [
            "a*",
            "a+",
            "[a-z]*",
            "(ab)+",
            "a{2,}",
            "build-.*",
            "(a{1,4})+",
        ] {
            let refusal =
                BoundedPattern::new(pattern).expect_err("an unbounded quantifier was accepted");
            assert!(
                matches!(refusal.category(), "not_canonical" | "too_large"),
                "{pattern} was refused as {}",
                refusal.category()
            );
        }
        // The paired accepting cases, differing only in the ceiling.
        for pattern in ["a{2,8}", "[a-z]{1,16}", "(ab){1,4}", "a?", "build-.{0,32}"] {
            assert!(
                BoundedPattern::new(pattern).is_ok(),
                "{pattern} was refused"
            );
        }
    }

    #[test]
    fn a_backreference_or_a_lookaround_is_refused() {
        for pattern in ["(a){1,2}\\1", "(?=secret)", "(?!secret)", "(?:ab){1,2}"] {
            assert_eq!(
                BoundedPattern::new(pattern)
                    .expect_err("an unbounded construct was accepted")
                    .category(),
                "not_canonical"
            );
        }
        assert!(BoundedPattern::new("(a){1,2}b").is_ok());
    }

    #[test]
    fn the_product_of_the_repetition_ceilings_is_bounded() {
        // A pattern can name only bounded repetitions and still ask for
        // unbounded work by nesting them, so the bound is on the product.
        let refusal = BoundedPattern::new("a{1,64}b{1,64}").expect_err("4096 exceeds the ceiling");
        assert_eq!(refusal.category(), "too_large");
        assert_eq!(
            refusal,
            AutomationError::TooLarge {
                field: "pattern_expansion",
                max: MAX_PATTERN_EXPANSION as usize,
                actual: 4_096,
            }
        );
        assert!(
            BoundedPattern::new("a{1,32}b{1,32}").is_ok(),
            "1024 is exactly the ceiling"
        );
    }

    #[test]
    fn a_malformed_pattern_is_refused() {
        for pattern in [
            "(ab",    // unclosed group
            "ab)",    // closes before it opens
            "[a-z",   // unclosed class
            "a]",     // class closes before it opens
            "{1,2}",  // a repetition with nothing to repeat
            "a{}",    // no bound at all
            "a{2,1}", // ceiling below floor
            "ab\\",   // trailing escape
            "",       // empty
        ] {
            assert!(
                BoundedPattern::new(pattern).is_err(),
                "{pattern} was accepted"
            );
        }
    }

    #[test]
    fn membership_is_a_set_so_declaration_order_does_not_change_the_value() {
        let one = FilterPredicate::member_of(&["main", "release", "hotfix"]).expect("valid");
        let other = FilterPredicate::member_of(&["hotfix", "main", "release"]).expect("valid");
        assert_eq!(one, other);
        let duplicated =
            FilterPredicate::member_of(&["main", "main", "release", "hotfix"]).expect("valid");
        assert_eq!(one, duplicated);
        assert_eq!(
            FilterExpression::field("branch", one)
                .expect("valid")
                .render(),
            FilterExpression::field("branch", other)
                .expect("valid")
                .render()
        );

        // An empty set admits nothing and is refused rather than read as
        // "no constraint".
        assert_eq!(
            FilterPredicate::member_of(&[])
                .expect_err("an empty set")
                .category(),
            "not_canonical"
        );
        let too_many: Vec<String> = (0..=MAX_MEMBERSHIP_VALUES).map(|n| n.to_string()).collect();
        let borrowed: Vec<&str> = too_many.iter().map(String::as_str).collect();
        assert_eq!(
            FilterPredicate::member_of(&borrowed)
                .expect_err("beyond the ceiling")
                .category(),
            "too_large"
        );
    }

    #[test]
    fn depth_and_node_count_are_bounded() {
        let leaf = eq("a", "b");
        // Nesting past the depth ceiling is refused at the constructor that
        // crosses it, not tolerated and truncated later.
        let mut nested = leaf.clone();
        for _ in 1..MAX_FILTER_DEPTH {
            nested = FilterExpression::negating(nested).expect("within the ceiling");
        }
        assert_eq!(nested.depth(), MAX_FILTER_DEPTH);
        let refusal = FilterExpression::negating(nested).expect_err("one level past the ceiling");
        assert_eq!(refusal.category(), "too_large");
        assert_eq!(
            refusal,
            AutomationError::TooLarge {
                field: "filter_depth",
                max: MAX_FILTER_DEPTH,
                actual: MAX_FILTER_DEPTH + 1,
            }
        );

        let wide: Vec<FilterExpression> = (0..MAX_FILTER_NODES).map(|_| leaf.clone()).collect();
        assert_eq!(
            FilterExpression::all(wide)
                .expect_err("the combinator is a node too")
                .category(),
            "too_large"
        );
        let fits: Vec<FilterExpression> = (0..MAX_FILTER_NODES - 1).map(|_| leaf.clone()).collect();
        let accepted = FilterExpression::all(fits).expect("exactly the ceiling");
        assert_eq!(accepted.nodes(), MAX_FILTER_NODES);

        // A combinator with no operands admits everything or nothing depending
        // on which one it is, so it is refused rather than guessed at.
        for empty in [
            FilterExpression::all(Vec::new()),
            FilterExpression::any(Vec::new()),
        ] {
            assert_eq!(empty.expect_err("no operands").category(), "not_canonical");
        }
    }

    #[test]
    fn every_condition_round_trips_through_its_canonical_rendering() {
        let corpus = corpus();
        assert!(corpus.len() >= 14, "the corpus was shrunk");
        for expression in &corpus {
            let rendered = expression.render();
            let read = FilterExpression::from_rendering(&rendered)
                .unwrap_or_else(|error| panic!("{rendered} did not read back: {error}"));
            assert_eq!(&read, expression);
            assert_eq!(read.render(), rendered, "re-rendering was not identical");
        }
    }

    #[test]
    fn equal_conditions_render_identically_and_unequal_ones_do_not() {
        let corpus = corpus();
        for left in &corpus {
            for right in &corpus {
                assert_eq!(
                    left == right,
                    left.render() == right.render(),
                    "{} and {} disagree",
                    left.render(),
                    right.render()
                );
            }
        }
    }

    #[test]
    fn the_rendering_is_the_one_the_reader_accepts() {
        // Every constructible expression renders inside the bound the reader
        // enforces, so `render` cannot produce a value `from_rendering` refuses.
        for expression in corpus() {
            assert!(expression.render().len() <= MAX_FILTER_RENDERING_BYTES);
        }
        let long = "v".repeat(200);
        let wide: Vec<FilterExpression> = (0..MAX_FILTER_NODES - 1)
            .map(|_| {
                FilterExpression::field(
                    "field",
                    FilterPredicate::member_of(&[long.as_str()]).expect("valid"),
                )
                .expect("valid")
            })
            .collect();
        match FilterExpression::all(wide) {
            Ok(expression) => {
                let rendered = expression.render();
                assert!(rendered.len() <= MAX_FILTER_RENDERING_BYTES);
                assert_eq!(
                    FilterExpression::from_rendering(&rendered).expect("reads back"),
                    expression
                );
            }
            Err(error) => assert_eq!(error.category(), "too_large"),
        }
    }

    #[test]
    fn a_malformed_rendering_is_refused_rather_than_normalized() {
        for rendered in [
            "eq(repository,7:acme/app)", // the count is not the text's
            "eq(repository,3:acme/app)", // trailing input after the literal
            "eq(repository,acme/app)",   // no count at all
            "eq(repository,:acme)",      // empty count
            "eq(repository,-1:acme)",    // not a count
            "eq(repository)",            // no literal
            "exists(repository,3:abc)",  // a literal where none belongs
            "jq(repository,3:abc)",      // not a declared predicate
            "eval(1:1)",                 // still not one
            "all()",                     // no operands
            "any()",                     // no operands
            "not()",                     // no operand
            "all(eq(a,1:b)",             // unclosed
            "eq(a,1:b))",                // trailing input
            "eq(a b,1:c)",               // a field outside the grammar
            "eq(,1:c)",                  // no field
            "repository",                // not a node at all
            "",                          // empty
        ] {
            let refusal = FilterExpression::from_rendering(rendered)
                .expect_err("a malformed rendering was accepted");
            assert!(
                matches!(
                    refusal.category(),
                    "not_canonical" | "unknown_vocabulary" | "field_invalid" | "too_large"
                ),
                "{rendered} was refused as {}",
                refusal.category()
            );
        }
        // The paired accepting cases, differing only in the rejected thing.
        for rendered in [
            "eq(repository,8:acme/app)",
            "exists(repository)",
            "all(eq(a,1:b))",
            "any(eq(a,1:b),not(exists(c)))",
            "in(branch,4:main,7:release)",
            "matches(tag,11:v[0-9]{1,3})",
        ] {
            assert!(
                FilterExpression::from_rendering(rendered).is_ok(),
                "{rendered} was refused"
            );
        }
    }

    #[test]
    fn a_route_filters_by_one_condition_however_it_was_declared() {
        // The equality shorthand and the full condition are the same
        // vocabulary, so a route declared either way filters identically.
        let shorthand = EventFilters::requiring_all(vec![
            EventFilter::requiring("repository", "acme/app").expect("valid"),
            EventFilter::requiring("branch", "main").expect("valid"),
        ]);
        let spelled_out = EventFilters::matching(
            FilterExpression::all(vec![eq("repository", "acme/app"), eq("branch", "main")])
                .expect("bounded"),
        );
        let one = shorthand
            .canonical_expression()
            .expect("bounded")
            .expect("a declared condition");
        let other = spelled_out
            .canonical_expression()
            .expect("bounded")
            .expect("a declared condition");
        assert_eq!(one, other);
        assert_eq!(one.render(), other.render());
        assert_eq!(
            one.render(),
            "all(eq(repository,8:acme/app),eq(branch,4:main))"
        );

        // Accepting every allowed event type stays a named decision rather than
        // becoming a condition that happens to admit everything.
        assert_eq!(
            EventFilters::accept_all_allowed_types()
                .canonical_expression()
                .expect("bounded"),
            None
        );
        assert_eq!(EventFilters::accept_all_allowed_types().expression(), None);
        assert!(spelled_out.expression().is_some());
    }

    #[test]
    fn a_filter_list_too_large_to_lower_is_refused_rather_than_truncated() {
        let filters: Vec<EventFilter> = (0..MAX_FILTER_NODES + 4)
            .map(|n| EventFilter::requiring("branch", &n.to_string()).expect("valid"))
            .collect();
        let declared = EventFilters::requiring_all(filters);
        let refusal = declared
            .canonical_expression()
            .expect_err("beyond the node ceiling");
        assert_eq!(refusal.category(), "too_large");
        // The declaration is still readable in full: nothing was dropped to
        // make it fit.
        assert_eq!(declared.as_slice().len(), MAX_FILTER_NODES + 4);
    }

    #[test]
    fn a_filter_field_is_a_path_rather_than_prose() {
        for label in [
            "the repository name",
            "repo/name",
            "repo,name",
            "repo(name)",
            "repo..name",
            ".repo",
            "repo.",
            "",
        ] {
            assert!(
                FilterField::new(label).is_err(),
                "{label} was accepted as a field path"
            );
        }
        for path in ["repository", "payload.head_sha", "a.b.c.d", "x-request-id"] {
            assert_eq!(FilterField::new(path).expect("valid path").as_str(), path);
        }
        let deep = ["a"; MAX_FILTER_FIELD_SEGMENTS + 1].join(".");
        assert_eq!(
            FilterField::new(&deep)
                .expect_err("beyond the segment ceiling")
                .category(),
            "too_large"
        );
    }
}
