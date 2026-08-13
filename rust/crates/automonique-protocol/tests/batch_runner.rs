// SPDX-License-Identifier: Elastic-2.0

//! The batch runner model.
//!
//! The first module pins the vocabulary this model reuses from
//! [`automonique_protocol::runs_api`] rather than re-spells, and the bound it
//! shares with the admin lane's submission key. The second is the rollup's
//! truth table, enumerated exhaustively. The rest exercise the construction
//! refusals, the document round trip and the bounds.

use std::collections::BTreeMap;

use automonique_protocol::admin::MAX_RUN_SUBMISSION_KEY_BYTES;
use automonique_protocol::batch_runner::{
    BATCH_SCHEMA_V1, BatchError, BatchId, BatchLabel, BatchMember, BatchMemberKey, BatchPlan,
    BatchProgress, BatchState, ConcurrencyKind, ConcurrencyPolicy, MAX_BATCH_CANONICAL_BYTES,
    MAX_BATCH_ID_BYTES, MAX_BATCH_LABEL_BYTES, MAX_BATCH_MEMBER_KEY_BYTES, MAX_BATCH_MEMBERS,
    MemberProgress, roll_up,
};
use automonique_protocol::codec::CodecError;
use automonique_protocol::primitives::ValueError;
use automonique_protocol::runs_api::RunState;
use automonique_protocol::wire::{JsonValue, parse_canonical};

fn batch_id() -> BatchId {
    BatchId::new("nightly-eval-1").expect("valid batch id")
}

fn key(index: usize) -> BatchMemberKey {
    BatchMemberKey::new(format!("operator:batch:{index}")).expect("valid member key")
}

fn keys(count: usize) -> Vec<BatchMemberKey> {
    (0..count).map(key).collect()
}

fn plan(count: usize) -> BatchPlan {
    BatchPlan::new(batch_id(), None, keys(count), ConcurrencyPolicy::Sequential)
        .expect("valid plan")
}

fn observed(plan: &BatchPlan, states: &[MemberProgress]) -> BatchProgress {
    let members = plan
        .members()
        .iter()
        .zip(states)
        .map(|(key, state)| BatchMember::new(key.clone(), *state))
        .collect();
    BatchProgress::observe(plan, members).expect("valid progress")
}

/// Every member state, in the order the model declares them.
fn all_progress() -> [MemberProgress; 7] {
    MemberProgress::ALL
}

/// The vocabularies this model reuses, against the modules that own them.
mod vocabulary {
    use super::*;

    /// The six run states are [`RunState`]'s, not a second spelling table.
    ///
    /// A rename in `runs_api` changes what [`MemberProgress::as_str`] returns,
    /// because it calls [`RunState::as_str`]. This test states that it does, so
    /// a future edit that pasted the six words in here would fail rather than
    /// quietly forking the vocabulary.
    #[test]
    fn member_progress_carries_run_state_spellings_unchanged() {
        for state in RunState::ALL {
            let progress = MemberProgress::Run(state);
            assert_eq!(
                progress.as_str(),
                state.as_str(),
                "{state} must not acquire a second spelling"
            );
            assert_eq!(
                MemberProgress::from_spelling(state.as_str()),
                Some(progress),
                "{state} must parse back to the run it names"
            );
            assert_eq!(progress.run_state(), Some(state));
            assert_eq!(
                progress.is_terminal(),
                state.is_terminal(),
                "{state} terminality must be the run's"
            );
        }
    }

    /// The seventh value is the one a run vocabulary cannot express, and it does
    /// not collide with any of the six.
    #[test]
    fn unsubmitted_is_outside_the_run_vocabulary() {
        assert_eq!(MemberProgress::Unsubmitted.as_str(), "unsubmitted");
        assert_eq!(
            RunState::from_spelling("unsubmitted"),
            None,
            "the run vocabulary must not already own this word"
        );
        assert_eq!(MemberProgress::Unsubmitted.run_state(), None);
        assert!(!MemberProgress::Unsubmitted.is_terminal());
        assert!(MemberProgress::Unsubmitted.has_not_started());
    }

    /// `ALL` is exactly `{Unsubmitted}` union `Run(RunState::ALL)`, derived here
    /// from `RunState::ALL` so a variant added there fails this test.
    #[test]
    fn member_progress_all_is_the_run_states_plus_one() {
        let expected: Vec<MemberProgress> = std::iter::once(MemberProgress::Unsubmitted)
            .chain(RunState::ALL.into_iter().map(MemberProgress::Run))
            .collect();
        assert_eq!(MemberProgress::ALL.to_vec(), expected);
        assert_eq!(MemberProgress::ALL.len(), RunState::ALL.len() + 1);
    }

    /// Every spelling is distinct, so no two member states share a wire word.
    #[test]
    fn member_progress_spellings_are_distinct() {
        let mut seen: BTreeMap<&str, MemberProgress> = BTreeMap::new();
        for progress in MemberProgress::ALL {
            assert!(
                seen.insert(progress.as_str(), progress).is_none(),
                "{progress} repeats a spelling"
            );
            assert_eq!(
                MemberProgress::from_spelling(progress.as_str()),
                Some(progress)
            );
        }
        assert_eq!(seen.len(), 7);
    }

    /// The member key bound is the admin lane's submission key bound, not a
    /// second number that happens to match today.
    #[test]
    fn a_member_key_is_bounded_exactly_as_a_submission_key() {
        assert_eq!(MAX_BATCH_MEMBER_KEY_BYTES, MAX_RUN_SUBMISSION_KEY_BYTES);
        assert_eq!(BatchMemberKey::MAX_BYTES, MAX_RUN_SUBMISSION_KEY_BYTES);
    }

    /// The schema name is versioned, dotted and inside the namespace.
    #[test]
    fn the_schema_name_is_canonical() {
        assert_eq!(BATCH_SCHEMA_V1, "automonique.batch/v1");
        assert!(BATCH_SCHEMA_V1.starts_with("automonique."));
        assert!(BATCH_SCHEMA_V1.ends_with("/v1"));
        assert_eq!(plan(1).schema(), BATCH_SCHEMA_V1);
        assert_eq!(
            observed(&plan(1), &[MemberProgress::Unsubmitted]).schema(),
            BATCH_SCHEMA_V1
        );
    }

    /// The batch rollup is its own closed vocabulary of six, with distinct
    /// spellings that parse back.
    #[test]
    fn the_batch_rollup_vocabulary_is_closed() {
        assert_eq!(BatchState::ALL.len(), 6);
        let mut seen: Vec<&str> = BatchState::ALL.iter().map(|s| s.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 6, "a batch state repeats a spelling");
        for state in BatchState::ALL {
            assert_eq!(BatchState::from_spelling(state.as_str()), Some(state));
        }
        assert_eq!(BatchState::from_spelling("partial"), None);
        assert_eq!(BatchState::from_spelling("unknown"), None);
    }
}

/// The rollup: a total function, enumerated.
mod rollup {
    use super::*;

    /// An independently written decision over which member states are present.
    ///
    /// Expressed as seven booleans and a nested `if`, rather than by iterating
    /// the slice the way `roll_up` does, so the two derivations can disagree.
    fn oracle(present: &[MemberProgress]) -> BatchState {
        let has = |value: MemberProgress| present.contains(&value);
        let unsubmitted = has(MemberProgress::Unsubmitted);
        let ready = has(MemberProgress::Run(RunState::Ready));
        let running = has(MemberProgress::Run(RunState::Running));
        let completed = has(MemberProgress::Run(RunState::Completed));
        let failed = has(MemberProgress::Run(RunState::Failed));
        let cancelled = has(MemberProgress::Run(RunState::Cancelled));
        let timed_out = has(MemberProgress::Run(RunState::TimedOut));

        if unsubmitted || ready || running {
            if running || completed || failed || cancelled || timed_out {
                BatchState::Running
            } else {
                BatchState::Pending
            }
        } else if failed || timed_out {
            BatchState::Failed
        } else if completed && !cancelled {
            BatchState::Completed
        } else if cancelled && !completed {
            BatchState::Cancelled
        } else {
            BatchState::Mixed
        }
    }

    /// Every non-empty subset of the seven member states, as a member list.
    fn subsets() -> Vec<Vec<MemberProgress>> {
        let all = all_progress();
        (1_u32..(1 << 7))
            .map(|mask| {
                all.iter()
                    .enumerate()
                    .filter(|(index, _)| mask & (1 << index) != 0)
                    .map(|(_, progress)| *progress)
                    .collect()
            })
            .collect()
    }

    /// The truth table, in full: 127 non-empty subsets, each mapped to exactly
    /// one batch state and printed.
    ///
    /// Exhaustive because the answer depends only on which of the seven member
    /// states are present — proved separately by
    /// `the_answer_ignores_order_and_multiplicity` — so the 127 subsets are the
    /// whole domain, not a sample of it.
    #[test]
    fn the_truth_table_is_exhaustive_and_total() {
        let subsets = subsets();
        assert_eq!(subsets.len(), 127, "2^7 - 1 non-empty subsets");

        let mut buckets: BTreeMap<&str, usize> = BTreeMap::new();
        for members in &subsets {
            let derived = roll_up(members).unwrap_or_else(|| {
                panic!("a non-empty member list must have a state: {members:?}")
            });
            let expected = oracle(members);
            assert_eq!(
                derived,
                expected,
                "rollup disagrees with the oracle for {:?}",
                members.iter().map(|m| m.as_str()).collect::<Vec<_>>()
            );

            // Exactly one: the answer is one of the six and equals no other.
            assert_eq!(
                BatchState::ALL
                    .into_iter()
                    .filter(|candidate| *candidate == derived)
                    .count(),
                1,
                "{derived} is not exactly one of the closed six"
            );

            println!(
                "{:<64} -> {}",
                members
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join("+"),
                derived
            );
            *buckets.entry(derived.as_str()).or_default() += 1;
        }

        // The shape of the whole table as a numeric fingerprint. A rollup that
        // answered one combination differently moves two of these counts, so
        // this catches a mutation the spot checks below might walk past.
        //
        // - the 15 all-terminal subsets split 12 failed / 1 completed /
        //   1 cancelled / 1 mixed: a subset containing `failed` or `timed_out`
        //   is failed (12 of the 15), and the three that contain neither are
        //   {completed}, {cancelled} and {completed, cancelled};
        // - of the 112 subsets carrying a live member, the 3 built only from
        //   `unsubmitted` and `ready` are pending and the other 109 running.
        assert_eq!(
            buckets,
            BTreeMap::from([
                ("pending", 3),
                ("running", 109),
                ("completed", 1),
                ("failed", 12),
                ("cancelled", 1),
                ("mixed", 1),
            ]),
            "the rollup's partition of the 127 subsets changed"
        );
        assert_eq!(buckets.values().sum::<usize>(), 127);
        assert_eq!(
            buckets.len(),
            BatchState::ALL.len(),
            "a state is unreachable"
        );
    }

    /// The degenerate input, stated rather than assumed away.
    #[test]
    fn an_empty_member_list_has_no_state() {
        assert_eq!(roll_up(&[]), None);
        // And it is unreachable through the plan types, so the `None` arm is a
        // statement about this function rather than a state a batch can be in.
        assert_eq!(
            BatchPlan::new(batch_id(), None, Vec::new(), ConcurrencyPolicy::Sequential)
                .expect_err("an empty batch is refused"),
            BatchError::EmptyBatch
        );
    }

    /// The answer is a function of the present set, not of the sequence.
    #[test]
    fn the_answer_ignores_order_and_multiplicity() {
        for members in subsets() {
            let base = roll_up(&members).expect("non-empty");

            let mut reversed = members.clone();
            reversed.reverse();
            assert_eq!(roll_up(&reversed), Some(base), "order changed {members:?}");

            let doubled: Vec<MemberProgress> =
                members.iter().chain(members.iter()).copied().collect();
            assert_eq!(
                roll_up(&doubled),
                Some(base),
                "multiplicity changed {members:?}"
            );

            let mut heavy = members.clone();
            heavy.push(members[0]);
            heavy.push(members[members.len() - 1]);
            assert_eq!(roll_up(&heavy), Some(base), "repeats changed {members:?}");
        }
    }

    /// Hand-checked rows, so the oracle itself is anchored to stated truth
    /// rather than to a second copy of the implementation.
    #[test]
    fn the_named_cases_are_what_the_rule_says() {
        use MemberProgress::{Run, Unsubmitted};
        use RunState::{Cancelled, Completed, Failed, Ready, Running, TimedOut};

        let cases: [(&[MemberProgress], BatchState); 16] = [
            (&[Unsubmitted], BatchState::Pending),
            (&[Run(Ready)], BatchState::Pending),
            (&[Unsubmitted, Run(Ready)], BatchState::Pending),
            (&[Run(Running)], BatchState::Running),
            (&[Unsubmitted, Run(Running)], BatchState::Running),
            // A member already finished while another has not started: work is
            // under way, so the batch is running rather than pending.
            (&[Unsubmitted, Run(Completed)], BatchState::Running),
            (&[Run(Ready), Run(Failed)], BatchState::Running),
            (&[Run(Completed)], BatchState::Completed),
            (&[Run(Completed), Run(Completed)], BatchState::Completed),
            (&[Run(Cancelled)], BatchState::Cancelled),
            (&[Run(Failed)], BatchState::Failed),
            (&[Run(TimedOut)], BatchState::Failed),
            // A loss outranks everything else that ended.
            (&[Run(Completed), Run(Failed)], BatchState::Failed),
            (&[Run(Cancelled), Run(TimedOut)], BatchState::Failed),
            (
                &[Run(Completed), Run(Cancelled), Run(Failed)],
                BatchState::Failed,
            ),
            // The one ambiguous end: nothing lost, not all completed.
            (&[Run(Completed), Run(Cancelled)], BatchState::Mixed),
        ];

        for (members, expected) in cases {
            assert_eq!(
                roll_up(members),
                Some(expected),
                "{:?}",
                members.iter().map(|m| m.as_str()).collect::<Vec<_>>()
            );
        }
    }

    /// Terminality of the rollup agrees with terminality of the members.
    #[test]
    fn a_terminal_batch_is_exactly_one_whose_members_all_ended() {
        for members in subsets() {
            let state = roll_up(&members).expect("non-empty");
            assert_eq!(
                state.is_terminal(),
                members.iter().all(|member| member.is_terminal()),
                "{state} disagrees with its members about having ended"
            );
        }
    }
}

/// Construction refusals.
mod refusals {
    use super::*;

    #[test]
    fn an_empty_batch_is_refused() {
        assert_eq!(
            BatchPlan::new(batch_id(), None, Vec::new(), ConcurrencyPolicy::Sequential)
                .expect_err("refused"),
            BatchError::EmptyBatch
        );
    }

    #[test]
    fn a_batch_above_the_ceiling_is_refused_rather_than_truncated() {
        let plan = BatchPlan::new(
            batch_id(),
            None,
            keys(MAX_BATCH_MEMBERS),
            ConcurrencyPolicy::Sequential,
        )
        .expect("a maximal batch is admitted");
        assert_eq!(plan.members().len(), MAX_BATCH_MEMBERS);

        assert_eq!(
            BatchPlan::new(
                batch_id(),
                None,
                keys(MAX_BATCH_MEMBERS + 1),
                ConcurrencyPolicy::Sequential
            )
            .expect_err("refused"),
            BatchError::TooManyMembers {
                max_members: MAX_BATCH_MEMBERS,
                actual_members: MAX_BATCH_MEMBERS + 1,
            }
        );
    }

    #[test]
    fn a_repeated_member_key_is_refused() {
        let repeated = vec![key(0), key(1), key(0)];
        assert_eq!(
            BatchPlan::new(batch_id(), None, repeated, ConcurrencyPolicy::Sequential)
                .expect_err("refused"),
            BatchError::DuplicateMember { key: key(0) }
        );

        // Adjacent repeats too, so the check is not an accident of ordering.
        assert_eq!(
            BatchPlan::new(
                batch_id(),
                None,
                vec![key(7), key(7)],
                ConcurrencyPolicy::Sequential
            )
            .expect_err("refused"),
            BatchError::DuplicateMember { key: key(7) }
        );
    }

    #[test]
    fn distinct_members_keep_declaration_order() {
        let declared = vec![key(9), key(3), key(5)];
        let plan = BatchPlan::new(
            batch_id(),
            None,
            declared.clone(),
            ConcurrencyPolicy::Sequential,
        )
        .expect("valid plan");
        assert_eq!(
            plan.members(),
            declared.as_slice(),
            "a sequential policy names the declared order, so it cannot be sorted away"
        );
    }

    #[test]
    fn a_zero_concurrency_ceiling_is_refused() {
        assert_eq!(
            ConcurrencyPolicy::bounded_parallel(0).expect_err("refused"),
            BatchError::ConcurrencyCeilingZero
        );
        assert_eq!(
            ConcurrencyPolicy::bounded_parallel(1).expect("one is a ceiling"),
            ConcurrencyPolicy::BoundedParallel { max_in_flight: 1 }
        );
    }

    #[test]
    fn a_ceiling_no_batch_could_reach_is_refused() {
        let largest = u32::try_from(MAX_BATCH_MEMBERS).expect("ceiling fits u32");
        assert_eq!(
            ConcurrencyPolicy::bounded_parallel(largest).expect("the largest binding ceiling"),
            ConcurrencyPolicy::BoundedParallel {
                max_in_flight: largest
            }
        );
        assert_eq!(
            ConcurrencyPolicy::bounded_parallel(largest + 1).expect_err("refused"),
            BatchError::ConcurrencyCeilingUnreachable {
                max_members: MAX_BATCH_MEMBERS,
                requested: largest + 1,
            }
        );
        assert_eq!(
            ConcurrencyPolicy::bounded_parallel(u32::MAX).expect_err("refused"),
            BatchError::ConcurrencyCeilingUnreachable {
                max_members: MAX_BATCH_MEMBERS,
                requested: u32::MAX,
            }
        );
    }

    #[test]
    fn there_is_no_unbounded_concurrency_spelling() {
        assert_eq!(ConcurrencyKind::ALL.len(), 2);
        assert_eq!(
            ConcurrencyKind::ALL
                .into_iter()
                .map(ConcurrencyKind::as_str)
                .collect::<Vec<_>>(),
            ["sequential", "bounded_parallel"]
        );
        for spelling in ["unbounded", "unlimited", "parallel", "concurrent", ""] {
            assert_eq!(
                ConcurrencyKind::from_spelling(spelling),
                None,
                "{spelling} is not a concurrency policy"
            );
        }
        // Every policy this model can build declares a finite ceiling.
        for policy in [
            ConcurrencyPolicy::Sequential,
            ConcurrencyPolicy::bounded_parallel(4).expect("valid"),
        ] {
            assert!(policy.effective_in_flight(MAX_BATCH_MEMBERS) >= 1);
            assert!(policy.effective_in_flight(MAX_BATCH_MEMBERS) <= MAX_BATCH_MEMBERS);
        }
    }

    #[test]
    fn an_in_flight_ceiling_binds_at_the_membership() {
        let policy = ConcurrencyPolicy::bounded_parallel(64).expect("valid");
        assert_eq!(policy.effective_in_flight(0), 0);
        assert_eq!(policy.effective_in_flight(3), 3);
        assert_eq!(policy.effective_in_flight(64), 64);
        assert_eq!(policy.effective_in_flight(200), 64);

        assert_eq!(ConcurrencyPolicy::Sequential.effective_in_flight(0), 0);
        assert_eq!(ConcurrencyPolicy::Sequential.effective_in_flight(200), 1);

        let plan = BatchPlan::new(batch_id(), None, keys(3), policy).expect("valid plan");
        assert_eq!(plan.effective_in_flight(), 3);
        assert_eq!(plan.concurrency(), policy);
    }

    #[test]
    fn bad_identifiers_are_refused_at_construction() {
        assert_eq!(BatchId::new("").expect_err("empty"), ValueError::Empty);
        assert_eq!(
            BatchMemberKey::new("").expect_err("empty"),
            ValueError::Empty
        );
        assert_eq!(
            BatchMemberKey::new("has\nnewline").expect_err("control"),
            ValueError::ControlCharacter
        );
        assert_eq!(
            BatchLabel::new("bell\u{7}").expect_err("control"),
            ValueError::ControlCharacter
        );
        assert_eq!(
            BatchId::new("x".repeat(MAX_BATCH_ID_BYTES + 1)).expect_err("too long"),
            ValueError::TooLong {
                max_bytes: MAX_BATCH_ID_BYTES,
                actual_bytes: MAX_BATCH_ID_BYTES + 1,
            }
        );
        assert_eq!(
            BatchMemberKey::new("k".repeat(MAX_BATCH_MEMBER_KEY_BYTES + 1)).expect_err("too long"),
            ValueError::TooLong {
                max_bytes: MAX_BATCH_MEMBER_KEY_BYTES,
                actual_bytes: MAX_BATCH_MEMBER_KEY_BYTES + 1,
            }
        );
        assert_eq!(
            BatchLabel::new("l".repeat(MAX_BATCH_LABEL_BYTES + 1)).expect_err("too long"),
            ValueError::TooLong {
                max_bytes: MAX_BATCH_LABEL_BYTES,
                actual_bytes: MAX_BATCH_LABEL_BYTES + 1,
            }
        );
        // The maxima themselves are admitted, so the bound is a ceiling and not
        // an off-by-one.
        assert!(BatchId::new("x".repeat(MAX_BATCH_ID_BYTES)).is_ok());
        assert!(BatchMemberKey::new("k".repeat(MAX_BATCH_MEMBER_KEY_BYTES)).is_ok());
        assert!(BatchLabel::new("l".repeat(MAX_BATCH_LABEL_BYTES)).is_ok());
    }

    #[test]
    fn a_progress_reading_must_cover_every_member() {
        let plan = plan(3);
        let short = vec![
            BatchMember::new(key(0), MemberProgress::Unsubmitted),
            BatchMember::new(key(1), MemberProgress::Unsubmitted),
        ];
        assert_eq!(
            BatchProgress::observe(&plan, short).expect_err("refused"),
            BatchError::ProgressIncomplete {
                expected: 3,
                actual: 2,
            }
        );

        let long = (0..4)
            .map(|index| BatchMember::new(key(index), MemberProgress::Unsubmitted))
            .collect();
        assert_eq!(
            BatchProgress::observe(&plan, long).expect_err("refused"),
            BatchError::ProgressIncomplete {
                expected: 3,
                actual: 4,
            }
        );
    }

    #[test]
    fn a_progress_reading_must_line_up_with_the_plan() {
        let plan = plan(3);
        let reordered = vec![
            BatchMember::new(key(0), MemberProgress::Unsubmitted),
            BatchMember::new(key(2), MemberProgress::Unsubmitted),
            BatchMember::new(key(1), MemberProgress::Unsubmitted),
        ];
        assert_eq!(
            BatchProgress::observe(&plan, reordered).expect_err("refused"),
            BatchError::ProgressMemberMismatch { position: 1 }
        );

        let foreign = vec![
            BatchMember::new(key(0), MemberProgress::Unsubmitted),
            BatchMember::new(key(1), MemberProgress::Unsubmitted),
            BatchMember::new(key(99), MemberProgress::Unsubmitted),
        ];
        assert_eq!(
            BatchProgress::observe(&plan, foreign).expect_err("refused"),
            BatchError::ProgressMemberMismatch { position: 2 }
        );
    }

    /// Every refusal reports a distinct stable category.
    #[test]
    fn refusal_categories_are_distinct_and_prefixed() {
        let refusals = [
            BatchError::EmptyBatch,
            BatchError::TooManyMembers {
                max_members: 1,
                actual_members: 2,
            },
            BatchError::DuplicateMember { key: key(0) },
            BatchError::ConcurrencyCeilingZero,
            BatchError::ConcurrencyCeilingUnreachable {
                max_members: 1,
                requested: 2,
            },
            BatchError::InvalidBody,
            BatchError::UnknownSchema,
            BatchError::DocumentTooLarge {
                max_bytes: 1,
                actual_bytes: 2,
            },
            BatchError::ProgressIncomplete {
                expected: 1,
                actual: 2,
            },
            BatchError::ProgressMemberMismatch { position: 0 },
            BatchError::RollupContradictsMembers {
                carried: BatchState::Completed,
                derived: BatchState::Failed,
            },
            BatchError::Field {
                field: "batch_id",
                error: ValueError::Empty,
            },
        ];
        let mut categories: Vec<&str> = refusals.iter().map(BatchError::category).collect();
        let total = categories.len();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(categories.len(), total, "two refusals share a category");
        for refusal in &refusals {
            assert!(
                !refusal.to_string().is_empty(),
                "{refusal:?} renders as nothing"
            );
        }
    }
}

/// Documents: deterministic rendering, round trip, and refusal on read.
mod documents {
    use super::*;

    fn full_plan() -> BatchPlan {
        BatchPlan::new(
            batch_id(),
            Some(BatchLabel::new("nightly evaluation").expect("valid label")),
            keys(4),
            ConcurrencyPolicy::bounded_parallel(2).expect("valid policy"),
        )
        .expect("valid plan")
    }

    #[test]
    fn a_plan_round_trips_through_canonical_bytes() {
        let plan = full_plan();
        let bytes = plan.to_canonical_bytes();
        let decoded = BatchPlan::from_canonical_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, plan);
        assert_eq!(
            decoded.to_canonical_bytes(),
            bytes,
            "encoding is not stable"
        );
    }

    #[test]
    fn a_plan_without_a_label_round_trips_too() {
        let plan = plan(2);
        let decoded = BatchPlan::from_canonical_bytes(&plan.to_canonical_bytes()).expect("decodes");
        assert_eq!(decoded, plan);
        assert_eq!(decoded.label(), None);
    }

    #[test]
    fn progress_round_trips_and_carries_the_derived_state() {
        let plan = full_plan();
        let progress = observed(
            &plan,
            &[
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Run(RunState::Running),
                MemberProgress::Unsubmitted,
                MemberProgress::Run(RunState::Failed),
            ],
        );
        assert_eq!(progress.state(), BatchState::Running);
        assert_eq!(progress.batch_id(), plan.id());

        let bytes = progress.to_canonical_bytes();
        let decoded = BatchProgress::from_canonical_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, progress);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn rendering_is_deterministic_regardless_of_how_the_value_was_built() {
        let left = full_plan();
        let right = BatchPlan::new(
            BatchId::new("nightly-eval-1").expect("valid"),
            Some(BatchLabel::new("nightly evaluation").expect("valid")),
            keys(4),
            ConcurrencyPolicy::bounded_parallel(2).expect("valid"),
        )
        .expect("valid plan");
        assert_eq!(left.to_canonical_bytes(), right.to_canonical_bytes());

        // The bytes really are canonical: the parser refuses anything that is
        // not, so a successful re-parse is the statement.
        parse_canonical(&left.to_canonical_bytes()).expect("canonical");
        let text = String::from_utf8(left.to_canonical_bytes()).expect("utf-8");
        assert!(
            text.contains("\"schema\":\"automonique.batch/v1\""),
            "{text}"
        );
        assert!(
            text.starts_with("{\"batch_id\":"),
            "keys are sorted: {text}"
        );
    }

    #[test]
    fn an_unknown_member_state_spelling_is_refused_on_read() {
        let plan = plan(1);
        let progress = observed(&plan, &[MemberProgress::Run(RunState::Completed)]);
        let text = String::from_utf8(progress.to_canonical_bytes()).expect("utf-8");
        let tampered = text.replace("\"state\":\"completed\"", "\"state\":\"finished\"");
        assert_ne!(tampered, text, "the fixture must actually change");

        assert_eq!(
            BatchProgress::from_canonical_bytes(tampered.as_bytes()).expect_err("refused"),
            BatchError::Codec(CodecError::UnknownEnumValue { field: "state" })
        );
    }

    #[test]
    fn an_unknown_batch_state_spelling_is_refused_on_read() {
        let plan = plan(1);
        let progress = observed(&plan, &[MemberProgress::Run(RunState::Completed)]);
        let document = match progress.to_document() {
            JsonValue::Object(mut entries) => {
                for (name, value) in &mut entries {
                    if name == "state" {
                        *value = JsonValue::String("done".to_owned());
                    }
                }
                JsonValue::Object(entries)
            }
            other => panic!("a progress document is an object: {other:?}"),
        };
        assert_eq!(
            BatchProgress::from_document(&document).expect_err("refused"),
            BatchError::Codec(CodecError::UnknownEnumValue { field: "state" })
        );
    }

    #[test]
    fn a_document_that_contradicts_its_own_members_is_refused() {
        let plan = plan(2);
        let progress = observed(
            &plan,
            &[
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Run(RunState::Failed),
            ],
        );
        assert_eq!(progress.state(), BatchState::Failed);

        let document = match progress.to_document() {
            JsonValue::Object(mut entries) => {
                for (name, value) in &mut entries {
                    if name == "state" {
                        *value = JsonValue::String("completed".to_owned());
                    }
                }
                JsonValue::Object(entries)
            }
            other => panic!("a progress document is an object: {other:?}"),
        };
        assert_eq!(
            BatchProgress::from_document(&document).expect_err("refused"),
            BatchError::RollupContradictsMembers {
                carried: BatchState::Completed,
                derived: BatchState::Failed,
            }
        );
    }

    #[test]
    fn a_malformed_concurrency_policy_is_refused() {
        let parallel = full_plan();
        let text = String::from_utf8(parallel.to_canonical_bytes()).expect("utf-8");

        // A bounded-parallel policy with no ceiling is not "unbounded"; it is a
        // document this build does not define.
        let ceilingless = text.replace("\"max_in_flight\":2", "\"max_in_flight\":null");
        assert_ne!(ceilingless, text);
        assert_eq!(
            BatchPlan::from_canonical_bytes(ceilingless.as_bytes()).expect_err("refused"),
            BatchError::InvalidBody
        );

        // A sequential policy carrying a ceiling contradicts itself.
        let sequential = plan(2);
        let sequential_text = String::from_utf8(sequential.to_canonical_bytes()).expect("utf-8");
        let contradictory =
            sequential_text.replace("\"max_in_flight\":null", "\"max_in_flight\":4");
        assert_ne!(contradictory, sequential_text);
        assert_eq!(
            BatchPlan::from_canonical_bytes(contradictory.as_bytes()).expect_err("refused"),
            BatchError::InvalidBody
        );

        // An unknown kind fails closed rather than defaulting.
        let unknown = text.replace("\"kind\":\"bounded_parallel\"", "\"kind\":\"unbounded\"");
        assert_ne!(unknown, text);
        assert_eq!(
            BatchPlan::from_canonical_bytes(unknown.as_bytes()).expect_err("refused"),
            BatchError::Codec(CodecError::UnknownEnumValue { field: "kind" })
        );

        // A zero ceiling on the wire is refused by the same constructor rule.
        let zero = text.replace("\"max_in_flight\":2", "\"max_in_flight\":0");
        assert_eq!(
            BatchPlan::from_canonical_bytes(zero.as_bytes()).expect_err("refused"),
            BatchError::ConcurrencyCeilingZero
        );
    }

    #[test]
    fn a_foreign_or_missing_schema_is_refused() {
        let plan = full_plan();
        let text = String::from_utf8(plan.to_canonical_bytes()).expect("utf-8");
        let foreign = text.replace(BATCH_SCHEMA_V1, "automonique.batch/v2");
        assert_ne!(foreign, text);
        assert_eq!(
            BatchPlan::from_canonical_bytes(foreign.as_bytes()).expect_err("refused"),
            BatchError::UnknownSchema
        );

        // A body missing a field is not a body with a default.
        let dropped = JsonValue::Object(vec![(
            "schema".to_owned(),
            JsonValue::String(BATCH_SCHEMA_V1.to_owned()),
        )]);
        assert_eq!(
            BatchPlan::from_document(&dropped).expect_err("refused"),
            BatchError::InvalidBody
        );
    }

    #[test]
    fn a_document_with_repeated_members_is_refused_on_read() {
        let progress = observed(&plan(2), &[MemberProgress::Unsubmitted; 2]);
        let text = String::from_utf8(progress.to_canonical_bytes()).expect("utf-8");
        let repeated = text.replace("operator:batch:1", "operator:batch:0");
        assert_ne!(repeated, text);
        assert_eq!(
            BatchProgress::from_canonical_bytes(repeated.as_bytes()).expect_err("refused"),
            BatchError::DuplicateMember { key: key(0) }
        );

        let plan_text = String::from_utf8(plan(2).to_canonical_bytes()).expect("utf-8");
        let repeated_plan = plan_text.replace("operator:batch:1", "operator:batch:0");
        assert_eq!(
            BatchPlan::from_canonical_bytes(repeated_plan.as_bytes()).expect_err("refused"),
            BatchError::DuplicateMember { key: key(0) }
        );
    }

    #[test]
    fn an_empty_members_array_is_refused_on_read() {
        let empty_plan = JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String("nightly-eval-1".to_owned()),
            ),
            ("concurrency".to_owned(), plan(1).concurrency_document()),
            ("label".to_owned(), JsonValue::Null),
            ("members".to_owned(), JsonValue::Array(Vec::new())),
            (
                "schema".to_owned(),
                JsonValue::String(BATCH_SCHEMA_V1.to_owned()),
            ),
        ]);
        assert_eq!(
            BatchPlan::from_document(&empty_plan).expect_err("refused"),
            BatchError::EmptyBatch
        );

        let empty_progress = JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String("nightly-eval-1".to_owned()),
            ),
            ("members".to_owned(), JsonValue::Array(Vec::new())),
            (
                "schema".to_owned(),
                JsonValue::String(BATCH_SCHEMA_V1.to_owned()),
            ),
            ("state".to_owned(), JsonValue::String("pending".to_owned())),
        ]);
        assert_eq!(
            BatchProgress::from_document(&empty_progress).expect_err("refused"),
            BatchError::EmptyBatch
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_before_it_is_parsed() {
        let payload = vec![b'x'; MAX_BATCH_CANONICAL_BYTES + 1];
        assert_eq!(
            BatchPlan::from_canonical_bytes(&payload).expect_err("refused"),
            BatchError::DocumentTooLarge {
                max_bytes: MAX_BATCH_CANONICAL_BYTES,
                actual_bytes: MAX_BATCH_CANONICAL_BYTES + 1,
            }
        );
        assert_eq!(
            BatchProgress::from_canonical_bytes(&payload).expect_err("refused"),
            BatchError::DocumentTooLarge {
                max_bytes: MAX_BATCH_CANONICAL_BYTES,
                actual_bytes: MAX_BATCH_CANONICAL_BYTES + 1,
            }
        );
    }

    /// A batch at every ceiling, with keys and a label at theirs, still fits.
    #[test]
    fn a_maximal_batch_fits_the_document_ceiling() {
        // Keys built from quotes, which JSON-escapes to two bytes each, with a
        // distinct decimal tail so the membership stays distinct.
        let members: Vec<BatchMemberKey> = (0..MAX_BATCH_MEMBERS)
            .map(|index| {
                let tail = format!("{index:03}");
                let padding = "\"".repeat(MAX_BATCH_MEMBER_KEY_BYTES - tail.len());
                BatchMemberKey::new(format!("{padding}{tail}")).expect("valid key")
            })
            .collect();
        let plan = BatchPlan::new(
            BatchId::new("b".repeat(MAX_BATCH_ID_BYTES)).expect("valid id"),
            Some(BatchLabel::new("l".repeat(MAX_BATCH_LABEL_BYTES)).expect("valid label")),
            members.clone(),
            ConcurrencyPolicy::bounded_parallel(
                u32::try_from(MAX_BATCH_MEMBERS).expect("fits u32"),
            )
            .expect("valid policy"),
        )
        .expect("valid plan");

        let plan_bytes = plan.to_canonical_bytes();
        println!(
            "maximal plan: {} of {MAX_BATCH_CANONICAL_BYTES} bytes",
            plan_bytes.len()
        );
        assert!(plan_bytes.len() <= MAX_BATCH_CANONICAL_BYTES);
        assert_eq!(
            BatchPlan::from_canonical_bytes(&plan_bytes).expect("decodes"),
            plan
        );

        let progress = BatchProgress::observe(
            &plan,
            members
                .into_iter()
                .map(|key| BatchMember::new(key, MemberProgress::Run(RunState::TimedOut)))
                .collect(),
        )
        .expect("valid progress");
        assert_eq!(progress.state(), BatchState::Failed);

        let progress_bytes = progress.to_canonical_bytes();
        println!(
            "maximal progress: {} of {MAX_BATCH_CANONICAL_BYTES} bytes",
            progress_bytes.len()
        );
        assert!(progress_bytes.len() <= MAX_BATCH_CANONICAL_BYTES);
        assert_eq!(
            BatchProgress::from_canonical_bytes(&progress_bytes).expect("decodes"),
            progress
        );
    }
}

/// A helper the document tests use to build a policy body without reaching into
/// the module's private encoder.
trait ConcurrencyDocument {
    fn concurrency_document(&self) -> JsonValue;
}

impl ConcurrencyDocument for BatchPlan {
    fn concurrency_document(&self) -> JsonValue {
        match self.to_document() {
            JsonValue::Object(entries) => entries
                .into_iter()
                .find(|(name, _)| name == "concurrency")
                .map(|(_, value)| value)
                .expect("a plan document carries its concurrency"),
            other => panic!("a plan document is an object: {other:?}"),
        }
    }
}
