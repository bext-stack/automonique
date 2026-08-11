// SPDX-License-Identifier: Elastic-2.0

//! R1-12 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-12.md`.

use automonique_protocol::codec::{MajorVersion, VersionRange};
use automonique_protocol::journal::{
    ActionLedger, ActionOutcome, ActionPayload, AggregateId, CursorResume, DomainEvent,
    EventSchemaVersion, Journal, JournalCursor, JournalError, Projection, RetainedRange,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn aggregate(id: &str) -> AggregateId {
    AggregateId::new("work", id).expect("valid aggregate")
}

fn schema(version: u32) -> EventSchemaVersion {
    EventSchemaVersion::new(version).expect("non-zero schema version")
}

fn event(event_id: u64, aggregate_id: &str, revision: u64, schema_version: u32) -> DomainEvent {
    DomainEvent::new(
        event_id,
        aggregate(aggregate_id),
        Revision::new(revision).expect("non-zero revision"),
        schema(schema_version),
        EpochMillis::from_millis(i64::try_from(event_id).expect("small id")),
        "changed",
    )
    .expect("valid event")
}

fn range(min: u32, max: u32) -> VersionRange {
    VersionRange::new(
        MajorVersion::new(min).expect("non-zero"),
        MajorVersion::new(max).expect("non-zero"),
    )
    .expect("ordered range")
}

mod global_ordering {
    use super::*;

    #[test]
    fn event_identifiers_strictly_increase_across_the_journal() {
        let mut journal = Journal::new();
        journal.append(event(1, "w-1", 1, 1)).expect("first");
        journal.append(event(2, "w-2", 1, 1)).expect("second");

        for offered in [2, 1, 0] {
            assert_eq!(
                journal
                    .append(event(offered, "w-3", 1, 1))
                    .expect_err("not increasing"),
                JournalError::EventIdNotIncreasing { last: 2, offered }
            );
        }
        journal
            .append(event(3, "w-3", 1, 1))
            .expect("strictly greater");
        assert_eq!(journal.events().len(), 3);
    }

    #[test]
    fn a_refused_append_leaves_the_journal_unchanged() {
        let mut journal = Journal::new();
        journal.append(event(5, "w-1", 1, 1)).expect("first");
        assert!(journal.append(event(5, "w-2", 1, 1)).is_err());
        assert_eq!(journal.events().len(), 1);
    }
}

mod revision_algebra {
    use super::*;

    #[test]
    fn revisions_start_at_the_first_and_increase_by_exactly_one() {
        let mut journal = Journal::new();
        journal
            .append(event(1, "w-1", 1, 1))
            .expect("first revision");
        journal.append(event(2, "w-1", 2, 1)).expect("successor");
        journal.append(event(3, "w-1", 3, 1)).expect("successor");
        assert_eq!(
            journal.revision_of(&aggregate("w-1")).expect("known").get(),
            3
        );
    }

    #[test]
    fn a_non_successor_append_conflicts_naming_expected_and_observed() {
        let mut journal = Journal::new();
        journal.append(event(1, "w-1", 1, 1)).expect("first");

        // Skipping a revision, and repeating one, are both conflicts.
        assert_eq!(
            journal.append(event(2, "w-1", 3, 1)).expect_err("gap"),
            JournalError::RevisionConflict {
                expected: 2,
                observed: 3,
            }
        );
        assert_eq!(
            journal.append(event(2, "w-1", 1, 1)).expect_err("repeat"),
            JournalError::RevisionConflict {
                expected: 2,
                observed: 1,
            }
        );
    }

    #[test]
    fn a_first_event_must_use_the_first_revision() {
        let mut journal = Journal::new();
        assert_eq!(
            journal
                .append(event(1, "fresh", 7, 1))
                .expect_err("not first"),
            JournalError::RevisionConflict {
                expected: 1,
                observed: 7,
            }
        );
    }

    #[test]
    fn revisions_are_tracked_per_aggregate_not_globally() {
        let mut journal = Journal::new();
        journal.append(event(1, "w-1", 1, 1)).expect("w-1 first");
        // A different aggregate starts again at the first revision.
        journal.append(event(2, "w-2", 1, 1)).expect("w-2 first");
        journal.append(event(3, "w-1", 2, 1)).expect("w-1 second");

        assert_eq!(
            journal.revision_of(&aggregate("w-1")).expect("known").get(),
            2
        );
        assert_eq!(
            journal.revision_of(&aggregate("w-2")).expect("known").get(),
            1
        );
        assert!(journal.revision_of(&aggregate("absent")).is_none());
    }
}

mod schema_independence {
    use super::*;

    #[test]
    fn an_event_decode_range_is_declared_independently_and_fails_closed() {
        let readable = range(2, 4);
        event(1, "w-1", 1, 3)
            .decodable_within(readable)
            .expect("inside the range");

        for version in [1, 5] {
            let error = event(1, "w-1", 1, version)
                .decodable_within(readable)
                .expect_err("outside the range");
            assert_eq!(
                error,
                JournalError::EventSchemaOutOfRange {
                    supported_min: 2,
                    supported_max: 4,
                    offered: version,
                }
            );
        }
    }

    #[test]
    fn the_boundaries_of_the_decode_range_are_inclusive() {
        let readable = range(2, 4);
        for version in [2, 3, 4] {
            event(1, "w-1", 1, version)
                .decodable_within(readable)
                .expect("inclusive boundary");
        }
    }

    #[test]
    fn a_zero_event_schema_version_is_refused() {
        assert_eq!(
            EventSchemaVersion::new(0).expect_err("zero").category(),
            "field_invalid"
        );
    }
}

mod outcome_vocabulary {
    use super::*;

    /// Every variant of `ActionOutcome`, named one at a time.
    ///
    /// Written out here rather than read back out of `ActionOutcome::ALL`,
    /// because `ALL` is exactly what these tests have to check.
    const EVERY_OUTCOME: [ActionOutcome; 6] = [
        ActionOutcome::Accepted,
        ActionOutcome::Completed,
        ActionOutcome::Rejected,
        ActionOutcome::Conflict,
        ActionOutcome::Unknown,
        ActionOutcome::ResyncRequired,
    ];

    /// The wire spelling each variant is required to keep.
    ///
    /// The match is exhaustive over `ActionOutcome`, which is what ties this
    /// file to the enum: `ALL` is a hand-written array and nothing inside the
    /// type stops a seventh variant being added without extending it, but a
    /// seventh variant makes this match non-exhaustive, so the suite stops
    /// compiling until the variant is named here — and the assertions below
    /// then require it to be present in `ALL` as well.
    fn wire_spelling(outcome: ActionOutcome) -> &'static str {
        match outcome {
            ActionOutcome::Accepted => "accepted",
            ActionOutcome::Completed => "completed",
            ActionOutcome::Rejected => "rejected",
            ActionOutcome::Conflict => "conflict",
            ActionOutcome::Unknown => "unknown",
            ActionOutcome::ResyncRequired => "resync_required",
        }
    }

    #[test]
    fn every_variant_of_the_outcome_enum_is_present_in_all() {
        for outcome in EVERY_OUTCOME {
            assert!(
                ActionOutcome::ALL.contains(&outcome),
                "{outcome:?} is a variant of ActionOutcome but is absent from \
                 ActionOutcome::ALL, so anything exhaustive over ALL silently \
                 misses it"
            );
        }
        assert_eq!(
            ActionOutcome::ALL.len(),
            EVERY_OUTCOME.len(),
            "ALL and the named variants disagree about how many outcomes exist"
        );
    }

    #[test]
    fn every_outcome_keeps_its_wire_spelling() {
        // Distinctness alone would let all six be renamed at once. These are
        // the literals a peer decodes, so they are pinned literally.
        for outcome in EVERY_OUTCOME {
            assert_eq!(
                outcome.as_str(),
                wire_spelling(outcome),
                "the wire spelling of {outcome:?} changed, so a peer that \
                 decodes the recorded spelling stops understanding it"
            );
        }
    }

    #[test]
    fn the_outcome_set_is_closed_and_every_spelling_is_distinct() {
        assert_eq!(ActionOutcome::ALL.len(), 6);
        let mut spellings: Vec<&str> = ActionOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two outcomes share a spelling");
    }

    #[test]
    fn transport_failure_and_operation_failure_are_distinct() {
        // Rejected states the effect did not happen. Unknown does not know.
        assert!(ActionOutcome::Rejected.states_no_effect());
        assert!(ActionOutcome::Conflict.states_no_effect());
        assert!(
            !ActionOutcome::Unknown.states_no_effect(),
            "treating a transport failure as an operation failure is how a \
             duplicate effect gets issued"
        );
        assert_ne!(ActionOutcome::Rejected, ActionOutcome::Unknown);
    }

    #[test]
    fn accepted_and_completed_are_not_the_same_outcome() {
        assert_ne!(ActionOutcome::Accepted, ActionOutcome::Completed);
        assert!(!ActionOutcome::Accepted.states_no_effect());
        assert!(!ActionOutcome::Completed.states_no_effect());
    }
}

mod idempotency_exactness {
    use super::*;

    fn payload(digest: &str) -> ActionPayload {
        ActionPayload::digest(digest).expect("valid digest")
    }

    #[test]
    fn the_same_key_and_target_replay_to_the_identical_receipt() {
        let mut ledger = ActionLedger::new();
        let first = ledger
            .record(
                "a-1",
                "work/w-1",
                "key-1",
                Some(Revision::FIRST),
                ActionOutcome::Accepted,
            )
            .expect("first record");
        // A replay carrying a different action id and outcome still returns the
        // original receipt: the key decides, not the caller's second opinion.
        let replay = ledger
            .record("a-2", "work/w-1", "key-1", None, ActionOutcome::Completed)
            .expect("replay");
        assert_eq!(first, replay);
        assert_eq!(replay.action_id(), "a-1");
        assert_eq!(replay.outcome(), ActionOutcome::Accepted);
    }

    #[test]
    fn the_same_key_against_a_different_target_is_a_conflict() {
        let mut ledger = ActionLedger::new();
        ledger
            .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
            .expect("first");
        assert_eq!(
            ledger
                .record("a-1", "work/w-2", "key-1", None, ActionOutcome::Accepted)
                .expect_err("retargeted"),
            JournalError::IdempotencyConflict {
                recorded_target: "work/w-1".to_owned(),
                offered_target: "work/w-2".to_owned(),
            }
        );
        // The original stands.
        assert_eq!(
            ledger.find("key-1").expect("still recorded").target(),
            "work/w-1"
        );
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut ledger = ActionLedger::new();
        ledger
            .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Completed)
            .expect("first");
        let second = ledger
            .record("a-2", "work/w-2", "key-2", None, ActionOutcome::Rejected)
            .expect("second");
        assert_eq!(second.outcome(), ActionOutcome::Rejected);
        assert_eq!(ledger.find("key-1").expect("found").target(), "work/w-1");
    }

    #[test]
    fn the_same_key_target_and_payload_replay_to_the_identical_receipt() {
        let mut ledger = ActionLedger::new();
        let first = ledger
            .record_with_payload(
                "a-1",
                "work/w-1",
                "key-1",
                Some(Revision::FIRST),
                payload("sha256:aaa"),
                ActionOutcome::Accepted,
            )
            .expect("first record");
        let replay = ledger
            .record_with_payload(
                "a-2",
                "work/w-1",
                "key-1",
                None,
                payload("sha256:aaa"),
                ActionOutcome::Completed,
            )
            .expect("replay");
        assert_eq!(first, replay);
        assert_eq!(replay.payload().as_digest(), Some("sha256:aaa"));
    }

    #[test]
    fn the_same_key_with_a_different_payload_is_a_conflict() {
        let mut ledger = ActionLedger::new();
        ledger
            .record_with_payload(
                "a-1",
                "work/w-1",
                "key-1",
                None,
                payload("sha256:aaa"),
                ActionOutcome::Accepted,
            )
            .expect("first");
        // Same key, same target, changed payload: a changed request, so it is
        // refused rather than overwriting or executing a second time.
        assert_eq!(
            ledger
                .record_with_payload(
                    "a-1",
                    "work/w-1",
                    "key-1",
                    None,
                    payload("sha256:bbb"),
                    ActionOutcome::Accepted,
                )
                .expect_err("changed payload"),
            JournalError::IdempotencyPayloadConflict {
                recorded_payload: payload("sha256:aaa"),
                offered_payload: payload("sha256:bbb"),
            }
        );
        // The original stands.
        assert_eq!(
            ledger
                .find("key-1")
                .expect("still recorded")
                .payload()
                .as_digest(),
            Some("sha256:aaa")
        );
    }

    #[test]
    fn a_payload_cannot_appear_under_a_key_recorded_without_one() {
        let mut ledger = ActionLedger::new();
        ledger
            .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
            .expect("first");
        assert_eq!(
            ledger
                .record_with_payload(
                    "a-1",
                    "work/w-1",
                    "key-1",
                    None,
                    payload("sha256:aaa"),
                    ActionOutcome::Accepted,
                )
                .expect_err("payload appeared under a payload-free key"),
            JournalError::IdempotencyPayloadConflict {
                recorded_payload: ActionPayload::absent(),
                offered_payload: payload("sha256:aaa"),
            }
        );
    }

    #[test]
    fn absence_and_an_empty_digest_do_not_share_a_spelling() {
        // If an empty digest were constructible it would be indistinguishable
        // from "carried nothing", and a changed request would replay clean.
        assert_eq!(
            ActionPayload::digest("").expect_err("empty").category(),
            "field_invalid"
        );
        assert_eq!(ActionPayload::absent().as_digest(), None);
        assert_ne!(ActionPayload::absent(), payload("sha256:aaa"));
    }
}

mod receipt_durability {
    use super::*;

    #[test]
    fn a_receipt_outlives_the_request_that_produced_it() {
        let mut ledger = ActionLedger::new();
        {
            // A short-lived scope stands in for a client connection.
            let target = String::from("work/w-1");
            ledger
                .record("a-1", &target, "key-1", None, ActionOutcome::Completed)
                .expect("recorded");
        }
        let found = ledger.find("key-1").expect("queryable after disconnect");
        assert_eq!(found.target(), "work/w-1");
        assert_eq!(found.outcome(), ActionOutcome::Completed);
    }

    #[test]
    fn a_lookup_answers_for_the_key_it_was_given() {
        let mut ledger = ActionLedger::new();
        ledger
            .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
            .expect("first");
        ledger
            .record("a-2", "work/w-2", "key-2", None, ActionOutcome::Completed)
            .expect("second");

        // Everything else in this file that reads a receipt back reads it
        // through `find`, and every one of those reads would be satisfied by a
        // lookup that returned an arbitrary recorded receipt. The key has to
        // decide which one comes back, and an unrecorded key has to come back
        // empty rather than borrowing somebody else's answer.
        let second = ledger.find("key-2").expect("key-2 was recorded");
        assert_eq!(second.action_id(), "a-2");
        assert_eq!(second.target(), "work/w-2");
        assert_eq!(second.outcome(), ActionOutcome::Completed);

        let first = ledger.find("key-1").expect("key-1 was recorded");
        assert_eq!(first.action_id(), "a-1");
        assert_eq!(first.target(), "work/w-1");

        assert!(
            ledger.find("key-3").is_none(),
            "an unrecorded key resolved to some other receipt"
        );
    }

    /// A receipt owns its data.
    ///
    /// `ActionReceipt` takes no lifetime argument, so a receipt that borrows
    /// from a connection cannot be named at all. That is the compile-fail case
    /// on `ActionReceipt` itself — a `Session<'connection>` holding an
    /// `ActionReceipt<'connection>` — paired with the passing case that differs
    /// from it only in that lifetime. This test pins the runtime half.
    #[test]
    fn a_receipt_is_clonable_and_owns_every_field() {
        let mut ledger = ActionLedger::new();
        let receipt = ledger
            .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
            .expect("recorded");
        let owned = receipt.clone();
        drop(ledger);
        assert_eq!(owned.idempotency_key(), "key-1");
        assert_eq!(owned.action_id(), "a-1");
    }
}

mod cursor_monotonicity {
    use super::*;

    #[test]
    fn cursors_advance_only_forward() {
        let mut cursor = JournalCursor::new("projector", "work", 10).expect("valid");
        cursor.advance_to(15).expect("forward");
        cursor.advance_to(15).expect("idempotent");
        assert_eq!(
            cursor.advance_to(14).expect_err("backwards"),
            JournalError::CursorWentBackwards {
                current: 15,
                offered: 14,
            }
        );
        assert_eq!(cursor.position(), 15, "a refusal does not move the cursor");
    }

    #[test]
    fn a_cursor_requires_a_consumer_and_a_topic() {
        assert!(JournalCursor::new("", "work", 0).is_err());
        assert!(JournalCursor::new("projector", "", 0).is_err());
    }

    #[test]
    fn cursors_are_keyed_by_consumer_identity_and_topic() {
        let projector = JournalCursor::new("projector", "work", 10).expect("valid");
        assert_eq!(projector.consumer(), "projector");
        assert_eq!(projector.topic(), "work");
        assert_ne!(
            projector,
            JournalCursor::new("auditor", "work", 10).expect("valid"),
            "two consumers on one topic are not one cursor"
        );
        assert_ne!(
            projector,
            JournalCursor::new("projector", "runs", 10).expect("valid"),
            "one consumer on two topics is not one cursor"
        );
    }

    #[test]
    fn an_out_of_range_cursor_yields_resync_with_snapshot_coordinates() {
        let retained = RetainedRange::new(100, 400).expect("ordered window");
        let stale = JournalCursor::new("projector", "work", 42).expect("valid");

        let resume = stale.resume_within(retained);
        assert_eq!(
            resume,
            CursorResume::ResyncRequired {
                snapshot_from: 100,
                snapshot_to: 400,
            },
            "a cursor below retention must be told where to catch up from"
        );
        assert_eq!(resume.outcome(), Some(ActionOutcome::ResyncRequired));
        assert_eq!(
            resume.outcome().expect("terminal outcome").as_str(),
            "resync_required"
        );
    }

    #[test]
    fn a_retained_cursor_resumes_live_at_its_own_position() {
        let retained = RetainedRange::new(100, 400).expect("ordered window");
        for position in [100, 250, 400] {
            let cursor = JournalCursor::new("projector", "work", position).expect("valid");
            assert_eq!(
                cursor.resume_within(retained),
                CursorResume::Live { from: position }
            );
            assert_eq!(
                cursor.resume_within(retained).outcome(),
                None,
                "live delivery is not a terminal outcome"
            );
        }
        // One position below the window is already outside it.
        let stale = JournalCursor::new("projector", "work", 99).expect("valid");
        assert!(matches!(
            stale.resume_within(retained),
            CursorResume::ResyncRequired { .. }
        ));
    }

    /// A cursor above the retained window resumes live.
    ///
    /// This is the implemented reading of the contract sentence "a cursor
    /// outside the retained range yields `resync_required`": `resume_within`
    /// reads "outside" as "below". Under the literal reading, position 401 is
    /// outside `100..=400` and would resync, so this test encodes the opposite
    /// of the contract's wording and does so deliberately — `position` is the
    /// *next* position the consumer will receive, so `last + 1` is the ordinary
    /// caught-up state and resyncing it would demand a snapshot of history the
    /// consumer already has. `event::resolve_subscription` applies the same
    /// rule. The evidence file records the Cursor monotonicity row as not
    /// closed on account of the difference rather than treating this test as
    /// settling it.
    #[test]
    fn a_caught_up_cursor_is_live_rather_than_a_resync() {
        let retained = RetainedRange::new(100, 400).expect("ordered window");
        let cursor = JournalCursor::new("projector", "work", 401).expect("valid");
        assert_eq!(
            cursor.resume_within(retained),
            CursorResume::Live { from: 401 }
        );
    }

    #[test]
    fn a_retained_range_that_retains_nothing_cannot_be_built() {
        assert_eq!(
            RetainedRange::new(400, 100).expect_err("inverted"),
            JournalError::InvertedRetainedRange { from: 400, to: 100 }
        );
        // A window holding a single position is legitimate and inclusive.
        let single = RetainedRange::new(400, 400).expect("ordered");
        assert_eq!((single.first(), single.last()), (400, 400));
    }
}

mod replay_purity {
    use super::*;

    #[derive(Default)]
    struct Ledger {
        seen: Vec<u64>,
    }

    impl Projection for Ledger {
        fn apply(&mut self, event: &DomainEvent) {
            self.seen.push(event.event_id());
        }
    }

    #[test]
    fn replay_rebuilds_a_projection_in_global_order() {
        let mut journal = Journal::new();
        journal.append(event(1, "w-1", 1, 1)).expect("first");
        journal.append(event(2, "w-2", 1, 1)).expect("second");
        journal.append(event(3, "w-1", 2, 1)).expect("third");

        let mut projection = Ledger::default();
        journal.replay(&mut projection);
        assert_eq!(projection.seen, vec![1, 2, 3]);
    }

    #[test]
    fn replay_is_repeatable_and_changes_nothing() {
        let mut journal = Journal::new();
        journal.append(event(1, "w-1", 1, 1)).expect("first");
        let before = journal.clone();

        for _ in 0..3 {
            let mut projection = Ledger::default();
            journal.replay(&mut projection);
            assert_eq!(projection.seen, vec![1]);
        }
        assert_eq!(journal, before, "replay mutated the journal");
    }
}
