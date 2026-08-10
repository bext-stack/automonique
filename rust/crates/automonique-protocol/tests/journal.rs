// SPDX-License-Identifier: Elastic-2.0

//! R1-12 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-12.md`.

use automonique_protocol::codec::{MajorVersion, VersionRange};
use automonique_protocol::journal::{
    ActionLedger, ActionOutcome, AggregateId, DomainEvent, EventSchemaVersion, Journal,
    JournalCursor, JournalError, Projection,
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

    /// A receipt owns its data.
    ///
    /// `ActionReceipt` has no lifetime parameter, so it cannot borrow from a
    /// connection. The compile-fail case lives in the library doc tests where
    /// it executes; this pins the positive half.
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
