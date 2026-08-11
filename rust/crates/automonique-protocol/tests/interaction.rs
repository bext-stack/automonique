// SPDX-License-Identifier: Elastic-2.0

//! R1-25 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-25.md`.

use automonique_protocol::interaction::{
    AttemptLineage, AttemptRef, CancelRequest, CancelScope, CheckpointLog, CheckpointRef,
    CommandId, CommandInvocation, CommandParameter, ComponentUsage, CompressionOperation,
    CompressionParts, ContentDigest, ContextComponentClass, CreateCheckpoint, Delivery,
    EstimatedTokens, ExtensionId, InputQueue, IntentEffect, IntentLedger, InteractionError,
    InteractionText, ListCheckpoints, MAX_PROTECTED_FACTS, MAX_QUEUED_ITEMS, MissingCountReason,
    NamespacedKey, NamespacedProjection, ProjectionAction, QueueItemId, QueuePosition, QueuedInput,
    ReorderRequest, ReportedCount, ReportedTokens, RequestKind, RequestRef, RequiredAuthority,
    RestoreCheckpoint, RetryRequest, SessionRef, SteerRequest, SurfaceKind, SurfaceProjection,
    Transcript, TranscriptEntry, TranscriptEntryId, TranscriptRange, TurnContextUsage, TurnRef,
    UndoRequest, UndoTarget, UndoTargetKind, VerificationStatus, authorize, derive_view,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn session() -> SessionRef {
    SessionRef::new("s-1").expect("valid session")
}

fn item(id: &str) -> QueueItemId {
    QueueItemId::new(id).expect("valid queue item")
}

fn text(value: &str) -> InteractionText {
    InteractionText::new(value).expect("valid text")
}

fn steer(value: &str) -> RequestKind {
    RequestKind::Steer(SteerRequest::new(text(value)))
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::new(value).expect("valid digest")
}

fn queued(id: &str, position: u32, request: RequestKind) -> QueuedInput {
    QueuedInput::new(item(id), session(), QueuePosition::new(position), request)
}

fn queue_of(ids: &[&str]) -> InputQueue {
    let mut items = Vec::with_capacity(ids.len());
    for (index, id) in ids.iter().enumerate() {
        let position = u32::try_from(index).expect("index fits a position");
        items.push(queued(id, position, steer("go")));
    }
    InputQueue::new(session(), items).expect("valid queue")
}

fn identities(queue: &InputQueue) -> Vec<String> {
    queue
        .identities()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect()
}

fn full_usage() -> Vec<ComponentUsage> {
    ContextComponentClass::ALL
        .into_iter()
        .map(|class| {
            ComponentUsage::new(
                class,
                Some(EstimatedTokens::new(10)),
                ReportedCount::Reported(ReportedTokens::new(20)),
            )
        })
        .collect()
}

fn compression_parts<'a>(source: TranscriptRange, facts: &'a [&'a str]) -> CompressionParts<'a> {
    CompressionParts {
        source,
        compressor_provider: "provider-a",
        compressor_model: "model-a",
        prompt_digest: digest("sha256:prompt"),
        output_digest: digest("sha256:output"),
        protected_facts: facts,
        verification: VerificationStatus::Verified,
    }
}

fn transcript_of(revisions: &[u64]) -> Transcript {
    let mut transcript = Transcript::new();
    for value in revisions {
        transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new(format!("e-{value}")).expect("valid entry id"),
                revision(*value),
                digest(&format!("sha256:{value}")),
            ))
            .expect("advancing revision");
    }
    transcript
}

mod queue_identity {
    use super::*;

    #[test]
    fn a_queued_item_is_durable_rather_than_an_in_memory_prompt_string() {
        let queue = queue_of(&["q-a", "q-b"]);
        let first = &queue.items()[0];
        assert_eq!(first.id().as_str(), "q-a");
        assert_eq!(first.session(), &session());
        assert_eq!(first.position(), QueuePosition::FIRST);
        assert_eq!(first.request().kind(), "steer");
        assert_eq!(queue.session(), &session());
    }

    #[test]
    fn the_five_request_kinds_are_not_interchangeable() {
        let undo_target = UndoTarget::new(UndoTargetKind::FileEdit, text("src/main.rs"))
            .expect("a file edit is reversible");
        let kinds = [
            steer("prefer the smaller diff"),
            RequestKind::Retry(RetryRequest::derive(
                AttemptLineage::root(AttemptRef::new("a-1").expect("valid attempt")),
                AttemptRef::new("a-2").expect("valid attempt"),
                text("provider timed out"),
            )),
            RequestKind::Reorder(ReorderRequest::new(item("q-a"), QueuePosition::FIRST)),
            RequestKind::Cancel(CancelRequest::new(
                RequestRef::new("r-1").expect("valid request"),
                CancelScope::Turn,
            )),
            RequestKind::Undo(UndoRequest::new(
                RequestRef::new("r-2").expect("valid request"),
                undo_target,
            )),
        ];

        let spellings: Vec<&str> = kinds.iter().map(RequestKind::kind).collect();
        assert_eq!(spellings, RequestKind::KINDS);

        // Each payload is reachable only through its own variant: a cancel does
        // not answer a steer's accessor, and nothing turns one into the other.
        for kind in &kinds {
            let steering = matches!(kind, RequestKind::Steer(_));
            let cancelling = matches!(kind, RequestKind::Cancel(_));
            assert!(
                !(steering && cancelling),
                "a request kind answered to two payloads"
            );
        }
        let RequestKind::Cancel(cancel) = &kinds[3] else {
            panic!("the fourth kind is a cancel");
        };
        assert_eq!(cancel.scope(), CancelScope::Turn);
        assert_eq!(cancel.request().as_str(), "r-1");
    }

    #[test]
    fn identities_are_preserved_across_reorder() {
        let queue = queue_of(&["q-a", "q-b", "q-c", "q-d"]);
        let moved = queue
            .reorder(&ReorderRequest::new(item("q-d"), QueuePosition::FIRST))
            .expect("q-d moves to the front");

        assert_eq!(
            identities(&moved),
            ["q-d", "q-a", "q-b", "q-c"],
            "reordering changes the order"
        );
        let mut before = identities(&queue);
        let mut after = identities(&moved);
        before.sort();
        after.sort();
        assert_eq!(
            before, after,
            "no identity was invented, dropped or renamed"
        );
        after.dedup();
        assert_eq!(after.len(), 4, "no identity was duplicated");

        let positions: Vec<u32> = moved
            .items()
            .iter()
            .map(|entry| entry.position().get())
            .collect();
        assert_eq!(positions, [0, 1, 2, 3], "positions stay monotonic");
    }

    #[test]
    fn reorder_cannot_invent_an_identity_or_address_a_slot_that_is_not_there() {
        let queue = queue_of(&["q-a", "q-b"]);
        let unknown = queue
            .reorder(&ReorderRequest::new(item("q-z"), QueuePosition::FIRST))
            .expect_err("q-z is not queued");
        assert_eq!(unknown.category(), "unknown_identity");

        let outside = queue
            .reorder(&ReorderRequest::new(item("q-a"), QueuePosition::new(9)))
            .expect_err("position 9 is outside a two-item queue");
        assert_eq!(outside.category(), "position_out_of_range");
    }

    #[test]
    fn empty_over_bound_and_duplicate_identity_queues_fail() {
        let empty = InputQueue::new(session(), Vec::new()).expect_err("no items");
        assert_eq!(empty.category(), "queue_empty");

        let mut over = Vec::with_capacity(MAX_QUEUED_ITEMS + 1);
        for index in 0..=MAX_QUEUED_ITEMS {
            let position = u32::try_from(index).expect("index fits a position");
            over.push(queued(&format!("q-{index}"), position, steer("go")));
        }
        let over_bound = InputQueue::new(session(), over).expect_err("one item too many");
        assert_eq!(over_bound.category(), "too_many");

        let duplicate = InputQueue::new(
            session(),
            vec![queued("q-a", 0, steer("go")), queued("q-a", 1, steer("go"))],
        )
        .expect_err("q-a occurs twice");
        assert_eq!(duplicate.category(), "duplicate_identity");
    }

    #[test]
    fn a_queued_item_cannot_be_smuggled_into_another_sessions_queue() {
        let foreign = QueuedInput::new(
            item("q-a"),
            SessionRef::new("s-2").expect("valid session"),
            QueuePosition::FIRST,
            steer("go"),
        );
        let error = InputQueue::new(session(), vec![foreign]).expect_err("foreign session");
        assert_eq!(error.category(), "session_mismatch");
    }

    #[test]
    fn position_arithmetic_is_checked() {
        assert_eq!(
            QueuePosition::FIRST.checked_next().expect("first advances"),
            QueuePosition::new(1)
        );
        let overflow = QueuePosition::MAX
            .checked_next()
            .expect_err("the last position has no successor");
        assert_eq!(overflow.category(), "position_overflow");

        let at_ceiling = InputQueue::new(
            session(),
            vec![queued("q-a", QueuePosition::MAX.get(), steer("go"))],
        )
        .expect("a single item at the last position");
        let appended = at_ceiling
            .append(item("q-b"), steer("go"))
            .expect_err("there is no position after the last one");
        assert_eq!(appended.category(), "position_overflow");

        let stalled = InputQueue::new(
            session(),
            vec![queued("q-a", 4, steer("go")), queued("q-b", 4, steer("go"))],
        )
        .expect_err("positions must strictly increase");
        assert_eq!(stalled.category(), "position_not_monotonic");
    }

    #[test]
    fn appending_assigns_the_next_position_and_refuses_a_repeated_identity() {
        let queue = queue_of(&["q-a", "q-b"]);
        let grown = queue
            .append(item("q-c"), steer("also run the linter"))
            .expect("a new identity appends");
        assert_eq!(identities(&grown), ["q-a", "q-b", "q-c"]);
        assert_eq!(grown.items()[2].position(), QueuePosition::new(2));
        assert_eq!(
            identities(&queue),
            ["q-a", "q-b"],
            "the original queue is a value, not a shared buffer"
        );

        let repeated = queue
            .append(item("q-a"), steer("go"))
            .expect_err("q-a is already queued");
        assert_eq!(repeated.category(), "duplicate_identity");
    }
}

mod attempt_lineage {
    use super::*;

    fn attempt(id: &str) -> AttemptRef {
        AttemptRef::new(id).expect("valid attempt")
    }

    #[test]
    fn a_retry_names_its_predecessor_and_the_original() {
        let root = AttemptLineage::root(attempt("a-1"));
        assert_eq!(root.original(), &attempt("a-1"));
        assert_eq!(root.predecessor(), &attempt("a-1"));

        let retry = RetryRequest::derive(root, attempt("a-2"), text("provider timed out"));
        assert_eq!(retry.original(), &attempt("a-1"));
        assert_eq!(retry.predecessor(), &attempt("a-1"));
        assert_eq!(retry.successor(), &attempt("a-2"));
        assert_eq!(retry.reason().as_str(), "provider timed out");
    }

    #[test]
    fn a_retry_of_a_retry_records_the_original_as_well_as_the_immediate_predecessor() {
        let first = RetryRequest::derive(
            AttemptLineage::root(attempt("a-1")),
            attempt("a-2"),
            text("provider timed out"),
        );
        let second = RetryRequest::derive(
            first.successor_lineage(),
            attempt("a-3"),
            text("tool failed"),
        );
        assert_eq!(second.original(), &attempt("a-1"), "the original survives");
        assert_eq!(
            second.predecessor(),
            &attempt("a-2"),
            "the immediate predecessor is the attempt just retried"
        );
        assert_eq!(second.successor(), &attempt("a-3"));

        let third = RetryRequest::derive(
            second.successor_lineage(),
            attempt("a-4"),
            text("rate limited"),
        );
        assert_eq!(third.original(), &attempt("a-1"));
        assert_eq!(third.predecessor(), &attempt("a-3"));
    }

    #[test]
    fn no_constructor_addresses_or_mutates_prior_evidence() {
        let mut transcript = transcript_of(&[1, 2]);
        let before: Vec<String> = transcript
            .entries()
            .iter()
            .map(|entry| entry.digest().as_str().to_owned())
            .collect();

        // Building the whole retry chain needs attempt identities and a reason.
        // No constructor accepts a transcript, so there is nothing to address.
        let first = RetryRequest::derive(
            AttemptLineage::root(attempt("a-1")),
            attempt("a-2"),
            text("provider timed out"),
        );
        let _second = RetryRequest::derive(
            first.successor_lineage(),
            attempt("a-3"),
            text("tool failed"),
        );

        let after: Vec<String> = transcript
            .entries()
            .iter()
            .map(|entry| entry.digest().as_str().to_owned())
            .collect();
        assert_eq!(before, after, "a retry left prior evidence untouched");

        // Nor can the evidence be replaced at the revision it already occupies.
        let rewrite = transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-2").expect("valid entry id"),
                revision(2),
                digest("sha256:rewritten"),
            ))
            .expect_err("revision 2 is already recorded");
        assert_eq!(rewrite.category(), "revision_not_advancing");
        assert_eq!(transcript.entries().len(), 2);
    }
}

mod idempotent_intents {
    use super::*;

    fn request(id: &str) -> RequestRef {
        RequestRef::new(id).expect("valid request")
    }

    #[test]
    fn a_repeated_stop_yields_one_typed_outcome_and_one_effect() {
        let mut ledger = IntentLedger::new();
        let stop = CancelRequest::new(request("r-1"), CancelScope::Turn);

        let first = ledger.submit_cancel(&stop);
        let second = ledger.submit_cancel(&stop);
        assert_eq!(first.effect(), second.effect());
        assert_eq!(first.effect(), IntentEffect::Stopped(CancelScope::Turn));
        assert_eq!(first.delivery(), Delivery::FirstObservation);
        assert_eq!(second.delivery(), Delivery::Replay);
        assert_eq!(ledger.effect_count(), 1, "the stop took effect once");
    }

    #[test]
    fn a_repeated_undo_yields_one_typed_outcome_and_one_effect() {
        let mut ledger = IntentLedger::new();
        let target = UndoTarget::new(UndoTargetKind::FileEdit, text("src/main.rs"))
            .expect("a file edit is reversible");
        let undo = UndoRequest::new(request("r-9"), target);

        let first = ledger.submit_undo(&undo);
        let second = ledger.submit_undo(&undo);
        assert_eq!(first.effect(), second.effect());
        assert_eq!(
            first.effect(),
            IntentEffect::Reversed(UndoTargetKind::FileEdit)
        );
        assert_eq!(second.delivery(), Delivery::Replay);
        assert_eq!(ledger.effect_count(), 1);
        assert_eq!(
            ledger.effects(),
            [IntentEffect::Reversed(UndoTargetKind::FileEdit)]
        );
    }

    #[test]
    fn idempotency_is_keyed_by_request_identity_not_by_shape() {
        let mut ledger = IntentLedger::new();
        let first = ledger.submit_cancel(&CancelRequest::new(request("r-1"), CancelScope::Turn));
        let second = ledger.submit_cancel(&CancelRequest::new(request("r-2"), CancelScope::Turn));
        assert_eq!(first.delivery(), Delivery::FirstObservation);
        assert_eq!(
            second.delivery(),
            Delivery::FirstObservation,
            "a different identity is not a replay of the first"
        );
        assert_eq!(
            ledger.effect_count(),
            2,
            "two distinct requests are two effects, however alike"
        );
    }

    #[test]
    fn an_irreversible_undo_target_fails_with_its_own_category() {
        for kind in [
            UndoTargetKind::TranscriptEntry,
            UndoTargetKind::ExternalEffect,
        ] {
            assert!(!kind.is_reversible());
            let error = UndoTarget::new(kind, text("x")).expect_err("not reversible");
            assert_eq!(error.category(), "not_reversible");
            assert_eq!(error, InteractionError::NotReversible { target: kind });
            assert!(error.to_string().contains(kind.as_str()));
        }
        for kind in [
            UndoTargetKind::FileEdit,
            UndoTargetKind::QueuedInput,
            UndoTargetKind::CheckpointRestore,
        ] {
            let target = UndoTarget::new(kind, text("target-1")).expect("reversible");
            assert_eq!(target.kind(), kind);
            assert_eq!(target.identity().as_str(), "target-1");
        }
        assert_eq!(UndoTargetKind::ALL.len(), 5);
    }
}

mod checkpoint_identity {
    use super::*;

    fn reference(value: &str, at: u64) -> CheckpointRef {
        CheckpointRef::new(digest(value), revision(at))
    }

    fn log_with(entries: &[(&str, u64)]) -> CheckpointLog {
        let mut log = CheckpointLog::new();
        for (value, at) in entries {
            log.record(CreateCheckpoint::new(
                session(),
                reference(value, *at),
                text("before edit"),
                EpochMillis::EPOCH,
            ))
            .expect("valid checkpoint");
        }
        log
    }

    #[test]
    fn create_list_and_restore_are_distinct_operations() {
        let mut names = vec![
            CreateCheckpoint::OPERATION,
            ListCheckpoints::OPERATION,
            RestoreCheckpoint::OPERATION,
        ];
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "the three operations share no name");

        let log = log_with(&[("sha256:aa", 1), ("sha256:bb", 2)]);
        let listed = log.list(&ListCheckpoints::new(session(), 10));
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].label().as_str(), "before edit");
        assert_eq!(listed[0].created_at(), EpochMillis::EPOCH);

        let truncated = log.list(&ListCheckpoints::new(session(), 1));
        assert_eq!(truncated.len(), 1, "a listing honours its own bound");

        let elsewhere = log.list(&ListCheckpoints::new(
            SessionRef::new("s-2").expect("valid session"),
            10,
        ));
        assert!(elsewhere.is_empty(), "listing is scoped to its session");
    }

    #[test]
    fn a_restore_requires_the_exact_digest_and_revision() {
        let log = log_with(&[("sha256:aa", 1), ("sha256:bb", 2)]);

        let restored = log
            .restore(&RestoreCheckpoint::new(reference("sha256:bb", 2)))
            .expect("the exact digest and revision resolve");
        assert_eq!(restored.reference().digest().as_str(), "sha256:bb");
        assert_eq!(restored.reference().revision(), revision(2));

        let wrong_revision = log
            .restore(&RestoreCheckpoint::new(reference("sha256:bb", 3)))
            .expect_err("the digest is recorded at revision 2");
        assert_eq!(wrong_revision.category(), "checkpoint_revision_mismatch");
    }

    #[test]
    fn an_unknown_target_fails() {
        let log = log_with(&[("sha256:aa", 1)]);
        let unknown = log
            .restore(&RestoreCheckpoint::new(reference("sha256:zz", 1)))
            .expect_err("no such checkpoint");
        assert_eq!(unknown.category(), "unknown_checkpoint");
        assert!(unknown.to_string().contains("sha256:zz"));

        let empty = CheckpointLog::new()
            .restore(&RestoreCheckpoint::new(reference("sha256:aa", 1)))
            .expect_err("an empty log resolves nothing");
        assert_eq!(empty.category(), "unknown_checkpoint");
    }

    #[test]
    fn a_digest_identifies_at_most_one_restore_point() {
        let mut log = log_with(&[("sha256:aa", 1)]);
        let duplicate = log
            .record(CreateCheckpoint::new(
                session(),
                reference("sha256:aa", 2),
                text("again"),
                EpochMillis::EPOCH,
            ))
            .expect_err("the digest is already recorded");
        assert_eq!(duplicate.category(), "duplicate_identity");
    }
}

mod compression_lineage {
    use super::*;

    fn range() -> TranscriptRange {
        TranscriptRange::new(revision(1), revision(3)).expect("a forward range")
    }

    #[test]
    fn every_lineage_component_is_recorded() {
        let facts = ["the migration is reversible", "the tenant is acme"];
        let compression = CompressionOperation::record(compression_parts(range(), &facts))
            .expect("a complete compression");

        assert_eq!(compression.source().from(), revision(1));
        assert_eq!(compression.source().to(), revision(3));
        assert_eq!(compression.compressor_provider(), "provider-a");
        assert_eq!(compression.compressor_model(), "model-a");
        assert_eq!(compression.prompt_digest().as_str(), "sha256:prompt");
        assert_eq!(compression.output_digest().as_str(), "sha256:output");
        assert_eq!(compression.protected_facts().len(), 2);
        assert_eq!(compression.verification(), VerificationStatus::Verified);
    }

    #[test]
    fn a_missing_or_over_bound_component_is_refused() {
        let facts = ["a fact"];

        let mut parts = compression_parts(range(), &facts);
        parts.compressor_provider = "";
        let no_provider = CompressionOperation::record(parts).expect_err("no provider");
        assert_eq!(no_provider.category(), "field_invalid");

        let mut parts = compression_parts(range(), &facts);
        parts.compressor_model = "";
        let no_model = CompressionOperation::record(parts).expect_err("no model");
        assert_eq!(no_model.category(), "field_invalid");

        let none: [&str; 0] = [];
        let mut parts = compression_parts(range(), &facts);
        parts.protected_facts = &none;
        let no_facts = CompressionOperation::record(parts).expect_err("no protected facts");
        assert_eq!(no_facts.category(), "field_invalid");

        let many = vec!["a fact"; MAX_PROTECTED_FACTS + 1];
        let mut parts = compression_parts(range(), &facts);
        parts.protected_facts = &many;
        let too_many = CompressionOperation::record(parts).expect_err("one fact too many");
        assert_eq!(too_many.category(), "too_many");

        let inverted = TranscriptRange::new(revision(3), revision(1))
            .expect_err("a range cannot end before it begins");
        assert_eq!(inverted.category(), "range_inverted");
    }

    #[test]
    fn verification_status_is_explicit_rather_than_inferred_from_absence() {
        let facts = ["a fact"];
        for status in VerificationStatus::ALL {
            let mut parts = compression_parts(range(), &facts);
            parts.verification = status;
            let compression =
                CompressionOperation::record(parts).expect("every status is recordable");
            assert_eq!(compression.verification(), status);
        }
        assert_ne!(VerificationStatus::NotRun, VerificationStatus::Verified);
        assert_ne!(VerificationStatus::Rejected, VerificationStatus::NotRun);
    }

    #[test]
    fn a_compression_is_a_derived_view_and_never_a_transcript_rewrite() {
        let transcript = transcript_of(&[1, 2, 3]);
        let before: Vec<String> = transcript
            .entries()
            .iter()
            .map(|entry| entry.digest().as_str().to_owned())
            .collect();

        let facts = ["the tenant is acme"];
        let compression = CompressionOperation::record(compression_parts(range(), &facts))
            .expect("a complete compression");
        let view = derive_view(&transcript, &compression).expect("the range is covered");

        assert_eq!(view.source().from(), revision(1));
        assert_eq!(view.source().to(), revision(3));
        assert_eq!(view.digest().as_str(), "sha256:output");
        assert_eq!(view.verification(), VerificationStatus::Verified);

        let after: Vec<String> = transcript
            .entries()
            .iter()
            .map(|entry| entry.digest().as_str().to_owned())
            .collect();
        assert_eq!(before, after, "the authoritative entries are untouched");
        assert_eq!(transcript.entries().len(), 3, "nothing was elided");
        assert!(
            !before.contains(&view.digest().as_str().to_owned()),
            "the derived view is a separate value, not one of the entries"
        );
    }

    #[test]
    fn a_compression_cannot_name_a_range_the_transcript_does_not_hold() {
        let transcript = transcript_of(&[1, 2]);
        let facts = ["a fact"];
        let compression = CompressionOperation::record(compression_parts(range(), &facts))
            .expect("a complete compression");
        let error =
            derive_view(&transcript, &compression).expect_err("revision 3 was never recorded");
        assert_eq!(error.category(), "unknown_transcript_range");
    }

    #[test]
    fn an_authoritative_entry_cannot_be_replaced_at_its_own_revision() {
        let mut transcript = transcript_of(&[1, 2]);
        let error = transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-1").expect("valid entry id"),
                revision(1),
                digest("sha256:rewritten"),
            ))
            .expect_err("revision 1 is behind the last entry");
        assert_eq!(error.category(), "revision_not_advancing");
        assert_eq!(transcript.entries()[0].digest().as_str(), "sha256:1");

        transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-3").expect("valid entry id"),
                revision(3),
                digest("sha256:3"),
            ))
            .expect("appending forward is the only way to add");
        assert_eq!(transcript.entries().len(), 3);
    }
}

mod context_usage {
    use super::*;

    fn turn() -> TurnRef {
        TurnRef::new("t-1").expect("valid turn")
    }

    #[test]
    fn all_eight_component_classes_are_covered() {
        assert_eq!(ContextComponentClass::ALL.len(), 8);
        let usage = TurnContextUsage::new(turn(), &full_usage()).expect("a complete breakdown");
        assert_eq!(usage.turn(), &turn());
        for class in ContextComponentClass::ALL {
            assert_eq!(
                usage.component(class).class(),
                class,
                "lookup answers for the class asked about"
            );
            assert_eq!(
                ContextComponentClass::ALL[class.index()],
                class,
                "the index and the canonical order agree"
            );
        }
        let mut spellings: Vec<&str> = ContextComponentClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }

    #[test]
    fn a_missing_or_repeated_class_is_refused() {
        let mut short = full_usage();
        short.retain(|usage| usage.class() != ContextComponentClass::Mcp);
        let missing = TurnContextUsage::new(turn(), &short).expect_err("mcp is absent");
        assert_eq!(missing.category(), "missing_component_class");
        assert_eq!(
            missing,
            InteractionError::MissingComponentClass {
                class: ContextComponentClass::Mcp
            }
        );

        let mut repeated = full_usage();
        repeated.push(ComponentUsage::new(
            ContextComponentClass::Tools,
            None,
            ReportedCount::Absent(MissingCountReason::TurnIncomplete),
        ));
        let duplicate = TurnContextUsage::new(turn(), &repeated).expect_err("tools occurs twice");
        assert_eq!(duplicate.category(), "duplicate_component_class");
    }

    #[test]
    fn estimated_and_reported_counts_are_independently_nullable() {
        let combinations = [
            (
                Some(EstimatedTokens::new(10)),
                ReportedCount::Reported(ReportedTokens::new(20)),
            ),
            (None, ReportedCount::Reported(ReportedTokens::new(20))),
            (
                Some(EstimatedTokens::new(10)),
                ReportedCount::Absent(MissingCountReason::ProviderDidNotReport),
            ),
            (
                None,
                ReportedCount::Absent(MissingCountReason::TurnIncomplete),
            ),
        ];
        for (estimated, reported) in combinations {
            let usage = ComponentUsage::new(ContextComponentClass::Memory, estimated, reported);
            assert_eq!(usage.estimated(), estimated);
            assert_eq!(usage.reported(), reported);
        }
    }

    #[test]
    fn a_null_provider_count_carries_a_reason_and_never_defaults_to_the_estimate() {
        for reason in MissingCountReason::ALL {
            let usage = ComponentUsage::new(
                ContextComponentClass::Skills,
                Some(EstimatedTokens::new(4_242)),
                ReportedCount::Absent(reason),
            );
            assert_eq!(usage.reported().tokens(), None, "no count is invented");
            assert_ne!(usage.reported().tokens(), Some(4_242));
            assert_eq!(usage.reported().missing_reason(), Some(reason));
            assert!(!reason.as_str().is_empty());
            assert_eq!(
                usage.estimated().map(EstimatedTokens::get),
                Some(4_242),
                "the estimate stays on its own side"
            );
        }

        let mut components = full_usage();
        components.retain(|usage| usage.class() != ContextComponentClass::Attachments);
        components.push(ComponentUsage::new(
            ContextComponentClass::Attachments,
            Some(EstimatedTokens::new(1_000)),
            ReportedCount::Absent(MissingCountReason::NotBrokenDownByProvider),
        ));
        let usage = TurnContextUsage::new(turn(), &components).expect("a complete breakdown");
        let total = usage.reported_total();
        assert_eq!(
            total.reported_tokens(),
            7 * 20,
            "the unreported class contributes nothing, not its estimate"
        );
        assert_eq!(
            total.unreported(),
            [ContextComponentClass::Attachments],
            "the unreported class is named rather than filled in"
        );
    }
}

mod projection_authority {
    use super::*;

    fn action(command: &str, authority: RequiredAuthority) -> ProjectionAction {
        ProjectionAction::new(
            CommandId::new(command).expect("valid command"),
            authority,
            text("Do the thing"),
        )
    }

    fn projection() -> SurfaceProjection {
        SurfaceProjection::of_queue(
            SurfaceKind::Tui,
            &queue_of(&["q-a", "q-b"]),
            vec![
                action("automonique.interaction.stop", RequiredAuthority::Interrupt),
                action("automonique.interaction.undo", RequiredAuthority::Reverse),
            ],
        )
        .expect("a valid projection")
    }

    #[test]
    fn a_projection_exposes_observed_state_and_changes_none_of_it() {
        let queue = queue_of(&["q-a", "q-b"]);
        let observed = projection();
        assert_eq!(observed.surface(), SurfaceKind::Tui);
        assert_eq!(observed.session(), &session());
        assert_eq!(
            observed
                .observed()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect::<Vec<String>>(),
            identities(&queue)
        );
        // The projection is a snapshot: reordering the queue afterwards leaves
        // the already-taken projection alone, because it holds no handle to it.
        let moved = queue
            .reorder(&ReorderRequest::new(item("q-b"), QueuePosition::FIRST))
            .expect("q-b moves to the front");
        assert_eq!(identities(&moved), ["q-b", "q-a"]);
        assert_eq!(
            observed.observed()[0].as_str(),
            "q-a",
            "the projection did not follow the change it cannot make"
        );
    }

    #[test]
    fn every_action_names_the_authority_it_requires() {
        let observed = projection();
        assert_eq!(observed.actions().len(), 2);
        assert_eq!(
            observed.actions()[0].authority(),
            RequiredAuthority::Interrupt
        );
        assert_eq!(
            observed.actions()[1].authority(),
            RequiredAuthority::Reverse
        );

        let stop = &observed.actions()[0];
        let intent = authorize(stop, &[RequiredAuthority::Interrupt]).expect("granted");
        assert_eq!(intent.command(), stop.command());
        assert_eq!(intent.authority(), RequiredAuthority::Interrupt);
    }

    #[test]
    fn a_presentation_shortcut_is_not_a_new_authority() {
        let observed = projection();
        for offered in observed.actions() {
            let refused = authorize(offered, &[RequiredAuthority::Observe])
                .expect_err("observing does not grant acting");
            assert_eq!(refused.category(), "authority_required");
            assert_eq!(
                refused,
                InteractionError::AuthorityRequired {
                    authority: offered.authority()
                }
            );
            assert!(refused.to_string().contains(offered.authority().as_str()));
            authorize(offered, &RequiredAuthority::ALL).expect("a full grant permits it");
        }
        assert_eq!(RequiredAuthority::ALL.len(), 6);
    }

    #[test]
    fn a_namespaced_projection_cannot_address_another_extensions_namespace() {
        let mine = ExtensionId::new("ext-a").expect("valid extension");
        let theirs = ExtensionId::new("ext-b").expect("valid extension");
        let own_key = NamespacedKey::new(mine.clone(), text("panel.width"));
        let foreign_key = NamespacedKey::new(theirs.clone(), text("panel.width"));

        let namespaced = NamespacedProjection::new(mine.clone(), projection())
            .with_entry(own_key.clone(), text("240"))
            .expect("a key in the owner's namespace");
        assert_eq!(namespaced.owner(), &mine);
        assert_eq!(namespaced.projection().surface(), SurfaceKind::Tui);
        assert_eq!(
            namespaced
                .read(&own_key)
                .expect("an own key resolves")
                .map(InteractionText::as_str),
            Some("240")
        );

        let unwritten = NamespacedKey::new(mine, text("panel.height"));
        assert!(
            namespaced
                .read(&unwritten)
                .expect("an own key is readable")
                .is_none(),
            "an unwritten key inside the namespace is simply absent"
        );

        let refused_read = namespaced
            .read(&foreign_key)
            .expect_err("ext-b's namespace is not ext-a's to read");
        assert_eq!(refused_read.category(), "foreign_namespace");
        assert!(refused_read.to_string().contains("ext-b"));

        let refused_write = namespaced
            .with_entry(foreign_key, text("1"))
            .expect_err("ext-b's namespace is not ext-a's to write");
        assert_eq!(refused_write.category(), "foreign_namespace");
    }

    #[test]
    fn one_command_vocabulary_serves_every_surface() {
        assert_eq!(SurfaceKind::ALL.len(), 5);
        let command = CommandId::new("automonique.interaction.retry").expect("valid command");
        let parameters = vec![CommandParameter::new(text("attempt"), text("a-2"))];

        let invocations: Vec<CommandInvocation> = SurfaceKind::ALL
            .into_iter()
            .map(|surface| {
                CommandInvocation::new(command.clone(), surface, parameters.clone())
                    .expect("valid invocation")
            })
            .collect();
        assert_eq!(invocations.len(), 5);
        for (invocation, surface) in invocations.iter().zip(SurfaceKind::ALL) {
            assert_eq!(invocation.surface(), surface);
            assert_eq!(
                invocation.command(),
                &command,
                "the identifier does not change per surface"
            );
            assert_eq!(
                invocation.parameters(),
                parameters.as_slice(),
                "the parameters do not change per surface"
            );
        }

        let repeated = CommandInvocation::new(
            command,
            SurfaceKind::Cli,
            vec![
                CommandParameter::new(text("attempt"), text("a-2")),
                CommandParameter::new(text("attempt"), text("a-3")),
            ],
        )
        .expect_err("one parameter name, one value");
        assert_eq!(repeated.category(), "duplicate_identity");
    }
}

mod quality {
    use super::*;

    /// Produce one error of every category through a real call, so the
    /// published category list is measured rather than declared.
    fn produced_categories() -> Vec<&'static str> {
        let facts = ["a fact"];
        let range = TranscriptRange::new(revision(1), revision(3)).expect("a forward range");
        let mut parts = compression_parts(range, &facts);
        parts.compressor_provider = "";
        let field = CompressionOperation::record(parts).expect_err("no provider");

        let many = vec!["a fact"; MAX_PROTECTED_FACTS + 1];
        let mut parts = compression_parts(range, &facts);
        parts.protected_facts = &many;
        let too_many = CompressionOperation::record(parts).expect_err("too many facts");

        let queue = queue_of(&["q-a", "q-b"]);
        let queue_empty = InputQueue::new(session(), Vec::new()).expect_err("no items");
        let duplicate = InputQueue::new(
            session(),
            vec![queued("q-a", 0, steer("go")), queued("q-a", 1, steer("go"))],
        )
        .expect_err("q-a twice");
        let unknown = queue
            .reorder(&ReorderRequest::new(item("q-z"), QueuePosition::FIRST))
            .expect_err("q-z is not queued");
        let session_mismatch = InputQueue::new(
            session(),
            vec![QueuedInput::new(
                item("q-a"),
                SessionRef::new("s-2").expect("valid session"),
                QueuePosition::FIRST,
                steer("go"),
            )],
        )
        .expect_err("foreign session");
        let not_monotonic = InputQueue::new(
            session(),
            vec![queued("q-a", 4, steer("go")), queued("q-b", 4, steer("go"))],
        )
        .expect_err("stalled positions");
        let out_of_range = queue
            .reorder(&ReorderRequest::new(item("q-a"), QueuePosition::new(9)))
            .expect_err("outside the queue");
        let overflow = QueuePosition::MAX.checked_next().expect_err("no successor");

        let not_reversible = UndoTarget::new(UndoTargetKind::TranscriptEntry, text("e-1"))
            .expect_err("evidence is not reversible");

        let mut log = CheckpointLog::new();
        log.record(CreateCheckpoint::new(
            session(),
            CheckpointRef::new(digest("sha256:aa"), revision(1)),
            text("before edit"),
            EpochMillis::EPOCH,
        ))
        .expect("valid checkpoint");
        let unknown_checkpoint = log
            .restore(&RestoreCheckpoint::new(CheckpointRef::new(
                digest("sha256:zz"),
                revision(1),
            )))
            .expect_err("no such checkpoint");
        let revision_mismatch = log
            .restore(&RestoreCheckpoint::new(CheckpointRef::new(
                digest("sha256:aa"),
                revision(7),
            )))
            .expect_err("recorded at revision 1");

        let inverted =
            TranscriptRange::new(revision(3), revision(1)).expect_err("an inverted range");
        let mut transcript = transcript_of(&[1, 2]);
        let not_advancing = transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-2").expect("valid entry id"),
                revision(2),
                digest("sha256:rewritten"),
            ))
            .expect_err("revision 2 is recorded");
        let compression = CompressionOperation::record(compression_parts(range, &facts))
            .expect("a complete compression");
        let unknown_range =
            derive_view(&transcript, &compression).expect_err("revision 3 was never recorded");

        let mut short = full_usage();
        short.retain(|usage| usage.class() != ContextComponentClass::Mcp);
        let missing_class = TurnContextUsage::new(TurnRef::new("t-1").expect("valid turn"), &short)
            .expect_err("mcp is absent");
        let mut repeated = full_usage();
        repeated.push(ComponentUsage::new(
            ContextComponentClass::Tools,
            None,
            ReportedCount::Absent(MissingCountReason::TurnIncomplete),
        ));
        let duplicate_class =
            TurnContextUsage::new(TurnRef::new("t-1").expect("valid turn"), &repeated)
                .expect_err("tools twice");

        let namespaced = NamespacedProjection::new(
            ExtensionId::new("ext-a").expect("valid extension"),
            SurfaceProjection::new(SurfaceKind::Cli, session(), Vec::new(), Vec::new())
                .expect("a valid projection"),
        );
        let foreign = namespaced
            .read(&NamespacedKey::new(
                ExtensionId::new("ext-b").expect("valid extension"),
                text("panel.width"),
            ))
            .expect_err("another namespace");

        let authority = authorize(
            &ProjectionAction::new(
                CommandId::new("automonique.interaction.stop").expect("valid command"),
                RequiredAuthority::Interrupt,
                text("Stop"),
            ),
            &[RequiredAuthority::Observe],
        )
        .expect_err("not granted");

        vec![
            field.category(),
            too_many.category(),
            queue_empty.category(),
            duplicate.category(),
            unknown.category(),
            session_mismatch.category(),
            not_monotonic.category(),
            out_of_range.category(),
            overflow.category(),
            not_reversible.category(),
            unknown_checkpoint.category(),
            revision_mismatch.category(),
            inverted.category(),
            not_advancing.category(),
            unknown_range.category(),
            missing_class.category(),
            duplicate_class.category(),
            foreign.category(),
            authority.category(),
        ]
    }

    #[test]
    fn every_published_category_is_reachable_and_distinct() {
        let mut published = InteractionError::CATEGORIES.to_vec();
        let total = published.len();
        published.sort_unstable();
        published.dedup();
        assert_eq!(published.len(), total, "no category is published twice");

        let mut produced = produced_categories();
        assert_eq!(
            produced.len(),
            InteractionError::CATEGORIES.len(),
            "one rejection per published category"
        );
        produced.sort_unstable();
        produced.dedup();
        assert_eq!(
            produced, published,
            "every published category is produced by a real rejection, and no other"
        );
        for category in &produced {
            assert!(!category.is_empty());
        }
    }

    #[test]
    fn every_bound_is_a_public_constant_a_fixture_can_read() {
        assert_eq!(MAX_QUEUED_ITEMS, 256);
        assert_eq!(MAX_PROTECTED_FACTS, 64);

        // The bound is the edge the rejection uses, not a separate number.
        let mut items = Vec::with_capacity(MAX_QUEUED_ITEMS);
        for index in 0..MAX_QUEUED_ITEMS {
            let position = u32::try_from(index).expect("index fits a position");
            items.push(queued(&format!("q-{index}"), position, steer("go")));
        }
        let at_bound = InputQueue::new(session(), items.clone()).expect("exactly at the bound");
        assert_eq!(at_bound.items().len(), MAX_QUEUED_ITEMS);

        let position = u32::try_from(MAX_QUEUED_ITEMS).expect("index fits a position");
        items.push(queued("q-over", position, steer("go")));
        let over = InputQueue::new(session(), items).expect_err("one past the bound");
        assert_eq!(
            over,
            InteractionError::TooMany {
                field: "queued_items",
                max: MAX_QUEUED_ITEMS,
                actual: MAX_QUEUED_ITEMS + 1,
            }
        );
    }

    #[test]
    fn every_closed_vocabulary_spells_its_members_distinctly() {
        fn distinct(spellings: Vec<&str>) {
            let total = spellings.len();
            let mut sorted = spellings;
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), total);
            for spelling in &sorted {
                assert!(!spelling.is_empty());
            }
        }

        distinct(SurfaceKind::ALL.iter().map(|kind| kind.as_str()).collect());
        distinct(CancelScope::ALL.iter().map(|kind| kind.as_str()).collect());
        distinct(
            UndoTargetKind::ALL
                .iter()
                .map(|kind| kind.as_str())
                .collect(),
        );
        distinct(
            VerificationStatus::ALL
                .iter()
                .map(|status| status.as_str())
                .collect(),
        );
        distinct(
            ContextComponentClass::ALL
                .iter()
                .map(|class| class.as_str())
                .collect(),
        );
        distinct(
            MissingCountReason::ALL
                .iter()
                .map(|reason| reason.as_str())
                .collect(),
        );
        distinct(
            RequiredAuthority::ALL
                .iter()
                .map(|authority| authority.as_str())
                .collect(),
        );
        distinct(RequestKind::KINDS.to_vec());
        distinct(vec![
            Delivery::FirstObservation.as_str(),
            Delivery::Replay.as_str(),
        ]);
    }
}

/// Regressions found by adversarial review of this module.
///
/// Both defects were live and the suite passed over them. Each test here fails
/// if its fix is reverted.
mod review_regressions {
    use super::*;

    fn request(id: &str) -> RequestRef {
        RequestRef::new(id).expect("valid request")
    }

    #[test]
    fn a_reused_request_identity_is_a_collision_not_a_replay() {
        let mut ledger = IntentLedger::new();
        let stop = CancelRequest::new(request("r-1"), CancelScope::Turn);
        let target = UndoTarget::new(UndoTargetKind::FileEdit, text("src/main.rs"))
            .expect("a file edit is reversible");
        let undo = UndoRequest::new(request("r-1"), target);

        let stopped = ledger.submit_cancel(&stop);
        assert_eq!(stopped.delivery(), Delivery::FirstObservation);

        // The undo reuses the stop's request identity. Answering it with the
        // recorded stop would drop the undo and report success for it.
        let answered = ledger.submit_undo(&undo);
        assert_eq!(
            answered.delivery(),
            Delivery::RequestIdentityCollision,
            "an undo answered with a stop must say so"
        );
        assert_ne!(
            answered.delivery(),
            Delivery::Replay,
            "a different intent is not a replay of an earlier one"
        );
        assert_eq!(ledger.effect_count(), 1, "no second effect was issued");
    }

    #[test]
    fn a_repeated_transcript_identity_is_refused() {
        let mut transcript = Transcript::new();
        transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-1").expect("valid entry id"),
                revision(1),
                digest("sha256:1"),
            ))
            .expect("first entry");

        // Same identity, advancing revision, different digest: an append that
        // would leave one identity holding two conflicting digests.
        let error = transcript
            .append(TranscriptEntry::new(
                TranscriptEntryId::new("e-1").expect("valid entry id"),
                revision(2),
                digest("sha256:2"),
            ))
            .expect_err("a repeated identity is a rewrite wearing an append's clothes");
        assert_eq!(error.category(), "duplicate_transcript_entry");
        assert_eq!(transcript.entries().len(), 1);
    }
}
