// SPDX-License-Identifier: Elastic-2.0

//! R1-09 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/state-and-protocols.md`.

use automonique_protocol::event::{
    ApprovalClass, ApprovalDecision, ApprovalLedger, Authority, ConsumerCursor, EventCoordinates,
    EventError, EventKind, MAX_INLINE_RAW_BYTES, MAX_RETRY_AFTER_MS, MemberRule, PreviewEvent,
    ProviderApprovalRequest, RawPayload, RawProviderRecord, RecordedEvent, RecordedEventParts,
    RetentionPolicy, RetryCategory, RetryContext, RunTimeline, StepStatus, SubscriptionStart,
    resolve_subscription,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::provider::{
    BinaryProvenance, ProviderRequestId, ProviderSessionId, ProviderTurnId,
};

const SHA_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn provenance() -> BinaryProvenance {
    BinaryProvenance::new("1.0.0", SHA_A, None).expect("valid provenance")
}

fn coordinates() -> EventCoordinates {
    EventCoordinates::new(
        ProviderSessionId::new("s-1").expect("valid"),
        Some(ProviderTurnId::new("t-1").expect("valid")),
        None,
    )
}

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

/// The exact members one kind requires, and nothing it merely allows.
///
/// Derived from the kind's own rules rather than from a table restated here, so
/// a kind whose rules change is built correctly by every test that uses this.
fn required_body(kind: EventKind) -> (Option<StepStatus>, Option<RetryContext>) {
    (
        matches!(kind.step_rule(), MemberRule::Required).then_some(StepStatus::InProgress),
        matches!(kind.retry_rule(), MemberRule::Required).then(|| {
            RetryContext::new(RetryCategory::Transport, true, None, 1).expect("a coherent context")
        }),
    )
}

fn recorded(sequence: u64, kind: EventKind, authority: Authority) -> RecordedEvent {
    let (step, retry) = required_body(kind);
    RecordedEvent::new(RecordedEventParts {
        sequence,
        coordinates: coordinates(),
        kind,
        authority,
        at: at(1_000 + i64::try_from(sequence).expect("small sequence")),
        source_schema_version: 1,
        raw: None,
        step,
        retry,
    })
    .expect("a kind paired with the body it requires")
}

/// The authority a kind can actually be recorded under.
const fn admissible_authority(kind: EventKind) -> Authority {
    if kind.is_preview_only() {
        Authority::Synthetic
    } else {
        Authority::Authoritative
    }
}

mod envelope_bounds {
    use super::*;

    #[test]
    fn an_inline_payload_at_the_ceiling_is_accepted() {
        let record = RawProviderRecord::inline(
            provenance(),
            "message.delta",
            "cursor-1",
            vec![0_u8; MAX_INLINE_RAW_BYTES],
        )
        .expect("exactly at the ceiling");
        assert!(
            matches!(record.payload(), RawPayload::Inline(bytes) if bytes.len() == MAX_INLINE_RAW_BYTES)
        );
    }

    #[test]
    fn one_byte_over_the_ceiling_must_become_an_artifact() {
        let error = RawProviderRecord::inline(
            provenance(),
            "message.delta",
            "cursor-1",
            vec![0_u8; MAX_INLINE_RAW_BYTES + 1],
        )
        .expect_err("over the ceiling");
        assert_eq!(
            error,
            EventError::RawPayloadTooLarge {
                max_bytes: MAX_INLINE_RAW_BYTES,
                actual_bytes: MAX_INLINE_RAW_BYTES + 1,
            }
        );

        // The same content is representable by reference, which is the point:
        // large output is not lost, it simply cannot inflate the record.
        RawProviderRecord::artifact(provenance(), "message.delta", "cursor-1", "sha256:bbbb")
            .expect("an artifact reference is bounded");
    }

    #[test]
    fn source_coordinates_are_bounded() {
        for (source_type, cursor) in [("", "c"), ("t", ""), ("t\u{7}", "c")] {
            assert!(
                RawProviderRecord::inline(provenance(), source_type, cursor, Vec::new()).is_err(),
                "{source_type:?}/{cursor:?} was accepted"
            );
        }
        assert!(
            RawProviderRecord::inline(provenance(), &"x".repeat(300), "c", Vec::new()).is_err()
        );
    }

    #[test]
    fn a_raw_record_carries_the_binary_it_came_from() {
        let record = RawProviderRecord::inline(provenance(), "t", "c", Vec::new()).expect("valid");
        assert_eq!(record.provenance().digest(), SHA_A);
        assert_eq!(record.source_type(), "t");
        assert_eq!(record.source_cursor(), "c");
    }
}

mod authority_is_required {
    use super::*;

    #[test]
    fn recording_an_event_takes_an_explicit_authority() {
        // Both authorities are constructible only by naming one; there is no
        // `RecordedEvent::default()` and no inference from the kind.
        let authoritative = recorded(
            1,
            EventKind::AssistantMessageCompleted,
            Authority::Authoritative,
        );
        let synthetic = recorded(2, EventKind::ProviderFault, Authority::Synthetic);
        assert_eq!(authoritative.authority(), Authority::Authoritative);
        assert_eq!(synthetic.authority(), Authority::Synthetic);
        assert_eq!(Authority::Authoritative.as_str(), "authoritative");
        assert_eq!(Authority::Synthetic.as_str(), "synthetic");
    }

    #[test]
    fn preview_is_not_an_authority_value_at_all() {
        // `Authority` has exactly two variants. A preview is a different type,
        // so "preview authority" is not expressible.
        let preview = PreviewEvent::new(1, coordinates(), at(1_000), "partial");
        assert_eq!(preview.text(), "partial");
        assert_eq!(preview.sequence(), 1);
    }
}

mod preview_cannot_authorize {
    use super::*;

    #[test]
    fn terminal_reporting_reads_only_recorded_events() {
        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                1,
                EventKind::TurnStarted,
                Authority::Authoritative,
            ))
            .expect("first event");
        timeline
            .record(recorded(
                2,
                EventKind::RunTerminal,
                Authority::Authoritative,
            ))
            .expect("terminal");

        let terminal = timeline.terminal().expect("a terminal exists");
        assert_eq!(terminal.kind(), EventKind::RunTerminal);
        assert_ne!(terminal.authority(), Authority::Synthetic);
    }

    /// Dropping every preview must not change the derived terminal outcome.
    ///
    /// The timeline cannot hold previews at all, so this holds by construction;
    /// the test drives a realistic mixed stream to prove the two collections
    /// stay independent.
    #[test]
    fn dropping_every_preview_leaves_the_terminal_outcome_unchanged() {
        let mut previews = vec![
            PreviewEvent::new(10, coordinates(), at(1_010), "par"),
            PreviewEvent::new(11, coordinates(), at(1_011), "partia"),
            PreviewEvent::new(12, coordinates(), at(1_012), "partial"),
        ];

        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                13,
                EventKind::AssistantMessageCompleted,
                Authority::Authoritative,
            ))
            .expect("authoritative message");
        timeline
            .record(recorded(
                14,
                EventKind::RunTerminal,
                Authority::Authoritative,
            ))
            .expect("terminal");

        let before = timeline.terminal().cloned();
        previews.clear();
        let after = timeline.terminal().cloned();
        assert_eq!(before, after);
        assert!(before.is_some());
    }
}

mod kind_coverage {
    use super::*;

    #[test]
    fn every_declared_kind_is_representable_with_a_distinct_spelling() {
        assert_eq!(EventKind::ALL.len(), 24);
        let mut spellings: Vec<&str> = EventKind::ALL.iter().map(|kind| kind.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two kinds share a wire spelling");

        for kind in EventKind::ALL {
            let event = recorded(1, kind, admissible_authority(kind));
            assert_eq!(event.kind(), kind);
            assert!(!kind.as_str().is_empty());
            assert_eq!(
                EventKind::from_spelling(kind.as_str()),
                Some(kind),
                "a kind does not parse back from its own spelling"
            );
        }
        assert_eq!(EventKind::from_spelling("assistant_message"), None);
    }

    #[test]
    fn exactly_one_kind_is_terminal() {
        let terminal: Vec<EventKind> = EventKind::ALL
            .into_iter()
            .filter(|kind| kind.is_terminal())
            .collect();
        assert_eq!(terminal, vec![EventKind::RunTerminal]);
    }

    #[test]
    fn exactly_one_kind_is_preview_only() {
        let preview: Vec<EventKind> = EventKind::ALL
            .into_iter()
            .filter(|kind| kind.is_preview_only())
            .collect();
        assert_eq!(preview, vec![EventKind::AssistantMessageDelta]);
    }
}

/// The body members a kind carries, and the refusals that keep them exact.
mod body_members {
    use super::*;

    #[test]
    fn every_kind_states_a_rule_for_all_three_members() {
        for kind in EventKind::ALL {
            for rule in [kind.step_rule(), kind.retry_rule(), kind.text_rule()] {
                assert!(
                    MemberRule::ALL.contains(&rule),
                    "{} produced a rule outside the closed set",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn the_step_kinds_are_exactly_the_tool_call_and_subagent_kinds() {
        let required: Vec<EventKind> = EventKind::ALL
            .into_iter()
            .filter(|kind| matches!(kind.step_rule(), MemberRule::Required))
            .collect();
        assert_eq!(
            required,
            vec![
                EventKind::ToolCallStarted,
                EventKind::ToolCallUpdated,
                EventKind::ToolCallCompleted,
                EventKind::SubagentStarted,
                EventKind::SubagentEvent,
                EventKind::SubagentCompleted,
            ]
        );
        // Nothing else may carry one: a session event with a step status would
        // invite a renderer to draw a step that does not exist.
        for kind in EventKind::ALL {
            assert!(
                matches!(
                    kind.step_rule(),
                    MemberRule::Required | MemberRule::Forbidden
                ),
                "a step status is never merely optional"
            );
        }
    }

    #[test]
    fn the_retry_kinds_are_exactly_the_two_problem_kinds() {
        let required: Vec<EventKind> = EventKind::ALL
            .into_iter()
            .filter(|kind| matches!(kind.retry_rule(), MemberRule::Required))
            .collect();
        assert_eq!(
            required,
            vec![EventKind::ProviderWarning, EventKind::ProviderFault]
        );
    }

    #[test]
    fn a_required_member_that_is_absent_is_refused_by_name() {
        let error = RecordedEvent::new(RecordedEventParts {
            sequence: 1,
            coordinates: coordinates(),
            kind: EventKind::ToolCallStarted,
            authority: Authority::Authoritative,
            at: at(1),
            source_schema_version: 1,
            raw: None,
            step: None,
            retry: None,
        })
        .expect_err("a tool call without a step status");
        assert_eq!(
            error,
            EventError::BodyMemberRefused {
                member: "step",
                kind: EventKind::ToolCallStarted,
                rule: MemberRule::Required,
            }
        );
        assert_eq!(error.category(), "body_member_refused");
    }

    #[test]
    fn a_forbidden_member_that_is_present_is_refused_by_name() {
        let error = RecordedEvent::new(RecordedEventParts {
            sequence: 1,
            coordinates: coordinates(),
            kind: EventKind::TurnStarted,
            authority: Authority::Authoritative,
            at: at(1),
            source_schema_version: 1,
            raw: None,
            step: Some(StepStatus::Pending),
            retry: None,
        })
        .expect_err("a turn start carrying a step status");
        assert_eq!(
            error,
            EventError::BodyMemberRefused {
                member: "step",
                kind: EventKind::TurnStarted,
                rule: MemberRule::Forbidden,
            }
        );
    }

    /// The one-way rule: a delta may never be authoritative, and every other
    /// kind may still be synthetic.
    #[test]
    fn a_preview_only_kind_cannot_be_recorded_as_authoritative() {
        let error = RecordedEvent::new(RecordedEventParts {
            sequence: 1,
            coordinates: coordinates(),
            kind: EventKind::AssistantMessageDelta,
            authority: Authority::Authoritative,
            at: at(1),
            source_schema_version: 1,
            raw: None,
            step: None,
            retry: None,
        })
        .expect_err("an authoritative delta");
        assert_eq!(
            error,
            EventError::PreviewClaimedAuthority {
                kind: EventKind::AssistantMessageDelta,
            }
        );
        for kind in EventKind::ALL {
            let event = recorded(1, kind, Authority::Synthetic);
            assert_eq!(event.authority(), Authority::Synthetic);
        }
    }

    #[test]
    fn a_step_status_settles_only_at_its_two_final_states() {
        let settled: Vec<StepStatus> = StepStatus::ALL
            .into_iter()
            .filter(|status| status.is_settled())
            .collect();
        assert_eq!(settled, vec![StepStatus::Completed, StepStatus::Error]);
        for status in StepStatus::ALL {
            assert_eq!(StepStatus::from_spelling(status.as_str()), Some(status));
        }
        assert_eq!(StepStatus::from_spelling("in-progress"), None);
    }

    #[test]
    fn a_retry_context_refuses_an_incoherent_wait() {
        for category in RetryCategory::ALL {
            assert_eq!(
                RetryCategory::from_spelling(category.as_str()),
                Some(category)
            );
        }
        assert_eq!(RetryCategory::from_spelling("rate-limited"), None);

        assert_eq!(
            RetryContext::new(RetryCategory::RateLimited, true, Some(1_000), 0)
                .expect_err("an attempt nobody made"),
            EventError::RetryContextIncoherent { field: "attempt" }
        );
        assert_eq!(
            RetryContext::new(RetryCategory::Rejected, false, Some(1_000), 1)
                .expect_err("a wait for something that will not be retried"),
            EventError::RetryContextIncoherent {
                field: "retry_after_ms",
            }
        );
        assert_eq!(
            RetryContext::new(
                RetryCategory::RateLimited,
                true,
                Some(MAX_RETRY_AFTER_MS + 1),
                1
            )
            .expect_err("a wait past the ceiling"),
            EventError::RetryContextIncoherent {
                field: "retry_after_ms",
            }
        );
        let context = RetryContext::new(
            RetryCategory::RateLimited,
            true,
            Some(MAX_RETRY_AFTER_MS),
            3,
        )
        .expect("exactly at the ceiling");
        assert_eq!(context.retry_after_ms(), Some(MAX_RETRY_AFTER_MS));
        assert_eq!(context.attempt(), 3);
        assert!(context.retryable());
        // A refusal with no advertised wait is coherent: it says "not this
        // time" without pretending to know when.
        assert!(
            RetryContext::new(RetryCategory::Rejected, false, None, 1)
                .expect("a plain refusal")
                .retry_after_ms()
                .is_none()
        );
    }
}

mod terminal_uniqueness {
    use super::*;

    #[test]
    fn a_second_terminal_is_a_conflict_rather_than_an_overwrite() {
        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                1,
                EventKind::RunTerminal,
                Authority::Authoritative,
            ))
            .expect("first terminal");
        assert_eq!(
            timeline
                .record(recorded(
                    2,
                    EventKind::RunTerminal,
                    Authority::Authoritative
                ))
                .expect_err("second terminal"),
            EventError::TerminalAlreadyRecorded { existing: 1 }
        );
        // The original terminal is intact.
        assert_eq!(timeline.terminal().expect("terminal").sequence(), 1);
        assert_eq!(timeline.events().len(), 1);
    }

    #[test]
    fn nothing_is_accepted_after_the_terminal() {
        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                1,
                EventKind::RunTerminal,
                Authority::Authoritative,
            ))
            .expect("terminal");
        assert_eq!(
            timeline
                .record(recorded(
                    2,
                    EventKind::UsageUpdated,
                    Authority::Authoritative
                ))
                .expect_err("after terminal"),
            EventError::RunAlreadyTerminal
        );
    }
}

mod cursor_semantics {
    use super::*;

    #[test]
    fn sequences_must_strictly_increase() {
        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                5,
                EventKind::TurnStarted,
                Authority::Authoritative,
            ))
            .expect("first");
        for offered in [5, 4, 0] {
            assert_eq!(
                timeline
                    .record(recorded(
                        offered,
                        EventKind::UsageUpdated,
                        Authority::Authoritative
                    ))
                    .expect_err("not increasing"),
                EventError::SequenceNotIncreasing { last: 5, offered }
            );
        }
        timeline
            .record(recorded(
                6,
                EventKind::UsageUpdated,
                Authority::Authoritative,
            ))
            .expect("strictly greater is accepted");
    }

    #[test]
    fn a_cursor_never_rewinds_silently() {
        let mut cursor = ConsumerCursor::new("dashboard", "runs", 10).expect("valid");
        cursor.advance_to(11).expect("forward");
        assert_eq!(cursor.position(), 11);
        cursor.advance_to(11).expect("idempotent");
        assert_eq!(
            cursor.advance_to(9).expect_err("backwards"),
            EventError::CursorWentBackwards {
                current: 11,
                offered: 9,
            }
        );
        assert_eq!(cursor.position(), 11, "a refusal does not move the cursor");
    }

    #[test]
    fn an_out_of_range_cursor_yields_resync_with_snapshot_coordinates() {
        let stale = ConsumerCursor::new("dashboard", "runs", 3).expect("valid");
        assert_eq!(
            resolve_subscription(&stale, 10, 42),
            SubscriptionStart::ResyncRequired {
                snapshot_from: 10,
                snapshot_to: 42,
            }
        );

        let current = ConsumerCursor::new("dashboard", "runs", 12).expect("valid");
        assert_eq!(
            resolve_subscription(&current, 10, 42),
            SubscriptionStart::Live { from: 12 }
        );
    }

    #[test]
    fn a_resync_is_never_an_empty_success() {
        let stale = ConsumerCursor::new("dashboard", "runs", 0).expect("valid");
        let outcome = resolve_subscription(&stale, 100, 200);
        // The only other variant carries a live position; there is no third
        // "nothing to say" outcome a caller could mistake for an empty stream.
        match outcome {
            SubscriptionStart::ResyncRequired {
                snapshot_from,
                snapshot_to,
            } => {
                assert_eq!(snapshot_from, 100);
                assert_eq!(snapshot_to, 200);
            }
            SubscriptionStart::Live { .. } => panic!("a stale cursor resumed live"),
        }
    }
}

mod approval_idempotency {
    use super::*;

    fn request(id: &str) -> ProviderApprovalRequest {
        ProviderApprovalRequest::new(
            ApprovalClass::Command,
            ProviderRequestId::new(id).expect("valid"),
            None,
            ProviderTurnId::new("t-1").expect("valid"),
        )
    }

    #[test]
    fn replaying_the_same_decision_returns_the_identical_receipt() {
        let mut ledger = ApprovalLedger::new();
        let first = ledger
            .decide(&request("r-1"), ApprovalDecision::Allow, at(5_000))
            .expect("first decision");
        // A later replay, with a different clock reading, returns the original
        // receipt rather than re-stamping it.
        let replay = ledger
            .decide(&request("r-1"), ApprovalDecision::Allow, at(9_999))
            .expect("replay");
        assert_eq!(first, replay);
        assert_eq!(replay.at(), at(5_000));
    }

    #[test]
    fn a_conflicting_second_decision_is_refused_rather_than_replacing() {
        let mut ledger = ApprovalLedger::new();
        ledger
            .decide(&request("r-1"), ApprovalDecision::Allow, at(5_000))
            .expect("first decision");
        assert_eq!(
            ledger
                .decide(&request("r-1"), ApprovalDecision::Deny, at(6_000))
                .expect_err("conflict"),
            EventError::ApprovalConflict {
                recorded: ApprovalDecision::Allow,
                offered: ApprovalDecision::Deny,
            }
        );
        // The original decision stands.
        let unchanged = ledger
            .decide(&request("r-1"), ApprovalDecision::Allow, at(7_000))
            .expect("still allow");
        assert_eq!(unchanged.decision(), ApprovalDecision::Allow);
        assert_eq!(unchanged.at(), at(5_000));
    }

    #[test]
    fn distinct_requests_are_decided_independently() {
        let mut ledger = ApprovalLedger::new();
        ledger
            .decide(&request("r-1"), ApprovalDecision::Allow, at(1))
            .expect("allow one");
        let denied = ledger
            .decide(&request("r-2"), ApprovalDecision::Deny, at(2))
            .expect("deny another");
        assert_eq!(denied.decision(), ApprovalDecision::Deny);
        assert_eq!(denied.request().as_str(), "r-2");
    }
}

mod retention_split {
    use super::*;

    #[test]
    fn preview_retention_must_be_shorter_than_authoritative() {
        RetentionPolicy::new(60_000, 3_600_000).expect("previews expire first");
        assert_eq!(
            RetentionPolicy::new(3_600_000, 60_000).expect_err("inverted"),
            EventError::RetentionWouldOutliveEvidence {
                preview_ms: 3_600_000,
                authoritative_ms: 60_000,
            }
        );
        assert!(
            RetentionPolicy::new(1_000, 1_000).is_err(),
            "equal horizons defeat the split"
        );
    }

    #[test]
    fn expiring_previews_cannot_reach_an_authoritative_record() {
        let policy = RetentionPolicy::new(1_000, 10_000).expect("valid policy");
        let mut previews = vec![
            PreviewEvent::new(1, coordinates(), at(0), "old"),
            PreviewEvent::new(2, coordinates(), at(4_500), "recent"),
        ];
        let mut timeline = RunTimeline::new();
        timeline
            .record(recorded(
                3,
                EventKind::AssistantMessageCompleted,
                Authority::Authoritative,
            ))
            .expect("authoritative");

        policy.expire_previews(&mut previews, at(5_000));

        assert_eq!(previews.len(), 1, "only the old preview expired");
        assert_eq!(previews[0].sequence(), 2);
        // The signature takes previews only, so there is no call through which
        // this could have removed the authoritative record.
        assert_eq!(timeline.events().len(), 1);
        assert_eq!(policy.preview_ms(), 1_000);
        assert_eq!(policy.authoritative_ms(), 10_000);
    }
}
