// SPDX-License-Identifier: Elastic-2.0

//! The normalized progress frame: its body rules, its bytes, and its refusals.
//!
//! The frame is the one shape the CLI, both chat bridges and the desktop client
//! render a live run from, so the properties held here are the ones every
//! surface silently depends on: a body carries exactly the members its kind
//! declares, an encoding is canonical and round-trips byte-for-byte, and every
//! untrusted spelling fails closed rather than decoding to something plausible.

use automonique_protocol::codec::CodecError;
use automonique_protocol::event::{
    Authority, EventError, EventKind, MAX_RETRY_AFTER_MS, MemberRule, RetryCategory, RetryContext,
    StepStatus,
};
use automonique_protocol::primitives::{EpochMillis, ValueError};
use automonique_protocol::progress_api::{
    MAX_PROGRESS_CANONICAL_BYTES, MAX_PROGRESS_TEXT_BYTES, PROGRESS_API_SCHEMA_V1,
    PROGRESS_PROTOCOL, ProgressApiError, ProgressBody, ProgressBodyParts, ProgressFrame,
    ProgressFrameParts, ProgressText, SPOOL_PAYLOAD_CEILING_BYTES, member_rules,
};
use automonique_protocol::tools::RunId;

fn run_id() -> RunId {
    RunId::new("run-progress-1").expect("a valid run identity")
}

fn retry() -> RetryContext {
    RetryContext::new(RetryCategory::RateLimited, true, Some(9_000), 2).expect("a coherent context")
}

/// The exact members one kind requires, drawn from the kind's own rules.
fn required_parts(kind: EventKind) -> ProgressBodyParts {
    ProgressBodyParts {
        text: matches!(kind.text_rule(), MemberRule::Required)
            .then(|| ProgressText::new("shown").expect("plain text")),
        step: matches!(kind.step_rule(), MemberRule::Required).then_some(StepStatus::InProgress),
        retry: matches!(kind.retry_rule(), MemberRule::Required).then(retry),
    }
}

fn frame(kind: EventKind, sequence: u64) -> ProgressFrame {
    let authority = if kind.is_preview_only() {
        Authority::Synthetic
    } else {
        Authority::Authoritative
    };
    ProgressFrame::new(ProgressFrameParts {
        run_id: run_id(),
        sequence,
        at_ms: EpochMillis::from_millis(1_700_000_000_000),
        authority,
        kind,
        body: ProgressBody::new(kind, required_parts(kind)).expect("the body its kind requires"),
    })
    .expect("a frame with a stamped sequence")
}

/// The body a kind admits, and the two ways it can fail to.
mod body_rules {
    use super::*;

    #[test]
    fn every_kind_can_build_the_body_it_requires() {
        for kind in EventKind::ALL {
            let body = ProgressBody::new(kind, required_parts(kind))
                .unwrap_or_else(|error| panic!("{}: {error}", kind.as_str()));
            assert_eq!(
                body.step().is_some(),
                matches!(kind.step_rule(), MemberRule::Required)
            );
            assert_eq!(
                body.retry().is_some(),
                matches!(kind.retry_rule(), MemberRule::Required)
            );
            assert_eq!(
                body.text().is_some(),
                matches!(kind.text_rule(), MemberRule::Required)
            );
        }
    }

    /// The published rule table is the kinds' own answers, not a second list.
    #[test]
    fn the_rule_table_covers_every_kind_exactly_once() {
        let rules = member_rules();
        assert_eq!(rules.len(), EventKind::ALL.len());
        for (kind, text, step, retry) in rules {
            assert_eq!(text, kind.text_rule());
            assert_eq!(step, kind.step_rule());
            assert_eq!(retry, kind.retry_rule());
        }
    }

    #[test]
    fn an_empty_body_is_admitted_by_exactly_the_kinds_that_require_nothing() {
        for kind in EventKind::ALL {
            let requires_nothing = [kind.text_rule(), kind.step_rule(), kind.retry_rule()]
                .into_iter()
                .all(|rule| !matches!(rule, MemberRule::Required));
            assert_eq!(
                ProgressBody::empty(kind).is_ok(),
                requires_nothing,
                "{} disagreed about carrying an empty body",
                kind.as_str()
            );
        }
    }

    #[test]
    fn a_forbidden_member_is_refused_by_name() {
        let error = ProgressBody::new(
            EventKind::SessionCreated,
            ProgressBodyParts {
                text: Some(ProgressText::new("a session").expect("plain text")),
                step: None,
                retry: None,
            },
        )
        .expect_err("a session creation carrying display text");
        assert_eq!(
            error,
            EventError::BodyMemberRefused {
                member: "text",
                kind: EventKind::SessionCreated,
                rule: MemberRule::Forbidden,
            }
        );
    }

    #[test]
    fn a_fault_carries_both_its_retry_context_and_its_sentence() {
        // The reason the body is three members rather than a union of three
        // shapes: a fault has a retry story *and* something to show, and a
        // union would have forced one of the two out.
        let body = ProgressBody::new(
            EventKind::ProviderFault,
            ProgressBodyParts {
                text: Some(ProgressText::new("upstream said no").expect("plain text")),
                step: None,
                retry: Some(retry()),
            },
        )
        .expect("a fault carrying both");
        assert_eq!(body.retry(), Some(retry()));
        assert_eq!(
            body.text().map(ProgressText::as_str),
            Some("upstream said no")
        );
    }
}

/// What [`ProgressText`] admits, drops, and refuses.
mod display_text {
    use super::*;

    #[test]
    fn a_newline_and_a_tab_are_content_and_every_other_control_is_not() {
        assert_eq!(
            ProgressText::new("one\ntwo\tthree")
                .expect("prose")
                .as_str(),
            "one\ntwo\tthree"
        );
        for control in ['\u{0}', '\u{1b}', '\u{7}', '\u{8}', '\r'] {
            assert_eq!(
                ProgressText::new(format!("before{control}after")).expect_err("a control"),
                ValueError::ControlCharacter,
                "{control:?} was admitted"
            );
        }
        assert_eq!(ProgressText::new("").expect_err("empty"), ValueError::Empty);
        assert_eq!(
            ProgressText::new("x".repeat(MAX_PROGRESS_TEXT_BYTES + 1)).expect_err("over"),
            ValueError::TooLong {
                max_bytes: MAX_PROGRESS_TEXT_BYTES,
                actual_bytes: MAX_PROGRESS_TEXT_BYTES + 1,
            }
        );
        assert!(ProgressText::new("x".repeat(MAX_PROGRESS_TEXT_BYTES)).is_ok());
    }

    /// The producer's half: a run must never fail because its progress could
    /// not be rendered, so an emitter sanitizes rather than refusing.
    #[test]
    fn sanitizing_drops_the_forbidden_and_truncates_on_a_character_boundary() {
        assert_eq!(
            ProgressText::sanitized("ok\u{1b}[31m")
                .expect("something survived")
                .as_str(),
            "ok[31m"
        );
        assert!(ProgressText::sanitized("").is_none());
        assert!(ProgressText::sanitized("\u{0}\u{1}\r").is_none());

        // A multi-byte character straddling the ceiling is dropped whole: half
        // of one is not UTF-8, and a truncation that produced it would be a
        // corruption rather than a shortening.
        let over = "é".repeat(MAX_PROGRESS_TEXT_BYTES);
        let sanitized = ProgressText::sanitized(&over).expect("a prefix survives");
        assert!(sanitized.as_str().len() <= MAX_PROGRESS_TEXT_BYTES);
        assert!(
            sanitized.as_str().chars().all(|character| character == 'é'),
            "truncation split a character"
        );
        assert_eq!(
            sanitized.as_str().len(),
            MAX_PROGRESS_TEXT_BYTES,
            "an even two-byte fill should reach the ceiling exactly"
        );
    }
}

/// Bytes: canonical, bounded, and the same in both directions.
mod encoding {
    use super::*;

    #[test]
    fn every_kind_round_trips_byte_for_byte() {
        for (index, kind) in EventKind::ALL.into_iter().enumerate() {
            let sequence = u64::try_from(index).expect("small index") + 1;
            let original = frame(kind, sequence);
            let bytes = original.to_canonical_bytes().expect("a frame encodes");
            let decoded = ProgressFrame::from_canonical_bytes(&bytes).expect("a frame decodes");
            assert_eq!(decoded, original, "{} did not round-trip", kind.as_str());
            assert_eq!(
                decoded.to_canonical_bytes().expect("re-encodes"),
                bytes,
                "{} re-encoded differently",
                kind.as_str()
            );
        }
    }

    /// The exact bytes, so a change to the shape is visible in a review rather
    /// than only in a digest.
    #[test]
    fn the_encoding_is_the_canonical_spelling_and_nothing_else() {
        let bytes = ProgressFrame::new(ProgressFrameParts {
            run_id: run_id(),
            sequence: 7,
            at_ms: EpochMillis::from_millis(12),
            authority: Authority::Authoritative,
            kind: EventKind::ToolCallStarted,
            body: ProgressBody::new(
                EventKind::ToolCallStarted,
                ProgressBodyParts {
                    text: Some(ProgressText::new("read_file").expect("plain text")),
                    step: Some(StepStatus::InProgress),
                    retry: None,
                },
            )
            .expect("a tool call with its step"),
        })
        .expect("a stamped frame")
        .to_canonical_bytes()
        .expect("it encodes");
        assert_eq!(
            String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
            "{\"at_ms\":12,\"authority\":\"authoritative\",\
             \"body\":{\"retry\":null,\"step\":\"in_progress\",\"text\":\"read_file\"},\
             \"kind\":\"tool_call_started\",\"run_id\":\"run-progress-1\",\"sequence\":7}"
        );
    }

    #[test]
    fn a_retry_context_carries_all_four_of_its_members() {
        let bytes = ProgressFrame::new(ProgressFrameParts {
            run_id: run_id(),
            sequence: 3,
            at_ms: EpochMillis::from_millis(0),
            authority: Authority::Synthetic,
            kind: EventKind::ProviderWarning,
            body: ProgressBody::new(
                EventKind::ProviderWarning,
                ProgressBodyParts {
                    text: None,
                    step: None,
                    retry: Some(retry()),
                },
            )
            .expect("a warning with its context"),
        })
        .expect("a stamped frame")
        .to_canonical_bytes()
        .expect("it encodes");
        assert_eq!(
            String::from_utf8(bytes).expect("canonical JSON is UTF-8"),
            "{\"at_ms\":0,\"authority\":\"synthetic\",\
             \"body\":{\"retry\":{\"attempt\":2,\"category\":\"rate_limited\",\
             \"retry_after_ms\":9000,\"retryable\":true},\"step\":null,\"text\":null},\
             \"kind\":\"provider_warning\",\"run_id\":\"run-progress-1\",\"sequence\":3}"
        );
    }

    /// A frame is stored as one spool event's payload, so its ceiling has to be
    /// inside the spool's. The constant assertion in the module proves the two
    /// numbers relate; this proves a maximal frame actually encodes under it.
    #[test]
    fn a_maximal_frame_fits_one_spool_event_payload() {
        const { assert!(MAX_PROGRESS_CANONICAL_BYTES <= SPOOL_PAYLOAD_CEILING_BYTES) };
        let text = ProgressText::new("\"".repeat(MAX_PROGRESS_TEXT_BYTES))
            .expect("a maximal, maximally escaping text");
        let bytes = ProgressFrame::new(ProgressFrameParts {
            run_id: RunId::new("r".repeat(256)).expect("a maximal run identity"),
            sequence: u64::try_from(i64::MAX).expect("the wire ceiling"),
            at_ms: EpochMillis::from_millis(i64::MAX),
            authority: Authority::Synthetic,
            kind: EventKind::AssistantMessageDelta,
            body: ProgressBody::new(
                EventKind::AssistantMessageDelta,
                ProgressBodyParts {
                    text: Some(text),
                    step: None,
                    retry: None,
                },
            )
            .expect("a delta with its text"),
        })
        .expect("a stamped frame")
        .to_canonical_bytes()
        .expect("a maximal frame still encodes");
        assert!(
            bytes.len() <= MAX_PROGRESS_CANONICAL_BYTES,
            "a maximal frame is {} bytes",
            bytes.len()
        );
        assert!(bytes.len() <= SPOOL_PAYLOAD_CEILING_BYTES);
    }

    #[test]
    fn the_schema_and_protocol_names_are_the_stable_ones() {
        assert_eq!(PROGRESS_PROTOCOL, "automonique.progress");
        assert_eq!(PROGRESS_API_SCHEMA_V1, "automonique.progress/v1");
    }
}

/// Everything a peer can send that this build refuses.
mod refusals {
    use super::*;

    #[test]
    fn a_sequence_of_zero_names_no_appended_event() {
        let body = ProgressBody::empty(EventKind::TurnStarted).expect("an empty body");
        assert_eq!(
            ProgressFrame::new(ProgressFrameParts {
                run_id: run_id(),
                sequence: 0,
                at_ms: EpochMillis::from_millis(1),
                authority: Authority::Authoritative,
                kind: EventKind::TurnStarted,
                body,
            })
            .expect_err("sequence zero"),
            ProgressApiError::UnwrittenSequence
        );
    }

    #[test]
    fn an_instant_before_the_epoch_is_refused() {
        let body = ProgressBody::empty(EventKind::TurnStarted).expect("an empty body");
        assert_eq!(
            ProgressFrame::new(ProgressFrameParts {
                run_id: run_id(),
                sequence: 1,
                at_ms: EpochMillis::from_millis(-1),
                authority: Authority::Authoritative,
                kind: EventKind::TurnStarted,
                body,
            })
            .expect_err("before the epoch"),
            ProgressApiError::TimeBeforeEpoch
        );
    }

    #[test]
    fn an_authoritative_delta_is_refused_at_the_frame_too() {
        let body = ProgressBody::new(
            EventKind::AssistantMessageDelta,
            ProgressBodyParts {
                text: Some(ProgressText::new("half a sentence").expect("plain text")),
                step: None,
                retry: None,
            },
        )
        .expect("a delta with its text");
        assert_eq!(
            ProgressFrame::new(ProgressFrameParts {
                run_id: run_id(),
                sequence: 1,
                at_ms: EpochMillis::from_millis(1),
                authority: Authority::Authoritative,
                kind: EventKind::AssistantMessageDelta,
                body,
            })
            .expect_err("an authoritative delta"),
            ProgressApiError::Event(EventError::PreviewClaimedAuthority {
                kind: EventKind::AssistantMessageDelta,
            })
        );
    }

    #[test]
    fn every_undefined_spelling_fails_closed() {
        for (payload, field) in [
            (
                "{\"at_ms\":1,\"authority\":\"authoritative\",\"body\":{\"retry\":null,\
                 \"step\":null,\"text\":null},\"kind\":\"message_delta\",\
                 \"run_id\":\"run-progress-1\",\"sequence\":1}",
                "kind",
            ),
            (
                "{\"at_ms\":1,\"authority\":\"trusted\",\"body\":{\"retry\":null,\
                 \"step\":null,\"text\":null},\"kind\":\"turn_started\",\
                 \"run_id\":\"run-progress-1\",\"sequence\":1}",
                "authority",
            ),
            (
                "{\"at_ms\":1,\"authority\":\"authoritative\",\"body\":{\"retry\":null,\
                 \"step\":\"running\",\"text\":null},\"kind\":\"tool_call_started\",\
                 \"run_id\":\"run-progress-1\",\"sequence\":1}",
                "step",
            ),
        ] {
            assert_eq!(
                ProgressFrame::from_canonical_bytes(payload.as_bytes())
                    .expect_err("an undefined spelling"),
                ProgressApiError::Codec(CodecError::UnknownEnumValue { field }),
                "{field} did not fail closed"
            );
        }
    }

    /// Absent and present-and-null are different facts, and the wire carries
    /// only the second: a body missing a member is refused rather than defaulted.
    #[test]
    fn an_omitted_body_member_is_not_the_same_as_a_null_one() {
        let omitted = "{\"at_ms\":1,\"authority\":\"authoritative\",\"body\":{\"step\":null,\
                       \"text\":null},\"kind\":\"turn_started\",\"run_id\":\"run-progress-1\",\
                       \"sequence\":1}";
        assert_eq!(
            ProgressFrame::from_canonical_bytes(omitted.as_bytes()).expect_err("a short body"),
            ProgressApiError::InvalidBody
        );
    }

    #[test]
    fn a_body_that_disagrees_with_its_kind_is_refused_on_the_way_in() {
        // A turn start that arrived carrying a step status: well-formed JSON,
        // every member individually valid, and a shape this vocabulary does not
        // define.
        let payload = "{\"at_ms\":1,\"authority\":\"authoritative\",\"body\":{\"retry\":null,\
                       \"step\":\"pending\",\"text\":null},\"kind\":\"turn_started\",\
                       \"run_id\":\"run-progress-1\",\"sequence\":1}";
        assert_eq!(
            ProgressFrame::from_canonical_bytes(payload.as_bytes()).expect_err("a mismatched body"),
            ProgressApiError::Event(EventError::BodyMemberRefused {
                member: "step",
                kind: EventKind::TurnStarted,
                rule: MemberRule::Forbidden,
            })
        );
    }

    #[test]
    fn a_non_canonical_spelling_is_refused_rather_than_normalized() {
        let spaced = "{\"at_ms\": 1, \"authority\":\"authoritative\",\"body\":{\"retry\":null,\
                      \"step\":null,\"text\":null},\"kind\":\"turn_started\",\
                      \"run_id\":\"run-progress-1\",\"sequence\":1}";
        assert_eq!(
            ProgressFrame::from_canonical_bytes(spaced.as_bytes())
                .expect_err("insignificant space"),
            ProgressApiError::Codec(CodecError::NonCanonicalJson)
        );
    }

    #[test]
    fn a_payload_above_the_frame_ceiling_is_refused_before_it_is_parsed() {
        let oversized = vec![b'{'; MAX_PROGRESS_CANONICAL_BYTES + 1];
        assert_eq!(
            ProgressFrame::from_canonical_bytes(&oversized).expect_err("over the ceiling"),
            ProgressApiError::FrameTooLarge {
                max_bytes: MAX_PROGRESS_CANONICAL_BYTES,
                actual_bytes: MAX_PROGRESS_CANONICAL_BYTES + 1,
            }
        );
    }

    #[test]
    fn an_incoherent_retry_context_is_refused_on_the_way_in() {
        let payload = "{\"at_ms\":1,\"authority\":\"authoritative\",\
                       \"body\":{\"retry\":{\"attempt\":0,\"category\":\"timeout\",\
                       \"retry_after_ms\":null,\"retryable\":true},\"step\":null,\"text\":null},\
                       \"kind\":\"provider_fault\",\"run_id\":\"run-progress-1\",\"sequence\":1}";
        assert_eq!(
            ProgressFrame::from_canonical_bytes(payload.as_bytes()).expect_err("attempt zero"),
            ProgressApiError::Event(EventError::RetryContextIncoherent { field: "attempt" })
        );

        let waiting = format!(
            "{{\"at_ms\":1,\"authority\":\"authoritative\",\
             \"body\":{{\"retry\":{{\"attempt\":1,\"category\":\"timeout\",\
             \"retry_after_ms\":{},\"retryable\":true}},\"step\":null,\"text\":null}},\
             \"kind\":\"provider_fault\",\"run_id\":\"run-progress-1\",\"sequence\":1}}",
            MAX_RETRY_AFTER_MS + 1
        );
        assert_eq!(
            ProgressFrame::from_canonical_bytes(waiting.as_bytes())
                .expect_err("a wait past the ceiling"),
            ProgressApiError::Event(EventError::RetryContextIncoherent {
                field: "retry_after_ms",
            })
        );
    }

    #[test]
    fn every_refusal_has_a_stable_category() {
        let categories: Vec<&str> = [
            ProgressApiError::InvalidBody,
            ProgressApiError::Field {
                field: "text",
                error: ValueError::Empty,
            },
            ProgressApiError::CounterOutOfRange { field: "sequence" },
            ProgressApiError::UnwrittenSequence,
            ProgressApiError::TimeBeforeEpoch,
            ProgressApiError::FrameTooLarge {
                max_bytes: 1,
                actual_bytes: 2,
            },
            ProgressApiError::MessageTooLarge {
                max_bytes: 1,
                actual_bytes: 2,
            },
        ]
        .iter()
        .map(ProgressApiError::category)
        .collect();
        assert_eq!(
            categories,
            vec![
                "progress_invalid_body",
                "progress_invalid_field",
                "progress_counter_out_of_range",
                "progress_unwritten_sequence",
                "progress_time_before_epoch",
                "progress_frame_too_large",
                "progress_message_too_large",
            ]
        );
        // The two wrapping arms report the wrapped category rather than a
        // third spelling, so a peer sees one vocabulary for one fault.
        assert_eq!(
            ProgressApiError::Codec(CodecError::NonCanonicalJson).category(),
            CodecError::NonCanonicalJson.category()
        );
        assert_eq!(
            ProgressApiError::Event(EventError::RunAlreadyTerminal).category(),
            EventError::RunAlreadyTerminal.category()
        );
    }
}

/// The live stream: what a subscriber says, what it is told, and where it may
/// resume.
mod stream {
    use super::*;
    use automonique_protocol::event::{ConsumerCursor, SubscriptionStart, resolve_subscription};
    use automonique_protocol::progress_api::{
        MAX_PROGRESS_STREAM_CANONICAL_BYTES, MAX_SUBSCRIBE_CANONICAL_BYTES,
        PROGRESS_STREAM_PROTOCOL, PROGRESS_STREAM_SCHEMA_V1, StreamMessage, StreamMessageKind,
        StreamRefusal, SubscribeRequest, resume_from,
    };

    /// One message of every kind, so a coverage check has something to walk.
    fn message(kind: StreamMessageKind) -> StreamMessage {
        match kind {
            StreamMessageKind::Greeting => StreamMessage::Greeting { capability: 3 },
            StreamMessageKind::Live => StreamMessage::Live { from: 12 },
            StreamMessageKind::ResyncRequired => StreamMessage::ResyncRequired {
                snapshot_from: 4,
                snapshot_to: 9,
            },
            StreamMessageKind::Frame => {
                StreamMessage::Frame(frame(EventKind::AssistantMessageCompleted, 7))
            }
            StreamMessageKind::Lagged => StreamMessage::Lagged {
                delivered_through: 5,
            },
            StreamMessageKind::Retired => StreamMessage::Retired {
                delivered_through: 5,
            },
            StreamMessageKind::Refused => StreamMessage::Refused {
                refusal: StreamRefusal::SubscriberLimit,
            },
        }
    }

    #[test]
    fn every_kind_round_trips_and_reports_itself() {
        assert_eq!(StreamMessageKind::ALL.len(), 7);
        for kind in StreamMessageKind::ALL {
            let message = message(kind);
            assert_eq!(message.kind(), kind);
            let encoded = message.to_canonical_bytes().expect("it encodes");
            assert_eq!(
                StreamMessage::from_canonical_bytes(&encoded).expect("it decodes"),
                message,
                "{kind} did not round-trip"
            );
            // Canonical means one spelling, so re-encoding a decode is the same
            // bytes rather than merely the same value.
            assert_eq!(
                StreamMessage::from_canonical_bytes(&encoded)
                    .expect("it decodes")
                    .to_canonical_bytes()
                    .expect("it re-encodes"),
                encoded
            );
        }
    }

    /// The exact bytes of the two endings, so a change to either is visible in
    /// review rather than only in a client's failure.
    #[test]
    fn the_two_endings_have_exactly_these_bytes() {
        assert_eq!(
            StreamMessage::Lagged {
                delivered_through: 5
            }
            .to_canonical_bytes()
            .expect("it encodes"),
            br#"{"body":{"delivered_through":5},"kind":"lagged"}"#
        );
        assert_eq!(
            StreamMessage::Retired {
                delivered_through: 5
            }
            .to_canonical_bytes()
            .expect("it encodes"),
            br#"{"body":{"delivered_through":5},"kind":"retired"}"#
        );
    }

    /// Four kinds end the conversation and three do not, and the run's own
    /// terminal is none of them.
    #[test]
    fn the_terminal_set_is_the_four_that_end_a_subscription() {
        let terminal: Vec<&str> = StreamMessageKind::ALL
            .into_iter()
            .filter(|kind| kind.is_terminal())
            .map(StreamMessageKind::as_str)
            .collect();
        assert_eq!(
            terminal,
            vec!["resync_required", "lagged", "retired", "refused"]
        );
        // A `run_terminal` frame ends the *run*'s provider stream and not the
        // subscription: the two are different endings and the wire says so.
        let run_end = StreamMessage::Frame(frame(EventKind::RunTerminal, 3));
        assert!(!run_end.is_terminal());
        assert!(matches!(&run_end, StreamMessage::Frame(inner) if inner.kind().is_terminal()));
    }

    #[test]
    fn an_undefined_kind_or_category_fails_closed() {
        for payload in [
            br#"{"body":{"from":1},"kind":"live_v2"}"#.as_slice(),
            br#"{"body":{"delivered_through":1},"kind":"stalled"}"#.as_slice(),
        ] {
            assert_eq!(
                StreamMessage::from_canonical_bytes(payload),
                Err(ProgressApiError::Codec(CodecError::UnknownEnumValue {
                    field: "kind"
                }))
            );
        }
        assert_eq!(
            StreamMessage::from_canonical_bytes(
                br#"{"body":{"category":"too_busy"},"kind":"refused"}"#
            ),
            Err(ProgressApiError::Codec(CodecError::UnknownEnumValue {
                field: "category"
            }))
        );
    }

    #[test]
    fn a_body_that_is_not_its_kinds_shape_is_refused() {
        for payload in [
            // The wrong body for the kind.
            br#"{"body":{"from":1},"kind":"lagged"}"#.as_slice(),
            // A member the kind does not declare, alongside one it does.
            br#"{"body":{"delivered_through":1,"why":"slow"},"kind":"lagged"}"#.as_slice(),
            // A window that ends below where it starts retains nothing, and the
            // one spelling of nothing this shape admits is the pair of zeroes.
            br#"{"body":{"snapshot_from":9,"snapshot_to":4},"kind":"resync_required"}"#.as_slice(),
        ] {
            assert_eq!(
                StreamMessage::from_canonical_bytes(payload),
                Err(ProgressApiError::InvalidBody),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn a_subscription_round_trips_and_bounds_itself() {
        let request = SubscribeRequest::new(run_id(), 41);
        let encoded = request.to_canonical_bytes().expect("it encodes");
        assert_eq!(encoded, br#"{"cursor":41,"run_id":"run-progress-1"}"#);
        assert_eq!(
            SubscribeRequest::from_canonical_bytes(&encoded).expect("it decodes"),
            request
        );
        assert_eq!(request.cursor(), 41);
        assert_eq!(request.run_id().as_str(), "run-progress-1");

        // A payload past the request ceiling is refused on its length, before
        // anything is parsed.
        let oversized = vec![b'{'; MAX_SUBSCRIBE_CANONICAL_BYTES + 1];
        assert_eq!(
            SubscribeRequest::from_canonical_bytes(&oversized),
            Err(ProgressApiError::MessageTooLarge {
                max_bytes: MAX_SUBSCRIBE_CANONICAL_BYTES,
                actual_bytes: oversized.len(),
            })
        );
    }

    /// A maximal frame still fits one stream message.
    #[test]
    fn the_largest_frame_fits_inside_a_message() {
        let text = "t".repeat(MAX_PROGRESS_TEXT_BYTES);
        let frame = ProgressFrame::new(ProgressFrameParts {
            run_id: run_id(),
            sequence: u64::MAX >> 1,
            at_ms: EpochMillis::from_millis(i64::MAX),
            authority: Authority::Authoritative,
            kind: EventKind::AssistantMessageCompleted,
            body: ProgressBody::new(
                EventKind::AssistantMessageCompleted,
                ProgressBodyParts {
                    text: Some(ProgressText::new(text).expect("plain text")),
                    step: None,
                    retry: None,
                },
            )
            .expect("a message with its text"),
        })
        .expect("a stamped frame");
        let encoded = StreamMessage::Frame(frame)
            .to_canonical_bytes()
            .expect("a maximal frame still fits one message");
        assert!(encoded.len() <= MAX_PROGRESS_STREAM_CANONICAL_BYTES);
        assert!(encoded.len() > MAX_PROGRESS_TEXT_BYTES);
    }

    /// The exclusive cursor and the inclusive one differ by exactly one, and
    /// that is a fact rather than a comment.
    ///
    /// `resume_from` converts rather than restating the rule, so this walks the
    /// whole shared domain and checks the conversion against
    /// `event::resolve_subscription` — the module the plan says already carries
    /// this shape.
    #[test]
    fn resuming_agrees_with_the_event_lanes_own_decision_shifted_by_one() {
        for first in 1_u64..=6 {
            for last in first..=8 {
                for delivered_through in 0_u64..=10 {
                    let ours = resume_from(delivered_through, Some((first, last)));
                    let theirs = resolve_subscription(
                        &ConsumerCursor::new("subscriber", "run", delivered_through + 1)
                            .expect("a cursor"),
                        first,
                        last,
                    );
                    assert_eq!(
                        ours, theirs,
                        "cursor {delivered_through} against {first}..={last}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_cursor_at_the_boundary_resumes_and_one_below_it_does_not() {
        // The window holds 5..=9. A subscriber that received four wants five,
        // which is held; one that received three wants four, which is not.
        assert_eq!(
            resume_from(4, Some((5, 9))),
            SubscriptionStart::Live { from: 5 }
        );
        assert_eq!(
            resume_from(3, Some((5, 9))),
            SubscriptionStart::ResyncRequired {
                snapshot_from: 5,
                snapshot_to: 9,
            }
        );
        // A subscriber that is already past the window is live, not ahead: the
        // next frame it wants simply has not been produced.
        assert_eq!(
            resume_from(20, Some((5, 9))),
            SubscriptionStart::Live { from: 21 }
        );
    }

    #[test]
    fn an_empty_window_answers_by_what_the_subscriber_claims() {
        // Nothing retained and nothing received: everything there is, is
        // nothing, and that is a truthful live answer.
        assert_eq!(resume_from(0, None), SubscriptionStart::Live { from: 1 });
        // Nothing retained and something received: a claim of continuity this
        // endpoint cannot support, answered with the empty window.
        assert_eq!(
            resume_from(1, None),
            SubscriptionStart::ResyncRequired {
                snapshot_from: 0,
                snapshot_to: 0,
            }
        );
    }

    /// The mapping from a decision to a message is the protocol's, not a
    /// caller's.
    #[test]
    fn a_subscription_decision_becomes_exactly_one_message() {
        assert_eq!(
            StreamMessage::from_subscription(SubscriptionStart::Live { from: 8 }),
            StreamMessage::Live { from: 8 }
        );
        assert_eq!(
            StreamMessage::from_subscription(SubscriptionStart::ResyncRequired {
                snapshot_from: 2,
                snapshot_to: 6,
            }),
            StreamMessage::ResyncRequired {
                snapshot_from: 2,
                snapshot_to: 6,
            }
        );
    }

    #[test]
    fn every_refusal_spelling_is_closed_and_round_trips() {
        assert_eq!(StreamRefusal::ALL.len(), 4);
        let spellings: Vec<&str> = StreamRefusal::ALL
            .into_iter()
            .map(StreamRefusal::as_str)
            .collect();
        assert_eq!(
            spellings,
            vec![
                "subscriber_limit",
                "malformed_request",
                "field_invalid",
                "internal"
            ]
        );
        for refusal in StreamRefusal::ALL {
            assert_eq!(
                StreamRefusal::from_spelling(refusal.as_str()),
                Some(refusal)
            );
        }
        assert_eq!(StreamRefusal::from_spelling("subscriber_limit "), None);
        assert_eq!(StreamRefusal::from_spelling("SUBSCRIBER_LIMIT"), None);
    }

    /// The stream's names are its own, and are not the frame's.
    #[test]
    fn the_stream_names_itself_apart_from_the_frame() {
        assert_eq!(PROGRESS_STREAM_PROTOCOL, "automonique.progress.stream");
        assert_eq!(PROGRESS_STREAM_SCHEMA_V1, "automonique.progress.stream/v1");
        assert_ne!(PROGRESS_STREAM_PROTOCOL, PROGRESS_PROTOCOL);
        assert_ne!(PROGRESS_STREAM_SCHEMA_V1, PROGRESS_API_SCHEMA_V1);
    }
}
