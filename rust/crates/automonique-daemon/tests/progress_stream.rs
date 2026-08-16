// SPDX-License-Identifier: Elastic-2.0

//! The normalized progress stream, from provider bytes to rendered surface.
//!
//! Four claims, in the order the bytes travel:
//!
//! 1. the projection from the adapter's closed vocabulary onto the shared one is
//!    exhaustive, injective, and admits the body each kind requires;
//! 2. a fixture transcript fed to the mapper produces exactly one frame
//!    sequence, and a bad line ends it with one warning rather than a panic;
//! 3. the hub retains what it is given, bounded, and pages from a cursor;
//! 4. both renderers fold the same frames into their own surface's shape.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use automonique_agents::{
    ExecutionMode, ProviderItemKind, RecordedKind, RunCoordinates, SessionScope,
};
use automonique_daemon::progress::{
    PREVIEW_FLUSH_BYTES, ProviderProgressMapper, STREAM_REFUSED_PREFIX, STREAM_WARNING_TEXT,
    frame_kind, item_frame_authority, item_frame_kind,
};
use automonique_daemon::progress_hub::{
    HUB_ATTEMPT_FRAMES, HUB_ATTEMPTS, HUB_TERMINAL_RETENTION, ProgressHub,
};
use automonique_daemon::slack::{MAX_TASK_CARD_LINES, RunTaskCard};
use automonique_daemon::telegram_bridge::{MAX_PROGRESS_STEP_LINES, RunProgressView};
use automonique_protocol::event::{
    Authority, EventKind, MemberRule, RetryCategory, RetryContext, StepStatus,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
};
use automonique_protocol::tools::RunId;
use automonique_runner::backend::{CapturedFrame, ProgressMapper};

const RUN: &str = "run-progress-suite";

/// The fixture transcript, byte-identical to the adapter suite's own.
const FIXTURE: &str = concat!(
    "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n",
    "{\"type\":\"turn.started\"}\n",
    "{\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}\n",
    "{\"type\":\"item.updated\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"partial\"}}\n",
    "{\"type\":\"item.completed\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"fixture answer\"}}\n",
    "{\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":1,\"input_tokens\":2,\"output_tokens\":3}}\n",
);

fn coordinates() -> RunCoordinates {
    RunCoordinates::new(
        RUN,
        "turn-1",
        SessionScope::new("automonique", "daemon", "run-lane").expect("a scope"),
    )
    .expect("coordinates")
}

fn mapper() -> ProviderProgressMapper {
    ProviderProgressMapper::new(&coordinates(), &ExecutionMode::NewSession)
}

/// Feed a transcript one byte at a time.
///
/// The hostile split: a chunk boundary inside a line, inside an escape, and
/// inside a multi-byte character, on every byte. A mapper that only worked on
/// whole lines fails here rather than in production against a slow pipe.
fn drive(mapper: &mut ProviderProgressMapper, transcript: &str) -> Vec<CapturedFrame> {
    let mut frames = Vec::new();
    for byte in transcript.as_bytes() {
        frames.extend(mapper.push(&[*byte]));
    }
    frames.extend(mapper.finish());
    frames
}

/// One captured frame stamped at `sequence`, as the spool would.
fn stamp(frame: &CapturedFrame, sequence: u64) -> ProgressFrame {
    ProgressFrame::new(ProgressFrameParts {
        run_id: RunId::new(RUN).expect("a valid run identity"),
        sequence,
        at_ms: EpochMillis::from_millis(1_700_000_000_000),
        authority: frame.authority,
        kind: frame.kind,
        body: frame.body.clone(),
    })
    .expect("a stamped frame")
}

fn stamped(frames: &[CapturedFrame]) -> Vec<ProgressFrame> {
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| stamp(frame, u64::try_from(index).expect("a small index") + 1))
        .collect()
}

/// The projection between two closed vocabularies.
mod mapping {
    use super::*;

    /// Exhaustive over both published sets, and injective on each.
    ///
    /// The `ALL` arrays are the domain, so a member added to either without a
    /// mapping fails to compile in `progress.rs` and is counted here.
    #[test]
    fn every_adapter_kind_and_item_kind_projects_onto_a_distinct_shared_kind() {
        assert_eq!(RecordedKind::ALL.len(), 7);
        assert_eq!(ProviderItemKind::ALL.len(), 1);

        let mut seen = BTreeSet::new();
        for kind in RecordedKind::ALL {
            let projected = frame_kind(kind);
            assert!(
                seen.insert(projected),
                "{} projects onto {}, which is already taken",
                kind.as_str(),
                projected.as_str()
            );
        }
        for item in ProviderItemKind::ALL {
            let projected = item_frame_kind(item);
            assert!(
                seen.insert(projected),
                "an item preview projects onto a kind a record already produces"
            );
            // A preview may only ever be synthetic, and the shared vocabulary
            // enforces it: this is the projection agreeing in advance.
            assert!(projected.is_preview_only());
            assert_eq!(item_frame_authority(item), Authority::Synthetic);
        }
        assert_eq!(
            seen.len(),
            RecordedKind::ALL.len() + ProviderItemKind::ALL.len()
        );
    }

    /// Every projected kind is one this producer can actually build a body for.
    ///
    /// A projection onto a kind whose required member the adapter never carries
    /// would be a frame that silently never gets emitted.
    #[test]
    fn every_projected_kind_requires_only_members_this_producer_can_supply() {
        for kind in RecordedKind::ALL
            .into_iter()
            .map(frame_kind)
            .chain(ProviderItemKind::ALL.into_iter().map(item_frame_kind))
        {
            // A step status is required only by the tool-call and subagent
            // kinds, which this grammar cannot produce; if that ever changes the
            // producer has to carry a real status rather than invent one.
            assert_ne!(
                kind.step_rule(),
                MemberRule::Required,
                "{} needs a step status this adapter cannot observe",
                kind.as_str()
            );
        }
    }

    /// The one shared kind an item preview becomes, spelled out.
    #[test]
    fn an_agent_message_preview_is_an_assistant_message_delta() {
        assert_eq!(
            item_frame_kind(ProviderItemKind::AgentMessage),
            EventKind::AssistantMessageDelta
        );
        assert_eq!(
            frame_kind(RecordedKind::AssistantMessageCompleted),
            EventKind::AssistantMessageCompleted
        );
    }
}

/// Bytes in, frames out.
mod normalization {
    use super::*;

    #[test]
    fn the_fixture_transcript_produces_exactly_its_frame_sequence() {
        let frames = drive(&mut mapper(), FIXTURE);
        let kinds: Vec<EventKind> = frames.iter().map(|frame| frame.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::SessionCreated,
                EventKind::TurnStarted,
                // The preview is flushed *before* the message it previewed, so
                // a reader never sees a finished answer redrawn as a draft.
                EventKind::AssistantMessageDelta,
                EventKind::AssistantMessageCompleted,
                EventKind::UsageUpdated,
                EventKind::TurnCompleted,
            ],
            "the projected sequence changed"
        );

        let delta = frames
            .iter()
            .find(|frame| frame.kind == EventKind::AssistantMessageDelta)
            .expect("a preview frame");
        assert_eq!(delta.authority, Authority::Synthetic);
        assert_eq!(delta.body.text().map(ProgressText::as_str), Some("partial"));

        let completed = frames
            .iter()
            .find(|frame| frame.kind == EventKind::AssistantMessageCompleted)
            .expect("an answer frame");
        assert_eq!(completed.authority, Authority::Authoritative);
        assert_eq!(
            completed.body.text().map(ProgressText::as_str),
            Some("fixture answer")
        );
        // Every frame stamps and encodes: a projection that produced a body its
        // kind refuses would be caught here rather than at the spool.
        for frame in stamped(&frames) {
            frame.to_canonical_bytes().expect("a frame encodes");
        }
    }

    /// One bad line ends the stream with one warning, and nothing after it.
    #[test]
    fn a_refused_stream_emits_one_warning_and_then_nothing() {
        let mut mapper = mapper();
        let mut frames = mapper.push(
            "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n\
             {\"type\":\"turn.reversed\"}\n"
                .as_bytes(),
        );
        // Everything accepted before the bad line is still true and still
        // projected, and then the warning that ends the stream.
        assert_eq!(
            frames.first().map(|frame| frame.kind),
            Some(EventKind::SessionCreated)
        );
        let warning = frames.last().expect("a warning frame");
        assert_eq!(warning.kind, EventKind::ProviderWarning);
        assert_eq!(warning.authority, Authority::Synthetic);
        let text = warning
            .body
            .text()
            .map(ProgressText::as_str)
            .expect("the warning names its refusal");
        assert!(text.starts_with(STREAM_REFUSED_PREFIX), "{text}");
        assert!(text.contains("unknown_event"), "{text}");
        // The offending token is named — it is already sanitized to a schema
        // keyword — and the line that carried it never is.
        assert!(text.contains("turn.reversed"), "{text}");
        assert_eq!(
            warning.body.retry().map(RetryContext::retryable),
            Some(false),
            "a poisoned parse is not something to try again"
        );

        // A refused stream stays refused, through both entry points.
        frames = mapper.push(b"{\"type\":\"turn.started\"}\n");
        assert!(frames.is_empty());
        assert!(mapper.finish().is_empty());
    }

    #[test]
    fn a_session_stream_warns_on_garbage_and_keeps_rendering() {
        let mut mapper =
            ProviderProgressMapper::for_session(&coordinates(), &ExecutionMode::NewSession);
        let transcript = "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n\
                          garbage\n\
                          {\"type\":\"turn.started\"}\n";
        let frames = mapper.push(transcript.as_bytes());
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame.kind == EventKind::ProviderWarning)
                .count(),
            1
        );
        assert!(
            frames
                .iter()
                .any(|frame| frame.kind == EventKind::TurnStarted)
        );
        assert!(frames.iter().any(|frame| {
            frame.body.text().map(ProgressText::as_str) == Some(STREAM_WARNING_TEXT)
        }));
    }

    /// A truncated final line is held, never salvaged into a frame.
    #[test]
    fn a_transcript_cut_mid_line_produces_no_frame_for_the_fragment() {
        let mut mapper = mapper();
        let cut = &FIXTURE[..FIXTURE.len() - 20];
        let frames = drive(&mut mapper, cut);
        assert!(
            frames
                .iter()
                .all(|frame| frame.kind != EventKind::TurnCompleted),
            "a fragment was completed into a turn"
        );
    }
}

/// The bound that keeps previews from spending a run's whole budget.
mod coalescing {
    use super::*;

    /// A flood of preview updates is coalesced into far fewer frames.
    ///
    /// The provider's update carries the item's whole text, so the correct
    /// reading is "keep the latest" — and the measurable consequence is that a
    /// thousand updates cost a handful of frames rather than a thousand.
    #[test]
    fn a_preview_flood_is_coalesced_into_a_bounded_number_of_frames() {
        let mut transcript = String::from(
            "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n\
             {\"type\":\"turn.started\"}\n\
             {\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}\n",
        );
        let updates = 1_000;
        for index in 0..updates {
            transcript.push_str(&format!(
                "{{\"type\":\"item.updated\",\"item\":{{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"draft {index}\"}}}}\n"
            ));
        }
        transcript.push_str(
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"done\"}}\n\
             {\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":1,\"input_tokens\":2,\"output_tokens\":3}}\n",
        );

        let mut mapper = mapper();
        let frames = drive(&mut mapper, &transcript);
        let previews = frames
            .iter()
            .filter(|frame| frame.kind == EventKind::AssistantMessageDelta)
            .count();
        assert!(previews > 0, "the flood produced no preview at all");
        assert!(
            previews < updates / 10,
            "{updates} updates became {previews} frames, which is not coalescing"
        );

        // Every emitted preview is small: none of them is the accumulation of
        // the ones it replaced.
        for frame in &frames {
            if frame.kind != EventKind::AssistantMessageDelta {
                continue;
            }
            let text = frame
                .body
                .text()
                .map(ProgressText::as_str)
                .unwrap_or_default();
            assert!(
                text.len() < PREVIEW_FLUSH_BYTES,
                "a preview grew to {} bytes",
                text.len()
            );
        }

        // The answer still arrives, unaffected by how much was shown first.
        assert_eq!(
            frames
                .iter()
                .find(|frame| frame.kind == EventKind::AssistantMessageCompleted)
                .and_then(|frame| frame.body.text())
                .map(ProgressText::as_str),
            Some("done")
        );
    }
}

/// The bounded in-memory echo of a live attempt.
mod hub {
    use super::*;

    fn preview(sequence: u64, text: &str) -> ProgressFrame {
        ProgressFrame::new(ProgressFrameParts {
            run_id: RunId::new(RUN).expect("a valid run identity"),
            sequence,
            at_ms: EpochMillis::from_millis(1),
            authority: Authority::Synthetic,
            kind: EventKind::AssistantMessageDelta,
            body: ProgressBody::new(
                EventKind::AssistantMessageDelta,
                ProgressBodyParts {
                    text: Some(ProgressText::new(text).expect("plain text")),
                    step: None,
                    retry: None,
                },
            )
            .expect("a delta with its text"),
        })
        .expect("a stamped frame")
    }

    fn publish(hub: &ProgressHub, run: &str, frame: &ProgressFrame) {
        hub.publish(
            run,
            frame.sequence(),
            &frame.to_canonical_bytes().expect("it encodes"),
        );
    }

    #[test]
    fn frames_page_from_a_cursor_in_sequence_order() {
        let hub = ProgressHub::new();
        for sequence in 1..=5 {
            publish(&hub, RUN, &preview(sequence, &format!("draft {sequence}")));
        }
        let all = hub.frames_after(RUN, 0);
        assert_eq!(all.len(), 5);
        assert_eq!(
            all.iter().map(ProgressFrame::sequence).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(hub.frames_after(RUN, 3).len(), 2);
        assert!(hub.frames_after(RUN, 5).is_empty());
        assert!(hub.frames_after("another-run", 0).is_empty());
        assert_eq!(hub.oldest_retained(RUN), Some(1));
    }

    /// A full ring drops its oldest rather than growing or blocking.
    #[test]
    fn the_ring_forgets_the_oldest_frame_rather_than_growing() {
        let hub = ProgressHub::new();
        let total = u64::try_from(HUB_ATTEMPT_FRAMES).expect("a small bound") + 40;
        for sequence in 1..=total {
            publish(&hub, RUN, &preview(sequence, "draft"));
        }
        let retained = hub.frames_after(RUN, 0);
        assert_eq!(retained.len(), HUB_ATTEMPT_FRAMES);
        assert_eq!(hub.oldest_retained(RUN), Some(41));
        assert_eq!(retained.last().map(ProgressFrame::sequence), Some(total));
        // A reader whose cursor fell out of the window learns it from the
        // oldest retained sequence rather than from a silently short page.
        assert!(hub.oldest_retained(RUN).is_some_and(|oldest| oldest > 1));
    }

    #[test]
    fn the_attempt_ceiling_refuses_a_new_attempt_rather_than_evicting_one() {
        let hub = ProgressHub::new();
        for index in 0..=HUB_ATTEMPTS {
            let run = format!("run-{index}");
            publish(&hub, &run, &preview(1, "draft"));
        }
        assert_eq!(hub.retained_attempts(), HUB_ATTEMPTS);
        // The attempts already being watched kept their frames; the one over
        // the ceiling got none.
        assert_eq!(hub.frames_after("run-0", 0).len(), 1);
        assert!(
            hub.frames_after(&format!("run-{HUB_ATTEMPTS}"), 0)
                .is_empty()
        );
    }

    /// A retired attempt is kept for its retention window and then forgotten.
    ///
    /// The window is what makes a bridge restart free: a connector that dies
    /// after the run ends and comes back inside it still resumes from its
    /// cursor. After it, the durable spool is the only record — which is the
    /// whole of what the live tier promises.
    #[test]
    fn retiring_an_attempt_keeps_it_for_the_retention_window() {
        let hub = ProgressHub::new();
        let start = Instant::now();
        publish(&hub, RUN, &preview(1, "draft"));
        assert_eq!(hub.retained_attempts(), 1);

        hub.retire_at(RUN, start);
        assert_eq!(hub.retained_attempts(), 1, "a retirement is not an erasure");
        assert_eq!(hub.frames_after(RUN, 0).len(), 1);
        assert_eq!(hub.oldest_retained(RUN), Some(1));

        // One millisecond before the window closes, and one after it.
        hub.sweep_at(start + HUB_TERMINAL_RETENTION - Duration::from_millis(1));
        assert_eq!(hub.retained_attempts(), 1);
        hub.sweep_at(start + HUB_TERMINAL_RETENTION);
        assert_eq!(hub.retained_attempts(), 0);
        assert!(hub.frames_after(RUN, 0).is_empty());
        assert_eq!(hub.oldest_retained(RUN), None);
    }

    /// The runner's publishing seam reaches the ring it was made from.
    #[test]
    fn the_runner_seam_publishes_into_the_hub() {
        let hub = Arc::new(ProgressHub::new());
        let publisher = hub.publisher(RUN);
        let frame = preview(7, "through the seam");
        publisher.publish(7, &frame.to_canonical_bytes().expect("it encodes"));
        assert_eq!(hub.frames_after(RUN, 0), vec![frame]);
    }
}

/// The two surfaces, folding the same frames their own way.
mod renderers {
    use super::*;

    fn tool_call(sequence: u64, label: &str, status: StepStatus) -> ProgressFrame {
        ProgressFrame::new(ProgressFrameParts {
            run_id: RunId::new(RUN).expect("a valid run identity"),
            sequence,
            at_ms: EpochMillis::from_millis(1),
            authority: Authority::Authoritative,
            kind: EventKind::ToolCallStarted,
            body: ProgressBody::new(
                EventKind::ToolCallStarted,
                ProgressBodyParts {
                    text: Some(ProgressText::new(label).expect("plain text")),
                    step: Some(status),
                    retry: None,
                },
            )
            .expect("a tool call with its step"),
        })
        .expect("a stamped frame")
    }

    fn message(sequence: u64, text: &str, kind: EventKind) -> ProgressFrame {
        let authority = if kind.is_preview_only() {
            Authority::Synthetic
        } else {
            Authority::Authoritative
        };
        ProgressFrame::new(ProgressFrameParts {
            run_id: RunId::new(RUN).expect("a valid run identity"),
            sequence,
            at_ms: EpochMillis::from_millis(1),
            authority,
            kind,
            body: ProgressBody::new(
                kind,
                ProgressBodyParts {
                    text: Some(ProgressText::new(text).expect("plain text")),
                    step: None,
                    retry: None,
                },
            )
            .expect("a message with its text"),
        })
        .expect("a stamped frame")
    }

    fn warning(sequence: u64, text: &str) -> ProgressFrame {
        ProgressFrame::new(ProgressFrameParts {
            run_id: RunId::new(RUN).expect("a valid run identity"),
            sequence,
            at_ms: EpochMillis::from_millis(1),
            authority: Authority::Synthetic,
            kind: EventKind::ProviderWarning,
            body: ProgressBody::new(
                EventKind::ProviderWarning,
                ProgressBodyParts {
                    text: Some(ProgressText::new(text).expect("plain text")),
                    step: None,
                    retry: Some(
                        RetryContext::new(RetryCategory::RateLimited, true, Some(1_000), 1)
                            .expect("a coherent context"),
                    ),
                },
            )
            .expect("a warning with its context"),
        })
        .expect("a stamped frame")
    }

    /// The exact Telegram snapshot, so a change to it is visible in review.
    #[test]
    fn the_telegram_view_renders_one_replaceable_snapshot() {
        let mut view = RunProgressView::new();
        let snapshot = view
            .absorb(&[
                tool_call(1, "read_file", StepStatus::InProgress),
                message(2, "half a sen", EventKind::AssistantMessageDelta),
            ])
            .expect("something to show");
        assert_eq!(snapshot, "read_file — in_progress\nhalf a sen");
        assert_eq!(view.cursor(), 2);

        // A snapshot replaces its predecessor, so the later text supersedes the
        // earlier one rather than being appended to it.
        let snapshot = view
            .absorb(&[
                tool_call(3, "read_file", StepStatus::Completed),
                message(4, "half a sentence", EventKind::AssistantMessageCompleted),
            ])
            .expect("something to show");
        assert_eq!(
            snapshot,
            "read_file — in_progress\nread_file — completed\nhalf a sentence"
        );

        // Nothing new means nothing to send: a renderer that redrew the same
        // words would spend a transport call to change nothing.
        assert_eq!(view.absorb(&[]), None);
        // And a re-delivered frame is ignored rather than folded twice.
        assert_eq!(
            view.absorb(&[tool_call(1, "read_file", StepStatus::Pending)]),
            None
        );
        assert_eq!(view.cursor(), 4);
    }

    #[test]
    fn the_telegram_view_bounds_its_step_lines() {
        let mut view = RunProgressView::new();
        let frames: Vec<ProgressFrame> = (1..=40)
            .map(|sequence| tool_call(sequence, &format!("step {sequence}"), StepStatus::Completed))
            .collect();
        let snapshot = view.absorb(&frames).expect("something to show");
        assert_eq!(snapshot.lines().count(), MAX_PROGRESS_STEP_LINES);
        // The most recent lines are the ones kept: a long run renders as what is
        // happening now.
        assert!(snapshot.contains("step 40 — completed"), "{snapshot}");
        assert!(!snapshot.contains("step 1 —"), "{snapshot}");
    }

    #[test]
    fn a_warning_is_marked_in_the_telegram_snapshot() {
        let mut view = RunProgressView::new();
        let snapshot = view
            .absorb(&[warning(1, "the provider asked us to slow down")])
            .expect("something to show");
        assert_eq!(snapshot, "⚠ the provider asked us to slow down");
    }

    /// The exact Slack chunk: appended lines, never a redraw.
    #[test]
    fn the_slack_card_appends_only_what_is_new() {
        let mut card = RunTaskCard::new();
        let lines = card.absorb(&[
            tool_call(1, "read_file", StepStatus::InProgress),
            message(2, "half a sen", EventKind::AssistantMessageDelta),
        ]);
        assert_eq!(
            lines,
            vec![
                String::from("• read_file _in_progress_"),
                String::from("half a sen"),
            ]
        );
        assert_eq!(card.cursor(), 2);

        // A preview repeated verbatim is not appended again — the reader has
        // already seen that sentence.
        let lines = card.absorb(&[
            message(3, "half a sen", EventKind::AssistantMessageDelta),
            message(4, "half a sentence", EventKind::AssistantMessageCompleted),
        ]);
        assert_eq!(lines, vec![String::from("half a sentence")]);

        // Nothing new is an empty chunk, which is a reason to append nothing.
        assert!(card.absorb(&[]).is_empty());
        assert!(
            card.absorb(&[tool_call(1, "read_file", StepStatus::Pending)])
                .is_empty(),
            "a re-delivered frame was appended a second time"
        );
    }

    #[test]
    fn the_slack_card_bounds_one_chunk() {
        let mut card = RunTaskCard::new();
        let frames: Vec<ProgressFrame> = (1..=64)
            .map(|sequence| tool_call(sequence, &format!("step {sequence}"), StepStatus::Completed))
            .collect();
        let lines = card.absorb(&frames);
        assert_eq!(lines.len(), MAX_TASK_CARD_LINES);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("• step 64 _completed_")
        );
    }

    #[test]
    fn a_warning_is_marked_in_the_slack_chunk() {
        let mut card = RunTaskCard::new();
        assert_eq!(
            card.absorb(&[warning(1, "the provider asked us to slow down")]),
            vec![String::from(":warning: the provider asked us to slow down")]
        );
    }

    /// Both renderers read the same live hub, from their own cursors.
    #[test]
    fn both_renderers_consume_the_same_hub_in_process() {
        let hub = ProgressHub::new();
        for frame in [
            tool_call(1, "read_file", StepStatus::InProgress),
            message(2, "an answer", EventKind::AssistantMessageCompleted),
        ] {
            hub.publish(
                RUN,
                frame.sequence(),
                &frame.to_canonical_bytes().expect("it encodes"),
            );
        }
        let mut view = RunProgressView::new();
        let mut card = RunTaskCard::new();
        assert_eq!(
            view.poll(&hub, RUN),
            Some(String::from("read_file — in_progress\nan answer"))
        );
        assert_eq!(
            card.poll(&hub, RUN),
            vec![
                String::from("• read_file _in_progress_"),
                String::from("an answer"),
            ]
        );
        assert_eq!(view.cursor(), 2);
        assert_eq!(card.cursor(), 2);
        // A second poll with nothing new changes nothing on either surface.
        assert_eq!(view.poll(&hub, RUN), None);
        assert!(card.poll(&hub, RUN).is_empty());
    }
}
