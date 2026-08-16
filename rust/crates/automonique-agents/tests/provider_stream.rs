// SPDX-License-Identifier: Elastic-2.0

//! Byte-exact proofs for the incremental provider event stream.
//!
//! # Fixture provenance
//!
//! The JSONL lines below are hand-written to the event vocabulary this crate's
//! normalizer accepts (`src/normalize.rs` at HEAD), and match the shapes
//! already pinned by `tests/codex_adapter.rs`. **No provider CLI was executed
//! to produce them, no network was contacted, and no provider credential was
//! read.** They are fixture bytes: the `thread_id` is the literal
//! `fixture-session`, and every text value is test content.

use automonique_agents::{
    AdapterError, ExecutionMode, MAX_JSONL_LINE_BYTES, MAX_STREAM_EVENTS, NormalizedEvent,
    ProviderDisposition, ProviderEventStream, RunCoordinates, SessionScope, StreamPolicy,
    normalize_jsonl,
};

/// One complete successful turn, exactly as the normalizer accepts it.
const SUCCESS_FIXTURE: &str = concat!(
    "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n",
    "{\"type\":\"turn.started\"}\n",
    "{\"type\":\"item.started\",\"item\":{\"id\":\"message-1\",\"type\":\"agent_message\"}}\n",
    "{\"type\":\"item.updated\",\"item\":{\"id\":\"message-1\",\"type\":\"agent_message\",\"text\":\"preview fragment\"}}\n",
    "{\"type\":\"item.completed\",\"item\":{\"id\":\"message-1\",\"type\":\"agent_message\",\"text\":\"final answer\"}}\n",
    "{\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":1,\"input_tokens\":2,\"output_tokens\":3}}\n",
);

/// The prefix every ordering-sensitive fixture needs before its own line.
const OPEN_TURN: &str = concat!(
    "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n",
    "{\"type\":\"turn.started\"}\n",
);

fn scope() -> SessionScope {
    SessionScope::new("tenant-a", "codex-account", "codex-cli").expect("scope")
}

fn coordinates() -> RunCoordinates {
    RunCoordinates::new("run-1", "turn-1", scope()).expect("coordinates")
}

/// A total, comparable rendering of one normalized event.
fn summary(event: &NormalizedEvent) -> String {
    match event {
        NormalizedEvent::Preview {
            sequence,
            run_id,
            turn_id,
            provider_session_id,
            text,
        } => format!("{sequence}|preview|{run_id}|{turn_id}|{provider_session_id}|{text}"),
        NormalizedEvent::Recorded(recorded) => format!(
            "{}|{:?}|{}|{}|{}|{}",
            recorded.sequence(),
            recorded.kind(),
            recorded.run_id(),
            recorded.turn_id(),
            recorded.provider_session_id(),
            recorded.text().unwrap_or("")
        ),
    }
}

fn summaries(events: &[NormalizedEvent]) -> Vec<String> {
    events.iter().map(summary).collect()
}

/// The one true expansion of [`SUCCESS_FIXTURE`].
fn expected_success_events() -> Vec<String> {
    vec![
        "1|SessionCreated|run-1|turn-1|fixture-session|".to_owned(),
        "2|TurnStarted|run-1|turn-1|fixture-session|".to_owned(),
        "3|preview|run-1|turn-1|fixture-session|preview fragment".to_owned(),
        "4|AssistantMessageCompleted|run-1|turn-1|fixture-session|final answer".to_owned(),
        "5|UsageUpdated|run-1|turn-1|fixture-session|".to_owned(),
        "6|TurnCompleted|run-1|turn-1|fixture-session|".to_owned(),
    ]
}

/// Feed `bytes` in one chunk and finish.
fn parse_all(bytes: &[u8]) -> Result<Vec<String>, AdapterError> {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);
    stream.push_bytes(bytes)?;
    let transcript = stream.finish()?;
    Ok(summaries(transcript.events()))
}

#[test]
fn fixture_lines_become_exactly_these_normalized_events() {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);

    let accepted = stream
        .push_bytes(SUCCESS_FIXTURE.as_bytes())
        .expect("fixture accepted");
    assert_eq!(accepted, 6, "six events complete from six lines");
    assert_eq!(stream.pending_bytes(), 0);
    assert_eq!(stream.total_bytes(), SUCCESS_FIXTURE.len());
    assert_eq!(summaries(stream.events()), expected_success_events());

    let transcript = stream.finish().expect("complete transcript");
    assert_eq!(transcript.disposition(), ProviderDisposition::Succeeded);
    let usage = transcript.usage().expect("provider usage");
    assert_eq!(usage.cached_input_tokens(), 1);
    assert_eq!(usage.input_tokens(), 2);
    assert_eq!(usage.output_tokens(), 3);
    assert_eq!(
        transcript.binding().provider_session_id(),
        "fixture-session"
    );
    assert_eq!(summaries(transcript.events()), expected_success_events());
}

#[test]
fn chunk_boundaries_cannot_change_the_result() {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);

    // One byte at a time splits every line, every JSON token, and the
    // multi-byte-free ASCII payload at arbitrary points.
    let mut accepted_total = 0;
    for byte in SUCCESS_FIXTURE.as_bytes() {
        accepted_total += stream
            .push_bytes(&[*byte])
            .expect("single byte accepted or held");
    }
    assert_eq!(accepted_total, 6);
    let transcript = stream.finish().expect("transcript");
    assert_eq!(summaries(transcript.events()), expected_success_events());
    assert_eq!(transcript.disposition(), ProviderDisposition::Succeeded);

    // A multi-byte character split across two chunks must still round-trip.
    let line = "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n\
                {\"type\":\"turn.started\"}\n\
                {\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}\n\
                {\"type\":\"item.updated\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"héllo\"}}\n";
    let split = line.find('é').expect("multi-byte character") + 1;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);
    stream
        .push_bytes(&line.as_bytes()[..split])
        .expect("first half held");
    stream
        .push_bytes(&line.as_bytes()[split..])
        .expect("second half completes");
    assert_eq!(
        summary(&stream.events()[2]),
        "3|preview|run-1|turn-1|fixture-session|héllo"
    );
}

#[test]
fn the_whole_buffer_path_and_the_stream_agree() {
    let transcript = normalize_jsonl(
        &coordinates(),
        &ExecutionMode::NewSession,
        SUCCESS_FIXTURE.as_bytes(),
    )
    .expect("whole-buffer normalization");
    assert_eq!(
        summaries(transcript.events()),
        parse_all(SUCCESS_FIXTURE.as_bytes()).expect("streamed normalization"),
        "the live and captured paths must not be two grammars"
    );
}

#[test]
fn an_unknown_event_kind_is_refused_and_named_without_echoing_the_payload() {
    let payload = "secret-workspace-content-do-not-echo";
    let line = format!("{{\"type\":\"turn.interrupted\",\"reason\":\"{payload}\"}}\n");
    let error = parse_all(line.as_bytes()).expect_err("unknown kind refused");
    assert_eq!(error.category(), "unknown_event");
    assert_eq!(
        error.unknown_kind().expect("kind named").as_str(),
        "turn.interrupted"
    );
    let message = error.to_string();
    assert!(
        message.contains("turn.interrupted"),
        "the refusal must name the kind: {message}"
    );
    assert!(
        !message.contains(payload),
        "the refusal must never echo payload bytes: {message}"
    );
}

#[test]
fn an_unknown_item_type_is_named_distinctly_from_the_event_that_carried_it() {
    // `item.started` is a known event; `tool_call` is not a known item.
    let line = format!(
        "{OPEN_TURN}{{\"type\":\"item.started\",\"item\":{{\"id\":\"item-1\",\"type\":\"tool_call\"}}}}\n"
    );
    let error = parse_all(line.as_bytes()).expect_err("unknown item refused");
    assert_eq!(error.category(), "unknown_event");
    assert_eq!(
        error.unknown_kind().expect("kind named").as_str(),
        "item:tool_call"
    );
}

#[test]
fn an_unnameable_kind_collapses_to_a_placeholder_rather_than_leaking_bytes() {
    let spaced = parse_all(b"{\"type\":\"kind with spaces\"}\n").expect_err("refused");
    assert_eq!(
        spaced.unknown_kind().expect("kind").as_str(),
        "<unprintable>",
        "a token outside the keyword character set is not repeated back"
    );
    assert!(!spaced.to_string().contains("kind with spaces"));

    let oversized = format!("{{\"type\":\"{}\"}}\n", "k".repeat(65));
    let error = parse_all(oversized.as_bytes()).expect_err("refused");
    assert_eq!(error.unknown_kind().expect("kind").as_str(), "<oversized>");

    let empty = parse_all(b"{\"type\":\"\"}\n").expect_err("refused");
    assert_eq!(empty.unknown_kind().expect("kind").as_str(), "<empty>");
}

#[test]
fn an_oversized_line_is_refused_before_it_is_buffered_and_stays_refused() {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);

    // No newline anywhere: the bound must apply to what is held, not only to
    // what completed.
    let flood = vec![b'x'; MAX_JSONL_LINE_BYTES + 1];
    let error = stream
        .push_bytes(&flood)
        .expect_err("oversized line refused");
    assert_eq!(error.category(), "output_too_large");

    // A refused stream stays refused, with the same reason, and accepts
    // nothing afterwards.
    let again = stream
        .push_bytes(b"{\"type\":\"turn.started\"}\n")
        .expect_err("stream stays refused");
    assert_eq!(again.category(), "output_too_large");
    assert!(stream.events().is_empty());
    assert_eq!(
        stream
            .finish()
            .expect_err("finish stays refused")
            .category(),
        "output_too_large"
    );

    // The same bound applies to a line that does terminate.
    let terminated = format!(
        "{{\"type\":\"thread.started\",\"thread_id\":\"{}\"}}\n",
        "x".repeat(MAX_JSONL_LINE_BYTES)
    );
    assert_eq!(
        parse_all(terminated.as_bytes())
            .expect_err("terminated oversized line refused")
            .category(),
        "output_too_large"
    );
}

#[test]
fn a_truncated_final_line_is_held_while_streaming_and_refused_at_finish() {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let complete = SUCCESS_FIXTURE.as_bytes();
    // Cut inside the final `turn.completed` line, after its own newline-
    // terminated predecessors.
    let final_line_start = complete[..complete.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("a preceding line exists")
        + 1;
    let cut = complete.len() - 12;

    let mut stream = ProviderEventStream::new(&coordinates, &mode);
    stream
        .push_bytes(&complete[..cut])
        .expect("prefix accepted");
    assert_eq!(
        stream.pending_bytes(),
        cut - final_line_start,
        "the incomplete line is held, not parsed"
    );
    assert_eq!(
        summaries(stream.events()),
        expected_success_events()[..4].to_vec(),
        "only the completed lines produced events"
    );
    assert_eq!(
        stream
            .finish()
            .expect_err("an incomplete final line cannot be a complete transcript")
            .category(),
        "incomplete_final_line"
    );

    // Holding is not losing: the remainder completes the same line.
    let mut stream = ProviderEventStream::new(&coordinates, &mode);
    stream.push_bytes(&complete[..cut]).expect("prefix");
    stream.push_bytes(&complete[cut..]).expect("remainder");
    let transcript = stream.finish().expect("completed transcript");
    assert_eq!(summaries(transcript.events()), expected_success_events());
}

#[test]
fn too_many_events_are_refused_rather_than_dropped() {
    let coordinates = coordinates();
    let mode = ExecutionMode::NewSession;
    let mut stream = ProviderEventStream::new(&coordinates, &mode);
    stream
        .push_bytes(OPEN_TURN.as_bytes())
        .expect("turn opened");
    stream
        .push_bytes(
            b"{\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}\n",
        )
        .expect("item opened");

    // Two events exist already, and each update adds exactly one more.
    let update =
        b"{\"type\":\"item.updated\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"f\"}}\n";
    let mut refusal = None;
    for _ in 0..MAX_STREAM_EVENTS {
        if let Err(error) = stream.push_bytes(update) {
            refusal = Some(error);
            break;
        }
    }
    let refusal = refusal.expect("the event ceiling must be reached");
    assert_eq!(refusal.category(), "too_many_events");
    assert_eq!(
        stream.events().len(),
        MAX_STREAM_EVENTS + 1,
        "the refusal fires on the event that crossed the ceiling"
    );
}

#[test]
fn framing_and_encoding_faults_fail_closed() {
    assert_eq!(
        parse_all(b"\n").expect_err("blank line refused").category(),
        "invalid_json",
        "a blank line means the writer lost framing"
    );
    assert_eq!(
        parse_all(b"{\"type\":\"thread.started\",\"thread_id\":\"\xff\"}\n")
            .expect_err("invalid utf-8 refused")
            .category(),
        "invalid_utf8"
    );
    assert_eq!(
        parse_all(
            b"{\"type\":\"thread.started\",\"type\":\"thread.started\",\"thread_id\":\"x\"}\n"
        )
        .expect_err("duplicate key refused")
        .category(),
        "invalid_json"
    );
    assert_eq!(
        parse_all(b"{\"type\":\"turn.started\"}\n")
            .expect_err("out-of-order refused")
            .category(),
        "event_order"
    );
    // A stream that never reached a disposition is not a transcript.
    assert_eq!(
        parse_all(OPEN_TURN.as_bytes())
            .expect_err("no disposition")
            .category(),
        "event_order"
    );
}

#[test]
fn session_policy_warns_on_garbage_and_continues_to_the_terminal_result() {
    let mut bytes = String::from(OPEN_TURN);
    bytes.push_str("this is not json\n");
    bytes.push_str(
        "{\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}\n\
         {\"type\":\"item.completed\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"done\"}}\n\
         {\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":0,\"input_tokens\":1,\"output_tokens\":1}}\n",
    );
    let mut stream = ProviderEventStream::with_policy(
        &coordinates(),
        &ExecutionMode::NewSession,
        StreamPolicy::Session,
    );
    stream
        .push_bytes(bytes.as_bytes())
        .expect("session continues");
    assert_eq!(stream.warning_count(), 1);
    let transcript = stream.finish_session(true).expect("terminal transcript");
    assert_eq!(transcript.warning_count(), 1);
    assert_eq!(transcript.disposition(), ProviderDisposition::Succeeded);
}

#[test]
fn session_policy_turns_truncation_or_nonzero_exit_into_failed_completion() {
    for (bytes, exit_success, warnings) in [
        (format!("{OPEN_TURN}{{\"type\":\"item.started\""), true, 1),
        (OPEN_TURN.to_owned(), false, 0),
    ] {
        let mut stream = ProviderEventStream::with_policy(
            &coordinates(),
            &ExecutionMode::NewSession,
            StreamPolicy::Session,
        );
        stream
            .push_bytes(bytes.as_bytes())
            .expect("prefix accepted");
        let transcript = stream
            .finish_session(exit_success)
            .expect("supervisor terminalizes failure");
        assert_eq!(transcript.warning_count(), warnings);
        assert_eq!(transcript.disposition(), ProviderDisposition::Failed);
        assert!(transcript.events().iter().any(|event| matches!(
            event,
            NormalizedEvent::Recorded(recorded)
                if recorded.kind() == automonique_agents::RecordedKind::TurnCompleted
        )));
    }
}
