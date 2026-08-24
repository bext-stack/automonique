// SPDX-License-Identifier: Elastic-2.0

use automonique_agents::{
    JCODE_API_SCHEMA_ID, JCODE_API_STDIO_ARGUMENTS, JCODE_API_VERSION, JcodeEvent,
    JcodeExecutionIdentity, JcodeFrameDecoder, JcodeInterruptedReason, JcodeNativeAdapter,
    JcodeNativeEvent, JcodeNegotiation, JcodeProtocolError, JcodeRequest, JcodeTerminalOutcome,
    JcodeTurnCollector, REQUIRED_JCODE_CAPABILITIES, RunCoordinates, SessionScope,
    encode_jcode_request,
};

fn capabilities() -> String {
    REQUIRED_JCODE_CAPABILITIES
        .iter()
        .map(|capability| format!("\"{capability}\""))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn typed_requests_are_single_protocol_v1_frames() {
    let request = JcodeRequest::SendMessage {
        session_id: "session-1".to_owned(),
        content: "hello".to_owned(),
        images: Vec::new(),
        no_reply: false,
    };
    let encoded = encode_jcode_request(7, &request).expect("request encodes");
    assert_eq!(encoded.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("json");
    assert_eq!(value["v"], JCODE_API_VERSION);
    assert_eq!(value["id"], 7);
    assert_eq!(value["req"], "send_message");
    assert_eq!(value["content"], "hello");
    assert!(value.get("images").is_none());
    assert!(value.get("no_reply").is_none());

    let input = JcodeRequest::StdinResponse {
        session_id: "session-1".to_owned(),
        request_id: "stdin-1".to_owned(),
        input: "fixture input".to_owned(),
    };
    let encoded = encode_jcode_request(8, &input).expect("input encodes");
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains("\"req\":\"stdin_response\"")
    );
}

#[test]
fn handshake_requires_version_and_every_execution_capability() {
    let line = format!(
        "{{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/fixture\",\"capabilities\":[{}]}}\n",
        capabilities()
    );
    let mut decoder = JcodeFrameDecoder::new();
    let events = decoder.push(line.as_bytes()).expect("compatible hello");
    assert!(matches!(
        events.as_slice(),
        [JcodeEvent::HelloOk { reply_to: 1, .. }]
    ));

    let missing = line.replace("\"cancellation\",", "");
    let error = JcodeFrameDecoder::new()
        .push(missing.as_bytes())
        .unwrap_err();
    assert_eq!(error, JcodeProtocolError::MissingCapability);

    let incompatible = line.replace("\"v\":1", "\"v\":2");
    let error = JcodeFrameDecoder::new()
        .push(incompatible.as_bytes())
        .unwrap_err();
    assert_eq!(error, JcodeProtocolError::UnsupportedVersion);
}

#[test]
fn a_turn_binds_session_tools_input_usage_and_terminality() {
    let transcript = concat!(
        "{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"session-1\"}\n",
        "{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"session-1\",\"text\":\"hel\"}\n",
        "{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
        "{\"v\":1,\"ev\":\"tool_exec\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
        "{\"v\":1,\"ev\":\"tool_done\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\",\"output\":\"fixture\",\"error\":null}\n",
        "{\"v\":1,\"ev\":\"stdin_request\",\"session_id\":\"session-1\",\"request_id\":\"stdin-1\",\"prompt\":\"Continue?\",\"is_password\":false,\"tool_call_id\":\"call-1\"}\n",
        "{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"session-1\",\"text\":\"lo\"}\n",
        "{\"v\":1,\"ev\":\"token_usage\",\"session_id\":\"session-1\",\"input\":10,\"output\":2,\"cache_read_input\":3}\n",
        "{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"session-1\"}\n",
    );
    let mut decoder = JcodeFrameDecoder::new();
    let events = decoder.push(transcript.as_bytes()).expect("events decode");
    let mut turn = JcodeTurnCollector::new("session-1").expect("collector");
    for event in &events[..6] {
        turn.observe(event).expect("prefix accepted");
    }
    turn.resolve_input("stdin-1")
        .expect("authority resolved it");
    for event in &events[6..] {
        turn.observe(event).expect("suffix accepted");
    }
    let result = turn.finish().expect("terminal turn");
    assert_eq!(result.session_id(), "session-1");
    assert_eq!(result.text(), "hello");
    assert_eq!(result.input_tokens(), 10);
    assert_eq!(result.output_tokens(), 2);
    assert_eq!(result.cache_read_input_tokens(), 3);
}

fn execution_identity() -> JcodeExecutionIdentity {
    JcodeExecutionIdentity::pinned("a".repeat(64), "b".repeat(64), "jcode/fixture-0.79.1")
        .expect("pinned identity")
}

fn coordinates() -> RunCoordinates {
    RunCoordinates::new(
        "run-jcode-1",
        "turn-jcode-1",
        SessionScope::new("tenant-1", "account-1", "jcode").expect("scope"),
    )
    .expect("coordinates")
}

#[test]
fn execution_identity_pins_binary_configuration_schema_and_argv() {
    let identity = execution_identity();
    assert_eq!(identity.executable_sha256(), "a".repeat(64));
    assert_eq!(identity.configuration_sha256(), "b".repeat(64));
    assert_eq!(identity.schema_id(), JCODE_API_SCHEMA_ID);
    assert_eq!(identity.expected_server(), "jcode/fixture-0.79.1");
    assert_eq!(identity.arguments(), JCODE_API_STDIO_ARGUMENTS);
    assert_eq!(
        JcodeExecutionIdentity::pinned("not-a-digest", "b".repeat(64), "jcode/fixture")
            .unwrap_err(),
        JcodeProtocolError::InvalidField("executable_sha256")
    );
}

#[test]
fn compatible_fixture_gets_stable_turn_identity_and_read_order_sequences() {
    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    let mut envelopes = Vec::new();
    for chunk in include_bytes!("fixtures/jcode_api_stdio/complete_turn.jsonl").chunks(37) {
        envelopes.extend(adapter.push(chunk).expect("fixture chunk accepted"));
    }
    assert_eq!(
        envelopes
            .iter()
            .map(|envelope| envelope.sequence())
            .collect::<Vec<_>>(),
        (1..=envelopes.len() as u64).collect::<Vec<_>>()
    );
    assert!(envelopes.iter().all(|envelope| {
        envelope.run_id() == "run-jcode-1"
            && envelope.turn_id() == "turn-jcode-1"
            && envelope.identity() == &execution_identity()
    }));
    assert_eq!(
        envelopes.last().expect("terminal").event(),
        &JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::Completed,
            provider_code: None,
        }
    );
    assert_eq!(adapter.terminal(), Some(JcodeTerminalOutcome::Completed));
    assert_eq!(adapter.finish_eof().expect("idempotent EOF"), None);
}

#[test]
fn negotiation_is_first_correlated_and_bound_to_the_reported_server() {
    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    assert_eq!(
        adapter
            .push(b"{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"session-1\"}\n")
            .unwrap_err(),
        JcodeProtocolError::HandshakeRequired
    );

    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    assert_eq!(
        adapter
            .push(b"{\"v\":1,\"reply_to\":12,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/fixture-0.79.1\",\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}\n")
            .unwrap_err(),
        JcodeProtocolError::ReplyMismatch
    );

    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    assert_eq!(
        adapter
            .push(b"{\"v\":1,\"reply_to\":11,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/drifted\",\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}\n")
            .unwrap_err(),
        JcodeProtocolError::IdentityMismatch
    );
}

#[test]
fn eof_is_one_interrupted_unknown_terminal_never_success() {
    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    let prefix = adapter
        .push(include_bytes!(
            "fixtures/jcode_api_stdio/eof_before_terminal.jsonl"
        ))
        .expect("prefix");
    let terminal = adapter
        .finish_eof()
        .expect("EOF settles")
        .expect("first EOF emits terminal");
    assert_eq!(terminal.sequence(), prefix.len() as u64 + 1);
    assert_eq!(
        terminal.event(),
        &JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::InterruptedUnknown(JcodeInterruptedReason::ProviderEof),
            provider_code: None,
        }
    );
    assert_eq!(adapter.finish_eof().expect("second EOF"), None);

    let mut partial =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    let incomplete = include_bytes!("fixtures/jcode_api_stdio/incomplete_frame.jsonl");
    partial
        .push(&incomplete[..incomplete.len() - 1])
        .expect("complete prefix accepted");
    assert!(matches!(
        partial
            .finish_eof()
            .expect("EOF")
            .expect("terminal")
            .event(),
        JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::InterruptedUnknown(
                JcodeInterruptedReason::IncompleteFrame
            ),
            ..
        }
    ));
}

#[test]
fn a_second_terminal_or_cross_session_frame_fails_closed() {
    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    assert_eq!(
        adapter
            .push(include_bytes!(
                "fixtures/jcode_api_stdio/duplicate_terminal.jsonl"
            ))
            .unwrap_err(),
        JcodeProtocolError::EventOrder
    );

    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    adapter
        .push(include_bytes!(
            "fixtures/jcode_api_stdio/eof_before_terminal.jsonl"
        ))
        .expect("prefix");
    assert_eq!(
        adapter
            .push(b"{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"session-other\",\"text\":\"wrong\"}\n")
            .unwrap_err(),
        JcodeProtocolError::SessionMismatch
    );
}

#[test]
fn a_correlated_provider_error_is_one_failed_terminal() {
    let mut adapter =
        JcodeNativeAdapter::new(execution_identity(), &coordinates(), 11, 13).expect("adapter");
    adapter
        .push(include_bytes!(
            "fixtures/jcode_api_stdio/eof_before_terminal.jsonl"
        ))
        .expect("prefix");
    let terminal = adapter
        .push(b"{\"v\":1,\"reply_to\":13,\"ev\":\"error\",\"code\":\"internal\"}\n")
        .expect("correlated error")
        .pop()
        .expect("terminal");
    assert_eq!(
        terminal.event(),
        &JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::ProviderFailed,
            provider_code: Some("internal".to_owned()),
        }
    );
    assert_eq!(adapter.finish_eof().expect("EOF after terminal"), None);
}

#[test]
fn a_process_negotiation_token_starts_a_bound_turn_and_preserves_upstream_eof_state() {
    let mut decoder = JcodeFrameDecoder::new();
    let hello = decoder
        .push(include_bytes!(
            "fixtures/jcode_api_stdio/eof_before_terminal.jsonl"
        ))
        .expect("fixture")
        .remove(0);
    let negotiation = JcodeNegotiation::accept(execution_identity(), 11, &hello)
        .expect("exact hello creates token");
    let mut adapter =
        JcodeNativeAdapter::after_negotiation(negotiation, &coordinates(), 13, "session-1")
            .expect("bound turn");
    let accepted = adapter
        .observe_decoded(JcodeEvent::MessageAccepted {
            session_id: "session-1".to_owned(),
        })
        .expect("decoded event");
    assert_eq!(accepted.sequence(), 1);
    let terminal = adapter
        .finish_eof_with_pending_frame(true)
        .expect("EOF")
        .expect("one terminal");
    assert_eq!(terminal.sequence(), 2);
    assert!(matches!(
        terminal.event(),
        JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::InterruptedUnknown(
                JcodeInterruptedReason::IncompleteFrame
            ),
            ..
        }
    ));
    assert_eq!(adapter.finish_eof().expect("repeat EOF"), None);
}

#[test]
fn a_supervisor_cancel_settles_the_native_turn_once_as_cancelled() {
    let mut decoder = JcodeFrameDecoder::new();
    let hello = decoder
        .push(include_bytes!(
            "fixtures/jcode_api_stdio/eof_before_terminal.jsonl"
        ))
        .expect("fixture")
        .remove(0);
    let negotiation = JcodeNegotiation::accept(execution_identity(), 11, &hello).expect("hello");
    let mut adapter =
        JcodeNativeAdapter::after_negotiation(negotiation, &coordinates(), 13, "session-1")
            .expect("bound turn");
    adapter
        .observe_decoded(JcodeEvent::MessageAccepted {
            session_id: "session-1".to_owned(),
        })
        .expect("accepted");
    adapter.mark_cancellation_requested().expect("cancel bound");
    assert_eq!(
        adapter.mark_cancellation_requested().unwrap_err(),
        JcodeProtocolError::EventOrder
    );
    let terminal = adapter
        .observe_decoded(JcodeEvent::TurnDone {
            session_id: "session-1".to_owned(),
        })
        .expect("terminal");
    assert_eq!(
        terminal.event(),
        &JcodeNativeEvent::Terminal {
            outcome: JcodeTerminalOutcome::Cancelled,
            provider_code: None,
        }
    );
    assert_eq!(adapter.finish_eof().expect("EOF"), None);
}

#[test]
fn duplicate_frames_cross_session_events_and_unfinished_turns_fail_closed() {
    let mut decoder = JcodeFrameDecoder::new();
    let events = decoder
        .push(b"{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"session-2\"}\n")
        .expect("frame");
    let mut turn = JcodeTurnCollector::new("session-1").expect("collector");
    assert_eq!(
        turn.observe(&events[0]),
        Err(JcodeProtocolError::SessionMismatch)
    );
    assert_eq!(turn.finish().unwrap_err(), JcodeProtocolError::EventOrder);

    let duplicate = concat!(
        "{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"session-1\"}\n",
        "{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
        "{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
    );
    let events = JcodeFrameDecoder::new()
        .push(duplicate.as_bytes())
        .expect("frames");
    let mut turn = JcodeTurnCollector::new("session-1").expect("collector");
    turn.observe(&events[0]).unwrap();
    turn.observe(&events[1]).unwrap();
    assert_eq!(
        turn.observe(&events[2]),
        Err(JcodeProtocolError::EventOrder)
    );
}

#[test]
fn additive_events_are_bounded_and_skipped_by_safe_kind() {
    let mut decoder = JcodeFrameDecoder::new();
    let events = decoder
        .push(b"{\"v\":1,\"ev\":\"future_progress\",\"secret\":\"not retained\"}\n")
        .expect("additive event");
    assert_eq!(
        events,
        vec![JcodeEvent::Unknown {
            kind: "future_progress".to_owned()
        }]
    );
}
