// SPDX-License-Identifier: Elastic-2.0

use automonique_agents::{
    JCODE_API_VERSION, JcodeEvent, JcodeFrameDecoder, JcodeProtocolError, JcodeRequest,
    JcodeTurnCollector, PermissionDecision, REQUIRED_JCODE_CAPABILITIES, encode_jcode_request,
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

    let permission = JcodeRequest::PermissionResponse {
        session_id: "session-1".to_owned(),
        request_id: "permission-1".to_owned(),
        decision: PermissionDecision::Deny,
    };
    let encoded = encode_jcode_request(8, &permission).expect("decision encodes");
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains("\"decision\":\"deny\"")
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
fn a_turn_binds_session_tools_permissions_usage_and_terminality() {
    let transcript = concat!(
        "{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"session-1\"}\n",
        "{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"session-1\",\"text\":\"hel\"}\n",
        "{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
        "{\"v\":1,\"ev\":\"tool_exec\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\"}\n",
        "{\"v\":1,\"ev\":\"tool_done\",\"session_id\":\"session-1\",\"call_id\":\"call-1\",\"name\":\"read\",\"output\":\"fixture\",\"error\":null}\n",
        "{\"v\":1,\"ev\":\"permission_request\",\"session_id\":\"session-1\",\"request_id\":\"permission-1\",\"tool_name\":\"write\",\"description\":\"fixture request\"}\n",
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
    turn.resolve_permission("permission-1")
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
