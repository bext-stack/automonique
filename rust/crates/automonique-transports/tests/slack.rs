// SPDX-License-Identifier: Elastic-2.0

use automonique_transports::{
    MAX_SLACK_ENVELOPE_BYTES, MAX_SLACK_IDENTIFIER_BYTES, MAX_SLACK_RETRY_ATTEMPT,
    MAX_SLACK_TEXT_BYTES, SlackAccessPolicy, SlackAckPlan, SlackAppId, SlackDisposition,
    SlackEnvelopeId, SlackEnvelopeType, SlackError, SlackIngress, SlackInputKind, SlackPrincipal,
    SlackRefusal, parse_slack_envelope,
};

const FIRST_KEY: &str = "11111111-2222-3333-4444-555555555555";
const SECOND_KEY: &str = "99999999-8888-7777-6666-555555555555";

fn policy() -> SlackAccessPolicy {
    SlackAccessPolicy::new(
        SlackAppId::new("A0FIRST").expect("app"),
        [SlackPrincipal::new("T01TEAM", "C01CHAN", "U01USER").expect("principal")],
    )
    .expect("policy")
}

/// A plain user message event with the given JSON-encoded `text`.
fn message_event(text: &str) -> String {
    format!(
        r#"{{"channel":"C01CHAN","text":{text},"ts":"1700000000.000100","type":"message","user":"U01USER"}}"#
    )
}

/// A well-formed `events_api` frame wrapping `event`.
fn events_api(envelope_id: &str, retry_attempt: u32, event: &str) -> String {
    format!(
        r#"{{"accepts_response_payload":false,"envelope_id":"{envelope_id}","payload":{{"event":{event},"team_id":"T01TEAM","type":"event_callback"}},"retry_attempt":{retry_attempt},"type":"events_api"}}"#
    )
}

/// An `events_api` frame with a fixed short ack key, for refusal tables.
fn keyed_event(event: &str) -> String {
    format!(
        r#"{{"envelope_id":"E1","payload":{{"event":{event},"team_id":"T01TEAM","type":"event_callback"}},"type":"events_api"}}"#
    )
}

/// A string carrying an embedded NUL, JSON-escaped by `serde_json`.
///
/// Built from bytes so the source file itself stays free of control characters:
/// the resulting JSON is syntactically valid and exercises the parser's own
/// character bounds rather than the JSON reader's.
fn nul_string() -> String {
    String::from_utf8(vec![b'a', 0, b'b']).expect("utf-8")
}

fn json(value: &str) -> String {
    serde_json::to_string(value).expect("json string")
}

fn ack_key(plan: &SlackAckPlan) -> Option<&str> {
    plan.ack_key().map(SlackEnvelopeId::as_str)
}

fn planned_ack(plan: &SlackAckPlan) -> Option<&str> {
    plan.planned_ack().map(SlackEnvelopeId::as_str)
}

#[test]
fn admitted_message_has_exact_coordinates_and_a_plan_then_ack_decision() {
    let frame = events_api(FIRST_KEY, 0, &message_event(r#""deploy please""#));
    let envelope = parse_slack_envelope(frame.as_bytes(), &policy()).expect("envelope");

    assert_eq!(envelope.envelope_type(), Some(SlackEnvelopeType::EventsApi));
    assert_eq!(envelope.disposition(), SlackDisposition::Admitted);
    assert!(!envelope.accepts_response_payload());
    assert!(!envelope.retry().is_redelivery());
    assert_eq!(
        envelope.envelope_id().map(SlackEnvelopeId::as_str),
        Some(FIRST_KEY)
    );

    let ingress = envelope.ingress().expect("ingress");
    assert_eq!(
        ingress.source_key(),
        "slack:A0FIRST:T01TEAM:C01CHAN:1700000000.000100"
    );
    assert_eq!(ingress.scope(), "slack:A0FIRST:T01TEAM:C01CHAN");
    assert_eq!(ingress.kind(), SlackInputKind::Message);
    assert_eq!(ingress.content(), Some("deploy please"));
    assert_eq!(ingress.principal().team(), "T01TEAM");
    assert_eq!(ingress.principal().channel(), "C01CHAN");
    assert_eq!(ingress.principal().user(), "U01USER");

    // Plan-then-ack: this layer names a key to send later; it sends nothing.
    assert_eq!(planned_ack(envelope.ack()), Some(FIRST_KEY));
    assert_eq!(
        *envelope.ack(),
        SlackAckPlan::AckAfterDurableRecord(SlackEnvelopeId::new(FIRST_KEY).unwrap())
    );
}

#[test]
fn app_mention_is_admitted_with_its_own_input_kind() {
    let event = r#"{"channel":"C01CHAN","text":"<@U0BOT> status","ts":"1700000000.000300","type":"app_mention","user":"U01USER"}"#;
    let envelope = parse_slack_envelope(events_api(FIRST_KEY, 0, event).as_bytes(), &policy())
        .expect("mention");
    assert_eq!(envelope.disposition(), SlackDisposition::Admitted);
    let ingress = envelope.ingress().expect("ingress");
    assert_eq!(ingress.kind(), SlackInputKind::AppMention);
    assert_eq!(ingress.content(), Some("<@U0BOT> status"));
}

#[test]
fn denied_actor_is_content_free_durable_evidence_and_is_still_acknowledged() {
    let event = r#"{"channel":"C01CHAN","text":"secret plan","ts":"1700000000.000200","type":"message","user":"U09OTHER"}"#;
    let envelope = parse_slack_envelope(events_api(FIRST_KEY, 0, event).as_bytes(), &policy())
        .expect("denial");

    assert_eq!(envelope.disposition(), SlackDisposition::Denied);
    let ingress = envelope.ingress().expect("denial is durable evidence");
    assert_eq!(ingress.content(), None);
    assert_eq!(
        ingress.source_key(),
        "slack:A0FIRST:T01TEAM:C01CHAN:1700000000.000200"
    );
    // The access outcome never changes the ack: withholding here would make
    // Slack redeliver every denied message.
    assert_eq!(planned_ack(envelope.ack()), Some(FIRST_KEY));

    let rendered = format!("{envelope:?}");
    assert!(!rendered.contains("secret plan"), "{rendered}");
    assert!(!rendered.contains("U09OTHER"), "{rendered}");
    assert!(!rendered.contains("C01CHAN"), "{rendered}");
    assert!(!rendered.contains("T01TEAM"), "{rendered}");
    assert!(!rendered.contains("A0FIRST"), "{rendered}");
}

#[test]
fn text_bound_is_byte_exact_and_one_over_refuses_without_wedging() {
    let at_limit = "x".repeat(MAX_SLACK_TEXT_BYTES);
    let frame = events_api(FIRST_KEY, 0, &message_event(&json(&at_limit)));
    let admitted = parse_slack_envelope(frame.as_bytes(), &policy()).expect("at-limit text");
    assert_eq!(admitted.disposition(), SlackDisposition::Admitted);
    assert_eq!(
        admitted
            .ingress()
            .and_then(SlackIngress::content)
            .map(str::len),
        Some(MAX_SLACK_TEXT_BYTES)
    );

    let over_limit = "x".repeat(MAX_SLACK_TEXT_BYTES + 1);
    let frame = events_api(SECOND_KEY, 0, &message_event(&json(&over_limit)));
    let refused = parse_slack_envelope(frame.as_bytes(), &policy()).expect("refusal, not an error");
    assert_eq!(
        refused.disposition(),
        SlackDisposition::Refused(SlackRefusal::InvalidField("text"))
    );
    assert!(refused.ingress().is_none());
    assert_eq!(planned_ack(refused.ack()), None);
    assert_eq!(ack_key(refused.ack()), Some(SECOND_KEY));

    // One oversized frame wedges nothing: the next frame still admits.
    let next = events_api(FIRST_KEY, 0, &message_event(r#""ok""#));
    assert_eq!(
        parse_slack_envelope(next.as_bytes(), &policy())
            .expect("next frame")
            .disposition(),
        SlackDisposition::Admitted
    );
}

#[test]
fn redelivery_keeps_the_dedup_identity_while_the_ack_key_changes() {
    let event = message_event(r#""ship it""#);
    let first = parse_slack_envelope(events_api(FIRST_KEY, 0, &event).as_bytes(), &policy())
        .expect("first delivery");
    let redelivery = format!(
        r#"{{"accepts_response_payload":false,"envelope_id":"{SECOND_KEY}","payload":{{"event":{event},"team_id":"T01TEAM","type":"event_callback"}},"retry_attempt":2,"retry_reason":"timeout","type":"events_api"}}"#
    );
    let second = parse_slack_envelope(redelivery.as_bytes(), &policy()).expect("redelivery");

    // (team_id, channel, ts) is the dedup identity and survives redelivery.
    assert_eq!(
        first.ingress().expect("first").source_key(),
        second.ingress().expect("second").source_key()
    );
    // envelope_id is per delivery attempt and is not part of that identity.
    assert_ne!(first.envelope_id(), second.envelope_id());
    assert!(
        !first
            .ingress()
            .expect("first")
            .source_key()
            .contains(FIRST_KEY)
    );
    assert_eq!(planned_ack(first.ack()), Some(FIRST_KEY));
    assert_eq!(planned_ack(second.ack()), Some(SECOND_KEY));

    assert!(!first.retry().is_redelivery());
    assert_eq!(first.retry().attempt(), 0);
    assert_eq!(first.retry().reason(), None);
    assert!(second.retry().is_redelivery());
    assert_eq!(second.retry().attempt(), 2);
    assert_eq!(second.retry().reason(), Some("timeout"));
}

#[test]
fn retry_attempt_bound_is_exact() {
    let event = message_event(r#""x""#);
    let at_limit = parse_slack_envelope(
        events_api(FIRST_KEY, MAX_SLACK_RETRY_ATTEMPT, &event).as_bytes(),
        &policy(),
    )
    .expect("at-limit retry");
    assert_eq!(at_limit.disposition(), SlackDisposition::Admitted);
    assert_eq!(at_limit.retry().attempt(), MAX_SLACK_RETRY_ATTEMPT);

    let over = parse_slack_envelope(
        events_api(FIRST_KEY, MAX_SLACK_RETRY_ATTEMPT + 1, &event).as_bytes(),
        &policy(),
    )
    .expect("refusal keeps the key");
    assert_eq!(
        over.disposition(),
        SlackDisposition::Refused(SlackRefusal::InvalidField("retry_attempt"))
    );
    assert_eq!(ack_key(over.ack()), Some(FIRST_KEY));
    assert_eq!(planned_ack(over.ack()), None);
}

#[test]
fn source_identity_is_distinct_for_the_same_event_on_two_apps() {
    let frame = events_api(FIRST_KEY, 0, &message_event(r#""x""#));
    let first = parse_slack_envelope(frame.as_bytes(), &policy()).expect("first app");
    let second_policy = SlackAccessPolicy::new(
        SlackAppId::new("A0SECOND").unwrap(),
        [SlackPrincipal::new("T01TEAM", "C01CHAN", "U01USER").unwrap()],
    )
    .unwrap();
    let second = parse_slack_envelope(frame.as_bytes(), &second_policy).expect("second app");
    assert_ne!(
        first.ingress().expect("first").source_key(),
        second.ingress().expect("second").source_key()
    );
    assert_ne!(
        first.ingress().expect("first").scope(),
        second.ingress().expect("second").scope()
    );
}

#[test]
fn control_frames_are_never_acknowledged() {
    for frame in [
        r#"{"connection_info":{"app_id":"A0FIRST"},"debug_info":{"host":"applink-1"},"num_connections":1,"type":"hello"}"#,
        r#"{"debug_info":{"host":"applink-1"},"reason":"warning","type":"disconnect"}"#,
    ] {
        let envelope = parse_slack_envelope(frame.as_bytes(), &policy()).expect("control frame");
        assert_eq!(envelope.disposition(), SlackDisposition::ConnectionControl);
        assert_eq!(*envelope.ack(), SlackAckPlan::NeverAcknowledged);
        assert_eq!(planned_ack(envelope.ack()), None, "{frame}");
        assert_eq!(ack_key(envelope.ack()), None, "{frame}");
        assert!(envelope.ingress().is_none(), "{frame}");
        assert!(envelope.envelope_id().is_none(), "{frame}");
        assert!(
            envelope
                .envelope_type()
                .is_some_and(|kind| !kind.is_acknowledgeable()),
            "{frame}"
        );
    }
}

#[test]
fn unknown_envelope_type_refuses_but_still_surfaces_the_ack_key() {
    let envelope = parse_slack_envelope(
        format!(r#"{{"envelope_id":"{FIRST_KEY}","payload":{{}},"type":"events_api_v2"}}"#)
            .as_bytes(),
        &policy(),
    )
    .expect("unknown type is a refusal, not a hard error");

    assert_eq!(
        envelope.disposition(),
        SlackDisposition::Refused(SlackRefusal::UnknownEnvelopeType)
    );
    assert_eq!(envelope.envelope_type(), None);
    assert_eq!(
        envelope.envelope_id().map(SlackEnvelopeId::as_str),
        Some(FIRST_KEY)
    );
    // The key is recoverable for an explicit caller policy, but this layer
    // plans no ack for it.
    assert_eq!(ack_key(envelope.ack()), Some(FIRST_KEY));
    assert_eq!(planned_ack(envelope.ack()), None);
    assert_eq!(
        *envelope.ack(),
        SlackAckPlan::AckWithheld(SlackEnvelopeId::new(FIRST_KEY).unwrap())
    );
}

#[test]
fn unknown_envelope_type_without_a_key_plans_nothing_at_all() {
    let envelope = parse_slack_envelope(br#"{"type":"future_frame"}"#, &policy()).expect("refusal");
    assert_eq!(
        envelope.disposition(),
        SlackDisposition::Refused(SlackRefusal::UnknownEnvelopeType)
    );
    assert_eq!(*envelope.ack(), SlackAckPlan::NoAckKey);
    assert_eq!(ack_key(envelope.ack()), None);
    assert_eq!(planned_ack(envelope.ack()), None);
}

#[test]
fn recognised_non_event_envelopes_are_acknowledged_content_free() {
    for wire_type in ["slash_commands", "interactive"] {
        let frame = format!(
            r#"{{"accepts_response_payload":true,"envelope_id":"{FIRST_KEY}","payload":{{"command":"/deploy"}},"type":"{wire_type}"}}"#
        );
        let envelope = parse_slack_envelope(frame.as_bytes(), &policy()).expect("envelope");
        assert_eq!(
            envelope.disposition(),
            SlackDisposition::IgnoredUnsupported,
            "{wire_type}"
        );
        assert!(envelope.ingress().is_none(), "{wire_type}");
        assert!(envelope.accepts_response_payload(), "{wire_type}");
        assert_eq!(planned_ack(envelope.ack()), Some(FIRST_KEY), "{wire_type}");
    }
}

#[test]
fn unsupported_events_are_content_free_and_still_acknowledged() {
    for event in [
        // Not a message-shaped event.
        r#"{"item":{"channel":"C01CHAN"},"reaction":"eyes","type":"reaction_added","user":"U01USER"}"#,
        // Subtyped messages carry different coordinates.
        r#"{"channel":"C01CHAN","subtype":"channel_join","text":"joined","ts":"1700000000.000400","type":"message","user":"U01USER"}"#,
        r#"{"channel":"C01CHAN","subtype":"message_changed","ts":"1700000000.000500","type":"message"}"#,
        // A bot-authored message would let the app answer itself.
        r#"{"bot_id":"B0BOT","channel":"C01CHAN","text":"beep","ts":"1700000000.000600","type":"message","user":"U01USER"}"#,
        // Attachment-only posts arrive with an absent or empty text.
        r#"{"channel":"C01CHAN","files":[],"ts":"1700000000.000700","type":"message","user":"U01USER"}"#,
        r#"{"channel":"C01CHAN","text":"","ts":"1700000000.000800","type":"message","user":"U01USER"}"#,
    ] {
        let envelope = parse_slack_envelope(events_api(FIRST_KEY, 0, event).as_bytes(), &policy())
            .expect("unsupported event");
        assert_eq!(
            envelope.disposition(),
            SlackDisposition::IgnoredUnsupported,
            "{event}"
        );
        assert!(envelope.ingress().is_none(), "{event}");
        assert_eq!(planned_ack(envelope.ack()), Some(FIRST_KEY), "{event}");
    }
}

#[test]
fn hostile_frames_without_a_recoverable_ack_key_fail_closed() {
    let cases: [(&str, SlackError); 18] = [
        // No type and no key: nothing to record, nothing to ack.
        ("{}", SlackError::InvalidEnvelope),
        (
            r#"{"payload":{"team_id":"T01TEAM"}}"#,
            SlackError::InvalidEnvelope,
        ),
        // Not an object.
        ("[]", SlackError::InvalidEnvelope),
        ("null", SlackError::InvalidEnvelope),
        (r#""events_api""#, SlackError::InvalidEnvelope),
        ("17", SlackError::InvalidEnvelope),
        // Truncated and trailing-byte frames.
        (r#"{"type":"events_api""#, SlackError::InvalidEnvelope),
        (
            r#"{"envelope_id":"E1","type":"hello"}{"type":"hello"}"#,
            SlackError::InvalidEnvelope,
        ),
        // Duplicate keys are ambiguous, not last-wins.
        (
            r#"{"type":"hello","type":"disconnect"}"#,
            SlackError::InvalidEnvelope,
        ),
        (
            r#"{"envelope_id":"E1","envelope_id":"E2","type":"events_api"}"#,
            SlackError::InvalidEnvelope,
        ),
        // A key that exists but cannot serve as an ack key.
        (
            r#"{"envelope_id":42,"type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"envelope_id":null,"type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"envelope_id":"","type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"envelope_id":"has:colon","type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"envelope_id":"has space","type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"envelope_id":"héllo","type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        // Acknowledgeable types must carry a key.
        (
            r#"{"payload":{},"type":"events_api"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
        (
            r#"{"type":"slash_commands"}"#,
            SlackError::InvalidField("envelope_id"),
        ),
    ];
    for (frame, expected) in cases {
        assert_eq!(
            parse_slack_envelope(frame.as_bytes(), &policy()).expect_err(frame),
            expected,
            "{frame}"
        );
    }

    let long_key = "e".repeat(MAX_SLACK_IDENTIFIER_BYTES + 1);
    for frame in [
        format!(r#"{{"envelope_id":"{long_key}","type":"events_api"}}"#),
        format!(
            r#"{{"envelope_id":{},"type":"events_api"}}"#,
            json(&nul_string())
        ),
    ] {
        assert_eq!(
            parse_slack_envelope(frame.as_bytes(), &policy()).expect_err(&frame),
            SlackError::InvalidField("envelope_id"),
            "{frame}"
        );
    }
    assert_eq!(
        parse_slack_envelope(br#"{"type":"interactive"}"#, &policy()).expect_err("no key"),
        SlackError::InvalidField("envelope_id")
    );
    assert_eq!(
        parse_slack_envelope(b"", &policy()).expect_err("empty frame"),
        SlackError::LimitExceeded
    );
    assert_eq!(
        parse_slack_envelope(&vec![b' '; MAX_SLACK_ENVELOPE_BYTES + 1], &policy())
            .expect_err("oversized frame"),
        SlackError::LimitExceeded
    );
}

#[test]
fn hostile_frames_with_a_recoverable_ack_key_refuse_explicitly() {
    let cases: Vec<(String, SlackRefusal)> = vec![
        // Envelope-level shape.
        (
            r#"{"envelope_id":"E1"}"#.to_owned(),
            SlackRefusal::MissingEnvelopeType,
        ),
        (
            r#"{"envelope_id":"E1","type":7}"#.to_owned(),
            SlackRefusal::MissingEnvelopeType,
        ),
        (
            r#"{"envelope_id":"E1","type":null}"#.to_owned(),
            SlackRefusal::MissingEnvelopeType,
        ),
        (
            r#"{"envelope_id":"E1","type":"events_api_v2"}"#.to_owned(),
            SlackRefusal::UnknownEnvelopeType,
        ),
        (
            r#"{"envelope_id":"E1","type":""}"#.to_owned(),
            SlackRefusal::UnknownEnvelopeType,
        ),
        // Control frames carry no ack key; one that does is ambiguous.
        (
            r#"{"envelope_id":"E1","type":"hello"}"#.to_owned(),
            SlackRefusal::ControlFrameCarriedAckKey,
        ),
        (
            r#"{"envelope_id":"E1","type":"disconnect"}"#.to_owned(),
            SlackRefusal::ControlFrameCarriedAckKey,
        ),
        // Retry metadata.
        (
            r#"{"envelope_id":"E1","retry_attempt":-1,"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("retry_attempt"),
        ),
        (
            r#"{"envelope_id":"E1","retry_attempt":99999999999999999999,"type":"events_api"}"#
                .to_owned(),
            SlackRefusal::InvalidField("retry_attempt"),
        ),
        (
            r#"{"envelope_id":"E1","retry_attempt":1.5,"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("retry_attempt"),
        ),
        (
            r#"{"envelope_id":"E1","retry_attempt":"3","type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("retry_attempt"),
        ),
        (
            r#"{"envelope_id":"E1","retry_reason":7,"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("retry_reason"),
        ),
        (
            r#"{"envelope_id":"E1","retry_reason":"","type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("retry_reason"),
        ),
        (
            r#"{"accepts_response_payload":"yes","envelope_id":"E1","type":"events_api"}"#
                .to_owned(),
            SlackRefusal::InvalidField("accepts_response_payload"),
        ),
        // Payload shape.
        (
            r#"{"envelope_id":"E1","type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":null,"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":[],"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":"event_callback","type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":{"team_id":"T01TEAM","type":"url_verification"},"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":{"event":{},"team_id":"T01TEAM"},"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidPayload,
        ),
        (
            r#"{"envelope_id":"E1","payload":{"type":"event_callback"},"type":"events_api"}"#
                .to_owned(),
            SlackRefusal::InvalidField("team_id"),
        ),
        (
            r#"{"envelope_id":"E1","payload":{"team_id":7,"type":"event_callback"},"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidField("team_id"),
        ),
        (
            r#"{"envelope_id":"E1","payload":{"team_id":"T01TEAM","type":"event_callback"},"type":"events_api"}"#.to_owned(),
            SlackRefusal::InvalidEvent,
        ),
        // Event shape.
        (keyed_event(r#""message""#), SlackRefusal::InvalidEvent),
        (keyed_event("[]"), SlackRefusal::InvalidEvent),
        (keyed_event("{}"), SlackRefusal::InvalidEvent),
        (keyed_event(r#"{"type":3}"#), SlackRefusal::InvalidEvent),
        (keyed_event(r#"{"type":null}"#), SlackRefusal::InvalidEvent),
        // Message coordinates must be exact.
        (
            keyed_event(
                r#"{"text":"x","ts":"1700000000.000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("channel"),
        ),
        (
            keyed_event(
                r#"{"channel":7,"text":"x","ts":"1700000000.000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("channel"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01:CHAN","text":"x","ts":"1700000000.000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("channel"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":"1700000000.000100","type":"message"}"#,
            ),
            SlackRefusal::InvalidField("user"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":"1700000000.000100","type":"message","user":null}"#,
            ),
            SlackRefusal::InvalidField("user"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":"1700000000.000100","type":"message","user":"U01ÜSER"}"#,
            ),
            SlackRefusal::InvalidField("user"),
        ),
        (
            keyed_event(r#"{"channel":"C01CHAN","text":"x","type":"message","user":"U01USER"}"#),
            SlackRefusal::InvalidField("ts"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":1700000000.0001,"type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("ts"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":"1700000000:000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("ts"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":"x","ts":"","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("ts"),
        ),
        // Content shape.
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":42,"ts":"1700000000.000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("text"),
        ),
        (
            keyed_event(
                r#"{"channel":"C01CHAN","text":["x"],"ts":"1700000000.000100","type":"message","user":"U01USER"}"#,
            ),
            SlackRefusal::InvalidField("text"),
        ),
        (
            keyed_event(&message_event(&json(&nul_string()))),
            SlackRefusal::InvalidField("text"),
        ),
    ];

    for (frame, expected) in cases {
        let envelope = parse_slack_envelope(frame.as_bytes(), &policy())
            .unwrap_or_else(|error| panic!("{frame} must refuse with a key, got {error}"));
        assert_eq!(
            envelope.disposition(),
            SlackDisposition::Refused(expected),
            "{frame}"
        );
        assert!(envelope.ingress().is_none(), "{frame}");
        // Explicit, never defaulted: the key survives, the ack does not.
        assert_eq!(ack_key(envelope.ack()), Some("E1"), "{frame}");
        assert_eq!(planned_ack(envelope.ack()), None, "{frame}");
    }
}

#[test]
fn team_id_refusal_reports_its_own_field_name() {
    // `team_id` is validated alongside the channel and user, so a separator
    // there is reported against `team_id`, not a neighbouring coordinate.
    let frame = r#"{"envelope_id":"E1","payload":{"event":{"channel":"C01CHAN","text":"x","ts":"1700000000.000100","type":"message","user":"U01USER"},"team_id":"T01:TEAM","type":"event_callback"},"type":"events_api"}"#;
    let envelope = parse_slack_envelope(frame.as_bytes(), &policy()).expect("refusal");
    assert_eq!(
        envelope.disposition(),
        SlackDisposition::Refused(SlackRefusal::InvalidField("team_id"))
    );
}

#[test]
fn separator_free_identifiers_keep_dedup_keys_unambiguous() {
    // Without the `:` restriction these two distinct events would compose to
    // the identical source key `slack:A0FIRST:T01TEAM:C01:CHAN:1700000000.1`.
    let split_team = r#"{"envelope_id":"E1","payload":{"event":{"channel":"CHAN","text":"x","ts":"1700000000.1","type":"message","user":"U01USER"},"team_id":"T01TEAM:C01","type":"event_callback"},"type":"events_api"}"#;
    let split_channel = r#"{"envelope_id":"E1","payload":{"event":{"channel":"C01:CHAN","text":"x","ts":"1700000000.1","type":"message","user":"U01USER"},"team_id":"T01TEAM","type":"event_callback"},"type":"events_api"}"#;
    for frame in [split_team, split_channel] {
        let envelope = parse_slack_envelope(frame.as_bytes(), &policy()).expect("refusal");
        assert!(
            matches!(
                envelope.disposition(),
                SlackDisposition::Refused(SlackRefusal::InvalidField(_))
            ),
            "{frame}"
        );
        assert!(envelope.ingress().is_none(), "{frame}");
    }
}

#[test]
fn policy_requires_exact_nonempty_separator_free_coordinates() {
    assert_eq!(
        SlackAppId::new("").expect_err("empty app"),
        SlackError::InvalidField("app_id")
    );
    assert_eq!(
        SlackAppId::new("A0:FIRST").expect_err("separator in app"),
        SlackError::InvalidField("app_id")
    );
    assert_eq!(
        SlackEnvelopeId::new("").expect_err("empty key"),
        SlackError::InvalidField("envelope_id")
    );
    assert_eq!(
        SlackPrincipal::new("", "C01CHAN", "U01USER").expect_err("empty team"),
        SlackError::InvalidField("team_id")
    );
    assert_eq!(
        SlackPrincipal::new("T01TEAM", "C01 CHAN", "U01USER").expect_err("space in channel"),
        SlackError::InvalidField("channel")
    );
    assert_eq!(
        SlackPrincipal::new("T01TEAM", "C01CHAN", "U01ÜSER").expect_err("non-ascii user"),
        SlackError::InvalidField("user")
    );
    assert_eq!(
        SlackAccessPolicy::new(SlackAppId::new("A0FIRST").unwrap(), []).expect_err("empty policy"),
        SlackError::InvalidField("principals")
    );
}
