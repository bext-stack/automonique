// SPDX-License-Identifier: Elastic-2.0

use automonique_transports::{
    MAX_TELEGRAM_INPUT_BYTES, TelegramAccessPolicy, TelegramBotId, TelegramDisposition,
    TelegramError, TelegramInputKind, TelegramPrincipal, parse_telegram_updates,
};

fn policy() -> TelegramAccessPolicy {
    TelegramAccessPolicy::new(
        TelegramBotId::new(7).expect("bot"),
        [TelegramPrincipal::new(-100, 42).expect("principal")],
    )
    .expect("policy")
}

#[test]
fn admitted_message_has_stable_source_scope_and_offset() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":9,"message":{"chat":{"id":-100},"from":{"id":42},"text":"hello"}}]}"#,
        9,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.next_offset(), 10);
    let [update] = batch.updates() else {
        panic!("one update")
    };
    assert_eq!(update.source_key(), "telegram:7:update:9");
    assert_eq!(update.scope(), "telegram:7:-100");
    assert_eq!(update.kind(), TelegramInputKind::Message);
    assert_eq!(update.disposition(), TelegramDisposition::Admitted);
    assert_eq!(
        update.principal(),
        Some(TelegramPrincipal::new(-100, 42).unwrap())
    );
    assert_eq!(update.content(), Some("hello"));
}

#[test]
fn denied_actor_is_returned_for_durable_disposition() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":10,"message":{"chat":{"id":-100},"from":{"id":99},"text":"denied"}}]}"#,
        10,
        &policy(),
    )
    .expect("batch");
    assert_eq!(
        batch.updates()[0].disposition(),
        TelegramDisposition::Denied
    );
    assert_eq!(batch.next_offset(), 11);
    assert_eq!(batch.updates()[0].content(), None);
    let rendered = format!("{:?}", batch.updates()[0]);
    assert!(!rendered.contains("denied"));
    assert!(!rendered.contains("-100"));
    assert!(!rendered.contains("99"));
}

#[test]
fn callback_uses_actor_and_message_chat_coordinates() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"callback_query":{"data":"approve:7","from":{"id":42},"message":{"chat":{"id":-100}}},"update_id":11}]}"#,
        0,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.updates()[0].kind(), TelegramInputKind::Callback);
    assert_eq!(batch.updates()[0].content(), Some("approve:7"));
}

#[test]
fn already_durable_updates_are_ignored_without_rewinding() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":8,"message":{"chat":{"id":-100},"from":{"id":42},"text":"old"}},{"update_id":9,"message":{"chat":{"id":-100},"from":{"id":42},"text":"new"}}]}"#,
        9,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.updates().len(), 1);
    assert_eq!(batch.updates()[0].update_id(), 9);
    assert_eq!(batch.next_offset(), 10);
}

#[test]
fn duplicate_reordered_and_exhausted_ids_fail_closed() {
    for payload in [
        br#"{"ok":true,"result":[{"update_id":2,"message":{"chat":{"id":-100},"from":{"id":42},"text":"a"}},{"update_id":2,"message":{"chat":{"id":-100},"from":{"id":42},"text":"b"}}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"update_id":3,"message":{"chat":{"id":-100},"from":{"id":42},"text":"a"}},{"update_id":2,"message":{"chat":{"id":-100},"from":{"id":42},"text":"b"}}]}"#.as_slice(),
    ] {
        assert_eq!(
            parse_telegram_updates(payload, 0, &policy()).expect_err("ordering refusal"),
            TelegramError::NonMonotonicUpdates
        );
    }
    let exhausted = format!(
        "{{\"ok\":true,\"result\":[{{\"update_id\":{},\"message\":{{\"chat\":{{\"id\":-100}},\"from\":{{\"id\":42}},\"text\":\"x\"}}}}]}}",
        u64::MAX
    );
    assert_eq!(
        parse_telegram_updates(exhausted.as_bytes(), 0, &policy()).expect_err("overflow"),
        TelegramError::OffsetExhausted
    );
}

#[test]
fn malformed_error_and_ambiguous_update_shapes_are_refused() {
    for payload in [
        br#"{"ok":false,"result":[]}"#.as_slice(),
        br#"{"ok":true,"result":[{"callback_query":{},"message":{},"update_id":1}]}"#.as_slice(),
        br#"{"future":1,"ok":true,"result":[]}"#.as_slice(),
        br#"{"ok":false,"ok":true,"result":[]}"#.as_slice(),
        br#"{"ok":true,"result":[{"edited_message":{},"message":{},"update_id":1}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"callback_query":{"data":"x","from":{"id":42},"game_short_name":"g","message":{"chat":{"id":-100}}},"update_id":1}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"callback_query":{"data":"x","from":{"id":42},"inline_message_id":"i","message":{"chat":{"id":-100}}},"update_id":1}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"message":{"chat":{"id":-100},"from":{"id":42},"text":42},"update_id":1}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"message":{"chat":{"id":-100},"from":{"id":42},"text":null},"update_id":1}]}"#.as_slice(),
    ] {
        assert_eq!(
            parse_telegram_updates(payload, 0, &policy()).expect_err("shape refusal"),
            TelegramError::InvalidResponse
        );
    }
}

#[test]
fn unsupported_fresh_updates_are_content_free_and_do_not_wedge_the_offset() {
    for payload in [
        br#"{"ok":true,"result":[{"update_id":12}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"message":{"chat":{"id":-100},"from":{"id":42},"photo":[]},"update_id":12}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"message":{"chat":{"id":-100},"from":{"id":42},"location":{"latitude":1.25,"longitude":2.5}},"update_id":12}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"edited_message":{},"update_id":12}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"callback_query":{"from":{"id":42},"inline_message_id":"i","game_short_name":"g"},"update_id":12}]}"#.as_slice(),
    ] {
        let batch = parse_telegram_updates(payload, 12, &policy()).expect("ignored update");
        assert_eq!(batch.next_offset(), 13);
        let update = &batch.updates()[0];
        assert_eq!(update.kind(), TelegramInputKind::Unsupported);
        assert_eq!(update.disposition(), TelegramDisposition::IgnoredUnsupported);
        assert_eq!(update.principal(), None);
        assert_eq!(update.content(), None);
    }
}

#[test]
fn malformed_old_update_is_skipped_before_payload_decoding() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"future":{"hostile":"shape"},"update_id":8},{"message":{"chat":{"id":-100},"from":{"id":42},"text":"fresh"},"update_id":9}]}"#,
        9,
        &policy(),
    )
    .expect("old payload shape is irrelevant");
    assert_eq!(batch.updates().len(), 1);
    assert_eq!(batch.updates()[0].content(), Some("fresh"));
    assert_eq!(batch.next_offset(), 10);
}

#[test]
fn floating_point_fields_in_old_or_unsupported_payloads_do_not_wedge() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"message":{"location":{"latitude":1.25,"longitude":2.5}},"update_id":8},{"message":{"chat":{"id":-100},"from":{"id":42},"text":"fresh"},"update_id":9}]}"#,
        9,
        &policy(),
    )
    .expect("old float payload is irrelevant");
    assert_eq!(batch.updates().len(), 1);
    assert_eq!(batch.updates()[0].content(), Some("fresh"));

    let callback = parse_telegram_updates(
        br#"{"ok":true,"result":[{"callback_query":{"data":"x","from":{"id":42},"message":{"chat":{"id":-100},"location":{"latitude":1.25,"longitude":2.5}}},"update_id":10}]}"#,
        10,
        &policy(),
    )
    .expect("callback ignores unrelated float fields");
    assert_eq!(callback.updates()[0].content(), Some("x"));
}

#[test]
fn source_identity_is_distinct_for_the_same_update_on_two_bots() {
    let payload = br#"{"ok":true,"result":[{"message":{"chat":{"id":-100},"from":{"id":42},"text":"x"},"update_id":14}]}"#;
    let first = parse_telegram_updates(payload, 0, &policy()).unwrap();
    let second_policy = TelegramAccessPolicy::new(
        TelegramBotId::new(8).unwrap(),
        [TelegramPrincipal::new(-100, 42).unwrap()],
    )
    .unwrap();
    let second = parse_telegram_updates(payload, 0, &second_policy).unwrap();
    assert_ne!(
        first.updates()[0].source_key(),
        second.updates()[0].source_key()
    );
}

#[test]
fn content_and_response_bounds_are_enforced() {
    let oversized = "x".repeat(MAX_TELEGRAM_INPUT_BYTES + 1);
    let payload = format!(
        "{{\"ok\":true,\"result\":[{{\"update_id\":1,\"message\":{{\"chat\":{{\"id\":-100}},\"from\":{{\"id\":42}},\"text\":{}}}}}]}}",
        serde_json::to_string(&oversized).expect("string")
    );
    assert_eq!(
        parse_telegram_updates(payload.as_bytes(), 0, &policy()).expect_err("content bound"),
        TelegramError::InvalidField("content")
    );
    assert_eq!(
        parse_telegram_updates(&vec![b' '; 1024 * 1024 + 1], 0, &policy())
            .expect_err("response bound"),
        TelegramError::LimitExceeded
    );
}

#[test]
fn policy_requires_exact_nonempty_coordinates() {
    assert_eq!(
        TelegramBotId::new(0).expect_err("zero bot"),
        TelegramError::InvalidField("bot_id")
    );
    assert_eq!(
        TelegramPrincipal::new(0, 1).expect_err("zero chat"),
        TelegramError::InvalidField("chat_id")
    );
    assert_eq!(
        TelegramAccessPolicy::new(TelegramBotId::new(1).unwrap(), []).expect_err("empty policy"),
        TelegramError::InvalidField("principals")
    );
}
