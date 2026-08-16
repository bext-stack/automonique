// SPDX-License-Identifier: Elastic-2.0

use automonique_transports::{
    MAX_TELEGRAM_INPUT_BYTES, TelegramAccessPolicy, TelegramAttachmentKind, TelegramBotId,
    TelegramDisposition, TelegramError, TelegramInputKind, TelegramPrincipal,
    parse_telegram_updates,
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
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"text":"hello"}}]}"#,
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
    assert_eq!(update.message_id(), Some(77));
    assert_eq!(update.kind(), TelegramInputKind::Message);
    assert_eq!(update.disposition(), TelegramDisposition::Admitted);
    assert_eq!(
        update.principal(),
        Some(TelegramPrincipal::new(-100, 42).unwrap())
    );
    assert_eq!(update.content(), Some("hello"));
}

#[test]
fn direct_reply_identity_is_retained() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"reply_to_message":{"message_id":55},"text":"send this"}}]}"#,
        9,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.updates()[0].reply_to_message_id(), Some(55));
}

/// A forum topic is a separate room, and a reply chain in an ordinary
/// supergroup is not — even though Telegram spells both with a
/// `message_thread_id`. Only the flag tells them apart, so only the flag is
/// allowed to.
#[test]
fn only_a_flagged_forum_topic_reports_a_thread_coordinate() {
    let topic = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"message_thread_id":31,"is_topic_message":true,"text":"in the topic"}}]}"#,
        9,
        &policy(),
    )
    .expect("topic");
    assert_eq!(topic.updates()[0].forum_topic_id(), Some(31));

    // The same coordinate without the flag is a reply chain, and reporting it
    // would split one group conversation into a session per chain.
    let reply_chain = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"message_thread_id":31,"text":"in a reply chain"}}]}"#,
        9,
        &policy(),
    )
    .expect("reply chain");
    assert_eq!(reply_chain.updates()[0].forum_topic_id(), None);

    // A direct message has no thread at all, which is what keeps the bare chat
    // scope the primary session.
    let direct = parse_telegram_updates(
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"text":"hello"}}]}"#,
        9,
        &policy(),
    )
    .expect("direct");
    assert_eq!(direct.updates()[0].forum_topic_id(), None);

    // A malformed coordinate is refused rather than folded into the chat.
    for payload in [
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"message_thread_id":0,"is_topic_message":true,"text":"hi"}}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"message_thread_id":"31","is_topic_message":true,"text":"hi"}}]}"#.as_slice(),
        br#"{"ok":true,"result":[{"update_id":9,"message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"message_thread_id":31,"is_topic_message":"yes","text":"hi"}}]}"#.as_slice(),
    ] {
        assert!(
            parse_telegram_updates(payload, 9, &policy()).is_err(),
            "a malformed thread coordinate must not become the chat scope"
        );
    }
}

#[test]
fn edits_attachments_and_business_deletes_have_closed_semantics() {
    let edited = parse_telegram_updates(
        br#"{"ok":true,"result":[{"edited_message":{"message_id":77,"chat":{"id":-100},"from":{"id":42},"text":"changed"},"update_id":20}]}"#,
        20,
        &policy(),
    )
    .expect("edited");
    assert_eq!(edited.updates()[0].kind(), TelegramInputKind::EditedMessage);
    assert_eq!(edited.updates()[0].content(), Some("changed"));
    assert_eq!(
        edited.updates()[0].disposition(),
        TelegramDisposition::Admitted
    );

    let attachment = parse_telegram_updates(
        br#"{"ok":true,"result":[{"message":{"message_id":78,"chat":{"id":-100},"from":{"id":42},"document":{"file_id":"opaque"},"caption":"please inspect"},"update_id":21}]}"#,
        21,
        &policy(),
    )
    .expect("attachment");
    assert_eq!(
        attachment.updates()[0].kind(),
        TelegramInputKind::Attachment
    );
    assert_eq!(
        attachment.updates()[0].attachment_kind(),
        Some(TelegramAttachmentKind::Document)
    );
    assert_eq!(attachment.updates()[0].content(), Some("please inspect"));

    let deleted = parse_telegram_updates(
        br#"{"ok":true,"result":[{"deleted_business_messages":{"business_connection_id":"opaque","chat":{"id":-100},"message_ids":[77,78]},"update_id":22}]}"#,
        22,
        &policy(),
    )
    .expect("deletion");
    assert_eq!(
        deleted.updates()[0].kind(),
        TelegramInputKind::DeletedMessage
    );
    assert_eq!(
        deleted.updates()[0].disposition(),
        TelegramDisposition::IgnoredUnsupported
    );
    assert_eq!(deleted.updates()[0].principal(), None);
    assert_eq!(deleted.updates()[0].content(), None);
    assert_eq!(deleted.updates()[0].scope(), "telegram:7:-100");
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
        br#"{"ok":true,"result":[{"callback_query":{"id":"cbq-9","data":"approve:7","from":{"id":42},"message":{"message_id":5,"chat":{"id":-100}}},"update_id":11}]}"#,
        0,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.updates()[0].kind(), TelegramInputKind::Callback);
    assert_eq!(batch.updates()[0].content(), Some("approve:7"));
    // Both coordinates a press needs to be answered in place: the query
    // identifier dismisses the spinner and the message identifier is the
    // keyboard that has to stop looking live.
    assert_eq!(batch.updates()[0].callback_query_id(), Some("cbq-9"));
    assert_eq!(batch.updates()[0].message_id(), Some(5));
}

/// A press this bot refused carries no acknowledgement coordinate.
///
/// Acknowledging it would tell whoever pressed the button that it worked, which
/// is exactly what a denied sender must not learn.
#[test]
fn a_denied_callback_carries_no_acknowledgement_coordinate() {
    let batch = parse_telegram_updates(
        br#"{"ok":true,"result":[{"callback_query":{"id":"cbq-9","data":"approve:7","from":{"id":99},"message":{"message_id":5,"chat":{"id":-100}}},"update_id":11}]}"#,
        0,
        &policy(),
    )
    .expect("batch");
    assert_eq!(batch.updates()[0].kind(), TelegramInputKind::Callback);
    assert_eq!(batch.updates()[0].content(), None);
    assert_eq!(batch.updates()[0].callback_query_id(), None);
}

/// A callback with no identifier or no message coordinate is refused.
#[test]
fn a_callback_missing_a_coordinate_is_refused_rather_than_half_admitted() {
    for payload in [
        // No `id`: nothing to acknowledge.
        br#"{"ok":true,"result":[{"callback_query":{"data":"approve:7","from":{"id":42},"message":{"message_id":5,"chat":{"id":-100}}},"update_id":11}]}"#.as_slice(),
        // No `message_id`: no keyboard to strip.
        br#"{"ok":true,"result":[{"callback_query":{"id":"cbq-9","data":"approve:7","from":{"id":42},"message":{"chat":{"id":-100}}},"update_id":11}]}"#.as_slice(),
    ] {
        assert!(
            parse_telegram_updates(payload, 0, &policy()).is_err(),
            "a half-addressed press must not be admitted"
        );
    }
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
        br#"{"ok":true,"result":[{"callback_query":{"id":"cbq-1","data":"x","from":{"id":42},"message":{"message_id":3,"chat":{"id":-100},"location":{"latitude":1.25,"longitude":2.5}}},"update_id":10}]}"#,
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
