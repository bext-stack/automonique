// SPDX-License-Identifier: Elastic-2.0

//! Fuzz the Slack response decoders against arbitrary bytes.
//!
//! Nine decoders share one strict-JSON front end and one `ok`/`error`
//! envelope, so they share a corpus: a body that gets one of them past the
//! envelope and into field extraction gets the others there too. Feeding every
//! decoder the same bytes is also how a body shaped for one method but answered
//! by another gets tried, which is a real failure mode for an API where the
//! method lives in the URL and not in the response.

#![no_main]

use libfuzzer_sys::fuzz_target;

use automonique_slack_connector::{
    decode_ack, decode_apps_connections_open, decode_auth_test, decode_conversations_history,
    decode_conversations_info, decode_conversations_list, decode_error_code, decode_post_message,
    decode_users_info,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_ack(data);
    let _ = decode_apps_connections_open(data);
    let _ = decode_auth_test(data);
    let _ = decode_conversations_info(data);
    let _ = decode_post_message(data);
    let _ = decode_users_info(data);

    // The paged decoders refuse a page longer than the limit that was asked
    // for, so the limit is a decision boundary rather than a passenger. Both
    // ends of it are worth reaching: 0 admits nothing, and the maximum admits
    // any page the body can express.
    for limit in [0_u16, 1, u16::MAX] {
        let _ = decode_conversations_history(data, limit);
        let _ = decode_conversations_list(data, limit);
    }

    // Error classification is infallible by design — it always returns a code —
    // which makes it the one decoder here where a panic is the only way to
    // fail. The fallback is a fixed spelling because the fuzzer's budget is
    // better spent on the body than on a string it merely echoes.
    let _ = decode_error_code(data, "fuzz_fallback");
});
