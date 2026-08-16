// SPDX-License-Identifier: Elastic-2.0

//! Fuzz the Telegram long-poll parser against arbitrary bytes.
//!
//! This parser and its Slack sibling are the only two in the workspace that
//! face bytes chosen by someone outside it. The protocol crate's decoders read
//! this project's own wire; `parse_telegram_updates` reads whatever arrives on
//! a long poll.
//!
//! The allowlist is fixed rather than fuzzed. Policy decides which parsed
//! updates are *admitted*, not how bytes are *parsed*, so varying it would
//! spend the fuzzer's budget re-deciding a branch instead of finding a parse
//! bug. The offset is exercised at both ends of its range because it gates the
//! parser's own skip-and-advance arithmetic.

#![no_main]

use libfuzzer_sys::fuzz_target;

use automonique_transports::{
    TelegramAccessPolicy, TelegramBotId, TelegramPrincipal, parse_telegram_updates,
};

fuzz_target!(|data: &[u8]| {
    let policy = TelegramAccessPolicy::new(
        TelegramBotId::new(1).expect("a fixed bot id is valid"),
        [
            TelegramPrincipal::new(-100, 7).expect("a fixed principal is valid"),
            TelegramPrincipal::new(11, 13).expect("a fixed principal is valid"),
        ],
    )
    .expect("a fixed allowlist is nonempty");

    for offset in [0, 1, u64::MAX / 2, u64::MAX] {
        let Ok(batch) = parse_telegram_updates(data, offset, &policy) else {
            continue;
        };
        // The whole point of the offset is that a long poll never re-delivers
        // what it has already acknowledged. A batch that moved the offset
        // backwards would replay updates forever.
        assert!(
            batch.next_offset() >= offset,
            "a parsed batch moved the acknowledged offset backwards"
        );
    }
});
