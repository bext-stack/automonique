// SPDX-License-Identifier: Elastic-2.0

//! Transports-side pin for the composer's carried foreign bounds.
//!
//! The protocol crate's composer module carries this crate's text bounds as
//! values it cannot check (`automonique-protocol` is dependency-free). This
//! test is the closing half: it pins the authoritative constants to the exact
//! values the composer's transport-fit table records. On failure, update both
//! places together — the table in `automonique-protocol/src/composer.rs` and
//! this pin.

#[test]
fn the_text_bounds_the_composer_carries_match_the_authoritative_constants() {
    assert_eq!(
        automonique_transports::MAX_SLACK_TEXT_BYTES,
        16_384,
        "Slack text bound moved: update the composer's transport-fit table in \
         automonique-protocol/src/composer.rs together with this pin"
    );
    assert_eq!(
        automonique_transports::MAX_TELEGRAM_INPUT_BYTES,
        16_384,
        "Telegram input bound moved: update the composer's transport-fit table \
         together with this pin"
    );
}
