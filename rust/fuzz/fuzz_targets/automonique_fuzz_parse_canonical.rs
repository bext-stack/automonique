// SPDX-License-Identifier: Elastic-2.0

//! Fuzz the canonical JSON parser against arbitrary bytes.
//!
//! The target checks the strictness contract rather than merely surviving:
//! whatever `parse_canonical` accepts must re-encode to exactly the bytes it
//! was handed. A parser that silently normalised a second spelling would leave
//! this assertion, not the absence of a crash, to catch it.

#![no_main]

use libfuzzer_sys::fuzz_target;

use automonique_protocol::wire::parse_canonical;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = parse_canonical(data) else {
        return;
    };

    assert_eq!(
        value.to_canonical_bytes(),
        data,
        "an accepted payload was not already canonical"
    );

    // Re-parsing the re-encoding must land on the same value: encoding is
    // injective only if this holds, and a fuzzer reaches shapes a generated
    // tree does not.
    assert_eq!(
        parse_canonical(&value.to_canonical_bytes()),
        Ok(value),
        "a canonical payload did not survive a second round trip"
    );
});
