// SPDX-License-Identifier: Elastic-2.0

//! Fuzz the length-prefixed framing decoder against arbitrary bytes.
//!
//! The length prefix is the first thing a hostile peer controls and the last
//! thing that should be trusted, so the assertions are about what the decoder
//! is allowed to conclude from it: a frame it reports must lie inside the input
//! it was given, and a request for more bytes must be for bytes it does not
//! already have.

#![no_main]

use libfuzzer_sys::fuzz_target;

use automonique_protocol::codec::{FrameDecode, LENGTH_PREFIX_BYTES, decode_frame, encode_frame};
use automonique_protocol::wire::parse_canonical;

fuzz_target!(|data: &[u8]| {
    match decode_frame(data) {
        Ok(FrameDecode::Frame { payload, consumed }) => {
            assert_eq!(
                consumed,
                LENGTH_PREFIX_BYTES + payload.len(),
                "a frame consumed something other than its prefix and payload"
            );
            assert!(consumed <= data.len(), "a frame consumed past its input");
            assert_eq!(
                payload,
                &data[LENGTH_PREFIX_BYTES..consumed],
                "a frame's payload was not the bytes it borrowed"
            );

            // Re-framing the payload must reproduce the frame exactly, which is
            // what makes a stream reader and a stream writer agree.
            let mut reframed = Vec::new();
            encode_frame(payload, &mut reframed).expect("a decoded payload is within the ceiling");
            assert_eq!(
                reframed.as_slice(),
                &data[..consumed],
                "re-framing a decoded payload changed its bytes"
            );

            // Frames carry canonical JSON, so keep going: this is the only
            // target that reaches the parser through real framing.
            let _ = parse_canonical(payload);
        }
        Ok(FrameDecode::NeedMore { additional }) => {
            // The request is for bytes that are genuinely outstanding, in both
            // of the decoder's two states. Below a full prefix it can only ask
            // for the rest of the prefix, because it cannot yet know the
            // payload length; above one it knows the whole remainder. Asking
            // for more than either would stall a reader on bytes the sender
            // will never send.
            let expected = if data.len() < LENGTH_PREFIX_BYTES {
                LENGTH_PREFIX_BYTES - data.len()
            } else {
                let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
                prefix.copy_from_slice(&data[..LENGTH_PREFIX_BYTES]);
                let declared = u32::from_be_bytes(prefix) as usize;
                (LENGTH_PREFIX_BYTES + declared) - data.len()
            };
            assert_eq!(
                additional.get(),
                expected,
                "a truncated frame asked for the wrong number of bytes"
            );
        }
        Err(_) => {}
    }
});
