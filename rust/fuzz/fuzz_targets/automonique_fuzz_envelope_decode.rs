// SPDX-License-Identifier: Elastic-2.0

//! Fuzz every message decoder in the protocol crate against arbitrary bytes.
//!
//! These are the entry points a peer's bytes reach after unframing. Each has
//! its own error type and its own field rules, but they share one obligation:
//! refuse, never panic and never accept a payload that is not its own canonical
//! spelling. One target covers all of them because they share a corpus — a
//! payload that reaches deep into one decoder usually reaches deep into its
//! sibling too.

#![no_main]

use libfuzzer_sys::fuzz_target;

use automonique_protocol::codec::{MajorVersion, ProtocolName, SupportedProtocol, VersionRange};
use automonique_protocol::wire::Message;

/// Call every typed decoder on the same payload.
macro_rules! decode_each {
    ($payload:expr, $($decoder:path),* $(,)?) => {
        $( let _ = <$decoder>::from_canonical_bytes($payload); )*
    };
}

fuzz_target!(|data: &[u8]| {
    // Decoding is idempotent: re-encoding a decoded message and decoding that
    // again lands on the same message. The envelope fields are re-rendered from
    // parsed values rather than copied, so this catches a field that decodes
    // into something with a different spelling.
    //
    // Note what is deliberately *not* asserted: that the re-encoding equals the
    // input. It does not, and must not. Unknown top-level fields decode and are
    // dropped — `fixtures/wire-v1.json`'s `envelope-unknown-additive-field`
    // pins that — because a peer on a later minor version has to be able to add
    // a field without this one refusing the message. Idempotence is the
    // strongest law that survives that tolerance.
    if let Ok(message) = Message::from_canonical_bytes(data) {
        let reencoded = message.to_canonical_bytes();
        assert_eq!(
            Message::from_canonical_bytes(&reencoded),
            Ok(message),
            "re-encoding a decoded message changed what it decodes to"
        );
    }

    let supported = [
        SupportedProtocol::new(
            ProtocolName::new("automonique.runner").expect("a fixed name is valid"),
            VersionRange::new(
                MajorVersion::new(1).expect("a fixed version is valid"),
                MajorVersion::new(1).expect("a fixed version is valid"),
            )
            .expect("a fixed range is ordered"),
        ),
        SupportedProtocol::new(
            ProtocolName::new("automonique.admin").expect("a fixed name is valid"),
            VersionRange::new(
                MajorVersion::new(1).expect("a fixed version is valid"),
                MajorVersion::new(4).expect("a fixed version is valid"),
            )
            .expect("a fixed range is ordered"),
        ),
    ];
    // Both the admitting and the empty-slate paths: an empty slice implements
    // nothing, which is its own branch through negotiation.
    let _ = Message::from_canonical_bytes_admitted(data, &supported);
    let _ = Message::from_canonical_bytes_admitted(data, &[]);

    decode_each!(
        data,
        automonique_protocol::admin::AdminRequest,
        automonique_protocol::admin::AdminResponse,
        automonique_protocol::admin::LocalRequest,
        automonique_protocol::approval_api::ApprovalRequest,
        automonique_protocol::approval_api::ApprovalResponse,
        automonique_protocol::automation_api::AutomationRequest,
        automonique_protocol::automation_api::AutomationResponse,
        automonique_protocol::batch_api::BatchRequest,
        automonique_protocol::batch_api::BatchResponse,
        automonique_protocol::batch_runner::BatchPlan,
        automonique_protocol::batch_runner::BatchProgress,
        automonique_protocol::execute_api::ExecuteRequest,
        automonique_protocol::execute_api::ExecuteResponse,
        automonique_protocol::memory_api::MemoryRequest,
        automonique_protocol::memory_api::MemoryResponse,
        automonique_protocol::parity::IntendedActionEnvelope,
        automonique_protocol::parity::DeviationRegistry,
        automonique_protocol::release::ReleaseManifest,
        automonique_protocol::release_trust_root::ReleaseAttestation,
        automonique_protocol::runs_api::RunsRequest,
        automonique_protocol::runs_api::RunsResponse,
    );
});
