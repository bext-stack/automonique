// SPDX-License-Identifier: Elastic-2.0

//! The native workspace-memory control protocol: bounded values, closed
//! vocabularies, a trust vocabulary with no policy in it, and decoders that fail
//! closed.
//!
//! Nothing here talks to a socket or a database, because there is nothing to talk
//! to: this lane is a model and no daemon serves it. What is pinned is the shape
//! a lane would carry — which words exist, which bodies are exact, what a page may
//! carry, how a corrected item is told apart from a current one, and which of
//! these values a hostile or drifting peer can put past the decoder. The durable
//! behaviour is `automonique-store`'s `tests/context_memory.rs`.

use automonique_protocol::approval_api::ApprovalDisposition;
use automonique_protocol::codec::{CodecError, RequestId, encode_frame};
use automonique_protocol::context::{MAX_CONTEXT_FIELD_BYTES, SuppliedClass, TrustClass};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::memory_api::{
    ContentDigest, ListMemory, MAX_MEMORY_API_FIELD_BYTES, MAX_MEMORY_CANONICAL_BYTES,
    MAX_MEMORY_PAGE_ITEMS, MEMORY_API_SCHEMA_V1, MEMORY_DIGEST_CHARS, MEMORY_PROTOCOL,
    MemoryApiError, MemoryConflictField, MemoryContinuation, MemoryCursor, MemoryDetail,
    MemoryDetailView, MemoryDisposition, MemoryItemParts, MemoryKey, MemoryLabel, MemoryListPage,
    MemoryPageSize, MemoryReceiptView, MemoryRefusal, MemoryRequest, MemoryResponse, MemoryTrust,
    MemoryWorkspace, OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES, RecordMemory, RecordedMemory,
    SupersedeMemory, SupersessionReceiptParts, SupersessionReceiptView, SupersessionStamp,
    decode_memory_trust,
};
use automonique_protocol::primitives::{EpochMillis, ValueError};
use automonique_protocol::wire::JsonValue;

const DIGEST_A: &str = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
const DIGEST_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn request_id() -> RequestId {
    RequestId::new("memory-test-1").expect("request identifier")
}

fn workspace(value: &str) -> MemoryWorkspace {
    MemoryWorkspace::new(value).expect("workspace")
}

fn key(value: &str) -> MemoryKey {
    MemoryKey::new(value).expect("memory key")
}

fn label(value: &str) -> MemoryLabel {
    MemoryLabel::new(value).expect("label")
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::new(value).expect("content digest")
}

fn presented() -> RecordMemory {
    RecordMemory::new(
        workspace("acme/api"),
        key("lesson-1"),
        label("prefers-explicit-migrations"),
        digest(DIGEST_A),
        MemoryTrust::ACTOR_SUPPLIED,
    )
}

fn item(entry_id: u64, space: &str, memory_key: &str, stamp: Option<&str>) -> MemoryDetailView {
    let supersession = stamp.map(|replacement| SupersessionStamp {
        replacement_key: MemoryKey::replacement(replacement).expect("replacement key"),
        superseded_at: EpochMillis::from_millis(1_700_000_100_000),
    });
    let revision = if supersession.is_some() { 2 } else { 1 };
    MemoryDetailView::new(MemoryItemParts {
        entry_id,
        workspace: workspace(space),
        memory_key: key(memory_key),
        label: label("prefers-explicit-migrations"),
        content_digest: digest(DIGEST_A),
        trust: MemoryTrust::UNTRUSTED,
        created_at: EpochMillis::from_millis(1_700_000_000_000),
        supersession,
        revision,
    })
    .expect("item view")
}

fn receipt(disposition: MemoryDisposition) -> MemoryReceiptView {
    MemoryReceiptView::new(
        7,
        workspace("acme/api"),
        key("lesson-1"),
        disposition,
        EpochMillis::from_millis(1_700_000_000_000),
    )
    .expect("receipt")
}

fn supersession_receipt(disposition: MemoryDisposition) -> SupersessionReceiptView {
    SupersessionReceiptView::new(SupersessionReceiptParts {
        entry_id: 7,
        workspace: workspace("acme/api"),
        memory_key: key("lesson-1"),
        replacement_key: MemoryKey::replacement("lesson-2").expect("replacement key"),
        disposition,
        superseded_at: EpochMillis::from_millis(1_700_000_100_000),
        revision: 2,
    })
    .expect("supersession receipt")
}

fn every_request() -> Vec<MemoryRequest> {
    vec![
        MemoryRequest::RecordMemory {
            request_id: request_id(),
            item: presented(),
        },
        MemoryRequest::SupersedeMemory {
            request_id: request_id(),
            correction: SupersedeMemory::new(
                workspace("acme/api"),
                key("lesson-1"),
                MemoryKey::replacement("lesson-2").expect("replacement key"),
            )
            .expect("correction"),
        },
        MemoryRequest::ListMemory {
            request_id: request_id(),
            query: ListMemory::new(
                workspace("acme/api"),
                MemoryCursor::new(9),
                MemoryPageSize::MAX,
            ),
        },
        MemoryRequest::MemoryDetail {
            request_id: request_id(),
            query: MemoryDetail::new(workspace("acme/api"), key("lesson-1")),
        },
    ]
}

fn every_response() -> Vec<MemoryResponse> {
    vec![
        MemoryResponse::Recorded {
            request_id: request_id(),
            receipt: receipt(MemoryDisposition::Recorded),
        },
        MemoryResponse::Recorded {
            request_id: request_id(),
            receipt: receipt(MemoryDisposition::AlreadyRecorded),
        },
        MemoryResponse::Superseded {
            request_id: request_id(),
            receipt: supersession_receipt(MemoryDisposition::Recorded),
        },
        MemoryResponse::Superseded {
            request_id: request_id(),
            receipt: supersession_receipt(MemoryDisposition::AlreadyRecorded),
        },
        MemoryResponse::MemoryList {
            request_id: request_id(),
            page: MemoryListPage::new(
                vec![
                    item(1, "acme/api", "lesson-1", Some("lesson-3")),
                    item(2, "acme/api", "lesson-2", None),
                ],
                MemoryContinuation::More(MemoryCursor::new(2)),
            )
            .expect("page"),
        },
        MemoryResponse::MemoryList {
            request_id: request_id(),
            page: MemoryListPage::new(Vec::new(), MemoryContinuation::Complete).expect("page"),
        },
        MemoryResponse::MemoryDetail {
            request_id: request_id(),
            item: item(1, "acme/api", "lesson-1", None),
        },
        MemoryResponse::MemoryDetail {
            request_id: request_id(),
            item: item(1, "acme/api", "lesson-1", Some("lesson-2")),
        },
        MemoryResponse::conflict(
            request_id(),
            &presented(),
            RecordedMemory {
                entry_id: 4,
                label: label("prefers-implicit-migrations"),
                content_digest: digest(DIGEST_B),
                trust: MemoryTrust::UNTRUSTED,
            },
        )
        .expect("conflict"),
        MemoryResponse::Refused {
            request_id: request_id(),
            refusal: MemoryRefusal::AlreadySuperseded,
        },
    ]
}

fn encode(request: &MemoryRequest) -> Vec<u8> {
    request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes()
}

fn encode_response(response: &MemoryResponse) -> Vec<u8> {
    response
        .to_message()
        .expect("encode response")
        .to_canonical_bytes()
}

// ---------------------------------------------------------------------------
// Round trips and the envelope.
// ---------------------------------------------------------------------------

#[test]
fn every_request_and_response_survives_its_own_codec() {
    for request in every_request() {
        let payload = encode(&request);
        assert_eq!(
            MemoryRequest::from_canonical_bytes(&payload).expect("admitted request"),
            request,
        );
    }
    for response in every_response() {
        let payload = encode_response(&response);
        assert_eq!(
            MemoryResponse::from_canonical_bytes(&payload).expect("admitted response"),
            response,
        );
    }
}

#[test]
fn the_protocol_name_and_schema_are_the_ones_this_build_declares() {
    assert_eq!(MEMORY_PROTOCOL, "automonique.memory");
    assert_eq!(MEMORY_API_SCHEMA_V1, "automonique.memory/v1");
    // A versioned dotted name, and the schema is exactly the protocol name plus
    // its major version.
    assert_eq!(MEMORY_API_SCHEMA_V1, format!("{MEMORY_PROTOCOL}/v1"));

    let payload = encode(&MemoryRequest::MemoryDetail {
        request_id: request_id(),
        query: MemoryDetail::new(workspace("acme/api"), key("lesson-1")),
    });
    let text = String::from_utf8(payload).expect("utf-8 payload");
    assert_eq!(
        text,
        r#"{"body":{"memory_key":"lesson-1","workspace":"acme/api"},"kind":"memory_detail","protocol":"automonique.memory","request_id":"memory-test-1","version":1}"#,
    );
}

/// The same value encodes to the same bytes, every time and from every path.
#[test]
fn encoding_is_deterministic() {
    for request in every_request() {
        assert_eq!(encode(&request), encode(&request));
    }
    for response in every_response() {
        assert_eq!(encode_response(&response), encode_response(&response));
    }
    // A value rebuilt from its own bytes encodes to those same bytes, so a
    // relay that decodes and re-encodes changes nothing.
    for response in every_response() {
        let payload = encode_response(&response);
        let round_tripped =
            MemoryResponse::from_canonical_bytes(&payload).expect("admitted response");
        assert_eq!(encode_response(&round_tripped), payload);
    }
}

#[test]
fn a_frame_from_another_protocol_is_refused_before_a_body_is_read() {
    for payload in [
        br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"memory_detail","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"memory_detail","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"memory_detail","protocol":"automonique.memory.v2","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            MemoryRequest::from_canonical_bytes(payload)
                .expect_err("foreign protocol")
                .category(),
            "unknown_protocol",
        );
    }
    // A major version this build does not implement is refused too, rather than
    // being read as version one.
    let future = br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"memory_detail","protocol":"automonique.memory","request_id":"r","version":2}"#;
    assert!(MemoryRequest::from_canonical_bytes(future).is_err());
}

/// The moves this protocol does not have are refused rather than guessed.
///
/// Deliberately the ones a reader might expect from the epic: there is no delete,
/// no in-place amendment, no un-supersession, and no retrieval.
#[test]
fn a_kind_this_protocol_does_not_define_is_refused_rather_than_guessed() {
    for payload in [
        br#"{"body":{},"kind":"amend_memory","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"delete_memory","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"memory_key":"lesson-1","workspace":"w"},"kind":"unsupersede_memory","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"query":"migrations","workspace":"w"},"kind":"retrieve_memory","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"query":"migrations","workspace":"w"},"kind":"search_memory","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            MemoryRequest::from_canonical_bytes(payload).expect_err("unknown kind"),
            MemoryApiError::UnknownKind,
        );
    }
    let response = br#"{"body":{},"kind":"memory_amended","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryResponse::from_canonical_bytes(response).expect_err("unknown kind"),
        MemoryApiError::UnknownKind,
    );
}

/// No message on this protocol has a member content could travel in.
///
/// The module's central claim is that it binds content by digest and stores none
/// of it. A field named for content appearing in any body would break that claim
/// silently, so the member names are enumerated from real encodings rather than
/// trusted.
#[test]
fn no_body_on_this_protocol_carries_content() {
    let forbidden = [
        "content",
        "text",
        "payload",
        "bytes",
        "body_text",
        "snippet",
        "memory_text",
        "value",
    ];
    let mut seen = Vec::new();
    for payload in every_request()
        .iter()
        .map(encode)
        .chain(every_response().iter().map(encode_response))
    {
        let text = String::from_utf8(payload).expect("utf-8 payload");
        for name in &forbidden {
            assert!(
                !text.contains(&format!("\"{name}\":")),
                "a body declared a {name} member: {text}",
            );
        }
        seen.push(text);
    }
    assert_eq!(seen.len(), every_request().len() + every_response().len());
}

// ---------------------------------------------------------------------------
// Field-set exactness. A body is the exact set of members its kind declares.
// ---------------------------------------------------------------------------

/// Every body member, and one member no body declares, refused both ways.
///
/// Removing a declared member and adding an undeclared one are the two ways a
/// body drifts, and both are `memory_invalid_body` rather than a value read as
/// absent or a value silently ignored.
#[test]
fn every_body_is_the_exact_field_set_its_kind_declares() {
    for request in every_request() {
        let text = String::from_utf8(encode(&request)).expect("utf-8 payload");
        // Appended in sorted position, so the canonical codec has no ordering
        // complaint to make and the refusal can only be the field set's.
        let widened = text.replace(r#"},"kind":"#, r#","zz_extra":1},"kind":"#);
        assert_eq!(
            MemoryRequest::from_canonical_bytes(widened.as_bytes())
                .expect_err("a widened body was admitted"),
            MemoryApiError::InvalidBody,
            "widening {text}",
        );
    }
    for response in every_response() {
        let text = String::from_utf8(encode_response(&response)).expect("utf-8 payload");
        let widened = text.replace(r#"},"kind":"#, r#","zz_extra":1},"kind":"#);
        assert_eq!(
            MemoryResponse::from_canonical_bytes(widened.as_bytes())
                .expect_err("a widened body was admitted"),
            MemoryApiError::InvalidBody,
            "widening {text}",
        );
    }
}

/// Every declared member of every body, dropped one at a time, refuses decode.
///
/// This is the field-set exactness proof in the other direction, and it is
/// exhaustive rather than a sample: a member that could go missing and still
/// decode would be a member the protocol did not really require.
#[test]
fn dropping_any_declared_member_from_any_body_refuses_decode() {
    for text in every_request()
        .iter()
        .map(|request| String::from_utf8(encode(request)).expect("utf-8"))
    {
        for narrowed in bodies_missing_one_member(&text) {
            assert_eq!(
                MemoryRequest::from_canonical_bytes(narrowed.as_bytes())
                    .expect_err("a narrowed body was admitted"),
                MemoryApiError::InvalidBody,
                "narrowing {text} to {narrowed}",
            );
        }
    }
    for text in every_response()
        .iter()
        .map(|response| String::from_utf8(encode_response(response)).expect("utf-8"))
    {
        for narrowed in bodies_missing_one_member(&text) {
            // A page's own members are judged by the page decoder; an item's are
            // judged by the item decoder. Both answer `memory_invalid_body`,
            // except a half-dropped supersession pair, which has its own word.
            let refusal = MemoryResponse::from_canonical_bytes(narrowed.as_bytes())
                .expect_err("a narrowed body was admitted");
            assert!(
                refusal == MemoryApiError::InvalidBody
                    || refusal == MemoryApiError::SupersessionIncoherent,
                "narrowing {text} to {narrowed} gave {refusal:?}",
            );
        }
    }
}

/// Rebuild a message's text once per top-level body member, each time without one.
fn bodies_missing_one_member(text: &str) -> Vec<String> {
    let payload = text.as_bytes();
    let message = automonique_protocol::wire::Message::from_canonical_bytes(payload)
        .expect("a canonical message");
    let JsonValue::Object(members) = message.body() else {
        return Vec::new();
    };
    (0..members.len())
        .map(|dropped| {
            let kept: Vec<(String, JsonValue)> = members
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, member)| member.clone())
                .collect();
            let narrowed = automonique_protocol::wire::Message::new(
                message.envelope().clone(),
                JsonValue::Object(kept),
            );
            String::from_utf8(narrowed.to_canonical_bytes()).expect("utf-8")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The trust vocabulary, and the policy class this protocol will not hold.
// ---------------------------------------------------------------------------

/// Three words, and every one of them is `context`'s own.
///
/// The pin is structural rather than a second list: [`MemoryTrust::as_str`]
/// delegates to [`TrustClass::as_str`], so this test proves the delegation holds
/// for every value and that the set is exactly `TrustClass::ALL` minus `policy`.
#[test]
fn the_trust_vocabulary_is_three_closed_words_pinned_to_context() {
    assert_eq!(
        MemoryTrust::ALL.map(MemoryTrust::as_str),
        ["untrusted", "compatibility", "actor_supplied"],
    );
    assert_eq!(
        MemoryTrust::ALL.map(MemoryTrust::class),
        [
            TrustClass::Untrusted,
            TrustClass::Compatibility,
            TrustClass::ActorSupplied,
        ],
    );
    for trust in MemoryTrust::ALL {
        assert_eq!(trust.as_str(), trust.class().as_str());
        assert_eq!(MemoryTrust::from_spelling(trust.as_str()), Some(trust));
    }

    // Ordered least to most trusted, as the protocol orders them.
    assert!(MemoryTrust::UNTRUSTED < MemoryTrust::COMPATIBILITY);
    assert!(MemoryTrust::COMPATIBILITY < MemoryTrust::ACTOR_SUPPLIED);

    // The set is exactly one word short of `TrustClass`, and the missing word is
    // the policy class.
    assert_eq!(TrustClass::ALL.len(), MemoryTrust::ALL.len() + 1);
    let refused: Vec<TrustClass> = TrustClass::ALL
        .into_iter()
        .filter(|class| MemoryTrust::from_spelling(class.as_str()).is_none())
        .collect();
    assert_eq!(refused, vec![TrustClass::Policy]);

    // And memory is a supplied class, which is why: the manifest's policy slot
    // cannot receive one.
    assert_eq!(SuppliedClass::Memory.as_str(), "memory");
}

/// A memory item may not carry policy trust, at construction or on the wire.
///
/// `SuppliedComponent::new` lowers a requested policy trust to `actor_supplied`
/// and proceeds; this protocol refuses, because a durable row that quietly said
/// `actor_supplied` when its writer said `policy` would be a permanent record of
/// a claim nobody made.
#[test]
fn a_memory_may_not_carry_policy_trust() {
    assert_eq!(
        MemoryTrust::new(TrustClass::Policy).expect_err("policy trust"),
        MemoryApiError::PolicyTrustRefused,
    );
    assert_eq!(MemoryTrust::from_spelling("policy"), None);
    assert_eq!(
        decode_memory_trust("policy").expect_err("policy trust"),
        MemoryApiError::PolicyTrustRefused,
    );
    // Refused by its own name rather than as an unknown word: `policy` is a word
    // this build defines and this protocol will not accept for a memory.
    assert_eq!(
        decode_memory_trust("policy")
            .expect_err("policy trust")
            .category(),
        "memory_policy_trust_refused",
    );

    // Every place a trust travels: the recording, the served item, and the
    // recorded side of a conflict.
    let recording = br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","label":"l","memory_key":"lesson-1","trust_class":"policy","workspace":"w"},"kind":"record_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(recording).expect_err("policy trust on the wire"),
        MemoryApiError::PolicyTrustRefused,
    );
    for payload in [
        br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","created_at_ms":1,"entry_id":1,"label":"l","memory_key":"lesson-1","revision":1,"superseded_at_ms":null,"superseded_by":null,"trust_class":"policy","workspace":"w"},"kind":"memory_detail_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"entry_id":4,"field":"trust_class","recorded_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","recorded_label":"l","recorded_trust":"policy"},"kind":"memory_conflict","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            MemoryResponse::from_canonical_bytes(payload).expect_err("policy trust on the wire"),
            MemoryApiError::PolicyTrustRefused,
        );
    }
}

#[test]
fn a_trust_word_this_build_does_not_define_fails_closed() {
    for spelling in [
        "trusted",
        "UNTRUSTED",
        "Actor_Supplied",
        "actorsupplied",
        "system",
        "",
    ] {
        assert_eq!(
            decode_memory_trust(spelling).expect_err("undefined trust"),
            MemoryApiError::Codec(CodecError::UnknownEnumValue {
                field: "trust_class"
            }),
            "{spelling} decoded",
        );
        assert_eq!(MemoryTrust::from_spelling(spelling), None);
    }
    let payload = br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","label":"l","memory_key":"lesson-1","trust_class":"trusted","workspace":"w"},"kind":"record_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(payload).expect_err("undefined trust"),
        MemoryApiError::Codec(CodecError::UnknownEnumValue {
            field: "trust_class"
        }),
    );
}

// ---------------------------------------------------------------------------
// The other closed vocabularies.
// ---------------------------------------------------------------------------

#[test]
fn a_disposition_a_conflict_field_and_a_refusal_all_fail_closed() {
    assert_eq!(
        MemoryDisposition::ALL.map(MemoryDisposition::as_str),
        ["recorded", "already_recorded"],
    );
    assert!(MemoryDisposition::Recorded.wrote());
    assert!(!MemoryDisposition::AlreadyRecorded.wrote());
    assert_eq!(MemoryDisposition::from_spelling("replayed"), None);
    // The same two words another lane already renders for the same idea, and the
    // same two `automonique_store::context_memory::MemoryDisposition` stores.
    // Neither crate depends on the other, so the agreement is asserted.
    assert_eq!(
        MemoryDisposition::ALL.map(MemoryDisposition::as_str),
        ApprovalDisposition::ALL.map(ApprovalDisposition::as_str),
    );

    // The store's own column names, in the order the store compares them.
    assert_eq!(
        MemoryConflictField::ALL.map(MemoryConflictField::as_str),
        ["label", "content_digest", "trust_class"],
    );
    assert_eq!(MemoryConflictField::from_spelling("memory_key"), None);
    assert_eq!(MemoryConflictField::from_spelling("workspace"), None);

    assert_eq!(
        MemoryRefusal::ALL.map(MemoryRefusal::as_str),
        [
            "unknown_memory",
            "unknown_replacement",
            "already_superseded",
            "cursor_out_of_range",
            "store_full",
            "invalid_field",
        ],
    );
    // A replay is a success, not a refusal, and a differing binding is a
    // conflict arm; neither has a refusal word.
    assert_eq!(MemoryRefusal::from_spelling("already_recorded"), None);
    assert_eq!(MemoryRefusal::from_spelling("conflict"), None);
    // Nor is there a word for the deletion this protocol does not offer.
    assert_eq!(
        MemoryRefusal::from_spelling("retention_forbids_deletion"),
        None
    );

    for (payload, field) in [
        (
            br#"{"body":{"created_at_ms":1,"disposition":"maybe","entry_id":1,"memory_key":"lesson-1","workspace":"w"},"kind":"memory_recorded","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
            "disposition",
        ),
        (
            br#"{"body":{"refusal":"already_recorded"},"kind":"refused","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
            "refusal",
        ),
        (
            br#"{"body":{"entry_id":4,"field":"memory_key","recorded_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","recorded_label":"l","recorded_trust":"untrusted"},"kind":"memory_conflict","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
            "field",
        ),
    ] {
        assert_eq!(
            MemoryResponse::from_canonical_bytes(payload).expect_err("undefined enum value"),
            MemoryApiError::Codec(CodecError::UnknownEnumValue { field }),
        );
    }
}

// ---------------------------------------------------------------------------
// Bounded fields and the digest grammar.
// ---------------------------------------------------------------------------

#[test]
fn the_bounded_fields_share_one_grammar_and_report_their_own_field() {
    // The bound is the context bound, not a number of this protocol's own.
    assert_eq!(MAX_MEMORY_API_FIELD_BYTES, MAX_CONTEXT_FIELD_BYTES);
    assert_eq!(MemoryWorkspace::MAX_BYTES, MAX_MEMORY_API_FIELD_BYTES);
    assert_eq!(MemoryKey::MAX_BYTES, MAX_MEMORY_API_FIELD_BYTES);
    assert_eq!(MemoryLabel::MAX_BYTES, MAX_MEMORY_API_FIELD_BYTES);

    let over_long = "a".repeat(MAX_MEMORY_API_FIELD_BYTES + 1);
    assert_eq!(
        MemoryWorkspace::new("").expect_err("empty workspace"),
        MemoryApiError::Field {
            field: "workspace",
            error: ValueError::Empty,
        },
    );
    assert_eq!(
        MemoryKey::new("").expect_err("empty key"),
        MemoryApiError::Field {
            field: "memory_key",
            error: ValueError::Empty,
        },
    );
    // Same grammar, its own field name, so a caller is not told the wrong field
    // was wrong.
    assert_eq!(
        MemoryKey::replacement("").expect_err("empty replacement"),
        MemoryApiError::Field {
            field: "replacement_key",
            error: ValueError::Empty,
        },
    );
    assert_eq!(
        MemoryLabel::new("a\nb").expect_err("control-bearing label"),
        MemoryApiError::Field {
            field: "label",
            error: ValueError::ControlCharacter,
        },
    );
    assert_eq!(
        MemoryWorkspace::new(&over_long).expect_err("over-long workspace"),
        MemoryApiError::Field {
            field: "workspace",
            error: ValueError::TooLong {
                max_bytes: MAX_MEMORY_API_FIELD_BYTES,
                actual_bytes: MAX_MEMORY_API_FIELD_BYTES + 1,
            },
        },
    );

    // The bound itself is admitted, so the refusals above are bounds and not
    // off-by-ones.
    let maximal = "a".repeat(MAX_MEMORY_API_FIELD_BYTES);
    assert!(MemoryWorkspace::new(&maximal).is_ok());
    assert!(MemoryKey::new(&maximal).is_ok());
    assert!(MemoryKey::replacement(&maximal).is_ok());
    assert!(MemoryLabel::new(&maximal).is_ok());
}

#[test]
fn an_ungrammatical_field_on_the_wire_is_refused_by_its_own_field_name() {
    let payload = br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","label":"l","memory_key":"lesson-1","trust_class":"untrusted","workspace":""},"kind":"record_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(payload).expect_err("empty workspace"),
        MemoryApiError::Field {
            field: "workspace",
            error: ValueError::Empty,
        },
    );
    let payload = br#"{"body":{"memory_key":"lesson-1","replacement_key":"","workspace":"w"},"kind":"supersede_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(payload).expect_err("empty replacement"),
        MemoryApiError::Field {
            field: "replacement_key",
            error: ValueError::Empty,
        },
    );
}

/// Exactly sixty-four lowercase hexadecimal digits, and nothing adjacent to it.
///
/// Uppercase is refused rather than folded, so one digest has exactly one wire
/// spelling; a prefixed `sha256:` digest is refused rather than stripped, because
/// stripping is the caller's move to make and doing it here would admit two
/// spellings of one value.
#[test]
fn the_content_digest_grammar_is_sixty_four_lowercase_hex() {
    assert_eq!(MEMORY_DIGEST_CHARS, 64);
    assert_eq!(ContentDigest::CHARS, MEMORY_DIGEST_CHARS);
    assert_eq!(DIGEST_A.len(), MEMORY_DIGEST_CHARS);
    assert!(ContentDigest::new(DIGEST_A).is_ok());
    assert!(ContentDigest::new(DIGEST_B).is_ok());

    for (bad, why) in [
        ("", "empty"),
        (&DIGEST_A[..63], "one short"),
        (&format!("{DIGEST_A}a"), "one long"),
        (&DIGEST_A.to_uppercase(), "uppercase"),
        (
            "A1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            "one uppercase digit",
        ),
        (
            "g1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
            "not hexadecimal",
        ),
        (
            "sha256:b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c",
            "prefixed",
        ),
    ] {
        assert_eq!(
            ContentDigest::new(bad).expect_err(why),
            MemoryApiError::Digest {
                field: "content_digest",
            },
            "{why} was admitted",
        );
    }
    // The conflict's recorded digest reports its own field name.
    assert_eq!(
        ContentDigest::recorded("").expect_err("empty recorded digest"),
        MemoryApiError::Digest {
            field: "recorded_digest",
        },
    );

    // And on the wire, in the recording that presents one and the item that
    // reports one.
    let payload = br#"{"body":{"content_digest":"A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4A1B2C3D4","label":"l","memory_key":"lesson-1","trust_class":"untrusted","workspace":"w"},"kind":"record_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(payload).expect_err("uppercase digest"),
        MemoryApiError::Digest {
            field: "content_digest",
        },
    );
    let payload = br#"{"body":{"content_digest":"abc","created_at_ms":1,"entry_id":1,"label":"l","memory_key":"lesson-1","revision":1,"superseded_at_ms":null,"superseded_by":null,"trust_class":"untrusted","workspace":"w"},"kind":"memory_detail_result","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryResponse::from_canonical_bytes(payload).expect_err("short digest"),
        MemoryApiError::Digest {
            field: "content_digest",
        },
    );
}

// ---------------------------------------------------------------------------
// Write-once, and the supersession stamp.
// ---------------------------------------------------------------------------

/// A row's revision and its supersession stamp are coupled, both ways.
///
/// This is the store's database `CHECK` re-derived on the wire, because a wire
/// value is read by clients that never see the table. A half-stamped row admitted
/// as a correction would let a reader believe an item was corrected by nothing.
#[test]
fn an_item_couples_its_revision_to_its_supersession_stamp() {
    let stamp = || SupersessionStamp {
        replacement_key: MemoryKey::replacement("lesson-2").expect("replacement"),
        superseded_at: EpochMillis::from_millis(2),
    };
    let parts = |supersession, revision| MemoryItemParts {
        entry_id: 1,
        workspace: workspace("w"),
        memory_key: key("lesson-1"),
        label: label("l"),
        content_digest: digest(DIGEST_A),
        trust: MemoryTrust::UNTRUSTED,
        created_at: EpochMillis::from_millis(1),
        supersession,
        revision,
    };

    // The two coherent shapes.
    assert!(MemoryDetailView::new(parts(None, 1)).is_ok());
    assert!(MemoryDetailView::new(parts(Some(stamp()), 2)).is_ok());
    assert!(
        !MemoryDetailView::new(parts(None, 1))
            .expect("item")
            .is_superseded()
    );
    assert!(
        MemoryDetailView::new(parts(Some(stamp()), 2))
            .expect("item")
            .is_superseded()
    );

    // A stamp without the revision, and a revision without the stamp.
    assert_eq!(
        MemoryDetailView::new(parts(Some(stamp()), 1)).expect_err("stamped at revision one"),
        MemoryApiError::SupersessionIncoherent,
    );
    assert_eq!(
        MemoryDetailView::new(parts(None, 2)).expect_err("revision two without a stamp"),
        MemoryApiError::SupersessionIncoherent,
    );
    // And a revision the table admits no value for.
    for revision in [0_u64, 3, 7] {
        assert_eq!(
            MemoryDetailView::new(parts(None, revision)).expect_err("unknown revision"),
            MemoryApiError::RevisionUnknown { revision },
        );
    }

    // Half a stamp on the wire is refused rather than read as unstamped.
    for payload in [
        br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","created_at_ms":1,"entry_id":1,"label":"l","memory_key":"lesson-1","revision":2,"superseded_at_ms":2,"superseded_by":null,"trust_class":"untrusted","workspace":"w"},"kind":"memory_detail_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","created_at_ms":1,"entry_id":1,"label":"l","memory_key":"lesson-1","revision":2,"superseded_at_ms":null,"superseded_by":"lesson-2","trust_class":"untrusted","workspace":"w"},"kind":"memory_detail_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        // Both columns present, but the revision says the row was never stamped.
        br#"{"body":{"content_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","created_at_ms":1,"entry_id":1,"label":"l","memory_key":"lesson-1","revision":1,"superseded_at_ms":2,"superseded_by":"lesson-2","trust_class":"untrusted","workspace":"w"},"kind":"memory_detail_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            MemoryResponse::from_canonical_bytes(payload).expect_err("half-stamped row"),
            MemoryApiError::SupersessionIncoherent,
        );
    }
}

/// A correction that names the item it corrects is refused everywhere it can be
/// spelled.
#[test]
fn an_item_may_not_be_its_own_replacement() {
    assert_eq!(
        SupersedeMemory::new(
            workspace("w"),
            key("lesson-1"),
            MemoryKey::replacement("lesson-1").expect("replacement"),
        )
        .expect_err("self supersession"),
        MemoryApiError::SelfSupersession,
    );
    assert_eq!(
        SupersessionReceiptView::new(SupersessionReceiptParts {
            entry_id: 1,
            workspace: workspace("w"),
            memory_key: key("lesson-1"),
            replacement_key: MemoryKey::replacement("lesson-1").expect("replacement"),
            disposition: MemoryDisposition::Recorded,
            superseded_at: EpochMillis::from_millis(1),
            revision: 2,
        })
        .expect_err("self supersession"),
        MemoryApiError::SelfSupersession,
    );
    assert_eq!(
        MemoryDetailView::new(MemoryItemParts {
            entry_id: 1,
            workspace: workspace("w"),
            memory_key: key("lesson-1"),
            label: label("l"),
            content_digest: digest(DIGEST_A),
            trust: MemoryTrust::UNTRUSTED,
            created_at: EpochMillis::from_millis(1),
            supersession: Some(SupersessionStamp {
                replacement_key: MemoryKey::replacement("lesson-1").expect("replacement"),
                superseded_at: EpochMillis::from_millis(2),
            }),
            revision: 2,
        })
        .expect_err("self supersession"),
        MemoryApiError::SelfSupersession,
    );
    let payload = br#"{"body":{"memory_key":"lesson-1","replacement_key":"lesson-1","workspace":"w"},"kind":"supersede_memory","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryRequest::from_canonical_bytes(payload).expect_err("self supersession on the wire"),
        MemoryApiError::SelfSupersession,
    );
}

/// A stamped row has exactly one revision, and the supersession receipt says so.
#[test]
fn a_supersession_receipt_admits_only_the_stamped_revision() {
    assert_eq!(SupersessionReceiptView::SUPERSEDED_REVISION, 2);
    for revision in [0_u64, 1, 3] {
        assert_eq!(
            SupersessionReceiptView::new(SupersessionReceiptParts {
                entry_id: 1,
                workspace: workspace("w"),
                memory_key: key("lesson-1"),
                replacement_key: MemoryKey::replacement("lesson-2").expect("replacement"),
                disposition: MemoryDisposition::Recorded,
                superseded_at: EpochMillis::from_millis(1),
                revision,
            })
            .expect_err("unstamped revision"),
            MemoryApiError::RevisionUnknown { revision },
        );
    }
    let payload = br#"{"body":{"disposition":"recorded","entry_id":1,"memory_key":"lesson-1","replacement_key":"lesson-2","revision":1,"superseded_at_ms":1,"workspace":"w"},"kind":"memory_superseded","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryResponse::from_canonical_bytes(payload).expect_err("unstamped revision on the wire"),
        MemoryApiError::RevisionUnknown { revision: 1 },
    );
}

/// The two supersession refusals this protocol reserves, and the replay that is
/// not one of them.
#[test]
fn the_supersession_refusal_arms_say_what_they_mean() {
    // Superseding an item that is already superseded by a *different*
    // replacement is a rejection, not a conflict: a supersession is one-way and
    // one-time, so there is no current version to retry against.
    let refused = MemoryResponse::Refused {
        request_id: request_id(),
        refusal: MemoryRefusal::AlreadySuperseded,
    };
    assert_eq!(refused.outcome(), ActionOutcome::Rejected);
    let payload = encode_response(&refused);
    assert_eq!(
        MemoryResponse::from_canonical_bytes(&payload).expect("admitted"),
        refused,
    );

    // A replacement that is not recorded is a refusal this model can express and
    // the daemon must decide.
    let absent = MemoryResponse::Refused {
        request_id: request_id(),
        refusal: MemoryRefusal::UnknownReplacement,
    };
    assert_eq!(absent.outcome(), ActionOutcome::Rejected);
    assert_eq!(
        MemoryResponse::from_canonical_bytes(&encode_response(&absent)).expect("admitted"),
        absent,
    );

    // Naming the same replacement again is a *replay*, and a replay is a
    // success carrying `already_recorded` — never a refusal.
    let replay = MemoryResponse::Superseded {
        request_id: request_id(),
        receipt: supersession_receipt(MemoryDisposition::AlreadyRecorded),
    };
    assert_eq!(replay.outcome(), ActionOutcome::Accepted);
    assert!(
        !supersession_receipt(MemoryDisposition::AlreadyRecorded)
            .disposition()
            .wrote()
    );
}

// ---------------------------------------------------------------------------
// The conflict arm.
// ---------------------------------------------------------------------------

/// The differing field is derived from both sides, in the order the store
/// compares them, and never taken on the answering side's word.
#[test]
fn a_conflict_names_the_first_field_that_actually_differs() {
    for (recorded, expected) in [
        (
            RecordedMemory {
                entry_id: 4,
                label: label("something-else"),
                content_digest: digest(DIGEST_B),
                trust: MemoryTrust::UNTRUSTED,
            },
            MemoryConflictField::Label,
        ),
        (
            RecordedMemory {
                entry_id: 4,
                label: label("prefers-explicit-migrations"),
                content_digest: digest(DIGEST_B),
                trust: MemoryTrust::UNTRUSTED,
            },
            MemoryConflictField::ContentDigest,
        ),
        (
            RecordedMemory {
                entry_id: 4,
                label: label("prefers-explicit-migrations"),
                content_digest: digest(DIGEST_A),
                trust: MemoryTrust::UNTRUSTED,
            },
            MemoryConflictField::TrustClass,
        ),
    ] {
        let answer =
            MemoryResponse::conflict(request_id(), &presented(), recorded).expect("conflict");
        let MemoryResponse::Conflict { field, .. } = answer else {
            panic!("expected a conflict")
        };
        assert_eq!(field, expected);
    }
}

/// An exact replay is not a conflict, and this constructor will not manufacture
/// one.
#[test]
fn a_conflict_that_agrees_on_every_field_is_refused() {
    assert_eq!(
        MemoryResponse::conflict(
            request_id(),
            &presented(),
            RecordedMemory {
                entry_id: 4,
                label: label("prefers-explicit-migrations"),
                content_digest: digest(DIGEST_A),
                trust: MemoryTrust::ACTOR_SUPPLIED,
            },
        )
        .expect_err("agreement is not a conflict"),
        MemoryApiError::ConflictWithoutDisagreement,
    );
}

#[test]
fn a_conflict_on_an_unwritten_row_is_refused_at_both_ends() {
    assert_eq!(
        MemoryResponse::conflict(
            request_id(),
            &presented(),
            RecordedMemory {
                entry_id: 0,
                label: label("something-else"),
                content_digest: digest(DIGEST_B),
                trust: MemoryTrust::UNTRUSTED,
            },
        )
        .expect_err("unwritten row"),
        MemoryApiError::UnwrittenRow { field: "entry_id" },
    );
    let payload = br#"{"body":{"entry_id":0,"field":"label","recorded_digest":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","recorded_label":"l","recorded_trust":"untrusted"},"kind":"memory_conflict","protocol":"automonique.memory","request_id":"r","version":1}"#;
    assert_eq!(
        MemoryResponse::from_canonical_bytes(payload).expect_err("unwritten row"),
        MemoryApiError::UnwrittenRow { field: "entry_id" },
    );
}

/// A conflict carries the recorded side and never the caller's own payload.
///
/// The workspace and the key are deliberately absent: the caller supplied both
/// and already holds them, so repeating them would be an echo rather than
/// information.
#[test]
fn a_conflict_body_carries_the_recorded_side_and_not_the_callers() {
    let answer = MemoryResponse::conflict(
        request_id(),
        &presented(),
        RecordedMemory {
            entry_id: 4,
            label: label("prefers-implicit-migrations"),
            content_digest: digest(DIGEST_B),
            trust: MemoryTrust::UNTRUSTED,
        },
    )
    .expect("conflict");
    let text = String::from_utf8(encode_response(&answer)).expect("utf-8");

    // The recorded coordinates travel.
    assert!(text.contains(r#""recorded_label":"prefers-implicit-migrations""#));
    assert!(text.contains(&format!(r#""recorded_digest":"{DIGEST_B}""#)));
    assert!(text.contains(r#""recorded_trust":"untrusted""#));
    assert!(text.contains(r#""entry_id":4"#));

    // The caller's own do not.
    for echoed in [
        "prefers-explicit-migrations",
        DIGEST_A,
        "lesson-1",
        "acme/api",
        "actor_supplied",
    ] {
        assert!(
            !text.contains(echoed),
            "the conflict echoed the caller's {echoed}: {text}",
        );
    }
}

// ---------------------------------------------------------------------------
// Paging, and the workspace boundary.
// ---------------------------------------------------------------------------

#[test]
fn a_page_size_outside_the_protocols_range_is_refused_rather_than_clamped() {
    assert_eq!(
        MemoryPageSize::new(0).expect_err("zero page"),
        MemoryApiError::PageSizeOutOfRange {
            max_items: MAX_MEMORY_PAGE_ITEMS,
            requested: 0,
        },
    );
    assert_eq!(
        MemoryPageSize::new(MAX_MEMORY_PAGE_ITEMS + 1).expect_err("over-long page"),
        MemoryApiError::PageSizeOutOfRange {
            max_items: MAX_MEMORY_PAGE_ITEMS,
            requested: MAX_MEMORY_PAGE_ITEMS + 1,
        },
    );
    assert_eq!(MemoryPageSize::MAX.get(), MAX_MEMORY_PAGE_ITEMS);

    for requested in [0_usize, MAX_MEMORY_PAGE_ITEMS + 1] {
        let payload = format!(
            r#"{{"body":{{"cursor":0,"page_size":{requested},"workspace":"w"}},"kind":"list_memory","protocol":"automonique.memory","request_id":"r","version":1}}"#
        );
        assert_eq!(
            MemoryRequest::from_canonical_bytes(payload.as_bytes()).expect_err("page size"),
            MemoryApiError::PageSizeOutOfRange {
                max_items: MAX_MEMORY_PAGE_ITEMS,
                requested,
            },
        );
    }
    // The bound itself is admitted.
    let payload = format!(
        r#"{{"body":{{"cursor":0,"page_size":{MAX_MEMORY_PAGE_ITEMS},"workspace":"w"}},"kind":"list_memory","protocol":"automonique.memory","request_id":"r","version":1}}"#
    );
    assert!(MemoryRequest::from_canonical_bytes(payload.as_bytes()).is_ok());
}

#[test]
fn a_page_refuses_to_be_over_long_out_of_order_or_to_rewind() {
    let rows: Vec<MemoryDetailView> = (1..=u64::try_from(MAX_MEMORY_PAGE_ITEMS + 1)
        .expect("small"))
        .map(|entry_id| item(entry_id, "acme/api", &format!("lesson-{entry_id}"), None))
        .collect();
    assert_eq!(
        MemoryListPage::new(rows, MemoryContinuation::Complete).expect_err("over-long page"),
        MemoryApiError::PageTooLarge {
            max_items: MAX_MEMORY_PAGE_ITEMS,
            actual_items: MAX_MEMORY_PAGE_ITEMS + 1,
        },
    );

    // A repeat and a step backwards both mean the next page would re-serve or
    // skip a row.
    for pair in [[2_u64, 2], [2, 1]] {
        let out_of_order = pair
            .iter()
            .map(|entry_id| item(*entry_id, "acme/api", "lesson-1", None))
            .collect();
        assert_eq!(
            MemoryListPage::new(out_of_order, MemoryContinuation::Complete)
                .expect_err("out of order"),
            MemoryApiError::PageOutOfOrder,
        );
    }

    let two = vec![
        item(1, "acme/api", "lesson-1", None),
        item(2, "acme/api", "lesson-2", None),
    ];
    assert_eq!(
        MemoryListPage::new(two.clone(), MemoryContinuation::More(MemoryCursor::new(1)))
            .expect_err("rewinding cursor"),
        MemoryApiError::ContinuationRewinds,
    );
    // A cursor at the last row served is exactly right.
    assert!(MemoryListPage::new(two, MemoryContinuation::More(MemoryCursor::new(2))).is_ok());

    // An empty page that says more may follow is legal: the workspace filter can
    // exclude every row in one scanned window.
    assert!(
        MemoryListPage::new(Vec::new(), MemoryContinuation::More(MemoryCursor::new(9))).is_ok()
    );
}

#[test]
fn a_page_whose_marker_and_cursor_disagree_is_refused_at_decode() {
    for payload in [
        br#"{"body":{"memories":[],"more":true,"next_cursor":null},"kind":"memory_list_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"memories":[],"more":false,"next_cursor":3},"kind":"memory_list_result","protocol":"automonique.memory","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            MemoryResponse::from_canonical_bytes(payload).expect_err("incoherent continuation"),
            MemoryApiError::ContinuationIncoherent,
        );
    }
}

/// A listing answer may not exceed the question, and may not cross the workspace.
///
/// The workspace is the one boundary this store has, so a page that crossed it
/// would let one project's memory answer another project's listing — and the
/// answer would look perfectly well-formed to a client.
#[test]
fn a_listing_answer_stays_inside_its_question() {
    let query = ListMemory::new(
        workspace("acme/api"),
        MemoryCursor::START,
        MemoryPageSize::new(1).expect("one"),
    );
    let over_long = MemoryListPage::new(
        vec![
            item(1, "acme/api", "lesson-1", None),
            item(2, "acme/api", "lesson-2", None),
        ],
        MemoryContinuation::Complete,
    )
    .expect("page");
    assert_eq!(
        MemoryResponse::listing(request_id(), &query, over_long).expect_err("over-long answer"),
        MemoryApiError::PageAboveRequestedSize {
            requested: 1,
            actual_items: 2,
        },
    );

    let query = ListMemory::new(
        workspace("acme/api"),
        MemoryCursor::START,
        MemoryPageSize::MAX,
    );
    let foreign = MemoryListPage::new(
        vec![
            item(1, "acme/api", "lesson-1", None),
            item(2, "acme/web", "lesson-2", None),
        ],
        MemoryContinuation::Complete,
    )
    .expect("page");
    assert_eq!(
        MemoryResponse::listing(request_id(), &query, foreign).expect_err("foreign workspace"),
        MemoryApiError::PageOutsideWorkspace,
    );

    // The matching page is served, corrected items included.
    let matching = MemoryListPage::new(
        vec![
            item(1, "acme/api", "lesson-1", Some("lesson-2")),
            item(2, "acme/api", "lesson-2", None),
        ],
        MemoryContinuation::Complete,
    )
    .expect("page");
    let served = MemoryResponse::listing(request_id(), &query, matching).expect("served");
    let MemoryResponse::MemoryList { page, .. } = &served else {
        panic!("expected a listing")
    };
    assert!(page.entries()[0].is_superseded());
    assert!(!page.entries()[1].is_superseded());
}

// ---------------------------------------------------------------------------
// Rows this product could not have written.
// ---------------------------------------------------------------------------

#[test]
fn an_unwritten_row_and_an_impossible_instant_are_refused() {
    assert_eq!(
        MemoryReceiptView::new(
            0,
            workspace("w"),
            key("lesson-1"),
            MemoryDisposition::Recorded,
            EpochMillis::from_millis(1),
        )
        .expect_err("unwritten row"),
        MemoryApiError::UnwrittenRow { field: "entry_id" },
    );
    assert_eq!(
        MemoryReceiptView::new(
            1,
            workspace("w"),
            key("lesson-1"),
            MemoryDisposition::Recorded,
            EpochMillis::from_millis(-1),
        )
        .expect_err("pre-epoch instant"),
        MemoryApiError::TimeBeforeEpoch {
            field: "created_at_ms",
        },
    );
    assert_eq!(
        MemoryDetailView::new(MemoryItemParts {
            entry_id: 0,
            workspace: workspace("w"),
            memory_key: key("lesson-1"),
            label: label("l"),
            content_digest: digest(DIGEST_A),
            trust: MemoryTrust::UNTRUSTED,
            created_at: EpochMillis::from_millis(1),
            supersession: None,
            revision: 1,
        })
        .expect_err("unwritten row"),
        MemoryApiError::UnwrittenRow { field: "entry_id" },
    );
    assert_eq!(
        MemoryDetailView::new(MemoryItemParts {
            entry_id: 1,
            workspace: workspace("w"),
            memory_key: key("lesson-1"),
            label: label("l"),
            content_digest: digest(DIGEST_A),
            trust: MemoryTrust::UNTRUSTED,
            created_at: EpochMillis::from_millis(1),
            supersession: Some(SupersessionStamp {
                replacement_key: MemoryKey::replacement("lesson-2").expect("replacement"),
                superseded_at: EpochMillis::from_millis(-1),
            }),
            revision: 2,
        })
        .expect_err("pre-epoch stamp"),
        MemoryApiError::TimeBeforeEpoch {
            field: "superseded_at_ms",
        },
    );
}

// ---------------------------------------------------------------------------
// Outcomes, and the honesty of the whole slice.
// ---------------------------------------------------------------------------

#[test]
fn every_answer_reports_one_of_the_four_outcomes_this_protocol_produces() {
    for response in every_response() {
        let outcome = response.outcome();
        assert!(
            !OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES.contains(&outcome),
            "{outcome:?} was produced",
        );
    }
    assert_eq!(
        OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES,
        [ActionOutcome::Unknown, ActionOutcome::ResyncRequired],
    );

    // A durable write is `accepted` on a fresh write and on a replay alike: the
    // row is committed either way, and `completed` would say the memory took
    // effect, which is a claim about a component this release does not contain.
    for disposition in MemoryDisposition::ALL {
        assert_eq!(
            MemoryResponse::Recorded {
                request_id: request_id(),
                receipt: receipt(disposition),
            }
            .outcome(),
            ActionOutcome::Accepted,
        );
        assert_eq!(
            MemoryResponse::Superseded {
                request_id: request_id(),
                receipt: supersession_receipt(disposition),
            }
            .outcome(),
            ActionOutcome::Accepted,
        );
    }
    assert_eq!(
        MemoryResponse::MemoryDetail {
            request_id: request_id(),
            item: item(1, "w", "lesson-1", None),
        }
        .outcome(),
        ActionOutcome::Completed,
    );
    for refusal in MemoryRefusal::ALL {
        assert_eq!(
            MemoryResponse::Refused {
                request_id: request_id(),
                refusal,
            }
            .outcome(),
            ActionOutcome::Rejected,
        );
    }
    assert_eq!(
        every_response()
            .into_iter()
            .filter(|response| matches!(response, MemoryResponse::Conflict { .. }))
            .map(|response| response.outcome())
            .collect::<Vec<_>>(),
        vec![ActionOutcome::Conflict],
    );
}

/// Exactly two requests on this protocol change durable state, and they are the
/// two mutations the durable store offers.
#[test]
fn recording_and_superseding_are_the_only_mutations_this_protocol_has() {
    for request in every_request() {
        assert_eq!(
            request.is_mutation(),
            matches!(
                request,
                MemoryRequest::RecordMemory { .. } | MemoryRequest::SupersedeMemory { .. }
            ),
        );
    }
    assert_eq!(
        every_request()
            .iter()
            .filter(|request| request.is_mutation())
            .count(),
        2,
    );
}

#[test]
fn every_answer_carries_the_correlation_identifier_of_its_question() {
    for response in every_response() {
        assert_eq!(response.request_id().as_str(), request_id().as_str());
    }
    for request in every_request() {
        assert_eq!(request.request_id().as_str(), request_id().as_str());
    }
}

// ---------------------------------------------------------------------------
// Frame arithmetic.
// ---------------------------------------------------------------------------

/// A maximal page of maximal items fits one frame, with headroom.
///
/// The relation is a compile-time assertion in `memory_api.rs`, so this build
/// could not have linked if it stopped holding. What is measured here is the
/// consequence: a real page, framed the way a local socket would frame it, fits.
#[test]
fn a_maximal_page_of_maximal_items_fits_one_frame() {
    let worst = "\"".repeat(MAX_MEMORY_API_FIELD_BYTES);
    let entries: Vec<MemoryDetailView> = (1..=u64::try_from(MAX_MEMORY_PAGE_ITEMS).expect("small"))
        .map(|entry_id| {
            MemoryDetailView::new(MemoryItemParts {
                entry_id,
                workspace: MemoryWorkspace::new(&worst).expect("workspace"),
                memory_key: MemoryKey::new(&format!("k{entry_id}{worst}")[..worst.len()])
                    .expect("key"),
                label: MemoryLabel::new(&worst).expect("label"),
                content_digest: digest(DIGEST_A),
                trust: MemoryTrust::ACTOR_SUPPLIED,
                created_at: EpochMillis::from_millis(i64::MAX),
                supersession: Some(SupersessionStamp {
                    replacement_key: MemoryKey::replacement(
                        &format!("r{entry_id}{worst}")[..worst.len()],
                    )
                    .expect("replacement"),
                    superseded_at: EpochMillis::from_millis(i64::MAX),
                }),
                revision: 2,
            })
            .expect("item")
        })
        .collect();
    let page = MemoryListPage::new(
        entries,
        MemoryContinuation::More(MemoryCursor::new(u64::MAX >> 1)),
    )
    .expect("maximal page");
    let payload = encode_response(&MemoryResponse::MemoryList {
        request_id: RequestId::new("a".repeat(128)).expect("maximal request identifier"),
        page,
    });
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("a maximal page fits one frame");
    assert!(
        frame.len() < MAX_MEMORY_CANONICAL_BYTES,
        "a maximal page framed to {} bytes",
        frame.len(),
    );
}
