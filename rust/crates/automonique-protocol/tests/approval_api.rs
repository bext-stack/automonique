// SPDX-License-Identifier: Elastic-2.0

//! The native Approval decision API: bounded values, closed vocabularies, and
//! decoders that fail closed.
//!
//! Nothing here talks to a socket or a database. What is pinned is the shape of
//! the wire: which words exist, which bodies are exact, what a page may carry,
//! and which of these values a hostile or drifting peer can put past the
//! decoder. The live behaviour is `automonique-daemon`'s
//! `tests/approval_live.rs`; the durable behaviour is `automonique-store`'s.

use automonique_protocol::approval_api::{
    APPROVAL_API_SCHEMA_V1, APPROVAL_PROTOCOL, ApprovalApiError, ApprovalContinuation,
    ApprovalCursor, ApprovalDecision, ApprovalDisposition, ApprovalKey, ApprovalListPage,
    ApprovalPageSize, ApprovalReceiptView, ApprovalRecordParts, ApprovalRecordView,
    ApprovalRefusal, ApprovalRequest, ApprovalResponse, ApprovalSubject, ApprovalsBySubject,
    ConflictField, Decider, ListApprovals, MAX_APPROVAL_API_FIELD_BYTES,
    MAX_APPROVAL_CANONICAL_BYTES, MAX_APPROVAL_PAGE_ITEMS, OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES,
    RecordApproval, RecordedApproval, decode_decision,
};
use automonique_protocol::codec::{CodecError, RequestId, encode_frame};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::primitives::{EpochMillis, ValueError};

fn request_id() -> RequestId {
    RequestId::new("approval-test-1").expect("request identifier")
}

fn key(value: &str) -> ApprovalKey {
    ApprovalKey::new(value).expect("approval key")
}

fn subject(value: &str) -> ApprovalSubject {
    ApprovalSubject::new(value).expect("subject")
}

fn decider(value: &str) -> Decider {
    Decider::new(value).expect("decider")
}

fn presented() -> RecordApproval {
    RecordApproval::new(
        key("deploy-2026-08-13"),
        subject("command:shutdown"),
        ApprovalDecision::Granted,
        decider("ben"),
    )
}

fn record(
    entry_id: u64,
    approval_key: &str,
    name: &str,
    decision: ApprovalDecision,
) -> ApprovalRecordView {
    ApprovalRecordView::new(ApprovalRecordParts {
        entry_id,
        approval_key: key(approval_key),
        subject: subject(name),
        decision,
        decider: decider("ben"),
        decided_at: EpochMillis::from_millis(1_700_000_000_000),
        revision: 1,
    })
    .expect("record")
}

fn receipt(disposition: ApprovalDisposition) -> ApprovalReceiptView {
    ApprovalReceiptView::new(
        7,
        key("deploy-2026-08-13"),
        ApprovalDecision::Granted,
        disposition,
        EpochMillis::from_millis(1_700_000_000_000),
    )
    .expect("receipt")
}

fn every_request() -> Vec<ApprovalRequest> {
    vec![
        ApprovalRequest::RecordApproval {
            request_id: request_id(),
            decision: presented(),
        },
        ApprovalRequest::ListApprovals {
            request_id: request_id(),
            query: ListApprovals::new(ApprovalCursor::new(9), ApprovalPageSize::MAX),
        },
        ApprovalRequest::ApprovalDetail {
            request_id: request_id(),
            approval_key: key("deploy-2026-08-13"),
        },
        ApprovalRequest::ApprovalsBySubject {
            request_id: request_id(),
            query: ApprovalsBySubject::new(
                subject("command:shutdown"),
                ApprovalCursor::START,
                ApprovalPageSize::new(4).expect("page size"),
            ),
        },
    ]
}

fn every_response() -> Vec<ApprovalResponse> {
    vec![
        ApprovalResponse::Recorded {
            request_id: request_id(),
            receipt: receipt(ApprovalDisposition::Recorded),
        },
        ApprovalResponse::Recorded {
            request_id: request_id(),
            receipt: receipt(ApprovalDisposition::AlreadyRecorded),
        },
        ApprovalResponse::ApprovalList {
            request_id: request_id(),
            page: ApprovalListPage::new(
                vec![
                    record(1, "deploy-1", "command:shutdown", ApprovalDecision::Granted),
                    record(2, "deploy-2", "command:shutdown", ApprovalDecision::Denied),
                ],
                ApprovalContinuation::More(ApprovalCursor::new(2)),
            )
            .expect("page"),
        },
        ApprovalResponse::ApprovalList {
            request_id: request_id(),
            page: ApprovalListPage::new(Vec::new(), ApprovalContinuation::Complete).expect("page"),
        },
        ApprovalResponse::ApprovalDetail {
            request_id: request_id(),
            record: record(1, "deploy-1", "command:shutdown", ApprovalDecision::Denied),
        },
        ApprovalResponse::conflict(
            request_id(),
            &presented(),
            RecordedApproval {
                entry_id: 4,
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Denied,
                decider: decider("dana"),
            },
        )
        .expect("conflict"),
        ApprovalResponse::Refused {
            request_id: request_id(),
            refusal: ApprovalRefusal::LedgerFull,
        },
    ]
}

fn encode(request: &ApprovalRequest) -> Vec<u8> {
    request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes()
}

fn encode_response(response: &ApprovalResponse) -> Vec<u8> {
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
            ApprovalRequest::from_canonical_bytes(&payload).expect("admitted request"),
            request,
        );
    }
    for response in every_response() {
        let payload = encode_response(&response);
        assert_eq!(
            ApprovalResponse::from_canonical_bytes(&payload).expect("admitted response"),
            response,
        );
    }
}

#[test]
fn the_protocol_name_and_schema_are_the_ones_this_build_declares() {
    assert_eq!(APPROVAL_PROTOCOL, "automonique.approval");
    assert_eq!(APPROVAL_API_SCHEMA_V1, "automonique.approval/v1");
    let payload = encode(&ApprovalRequest::ApprovalDetail {
        request_id: request_id(),
        approval_key: key("deploy-1"),
    });
    let text = String::from_utf8(payload).expect("utf-8 payload");
    assert_eq!(
        text,
        r#"{"body":{"approval_key":"deploy-1"},"kind":"approval_detail","protocol":"automonique.approval","request_id":"approval-test-1","version":1}"#,
    );
}

#[test]
fn a_frame_from_another_protocol_is_refused_before_a_body_is_read() {
    for payload in [
        br#"{"body":{"approval_key":"deploy-1"},"kind":"approval_detail","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"approval_key":"deploy-1"},"kind":"approval_detail","protocol":"automonique.approval.v2","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            ApprovalRequest::from_canonical_bytes(payload)
                .expect_err("foreign protocol")
                .category(),
            "unknown_protocol",
        );
    }
    // A major version this build does not implement is refused too, rather
    // than being read as version one.
    let future = br#"{"body":{"approval_key":"deploy-1"},"kind":"approval_detail","protocol":"automonique.approval","request_id":"r","version":2}"#;
    assert!(ApprovalRequest::from_canonical_bytes(future).is_err());
}

#[test]
fn a_kind_this_protocol_does_not_define_is_refused_rather_than_guessed() {
    for payload in [
        br#"{"body":{},"kind":"amend_approval","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
        // Deliberately the two mutations a write-once ledger does not have.
        br#"{"body":{"approval_key":"deploy-1"},"kind":"revoke_approval","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"approval_key":"deploy-1"},"kind":"delete_approval","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            ApprovalRequest::from_canonical_bytes(payload).expect_err("unknown kind"),
            ApprovalApiError::UnknownKind,
        );
    }
    let response = br#"{"body":{},"kind":"approval_amended","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalResponse::from_canonical_bytes(response).expect_err("unknown kind"),
        ApprovalApiError::UnknownKind,
    );
}

// ---------------------------------------------------------------------------
// Field-set exactness. A body is the exact set of members its kind declares.
// ---------------------------------------------------------------------------

/// Every body member, and one member no body declares, refused both ways.
///
/// Removing a declared member and adding an undeclared one are the two ways a
/// body drifts, and both are `approval_invalid_body` rather than a value read
/// as absent or a value silently ignored.
#[test]
fn every_body_is_the_exact_field_set_its_kind_declares() {
    for request in every_request() {
        let text = String::from_utf8(encode(&request)).expect("utf-8 payload");
        // Appended in sorted position, so the canonical codec has no ordering
        // complaint to make and the refusal can only be the field set's.
        let widened = text.replace(r#"},"kind":"#, r#","zz_extra":1},"kind":"#);
        assert_eq!(
            ApprovalRequest::from_canonical_bytes(widened.as_bytes())
                .expect_err("a widened body was admitted"),
            ApprovalApiError::InvalidBody,
            "widening {text}",
        );
    }
    for response in every_response() {
        let text = String::from_utf8(encode_response(&response)).expect("utf-8 payload");
        // Appended in sorted position, so the canonical codec has no ordering
        // complaint to make and the refusal can only be the field set's.
        let widened = text.replace(r#"},"kind":"#, r#","zz_extra":1},"kind":"#);
        assert_eq!(
            ApprovalResponse::from_canonical_bytes(widened.as_bytes())
                .expect_err("a widened body was admitted"),
            ApprovalApiError::InvalidBody,
            "widening {text}",
        );
    }
}

#[test]
fn a_body_missing_a_declared_member_is_refused() {
    for (payload, label) in [
        (
            br#"{"body":{"approval_key":"deploy-1","decider":"ben","decision":"granted"},"kind":"record_approval","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "record without a subject",
        ),
        (
            br#"{"body":{"approval_key":"deploy-1","decider":"ben","subject":"s"},"kind":"record_approval","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "record without a decision",
        ),
        (
            br#"{"body":{"since":0},"kind":"list_approvals","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "listing without a page size",
        ),
        (
            br#"{"body":{"page_size":4,"since":0},"kind":"approvals_by_subject","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "subject listing without a subject",
        ),
        (
            br#"{"body":{},"kind":"approval_detail","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "detail without a key",
        ),
    ] {
        assert_eq!(
            ApprovalRequest::from_canonical_bytes(payload).expect_err(label),
            ApprovalApiError::InvalidBody,
            "{label}",
        );
    }
}

// ---------------------------------------------------------------------------
// Closed vocabularies, and decoders that fail closed on a word they do not know.
// ---------------------------------------------------------------------------

/// The two decision spellings, pinned by literal.
///
/// This is one half of the agreement with
/// `automonique_store::approval_ledger`'s `CHECK (decision IN ('granted',
/// 'denied'))`; that crate's own tests pin the other half. Neither crate depends
/// on the other, so the pin has to be a literal one in both places, and a rename
/// on either side fails a test rather than landing.
#[test]
fn the_decision_vocabulary_is_two_closed_words() {
    assert_eq!(ApprovalDecision::Granted.as_str(), "granted");
    assert_eq!(ApprovalDecision::Denied.as_str(), "denied");
    assert_eq!(
        ApprovalDecision::ALL,
        [ApprovalDecision::Granted, ApprovalDecision::Denied]
    );
    assert!(ApprovalDecision::Granted.grants());
    assert!(!ApprovalDecision::Denied.grants());

    // `denied` is this crate's own spelling for a refusal, and the agreement is
    // asserted rather than assumed: two other closed vocabularies here render
    // the same word for the same idea.
    assert_eq!(
        automonique_protocol::sandbox::NetworkAccess::Denied.as_str(),
        ApprovalDecision::Denied.as_str(),
    );
    assert_eq!(
        automonique_protocol::connector_conformance::DispositionOutcome::Denied.as_str(),
        ApprovalDecision::Denied.as_str(),
    );
}

#[test]
fn a_decision_word_this_build_does_not_define_fails_closed() {
    for spelling in ["approved", "GRANTED", "Denied", "refused", "pending", ""] {
        assert_eq!(
            decode_decision(spelling).expect_err("undefined decision"),
            ApprovalApiError::Codec(CodecError::UnknownEnumValue { field: "decision" }),
            "{spelling} decoded",
        );
        assert_eq!(ApprovalDecision::from_spelling(spelling), None);
    }
    // And on the wire, in both the request that carries one and the record that
    // reports one.
    let payload = br#"{"body":{"approval_key":"deploy-1","decider":"ben","decision":"maybe","subject":"s"},"kind":"record_approval","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalRequest::from_canonical_bytes(payload).expect_err("undefined decision"),
        ApprovalApiError::Codec(CodecError::UnknownEnumValue { field: "decision" }),
    );
}

#[test]
fn a_disposition_a_refusal_and_a_conflict_field_all_fail_closed() {
    assert_eq!(ApprovalDisposition::Recorded.as_str(), "recorded");
    assert_eq!(
        ApprovalDisposition::AlreadyRecorded.as_str(),
        "already_recorded"
    );
    assert!(ApprovalDisposition::Recorded.wrote());
    assert!(!ApprovalDisposition::AlreadyRecorded.wrote());
    assert_eq!(ApprovalDisposition::from_spelling("replayed"), None);

    assert_eq!(
        ApprovalRefusal::ALL.map(ApprovalRefusal::as_str),
        [
            "unknown_approval",
            "cursor_out_of_range",
            "ledger_full",
            "invalid_field"
        ],
    );
    assert_eq!(ApprovalRefusal::from_spelling("already_recorded"), None);
    assert_eq!(ApprovalRefusal::from_spelling("conflict"), None);

    assert_eq!(
        ConflictField::ALL.map(ConflictField::as_str),
        ["subject", "decision", "decider"],
    );
    assert_eq!(ConflictField::from_spelling("approval_key"), None);

    for (payload, field) in [
        (
            br#"{"body":{"approval_key":"deploy-1","decided_at_ms":1,"decision":"granted","disposition":"maybe","entry_id":1},"kind":"approval_recorded","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "disposition",
        ),
        (
            br#"{"body":{"refusal":"already_recorded"},"kind":"refused","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "refusal",
        ),
        (
            br#"{"body":{"entry_id":4,"field":"approval_key","recorded_decider":"dana","recorded_decision":"denied","recorded_subject":"s"},"kind":"approval_conflict","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
            "field",
        ),
    ] {
        assert_eq!(
            ApprovalResponse::from_canonical_bytes(payload).expect_err("undefined enum value"),
            ApprovalApiError::Codec(CodecError::UnknownEnumValue { field }),
        );
    }
}

// ---------------------------------------------------------------------------
// Bounded identifiers.
// ---------------------------------------------------------------------------

#[test]
fn the_three_identifiers_share_one_grammar_and_report_their_own_field() {
    let over_long = "a".repeat(MAX_APPROVAL_API_FIELD_BYTES + 1);
    assert_eq!(
        ApprovalKey::new("").expect_err("empty key"),
        ApprovalApiError::Field {
            field: "approval_key",
            error: ValueError::Empty,
        },
    );
    assert_eq!(
        ApprovalSubject::new("a\nb").expect_err("control-bearing subject"),
        ApprovalApiError::Field {
            field: "subject",
            error: ValueError::ControlCharacter,
        },
    );
    assert_eq!(
        Decider::new(&over_long).expect_err("over-long decider"),
        ApprovalApiError::Field {
            field: "decider",
            error: ValueError::TooLong {
                max_bytes: MAX_APPROVAL_API_FIELD_BYTES,
                actual_bytes: MAX_APPROVAL_API_FIELD_BYTES + 1,
            },
        },
    );
    // The bound itself is admitted, so the refusals above are bounds and not
    // off-by-ones.
    let maximal = "a".repeat(MAX_APPROVAL_API_FIELD_BYTES);
    assert!(ApprovalKey::new(&maximal).is_ok());
    assert!(ApprovalSubject::new(&maximal).is_ok());
    assert!(Decider::new(&maximal).is_ok());
    assert_eq!(ApprovalKey::MAX_BYTES, MAX_APPROVAL_API_FIELD_BYTES);
    assert_eq!(ApprovalSubject::MAX_BYTES, MAX_APPROVAL_API_FIELD_BYTES);
    assert_eq!(Decider::MAX_BYTES, MAX_APPROVAL_API_FIELD_BYTES);
}

#[test]
fn an_ungrammatical_identifier_on_the_wire_is_refused_by_its_own_field_name() {
    let payload = br#"{"body":{"approval_key":"","decider":"ben","decision":"granted","subject":"s"},"kind":"record_approval","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalRequest::from_canonical_bytes(payload).expect_err("empty key"),
        ApprovalApiError::Field {
            field: "approval_key",
            error: ValueError::Empty,
        },
    );
}

// ---------------------------------------------------------------------------
// Paging.
// ---------------------------------------------------------------------------

#[test]
fn a_page_size_outside_the_protocols_range_is_refused_rather_than_clamped() {
    assert_eq!(
        ApprovalPageSize::new(0).expect_err("zero page"),
        ApprovalApiError::PageSizeOutOfRange {
            max_items: MAX_APPROVAL_PAGE_ITEMS,
            requested: 0,
        },
    );
    assert_eq!(
        ApprovalPageSize::new(MAX_APPROVAL_PAGE_ITEMS + 1).expect_err("over-long page"),
        ApprovalApiError::PageSizeOutOfRange {
            max_items: MAX_APPROVAL_PAGE_ITEMS,
            requested: MAX_APPROVAL_PAGE_ITEMS + 1,
        },
    );
    assert_eq!(ApprovalPageSize::MAX.get(), MAX_APPROVAL_PAGE_ITEMS);

    // Both listing decoders judge it by the same rule.
    for kind in ["list_approvals", "approvals_by_subject"] {
        let payload = format!(
            r#"{{"body":{{"page_size":0,"since":0,"subject":"s"}},"kind":"{kind}","protocol":"automonique.approval","request_id":"r","version":1}}"#
        );
        // The whole-ledger listing declares no `subject`, so it refuses this
        // body for the field set before it ever reaches the size; the subject
        // listing reaches the size. Either way, nothing is clamped.
        assert!(ApprovalRequest::from_canonical_bytes(payload.as_bytes()).is_err());
    }
    let payload = br#"{"body":{"page_size":0,"since":0},"kind":"list_approvals","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalRequest::from_canonical_bytes(payload).expect_err("zero page"),
        ApprovalApiError::PageSizeOutOfRange {
            max_items: MAX_APPROVAL_PAGE_ITEMS,
            requested: 0,
        },
    );
}

#[test]
fn a_page_refuses_to_be_over_long_out_of_order_or_to_rewind() {
    let rows: Vec<ApprovalRecordView> = (1..=u64::try_from(MAX_APPROVAL_PAGE_ITEMS + 1)
        .expect("small"))
        .map(|entry_id| {
            record(
                entry_id,
                &format!("deploy-{entry_id}"),
                "command:shutdown",
                ApprovalDecision::Granted,
            )
        })
        .collect();
    assert_eq!(
        ApprovalListPage::new(rows.clone(), ApprovalContinuation::Complete)
            .expect_err("over-long page"),
        ApprovalApiError::PageTooLarge {
            max_items: MAX_APPROVAL_PAGE_ITEMS,
            actual_items: MAX_APPROVAL_PAGE_ITEMS + 1,
        },
    );

    // A repeat and a step backwards both mean the next page would re-serve or
    // skip a row.
    for pair in [[2_u64, 2], [2, 1]] {
        let out_of_order = pair
            .iter()
            .map(|entry_id| {
                record(
                    *entry_id,
                    "deploy-1",
                    "command:shutdown",
                    ApprovalDecision::Granted,
                )
            })
            .collect();
        assert_eq!(
            ApprovalListPage::new(out_of_order, ApprovalContinuation::Complete)
                .expect_err("out of order"),
            ApprovalApiError::PageOutOfOrder,
        );
    }

    let two = vec![
        record(1, "deploy-1", "command:shutdown", ApprovalDecision::Granted),
        record(2, "deploy-2", "command:shutdown", ApprovalDecision::Granted),
    ];
    assert_eq!(
        ApprovalListPage::new(
            two.clone(),
            ApprovalContinuation::More(ApprovalCursor::new(1))
        )
        .expect_err("rewinding cursor"),
        ApprovalApiError::ContinuationRewinds,
    );
    // A cursor at the last row served is exactly right.
    assert!(ApprovalListPage::new(two, ApprovalContinuation::More(ApprovalCursor::new(2))).is_ok());

    // An empty page that says more may follow is legal: a subject filter can
    // exclude every row in one scanned window.
    assert!(
        ApprovalListPage::new(
            Vec::new(),
            ApprovalContinuation::More(ApprovalCursor::new(9))
        )
        .is_ok()
    );
}

#[test]
fn a_page_whose_marker_and_cursor_disagree_is_refused_at_decode() {
    for payload in [
        br#"{"body":{"approvals":[],"more":true,"next_cursor":null},"kind":"approval_list_result","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
        br#"{"body":{"approvals":[],"more":false,"next_cursor":3},"kind":"approval_list_result","protocol":"automonique.approval","request_id":"r","version":1}"#.as_slice(),
    ] {
        assert_eq!(
            ApprovalResponse::from_canonical_bytes(payload).expect_err("incoherent continuation"),
            ApprovalApiError::ContinuationIncoherent,
        );
    }
}

#[test]
fn a_listing_answer_may_not_carry_more_than_the_query_asked_for() {
    let query = ListApprovals::new(
        ApprovalCursor::START,
        ApprovalPageSize::new(1).expect("one"),
    );
    let page = ApprovalListPage::new(
        vec![
            record(1, "deploy-1", "command:shutdown", ApprovalDecision::Granted),
            record(2, "deploy-2", "command:shutdown", ApprovalDecision::Granted),
        ],
        ApprovalContinuation::Complete,
    )
    .expect("page");
    assert_eq!(
        ApprovalResponse::listing(request_id(), query, page).expect_err("over-long answer"),
        ApprovalApiError::PageAboveRequestedSize {
            requested: 1,
            actual_items: 2,
        },
    );
}

/// A subject listing that carries somebody else's decision is refused, not
/// served.
///
/// This is the one enforcement a client cannot perform for itself: the answer
/// would look perfectly well-formed and would silently contradict the question.
#[test]
fn a_subject_listing_may_not_carry_another_subjects_decision() {
    let query = ApprovalsBySubject::new(
        subject("command:shutdown"),
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    let page = ApprovalListPage::new(
        vec![
            record(1, "deploy-1", "command:shutdown", ApprovalDecision::Granted),
            record(
                2,
                "deploy-2",
                "command:pause-intake",
                ApprovalDecision::Denied,
            ),
        ],
        ApprovalContinuation::Complete,
    )
    .expect("page");
    assert_eq!(
        ApprovalResponse::subject_listing(request_id(), &query, page).expect_err("foreign subject"),
        ApprovalApiError::PageOutsideSubject,
    );

    // The matching page is served.
    let page = ApprovalListPage::new(
        vec![record(
            1,
            "deploy-1",
            "command:shutdown",
            ApprovalDecision::Granted,
        )],
        ApprovalContinuation::Complete,
    )
    .expect("page");
    assert!(matches!(
        ApprovalResponse::subject_listing(request_id(), &query, page).expect("served"),
        ApprovalResponse::ApprovalList { .. },
    ));
}

// ---------------------------------------------------------------------------
// Records and receipts: rows this product could not have written.
// ---------------------------------------------------------------------------

/// A write-once row has exactly one revision, and the decoder says so.
///
/// The ledger pins the column with a database `CHECK` and has no update path, so
/// any other value is a row a second writer produced. A reader must not accept
/// it as an amended decision.
#[test]
fn a_record_above_revision_one_is_an_amended_row_and_is_refused() {
    for revision in [0_u64, 2, 7] {
        assert_eq!(
            ApprovalRecordView::new(ApprovalRecordParts {
                entry_id: 1,
                approval_key: key("deploy-1"),
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Granted,
                decider: decider("ben"),
                decided_at: EpochMillis::from_millis(1),
                revision,
            })
            .expect_err("amended row"),
            ApprovalApiError::RowAmended { revision },
        );
    }
    let payload = br#"{"body":{"approval_key":"deploy-1","decided_at_ms":1,"decider":"ben","decision":"granted","entry_id":1,"revision":2,"subject":"s"},"kind":"approval_detail_result","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalResponse::from_canonical_bytes(payload).expect_err("amended row on the wire"),
        ApprovalApiError::RowAmended { revision: 2 },
    );
}

#[test]
fn an_unwritten_row_and_an_impossible_instant_are_refused() {
    assert_eq!(
        ApprovalRecordView::new(ApprovalRecordParts {
            entry_id: 0,
            approval_key: key("deploy-1"),
            subject: subject("command:shutdown"),
            decision: ApprovalDecision::Granted,
            decider: decider("ben"),
            decided_at: EpochMillis::from_millis(1),
            revision: 1,
        })
        .expect_err("unwritten row"),
        ApprovalApiError::UnwrittenRow { field: "entry_id" },
    );
    assert_eq!(
        ApprovalRecordView::new(ApprovalRecordParts {
            entry_id: 1,
            approval_key: key("deploy-1"),
            subject: subject("command:shutdown"),
            decision: ApprovalDecision::Granted,
            decider: decider("ben"),
            decided_at: EpochMillis::from_millis(-1),
            revision: 1,
        })
        .expect_err("pre-epoch instant"),
        ApprovalApiError::TimeBeforeEpoch {
            field: "decided_at_ms",
        },
    );
    assert_eq!(
        ApprovalReceiptView::new(
            0,
            key("deploy-1"),
            ApprovalDecision::Granted,
            ApprovalDisposition::Recorded,
            EpochMillis::from_millis(1),
        )
        .expect_err("unwritten row"),
        ApprovalApiError::UnwrittenRow { field: "entry_id" },
    );
    assert_eq!(
        ApprovalReceiptView::new(
            1,
            key("deploy-1"),
            ApprovalDecision::Granted,
            ApprovalDisposition::Recorded,
            EpochMillis::from_millis(-1),
        )
        .expect_err("pre-epoch instant"),
        ApprovalApiError::TimeBeforeEpoch {
            field: "decided_at_ms",
        },
    );
}

// ---------------------------------------------------------------------------
// The conflict arm.
// ---------------------------------------------------------------------------

/// The differing field is derived from both sides, in the order the ledger
/// compares them, and never taken on the answering side's word.
#[test]
fn a_conflict_names_the_first_field_that_actually_differs() {
    for (recorded, expected) in [
        (
            RecordedApproval {
                entry_id: 4,
                subject: subject("command:pause-intake"),
                decision: ApprovalDecision::Denied,
                decider: decider("dana"),
            },
            ConflictField::Subject,
        ),
        (
            RecordedApproval {
                entry_id: 4,
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Denied,
                decider: decider("dana"),
            },
            ConflictField::Decision,
        ),
        (
            RecordedApproval {
                entry_id: 4,
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Granted,
                decider: decider("dana"),
            },
            ConflictField::Decider,
        ),
    ] {
        let answer =
            ApprovalResponse::conflict(request_id(), &presented(), recorded).expect("conflict");
        let ApprovalResponse::Conflict { field, .. } = answer else {
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
        ApprovalResponse::conflict(
            request_id(),
            &presented(),
            RecordedApproval {
                entry_id: 4,
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Granted,
                decider: decider("ben"),
            },
        )
        .expect_err("agreement is not a conflict"),
        ApprovalApiError::ConflictWithoutDisagreement,
    );
}

#[test]
fn a_conflict_on_an_unwritten_row_is_refused_at_both_ends() {
    assert_eq!(
        ApprovalResponse::conflict(
            request_id(),
            &presented(),
            RecordedApproval {
                entry_id: 0,
                subject: subject("command:shutdown"),
                decision: ApprovalDecision::Denied,
                decider: decider("dana"),
            },
        )
        .expect_err("unwritten row"),
        ApprovalApiError::UnwrittenRow { field: "entry_id" },
    );
    let payload = br#"{"body":{"entry_id":0,"field":"decision","recorded_decider":"dana","recorded_decision":"denied","recorded_subject":"s"},"kind":"approval_conflict","protocol":"automonique.approval","request_id":"r","version":1}"#;
    assert_eq!(
        ApprovalResponse::from_canonical_bytes(payload).expect_err("unwritten row"),
        ApprovalApiError::UnwrittenRow { field: "entry_id" },
    );
}

/// A conflict carries the recorded side and never the caller's own payload.
///
/// The key is deliberately absent: the caller supplied it and already holds it,
/// so repeating it would be an echo rather than information.
#[test]
fn a_conflict_body_carries_the_recorded_side_and_no_key() {
    let answer = ApprovalResponse::conflict(
        request_id(),
        &presented(),
        RecordedApproval {
            entry_id: 4,
            subject: subject("command:shutdown"),
            decision: ApprovalDecision::Denied,
            decider: decider("dana"),
        },
    )
    .expect("conflict");
    let text = String::from_utf8(encode_response(&answer)).expect("utf-8");
    assert!(text.contains(r#""recorded_decision":"denied""#));
    assert!(text.contains(r#""recorded_decider":"dana""#));
    assert!(
        !text.contains("deploy-2026-08-13"),
        "the conflict echoed the caller's key: {text}",
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

    // A durable decision is `accepted` on a fresh recording and on a replay
    // alike: the row is committed either way, and `completed` would say the
    // decision took effect, which is a claim about a component this release does
    // not contain.
    for disposition in ApprovalDisposition::ALL {
        assert_eq!(
            ApprovalResponse::Recorded {
                request_id: request_id(),
                receipt: receipt(disposition),
            }
            .outcome(),
            ActionOutcome::Accepted,
        );
    }
    assert_eq!(
        ApprovalResponse::ApprovalDetail {
            request_id: request_id(),
            record: record(1, "deploy-1", "s", ApprovalDecision::Granted),
        }
        .outcome(),
        ActionOutcome::Completed,
    );
    assert_eq!(
        ApprovalResponse::Refused {
            request_id: request_id(),
            refusal: ApprovalRefusal::UnknownApproval,
        }
        .outcome(),
        ActionOutcome::Rejected,
    );
    assert_eq!(
        every_response()
            .into_iter()
            .filter(|response| matches!(response, ApprovalResponse::Conflict { .. }))
            .map(|response| response.outcome())
            .collect::<Vec<_>>(),
        vec![ActionOutcome::Conflict],
    );
}

/// Exactly one request on this protocol changes durable state.
#[test]
fn recording_is_the_only_mutation_this_protocol_has() {
    for request in every_request() {
        assert_eq!(
            request.is_mutation(),
            matches!(request, ApprovalRequest::RecordApproval { .. }),
        );
    }
    assert_eq!(
        every_request()
            .iter()
            .filter(|request| request.is_mutation())
            .count(),
        1,
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

/// A maximal page of maximal records fits one frame, with headroom.
///
/// The relation is a compile-time assertion in `approval_api.rs`, so this build
/// could not have linked if it stopped holding. What is measured here is the
/// consequence: a real page, framed the way the local socket frames it, fits.
#[test]
fn a_maximal_page_of_maximal_records_fits_one_frame() {
    let worst = "\"".repeat(MAX_APPROVAL_API_FIELD_BYTES);
    let entries: Vec<ApprovalRecordView> = (1..=u64::try_from(MAX_APPROVAL_PAGE_ITEMS)
        .expect("small"))
        .map(|entry_id| {
            ApprovalRecordView::new(ApprovalRecordParts {
                entry_id,
                approval_key: ApprovalKey::new(&format!("{entry_id}{worst}")[..worst.len()])
                    .expect("key"),
                subject: ApprovalSubject::new(&worst).expect("subject"),
                decision: ApprovalDecision::Granted,
                decider: Decider::new(&worst).expect("decider"),
                decided_at: EpochMillis::from_millis(i64::MAX),
                revision: 1,
            })
            .expect("record")
        })
        .collect();
    let page = ApprovalListPage::new(
        entries,
        ApprovalContinuation::More(ApprovalCursor::new(u64::MAX >> 1)),
    )
    .expect("maximal page");
    let payload = encode_response(&ApprovalResponse::ApprovalList {
        request_id: RequestId::new("a".repeat(128)).expect("maximal request identifier"),
        page,
    });
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("a maximal page fits one frame");
    assert!(
        frame.len() < MAX_APPROVAL_CANONICAL_BYTES,
        "a maximal page framed to {} bytes",
        frame.len(),
    );
}
