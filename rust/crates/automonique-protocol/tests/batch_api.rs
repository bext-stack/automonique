// SPDX-License-Identifier: Elastic-2.0

//! The native Batch control API: bounded values, refusing decoders, and a
//! rolled-up batch state that cannot be fabricated.
//!
//! What this file proves is that the lane's *shape* holds — every body is exact,
//! every closed vocabulary fails shut, every bound is a bound rather than a
//! clamp, and the derived batch state on a detail read is checked against the
//! members beside it rather than believed. What it deliberately does not prove is
//! anything about a daemon or a database; `automonique-daemon`'s
//! `tests/batch_live.rs` owns that.

use automonique_protocol::batch_api::{
    AdvanceMember, BATCH_CONTROL_API_SCHEMA_V1, BATCH_CONTROL_PROTOCOL, BatchApiError,
    BatchContinuation, BatchCursor, BatchDetailResult, BatchListPage, BatchPageSize,
    BatchReceiptView, BatchRecordView, BatchRefusal, BatchRequest, BatchResponse, ListBatches,
    MAX_BATCH_CONTROL_CANONICAL_BYTES, MAX_BATCH_CONTROL_MEMBERS, MAX_BATCH_PAGE_ITEMS,
    MemberReceiptParts, MemberReceiptView, MemberView, OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES,
    RegisterBatch,
};
use automonique_protocol::batch_runner::{
    BatchError, BatchId, BatchLabel, BatchMemberKey, BatchState, ConcurrencyPolicy,
    MAX_BATCH_MEMBERS, MemberProgress, roll_up,
};
use automonique_protocol::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId, encode_frame,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::runs_api::RunState;
use automonique_protocol::wire::{JsonValue, Message};

fn request_id() -> RequestId {
    RequestId::new("batch-1").expect("request identifier")
}

fn identity(value: &str) -> BatchId {
    BatchId::new(value).expect("batch identity")
}

fn key(value: &str) -> BatchMemberKey {
    BatchMemberKey::new(value).expect("member key")
}

fn label(value: &str) -> BatchLabel {
    BatchLabel::new(value).expect("label")
}

fn keys(values: &[&str]) -> Vec<BatchMemberKey> {
    values.iter().map(|value| key(value)).collect()
}

fn registration(members: &[&str], concurrency: ConcurrencyPolicy) -> RegisterBatch {
    RegisterBatch::new(
        identity("nightly-eval"),
        Some(label("nightly")),
        concurrency,
        keys(members),
    )
    .expect("registration")
}

fn batch_row(entry_id: u64, batch_id: &str, concurrency: ConcurrencyPolicy) -> BatchRecordView {
    BatchRecordView::new(
        entry_id,
        identity(batch_id),
        Some(label("nightly")),
        concurrency,
        EpochMillis::from_millis(1_700_000_000_000),
        1,
    )
    .expect("batch row")
}

/// One member row, with the revision its progress implies.
///
/// Registration is the only writer of `unsubmitted` and it always writes
/// revision one, so a member at any other progress is at two or above.
fn member(value: &str, ordinal: u32, progress: MemberProgress) -> MemberView {
    let (sequence, revision) = match progress {
        MemberProgress::Unsubmitted => (0, 1),
        MemberProgress::Run(RunState::Ready) => (0, 2),
        _ => (u64::from(ordinal) + 1, 3),
    };
    MemberView::new(
        key(value),
        ordinal,
        progress,
        sequence,
        revision,
        EpochMillis::from_millis(1_700_000_001_000),
    )
    .expect("member row")
}

fn detail(members: Vec<MemberView>) -> BatchDetailResult {
    BatchDetailResult::new(
        batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
        members,
    )
    .expect("detail")
}

fn round_trip_request(request: &BatchRequest) {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    assert_eq!(
        &BatchRequest::from_canonical_bytes(&payload).expect("decode request"),
        request,
    );
}

fn round_trip_response(response: &BatchResponse) {
    let payload = response
        .to_message()
        .expect("encode response")
        .to_canonical_bytes();
    assert_eq!(
        &BatchResponse::from_canonical_bytes(&payload).expect("decode response"),
        response,
    );
}

/// Hand-roll one frame body under this protocol's envelope.
///
/// Everything that tests a body the encoder would never produce goes through
/// here, so a refusal is the decoder's own rather than a constructor's.
fn framed(kind: &str, body: JsonValue) -> Vec<u8> {
    Message::new(
        Envelope::new(
            ProtocolName::new(BATCH_CONTROL_PROTOCOL).expect("protocol name"),
            MajorVersion::FIRST,
            request_id(),
            MessageKind::new(kind).expect("kind"),
        ),
        body,
    )
    .to_canonical_bytes()
}

fn object(fields: &[(&str, JsonValue)]) -> JsonValue {
    JsonValue::Object(
        fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    )
}

fn text(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

fn sequential_body() -> JsonValue {
    object(&[
        ("kind", text("sequential")),
        ("max_in_flight", JsonValue::Null),
    ])
}

// ---------------------------------------------------------------------------
// The names, the bounds, and where they come from.
// ---------------------------------------------------------------------------

#[test]
fn the_protocol_names_are_pinned_by_literal_and_are_nobody_else_s() {
    assert_eq!(BATCH_CONTROL_PROTOCOL, "automonique.batch.control");
    assert_eq!(BATCH_CONTROL_API_SCHEMA_V1, "automonique.batch.control/v1");

    // The envelope grammar admits lowercase, digits and dots and nothing else,
    // so the name this lane declares is one the codec can actually carry. A
    // hyphenated spelling would be refused here rather than at a peer.
    ProtocolName::new(BATCH_CONTROL_PROTOCOL).expect("the declared name is a legal protocol name");
    assert!(
        ProtocolName::new("automonique.batch-control").is_err(),
        "the hyphenated spelling is not a name this envelope can carry",
    );

    // The document model's schema is a different string. One spelling for both
    // would let a client admit a control frame under a document's name.
    assert_ne!(
        BATCH_CONTROL_API_SCHEMA_V1,
        automonique_protocol::batch_runner::BATCH_SCHEMA_V1,
    );
    for other in [
        automonique_protocol::admin::ADMIN_PROTOCOL,
        automonique_protocol::runs_api::RUNS_PROTOCOL,
        automonique_protocol::automation_api::AUTOMATION_PROTOCOL,
        automonique_protocol::approval_api::APPROVAL_PROTOCOL,
    ] {
        assert_ne!(BATCH_CONTROL_PROTOCOL, other);
    }
}

#[test]
fn this_lane_carries_fewer_members_than_the_model_and_says_so() {
    // The divergence is deliberate and is the reason the ceiling exists: a
    // maximal registration of the model's 256 keys does not fit the 64 KiB frame
    // the local socket reads under.
    assert_eq!(MAX_BATCH_CONTROL_MEMBERS, 128);
    assert_eq!(MAX_BATCH_MEMBERS, 256);
    // Both sides are constants, so the ordering between them is a compile-time
    // fact rather than something to discover at run time.
    const _: () = assert!(
        MAX_BATCH_CONTROL_MEMBERS < MAX_BATCH_MEMBERS,
        "this lane must carry fewer members than the model represents"
    );

    let too_many: Vec<String> = (0..=MAX_BATCH_CONTROL_MEMBERS)
        .map(|index| format!("record-{index}"))
        .collect();
    assert_eq!(
        RegisterBatch::new(
            identity("nightly-eval"),
            None,
            ConcurrencyPolicy::Sequential,
            too_many.iter().map(|value| key(value)).collect(),
        )
        .expect_err("a membership above the lane ceiling"),
        BatchApiError::MembershipTooLarge {
            max_members: MAX_BATCH_CONTROL_MEMBERS,
            actual_members: MAX_BATCH_CONTROL_MEMBERS + 1,
        },
    );

    // The ceiling itself is admitted, so the refusal above is a bound and not an
    // off-by-one.
    let exactly: Vec<String> = (0..MAX_BATCH_CONTROL_MEMBERS)
        .map(|index| format!("record-{index}"))
        .collect();
    RegisterBatch::new(
        identity("nightly-eval"),
        None,
        ConcurrencyPolicy::Sequential,
        exactly.iter().map(|value| key(value)).collect(),
    )
    .expect("a maximal membership");
}

#[test]
fn a_maximal_registration_fits_one_frame_with_headroom() {
    // The relation between the ceilings is a compile-time assertion in
    // `batch_api`, so this build could not have linked if it stopped holding.
    // What is measured here is the consequence: a real maximal registration,
    // framed the way the socket frames it, fits the bound with room to spare.
    let worst = "\"".repeat(BatchMemberKey::MAX_BYTES);
    let members: Vec<BatchMemberKey> = (0..MAX_BATCH_CONTROL_MEMBERS)
        .map(|index| key(&format!("{index:03}{}", &worst[..worst.len() - 3])))
        .collect();
    let request = BatchRequest::RegisterBatch {
        request_id: RequestId::new("a".repeat(64)).expect("request identifier"),
        registration: RegisterBatch::new(
            identity(&"\"".repeat(BatchId::MAX_BYTES)),
            Some(label(&"\"".repeat(BatchLabel::MAX_BYTES))),
            ConcurrencyPolicy::bounded_parallel(256).expect("ceiling"),
            members,
        )
        .expect("maximal registration"),
    };
    let payload = request
        .to_message()
        .expect("encode maximal registration")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("a maximal registration fits one frame");
    assert!(
        frame.len() < MAX_BATCH_CONTROL_CANONICAL_BYTES,
        "a maximal registration framed to {} bytes",
        frame.len(),
    );
    // And it round-trips at that size, so the bound is not merely arithmetic.
    round_trip_request(&request);
}

#[test]
fn a_maximal_detail_fits_one_frame() {
    let worst = "\"".repeat(BatchMemberKey::MAX_BYTES);
    let members: Vec<MemberView> = (0..MAX_BATCH_CONTROL_MEMBERS)
        .map(|index| {
            member(
                &format!("{index:03}{}", &worst[..worst.len() - 3]),
                u32::try_from(index).expect("ordinal"),
                MemberProgress::Run(RunState::Completed),
            )
        })
        .collect();
    let response = BatchResponse::BatchDetail {
        request_id: RequestId::new("a".repeat(64)).expect("request identifier"),
        detail: BatchDetailResult::new(
            batch_row(
                u64::MAX >> 1,
                &"\"".repeat(BatchId::MAX_BYTES),
                ConcurrencyPolicy::Sequential,
            ),
            members,
        )
        .expect("maximal detail"),
    };
    let payload = response
        .to_message()
        .expect("encode maximal detail")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("a maximal detail fits one frame");
    assert!(
        frame.len() < MAX_BATCH_CONTROL_CANONICAL_BYTES,
        "a maximal detail framed to {} bytes",
        frame.len(),
    );
    round_trip_response(&response);
}

// ---------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------

#[test]
fn every_request_round_trips_through_its_own_codec() {
    for request in [
        BatchRequest::RegisterBatch {
            request_id: request_id(),
            registration: registration(
                &["record-1", "record-2"],
                ConcurrencyPolicy::bounded_parallel(4).expect("ceiling"),
            ),
        },
        BatchRequest::RegisterBatch {
            request_id: request_id(),
            registration: RegisterBatch::new(
                identity("nightly-eval"),
                None,
                ConcurrencyPolicy::Sequential,
                keys(&["record-1"]),
            )
            .expect("registration without a label"),
        },
        BatchRequest::AdvanceMember {
            request_id: request_id(),
            advance: AdvanceMember::new(
                identity("nightly-eval"),
                key("record-1"),
                2,
                MemberProgress::Run(RunState::Running),
                7,
            )
            .expect("advance"),
        },
        BatchRequest::AdvanceMember {
            request_id: request_id(),
            advance: AdvanceMember::new(
                identity("nightly-eval"),
                key("record-1"),
                1,
                MemberProgress::Run(RunState::Ready),
                0,
            )
            .expect("submission recorded"),
        },
        BatchRequest::ListBatches {
            request_id: request_id(),
            query: ListBatches::new(BatchCursor::new(4), BatchPageSize::MAX),
        },
        BatchRequest::BatchDetail {
            request_id: request_id(),
            batch_id: identity("nightly-eval"),
        },
    ] {
        round_trip_request(&request);
    }
}

#[test]
fn every_response_round_trips_through_its_own_codec() {
    for response in [
        BatchResponse::Registered {
            request_id: request_id(),
            receipt: BatchReceiptView::new(
                3,
                identity("nightly-eval"),
                2,
                1,
                EpochMillis::from_millis(1_700_000_000_000),
            )
            .expect("receipt"),
        },
        BatchResponse::MemberAdvanced {
            request_id: request_id(),
            receipt: MemberReceiptView::new(MemberReceiptParts {
                batch_id: identity("nightly-eval"),
                member_key: key("record-1"),
                ordinal: 0,
                progress: MemberProgress::Run(RunState::Completed),
                last_sequence: 9,
                revision: 4,
                updated_at: EpochMillis::from_millis(1_700_000_002_000),
            })
            .expect("receipt"),
        },
        BatchResponse::BatchList {
            request_id: request_id(),
            page: BatchListPage::new(
                vec![
                    batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
                    batch_row(
                        2,
                        "weekly-eval",
                        ConcurrencyPolicy::bounded_parallel(8).expect("ceiling"),
                    ),
                ],
                BatchContinuation::More(BatchCursor::new(2)),
            )
            .expect("page"),
        },
        BatchResponse::BatchList {
            request_id: request_id(),
            page: BatchListPage::new(Vec::new(), BatchContinuation::Complete).expect("empty page"),
        },
        BatchResponse::BatchDetail {
            request_id: request_id(),
            detail: detail(vec![
                member("record-1", 0, MemberProgress::Run(RunState::Completed)),
                member("record-2", 1, MemberProgress::Unsubmitted),
            ]),
        },
        BatchResponse::conflict(request_id(), 2, 5).expect("conflict"),
        BatchResponse::Refused {
            request_id: request_id(),
            refusal: BatchRefusal::UnknownMember,
        },
    ] {
        round_trip_response(&response);
    }
}

#[test]
fn a_batch_without_a_label_survives_the_round_trip_as_absent() {
    // `null` and the empty string are different answers, and the empty string is
    // not a label at all: an unlabelled batch is one the operator did not name.
    let row = BatchRecordView::new(
        1,
        identity("nightly-eval"),
        None,
        ConcurrencyPolicy::Sequential,
        EpochMillis::from_millis(1),
        1,
    )
    .expect("unlabelled row");
    let response = BatchResponse::BatchList {
        request_id: request_id(),
        page: BatchListPage::new(vec![row], BatchContinuation::Complete).expect("page"),
    };
    round_trip_response(&response);
    let payload = framed(
        "batch_list_result",
        object(&[
            (
                "batches",
                JsonValue::Array(vec![object(&[
                    ("batch_id", text("nightly-eval")),
                    ("concurrency", sequential_body()),
                    ("created_at_ms", JsonValue::Integer(1)),
                    ("entry_id", JsonValue::Integer(1)),
                    ("label", text("")),
                    ("revision", JsonValue::Integer(1)),
                ])]),
            ),
            ("more", JsonValue::Bool(false)),
            ("next_cursor", JsonValue::Null),
        ]),
    );
    assert!(
        matches!(
            BatchResponse::from_canonical_bytes(&payload).expect_err("an empty label"),
            BatchApiError::Field { field: "label", .. },
        ),
        "an empty label decoded as a label",
    );
}

// ---------------------------------------------------------------------------
// Field-set exactness.
// ---------------------------------------------------------------------------

#[test]
fn every_body_is_the_exact_field_set_its_kind_declares() {
    let register = [
        ("batch_id", text("nightly-eval")),
        ("concurrency", sequential_body()),
        ("label", JsonValue::Null),
        ("members", JsonValue::Array(vec![text("record-1")])),
    ];
    let advance = [
        ("batch_id", text("nightly-eval")),
        ("expected_revision", JsonValue::Integer(2)),
        ("last_sequence", JsonValue::Integer(7)),
        ("member_key", text("record-1")),
        ("state", text("running")),
    ];
    let list = [
        ("page_size", JsonValue::Integer(4)),
        ("since", JsonValue::Integer(0)),
    ];
    let read = [("batch_id", text("nightly-eval"))];

    for (kind, fields) in [
        ("register_batch", register.as_slice()),
        ("advance_member", advance.as_slice()),
        ("list_batches", list.as_slice()),
        ("batch_detail", read.as_slice()),
    ] {
        // Exact is accepted.
        BatchRequest::from_canonical_bytes(&framed(kind, object(fields)))
            .unwrap_or_else(|error| panic!("{kind} exact body: {error}"));

        // One more member is not.
        let mut widened = fields.to_vec();
        widened.push(("actor", text("ben")));
        assert_eq!(
            BatchRequest::from_canonical_bytes(&framed(kind, object(&widened)))
                .expect_err("a widened body"),
            BatchApiError::InvalidBody,
            "{kind} accepted a field it does not declare",
        );

        // One fewer is not either. Every declared field is required, including
        // the ones whose value may be `null`.
        for omitted in 0..fields.len() {
            let narrowed: Vec<(&str, JsonValue)> = fields
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, field)| field.clone())
                .collect();
            assert_eq!(
                BatchRequest::from_canonical_bytes(&framed(kind, object(&narrowed)))
                    .expect_err("a narrowed body"),
                BatchApiError::InvalidBody,
                "{kind} accepted a body missing {}",
                fields[omitted].0,
            );
        }
    }
}

#[test]
fn a_kind_this_protocol_does_not_define_is_refused_rather_than_guessed() {
    for kind in [
        "register",
        "advance",
        "list_runs",
        "record_approval",
        "status",
    ] {
        assert_eq!(
            BatchRequest::from_canonical_bytes(&framed(kind, object(&[])))
                .expect_err("an undefined kind"),
            BatchApiError::UnknownKind,
        );
    }
    for kind in ["batch_accepted", "batch_list", "approval_recorded"] {
        assert_eq!(
            BatchResponse::from_canonical_bytes(&framed(kind, object(&[])))
                .expect_err("an undefined kind"),
            BatchApiError::UnknownKind,
        );
    }
}

// ---------------------------------------------------------------------------
// Closed vocabularies fail shut.
// ---------------------------------------------------------------------------

#[test]
fn a_progress_word_this_build_does_not_define_is_refused() {
    for spelling in ["finished", "RUNNING", "", "unsubmitted "] {
        let payload = framed(
            "advance_member",
            object(&[
                ("batch_id", text("nightly-eval")),
                ("expected_revision", JsonValue::Integer(2)),
                ("last_sequence", JsonValue::Integer(7)),
                ("member_key", text("record-1")),
                ("state", text(spelling)),
            ]),
        );
        assert_eq!(
            BatchRequest::from_canonical_bytes(&payload).expect_err("an undefined progress"),
            BatchApiError::Codec(CodecError::UnknownEnumValue { field: "state" }),
            "{spelling:?} was admitted",
        );
    }

    // All seven defined words are admitted, so the refusals above are the
    // vocabulary and not an accident of the decoder.
    for progress in MemberProgress::ALL {
        let sequence = u64::from(!progress.has_not_started());
        let payload = framed(
            "advance_member",
            object(&[
                ("batch_id", text("nightly-eval")),
                ("expected_revision", JsonValue::Integer(2)),
                (
                    "last_sequence",
                    JsonValue::Integer(i64::try_from(sequence).expect("sequence")),
                ),
                ("member_key", text("record-1")),
                ("state", text(progress.as_str())),
            ]),
        );
        let BatchRequest::AdvanceMember { advance, .. } =
            BatchRequest::from_canonical_bytes(&payload).expect("a defined progress")
        else {
            panic!("a register frame decoded as an advance")
        };
        assert_eq!(advance.progress(), progress);
    }
}

#[test]
fn a_concurrency_kind_this_build_does_not_define_is_refused() {
    for kind in ["unbounded", "SEQUENTIAL", "parallel"] {
        let payload = framed(
            "register_batch",
            object(&[
                ("batch_id", text("nightly-eval")),
                (
                    "concurrency",
                    object(&[("kind", text(kind)), ("max_in_flight", JsonValue::Null)]),
                ),
                ("label", JsonValue::Null),
                ("members", JsonValue::Array(vec![text("record-1")])),
            ]),
        );
        assert_eq!(
            BatchRequest::from_canonical_bytes(&payload).expect_err("an undefined kind"),
            BatchApiError::Codec(CodecError::UnknownEnumValue { field: "kind" }),
        );
    }
}

#[test]
fn a_concurrency_kind_and_its_ceiling_imply_each_other() {
    for (kind, ceiling, label) in [
        ("sequential", JsonValue::Integer(4), "a sequential ceiling"),
        (
            "bounded_parallel",
            JsonValue::Null,
            "a bounded parallel without one",
        ),
    ] {
        let payload = framed(
            "register_batch",
            object(&[
                ("batch_id", text("nightly-eval")),
                (
                    "concurrency",
                    object(&[("kind", text(kind)), ("max_in_flight", ceiling)]),
                ),
                ("label", JsonValue::Null),
                ("members", JsonValue::Array(vec![text("record-1")])),
            ]),
        );
        assert_eq!(
            BatchRequest::from_canonical_bytes(&payload).expect_err(label),
            BatchApiError::InvalidBody,
            "{label} was admitted",
        );
    }

    // A ceiling that admits nothing, and one no batch could ever reach, are the
    // model's own refusals rather than restatements of them.
    for (ceiling, expected) in [
        (0, BatchError::ConcurrencyCeilingZero),
        (
            i64::try_from(MAX_BATCH_MEMBERS).expect("ceiling") + 1,
            BatchError::ConcurrencyCeilingUnreachable {
                max_members: MAX_BATCH_MEMBERS,
                requested: u32::try_from(MAX_BATCH_MEMBERS).expect("ceiling") + 1,
            },
        ),
    ] {
        let payload = framed(
            "register_batch",
            object(&[
                ("batch_id", text("nightly-eval")),
                (
                    "concurrency",
                    object(&[
                        ("kind", text("bounded_parallel")),
                        ("max_in_flight", JsonValue::Integer(ceiling)),
                    ]),
                ),
                ("label", JsonValue::Null),
                ("members", JsonValue::Array(vec![text("record-1")])),
            ]),
        );
        assert_eq!(
            BatchRequest::from_canonical_bytes(&payload).expect_err("an incoherent ceiling"),
            BatchApiError::Model(expected),
        );
    }
}

#[test]
fn a_refusal_word_this_build_does_not_define_is_refused() {
    for spelling in ["ledger_full", "unknown_approval", "UNKNOWN_BATCH", ""] {
        assert_eq!(
            BatchResponse::from_canonical_bytes(&framed(
                "refused",
                object(&[("refusal", text(spelling))]),
            ))
            .expect_err("an undefined refusal"),
            BatchApiError::Codec(CodecError::UnknownEnumValue { field: "refusal" }),
        );
    }
    // Every defined word round-trips, and the thirteen spellings are distinct.
    let mut spellings: Vec<&str> = BatchRefusal::ALL.iter().map(|r| r.as_str()).collect();
    spellings.sort_unstable();
    let unique = spellings.len();
    spellings.dedup();
    assert_eq!(spellings.len(), unique, "two refusals share a spelling");
    for refusal in BatchRefusal::ALL {
        assert_eq!(BatchRefusal::from_spelling(refusal.as_str()), Some(refusal));
        round_trip_response(&BatchResponse::Refused {
            request_id: request_id(),
            refusal,
        });
    }
}

// ---------------------------------------------------------------------------
// Registrations and advances a caller cannot make.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_or_repeated_membership_is_refused_rather_than_collapsed() {
    assert_eq!(
        RegisterBatch::new(
            identity("nightly-eval"),
            None,
            ConcurrencyPolicy::Sequential,
            Vec::new(),
        )
        .expect_err("an empty membership"),
        BatchApiError::Model(BatchError::EmptyBatch),
    );
    assert_eq!(
        RegisterBatch::new(
            identity("nightly-eval"),
            None,
            ConcurrencyPolicy::Sequential,
            keys(&["record-1", "record-2", "record-1"]),
        )
        .expect_err("a repeated member"),
        BatchApiError::Model(BatchError::DuplicateMember {
            key: key("record-1")
        }),
    );

    // And the decoder refuses both, so a hand-rolled frame cannot get past the
    // constructor by going round it.
    for members in [
        JsonValue::Array(Vec::new()),
        JsonValue::Array(vec![text("record-1"), text("record-1")]),
    ] {
        let payload = framed(
            "register_batch",
            object(&[
                ("batch_id", text("nightly-eval")),
                ("concurrency", sequential_body()),
                ("label", JsonValue::Null),
                ("members", members),
            ]),
        );
        assert!(
            matches!(
                BatchRequest::from_canonical_bytes(&payload).expect_err("an illegal membership"),
                BatchApiError::Model(_),
            ),
            "an illegal membership was admitted",
        );
    }
}

#[test]
fn the_declared_order_of_a_membership_is_kept_and_never_sorted() {
    // The order becomes the members' ordinals, because a sequential policy names
    // it. A registration that sorted would silently re-order the batch.
    let registration = registration(&["zulu", "alpha", "mike"], ConcurrencyPolicy::Sequential);
    assert_eq!(
        registration
            .members()
            .iter()
            .map(BatchMemberKey::as_str)
            .collect::<Vec<_>>(),
        vec!["zulu", "alpha", "mike"],
    );
    let request = BatchRequest::RegisterBatch {
        request_id: request_id(),
        registration,
    };
    round_trip_request(&request);
    let BatchRequest::RegisterBatch { registration, .. } = request else {
        unreachable!()
    };
    let payload = BatchRequest::RegisterBatch {
        request_id: request_id(),
        registration: registration.clone(),
    }
    .to_message()
    .expect("encode")
    .to_canonical_bytes();
    let BatchRequest::RegisterBatch {
        registration: decoded,
        ..
    } = BatchRequest::from_canonical_bytes(&payload).expect("decode")
    else {
        panic!("a register frame decoded as something else")
    };
    assert_eq!(decoded.members(), registration.members());
}

#[test]
fn an_advance_couples_its_sequence_to_its_progress() {
    // `unsubmitted` and `ready` mean zero spool events; everything else means at
    // least one. A property of the request alone, judged before any frame.
    for (progress, sequence) in [
        (MemberProgress::Unsubmitted, 1),
        (MemberProgress::Run(RunState::Ready), 7),
        (MemberProgress::Run(RunState::Running), 0),
        (MemberProgress::Run(RunState::Completed), 0),
    ] {
        assert_eq!(
            AdvanceMember::new(identity("b"), key("m"), 2, progress, sequence)
                .expect_err("an incoherent sequence"),
            BatchApiError::SequenceCoupling {
                progress,
                last_sequence: sequence,
            },
        );
    }
    // The coherent pairings are admitted.
    for (progress, sequence) in [
        (MemberProgress::Unsubmitted, 0),
        (MemberProgress::Run(RunState::Ready), 0),
        (MemberProgress::Run(RunState::Running), 1),
        (MemberProgress::Run(RunState::TimedOut), u64::MAX >> 1),
    ] {
        AdvanceMember::new(identity("b"), key("m"), 2, progress, sequence)
            .expect("a coherent report");
    }
}

#[test]
fn an_advance_that_expects_revision_zero_names_a_row_no_writer_produced() {
    assert_eq!(
        AdvanceMember::new(
            identity("b"),
            key("m"),
            0,
            MemberProgress::Run(RunState::Running),
            1,
        )
        .expect_err("revision zero"),
        BatchApiError::UnwrittenRevision,
    );
    let payload = framed(
        "advance_member",
        object(&[
            ("batch_id", text("nightly-eval")),
            ("expected_revision", JsonValue::Integer(0)),
            ("last_sequence", JsonValue::Integer(7)),
            ("member_key", text("record-1")),
            ("state", text("running")),
        ]),
    );
    assert_eq!(
        BatchRequest::from_canonical_bytes(&payload).expect_err("revision zero on the wire"),
        BatchApiError::UnwrittenRevision,
    );
}

#[test]
fn an_advance_receipt_cannot_describe_the_row_registration_wrote() {
    // Registration is the only writer of revision one and it always writes
    // `unsubmitted`, and the lattice has no edge back to `unsubmitted`.
    for (progress, revision) in [
        (MemberProgress::Run(RunState::Running), 1),
        (MemberProgress::Run(RunState::Running), 0),
        (MemberProgress::Unsubmitted, 2),
    ] {
        assert_eq!(
            MemberReceiptView::new(MemberReceiptParts {
                batch_id: identity("b"),
                member_key: key("m"),
                ordinal: 0,
                progress,
                last_sequence: u64::from(!progress.has_not_started()),
                revision,
                updated_at: EpochMillis::from_millis(1),
            })
            .expect_err("a receipt no advance produced"),
            BatchApiError::NotAnAdvance { progress, revision },
        );
    }
}

// ---------------------------------------------------------------------------
// The rolled-up state.
// ---------------------------------------------------------------------------

#[test]
fn the_detail_state_is_derived_from_its_members_and_never_supplied() {
    for (progresses, expected) in [
        (
            vec![MemberProgress::Unsubmitted, MemberProgress::Unsubmitted],
            BatchState::Pending,
        ),
        (
            vec![
                MemberProgress::Unsubmitted,
                MemberProgress::Run(RunState::Ready),
            ],
            BatchState::Pending,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Running),
                MemberProgress::Unsubmitted,
            ],
            BatchState::Running,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Unsubmitted,
            ],
            BatchState::Running,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Run(RunState::Completed),
            ],
            BatchState::Completed,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Run(RunState::Failed),
            ],
            BatchState::Failed,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Cancelled),
                MemberProgress::Run(RunState::TimedOut),
            ],
            BatchState::Failed,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Cancelled),
                MemberProgress::Run(RunState::Cancelled),
            ],
            BatchState::Cancelled,
        ),
        (
            vec![
                MemberProgress::Run(RunState::Completed),
                MemberProgress::Run(RunState::Cancelled),
            ],
            BatchState::Mixed,
        ),
    ] {
        let members: Vec<MemberView> = progresses
            .iter()
            .enumerate()
            .map(|(index, progress)| {
                member(
                    &format!("record-{index}"),
                    u32::try_from(index).expect("ordinal"),
                    *progress,
                )
            })
            .collect();
        let detail = detail(members);
        assert_eq!(
            detail.rolled_up_state(),
            expected,
            "{progresses:?} rolled up wrongly",
        );
        // The one authority: the answer is exactly what the batch model derives.
        assert_eq!(roll_up(&progresses), Some(expected));
        round_trip_response(&BatchResponse::BatchDetail {
            request_id: request_id(),
            detail,
        });
    }
}

#[test]
fn a_detail_body_that_contradicts_its_own_members_is_refused_not_believed() {
    // This is the trap that makes serving a derived state over a store that does
    // not persist one safe. The body below is a perfectly well-formed frame
    // claiming `completed` over one completed member and one that never started.
    let members = JsonValue::Array(vec![
        object(&[
            ("key", text("record-1")),
            ("last_sequence", JsonValue::Integer(4)),
            ("ordinal", JsonValue::Integer(0)),
            ("revision", JsonValue::Integer(3)),
            ("state", text("completed")),
            ("updated_at_ms", JsonValue::Integer(1)),
        ]),
        object(&[
            ("key", text("record-2")),
            ("last_sequence", JsonValue::Integer(0)),
            ("ordinal", JsonValue::Integer(1)),
            ("revision", JsonValue::Integer(1)),
            ("state", text("unsubmitted")),
            ("updated_at_ms", JsonValue::Integer(1)),
        ]),
    ]);
    let batch = object(&[
        ("batch_id", text("nightly-eval")),
        ("concurrency", sequential_body()),
        ("created_at_ms", JsonValue::Integer(1)),
        ("entry_id", JsonValue::Integer(1)),
        ("label", JsonValue::Null),
        ("revision", JsonValue::Integer(1)),
    ]);
    for claimed in ["completed", "pending", "failed", "cancelled", "mixed"] {
        let payload = framed(
            "batch_detail_result",
            object(&[
                ("batch", batch.clone()),
                ("members", members.clone()),
                ("state", text(claimed)),
            ]),
        );
        assert_eq!(
            BatchResponse::from_canonical_bytes(&payload).expect_err("a fabricated rollup"),
            BatchApiError::Model(BatchError::RollupContradictsMembers {
                carried: BatchState::from_spelling(claimed).expect("state"),
                derived: BatchState::Running,
            }),
            "a body claiming {claimed} was believed",
        );
    }

    // The truthful spelling is admitted, so the refusals above are the check and
    // not a decoder that refuses every detail body.
    let payload = framed(
        "batch_detail_result",
        object(&[
            ("batch", batch),
            ("members", members),
            ("state", text("running")),
        ]),
    );
    let BatchResponse::BatchDetail { detail, .. } =
        BatchResponse::from_canonical_bytes(&payload).expect("a truthful rollup")
    else {
        panic!("a detail frame decoded as something else")
    };
    assert_eq!(detail.rolled_up_state(), BatchState::Running);
}

#[test]
fn a_membership_that_is_not_the_ordinals_zero_to_n_is_refused() {
    for (ordinals, position) in [(vec![0, 2], 1), (vec![1, 0], 0), (vec![0, 0], 1)] {
        let members: Vec<MemberView> = ordinals
            .iter()
            .enumerate()
            .map(|(index, ordinal)| {
                member(
                    &format!("record-{index}"),
                    *ordinal,
                    MemberProgress::Unsubmitted,
                )
            })
            .collect();
        assert_eq!(
            BatchDetailResult::new(
                batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
                members,
            )
            .expect_err("a membership with a hole in it"),
            BatchApiError::MembersOutOfOrder { position },
            "{ordinals:?} was admitted",
        );
    }
}

#[test]
fn a_detail_with_no_member_is_refused_rather_than_rolled_up_to_completed() {
    // Vacuously, "every member ended" and "every member completed" are both true
    // of nothing, so an empty batch that answered `completed` would be a batch
    // that never ran reporting success.
    assert_eq!(
        BatchDetailResult::new(
            batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
            Vec::new(),
        )
        .expect_err("an empty membership"),
        BatchApiError::Model(BatchError::EmptyBatch),
    );
    assert_eq!(roll_up(&[]), None);
}

#[test]
fn a_detail_that_repeats_a_member_key_is_refused() {
    let repeated = JsonValue::Array(vec![
        object(&[
            ("key", text("record-1")),
            ("last_sequence", JsonValue::Integer(0)),
            ("ordinal", JsonValue::Integer(0)),
            ("revision", JsonValue::Integer(1)),
            ("state", text("unsubmitted")),
            ("updated_at_ms", JsonValue::Integer(1)),
        ]),
        object(&[
            ("key", text("record-1")),
            ("last_sequence", JsonValue::Integer(0)),
            ("ordinal", JsonValue::Integer(1)),
            ("revision", JsonValue::Integer(1)),
            ("state", text("unsubmitted")),
            ("updated_at_ms", JsonValue::Integer(1)),
        ]),
    ]);
    let payload = framed(
        "batch_detail_result",
        object(&[
            (
                "batch",
                object(&[
                    ("batch_id", text("nightly-eval")),
                    ("concurrency", sequential_body()),
                    ("created_at_ms", JsonValue::Integer(1)),
                    ("entry_id", JsonValue::Integer(1)),
                    ("label", JsonValue::Null),
                    ("revision", JsonValue::Integer(1)),
                ]),
            ),
            ("members", repeated),
            ("state", text("pending")),
        ]),
    );
    assert_eq!(
        BatchResponse::from_canonical_bytes(&payload).expect_err("a repeated member"),
        BatchApiError::Model(BatchError::DuplicateMember {
            key: key("record-1")
        }),
    );
}

// ---------------------------------------------------------------------------
// Paging.
// ---------------------------------------------------------------------------

#[test]
fn a_page_size_is_a_bound_and_never_a_clamp() {
    assert_eq!(
        BatchPageSize::new(0).expect_err("a page that admits nothing"),
        BatchApiError::PageSizeOutOfRange {
            max_items: MAX_BATCH_PAGE_ITEMS,
            requested: 0,
        },
    );
    assert_eq!(
        BatchPageSize::new(MAX_BATCH_PAGE_ITEMS + 1).expect_err("a page above the ceiling"),
        BatchApiError::PageSizeOutOfRange {
            max_items: MAX_BATCH_PAGE_ITEMS,
            requested: MAX_BATCH_PAGE_ITEMS + 1,
        },
    );
    assert_eq!(
        BatchPageSize::new(MAX_BATCH_PAGE_ITEMS)
            .expect("the ceiling itself")
            .get(),
        MAX_BATCH_PAGE_ITEMS,
    );
}

#[test]
fn a_page_is_refused_when_it_is_too_long_out_of_order_or_incoherent() {
    let rows: Vec<BatchRecordView> = (1..=MAX_BATCH_PAGE_ITEMS + 1)
        .map(|index| {
            batch_row(
                u64::try_from(index).expect("entry"),
                &format!("batch-{index}"),
                ConcurrencyPolicy::Sequential,
            )
        })
        .collect();
    assert_eq!(
        BatchListPage::new(rows.clone(), BatchContinuation::Complete)
            .expect_err("an over-long page"),
        BatchApiError::PageTooLarge {
            max_items: MAX_BATCH_PAGE_ITEMS,
            actual_items: MAX_BATCH_PAGE_ITEMS + 1,
        },
    );

    for entries in [
        vec![
            batch_row(2, "b", ConcurrencyPolicy::Sequential),
            batch_row(1, "a", ConcurrencyPolicy::Sequential),
        ],
        vec![
            batch_row(1, "a", ConcurrencyPolicy::Sequential),
            batch_row(1, "b", ConcurrencyPolicy::Sequential),
        ],
    ] {
        assert_eq!(
            BatchListPage::new(entries, BatchContinuation::Complete)
                .expect_err("an unordered page"),
            BatchApiError::PageOutOfOrder,
        );
    }

    assert_eq!(
        BatchListPage::new(
            vec![
                batch_row(1, "a", ConcurrencyPolicy::Sequential),
                batch_row(4, "b", ConcurrencyPolicy::Sequential),
            ],
            BatchContinuation::More(BatchCursor::new(2)),
        )
        .expect_err("a cursor that rewinds"),
        BatchApiError::ContinuationRewinds,
    );

    // A page longer than the query asked for is refused at the answering end,
    // because it would look well-formed and silently contradict the question.
    let query = ListBatches::new(BatchCursor::START, BatchPageSize::new(1).expect("size"));
    assert_eq!(
        BatchResponse::listing(
            request_id(),
            query,
            BatchListPage::new(
                vec![
                    batch_row(1, "a", ConcurrencyPolicy::Sequential),
                    batch_row(2, "b", ConcurrencyPolicy::Sequential),
                ],
                BatchContinuation::Complete,
            )
            .expect("page"),
        )
        .expect_err("a page above the requested size"),
        BatchApiError::PageAboveRequestedSize {
            requested: 1,
            actual_items: 2,
        },
    );
}

#[test]
fn a_continuation_marker_and_its_cursor_must_agree() {
    for (more, cursor) in [
        (JsonValue::Bool(true), JsonValue::Null),
        (JsonValue::Bool(false), JsonValue::Integer(3)),
    ] {
        let payload = framed(
            "batch_list_result",
            object(&[
                ("batches", JsonValue::Array(Vec::new())),
                ("more", more),
                ("next_cursor", cursor),
            ]),
        );
        assert_eq!(
            BatchResponse::from_canonical_bytes(&payload).expect_err("an incoherent continuation"),
            BatchApiError::ContinuationIncoherent,
        );
    }
}

// ---------------------------------------------------------------------------
// Outcomes and conflicts.
// ---------------------------------------------------------------------------

#[test]
fn every_answer_reports_the_outcome_the_plan_s_vocabulary_gives_it() {
    let receipt = BatchReceiptView::new(1, identity("b"), 1, 1, EpochMillis::from_millis(1))
        .expect("receipt");
    for (response, expected) in [
        (
            BatchResponse::Registered {
                request_id: request_id(),
                receipt: receipt.clone(),
            },
            ActionOutcome::Accepted,
        ),
        (
            BatchResponse::MemberAdvanced {
                request_id: request_id(),
                receipt: MemberReceiptView::new(MemberReceiptParts {
                    batch_id: identity("b"),
                    member_key: key("m"),
                    ordinal: 0,
                    progress: MemberProgress::Run(RunState::Ready),
                    last_sequence: 0,
                    revision: 2,
                    updated_at: EpochMillis::from_millis(1),
                })
                .expect("receipt"),
            },
            ActionOutcome::Accepted,
        ),
        (
            BatchResponse::BatchList {
                request_id: request_id(),
                page: BatchListPage::new(Vec::new(), BatchContinuation::Complete).expect("page"),
            },
            ActionOutcome::Completed,
        ),
        (
            BatchResponse::BatchDetail {
                request_id: request_id(),
                detail: detail(vec![member("record-1", 0, MemberProgress::Unsubmitted)]),
            },
            ActionOutcome::Completed,
        ),
        (
            BatchResponse::conflict(request_id(), 2, 5).expect("conflict"),
            ActionOutcome::Conflict,
        ),
        (
            BatchResponse::Refused {
                request_id: request_id(),
                refusal: BatchRefusal::RegistryFull,
            },
            ActionOutcome::Rejected,
        ),
    ] {
        assert_eq!(response.outcome(), expected);
        assert!(
            !OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES.contains(&expected),
            "this protocol produced an outcome it says it cannot",
        );
    }
    assert_eq!(
        OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES,
        [ActionOutcome::Unknown, ActionOutcome::ResyncRequired],
    );
}

#[test]
fn a_conflict_must_name_two_revisions_that_actually_disagree() {
    assert_eq!(
        BatchResponse::conflict(request_id(), 3, 3).expect_err("agreement"),
        BatchApiError::ConflictWithoutDisagreement,
    );
    for (expected, durable) in [(0, 3), (3, 0)] {
        assert_eq!(
            BatchResponse::conflict(request_id(), expected, durable).expect_err("revision zero"),
            BatchApiError::UnwrittenRevision,
        );
    }
    // And the decoder re-derives both, so a hand-rolled conflict cannot claim
    // agreement either.
    let payload = framed(
        "revision_conflict",
        object(&[
            ("durable_revision", JsonValue::Integer(3)),
            ("expected_revision", JsonValue::Integer(3)),
        ]),
    );
    assert_eq!(
        BatchResponse::from_canonical_bytes(&payload).expect_err("agreement on the wire"),
        BatchApiError::ConflictWithoutDisagreement,
    );
}

#[test]
fn a_mutation_is_distinguishable_from_a_read() {
    assert!(
        BatchRequest::RegisterBatch {
            request_id: request_id(),
            registration: registration(&["record-1"], ConcurrencyPolicy::Sequential),
        }
        .is_mutation()
    );
    assert!(
        BatchRequest::AdvanceMember {
            request_id: request_id(),
            advance: AdvanceMember::new(
                identity("b"),
                key("m"),
                1,
                MemberProgress::Run(RunState::Ready),
                0,
            )
            .expect("advance"),
        }
        .is_mutation()
    );
    assert!(
        !BatchRequest::ListBatches {
            request_id: request_id(),
            query: ListBatches::new(BatchCursor::START, BatchPageSize::MAX),
        }
        .is_mutation()
    );
    assert!(
        !BatchRequest::BatchDetail {
            request_id: request_id(),
            batch_id: identity("b"),
        }
        .is_mutation()
    );
}

#[test]
fn a_row_identity_or_revision_of_zero_names_a_row_nothing_wrote() {
    assert_eq!(
        BatchReceiptView::new(0, identity("b"), 1, 1, EpochMillis::from_millis(1))
            .expect_err("entry zero"),
        BatchApiError::UnwrittenRow { field: "entry_id" },
    );
    assert_eq!(
        BatchReceiptView::new(1, identity("b"), 1, 0, EpochMillis::from_millis(1))
            .expect_err("revision zero"),
        BatchApiError::UnwrittenRevision,
    );
    assert_eq!(
        BatchReceiptView::new(1, identity("b"), 0, 1, EpochMillis::from_millis(1))
            .expect_err("a batch that wrote no member"),
        BatchApiError::Model(BatchError::EmptyBatch),
    );
    assert_eq!(
        BatchReceiptView::new(1, identity("b"), 1, 1, EpochMillis::from_millis(-1))
            .expect_err("before the epoch"),
        BatchApiError::TimeBeforeEpoch {
            field: "created_at_ms",
        },
    );
    assert_eq!(
        BatchRecordView::new(
            0,
            identity("b"),
            None,
            ConcurrencyPolicy::Sequential,
            EpochMillis::from_millis(1),
            1,
        )
        .expect_err("entry zero"),
        BatchApiError::UnwrittenRow { field: "entry_id" },
    );
}

#[test]
fn every_refusal_category_names_this_lane_and_not_the_document_model() {
    // A metric label has to say which lane refused. The transport's own refusals
    // carry this lane's prefix; a refusal that is a property of the *batch*
    // keeps the model's, which is how a reader tells "the frame was wrong" from
    // "the batch was wrong".
    for error in [
        BatchApiError::UnknownKind,
        BatchApiError::InvalidBody,
        BatchApiError::MembershipTooLarge {
            max_members: 1,
            actual_members: 2,
        },
        BatchApiError::UnwrittenRevision,
        BatchApiError::MembersOutOfOrder { position: 0 },
        BatchApiError::ConflictWithoutDisagreement,
        BatchApiError::NotAnAdvance {
            progress: MemberProgress::Unsubmitted,
            revision: 1,
        },
    ] {
        assert!(
            error.category().starts_with("batch_control_"),
            "{} is not this lane's spelling",
            error.category(),
        );
    }
    assert_eq!(
        BatchApiError::Model(BatchError::EmptyBatch).category(),
        "batch_empty",
    );
    assert_eq!(
        BatchApiError::Codec(CodecError::UnknownProtocol).category(),
        "unknown_protocol",
    );
}
