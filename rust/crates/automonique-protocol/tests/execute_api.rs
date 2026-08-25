// SPDX-License-Identifier: Elastic-2.0

//! The Execute lane's wire surface, including its second version.
//!
//! Two things are proved here that a round-trip alone would not.
//!
//! **Version one's bytes did not change.** The fixtures below are written out
//! as literals rather than derived from the encoder, so a change to how
//! `execute_run` or `execute_accepted` is written fails here instead of
//! silently making this build unable to talk to a version-one peer.
//!
//! **A kind and its version must agree.** Range admission alone would let a
//! peer write `cancel_run` at version one and have it accepted, which would
//! make the version a decoration. Every kind is asserted at its own version and
//! refused at the other.

use automonique_protocol::codec::{MajorVersion, RequestId};
use automonique_protocol::execute_api::{
    ApprovalContextField, CancelRequestRef, CancelRunOutcome, EXECUTE_CANCEL_VERSION,
    EXECUTE_PROTOCOL, ExecuteApiError, ExecuteRefusal, ExecuteRequest, ExecuteResponse,
    MAX_CANCEL_REQUEST_REF_BYTES,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::tools::RunId;

fn request_id(value: &str) -> RequestId {
    RequestId::new(value).expect("request identifier")
}

fn run_id(value: &str) -> RunId {
    RunId::new(value).expect("run identifier")
}

fn request_ref(value: &str) -> CancelRequestRef {
    CancelRequestRef::new(value).expect("cancellation reference")
}

fn encoded(request: &ExecuteRequest) -> String {
    String::from_utf8(request.to_message().expect("encode").to_canonical_bytes()).expect("utf-8")
}

fn encoded_response(response: &ExecuteResponse) -> String {
    String::from_utf8(response.to_message().expect("encode").to_canonical_bytes()).expect("utf-8")
}

/// Re-encode one message at a different declared version.
///
/// A textual substitution on the canonical bytes, so the test builds a frame
/// this crate would never write — which is exactly the peer it has to refuse.
fn at_version(bytes: &str, from: u32, to: u32) -> Vec<u8> {
    bytes
        .replace(&format!("\"version\":{from}"), &format!("\"version\":{to}"))
        .into_bytes()
}

// ---------------------------------------------------------------------------
// Version one, unchanged
// ---------------------------------------------------------------------------

#[test]
fn execute_run_is_still_written_at_version_one_with_these_exact_bytes() {
    let request = ExecuteRequest::ExecuteRun {
        request_id: request_id("r-1"),
        run_id: run_id("run-alpha"),
    };
    assert_eq!(
        encoded(&request),
        r#"{"body":{"run_id":"run-alpha"},"kind":"execute_run","protocol":"automonique.execute","request_id":"r-1","version":1}"#
    );
    assert_eq!(request.version(), MajorVersion::FIRST);
    assert_eq!(
        ExecuteRequest::from_canonical_bytes(encoded(&request).as_bytes()).expect("round trip"),
        request
    );
}

#[test]
fn execute_accepted_is_still_written_at_version_one_with_these_exact_bytes() {
    let response =
        ExecuteResponse::accepted(request_id("r-1"), run_id("run-alpha"), 7).expect("accepted");
    assert_eq!(
        encoded_response(&response),
        r#"{"body":{"run_id":"run-alpha","submission_id":7},"kind":"execute_accepted","protocol":"automonique.execute","request_id":"r-1","version":1}"#
    );
    assert_eq!(
        ExecuteResponse::from_canonical_bytes(encoded_response(&response).as_bytes())
            .expect("round trip"),
        response
    );
}

#[test]
fn a_refusal_is_written_at_version_one_so_a_version_one_peer_can_read_it() {
    let response = ExecuteResponse::Refused {
        request_id: request_id("r-1"),
        refusal: ExecuteRefusal::NoLiveAttempt,
    };
    assert_eq!(
        encoded_response(&response),
        r#"{"body":{"refusal":"no_live_attempt"},"kind":"refused","protocol":"automonique.execute","request_id":"r-1","version":1}"#
    );
    assert_eq!(
        ExecuteResponse::from_canonical_bytes(encoded_response(&response).as_bytes())
            .expect("round trip"),
        response
    );
}

// ---------------------------------------------------------------------------
// Version two
// ---------------------------------------------------------------------------

#[test]
fn the_lane_admits_one_through_two_and_writes_cancellation_at_two() {
    assert_eq!(EXECUTE_CANCEL_VERSION.get(), 2);
    assert_eq!(EXECUTE_PROTOCOL, "automonique.execute");

    let request = ExecuteRequest::CancelRun {
        request_id: request_id("r-1"),
        run_id: run_id("run-alpha"),
        request_ref: request_ref("tg:1:2"),
        observed_sequence: 5,
    };
    assert_eq!(request.version(), EXECUTE_CANCEL_VERSION);
    assert_eq!(
        encoded(&request),
        r#"{"body":{"observed_sequence":5,"request_ref":"tg:1:2","run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#
    );
    assert_eq!(
        ExecuteRequest::from_canonical_bytes(encoded(&request).as_bytes()).expect("round trip"),
        request
    );
    assert_eq!(request.run_id().as_str(), "run-alpha");
    assert_eq!(request.request_id().as_str(), "r-1");
}

#[test]
fn a_cancellation_result_round_trips_every_outcome() {
    for outcome in CancelRunOutcome::ALL {
        let response = ExecuteResponse::Cancelled {
            request_id: request_id("r-1"),
            run_id: run_id("run-alpha"),
            outcome,
        };
        let bytes = encoded_response(&response);
        assert!(bytes.contains("\"kind\":\"cancel_result\""), "{bytes}");
        assert!(bytes.contains("\"version\":2"), "{bytes}");
        assert_eq!(
            ExecuteResponse::from_canonical_bytes(bytes.as_bytes()).expect("round trip"),
            response
        );
    }
}

#[test]
fn a_delivered_cancellation_is_accepted_and_a_conflicting_one_is_rejected() {
    // The outcome axis is what a journal reads, and a conflict delivered
    // nothing — reporting it as accepted would record a cancellation that did
    // not happen.
    for (outcome, expected) in [
        (CancelRunOutcome::Delivered, ActionOutcome::Accepted),
        (CancelRunOutcome::AlreadyDelivered, ActionOutcome::Accepted),
        (CancelRunOutcome::Conflict, ActionOutcome::Rejected),
    ] {
        let response = ExecuteResponse::Cancelled {
            request_id: request_id("r-1"),
            run_id: run_id("run-alpha"),
            outcome,
        };
        assert_eq!(response.outcome(), expected, "{outcome}");
        assert_eq!(outcome.is_recorded(), expected == ActionOutcome::Accepted);
    }
}

// ---------------------------------------------------------------------------
// A kind and its version must agree
// ---------------------------------------------------------------------------

#[test]
fn a_cancel_written_at_version_one_is_refused_rather_than_admitted() {
    let request = ExecuteRequest::CancelRun {
        request_id: request_id("r-1"),
        run_id: run_id("run-alpha"),
        request_ref: request_ref("ref-a"),
        observed_sequence: 0,
    };
    let downgraded = at_version(&encoded(&request), 2, 1);
    let refusal =
        ExecuteRequest::from_canonical_bytes(&downgraded).expect_err("a downgraded cancel");
    assert_eq!(
        refusal,
        ExecuteApiError::KindVersion {
            kind: "cancel_run",
            expected: 2,
            offered: 1,
        }
    );
    assert_eq!(refusal.category(), "execute_kind_version");
}

#[test]
fn a_start_written_at_version_two_is_refused_rather_than_admitted() {
    let request = ExecuteRequest::ExecuteRun {
        request_id: request_id("r-1"),
        run_id: run_id("run-alpha"),
    };
    let upgraded = at_version(&encoded(&request), 1, 2);
    let refusal = ExecuteRequest::from_canonical_bytes(&upgraded).expect_err("an upgraded start");
    assert_eq!(
        refusal,
        ExecuteApiError::KindVersion {
            kind: "execute_run",
            expected: 1,
            offered: 2,
        }
    );
}

#[test]
fn a_version_outside_the_range_is_refused_by_the_codec_not_by_the_kind() {
    let request = ExecuteRequest::CancelRun {
        request_id: request_id("r-1"),
        run_id: run_id("run-alpha"),
        request_ref: request_ref("ref-a"),
        observed_sequence: 0,
    };
    let beyond = at_version(&encoded(&request), 2, 3);
    let refusal = ExecuteRequest::from_canonical_bytes(&beyond).expect_err("a version-three peer");
    // A different refusal from the one above, and deliberately: "this build
    // does not speak that version" and "that kind does not belong to that
    // version" are different facts about a peer.
    assert_ne!(refusal.category(), "execute_kind_version");
    assert!(
        refusal.to_string().contains('3'),
        "the refusal must name the version offered: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Bodies and fields
// ---------------------------------------------------------------------------

#[test]
fn a_cancel_body_must_carry_exactly_its_three_fields() {
    let complete = r#"{"body":{"observed_sequence":0,"request_ref":"ref-a","run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#;
    assert!(ExecuteRequest::from_canonical_bytes(complete.as_bytes()).is_ok());

    for incomplete in [
        // Missing the reference.
        r#"{"body":{"observed_sequence":0,"run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#,
        // Missing the sequence: absent is not zero, because a caller that
        // omitted it made no claim and one that sent zero made one.
        r#"{"body":{"request_ref":"ref-a","run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#,
        // One field too many.
        r#"{"body":{"extra":1,"observed_sequence":0,"request_ref":"ref-a","run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#,
        // A negative sequence is not a sequence.
        r#"{"body":{"observed_sequence":-1,"request_ref":"ref-a","run_id":"run-alpha"},"kind":"cancel_run","protocol":"automonique.execute","request_id":"r-1","version":2}"#,
    ] {
        assert_eq!(
            ExecuteRequest::from_canonical_bytes(incomplete.as_bytes())
                .expect_err("an inexact body")
                .category(),
            "execute_invalid_body",
            "{incomplete}"
        );
    }
}

#[test]
fn a_cancellation_reference_is_bounded_non_empty_and_control_free() {
    assert!(CancelRequestRef::new("").is_err());
    assert!(CancelRequestRef::new("ref\u{7}bell").is_err());
    assert!(CancelRequestRef::new("x".repeat(MAX_CANCEL_REQUEST_REF_BYTES + 1)).is_err());

    // The boundary is admitted, so the ceiling is a ceiling and not an
    // off-by-one, and the shape the Telegram bridge mints is legal.
    let boundary = "x".repeat(MAX_CANCEL_REQUEST_REF_BYTES);
    assert_eq!(request_ref(&boundary).as_str(), boundary);
    assert_eq!(request_ref("tg:-1001:42").to_string(), "tg:-1001:42");

    // Well inside the durable ledger's own 256-byte bound, so a reference this
    // protocol admits is one that ledger stores.
    const { assert!(MAX_CANCEL_REQUEST_REF_BYTES <= 256) };
}

// ---------------------------------------------------------------------------
// The refusal vocabulary
// ---------------------------------------------------------------------------

#[test]
fn every_refusal_round_trips_its_exact_spelling_and_none_is_shared() {
    assert_eq!(ExecuteRefusal::ALL.len(), 25);
    let mut spellings: Vec<&str> = ExecuteRefusal::ALL
        .into_iter()
        .map(ExecuteRefusal::as_str)
        .collect();
    for refusal in ExecuteRefusal::ALL {
        assert_eq!(
            ExecuteRefusal::from_spelling(refusal.as_str()),
            Some(refusal)
        );
        assert_eq!(refusal.to_string(), refusal.as_str());
    }
    let count = spellings.len();
    spellings.sort_unstable();
    spellings.dedup();
    assert_eq!(spellings.len(), count, "two refusals share a spelling");
}

#[test]
fn a_context_drift_refusal_names_the_field_it_drifted_on() {
    // The drifted field travels on the wire rather than only in a log, because
    // "your approval no longer applies" and "your approval no longer applies
    // because the program changed" are different facts to whoever decides
    // whether to approve again.
    assert_eq!(ApprovalContextField::ALL.len(), 5);
    for field in ApprovalContextField::ALL {
        let refusal = ExecuteRefusal::ApprovalContextDrift { field };
        assert_eq!(refusal.as_str(), field.drift_spelling());
        assert_eq!(
            ExecuteRefusal::from_spelling(refusal.as_str()),
            Some(refusal)
        );
        assert!(
            refusal.as_str().ends_with(field.as_str()),
            "the spelling must name the field"
        );
        assert!(!refusal.is_host_wide(), "drift is about this launch");
    }
    // A bare stem is not a spelling: every drift refusal names a field.
    assert_eq!(
        ExecuteRefusal::from_spelling("approval_context_drift"),
        None
    );
}

#[test]
fn the_approval_refusals_are_about_this_launch_and_not_about_the_host() {
    // Every one of them is answered by a decision or a re-proposal, so a
    // caller that retries with a different run is not making any of them
    // truthful by accident — except that none of them is host-wide, which is
    // what `is_host_wide` exists to say.
    for refusal in [
        ExecuteRefusal::ApprovalForbidden,
        ExecuteRefusal::ApprovalRequired,
        ExecuteRefusal::ApprovalDenied,
        ExecuteRefusal::ApprovalUnreachable,
    ] {
        assert!(!refusal.is_host_wide());
    }
    assert_eq!(
        ExecuteRefusal::ApprovalUnreachable.as_str(),
        "approval_unreachable"
    );
    assert_eq!(ExecuteRefusal::ApprovalDenied.as_str(), "approval_denied");
    assert_eq!(
        ExecuteRefusal::ApprovalRequired.as_str(),
        "approval_required"
    );
    assert_eq!(
        ExecuteRefusal::ApprovalForbidden.as_str(),
        "approval_forbidden"
    );
}

#[test]
fn the_two_cancellation_refusals_are_about_the_run_not_about_the_host() {
    // A host-wide refusal is not made truthful by asking again with a different
    // run, and both of these are about the run that was named.
    assert!(!ExecuteRefusal::NoLiveAttempt.is_host_wide());
    assert!(!ExecuteRefusal::CancelNotDelivered.is_host_wide());
    assert_eq!(ExecuteRefusal::NoLiveAttempt.as_str(), "no_live_attempt");
    assert_eq!(
        ExecuteRefusal::CancelNotDelivered.as_str(),
        "cancel_not_delivered"
    );
}

#[test]
fn an_unanswering_source_route_is_its_own_refusal_about_the_run() {
    // A successor that cannot reach the generation still hosting a run's
    // attempt says so, in its own word: neither "already executing" (it does
    // not know) nor "no live attempt" (it does not know that either). It is
    // about the named run, so a different run is not refused by it.
    assert!(!ExecuteRefusal::SourceRouteUnavailable.is_host_wide());
    assert_eq!(
        ExecuteRefusal::SourceRouteUnavailable.as_str(),
        "source_route_unavailable"
    );
    assert_eq!(
        ExecuteRefusal::from_spelling("source_route_unavailable"),
        Some(ExecuteRefusal::SourceRouteUnavailable)
    );
}

#[test]
fn an_unknown_refusal_or_outcome_spelling_fails_closed() {
    for unknown in ["", "cancelled", "NO_LIVE_ATTEMPT", "no-live-attempt"] {
        assert_eq!(ExecuteRefusal::from_spelling(unknown), None);
    }
    for unknown in ["", "sent", "DELIVERED", "already-delivered"] {
        assert_eq!(CancelRunOutcome::from_spelling(unknown), None);
    }

    // On the wire the same rule holds: an unknown spelling is refused, never
    // decoded to a default.
    let forged = r#"{"body":{"outcome":"probably","run_id":"run-alpha"},"kind":"cancel_result","protocol":"automonique.execute","request_id":"r-1","version":2}"#;
    assert!(ExecuteResponse::from_canonical_bytes(forged.as_bytes()).is_err());
}

#[test]
fn every_cancellation_outcome_round_trips_its_exact_spelling() {
    assert_eq!(CancelRunOutcome::ALL.len(), 3);
    for outcome in CancelRunOutcome::ALL {
        assert_eq!(
            CancelRunOutcome::from_spelling(outcome.as_str()),
            Some(outcome)
        );
        assert_eq!(outcome.to_string(), outcome.as_str());
    }
    assert_eq!(CancelRunOutcome::Delivered.as_str(), "delivered");
    assert_eq!(
        CancelRunOutcome::AlreadyDelivered.as_str(),
        "already_delivered"
    );
    assert_eq!(CancelRunOutcome::Conflict.as_str(), "conflict");
}

#[test]
fn an_unknown_kind_is_refused_at_either_version() {
    for version in [1, 2] {
        let payload = format!(
            r#"{{"body":{{"run_id":"run-alpha"}},"kind":"stop_run","protocol":"automonique.execute","request_id":"r-1","version":{version}}}"#
        );
        assert_eq!(
            ExecuteRequest::from_canonical_bytes(payload.as_bytes())
                .expect_err("an unknown kind")
                .category(),
            "execute_unknown_kind"
        );
    }
}
