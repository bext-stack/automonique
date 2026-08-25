// SPDX-License-Identifier: Elastic-2.0

//! The Automation control surface.
//!
//! The first module pins the enablement vocabulary against both authorities:
//! [`automonique_protocol::automation`], which this crate can import, and
//! `automonique_store::automation_store`, which it cannot. The rest exercise
//! framing, the cause coupling, the page invariants, the outcome vocabulary and
//! the bounds.

use std::fs;
use std::path::PathBuf;

use automonique_protocol::automation::{
    AutomationActor, AutomationEnablement, CanonicalSchedule, DstPolicy, EnablementState,
};
use automonique_protocol::automation_api::{
    AUTOMATION_API_SCHEMA_V1, AUTOMATION_PROTOCOL, AutomationApiError, AutomationContinuation,
    AutomationCursor, AutomationId, AutomationListPage, AutomationOccurrenceKey,
    AutomationPageSize, AutomationPrompt, AutomationReceiptView, AutomationRecordParts,
    AutomationRecordView, AutomationRefusal, AutomationRequest, AutomationResponse,
    AutomationSchedule, AutomationScope, AutomationStateFilter, ENABLEMENT_STATES, ListAutomations,
    MAX_AUTOMATION_API_FIELD_BYTES, MAX_AUTOMATION_CANONICAL_BYTES, MAX_AUTOMATION_PAGE_ITEMS,
    MAX_AUTOMATION_PROMPT_BYTES, MAX_AUTOMATION_SCOPE_BYTES, MAX_OCCURRENCE_KEY_BYTES,
    MAX_SCHEDULED_AUTOMATION_ID_BYTES, OCCURRENCE_KEY_PREFIX,
    OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES, PauseReason, RegisterAutomation, SetEnablement,
    decode_enablement, permits_transition, requires_cause,
};
use automonique_protocol::codec::{CodecError, MajorVersion, RequestId, encode_frame};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::wire::{JsonValue, Message};

fn request_id() -> RequestId {
    RequestId::new("automation-1").expect("valid request id")
}

fn id(value: &str) -> AutomationId {
    AutomationId::new(value).expect("valid automation identity")
}

fn who(value: &str) -> AutomationActor {
    AutomationActor::new(value).expect("valid actor")
}

fn why(value: &str) -> PauseReason {
    PauseReason::new(value).expect("valid cause")
}

fn every(interval_ms: i64) -> AutomationSchedule {
    AutomationSchedule::every(interval_ms).expect("valid interval")
}

fn scope(value: &str) -> AutomationScope {
    AutomationScope::new(value).expect("valid scope")
}

fn prompt(value: &str) -> AutomationPrompt {
    AutomationPrompt::new(value).expect("valid prompt")
}

/// A registration carrying one representative job.
fn registration(automation: &str) -> RegisterAutomation {
    RegisterAutomation::new(
        id(automation),
        who("ben"),
        every(60_000),
        scope("workspace:reports"),
        prompt("summarize the night"),
    )
    .expect("a scheduled registration")
}

/// One record at whatever coordinates a test needs, with no job: the shape of
/// a row registered before schedules existed.
fn record(
    entry_id: u64,
    automation: &str,
    revision: u64,
    enablement: EnablementState,
    actor: &str,
    cause: Option<&str>,
) -> AutomationRecordView {
    AutomationRecordView::new(AutomationRecordParts {
        entry_id,
        automation_id: id(automation),
        revision,
        enablement,
        actor: who(actor),
        cause: cause.map(why),
        created_at: EpochMillis::from_millis(1_700_000_000_000),
        updated_at: EpochMillis::from_millis(1_700_000_001_000),
        schedule: None,
        scope: None,
        next_fire_at: None,
        last_fired_at: None,
    })
    .expect("coherent record")
}

/// One scheduled record: enabled, at revision one, due once and fired never.
fn scheduled(entry_id: u64, automation: &str) -> AutomationRecordView {
    AutomationRecordView::new(AutomationRecordParts {
        entry_id,
        automation_id: id(automation),
        revision: 1,
        enablement: EnablementState::Enabled,
        actor: who("ben"),
        cause: None,
        created_at: EpochMillis::from_millis(1_700_000_000_000),
        updated_at: EpochMillis::from_millis(1_700_000_000_000),
        schedule: Some(every(60_000)),
        scope: Some(scope("workspace:reports")),
        next_fire_at: Some(EpochMillis::from_millis(1_700_000_060_000)),
        last_fired_at: None,
    })
    .expect("coherent scheduled record")
}

/// A freshly registered automation: enabled, revision one, no cause.
fn enabled(entry_id: u64, automation: &str) -> AutomationRecordView {
    record(
        entry_id,
        automation,
        1,
        EnablementState::Enabled,
        "operator",
        None,
    )
}

fn listing(page_size: usize) -> ListAutomations {
    ListAutomations::new(
        AutomationStateFilter::any(),
        AutomationCursor::START,
        AutomationPageSize::new(page_size).expect("valid page size"),
    )
}

/// The workspace source of a sibling crate this dependency-free crate cannot
/// import.
fn sibling_source(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is a workspace sibling: {error}", path.display()))
}

/// The `Variant => "spelling"` arms that follow `anchor` in a source text.
fn match_arms(text: &str, anchor: &str) -> Vec<(String, String)> {
    let start = text
        .find(anchor)
        .unwrap_or_else(|| panic!("{anchor} is declared in the sibling source"));
    let mut arms = Vec::new();
    for line in text[start..].lines().skip(1) {
        let trimmed = line.trim();
        if trimmed == "}" {
            break;
        }
        let Some((left, right)) = trimmed.split_once(" => ") else {
            continue;
        };
        let Some(variant) = left.rsplit("::").next() else {
            continue;
        };
        let spelling = right
            .trim_end_matches(',')
            .trim_matches('"')
            .trim_end_matches("\".to_owned()");
        arms.push((variant.trim().to_owned(), spelling.to_owned()));
    }
    assert!(!arms.is_empty(), "no arms were read after {anchor}");
    arms
}

/// The enablement vocabulary, against both crates that own a copy of it.
mod vocabulary {
    use super::*;

    #[test]
    fn the_wire_reuses_the_automation_model_s_states_rather_than_re_spelling_them() {
        // Not "these two arrays are equal" — the same array. A second spelling
        // table here is exactly what this module exists not to have.
        assert_eq!(ENABLEMENT_STATES, EnablementState::ALL);
        assert_eq!(ENABLEMENT_STATES.len(), 3);
        assert_eq!(ENABLEMENT_STATES[0].as_str(), "enabled");
        assert_eq!(ENABLEMENT_STATES[1].as_str(), "paused");
        assert_eq!(ENABLEMENT_STATES[2].as_str(), "archived");
    }

    #[test]
    fn the_enablement_spellings_are_pinned_against_the_store_crate() {
        // `automonique_store::automation_store::EnablementState` is the durable
        // authority: those three words are the stored column text and a
        // database CHECK constraint. This crate cannot import it, so the pin is
        // a read of the sibling source, and a rename on either side fails here
        // rather than silently splitting the wire from the table.
        let store = sibling_source("automonique-store/src/automation_store.rs");
        let declared: Vec<String> = match_arms(&store, "impl EnablementState {")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        let carried: Vec<String> = ENABLEMENT_STATES
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect();
        assert_eq!(
            declared, carried,
            "automonique_store::automation_store spells its states differently"
        );

        let variants: Vec<String> = match_arms(&store, "impl EnablementState {")
            .into_iter()
            .map(|(variant, _)| variant)
            .collect();
        assert_eq!(variants, vec!["Enabled", "Paused", "Archived"]);
    }

    #[test]
    fn the_stored_check_constraint_admits_exactly_the_carried_words() {
        // The vocabulary is not only Rust: the table refuses anything else in a
        // CHECK. A word this protocol could encode that the CHECK rejects would
        // be a request the store refuses for a reason no client could read.
        let store = sibling_source("automonique-store/src/automation_store.rs");
        for state in ENABLEMENT_STATES {
            assert!(
                store.contains(&format!("'{}'", state.as_str())),
                "{} is not a literal in the automations schema",
                state.as_str(),
            );
        }
    }

    #[test]
    fn the_field_bound_agrees_with_the_store_s_identifier_bound() {
        let store = sibling_source("automonique-store/src/automation_store.rs");
        assert!(
            store.contains(&format!(
                "MAX_IDENTIFIER_BYTES: usize = {MAX_AUTOMATION_API_FIELD_BYTES}"
            )),
            "the wire bound and the stored identifier bound disagree",
        );
        assert_eq!(AutomationId::MAX_BYTES, MAX_AUTOMATION_API_FIELD_BYTES);
        assert_eq!(PauseReason::MAX_BYTES, MAX_AUTOMATION_API_FIELD_BYTES);
    }

    #[test]
    fn the_lattice_agrees_with_the_store_and_with_the_automation_model() {
        // Every ordered pair, decided the same way in both places. A lattice
        // that agreed on the six legal moves but disagreed on one refusal would
        // pass a spot check and fail an operator.
        for from in ENABLEMENT_STATES {
            for to in ENABLEMENT_STATES {
                let expected = matches!(
                    (from, to),
                    (EnablementState::Enabled, EnablementState::Paused)
                        | (EnablementState::Paused, EnablementState::Enabled)
                        | (
                            EnablementState::Enabled | EnablementState::Paused,
                            EnablementState::Archived
                        )
                );
                assert_eq!(
                    permits_transition(from, to),
                    expected,
                    "{} -> {}",
                    from.as_str(),
                    to.as_str(),
                );
            }
            // Nothing transitions to itself, and nothing leaves `archived`.
            assert!(!permits_transition(from, from));
            assert!(!permits_transition(EnablementState::Archived, from));
        }
    }

    #[test]
    fn exactly_the_withdrawn_states_require_a_cause() {
        assert!(!requires_cause(EnablementState::Enabled));
        assert!(requires_cause(EnablementState::Paused));
        assert!(requires_cause(EnablementState::Archived));
        for state in ENABLEMENT_STATES {
            assert_eq!(requires_cause(state), !state.admits_occurrence());
        }
    }

    #[test]
    fn an_undefined_enablement_word_fails_closed() {
        for state in ENABLEMENT_STATES {
            assert_eq!(decode_enablement(state.as_str()), Ok(state));
        }
        for undefined in ["Enabled", "disabled", "ENABLED", "", "enabled "] {
            assert_eq!(
                decode_enablement(undefined),
                Err(AutomationApiError::Codec(CodecError::UnknownEnumValue {
                    field: "enablement"
                })),
            );
        }
    }

    #[test]
    fn the_refusal_words_are_pinned_by_literal_and_round_trip() {
        assert_eq!(AutomationRefusal::ALL.len(), 8);
        assert_eq!(
            AutomationRefusal::ALL
                .iter()
                .map(|refusal| refusal.as_str())
                .collect::<Vec<_>>(),
            vec![
                "unknown_automation",
                "already_registered",
                "illegal_transition",
                "cause_required",
                "cause_forbidden",
                "cursor_out_of_range",
                "registry_full",
                "invalid_field",
            ],
        );
        for refusal in AutomationRefusal::ALL {
            assert_eq!(
                AutomationRefusal::from_spelling(refusal.as_str()),
                Some(refusal)
            );
            assert_eq!(refusal.to_string(), refusal.as_str());
        }
        assert_eq!(AutomationRefusal::from_spelling("revision_mismatch"), None);
        assert_eq!(AutomationRefusal::from_spelling(""), None);
    }

    /// Every refusal this lane can answer stands for a store condition that
    /// exists.
    ///
    /// The assertion is deliberately one-directional. Not every store category
    /// becomes a refusal — corruption, schema drift and SQLite failure are the
    /// daemon's fault rather than a client's, and answering them as refusals
    /// would present our broken storage as their mistake. But a refusal *word*
    /// with no store condition behind it would be a refusal this lane invented,
    /// which is the failure this test exists to prevent.
    ///
    /// One word is this lane's own and says so: `unknown_automation` stands for
    /// the store's generic `not_found`, spelled specifically because a client
    /// reading "not_found" on a control protocol cannot tell what was not
    /// found.
    #[test]
    fn every_client_facing_refusal_stands_for_a_store_condition() {
        let store = sibling_source("automonique-store/src/automation_store.rs");
        for (refusal, store_category) in [
            (AutomationRefusal::UnknownAutomation, "not_found"),
            (AutomationRefusal::AlreadyRegistered, "already_registered"),
            (AutomationRefusal::IllegalTransition, "illegal_transition"),
            (AutomationRefusal::CauseRequired, "cause_required"),
            (AutomationRefusal::CauseForbidden, "cause_forbidden"),
            (AutomationRefusal::CursorOutOfRange, "cursor_out_of_range"),
            (AutomationRefusal::RegistryFull, "registry_full"),
            (AutomationRefusal::InvalidField, "invalid_field"),
        ] {
            assert!(
                AutomationRefusal::ALL.contains(&refusal),
                "{refusal} left the refusal set without leaving this table",
            );
            assert!(
                store.contains(&format!("=> \"{store_category}\"")),
                "{store_category} is not a category automation_store produces",
            );
        }
        assert_eq!(
            AutomationRefusal::ALL.len(),
            8,
            "a refusal was added without a store condition behind it",
        );

        // A stale revision *is* a store category, and it is deliberately not a
        // refusal here: it is the `Conflict` answer, which a client retries
        // differently from a rejection.
        assert!(store.contains("=> \"revision_mismatch\""));
        assert_eq!(AutomationRefusal::from_spelling("revision_mismatch"), None);
    }
}

/// Framing: the protocol name, the version, and exact bodies.
mod framing {
    use super::*;

    fn round_trip_request(request: &AutomationRequest) -> AutomationRequest {
        let payload = request.to_message().expect("encode").to_canonical_bytes();
        AutomationRequest::from_canonical_bytes(&payload).expect("decode")
    }

    fn round_trip_response(response: &AutomationResponse) -> AutomationResponse {
        let payload = response.to_message().expect("encode").to_canonical_bytes();
        AutomationResponse::from_canonical_bytes(&payload).expect("decode")
    }

    #[test]
    fn the_protocol_name_and_schema_are_stable() {
        assert_eq!(AUTOMATION_PROTOCOL, "automonique.automation");
        assert_eq!(AUTOMATION_API_SCHEMA_V1, "automonique.automation/v1");
        assert_ne!(
            AUTOMATION_PROTOCOL,
            automonique_protocol::admin::ADMIN_PROTOCOL
        );
        assert_ne!(
            AUTOMATION_PROTOCOL,
            automonique_protocol::runs_api::RUNS_PROTOCOL
        );

        let message = AutomationRequest::AutomationDetail {
            request_id: request_id(),
            automation_id: id("nightly-report"),
        }
        .to_message()
        .expect("encode");
        assert_eq!(message.envelope().protocol().as_str(), AUTOMATION_PROTOCOL);
        assert_eq!(message.envelope().version(), MajorVersion::FIRST);
    }

    #[test]
    fn every_request_round_trips_through_the_canonical_codec() {
        for request in [
            AutomationRequest::RegisterAutomation {
                request_id: request_id(),
                registration: registration("nightly-report"),
            },
            AutomationRequest::RegisterAutomation {
                request_id: request_id(),
                registration: RegisterAutomation::new(
                    id("nightly-report"),
                    who("ben"),
                    AutomationSchedule::once(EpochMillis::from_millis(1_700_000_000_000))
                        .expect("valid instant"),
                    scope("workspace:reports"),
                    prompt("a prompt\nwith a newline"),
                )
                .expect("a one-shot registration"),
            },
            AutomationRequest::SetEnablement {
                request_id: request_id(),
                transition: SetEnablement::new(
                    id("nightly-report"),
                    1,
                    EnablementState::Paused,
                    who("ben"),
                    Some(why("provider outage")),
                )
                .expect("coupled"),
            },
            AutomationRequest::SetEnablement {
                request_id: request_id(),
                transition: SetEnablement::new(
                    id("nightly-report"),
                    2,
                    EnablementState::Enabled,
                    who("dana"),
                    None,
                )
                .expect("coupled"),
            },
            AutomationRequest::ListAutomations {
                request_id: request_id(),
                query: ListAutomations::new(
                    AutomationStateFilter::only([EnablementState::Paused]).expect("filter"),
                    AutomationCursor::new(7),
                    AutomationPageSize::new(4).expect("page size"),
                ),
            },
            AutomationRequest::AutomationDetail {
                request_id: request_id(),
                automation_id: id("nightly-report"),
            },
        ] {
            assert_eq!(round_trip_request(&request), request);
        }
    }

    #[test]
    fn every_response_round_trips_through_the_canonical_codec() {
        let receipt = AutomationReceiptView::new(
            3,
            id("nightly-report"),
            EnablementState::Paused,
            2,
            EpochMillis::from_millis(1_700_000_002_000),
        )
        .expect("receipt");
        for response in [
            AutomationResponse::Accepted {
                request_id: request_id(),
                receipt,
            },
            AutomationResponse::AutomationList {
                request_id: request_id(),
                page: AutomationListPage::new(
                    vec![enabled(1, "a"), enabled(2, "b")],
                    AutomationContinuation::More(AutomationCursor::new(2)),
                )
                .expect("page"),
            },
            AutomationResponse::AutomationDetail {
                request_id: request_id(),
                record: record(
                    4,
                    "nightly-report",
                    3,
                    EnablementState::Archived,
                    "dana",
                    Some("superseded"),
                ),
                prompt: None,
            },
            AutomationResponse::detail(
                request_id(),
                scheduled(5, "nightly-report"),
                Some(prompt("summarize the night")),
            )
            .expect("a coherent detail"),
            AutomationResponse::AutomationList {
                request_id: request_id(),
                page: AutomationListPage::new(
                    vec![scheduled(1, "a"), enabled(2, "b")],
                    AutomationContinuation::Complete,
                )
                .expect("a page mixing scheduled and unscheduled rows"),
            },
            AutomationResponse::conflict(request_id(), 1, 4).expect("conflict"),
            AutomationResponse::Refused {
                request_id: request_id(),
                refusal: AutomationRefusal::UnknownAutomation,
            },
        ] {
            assert_eq!(round_trip_response(&response), response);
        }
    }

    /// A request that names another protocol, or another version, is refused
    /// outright rather than being read with this lane's decoder.
    #[test]
    fn a_foreign_envelope_is_refused_by_this_lane_s_decoder() {
        for payload in [
            br#"{"body":{"automation_id":"a"},"kind":"automation_detail","protocol":"automonique.admin","request_id":"r","version":1}"#.as_slice(),
            br#"{"body":{"automation_id":"a"},"kind":"automation_detail","protocol":"automonique.automation","request_id":"r","version":2}"#.as_slice(),
        ] {
            assert!(AutomationRequest::from_canonical_bytes(payload).is_err());
        }
    }

    #[test]
    fn an_unknown_kind_is_refused_on_both_directions() {
        let request = br#"{"body":{},"kind":"delete_automation","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationRequest::from_canonical_bytes(request),
            Err(AutomationApiError::UnknownKind)
        );
        let response = br#"{"body":{},"kind":"automation_deleted","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(response),
            Err(AutomationApiError::UnknownKind)
        );
    }

    /// Field-set exactness, in both directions: a body with an extra member is
    /// refused just as firmly as one with a member missing. A decoder that
    /// ignored unknown members would let a later build's field travel through
    /// this one unnoticed.
    #[test]
    fn a_body_that_is_not_the_exact_declared_shape_is_refused() {
        for payload in [
            // register: extra member.
            br#"{"body":{"actor":"ben","automation_id":"a","prompt":"p","schedule":"every@1000","scope":"s","trigger":"manual"},"kind":"register_automation","protocol":"automonique.automation","request_id":"r","version":1}"#.as_slice(),
            // register: missing members — the job is not optional.
            br#"{"body":{"actor":"ben","automation_id":"a"},"kind":"register_automation","protocol":"automonique.automation","request_id":"r","version":1}"#.as_slice(),
            // set_enablement: missing `cause`, which is required *as a member*
            // even when its value is null.
            br#"{"body":{"actor":"ben","automation_id":"a","expected_revision":1,"target":"enabled"},"kind":"set_enablement","protocol":"automonique.automation","request_id":"r","version":1}"#.as_slice(),
            // list: extra member.
            br#"{"body":{"before":1,"page_size":4,"since":0,"states":null},"kind":"list_automations","protocol":"automonique.automation","request_id":"r","version":1}"#.as_slice(),
            // detail: extra member.
            br#"{"body":{"automation_id":"a","revision":1},"kind":"automation_detail","protocol":"automonique.automation","request_id":"r","version":1}"#.as_slice(),
        ] {
            assert_eq!(
                AutomationRequest::from_canonical_bytes(payload),
                Err(AutomationApiError::InvalidBody),
                "an inexact body was admitted",
            );
        }
    }

    /// A detail answer without its `prompt` member is not a record that
    /// happens to lack a prompt; it is a body of the wrong shape. And a page
    /// item carrying one is a record of the wrong shape the other way.
    #[test]
    fn a_detail_answer_carries_its_prompt_member_even_when_null() {
        let without = br#"{"body":{"actor":"ben","automation_id":"a","cause":null,"created_at_ms":0,"enablement":"enabled","entry_id":1,"last_fired_at_ms":null,"next_fire_at_ms":null,"revision":1,"schedule":null,"scope":null,"updated_at_ms":0},"kind":"automation_detail_result","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(without),
            Err(AutomationApiError::InvalidBody),
        );
        let with_null = br#"{"body":{"actor":"ben","automation_id":"a","cause":null,"created_at_ms":0,"enablement":"enabled","entry_id":1,"last_fired_at_ms":null,"next_fire_at_ms":null,"prompt":null,"revision":1,"schedule":null,"scope":null,"updated_at_ms":0},"kind":"automation_detail_result","protocol":"automonique.automation","request_id":"r","version":1}"#;
        let AutomationResponse::AutomationDetail { record, prompt, .. } =
            AutomationResponse::from_canonical_bytes(with_null).expect("an unscheduled detail")
        else {
            panic!("a detail answer decoded as something else")
        };
        assert!(!record.is_scheduled());
        assert_eq!(prompt, None);
        let page = br#"{"body":{"automations":[{"actor":"ben","automation_id":"a","cause":null,"created_at_ms":0,"enablement":"enabled","entry_id":1,"last_fired_at_ms":null,"next_fire_at_ms":null,"prompt":null,"revision":1,"schedule":null,"scope":null,"updated_at_ms":0}],"more":false,"next_cursor":null},"kind":"automation_list_result","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(page),
            Err(AutomationApiError::InvalidBody),
        );
    }

    #[test]
    fn a_refusal_word_this_build_does_not_define_fails_closed() {
        let payload = br#"{"body":{"refusal":"not_authorized"},"kind":"refused","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(payload),
            Err(AutomationApiError::Codec(CodecError::UnknownEnumValue {
                field: "refusal"
            })),
        );
    }

    /// The compile-time frame arithmetic, measured rather than restated.
    ///
    /// A maximal page is built from real records carrying four maximal
    /// bounded strings each, encoded by the real codec and framed the way the
    /// socket frames it. Restating the constant would prove only that the
    /// constant equals itself.
    #[test]
    fn a_maximal_page_and_record_fit_one_frame() {
        // Every byte a quote, which JSON-escapes to two: the worst case the
        // arithmetic budgets for.
        let long = "\"".repeat(MAX_AUTOMATION_API_FIELD_BYTES);
        let long_scope = "\"".repeat(MAX_AUTOMATION_SCOPE_BYTES);
        let maximal = |entry_id: u64| {
            AutomationRecordView::new(AutomationRecordParts {
                entry_id,
                automation_id: id(&long),
                revision: u64::MAX >> 1,
                enablement: EnablementState::Archived,
                actor: who(&long),
                cause: Some(why(&long)),
                created_at: EpochMillis::from_millis(i64::MAX),
                updated_at: EpochMillis::from_millis(i64::MAX),
                schedule: Some(every(i64::MAX)),
                scope: Some(scope(&long_scope)),
                next_fire_at: Some(EpochMillis::from_millis(i64::MAX)),
                last_fired_at: Some(EpochMillis::from_millis(i64::MAX)),
            })
            .expect("maximal record")
        };
        let entries: Vec<AutomationRecordView> = (1..=MAX_AUTOMATION_PAGE_ITEMS as u64)
            .map(maximal)
            .collect();
        let page = AutomationListPage::new(
            entries,
            AutomationContinuation::More(AutomationCursor::new(MAX_AUTOMATION_PAGE_ITEMS as u64)),
        )
        .expect("maximal page");
        let payload = AutomationResponse::AutomationList {
            request_id: RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("request id"),
            page,
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal page fits one frame");
        assert!(
            frame.len() <= MAX_AUTOMATION_CANONICAL_BYTES,
            "a maximal page framed to {} bytes; the frame holds {MAX_AUTOMATION_CANONICAL_BYTES}",
            frame.len(),
        );

        // And the largest single mutation request, which carries three maximal
        // identifiers of its own.
        let payload = AutomationRequest::SetEnablement {
            request_id: RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("request id"),
            transition: SetEnablement::new(
                id(&long),
                u64::MAX >> 1,
                EnablementState::Archived,
                who(&long),
                Some(why(&long)),
            )
            .expect("maximal transition"),
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal transition fits one frame");
        assert!(
            frame.len() <= MAX_AUTOMATION_CANONICAL_BYTES,
            "a maximal transition framed to {} bytes",
            frame.len(),
        );

        // And a detail read, which is the one answer that carries the prompt.
        let payload = AutomationResponse::detail(
            RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("request id"),
            maximal(1),
            Some(prompt(&"\"".repeat(MAX_AUTOMATION_PROMPT_BYTES))),
        )
        .expect("a coherent detail")
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal detail fits one frame");
        assert!(
            frame.len() <= MAX_AUTOMATION_CANONICAL_BYTES,
            "a maximal detail framed to {} bytes",
            frame.len(),
        );

        // And the largest registration, whose identity is bounded by the key
        // it must derive rather than by the identity grammar.
        let payload = AutomationRequest::RegisterAutomation {
            request_id: RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("request id"),
            registration: RegisterAutomation::new(
                id(&"\"".repeat(MAX_SCHEDULED_AUTOMATION_ID_BYTES)),
                who(&long),
                every(i64::MAX),
                scope(&long_scope),
                prompt(&"\"".repeat(MAX_AUTOMATION_PROMPT_BYTES)),
            )
            .expect("maximal registration"),
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        let mut frame = Vec::new();
        encode_frame(&payload, &mut frame).expect("a maximal registration fits one frame");
        assert!(
            frame.len() <= MAX_AUTOMATION_CANONICAL_BYTES,
            "a maximal registration framed to {} bytes",
            frame.len(),
        );
    }
}

/// The cause coupling, decided before a socket is opened.
mod coupling {
    use super::*;

    #[test]
    fn a_withdrawal_with_no_stated_cause_is_refused_at_construction() {
        for state in [EnablementState::Paused, EnablementState::Archived] {
            assert_eq!(
                SetEnablement::new(id("a"), 1, state, who("ben"), None),
                Err(AutomationApiError::CauseRequired { state }),
            );
        }
    }

    #[test]
    fn a_resume_that_states_a_cause_is_refused_at_construction() {
        assert_eq!(
            SetEnablement::new(
                id("a"),
                2,
                EnablementState::Enabled,
                who("ben"),
                Some(why("because")),
            ),
            Err(AutomationApiError::CauseForbidden {
                state: EnablementState::Enabled
            }),
        );
    }

    /// The coupling is not merely a constructor courtesy: a hand-rolled frame
    /// that violates it is refused by the decoder too, so a peer that never
    /// called the constructor cannot smuggle one past.
    #[test]
    fn the_coupling_is_re_decided_on_the_wire() {
        let causeless_pause = br#"{"body":{"actor":"ben","automation_id":"a","cause":null,"expected_revision":1,"target":"paused"},"kind":"set_enablement","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationRequest::from_canonical_bytes(causeless_pause),
            Err(AutomationApiError::CauseRequired {
                state: EnablementState::Paused
            }),
        );

        let caused_resume = br#"{"body":{"actor":"ben","automation_id":"a","cause":"why","expected_revision":2,"target":"enabled"},"kind":"set_enablement","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationRequest::from_canonical_bytes(caused_resume),
            Err(AutomationApiError::CauseForbidden {
                state: EnablementState::Enabled
            }),
        );
    }

    #[test]
    fn an_empty_cause_is_refused_rather_than_read_as_no_reason_given() {
        assert!(matches!(
            PauseReason::new(""),
            Err(AutomationApiError::Field { field: "cause", .. })
        ));
        let empty = br#"{"body":{"actor":"ben","automation_id":"a","cause":"","expected_revision":1,"target":"paused"},"kind":"set_enablement","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert!(matches!(
            AutomationRequest::from_canonical_bytes(empty),
            Err(AutomationApiError::Field { field: "cause", .. })
        ));
    }

    #[test]
    fn a_zero_expected_revision_names_a_row_no_writer_produced() {
        assert_eq!(
            SetEnablement::new(id("a"), 0, EnablementState::Enabled, who("ben"), None),
            Err(AutomationApiError::UnwrittenRevision),
        );
    }

    #[test]
    fn a_record_repeats_every_coupling_the_store_re_derives_on_read() {
        let parts = |enablement, revision, cause: Option<&str>| AutomationRecordParts {
            entry_id: 1,
            automation_id: id("a"),
            revision,
            enablement,
            actor: who("ben"),
            cause: cause.map(why),
            created_at: EpochMillis::EPOCH,
            updated_at: EpochMillis::EPOCH,
            schedule: None,
            scope: None,
            next_fire_at: None,
            last_fired_at: None,
        };
        assert_eq!(
            AutomationRecordView::new(parts(EnablementState::Paused, 2, None)),
            Err(AutomationApiError::CauseRequired {
                state: EnablementState::Paused
            }),
        );
        assert_eq!(
            AutomationRecordView::new(parts(EnablementState::Enabled, 1, Some("why"))),
            Err(AutomationApiError::CauseForbidden {
                state: EnablementState::Enabled
            }),
        );
        // A withdrawn row at revision one is a row registration could not have
        // written: registration always writes `enabled`.
        assert_eq!(
            AutomationRecordView::new(parts(EnablementState::Archived, 1, Some("why"))),
            Err(AutomationApiError::WithdrawnAtFirstRevision),
        );
        assert_eq!(
            AutomationRecordView::new(parts(EnablementState::Enabled, 0, None)),
            Err(AutomationApiError::UnwrittenRevision),
        );
        // But an *enabled* row above revision one is legal: it was resumed.
        let resumed = AutomationRecordView::new(parts(EnablementState::Enabled, 3, None))
            .expect("a resumed automation");
        assert_eq!(
            resumed.resumed_by().map(AutomationActor::as_str),
            Some("ben")
        );
    }

    #[test]
    fn a_never_paused_automation_names_nobody_as_having_resumed_it() {
        assert_eq!(enabled(1, "a").resumed_by(), None);
    }

    /// The flat columns reassemble into the rich model's own shape.
    #[test]
    fn a_record_projects_onto_the_automation_model_s_enablement() {
        assert_eq!(
            enabled(1, "a").enablement_value(),
            Some(AutomationEnablement::newly_declared()),
        );

        let paused = record(
            1,
            "a",
            2,
            EnablementState::Paused,
            "ben",
            Some("provider outage"),
        );
        let Some(AutomationEnablement::Paused { cause }) = paused.enablement_value() else {
            panic!("a paused row did not project onto a paused enablement")
        };
        assert_eq!(cause.actor().as_str(), "ben");
        assert_eq!(cause.reason(), "provider outage");

        let resumed = record(1, "a", 3, EnablementState::Enabled, "dana", None);
        assert_eq!(
            resumed.enablement_value(),
            Some(AutomationEnablement::Enabled {
                resumed_by: Some(who("dana"))
            }),
        );
    }
}

/// Pages, filters and cursors.
mod pagination {
    use super::*;

    #[test]
    fn a_page_that_repeats_or_rewinds_an_entry_is_refused() {
        assert_eq!(
            AutomationListPage::new(
                vec![enabled(2, "b"), enabled(2, "b")],
                AutomationContinuation::Complete,
            ),
            Err(AutomationApiError::PageOutOfOrder),
        );
        assert_eq!(
            AutomationListPage::new(
                vec![enabled(2, "b"), enabled(1, "a")],
                AutomationContinuation::Complete,
            ),
            Err(AutomationApiError::PageOutOfOrder),
        );
        // A continuation below the last row served would hand that row back.
        assert_eq!(
            AutomationListPage::new(
                vec![enabled(1, "a"), enabled(4, "d")],
                AutomationContinuation::More(AutomationCursor::new(3)),
            ),
            Err(AutomationApiError::ContinuationRewinds),
        );
        // The store's own cursor — the last entry served, resumed *after* — is
        // the boundary and is admitted.
        assert!(
            AutomationListPage::new(
                vec![enabled(1, "a"), enabled(4, "d")],
                AutomationContinuation::More(AutomationCursor::new(4)),
            )
            .is_ok()
        );
    }

    #[test]
    fn an_empty_page_may_still_report_that_rows_follow() {
        // A filter can exclude every row in one scanned window while rows
        // remain behind it. Reporting `complete` there would stop a client.
        let page = AutomationListPage::new(
            Vec::new(),
            AutomationContinuation::More(AutomationCursor::new(9)),
        )
        .expect("an empty continuing page");
        assert!(page.entries().is_empty());
        assert!(page.continuation().has_more());
    }

    #[test]
    fn a_page_above_the_protocol_bound_is_refused_rather_than_truncated() {
        let entries: Vec<AutomationRecordView> = (1..=MAX_AUTOMATION_PAGE_ITEMS as u64 + 1)
            .map(|entry_id| enabled(entry_id, &format!("a{entry_id}")))
            .collect();
        assert_eq!(
            AutomationListPage::new(entries, AutomationContinuation::Complete),
            Err(AutomationApiError::PageTooLarge {
                max_items: MAX_AUTOMATION_PAGE_ITEMS,
                actual_items: MAX_AUTOMATION_PAGE_ITEMS + 1,
            }),
        );
    }

    #[test]
    fn a_page_size_outside_the_protocol_range_is_refused() {
        assert_eq!(
            AutomationPageSize::new(0),
            Err(AutomationApiError::PageSizeOutOfRange {
                max_items: MAX_AUTOMATION_PAGE_ITEMS,
                requested: 0,
            }),
        );
        assert!(AutomationPageSize::new(MAX_AUTOMATION_PAGE_ITEMS + 1).is_err());
        assert_eq!(
            AutomationPageSize::new(MAX_AUTOMATION_PAGE_ITEMS)
                .expect("the ceiling itself")
                .get(),
            MAX_AUTOMATION_PAGE_ITEMS,
        );
        assert_eq!(AutomationPageSize::MAX.get(), MAX_AUTOMATION_PAGE_ITEMS);
    }

    #[test]
    fn a_state_filter_is_a_set_and_encodes_in_one_order() {
        assert_eq!(
            AutomationStateFilter::only([]),
            Err(AutomationApiError::StateFilterEmpty)
        );
        assert_eq!(
            AutomationStateFilter::only([EnablementState::Paused, EnablementState::Paused]),
            Err(AutomationApiError::StateFilterRepeats {
                state: EnablementState::Paused
            }),
        );
        let forwards =
            AutomationStateFilter::only([EnablementState::Enabled, EnablementState::Archived])
                .expect("filter");
        let backwards =
            AutomationStateFilter::only([EnablementState::Archived, EnablementState::Enabled])
                .expect("filter");
        assert_eq!(forwards, backwards);
        assert!(forwards.admits(EnablementState::Enabled));
        assert!(!forwards.admits(EnablementState::Paused));

        // The absence of a filter admits everything.
        let any = AutomationStateFilter::any();
        assert_eq!(any.states(), None);
        for state in ENABLEMENT_STATES {
            assert!(any.admits(state));
        }
    }

    #[test]
    fn a_listing_answer_cannot_contradict_the_query_it_answers() {
        let query = ListAutomations::new(
            AutomationStateFilter::only([EnablementState::Paused]).expect("filter"),
            AutomationCursor::START,
            AutomationPageSize::new(1).expect("page size"),
        );

        // A row the filter excludes.
        let page = AutomationListPage::new(vec![enabled(1, "a")], AutomationContinuation::Complete)
            .expect("page");
        assert_eq!(
            AutomationResponse::listing(request_id(), &query, page),
            Err(AutomationApiError::PageOutsideFilter),
        );

        // More rows than were asked for.
        let paused = |entry_id: u64| {
            record(
                entry_id,
                &format!("a{entry_id}"),
                2,
                EnablementState::Paused,
                "ben",
                Some("outage"),
            )
        };
        let page =
            AutomationListPage::new(vec![paused(1), paused(2)], AutomationContinuation::Complete)
                .expect("page");
        assert_eq!(
            AutomationResponse::listing(request_id(), &query, page),
            Err(AutomationApiError::PageAboveRequestedSize {
                requested: 1,
                actual_items: 2,
            }),
        );

        // And the answer the query does admit.
        let page = AutomationListPage::new(vec![paused(1)], AutomationContinuation::Complete)
            .expect("page");
        assert!(matches!(
            AutomationResponse::listing(request_id(), &query, page),
            Ok(AutomationResponse::AutomationList { .. }),
        ));
    }

    #[test]
    fn a_cursor_is_the_store_s_own_exclusive_position() {
        assert_eq!(AutomationCursor::START.position(), 0);
        assert_eq!(AutomationCursor::new(9).position(), 9);
        // Zero is a legal wire value here — it is where a listing begins —
        // which is why `since` is not an `Option` on this protocol.
        assert_eq!(listing(1).since(), AutomationCursor::START);
    }
}

/// The outcome vocabulary, and what a conflict is allowed to say.
mod outcomes {
    use super::*;

    #[test]
    fn each_answer_reports_the_outcome_its_shape_earns() {
        let receipt =
            AutomationReceiptView::new(1, id("a"), EnablementState::Enabled, 1, EpochMillis::EPOCH)
                .expect("receipt");
        assert_eq!(
            AutomationResponse::Accepted {
                request_id: request_id(),
                receipt,
            }
            .outcome(),
            ActionOutcome::Accepted,
        );
        assert_eq!(
            AutomationResponse::AutomationList {
                request_id: request_id(),
                page: AutomationListPage::new(Vec::new(), AutomationContinuation::Complete)
                    .expect("page"),
            }
            .outcome(),
            ActionOutcome::Completed,
        );
        assert_eq!(
            AutomationResponse::AutomationDetail {
                request_id: request_id(),
                record: enabled(1, "a"),
                prompt: None,
            }
            .outcome(),
            ActionOutcome::Completed,
        );
        assert_eq!(
            AutomationResponse::conflict(request_id(), 1, 2)
                .expect("conflict")
                .outcome(),
            ActionOutcome::Conflict,
        );
        assert_eq!(
            AutomationResponse::Refused {
                request_id: request_id(),
                refusal: AutomationRefusal::RegistryFull,
            }
            .outcome(),
            ActionOutcome::Rejected,
        );
    }

    #[test]
    fn the_two_unreachable_outcomes_are_never_produced() {
        assert_eq!(
            OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES,
            [ActionOutcome::Unknown, ActionOutcome::ResyncRequired],
        );
        let answers = [
            AutomationResponse::AutomationList {
                request_id: request_id(),
                page: AutomationListPage::new(Vec::new(), AutomationContinuation::Complete)
                    .expect("page"),
            },
            AutomationResponse::AutomationDetail {
                request_id: request_id(),
                record: enabled(1, "a"),
                prompt: None,
            },
            AutomationResponse::conflict(request_id(), 1, 2).expect("conflict"),
            AutomationResponse::Refused {
                request_id: request_id(),
                refusal: AutomationRefusal::InvalidField,
            },
        ];
        for answer in &answers {
            assert!(
                !OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES.contains(&answer.outcome()),
                "{answer:?} produced an outcome this protocol cannot",
            );
        }
        // And the four that *are* produced cover exactly the other four.
        let mut produced: Vec<ActionOutcome> =
            answers.iter().map(AutomationResponse::outcome).collect();
        produced.push(ActionOutcome::Accepted);
        for outcome in ActionOutcome::ALL {
            assert_eq!(
                produced.contains(&outcome),
                !OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES.contains(&outcome),
                "{outcome:?}",
            );
        }
    }

    #[test]
    fn a_conflict_that_names_the_expected_revision_is_not_a_conflict() {
        assert_eq!(
            AutomationResponse::conflict(request_id(), 4, 4),
            Err(AutomationApiError::ConflictWithoutDisagreement),
        );
        assert_eq!(
            AutomationResponse::conflict(request_id(), 0, 4),
            Err(AutomationApiError::UnwrittenRevision),
        );
        assert_eq!(
            AutomationResponse::conflict(request_id(), 4, 0),
            Err(AutomationApiError::UnwrittenRevision),
        );
        // The wire re-decides it, so a hand-rolled agreeing conflict is refused
        // rather than rendered as one.
        let agreeing = br#"{"body":{"durable_revision":4,"expected_revision":4},"kind":"revision_conflict","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(agreeing),
            Err(AutomationApiError::ConflictWithoutDisagreement),
        );
    }

    /// A refusal is one closed word and carries no echo of what was sent.
    #[test]
    fn a_refusal_body_carries_the_word_and_nothing_else() {
        let payload = AutomationResponse::Refused {
            request_id: request_id(),
            refusal: AutomationRefusal::AlreadyRegistered,
        }
        .to_message()
        .expect("encode")
        .to_canonical_bytes();
        let message = Message::from_canonical_bytes(&payload).expect("decode");
        let JsonValue::Object(entries) = message.body() else {
            panic!("a refusal body is an object")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "refusal");
        assert_eq!(
            entries[0].1,
            JsonValue::String("already_registered".to_owned())
        );
    }

    #[test]
    fn a_mutation_is_distinguishable_from_a_read_without_decoding_a_body() {
        assert!(
            AutomationRequest::RegisterAutomation {
                request_id: request_id(),
                registration: registration("a"),
            }
            .is_mutation()
        );
        assert!(
            AutomationRequest::SetEnablement {
                request_id: request_id(),
                transition: SetEnablement::new(
                    id("a"),
                    1,
                    EnablementState::Paused,
                    who("ben"),
                    Some(why("outage")),
                )
                .expect("coupled"),
            }
            .is_mutation()
        );
        assert!(
            !AutomationRequest::ListAutomations {
                request_id: request_id(),
                query: listing(1),
            }
            .is_mutation()
        );
        assert!(
            !AutomationRequest::AutomationDetail {
                request_id: request_id(),
                automation_id: id("a"),
            }
            .is_mutation()
        );
    }
}

/// Bounded identifiers.
mod bounds {
    use super::*;

    #[test]
    fn every_bounded_field_refuses_the_same_three_shapes() {
        let over_long = "a".repeat(MAX_AUTOMATION_API_FIELD_BYTES + 1);
        for (field, empty, control, long) in [
            (
                "automation_id",
                AutomationId::new("").err(),
                AutomationId::new("night\nly").err(),
                AutomationId::new(&over_long).err(),
            ),
            (
                "cause",
                PauseReason::new("").err(),
                PauseReason::new("out\tage").err(),
                PauseReason::new(&over_long).err(),
            ),
        ] {
            for error in [empty, control, long] {
                let Some(AutomationApiError::Field {
                    field: refused_field,
                    ..
                }) = error
                else {
                    panic!("{field} admitted a value outside its grammar")
                };
                assert_eq!(refused_field, field);
            }
        }
        // The bound itself is admitted, so the refusals above are bounds and
        // not off-by-ones.
        assert!(AutomationId::new("a".repeat(MAX_AUTOMATION_API_FIELD_BYTES)).is_ok());
        assert!(PauseReason::new("a".repeat(MAX_AUTOMATION_API_FIELD_BYTES)).is_ok());
    }

    /// An identity carrying whitespace is admitted, and deliberately so: the
    /// durable registry stores it, and a wire type stricter than the table
    /// would make a stored row unreadable through the only surface serving it.
    #[test]
    fn an_identity_with_a_space_is_carried_rather_than_refused() {
        let spaced = id("nightly report");
        assert_eq!(spaced.as_str(), "nightly report");
        assert_eq!(spaced.to_string(), "nightly report");
        let request = AutomationRequest::AutomationDetail {
            request_id: request_id(),
            automation_id: spaced,
        };
        let payload = request.to_message().expect("encode").to_canonical_bytes();
        assert_eq!(
            AutomationRequest::from_canonical_bytes(&payload).expect("decode"),
            request,
        );
    }

    #[test]
    fn a_zero_row_identity_names_a_row_no_writer_produced() {
        assert_eq!(
            AutomationRecordView::new(AutomationRecordParts {
                entry_id: 0,
                automation_id: id("a"),
                revision: 1,
                enablement: EnablementState::Enabled,
                actor: who("ben"),
                cause: None,
                created_at: EpochMillis::EPOCH,
                updated_at: EpochMillis::EPOCH,
                schedule: None,
                scope: None,
                next_fire_at: None,
                last_fired_at: None,
            }),
            Err(AutomationApiError::UnwrittenRow { field: "entry_id" }),
        );
        assert_eq!(
            AutomationReceiptView::new(0, id("a"), EnablementState::Enabled, 1, EpochMillis::EPOCH),
            Err(AutomationApiError::UnwrittenRow { field: "entry_id" }),
        );
    }

    #[test]
    fn an_instant_before_the_epoch_is_refused_on_both_timestamps() {
        for (field, parts) in [
            (
                "created_at_ms",
                AutomationRecordParts {
                    entry_id: 1,
                    automation_id: id("a"),
                    revision: 1,
                    enablement: EnablementState::Enabled,
                    actor: who("ben"),
                    cause: None,
                    created_at: EpochMillis::from_millis(-1),
                    updated_at: EpochMillis::EPOCH,
                    schedule: None,
                    scope: None,
                    next_fire_at: None,
                    last_fired_at: None,
                },
            ),
            (
                "updated_at_ms",
                AutomationRecordParts {
                    entry_id: 1,
                    automation_id: id("a"),
                    revision: 1,
                    enablement: EnablementState::Enabled,
                    actor: who("ben"),
                    cause: None,
                    created_at: EpochMillis::EPOCH,
                    updated_at: EpochMillis::from_millis(-1),
                    schedule: None,
                    scope: None,
                    next_fire_at: None,
                    last_fired_at: None,
                },
            ),
            (
                "next_fire_at_ms",
                AutomationRecordParts {
                    entry_id: 1,
                    automation_id: id("a"),
                    revision: 1,
                    enablement: EnablementState::Enabled,
                    actor: who("ben"),
                    cause: None,
                    created_at: EpochMillis::EPOCH,
                    updated_at: EpochMillis::EPOCH,
                    schedule: Some(every(1_000)),
                    scope: Some(scope("s")),
                    next_fire_at: Some(EpochMillis::from_millis(-1)),
                    last_fired_at: None,
                },
            ),
            (
                "last_fired_at_ms",
                AutomationRecordParts {
                    entry_id: 1,
                    automation_id: id("a"),
                    revision: 1,
                    enablement: EnablementState::Enabled,
                    actor: who("ben"),
                    cause: None,
                    created_at: EpochMillis::EPOCH,
                    updated_at: EpochMillis::EPOCH,
                    schedule: Some(every(1_000)),
                    scope: Some(scope("s")),
                    next_fire_at: None,
                    last_fired_at: Some(EpochMillis::from_millis(-1)),
                },
            ),
        ] {
            assert_eq!(
                AutomationRecordView::new(parts),
                Err(AutomationApiError::TimeBeforeEpoch { field }),
            );
        }
    }

    #[test]
    fn every_error_has_a_distinct_stable_category() {
        let categories = [
            AutomationApiError::UnknownKind.category(),
            AutomationApiError::InvalidBody.category(),
            AutomationApiError::StateFilterEmpty.category(),
            AutomationApiError::UnwrittenRevision.category(),
            AutomationApiError::WithdrawnAtFirstRevision.category(),
            AutomationApiError::ContinuationIncoherent.category(),
            AutomationApiError::ContinuationRewinds.category(),
            AutomationApiError::PageOutOfOrder.category(),
            AutomationApiError::PageOutsideFilter.category(),
            AutomationApiError::ConflictWithoutDisagreement.category(),
            AutomationApiError::UnsupportedSchedule { kind: "cron" }.category(),
            AutomationApiError::InvalidSchedule.category(),
            AutomationApiError::JobIncoherent.category(),
            AutomationApiError::OccurrenceKeyTooLong { max_bytes: 0 }.category(),
            AutomationApiError::OccurrenceKeyMalformed.category(),
        ];
        let mut unique = categories.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), categories.len(), "a category is duplicated");
        for category in categories {
            assert!(
                category.starts_with("automation_"),
                "{category} is not namespaced to this lane",
            );
        }
    }
}

/// The job: schedule, scope, prompt, and the occurrence key they derive.
mod job {
    use super::*;

    #[test]
    fn a_schedule_round_trips_through_its_canonical_rendering() {
        for (schedule, rendering) in [
            (every(60_000), "every@60000"),
            (
                AutomationSchedule::once(EpochMillis::from_millis(1_700_000_000_000))
                    .expect("instant"),
                "once@1700000000000",
            ),
            (
                AutomationSchedule::once(EpochMillis::EPOCH).expect("the epoch itself"),
                "once@0",
            ),
        ] {
            assert_eq!(schedule.render(), rendering);
            assert_eq!(schedule.to_string(), rendering);
            assert_eq!(
                AutomationSchedule::from_rendering(rendering).expect("its own rendering"),
                schedule,
            );
            assert_eq!(
                AutomationSchedule::parse(rendering).expect("a rendering is an expression"),
                schedule,
            );
            // The projection is lossless in both directions.
            assert_eq!(
                AutomationSchedule::from_canonical(schedule.canonical()).expect("projected"),
                schedule,
            );
            assert_eq!(
                CanonicalSchedule::from_rendering(rendering).expect("canonical"),
                schedule.canonical(),
            );
        }
        assert_eq!(every(1).kind(), "every");
        assert_eq!(
            AutomationSchedule::once(EpochMillis::EPOCH)
                .expect("instant")
                .kind(),
            "once"
        );
    }

    #[test]
    fn the_recognized_phrases_resolve_and_prose_does_not() {
        assert_eq!(
            AutomationSchedule::parse("hourly").expect("hourly"),
            every(60 * 60 * 1_000)
        );
        assert_eq!(
            AutomationSchedule::parse("every hour").expect("every hour"),
            every(60 * 60 * 1_000)
        );
        for prose in [
            "",
            "soon",
            "every@",
            "every@-1",
            "every@0",
            "every@+5",
            "every@007",
            "once@",
            "once@1.5",
            "once@ 5",
            "weekly",
        ] {
            assert_eq!(
                AutomationSchedule::parse(prose),
                Err(AutomationApiError::InvalidSchedule),
                "{prose:?} resolved to a schedule",
            );
        }
        assert_eq!(
            AutomationSchedule::once(EpochMillis::from_millis(-1)),
            Err(AutomationApiError::TimeBeforeEpoch { field: "schedule" }),
        );
        assert_eq!(
            AutomationSchedule::from_rendering("once@-1"),
            Err(AutomationApiError::TimeBeforeEpoch { field: "schedule" }),
        );
    }

    /// Cron is canonical and is refused anyway, by name.
    #[test]
    fn a_cron_schedule_is_refused_with_a_typed_unsupported_refusal() {
        let cron = CanonicalSchedule::cron("0 0 * * *", "UTC", DstPolicy::SkipMissingFireFirst)
            .expect("a canonical cron schedule");
        assert_eq!(
            AutomationSchedule::from_canonical(cron.clone()),
            Err(AutomationApiError::UnsupportedSchedule { kind: "cron" }),
        );
        assert_eq!(
            AutomationSchedule::from_rendering(&cron.render()),
            Err(AutomationApiError::UnsupportedSchedule { kind: "cron" }),
        );
        // `daily` is a recognized phrase that resolves to cron, so it is
        // unsupported rather than ambiguous.
        assert_eq!(
            AutomationSchedule::parse("daily"),
            Err(AutomationApiError::UnsupportedSchedule { kind: "cron" }),
        );
        // And a hand-rolled frame carrying one is refused by the decoder under
        // the same typed category, never admitted as a job that fires nothing.
        let payload = br#"{"body":{"actor":"ben","automation_id":"a","prompt":"p","schedule":"cron@0 0 * * *@UTC@skip_missing_fire_first","scope":"s"},"kind":"register_automation","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationRequest::from_canonical_bytes(payload),
            Err(AutomationApiError::UnsupportedSchedule { kind: "cron" }),
        );
        assert_eq!(
            AutomationApiError::UnsupportedSchedule { kind: "cron" }.category(),
            "automation_unsupported_schedule"
        );
    }

    #[test]
    fn the_first_occurrence_is_the_instant_or_one_interval_after_registration() {
        let registered = EpochMillis::from_millis(1_000);
        assert_eq!(
            every(250).first_occurrence(registered),
            Some(EpochMillis::from_millis(1_250))
        );
        let at = EpochMillis::from_millis(5);
        assert_eq!(
            AutomationSchedule::once(at)
                .expect("instant")
                .first_occurrence(registered),
            Some(at),
            "a one-shot fires at its instant whenever it was registered",
        );
        assert_eq!(
            every(i64::MAX).first_occurrence(registered),
            None,
            "an interval past the end of time never fires rather than wrapping",
        );
    }

    /// The catch-up policy: the oldest due instant fires once, the instants
    /// the lane missed are skipped, and the successor is the first one after
    /// `now`.
    #[test]
    fn the_next_occurrence_skips_what_was_missed_and_never_bursts() {
        let interval = every(10);
        let fired = EpochMillis::from_millis(100);
        let at = |ms| EpochMillis::from_millis(ms);
        // Kept up: the very next instant.
        assert_eq!(interval.next_after(fired, at(100)), Some(at(110)));
        assert_eq!(interval.next_after(fired, at(109)), Some(at(110)));
        // Exactly on the successor: `now` is not later than it, so skip it.
        assert_eq!(interval.next_after(fired, at(110)), Some(at(120)));
        // Far behind: 110, 120, 130 are skipped and 140 is first after 135.
        assert_eq!(interval.next_after(fired, at(135)), Some(at(140)));
        assert_eq!(interval.next_after(fired, at(140)), Some(at(150)));
        // The successor is always strictly later than `now`, on the grid, and
        // never further than one interval past `now` once the lane is behind.
        for now in 90..200 {
            let next = interval.next_after(fired, at(now)).expect("a successor");
            assert!(next.as_millis() > now, "next {next:?} is not after {now}");
            assert_eq!((next.as_millis() - fired.as_millis()) % 10, 0);
            if now >= 110 {
                assert!(
                    next.as_millis() - now <= 10,
                    "a whole interval was skipped needlessly at {now}"
                );
            } else {
                assert_eq!(
                    next,
                    at(110),
                    "ahead of schedule, the successor is simply next"
                );
            }
        }
        // A one-shot has no successor.
        assert_eq!(
            AutomationSchedule::once(fired)
                .expect("instant")
                .next_after(fired, at(5_000)),
            None
        );
        // Past the end of time is exhaustion, not a wrapped instant.
        assert_eq!(
            every(10).next_after(EpochMillis::from_millis(i64::MAX - 5), at(0)),
            None
        );
    }

    #[test]
    fn an_occurrence_key_is_derived_from_the_identity_and_instant_alone() {
        let instant = EpochMillis::from_millis(1_700_000_000_000);
        let key = AutomationOccurrenceKey::derive(&id("nightly-report"), instant).expect("a key");
        assert_eq!(key.as_str(), "automation:nightly-report:1700000000000");
        assert_eq!(key.to_string(), key.as_str());
        assert!(key.as_str().starts_with(OCCURRENCE_KEY_PREFIX));
        // The same inputs derive the same bytes: that is the whole property.
        assert_eq!(
            AutomationOccurrenceKey::derive(&id("nightly-report"), instant).expect("a key"),
            key,
        );
        // And it reads back, including an identity carrying a colon: the
        // instant is the trailing decimal, split from the right.
        assert_eq!(
            AutomationOccurrenceKey::parse(key.as_str()).expect("its own key"),
            (id("nightly-report"), instant),
        );
        let colon =
            AutomationOccurrenceKey::derive(&id("ws:reports:nightly"), EpochMillis::from_millis(7))
                .expect("a key");
        assert_eq!(colon.as_str(), "automation:ws:reports:nightly:7");
        assert_eq!(
            AutomationOccurrenceKey::parse(colon.as_str()).expect("split from the right"),
            (id("ws:reports:nightly"), EpochMillis::from_millis(7)),
        );
        for malformed in [
            "",
            "automation:",
            "automation:a",
            "automation:a:",
            "automation::5",
            "automation:a:-5",
            "automation:a:05",
            "automation:a:+5",
            "automation:a:5 ",
            "automatio:a:5",
            "a:5",
        ] {
            assert_eq!(
                AutomationOccurrenceKey::parse(malformed),
                Err(AutomationApiError::OccurrenceKeyMalformed),
                "{malformed:?} parsed as an occurrence key",
            );
        }
        assert_eq!(
            AutomationOccurrenceKey::derive(&id("a"), EpochMillis::from_millis(-1)),
            Err(AutomationApiError::TimeBeforeEpoch {
                field: "occurrence_instant"
            }),
        );
    }

    /// The key fits the durable submit lane's bound, and the identity bound
    /// that guarantees it is the derived one.
    #[test]
    fn a_scheduled_identity_is_bounded_by_the_key_it_must_derive() {
        assert_eq!(
            MAX_SCHEDULED_AUTOMATION_ID_BYTES,
            MAX_OCCURRENCE_KEY_BYTES - OCCURRENCE_KEY_PREFIX.len() - 1 - 19,
        );
        const {
            assert!(MAX_SCHEDULED_AUTOMATION_ID_BYTES < MAX_AUTOMATION_API_FIELD_BYTES);
        }
        let widest = "a".repeat(MAX_SCHEDULED_AUTOMATION_ID_BYTES);
        let key = AutomationOccurrenceKey::derive(&id(&widest), EpochMillis::from_millis(i64::MAX))
            .expect("the widest identity at the latest instant still fits");
        assert_eq!(key.as_str().len(), MAX_OCCURRENCE_KEY_BYTES);
        let over = "a".repeat(MAX_SCHEDULED_AUTOMATION_ID_BYTES + 1);
        assert_eq!(
            AutomationOccurrenceKey::derive(&id(&over), EpochMillis::from_millis(i64::MAX)),
            Err(AutomationApiError::OccurrenceKeyTooLong {
                max_bytes: MAX_OCCURRENCE_KEY_BYTES
            }),
        );
        // The registration is where an operator meets the bound: an identity
        // the registry could hold but the lane could never fire is refused
        // before a frame is spent.
        assert!(
            RegisterAutomation::new(id(&widest), who("ben"), every(1), scope("s"), prompt("p"))
                .is_ok()
        );
        assert!(matches!(
            RegisterAutomation::new(id(&over), who("ben"), every(1), scope("s"), prompt("p")),
            Err(AutomationApiError::Field {
                field: "automation_id",
                error: automonique_protocol::primitives::ValueError::TooLong { .. },
            }),
        ));
        // And the wire re-decides it.
        let payload = format!(
            r#"{{"body":{{"actor":"ben","automation_id":"{over}","prompt":"p","schedule":"every@1","scope":"s"}},"kind":"register_automation","protocol":"automonique.automation","request_id":"r","version":1}}"#
        );
        assert!(matches!(
            AutomationRequest::from_canonical_bytes(payload.as_bytes()),
            Err(AutomationApiError::Field {
                field: "automation_id",
                ..
            }),
        ));
    }

    #[test]
    fn the_scope_and_prompt_carry_the_durable_submit_lane_s_bounds() {
        // The scope is admitted by two lanes and carries the narrower bound:
        // the scheduler core's identifier ceiling, which this crate cannot
        // import and so pins against the core's own source.
        const {
            assert!(
                MAX_AUTOMATION_SCOPE_BYTES
                    <= automonique_protocol::admin::MAX_SYNTHETIC_SCOPE_BYTES
            );
        }
        let core = sibling_source("automonique-core/src/lib.rs");
        assert!(
            core.contains(&format!(
                "const MAX_ID_BYTES: usize = {MAX_AUTOMATION_SCOPE_BYTES};"
            )),
            "the scope bound is not the scheduler core's identifier ceiling",
        );
        assert_eq!(
            MAX_AUTOMATION_PROMPT_BYTES,
            automonique_protocol::admin::MAX_SYNTHETIC_TASK_BYTES
        );
        assert_eq!(
            MAX_OCCURRENCE_KEY_BYTES,
            automonique_protocol::admin::MAX_SYNTHETIC_KEY_BYTES
        );
        assert_eq!(AutomationScope::MAX_BYTES, MAX_AUTOMATION_SCOPE_BYTES);
        assert_eq!(AutomationPrompt::MAX_BYTES, MAX_AUTOMATION_PROMPT_BYTES);

        // A scope is an identifier: control-free.
        assert!(AutomationScope::new("a".repeat(MAX_AUTOMATION_SCOPE_BYTES)).is_ok());
        for bad in ["", "ws\n1", &"a".repeat(MAX_AUTOMATION_SCOPE_BYTES + 1)] {
            assert!(
                matches!(
                    AutomationScope::new(bad),
                    Err(AutomationApiError::Field { field: "scope", .. })
                ),
                "{bad:?} was admitted as a scope",
            );
        }

        // A prompt is prose: a newline is text, a NUL is not.
        assert_eq!(prompt("line one\nline two").as_str(), "line one\nline two");
        assert!(AutomationPrompt::new("a".repeat(MAX_AUTOMATION_PROMPT_BYTES)).is_ok());
        for bad in ["", "a\0b", &"a".repeat(MAX_AUTOMATION_PROMPT_BYTES + 1)] {
            assert!(
                matches!(
                    AutomationPrompt::new(bad),
                    Err(AutomationApiError::Field {
                        field: "prompt",
                        ..
                    })
                ),
                "{bad:?} was admitted as a prompt",
            );
        }
        // The same lane's own constructor agrees on every one of them.
        for (scope_text, task) in [("s", "p"), ("s", "line one\nline two")] {
            assert!(
                automonique_protocol::admin::SyntheticSubmission::new(scope_text, "k", task)
                    .is_ok()
            );
        }
        assert!(automonique_protocol::admin::SyntheticSubmission::new("s", "k", "a\0b").is_err());
        assert!(automonique_protocol::admin::SyntheticSubmission::new("ws\n1", "k", "p").is_err());
    }

    #[test]
    fn a_record_s_job_fields_imply_one_another() {
        let parts = |schedule: Option<AutomationSchedule>,
                     scope_text: Option<&str>,
                     next: Option<i64>,
                     last: Option<i64>| AutomationRecordParts {
            entry_id: 1,
            automation_id: id("a"),
            revision: 1,
            enablement: EnablementState::Enabled,
            actor: who("ben"),
            cause: None,
            created_at: EpochMillis::EPOCH,
            updated_at: EpochMillis::EPOCH,
            schedule,
            scope: scope_text.map(scope),
            next_fire_at: next.map(EpochMillis::from_millis),
            last_fired_at: last.map(EpochMillis::from_millis),
        };
        for incoherent in [
            parts(Some(every(1)), None, None, None),
            parts(None, Some("s"), None, None),
            parts(None, None, Some(1), None),
            parts(None, None, None, Some(1)),
        ] {
            assert_eq!(
                AutomationRecordView::new(incoherent),
                Err(AutomationApiError::JobIncoherent)
            );
        }
        let bare = AutomationRecordView::new(parts(None, None, None, None)).expect("no job");
        assert!(!bare.is_scheduled());
        assert_eq!(bare.next_fire_at(), None);
        assert!(
            bare.admits_occurrence(),
            "enablement is the other half of the question"
        );
        let exhausted = AutomationRecordView::new(parts(Some(every(1)), Some("s"), None, Some(9)))
            .expect("a fired job with nothing further scheduled");
        assert!(exhausted.is_scheduled());
        assert_eq!(exhausted.last_fired_at(), Some(EpochMillis::from_millis(9)));
        assert_eq!(exhausted.scope().map(AutomationScope::as_str), Some("s"));
        assert_eq!(exhausted.schedule(), Some(&every(1)));

        // The wire re-decides the coupling.
        let scope_without_schedule = br#"{"body":{"automations":[{"actor":"ben","automation_id":"a","cause":null,"created_at_ms":0,"enablement":"enabled","entry_id":1,"last_fired_at_ms":null,"next_fire_at_ms":null,"revision":1,"schedule":null,"scope":"s","updated_at_ms":0}],"more":false,"next_cursor":null},"kind":"automation_list_result","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(scope_without_schedule),
            Err(AutomationApiError::JobIncoherent),
        );
    }

    #[test]
    fn a_detail_s_prompt_and_its_record_s_job_imply_one_another() {
        assert_eq!(
            AutomationResponse::detail(request_id(), scheduled(1, "a"), None),
            Err(AutomationApiError::JobIncoherent),
        );
        assert_eq!(
            AutomationResponse::detail(request_id(), enabled(1, "a"), Some(prompt("p"))),
            Err(AutomationApiError::JobIncoherent),
        );
        let answer = AutomationResponse::detail(request_id(), scheduled(1, "a"), Some(prompt("p")))
            .expect("coherent");
        let payload = answer.to_message().expect("encode").to_canonical_bytes();
        let text = std::str::from_utf8(&payload).expect("canonical JSON is UTF-8");
        assert!(text.contains(
            r#""next_fire_at_ms":1700000060000,"prompt":"p","revision":1,"schedule":"every@60000","scope":"workspace:reports""#
        ));
        assert_eq!(
            AutomationResponse::from_canonical_bytes(&payload).expect("decode"),
            answer
        );
        // A prompt on an unscheduled record is refused on the way in too.
        let prompt_without_job = br#"{"body":{"actor":"ben","automation_id":"a","cause":null,"created_at_ms":0,"enablement":"enabled","entry_id":1,"last_fired_at_ms":null,"next_fire_at_ms":null,"prompt":"p","revision":1,"schedule":null,"scope":null,"updated_at_ms":0},"kind":"automation_detail_result","protocol":"automonique.automation","request_id":"r","version":1}"#;
        assert_eq!(
            AutomationResponse::from_canonical_bytes(prompt_without_job),
            Err(AutomationApiError::JobIncoherent),
        );
    }

    #[test]
    fn a_registration_carries_its_job_in_canonical_order() {
        let payload = AutomationRequest::RegisterAutomation {
            request_id: request_id(),
            registration: registration("nightly-report"),
        }
        .to_message()
        .expect("encode")
        .to_canonical_bytes();
        assert_eq!(
            std::str::from_utf8(&payload).expect("UTF-8"),
            r#"{"body":{"actor":"ben","automation_id":"nightly-report","prompt":"summarize the night","schedule":"every@60000","scope":"workspace:reports"},"kind":"register_automation","protocol":"automonique.automation","request_id":"automation-1","version":1}"#,
        );
        let decoded = AutomationRequest::from_canonical_bytes(&payload).expect("decode");
        let AutomationRequest::RegisterAutomation { registration, .. } = decoded else {
            panic!("a registration decoded as something else")
        };
        assert_eq!(registration.schedule(), &every(60_000));
        assert_eq!(registration.scope().as_str(), "workspace:reports");
        assert_eq!(registration.prompt().as_str(), "summarize the night");
    }
}
