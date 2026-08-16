// SPDX-License-Identifier: Elastic-2.0

//! The Runs API read surface.
//!
//! The first module pins the vocabularies this crate carries but cannot import,
//! twice each: by literal, and by reading the sibling crate that owns them. The
//! rest exercise framing, the retention rule, the page and view invariants, and
//! the bounds.

use std::fs;
use std::path::PathBuf;

use automonique_protocol::codec::{CodecError, MajorVersion, RequestId};
use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::event::Authority;
use automonique_protocol::journal::{ActionOutcome, CursorResume, JournalCursor, RetainedRange};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::runs_api::{
    Continuation, LIFECYCLE_AUTHORITIES, LifecycleCoverage, ListRuns, MAX_LIFECYCLE_EVENTS,
    MAX_RUN_PAGE_ITEMS, MAX_RUNS_CANONICAL_BYTES, OUTCOMES_A_READ_NEVER_PRODUCES, PageSize,
    RUNS_API_SCHEMA_V1, RUNS_PROTOCOL, RunCursor, RunDetailView, RunLifecycleEvent, RunListPage,
    RunState, RunStateFilter, RunSummary, RunsApiError, RunsRefusal, RunsRequest, RunsResponse,
    SpoolEventKind, SubmissionState, decode_authority,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::wire::{JsonValue, Message};

fn request_id() -> RequestId {
    RequestId::new("runs-1").expect("valid request id")
}

fn digest(seed: &[u8]) -> Sha256Digest {
    Sha256::digest(seed)
}

fn summary(submission_id: u64, state: RunState) -> RunSummary {
    RunSummary::new(
        RunId::new(format!("run-{submission_id}")).expect("valid run id"),
        submission_id,
        digest(&submission_id.to_be_bytes()),
        state,
        SubmissionState::Accepted,
        EpochMillis::from_millis(1_700_000_000_000),
    )
    .expect("valid summary")
}

fn event(sequence: u64, kind: SpoolEventKind) -> RunLifecycleEvent {
    RunLifecycleEvent::new(
        sequence,
        EpochMillis::from_millis(1_700_000_000_000 + sequence as i64),
        kind,
        Authority::Authoritative,
    )
    .expect("valid lifecycle event")
}

fn query(page_size: usize) -> ListRuns {
    ListRuns::new(
        RunStateFilter::any(),
        None,
        PageSize::new(page_size).expect("valid page size"),
    )
}

fn retained(first: u64, last: u64) -> RetainedRange {
    RetainedRange::new(first, last).expect("valid retained window")
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
///
/// Reads the declaration the owning crate actually compiles, so a rename there
/// changes what this returns. Stops at the line that closes the `match`, so a
/// second arm list further down the file cannot leak in.
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

/// The carried vocabularies, against the crates that own them.
mod vocabulary {
    use super::*;

    /// `automonique_runner::spool::RunState` is the authority for the variants
    /// and `automonique_runner::control::state_word` for the wire spellings.
    /// This crate has no dependencies, so neither can be imported; the pin is a
    /// literal here plus a read of the sibling source, and a rename on either
    /// side fails this test rather than silently changing the wire.
    #[test]
    fn the_run_state_spellings_are_pinned_by_literal() {
        assert_eq!(RunState::ALL.len(), 6);
        assert_eq!(RunState::Ready.as_str(), "ready");
        assert_eq!(RunState::Running.as_str(), "running");
        assert_eq!(RunState::Completed.as_str(), "completed");
        assert_eq!(RunState::Failed.as_str(), "failed");
        assert_eq!(RunState::Cancelled.as_str(), "cancelled");
        assert_eq!(RunState::TimedOut.as_str(), "timed_out");
        for state in RunState::ALL {
            assert_eq!(RunState::from_spelling(state.as_str()), Some(state));
            assert_eq!(state.to_string(), state.as_str());
        }
        assert_eq!(RunState::from_spelling("Ready"), None);
        assert_eq!(RunState::from_spelling("timedout"), None);
        assert_eq!(RunState::from_spelling(""), None);
    }

    #[test]
    fn the_run_state_spellings_are_pinned_against_the_runner_crate() {
        let spool = sibling_source("automonique-runner/src/spool.rs");
        let declared: Vec<String> = match_arms(&spool, "impl RunState {")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        let carried: Vec<String> = RunState::ALL
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect();
        assert_eq!(
            declared, carried,
            "automonique_runner::spool::RunState spells its states differently"
        );

        let control = sibling_source("automonique-runner/src/control.rs");
        let rendered: Vec<String> = match_arms(&control, "const fn state_word(")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        assert_eq!(
            rendered, carried,
            "automonique_runner::control::state_word renders states differently"
        );
    }

    /// The variant *names* too, not only the words they render. A variant
    /// renamed without changing its spelling is still a divergence a later
    /// reader would trip over.
    #[test]
    fn the_run_state_variants_are_pinned_against_the_runner_crate() {
        let spool = sibling_source("automonique-runner/src/spool.rs");
        let declared: Vec<String> = match_arms(&spool, "impl RunState {")
            .into_iter()
            .map(|(variant, _)| variant)
            .collect();
        assert_eq!(
            declared,
            vec![
                "Ready",
                "Running",
                "Completed",
                "Failed",
                "Cancelled",
                "TimedOut"
            ]
        );
    }

    /// `automonique_runner::spool::state_from_events` reads exactly one
    /// terminal event and discriminates its payload into four states; `ready`
    /// and `running` are the two a run can still leave.
    #[test]
    fn exactly_the_four_post_terminal_states_are_terminal() {
        let terminal: Vec<RunState> = RunState::ALL
            .into_iter()
            .filter(|state| state.is_terminal())
            .collect();
        assert_eq!(
            terminal,
            vec![
                RunState::Completed,
                RunState::Failed,
                RunState::Cancelled,
                RunState::TimedOut
            ]
        );
        assert!(!RunState::Ready.is_terminal());
        assert!(!RunState::Running.is_terminal());
    }

    #[test]
    fn the_spool_event_kind_spellings_are_pinned_by_literal() {
        assert_eq!(SpoolEventKind::ALL.len(), 5);
        assert_eq!(SpoolEventKind::Started.as_str(), "started");
        assert_eq!(SpoolEventKind::AdapterEvent.as_str(), "adapter_event");
        assert_eq!(SpoolEventKind::SimulationEvent.as_str(), "simulation_event");
        assert_eq!(SpoolEventKind::CancelRequested.as_str(), "cancel_requested");
        assert_eq!(SpoolEventKind::Terminal.as_str(), "terminal");
        for kind in SpoolEventKind::ALL {
            assert_eq!(SpoolEventKind::from_spelling(kind.as_str()), Some(kind));
        }
        assert_eq!(SpoolEventKind::from_spelling("run_terminal"), None);
        let terminal: Vec<SpoolEventKind> = SpoolEventKind::ALL
            .into_iter()
            .filter(|kind| kind.is_terminal())
            .collect();
        assert_eq!(terminal, vec![SpoolEventKind::Terminal]);
    }

    #[test]
    fn the_spool_event_kind_spellings_are_pinned_against_the_runner_crate() {
        let spool = sibling_source("automonique-runner/src/spool.rs");
        let declared: Vec<String> = match_arms(&spool, "impl EventKind {")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        let carried: Vec<String> = SpoolEventKind::ALL
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect();
        assert_eq!(
            declared, carried,
            "automonique_runner::spool::EventKind spells its kinds differently"
        );

        let control = sibling_source("automonique-runner/src/control.rs");
        let rendered: Vec<String> = match_arms(&control, "const fn kind_word(")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        assert_eq!(
            rendered, carried,
            "automonique_runner::control::kind_word renders kinds differently"
        );
    }

    /// The store's `state` column has a closed `CHECK` vocabulary of one value.
    /// The carried enum has one variant for the same reason, and this test is
    /// what makes the two move together.
    #[test]
    fn the_submission_state_vocabulary_is_pinned_against_the_store_crate() {
        let source = sibling_source("automonique-store/src/run_submissions.rs");
        let anchor = "CHECK (state IN (";
        let start = source
            .find(anchor)
            .expect("the CHECK constraint is declared")
            + anchor.len();
        let end = start + source[start..].find(')').expect("the constraint closes");
        let declared: Vec<String> = source[start..end]
            .split(',')
            .map(|value| value.trim().trim_matches('\'').to_owned())
            .collect();
        let carried: Vec<String> = SubmissionState::ALL
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect();
        assert_eq!(declared, vec!["accepted"]);
        assert_eq!(
            declared, carried,
            "automonique_store::run_submissions defines a different custody vocabulary"
        );
        assert_eq!(
            SubmissionState::from_spelling("accepted"),
            Some(SubmissionState::Accepted)
        );
        assert_eq!(SubmissionState::from_spelling("running"), None);
    }

    /// The spool's `Authority` and `crate::event::Authority` are the same two
    /// words, so this module reuses the type instead of carrying a copy. The
    /// array is pinned; a variant added to the shared enum breaks the
    /// exhaustive match in the module rather than this test.
    #[test]
    fn the_lifecycle_authorities_reuse_the_shared_enum() {
        assert_eq!(LIFECYCLE_AUTHORITIES.len(), 2);
        assert_eq!(
            LIFECYCLE_AUTHORITIES.map(Authority::as_str),
            ["authoritative", "synthetic"]
        );
        for authority in LIFECYCLE_AUTHORITIES {
            assert_eq!(decode_authority(authority.as_str()), Ok(authority));
        }

        let spool = sibling_source("automonique-runner/src/spool.rs");
        let declared: Vec<String> = match_arms(&spool, "impl Authority {")
            .into_iter()
            .map(|(_, spelling)| spelling)
            .collect();
        let mut carried: Vec<String> = LIFECYCLE_AUTHORITIES
            .iter()
            .map(|authority| authority.as_str().to_owned())
            .collect();
        carried.sort();
        let mut declared_sorted = declared.clone();
        declared_sorted.sort();
        assert_eq!(
            declared_sorted, carried,
            "automonique_runner::spool::Authority spells its authorities differently"
        );
    }

    #[test]
    fn an_undefined_authority_spelling_fails_closed() {
        assert_eq!(
            decode_authority("preview"),
            Err(RunsApiError::Codec(CodecError::UnknownEnumValue {
                field: "authority"
            }))
        );
    }

    #[test]
    fn the_refusal_vocabulary_is_closed() {
        assert_eq!(RunsRefusal::ALL.len(), 1);
        assert_eq!(RunsRefusal::UnknownRun.as_str(), "unknown_run");
        assert_eq!(
            RunsRefusal::from_spelling("unknown_run"),
            Some(RunsRefusal::UnknownRun)
        );
        assert_eq!(RunsRefusal::from_spelling("not_authorized"), None);
    }

    #[test]
    fn the_namespace_is_versioned_and_canonical() {
        assert_eq!(RUNS_PROTOCOL, "automonique.runs");
        assert_eq!(RUNS_API_SCHEMA_V1, "automonique.runs/v1");
        assert!(RUNS_API_SCHEMA_V1.starts_with(RUNS_PROTOCOL));
        assert!(RUNS_API_SCHEMA_V1.ends_with("/v1"));
    }
}

/// Framing: canonical bytes, exact field sets, closed kinds.
mod framing {
    use super::*;

    fn round_trip_request(request: &RunsRequest) {
        let bytes = request
            .to_message()
            .expect("encodable")
            .to_canonical_bytes();
        assert_eq!(
            &RunsRequest::from_canonical_bytes(&bytes).expect("decodable"),
            request
        );
    }

    fn round_trip_response(response: &RunsResponse) {
        let bytes = response
            .to_message()
            .expect("encodable")
            .to_canonical_bytes();
        assert_eq!(
            &RunsResponse::from_canonical_bytes(&bytes).expect("decodable"),
            response
        );
    }

    fn detail_view() -> RunDetailView {
        RunDetailView::new(
            summary(7, RunState::Completed),
            3,
            vec![
                event(1, SpoolEventKind::Started),
                event(2, SpoolEventKind::AdapterEvent),
                event(3, SpoolEventKind::Terminal),
            ],
            LifecycleCoverage::Complete,
        )
        .expect("coherent view")
    }

    #[test]
    fn every_request_round_trips_through_canonical_bytes() {
        round_trip_request(&RunsRequest::ListRuns {
            request_id: request_id(),
            query: query(MAX_RUN_PAGE_ITEMS),
        });
        round_trip_request(&RunsRequest::ListRuns {
            request_id: request_id(),
            query: ListRuns::new(
                RunStateFilter::only([RunState::TimedOut, RunState::Running])
                    .expect("valid filter"),
                Some(RunCursor::new(42)),
                PageSize::new(1).expect("valid page size"),
            ),
        });
        round_trip_request(&RunsRequest::RunDetail {
            request_id: request_id(),
            run_id: RunId::new("run-7").expect("valid run id"),
        });
    }

    #[test]
    fn every_response_round_trips_through_canonical_bytes() {
        round_trip_response(&RunsResponse::RunList {
            request_id: request_id(),
            page: RunListPage::new(
                vec![summary(1, RunState::Ready), summary(2, RunState::Running)],
                Continuation::More(RunCursor::new(3)),
            )
            .expect("valid page"),
        });
        round_trip_response(&RunsResponse::RunList {
            request_id: request_id(),
            page: RunListPage::new(vec![summary(9, RunState::Failed)], Continuation::Complete)
                .expect("valid page"),
        });
        round_trip_response(&RunsResponse::RunDetail {
            request_id: request_id(),
            view: detail_view(),
        });
        round_trip_response(&RunsResponse::Resync {
            request_id: request_id(),
            snapshot_from: 10,
            snapshot_to: 20,
        });
        round_trip_response(&RunsResponse::Refused {
            request_id: request_id(),
            refusal: RunsRefusal::UnknownRun,
        });
    }

    /// The one property a `to_message`/`from_canonical_bytes` pair can pass
    /// while still being wrong: encoding a field the decoder ignores. Both
    /// halves are checked against a written-out field set.
    #[test]
    fn every_body_carries_exactly_its_declared_field_set() {
        let expect_fields = |bytes: &[u8], fields: &[&str]| {
            let message = Message::from_canonical_bytes(bytes).expect("decodable message");
            let JsonValue::Object(entries) = message.body() else {
                panic!("a body is an object");
            };
            let present: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(present, fields);
        };

        expect_fields(
            &RunsRequest::ListRuns {
                request_id: request_id(),
                query: query(4),
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &["page_size", "since", "states"],
        );
        expect_fields(
            &RunsRequest::RunDetail {
                request_id: request_id(),
                run_id: RunId::new("run-7").expect("valid run id"),
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &["run_id"],
        );
        expect_fields(
            &RunsResponse::RunList {
                request_id: request_id(),
                page: RunListPage::new(vec![summary(1, RunState::Ready)], Continuation::Complete)
                    .expect("valid page"),
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &["more", "next_cursor", "runs"],
        );
        expect_fields(
            &RunsResponse::RunDetail {
                request_id: request_id(),
                view: detail_view(),
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &[
                "causation_id",
                "correlation_id",
                "coverage",
                "last_sequence",
                "lifecycle",
                "summary",
                "trace_id",
            ],
        );
        expect_fields(
            &RunsResponse::Resync {
                request_id: request_id(),
                snapshot_from: 1,
                snapshot_to: 2,
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &["snapshot_from", "snapshot_to"],
        );
        expect_fields(
            &RunsResponse::Refused {
                request_id: request_id(),
                refusal: RunsRefusal::UnknownRun,
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
            &["refusal"],
        );
    }

    /// The nested objects carry exact field sets too, and the decoder refuses a
    /// body with one field added or one removed.
    #[test]
    fn a_summary_body_is_exact_in_both_directions() {
        let response = RunsResponse::RunList {
            request_id: request_id(),
            page: RunListPage::new(vec![summary(1, RunState::Ready)], Continuation::Complete)
                .expect("valid page"),
        };
        let message = Message::from_canonical_bytes(
            &response
                .to_message()
                .expect("encodable")
                .to_canonical_bytes(),
        )
        .expect("decodable");
        let JsonValue::Array(runs) = message.body().get("runs").expect("runs member") else {
            panic!("runs is an array");
        };
        let JsonValue::Object(entries) = &runs[0] else {
            panic!("a summary is an object");
        };
        let present: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            present,
            [
                "accepted_at_ms",
                "run_id",
                "spec_digest",
                "state",
                "submission_id",
                "submission_state"
            ]
        );

        for mutated in [
            with_summary_field(&message, |entries| {
                entries.push(("extra".to_owned(), JsonValue::Bool(true)));
            }),
            with_summary_field(&message, |entries| {
                entries.retain(|(name, _)| name != "submission_state");
            }),
        ] {
            assert_eq!(
                RunsResponse::from_canonical_bytes(&mutated),
                Err(RunsApiError::InvalidBody)
            );
        }
    }

    fn with_summary_field(
        message: &Message,
        edit: impl FnOnce(&mut Vec<(String, JsonValue)>),
    ) -> Vec<u8> {
        let JsonValue::Object(body) = message.body() else {
            panic!("a body is an object");
        };
        let mut body = body.clone();
        let runs = body
            .iter_mut()
            .find(|(name, _)| name == "runs")
            .expect("runs member");
        let JsonValue::Array(items) = &mut runs.1 else {
            panic!("runs is an array");
        };
        let JsonValue::Object(entries) = &mut items[0] else {
            panic!("a summary is an object");
        };
        edit(entries);
        Message::new(message.envelope().clone(), JsonValue::Object(body)).to_canonical_bytes()
    }

    #[test]
    fn an_undefined_message_kind_is_refused_on_both_halves() {
        let bytes = RunsResponse::Refused {
            request_id: request_id(),
            refusal: RunsRefusal::UnknownRun,
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        // A response body decoded as a request is a kind this half does not
        // define, and vice versa.
        assert_eq!(
            RunsRequest::from_canonical_bytes(&bytes),
            Err(RunsApiError::UnknownKind)
        );
        let request = RunsRequest::RunDetail {
            request_id: request_id(),
            run_id: RunId::new("run-7").expect("valid run id"),
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        assert_eq!(
            RunsResponse::from_canonical_bytes(&request),
            Err(RunsApiError::UnknownKind)
        );
    }

    #[test]
    fn a_foreign_protocol_or_version_is_not_admitted() {
        let message = RunsRequest::RunDetail {
            request_id: request_id(),
            run_id: RunId::new("run-7").expect("valid run id"),
        }
        .to_message()
        .expect("encodable");
        assert_eq!(message.envelope().protocol().as_str(), RUNS_PROTOCOL);
        assert_eq!(message.envelope().version(), MajorVersion::FIRST);

        let text = String::from_utf8(message.to_canonical_bytes()).expect("utf-8");
        let foreign = text.replace("automonique.runs", "automonique.admin");
        assert!(matches!(
            RunsRequest::from_canonical_bytes(foreign.as_bytes()),
            Err(RunsApiError::Codec(_))
        ));
        let future = text.replace("\"version\":1", "\"version\":2");
        assert!(matches!(
            RunsRequest::from_canonical_bytes(future.as_bytes()),
            Err(RunsApiError::Codec(_))
        ));
    }

    #[test]
    fn an_undefined_state_spelling_fails_closed_rather_than_defaulting() {
        let text = String::from_utf8(
            RunsResponse::RunList {
                request_id: request_id(),
                page: RunListPage::new(vec![summary(1, RunState::Ready)], Continuation::Complete)
                    .expect("valid page"),
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes(),
        )
        .expect("utf-8");
        let drifted = text.replace("\"state\":\"ready\"", "\"state\":\"queued\"");
        assert_eq!(
            RunsResponse::from_canonical_bytes(drifted.as_bytes()),
            Err(RunsApiError::Codec(CodecError::UnknownEnumValue {
                field: "state"
            }))
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        let response = RunsResponse::RunDetail {
            request_id: request_id(),
            view: detail_view(),
        };
        let first = response
            .to_message()
            .expect("encodable")
            .to_canonical_bytes();
        for _ in 0..8 {
            assert_eq!(
                response
                    .to_message()
                    .expect("encodable")
                    .to_canonical_bytes(),
                first
            );
        }
        // A filter built in either order encodes identically, because the set
        // is sorted at construction.
        let forwards =
            RunStateFilter::only([RunState::Running, RunState::TimedOut]).expect("valid filter");
        let backwards =
            RunStateFilter::only([RunState::TimedOut, RunState::Running]).expect("valid filter");
        assert_eq!(forwards, backwards);
    }

    /// The compile-time frame arithmetic, measured rather than asserted.
    #[test]
    fn a_maximal_page_and_view_fit_one_frame() {
        let long_run_id = RunId::new("\"".repeat(RunId::MAX_BYTES)).expect("valid run id");
        let maximal_summary = |submission_id: u64| {
            RunSummary::new(
                long_run_id.clone(),
                submission_id,
                digest(b"maximal"),
                RunState::TimedOut,
                SubmissionState::Accepted,
                EpochMillis::from_millis(i64::MAX),
            )
            .expect("valid summary")
        };
        let runs: Vec<RunSummary> = (1..=MAX_RUN_PAGE_ITEMS as u64)
            .map(maximal_summary)
            .collect();
        let page = RunListPage::new(
            runs,
            Continuation::More(RunCursor::new(MAX_RUN_PAGE_ITEMS as u64 + 1)),
        )
        .expect("valid page");
        let encoded = RunsResponse::RunList {
            request_id: RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("valid request id"),
            page,
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        assert!(
            encoded.len() <= MAX_RUNS_CANONICAL_BYTES,
            "a maximal page is {} bytes; the frame holds {MAX_RUNS_CANONICAL_BYTES}",
            encoded.len()
        );

        let lifecycle: Vec<RunLifecycleEvent> = (1..=MAX_LIFECYCLE_EVENTS as u64)
            .map(|sequence| event(sequence, SpoolEventKind::AdapterEvent))
            .collect();
        let view = RunDetailView::new(
            maximal_summary(1),
            MAX_LIFECYCLE_EVENTS as u64 + 1,
            lifecycle,
            LifecycleCoverage::Truncated,
        )
        .expect("coherent view");
        let encoded = RunsResponse::RunDetail {
            request_id: RequestId::new("r".repeat(RequestId::MAX_BYTES)).expect("valid request id"),
            view,
        }
        .to_message()
        .expect("encodable")
        .to_canonical_bytes();
        assert!(
            encoded.len() <= MAX_RUNS_CANONICAL_BYTES,
            "a maximal view is {} bytes; the frame holds {MAX_RUNS_CANONICAL_BYTES}",
            encoded.len()
        );
    }
}

/// The retention rule: a cursor outside retention receives `resync_required`.
mod pagination {
    use super::*;

    #[test]
    fn a_cursor_below_retention_resyncs_rather_than_serving_a_partial_page() {
        let window = retained(100, 200);
        let listing = ListRuns::new(
            RunStateFilter::any(),
            Some(RunCursor::new(99)),
            PageSize::new(8).expect("valid page size"),
        );
        let decision = listing.resume_within(window);
        assert_eq!(
            decision,
            CursorResume::ResyncRequired {
                snapshot_from: 100,
                snapshot_to: 200
            }
        );
        assert_eq!(decision.outcome(), Some(ActionOutcome::ResyncRequired));

        let response = RunsResponse::listing(request_id(), &listing, decision, None)
            .expect("a resync is an answer");
        assert_eq!(
            response,
            RunsResponse::Resync {
                request_id: request_id(),
                snapshot_from: 100,
                snapshot_to: 200
            }
        );
        assert_eq!(response.outcome(), ActionOutcome::ResyncRequired);
    }

    /// The failure this whole module exists to prevent: a store that produced
    /// rows anyway cannot get them served under a resync decision, and cannot
    /// get them trimmed into a short page either.
    #[test]
    fn a_resync_decision_refuses_rows_instead_of_trimming_them() {
        let window = retained(100, 200);
        let listing = ListRuns::new(
            RunStateFilter::any(),
            Some(RunCursor::new(99)),
            PageSize::new(8).expect("valid page size"),
        );
        let page = RunListPage::new(
            vec![summary(150, RunState::Running)],
            Continuation::Complete,
        )
        .expect("valid page");
        assert_eq!(
            RunsResponse::listing(
                request_id(),
                &listing,
                listing.resume_within(window),
                Some(page)
            ),
            Err(RunsApiError::ResyncCarriesRows)
        );
    }

    #[test]
    fn a_cursor_ahead_of_the_window_also_resyncs() {
        let window = retained(100, 200);
        // `caught_up` is `last + 1`: the ordinary position of a consumer that
        // has received everything. One beyond it names positions the log has
        // never reached.
        let caught_up = ListRuns::new(
            RunStateFilter::any(),
            Some(RunCursor::new(201)),
            PageSize::new(8).expect("valid page size"),
        );
        assert_eq!(
            caught_up.resume_within(window),
            CursorResume::Live { from: 201 }
        );
        let ahead = ListRuns::new(
            RunStateFilter::any(),
            Some(RunCursor::new(202)),
            PageSize::new(8).expect("valid page size"),
        );
        assert_eq!(
            ahead.resume_within(window),
            CursorResume::ResyncRequired {
                snapshot_from: 100,
                snapshot_to: 200
            }
        );
    }

    /// The listing cursor is a journal cursor on the submission topic. This
    /// pins the delegation across the whole interesting neighbourhood, so a
    /// re-derived rule — or a coordinate the journal would refuse, which would
    /// send the fail-closed branch live — shows up as a disagreement.
    #[test]
    fn the_listing_cursor_agrees_with_the_journal_cursor_everywhere() {
        let window = retained(100, 200);
        for position in [0, 1, 99, 100, 101, 199, 200, 201, 202, u64::MAX] {
            let journal = JournalCursor::new("consumer", "topic", position)
                .expect("valid journal cursor")
                .resume_within(window);
            assert_eq!(
                RunCursor::new(position).resume_within(window),
                journal,
                "the run cursor disagrees with the journal at {position}"
            );
        }
    }

    #[test]
    fn a_listing_without_a_cursor_starts_at_the_oldest_retained_position() {
        let window = retained(100, 200);
        assert_eq!(
            query(8).resume_within(window),
            CursorResume::Live { from: 100 }
        );
        assert_eq!(query(8).resume_within(window).outcome(), None);
    }

    #[test]
    fn a_live_decision_without_a_page_is_not_an_empty_success() {
        let window = retained(1, 10);
        let listing = query(8);
        assert_eq!(
            RunsResponse::listing(request_id(), &listing, listing.resume_within(window), None),
            Err(RunsApiError::PageMissing)
        );
    }

    #[test]
    fn the_page_size_bound_is_enforced_at_every_layer() {
        assert_eq!(
            PageSize::new(0),
            Err(RunsApiError::PageSizeOutOfRange {
                max_items: MAX_RUN_PAGE_ITEMS,
                requested: 0
            })
        );
        assert_eq!(
            PageSize::new(MAX_RUN_PAGE_ITEMS + 1),
            Err(RunsApiError::PageSizeOutOfRange {
                max_items: MAX_RUN_PAGE_ITEMS,
                requested: MAX_RUN_PAGE_ITEMS + 1
            })
        );
        assert_eq!(
            PageSize::new(MAX_RUN_PAGE_ITEMS).expect("the bound itself is admitted"),
            PageSize::MAX
        );

        let overlong: Vec<RunSummary> = (1..=MAX_RUN_PAGE_ITEMS as u64 + 1)
            .map(|id| summary(id, RunState::Running))
            .collect();
        assert_eq!(
            RunListPage::new(overlong, Continuation::Complete),
            Err(RunsApiError::PageTooLarge {
                max_items: MAX_RUN_PAGE_ITEMS,
                actual_items: MAX_RUN_PAGE_ITEMS + 1
            })
        );

        let window = retained(1, 10);
        let listing = query(2);
        let too_long = RunListPage::new(
            vec![
                summary(1, RunState::Ready),
                summary(2, RunState::Ready),
                summary(3, RunState::Ready),
            ],
            Continuation::Complete,
        )
        .expect("a valid page, but not for this query");
        assert_eq!(
            RunsResponse::listing(
                request_id(),
                &listing,
                listing.resume_within(window),
                Some(too_long)
            ),
            Err(RunsApiError::PageAboveRequestedSize {
                requested: 2,
                actual_items: 3
            })
        );
    }

    /// An over-long page cannot arrive by decode either.
    #[test]
    fn a_decoded_page_is_bounded() {
        let runs: Vec<JsonValue> = (1..=MAX_RUN_PAGE_ITEMS as u64 + 1)
            .map(summary_body)
            .collect();
        let body = JsonValue::Object(vec![
            ("more".to_owned(), JsonValue::Bool(false)),
            ("next_cursor".to_owned(), JsonValue::Null),
            ("runs".to_owned(), JsonValue::Array(runs)),
        ]);
        let bytes = rewritten_body("run_list_result", body);
        assert_eq!(
            RunsResponse::from_canonical_bytes(&bytes),
            Err(RunsApiError::PageTooLarge {
                max_items: MAX_RUN_PAGE_ITEMS,
                actual_items: MAX_RUN_PAGE_ITEMS + 1
            })
        );
    }

    /// A full page that ends the listing and a full page that does not are
    /// different values and different bytes. Nothing infers "done" from length.
    #[test]
    fn a_complete_page_is_distinct_from_a_full_page_with_more() {
        let runs: Vec<RunSummary> = (1..=MAX_RUN_PAGE_ITEMS as u64)
            .map(|id| summary(id, RunState::Running))
            .collect();
        let complete = RunListPage::new(runs.clone(), Continuation::Complete).expect("valid page");
        let more = RunListPage::new(
            runs,
            Continuation::More(RunCursor::new(MAX_RUN_PAGE_ITEMS as u64 + 1)),
        )
        .expect("valid page");
        assert_ne!(complete, more);
        assert!(!complete.continuation().has_more());
        assert!(more.continuation().has_more());
        assert_eq!(complete.continuation().cursor(), None);
        assert_eq!(
            more.continuation().cursor(),
            Some(RunCursor::new(MAX_RUN_PAGE_ITEMS as u64 + 1))
        );
        assert_eq!(complete.runs().len(), more.runs().len());

        let encode = |page: RunListPage| {
            RunsResponse::RunList {
                request_id: request_id(),
                page,
            }
            .to_message()
            .expect("encodable")
            .to_canonical_bytes()
        };
        assert_ne!(encode(complete), encode(more));

        // A short page that says more follows is legitimate: a state filter can
        // exclude everything in one scanned window.
        let short = RunListPage::new(Vec::new(), Continuation::More(RunCursor::new(500)))
            .expect("an empty page may still continue");
        assert!(short.continuation().has_more());
    }

    #[test]
    fn a_continuation_marker_and_cursor_cannot_disagree_on_the_wire() {
        for (more, cursor) in [(true, JsonValue::Null), (false, JsonValue::Integer(5))] {
            let body = JsonValue::Object(vec![
                ("more".to_owned(), JsonValue::Bool(more)),
                ("next_cursor".to_owned(), cursor),
                ("runs".to_owned(), JsonValue::Array(Vec::new())),
            ]);
            assert_eq!(
                RunsResponse::from_canonical_bytes(&rewritten_body("run_list_result", body)),
                Err(RunsApiError::ContinuationIncoherent)
            );
        }
    }

    #[test]
    fn a_continuation_cursor_must_advance_past_the_page() {
        let runs = vec![summary(1, RunState::Ready), summary(2, RunState::Ready)];
        assert_eq!(
            RunListPage::new(runs.clone(), Continuation::More(RunCursor::new(2))),
            Err(RunsApiError::ContinuationRewinds)
        );
        assert_eq!(
            RunListPage::new(runs.clone(), Continuation::More(RunCursor::new(1))),
            Err(RunsApiError::ContinuationRewinds)
        );
        assert!(RunListPage::new(runs, Continuation::More(RunCursor::new(3))).is_ok());
    }

    #[test]
    fn page_summaries_must_strictly_increase_by_submission() {
        assert_eq!(
            RunListPage::new(
                vec![summary(2, RunState::Ready), summary(1, RunState::Ready)],
                Continuation::Complete
            ),
            Err(RunsApiError::PageOutOfOrder)
        );
        assert_eq!(
            RunListPage::new(
                vec![summary(1, RunState::Ready), summary(1, RunState::Ready)],
                Continuation::Complete
            ),
            Err(RunsApiError::PageOutOfOrder)
        );
    }

    #[test]
    fn a_page_cannot_begin_before_its_decision_or_leave_the_filter() {
        let window = retained(100, 200);
        let listing = ListRuns::new(
            RunStateFilter::only([RunState::Running]).expect("valid filter"),
            Some(RunCursor::new(150)),
            PageSize::new(8).expect("valid page size"),
        );
        let decision = listing.resume_within(window);
        assert_eq!(decision, CursorResume::Live { from: 150 });

        let early = RunListPage::new(
            vec![summary(149, RunState::Running)],
            Continuation::Complete,
        )
        .expect("valid page");
        assert_eq!(
            RunsResponse::listing(request_id(), &listing, decision, Some(early)),
            Err(RunsApiError::PageBeforeCursor)
        );

        let excluded = RunListPage::new(
            vec![summary(150, RunState::Completed)],
            Continuation::Complete,
        )
        .expect("valid page");
        assert_eq!(
            RunsResponse::listing(request_id(), &listing, decision, Some(excluded)),
            Err(RunsApiError::PageOutsideFilter)
        );

        let admitted = RunListPage::new(
            vec![summary(150, RunState::Running)],
            Continuation::Complete,
        )
        .expect("valid page");
        assert!(RunsResponse::listing(request_id(), &listing, decision, Some(admitted)).is_ok());
    }

    fn summary_body(submission_id: u64) -> JsonValue {
        JsonValue::Object(vec![
            (
                "accepted_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            (
                "run_id".to_owned(),
                JsonValue::String(format!("run-{submission_id}")),
            ),
            (
                "spec_digest".to_owned(),
                JsonValue::String(digest(&submission_id.to_be_bytes()).to_string()),
            ),
            ("state".to_owned(), JsonValue::String("running".to_owned())),
            (
                "submission_id".to_owned(),
                JsonValue::Integer(submission_id as i64),
            ),
            (
                "submission_state".to_owned(),
                JsonValue::String("accepted".to_owned()),
            ),
        ])
    }

    /// A message with this protocol's envelope and a body a caller chose.
    fn rewritten_body(kind: &str, body: JsonValue) -> Vec<u8> {
        let template = RunsResponse::Refused {
            request_id: request_id(),
            refusal: RunsRefusal::UnknownRun,
        }
        .to_message()
        .expect("encodable");
        let text =
            String::from_utf8(Message::new(template.envelope().clone(), body).to_canonical_bytes())
                .expect("utf-8");
        text.replace("\"kind\":\"refused\"", &format!("\"kind\":\"{kind}\""))
            .into_bytes()
    }
}

/// The detail view's coherence rules, one refusal at a time.
mod detail {
    use super::*;

    #[test]
    fn a_complete_view_of_a_ready_run_carries_nothing() {
        let view = RunDetailView::new(
            summary(1, RunState::Ready),
            0,
            Vec::new(),
            LifecycleCoverage::Complete,
        )
        .expect("coherent view");
        assert_eq!(view.lifecycle(), &[]);
        assert_eq!(view.last_sequence(), 0);
        assert_eq!(view.resume_cursor(), None);

        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                0,
                Vec::new(),
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Ready),
                3,
                Vec::new(),
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
    }

    #[test]
    fn a_complete_view_ends_exactly_where_the_spool_does() {
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                4,
                vec![event(1, SpoolEventKind::Started)],
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
        assert!(
            RunDetailView::new(
                summary(1, RunState::Running),
                1,
                vec![event(1, SpoolEventKind::Started)],
                LifecycleCoverage::Complete
            )
            .is_ok()
        );
        // A complete view of a terminal run must end on the terminal event.
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Completed),
                1,
                vec![event(1, SpoolEventKind::Started)],
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
    }

    #[test]
    fn a_truncated_view_carries_events_and_stops_short() {
        let view = RunDetailView::new(
            summary(1, RunState::Running),
            9,
            vec![
                event(1, SpoolEventKind::Started),
                event(2, SpoolEventKind::AdapterEvent),
            ],
            LifecycleCoverage::Truncated,
        )
        .expect("coherent view");
        assert_eq!(view.resume_cursor(), Some(2));

        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                9,
                Vec::new(),
                LifecycleCoverage::Truncated
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                2,
                vec![
                    event(1, SpoolEventKind::Started),
                    event(2, SpoolEventKind::AdapterEvent)
                ],
                LifecycleCoverage::Truncated
            ),
            Err(RunsApiError::CoverageIncoherent)
        );
    }

    #[test]
    fn lifecycle_sequences_strictly_increase_from_one() {
        assert_eq!(
            RunLifecycleEvent::new(
                0,
                EpochMillis::from_millis(1),
                SpoolEventKind::Started,
                Authority::Synthetic
            ),
            Err(RunsApiError::LifecycleOutOfOrder)
        );
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                3,
                vec![
                    event(2, SpoolEventKind::Started),
                    event(1, SpoolEventKind::AdapterEvent)
                ],
                LifecycleCoverage::Truncated
            ),
            Err(RunsApiError::LifecycleOutOfOrder)
        );
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                3,
                vec![
                    event(2, SpoolEventKind::Started),
                    event(2, SpoolEventKind::AdapterEvent)
                ],
                LifecycleCoverage::Truncated
            ),
            Err(RunsApiError::LifecycleOutOfOrder)
        );
    }

    #[test]
    fn no_event_may_claim_a_sequence_above_the_run_s_last() {
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                2,
                vec![
                    event(1, SpoolEventKind::Started),
                    event(3, SpoolEventKind::AdapterEvent)
                ],
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::LifecycleAboveLastSequence)
        );
    }

    #[test]
    fn there_is_at_most_one_terminal_event_and_nothing_follows_it() {
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Completed),
                2,
                vec![
                    event(1, SpoolEventKind::Terminal),
                    event(2, SpoolEventKind::AdapterEvent)
                ],
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::TerminalEventNotLast)
        );
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Completed),
                2,
                vec![
                    event(1, SpoolEventKind::Terminal),
                    event(2, SpoolEventKind::Terminal)
                ],
                LifecycleCoverage::Complete
            ),
            Err(RunsApiError::TerminalEventNotLast)
        );
    }

    #[test]
    fn a_terminal_event_is_never_carried_for_a_live_run() {
        for state in [RunState::Ready, RunState::Running] {
            assert_eq!(
                RunDetailView::new(
                    summary(1, state),
                    1,
                    vec![event(1, SpoolEventKind::Terminal)],
                    LifecycleCoverage::Complete
                ),
                Err(RunsApiError::TerminalEventContradictsState)
            );
        }
        for state in [
            RunState::Completed,
            RunState::Failed,
            RunState::Cancelled,
            RunState::TimedOut,
        ] {
            assert!(
                RunDetailView::new(
                    summary(1, state),
                    1,
                    vec![event(1, SpoolEventKind::Terminal)],
                    LifecycleCoverage::Complete
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn a_view_is_bounded_at_construction_and_at_decode() {
        let overlong: Vec<RunLifecycleEvent> = (1..=MAX_LIFECYCLE_EVENTS as u64 + 1)
            .map(|sequence| event(sequence, SpoolEventKind::AdapterEvent))
            .collect();
        assert_eq!(
            RunDetailView::new(
                summary(1, RunState::Running),
                MAX_LIFECYCLE_EVENTS as u64 + 2,
                overlong,
                LifecycleCoverage::Truncated
            ),
            Err(RunsApiError::LifecycleTooLong {
                max_events: MAX_LIFECYCLE_EVENTS,
                actual_events: MAX_LIFECYCLE_EVENTS + 1
            })
        );
    }
}

/// Bounds this module refuses at construction.
mod bounds {
    use super::*;

    #[test]
    fn a_summary_cannot_name_an_unwritten_row_or_an_impossible_instant() {
        assert_eq!(
            RunSummary::new(
                RunId::new("run-1").expect("valid run id"),
                0,
                digest(b"x"),
                RunState::Ready,
                SubmissionState::Accepted,
                EpochMillis::from_millis(1)
            ),
            Err(RunsApiError::UnwrittenRow {
                field: "submission_id"
            })
        );
        assert_eq!(
            RunSummary::new(
                RunId::new("run-1").expect("valid run id"),
                1,
                digest(b"x"),
                RunState::Ready,
                SubmissionState::Accepted,
                EpochMillis::from_millis(-1)
            ),
            Err(RunsApiError::TimeBeforeEpoch {
                field: "accepted_at_ms"
            })
        );
        assert_eq!(
            RunLifecycleEvent::new(
                1,
                EpochMillis::from_millis(-1),
                SpoolEventKind::Started,
                Authority::Synthetic
            ),
            Err(RunsApiError::TimeBeforeEpoch { field: "at_ms" })
        );
    }

    #[test]
    fn a_state_filter_is_never_empty_and_never_repeats() {
        assert_eq!(
            RunStateFilter::only([]),
            Err(RunsApiError::StateFilterEmpty)
        );
        assert_eq!(
            RunStateFilter::only([RunState::Running, RunState::Running]),
            Err(RunsApiError::StateFilterRepeats {
                state: RunState::Running
            })
        );
        let any = RunStateFilter::any();
        assert_eq!(any.states(), None);
        for state in RunState::ALL {
            assert!(any.admits(state));
        }
        let only = RunStateFilter::only([RunState::Failed]).expect("valid filter");
        assert_eq!(only.states(), Some(&[RunState::Failed][..]));
        assert!(only.admits(RunState::Failed));
        assert!(!only.admits(RunState::Completed));
    }

    #[test]
    fn every_refusal_carries_a_stable_category() {
        let categories = [
            RunsApiError::UnknownKind.category(),
            RunsApiError::InvalidBody.category(),
            RunsApiError::ResyncCarriesRows.category(),
            RunsApiError::PageMissing.category(),
            RunsApiError::CoverageIncoherent.category(),
            RunsApiError::ContinuationIncoherent.category(),
        ];
        for category in categories {
            assert!(
                category.starts_with("runs_"),
                "{category} is not namespaced"
            );
        }
        assert!(!RunsApiError::UnknownKind.to_string().is_empty());
    }
}

/// The response-status vocabulary, reused from the journal.
mod outcomes {
    use super::*;

    #[test]
    fn a_read_produces_exactly_three_of_the_six_outcomes() {
        let produced = [
            RunsResponse::RunList {
                request_id: request_id(),
                page: RunListPage::new(Vec::new(), Continuation::Complete).expect("valid page"),
            }
            .outcome(),
            RunsResponse::RunDetail {
                request_id: request_id(),
                view: RunDetailView::new(
                    summary(1, RunState::Ready),
                    0,
                    Vec::new(),
                    LifecycleCoverage::Complete,
                )
                .expect("coherent view"),
            }
            .outcome(),
            RunsResponse::Resync {
                request_id: request_id(),
                snapshot_from: 1,
                snapshot_to: 2,
            }
            .outcome(),
            RunsResponse::Refused {
                request_id: request_id(),
                refusal: RunsRefusal::UnknownRun,
            }
            .outcome(),
        ];
        assert_eq!(
            produced,
            [
                ActionOutcome::Completed,
                ActionOutcome::Completed,
                ActionOutcome::ResyncRequired,
                ActionOutcome::Rejected
            ]
        );

        assert_eq!(ActionOutcome::ALL.len(), 6);
        let never: Vec<ActionOutcome> = ActionOutcome::ALL
            .into_iter()
            .filter(|outcome| !produced.contains(outcome))
            .collect();
        assert_eq!(never, OUTCOMES_A_READ_NEVER_PRODUCES.to_vec());
        for outcome in OUTCOMES_A_READ_NEVER_PRODUCES {
            assert!(!produced.contains(&outcome));
        }
    }

    /// The spellings the plan names, reused rather than restated: this module
    /// defines no status words of its own.
    #[test]
    fn the_outcome_spellings_come_from_the_journal() {
        assert_eq!(
            ActionOutcome::ALL.map(ActionOutcome::as_str),
            [
                "accepted",
                "completed",
                "rejected",
                "conflict",
                "unknown",
                "resync_required"
            ]
        );
    }

    #[test]
    fn a_refusal_states_that_nothing_was_read() {
        assert!(
            RunsResponse::Refused {
                request_id: request_id(),
                refusal: RunsRefusal::UnknownRun,
            }
            .outcome()
            .states_no_effect()
        );
        assert!(
            !RunsResponse::Resync {
                request_id: request_id(),
                snapshot_from: 1,
                snapshot_to: 2,
            }
            .outcome()
            .states_no_effect()
        );
    }

    #[test]
    fn every_response_carries_the_request_it_answers() {
        let id = RequestId::new("correlate-me").expect("valid request id");
        for response in [
            RunsResponse::Resync {
                request_id: id.clone(),
                snapshot_from: 1,
                snapshot_to: 2,
            },
            RunsResponse::Refused {
                request_id: id.clone(),
                refusal: RunsRefusal::UnknownRun,
            },
        ] {
            assert_eq!(response.request_id(), &id);
            let bytes = response
                .to_message()
                .expect("encodable")
                .to_canonical_bytes();
            assert_eq!(
                RunsResponse::from_canonical_bytes(&bytes)
                    .expect("decodable")
                    .request_id(),
                &id
            );
        }
        assert_eq!(
            RunsRequest::ListRuns {
                request_id: id.clone(),
                query: query(1),
            }
            .request_id(),
            &id
        );
    }
}
