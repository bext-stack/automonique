// SPDX-License-Identifier: Elastic-2.0

//! Deterministic replay of the golden-trace corpus.
//!
//! This is the deliverable of the corpus, not the corpus itself: every fixture
//! under `tests/fixtures/parity/` is replayed against the real router with the
//! shadow surfaces, and every position of every diff has to classify parity or
//! known-deviation. An unaccounted position is a regression and fails here.
//!
//! # What a synthetic fixture proves, and what it does not
//!
//! The fixtures in this corpus carry `provenance: synthetic`. Their reference
//! envelopes were minted from this build's own decisions, so they pin *current
//! behaviour*: a change that alters what the router decides fails this test, and
//! that is what they are for. They are **not** evidence of parity with the
//! reference engine — only a fixture whose reference envelopes were captured
//! from that engine's real messages (`provenance: captured`) is that, and the
//! capture tool anonymizes those at capture time.
//!
//! Stating the difference matters because the weighted score treats both alike
//! once they carry a category. A corpus of synthetic fixtures can reach a high
//! score while proving nothing about the reference engine, which is exactly why
//! `production-representative` carries three times the weight of `happy`.
//!
//! # The mismatch ritual
//!
//! One command: `python3 tools/parity/traces.py export --database <shadow db>
//! --scope <scope> --parity-row <ledger key> --category <category> --output
//! <this directory>/<scope>`. The tool anonymizes structured identifiers at
//! capture; the `.cjson` it produces is part of the corpus from the next run of
//! this test with no other step. Note what an export carries and does not —
//! `tools/parity/traces.py`'s own documentation states it: the shadow database
//! retains intended actions, not the inbound events that provoked them, so an
//! exported trace is a *comparison* trace and a *replay* trace additionally
//! needs the events.

use std::path::{Path, PathBuf};

use automonique_daemon::parity_trace::{REPLAY_CLOCK_MS, Trace, TraceError, TraceRecord, replay};
use automonique_protocol::parity::{
    Category, Classification, ComparisonVerdict, DeviationEntry, DeviationRegistry, ParityEngine,
    ParityScore, ScoredComparison,
};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parity")
}

/// Every fixture in the corpus, sorted so a failure names the same file twice.
fn fixtures() -> Vec<PathBuf> {
    let mut found = Vec::new();
    let scopes = std::fs::read_dir(corpus_root()).expect("the corpus directory exists");
    for scope in scopes {
        let scope = scope.expect("a corpus entry").path();
        if !scope.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&scope).expect("a scope directory") {
            let path = entry.expect("a fixture entry").path();
            if path
                .extension()
                .is_some_and(|extension| extension == "cjson")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    assert!(!found.is_empty(), "the corpus must not be empty");
    found
}

fn load(path: &Path) -> Trace {
    let bytes = std::fs::read(path).expect("fixture is readable");
    Trace::from_lines(&bytes)
        .unwrap_or_else(|error| panic!("{} is not a trace: {error}", path.display()))
}

fn name(path: &Path) -> String {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn every_fixture_replays_to_parity_or_a_registered_deviation() {
    let registry = DeviationRegistry::empty();
    for path in fixtures() {
        let trace = load(&path);
        let outcome = replay(&trace, &registry)
            .unwrap_or_else(|error| panic!("{} did not replay: {error}", path.display()));
        let regressions = outcome.regressions();
        assert!(
            regressions.is_empty(),
            "{} regressed at {} position(s): {:?}",
            name(&path),
            regressions.len(),
            regressions
                .iter()
                .map(|difference| (
                    difference.sequence,
                    difference.comparison.verdict().as_str(),
                    difference.comparison.differences().to_vec()
                ))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn replaying_one_fixture_twice_produces_byte_identical_streams() {
    let registry = DeviationRegistry::empty();
    for path in fixtures() {
        let trace = load(&path);
        let first = replay(&trace, &registry).expect("replays");
        let second = replay(&trace, &registry).expect("replays");
        let bytes = |outcome: &automonique_daemon::parity_trace::ReplayOutcome| {
            outcome
                .candidate
                .iter()
                .map(automonique_protocol::parity::IntendedActionEnvelope::to_canonical_bytes)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            bytes(&first),
            bytes(&second),
            "{} is not deterministic",
            name(&path)
        );
    }
}

#[test]
fn the_corpus_carries_more_than_one_category() {
    let categories: Vec<Category> = fixtures()
        .iter()
        .map(|path| load(path).header().category)
        .collect();
    for expected in [Category::Happy, Category::Error, Category::Edge] {
        assert!(
            categories.contains(&expected),
            "the corpus has no {} fixture",
            expected.as_str()
        );
    }
}

#[test]
fn the_corpus_scores_against_the_weighted_bands() {
    let registry = DeviationRegistry::empty();
    let mut corpus = Vec::new();
    for path in fixtures() {
        let trace = load(&path);
        let outcome = replay(&trace, &registry).expect("replays");
        for difference in &outcome.differences {
            corpus.push(ScoredComparison {
                category: trace.header().category,
                classification: difference.classification,
            });
        }
    }
    let score = ParityScore::compute(&corpus).expect("the corpus is not empty");
    // A green corpus scores full marks. The assertion is on the *band* as well
    // as the number, so a future fixture that regresses moves the band and not
    // just a digit.
    assert_eq!(score.score(), 100);
    assert_eq!(
        score.band(),
        automonique_protocol::parity::Band::CutoverReady
    );
}

#[test]
fn a_fixture_whose_reference_stream_is_edited_regresses() {
    // The corpus would be worthless if a changed reference envelope still
    // passed, so one is changed here and the failure is asserted.
    let path = corpus_root().join("slack-ticket-routing/intake-happy.cjson");
    let text = std::fs::read_to_string(&path).expect("fixture is readable");
    let edited = text.replace("Confirmation required", "Confirmation demanded");
    assert_ne!(
        edited, text,
        "the fixture no longer contains the edited text"
    );
    let trace = Trace::from_lines(edited.as_bytes()).expect("still a trace");
    let outcome = replay(&trace, &DeviationRegistry::empty()).expect("replays");
    assert!(!outcome.accounted(), "an edited reference must regress");
    assert_eq!(
        outcome.regressions()[0].comparison.verdict(),
        ComparisonVerdict::Mismatch
    );
}

#[test]
fn a_registered_deviation_turns_that_same_regression_into_a_known_one() {
    let path = corpus_root().join("slack-ticket-routing/intake-happy.cjson");
    let text = std::fs::read_to_string(&path).expect("fixture is readable");
    let edited = text.replace("Confirmation required", "Confirmation demanded");
    let trace = Trace::from_lines(edited.as_bytes()).expect("still a trace");

    let registry = DeviationRegistry::new(vec![
        DeviationEntry::new(
            "fixture-only-0001",
            "slack-ticket-routing",
            automonique_protocol::parity::ActionKind::SlackThreadReply,
            automonique_protocol::parity::ComparisonField::RenderedMessage,
            automonique_protocol::parity::Relation::ValueDiffers,
            automonique_protocol::parity::DeviationReason::DeliberateImprovement,
        )
        .expect("valid entry"),
    ])
    .expect("valid registry");

    let outcome = replay(&trace, &registry).expect("replays");
    assert!(
        outcome.accounted(),
        "the registered deviation accounts for it"
    );
    let known = outcome
        .differences
        .iter()
        .find(|difference| difference.classification == Classification::KnownDeviation)
        .expect("one position is a known deviation");
    assert_eq!(known.deviations, vec![String::from("fixture-only-0001")]);
}

#[test]
fn a_trace_for_a_scope_with_no_binding_is_refused() {
    let path = corpus_root().join("slack-ticket-routing/intake-happy.cjson");
    let text = std::fs::read_to_string(&path).expect("fixture is readable");
    let foreign = text.replace(
        "\"scope\":\"slack-ticket-routing\"",
        "\"scope\":\"some-other-scope\"",
    );
    let trace = Trace::from_lines(foreign.as_bytes()).expect("still a trace");
    assert_eq!(
        replay(&trace, &DeviationRegistry::empty()),
        Err(TraceError::UnknownScope)
    );
}

#[test]
fn a_trace_declaring_provider_interactions_this_scope_cannot_consume_is_refused() {
    let trace = load(&corpus_root().join("slack-ticket-routing/intake-happy.cjson"));
    let mut records = trace.records().to_vec();
    records.push(TraceRecord::ProviderInteraction {
        prompt_digest: String::from(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        response: String::from("an answer nothing in this scope can ask for"),
    });
    let widened = Trace::new(trace.header().clone(), records).expect("valid trace");
    assert_eq!(
        replay(&widened, &DeviationRegistry::empty()),
        Err(TraceError::ProviderInteractionUnconsumed)
    );
}

#[test]
fn every_fixture_round_trips_through_its_own_canonical_form() {
    for path in fixtures() {
        let bytes = std::fs::read(&path).expect("fixture is readable");
        let trace = Trace::from_lines(&bytes).expect("decodes");
        assert_eq!(
            trace.to_lines(),
            bytes,
            "{} is checked in in a non-canonical spelling",
            name(&path)
        );
    }
}

#[test]
fn every_reference_envelope_is_attributed_to_the_reference_engine() {
    for path in fixtures() {
        let trace = load(&path);
        assert!(
            trace.envelopes(ParityEngine::ShadowCandidate).is_empty(),
            "{} records candidate envelopes; the candidate is produced by replay, \
             not read from the fixture",
            name(&path)
        );
        for envelope in trace.envelopes(ParityEngine::LegacyObserved) {
            assert_eq!(
                envelope.observed_at_ms(),
                REPLAY_CLOCK_MS,
                "{} carries a clock the replay cannot reproduce",
                name(&path)
            );
        }
    }
}
