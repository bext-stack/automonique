// SPDX-License-Identifier: Elastic-2.0

//! The offline parity verbs, end to end over a real database.
//!
//! Three properties are worth a test here and the rest are rendering: comparing
//! twice writes nothing the second time, an unregistered mismatch scores as a
//! regression while a registered one does not, and a gate decision is immutable
//! under its own key.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_cli::run;
use automonique_protocol::parity::{
    ActionKind, IntendedAction, IntendedActionEnvelope, ParityEngine,
};
use automonique_store::shadow_comparisons::{IntendedActionRecord, ShadowComparisonStore};
use tempfile::TempDir;

const SCOPE: &str = "slack-ticket-routing";
const SOURCE: &str = "slack:T0TRACE0001:event:Ev0000000001";

fn private_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private permissions");
    directory
}

fn reply(text: &str) -> IntendedAction {
    IntendedAction::new(
        ActionKind::SlackThreadReply,
        vec![
            String::from("C0TRACE0001"),
            String::from("1700000000.000100"),
            text.to_owned(),
        ],
    )
    .expect("valid action")
}

/// A database holding one position from each engine.
fn database(directory: &TempDir, shadow_text: &str, legacy_text: &str) -> PathBuf {
    let path = directory.path().join("shadow-comparisons.sqlite3");
    let mut store = ShadowComparisonStore::open(&path).expect("opens");
    for (engine, text) in [
        (ParityEngine::ShadowCandidate, shadow_text),
        (ParityEngine::LegacyObserved, legacy_text),
    ] {
        let envelope =
            IntendedActionEnvelope::new(SCOPE, SOURCE, engine, 0, reply(text), 1_700_000_000_000)
                .expect("valid envelope");
        let bytes = envelope.to_canonical_bytes();
        let digest = envelope.content_digest().to_hex();
        store
            .record_intended_action(IntendedActionRecord {
                scope: SCOPE,
                source_key: SOURCE,
                engine: engine.as_str(),
                sequence: 0,
                envelope: &bytes,
                envelope_digest: &digest,
                observed_at_ms: 1_700_000_000_000,
            })
            .expect("records");
    }
    path
}

fn invoke(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(arguments, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

fn registry_file(directory: &TempDir, entries: &str) -> PathBuf {
    let path = directory.path().join("deviations.json");
    fs::write(
        &path,
        format!("{{\"schema\": \"x\", \"entries\": [{entries}]}}"),
    )
    .expect("writes");
    path
}

fn text(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn comparing_an_agreement_scores_full_marks() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));

    let (code, out, err) = invoke(&["parity", "compare", &path, SCOPE]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("recorded 1"), "{out}");
    assert!(out.contains("regressions 0"), "{out}");

    let (code, out, _) = invoke(&["parity", "score", &path, SCOPE]);
    assert_eq!(code, 0);
    assert!(out.contains("score 100"), "{out}");
    assert!(out.contains("band cutover-ready"), "{out}");
    assert!(out.contains("production-representative 1/1"), "{out}");
}

#[test]
fn comparing_twice_writes_nothing_the_second_time() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    let (_, first, _) = invoke(&["parity", "compare", &path, SCOPE]);
    assert!(first.contains("recorded 1"), "{first}");
    let (code, second, _) = invoke(&["parity", "compare", &path, SCOPE]);
    assert_eq!(code, 0);
    assert!(second.contains("recorded 0"), "{second}");
    assert!(second.contains("replayed 1"), "{second}");
}

#[test]
fn an_unregistered_mismatch_scores_as_a_regression() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "working on it"));
    let (code, out, err) = invoke(&["parity", "compare", &path, SCOPE]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("regressions 1"), "{out}");

    let (_, scored, _) = invoke(&["parity", "score", &path, SCOPE]);
    assert!(scored.contains("score 0"), "{scored}");
    assert!(scored.contains("band block"), "{scored}");
}

#[test]
fn a_registered_deviation_accounts_for_that_same_mismatch() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "working on it"));
    let registry = registry_file(
        &directory,
        "{\"id\": \"dev-0001\", \"scope\": \"slack-ticket-routing\", \
         \"action_kind\": \"slack-thread-reply\", \"field\": \"rendered_message\", \
         \"relation\": \"value_differs\", \"reason\": \"deliberate-improvement\"}",
    );
    let (code, out, err) = invoke(&[
        "parity",
        "compare",
        &path,
        SCOPE,
        "--registry",
        &text(&registry),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("regressions 0"), "{out}");

    let (_, scored, _) = invoke(&["parity", "score", &path, SCOPE]);
    assert!(scored.contains("score 100"), "{scored}");
}

#[test]
fn the_category_flag_selects_the_weight_a_comparison_carries() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    let (code, _, err) = invoke(&["parity", "compare", &path, SCOPE, "--category", "edge"]);
    assert_eq!(code, 0, "{err}");
    let (_, scored, _) = invoke(&["parity", "score", &path, SCOPE]);
    assert!(scored.contains("edge 1/1"), "{scored}");
    assert!(scored.contains("production-representative 0/0"), "{scored}");
}

#[test]
fn a_category_outside_the_closed_set_is_an_argument_error() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    let (code, _, err) = invoke(&["parity", "compare", &path, SCOPE, "--category", "cheerful"]);
    assert_eq!(code, 2);
    assert!(err.contains("invalid_argument"), "{err}");
}

#[test]
fn a_gate_decision_records_the_score_the_band_and_the_registry_digest() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    invoke(&["parity", "compare", &path, SCOPE]);
    let (code, out, err) = invoke(&["parity", "gate", &path, SCOPE, "gate-0001", "owner"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("score 100"), "{out}");
    assert!(out.contains("band cutover-ready"), "{out}");
    assert!(out.contains("registry "), "{out}");
    assert!(
        out.contains("nothing was promoted"),
        "a gate must say what it did not do: {out}"
    );
}

#[test]
fn re_deciding_under_one_key_with_a_different_score_is_refused() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    invoke(&["parity", "compare", &path, SCOPE]);
    assert_eq!(
        invoke(&["parity", "gate", &path, SCOPE, "gate-0001", "owner"]).0,
        0
    );
    // The same key with a different registry changes the pinned digest, which
    // is exactly the rewrite the immutable row exists to refuse.
    let registry = registry_file(
        &directory,
        "{\"id\": \"dev-0001\", \"scope\": \"slack-ticket-routing\", \
         \"action_kind\": \"slack-thread-reply\", \"field\": \"rendered_message\", \
         \"relation\": \"value_differs\", \"reason\": \"bug-fix\"}",
    );
    let (code, _, err) = invoke(&[
        "parity",
        "gate",
        &path,
        SCOPE,
        "gate-0001",
        "owner",
        "--registry",
        &text(&registry),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("record_gate_decision"), "{err}");
}

#[test]
fn scoring_a_scope_with_no_comparisons_refuses_rather_than_answering_zero() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    let (code, out, err) = invoke(&["parity", "score", &path, "a-scope-nobody-recorded"]);
    assert_eq!(code, 1);
    assert!(out.is_empty());
    assert!(err.contains("score"), "{err}");
}

#[test]
fn a_registry_that_is_not_the_shape_it_claims_is_refused() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "on it"));
    let broken = directory.path().join("broken.json");
    fs::write(&broken, "{\"schema\": \"x\"}").expect("writes");
    let (code, _, err) = invoke(&[
        "parity",
        "compare",
        &path,
        SCOPE,
        "--registry",
        &text(&broken),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("registry"), "{err}");
}

#[test]
fn a_registry_entry_with_an_unknown_spelling_is_refused_rather_than_ignored() {
    let directory = private_directory();
    let path = text(&database(&directory, "on it", "working on it"));
    let registry = registry_file(
        &directory,
        "{\"id\": \"dev-0001\", \"scope\": \"slack-ticket-routing\", \
         \"action_kind\": \"slack-thread-reply\", \"field\": \"rendered_messages\", \
         \"relation\": \"value_differs\", \"reason\": \"deliberate-improvement\"}",
    );
    let (code, _, err) = invoke(&[
        "parity",
        "compare",
        &path,
        SCOPE,
        "--registry",
        &text(&registry),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown_spelling"), "{err}");
}

#[test]
fn a_malformed_invocation_is_a_bounded_usage_error() {
    let (code, out, err) = invoke(&["parity", "compare"]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.starts_with("usage: automonique doctor"));
}
