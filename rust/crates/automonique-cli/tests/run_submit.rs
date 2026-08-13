// SPDX-License-Identifier: Elastic-2.0

//! Argument and stdin discipline for `automonique run submit`.
//!
//! Every case here is refused by the client before it opens a connection, so
//! the suite is safe to run on a host that has a live daemon: no assertion
//! depends on `$XDG_RUNTIME_DIR`, and none of these inputs can reach one.
//! The connected half — the exact frame the client sends, a maximal document
//! carried whole, and the rendering of an accepted or refused answer — is
//! exercised against a fake admin server in `src/run_submit.rs`, which can name
//! its own runtime root without mutating the process environment.

use automonique_cli::run_with_input;
use automonique_protocol::admin::{MAX_RUN_SUBMISSION_KEY_BYTES, MAX_SUBMITTED_RUN_SPEC_BYTES};

#[test]
fn the_verb_shape_is_closed_and_reports_usage() {
    for arguments in [
        vec!["run"],
        vec!["run", "submit"],
        vec!["run", "submit", "operator:cli:1", "extra"],
        vec!["run", "bogus", "operator:cli:1"],
        vec!["submit-run", "operator:cli:1"],
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_input(
            arguments.clone(),
            b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("utf8 usage")
                .starts_with("usage: automonique doctor"),
            "{arguments:?} did not report usage",
        );
    }
}

#[test]
fn usage_documents_the_document_as_stdin() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(["run"], b"".as_slice(), &mut stdout, &mut stderr);
    assert_eq!(exit, 2);
    assert!(
        String::from_utf8(stderr)
            .expect("utf8 usage")
            .contains("automonique run submit <idempotency-key> < run-spec.bin"),
        "the RunSpec document must be advertised as stdin, never as an argument",
    );
}

#[test]
fn a_document_past_the_protocol_ceiling_is_refused_before_any_daemon_connection() {
    let document = vec![b'd'; MAX_SUBMITTED_RUN_SPEC_BYTES + 1];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(
        ["run", "submit", "operator:cli:oversize"],
        document.as_slice(),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"automonique run refused: document_too_large\n");
}

#[test]
fn an_empty_document_is_refused_rather_than_submitted() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(
        ["run", "submit", "operator:cli:empty"],
        b"".as_slice(),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"automonique run refused: empty_document\n");
}

#[test]
fn an_idempotency_key_outside_the_server_bound_is_refused_before_any_connection() {
    for key in [
        String::new(),
        "k".repeat(MAX_RUN_SUBMISSION_KEY_BYTES + 1),
        "operator:cli\n1".to_owned(),
        "operator:cli\u{0}1".to_owned(),
        "operator:cli\u{7f}1".to_owned(),
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_input(
            ["run", "submit", key.as_str()],
            b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2, "key {key:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            b"automonique run refused: invalid_idempotency_key\n"
        );
    }
}

#[test]
fn adding_the_verb_left_every_other_verb_reachable() {
    // `run` is a new first word, not a narrowing of an existing one: the
    // neighbouring groups must still parse to their own commands rather than
    // fall through to usage.
    for arguments in [
        vec!["reconcile", "inspect", "0"],
        vec!["outbox", "inspect", "0"],
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_input(arguments.clone(), b"".as_slice(), &mut stdout, &mut stderr);
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("utf8 refusal")
                .contains("refused: invalid_"),
            "{arguments:?} fell through to usage instead of its own parser",
        );
    }
}
