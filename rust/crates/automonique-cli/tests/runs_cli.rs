// SPDX-License-Identifier: Elastic-2.0

//! Argument discipline for `automonique runs`.
//!
//! Every case here is decided by the dispatcher before a connection is
//! attempted, so the suite is safe to run on a host that has a live daemon: no
//! assertion depends on `$XDG_RUNTIME_DIR`, and none of these inputs can reach
//! one. The connected half — the frame the client sends, the query the daemon
//! receives, and the rendering of a page, a view, a refusal and a resync — is
//! exercised against a fake Runs server in `src/runs.rs`, which can name its
//! own runtime root without mutating the process environment.
//!
//! The distinction being pinned is which layer refuses. A verb *shape* the
//! dispatcher cannot place reports usage and exits 2; a shape it can place but
//! whose words are outside their grammar is the verb's own refusal, named by
//! category. A word that fell through from one to the other would be reported
//! as the wrong kind of mistake.

use automonique_cli::run_with_input;

/// Run one command with no stdin, returning the exit code and both streams.
fn run(arguments: &[&str]) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(
        arguments.iter().copied(),
        b"".as_slice(),
        &mut stdout,
        &mut stderr,
    );
    (
        exit,
        String::from_utf8(stdout).expect("utf-8 stdout"),
        String::from_utf8(stderr).expect("utf-8 stderr"),
    )
}

#[test]
fn the_verb_shape_is_closed_and_reports_usage() {
    for arguments in [
        vec!["runs"],
        vec!["runs", "bogus"],
        vec!["runs", "detail"],
        vec!["runs", "detail", "run-1", "extra"],
        vec!["run", "list"],
        vec!["list", "runs"],
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert!(
            stderr.starts_with("usage: automonique doctor"),
            "{arguments:?} did not report usage: {stderr}",
        );
    }
}

#[test]
fn usage_documents_both_reads_and_their_flags() {
    let (_, _, stderr) = run(&["runs"]);
    for line in [
        "automonique runs list [--state <state>]... [--cursor <submission-id>] [--page <size>]",
        "automonique runs detail <run-id>",
    ] {
        assert!(stderr.contains(line), "usage omits {line:?}: {stderr}");
    }
}

#[test]
fn a_placeable_shape_with_bad_words_is_the_verbs_refusal_and_not_usage() {
    // `runs list` always places — the remaining words are flags the verb
    // judges — so an unknown flag is named rather than reported as a shape
    // this CLI does not have.
    for (arguments, expected) in [
        (vec!["runs", "list", "--nope"], "invalid_flag"),
        (vec!["runs", "list", "--state", "sleeping"], "invalid_state"),
        (vec!["runs", "list", "--cursor", "x"], "invalid_cursor"),
        (vec!["runs", "list", "--page", "0"], "invalid_page"),
        (vec!["runs", "list", "--page", "65"], "invalid_page"),
        (
            vec!["runs", "list", "--cursor", "1", "--cursor", "2"],
            "repeated_flag",
        ),
        (
            vec!["runs", "list", "--state", "ready", "--state", "ready"],
            "invalid_state_filter",
        ),
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert_eq!(
            stderr,
            format!("automonique runs refused: {expected}\n"),
            "{arguments:?} was refused by the wrong layer",
        );
    }
}

#[test]
fn a_run_identity_outside_the_protocol_grammar_is_refused_before_any_connection() {
    for run_id in ["", "run\n1", "run\u{0}1", "run\u{7f}1"] {
        let (exit, stdout, stderr) = run(&["runs", "detail", run_id]);
        assert_eq!(exit, 2, "run identity {run_id:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique runs refused: invalid_run_id\n");
    }
}

#[test]
fn the_flag_words_are_taken_as_values_and_never_as_the_next_flag() {
    // `--state` with nothing after it must not read the following flag as its
    // value, and `--cursor` must not read `--page` as a number. Each is the
    // refusal of the flag that was missing its value.
    for (arguments, expected) in [
        (vec!["runs", "list", "--state"], "invalid_state"),
        (vec!["runs", "list", "--cursor"], "invalid_cursor"),
        (vec!["runs", "list", "--page"], "invalid_page"),
        (
            vec!["runs", "list", "--cursor", "--page", "4"],
            "invalid_cursor",
        ),
    ] {
        let (exit, _, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert_eq!(stderr, format!("automonique runs refused: {expected}\n"));
    }
}

#[test]
fn adding_the_verb_left_every_other_verb_reachable() {
    // `runs` is a new first word that sits beside `run`, not a narrowing of
    // it: the neighbouring groups must still parse to their own commands
    // rather than fall through to this one or to usage.
    for arguments in [
        vec!["run", "submit", "operator:cli:1"],
        vec!["reconcile", "inspect", "0"],
        vec!["outbox", "inspect", "0"],
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("refused: ") && !stderr.contains("automonique runs refused"),
            "{arguments:?} was answered by the runs verb: {stderr}",
        );
    }
}
