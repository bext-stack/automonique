// SPDX-License-Identifier: Elastic-2.0

//! Argument discipline for `automonique approval`.
//!
//! Every case here is decided by the dispatcher before a connection is
//! attempted, so the suite is safe to run on a host that has a live daemon: no
//! assertion depends on `$XDG_RUNTIME_DIR`, and none of these inputs can reach
//! one. The connected half — the frame the client sends, the request the daemon
//! receives, and the rendering of a receipt, a page, a record, a refusal and a
//! conflict — is exercised against a fake Approval server in `src/approval.rs`,
//! which can name its own runtime root without mutating the process environment.
//!
//! The distinction being pinned is which layer refuses. A verb *shape* the
//! dispatcher cannot place reports usage and exits 2; a shape it can place but
//! whose words are outside their grammar is the verb's own refusal, named by
//! category. Both exit 2, and a word that fell through from one to the other
//! would be reported as the wrong kind of mistake.

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
        vec!["approval"],
        vec!["approval", "bogus"],
        vec!["approval", "detail"],
        vec!["approval", "detail", "k", "extra"],
        // `record` has an exact arity, and one word too few or too many is a
        // shape this CLI does not have rather than a word to judge.
        vec!["approval", "record"],
        vec!["approval", "record", "k"],
        vec!["approval", "record", "k", "s"],
        vec!["approval", "record", "k", "s", "granted"],
        vec!["approval", "record", "k", "s", "granted", "ben", "extra"],
        vec!["approval", "by-subject"],
        vec!["approvals", "list"],
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
fn usage_documents_every_approval_verb() {
    let (_, _, stderr) = run(&["approval"]);
    for line in [
        "automonique approval record <approval-key> <subject> <granted|denied> <decider>",
        "automonique approval list [--cursor <entry-id>] [--page <size>]",
        "automonique approval detail <approval-key>",
        "automonique approval by-subject <subject> [--cursor <entry-id>] [--page <size>]",
    ] {
        assert!(stderr.contains(line), "usage omits {line:?}: {stderr}");
    }
}

/// There is no `amend` and no `revoke`, because the ledger is write-once.
///
/// A verb that does not exist reports usage rather than being placed and then
/// refused: the absence is structural, not a validation an operator could argue
/// with.
#[test]
fn the_write_once_ledger_has_no_amend_and_no_revoke_verb() {
    for verb in ["amend", "revoke", "delete", "update", "set"] {
        let (exit, stdout, stderr) = run(&["approval", verb, "k", "s", "granted", "ben"]);
        assert_eq!(exit, 2, "approval {verb} was not refused");
        assert!(stdout.is_empty());
        assert!(
            stderr.starts_with("usage: automonique doctor"),
            "approval {verb} was placed as a verb: {stderr}",
        );
    }
}

#[test]
fn a_placeable_shape_with_bad_words_is_the_verbs_refusal_and_not_usage() {
    // `approval list` always places — the remaining words are flags the verb
    // judges — so an unknown flag is named rather than reported as a shape this
    // CLI does not have.
    for (arguments, expected) in [
        (vec!["approval", "list", "--nope"], "invalid_flag"),
        (vec!["approval", "list", "--cursor", "x"], "invalid_cursor"),
        (vec!["approval", "list", "--page", "0"], "invalid_page"),
        (vec!["approval", "list", "--page", "33"], "invalid_page"),
        (
            vec!["approval", "list", "--cursor", "1", "--cursor", "2"],
            "repeated_flag",
        ),
        (
            vec!["approval", "by-subject", "s", "--nope"],
            "invalid_flag",
        ),
        (
            vec!["approval", "by-subject", "s", "--page", "99"],
            "invalid_page",
        ),
        (vec!["approval", "by-subject", ""], "invalid_subject"),
        (vec!["approval", "detail", ""], "invalid_approval_key"),
        (
            vec!["approval", "record", "", "s", "granted", "ben"],
            "invalid_approval_key",
        ),
        (
            vec!["approval", "record", "k", "", "granted", "ben"],
            "invalid_subject",
        ),
        (
            vec!["approval", "record", "k", "s", "granted", ""],
            "invalid_decider",
        ),
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert_eq!(
            stderr,
            format!("automonique approval refused: {expected}\n"),
            "{arguments:?} was refused by the wrong layer",
        );
    }
}

/// The decision vocabulary is two words, and only two.
///
/// Judged by the protocol's own fail-closed decoder rather than by a local
/// match, so an operator's word and a wire value cannot be admitted by different
/// rules.
#[test]
fn a_decision_word_outside_the_closed_vocabulary_exits_two() {
    for decision in [
        "approved", "GRANTED", "Denied", "grant", "deny", "yes", "no", "pending", "", "granted ",
    ] {
        let (exit, stdout, stderr) = run(&["approval", "record", "k", "s", decision, "ben"]);
        assert_eq!(exit, 2, "decision {decision:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(
            stderr, "automonique approval refused: invalid_decision\n",
            "decision {decision:?} was refused by the wrong layer",
        );
    }
}

#[test]
fn an_identifier_outside_the_protocol_grammar_is_refused_before_any_connection() {
    for approval_key in ["", "k\n1", "k\u{0}1", "k\u{7f}1"] {
        let (exit, stdout, stderr) = run(&["approval", "detail", approval_key]);
        assert_eq!(exit, 2, "key {approval_key:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "automonique approval refused: invalid_approval_key\n"
        );
    }
    for subject in ["", "s\n1", "s\u{0}1"] {
        let (exit, _, stderr) = run(&["approval", "by-subject", subject]);
        assert_eq!(exit, 2, "subject {subject:?} was not refused");
        assert_eq!(stderr, "automonique approval refused: invalid_subject\n");
    }
}

#[test]
fn the_flag_words_are_taken_as_values_and_never_as_the_next_flag() {
    for (arguments, expected) in [
        (vec!["approval", "list", "--cursor"], "invalid_cursor"),
        (vec!["approval", "list", "--page"], "invalid_page"),
        (
            vec!["approval", "list", "--cursor", "--page", "4"],
            "invalid_cursor",
        ),
        (
            vec!["approval", "by-subject", "s", "--page"],
            "invalid_page",
        ),
    ] {
        let (exit, _, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert_eq!(
            stderr,
            format!("automonique approval refused: {expected}\n")
        );
    }
}

#[test]
fn adding_the_verb_left_every_other_verb_reachable() {
    // `approval` is a new first word: the neighbouring groups must still parse
    // to their own commands rather than fall through to this one or to usage.
    for arguments in [
        vec!["automation", "list", "--nope"],
        vec!["runs", "list", "--nope"],
        vec!["run", "submit", "operator:cli:1"],
        vec!["reconcile", "inspect", "0"],
        vec!["outbox", "inspect", "0"],
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("refused: ") && !stderr.contains("automonique approval refused"),
            "{arguments:?} was answered by the approval verb: {stderr}",
        );
    }
}
