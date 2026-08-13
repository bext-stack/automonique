// SPDX-License-Identifier: Elastic-2.0

//! Argument discipline for `automonique batch`.
//!
//! Every case here is decided by the dispatcher or the verb before a connection
//! is attempted, so the suite is safe to run on a host that has a live daemon: no
//! assertion depends on `$XDG_RUNTIME_DIR`, and none of these inputs can reach
//! one. The connected half — the frame the client sends, the request the daemon
//! receives, and the rendering of a receipt, a page, a detail view, a refusal and
//! a conflict — is exercised against a fake Batch server in `src/batch.rs`, which
//! can name its own runtime root without mutating the process environment.
//!
//! The distinction being pinned is which layer refuses. A verb *shape* the
//! dispatcher cannot place reports usage and exits 2; a shape it can place but
//! whose words are outside their grammar is the verb's own refusal, named by
//! category. Both exit 2, and a word that fell through from one to the other
//! would be reported as the wrong kind of mistake.

use automonique_cli::run_with_input;

/// Run one command with no stdin, returning the exit code and both streams.
///
/// `batch` reads nothing from stdin: a member key is a bounded, already-public
/// coordinate rather than content, so it travels in argv like an automation
/// identity or an approval key. An empty input stream here is the assertion that
/// no verb below is waiting for one.
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
        vec!["batch"],
        vec!["batch", "bogus"],
        vec!["batch", "detail"],
        vec!["batch", "detail", "b", "extra"],
        // `register` needs at least an identity; with nothing at all it is a
        // shape this CLI does not have rather than words to judge.
        vec!["batch", "register"],
        // `advance` has an exact arity, and one word too few or too many is a
        // shape rather than a word to judge.
        vec!["batch", "advance"],
        vec!["batch", "advance", "b"],
        vec!["batch", "advance", "b", "m"],
        vec!["batch", "advance", "b", "m", "1"],
        vec!["batch", "advance", "b", "m", "1", "ready"],
        vec!["batch", "advance", "b", "m", "1", "ready", "0", "extra"],
        vec!["batches", "list"],
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
fn usage_documents_every_batch_verb() {
    let (_, _, stderr) = run(&["batch"]);
    for line in [
        "automonique batch register <batch-id> [--label <label>] [--sequential | --parallel <ceiling>] <member-key>...",
        "automonique batch advance <batch-id> <member-key> <revision> <state> <last-sequence>",
        "automonique batch list [--cursor <entry-id>] [--page <size>]",
        "automonique batch detail <batch-id>",
    ] {
        assert!(stderr.contains(line), "usage omits {line:?}: {stderr}");
    }
}

/// There is no `deregister`, no `cancel` and no `add-member`.
///
/// The registry has no delete and no second registration, and a membership is
/// fixed at the moment it is declared. A verb that does not exist reports usage
/// rather than being placed and then refused: the absence is structural, not a
/// validation an operator could argue with.
#[test]
fn the_registry_has_no_delete_and_no_membership_edit_verb() {
    for verb in [
        "deregister",
        "delete",
        "cancel",
        "add-member",
        "remove-member",
        "resume",
        "run",
        "submit",
    ] {
        let (exit, stdout, stderr) = run(&["batch", verb, "b", "m", "1", "ready", "0"]);
        assert_eq!(exit, 2, "batch {verb} was not refused");
        assert!(stdout.is_empty());
        assert!(
            stderr.starts_with("usage: automonique doctor"),
            "batch {verb} was placed as a verb: {stderr}",
        );
    }
}

#[test]
fn a_placeable_shape_with_bad_words_is_the_verbs_refusal_and_not_usage() {
    // `batch list` and `batch register` always place — the remaining words are
    // the verb's own grammar — so a bad word is named rather than reported as a
    // shape this CLI does not have.
    for (arguments, expected) in [
        (vec!["batch", "list", "--nope"], "invalid_flag"),
        (vec!["batch", "list", "--cursor", "x"], "invalid_cursor"),
        (vec!["batch", "list", "--page", "0"], "invalid_page"),
        (vec!["batch", "list", "--page", "33"], "invalid_page"),
        (
            vec!["batch", "list", "--cursor", "1", "--cursor", "2"],
            "repeated_flag",
        ),
        (vec!["batch", "detail", ""], "invalid_batch_id"),
        (vec!["batch", "register", "", "m"], "invalid_batch_id"),
        // A batch with an identity and no member is a unit with nothing in it.
        (vec!["batch", "register", "b"], "invalid_membership"),
        (
            vec!["batch", "register", "b", "--sequential"],
            "invalid_membership",
        ),
        (
            vec!["batch", "register", "b", "m", "m"],
            "invalid_membership",
        ),
        (vec!["batch", "register", "b", ""], "invalid_member_key"),
        (
            vec!["batch", "register", "b", "--label", "", "m"],
            "invalid_label",
        ),
        (
            vec!["batch", "register", "b", "--parallel", "0", "m"],
            "invalid_parallel",
        ),
        (
            vec!["batch", "register", "b", "--parallel", "257", "m"],
            "invalid_parallel",
        ),
        (
            vec![
                "batch",
                "register",
                "b",
                "--parallel",
                "2",
                "--parallel",
                "3",
                "m",
            ],
            "repeated_flag",
        ),
        (
            vec![
                "batch",
                "register",
                "b",
                "--sequential",
                "--parallel",
                "2",
                "m",
            ],
            "repeated_flag",
        ),
        (
            vec!["batch", "advance", "", "m", "1", "ready", "0"],
            "invalid_batch_id",
        ),
        (
            vec!["batch", "advance", "b", "", "1", "ready", "0"],
            "invalid_member_key",
        ),
        (
            vec!["batch", "advance", "b", "m", "x", "ready", "0"],
            "invalid_revision",
        ),
        (
            vec!["batch", "advance", "b", "m", "1", "ready", "x"],
            "invalid_last_sequence",
        ),
        // Revision zero names a row no writer produced, and the sequence
        // coupling is a property of the request alone.
        (
            vec!["batch", "advance", "b", "m", "0", "ready", "0"],
            "invalid_advance",
        ),
        (
            vec!["batch", "advance", "b", "m", "1", "ready", "7"],
            "invalid_advance",
        ),
        (
            vec!["batch", "advance", "b", "m", "1", "running", "0"],
            "invalid_advance",
        ),
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert_eq!(
            stderr,
            format!("automonique batch refused: {expected}\n"),
            "{arguments:?} was refused by the wrong layer",
        );
    }
}

/// The progress vocabulary is seven words, and only seven.
///
/// Judged by the protocol's own fail-closed decoder rather than by a local
/// match, so an operator's word and a wire value cannot be admitted by different
/// rules.
#[test]
fn a_progress_word_outside_the_closed_vocabulary_exits_two() {
    for state in [
        "finished",
        "RUNNING",
        "Completed",
        "done",
        "succeeded",
        "pending",
        "queued",
        "",
        "running ",
    ] {
        let (exit, stdout, stderr) = run(&["batch", "advance", "b", "m", "1", state, "0"]);
        assert_eq!(exit, 2, "state {state:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(
            stderr, "automonique batch refused: invalid_state\n",
            "state {state:?} was refused by the wrong layer",
        );
    }
}

#[test]
fn an_identifier_outside_the_protocol_grammar_is_refused_before_any_connection() {
    for batch_id in ["", "b\n1", "b\u{0}1", "b\u{7f}1"] {
        let (exit, stdout, stderr) = run(&["batch", "detail", batch_id]);
        assert_eq!(exit, 2, "identity {batch_id:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique batch refused: invalid_batch_id\n");
    }
    for member_key in ["", "m\n1", "m\u{0}1"] {
        let (exit, _, stderr) = run(&["batch", "register", "b", member_key]);
        assert_eq!(exit, 2, "member {member_key:?} was not refused");
        assert_eq!(stderr, "automonique batch refused: invalid_member_key\n");
    }
}

#[test]
fn the_flag_words_are_taken_as_values_and_never_as_the_next_flag() {
    for (arguments, expected) in [
        (vec!["batch", "list", "--cursor"], "invalid_cursor"),
        (vec!["batch", "list", "--page"], "invalid_page"),
        (
            vec!["batch", "list", "--cursor", "--page", "4"],
            "invalid_cursor",
        ),
        (vec!["batch", "register", "b", "--label"], "invalid_label"),
        (
            vec!["batch", "register", "b", "--parallel"],
            "invalid_parallel",
        ),
        // A flag consumed the word after it, so the membership is empty rather
        // than holding the value the flag took.
        (
            vec!["batch", "register", "b", "--label", "m"],
            "invalid_membership",
        ),
    ] {
        let (exit, _, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert_eq!(stderr, format!("automonique batch refused: {expected}\n"));
    }
}

#[test]
fn adding_the_verb_left_every_other_verb_reachable() {
    // `batch` is a new first word: the neighbouring groups must still parse to
    // their own commands rather than fall through to this one or to usage.
    for arguments in [
        vec!["approval", "list", "--nope"],
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
            stderr.contains("refused: ") && !stderr.contains("automonique batch refused"),
            "{arguments:?} was answered by the batch verb: {stderr}",
        );
    }
}
