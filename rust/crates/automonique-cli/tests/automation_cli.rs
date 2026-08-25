// SPDX-License-Identifier: Elastic-2.0

//! Argument discipline for `automonique automation`.
//!
//! Every case here is decided by the dispatcher before a connection is
//! attempted, so the suite is safe to run on a host that has a live daemon: no
//! assertion depends on `$XDG_RUNTIME_DIR`, and none of these inputs can reach
//! one. The connected half — the frame the client sends, the request the daemon
//! receives, and the rendering of a receipt, a page, a record, a refusal and a
//! conflict — is exercised against a fake Automation server in
//! `src/automation.rs`, which can name its own runtime root without mutating the
//! process environment.
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
        vec!["automation"],
        vec!["automation", "bogus"],
        vec!["automation", "detail"],
        vec!["automation", "detail", "a", "extra"],
        // Every lifecycle verb has an exact arity, and one word too few or too
        // many is a shape this CLI does not have rather than a word to judge.
        vec!["automation", "register"],
        vec!["automation", "register", "a"],
        vec!["automation", "register", "a", "ben", "extra"],
        // After the two positional words come `--flag value` pairs and
        // nothing else: a bare word, or a flag with nothing after it, is a
        // shape rather than a value to judge.
        vec!["automation", "register", "a", "ben", "--schedule"],
        vec![
            "automation",
            "register",
            "a",
            "ben",
            "--schedule",
            "hourly",
            "extra",
        ],
        vec!["automation", "register", "a", "ben", "hourly", "--schedule"],
        vec!["automation", "pause", "a", "1", "ben"],
        vec!["automation", "pause", "a", "1", "ben", "why", "extra"],
        vec!["automation", "resume", "a", "1"],
        vec!["automation", "resume", "a", "1", "ben", "extra"],
        vec!["automation", "archive", "a", "1", "ben"],
        vec!["automations", "list"],
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
fn usage_documents_every_automation_verb() {
    let (_, _, stderr) = run(&["automation"]);
    for line in [
        "automonique automation register <automation-id> <actor>",
        "automonique automation pause <automation-id> <revision> <actor> <cause>",
        "automonique automation resume <automation-id> <revision> <actor>",
        "automonique automation archive <automation-id> <revision> <actor> <cause>",
        "automonique automation list [--state <state>]... [--cursor <entry-id>] [--page <size>]",
        "automonique automation detail <automation-id>",
    ] {
        assert!(stderr.contains(line), "usage omits {line:?}: {stderr}");
    }
}

#[test]
fn a_placeable_shape_with_bad_words_is_the_verbs_refusal_and_not_usage() {
    // `automation list` always places — the remaining words are flags the verb
    // judges — so an unknown flag is named rather than reported as a shape this
    // CLI does not have.
    for (arguments, expected) in [
        (vec!["automation", "list", "--nope"], "invalid_flag"),
        (
            vec!["automation", "list", "--state", "disabled"],
            "invalid_state",
        ),
        (
            vec!["automation", "list", "--cursor", "x"],
            "invalid_cursor",
        ),
        (vec!["automation", "list", "--page", "0"], "invalid_page"),
        (vec!["automation", "list", "--page", "33"], "invalid_page"),
        (
            vec!["automation", "list", "--cursor", "1", "--cursor", "2"],
            "repeated_flag",
        ),
        (
            vec![
                "automation",
                "list",
                "--state",
                "paused",
                "--state",
                "paused",
            ],
            "invalid_state_filter",
        ),
        (vec!["automation", "detail", ""], "invalid_automation_id"),
        (
            vec!["automation", "register", "", "ben"],
            "invalid_automation_id",
        ),
        (vec!["automation", "register", "a", ""], "invalid_actor"),
        // The job flags: each required once, each judged by grammar, and the
        // cron form refused by name because the daemon cannot evaluate it.
        (
            vec!["automation", "register", "a", "ben"],
            "missing_schedule",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "hourly",
                "--prompt",
                "p",
            ],
            "missing_scope",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "hourly",
                "--scope",
                "ws",
            ],
            "missing_prompt",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "daily",
                "--scope",
                "ws",
                "--prompt",
                "p",
            ],
            "unsupported_schedule",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "every other day",
                "--scope",
                "ws",
                "--prompt",
                "p",
            ],
            "invalid_schedule",
        ),
        (
            vec!["automation", "register", "a", "ben", "--trigger", "manual"],
            "invalid_flag",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "hourly",
                "--scope",
                "",
                "--prompt",
                "p",
            ],
            "invalid_scope",
        ),
        (
            vec![
                "automation",
                "register",
                "a",
                "ben",
                "--schedule",
                "hourly",
                "--scope",
                "ws",
                "--prompt",
                "",
            ],
            "invalid_prompt",
        ),
        (
            vec!["automation", "pause", "a", "zero", "ben", "why"],
            "invalid_revision",
        ),
        (
            vec!["automation", "pause", "a", "0", "ben", "why"],
            "invalid_revision",
        ),
        (
            vec!["automation", "pause", "a", "1", "ben", ""],
            "invalid_cause",
        ),
        (vec!["automation", "resume", "a", "1", ""], "invalid_actor"),
        (
            vec!["automation", "archive", "a", "1", "ben", ""],
            "invalid_cause",
        ),
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert!(stdout.is_empty(), "{arguments:?} wrote to stdout");
        assert_eq!(
            stderr,
            format!("automonique automation refused: {expected}\n"),
            "{arguments:?} was refused by the wrong layer",
        );
    }
}

#[test]
fn an_identity_outside_the_protocol_grammar_is_refused_before_any_connection() {
    for automation_id in ["", "a\n1", "a\u{0}1", "a\u{7f}1"] {
        let (exit, stdout, stderr) = run(&["automation", "detail", automation_id]);
        assert_eq!(exit, 2, "identity {automation_id:?} was not refused");
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "automonique automation refused: invalid_automation_id\n"
        );
    }
}

#[test]
fn the_flag_words_are_taken_as_values_and_never_as_the_next_flag() {
    for (arguments, expected) in [
        (vec!["automation", "list", "--state"], "invalid_state"),
        (vec!["automation", "list", "--cursor"], "invalid_cursor"),
        (vec!["automation", "list", "--page"], "invalid_page"),
        (
            vec!["automation", "list", "--cursor", "--page", "4"],
            "invalid_cursor",
        ),
    ] {
        let (exit, _, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} did not exit 2");
        assert_eq!(
            stderr,
            format!("automonique automation refused: {expected}\n")
        );
    }
}

/// There is no argument position for a reason on a resume.
///
/// The coupling this CLI enforces is structural rather than validated: `resume`
/// takes three words and `pause` takes four, so "resume because X" is not a
/// command an operator can type wrong — it is a command that does not exist.
#[test]
fn a_resume_has_nowhere_to_put_a_cause() {
    let (exit, stdout, stderr) = run(&["automation", "resume", "a", "1", "ben", "because"]);
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("usage: automonique doctor"));
}

#[test]
fn adding_the_verb_left_every_other_verb_reachable() {
    // `automation` is a new first word: the neighbouring groups must still
    // parse to their own commands rather than fall through to this one or to
    // usage.
    for arguments in [
        vec!["runs", "list", "--nope"],
        vec!["run", "submit", "operator:cli:1"],
        vec!["reconcile", "inspect", "0"],
        vec!["outbox", "inspect", "0"],
    ] {
        let (exit, stdout, stderr) = run(&arguments);
        assert_eq!(exit, 2, "{arguments:?} was not refused");
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("refused: ") && !stderr.contains("automonique automation refused"),
            "{arguments:?} was answered by the automation verb: {stderr}",
        );
    }
}
