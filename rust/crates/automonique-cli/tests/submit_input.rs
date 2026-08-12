// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::run_with_input;

#[test]
fn submission_task_is_bounded_before_any_daemon_connection() {
    let task = vec![b'x'; automonique_protocol::admin::MAX_SYNTHETIC_TASK_BYTES + 1];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_with_input(
        ["submit", "scope:test", "cli:test:large"],
        task.as_slice(),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"automonique submit refused: task_too_large\n");
}

#[test]
fn submission_task_must_be_nonempty_utf8_without_nul() {
    for (input, category) in [
        (b"".as_slice(), "admin_invalid_body"),
        (b"bad\0task".as_slice(), "admin_invalid_body"),
        (&[0xff][..], "task_not_utf8"),
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_input(
            ["submit", "scope:test", "cli:test:invalid"],
            input,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            format!("automonique submit refused: {category}\n")
        );
    }
}

#[test]
fn reconciliation_coordinates_are_parsed_and_refused_before_connection() {
    for arguments in [
        vec!["reconcile", "inspect", "0"],
        vec![
            "reconcile",
            "fail",
            "1",
            "generation-old",
            "not-an-epoch",
            "2",
            "decision-1",
        ],
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_with_input(arguments, b"".as_slice(), &mut stdout, &mut stderr);
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("utf8 refusal")
                .starts_with("automonique reconcile refused: invalid_")
        );
    }
}
