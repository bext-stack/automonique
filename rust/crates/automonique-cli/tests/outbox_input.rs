// SPDX-License-Identifier: Elastic-2.0

use std::ffi::OsString;

#[test]
fn outbox_cli_rejects_unknown_decision_and_invalid_coordinates_before_connecting() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = automonique_cli::run_with_input(
        [
            "outbox",
            "reconcile",
            "retry",
            "1",
            "foreground",
            "1",
            "1",
            "1",
        ],
        &b"unsafe\n"[..],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"automonique outbox refused: invalid_decision\n");

    stdout.clear();
    stderr.clear();
    let code = automonique_cli::run_with_input(
        [
            OsString::from("outbox"),
            OsString::from("inspect"),
            OsString::from("0"),
        ],
        &[][..],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert_eq!(stderr, b"automonique outbox refused: invalid_outbox_id\n");
}
