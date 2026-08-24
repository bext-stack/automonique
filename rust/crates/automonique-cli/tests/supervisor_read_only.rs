// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::inspect_supervisor_adapter;
use automonique_protocol::CheckStatus;

#[test]
fn unavailable_result_has_exact_typed_redacted_reason() {
    let check = inspect_supervisor_adapter(None);
    let reason = check.reason().expect("unavailable check has a reason");

    assert_eq!(check.code().as_str(), "supervisor.adapter");
    assert_eq!(check.status(), CheckStatus::Unavailable);
    assert_eq!(
        reason.code().as_str(),
        "supervisor.socket-readback-unavailable"
    );
    assert_eq!(
        reason.message().as_str(),
        "Supervisor readback is unavailable for the active admin socket"
    );
}

#[test]
fn repeated_inspection_is_deterministic_and_does_not_mutate_files() {
    let directory = tempfile::tempdir().expect("temporary observation directory");
    let marker = directory.path().join("marker");
    std::fs::write(&marker, b"unchanged").expect("marker");
    let before_entries = std::fs::read_dir(directory.path())
        .expect("entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    let before_marker = std::fs::read(&marker).expect("marker bytes");

    let first = inspect_supervisor_adapter(None);
    let second = inspect_supervisor_adapter(None);

    let after_entries = std::fs::read_dir(directory.path())
        .expect("entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(first, second);
    assert_eq!(after_entries, before_entries);
    assert_eq!(std::fs::read(marker).expect("marker bytes"), before_marker);
}
