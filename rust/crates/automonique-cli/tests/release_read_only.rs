// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{
    MAX_RELEASE_MANIFEST_BYTES, ReleaseInspection, ReleaseInspectionStatus, ReleaseIssue,
    inspect_release_manifest_structure,
};
use std::os::unix::fs::PermissionsExt;

const VALID: &str = r#"{
  "application_version": "0.1.0",
  "git_revision": "0123456789abcdef0123456789abcdef01234567",
  "build_target": "x86_64-unknown-linux-gnu",
  "protocol_range": {"minimum": 1, "maximum": 2},
  "database_schema_range": {"minimum": 3, "maximum": 3},
  "minimum_kernel": "6.1.0"
}"#;

fn manifest(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("temporary release directory");
    let path = directory.path().join("manifest.json");
    std::fs::write(&path, contents).expect("write fixture");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("private fixture");
    (directory, path)
}

fn issue(outcome: &ReleaseInspection) -> ReleaseIssue {
    outcome.issue().expect("inspection issue")
}

#[test]
fn valid_manifest_is_typed_and_inspection_does_not_mutate_it() {
    let (_directory, path) = manifest(VALID.as_bytes());
    let before = std::fs::read(&path).expect("before bytes");
    let before_mode = std::fs::metadata(&path)
        .expect("before metadata")
        .permissions()
        .mode();

    let outcome = inspect_release_manifest_structure(&path);

    let ReleaseInspection::Structured(parsed) = outcome else {
        panic!("expected structurally valid manifest");
    };
    assert_eq!(parsed.application_version, "0.1.0");
    assert_eq!(parsed.protocol_range.minimum, 1);
    assert_eq!(parsed.protocol_range.maximum, 2);
    assert_eq!(std::fs::read(&path).expect("after bytes"), before);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("after metadata")
            .permissions()
            .mode(),
        before_mode
    );
}

#[test]
fn structural_inspection_does_not_claim_runtime_compatibility() {
    let structurally_valid = VALID
        .replace("x86_64-unknown-linux-gnu", "another-supported-shape")
        .replace("6.1.0", "999.0.0");
    let (_directory, path) = manifest(structurally_valid.as_bytes());

    let outcome = inspect_release_manifest_structure(&path);

    assert_eq!(outcome.status(), ReleaseInspectionStatus::Structured);
    let ReleaseInspection::Structured(parsed) = outcome else {
        panic!("expected a structural result");
    };
    assert_eq!(parsed.minimum_kernel, "999.0.0");
}

#[test]
fn missing_manifest_is_unavailable_with_no_path_in_reason() {
    let directory = tempfile::tempdir().expect("directory");
    let outcome = inspect_release_manifest_structure(&directory.path().join("missing.json"));

    assert_eq!(outcome.status(), ReleaseInspectionStatus::Unavailable);
    let reason = issue(&outcome);
    assert_eq!(reason, ReleaseIssue::Missing);
    assert_eq!(reason.code(), "release.missing");
    assert!(
        !reason
            .message()
            .contains(directory.path().to_string_lossy().as_ref())
    );
}

#[test]
fn malformed_non_object_and_incomplete_json_are_closed_findings() {
    let (_directory, malformed) = manifest(br#"{"#);
    assert_eq!(
        issue(&inspect_release_manifest_structure(&malformed)),
        ReleaseIssue::MalformedJson
    );

    let (_directory, array) = manifest(br#"[]"#);
    assert_eq!(
        issue(&inspect_release_manifest_structure(&array)),
        ReleaseIssue::NonObjectJson
    );

    let (_directory, missing) = manifest(br#"{}"#);
    assert_eq!(
        issue(&inspect_release_manifest_structure(&missing)),
        ReleaseIssue::RequiredFieldMissing
    );

    let invalid = VALID.replace(
        "\"protocol_range\": {\"minimum\": 1, \"maximum\": 2}",
        "\"protocol_range\": {\"minimum\": 2, \"maximum\": 1}",
    );
    let (_directory, invalid) = manifest(invalid.as_bytes());
    assert_eq!(
        issue(&inspect_release_manifest_structure(&invalid)),
        ReleaseIssue::RequiredFieldInvalid
    );
}

#[test]
fn oversized_manifest_is_rejected_before_reading() {
    let (_directory, path) = manifest(&vec![b' '; MAX_RELEASE_MANIFEST_BYTES + 1]);
    assert_eq!(
        issue(&inspect_release_manifest_structure(&path)),
        ReleaseIssue::TooLarge
    );
}

#[test]
fn symlink_component_and_final_symlink_are_never_accepted() {
    let (directory, target) = manifest(VALID.as_bytes());
    let link_root = tempfile::tempdir().expect("link root");
    let linked_directory = link_root.path().join("release");
    std::os::unix::fs::symlink(directory.path(), &linked_directory).expect("directory symlink");
    assert_eq!(
        issue(&inspect_release_manifest_structure(
            &linked_directory.join("manifest.json")
        )),
        ReleaseIssue::SymlinkForbidden
    );

    let final_link = link_root.path().join("manifest.json");
    std::os::unix::fs::symlink(&target, &final_link).expect("manifest symlink");
    assert_eq!(
        issue(&inspect_release_manifest_structure(&final_link)),
        ReleaseIssue::SymlinkForbidden
    );
}

#[test]
fn wrong_type_and_permissive_mode_are_findings_without_repair() {
    let directory = tempfile::tempdir().expect("directory");
    assert_eq!(
        issue(&inspect_release_manifest_structure(directory.path())),
        ReleaseIssue::NotRegular
    );

    let (_directory, path) = manifest(VALID.as_bytes());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("permissive fixture");
    assert_eq!(
        issue(&inspect_release_manifest_structure(&path)),
        ReleaseIssue::PermissiveMode
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}
