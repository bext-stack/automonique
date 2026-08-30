// SPDX-License-Identifier: Elastic-2.0

use automonique_cli::{
    AttributionInspection, MAX_RELEASE_MANIFEST_BYTES, ReleaseInspection, ReleaseInspectionStatus,
    ReleaseIssue, inspect_release_attribution, inspect_release_manifest_structure,
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

/// A digest and a revision, in the spellings the deployed manifests use.
const WEB_ENTRY: &str = r#"{
  "schema": "automonique.web-entry-release/v1",
  "source_sha": "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6",
  "binary_sha256": "9f78792990ccb0ab4dd416a9912ebcf8511cdbdf02b7b06778cb08ff28136503"
}"#;

fn observed(path: &std::path::Path) -> automonique_cli::InspectedAttribution {
    match inspect_release_attribution(path) {
        AttributionInspection::Observed(observed) => observed,
        other => panic!("expected an observation, got {other:?}"),
    }
}

#[test]
fn a_deployed_manifest_names_its_binary_and_revision() {
    let (_directory, path) = manifest(WEB_ENTRY.as_bytes());

    let attribution = observed(&path);

    assert_eq!(
        attribution.schema.as_deref(),
        Some("automonique.web-entry-release/v1")
    );
    assert_eq!(
        attribution.binary_sha256.as_deref(),
        Some("9f78792990ccb0ab4dd416a9912ebcf8511cdbdf02b7b06778cb08ff28136503")
    );
    assert_eq!(
        attribution.source_revision.as_deref(),
        Some("39747eaf63f32ad43e3cb045b36bd6fbaed46cf6")
    );
}

#[test]
fn the_typed_manifest_shape_is_read_for_attribution_too() {
    // The strict structural manifest spells the revision `git_revision`. The
    // attribution reader understands every spelling this repository writes, so
    // a host is never told "no attribution" merely because it laid down the
    // other kind of manifest.
    let (_directory, path) = manifest(VALID.as_bytes());

    let attribution = observed(&path);

    assert_eq!(
        attribution.source_revision.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert_eq!(attribution.binary_sha256, None);
    assert_eq!(
        inspect_release_manifest_structure(&path).status(),
        ReleaseInspectionStatus::Structured
    );
}

#[test]
fn a_manifest_naming_two_different_revisions_has_named_none() {
    let contradictory = br#"{
      "source_sha": "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6",
      "git_revision": "d5666f9c85080609f58f2d201dbe15ae1b8fcbb3"
    }"#;
    let (_directory, path) = manifest(contradictory);

    assert_eq!(
        inspect_release_attribution(&path).issue(),
        Some(ReleaseIssue::RequiredFieldInvalid)
    );

    // The same revision under two spellings is one revision, not a conflict.
    let agreeing = br#"{
      "source_sha": "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6",
      "git_revision": "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6"
    }"#;
    let (_directory, path) = manifest(agreeing);
    assert_eq!(
        observed(&path).source_revision.as_deref(),
        Some("39747eaf63f32ad43e3cb045b36bd6fbaed46cf6")
    );
}

#[test]
fn a_malformed_digest_or_revision_is_absent_rather_than_believed() {
    let sloppy = br#"{
      "schema": "automonique.web-entry-release/v1",
      "source_sha": "c0ffee",
      "binary_sha256": "9F78792990CCB0AB4DD416A9912EBCF8511CDBDF02B7B06778CB08FF28136503"
    }"#;
    let (_directory, path) = manifest(sloppy);

    let attribution = observed(&path);

    assert_eq!(attribution.source_revision, None);
    assert_eq!(attribution.binary_sha256, None);
}

#[test]
fn a_prefixed_digest_is_read_without_its_algorithm_label() {
    let prefixed = br#"{
      "binary_sha256": "sha256:9f78792990ccb0ab4dd416a9912ebcf8511cdbdf02b7b06778cb08ff28136503"
    }"#;
    let (_directory, path) = manifest(prefixed);

    assert_eq!(
        observed(&path).binary_sha256.as_deref(),
        Some("9f78792990ccb0ab4dd416a9912ebcf8511cdbdf02b7b06778cb08ff28136503")
    );
}

#[test]
fn attribution_refuses_every_path_the_structural_reader_refuses() {
    // One reader underneath both, so a manifest that is world-readable, a
    // symlink, or absent is refused identically whichever question is asked.
    let (directory, path) = manifest(WEB_ENTRY.as_bytes());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("permissive fixture");
    assert_eq!(
        inspect_release_attribution(&path).issue(),
        Some(ReleaseIssue::PermissiveMode)
    );

    let link_root = tempfile::tempdir().expect("link root");
    let linked_directory = link_root.path().join("release");
    std::os::unix::fs::symlink(directory.path(), &linked_directory).expect("directory symlink");
    assert_eq!(
        inspect_release_attribution(&linked_directory.join("manifest.json")).issue(),
        Some(ReleaseIssue::SymlinkForbidden)
    );

    assert_eq!(
        inspect_release_attribution(&link_root.path().join("absent.json")).issue(),
        Some(ReleaseIssue::Missing)
    );
}
