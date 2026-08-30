// SPDX-License-Identifier: Elastic-2.0

//! Whether a release manifest on this host describes the binary that is running.
//!
//! The question the doctor used to ask was "is there a structurally valid
//! manifest next to the binary". Two real production failures pass that
//! question or sidestep it: a release directory whose `bin/` was replaced
//! without moving the `current` pointer, so the manifest is internally
//! consistent about a build that is not serving; and a manifest laid down
//! beside a binary that was later swapped, so the manifest is well-formed and
//! wrong. In both cases a reader that parses the manifest and stops learns a
//! revision that is not the running one — and believes it, because the document
//! is valid.
//!
//! The question that separates those from a healthy host is "does a manifest
//! describe **this** binary", which is a digest comparison against the running
//! executable, not a parse. That comparison is what this module performs.
//!
//! Two details matter for it to mean anything.
//!
//! The digest is taken from `/proc/self/exe`, which is the *running image*.
//! Reading the deployed path instead would hash whatever is on disk now, and
//! the failure being detected is precisely the case where those two differ
//! because the file was replaced under a live process.
//!
//! And the manifest is looked for in every place the running binary implies,
//! not just one. A binary deployed at `<root>/bin/<name>` has a release root a
//! level above it and, on the deployments this was written for, a `current`
//! symlink there naming the release the operator believes is live. Following
//! that pointer is what turns "no manifest anywhere" into the far more useful
//! "the release you think is live describes another binary".

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::release::{AttributionInspection, ReleaseIssue, inspect_release_attribution};

/// Ceiling on the executable read for a digest.
///
/// Not a security boundary — the file is this process's own image — but an
/// unbounded read of an arbitrary path is not something a diagnostic should do.
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// The running image, whatever the path it was launched from now holds.
const RUNNING_IMAGE: &str = "/proc/self/exe";

/// What the manifests reachable from the running binary say about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseAttribution {
    /// A manifest describes exactly this binary, and agrees about the revision.
    Confirmed,
    /// A manifest describes this binary but attributes it to another revision.
    RevisionDisagrees,
    /// A manifest was found, and the binary it describes is not this one.
    DescribesAnotherBuild,
    /// A manifest was found, and it records no binary digest to compare.
    DigestUnrecorded,
    /// No manifest exists in any location the running binary implies.
    Absent,
    /// A manifest exists but could not be read.
    Unreadable { issue: ReleaseIssue, finding: bool },
    /// The running image could not be digested, so nothing can be compared.
    BinaryUnreadable,
}

/// Digest this process's running image, or `None` if it cannot be read.
pub fn running_image_digest() -> Option<String> {
    digest_of(Path::new(RUNNING_IMAGE))
}

fn digest_of(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = file.take(MAX_EXECUTABLE_BYTES);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(encode_hex(&hasher.finalize()))
}

/// Every path a binary at this location implies a release manifest could be at.
///
/// Ordered nearest-first, deduplicated, and never containing the `current`
/// symlink itself: the pointer is *read*, and the directory it names is what
/// gets inspected, because the manifest reader refuses any path with a symbolic
/// link in it and would otherwise reject the one candidate that matters.
pub fn candidate_manifests(executable: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let Some(directory) = executable.parent() else {
        return candidates;
    };
    candidates.push(directory.join("manifest.json"));
    let Some(root) = directory.parent() else {
        return candidates;
    };
    candidates.push(root.join("manifest.json"));
    push_through_current(&mut candidates, root);
    // The daemon activates its own releases under `improvement-code/`, not at
    // the state root, so a daemon installed into `<root>/bin` is described by a
    // manifest one level deeper than the three paths above reach. Without this
    // the check reports `release.missing` for every daemon deployment, which
    // reads as "no manifest exists" when one does and is being honoured.
    push_through_current(&mut candidates, &root.join("improvement-code"));
    candidates.dedup();
    candidates
}

/// Add the manifest reached through `<root>/current`, when that link exists.
///
/// The link is read, never traversed: the manifest reader refuses a symlinked
/// path, so resolving it here and handing over the resolved directory is what
/// lets a release still be found through its selector.
fn push_through_current(candidates: &mut Vec<PathBuf>, root: &Path) {
    let Ok(target) = std::fs::read_link(root.join("current")) else {
        return;
    };
    let resolved = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    candidates.push(resolved.join("manifest.json"));
}

/// Compare every reachable manifest against the running image.
///
/// `running` is the digest of the image, and `built_from` is the revision the
/// binary reports for itself — `None` whenever the build is not attributable,
/// in which case no revision comparison is attempted, because a disagreement
/// with a revision the build cannot vouch for proves nothing about the manifest.
#[must_use]
pub fn attribute_release(
    candidates: &[PathBuf],
    running: Option<&str>,
    built_from: Option<&str>,
) -> ReleaseAttribution {
    let Some(running) = running else {
        return ReleaseAttribution::BinaryUnreadable;
    };
    let mut describes_another = false;
    let mut digest_unrecorded = false;
    let mut unreadable = None;
    for candidate in candidates {
        match inspect_release_attribution(candidate) {
            AttributionInspection::Observed(observed) => match observed.binary_sha256.as_deref() {
                Some(digest) if digest == running => {
                    return match observed.source_revision.as_deref() {
                        Some(claimed) if built_from.is_some_and(|built| built != claimed) => {
                            ReleaseAttribution::RevisionDisagrees
                        }
                        _ => ReleaseAttribution::Confirmed,
                    };
                }
                Some(_) => describes_another = true,
                None => digest_unrecorded = true,
            },
            AttributionInspection::Unavailable(ReleaseIssue::Missing) => {}
            AttributionInspection::Finding(issue) => {
                unreadable.get_or_insert((issue, true));
            }
            AttributionInspection::Unavailable(issue) => {
                unreadable.get_or_insert((issue, false));
            }
        }
    }
    if describes_another {
        return ReleaseAttribution::DescribesAnotherBuild;
    }
    if digest_unrecorded {
        return ReleaseAttribution::DigestUnrecorded;
    }
    match unreadable {
        Some((issue, finding)) => ReleaseAttribution::Unreadable { issue, finding },
        None => ReleaseAttribution::Absent,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{ReleaseAttribution, attribute_release, candidate_manifests, digest_of};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const RUNNING: &str = "0a609ef542838d044052155b33ebf74882cba957ef35a33743fde53649d1ab06";
    const OTHER: &str = "9f78792990ccb0ab4dd416a9912ebcf8511cdbdf02b7b06778cb08ff28136503";
    const REVISION: &str = "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6";

    fn write_manifest(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("manifest directory");
        }
        std::fs::write(path, body).expect("manifest");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private manifest");
    }

    fn manifest_body(digest: &str, revision: &str) -> String {
        format!(
            r#"{{"schema":"automonique.web-entry-release/v1","source_sha":"{revision}","binary_sha256":"{digest}"}}"#
        )
    }

    #[test]
    fn a_deployed_binary_looks_above_its_own_directory_and_through_current() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        std::os::unix::fs::symlink("releases/one", root.path().join("current")).expect("pointer");

        let candidates = candidate_manifests(&executable);

        assert_eq!(
            candidates,
            vec![
                root.path().join("bin/manifest.json"),
                root.path().join("manifest.json"),
                root.path().join("releases/one/manifest.json"),
            ]
        );
    }

    #[test]
    fn a_daemon_release_is_found_through_its_improvement_code_selector() {
        // The daemon activates under `improvement-code/`, so its manifest sits
        // one level deeper than a web entry's. Reached in the live layout this
        // is the difference between doctor validating the deployment and
        // reporting `release.missing` while a manifest is being honoured.
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        std::fs::create_dir_all(root.path().join("improvement-code")).expect("activation root");
        std::os::unix::fs::symlink(
            "releases/9ec663ba",
            root.path().join("improvement-code/current"),
        )
        .expect("pointer");

        let candidates = candidate_manifests(&executable);

        assert!(
            candidates.contains(
                &root
                    .path()
                    .join("improvement-code/releases/9ec663ba/manifest.json")
            ),
            "the daemon's activated release must be reachable, got {candidates:?}"
        );
    }

    #[test]
    fn a_manifest_under_current_that_names_another_binary_is_a_finding() {
        // The live defect, reproduced: `bin/` was replaced, `current` still
        // points at the release it was replaced from, and that release is
        // internally consistent about a build which is not the one running.
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        std::os::unix::fs::symlink("releases/one", root.path().join("current")).expect("pointer");
        write_manifest(
            &root.path().join("releases/one/manifest.json"),
            &manifest_body(OTHER, REVISION),
        );

        assert_eq!(
            attribute_release(&candidate_manifests(&executable), Some(RUNNING), None),
            ReleaseAttribution::DescribesAnotherBuild
        );
    }

    #[test]
    fn a_manifest_describing_the_running_binary_confirms_it() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        write_manifest(
            &root.path().join("manifest.json"),
            &manifest_body(RUNNING, REVISION),
        );

        let candidates = candidate_manifests(&executable);
        assert_eq!(
            attribute_release(&candidates, Some(RUNNING), Some(REVISION)),
            ReleaseAttribution::Confirmed
        );
        // A build that cannot vouch for a revision does not get to contradict
        // the manifest with one.
        assert_eq!(
            attribute_release(&candidates, Some(RUNNING), None),
            ReleaseAttribution::Confirmed
        );
    }

    #[test]
    fn a_manifest_matching_the_bytes_but_not_the_revision_is_a_finding() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        write_manifest(
            &root.path().join("manifest.json"),
            &manifest_body(RUNNING, REVISION),
        );

        assert_eq!(
            attribute_release(
                &candidate_manifests(&executable),
                Some(RUNNING),
                Some("d5666f9c85080609f58f2d201dbe15ae1b8fcbb3"),
            ),
            ReleaseAttribution::RevisionDisagrees
        );
    }

    #[test]
    fn a_correct_manifest_wins_over_a_stale_one_in_any_position() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        std::os::unix::fs::symlink("releases/one", root.path().join("current")).expect("pointer");
        write_manifest(
            &root.path().join("releases/one/manifest.json"),
            &manifest_body(OTHER, REVISION),
        );
        write_manifest(
            &root.path().join("manifest.json"),
            &manifest_body(RUNNING, REVISION),
        );

        assert_eq!(
            attribute_release(&candidate_manifests(&executable), Some(RUNNING), None),
            ReleaseAttribution::Confirmed
        );
    }

    #[test]
    fn a_manifest_without_a_binary_digest_cannot_be_checked() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");
        write_manifest(
            &root.path().join("manifest.json"),
            r#"{"schema":"automonique.web-entry-release/v1","source_sha":"39747eaf63f32ad43e3cb045b36bd6fbaed46cf6"}"#,
        );

        assert_eq!(
            attribute_release(&candidate_manifests(&executable), Some(RUNNING), None),
            ReleaseAttribution::DigestUnrecorded
        );
    }

    #[test]
    fn no_manifest_anywhere_is_absent_rather_than_a_finding() {
        let root = tempfile::tempdir().expect("root");
        let executable = root.path().join("bin/automonique-web-entry");
        std::fs::create_dir_all(executable.parent().expect("bin")).expect("bin");

        assert_eq!(
            attribute_release(&candidate_manifests(&executable), Some(RUNNING), None),
            ReleaseAttribution::Absent
        );
    }

    #[test]
    fn an_undigestible_image_compares_nothing() {
        assert_eq!(
            attribute_release(&[], None, Some(REVISION)),
            ReleaseAttribution::BinaryUnreadable
        );
        assert_eq!(digest_of(Path::new("/nonexistent/image")), None);
    }

    #[test]
    fn the_running_image_digests_to_the_test_binary() {
        let running = super::running_image_digest().expect("running image");
        let executable = std::env::current_exe().expect("current executable");
        assert_eq!(digest_of(&executable).as_deref(), Some(running.as_str()));
        assert_eq!(running.len(), 64);
    }
}
