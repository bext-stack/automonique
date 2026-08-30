// SPDX-License-Identifier: Elastic-2.0

//! Place the source revision this build came from into the build itself.
//!
//! Three environments have to produce an answer here, and only one of them has
//! a revision to hand:
//!
//! - a release pipeline, which knows exactly which commit it is building and
//!   says so in the variable named by `src/declaration.rs`;
//! - a working checkout, where `git` can be asked;
//! - a source tarball or a vendored build, where there is no `git` metadata at
//!   all.
//!
//! The third case is why this file exists in the shape it does. The tempting
//! failure is to fall back to something that *looks* like a revision — the
//! package version, a truncated digest, the last known value — and ship a
//! binary that names a commit it was not built from. A build that cannot
//! establish its revision emits `unknown`, and every consumer downstream is
//! written so that `unknown` is a usable answer.
//!
//! The same rule governs a modified working tree. A build made over
//! uncommitted changes is not the commit at `HEAD`, so it says `modified` and
//! nothing treats it as attributable.
//!
//! ## What the rerun directives can and cannot promise
//!
//! Cargo caches a build script's output. The directives below invalidate that
//! cache when `HEAD` moves, when the index is written (`git add`, `commit`,
//! `checkout`, `stash`), when a watched ref file changes, or when the
//! declaration variable changes — which covers every way a *commit* changes
//! under a build.
//!
//! It does not cover one case: editing a tracked file without touching the
//! index, after a build script run that observed a clean tree. That build
//! carries a stale `committed` claim. Closing it would mean invalidating this
//! crate — and therefore every crate that depends on it — on every source edit
//! in the workspace, which is a large, permanent cost on every developer build
//! and every CI job to correct a claim no release path can reach: a release is
//! built by `release_builder`, in a fresh worktree with a fresh target
//! directory, and declares its revision outright. The residual hole is
//! therefore local to a developer's incremental build, and it is why
//! `automonique doctor` verifies the *digest of the running executable*
//! against the manifest rather than trusting either side's revision alone.

use std::path::{Path, PathBuf};
use std::process::Command;

// A build script cannot link the crate it belongs to, so the variable's
// spelling is shared as source rather than restated here. See the file itself.
include!("src/declaration.rs");

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed={DECLARED_REVISION_VARIABLE}");
    let manifest_directory = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo always sets CARGO_MANIFEST_DIR"),
    );
    watch_git_metadata(&manifest_directory);
    let (revision, provenance) = identity(&manifest_directory);
    println!("cargo::rustc-env=AUTOMONIQUE_BUILD_SOURCE_REVISION={revision}");
    println!("cargo::rustc-env=AUTOMONIQUE_BUILD_PROVENANCE={provenance}");
    println!(
        "cargo::rustc-env=AUTOMONIQUE_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
}

/// Establish the revision and how it was established, or refuse to guess.
fn identity(manifest_directory: &Path) -> (String, &'static str) {
    if let Some(declared) = std::env::var_os(DECLARED_REVISION_VARIABLE) {
        let declared = declared.to_string_lossy().trim().to_owned();
        // A pipeline that declares a malformed revision has a bug, and silently
        // falling back to `git` here would attribute the build to whatever the
        // build host happened to have checked out. Stop instead.
        assert!(
            is_revision(&declared),
            "{DECLARED_REVISION_VARIABLE} must be 40 lowercase hexadecimal characters, \
             and this build will not substitute a revision of its own choosing"
        );
        return (declared, "declared");
    }
    let Some(revision) =
        git(manifest_directory, &["rev-parse", "HEAD"]).filter(|candidate| is_revision(candidate))
    else {
        return (String::new(), "unknown");
    };
    // A failed `status` is not a clean tree. Without an answer about the working
    // tree there is no basis for claiming the binary is the commit, so the
    // revision is dropped rather than published under a state nobody observed.
    match git(manifest_directory, &["status", "--porcelain"]) {
        Some(status) if status.is_empty() => (revision, "committed"),
        Some(_) => (revision, "modified"),
        None => (String::new(), "unknown"),
    }
}

/// Invalidate this build script whenever the commit under it could have moved.
///
/// Only paths that exist are watched. Cargo treats a `rerun-if-changed` path it
/// cannot stat as changed, so naming a ref file that is packed rather than
/// loose would rebuild this crate — and everything above it — on every single
/// cargo invocation.
fn watch_git_metadata(manifest_directory: &Path) {
    let mut watched = vec![
        String::from("HEAD"),
        String::from("index"),
        String::from("packed-refs"),
    ];
    if let Some(reference) = git(manifest_directory, &["symbolic-ref", "--quiet", "HEAD"]) {
        watched.push(reference);
    }
    for name in watched {
        let Some(path) = git(manifest_directory, &["rev-parse", "--git-path", &name]) else {
            continue;
        };
        let path = manifest_directory.join(path);
        if path.exists() {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }
}

/// Run one `git` command in the checkout, or return `None` for any refusal.
///
/// Every failure mode — no `git` on the host, no repository, a repository the
/// build user is not trusted to read — collapses to the same answer, because
/// they all mean the same thing here: this build cannot establish a revision.
fn git(repository: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

/// Whether a string is a full lowercase-hexadecimal git object name.
fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
