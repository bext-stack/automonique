// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::worktree::WorktreeAllocator;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

#[test]
fn state_and_source_roots_cannot_overlap_in_either_direction() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    let repository = temporary.path().join("repository");
    fs::create_dir(&repository).expect("repository");
    git(&repository, &["init", "-q"]);

    let descendant = repository.join("state");
    assert!(WorktreeAllocator::open(&repository, &descendant).is_err());
    assert!(!descendant.exists());

    assert!(WorktreeAllocator::open(&repository, temporary.path()).is_err());
}

#[test]
fn a_symlinked_state_leaf_is_denied_without_mutating_its_target() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    let repository = temporary.path().join("repository");
    let target = temporary.path().join("target");
    let state = temporary.path().join("state-link");
    fs::create_dir(&repository).expect("repository");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("target mode");
    git(&repository, &["init", "-q"]);
    symlink(&target, &state).expect("state symlink");
    assert!(WorktreeAllocator::open(&repository, &state).is_err());
    assert!(target.read_dir().expect("target entries").next().is_none());
}

#[test]
fn external_separate_git_directory_is_denied_before_state_creation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    let repository = temporary.path().join("repository");
    let git_directory = temporary.path().join("external-git");
    let state = temporary.path().join("state");
    fs::create_dir(&repository).expect("repository");
    let status = Command::new("git")
        .args(["init", "-q", "--separate-git-dir"])
        .arg(&git_directory)
        .arg(&repository)
        .status()
        .expect("initialize repository");
    assert!(status.success());
    assert!(WorktreeAllocator::open(&repository, &state).is_err());
    assert!(!state.exists());
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .status()
        .expect("run Git");
    assert!(status.success(), "git {arguments:?}");
}
