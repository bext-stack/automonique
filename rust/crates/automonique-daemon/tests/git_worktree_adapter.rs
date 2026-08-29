// SPDX-License-Identifier: Elastic-2.0

//! Local staging boundary, exercised against real repositories.
//!
//! These live in their own process rather than beside the module. Every case
//! here spawns a child process, and a unit test that forks while another test
//! in the same process holds an advisory lock can make that lock look held for
//! as long as the child takes to `exec`. Keeping them out of the library's
//! test binary keeps that interference out of unrelated suites.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_daemon::platform_v2_git_worktree_adapter::*;
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId, WorkContextIdentity};
use automonique_protocol::platform_v2_review::{
    ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind, ReviewProposalId,
};
use automonique_protocol::primitives::Revision;
use tempfile::TempDir;
/// The effective uid, read from a file this process just created rather than
/// through a syscall wrapper this integration target does not depend on.
fn uid() -> u32 {
    let probe = TempDir::new().unwrap();
    let path = probe.path().join("probe");
    fs::write(&path, b"probe").unwrap();
    fs::metadata(&path).unwrap().uid()
}

fn run(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A private repository with one commit, exactly the shape the registry
/// admits: an absolute canonical root owned by this uid, not group or
/// other writable, holding a real `.git`.
fn repository(temporary: &TempDir) -> PathBuf {
    let root = temporary.path().join("repository");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    run(&root, &["init", "--quiet", "--initial-branch=main", "."]);
    run(&root, &["config", "user.email", "review@example.invalid"]);
    run(&root, &["config", "user.name", "Review"]);
    fs::write(root.join("tracked.txt"), "base\n").unwrap();
    run(&root, &["add", "--", "tracked.txt"]);
    run(&root, &["commit", "--quiet", "-m", "base"]);
    // The registry admits only a private tree with a private `.git`, and
    // the capability re-checks it, so the fixture has to be that shape.
    fs::set_permissions(root.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::canonicalize(&root).unwrap()
}

fn grants_all() -> GitStagingGrants {
    GitStagingGrants {
        index_write: true,
        commit: true,
        conflict_resolution: true,
    }
}

fn adapter(root: &Path, grants: GitStagingGrants) -> GitWorktreeAdapter {
    GitWorktreeAdapter::new(GitWorktreeWriteCapability::production(root, uid(), grants).unwrap())
}

fn file(value: &str) -> RepositoryFile {
    RepositoryFile::new(value).unwrap()
}

fn actor() -> Actor {
    Actor::new("tenant-1", "actor-1").unwrap()
}

fn binding() -> GitStagingReviewBinding {
    GitStagingReviewBinding {
        project: ProjectId::new("project-1").unwrap(),
        workspace: WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap()),
        authority: ReviewAuthority::new(
            ReviewAuthorityKind::Git,
            ReviewAuthorityId::new("git-1").unwrap(),
        ),
        idempotency_key: IdempotencyKey::new("staging-1").unwrap(),
        expected_snapshot_revision: Revision::FIRST,
    }
}

fn plan_for(
    adapter: &GitWorktreeAdapter,
    root: &Path,
    family: GitStagingFamily,
    paths: &[RepositoryFile],
    side: Option<ConflictSide>,
    subject: Option<&str>,
) -> (GitStagingPlan, GitWorktreeObservation) {
    let state = adapter.read(paths).unwrap();
    let observation = adapter.observe(&state, family, paths, side).unwrap();
    let plan = GitStagingPlan::new(
        [7; 32],
        GitStagingTarget {
            canonical_root: root.to_path_buf(),
            family,
            proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
            files: paths.to_vec(),
            conflict_path: side.map(|_| paths[0].clone()),
            side,
            subject: subject.map(str::to_owned),
            observation_digest: observation.digest(),
            observed_head: observation.head().commit().clone(),
            observed_index_digest: observation.index_digest(),
        },
        &actor(),
        binding(),
    )
    .unwrap();
    (plan, observation)
}

fn started(plan: &GitStagingPlan) -> GitStagingSubmission {
    let mut submission = GitStagingSubmission::new(plan);
    submission.begin_custody().unwrap();
    submission
}

/// A path that could name a second file, reach outside the worktree, or
/// rewrite the repository's own metadata is unconstructable.
///
/// This is the local analogue of the pull-request connector's branch name
/// that cannot contain a slash: the hazard here is not a path segment on a
/// URL but a pathspec that means more than the one file it appears to.
#[test]
fn a_repository_path_cannot_escape_glob_or_name_the_git_directory() {
    for hostile in [
        "",
        "/etc/passwd",
        "../outside",
        "a/../../outside",
        "a/./b",
        "a//b",
        ".git/config",
        ".GIT/config",
        "nested/.Git/hooks/pre-commit",
        "-rf",
        "a\\b",
        "src/*.rs",
        "src/[a-z].rs",
        "src/?.rs",
        ":(glob)**/*.rs",
        "with\0nul",
        "with\nnewline",
        " leading/space",
        "trailing /space",
    ] {
        assert!(
            RepositoryFile::new(hostile).is_err(),
            "{hostile:?} must not be constructable",
        );
    }
    // The rendering is the other half: a valid path always reaches git as
    // a literal, top-rooted, single-file pathspec.
    assert_eq!(
        file("src/review.rs").pathspec(),
        ":(literal,top)src/review.rs"
    );
    // A ref name is not an object id, so a fence can never be a name that
    // moves.
    assert!(ObjectId::new("HEAD").is_err());
    assert!(ObjectId::new("refs/heads/main").is_err());
    assert!(ObjectId::new("0123456789ABCDEF0123456789ABCDEF01234567").is_err());
    assert!(ObjectId::new("0123456789abcdef0123456789abcdef01234567").is_ok());
    // A branch is always fully qualified, so a bare name or a ref outside
    // `refs/heads` cannot be observed as one.
    assert!(BranchRef::new("main").is_err());
    assert!(BranchRef::new("refs/remotes/origin/main").is_err());
    assert!(BranchRef::new("refs/heads/../../evil").is_err());
    assert!(BranchRef::new("refs/heads/main").is_ok());
}

/// A binding is a configuration fact. Only a read of the repository can
/// say what a staging write depends on.
#[test]
fn a_read_observes_the_head_the_index_and_each_named_file() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    fs::write(root.join("added.txt"), "new\n").unwrap();
    let paths = vec![file("added.txt"), file("tracked.txt")];
    let state = adapter.read(&paths).unwrap();

    assert!(matches!(state.head(), GitHead::Attached { .. }));
    assert_eq!(
        state.head().reference().map(BranchRef::as_str),
        Some("refs/heads/main")
    );
    assert!(state.identity_configured());
    assert!(!state.sequencer().in_progress());
    assert!(state.file(&file("tracked.txt")).unwrap().unstaged());
    assert!(state.file(&file("added.txt")).unwrap().untracked());
    // Nothing is staged yet, so the index equals HEAD.
    assert_eq!(state.staged_paths().count(), 0);

    // Staging one file moves the index, and the digest moves with it.
    let before = state.index_digest();
    run(&root, &["add", "--", "tracked.txt"]);
    let after = adapter.read(&paths).unwrap();
    assert_ne!(
        before,
        after.index_digest(),
        "an index mutation must change the digest the fence is built on",
    );
    assert_eq!(
        after.staged_paths().collect::<Vec<_>>(),
        vec!["tracked.txt"]
    );
}

/// The three grants are withheld independently, and the adapter refuses a
/// family it does not carry however the caller reached it.
#[test]
fn each_grant_is_withheld_on_its_own() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    let paths = vec![file("tracked.txt")];

    let index_only = adapter(
        &root,
        GitStagingGrants {
            index_write: true,
            ..GitStagingGrants::default()
        },
    );
    let state = index_only.read(&paths).unwrap();
    assert!(
        index_only
            .observe(&state, GitStagingFamily::Stage, &paths, None)
            .is_ok()
    );
    assert_eq!(
        index_only
            .observe(&state, GitStagingFamily::Commit, &paths, None)
            .unwrap_err(),
        GitWorktreeError::CommitWithheld,
        "a grant to move index entries must never imply recording them",
    );
    assert_eq!(
        index_only
            .observe(
                &state,
                GitStagingFamily::ResolveConflict,
                &paths,
                Some(ConflictSide::Ours)
            )
            .unwrap_err(),
        GitWorktreeError::ConflictResolutionWithheld,
    );

    // And the reverse: resolving is not implied by index writes either.
    let resolve_only = adapter(
        &root,
        GitStagingGrants {
            conflict_resolution: true,
            ..GitStagingGrants::default()
        },
    );
    assert_eq!(
        resolve_only
            .observe(&state, GitStagingFamily::Stage, &paths, None)
            .unwrap_err(),
        GitWorktreeError::CapabilityMismatch,
    );

    // A capability that permits nothing is a configuration mistake.
    assert!(
        GitWorktreeWriteCapability::production(&root, uid(), GitStagingGrants::default()).is_err()
    );
}

/// Staging performs the write and verifies it rather than assuming it.
#[test]
fn staging_moves_the_index_and_is_verified_afterwards() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    let paths = vec![file("tracked.txt")];
    let (plan, _) = plan_for(&adapter, &root, GitStagingFamily::Stage, &paths, None, None);
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap(),
        GitStagingCustody::Accepted
    );
    let state = adapter.read(&paths).unwrap();
    assert!(state.file(&file("tracked.txt")).unwrap().staged());

    // Reconciling an accepted write against the effect it produced
    // completes it; the same read without the acknowledgement never does.
    assert_eq!(
        adapter.reconcile(&plan, &mut submission).unwrap(),
        GitStagingCustody::Completed
    );
    let mut uncorrelated =
        GitStagingSubmission::restore(&plan, plan.digest(), GitStagingCustody::Ambiguous, None)
            .unwrap();
    assert_eq!(
        adapter.reconcile(&plan, &mut uncorrelated).unwrap(),
        GitStagingCustody::Ambiguous,
        "an observation nobody acknowledged could be another actor's write",
    );
}

/// Unstaging names the observed commit rather than `HEAD`.
#[test]
fn unstaging_restores_from_the_observed_commit_not_from_a_ref() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    run(&root, &["add", "--", "tracked.txt"]);
    let paths = vec![file("tracked.txt")];
    let (plan, _) = plan_for(
        &adapter,
        &root,
        GitStagingFamily::Unstage,
        &paths,
        None,
        None,
    );
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap(),
        GitStagingCustody::Accepted
    );
    let state = adapter.read(&paths).unwrap();
    assert!(!state.file(&file("tracked.txt")).unwrap().staged());
    assert!(state.file(&file("tracked.txt")).unwrap().unstaged());
}

/// A commit is only advertised when the whole index is the proposal.
///
/// `git commit` writes the index, not a file list. If anything else is
/// staged, this commit would record changes nobody reviewed, so nothing is
/// advertised at all.
#[test]
fn a_commit_is_refused_while_the_index_holds_anything_else() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    fs::write(root.join("other.txt"), "other\n").unwrap();
    run(&root, &["add", "--", "tracked.txt", "other.txt"]);
    let paths = vec![file("tracked.txt")];
    let state = adapter.read(&paths).unwrap();
    assert_eq!(
        adapter
            .observe(&state, GitStagingFamily::Commit, &paths, None)
            .unwrap_err(),
        GitWorktreeError::WorktreeChanged,
    );

    // With the index holding exactly the proposal, the commit is planned,
    // performed, and attributed by its own parent.
    run(&root, &["restore", "--staged", "--", "other.txt"]);
    let (plan, _) = plan_for(
        &adapter,
        &root,
        GitStagingFamily::Commit,
        &paths,
        None,
        Some("record the reviewed change"),
    );
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap(),
        GitStagingCustody::Accepted
    );
    let recorded = submission.resulting_head().cloned().unwrap();
    assert_ne!(&recorded, plan.observed_head());
    let state = adapter.read(&paths).unwrap();
    assert_eq!(state.head().commit(), &recorded);
    assert_eq!(
        adapter.reconcile(&plan, &mut submission).unwrap(),
        GitStagingCustody::Completed
    );
}

/// A commit is refused while any multi-step operation is in progress, and
/// while the repository names no committer.
#[test]
fn a_commit_is_refused_mid_operation_and_without_a_configured_identity() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    run(&root, &["add", "--", "tracked.txt"]);
    let paths = vec![file("tracked.txt")];
    assert!(
        adapter
            .observe(
                &adapter.read(&paths).unwrap(),
                GitStagingFamily::Commit,
                &paths,
                None
            )
            .is_ok()
    );

    // A merge in progress has its own completion semantics that one fenced
    // commit cannot honour.
    fs::write(
        fs::canonicalize(root.join(".git"))
            .unwrap()
            .join("MERGE_HEAD"),
        "0123456789abcdef0123456789abcdef01234567\n",
    )
    .unwrap();
    let state = adapter.read(&paths).unwrap();
    assert!(state.sequencer().in_progress());
    assert_eq!(
        adapter
            .observe(&state, GitStagingFamily::Commit, &paths, None)
            .unwrap_err(),
        GitWorktreeError::WorktreeChanged,
    );
    // Staging stays available: mid-merge is exactly when it is needed.
    assert!(
        adapter
            .observe(&state, GitStagingFamily::Unstage, &paths, None)
            .is_ok()
    );
    fs::remove_file(
        fs::canonicalize(root.join(".git"))
            .unwrap()
            .join("MERGE_HEAD"),
    )
    .unwrap();

    // Global and system configuration are disabled for every command here,
    // so a repository that names no committer would have a commit
    // attributed to somebody who never chose to be named.
    run(&root, &["config", "--unset", "user.email"]);
    let state = adapter.read(&paths).unwrap();
    assert!(!state.identity_configured());
    assert_eq!(
        adapter
            .observe(&state, GitStagingFamily::Commit, &paths, None)
            .unwrap_err(),
        GitWorktreeError::WorktreeChanged,
    );
}

/// A conflict resolution writes one of the two blobs git already holds,
/// and nothing else.
#[test]
fn resolving_a_conflict_writes_only_a_recorded_stage() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    run(&root, &["checkout", "--quiet", "-b", "side"]);
    fs::write(root.join("tracked.txt"), "incoming\n").unwrap();
    run(&root, &["commit", "--quiet", "-am", "side"]);
    run(&root, &["checkout", "--quiet", "main"]);
    fs::write(root.join("tracked.txt"), "current\n").unwrap();
    run(&root, &["commit", "--quiet", "-am", "current"]);
    // A conflicting merge, which leaves the path unmerged with both sides
    // recorded in the index.
    let merge = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["merge", "side"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(!merge.status.success(), "the merge must conflict");

    let paths = vec![file("tracked.txt")];
    let state = adapter.read(&paths).unwrap();
    let observed = state.file(&file("tracked.txt")).unwrap();
    assert!(observed.conflict().is_some());
    // Both sides were recorded, so both are observable and each is its own
    // plan with its own digest.
    let ours = adapter
        .observe(
            &state,
            GitStagingFamily::ResolveConflict,
            &paths,
            Some(ConflictSide::Ours),
        )
        .unwrap();
    let theirs = adapter
        .observe(
            &state,
            GitStagingFamily::ResolveConflict,
            &paths,
            Some(ConflictSide::Theirs),
        )
        .unwrap();
    assert_ne!(
        ours.digest(),
        theirs.digest(),
        "the side decides which bytes land, so it must be inside the digest",
    );

    let (plan, _) = plan_for(
        &adapter,
        &root,
        GitStagingFamily::ResolveConflict,
        &paths,
        Some(ConflictSide::Theirs),
        None,
    );
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap(),
        GitStagingCustody::Accepted
    );
    // Exactly the recorded stage-3 blob, in the working tree and in the
    // index. Nothing this process chose.
    assert_eq!(
        fs::read_to_string(root.join("tracked.txt")).unwrap(),
        "incoming\n"
    );
    let state = adapter.read(&paths).unwrap();
    assert!(
        state
            .file(&file("tracked.txt"))
            .unwrap()
            .conflict()
            .is_none()
    );
}

/// The digest is what makes the fence a fence.
///
/// A worktree that moves after advertisement produces a different
/// observation digest, so the plan's preflight refuses and — because the
/// refusal happens before any command that writes — nothing is half
/// applied.
#[test]
fn a_worktree_that_moved_after_advertisement_refuses_before_writing() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    let paths = vec![file("tracked.txt")];

    // (1) The index moved under us: somebody else staged another file.
    let (plan, _) = plan_for(&adapter, &root, GitStagingFamily::Stage, &paths, None, None);
    fs::write(root.join("other.txt"), "other\n").unwrap();
    run(&root, &["add", "--", "other.txt"]);
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap_err(),
        GitWorktreeError::WorktreeChanged
    );
    assert_eq!(
        submission.custody(),
        GitStagingCustody::Refused,
        "a refusal before any write is proved-not-started, never ambiguous",
    );
    assert!(
        !adapter
            .read(&paths)
            .unwrap()
            .file(&file("tracked.txt"))
            .unwrap()
            .staged(),
        "nothing may be half applied when the fence refuses",
    );

    // (2) HEAD moved under us.
    run(&root, &["restore", "--staged", "--", "other.txt"]);
    fs::remove_file(root.join("other.txt")).unwrap();
    let (plan, _) = plan_for(&adapter, &root, GitStagingFamily::Stage, &paths, None, None);
    fs::write(root.join("unrelated.txt"), "unrelated\n").unwrap();
    run(&root, &["add", "--", "unrelated.txt"]);
    run(&root, &["commit", "--quiet", "-m", "somebody else"]);
    run(&root, &["rm", "--quiet", "--cached", "--", "unrelated.txt"]);
    run(&root, &["commit", "--quiet", "-m", "and again"]);
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap_err(),
        GitWorktreeError::WorktreeChanged
    );
    assert_eq!(submission.custody(), GitStagingCustody::Refused);

    // (3) The named file's own bytes moved under us. The stat identity is
    // git's own freshness test, so a rewrite invalidates the observation
    // the client confirmed.
    let (plan, _) = plan_for(&adapter, &root, GitStagingFamily::Stage, &paths, None, None);
    std::thread::sleep(std::time::Duration::from_millis(10));
    fs::write(root.join("tracked.txt"), "changed again\n").unwrap();
    let mut submission = started(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut submission).unwrap_err(),
        GitWorktreeError::WorktreeChanged
    );
    assert_eq!(submission.custody(), GitStagingCustody::Refused);
}

/// A plan is bound to one capability, one shape, and one custody sequence.
#[test]
fn a_plan_is_bound_to_its_capability_shape_and_custody() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    let adapter = adapter(&root, grants_all());
    fs::write(root.join("tracked.txt"), "changed\n").unwrap();
    let paths = vec![file("tracked.txt")];
    let (plan, observation) =
        plan_for(&adapter, &root, GitStagingFamily::Stage, &paths, None, None);

    // Only a commit carries a subject, and only a resolution carries a
    // side. A shape that mixes them cannot be built.
    assert!(
        GitStagingPlan::new(
            [7; 32],
            GitStagingTarget {
                canonical_root: root.clone(),
                family: GitStagingFamily::Stage,
                proposal_id: ReviewProposalId::new("proposal-1").unwrap(),
                files: paths.clone(),
                conflict_path: None,
                side: None,
                subject: Some("a stage does not record anything".to_owned()),
                observation_digest: observation.digest(),
                observed_head: observation.head().commit().clone(),
                observed_index_digest: observation.index_digest(),
            },
            &actor(),
            binding(),
        )
        .is_err()
    );

    // A plan for one root is refused by an adapter bound to another.
    let elsewhere = TempDir::new().unwrap();
    let other_root = repository(&elsewhere);
    let other = GitWorktreeAdapter::new(
        GitWorktreeWriteCapability::production(&other_root, uid(), grants_all()).unwrap(),
    );
    let mut submission = started(&plan);
    assert_eq!(
        other.submit(&plan, &mut submission).unwrap_err(),
        GitWorktreeError::CapabilityMismatch
    );

    // Custody must have begun, and having begun cannot begin again.
    let mut fresh = GitStagingSubmission::new(&plan);
    assert_eq!(
        adapter.submit(&plan, &mut fresh).unwrap_err(),
        GitWorktreeError::SubmissionState
    );
    fresh.begin_custody().unwrap();
    assert!(fresh.begin_custody().is_err());

    // A restored row must be this plan's, and a head recorded for a family
    // that produces none is corruption rather than a state to carry on
    // from.
    assert!(
        GitStagingSubmission::restore(&plan, [0; 32], GitStagingCustody::CustodyStarted, None)
            .is_err()
    );
    assert!(
        GitStagingSubmission::restore(
            &plan,
            plan.digest(),
            GitStagingCustody::Accepted,
            Some(ObjectId::new("0123456789abcdef0123456789abcdef01234567").unwrap()),
        )
        .is_err(),
        "only a commit ever produces a new head",
    );
}

/// A repository that is not the private one the capability claims cannot
/// be minted for, whatever the registry said when it was loaded.
#[test]
fn a_capability_revalidates_the_repository_it_is_minted_for() {
    let temporary = TempDir::new().unwrap();
    let root = repository(&temporary);
    assert!(GitWorktreeWriteCapability::production(&root, uid(), grants_all()).is_ok());
    // Group-writable is exactly what the registry refuses at load, and it
    // has to stay refused here because a directory can be changed after a
    // registry was read.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        GitWorktreeWriteCapability::production(&root, uid(), grants_all())
            .err()
            .unwrap(),
        GitWorktreeError::RepositoryUnavailable
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    // A uid that does not own the tree cannot be written to on this
    // capability's account.
    assert!(GitWorktreeWriteCapability::production(&root, uid() + 1, grants_all()).is_err());
    // A relative path is not a canonical root.
    assert!(
        GitWorktreeWriteCapability::production(Path::new("repository"), uid(), grants_all())
            .is_err()
    );
}
