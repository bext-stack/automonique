// SPDX-License-Identifier: Elastic-2.0

//! Crate-internal tests for sealed Git broker authority.

use crate::git::{
    BranchName, CandidateCoordinates, CandidateId, CandidateRequest, CandidateScope, FaultPoint,
    GitBroker, GitError, GitOperation, LeaseProof, ObjectId, ReconcileDisposition,
};
use crate::protocol::{OpaqueId, Sha256Digest};
use crate::recovery::CandidateRecovery;
use crate::state::{
    AcquirePaths, AttemptState, ControllerRoot, StateError, StateStore, TransitionAttempt,
};
use crate::workspace_lease::{
    ActionId, AttemptId, BaseRevision, FenceEpoch, LeaseId, Mutation, RepoPath, Revision,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    repository: PathBuf,
    state: PathBuf,
    base: ObjectId,
    lease_store: StateStore,
    lease_epoch: FenceEpoch,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        #[cfg(unix)]
        std::fs::set_permissions(
            temporary.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private temporary directory");
        let repository = temporary.path().join("repository");
        let state = temporary.path().join("state");
        std::fs::create_dir(&repository).expect("repository directory");
        git(&repository, &["init", "-b", "main"]);
        std::fs::create_dir(repository.join("leased")).expect("leased directory");
        std::fs::write(repository.join("leased/a.txt"), b"base\n").expect("base file");
        std::fs::write(repository.join("outside.txt"), b"outside\n").expect("outside file");
        git(&repository, &["add", "leased/a.txt", "outside.txt"]);
        git(
            &repository,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@automonique.invalid",
                "commit",
                "-m",
                "base",
            ],
        );
        let base =
            ObjectId::parse(git_text(&repository, &["rev-parse", "HEAD"])).expect("base object ID");
        let mut lease_store = StateStore::open(
            &ControllerRoot { seal: () },
            temporary.path().join("lease-state.sqlite3"),
        )
        .expect("lease state opens");
        let authority = lease_store.broker_authority();
        let base_revision = BaseRevision::parse(base.as_str()).expect("base revision");
        lease_store
            .create_attempt(
                &authority,
                AttemptId::parse("attempt-1").expect("attempt"),
                OpaqueId::new("objective-1").expect("objective"),
                base_revision.clone(),
            )
            .expect("attempt created");
        let lease = lease_store
            .acquire_paths(
                &authority,
                AcquirePaths {
                    action_id: ActionId::parse("acquire-1").expect("action"),
                    lease_id: LeaseId::parse("lease-1").expect("lease"),
                    attempt_id: AttemptId::parse("attempt-1").expect("attempt"),
                    base_revision,
                    expected_revision: Revision::default(),
                    paths: vec![RepoPath::parse("leased").expect("path")],
                },
            )
            .expect("lease acquired");
        let lease_epoch = match lease {
            Mutation::Applied(receipt) | Mutation::Replayed(receipt) => receipt.epoch,
        };
        Self {
            _temporary: temporary,
            repository,
            state,
            base,
            lease_store,
            lease_epoch,
        }
    }

    fn broker(&self) -> GitBroker {
        GitBroker::open(&self.repository, &self.state).expect("broker opens")
    }

    fn proof(&self) -> LeaseProof {
        let authority = self.lease_store.broker_authority();
        let verified = self
            .lease_store
            .verify_active_lease(
                &authority,
                &AttemptId::parse("attempt-1").expect("attempt"),
                &LeaseId::parse("lease-1").expect("lease"),
                self.lease_epoch,
                &BaseRevision::parse(self.base.as_str()).expect("base"),
                vec![RepoPath::parse("leased").expect("path")],
            )
            .expect("active lease verified");
        LeaseProof::from_verified_active_lease(verified)
    }

    fn modify(&self) {
        std::fs::write(self.repository.join("leased/a.txt"), b"candidate\n")
            .expect("candidate file");
    }

    fn request(&self, id: &str, proof: LeaseProof) -> CandidateRequest {
        self.request_for(id, proof, GitOperation::CreateCandidate)
    }

    fn request_for(
        &self,
        id: &str,
        proof: LeaseProof,
        operation: GitOperation,
    ) -> CandidateRequest {
        let broker = self.broker();
        let branch = BranchName::parse("main").expect("branch");
        let candidates = vec![RepoPath::parse("leased/a.txt").expect("candidate path")];
        let tree = broker
            .inspect_candidate_tree(&self.base, &branch, &proof, &candidates)
            .expect("candidate tree");
        CandidateRequest::new(
            operation,
            CandidateId::parse(id).expect("candidate ID"),
            CandidateCoordinates::new(self.base.clone(), branch, tree),
            CandidateScope::new(proof, candidates).expect("scope"),
            "bounded candidate",
        )
        .expect("request")
    }
}

#[test]
fn exact_candidate_preserves_head_index_and_uses_only_proposal_ref() {
    let fixture = Fixture::new();
    fixture.modify();
    let broker = fixture.broker();
    let request = fixture.request("candidate-1", fixture.proof());
    let index = std::fs::read(fixture.repository.join(".git/index")).expect("index");
    let outcome = broker.create(&request).expect("candidate");
    assert_eq!(
        fixture.base.as_str(),
        git_text(&fixture.repository, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        index,
        std::fs::read(fixture.repository.join(".git/index")).expect("index")
    );
    assert_eq!(
        outcome.receipt().commit_oid().as_str(),
        git_text(
            &fixture.repository,
            &["rev-parse", outcome.receipt().ref_name()]
        )
    );
    let raw = git_text(
        &fixture.repository,
        &[
            "cat-file",
            "commit",
            outcome.receipt().commit_oid().as_str(),
        ],
    );
    assert!(raw.contains(
        "author Automonique Candidate Broker <candidate@automonique.invalid> 946684800 +0000"
    ));
    assert!(raw.contains(
        "committer Automonique Candidate Broker <candidate@automonique.invalid> 946684800 +0000"
    ));
    let refs = git_text(
        &fixture.repository,
        &["for-each-ref", "--format=%(refname)"],
    );
    assert_eq!(2, refs.lines().count());
}

#[test]
fn forbidden_operations_and_forged_coordinates_are_denied() {
    let fixture = Fixture::new();
    fixture.modify();
    for (index, operation) in [
        GitOperation::Push,
        GitOperation::Merge,
        GitOperation::Force,
        GitOperation::Reset,
        GitOperation::Stash,
        GitOperation::Checkout,
        GitOperation::RemoteEdit,
        GitOperation::Tag,
        GitOperation::HistoryRewrite,
    ]
    .into_iter()
    .enumerate()
    {
        let denied = fixture.request_for(&format!("deny-{index}"), fixture.proof(), operation);
        assert_eq!(
            Err(GitError::ForbiddenOperation(operation)),
            fixture.broker().create(&denied)
        );
    }
    let authority = fixture.lease_store.broker_authority();
    assert!(matches!(
        fixture.lease_store.verify_active_lease(
            &authority,
            &AttemptId::parse("attempt-1").expect("attempt"),
            &LeaseId::parse("lease-1").expect("lease"),
            fixture.lease_epoch,
            &BaseRevision::parse("f".repeat(40)).expect("base"),
            vec![RepoPath::parse("leased").expect("path")],
        ),
        Err(StateError::BaseRevisionMismatch)
    ));
}

#[test]
fn minted_proof_is_revoked_by_terminal_lease_release() {
    let mut fixture = Fixture::new();
    fixture.modify();
    let proof = fixture.proof();
    let authority = fixture.lease_store.broker_authority();
    fixture
        .lease_store
        .transition(
            &authority,
            TransitionAttempt {
                action_id: ActionId::parse("finish-1").expect("action"),
                attempt_id: AttemptId::parse("attempt-1").expect("attempt"),
                base_revision: BaseRevision::parse(fixture.base.as_str()).expect("base"),
                expected_revision: Revision::from_u64(1),
                target: AttemptState::Blocked,
                event_digest: Sha256Digest::new("a".repeat(64)).expect("digest"),
            },
        )
        .expect("terminal transition");
    assert_eq!(
        Err(GitError::LeaseProofMismatch),
        fixture.broker().inspect_candidate_tree(
            &fixture.base,
            &BranchName::parse("main").expect("branch"),
            &proof,
            &[RepoPath::parse("leased/a.txt").expect("path")],
        )
    );
}

#[test]
fn permissive_existing_state_root_is_refused_without_chmod() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new();
    let shared = fixture._temporary.path().join("shared-state");
    std::fs::create_dir(&shared).expect("shared directory");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
        .expect("permissive mode");
    assert!(matches!(
        GitBroker::open(&fixture.repository, &shared),
        Err(GitError::UnsafePath(
            "existing private state directory mode is not 0700"
        ))
    ));
    assert_eq!(
        0o755,
        std::fs::symlink_metadata(&shared).expect("metadata").mode() & 0o7777
    );
}

#[test]
fn stale_proof_cannot_reconcile_durable_intent() {
    let fixture = Fixture::new();
    fixture.modify();
    let proof = fixture.proof();
    let request = fixture.request("stale-proof", proof.clone());
    let broker = fixture.broker();
    assert_eq!(
        Err(GitError::InjectedFault(FaultPoint::AfterIntent)),
        broker.create_with_fault(&request, Some(FaultPoint::AfterIntent))
    );
    let other_store = Fixture::new();
    let stale = other_store.proof();
    assert_eq!(
        Err(GitError::LeaseProofMismatch),
        CandidateRecovery::new(&broker).reconcile(request.candidate_id(), &stale)
    );
    assert_eq!(
        None,
        broker
            .candidate_ref_oid(request.candidate_id())
            .expect("ref")
    );
}

#[test]
fn all_fault_boundaries_reconcile_one_commit_and_replay() {
    for (index, point) in [
        FaultPoint::AfterIntent,
        FaultPoint::AfterCommit,
        FaultPoint::AfterRef,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new();
        fixture.modify();
        let proof = fixture.proof();
        let request = fixture.request(&format!("fault-{index}"), proof.clone());
        let broker = fixture.broker();
        assert_eq!(
            Err(GitError::InjectedFault(point)),
            broker.create_with_fault(&request, Some(point))
        );
        let recovery = CandidateRecovery::new(&broker);
        let applied = recovery
            .reconcile(request.candidate_id(), &proof)
            .expect("reconciled");
        let replay = recovery
            .reconcile(request.candidate_id(), &proof)
            .expect("replayed");
        assert_eq!(ReconcileDisposition::Applied, applied.disposition());
        assert_eq!(ReconcileDisposition::Replayed, replay.disposition());
        assert_eq!(applied.receipt(), replay.receipt());
    }
}

#[test]
fn external_indirected_git_directory_is_refused() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let repository = temporary.path().join("worktree");
    let external = temporary.path().join("external-git");
    let output = Command::new("git")
        .args(["init", "-b", "main", "--separate-git-dir"])
        .arg(&external)
        .arg(&repository)
        .output()
        .expect("Git init starts");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        GitBroker::open(&repository, temporary.path().join("state")),
        Err(GitError::UnsafePath(
            "Git metadata directory is outside the repository"
        ))
    ));
}

#[test]
fn metadata_substitution_after_open_is_denied() {
    let fixture = Fixture::new();
    let broker = fixture.broker();
    std::fs::rename(
        fixture.repository.join(".git"),
        fixture.repository.join(".git-old"),
    )
    .expect("move Git directory");
    std::fs::create_dir(fixture.repository.join(".git")).expect("substitute Git directory");
    assert!(matches!(
        broker.candidate_ref_oid(&CandidateId::parse("candidate-1").expect("ID")),
        Err(GitError::RepositoryDrift(
            "repository metadata identity changed"
        ))
    ));
}

#[test]
fn oversized_git_output_is_killed_and_bounded() {
    let fixture = Fixture::new();
    fixture.modify();
    for index in 0..600 {
        let name = format!("untracked-{index:04}-{}", "x".repeat(80));
        std::fs::write(fixture.repository.join(name), b"x").expect("untracked file");
    }
    let proof = fixture.proof();
    let paths = vec![RepoPath::parse("leased/a.txt").expect("path")];
    assert_eq!(
        Err(GitError::GitOutputLimit),
        fixture.broker().inspect_candidate_tree(
            &fixture.base,
            &BranchName::parse("main").expect("branch"),
            &proof,
            &paths,
        )
    );
}

#[test]
fn blocked_git_metadata_read_times_out_and_is_reaped() {
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    let fixture = Fixture::new();
    fixture.modify();
    let broker = fixture.broker();
    let head = fixture.repository.join(".git/HEAD");
    std::fs::remove_file(&head).expect("remove HEAD");
    mkfifo(&head, Mode::S_IRUSR | Mode::S_IWUSR).expect("HEAD FIFO");
    let started = std::time::Instant::now();
    let proof = fixture.proof();
    let paths = vec![RepoPath::parse("leased/a.txt").expect("path")];
    assert_eq!(
        Err(GitError::GitTimeout),
        broker.inspect_candidate_tree(
            &fixture.base,
            &BranchName::parse("main").expect("branch"),
            &proof,
            &paths,
        )
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

fn git(repository: &Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .expect("Git fixture command starts");
    assert!(
        output.status.success(),
        "Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn git_text(repository: &Path, arguments: &[&str]) -> String {
    String::from_utf8(git(repository, arguments).stdout)
        .expect("UTF-8 Git output")
        .trim_end()
        .to_owned()
}
