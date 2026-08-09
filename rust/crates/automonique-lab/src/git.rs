// SPDX-License-Identifier: Elastic-2.0

//! Typed, proposal-only Git candidate creation.
//!
//! This module intentionally has no generic command surface. Every process is
//! selected from a closed recipe enum, uses a scrubbed environment, and can
//! affect only one private index and one namespaced proposal ref.

use crate::state::VerifiedActiveLease;
use crate::workspace_lease::{AttemptId, BaseRevision, FenceEpoch, LeaseId, RepoPath};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const INTENT_SCHEMA: &str = "automonique.git-candidate-intent/v1";
const RECEIPT_SCHEMA: &str = "automonique.git-candidate-receipt/v1";
const FIXED_NAME: &str = "Automonique Candidate Broker";
const FIXED_EMAIL: &str = "candidate@automonique.invalid";
const FIXED_DATE: &str = "2000-01-01T00:00:00 +0000";
const GIT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const GIT_WALL_LIMIT: Duration = if cfg!(test) {
    Duration::from_millis(500)
} else {
    Duration::from_secs(10)
};
const GIT_MAX_OUTPUT_BYTES: usize = if cfg!(test) {
    32 * 1024
} else {
    4 * 1024 * 1024
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOperation {
    CreateCandidate,
    Push,
    Merge,
    Force,
    Reset,
    Stash,
    Checkout,
    RemoteEdit,
    Tag,
    HistoryRewrite,
}

impl GitOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::CreateCandidate => "create_candidate",
            Self::Push => "push",
            Self::Merge => "merge",
            Self::Force => "force",
            Self::Reset => "reset",
            Self::Stash => "stash",
            Self::Checkout => "checkout",
            Self::RemoteEdit => "remote_edit",
            Self::Tag => "tag",
            Self::HistoryRewrite => "history_rewrite",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CandidateId(String);

impl CandidateId {
    pub fn parse(value: impl Into<String>) -> Result<Self, GitError> {
        let value = value.into();
        validate_token(&value, 64, "candidate ID")?;
        if value.ends_with('.') || value.contains("..") || value.ends_with(".lock") {
            return Err(GitError::InvalidInput(
                "candidate ID cannot form a safe ref",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BranchName(String);

impl BranchName {
    pub fn parse(value: impl Into<String>) -> Result<Self, GitError> {
        let value = value.into();
        validate_token(&value, 128, "branch name")?;
        if value.ends_with('.') || value.contains("..") || value.ends_with(".lock") {
            return Err(GitError::InvalidInput("branch name is not canonical"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ObjectId(String);

impl ObjectId {
    pub fn parse(value: impl Into<String>) -> Result<Self, GitError> {
        let value = value.into();
        if !matches!(value.len(), 40 | 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(GitError::InvalidInput(
                "object ID must be a full lowercase hex ID",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn zero(&self) -> String {
        "0".repeat(self.0.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateCoordinates {
    expected_base: ObjectId,
    expected_branch: BranchName,
    expected_tree: ObjectId,
}

impl CandidateCoordinates {
    pub const fn new(
        expected_base: ObjectId,
        expected_branch: BranchName,
        expected_tree: ObjectId,
    ) -> Self {
        Self {
            expected_base,
            expected_branch,
            expected_tree,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LeaseProof {
    instance_token: Option<Weak<()>>,
    store_binding: String,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    epoch: FenceEpoch,
    base: BaseRevision,
    exact_paths: Vec<RepoPath>,
}

impl LeaseProof {
    pub fn from_verified_active_lease(verified: VerifiedActiveLease) -> Self {
        Self {
            instance_token: Some(verified.lease_identity().clone()),
            store_binding: verified.store_binding().to_owned(),
            attempt_id: verified.attempt_id().clone(),
            lease_id: verified.lease_id().clone(),
            epoch: verified.epoch(),
            base: verified.base_revision().clone(),
            exact_paths: verified.paths().to_vec(),
        }
    }

    fn from_persisted(
        store_binding: String,
        attempt_id: AttemptId,
        lease_id: LeaseId,
        epoch: FenceEpoch,
        base: BaseRevision,
        exact_paths: Vec<RepoPath>,
    ) -> Result<Self, GitError> {
        let unique: BTreeSet<_> = exact_paths.iter().map(RepoPath::as_str).collect();
        if exact_paths.is_empty() || exact_paths.len() > 1_024 || unique.len() != exact_paths.len()
        {
            return Err(GitError::StateFailure("lease proof paths are invalid"));
        }
        Ok(Self {
            instance_token: None,
            store_binding: sha256_string(store_binding)?,
            attempt_id,
            lease_id,
            epoch,
            base,
            exact_paths,
        })
    }

    fn is_live(&self) -> bool {
        self.instance_token
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some()
    }
}

impl PartialEq for LeaseProof {
    fn eq(&self, other: &Self) -> bool {
        self.store_binding == other.store_binding
            && self.attempt_id == other.attempt_id
            && self.lease_id == other.lease_id
            && self.epoch == other.epoch
            && self.base == other.base
            && self.exact_paths == other.exact_paths
    }
}

impl Eq for LeaseProof {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateScope {
    lease_proof: LeaseProof,
    candidate_paths: Vec<RepoPath>,
}

impl CandidateScope {
    pub fn new(lease_proof: LeaseProof, candidate_paths: Vec<RepoPath>) -> Result<Self, GitError> {
        if !lease_proof.is_live() {
            return Err(GitError::LeaseProofMismatch);
        }
        validate_scope(&lease_proof.exact_paths, &candidate_paths)?;
        Ok(Self {
            lease_proof,
            candidate_paths,
        })
    }

    fn from_persisted(
        lease_proof: LeaseProof,
        candidate_paths: Vec<RepoPath>,
    ) -> Result<Self, GitError> {
        validate_scope(&lease_proof.exact_paths, &candidate_paths)?;
        Ok(Self {
            lease_proof,
            candidate_paths,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRequest {
    operation: GitOperation,
    candidate_id: CandidateId,
    expected_base: ObjectId,
    expected_branch: BranchName,
    lease_proof: LeaseProof,
    candidate_paths: Vec<RepoPath>,
    expected_tree: ObjectId,
    summary: String,
}

impl CandidateRequest {
    pub(crate) fn new(
        operation: GitOperation,
        candidate_id: CandidateId,
        coordinates: CandidateCoordinates,
        scope: CandidateScope,
        summary: impl Into<String>,
    ) -> Result<Self, GitError> {
        let summary = summary.into();
        if summary.is_empty() || summary.len() > 100 || summary.chars().any(char::is_control) {
            return Err(GitError::InvalidInput("candidate summary is invalid"));
        }
        Ok(Self {
            operation,
            candidate_id,
            expected_base: coordinates.expected_base,
            expected_branch: coordinates.expected_branch,
            lease_proof: scope.lease_proof,
            candidate_paths: scope.candidate_paths,
            expected_tree: coordinates.expected_tree,
            summary,
        })
    }

    pub const fn operation(&self) -> GitOperation {
        self.operation
    }

    pub fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    pub fn expected_tree(&self) -> &ObjectId {
        &self.expected_tree
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    AfterIntent,
    AfterCommit,
    AfterRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileDisposition {
    Applied,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateReceipt {
    candidate_id: CandidateId,
    operation_digest: String,
    ref_name: String,
    commit_oid: ObjectId,
    tree_oid: ObjectId,
    parent_oid: ObjectId,
    message_sha256: String,
}

impl CandidateReceipt {
    pub fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    pub fn operation_digest(&self) -> &str {
        &self.operation_digest
    }

    pub fn ref_name(&self) -> &str {
        &self.ref_name
    }

    pub fn commit_oid(&self) -> &ObjectId {
        &self.commit_oid
    }

    pub fn tree_oid(&self) -> &ObjectId {
        &self.tree_oid
    }

    pub fn parent_oid(&self) -> &ObjectId {
        &self.parent_oid
    }

    pub fn message_sha256(&self) -> &str {
        &self.message_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateOutcome {
    disposition: ReconcileDisposition,
    receipt: CandidateReceipt,
}

impl CandidateOutcome {
    pub const fn disposition(&self) -> ReconcileDisposition {
        self.disposition
    }

    pub fn receipt(&self) -> &CandidateReceipt {
        &self.receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitError {
    InvalidInput(&'static str),
    ForbiddenOperation(GitOperation),
    UnsafePath(&'static str),
    RepositoryDrift(&'static str),
    LeaseViolation(String),
    LeaseProofMismatch,
    SnapshotMismatch,
    ExistingOperationMismatch,
    ReconciliationConflict(&'static str),
    InjectedFault(FaultPoint),
    GitFailure(&'static str),
    GitTimeout,
    GitOutputLimit,
    StateFailure(&'static str),
}

impl fmt::Display for GitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Git broker error: {self:?}")
    }
}

impl Error for GitError {}

#[derive(Clone, Debug)]
struct CandidateIntent {
    request: CandidateRequest,
    operation_digest: String,
    ref_name: String,
    message: String,
}

impl CandidateIntent {
    fn to_value(&self) -> Value {
        json!({
            "candidate_id": self.request.candidate_id.as_str(),
            "candidate_paths": path_values(&self.request.candidate_paths),
            "expected_base": self.request.expected_base.as_str(),
            "expected_branch": self.request.expected_branch.as_str(),
            "expected_tree": self.request.expected_tree.as_str(),
            "lease_attempt_id": self.request.lease_proof.attempt_id.as_str(),
            "lease_base": self.request.lease_proof.base.as_str(),
            "lease_epoch": self.request.lease_proof.epoch.get(),
            "lease_id": self.request.lease_proof.lease_id.as_str(),
            "lease_paths": path_values(&self.request.lease_proof.exact_paths),
            "lease_store_binding": self.request.lease_proof.store_binding,
            "message": self.message,
            "operation": self.request.operation.as_str(),
            "operation_digest": self.operation_digest,
            "ref_name": self.ref_name,
            "schema": INTENT_SCHEMA,
            "summary": self.request.summary,
        })
    }

    fn from_value(value: Value) -> Result<Self, GitError> {
        let object = exact_object(
            value,
            &[
                "candidate_id",
                "candidate_paths",
                "expected_base",
                "expected_branch",
                "expected_tree",
                "lease_attempt_id",
                "lease_base",
                "lease_epoch",
                "lease_id",
                "lease_paths",
                "lease_store_binding",
                "message",
                "operation",
                "operation_digest",
                "ref_name",
                "schema",
                "summary",
            ],
        )?;
        if string(&object, "schema")? != INTENT_SCHEMA
            || string(&object, "operation")? != GitOperation::CreateCandidate.as_str()
        {
            return Err(GitError::StateFailure("unsupported candidate intent"));
        }
        let request = CandidateRequest::new(
            GitOperation::CreateCandidate,
            CandidateId::parse(string(&object, "candidate_id")?)?,
            CandidateCoordinates::new(
                ObjectId::parse(string(&object, "expected_base")?)?,
                BranchName::parse(string(&object, "expected_branch")?)?,
                ObjectId::parse(string(&object, "expected_tree")?)?,
            ),
            CandidateScope::from_persisted(
                LeaseProof::from_persisted(
                    string(&object, "lease_store_binding")?,
                    AttemptId::parse(string(&object, "lease_attempt_id")?)
                        .map_err(|_| GitError::StateFailure("lease proof is invalid"))?,
                    LeaseId::parse(string(&object, "lease_id")?)
                        .map_err(|_| GitError::StateFailure("lease proof is invalid"))?,
                    FenceEpoch::from_u64(unsigned(&object, "lease_epoch")?),
                    BaseRevision::parse(string(&object, "lease_base")?)
                        .map_err(|_| GitError::StateFailure("lease proof is invalid"))?,
                    paths(&object, "lease_paths")?,
                )?,
                paths(&object, "candidate_paths")?,
            )?,
            string(&object, "summary")?,
        )?;
        let intent = Self {
            operation_digest: sha256_string(string(&object, "operation_digest")?)?,
            ref_name: string(&object, "ref_name")?,
            message: string(&object, "message")?,
            request,
        };
        if intent.ref_name != candidate_ref(&intent.request.candidate_id)
            || intent.operation_digest != request_digest(&intent.request)?
            || intent.message != commit_message(&intent.request, &intent.operation_digest)
        {
            return Err(GitError::StateFailure("candidate intent integrity failure"));
        }
        Ok(intent)
    }
}

#[derive(Clone, Debug)]
struct PathIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PathIdentity {
    fn capture(path: &Path) -> Result<Self, GitError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| GitError::UnsafePath("repository metadata cannot be inspected"))?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify(&self) -> Result<(), GitError> {
        let current = Self::capture(&self.path)?;
        if current.device == self.device && current.inode == self.inode {
            Ok(())
        } else {
            Err(GitError::RepositoryDrift(
                "repository metadata identity changed",
            ))
        }
    }
}

pub struct GitBroker {
    repository: PathBuf,
    state_root: PathBuf,
    git_executable: PathBuf,
    repository_identity: PathIdentity,
    git_marker_identity: PathIdentity,
    git_dir_identity: Option<PathIdentity>,
    common_dir_identity: Option<PathIdentity>,
}

impl GitBroker {
    pub fn open(
        repository: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
    ) -> Result<Self, GitError> {
        let repository = repository.as_ref();
        let state_root = state_root.as_ref();
        reject_symlink_components(repository, false)?;
        reject_symlink_components(state_root, true)?;
        let repository = repository
            .canonicalize()
            .map_err(|_| GitError::UnsafePath("repository cannot be resolved"))?;
        create_private_directory(state_root)?;
        reject_symlink_components(state_root, false)?;
        let state_root = state_root
            .canonicalize()
            .map_err(|_| GitError::UnsafePath("state root cannot be resolved"))?;
        let git_executable = ["/usr/bin/git", "/bin/git"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or(GitError::GitFailure("Git executable is unavailable"))?;
        let git_marker = repository.join(".git");
        let marker_metadata = std::fs::symlink_metadata(&git_marker)
            .map_err(|_| GitError::UnsafePath("Git metadata marker is unavailable"))?;
        if marker_metadata.file_type().is_symlink() {
            return Err(GitError::UnsafePath("Git metadata marker is a symlink"));
        }
        let mut broker = Self {
            repository_identity: PathIdentity::capture(&repository)?,
            git_marker_identity: PathIdentity::capture(&git_marker)?,
            repository,
            state_root,
            git_executable,
            git_dir_identity: None,
            common_dir_identity: None,
        };
        let root = broker.git(GitRecipe::ShowTopLevel)?.stdout;
        let root = text_line(&root, "repository root")?;
        let actual = Path::new(root)
            .canonicalize()
            .map_err(|_| GitError::UnsafePath("Git repository root cannot be resolved"))?;
        if actual != broker.repository {
            return Err(GitError::UnsafePath(
                "repository path is not the worktree root",
            ));
        }
        let git_dir = broker.git(GitRecipe::GitDir)?.stdout;
        let git_dir = contained_metadata_directory(
            &broker.repository,
            text_line(&git_dir, "Git directory")?,
        )?;
        let common_dir = broker.git(GitRecipe::CommonDir)?.stdout;
        let common_dir = contained_metadata_directory(
            &broker.repository,
            text_line(&common_dir, "Git common directory")?,
        )?;
        broker.git_dir_identity = Some(PathIdentity::capture(&git_dir)?);
        broker.common_dir_identity = Some(PathIdentity::capture(&common_dir)?);
        Ok(broker)
    }

    pub fn inspect_candidate_tree(
        &self,
        expected_base: &ObjectId,
        expected_branch: &BranchName,
        lease_proof: &LeaseProof,
        candidate_paths: &[RepoPath],
    ) -> Result<ObjectId, GitError> {
        verify_proof_base(lease_proof, expected_base)?;
        validate_scope(&lease_proof.exact_paths, candidate_paths)?;
        self.verify_source(
            expected_base,
            expected_branch,
            &lease_proof.exact_paths,
            candidate_paths,
        )
    }

    pub fn create(&self, request: &CandidateRequest) -> Result<CandidateOutcome, GitError> {
        self.create_with_fault(request, None)
    }

    pub fn create_with_fault(
        &self,
        request: &CandidateRequest,
        fault: Option<FaultPoint>,
    ) -> Result<CandidateOutcome, GitError> {
        let intent = self.prepare(request)?;
        if fault == Some(FaultPoint::AfterIntent) {
            return Err(GitError::InjectedFault(FaultPoint::AfterIntent));
        }
        self.apply(&intent, fault)
    }

    pub fn reconcile(
        &self,
        candidate_id: &CandidateId,
        lease_proof: &LeaseProof,
    ) -> Result<CandidateOutcome, GitError> {
        let intent = self.load_intent(candidate_id)?;
        verify_same_proof(&intent.request.lease_proof, lease_proof)?;
        self.apply(&intent, None)
    }

    pub fn has_intent(&self, candidate_id: &CandidateId) -> bool {
        self.intent_path(candidate_id).is_file()
    }

    pub fn has_receipt(&self, candidate_id: &CandidateId) -> bool {
        self.receipt_path(candidate_id).is_file()
    }

    pub fn candidate_ref_oid(
        &self,
        candidate_id: &CandidateId,
    ) -> Result<Option<ObjectId>, GitError> {
        self.ref_oid(&candidate_ref(candidate_id))
    }

    fn prepare(&self, request: &CandidateRequest) -> Result<CandidateIntent, GitError> {
        if request.operation != GitOperation::CreateCandidate {
            return Err(GitError::ForbiddenOperation(request.operation));
        }
        verify_proof_base(&request.lease_proof, &request.expected_base)?;
        create_private_directory(&self.candidates_root())?;
        let operation_dir = self.operation_dir(&request.candidate_id);
        create_private_directory(&operation_dir)?;
        let intent_path = self.intent_path(&request.candidate_id);
        if intent_path.exists() {
            let intent = self.load_intent(&request.candidate_id)?;
            if intent.request != *request {
                return Err(GitError::ExistingOperationMismatch);
            }
            return Ok(intent);
        }
        let tree = self.verify_source(
            &request.expected_base,
            &request.expected_branch,
            &request.lease_proof.exact_paths,
            &request.candidate_paths,
        )?;
        if tree != request.expected_tree {
            return Err(GitError::SnapshotMismatch);
        }
        let operation_digest = request_digest(request)?;
        let intent = CandidateIntent {
            ref_name: candidate_ref(&request.candidate_id),
            message: commit_message(request, &operation_digest),
            request: request.clone(),
            operation_digest,
        };
        write_atomic(&intent_path, &canonical_json(&intent.to_value())?)?;
        Ok(intent)
    }

    fn apply(
        &self,
        intent: &CandidateIntent,
        fault: Option<FaultPoint>,
    ) -> Result<CandidateOutcome, GitError> {
        let receipt_path = self.receipt_path(&intent.request.candidate_id);
        if receipt_path.exists() {
            let receipt = self.load_receipt(&receipt_path)?;
            self.verify_receipt(intent, &receipt)?;
            return Ok(CandidateOutcome {
                disposition: ReconcileDisposition::Replayed,
                receipt,
            });
        }

        let existing_ref = self.ref_oid(&intent.ref_name)?;
        let commit_oid = if let Some(ref_oid) = existing_ref {
            self.verify_commit(intent, &ref_oid)?;
            ref_oid
        } else {
            let tree = self.verify_source(
                &intent.request.expected_base,
                &intent.request.expected_branch,
                &intent.request.lease_proof.exact_paths,
                &intent.request.candidate_paths,
            )?;
            if tree != intent.request.expected_tree {
                return Err(GitError::SnapshotMismatch);
            }
            let commit_oid = self.commit_tree(intent)?;
            self.verify_commit(intent, &commit_oid)?;
            if fault == Some(FaultPoint::AfterCommit) {
                return Err(GitError::InjectedFault(FaultPoint::AfterCommit));
            }
            self.update_ref(intent, &commit_oid)?;
            if fault == Some(FaultPoint::AfterRef) {
                return Err(GitError::InjectedFault(FaultPoint::AfterRef));
            }
            commit_oid
        };

        let receipt = CandidateReceipt {
            candidate_id: intent.request.candidate_id.clone(),
            operation_digest: intent.operation_digest.clone(),
            ref_name: intent.ref_name.clone(),
            commit_oid,
            tree_oid: intent.request.expected_tree.clone(),
            parent_oid: intent.request.expected_base.clone(),
            message_sha256: sha256_bytes(intent.message.as_bytes()),
        };
        write_atomic(&receipt_path, &canonical_json(&receipt_value(&receipt))?)?;
        Ok(CandidateOutcome {
            disposition: ReconcileDisposition::Applied,
            receipt,
        })
    }

    fn verify_source(
        &self,
        expected_base: &ObjectId,
        expected_branch: &BranchName,
        leased_paths: &[RepoPath],
        candidate_paths: &[RepoPath],
    ) -> Result<ObjectId, GitError> {
        let head = self.git(GitRecipe::Head)?.stdout;
        if text_line(&head, "HEAD")? != expected_base.as_str() {
            return Err(GitError::RepositoryDrift("HEAD differs from expected base"));
        }
        let branch = self.git(GitRecipe::SymbolicHead)?.stdout;
        if text_line(&branch, "branch")? != format!("refs/heads/{}", expected_branch.as_str()) {
            return Err(GitError::RepositoryDrift(
                "current branch differs from expected branch",
            ));
        }
        self.git(GitRecipe::VerifyCommit(expected_base))?;
        validate_scope(leased_paths, candidate_paths)?;
        for path in candidate_paths {
            self.verify_candidate_path(expected_base, path)?;
        }
        self.verify_no_filters(candidate_paths)?;
        let status = self.git(GitRecipe::Status)?.stdout;
        let dirty = parse_status(&status)?;
        let expected: BTreeSet<_> = candidate_paths.iter().map(RepoPath::as_str).collect();
        if dirty != expected {
            return Err(GitError::RepositoryDrift(
                "dirty paths differ from candidate paths",
            ));
        }
        self.build_tree(expected_base, candidate_paths)
    }

    fn verify_candidate_path(
        &self,
        expected_base: &ObjectId,
        path: &RepoPath,
    ) -> Result<(), GitError> {
        let mut current = self.repository.clone();
        let segments: Vec<_> = path.as_str().split('/').collect();
        for (index, segment) in segments.iter().enumerate() {
            current.push(segment);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(GitError::UnsafePath("candidate path contains a symlink"));
                    }
                    if index + 1 == segments.len() && !metadata.is_file() {
                        return Err(GitError::UnsafePath("candidate path is not a regular file"));
                    }
                    if index + 1 < segments.len() && !metadata.is_dir() {
                        return Err(GitError::UnsafePath("candidate parent is not a directory"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if index + 1 != segments.len() {
                        return Err(GitError::UnsafePath("candidate parent does not exist"));
                    }
                }
                Err(_) => return Err(GitError::UnsafePath("candidate path cannot be inspected")),
            }
        }
        let output = self.git(GitRecipe::LsTree(expected_base, path))?.stdout;
        if !output.is_empty() {
            let tab = output
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or(GitError::GitFailure("invalid ls-tree output"))?;
            let header = std::str::from_utf8(&output[..tab])
                .map_err(|_| GitError::GitFailure("invalid ls-tree output"))?;
            let mode = header
                .split_ascii_whitespace()
                .next()
                .ok_or(GitError::GitFailure("invalid ls-tree output"))?;
            if !matches!(mode, "100644" | "100755") {
                return Err(GitError::UnsafePath("base candidate is not a regular file"));
            }
        }
        Ok(())
    }

    fn verify_no_filters(&self, paths: &[RepoPath]) -> Result<(), GitError> {
        let output = self.git(GitRecipe::CheckFilter(paths))?.stdout;
        let fields: Vec<_> = output
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != paths.len() * 3 {
            return Err(GitError::GitFailure("invalid check-attr output"));
        }
        for (path, triple) in paths.iter().zip(fields.chunks_exact(3)) {
            if triple[0] != path.as_str().as_bytes()
                || triple[1] != b"filter"
                || !matches!(triple[2], b"unspecified" | b"unset")
            {
                return Err(GitError::UnsafePath(
                    "candidate content filter is not allowed",
                ));
            }
        }
        Ok(())
    }

    fn build_tree(&self, base: &ObjectId, paths: &[RepoPath]) -> Result<ObjectId, GitError> {
        let index = self.unique_index_path();
        self.git(GitRecipe::ReadTree(base, &index))?;
        secure_file(&index)?;
        if let Err(error) = self.git(GitRecipe::Add(paths, &index)) {
            let _ = std::fs::remove_file(&index);
            return Err(error);
        }
        let tree_result = self.git(GitRecipe::WriteTree(&index));
        let _ = std::fs::remove_file(index);
        let tree = tree_result?.stdout;
        ObjectId::parse(text_line(&tree, "candidate tree")?)
    }

    fn commit_tree(&self, intent: &CandidateIntent) -> Result<ObjectId, GitError> {
        let output = self
            .git(GitRecipe::CommitTree {
                tree: &intent.request.expected_tree,
                parent: &intent.request.expected_base,
                message: &intent.message,
            })?
            .stdout;
        ObjectId::parse(text_line(&output, "candidate commit")?)
    }

    fn update_ref(&self, intent: &CandidateIntent, commit: &ObjectId) -> Result<(), GitError> {
        let output = self.git_allow_failure(GitRecipe::UpdateRef {
            ref_name: &intent.ref_name,
            commit,
            zero: &intent.request.expected_base.zero(),
        })?;
        if !output.status.success() {
            return Err(GitError::ReconciliationConflict(
                "candidate ref compare-and-swap failed",
            ));
        }
        Ok(())
    }

    fn ref_oid(&self, ref_name: &str) -> Result<Option<ObjectId>, GitError> {
        let output = self.git_allow_failure(GitRecipe::ShowRef(ref_name))?;
        match output.status.code() {
            Some(0) => Ok(Some(ObjectId::parse(text_line(
                &output.stdout,
                "candidate ref",
            )?)?)),
            Some(1) => Ok(None),
            _ => Err(GitError::GitFailure("candidate ref inspection failed")),
        }
    }

    fn verify_commit(&self, intent: &CandidateIntent, commit: &ObjectId) -> Result<(), GitError> {
        let deterministic = self.commit_tree(intent)?;
        if deterministic != *commit {
            return Err(GitError::ReconciliationConflict(
                "candidate commit ID is not deterministic",
            ));
        }
        let raw = self.git(GitRecipe::CatCommit(commit))?.stdout;
        let separator = raw.windows(2).position(|window| window == b"\n\n").ok_or(
            GitError::ReconciliationConflict("candidate commit is malformed"),
        )?;
        let headers = std::str::from_utf8(&raw[..separator]).map_err(|_| {
            GitError::ReconciliationConflict("candidate commit headers are invalid")
        })?;
        let mut tree = None;
        let mut parents = Vec::new();
        let mut author = None;
        let mut committer = None;
        for line in headers.lines() {
            if let Some(value) = line.strip_prefix("tree ") {
                tree = Some(value);
            } else if let Some(value) = line.strip_prefix("parent ") {
                parents.push(value);
            } else if let Some(value) = line.strip_prefix("author ") {
                author = Some(value);
            } else if let Some(value) = line.strip_prefix("committer ") {
                committer = Some(value);
            }
        }
        let fixed_identity = format!("{FIXED_NAME} <{FIXED_EMAIL}> 946684800 +0000");
        let message = &raw[separator + 2..];
        if tree != Some(intent.request.expected_tree.as_str())
            || parents != [intent.request.expected_base.as_str()]
            || author != Some(fixed_identity.as_str())
            || committer != Some(fixed_identity.as_str())
            || message != intent.message.as_bytes()
        {
            return Err(GitError::ReconciliationConflict(
                "candidate commit differs from intent",
            ));
        }
        Ok(())
    }

    fn verify_receipt(
        &self,
        intent: &CandidateIntent,
        receipt: &CandidateReceipt,
    ) -> Result<(), GitError> {
        if receipt.candidate_id != intent.request.candidate_id
            || receipt.operation_digest != intent.operation_digest
            || receipt.ref_name != intent.ref_name
            || receipt.tree_oid != intent.request.expected_tree
            || receipt.parent_oid != intent.request.expected_base
            || receipt.message_sha256 != sha256_bytes(intent.message.as_bytes())
        {
            return Err(GitError::StateFailure(
                "candidate receipt differs from intent",
            ));
        }
        let ref_oid = self
            .ref_oid(&intent.ref_name)?
            .ok_or(GitError::ReconciliationConflict(
                "candidate receipt has no ref",
            ))?;
        if ref_oid != receipt.commit_oid {
            return Err(GitError::ReconciliationConflict(
                "candidate receipt ref differs",
            ));
        }
        self.verify_commit(intent, &receipt.commit_oid)
    }

    fn load_intent(&self, candidate_id: &CandidateId) -> Result<CandidateIntent, GitError> {
        let operation_dir = self.operation_dir(candidate_id);
        if !operation_dir.exists() {
            return Err(GitError::StateFailure("candidate intent does not exist"));
        }
        create_private_directory(&self.candidates_root())?;
        create_private_directory(&operation_dir)?;
        CandidateIntent::from_value(read_json(&self.intent_path(candidate_id))?)
    }

    fn load_receipt(&self, path: &Path) -> Result<CandidateReceipt, GitError> {
        receipt_from_value(read_json(path)?)
    }

    fn candidates_root(&self) -> PathBuf {
        self.state_root.join("git-candidates")
    }

    fn operation_dir(&self, candidate_id: &CandidateId) -> PathBuf {
        self.candidates_root().join(candidate_id.as_str())
    }

    fn intent_path(&self, candidate_id: &CandidateId) -> PathBuf {
        self.operation_dir(candidate_id).join("intent.json")
    }

    fn receipt_path(&self, candidate_id: &CandidateId) -> PathBuf {
        self.operation_dir(candidate_id).join("receipt.json")
    }

    fn unique_index_path(&self) -> PathBuf {
        self.state_root.join(format!(
            "candidate-index-{}-{}",
            std::process::id(),
            unique_nonce()
        ))
    }

    fn git(&self, recipe: GitRecipe<'_>) -> Result<Output, GitError> {
        let output = self.git_allow_failure(recipe)?;
        if !output.status.success() {
            return Err(GitError::GitFailure("typed Git recipe failed"));
        }
        Ok(output)
    }

    fn git_allow_failure(&self, recipe: GitRecipe<'_>) -> Result<Output, GitError> {
        self.verify_repository_metadata()?;
        let mut command = Command::new(&self.git_executable);
        command
            .current_dir(&self.repository)
            .env_clear()
            .env("HOME", &self.state_root)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.autocrlf=false")
            .arg("-c")
            .arg("i18n.commitEncoding=UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let mut input = None;
        match recipe {
            GitRecipe::ShowTopLevel => {
                command.args(["rev-parse", "--show-toplevel"]);
            }
            GitRecipe::GitDir => {
                command.args(["rev-parse", "--path-format=absolute", "--git-dir"]);
            }
            GitRecipe::CommonDir => {
                command.args(["rev-parse", "--path-format=absolute", "--git-common-dir"]);
            }
            GitRecipe::Head => {
                command.args(["rev-parse", "--verify", "HEAD"]);
            }
            GitRecipe::SymbolicHead => {
                command.args(["symbolic-ref", "--quiet", "HEAD"]);
            }
            GitRecipe::VerifyCommit(oid) => {
                command.args(["cat-file", "-e", &format!("{}^{{commit}}", oid.as_str())]);
            }
            GitRecipe::Status => {
                command.args([
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--no-renames",
                ]);
            }
            GitRecipe::LsTree(base, path) => {
                command.args(["ls-tree", "-z", base.as_str(), "--", path.as_str()]);
            }
            GitRecipe::CheckFilter(paths) => {
                command.args(["check-attr", "-z", "filter", "--"]);
                command.args(paths.iter().map(RepoPath::as_str));
            }
            GitRecipe::ReadTree(base, index) => {
                command
                    .env("GIT_INDEX_FILE", index)
                    .args(["read-tree", base.as_str()]);
            }
            GitRecipe::Add(paths, index) => {
                command
                    .env("GIT_INDEX_FILE", index)
                    .args(["add", "--all", "--"]);
                command.args(paths.iter().map(RepoPath::as_str));
            }
            GitRecipe::WriteTree(index) => {
                command.env("GIT_INDEX_FILE", index).arg("write-tree");
            }
            GitRecipe::CommitTree {
                tree,
                parent,
                message,
            } => {
                command
                    .env("GIT_AUTHOR_NAME", FIXED_NAME)
                    .env("GIT_AUTHOR_EMAIL", FIXED_EMAIL)
                    .env("GIT_AUTHOR_DATE", FIXED_DATE)
                    .env("GIT_COMMITTER_NAME", FIXED_NAME)
                    .env("GIT_COMMITTER_EMAIL", FIXED_EMAIL)
                    .env("GIT_COMMITTER_DATE", FIXED_DATE)
                    .stdin(Stdio::piped())
                    .args(["commit-tree", tree.as_str(), "-p", parent.as_str()]);
                input = Some(message.as_bytes());
            }
            GitRecipe::UpdateRef {
                ref_name,
                commit,
                zero,
            } => {
                command.args(["update-ref", ref_name, commit.as_str(), zero]);
            }
            GitRecipe::ShowRef(ref_name) => {
                command.args([
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("{ref_name}^{{commit}}"),
                ]);
            }
            GitRecipe::CatCommit(commit) => {
                command.args(["cat-file", "commit", commit.as_str()]);
            }
        }
        let mut child = command
            .spawn()
            .map_err(|_| GitError::GitFailure("Git process did not start"))?;
        if let Some(bytes) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(GitError::GitFailure("Git stdin unavailable"))?;
            if stdin.write_all(bytes).is_err() {
                terminate_git(&mut child)?;
                return Err(GitError::GitFailure("Git stdin failed"));
            }
        }
        bounded_wait(child)
    }

    fn verify_repository_metadata(&self) -> Result<(), GitError> {
        self.repository_identity.verify()?;
        self.git_marker_identity.verify()?;
        if let Some(identity) = &self.git_dir_identity {
            identity.verify()?;
        }
        if let Some(identity) = &self.common_dir_identity {
            identity.verify()?;
        }
        Ok(())
    }
}

enum GitRecipe<'a> {
    ShowTopLevel,
    GitDir,
    CommonDir,
    Head,
    SymbolicHead,
    VerifyCommit(&'a ObjectId),
    Status,
    LsTree(&'a ObjectId, &'a RepoPath),
    CheckFilter(&'a [RepoPath]),
    ReadTree(&'a ObjectId, &'a Path),
    Add(&'a [RepoPath], &'a Path),
    WriteTree(&'a Path),
    CommitTree {
        tree: &'a ObjectId,
        parent: &'a ObjectId,
        message: &'a str,
    },
    UpdateRef {
        ref_name: &'a str,
        commit: &'a ObjectId,
        zero: &'a str,
    },
    ShowRef(&'a str),
    CatCommit(&'a ObjectId),
}

fn bounded_wait(mut child: std::process::Child) -> Result<Output, GitError> {
    let group = match i32::try_from(child.id()) {
        Ok(pid) => Pid::from_raw(pid),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitError::GitFailure(
                "Git PID is outside the supported range",
            ));
        }
    };
    let stdout = child
        .stdout
        .take()
        .ok_or(GitError::GitFailure("Git stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(GitError::GitFailure("Git stderr unavailable"))?;
    let captured = Arc::new(AtomicUsize::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader = bounded_capture(stdout, Arc::clone(&captured), Arc::clone(&exceeded));
    let stderr_reader = bounded_capture(stderr, captured, Arc::clone(&exceeded));
    let deadline = Instant::now() + GIT_WALL_LIMIT;
    let mut forced = None;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            forced = Some(GitError::GitOutputLimit);
            break terminate_git(&mut child)?;
        }
        if Instant::now() >= deadline {
            forced = Some(GitError::GitTimeout);
            break terminate_git(&mut child)?;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| GitError::GitFailure("Git wait failed"))?
        {
            cleanup_git_group(group);
            break status;
        }
        thread::sleep(GIT_POLL_INTERVAL);
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| GitError::GitFailure("Git stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| GitError::GitFailure("Git stderr reader panicked"))??;
    if let Some(error) = forced {
        return Err(error);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn bounded_capture(
    mut input: impl Read + Send + 'static,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, GitError>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        let mut chunk = [0_u8; 8_192];
        loop {
            let read = input
                .read(&mut chunk)
                .map_err(|_| GitError::GitFailure("Git output read failed"))?;
            if read == 0 {
                return Ok(result);
            }
            let start = captured.fetch_add(read, Ordering::AcqRel);
            let remaining = GIT_MAX_OUTPUT_BYTES.saturating_sub(start);
            result.extend_from_slice(&chunk[..read.min(remaining)]);
            if read > remaining {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn terminate_git(child: &mut std::process::Child) -> Result<std::process::ExitStatus, GitError> {
    let group = Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| GitError::GitFailure("Git PID is invalid"))?,
    );
    let _ = killpg(group, Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_millis(50);
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| GitError::GitFailure("Git wait failed"))?
        {
            cleanup_git_group(group);
            return Ok(status);
        }
        thread::sleep(GIT_POLL_INTERVAL);
    }
    let _ = killpg(group, Signal::SIGKILL);
    let status = child
        .wait()
        .map_err(|_| GitError::GitFailure("Git reap failed"))?;
    cleanup_git_group(group);
    Ok(status)
}

fn cleanup_git_group(group: Pid) {
    let _ = killpg(group, Signal::SIGKILL);
}

fn validate_token(value: &str, maximum: usize, field: &'static str) -> Result<(), GitError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(GitError::InvalidInput(field));
    };
    if value.len() > maximum
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(GitError::InvalidInput(field));
    }
    Ok(())
}

fn validate_scope(leases: &[RepoPath], candidates: &[RepoPath]) -> Result<(), GitError> {
    if leases.is_empty()
        || candidates.is_empty()
        || leases.len() > 1_024
        || candidates.len() > 1_024
    {
        return Err(GitError::InvalidInput(
            "candidate scope must be bounded and non-empty",
        ));
    }
    let lease_set: BTreeSet<_> = leases.iter().map(RepoPath::as_str).collect();
    let candidate_set: BTreeSet<_> = candidates.iter().map(RepoPath::as_str).collect();
    if lease_set.len() != leases.len() || candidate_set.len() != candidates.len() {
        return Err(GitError::InvalidInput(
            "candidate scope contains duplicates",
        ));
    }
    for candidate in candidates {
        if !leases.iter().any(|lease| {
            candidate == lease
                || candidate
                    .as_str()
                    .strip_prefix(lease.as_str())
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) {
            return Err(GitError::LeaseViolation(candidate.as_str().to_owned()));
        }
    }
    Ok(())
}

fn verify_proof_base(proof: &LeaseProof, expected_base: &ObjectId) -> Result<(), GitError> {
    if proof.is_live() && proof.base.as_str() == expected_base.as_str() {
        Ok(())
    } else {
        Err(GitError::LeaseProofMismatch)
    }
}

fn verify_same_proof(expected: &LeaseProof, supplied: &LeaseProof) -> Result<(), GitError> {
    if supplied.is_live() && expected == supplied {
        Ok(())
    } else {
        Err(GitError::LeaseProofMismatch)
    }
}

fn parse_status(output: &[u8]) -> Result<BTreeSet<&str>, GitError> {
    let mut paths = BTreeSet::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 4 || record[2] != b' ' {
            return Err(GitError::GitFailure("invalid Git status output"));
        }
        let path = std::str::from_utf8(&record[3..])
            .map_err(|_| GitError::UnsafePath("non-UTF-8 repository path is not supported"))?;
        paths.insert(path);
    }
    Ok(paths)
}

fn request_value(request: &CandidateRequest) -> Value {
    json!({
        "candidate_id": request.candidate_id.as_str(),
        "candidate_paths": path_values(&request.candidate_paths),
        "expected_base": request.expected_base.as_str(),
        "expected_branch": request.expected_branch.as_str(),
        "expected_tree": request.expected_tree.as_str(),
        "lease_attempt_id": request.lease_proof.attempt_id.as_str(),
        "lease_base": request.lease_proof.base.as_str(),
        "lease_epoch": request.lease_proof.epoch.get(),
        "lease_id": request.lease_proof.lease_id.as_str(),
        "lease_paths": path_values(&request.lease_proof.exact_paths),
        "lease_store_binding": request.lease_proof.store_binding,
        "operation": request.operation.as_str(),
        "summary": request.summary,
    })
}

fn request_digest(request: &CandidateRequest) -> Result<String, GitError> {
    Ok(sha256_bytes(&canonical_json(&request_value(request))?))
}

fn commit_message(request: &CandidateRequest, operation_digest: &str) -> String {
    format!(
        "Automonique candidate {}\n\n{}\n\nAutomonique-Operation: sha256:{}\nAutomonique-Base: {}\nAutomonique-Tree: {}\n",
        request.candidate_id.as_str(),
        request.summary,
        operation_digest,
        request.expected_base.as_str(),
        request.expected_tree.as_str(),
    )
}

fn candidate_ref(candidate_id: &CandidateId) -> String {
    format!("refs/automonique/candidates/{}", candidate_id.as_str())
}

fn receipt_value(receipt: &CandidateReceipt) -> Value {
    json!({
        "candidate_id": receipt.candidate_id.as_str(),
        "commit_oid": receipt.commit_oid.as_str(),
        "message_sha256": receipt.message_sha256,
        "operation_digest": receipt.operation_digest,
        "parent_oid": receipt.parent_oid.as_str(),
        "ref_name": receipt.ref_name,
        "schema": RECEIPT_SCHEMA,
        "status": "candidate_committed",
        "tree_oid": receipt.tree_oid.as_str(),
    })
}

fn receipt_from_value(value: Value) -> Result<CandidateReceipt, GitError> {
    let object = exact_object(
        value,
        &[
            "candidate_id",
            "commit_oid",
            "message_sha256",
            "operation_digest",
            "parent_oid",
            "ref_name",
            "schema",
            "status",
            "tree_oid",
        ],
    )?;
    if string(&object, "schema")? != RECEIPT_SCHEMA
        || string(&object, "status")? != "candidate_committed"
    {
        return Err(GitError::StateFailure("unsupported candidate receipt"));
    }
    Ok(CandidateReceipt {
        candidate_id: CandidateId::parse(string(&object, "candidate_id")?)?,
        commit_oid: ObjectId::parse(string(&object, "commit_oid")?)?,
        message_sha256: sha256_string(string(&object, "message_sha256")?)?,
        operation_digest: sha256_string(string(&object, "operation_digest")?)?,
        parent_oid: ObjectId::parse(string(&object, "parent_oid")?)?,
        ref_name: string(&object, "ref_name")?,
        tree_oid: ObjectId::parse(string(&object, "tree_oid")?)?,
    })
}

fn path_values(paths: &[RepoPath]) -> Vec<&str> {
    paths.iter().map(RepoPath::as_str).collect()
}

fn paths(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Vec<RepoPath>, GitError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(GitError::StateFailure("candidate path list is invalid"))?
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or(GitError::StateFailure("candidate path is invalid"))?;
            RepoPath::parse(value).map_err(|_| GitError::StateFailure("candidate path is invalid"))
        })
        .collect()
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, GitError> {
    serde_json::to_vec(value).map_err(|_| GitError::StateFailure("canonical JSON failed"))
}

fn read_json(path: &Path) -> Result<Value, GitError> {
    reject_state_file(path)?;
    let bytes =
        std::fs::read(path).map_err(|_| GitError::StateFailure("broker state cannot be read"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| GitError::StateFailure("broker state is malformed"))?;
    if canonical_json(&value)? != bytes {
        return Err(GitError::StateFailure("broker state is not canonical"));
    }
    Ok(value)
}

fn exact_object(value: Value, fields: &[&str]) -> Result<serde_json::Map<String, Value>, GitError> {
    let object = value
        .as_object()
        .ok_or(GitError::StateFailure("broker state is not an object"))?;
    let actual: BTreeSet<_> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<_> = fields.iter().copied().collect();
    if actual != expected {
        return Err(GitError::StateFailure("broker state fields differ"));
    }
    value
        .as_object()
        .cloned()
        .ok_or(GitError::StateFailure("broker state is not an object"))
}

fn string(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, GitError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(GitError::StateFailure("broker state string is invalid"))
}

fn unsigned(object: &serde_json::Map<String, Value>, field: &'static str) -> Result<u64, GitError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(GitError::StateFailure("broker state integer is invalid"))
}

fn sha256_string(value: String) -> Result<String, GitError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value)
    } else {
        Err(GitError::StateFailure("SHA-256 digest is invalid"))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn text_line<'a>(bytes: &'a [u8], kind: &'static str) -> Result<&'a str, GitError> {
    std::str::from_utf8(bytes)
        .map(str::trim_end)
        .map_err(|_| GitError::GitFailure(kind))
}

fn contained_metadata_directory(repository: &Path, value: &str) -> Result<PathBuf, GitError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(GitError::UnsafePath("Git metadata path is not absolute"));
    }
    reject_symlink_components(path, false)?;
    let path = path
        .canonicalize()
        .map_err(|_| GitError::UnsafePath("Git metadata path cannot be resolved"))?;
    if !path.starts_with(repository) || !path.is_dir() {
        return Err(GitError::UnsafePath(
            "Git metadata directory is outside the repository",
        ));
    }
    Ok(path)
}

fn reject_symlink_components(path: &Path, final_may_be_missing: bool) -> Result<(), GitError> {
    if !path.is_absolute() {
        return Err(GitError::UnsafePath("broker paths must be absolute"));
    }
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    let mut missing_suffix = false;
    for component in &components {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(segment) => current.push(segment),
            Component::CurDir | Component::ParentDir => {
                return Err(GitError::UnsafePath("broker path is not canonical"));
            }
        }
        if missing_suffix {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(GitError::UnsafePath("broker path contains a symlink"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && final_may_be_missing => {
                missing_suffix = true;
            }
            Err(_) => return Err(GitError::UnsafePath("broker path cannot be inspected")),
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), GitError> {
    reject_symlink_components(path, true)?;
    let created = !path.exists();
    if created {
        std::fs::create_dir_all(path)
            .map_err(|_| GitError::StateFailure("private state directory cannot be created"))?;
    }
    reject_symlink_components(path, false)?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| GitError::StateFailure("private state directory cannot be inspected"))?;
    if !metadata.is_dir() {
        return Err(GitError::UnsafePath(
            "private state path is not a directory",
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(GitError::UnsafePath(
            "private state directory has a different owner",
        ));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o7777 != 0o700 {
        if !created {
            return Err(GitError::UnsafePath(
                "existing private state directory mode is not 0700",
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| GitError::StateFailure("private directory mode cannot be enforced"))?;
    }
    Ok(())
}

fn secure_file(path: &Path) -> Result<(), GitError> {
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| GitError::StateFailure("private file mode cannot be enforced"))?;
    Ok(())
}

fn reject_state_file(path: &Path) -> Result<(), GitError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| GitError::StateFailure("broker state cannot be inspected"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GitError::UnsafePath("broker state is not a regular file"));
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), GitError> {
    if path.exists() {
        return Err(GitError::StateFailure("broker state already exists"));
    }
    let parent = path
        .parent()
        .ok_or(GitError::StateFailure("broker state has no parent"))?;
    create_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".state-{}-{}.tmp",
        std::process::id(),
        unique_nonce()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|_| GitError::StateFailure("temporary broker state cannot be created"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| GitError::StateFailure("broker state cannot be persisted"))?;
    if std::fs::hard_link(&temporary, path).is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(GitError::StateFailure(
            "broker state cannot be published without replacement",
        ));
    }
    std::fs::remove_file(&temporary)
        .map_err(|_| GitError::StateFailure("temporary broker state cannot be removed"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| GitError::StateFailure("broker state directory cannot be persisted"))
}

fn unique_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}
