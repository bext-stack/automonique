// SPDX-License-Identifier: Elastic-2.0

//! Bounded, proposal-only allocation of detached Git worktrees.
//!
//! The allocator deliberately exposes no generic Git command, remote, push, or
//! credential surface. A request names one immutable commit and a bounded set
//! of repository paths. Durable intent is written before the fixed worktree
//! recipe, and a receipt is written only after the checkout has been verified.

use crate::state::VerifiedActiveLease;
use crate::workspace_lease::{BaseRevision, RepoPath};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const INTENT_SCHEMA: &str = "automonique.worktree-intent/v1";
const RECEIPT_SCHEMA: &str = "automonique.worktree-receipt/v1";
const PROGRESS_SCHEMA: &str = "automonique.worktree-progress/v1";
const MAX_RUN_ID_BYTES: usize = 128;
const MAX_PATHS: usize = 1_024;
const MAX_BUDGET: u64 = 16 * 1024 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_GIT_OUTPUT: usize = 4 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(5);

/// A validated allocation request. Arguments are data, never command text.
#[derive(Clone, Debug)]
pub struct WorktreeRequest {
    run_id: String,
    lease_identity: Weak<()>,
    store_binding: String,
    attempt_id: String,
    lease_id: String,
    lease_epoch: u64,
    expected_base: BaseRevision,
    leased_paths: Vec<RepoPath>,
    max_materialized_bytes: u64,
}

impl WorktreeRequest {
    pub fn new(
        verified_lease: VerifiedActiveLease,
        max_materialized_bytes: u64,
    ) -> Result<Self, WorktreeError> {
        let run_id = verified_lease.attempt_id().as_str().to_owned();
        validate_run_id(&run_id)?;
        let mut leased_paths = verified_lease.paths().to_vec();
        if leased_paths.is_empty() || leased_paths.len() > MAX_PATHS {
            return Err(WorktreeError::InvalidRequest(
                "lease paths must be non-empty and bounded",
            ));
        }
        leased_paths.sort();
        if leased_paths
            .windows(2)
            .any(|pair| pair[0].overlaps(&pair[1]))
        {
            return Err(WorktreeError::InvalidRequest(
                "lease paths must be unique and non-overlapping",
            ));
        }
        if max_materialized_bytes == 0 || max_materialized_bytes > MAX_BUDGET {
            return Err(WorktreeError::InvalidRequest(
                "materialized-byte budget is outside the supported range",
            ));
        }
        Ok(Self {
            run_id,
            lease_identity: verified_lease.lease_identity().clone(),
            store_binding: verified_lease.store_binding().to_owned(),
            attempt_id: verified_lease.attempt_id().as_str().to_owned(),
            lease_id: verified_lease.lease_id().as_str().to_owned(),
            lease_epoch: verified_lease.epoch().get(),
            expected_base: verified_lease.base_revision().clone(),
            leased_paths,
            max_materialized_bytes,
        })
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn expected_base(&self) -> &BaseRevision {
        &self.expected_base
    }

    #[must_use]
    pub fn leased_paths(&self) -> &[RepoPath] {
        &self.leased_paths
    }

    #[must_use]
    pub const fn max_materialized_bytes(&self) -> u64 {
        self.max_materialized_bytes
    }

    fn verify_authority(&self) -> Result<(), WorktreeError> {
        self.authority_guard().map(drop)
    }

    fn authority_guard(&self) -> Result<Arc<()>, WorktreeError> {
        self.lease_identity
            .upgrade()
            .ok_or(WorktreeError::LeaseAuthorityInactive)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorktreeFaultPoint {
    AfterWorktreeAdd,
    AfterSparseSet,
    AfterPopulate,
    AfterReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorktreeState {
    Allocated,
    Released,
}

impl WorktreeState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allocated => "allocated",
            Self::Released => "released",
        }
    }

    fn parse(value: &str) -> Result<Self, WorktreeError> {
        match value {
            "allocated" => Ok(Self::Allocated),
            "released" => Ok(Self::Released),
            _ => Err(WorktreeError::InvalidState("receipt status is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reconciliation {
    Applied,
    Replayed,
    Recovered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeReceipt {
    state: WorktreeState,
    request_digest: String,
    materialized_bytes: u64,
    reconciliation: Reconciliation,
}

impl WorktreeReceipt {
    #[must_use]
    pub const fn state(&self) -> WorktreeState {
        self.state
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub const fn materialized_bytes(&self) -> u64 {
        self.materialized_bytes
    }

    #[must_use]
    pub const fn reconciliation(&self) -> Reconciliation {
        self.reconciliation
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WorktreeError {
    InvalidRequest(&'static str),
    UnsafeRepository(&'static str),
    DirtyBase,
    BaseMismatch,
    UnsupportedTree(&'static str),
    BudgetExceeded,
    LeaseAuthorityInactive,
    LeaseOverlap,
    StateConflict,
    InvalidState(&'static str),
    DirtyWorktree,
    GitFailure(&'static str),
    GitTimeout,
    GitOutputLimit,
    IoFailure(&'static str),
    InjectedFault(WorktreeFaultPoint),
}

impl fmt::Display for WorktreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::UnsafeRepository(message)
            | Self::UnsupportedTree(message)
            | Self::InvalidState(message)
            | Self::GitFailure(message)
            | Self::IoFailure(message) => formatter.write_str(message),
            Self::DirtyBase => formatter.write_str("source repository is dirty"),
            Self::BaseMismatch => formatter.write_str("source HEAD does not match immutable base"),
            Self::BudgetExceeded => {
                formatter.write_str("materialized-byte budget would be exceeded")
            }
            Self::LeaseAuthorityInactive => formatter.write_str("active lease authority is absent"),
            Self::LeaseOverlap => {
                formatter.write_str("another allocated worktree overlaps the lease")
            }
            Self::StateConflict => {
                formatter.write_str("allocation state belongs to another request")
            }
            Self::DirtyWorktree => formatter.write_str("allocated worktree is dirty"),
            Self::GitTimeout => formatter.write_str("fixed Git recipe exceeded its time limit"),
            Self::GitOutputLimit => {
                formatter.write_str("fixed Git recipe exceeded its output limit")
            }
            Self::InjectedFault(point) => write!(formatter, "injected worktree fault at {point:?}"),
        }
    }
}

impl Error for WorktreeError {}

/// A broker bound to exactly one source repository and one private state root.
#[derive(Debug)]
pub struct WorktreeAllocator {
    repository: PathBuf,
    state_root: PathBuf,
    git: PathBuf,
}

impl WorktreeAllocator {
    pub fn open(repository: &Path, state_root: &Path) -> Result<Self, WorktreeError> {
        reject_symlink_components(repository, true)?;
        let repository = repository
            .canonicalize()
            .map_err(|_| WorktreeError::UnsafeRepository("repository is unavailable"))?;
        if !repository.is_dir() {
            return Err(WorktreeError::UnsafeRepository(
                "repository is not a directory",
            ));
        }
        let parent = state_root
            .parent()
            .ok_or(WorktreeError::InvalidRequest("state root has no parent"))?;
        reject_symlink_components(parent, true)?;
        let parent = parent
            .canonicalize()
            .map_err(|_| WorktreeError::IoFailure("state parent is unavailable"))?;
        let name = state_root
            .file_name()
            .ok_or(WorktreeError::InvalidRequest("state root has no name"))?;
        let state_root = parent.join(name);
        if state_root.starts_with(&repository) || repository.starts_with(&state_root) {
            return Err(WorktreeError::InvalidRequest(
                "state root and source repository must not overlap",
            ));
        }
        let git = [Path::new("/usr/bin/git"), Path::new("/bin/git")]
            .into_iter()
            .find(|path| path.is_file())
            .ok_or(WorktreeError::GitFailure(
                "fixed Git executable is unavailable",
            ))?
            .to_path_buf();
        let mut allocator = Self {
            repository,
            state_root,
            git,
        };
        allocator.verify_repository_identity()?;
        ensure_private_dir(&allocator.state_root)?;
        reject_symlink_components(&allocator.state_root, true)?;
        allocator.state_root = allocator
            .state_root
            .canonicalize()
            .map_err(|_| WorktreeError::IoFailure("state root is unavailable"))?;
        Ok(allocator)
    }

    pub fn allocate(&self, request: &WorktreeRequest) -> Result<WorktreeReceipt, WorktreeError> {
        self.allocate_with_fault(request, None)
    }

    pub fn allocate_with_fault(
        &self,
        request: &WorktreeRequest,
        fault: Option<WorktreeFaultPoint>,
    ) -> Result<WorktreeReceipt, WorktreeError> {
        request.verify_authority()?;
        self.verify_repository_identity()?;
        self.verify_source(request)?;
        let layout = self.layout(request)?;
        let digest = request_digest(request);
        let _allocator_lock = lock_operation(&self.state_root.join("allocator.lock"))?;

        let inventory = self.inventory(request)?;
        if inventory.bytes > request.max_materialized_bytes {
            return Err(WorktreeError::BudgetExceeded);
        }
        self.reject_overlapping_allocation(request, &layout.run_dir)?;
        ensure_private_dir(&layout.run_dir)?;
        let _operation_lock = lock_operation(&layout.lock)?;
        self.ensure_intent(&layout.intent, request, &digest)?;

        if let Some(receipt) = read_receipt(&layout.receipt, &digest)? {
            match receipt.state {
                WorktreeState::Allocated => {
                    if !layout.checkout.exists() {
                        return Err(WorktreeError::InvalidState("allocated worktree is missing"));
                    }
                    let inventory = self.inventory(request)?;
                    if inventory.bytes != receipt.materialized_bytes {
                        return Err(WorktreeError::InvalidState(
                            "receipt byte count is inconsistent",
                        ));
                    }
                    self.verify_checkout(request, &layout.checkout, inventory.bytes)?;
                }
                WorktreeState::Released if layout.checkout.exists() => {
                    return Err(WorktreeError::InvalidState(
                        "released worktree is unexpectedly present",
                    ));
                }
                WorktreeState::Released => {}
            }
            let _authority_guard = request.authority_guard()?;
            return Ok(WorktreeReceipt {
                reconciliation: Reconciliation::Replayed,
                ..receipt
            });
        }

        let mut phase =
            read_progress(&layout.progress, &digest)?.unwrap_or(WorktreeProgress::Intent);
        if !layout.progress.exists() {
            write_progress(&layout.progress, &digest, phase)?;
        }
        let recovered = phase != WorktreeProgress::Intent || layout.checkout.exists();

        if phase == WorktreeProgress::Intent {
            if layout.checkout.exists() {
                fs::set_permissions(&layout.checkout, fs::Permissions::from_mode(0o700)).map_err(
                    |_| WorktreeError::IoFailure("worktree permissions could not be set"),
                )?;
                self.verify_prepared_checkout(request, &layout.checkout)?;
            } else {
                let _authority_guard = request.authority_guard()?;
                self.run(GitRecipe::AddWorktree {
                    checkout: &layout.checkout,
                    base: request.expected_base(),
                })?;
                fs::set_permissions(&layout.checkout, fs::Permissions::from_mode(0o700)).map_err(
                    |_| WorktreeError::IoFailure("worktree permissions could not be set"),
                )?;
                if fault == Some(WorktreeFaultPoint::AfterWorktreeAdd) {
                    return Err(WorktreeError::InjectedFault(
                        WorktreeFaultPoint::AfterWorktreeAdd,
                    ));
                }
            }
            phase = WorktreeProgress::WorktreeAdded;
            write_progress(&layout.progress, &digest, phase)?;
        }
        if phase == WorktreeProgress::WorktreeAdded {
            self.verify_prepared_checkout(request, &layout.checkout)?;
            let patterns = inventory.patterns.join("\n") + "\n";
            let _authority_guard = request.authority_guard()?;
            self.run(GitRecipe::SparseSet {
                checkout: &layout.checkout,
                patterns: patterns.as_bytes(),
            })?;
            if fault == Some(WorktreeFaultPoint::AfterSparseSet) {
                return Err(WorktreeError::InjectedFault(
                    WorktreeFaultPoint::AfterSparseSet,
                ));
            }
            phase = WorktreeProgress::SparseSet;
            write_progress(&layout.progress, &digest, phase)?;
        }
        if phase == WorktreeProgress::SparseSet {
            let _authority_guard = request.authority_guard()?;
            self.run(GitRecipe::Populate {
                checkout: &layout.checkout,
                base: request.expected_base(),
            })?;
            if fault == Some(WorktreeFaultPoint::AfterPopulate) {
                return Err(WorktreeError::InjectedFault(
                    WorktreeFaultPoint::AfterPopulate,
                ));
            }
            phase = WorktreeProgress::Populated;
            write_progress(&layout.progress, &digest, phase)?;
        }
        if phase != WorktreeProgress::Populated {
            return Err(WorktreeError::InvalidState(
                "worktree progress is inconsistent",
            ));
        }
        self.verify_checkout(request, &layout.checkout, inventory.bytes)?;

        let receipt = WorktreeReceipt {
            state: WorktreeState::Allocated,
            request_digest: digest,
            materialized_bytes: inventory.bytes,
            reconciliation: if recovered {
                Reconciliation::Recovered
            } else {
                Reconciliation::Applied
            },
        };
        let _authority_guard = request.authority_guard()?;
        write_receipt(&layout.receipt, &receipt)?;
        if fault == Some(WorktreeFaultPoint::AfterReceipt) {
            return Err(WorktreeError::InjectedFault(
                WorktreeFaultPoint::AfterReceipt,
            ));
        }
        Ok(receipt)
    }

    pub fn release(&self, request: &WorktreeRequest) -> Result<WorktreeReceipt, WorktreeError> {
        request.verify_authority()?;
        self.verify_repository_identity()?;
        let layout = self.layout(request)?;
        let digest = request_digest(request);
        let _allocator_lock = lock_operation(&self.state_root.join("allocator.lock"))?;
        ensure_private_dir(&layout.run_dir)?;
        let _operation_lock = lock_operation(&layout.lock)?;
        self.ensure_intent(&layout.intent, request, &digest)?;
        let prior = read_receipt(&layout.receipt, &digest)?
            .ok_or(WorktreeError::InvalidState("allocation receipt is missing"))?;
        if prior.state == WorktreeState::Released {
            let _authority_guard = request.authority_guard()?;
            return Ok(WorktreeReceipt {
                reconciliation: Reconciliation::Replayed,
                ..prior
            });
        }

        let recovered = if layout.checkout.exists() {
            if !self
                .run(GitRecipe::Status {
                    checkout: &layout.checkout,
                })?
                .stdout
                .is_empty()
            {
                return Err(WorktreeError::DirtyWorktree);
            }
            let _authority_guard = request.authority_guard()?;
            self.run(GitRecipe::RemoveWorktree {
                checkout: &layout.checkout,
            })?;
            false
        } else {
            true
        };
        let receipt = WorktreeReceipt {
            state: WorktreeState::Released,
            request_digest: digest,
            materialized_bytes: prior.materialized_bytes,
            reconciliation: if recovered {
                Reconciliation::Recovered
            } else {
                Reconciliation::Applied
            },
        };
        let _authority_guard = request.authority_guard()?;
        write_receipt(&layout.receipt, &receipt)?;
        Ok(receipt)
    }

    fn layout(&self, request: &WorktreeRequest) -> Result<Layout, WorktreeError> {
        let run_dir = self.state_root.join(request.run_id());
        if !run_dir.starts_with(&self.state_root) {
            return Err(WorktreeError::InvalidRequest(
                "allocation escaped state root",
            ));
        }
        reject_symlink_components(&run_dir, false)?;
        Ok(Layout {
            intent: run_dir.join("intent.json"),
            receipt: run_dir.join("receipt.json"),
            progress: run_dir.join("progress.json"),
            checkout: run_dir.join("checkout"),
            lock: run_dir.join("operation.lock"),
            run_dir,
        })
    }

    fn verify_source(&self, request: &WorktreeRequest) -> Result<(), WorktreeError> {
        let head = text_output(self.run(GitRecipe::Head)?)?;
        if head != request.expected_base().as_str() {
            return Err(WorktreeError::BaseMismatch);
        }
        if !self.run(GitRecipe::StatusSource)?.stdout.is_empty() {
            return Err(WorktreeError::DirtyBase);
        }
        self.run(GitRecipe::VerifyCommit(request.expected_base()))?;
        Ok(())
    }

    fn reject_overlapping_allocation(
        &self,
        request: &WorktreeRequest,
        own_run_dir: &Path,
    ) -> Result<(), WorktreeError> {
        for entry in fs::read_dir(&self.state_root)
            .map_err(|_| WorktreeError::InvalidState("state root could not be enumerated"))?
        {
            let entry =
                entry.map_err(|_| WorktreeError::InvalidState("state entry is unavailable"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| WorktreeError::InvalidState("state entry is unavailable"))?;
            if metadata.file_type().is_symlink() {
                return Err(WorktreeError::InvalidState(
                    "symbolic link in allocator state is forbidden",
                ));
            }
            if !metadata.is_dir() || entry.path() == own_run_dir {
                continue;
            }
            let intent_path = entry.path().join("intent.json");
            if !intent_path.exists() {
                continue;
            }
            let (digest, paths) = read_intent_paths(&intent_path)?;
            let receipt_path = entry.path().join("receipt.json");
            if read_receipt(&receipt_path, &digest)?
                .is_some_and(|receipt| receipt.state == WorktreeState::Released)
            {
                continue;
            }
            if paths.iter().any(|existing| {
                request
                    .leased_paths()
                    .iter()
                    .any(|requested| existing.overlaps(requested))
            }) {
                return Err(WorktreeError::LeaseOverlap);
            }
        }
        Ok(())
    }

    fn verify_repository_identity(&self) -> Result<(), WorktreeError> {
        reject_symlink_components(&self.repository, true)?;
        let top = text_output(self.run_unchecked(GitRecipe::TopLevel)?)?;
        let top = Path::new(&top)
            .canonicalize()
            .map_err(|_| WorktreeError::UnsafeRepository("Git top level is unavailable"))?;
        if top != self.repository {
            return Err(WorktreeError::UnsafeRepository(
                "Git top level does not match the bound repository",
            ));
        }
        let marker = self.repository.join(".git");
        reject_symlink_components(&marker, true)?;
        if !fs::symlink_metadata(&marker)
            .map_err(|_| WorktreeError::UnsafeRepository("Git metadata is unavailable"))?
            .file_type()
            .is_dir()
        {
            return Err(WorktreeError::UnsafeRepository(
                "Git metadata must be a real directory",
            ));
        }
        for recipe in [GitRecipe::GitDir, GitRecipe::CommonDir] {
            let metadata_path = text_output(self.run_unchecked(recipe)?)?;
            let metadata_path = Path::new(&metadata_path)
                .canonicalize()
                .map_err(|_| WorktreeError::UnsafeRepository("Git metadata is unavailable"))?;
            if !metadata_path.starts_with(&self.repository) {
                return Err(WorktreeError::UnsafeRepository(
                    "Git metadata escaped the bound repository",
                ));
            }
        }
        Ok(())
    }

    fn inventory(&self, request: &WorktreeRequest) -> Result<Inventory, WorktreeError> {
        let output = self.run(GitRecipe::Inventory {
            base: request.expected_base(),
            paths: request.leased_paths(),
        })?;
        let mut bytes = 0_u64;
        let mut seen = BTreeSet::new();
        let mut tree_paths = BTreeSet::new();
        for record in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|r| !r.is_empty())
        {
            let tab = record
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or(WorktreeError::GitFailure("Git inventory was malformed"))?;
            let header = std::str::from_utf8(&record[..tab])
                .map_err(|_| WorktreeError::GitFailure("Git inventory was not UTF-8"))?;
            let path = std::str::from_utf8(&record[tab + 1..])
                .map_err(|_| WorktreeError::UnsupportedTree("non-UTF-8 paths are unsupported"))?;
            let mut parts = header.split_ascii_whitespace();
            let mode = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or_default();
            let _oid = parts.next().unwrap_or_default();
            let size = parts.next().unwrap_or_default();
            if mode == "120000" {
                return Err(WorktreeError::UnsupportedTree(
                    "symbolic links are not permitted in a lease",
                ));
            }
            if mode == "160000" || kind == "commit" {
                return Err(WorktreeError::UnsupportedTree(
                    "submodules are not permitted in a lease",
                ));
            }
            if kind == "blob" {
                let size = size
                    .parse::<u64>()
                    .map_err(|_| WorktreeError::GitFailure("Git blob size was malformed"))?;
                bytes = bytes
                    .checked_add(size)
                    .ok_or(WorktreeError::BudgetExceeded)?;
                seen.insert(path.to_owned());
            } else if kind == "tree" {
                tree_paths.insert(path.to_owned());
            }
        }
        for lease in request.leased_paths() {
            let exists = seen
                .iter()
                .any(|path| path == lease.as_str() || beneath(path, lease.as_str()))
                || tree_paths.contains(lease.as_str());
            if !exists {
                return Err(WorktreeError::InvalidRequest(
                    "a leased path does not exist at the immutable base",
                ));
            }
        }
        let mut attribute_input = Vec::new();
        for path in &seen {
            attribute_input.extend_from_slice(path.as_bytes());
            attribute_input.push(0);
        }
        let attributes = self.run(GitRecipe::CheckFilter(&attribute_input))?;
        let fields: Vec<&[u8]> = attributes.stdout.split(|byte| *byte == 0).collect();
        for triple in fields.chunks(3) {
            if triple.len() == 3 && !matches!(triple[2], b"unspecified" | b"unset" | b"") {
                return Err(WorktreeError::UnsupportedTree(
                    "content filters are not permitted",
                ));
            }
        }
        let mut patterns = Vec::with_capacity(request.leased_paths().len());
        for lease in request.leased_paths() {
            let mut pattern = String::from("/");
            for character in lease.as_str().chars() {
                if matches!(character, '*' | '?' | '[' | ']' | '\\') {
                    pattern.push('\\');
                }
                pattern.push(character);
            }
            if tree_paths.contains(lease.as_str()) {
                pattern.push('/');
            }
            patterns.push(pattern);
        }
        Ok(Inventory { bytes, patterns })
    }

    fn verify_checkout(
        &self,
        request: &WorktreeRequest,
        checkout: &Path,
        expected_bytes: u64,
    ) -> Result<(), WorktreeError> {
        self.verify_prepared_checkout(request, checkout)?;
        if !self.run(GitRecipe::Status { checkout })?.stdout.is_empty() {
            return Err(WorktreeError::DirtyWorktree);
        }
        let actual = verify_materialized(checkout, request.leased_paths())?;
        if actual > request.max_materialized_bytes || actual != expected_bytes {
            return Err(WorktreeError::BudgetExceeded);
        }
        Ok(())
    }

    fn verify_prepared_checkout(
        &self,
        request: &WorktreeRequest,
        checkout: &Path,
    ) -> Result<(), WorktreeError> {
        reject_symlink_components(checkout, true)?;
        let canonical = checkout
            .canonicalize()
            .map_err(|_| WorktreeError::InvalidState("worktree is unavailable"))?;
        if !canonical.starts_with(&self.state_root) {
            return Err(WorktreeError::InvalidState("worktree escaped state root"));
        }
        let top = text_output(self.run(GitRecipe::WorktreeTop { checkout })?)?;
        if Path::new(&top).canonicalize().ok().as_ref() != Some(&canonical) {
            return Err(WorktreeError::InvalidState(
                "worktree top level is inconsistent",
            ));
        }
        let head = text_output(self.run(GitRecipe::WorktreeHead { checkout })?)?;
        if head != request.expected_base().as_str() {
            return Err(WorktreeError::InvalidState("worktree base is inconsistent"));
        }
        if self
            .run_allow_failure(GitRecipe::SymbolicHead { checkout })?
            .status
            .success()
        {
            return Err(WorktreeError::InvalidState("worktree HEAD is not detached"));
        }
        Ok(())
    }

    fn ensure_intent(
        &self,
        path: &Path,
        request: &WorktreeRequest,
        digest: &str,
    ) -> Result<(), WorktreeError> {
        let value = intent_value(request, digest);
        if path.exists() {
            if read_json(path)? == value {
                return Ok(());
            }
            return Err(WorktreeError::StateConflict);
        }
        write_json(path, &value, false)
    }

    fn run(&self, recipe: GitRecipe<'_>) -> Result<Output, WorktreeError> {
        let output = self.run_allow_failure(recipe)?;
        if !output.status.success() {
            return Err(WorktreeError::GitFailure("fixed Git recipe failed"));
        }
        Ok(output)
    }

    fn run_allow_failure(&self, recipe: GitRecipe<'_>) -> Result<Output, WorktreeError> {
        self.run_unchecked(recipe)
    }

    fn run_unchecked(&self, recipe: GitRecipe<'_>) -> Result<Output, WorktreeError> {
        let mut command = Command::new(&self.git);
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
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.autocrlf=false",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let mut input = None;
        match recipe {
            GitRecipe::TopLevel => command.args(["rev-parse", "--show-toplevel"]),
            GitRecipe::GitDir => command.args(["rev-parse", "--path-format=absolute", "--git-dir"]),
            GitRecipe::CommonDir => {
                command.args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
            }
            GitRecipe::Head => command.args(["rev-parse", "--verify", "HEAD"]),
            GitRecipe::VerifyCommit(base) => {
                command.args(["cat-file", "-e", &format!("{}^{{commit}}", base.as_str())])
            }
            GitRecipe::StatusSource => command.args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--no-renames",
            ]),
            GitRecipe::CheckFilter(paths) => {
                command
                    .args(["check-attr", "-z", "--stdin", "filter"])
                    .stdin(Stdio::piped());
                input = Some(paths);
                &mut command
            }
            GitRecipe::Inventory { base, paths } => {
                command.args(["ls-tree", "-r", "-t", "-l", "-z", base.as_str(), "--"]);
                command.args(paths.iter().map(RepoPath::as_str))
            }
            GitRecipe::AddWorktree { checkout, base } => command.args([
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                checkout
                    .to_str()
                    .ok_or(WorktreeError::InvalidRequest("state path is not UTF-8"))?,
                base.as_str(),
            ]),
            GitRecipe::SparseSet { checkout, patterns } => {
                command
                    .arg("-C")
                    .arg(checkout)
                    .args(["sparse-checkout", "set", "--no-cone", "--stdin"])
                    .stdin(Stdio::piped());
                input = Some(patterns);
                &mut command
            }
            GitRecipe::Populate { checkout, base } => {
                command
                    .arg("-C")
                    .arg(checkout)
                    .args(["checkout", "--detach", base.as_str()])
            }
            GitRecipe::WorktreeTop { checkout } => command
                .arg("-C")
                .arg(checkout)
                .args(["rev-parse", "--show-toplevel"]),
            GitRecipe::WorktreeHead { checkout } => {
                command
                    .arg("-C")
                    .arg(checkout)
                    .args(["rev-parse", "--verify", "HEAD"])
            }
            GitRecipe::SymbolicHead { checkout } => {
                command
                    .arg("-C")
                    .arg(checkout)
                    .args(["symbolic-ref", "--quiet", "HEAD"])
            }
            GitRecipe::Status { checkout } => command.arg("-C").arg(checkout).args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--no-renames",
            ]),
            GitRecipe::RemoveWorktree { checkout } => {
                command.args(["worktree", "remove", "--"]).arg(checkout)
            }
        };
        let mut child = command
            .spawn()
            .map_err(|_| WorktreeError::GitFailure("Git process did not start"))?;
        if let Some(bytes) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(WorktreeError::GitFailure("Git stdin unavailable"))?;
            if stdin.write_all(bytes).is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WorktreeError::GitFailure("Git stdin failed"));
            }
        }
        bounded_wait(child)
    }
}

struct Layout {
    run_dir: PathBuf,
    intent: PathBuf,
    receipt: PathBuf,
    progress: PathBuf,
    checkout: PathBuf,
    lock: PathBuf,
}

struct Inventory {
    bytes: u64,
    patterns: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorktreeProgress {
    Intent,
    WorktreeAdded,
    SparseSet,
    Populated,
}

impl WorktreeProgress {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::WorktreeAdded => "worktree_added",
            Self::SparseSet => "sparse_set",
            Self::Populated => "populated",
        }
    }

    fn parse(value: &str) -> Result<Self, WorktreeError> {
        match value {
            "intent" => Ok(Self::Intent),
            "worktree_added" => Ok(Self::WorktreeAdded),
            "sparse_set" => Ok(Self::SparseSet),
            "populated" => Ok(Self::Populated),
            _ => Err(WorktreeError::InvalidState("worktree progress is invalid")),
        }
    }
}

enum GitRecipe<'a> {
    TopLevel,
    GitDir,
    CommonDir,
    Head,
    VerifyCommit(&'a BaseRevision),
    StatusSource,
    CheckFilter(&'a [u8]),
    Inventory {
        base: &'a BaseRevision,
        paths: &'a [RepoPath],
    },
    AddWorktree {
        checkout: &'a Path,
        base: &'a BaseRevision,
    },
    SparseSet {
        checkout: &'a Path,
        patterns: &'a [u8],
    },
    Populate {
        checkout: &'a Path,
        base: &'a BaseRevision,
    },
    WorktreeTop {
        checkout: &'a Path,
    },
    WorktreeHead {
        checkout: &'a Path,
    },
    SymbolicHead {
        checkout: &'a Path,
    },
    Status {
        checkout: &'a Path,
    },
    RemoveWorktree {
        checkout: &'a Path,
    },
}

fn validate_run_id(value: &str) -> Result<(), WorktreeError> {
    let Some(first) = value.bytes().next() else {
        return Err(WorktreeError::InvalidRequest("run ID is empty"));
    };
    if value.len() > MAX_RUN_ID_BYTES
        || !first.is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(WorktreeError::InvalidRequest("run ID is not canonical"));
    }
    Ok(())
}

fn request_digest(request: &WorktreeRequest) -> String {
    let bytes =
        serde_json::to_vec(&intent_value(request, "")).expect("bounded JSON is serializable");
    hex::encode(Sha256::digest(bytes))
}

fn intent_value(request: &WorktreeRequest, digest: &str) -> Value {
    json!({
        "schema": INTENT_SCHEMA,
        "request_digest": digest,
        "run_id": request.run_id(),
        "store_binding": request.store_binding,
        "attempt_id": request.attempt_id,
        "lease_id": request.lease_id,
        "lease_epoch": request.lease_epoch,
        "expected_base": request.expected_base().as_str(),
        "leased_paths": request.leased_paths().iter().map(RepoPath::as_str).collect::<Vec<_>>(),
        "max_materialized_bytes": request.max_materialized_bytes(),
    })
}

fn read_intent_paths(path: &Path) -> Result<(String, Vec<RepoPath>), WorktreeError> {
    let value = read_json(path)?;
    let object = value
        .as_object()
        .ok_or(WorktreeError::InvalidState("intent is not an object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(INTENT_SCHEMA) {
        return Err(WorktreeError::InvalidState("intent schema is invalid"));
    }
    let digest = object
        .get("request_digest")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(WorktreeError::InvalidState("intent digest is invalid"))?
        .to_owned();
    let values = object
        .get("leased_paths")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= MAX_PATHS)
        .ok_or(WorktreeError::InvalidState("intent paths are invalid"))?;
    let mut paths = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(WorktreeError::InvalidState("intent path is invalid"))
                .and_then(|value| {
                    RepoPath::parse(value)
                        .map_err(|_| WorktreeError::InvalidState("intent path is invalid"))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    if paths.windows(2).any(|pair| pair[0].overlaps(&pair[1])) {
        return Err(WorktreeError::InvalidState("intent paths overlap"));
    }
    Ok((digest, paths))
}

fn read_progress(path: &Path, digest: &str) -> Result<Option<WorktreeProgress>, WorktreeError> {
    if !path.exists() {
        return Ok(None);
    }
    let value = read_json(path)?;
    let object = value
        .as_object()
        .ok_or(WorktreeError::InvalidState("progress is not an object"))?;
    if object.len() != 3
        || object.get("schema").and_then(Value::as_str) != Some(PROGRESS_SCHEMA)
        || object.get("request_digest").and_then(Value::as_str) != Some(digest)
    {
        return Err(WorktreeError::StateConflict);
    }
    Ok(Some(WorktreeProgress::parse(
        object
            .get("phase")
            .and_then(Value::as_str)
            .ok_or(WorktreeError::InvalidState("progress phase is missing"))?,
    )?))
}

fn write_progress(path: &Path, digest: &str, phase: WorktreeProgress) -> Result<(), WorktreeError> {
    write_json(
        path,
        &json!({
            "schema": PROGRESS_SCHEMA,
            "request_digest": digest,
            "phase": phase.as_str(),
        }),
        true,
    )
}

fn receipt_value(receipt: &WorktreeReceipt) -> Value {
    json!({
        "schema": RECEIPT_SCHEMA,
        "request_digest": receipt.request_digest,
        "state": receipt.state.as_str(),
        "materialized_bytes": receipt.materialized_bytes,
    })
}

fn read_receipt(path: &Path, digest: &str) -> Result<Option<WorktreeReceipt>, WorktreeError> {
    if !path.exists() {
        return Ok(None);
    }
    let value = read_json(path)?;
    let object = value
        .as_object()
        .ok_or(WorktreeError::InvalidState("receipt is not an object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(RECEIPT_SCHEMA)
        || object.get("request_digest").and_then(Value::as_str) != Some(digest)
    {
        return Err(WorktreeError::StateConflict);
    }
    let state = WorktreeState::parse(
        object
            .get("state")
            .and_then(Value::as_str)
            .ok_or(WorktreeError::InvalidState("receipt status is missing"))?,
    )?;
    let materialized_bytes = object
        .get("materialized_bytes")
        .and_then(Value::as_u64)
        .ok_or(WorktreeError::InvalidState("receipt byte count is missing"))?;
    Ok(Some(WorktreeReceipt {
        state,
        request_digest: digest.to_owned(),
        materialized_bytes,
        reconciliation: Reconciliation::Recovered,
    }))
}

fn write_receipt(path: &Path, receipt: &WorktreeReceipt) -> Result<(), WorktreeError> {
    write_json(path, &receipt_value(receipt), true)
}

fn read_json(path: &Path) -> Result<Value, WorktreeError> {
    reject_symlink_components(path, true)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| WorktreeError::InvalidState("state file is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.len() > MAX_STATE_BYTES
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(WorktreeError::InvalidState("state file is unsafe"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| WorktreeError::InvalidState("state file could not be read"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STATE_BYTES {
        return Err(WorktreeError::InvalidState("state file is oversized"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| WorktreeError::InvalidState("state JSON is malformed"))
}

fn write_json(path: &Path, value: &Value, replace: bool) -> Result<(), WorktreeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| WorktreeError::IoFailure("state JSON could not be encoded"))?;
    let temp = path.with_extension(format!("new-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&temp)
        .map_err(|_| WorktreeError::IoFailure("temporary state file could not be created"))?;
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(WorktreeError::IoFailure(
            "state file could not be persisted",
        ));
    }
    if replace {
        fs::rename(&temp, path).map_err(|_| {
            let _ = fs::remove_file(&temp);
            WorktreeError::IoFailure("state file could not be installed")
        })?;
    } else {
        fs::hard_link(&temp, path).map_err(|error| {
            let _ = fs::remove_file(&temp);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                WorktreeError::StateConflict
            } else {
                WorktreeError::IoFailure("state file could not be installed")
            }
        })?;
        fs::remove_file(&temp)
            .map_err(|_| WorktreeError::IoFailure("temporary state file could not be removed"))?;
    }
    let directory = File::open(path.parent().expect("state file has parent"))
        .map_err(|_| WorktreeError::IoFailure("state directory could not be opened"))?;
    directory
        .sync_all()
        .map_err(|_| WorktreeError::IoFailure("state directory could not be synced"))
}

fn ensure_private_dir(path: &Path) -> Result<(), WorktreeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir()
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                return Err(WorktreeError::InvalidState("state directory is unsafe"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(error) = builder.create(path)
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(WorktreeError::IoFailure(
                    "state directory could not be created",
                ));
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| WorktreeError::InvalidState("state directory is unavailable"))?;
            if !metadata.file_type().is_dir()
                || metadata.mode() & 0o077 != 0
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                return Err(WorktreeError::InvalidState("state directory is unsafe"));
            }
        }
        Err(_) => return Err(WorktreeError::IoFailure("state directory is unavailable")),
    }
    Ok(())
}

fn lock_operation(path: &Path) -> Result<Flock<File>, WorktreeError> {
    reject_symlink_components(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| WorktreeError::IoFailure("operation lock could not be opened"))?;
    reject_symlink_components(path, true)?;
    let metadata = file
        .metadata()
        .map_err(|_| WorktreeError::InvalidState("operation lock is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(WorktreeError::InvalidState("operation lock is unsafe"));
    }
    let deadline = Instant::now() + GIT_TIMEOUT;
    let mut unlocked = file;
    loop {
        match Flock::lock(unlocked, FlockArg::LockExclusiveNonblock) {
            Ok(locked) => return Ok(locked),
            Err((file, nix::errno::Errno::EWOULDBLOCK)) if Instant::now() < deadline => {
                unlocked = file;
                thread::sleep(POLL);
            }
            Err((_file, nix::errno::Errno::EWOULDBLOCK)) => {
                return Err(WorktreeError::InvalidState("operation lock timed out"));
            }
            Err((_file, _)) => {
                return Err(WorktreeError::IoFailure(
                    "operation lock could not be acquired",
                ));
            }
        }
    }
}

fn reject_symlink_components(path: &Path, require_final: bool) -> Result<(), WorktreeError> {
    if !path.is_absolute() {
        return Err(WorktreeError::InvalidRequest(
            "filesystem path must be absolute",
        ));
    }
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            _ => {
                return Err(WorktreeError::InvalidRequest(
                    "filesystem path is not canonical",
                ));
            }
        }
        if index + 1 == components.len() && !require_final && !current.exists() {
            break;
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| WorktreeError::InvalidState("filesystem component is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(WorktreeError::InvalidState(
                "symbolic-link component is forbidden",
            ));
        }
    }
    Ok(())
}

fn verify_materialized(root: &Path, leases: &[RepoPath]) -> Result<u64, WorktreeError> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|_| WorktreeError::InvalidState("worktree could not be enumerated"))?
        {
            let entry =
                entry.map_err(|_| WorktreeError::InvalidState("worktree entry is unavailable"))?;
            let path = entry.path();
            if path == root.join(".git") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| WorktreeError::InvalidState("worktree metadata is unavailable"))?;
            if metadata.file_type().is_symlink() {
                return Err(WorktreeError::UnsupportedTree(
                    "symbolic links are forbidden",
                ));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| WorktreeError::InvalidState("worktree entry escaped its root"))?;
            let relative = relative.to_str().ok_or(WorktreeError::UnsupportedTree(
                "non-UTF-8 paths are unsupported",
            ))?;
            let allowed = leases.iter().any(|lease| {
                relative == lease.as_str()
                    || beneath(relative, lease.as_str())
                    || beneath(lease.as_str(), relative)
            });
            if !allowed {
                return Err(WorktreeError::InvalidState(
                    "materialized path is outside the lease",
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or(WorktreeError::BudgetExceeded)?;
            } else {
                return Err(WorktreeError::UnsupportedTree(
                    "special files are forbidden",
                ));
            }
        }
    }
    Ok(total)
}

fn beneath(path: &str, ancestor: &str) -> bool {
    path.strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn text_output(output: Output) -> Result<String, WorktreeError> {
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| WorktreeError::GitFailure("Git output was not UTF-8"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn bounded_wait(mut child: std::process::Child) -> Result<Output, WorktreeError> {
    let group = Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| WorktreeError::GitFailure("Git PID is invalid"))?,
    );
    let stdout = child
        .stdout
        .take()
        .ok_or(WorktreeError::GitFailure("Git stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(WorktreeError::GitFailure("Git stderr unavailable"))?;
    let count = Arc::new(AtomicUsize::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let out = capture(stdout, Arc::clone(&count), Arc::clone(&exceeded));
    let err = capture(stderr, count, Arc::clone(&exceeded));
    let deadline = Instant::now() + GIT_TIMEOUT;
    let mut forced = None;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            forced = Some(WorktreeError::GitOutputLimit);
            break terminate(&mut child, group)?;
        }
        if Instant::now() >= deadline {
            forced = Some(WorktreeError::GitTimeout);
            break terminate(&mut child, group)?;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| WorktreeError::GitFailure("Git wait failed"))?
        {
            let _ = killpg(group, Signal::SIGKILL);
            break status;
        }
        thread::sleep(POLL);
    };
    let stdout = out
        .join()
        .map_err(|_| WorktreeError::GitFailure("Git output reader panicked"))??;
    let stderr = err
        .join()
        .map_err(|_| WorktreeError::GitFailure("Git output reader panicked"))??;
    if let Some(error) = forced {
        return Err(error);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn capture(
    mut input: impl Read + Send + 'static,
    count: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, WorktreeError>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        let mut chunk = [0_u8; 8_192];
        loop {
            let read = input
                .read(&mut chunk)
                .map_err(|_| WorktreeError::GitFailure("Git output read failed"))?;
            if read == 0 {
                return Ok(result);
            }
            let start = count.fetch_add(read, Ordering::AcqRel);
            let remaining = MAX_GIT_OUTPUT.saturating_sub(start);
            result.extend_from_slice(&chunk[..read.min(remaining)]);
            if read > remaining {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn terminate(
    child: &mut std::process::Child,
    group: Pid,
) -> Result<std::process::ExitStatus, WorktreeError> {
    let _ = killpg(group, Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_millis(50);
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| WorktreeError::GitFailure("Git wait failed"))?
        {
            let _ = killpg(group, Signal::SIGKILL);
            return Ok(status);
        }
        thread::sleep(POLL);
    }
    let _ = killpg(group, Signal::SIGKILL);
    child
        .wait()
        .map_err(|_| WorktreeError::GitFailure("Git reap failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{OpaqueId, Sha256Digest};
    use crate::state::{AcquirePaths, AttemptState, ControllerRoot, StateStore, TransitionAttempt};
    use crate::workspace_lease::{ActionId, AttemptId, LeaseId, Mutation, Revision};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use std::sync::{Arc, Barrier};

    struct Fixture {
        _temporary: tempfile::TempDir,
        repository: PathBuf,
        state: PathBuf,
        base: BaseRevision,
        lease_store: StateStore,
        lease_epoch: crate::workspace_lease::FenceEpoch,
        lease_revision: Revision,
        leased_path: RepoPath,
    }

    impl Fixture {
        fn new(leased_path: &str) -> Self {
            Self::with_setup(leased_path, |_| {})
        }

        fn with_setup(leased_path: &str, setup: impl FnOnce(&Path)) -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
                .expect("private temporary directory");
            let repository = temporary.path().join("repository");
            let state = temporary.path().join("state");
            fs::create_dir(&repository).expect("repository directory");
            git(&repository, &["init", "-q"]);
            git(&repository, &["config", "user.name", "Fixture"]);
            git(
                &repository,
                &["config", "user.email", "fixture@automonique.invalid"],
            );
            fs::create_dir_all(repository.join("leased/nested")).expect("leased directory");
            fs::create_dir_all(repository.join("outside")).expect("outside directory");
            fs::write(repository.join("leased/file.txt"), b"leased\n").expect("leased file");
            fs::write(repository.join("leased/nested/second.txt"), b"second\n")
                .expect("second file");
            fs::write(repository.join("outside/hidden.txt"), b"hidden\n").expect("outside file");
            setup(&repository);
            git(&repository, &["add", "."]);
            git(&repository, &["commit", "-qm", "fixture"]);
            let base = BaseRevision::parse(git_text(&repository, &["rev-parse", "HEAD"]))
                .expect("base revision");
            let mut lease_store = StateStore::open(
                &ControllerRoot { seal: () },
                temporary.path().join("lease-state.sqlite3"),
            )
            .expect("lease store");
            let authority = lease_store.broker_authority();
            lease_store
                .create_attempt(
                    &authority,
                    AttemptId::parse("attempt-1").expect("attempt"),
                    OpaqueId::new("objective-1").expect("objective"),
                    base.clone(),
                )
                .expect("attempt");
            let leased_path = RepoPath::parse(leased_path).expect("lease path");
            let acquired = lease_store
                .acquire_paths(
                    &authority,
                    AcquirePaths {
                        action_id: ActionId::parse("acquire-1").expect("action"),
                        lease_id: LeaseId::parse("lease-1").expect("lease"),
                        attempt_id: AttemptId::parse("attempt-1").expect("attempt"),
                        base_revision: base.clone(),
                        expected_revision: Revision::default(),
                        paths: vec![leased_path.clone()],
                    },
                )
                .expect("lease acquired");
            let (lease_epoch, lease_revision) = match acquired {
                Mutation::Applied(receipt) | Mutation::Replayed(receipt) => {
                    (receipt.epoch, receipt.revision)
                }
            };
            Self {
                _temporary: temporary,
                repository,
                state,
                base,
                lease_store,
                lease_epoch,
                lease_revision,
                leased_path,
            }
        }

        fn request(&self, budget: u64) -> WorktreeRequest {
            let authority = self.lease_store.broker_authority();
            let verified = self
                .lease_store
                .verify_active_lease(
                    &authority,
                    &AttemptId::parse("attempt-1").expect("attempt"),
                    &LeaseId::parse("lease-1").expect("lease"),
                    self.lease_epoch,
                    &self.base,
                    vec![self.leased_path.clone()],
                )
                .expect("verified lease");
            WorktreeRequest::new(verified, budget).expect("request")
        }

        fn allocator(&self) -> WorktreeAllocator {
            WorktreeAllocator::open(&self.repository, &self.state).expect("allocator")
        }

        fn checkout(&self) -> PathBuf {
            self.state.join("attempt-1").join("checkout")
        }

        fn foreign_request(&self) -> (StateStore, WorktreeRequest) {
            let mut store = StateStore::open(
                &ControllerRoot { seal: () },
                self._temporary.path().join("foreign-lease-state.sqlite3"),
            )
            .expect("foreign lease store");
            let authority = store.broker_authority();
            let attempt = AttemptId::parse("attempt-2").expect("attempt");
            let lease = LeaseId::parse("lease-2").expect("lease");
            store
                .create_attempt(
                    &authority,
                    attempt.clone(),
                    OpaqueId::new("objective-2").expect("objective"),
                    self.base.clone(),
                )
                .expect("foreign attempt");
            let acquired = store
                .acquire_paths(
                    &authority,
                    AcquirePaths {
                        action_id: ActionId::parse("acquire-2").expect("action"),
                        lease_id: lease.clone(),
                        attempt_id: attempt.clone(),
                        base_revision: self.base.clone(),
                        expected_revision: Revision::default(),
                        paths: vec![self.leased_path.clone()],
                    },
                )
                .expect("foreign lease");
            let epoch = acquired.receipt().epoch;
            let verified = store
                .verify_active_lease(
                    &authority,
                    &attempt,
                    &lease,
                    epoch,
                    &self.base,
                    vec![self.leased_path.clone()],
                )
                .expect("foreign verified lease");
            let request = WorktreeRequest::new(verified, 1_024).expect("foreign request");
            (store, request)
        }

        fn revoke(&mut self) {
            let authority = self.lease_store.broker_authority();
            self.lease_store
                .transition(
                    &authority,
                    TransitionAttempt {
                        action_id: ActionId::parse("terminal-1").expect("action"),
                        attempt_id: AttemptId::parse("attempt-1").expect("attempt"),
                        base_revision: self.base.clone(),
                        expected_revision: self.lease_revision,
                        target: AttemptState::Cancelled,
                        event_digest: Sha256Digest::new("b".repeat(64)).expect("digest"),
                    },
                )
                .expect("terminal transition");
        }
    }

    #[test]
    fn verified_lease_materializes_only_its_paths_and_replays() {
        let fixture = Fixture::new("leased");
        let request = fixture.request(1_024);
        let allocator = fixture.allocator();
        let receipt = allocator.allocate(&request).expect("allocate");
        assert_eq!(receipt.state(), WorktreeState::Allocated);
        assert_eq!(receipt.materialized_bytes(), 14);
        assert!(fixture.checkout().join("leased/file.txt").is_file());
        assert!(!fixture.checkout().join("outside").exists());
        assert_eq!(
            fs::metadata(fixture.state.join("attempt-1/intent.json"))
                .expect("intent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            allocator
                .allocate(&request)
                .expect("replay")
                .reconciliation(),
            Reconciliation::Replayed
        );
    }

    #[test]
    fn inactive_authority_is_denied_before_allocation() {
        let fixture = Fixture::new("leased");
        let request = fixture.request(1_024);
        drop(fixture);
        assert_eq!(
            request.verify_authority(),
            Err(WorktreeError::LeaseAuthorityInactive)
        );
    }

    #[test]
    fn every_descendant_filter_is_denied_before_filter_execution() {
        let marker_holder = tempfile::tempdir().expect("marker holder");
        let marker = marker_holder.path().join("executed");
        let script = marker_holder.path().join("filter.sh");
        fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
        )
        .expect("filter script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("script mode");
        let fixture = Fixture::with_setup("leased", |repository| {
            fs::write(
                repository.join(".gitattributes"),
                b"leased/nested/** filter=marker\n",
            )
            .expect("attributes");
            git(
                repository,
                &[
                    "config",
                    "filter.marker.smudge",
                    script.to_str().expect("script path"),
                ],
            );
        });
        let request = fixture.request(1_024);
        assert!(matches!(
            fixture.allocator().allocate(&request),
            Err(WorktreeError::UnsupportedTree(_))
        ));
        assert!(!marker.exists());
        assert!(!fixture.checkout().exists());
    }

    #[test]
    fn every_mutation_fault_window_reconciles_without_duplicate_effect() {
        for point in [
            WorktreeFaultPoint::AfterWorktreeAdd,
            WorktreeFaultPoint::AfterSparseSet,
            WorktreeFaultPoint::AfterPopulate,
            WorktreeFaultPoint::AfterReceipt,
        ] {
            let fixture = Fixture::new("leased");
            let request = fixture.request(1_024);
            let allocator = fixture.allocator();
            assert_eq!(
                allocator.allocate_with_fault(&request, Some(point)),
                Err(WorktreeError::InjectedFault(point))
            );
            let recovered = fixture.allocator().allocate(&request).expect("recovered");
            assert_eq!(recovered.state(), WorktreeState::Allocated);
            assert_eq!(
                git_text(&fixture.repository, &["worktree", "list", "--porcelain"])
                    .matches("worktree ")
                    .count(),
                2
            );
        }
    }

    #[test]
    fn request_run_is_the_verified_attempt_and_distinct_authorities_still_cannot_overlap() {
        let fixture = Fixture::new("leased");
        let first = fixture.request(1_024);
        let (_foreign_store, second) = fixture.foreign_request();
        assert_eq!(first.run_id(), "attempt-1");
        assert_eq!(second.run_id(), "attempt-2");
        let allocator = fixture.allocator();
        allocator.allocate(&first).expect("first allocation");
        assert_eq!(
            allocator.allocate(&second),
            Err(WorktreeError::LeaseOverlap)
        );
        allocator.release(&first).expect("first release");
        assert_eq!(
            allocator
                .release(&first)
                .expect("release replay")
                .reconciliation(),
            Reconciliation::Replayed
        );
        assert!(allocator.allocate(&second).is_ok());
    }

    #[test]
    fn revoked_authority_stops_reconciliation_at_every_fault_boundary() {
        for point in [
            WorktreeFaultPoint::AfterWorktreeAdd,
            WorktreeFaultPoint::AfterSparseSet,
            WorktreeFaultPoint::AfterPopulate,
            WorktreeFaultPoint::AfterReceipt,
        ] {
            let mut fixture = Fixture::new("leased");
            let request = fixture.request(1_024);
            let allocator = fixture.allocator();
            assert_eq!(
                allocator.allocate_with_fault(&request, Some(point)),
                Err(WorktreeError::InjectedFault(point))
            );
            let before = git_text(&fixture.repository, &["worktree", "list", "--porcelain"])
                .matches("worktree ")
                .count();
            fixture.revoke();
            assert_eq!(
                fixture.allocator().allocate(&request),
                Err(WorktreeError::LeaseAuthorityInactive)
            );
            assert_eq!(
                git_text(&fixture.repository, &["worktree", "list", "--porcelain"])
                    .matches("worktree ")
                    .count(),
                before
            );
        }
    }

    #[test]
    fn concurrent_same_run_serializes_to_one_effect_and_one_replay() {
        let fixture = Fixture::new("leased");
        let request = Arc::new(fixture.request(1_024));
        let barrier = Arc::new(Barrier::new(2));
        let repository = fixture.repository.clone();
        let state = fixture.state.clone();
        let mut results = Vec::new();
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..2 {
                let request = Arc::clone(&request);
                let barrier = Arc::clone(&barrier);
                let repository = repository.clone();
                let state = state.clone();
                handles.push(scope.spawn(move || {
                    let allocator =
                        WorktreeAllocator::open(&repository, &state).expect("allocator");
                    barrier.wait();
                    allocator.allocate(&request)
                }));
            }
            for handle in handles {
                results.push(handle.join().expect("allocation thread"));
            }
        });
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    result.as_ref().expect("receipt").reconciliation() == Reconciliation::Applied
                })
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    result.as_ref().expect("receipt").reconciliation() == Reconciliation::Replayed
                })
                .count(),
            1
        );
    }

    #[test]
    fn populated_checkout_without_receipt_is_reconciled() {
        let fixture = Fixture::new("leased");
        let request = fixture.request(1_024);
        let allocator = fixture.allocator();
        allocator.allocate(&request).expect("allocation");
        fs::remove_file(fixture.state.join("attempt-1/receipt.json")).expect("remove receipt");
        assert_eq!(
            fixture
                .allocator()
                .allocate(&request)
                .expect("reconcile")
                .reconciliation(),
            Reconciliation::Recovered
        );
    }

    #[test]
    fn budget_dirty_base_tree_symlink_and_dirty_release_fail_closed() {
        let fixture = Fixture::new("leased");
        let tiny = fixture.request(3);
        assert_eq!(
            fixture.allocator().allocate(&tiny),
            Err(WorktreeError::BudgetExceeded)
        );
        assert!(!fixture.state.join("attempt-1").exists());

        let request = fixture.request(1_024);
        let allocator = fixture.allocator();
        allocator.allocate(&request).expect("allocate");
        fs::write(fixture.checkout().join("leased/file.txt"), b"dirty").expect("dirty checkout");
        assert_eq!(
            allocator.release(&request),
            Err(WorktreeError::DirtyWorktree)
        );

        let dirty_fixture = Fixture::new("leased");
        fs::write(dirty_fixture.repository.join("untracked"), b"dirty").expect("dirty base");
        assert_eq!(
            dirty_fixture
                .allocator()
                .allocate(&dirty_fixture.request(1_024)),
            Err(WorktreeError::DirtyBase)
        );

        let symlink_fixture = Fixture::with_setup("leased", |repository| {
            symlink("../outside/hidden.txt", repository.join("leased/link")).expect("tree symlink");
        });
        assert!(matches!(
            symlink_fixture
                .allocator()
                .allocate(&symlink_fixture.request(1_024)),
            Err(WorktreeError::UnsupportedTree(_))
        ));
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

    fn git_text(repository: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("run Git");
        assert!(output.status.success(), "git {arguments:?}");
        String::from_utf8(output.stdout)
            .expect("UTF-8")
            .trim()
            .to_owned()
    }
}
