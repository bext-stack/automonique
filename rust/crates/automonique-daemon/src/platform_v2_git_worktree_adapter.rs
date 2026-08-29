// SPDX-License-Identifier: Elastic-2.0

//! Exact, least-privilege local git staging boundary.
//!
//! This is the sibling of [`crate::platform_v2_github_pull_request_adapter`]
//! and it keeps that adapter's shape deliberately: a caller persists a
//! [`GitStagingSubmission`] after `begin_custody` and before `submit`, any
//! failure after that point is ambiguous, and `submit` refuses every state
//! except `CustodyStarted`, so an ambiguous write is never replayed blindly.
//!
//! What differs is what a "provider" is. The pull-request adapter talks to a
//! service that answers questions about itself; this one writes to a
//! filesystem the daemon owns. That is not the safer of the two:
//!
//! * **The substrate is shared.** Any other process running as the daemon uid
//!   — the agent working in the checkout, a scheduled job, a second review
//!   action — can move `HEAD` and rewrite the index while a control is
//!   advertised. So the observation this adapter produces names both, and
//!   they are what the caller's confirmation digest commits to. This is the
//!   field set PR #221 recorded as missing, and deriving it is what makes a
//!   staging digest a fence rather than a decoration.
//! * **There is no request to malform, only a command line.** So a path here
//!   is a [`RepositoryFile`], whose grammar admits no absolute path, no `..`,
//!   no `.git` component, and none of the characters git reads as pathspec
//!   magic; and it is rendered as `:(literal,top)<path>` after a `--`, so it
//!   can name exactly one file in exactly one worktree and cannot become a
//!   glob, an option, or a second path.
//! * **Reverting is not always possible.** Staging and unstaging move index
//!   entries and leave every byte on disk alone. A commit writes an object and
//!   moves a ref, and is the only one of the four whose effect is visible
//!   outside the checkout. Resolving a conflict overwrites a file in the
//!   working tree. Those are three powers, so the capability carries three
//!   independently withheld grants rather than one.
//!
//! What a conflict resolution may write is stated once and enforced twice: it
//! is exactly the blob git itself already recorded as stage 2 (`ours`) or
//! stage 3 (`theirs`) for that one path. `git checkout-index --stage=<n>` puts
//! those bytes in the working tree, and the index entry is then set with
//! `git update-index --cacheinfo` to the *observed* object id rather than to
//! whatever is on disk at that instant. No caller-supplied content exists
//! anywhere in this module, so none can be written.
//!
//! There is no `gh`, no shell, no ambient repository lookup, no ref a caller
//! can name, no push, and no generic execute fallback. Every command is built
//! by [`crate::platform_v2_lifecycle_adapter::safe_git_command`], which
//! disables system and global configuration, refuses `include`/`includeIf`,
//! points hooks at `/dev/null`, and neutralises configured filters.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_protocol::digest::Sha256;
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{ProjectId, WorkContextIdentity};
use automonique_protocol::platform_v2_review::{
    ConflictResolution, ReviewAuthority, ReviewAuthorityKind, ReviewProposalId, ReviewProposalKind,
};
use automonique_protocol::primitives::Revision;

use crate::platform_v2_lifecycle_adapter::{BoundedOutput, bounded_output, safe_git_command};

/// Longest repository-relative path this adapter will carry.
///
/// The review contract bounds its display path already; this is the second
/// ceiling, so a protocol change cannot widen what reaches a command line
/// without this file changing too.
pub const MAX_REPOSITORY_PATH_BYTES: usize = 1024;

/// Longest commit subject this adapter will carry.
pub const MAX_COMMIT_SUBJECT_BYTES: usize = 256;

/// Most paths one observation may name.
///
/// Matches the review contract's per-proposal file ceiling. A proposal larger
/// than this cannot be observed rather than being silently truncated.
pub const MAX_OBSERVED_FILES: usize = 128;

/// Most index entries that may differ from `HEAD` for a commit to be planned.
///
/// A commit writes the whole index, so the whole index-versus-`HEAD` change
/// set has to be observed and fenced. Beyond this the repository holds more
/// staged work than any review projection can describe, and the honest answer
/// is that nothing can be advertised for it.
pub const MAX_STAGED_PATHS: usize = 512;

/// Stable, content-free failures safe for receipts and logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitWorktreeError {
    InvalidPlan,
    CapabilityMismatch,
    /// The plan is a commit and this capability was not built with the commit
    /// grant. Distinct from [`Self::CapabilityMismatch`] so a withheld commit
    /// is observable as a withheld commit rather than as a mismatched target.
    CommitWithheld,
    /// The plan resolves a conflict and this capability was not built with
    /// that grant, which is withheld separately again because it is the only
    /// one that overwrites working-tree bytes.
    ConflictResolutionWithheld,
    /// The repository could not be read, or is not the one the capability is
    /// bound to.
    RepositoryUnavailable,
    /// The repository is configured in a way this adapter will not execute
    /// against: an `include` directive, or a filter it cannot neutralise.
    RepositoryUnsafe,
    /// `HEAD`, the index, the sequencer state, or an observed file is not what
    /// the plan pinned. Nothing was written.
    WorktreeChanged,
    /// Git itself refused the write.
    WriteRefused,
    SubmissionState,
}

/// Which of the independently withheld local writes a plan is.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GitStagingFamily {
    Stage,
    Unstage,
    Commit,
    ResolveConflict,
}

impl GitStagingFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Unstage => "unstage",
            Self::Commit => "commit",
            Self::ResolveConflict => "resolve_conflict",
        }
    }

    /// The review proposal kind this family performs.
    #[must_use]
    pub const fn from_proposal(kind: ReviewProposalKind) -> Self {
        match kind {
            ReviewProposalKind::Stage => Self::Stage,
            ReviewProposalKind::Unstage => Self::Unstage,
            ReviewProposalKind::Commit => Self::Commit,
            ReviewProposalKind::ResolveConflict => Self::ResolveConflict,
        }
    }
}

/// Which side of a conflict git already recorded for a path.
///
/// The two variants are the only two things a resolution can write, and they
/// name index stages rather than content: `Ours` is stage 2, `Theirs` is
/// stage 3. There is deliberately no third variant carrying bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictSide {
    Ours,
    Theirs,
}

impl ConflictSide {
    #[must_use]
    pub const fn from_resolution(value: ConflictResolution) -> Self {
        match value {
            ConflictResolution::KeepCurrent => Self::Ours,
            ConflictResolution::KeepIncoming => Self::Theirs,
        }
    }

    /// The index stage number this side is recorded at.
    #[must_use]
    pub const fn stage(self) -> u8 {
        match self {
            Self::Ours => 2,
            Self::Theirs => 3,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ours => "ours",
            Self::Theirs => "theirs",
        }
    }
}

/// A path that cannot escape the repository root and cannot mean more than one
/// file.
///
/// The grammar is the fence, not a check upstream of it. It admits no absolute
/// path, no `\`, no NUL or control byte, no empty, `.` or `..` component, no
/// component spelling `.git` in any ASCII case, no leading or trailing space
/// on any component, and none of `*?[]:\` — the characters git reads as
/// pathspec magic or as glob. A value that could name a second file, reach
/// outside the worktree, or rewrite the repository's own metadata therefore
/// cannot be constructed, so no code path can forget to reject one.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepositoryFile(String);

impl RepositoryFile {
    /// Validate one repository-relative path.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::InvalidPlan`] for anything outside the
    /// grammar.
    pub fn new(value: &str) -> Result<Self, GitWorktreeError> {
        if value.is_empty()
            || value.len() > MAX_REPOSITORY_PATH_BYTES
            || value.starts_with('/')
            || value.starts_with('-')
            || value.contains('\\')
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
            || value
                .bytes()
                .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b':'))
        {
            return Err(GitWorktreeError::InvalidPlan);
        }
        for component in value.split('/') {
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.eq_ignore_ascii_case(".git")
                || component != component.trim()
            {
                return Err(GitWorktreeError::InvalidPlan);
            }
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The exact single-file pathspec this path renders as.
    ///
    /// `literal` turns off every pathspec magic git would otherwise apply, and
    /// `top` roots the match at the top of the working tree. Together with the
    /// `--` every caller places before it, one of these can only ever name the
    /// one file it spells.
    #[must_use]
    pub fn pathspec(&self) -> String {
        format!(":(literal,top){}", self.0)
    }
}

/// One git object id, in either width git uses.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId(String);

impl ObjectId {
    /// Validate one object id.
    ///
    /// Lowercase hexadecimal only, at one of git's two widths. A ref name, an
    /// abbreviation, or a revision expression is not an observation of an
    /// object and cannot be spelled here, so a fence built from one of these
    /// can never be a name that moves.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::RepositoryUnavailable`] for anything else,
    /// because the only way one is constructed is by reading git's output.
    pub fn new(value: &str) -> Result<Self, GitWorktreeError> {
        if !matches!(value.len(), 40 | 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this id is the all-zero placeholder git prints for "absent".
    #[must_use]
    fn is_null(&self) -> bool {
        self.0.bytes().all(|byte| byte == b'0')
    }
}

/// A branch reference, always fully qualified.
///
/// Only `refs/heads/<name>` is admitted. A bare branch name is not a ref, and
/// a ref outside `refs/heads` is not a branch a commit may move, so neither
/// can be observed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchRef(String);

impl BranchRef {
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::RepositoryUnavailable`] for anything that
    /// is not a fully qualified branch reference.
    pub fn new(value: &str) -> Result<Self, GitWorktreeError> {
        let Some(name) = value.strip_prefix("refs/heads/") else {
            return Err(GitWorktreeError::RepositoryUnavailable);
        };
        if name.is_empty()
            || value.len() > 256
            || name.contains("..")
            || name.starts_with('.')
            || name.starts_with('/')
            || name.ends_with('/')
            || name.ends_with('.')
            || name.ends_with(".lock")
            || name.contains("//")
            || name.bytes().any(|byte| {
                byte <= 0x20
                    || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' | 0x7f)
            })
        {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `HEAD` resolved to.
///
/// An unborn `HEAD` is not representable, because there is no commit to fence
/// against and a digest that omitted one would commit to nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHead {
    /// `HEAD` names a branch that exists.
    Attached {
        reference: BranchRef,
        commit: ObjectId,
    },
    /// `HEAD` names a commit directly, as during a rebase or an explicit
    /// checkout of a revision.
    Detached { commit: ObjectId },
}

impl GitHead {
    #[must_use]
    pub const fn commit(&self) -> &ObjectId {
        match self {
            Self::Attached { commit, .. } | Self::Detached { commit } => commit,
        }
    }

    #[must_use]
    pub const fn reference(&self) -> Option<&BranchRef> {
        match self {
            Self::Attached { reference, .. } => Some(reference),
            Self::Detached { .. } => None,
        }
    }
}

/// Which multi-step operation, if any, the repository is in the middle of.
///
/// Every one of these has its own completion semantics that a single fenced
/// commit cannot honour, so a commit is refused while any is in progress.
/// Staging, unstaging and conflict resolution are allowed, because that is
/// exactly when they are needed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SequencerState {
    pub merge: bool,
    pub rebase: bool,
    pub cherry_pick: bool,
    pub revert: bool,
    pub bisect: bool,
}

impl SequencerState {
    #[must_use]
    pub const fn in_progress(self) -> bool {
        self.merge || self.rebase || self.cherry_pick || self.revert || self.bisect
    }
}

/// The stat identity of one working-tree entry.
///
/// This is the identity git's own index uses to decide whether a file has
/// changed, which is why it is what the fence carries: it is exactly as
/// precise as git's own freshness test and costs one `lstat`. Its one
/// residual is git's: a rewrite that preserves size, inode and both
/// timestamps to the nanosecond is not distinguished. The post-write
/// verification in `submit` is what catches the rest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileStamp {
    fn read(path: &Path) -> Option<Self> {
        // `symlink_metadata`, never `metadata`: a tracked symlink is an entry
        // in its own right, and following one would stamp something outside
        // the worktree.
        let metadata = fs::symlink_metadata(path).ok()?;
        Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

/// The two sides git recorded for one unmerged path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictStages {
    ours: Option<(u32, ObjectId)>,
    theirs: Option<(u32, ObjectId)>,
}

impl ConflictStages {
    /// The mode and object of one side, absent when git recorded none — a
    /// delete/modify conflict has only one side, and there is nothing to write
    /// for the other.
    #[must_use]
    pub fn side(&self, side: ConflictSide) -> Option<&(u32, ObjectId)> {
        match side {
            ConflictSide::Ours => self.ours.as_ref(),
            ConflictSide::Theirs => self.theirs.as_ref(),
        }
    }
}

/// What one file looked like in `HEAD`, in the index, and on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitFileObservation {
    path: RepositoryFile,
    head_object: Option<ObjectId>,
    index_object: Option<ObjectId>,
    conflict: Option<ConflictStages>,
    worktree: Option<FileStamp>,
    staged: bool,
    unstaged: bool,
    untracked: bool,
}

impl GitFileObservation {
    #[must_use]
    pub const fn path(&self) -> &RepositoryFile {
        &self.path
    }
    #[must_use]
    pub const fn conflict(&self) -> Option<&ConflictStages> {
        self.conflict.as_ref()
    }
    /// Whether the index entry differs from `HEAD`.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.staged
    }
    /// Whether the working tree differs from the index.
    #[must_use]
    pub const fn unstaged(&self) -> bool {
        self.unstaged
    }
    #[must_use]
    pub const fn untracked(&self) -> bool {
        self.untracked
    }
}

/// One mutation-free read of the whole repository.
///
/// Taken once and then observed against many times, so a capability request
/// covering every proposal in a snapshot costs a fixed number of processes
/// rather than one per proposal — and, more importantly, so every capability
/// it mints names the same `HEAD` and the same index by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeState {
    head: GitHead,
    index_digest: [u8; 32],
    sequencer: SequencerState,
    files: BTreeMap<RepositoryFile, GitFileObservation>,
    staged_paths: BTreeSet<String>,
    identity_configured: bool,
}

impl GitWorktreeState {
    #[must_use]
    pub const fn head(&self) -> &GitHead {
        &self.head
    }
    /// A digest over the whole index, expressed relative to `HEAD`.
    ///
    /// Built from `HEAD` plus the exact bytes of `git diff-index --cached`,
    /// which together determine every index entry: an entry that matches
    /// `HEAD` contributes nothing and every entry that does not is listed with
    /// its mode and object. Any index mutation changes it, and — unlike a
    /// digest of the index *file* — an opportunistic stat refresh by some
    /// other process does not.
    #[must_use]
    pub const fn index_digest(&self) -> [u8; 32] {
        self.index_digest
    }
    #[must_use]
    pub const fn sequencer(&self) -> SequencerState {
        self.sequencer
    }
    #[must_use]
    pub fn file(&self, path: &RepositoryFile) -> Option<&GitFileObservation> {
        self.files.get(path)
    }
    /// Every path whose index entry differs from `HEAD`, over the whole index.
    pub fn staged_paths(&self) -> impl Iterator<Item = &str> {
        self.staged_paths.iter().map(String::as_str)
    }
    /// Whether the repository's own configuration names a committer.
    ///
    /// System and global configuration are disabled for every command this
    /// module issues, so the only identity a commit can carry is one the
    /// operator put in the repository. When there is none, no commit is
    /// advertised: inventing an author would attribute a commit to somebody
    /// who did not choose to be named.
    #[must_use]
    pub const fn identity_configured(&self) -> bool {
        self.identity_configured
    }
}

/// What one mutation-free read proved about one proposal.
///
/// This is the whole of what a staging slot may be minted from. A registry
/// binding and an installed grant prove none of it, which is why nothing here
/// can be constructed without reading the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitWorktreeObservation {
    family: GitStagingFamily,
    head: GitHead,
    index_digest: [u8; 32],
    files: Vec<GitFileObservation>,
    /// Present exactly for a conflict resolution.
    side: Option<ConflictSide>,
    /// The mode and object a conflict resolution would write, taken from the
    /// index stage git recorded. Present exactly for a conflict resolution.
    resolved: Option<(u32, ObjectId)>,
    /// The whole index-versus-`HEAD` change set, present exactly for a commit,
    /// which writes all of it.
    staged_paths: Vec<String>,
}

impl GitWorktreeObservation {
    #[must_use]
    pub const fn family(&self) -> GitStagingFamily {
        self.family
    }
    #[must_use]
    pub const fn head(&self) -> &GitHead {
        &self.head
    }
    #[must_use]
    pub const fn index_digest(&self) -> [u8; 32] {
        self.index_digest
    }
    #[must_use]
    pub fn files(&self) -> &[GitFileObservation] {
        &self.files
    }
    #[must_use]
    pub const fn side(&self) -> Option<ConflictSide> {
        self.side
    }

    /// The commitment this observation makes, as bytes.
    ///
    /// Everything mutable the write depends on is in here: the commit `HEAD`
    /// resolved to, the branch it is attached to if any, the whole index, and
    /// each named file's `HEAD` object, index object, recorded conflict stages
    /// and working-tree stat identity. A caller folds this into its own
    /// confirmation digest, so a worktree that moves after advertisement
    /// produces a different digest and the client's confirmation stops
    /// matching.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut document = Vec::new();
        push_field(&mut document, b"automonique.git-worktree-observation/v1");
        push_field(&mut document, self.family.as_str().as_bytes());
        push_field(&mut document, self.head.commit().as_str().as_bytes());
        push_field(
            &mut document,
            self.head
                .reference()
                .map_or("", BranchRef::as_str)
                .as_bytes(),
        );
        push_field(&mut document, &self.index_digest);
        push_field(
            &mut document,
            self.side.map_or("", ConflictSide::as_str).as_bytes(),
        );
        match &self.resolved {
            Some((mode, object)) => {
                push_field(&mut document, &mode.to_be_bytes());
                push_field(&mut document, object.as_str().as_bytes());
            }
            None => {
                push_field(&mut document, &[]);
                push_field(&mut document, &[]);
            }
        }
        push_field(&mut document, &(self.files.len() as u64).to_be_bytes());
        for file in &self.files {
            push_field(&mut document, file.path.as_str().as_bytes());
            push_object(&mut document, file.head_object.as_ref());
            push_object(&mut document, file.index_object.as_ref());
            match &file.conflict {
                Some(stages) => {
                    push_stage(&mut document, stages.ours.as_ref());
                    push_stage(&mut document, stages.theirs.as_ref());
                }
                None => {
                    push_field(&mut document, &[]);
                    push_field(&mut document, &[]);
                }
            }
            match &file.worktree {
                Some(stamp) => {
                    let mut bytes = Vec::with_capacity(60);
                    bytes.extend_from_slice(&stamp.device.to_be_bytes());
                    bytes.extend_from_slice(&stamp.inode.to_be_bytes());
                    bytes.extend_from_slice(&stamp.size.to_be_bytes());
                    bytes.extend_from_slice(&stamp.mode.to_be_bytes());
                    bytes.extend_from_slice(&stamp.modified_seconds.to_be_bytes());
                    bytes.extend_from_slice(&stamp.modified_nanoseconds.to_be_bytes());
                    bytes.extend_from_slice(&stamp.changed_seconds.to_be_bytes());
                    bytes.extend_from_slice(&stamp.changed_nanoseconds.to_be_bytes());
                    push_field(&mut document, &bytes);
                }
                None => push_field(&mut document, &[]),
            }
            push_field(
                &mut document,
                &[
                    u8::from(file.staged),
                    u8::from(file.unstaged),
                    u8::from(file.untracked),
                ],
            );
        }
        push_field(
            &mut document,
            &(self.staged_paths.len() as u64).to_be_bytes(),
        );
        for path in &self.staged_paths {
            push_field(&mut document, path.as_bytes());
        }
        *Sha256::digest(&document).as_bytes()
    }
}

fn push_field(document: &mut Vec<u8>, field: &[u8]) {
    document.extend_from_slice(&(field.len() as u64).to_be_bytes());
    document.extend_from_slice(field);
}

fn push_object(document: &mut Vec<u8>, object: Option<&ObjectId>) {
    push_field(document, object.map_or("", ObjectId::as_str).as_bytes());
}

fn push_stage(document: &mut Vec<u8>, stage: Option<&(u32, ObjectId)>) {
    match stage {
        Some((mode, object)) => {
            let mut bytes = mode.to_be_bytes().to_vec();
            bytes.extend_from_slice(object.as_str().as_bytes());
            push_field(document, &bytes);
        }
        None => push_field(document, &[]),
    }
}

/// The three independently withheld local writes one binding grants.
///
/// Independent, with no implication between them, because they are three
/// different powers rather than three levels of one:
///
/// * `index_write` covers staging and unstaging. They move index entries and
///   leave every byte on disk alone, and each is the other's inverse on the
///   same surface, so withholding one and allowing the other would fence
///   nothing.
/// * `commit` is separate because it is the only one that writes an object and
///   moves a ref. Its effect is the only one visible outside the checkout — a
///   push, a pull-request head, a CI trigger can all see it — and the only one
///   this surface cannot undo. A deployment that wants an agent to prepare
///   changes from a phone but never record them installs `index_write` alone.
/// * `conflict_resolution` is separate again because it is the only one that
///   overwrites working-tree bytes. It does not imply `index_write` and is not
///   implied by it: what it may write is one path, collapsed to one side git
///   itself recorded, which is a strictly narrower power than staging an
///   arbitrary file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitStagingGrants {
    pub index_write: bool,
    pub commit: bool,
    pub conflict_resolution: bool,
}

impl GitStagingGrants {
    #[must_use]
    pub const fn any(self) -> bool {
        self.index_write || self.commit || self.conflict_resolution
    }

    #[must_use]
    pub const fn allows(self, family: GitStagingFamily) -> bool {
        match family {
            GitStagingFamily::Stage | GitStagingFamily::Unstage => self.index_write,
            GitStagingFamily::Commit => self.commit,
            GitStagingFamily::ResolveConflict => self.conflict_resolution,
        }
    }
}

/// One explicit local-repository capability fixed to one canonical root.
///
/// The root is re-validated here rather than trusted from the registry: a
/// registry is read once at load, and a directory can be replaced afterwards.
/// A capability is therefore proof that *at mint time* the root was an
/// absolute canonical path, owned by the expected uid, not group or other
/// writable, holding a real `.git` that is not a symlink and is owned on the
/// same terms.
pub struct GitWorktreeWriteCapability {
    canonical_root: PathBuf,
    expected_uid: u32,
    grants: GitStagingGrants,
}

impl GitWorktreeWriteCapability {
    /// Construct the fixed-root capability.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::RepositoryUnavailable`] when the root is
    /// not the exact private repository it claims to be, and
    /// [`GitWorktreeError::InvalidPlan`] when no grant was installed at all —
    /// a capability that permits nothing is a configuration mistake, not a
    /// capability.
    pub fn production(
        canonical_root: &Path,
        expected_uid: u32,
        grants: GitStagingGrants,
    ) -> Result<Self, GitWorktreeError> {
        if !grants.any() {
            return Err(GitWorktreeError::InvalidPlan);
        }
        validate_private_repository(canonical_root, expected_uid)?;
        Ok(Self {
            canonical_root: canonical_root.to_path_buf(),
            expected_uid,
            grants,
        })
    }

    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    #[must_use]
    pub const fn grants(&self) -> GitStagingGrants {
        self.grants
    }
}

/// The coordinates one staging plan names, grouped so the constructor cannot
/// acquire a tenth positional value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitStagingTarget {
    pub canonical_root: PathBuf,
    pub family: GitStagingFamily,
    pub proposal_id: ReviewProposalId,
    /// Every file the proposal names, in path order.
    pub files: Vec<RepositoryFile>,
    /// Present exactly for a conflict resolution: the one path it collapses.
    pub conflict_path: Option<RepositoryFile>,
    /// Present exactly for a conflict resolution.
    pub side: Option<ConflictSide>,
    /// Present exactly for a commit. Server-owned: it is the proposal's
    /// subject as the review snapshot carried it, never a client string.
    pub subject: Option<String>,
    /// The digest of the observation this plan was built from.
    pub observation_digest: [u8; 32],
    /// The commit `HEAD` resolved to when that observation was taken.
    pub observed_head: ObjectId,
    /// The index digest from the same observation.
    pub observed_index_digest: [u8; 32],
}

/// The review coordinate one staging plan is bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitStagingReviewBinding {
    pub project: ProjectId,
    pub workspace: WorkContextIdentity,
    pub authority: ReviewAuthority,
    pub idempotency_key: IdempotencyKey,
    pub expected_snapshot_revision: Revision,
}

/// Every authority and repository coordinate captured by the confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitStagingPlan {
    digest: [u8; 32],
    registry_generation_digest: [u8; 32],
    canonical_root: PathBuf,
    family: GitStagingFamily,
    proposal_id: ReviewProposalId,
    files: Vec<RepositoryFile>,
    conflict_path: Option<RepositoryFile>,
    side: Option<ConflictSide>,
    subject: Option<String>,
    observation_digest: [u8; 32],
    observed_head: ObjectId,
    observed_index_digest: [u8; 32],
    tenant: String,
    actor: String,
    project: ProjectId,
    workspace: WorkContextIdentity,
    authority: ReviewAuthority,
    idempotency_key: IdempotencyKey,
    expected_snapshot_revision: Revision,
}

impl GitStagingPlan {
    /// Bind a user-confirmed review action to one exact observed worktree.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::InvalidPlan`] when the shape does not match
    /// the family: only a commit carries a subject, only a conflict resolution
    /// carries a side and a path, and a conflict resolution's path must be one
    /// of the proposal's own files.
    pub fn new(
        registry_generation_digest: [u8; 32],
        provider: GitStagingTarget,
        actor: &Actor,
        review: GitStagingReviewBinding,
    ) -> Result<Self, GitWorktreeError> {
        let family_shape = match provider.family {
            GitStagingFamily::Stage | GitStagingFamily::Unstage => {
                provider.subject.is_none()
                    && provider.side.is_none()
                    && provider.conflict_path.is_none()
            }
            GitStagingFamily::Commit => {
                provider.subject.is_some()
                    && provider.side.is_none()
                    && provider.conflict_path.is_none()
            }
            GitStagingFamily::ResolveConflict => {
                provider.subject.is_none()
                    && provider.side.is_some()
                    && provider
                        .conflict_path
                        .as_ref()
                        .is_some_and(|path| provider.files.contains(path))
            }
        };
        let ordered = provider.files.windows(2).all(|pair| pair[0] < pair[1]);
        if !family_shape
            || provider.files.is_empty()
            || provider.files.len() > MAX_OBSERVED_FILES
            || !ordered
            || !provider.canonical_root.is_absolute()
            || review.authority.kind() != ReviewAuthorityKind::Git
            || provider
                .subject
                .as_deref()
                .is_some_and(|subject| !valid_subject(subject))
            || revision_successor(review.expected_snapshot_revision).is_none()
        {
            return Err(GitWorktreeError::InvalidPlan);
        }
        let mut plan = Self {
            digest: [0; 32],
            registry_generation_digest,
            canonical_root: provider.canonical_root,
            family: provider.family,
            proposal_id: provider.proposal_id,
            files: provider.files,
            conflict_path: provider.conflict_path,
            side: provider.side,
            subject: provider.subject,
            observation_digest: provider.observation_digest,
            observed_head: provider.observed_head,
            observed_index_digest: provider.observed_index_digest,
            tenant: actor.tenant().to_owned(),
            actor: actor.id().to_owned(),
            project: review.project,
            workspace: review.workspace,
            authority: review.authority,
            idempotency_key: review.idempotency_key,
            expected_snapshot_revision: review.expected_snapshot_revision,
        };
        plan.digest = plan_digest(&plan);
        Ok(plan)
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn registry_generation_digest(&self) -> [u8; 32] {
        self.registry_generation_digest
    }
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }
    #[must_use]
    pub const fn family(&self) -> GitStagingFamily {
        self.family
    }
    #[must_use]
    pub const fn proposal_id(&self) -> &ReviewProposalId {
        &self.proposal_id
    }
    #[must_use]
    pub fn files(&self) -> &[RepositoryFile] {
        &self.files
    }
    #[must_use]
    pub const fn side(&self) -> Option<ConflictSide> {
        self.side
    }
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
    #[must_use]
    pub const fn observation_digest(&self) -> [u8; 32] {
        self.observation_digest
    }
    #[must_use]
    pub const fn observed_head(&self) -> &ObjectId {
        &self.observed_head
    }
    #[must_use]
    pub const fn observed_index_digest(&self) -> [u8; 32] {
        self.observed_index_digest
    }
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    #[must_use]
    pub const fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub const fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn expected_snapshot_revision(&self) -> Revision {
        self.expected_snapshot_revision
    }
}

fn revision_successor(value: Revision) -> Option<Revision> {
    value
        .get()
        .checked_add(1)
        .and_then(|next| Revision::new(next).ok())
}

/// Durable custody state for a single plan digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitStagingCustody {
    NotStarted,
    CustodyStarted,
    Accepted,
    Ambiguous,
    Refused,
    Completed,
}

/// The minimal durable record a store must persist before the write.
///
/// `resulting_head` is this family's analogue of the pull-request adapter's
/// provider-issued number: a commit creates an identity that did not exist
/// before the write, and a later read cannot tell our commit from somebody
/// else's without it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitStagingSubmission {
    plan_digest: [u8; 32],
    custody: GitStagingCustody,
    resulting_head: Option<ObjectId>,
}

impl GitStagingSubmission {
    #[must_use]
    pub fn new(plan: &GitStagingPlan) -> Self {
        Self {
            plan_digest: plan.digest(),
            custody: GitStagingCustody::NotStarted,
            resulting_head: None,
        }
    }

    /// Rehydrate the exact durable state after a process restart.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::SubmissionState`] when the row is not this
    /// plan's, or when a recorded head is incoherent with the family and
    /// custody it is stored against.
    pub fn restore(
        plan: &GitStagingPlan,
        plan_digest: [u8; 32],
        custody: GitStagingCustody,
        resulting_head: Option<ObjectId>,
    ) -> Result<Self, GitWorktreeError> {
        if plan.digest() != plan_digest {
            return Err(GitWorktreeError::SubmissionState);
        }
        let coherent = match (plan.family, custody) {
            // Only a commit ever produces a new head.
            (
                GitStagingFamily::Stage
                | GitStagingFamily::Unstage
                | GitStagingFamily::ResolveConflict,
                _,
            ) => resulting_head.is_none(),
            // The head arrives with the commit itself, so it cannot exist
            // before the write was attempted.
            (
                GitStagingFamily::Commit,
                GitStagingCustody::NotStarted | GitStagingCustody::CustodyStarted,
            ) => resulting_head.is_none(),
            (
                GitStagingFamily::Commit,
                GitStagingCustody::Accepted | GitStagingCustody::Completed,
            ) => resulting_head.is_some(),
            // A write this process never saw acknowledged has no head, and one
            // that was acknowledged and later downgraded keeps the head it
            // earned.
            (
                GitStagingFamily::Commit,
                GitStagingCustody::Ambiguous | GitStagingCustody::Refused,
            ) => true,
        };
        if !coherent {
            return Err(GitWorktreeError::SubmissionState);
        }
        Ok(Self {
            plan_digest,
            custody,
            resulting_head,
        })
    }

    /// Transition to the state that must be durably committed before `submit`.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::SubmissionState`] unless custody has not
    /// started.
    pub fn begin_custody(&mut self) -> Result<(), GitWorktreeError> {
        if self.custody != GitStagingCustody::NotStarted {
            return Err(GitWorktreeError::SubmissionState);
        }
        self.custody = GitStagingCustody::CustodyStarted;
        Ok(())
    }

    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
    #[must_use]
    pub const fn custody(&self) -> GitStagingCustody {
        self.custody
    }
    /// The commit an accepted commit produced.
    #[must_use]
    pub const fn resulting_head(&self) -> Option<&ObjectId> {
        self.resulting_head.as_ref()
    }
}

/// Production adapter. It exposes only reads, preflight, one-shot submit, and
/// reconciliation.
pub struct GitWorktreeAdapter {
    capability: GitWorktreeWriteCapability,
}

impl GitWorktreeAdapter {
    #[must_use]
    pub const fn new(capability: GitWorktreeWriteCapability) -> Self {
        Self { capability }
    }

    #[must_use]
    pub const fn capability(&self) -> &GitWorktreeWriteCapability {
        &self.capability
    }

    /// Read the live repository baseline every capability is minted from.
    ///
    /// Deliberately mutation-free, and deliberately taken once for all the
    /// paths a caller cares about. `--no-optional-locks` keeps these reads from
    /// refreshing the index themselves, so observing a repository never
    /// invalidates the observation that is being taken.
    ///
    /// What it proves:
    ///
    /// * the working tree at the capability's canonical root is the top of a
    ///   repository, and the same one the capability is bound to;
    /// * `HEAD` resolves to a commit — an unborn `HEAD` has nothing to fence
    ///   against, so it is refused rather than represented;
    /// * the exact index, digested relative to that `HEAD`;
    /// * which multi-step operation, if any, is in progress;
    /// * for each named path, its object in `HEAD`, its object in the index,
    ///   the stages of any conflict git recorded, and its working-tree stat
    ///   identity.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::RepositoryUnavailable`] when the repository
    /// cannot be read or is not the bound one, and
    /// [`GitWorktreeError::RepositoryUnsafe`] when its configuration is one
    /// this adapter will not execute against.
    pub fn read(&self, paths: &[RepositoryFile]) -> Result<GitWorktreeState, GitWorktreeError> {
        if paths.len() > MAX_OBSERVED_FILES {
            return Err(GitWorktreeError::InvalidPlan);
        }
        validate_private_repository(
            &self.capability.canonical_root,
            self.capability.expected_uid,
        )?;
        let toplevel = self.text(&["rev-parse", "--show-toplevel"])?;
        if Path::new(&toplevel) != self.capability.canonical_root {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        let head_commit =
            ObjectId::new(&self.text(&["rev-parse", "--verify", "HEAD^{commit}"])?)?;
        let head = match self.optional_text(&["symbolic-ref", "--quiet", "HEAD"])? {
            Some(reference) => GitHead::Attached {
                reference: BranchRef::new(&reference)?,
                commit: head_commit,
            },
            None => GitHead::Detached {
                commit: head_commit,
            },
        };
        let git_dir = self.git_dir()?;
        let sequencer = SequencerState {
            merge: git_dir.join("MERGE_HEAD").exists(),
            rebase: git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists(),
            cherry_pick: git_dir.join("CHERRY_PICK_HEAD").exists(),
            revert: git_dir.join("REVERT_HEAD").exists(),
            bisect: git_dir.join("BISECT_LOG").exists(),
        };
        let cached = self.raw(&["diff-index", "--cached", "--no-renames", "-z", "HEAD", "--"])?;
        let staged_paths = parse_staged_paths(&cached)?;
        if staged_paths.len() > MAX_STAGED_PATHS {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        let mut index_document = Vec::new();
        push_field(&mut index_document, b"automonique.git-index/v1");
        push_field(&mut index_document, head.commit().as_str().as_bytes());
        push_field(&mut index_document, &cached);
        let index_digest = *Sha256::digest(&index_document).as_bytes();
        let files = self.observe_files(paths)?;
        let identity_configured = self
            .optional_text(&["config", "--local", "--get", "user.email"])?
            .is_some_and(|value| !value.is_empty())
            && self
                .optional_text(&["config", "--local", "--get", "user.name"])?
                .is_some_and(|value| !value.is_empty());
        Ok(GitWorktreeState {
            head,
            index_digest,
            sequencer,
            files,
            staged_paths,
            identity_configured,
        })
    }

    /// Derive one proposal's observation from one repository read.
    ///
    /// Every family's admission rule is here rather than at the call site, so
    /// a control cannot be advertised on a looser test than the write is
    /// admitted under:
    ///
    /// * **Stage** — every named file has working-tree changes the index does
    ///   not hold, or is untracked and not ignored. A file git does not report
    ///   as differing has nothing to stage, and a control for it would refuse.
    /// * **Unstage** — every named file's index entry differs from `HEAD`.
    /// * **Commit** — the repository is in no multi-step operation, `HEAD` is
    ///   attached to a branch, the repository names a committer, and the whole
    ///   index-versus-`HEAD` change set is exactly the proposal's files. That
    ///   last one is the honest reconciliation of a proposal that names files
    ///   with a `git commit` that writes the entire index: if anything else is
    ///   staged, this commit would record changes nobody reviewed, so nothing
    ///   is advertised.
    /// * **ResolveConflict** — the one named path is unmerged and git recorded
    ///   the requested side for it. A delete/modify conflict has only one
    ///   side, and the missing one is simply not advertised.
    ///
    /// # Errors
    ///
    /// Returns the withheld-grant error for a family this capability does not
    /// carry, and [`GitWorktreeError::WorktreeChanged`] when the repository
    /// does not support the family right now.
    pub fn observe(
        &self,
        state: &GitWorktreeState,
        family: GitStagingFamily,
        paths: &[RepositoryFile],
        side: Option<ConflictSide>,
    ) -> Result<GitWorktreeObservation, GitWorktreeError> {
        self.require_grant(family)?;
        if paths.is_empty() || paths.len() > MAX_OBSERVED_FILES {
            return Err(GitWorktreeError::InvalidPlan);
        }
        if (family == GitStagingFamily::ResolveConflict) != side.is_some() {
            return Err(GitWorktreeError::InvalidPlan);
        }
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let file = state
                .file(path)
                .ok_or(GitWorktreeError::WorktreeChanged)?
                .clone();
            files.push(file);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut resolved = None;
        let mut staged_paths = Vec::new();
        match family {
            GitStagingFamily::Stage => {
                if !files
                    .iter()
                    .all(|file| (file.unstaged || file.untracked) && file.conflict.is_none())
                {
                    return Err(GitWorktreeError::WorktreeChanged);
                }
            }
            GitStagingFamily::Unstage => {
                if !files
                    .iter()
                    .all(|file| file.staged && file.conflict.is_none())
                {
                    return Err(GitWorktreeError::WorktreeChanged);
                }
            }
            GitStagingFamily::Commit => {
                if state.sequencer.in_progress()
                    || state.head.reference().is_none()
                    || !state.identity_configured
                    || files.iter().any(|file| file.conflict.is_some())
                {
                    return Err(GitWorktreeError::WorktreeChanged);
                }
                let named = files
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<BTreeSet<_>>();
                let staged = state.staged_paths().collect::<BTreeSet<_>>();
                // A commit writes the index, not a file list. Advertising one
                // whose index holds anything beyond the proposal would record
                // changes nobody reviewed.
                if named != staged || staged.is_empty() {
                    return Err(GitWorktreeError::WorktreeChanged);
                }
                staged_paths = staged.into_iter().map(str::to_owned).collect();
            }
            GitStagingFamily::ResolveConflict => {
                let side = side.ok_or(GitWorktreeError::InvalidPlan)?;
                // Exactly one path is collapsed, and it has to be unmerged with
                // the requested side actually recorded.
                let [file] = files.as_slice() else {
                    return Err(GitWorktreeError::InvalidPlan);
                };
                let stage = file
                    .conflict
                    .as_ref()
                    .and_then(|stages| stages.side(side))
                    .ok_or(GitWorktreeError::WorktreeChanged)?;
                resolved = Some(stage.clone());
            }
        }
        Ok(GitWorktreeObservation {
            family,
            head: state.head.clone(),
            index_digest: state.index_digest,
            files,
            side,
            resolved,
            staged_paths,
        })
    }

    /// Re-read the repository and prove the plan's exact observation still
    /// holds.
    ///
    /// The comparison is on the observation digest, so nothing the plan
    /// committed to can move without this refusing: not `HEAD`, not the
    /// branch it is attached to, not the index, not a named file's object in
    /// `HEAD` or in the index, not a recorded conflict stage, and not a named
    /// file's working-tree stat identity.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::WorktreeChanged`] when anything the plan
    /// pinned has moved.
    pub fn preflight(
        &self,
        plan: &GitStagingPlan,
    ) -> Result<GitWorktreeObservation, GitWorktreeError> {
        self.verify_capability(plan)?;
        let state = self.read(&plan.files)?;
        let observation = self.observe(&state, plan.family, &plan.files, plan.side)?;
        if observation.digest() != plan.observation_digest
            || observation.head.commit() != &plan.observed_head
            || observation.index_digest != plan.observed_index_digest
        {
            return Err(GitWorktreeError::WorktreeChanged);
        }
        Ok(observation)
    }

    /// Perform the only write. The durable state must already say custody
    /// began.
    ///
    /// # Errors
    ///
    /// Returns the preflight's error, with custody left `Refused`, when the
    /// worktree moved before anything was written; and
    /// [`GitWorktreeError::WriteRefused`] with custody `Ambiguous` when git
    /// failed after the write may have started.
    pub fn submit(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        verify_submission(plan, submission)?;
        if submission.custody != GitStagingCustody::CustodyStarted {
            return Err(GitWorktreeError::SubmissionState);
        }
        let observation = match self.preflight(plan) {
            Ok(observation) => observation,
            Err(error) => {
                // Nothing has been written, so a moved worktree is a
                // proved-not-started refusal rather than ambiguity.
                submission.custody = GitStagingCustody::Refused;
                return Err(error);
            }
        };
        match plan.family {
            GitStagingFamily::Stage => self.submit_stage(plan, submission),
            GitStagingFamily::Unstage => self.submit_unstage(plan, submission),
            GitStagingFamily::Commit => self.submit_commit(plan, submission),
            GitStagingFamily::ResolveConflict => {
                self.submit_resolve(plan, &observation, submission)
            }
        }
    }

    fn submit_stage(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        let mut arguments = vec!["add".to_owned(), "--".to_owned()];
        arguments.extend(plan.files.iter().map(RepositoryFile::pathspec));
        self.write(&arguments, submission)?;
        // The write is verified rather than assumed: every named file must now
        // have an index entry that differs from HEAD.
        self.verify_after(plan, submission, |state| {
            plan.files
                .iter()
                .all(|path| state.file(path).is_some_and(GitFileObservation::staged))
        })
    }

    fn submit_unstage(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        // The source tree is the commit the plan observed, spelled as an object
        // id. `HEAD` is not named, so a ref that moved cannot be the one this
        // restores from.
        let mut arguments = vec![
            "restore".to_owned(),
            "--staged".to_owned(),
            format!("--source={}", plan.observed_head.as_str()),
            "--".to_owned(),
        ];
        arguments.extend(plan.files.iter().map(RepositoryFile::pathspec));
        self.write(&arguments, submission)?;
        self.verify_after(plan, submission, |state| {
            plan.files
                .iter()
                .all(|path| state.file(path).is_none_or(|file| !file.staged))
        })
    }

    fn submit_commit(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        let subject = plan
            .subject
            .as_deref()
            .ok_or(GitWorktreeError::InvalidPlan)?;
        if !valid_subject(subject) {
            return Err(GitWorktreeError::InvalidPlan);
        }
        // No signing, no editor, no hooks, no `--all`, and no pathspec:
        // exactly the index this plan fenced is what is recorded, which is why
        // the preflight required the whole index to be the proposal's files.
        // No `--allow-empty` either: an empty commit would mean the index no
        // longer differs from `HEAD`, which the fence has already excluded.
        self.write(
            &[
                "commit".to_owned(),
                "--no-gpg-sign".to_owned(),
                "--no-verify".to_owned(),
                "-m".to_owned(),
                subject.to_owned(),
            ],
            submission,
        )?;
        // The commit's own shape is the evidence that it was ours: the new head
        // must differ from the pinned one and have it as its first parent.
        // Anything else is somebody else's commit on the same branch, and
        // claiming it would forge attribution.
        let head = self
            .text(&["rev-parse", "--verify", "HEAD^{commit}"])
            .and_then(|value| ObjectId::new(&value));
        let parent = self
            .text(&["rev-parse", "--verify", "HEAD^1^{commit}"])
            .and_then(|value| ObjectId::new(&value));
        match (head, parent) {
            (Ok(head), Ok(parent))
                if head != plan.observed_head && parent == plan.observed_head =>
            {
                submission.resulting_head = Some(head);
                submission.custody = GitStagingCustody::Accepted;
                Ok(submission.custody)
            }
            _ => {
                submission.custody = GitStagingCustody::Ambiguous;
                Err(GitWorktreeError::WriteRefused)
            }
        }
    }

    fn submit_resolve(
        &self,
        plan: &GitStagingPlan,
        observation: &GitWorktreeObservation,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        let path = plan
            .conflict_path
            .as_ref()
            .ok_or(GitWorktreeError::InvalidPlan)?;
        let side = plan.side.ok_or(GitWorktreeError::InvalidPlan)?;
        let (mode, object) = observation
            .resolved
            .as_ref()
            .ok_or(GitWorktreeError::InvalidPlan)?;
        // Git writes the working-tree bytes, from the stage it is already
        // holding. This process never opens the file, so it can neither choose
        // the content nor follow a symlink out of the worktree.
        self.write(
            &[
                "checkout-index".to_owned(),
                "--force".to_owned(),
                format!("--stage={}", side.stage()),
                "--".to_owned(),
                path.as_str().to_owned(),
            ],
            submission,
        )?;
        // The index entry is set to the object the preflight observed, not to
        // whatever is on disk now, so a file rewritten between the two commands
        // cannot become what is staged.
        self.write(
            &[
                "update-index".to_owned(),
                "--add".to_owned(),
                "--cacheinfo".to_owned(),
                format!("{mode:06o},{},{}", object.as_str(), path.as_str()),
            ],
            submission,
        )?;
        self.verify_after(plan, submission, |state| {
            state.file(path).is_none_or(|file| file.conflict.is_none())
        })
    }

    /// Reconcile without ever issuing a write.
    ///
    /// The attribution rule is the one the check-rerun and pull-request
    /// adapters established. A later read carries no token proving our write
    /// produced what it sees, so an observation that merely *matches* what our
    /// write would have produced is not proof it was ours. Only a submission
    /// that already reached `Accepted` for this exact plan may complete.
    ///
    /// # Errors
    ///
    /// Returns [`GitWorktreeError::CapabilityMismatch`] when the plan is not
    /// this capability's, and the read's error when the repository cannot be
    /// observed.
    pub fn reconcile(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        self.verify_capability(plan)?;
        verify_submission(plan, submission)?;
        if matches!(
            submission.custody,
            GitStagingCustody::Refused | GitStagingCustody::Completed
        ) {
            return Ok(submission.custody);
        }
        let correlated = submission.custody == GitStagingCustody::Accepted;
        let state = self.read(&plan.files)?;
        let landed = match plan.family {
            GitStagingFamily::Stage => plan
                .files
                .iter()
                .all(|path| state.file(path).is_some_and(GitFileObservation::staged)),
            GitStagingFamily::Unstage => plan
                .files
                .iter()
                .all(|path| state.file(path).is_none_or(|file| !file.staged)),
            GitStagingFamily::Commit => submission
                .resulting_head
                .as_ref()
                .is_some_and(|head| state.head.commit() == head),
            GitStagingFamily::ResolveConflict => plan
                .conflict_path
                .as_ref()
                .is_some_and(|path| state.file(path).is_none_or(|file| file.conflict.is_none())),
        };
        submission.custody = match (landed, correlated, submission.custody) {
            (true, true, _) => GitStagingCustody::Completed,
            // An uncorrelated observation of the effect could be another
            // actor's write into the same shared checkout. Claiming it would
            // forge attribution, so this stays ambiguous rather than
            // resolving to a lie.
            (_, _, GitStagingCustody::NotStarted) => GitStagingCustody::NotStarted,
            (false, true, _) => GitStagingCustody::Accepted,
            _ => GitStagingCustody::Ambiguous,
        };
        Ok(submission.custody)
    }

    fn verify_after(
        &self,
        plan: &GitStagingPlan,
        submission: &mut GitStagingSubmission,
        landed: impl Fn(&GitWorktreeState) -> bool,
    ) -> Result<GitStagingCustody, GitWorktreeError> {
        match self.read(&plan.files) {
            Ok(state) if landed(&state) => {
                submission.custody = GitStagingCustody::Accepted;
                Ok(submission.custody)
            }
            // Git returned success and the repository does not show the effect,
            // or cannot be read at all. Either way this process cannot say the
            // write did not happen, so it stays ambiguous.
            _ => {
                submission.custody = GitStagingCustody::Ambiguous;
                Err(GitWorktreeError::WriteRefused)
            }
        }
    }

    fn verify_capability(&self, plan: &GitStagingPlan) -> Result<(), GitWorktreeError> {
        self.require_grant(plan.family)?;
        if self.capability.canonical_root != plan.canonical_root {
            return Err(GitWorktreeError::CapabilityMismatch);
        }
        Ok(())
    }

    /// The second, independent refusal of a withheld grant.
    ///
    /// The review adapter already refuses a family whose grant a binding does
    /// not carry. This is checked again here so an adapter handed a plan built
    /// from a binding that never granted it does not perform it, whatever the
    /// caller believed.
    fn require_grant(&self, family: GitStagingFamily) -> Result<(), GitWorktreeError> {
        if self.capability.grants.allows(family) {
            return Ok(());
        }
        Err(match family {
            GitStagingFamily::Commit => GitWorktreeError::CommitWithheld,
            GitStagingFamily::ResolveConflict => GitWorktreeError::ConflictResolutionWithheld,
            GitStagingFamily::Stage | GitStagingFamily::Unstage => {
                GitWorktreeError::CapabilityMismatch
            }
        })
    }

    fn observe_files(
        &self,
        paths: &[RepositoryFile],
    ) -> Result<BTreeMap<RepositoryFile, GitFileObservation>, GitWorktreeError> {
        let mut files = BTreeMap::new();
        if paths.is_empty() {
            return Ok(files);
        }
        let mut arguments = vec![
            "status".to_owned(),
            "--porcelain=v2".to_owned(),
            "-z".to_owned(),
            "--untracked-files=all".to_owned(),
            "--no-renames".to_owned(),
            "--ignore-submodules=all".to_owned(),
            "--".to_owned(),
        ];
        arguments.extend(paths.iter().map(RepositoryFile::pathspec));
        let raw = self.raw(&arguments.iter().map(String::as_str).collect::<Vec<_>>())?;
        let reported = parse_status(&raw)?;
        for path in paths {
            let Some(mut observation) = reported.get(path.as_str()).cloned() else {
                continue;
            };
            observation.path = path.clone();
            observation.worktree =
                FileStamp::read(&self.capability.canonical_root.join(path.as_str()));
            files.insert(path.clone(), observation);
        }
        Ok(files)
    }

    fn git_dir(&self) -> Result<PathBuf, GitWorktreeError> {
        let value = self.text(&["rev-parse", "--absolute-git-dir"])?;
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        Ok(path)
    }

    fn command(&self, arguments: &[&str]) -> Result<Command, GitWorktreeError> {
        let mut command = safe_git_command(&self.capability.canonical_root).map_err(|error| {
            if matches!(
                error,
                "platform_v2_lifecycle_git_include_unsafe" | "platform_v2_lifecycle_filter_unsafe"
            ) {
                GitWorktreeError::RepositoryUnsafe
            } else {
                GitWorktreeError::RepositoryUnavailable
            }
        })?;
        command.arg("--no-optional-locks");
        command.args(arguments);
        Ok(command)
    }

    fn raw(&self, arguments: &[&str]) -> Result<Vec<u8>, GitWorktreeError> {
        let output = self.run(arguments)?;
        if !output.status.success() {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        Ok(output.stdout)
    }

    fn run(&self, arguments: &[&str]) -> Result<BoundedOutput, GitWorktreeError> {
        let mut command = self.command(arguments)?;
        bounded_output(&mut command).map_err(|_| GitWorktreeError::RepositoryUnavailable)
    }

    fn text(&self, arguments: &[&str]) -> Result<String, GitWorktreeError> {
        let output = self.run(arguments)?;
        if !output.status.success() {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        decode_line(&output.stdout).ok_or(GitWorktreeError::RepositoryUnavailable)
    }

    /// Run a command whose non-zero exit means "absent" rather than "failed".
    fn optional_text(&self, arguments: &[&str]) -> Result<Option<String>, GitWorktreeError> {
        let output = self.run(arguments)?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(decode_line(&output.stdout))
    }

    /// Issue one write, marking custody ambiguous if it fails.
    ///
    /// Every failure after `begin_custody` is ambiguous by construction: this
    /// process cannot tell a command that did nothing from one that did part
    /// of its work and then failed, so it never claims the former.
    fn write(
        &self,
        arguments: &[String],
        submission: &mut GitStagingSubmission,
    ) -> Result<(), GitWorktreeError> {
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        match self.run(&borrowed) {
            Ok(output) if output.status.success() => Ok(()),
            _ => {
                submission.custody = GitStagingCustody::Ambiguous;
                Err(GitWorktreeError::WriteRefused)
            }
        }
    }
}

fn verify_submission(
    plan: &GitStagingPlan,
    submission: &GitStagingSubmission,
) -> Result<(), GitWorktreeError> {
    if submission.plan_digest != plan.digest || plan_digest(plan) != plan.digest {
        return Err(GitWorktreeError::SubmissionState);
    }
    Ok(())
}

fn decode_line(bytes: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?.trim();
    if value.is_empty() || value.len() > MAX_REPOSITORY_PATH_BYTES {
        return None;
    }
    Some(value.to_owned())
}

/// A commit subject this adapter will carry to git.
fn valid_subject(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && value.len() <= MAX_COMMIT_SUBJECT_BYTES
        && !value.chars().any(char::is_control)
        && trimmed == value
}

/// Read `git diff-index --cached -z` into the set of paths whose index entry
/// differs from `HEAD`.
///
/// The record shape is `:<mH> <mI> <hH> <hI> <status>\0<path>\0`.
fn parse_staged_paths(raw: &[u8]) -> Result<BTreeSet<String>, GitWorktreeError> {
    let mut paths = BTreeSet::new();
    let mut records = raw.split(|byte| *byte == 0).filter(|r| !r.is_empty());
    while let Some(header) = records.next() {
        if !header.starts_with(b":") {
            return Err(GitWorktreeError::RepositoryUnavailable);
        }
        let path = records
            .next()
            .ok_or(GitWorktreeError::RepositoryUnavailable)?;
        let path =
            std::str::from_utf8(path).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
        paths.insert(path.to_owned());
    }
    Ok(paths)
}

/// Read `git status --porcelain=v2 -z` into per-path observations.
///
/// Only the three record kinds this adapter asks for are admitted. `--no-renames`
/// keeps the two-path rename record from appearing, and an unrecognised record
/// is a refusal rather than something to skip: a status this process cannot
/// fully parse is not one it may mint a capability from.
fn parse_status(raw: &[u8]) -> Result<BTreeMap<String, GitFileObservation>, GitWorktreeError> {
    let mut files = BTreeMap::new();
    for record in raw.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        let record =
            std::str::from_utf8(record).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
        let (kind, rest) = record
            .split_once(' ')
            .ok_or(GitWorktreeError::RepositoryUnavailable)?;
        match kind {
            "1" => {
                // `<XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>`
                let fields = rest.splitn(7, ' ').collect::<Vec<_>>();
                let [
                    states,
                    _sub,
                    _head_mode,
                    _index_mode,
                    _worktree_mode,
                    head,
                    tail,
                ] = fields.as_slice()
                else {
                    return Err(GitWorktreeError::RepositoryUnavailable);
                };
                let (index, path) = tail
                    .split_once(' ')
                    .ok_or(GitWorktreeError::RepositoryUnavailable)?;
                let mut states = states.chars();
                let staged = states.next().is_some_and(|value| value != '.');
                let unstaged = states.next().is_some_and(|value| value != '.');
                let head_object = ObjectId::new(head)?;
                let index_object = ObjectId::new(index)?;
                files.insert(
                    path.to_owned(),
                    GitFileObservation {
                        path: RepositoryFile(path.to_owned()),
                        head_object: (!head_object.is_null()).then_some(head_object),
                        index_object: (!index_object.is_null()).then_some(index_object),
                        conflict: None,
                        worktree: None,
                        staged,
                        unstaged,
                        untracked: false,
                    },
                );
            }
            "u" => {
                // `<XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>`
                let fields = rest.splitn(10, ' ').collect::<Vec<_>>();
                let [
                    _states,
                    _sub,
                    _mode1,
                    mode2,
                    mode3,
                    _worktree_mode,
                    _stage1,
                    stage2,
                    stage3,
                    path,
                ] = fields.as_slice()
                else {
                    return Err(GitWorktreeError::RepositoryUnavailable);
                };
                files.insert(
                    (*path).to_owned(),
                    GitFileObservation {
                        path: RepositoryFile((*path).to_owned()),
                        head_object: None,
                        index_object: None,
                        conflict: Some(ConflictStages {
                            ours: parse_stage(mode2, stage2)?,
                            theirs: parse_stage(mode3, stage3)?,
                        }),
                        worktree: None,
                        staged: false,
                        unstaged: false,
                        untracked: false,
                    },
                );
            }
            "?" => {
                files.insert(
                    rest.to_owned(),
                    GitFileObservation {
                        path: RepositoryFile(rest.to_owned()),
                        head_object: None,
                        index_object: None,
                        conflict: None,
                        worktree: None,
                        staged: false,
                        unstaged: false,
                        untracked: true,
                    },
                );
            }
            _ => return Err(GitWorktreeError::RepositoryUnavailable),
        }
    }
    Ok(files)
}

/// One `<mode> <object>` pair from an unmerged status record.
///
/// A zero mode is git saying the side does not exist — a delete/modify
/// conflict — which is an absent side rather than a malformed one.
fn parse_stage(mode: &str, object: &str) -> Result<Option<(u32, ObjectId)>, GitWorktreeError> {
    let mode = u32::from_str_radix(mode, 8).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
    let object = ObjectId::new(object)?;
    if mode == 0 || object.is_null() {
        return Ok(None);
    }
    Ok(Some((mode, object)))
}

fn plan_digest(plan: &GitStagingPlan) -> [u8; 32] {
    let mut document = Vec::new();
    push_field(&mut document, b"automonique.git-staging-plan/v1");
    push_field(&mut document, &plan.registry_generation_digest);
    push_field(
        &mut document,
        plan.canonical_root.as_os_str().as_encoded_bytes(),
    );
    for field in [
        plan.family.as_str().as_bytes(),
        plan.proposal_id.as_str().as_bytes(),
        plan.conflict_path
            .as_ref()
            .map_or("", RepositoryFile::as_str)
            .as_bytes(),
        plan.side.map_or("", ConflictSide::as_str).as_bytes(),
        plan.subject.as_deref().unwrap_or_default().as_bytes(),
        plan.observed_head.as_str().as_bytes(),
        plan.tenant.as_bytes(),
        plan.actor.as_bytes(),
        plan.project.as_str().as_bytes(),
        plan.workspace.kind().as_str().as_bytes(),
        plan.workspace.id().as_bytes(),
        plan.authority.kind().as_str().as_bytes(),
        plan.authority.id().as_str().as_bytes(),
        plan.idempotency_key.as_str().as_bytes(),
    ] {
        push_field(&mut document, field);
    }
    push_field(&mut document, &plan.observation_digest);
    push_field(&mut document, &plan.observed_index_digest);
    push_field(&mut document, &(plan.files.len() as u64).to_be_bytes());
    for file in &plan.files {
        push_field(&mut document, file.as_str().as_bytes());
    }
    push_field(
        &mut document,
        &plan.expected_snapshot_revision.get().to_be_bytes(),
    );
    *Sha256::digest(&document).as_bytes()
}

/// The exact private-repository shape a capability may be minted for.
///
/// Deliberately the same test the review registry applies at load, repeated
/// here because a registry is read once and a directory can be replaced
/// afterwards.
fn validate_private_repository(path: &Path, expected_uid: u32) -> Result<(), GitWorktreeError> {
    if !path.is_absolute() {
        return Err(GitWorktreeError::RepositoryUnavailable);
    }
    let canonical = fs::canonicalize(path).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
    if canonical != path {
        return Err(GitWorktreeError::RepositoryUnavailable);
    }
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(GitWorktreeError::RepositoryUnavailable);
    }
    let git = canonical.join(".git");
    let metadata =
        fs::symlink_metadata(&git).map_err(|_| GitWorktreeError::RepositoryUnavailable)?;
    if metadata.file_type().is_symlink()
        || (!metadata.is_dir() && !metadata.is_file())
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(GitWorktreeError::RepositoryUnavailable);
    }
    Ok(())
}
