// SPDX-License-Identifier: Elastic-2.0

//! Domain rules for exclusive repository-path leases.
//!
//! This module deliberately performs no filesystem or Git operations. A workspace
//! broker resolves these canonical path tokens beneath a registered worktree and
//! persists the aggregate and its receipts in one transaction.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_REPO_PATH_BYTES: usize = 4096;
const MAX_LEASE_PATHS: usize = 1024;

/// A canonical, repository-relative POSIX path token.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RepoPath(String);

impl RepoPath {
    /// Parse and validate a repository-relative path.
    pub fn parse(value: impl Into<String>) -> Result<Self, RepoPathError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RepoPathError::Empty);
        }
        if value.len() > MAX_REPO_PATH_BYTES {
            return Err(RepoPathError::TooLong {
                bytes: value.len(),
                maximum: MAX_REPO_PATH_BYTES,
            });
        }
        if value.starts_with('/') {
            return Err(RepoPathError::Absolute);
        }
        if value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
        {
            return Err(RepoPathError::Absolute);
        }
        if value.contains('\\') {
            return Err(RepoPathError::Backslash);
        }
        if let Some((byte, character)) = value
            .char_indices()
            .find(|(_, character)| character.is_control())
        {
            return Err(RepoPathError::ControlCharacter { byte, character });
        }

        for (index, segment) in value.split('/').enumerate() {
            if segment.is_empty() {
                return Err(RepoPathError::EmptySegment { index });
            }
            if segment == "." || segment == ".." {
                return Err(RepoPathError::TraversalSegment { index });
            }
            if segment.eq_ignore_ascii_case(".git") {
                return Err(RepoPathError::ReservedGitSegment { index });
            }
        }
        Ok(Self(value))
    }

    /// Return the canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether two paths name the same path or one is an ancestor of the other.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self == other
            || is_ancestor(self.as_str(), other.as_str())
            || is_ancestor(other.as_str(), self.as_str())
    }
}

fn is_ancestor(ancestor: &str, descendant: &str) -> bool {
    descendant
        .strip_prefix(ancestor)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A lexical path-validation denial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepoPathError {
    Empty,
    TooLong { bytes: usize, maximum: usize },
    Absolute,
    Backslash,
    ControlCharacter { byte: usize, character: char },
    EmptySegment { index: usize },
    TraversalSegment { index: usize },
    ReservedGitSegment { index: usize },
}

impl fmt::Display for RepoPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("repository path is empty"),
            Self::TooLong { bytes, maximum } => {
                write!(
                    formatter,
                    "repository path has {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::Absolute => formatter.write_str("repository path must be relative"),
            Self::Backslash => formatter.write_str("repository path must use POSIX separators"),
            Self::ControlCharacter { byte, character } => write!(
                formatter,
                "repository path contains control character {character:?} at byte {byte}"
            ),
            Self::EmptySegment { index } => {
                write!(formatter, "repository path segment {index} is empty")
            }
            Self::TraversalSegment { index } => write!(
                formatter,
                "repository path segment {index} is a traversal segment"
            ),
            Self::ReservedGitSegment { index } => write!(
                formatter,
                "repository path segment {index} names reserved Git metadata"
            ),
        }
    }
}

impl Error for RepoPathError {}

/// A canonical full SHA-1 object ID used as an immutable Git base revision.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BaseRevision(String);

impl BaseRevision {
    /// Parse exactly 40 hexadecimal digits and normalize them to lower case.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, BaseRevisionError> {
        let value = value.as_ref();
        if value.len() != 40 {
            return Err(BaseRevisionError::WrongLength { bytes: value.len() });
        }
        if let Some((index, byte)) = value
            .bytes()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii_hexdigit())
        {
            return Err(BaseRevisionError::NonHexadecimal { index, byte });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BaseRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BaseRevisionError {
    WrongLength { bytes: usize },
    NonHexadecimal { index: usize, byte: u8 },
}

impl fmt::Display for BaseRevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { bytes } => {
                write!(formatter, "base revision has {bytes} bytes; expected 40")
            }
            Self::NonHexadecimal { index, .. } => {
                write!(
                    formatter,
                    "base revision contains a non-hex digit at byte {index}"
                )
            }
        }
    }
}

impl Error for BaseRevisionError {}

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("A validated ", $kind, " identifier.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_identifier($kind, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

identifier_type!(ActionId, "action");
identifier_type!(AttemptId, "attempt");
identifier_type!(LeaseId, "lease");

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty { kind });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong {
            kind,
            bytes: value.len(),
            maximum: MAX_IDENTIFIER_BYTES,
        });
    }
    if let Some((index, byte)) = value.bytes().enumerate().find(|(index, byte)| {
        if *index == 0 {
            !byte.is_ascii_alphanumeric()
        } else {
            !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b':' | b'-')
        }
    }) {
        return Err(IdentifierError::InvalidByte { kind, index, byte });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty {
        kind: &'static str,
    },
    TooLong {
        kind: &'static str,
        bytes: usize,
        maximum: usize,
    },
    InvalidByte {
        kind: &'static str,
        index: usize,
        byte: u8,
    },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(formatter, "{kind} identifier is empty"),
            Self::TooLong {
                kind,
                bytes,
                maximum,
            } => write!(
                formatter,
                "{kind} identifier has {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidByte { kind, index, .. } => {
                write!(
                    formatter,
                    "{kind} identifier has an invalid byte at {index}"
                )
            }
        }
    }
}

impl Error for IdentifierError {}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FenceEpoch(u64);

impl FenceEpoch {
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireLease {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub paths: Vec<RepoPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseLease {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub epoch: FenceEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub paths: Vec<RepoPath>,
    pub epoch: FenceEpoch,
    pub acquired_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireReceipt {
    pub action_id: ActionId,
    pub revision: Revision,
    pub grant: LeaseGrant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseReceipt {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub epoch: FenceEpoch,
    pub revision: Revision,
}

/// Distinguishes a newly committed mutation from retrieval of its durable receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation<T> {
    Applied(T),
    Replayed(T),
}

impl<T> Mutation<T> {
    #[must_use]
    pub fn receipt(&self) -> &T {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoredAction {
    Acquire {
        request: AcquireLease,
        receipt: AcquireReceipt,
    },
    Release {
        request: ReleaseLease,
        receipt: ReleaseReceipt,
    },
}

/// The typed, fail-closed reasons a lease mutation can be denied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseDenial {
    IdempotencyConflict {
        action_id: ActionId,
    },
    RevisionConflict {
        expected: Revision,
        actual: Revision,
    },
    BaseRevisionMismatch {
        expected: BaseRevision,
        actual: BaseRevision,
    },
    EmptyPathSet,
    TooManyPaths {
        count: usize,
        maximum: usize,
    },
    RequestedPathsOverlap {
        first: RepoPath,
        second: RepoPath,
    },
    LeaseAlreadyActive {
        lease_id: LeaseId,
    },
    PathConflict {
        requested: RepoPath,
        held: RepoPath,
        held_lease_id: LeaseId,
        held_attempt_id: AttemptId,
        held_epoch: FenceEpoch,
    },
    LeaseNotActive {
        lease_id: LeaseId,
    },
    LeaseOwnerMismatch {
        lease_id: LeaseId,
        expected: AttemptId,
        actual: AttemptId,
    },
    Fenced {
        lease_id: LeaseId,
        supplied: FenceEpoch,
        active: FenceEpoch,
    },
    RevisionOverflow,
    EpochOverflow,
}

impl fmt::Display for LeaseDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdempotencyConflict { action_id } => {
                write!(
                    formatter,
                    "action {action_id} was already used for another mutation"
                )
            }
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "lease revision conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::BaseRevisionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "base revision mismatch: expected {expected}, got {actual}"
                )
            }
            Self::EmptyPathSet => formatter.write_str("lease path set is empty"),
            Self::TooManyPaths { count, maximum } => {
                write!(formatter, "lease has {count} paths; maximum is {maximum}")
            }
            Self::RequestedPathsOverlap { first, second } => {
                write!(formatter, "requested paths overlap: {first} and {second}")
            }
            Self::LeaseAlreadyActive { lease_id } => {
                write!(formatter, "lease {lease_id} is already active")
            }
            Self::PathConflict {
                requested,
                held,
                held_lease_id,
                ..
            } => write!(
                formatter,
                "requested path {requested} overlaps {held} held by lease {held_lease_id}"
            ),
            Self::LeaseNotActive { lease_id } => {
                write!(formatter, "lease {lease_id} is not active")
            }
            Self::LeaseOwnerMismatch {
                lease_id,
                expected,
                actual,
            } => write!(
                formatter,
                "lease {lease_id} belongs to {expected}, not {actual}"
            ),
            Self::Fenced {
                lease_id,
                supplied,
                active,
            } => write!(
                formatter,
                "lease {lease_id} epoch {} is fenced by epoch {}",
                supplied.get(),
                active.get()
            ),
            Self::RevisionOverflow => formatter.write_str("lease revision exhausted"),
            Self::EpochOverflow => formatter.write_str("lease fencing epoch exhausted"),
        }
    }
}

impl Error for LeaseDenial {}

/// An exclusive lease aggregate for one immutable source base.
///
/// Callers must persist this aggregate and the returned receipt atomically. Its
/// `&mut self` API is designed to be serialized by the development store actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRegistry {
    base_revision: BaseRevision,
    revision: Revision,
    last_epoch: u64,
    active: BTreeMap<LeaseId, LeaseGrant>,
    actions: BTreeMap<ActionId, StoredAction>,
}

impl LeaseRegistry {
    #[must_use]
    pub fn new(base_revision: BaseRevision) -> Self {
        Self {
            base_revision,
            revision: Revision::default(),
            last_epoch: 0,
            active: BTreeMap::new(),
            actions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn base_revision(&self) -> &BaseRevision {
        &self.base_revision
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn last_epoch(&self) -> u64 {
        self.last_epoch
    }

    pub fn active_grants(&self) -> impl ExactSizeIterator<Item = &LeaseGrant> {
        self.active.values()
    }

    #[must_use]
    pub fn active_grant(&self, lease_id: &LeaseId) -> Option<&LeaseGrant> {
        self.active.get(lease_id)
    }

    pub fn acquire(
        &mut self,
        mut request: AcquireLease,
    ) -> Result<Mutation<AcquireReceipt>, LeaseDenial> {
        request.paths.sort();
        if let Some(stored) = self.actions.get(&request.action_id) {
            return match stored {
                StoredAction::Acquire {
                    request: original,
                    receipt,
                } if original == &request => Ok(Mutation::Replayed(receipt.clone())),
                _ => Err(LeaseDenial::IdempotencyConflict {
                    action_id: request.action_id,
                }),
            };
        }

        validate_path_set(&request.paths)?;
        self.validate_common(request.expected_revision, &request.base_revision)?;
        if self.active.contains_key(&request.lease_id) {
            return Err(LeaseDenial::LeaseAlreadyActive {
                lease_id: request.lease_id,
            });
        }
        for requested in &request.paths {
            for held in self.active.values() {
                if let Some(held_path) = held.paths.iter().find(|path| requested.overlaps(path)) {
                    return Err(LeaseDenial::PathConflict {
                        requested: requested.clone(),
                        held: held_path.clone(),
                        held_lease_id: held.lease_id.clone(),
                        held_attempt_id: held.attempt_id.clone(),
                        held_epoch: held.epoch,
                    });
                }
            }
        }

        let next_revision = next_revision(self.revision)?;
        let next_epoch = self
            .last_epoch
            .checked_add(1)
            .ok_or(LeaseDenial::EpochOverflow)?;
        let grant = LeaseGrant {
            lease_id: request.lease_id.clone(),
            attempt_id: request.attempt_id.clone(),
            base_revision: request.base_revision.clone(),
            paths: request.paths.clone(),
            epoch: FenceEpoch::from_u64(next_epoch),
            acquired_revision: next_revision,
        };
        let receipt = AcquireReceipt {
            action_id: request.action_id.clone(),
            revision: next_revision,
            grant: grant.clone(),
        };

        self.active.insert(grant.lease_id.clone(), grant);
        self.actions.insert(
            request.action_id.clone(),
            StoredAction::Acquire {
                request,
                receipt: receipt.clone(),
            },
        );
        self.revision = next_revision;
        self.last_epoch = next_epoch;
        Ok(Mutation::Applied(receipt))
    }

    pub fn release(
        &mut self,
        request: ReleaseLease,
    ) -> Result<Mutation<ReleaseReceipt>, LeaseDenial> {
        if let Some(stored) = self.actions.get(&request.action_id) {
            return match stored {
                StoredAction::Release {
                    request: original,
                    receipt,
                } if original == &request => Ok(Mutation::Replayed(receipt.clone())),
                _ => Err(LeaseDenial::IdempotencyConflict {
                    action_id: request.action_id,
                }),
            };
        }

        self.validate_common(request.expected_revision, &request.base_revision)?;
        let grant =
            self.active
                .get(&request.lease_id)
                .ok_or_else(|| LeaseDenial::LeaseNotActive {
                    lease_id: request.lease_id.clone(),
                })?;
        if grant.attempt_id != request.attempt_id {
            return Err(LeaseDenial::LeaseOwnerMismatch {
                lease_id: request.lease_id,
                expected: grant.attempt_id.clone(),
                actual: request.attempt_id,
            });
        }
        if grant.epoch != request.epoch {
            return Err(LeaseDenial::Fenced {
                lease_id: request.lease_id,
                supplied: request.epoch,
                active: grant.epoch,
            });
        }

        let next_revision = next_revision(self.revision)?;
        let receipt = ReleaseReceipt {
            action_id: request.action_id.clone(),
            lease_id: request.lease_id.clone(),
            attempt_id: request.attempt_id.clone(),
            epoch: request.epoch,
            revision: next_revision,
        };
        self.active.remove(&request.lease_id);
        self.actions.insert(
            request.action_id.clone(),
            StoredAction::Release {
                request,
                receipt: receipt.clone(),
            },
        );
        self.revision = next_revision;
        Ok(Mutation::Applied(receipt))
    }

    fn validate_common(
        &self,
        expected_revision: Revision,
        base_revision: &BaseRevision,
    ) -> Result<(), LeaseDenial> {
        if expected_revision != self.revision {
            return Err(LeaseDenial::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        if base_revision != &self.base_revision {
            return Err(LeaseDenial::BaseRevisionMismatch {
                expected: self.base_revision.clone(),
                actual: base_revision.clone(),
            });
        }
        Ok(())
    }
}

fn validate_path_set(paths: &[RepoPath]) -> Result<(), LeaseDenial> {
    if paths.is_empty() {
        return Err(LeaseDenial::EmptyPathSet);
    }
    if paths.len() > MAX_LEASE_PATHS {
        return Err(LeaseDenial::TooManyPaths {
            count: paths.len(),
            maximum: MAX_LEASE_PATHS,
        });
    }
    for (index, first) in paths.iter().enumerate() {
        if let Some(second) = paths[index + 1..]
            .iter()
            .find(|second| first.overlaps(second))
        {
            return Err(LeaseDenial::RequestedPathsOverlap {
                first: first.clone(),
                second: second.clone(),
            });
        }
    }
    Ok(())
}

fn next_revision(revision: Revision) -> Result<Revision, LeaseDenial> {
    revision
        .get()
        .checked_add(1)
        .map(Revision::from_u64)
        .ok_or(LeaseDenial::RevisionOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BaseRevision {
        BaseRevision::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    #[test]
    fn revision_overflow_is_fail_closed() {
        let mut registry = LeaseRegistry::new(base());
        registry.revision = Revision::from_u64(u64::MAX);
        let before = registry.clone();
        let denial = registry.acquire(AcquireLease {
            action_id: ActionId::parse("action").unwrap(),
            lease_id: LeaseId::parse("lease").unwrap(),
            attempt_id: AttemptId::parse("attempt").unwrap(),
            base_revision: base(),
            expected_revision: Revision::from_u64(u64::MAX),
            paths: vec![RepoPath::parse("src/lib.rs").unwrap()],
        });
        assert_eq!(denial, Err(LeaseDenial::RevisionOverflow));
        assert_eq!(registry, before);
    }

    #[test]
    fn epoch_overflow_is_fail_closed() {
        let mut registry = LeaseRegistry::new(base());
        registry.last_epoch = u64::MAX;
        let before = registry.clone();
        let denial = registry.acquire(AcquireLease {
            action_id: ActionId::parse("action").unwrap(),
            lease_id: LeaseId::parse("lease").unwrap(),
            attempt_id: AttemptId::parse("attempt").unwrap(),
            base_revision: base(),
            expected_revision: Revision::default(),
            paths: vec![RepoPath::parse("src/lib.rs").unwrap()],
        });
        assert_eq!(denial, Err(LeaseDenial::EpochOverflow));
        assert_eq!(registry, before);
    }

    #[test]
    fn release_revision_overflow_is_fail_closed() {
        let mut registry = LeaseRegistry::new(base());
        let acquired = registry
            .acquire(AcquireLease {
                action_id: ActionId::parse("acquire").unwrap(),
                lease_id: LeaseId::parse("lease").unwrap(),
                attempt_id: AttemptId::parse("attempt").unwrap(),
                base_revision: base(),
                expected_revision: Revision::default(),
                paths: vec![RepoPath::parse("src/lib.rs").unwrap()],
            })
            .unwrap()
            .receipt()
            .clone();
        registry.revision = Revision::from_u64(u64::MAX);
        let before = registry.clone();
        let denial = registry.release(ReleaseLease {
            action_id: ActionId::parse("release").unwrap(),
            lease_id: LeaseId::parse("lease").unwrap(),
            attempt_id: AttemptId::parse("attempt").unwrap(),
            base_revision: base(),
            expected_revision: Revision::from_u64(u64::MAX),
            epoch: acquired.grant.epoch,
        });
        assert_eq!(denial, Err(LeaseDenial::RevisionOverflow));
        assert_eq!(registry, before);
    }
}
