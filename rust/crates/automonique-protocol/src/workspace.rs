// SPDX-License-Identifier: Elastic-2.0

//! Workspace registrations, locks and content-addressed artifacts.
//!
//! Two things must be impossible here rather than merely rejected: a caller
//! supplying a host path, and an artifact existing without a retention class.
//!
//! A workspace is reached through an opaque token the host resolves. There is
//! no constructor taking a path, so an API client cannot name one:
//!
//! ```
//! use automonique_protocol::workspace::WorkspaceToken;
//! let token = WorkspaceToken::new("wt-3f9a").unwrap();
//! assert_eq!(token.as_str(), "wt-3f9a");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::workspace::WorkspaceToken;
//! use std::path::PathBuf;
//! // There is no path-shaped constructor.
//! let token = WorkspaceToken::from_path(PathBuf::from("/srv/work")).unwrap();
//! ```
//!
//! Digests reuse [`crate::release::ArtifactDigest`], so the weakened-algorithm
//! rule is enforced in one place rather than restated here.

use core::fmt;
use std::error::Error;

use crate::primitives::{Revision, ValueError};
use crate::release::ArtifactDigest;

/// Maximum UTF-8 byte length of a workspace or artifact identifier.
pub const MAX_WORKSPACE_FIELD_BYTES: usize = 256;

/// Why a workspace, lock or artifact operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceError {
    /// A value that must be an opaque token looked like a filesystem path.
    PathShapedToken,
    /// A storage locator embedded a path or a dereferenceable URL.
    LocatorNotOpaque,
    /// An immutable base was mutated in place.
    BaseIsImmutable {
        /// The revision that may not be changed.
        revision: u64,
    },
    /// A lock is already held.
    LockHeld {
        /// The current holder.
        holder: String,
    },
    /// A release was attempted by a party that does not hold the lock.
    NotLockHolder {
        /// The current holder.
        holder: String,
        /// Who attempted the release.
        attempted_by: String,
    },
    /// A deletion step was taken out of order.
    DeletionOutOfOrder {
        /// The state the artifact is in.
        current: &'static str,
        /// The step that was attempted.
        attempted: &'static str,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl WorkspaceError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::PathShapedToken => "path_shaped_token",
            Self::LocatorNotOpaque => "locator_not_opaque",
            Self::BaseIsImmutable { .. } => "base_is_immutable",
            Self::LockHeld { .. } => "lock_held",
            Self::NotLockHolder { .. } => "not_lock_holder",
            Self::DeletionOutOfOrder { .. } => "deletion_out_of_order",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathShapedToken => {
                formatter.write_str("a workspace token must be opaque, not a path")
            }
            Self::LocatorNotOpaque => {
                formatter.write_str("a storage locator must not embed a path or URL")
            }
            Self::BaseIsImmutable { revision } => write!(
                formatter,
                "base revision {revision} is immutable; register a new revision"
            ),
            Self::LockHeld { holder } => write!(formatter, "lock is held by {holder}"),
            Self::NotLockHolder {
                holder,
                attempted_by,
            } => write!(
                formatter,
                "lock is held by {holder}; {attempted_by} cannot release it"
            ),
            Self::DeletionOutOfOrder { current, attempted } => write!(
                formatter,
                "cannot {attempted} while the artifact is {current}"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for WorkspaceError {}

/// An opaque handle the host resolves to a working directory.
///
/// Deliberately not a path. A value that looks like one is refused, so a
/// caller cannot smuggle a host location through the token field.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceToken(String);

impl WorkspaceToken {
    /// Validate and construct a token.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::PathShapedToken`] for anything containing a
    /// separator, a drive letter or a traversal, and
    /// [`WorkspaceError::Field`] for a bounded-value violation.
    pub fn new(value: &str) -> Result<Self, WorkspaceError> {
        bounded(value, "workspace_token")?;
        if value.contains('/')
            || value.contains('\\')
            || value.contains("..")
            || value.contains(':')
            || value.starts_with('~')
        {
            return Err(WorkspaceError::PathShapedToken);
        }
        Ok(Self(value.to_owned()))
    }

    /// The opaque token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a workspace is isolated for a run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IsolationKind {
    /// Read-only view of an immutable snapshot.
    ReadOnlySnapshot,
    /// A writable copy made for one attempt.
    AttemptCopy,
    /// A writable overlay over an immutable base.
    Overlay,
}

/// A registered workspace at one immutable base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceRegistration {
    tenant: String,
    canonical_source: String,
    base_revision: Revision,
    snapshot: String,
    isolation: IsolationKind,
    token: WorkspaceToken,
}

impl WorkspaceRegistration {
    /// Register a workspace.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Field`] for an invalid component.
    pub fn new(
        tenant: &str,
        canonical_source: &str,
        base_revision: Revision,
        snapshot: &str,
        isolation: IsolationKind,
        token: WorkspaceToken,
    ) -> Result<Self, WorkspaceError> {
        bounded(tenant, "tenant")?;
        bounded(canonical_source, "canonical_source")?;
        bounded(snapshot, "snapshot")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            canonical_source: canonical_source.to_owned(),
            base_revision,
            snapshot: snapshot.to_owned(),
            isolation,
            token,
        })
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The immutable base revision.
    #[must_use]
    pub const fn base_revision(&self) -> Revision {
        self.base_revision
    }

    /// The immutable snapshot identity.
    #[must_use]
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }

    /// The isolation kind.
    #[must_use]
    pub const fn isolation(&self) -> IsolationKind {
        self.isolation
    }

    /// The opaque token a host resolves.
    #[must_use]
    pub const fn token(&self) -> &WorkspaceToken {
        &self.token
    }

    /// Refuse an in-place base change.
    ///
    /// # Errors
    ///
    /// Always returns [`WorkspaceError::BaseIsImmutable`]. Producing a changed
    /// base means registering a new revision with
    /// [`WorkspaceRegistration::at_new_base`], so evidence attached to the old
    /// base stays true.
    pub const fn set_base_revision(&self, _revision: Revision) -> Result<(), WorkspaceError> {
        Err(WorkspaceError::BaseIsImmutable {
            revision: self.base_revision.get(),
        })
    }

    /// Register a new workspace at a different base.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Field`] for an invalid snapshot.
    pub fn at_new_base(
        &self,
        base_revision: Revision,
        snapshot: &str,
        token: WorkspaceToken,
    ) -> Result<Self, WorkspaceError> {
        Self::new(
            &self.tenant,
            &self.canonical_source,
            base_revision,
            snapshot,
            self.isolation,
            token,
        )
    }
}

/// Exclusive locks over workspace paths.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockRegistry {
    held: Vec<(String, String)>,
}

impl LockRegistry {
    /// Start an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// Acquire a lock.
    ///
    /// Never blocks and never silently succeeds for a holder that already has
    /// it: a reentrant acquire is the same conflict as any other.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::LockHeld`] naming the current holder.
    pub fn acquire(&mut self, key: &str, holder: &str) -> Result<(), WorkspaceError> {
        bounded(key, "lock_key")?;
        bounded(holder, "holder")?;
        if let Some((_, current)) = self.held.iter().find(|(existing, _)| existing == key) {
            return Err(WorkspaceError::LockHeld {
                holder: current.clone(),
            });
        }
        self.held.push((key.to_owned(), holder.to_owned()));
        Ok(())
    }

    /// Release a lock.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::NotLockHolder`] when the caller does not hold
    /// it, and [`WorkspaceError::LockHeld`] semantics never apply to a free
    /// key: releasing an unheld key names the attempt rather than succeeding.
    pub fn release(&mut self, key: &str, holder: &str) -> Result<(), WorkspaceError> {
        let Some(index) = self.held.iter().position(|(existing, _)| existing == key) else {
            return Err(WorkspaceError::NotLockHolder {
                holder: String::new(),
                attempted_by: holder.to_owned(),
            });
        };
        if self.held[index].1 != holder {
            return Err(WorkspaceError::NotLockHolder {
                holder: self.held[index].1.clone(),
                attempted_by: holder.to_owned(),
            });
        }
        self.held.remove(index);
        Ok(())
    }

    /// Who holds a lock, if anyone.
    #[must_use]
    pub fn holder_of(&self, key: &str) -> Option<&str> {
        self.held
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, holder)| holder.as_str())
    }
}

/// Who may see an artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Visibility {
    /// The creating actor only.
    Private,
    /// Everyone in the owning tenant.
    Tenant,
    /// Explicitly published.
    Published,
}

/// How long an artifact is kept.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetentionClass {
    /// Short-lived working output.
    Ephemeral,
    /// Ordinary business retention.
    Standard,
    /// Retained for audit.
    Audit,
    /// Retained under legal hold; deletion is refused.
    LegalHold,
}

/// What an artifact is attached to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LinkRelation {
    /// Supplied with a transport input.
    Input,
    /// Attached to a work item.
    Work,
    /// Produced by a run.
    Run,
    /// Produced within a provider turn.
    Turn,
    /// Evidence for an approval.
    Approval,
    /// Published outward.
    Publication,
}

impl LinkRelation {
    /// Every relation, for coverage checks.
    pub const ALL: [Self; 6] = [
        Self::Input,
        Self::Work,
        Self::Run,
        Self::Turn,
        Self::Approval,
        Self::Publication,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Work => "work",
            Self::Run => "run",
            Self::Turn => "turn",
            Self::Approval => "approval",
            Self::Publication => "publication",
        }
    }
}

/// Where bytes live, named opaquely.
///
/// A locator names a backend and an opaque key. It never embeds a filesystem
/// path or a credential-bearing URL, so it is not dereferenceable by a client.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StorageLocator {
    backend: String,
    key: String,
}

impl StorageLocator {
    /// Name where bytes live.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::LocatorNotOpaque`] when the key looks like a
    /// path or URL, and [`WorkspaceError::Field`] for a bounded violation.
    pub fn new(backend: &str, key: &str) -> Result<Self, WorkspaceError> {
        bounded(backend, "backend")?;
        bounded(key, "locator_key")?;
        if key.contains("://") || key.starts_with('/') || key.contains('@') || key.contains('\\') {
            return Err(WorkspaceError::LocatorNotOpaque);
        }
        Ok(Self {
            backend: backend.to_owned(),
            key: key.to_owned(),
        })
    }

    /// The storage backend.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// The opaque key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Where an artifact is in its deletion sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeletionState {
    /// Readable.
    Live,
    /// Access removed; bytes still present.
    AccessRemoved,
    /// Tombstoned; the record of removal is durable.
    Tombstoned,
    /// Unreferenced bytes may be collected.
    Collectable,
}

impl DeletionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::AccessRemoved => "access removed",
            Self::Tombstoned => "tombstoned",
            Self::Collectable => "collectable",
        }
    }
}

/// A content-addressed artifact.
///
/// Identity is the digest, not a locator: the same bytes stored twice are one
/// artifact with two locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Artifact {
    digest: ArtifactDigest,
    size_bytes: u64,
    media_type: String,
    tenant: String,
    creator: String,
    visibility: Visibility,
    retention: RetentionClass,
    locators: Vec<StorageLocator>,
    deletion: DeletionState,
}

impl Artifact {
    /// Record an artifact.
    ///
    /// Visibility and retention are required arguments. There is no
    /// constructor that omits either, so an artifact cannot exist without a
    /// declared retention class.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Field`] for an invalid component.
    pub fn new(
        digest: ArtifactDigest,
        size_bytes: u64,
        media_type: &str,
        tenant: &str,
        creator: &str,
        visibility: Visibility,
        retention: RetentionClass,
    ) -> Result<Self, WorkspaceError> {
        bounded(media_type, "media_type")?;
        bounded(tenant, "tenant")?;
        bounded(creator, "creator")?;
        Ok(Self {
            digest,
            size_bytes,
            media_type: media_type.to_owned(),
            tenant: tenant.to_owned(),
            creator: creator.to_owned(),
            visibility,
            retention,
            locators: Vec::new(),
            deletion: DeletionState::Live,
        })
    }

    /// Content digest, which is the artifact's identity.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Declared visibility.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Declared retention class.
    #[must_use]
    pub const fn retention(&self) -> RetentionClass {
        self.retention
    }

    /// Current deletion state.
    #[must_use]
    pub const fn deletion(&self) -> DeletionState {
        self.deletion
    }

    /// Record another place the same bytes live.
    #[must_use]
    pub fn with_locator(mut self, locator: StorageLocator) -> Self {
        self.locators.push(locator);
        self
    }

    /// Every place the bytes live.
    #[must_use]
    pub fn locators(&self) -> &[StorageLocator] {
        &self.locators
    }

    /// Whether two artifacts are the same content.
    ///
    /// Compares digests, so the number of locators is irrelevant.
    #[must_use]
    pub fn is_same_content(&self, other: &Self) -> bool {
        self.digest.matches(&other.digest)
    }

    /// Remove access, the first deletion step.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::DeletionOutOfOrder`] unless the artifact is
    /// live, and refuses outright under legal hold.
    pub fn remove_access(&self) -> Result<Self, WorkspaceError> {
        self.advance(
            DeletionState::Live,
            DeletionState::AccessRemoved,
            "remove access",
        )
    }

    /// Record the durable tombstone, the second step.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::DeletionOutOfOrder`] unless access was
    /// removed first.
    pub fn tombstone(&self) -> Result<Self, WorkspaceError> {
        self.advance(
            DeletionState::AccessRemoved,
            DeletionState::Tombstoned,
            "tombstone",
        )
    }

    /// Permit collection of unreferenced bytes, the final step.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::DeletionOutOfOrder`] unless a tombstone
    /// exists. Bytes are never collected before the record of their removal is
    /// durable.
    pub fn permit_collection(&self) -> Result<Self, WorkspaceError> {
        self.advance(
            DeletionState::Tombstoned,
            DeletionState::Collectable,
            "permit collection",
        )
    }

    fn advance(
        &self,
        required: DeletionState,
        next: DeletionState,
        attempted: &'static str,
    ) -> Result<Self, WorkspaceError> {
        if self.retention == RetentionClass::LegalHold {
            return Err(WorkspaceError::DeletionOutOfOrder {
                current: "under legal hold",
                attempted,
            });
        }
        if self.deletion != required {
            return Err(WorkspaceError::DeletionOutOfOrder {
                current: self.deletion.as_str(),
                attempted,
            });
        }
        let mut next_state = self.clone();
        next_state.deletion = next;
        Ok(next_state)
    }
}

/// A typed attachment between an artifact and something that references it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactLink {
    relation: LinkRelation,
    digest: ArtifactDigest,
    target: String,
}

impl ArtifactLink {
    /// Attach an artifact to a target.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::Field`] for an invalid target.
    pub fn new(
        relation: LinkRelation,
        digest: ArtifactDigest,
        target: &str,
    ) -> Result<Self, WorkspaceError> {
        bounded(target, "link_target")?;
        Ok(Self {
            relation,
            digest,
            target: target.to_owned(),
        })
    }

    /// The relation kind.
    #[must_use]
    pub const fn relation(&self) -> LinkRelation {
        self.relation
    }

    /// The artifact digest.
    #[must_use]
    pub const fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    /// The referencing target.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), WorkspaceError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_WORKSPACE_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_WORKSPACE_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(WorkspaceError::Field { field, error }),
        None => Ok(()),
    }
}
