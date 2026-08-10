// SPDX-License-Identifier: Elastic-2.0

//! Unix peer authorization and the runtime-layout rules that protect a socket.
//!
//! Peer credentials are verified before request parsing, so an unauthorized
//! peer never reaches the codec. Everything here is a total function over
//! caller-supplied observations: no socket is opened, no `getsockopt` is
//! called, and no filesystem is read. A rule that cannot be evaluated offline
//! does not belong in this module.
//!
//! Refusals name the rule and the violating class only. A socket path, a peer's
//! command line and a credential value beyond the numeric IDs both sides
//! already know never appear in a refusal.

use std::error::Error;
use std::fmt;

/// Required mode of a private directory in the runtime tree.
pub const MODE_PRIVATE_DIRECTORY: u32 = 0o700;

/// Required mode of a mutable runtime file, including the control socket.
pub const MODE_PRIVATE_FILE: u32 = 0o600;

/// Required mode of an immutable sanitized specification.
pub const MODE_IMMUTABLE_SPEC: u32 = 0o400;

/// Why a peer, a runtime entry or a path was refused.
///
/// Exactly one reason is returned per decision. No variant carries a path, a
/// command line or any value beyond numeric identifiers and mode bits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PeerRefusal {
    /// The transport could not obtain kernel-supplied peer credentials.
    ///
    /// Distinct from [`PeerRefusal::UidNotAdmitted`]: not knowing who the peer
    /// is differs from knowing and refusing them.
    CredentialsUnavailable,
    /// The peer's user ID is not in the admitted set.
    UidNotAdmitted {
        /// The refused user ID.
        uid: u32,
    },
    /// The peer is root and the policy does not admit root explicitly.
    RootNotAdmitted,
    /// The policy requires a group and the peer's group is not in it.
    GidNotAdmitted {
        /// The refused group ID.
        gid: u32,
    },
    /// The observed mode grants access the requirement does not.
    ModeMorePermissive {
        /// Mode the entry must have.
        required: u32,
        /// Mode that was observed.
        observed: u32,
    },
    /// The observed mode differs from the exact requirement without being more
    /// permissive. Drift is visible in both directions.
    ModeMismatch {
        /// Mode the entry must have.
        required: u32,
        /// Mode that was observed.
        observed: u32,
    },
    /// The entry is owned by an unexpected user.
    UnexpectedOwner {
        /// Owner the entry must have.
        expected: u32,
        /// Owner that was observed.
        observed: u32,
    },
    /// A path component is a symbolic link.
    SymlinkComponent,
    /// A parent directory is writable by group or others.
    WritableParent,
    /// The path contains an embedded NUL.
    EmbeddedNul,
    /// The path is absolute where a runtime-relative path is required.
    AbsolutePath,
    /// The path escapes above the runtime root.
    PathEscape,
    /// The path is not canonical: it contains an empty or `.` component.
    NonCanonicalPath,
}

impl PeerRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::CredentialsUnavailable => "credentials_unavailable",
            Self::UidNotAdmitted { .. } => "uid_not_admitted",
            Self::RootNotAdmitted => "root_not_admitted",
            Self::GidNotAdmitted { .. } => "gid_not_admitted",
            Self::ModeMorePermissive { .. } => "mode_more_permissive",
            Self::ModeMismatch { .. } => "mode_mismatch",
            Self::UnexpectedOwner { .. } => "unexpected_owner",
            Self::SymlinkComponent => "symlink_component",
            Self::WritableParent => "writable_parent",
            Self::EmbeddedNul => "embedded_nul",
            Self::AbsolutePath => "absolute_path",
            Self::PathEscape => "path_escape",
            Self::NonCanonicalPath => "non_canonical_path",
        }
    }
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialsUnavailable => formatter.write_str("peer credentials are unavailable"),
            Self::UidNotAdmitted { uid } => {
                write!(formatter, "user {uid} is not in the admitted set")
            }
            Self::RootNotAdmitted => formatter.write_str("root is not admitted by this policy"),
            Self::GidNotAdmitted { gid } => {
                write!(formatter, "group {gid} is not in the admitted set")
            }
            Self::ModeMorePermissive { required, observed } => write!(
                formatter,
                "mode {observed:04o} is more permissive than the required {required:04o}"
            ),
            Self::ModeMismatch { required, observed } => write!(
                formatter,
                "mode {observed:04o} differs from the required {required:04o}"
            ),
            Self::UnexpectedOwner { expected, observed } => write!(
                formatter,
                "entry is owned by {observed}; expected {expected}"
            ),
            Self::SymlinkComponent => formatter.write_str("a path component is a symbolic link"),
            Self::WritableParent => {
                formatter.write_str("a parent directory is group- or world-writable")
            }
            Self::EmbeddedNul => formatter.write_str("path contains an embedded NUL"),
            Self::AbsolutePath => formatter.write_str("path is absolute"),
            Self::PathEscape => formatter.write_str("path escapes above the runtime root"),
            Self::NonCanonicalPath => formatter.write_str("path is not canonical"),
        }
    }
}

impl Error for PeerRefusal {}

/// Kernel-supplied credentials of a connected peer.
///
/// Constructible only from explicit components. There is no `Default`, no
/// ambient-authority constructor and no conversion from `()`: a credential is
/// evidence a transport obtained from the kernel, never something a message
/// body can assert.
///
/// ```compile_fail
/// use automonique_policy::peer::PeerCredential;
/// // Credentials have no default: an unknown peer is not a peer.
/// let credential = PeerCredential::default();
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerCredential {
    uid: u32,
    gid: u32,
    pid: i32,
}

impl PeerCredential {
    /// Record credentials a transport obtained from the kernel.
    #[must_use]
    pub const fn new(uid: u32, gid: u32, pid: i32) -> Self {
        Self { uid, gid, pid }
    }

    /// Connecting user ID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Connecting group ID.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// Connecting process ID.
    ///
    /// Diagnostic provenance only. A PID may be reused between the kernel's
    /// observation and any later use, so no admission rule may key on it.
    #[must_use]
    pub const fn pid(self) -> i32 {
        self.pid
    }
}

/// Proof that a peer was admitted by a policy.
///
/// Obtainable only from [`PeerPolicy::evaluate`], so a caller cannot fabricate
/// an admission or reach one from an error path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Admission {
    uid: u32,
}

impl Admission {
    /// The admitted user ID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }
}

/// Why a peer policy could not be constructed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PeerPolicyError {
    /// No user was admitted. A policy admitting nobody is a mistake, and a
    /// wildcard is not expressible, so an empty set is refused rather than
    /// silently admitting everyone.
    NoAdmittedUsers,
}

impl fmt::Display for PeerPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdmittedUsers => formatter.write_str("policy admits no user"),
        }
    }
}

impl Error for PeerPolicyError {}

/// Which peers may reach a local socket.
///
/// The admitted sets are explicit. There is no wildcard, no "any user" variant
/// and no implicit trust of root: a policy that admits `0` says so by listing
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPolicy {
    admitted_uids: Vec<u32>,
    admitted_gids: Option<Vec<u32>>,
}

impl PeerPolicy {
    /// Admit an explicit, non-empty set of user IDs.
    ///
    /// # Errors
    ///
    /// Returns [`PeerPolicyError::NoAdmittedUsers`] for an empty set.
    pub fn new(admitted_uids: &[u32]) -> Result<Self, PeerPolicyError> {
        if admitted_uids.is_empty() {
            return Err(PeerPolicyError::NoAdmittedUsers);
        }
        let mut uids = admitted_uids.to_vec();
        uids.sort_unstable();
        uids.dedup();
        Ok(Self {
            admitted_uids: uids,
            admitted_gids: None,
        })
    }

    /// Additionally require membership of an explicit group set.
    ///
    /// An empty group set means "no group requirement" and is expressed by not
    /// calling this method; passing an empty slice therefore clears it rather
    /// than admitting nothing.
    #[must_use]
    pub fn requiring_gids(mut self, admitted_gids: &[u32]) -> Self {
        if admitted_gids.is_empty() {
            self.admitted_gids = None;
        } else {
            let mut gids = admitted_gids.to_vec();
            gids.sort_unstable();
            gids.dedup();
            self.admitted_gids = Some(gids);
        }
        self
    }

    /// Whether this policy admits root explicitly.
    #[must_use]
    pub fn admits_root(&self) -> bool {
        self.admitted_uids.contains(&0)
    }

    /// Decide whether a peer may proceed to request parsing.
    ///
    /// The decision is total over credentials and policy. `credential` is
    /// `None` when the transport could not obtain kernel credentials, which is
    /// a refusal reason and never a default admit. There is no path on which an
    /// error yields an [`Admission`].
    ///
    /// # Errors
    ///
    /// Returns exactly one [`PeerRefusal`] naming why the peer was refused.
    pub fn evaluate(&self, credential: Option<PeerCredential>) -> Result<Admission, PeerRefusal> {
        let Some(credential) = credential else {
            return Err(PeerRefusal::CredentialsUnavailable);
        };
        let uid = credential.uid();
        if !self.admitted_uids.contains(&uid) {
            return Err(if uid == 0 {
                PeerRefusal::RootNotAdmitted
            } else {
                PeerRefusal::UidNotAdmitted { uid }
            });
        }
        if let Some(gids) = &self.admitted_gids
            && !gids.contains(&credential.gid())
        {
            return Err(PeerRefusal::GidNotAdmitted {
                gid: credential.gid(),
            });
        }
        Ok(Admission { uid })
    }
}

/// Observed permission and ownership facts about one runtime entry.
///
/// Supplied by a caller that stat'ed the entry, so the rules below are testable
/// without a filesystem.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EntryMetadata {
    mode: u32,
    owner_uid: u32,
    is_symlink: bool,
    parent_group_or_world_writable: bool,
}

impl EntryMetadata {
    /// Record observed metadata. `mode` is the permission bits only.
    #[must_use]
    pub const fn new(
        mode: u32,
        owner_uid: u32,
        is_symlink: bool,
        parent_group_or_world_writable: bool,
    ) -> Self {
        Self {
            mode,
            owner_uid,
            is_symlink,
            parent_group_or_world_writable,
        }
    }

    /// Observed permission bits.
    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }

    /// Observed owning user ID.
    #[must_use]
    pub const fn owner_uid(self) -> u32 {
        self.owner_uid
    }
}

/// Check one runtime entry against its exact requirement.
///
/// An exact mode is required: anything granting more access is
/// [`PeerRefusal::ModeMorePermissive`], and anything else that differs is
/// [`PeerRefusal::ModeMismatch`], so drift is visible in both directions.
///
/// # Errors
///
/// Returns the first violated rule, checked in order: symlink, ownership,
/// parent writability, then mode.
pub fn check_entry(
    metadata: EntryMetadata,
    required_mode: u32,
    expected_owner: u32,
) -> Result<(), PeerRefusal> {
    if metadata.is_symlink {
        return Err(PeerRefusal::SymlinkComponent);
    }
    if metadata.owner_uid != expected_owner {
        return Err(PeerRefusal::UnexpectedOwner {
            expected: expected_owner,
            observed: metadata.owner_uid,
        });
    }
    if metadata.parent_group_or_world_writable {
        return Err(PeerRefusal::WritableParent);
    }
    if metadata.mode != required_mode {
        // Any bit set beyond the requirement grants access it does not.
        return Err(if metadata.mode & !required_mode != 0 {
            PeerRefusal::ModeMorePermissive {
                required: required_mode,
                observed: metadata.mode,
            }
        } else {
            PeerRefusal::ModeMismatch {
                required: required_mode,
                observed: metadata.mode,
            }
        });
    }
    Ok(())
}

/// Check a runtime-relative path's spelling.
///
/// Evaluated over the supplied string alone, so it holds before any filesystem
/// call and cannot be defeated by a race.
///
/// # Errors
///
/// Returns the first violated rule: embedded NUL, absolute path, non-canonical
/// component, then escape above the runtime root.
pub fn check_relative_path(path: &str) -> Result<(), PeerRefusal> {
    if path.contains('\0') {
        return Err(PeerRefusal::EmbeddedNul);
    }
    if path.starts_with('/') {
        return Err(PeerRefusal::AbsolutePath);
    }
    if path.is_empty() {
        return Err(PeerRefusal::NonCanonicalPath);
    }
    let mut depth = 0_i32;
    for component in path.split('/') {
        match component {
            "" | "." => return Err(PeerRefusal::NonCanonicalPath),
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Err(PeerRefusal::PathEscape);
                }
            }
            _ => depth += 1,
        }
    }
    Ok(())
}
