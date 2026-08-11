// SPDX-License-Identifier: Elastic-2.0

//! Sandbox profiles, specs, attestation and violation dispositions.
//!
//! Two policies govern different traffic and must never substitute for one
//! another: a provider-control channel and a model-directed tool workload.
//! Collapsing them is what lets tool traffic inherit control-plane reach, so
//! they are distinct types:
//!
//! ```compile_fail
//! use automonique_protocol::sandbox::{ProviderControlEgress, ToolWorkloadEgress};
//! let control = ProviderControlEgress::denied();
//! // Tool traffic cannot be governed by the control-plane policy.
//! let workload: ToolWorkloadEgress = control;
//! ```
//!
//! The same binding, differing only in the type of the value assigned,
//! compiles — so the failure above is the type distinction and not a broken
//! snippet:
//!
//! ```
//! use automonique_protocol::sandbox::ToolWorkloadEgress;
//! let workload = ToolWorkloadEgress::denied();
//! let bound: ToolWorkloadEgress = workload;
//! assert_eq!(bound, ToolWorkloadEgress::denied());
//! ```
//!
//! An approval may not widen a spec. There is no accessor returning one, so
//! added authority produces a new reviewed plan rather than a mutation:
//!
//! ```compile_fail
//! use automonique_protocol::sandbox::ApprovalRequest;
//! let request = ApprovalRequest::new("command", "run tests").unwrap();
//! let widened = request.widened_spec();
//! ```
//!
//! The accessors the type does have compile, so that failure is the absence of
//! a spec-returning accessor rather than a mistyped call:
//!
//! ```
//! use automonique_protocol::sandbox::ApprovalRequest;
//! let request = ApprovalRequest::new("command", "run tests").unwrap();
//! assert_eq!(request.class(), "command");
//! ```
//!
//! This module defines the boundary. It does not enforce one: no namespace is
//! created, no seccomp filter loaded, no Landlock ruleset applied and no cgroup
//! allocated. Evidence must say that rather than implying a kernel property was
//! tested.

use core::fmt;
use std::error::Error;
use std::marker::PhantomData;
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};

use crate::identity::Actor;
use crate::models::ProviderAccountId;
use crate::primitives::{BoundedString, IdDomain, OpaqueId, Revision, ValueError};

/// Maximum UTF-8 byte length of a sandbox field.
pub const MAX_SANDBOX_FIELD_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a sandbox path.
pub const MAX_SANDBOX_PATH_BYTES: usize = 1_024;

/// Maximum number of entries in one sandbox list.
pub const MAX_SANDBOX_ENTRIES: usize = 256;

/// A bounded, control-free sandbox name.
pub type SandboxName = BoundedString<MAX_SANDBOX_FIELD_BYTES>;

/// Why a digest was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestError {
    /// The value carried no `algorithm:` prefix.
    MissingAlgorithm,
    /// The algorithm is not one this layer accepts.
    UnknownAlgorithm,
    /// The hexadecimal body was the wrong length for the algorithm.
    Length {
        /// Hex digits the algorithm produces.
        expected: usize,
        /// Hex digits supplied.
        actual: usize,
    },
    /// The body was not lowercase hexadecimal.
    NotLowercaseHex,
}

impl DigestError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MissingAlgorithm => "missing_algorithm",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::Length { .. } => "digest_length",
            Self::NotLowercaseHex => "not_lowercase_hex",
        }
    }
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAlgorithm => formatter.write_str("digest carries no algorithm prefix"),
            Self::UnknownAlgorithm => formatter.write_str("digest algorithm is not accepted"),
            Self::Length { expected, actual } => write!(
                formatter,
                "digest body is {actual} hex digits; the algorithm produces {expected}"
            ),
            Self::NotLowercaseHex => {
                formatter.write_str("digest body is not lowercase hexadecimal")
            }
        }
    }
}

impl Error for DigestError {}

/// Why a sandbox path was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathError {
    /// The bound or character rule was violated.
    Value(ValueError),
    /// The path did not start at the root.
    NotAbsolute,
    /// The path carried an empty component, so it was not canonical.
    EmptyComponent,
    /// The path carried a `.` or `..` component.
    TraversalComponent,
}

impl PathError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Value(inner) => inner.category(),
            Self::NotAbsolute => "not_absolute",
            Self::EmptyComponent => "empty_component",
            Self::TraversalComponent => "traversal_component",
        }
    }
}

impl From<ValueError> for PathError {
    fn from(value: ValueError) -> Self {
        Self::Value(value)
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(inner) => inner.fmt(formatter),
            Self::NotAbsolute => formatter.write_str("path does not start at the root"),
            Self::EmptyComponent => formatter.write_str("path carries an empty component"),
            Self::TraversalComponent => formatter.write_str("path carries a . or .. component"),
        }
    }
}

impl Error for PathError {}

/// Why a sandbox operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxError {
    /// A required enforcement feature is unavailable.
    ///
    /// Names the feature. There is no weaker profile to fall back to.
    RequiredEnforcementMissing {
        /// The absent feature.
        feature: String,
    },
    /// The host offers a required feature through an implementation the spec
    /// does not accept.
    ///
    /// Names the feature and the rejected implementation digest. An accepted
    /// implementation digest that nothing compares is not a control.
    EnforcementImplementationRejected {
        /// The feature whose implementation was rejected.
        feature: String,
        /// The digest the host offered.
        offered: String,
    },
    /// A budget was declared without a unit or above its ceiling.
    BudgetOutOfRange {
        /// The budget's unit.
        unit: &'static str,
        /// Maximum accepted quantity.
        max: u64,
        /// Quantity requested.
        requested: u64,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A digest-bearing field was rejected.
    Digest {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: DigestError,
    },
    /// A path-bearing field was rejected.
    Path {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: PathError,
    },
    /// A field that counts something was zero.
    NotPositive {
        /// The rejected field.
        field: &'static str,
    },
    /// A list exceeded its declared ceiling.
    TooManyEntries {
        /// The rejected field.
        field: &'static str,
        /// Maximum accepted entries.
        max: usize,
        /// Entries supplied.
        requested: usize,
    },
    /// A list named the same subject twice, so its meaning was ambiguous.
    DuplicateEntry {
        /// The rejected field.
        field: &'static str,
    },
    /// A spec granted more than the profile it compiles from.
    ///
    /// A profile is a minimum contract: a deployment may narrow it, and adding
    /// a capability requires a new plan revision rather than a wider spec.
    WidensProfile {
        /// The axis on which the spec exceeded its profile.
        axis: &'static str,
    },
}

impl SandboxError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::RequiredEnforcementMissing { .. } => "required_enforcement_missing",
            Self::EnforcementImplementationRejected { .. } => "enforcement_implementation_rejected",
            Self::BudgetOutOfRange { .. } => "budget_out_of_range",
            Self::Field { .. } => "field_invalid",
            Self::Digest { .. } => "digest_invalid",
            Self::Path { .. } => "path_invalid",
            Self::NotPositive { .. } => "not_positive",
            Self::TooManyEntries { .. } => "too_many_entries",
            Self::DuplicateEntry { .. } => "duplicate_entry",
            Self::WidensProfile { .. } => "widens_profile",
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredEnforcementMissing { feature } => write!(
                formatter,
                "required enforcement feature {feature} is unavailable; there is no weaker profile"
            ),
            Self::EnforcementImplementationRejected { feature, offered } => write!(
                formatter,
                "enforcement feature {feature} is offered by unaccepted implementation {offered}"
            ),
            Self::BudgetOutOfRange {
                unit,
                max,
                requested,
            } => write!(
                formatter,
                "budget of {requested} {unit} exceeds the maximum of {max}"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Digest { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Path { field, error } => write!(formatter, "field {field}: {error}"),
            Self::NotPositive { field } => write!(formatter, "field {field} is zero"),
            Self::TooManyEntries {
                field,
                max,
                requested,
            } => write!(
                formatter,
                "field {field} carries {requested} entries; the maximum is {max}"
            ),
            Self::DuplicateEntry { field } => {
                write!(formatter, "field {field} names the same entry twice")
            }
            Self::WidensProfile { axis } => write!(
                formatter,
                "spec grants more than its profile on {axis}; a profile is a minimum contract"
            ),
        }
    }
}

impl Error for SandboxError {}

/// A digest algorithm this layer accepts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
    /// BLAKE3, 256-bit output.
    Blake3,
}

impl DigestAlgorithm {
    /// Every accepted algorithm.
    pub const ALL: [Self; 3] = [Self::Sha256, Self::Sha512, Self::Blake3];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }

    /// Hexadecimal digits the algorithm produces.
    #[must_use]
    pub const fn hex_digits(self) -> usize {
        match self {
            Self::Sha256 | Self::Blake3 => 64,
            Self::Sha512 => 128,
        }
    }

    fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == value)
    }
}

/// A content digest: an algorithm and its lowercase hexadecimal body.
///
/// A digest field that accepts arbitrary text is not a digest. Parsing rejects
/// anything that is not `<algorithm>:<hex>` at the algorithm's own length, so
/// `landlock-1` and `sha256:policy` are not values of this type.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    hex: String,
}

impl Digest {
    /// Parse `<algorithm>:<hex>`.
    ///
    /// # Errors
    ///
    /// Returns [`DigestError`] when the prefix is absent or unknown, the body
    /// is the wrong length for the algorithm, or the body is not lowercase
    /// hexadecimal.
    pub fn parse(value: &str) -> Result<Self, DigestError> {
        let (algorithm, hex) = value.split_once(':').ok_or(DigestError::MissingAlgorithm)?;
        let algorithm =
            DigestAlgorithm::from_spelling(algorithm).ok_or(DigestError::UnknownAlgorithm)?;
        if hex.len() != algorithm.hex_digits() {
            return Err(DigestError::Length {
                expected: algorithm.hex_digits(),
                actual: hex.len(),
            });
        }
        if !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(DigestError::NotLowercaseHex);
        }
        Ok(Self {
            algorithm,
            hex: hex.to_owned(),
        })
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The lowercase hexadecimal body.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm.as_str(), self.hex)
    }
}

/// Marker trait implemented by digest domain types.
///
/// A domain says what a digest is *of*. Two digests of different domains are
/// different types, so a policy digest cannot be recorded in the workspace
/// security-context position.
pub trait DigestDomain {}

/// Domain of the complete compiled-policy digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyDomain;
impl DigestDomain for PolicyDomain {}

/// Domain of the workspace security-context hash.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkspaceContextDomain;
impl DigestDomain for WorkspaceContextDomain {}

/// Domain of an accepted enforcement-implementation digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImplementationDomain;
impl DigestDomain for ImplementationDomain {}

/// Domain of a Landlock ruleset digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LandlockRulesetDomain;
impl DigestDomain for LandlockRulesetDomain {}

/// Domain of a seccomp filter digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SeccompDomain;
impl DigestDomain for SeccompDomain {}

/// Domain of an egress-policy digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EgressPolicyDomain;
impl DigestDomain for EgressPolicyDomain {}

/// Domain of an external daemon's attested-context digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExternalDaemonDomain;
impl DigestDomain for ExternalDaemonDomain {}

/// A [`Digest`] tagged with what it is a digest of.
///
/// Tagging is not decoration: several digests sit next to each other in the
/// spec and in the attestation, and an untagged pair can be transposed at a
/// call site while still compiling. Tagged, the transposition does not:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::{PolicyDigest, WorkspaceContextHash};
/// let policy = PolicyDigest::parse(
///     "sha256:0000000000000000000000000000000000000000000000000000000000000001",
/// )
/// .unwrap();
/// let workspace: WorkspaceContextHash = policy;
/// ```
///
/// The same binding into its own domain, differing only in the target type,
/// compiles:
///
/// ```
/// use automonique_protocol::sandbox::PolicyDigest;
/// let policy = PolicyDigest::parse(
///     "sha256:0000000000000000000000000000000000000000000000000000000000000001",
/// )
/// .unwrap();
/// let bound: PolicyDigest = policy;
/// assert_eq!(bound.digest().hex().len(), 64);
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaggedDigest<D: DigestDomain> {
    digest: Digest,
    domain: PhantomData<D>,
}

impl<D: DigestDomain> TaggedDigest<D> {
    /// Tag an already parsed digest.
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self {
            digest,
            domain: PhantomData,
        }
    }

    /// Parse and tag `<algorithm>:<hex>`.
    ///
    /// # Errors
    ///
    /// Returns [`DigestError`] for anything [`Digest::parse`] rejects.
    pub fn parse(value: &str) -> Result<Self, DigestError> {
        Ok(Self::new(Digest::parse(value)?))
    }

    /// The untagged digest.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl<D: DigestDomain> fmt::Display for TaggedDigest<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.digest.fmt(formatter)
    }
}

/// The complete compiled-policy digest.
pub type PolicyDigest = TaggedDigest<PolicyDomain>;
/// The workspace security-context hash.
pub type WorkspaceContextHash = TaggedDigest<WorkspaceContextDomain>;
/// An accepted enforcement-implementation digest.
pub type ImplementationDigest = TaggedDigest<ImplementationDomain>;
/// A Landlock ruleset digest.
pub type LandlockRulesetDigest = TaggedDigest<LandlockRulesetDomain>;
/// A seccomp filter digest.
pub type SeccompDigest = TaggedDigest<SeccompDomain>;
/// An egress-policy digest.
pub type EgressPolicyDigest = TaggedDigest<EgressPolicyDomain>;
/// An external daemon's attested-context digest.
pub type ExternalDaemonDigest = TaggedDigest<ExternalDaemonDomain>;

/// Domain of a cgroup identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CgroupDomain;
impl IdDomain for CgroupDomain {}

/// Domain of an execution-backend identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionBackendDomain;
impl IdDomain for ExecutionBackendDomain {}

/// Domain of a kernel and boot identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelBootDomain;
impl IdDomain for KernelBootDomain {}

/// The cgroup a host ran under.
pub type CgroupId = OpaqueId<CgroupDomain, MAX_SANDBOX_FIELD_BYTES>;
/// The execution backend a host ran under.
pub type ExecutionBackendId = OpaqueId<ExecutionBackendDomain, MAX_SANDBOX_FIELD_BYTES>;
/// The kernel and boot a host ran under.
pub type KernelBootId = OpaqueId<KernelBootDomain, MAX_SANDBOX_FIELD_BYTES>;

/// An absolute, canonical sandbox path.
///
/// Traversal-shaped and non-canonical spellings are not values of this type, so
/// a grant cannot be written that resolves somewhere else. The root itself is
/// rejected: granting `/` is not a bounded grant.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SandboxPath(String);

impl SandboxPath {
    /// Validate and construct a path.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the value is empty, over
    /// [`MAX_SANDBOX_PATH_BYTES`], carries a control character, is relative,
    /// carries an empty component, or carries `.` or `..`.
    pub fn new(value: &str) -> Result<Self, PathError> {
        if value.is_empty() {
            return Err(PathError::Value(ValueError::Empty));
        }
        if value.len() > MAX_SANDBOX_PATH_BYTES {
            return Err(PathError::Value(ValueError::TooLong {
                max_bytes: MAX_SANDBOX_PATH_BYTES,
                actual_bytes: value.len(),
            }));
        }
        if value.chars().any(char::is_control) {
            return Err(PathError::Value(ValueError::ControlCharacter));
        }
        let Some(body) = value.strip_prefix('/') else {
            return Err(PathError::NotAbsolute);
        };
        for component in body.split('/') {
            if component.is_empty() {
                return Err(PathError::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(PathError::TraversalComponent);
            }
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// How much of a granted path the workload may do, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PathAccess {
    /// Read only.
    ReadOnly,
    /// Read and write.
    ReadWrite,
}

impl PathAccess {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
        }
    }
}

/// One path the spec grants, and how.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathGrant {
    path: SandboxPath,
    access: PathAccess,
}

impl PathGrant {
    /// Grant one path.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Path`] for an invalid path.
    pub fn new(path: &str, access: PathAccess) -> Result<Self, SandboxError> {
        Ok(Self {
            path: SandboxPath::new(path).map_err(|error| SandboxError::Path {
                field: "path_grant",
                error,
            })?,
            access,
        })
    }

    /// The granted path.
    #[must_use]
    pub const fn path(&self) -> &SandboxPath {
        &self.path
    }

    /// What the grant permits.
    #[must_use]
    pub const fn access(&self) -> PathAccess {
        self.access
    }
}

/// The readable and writable path grants of one spec.
///
/// The only operation deriving one set from another is [`PathGrants::narrowed_to`],
/// an intersection that also takes the lower access of each shared path. There
/// is no union, no insertion and no override, so no call order produces a wider
/// set than the one that was reviewed:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::PathGrants;
/// # fn grants() -> PathGrants { unreachable!() }
/// let existing = grants();
/// let requested = grants();
/// let widened = existing.union(&requested);
/// ```
///
/// The narrowing operation, differing only in which combination is asked for,
/// compiles:
///
/// ```no_run
/// use automonique_protocol::sandbox::PathGrants;
/// # fn grants() -> PathGrants { unreachable!() }
/// let existing = grants();
/// let requested = grants();
/// let narrowed = existing.narrowed_to(&requested);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathGrants {
    grants: Vec<PathGrant>,
}

impl PathGrants {
    /// Declare a reviewed grant set.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`]
    /// and [`SandboxError::DuplicateEntry`] when one path is granted twice,
    /// because two grants for one path have no single meaning.
    pub fn declare(grants: &[PathGrant]) -> Result<Self, SandboxError> {
        if grants.len() > MAX_SANDBOX_ENTRIES {
            return Err(SandboxError::TooManyEntries {
                field: "path_grants",
                max: MAX_SANDBOX_ENTRIES,
                requested: grants.len(),
            });
        }
        let mut collected: Vec<PathGrant> = Vec::with_capacity(grants.len());
        for grant in grants {
            if collected.iter().any(|held| held.path == grant.path) {
                return Err(SandboxError::DuplicateEntry {
                    field: "path_grants",
                });
            }
            collected.push(grant.clone());
        }
        Ok(Self { grants: collected })
    }

    /// Every grant.
    #[must_use]
    pub fn as_slice(&self) -> &[PathGrant] {
        &self.grants
    }

    /// How many paths are granted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether nothing is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// The readable grants, which is every grant: a writable path is readable.
    pub fn readable(&self) -> impl Iterator<Item = &PathGrant> {
        self.grants.iter()
    }

    /// The writable grants.
    pub fn writable(&self) -> impl Iterator<Item = &PathGrant> {
        self.grants
            .iter()
            .filter(|grant| grant.access == PathAccess::ReadWrite)
    }

    /// Intersect with a requested set, keeping the lower access of each shared
    /// path.
    ///
    /// The result is always a subset of `self` at no higher access, so a
    /// request cannot use this to acquire a path or a mode the reviewed set
    /// does not already contain.
    #[must_use]
    pub fn narrowed_to(&self, requested: &Self) -> Self {
        let grants = self
            .grants
            .iter()
            .filter_map(|grant| {
                requested
                    .grants
                    .iter()
                    .find(|other| other.path == grant.path)
                    .map(|other| PathGrant {
                        path: grant.path.clone(),
                        access: grant.access.min(other.access),
                    })
            })
            .collect();
        Self { grants }
    }

    /// Whether every grant here is covered by `other` at the same or a higher
    /// access.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        self.grants.iter().all(|grant| {
            other
                .grants
                .iter()
                .any(|held| held.path == grant.path && held.access >= grant.access)
        })
    }

    fn compare(&self, other: &Self) -> ProfileOrdering {
        containment_ordering(self.is_within(other), other.is_within(self))
    }
}

/// How much of the filesystem a profile grants, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilesystemAccess {
    /// Nothing.
    None,
    /// A registered immutable snapshot, read-only.
    ReadOnlySnapshot,
    /// One isolated writable workspace.
    IsolatedWritable,
    /// A writable workspace plus declared artifact grants.
    WritableWithGrants,
}

impl FilesystemAccess {
    /// Whether the profile grants any read at all.
    #[must_use]
    pub const fn permits_read(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether the profile grants a write.
    #[must_use]
    pub const fn permits_write(self) -> bool {
        matches!(self, Self::IsolatedWritable | Self::WritableWithGrants)
    }
}

/// How much network a profile grants a tool workload, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkAccess {
    /// No network at all.
    Denied,
    /// Named destinations through the egress broker.
    BrokeredNamed,
    /// Any destination the broker permits.
    BrokeredAny,
}

/// Egress policy for the trusted provider-control channel.
///
/// Distinct from [`ToolWorkloadEgress`] by type, not by convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderControlEgress(NetworkAccess);

impl ProviderControlEgress {
    /// Deny all control-plane egress.
    #[must_use]
    pub const fn denied() -> Self {
        Self(NetworkAccess::Denied)
    }

    /// Permit brokered control-plane egress.
    #[must_use]
    pub const fn brokered(access: NetworkAccess) -> Self {
        Self(access)
    }

    /// The granted access.
    #[must_use]
    pub const fn access(self) -> NetworkAccess {
        self.0
    }
}

/// Egress policy for model-directed tool traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolWorkloadEgress(NetworkAccess);

impl ToolWorkloadEgress {
    /// Deny all tool egress.
    #[must_use]
    pub const fn denied() -> Self {
        Self(NetworkAccess::Denied)
    }

    /// Permit brokered tool egress.
    #[must_use]
    pub const fn brokered(access: NetworkAccess) -> Self {
        Self(access)
    }

    /// The granted access.
    #[must_use]
    pub const fn access(self) -> NetworkAccess {
        self.0
    }
}

/// How two profiles, or two whole specs, relate.
///
/// A partial order, not a boolean: two profiles can each grant something the
/// other does not, and calling that "not narrower" would license a reuse that
/// widens one axis while narrowing another.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProfileOrdering {
    /// Grants strictly less on every axis it differs on.
    Narrower,
    /// Grants exactly the same.
    Identical,
    /// Grants strictly more on every axis it differs on.
    Wider,
    /// Grants more on one axis and less on another.
    Incomparable,
}

impl ProfileOrdering {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Narrower => "narrower",
            Self::Identical => "identical",
            Self::Wider => "wider",
            Self::Incomparable => "incomparable",
        }
    }

    /// Combine two axis orderings into the ordering of the whole.
    ///
    /// Disagreeing axes produce [`ProfileOrdering::Incomparable`] rather than
    /// resolving to the more permissive of the two.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Incomparable, _) | (_, Self::Incomparable) => Self::Incomparable,
            (Self::Identical, kept) | (kept, Self::Identical) => kept,
            (Self::Narrower, Self::Narrower) => Self::Narrower,
            (Self::Wider, Self::Wider) => Self::Wider,
            _ => Self::Incomparable,
        }
    }
}

/// Order two values whose type already orders least-to-most authority.
fn value_ordering<T: Ord>(left: T, right: T) -> ProfileOrdering {
    match left.cmp(&right) {
        core::cmp::Ordering::Less => ProfileOrdering::Narrower,
        core::cmp::Ordering::Equal => ProfileOrdering::Identical,
        core::cmp::Ordering::Greater => ProfileOrdering::Wider,
    }
}

/// Turn two containment answers into a partial order.
const fn containment_ordering(left_within_right: bool, right_within_left: bool) -> ProfileOrdering {
    match (left_within_right, right_within_left) {
        (true, true) => ProfileOrdering::Identical,
        (true, false) => ProfileOrdering::Narrower,
        (false, true) => ProfileOrdering::Wider,
        (false, false) => ProfileOrdering::Incomparable,
    }
}

fn is_subset<T: PartialEq>(left: &[T], right: &[T]) -> bool {
    left.iter().all(|item| right.contains(item))
}

/// Order two grant sets: fewer entries is narrower.
fn subset_ordering<T: PartialEq>(left: &[T], right: &[T]) -> ProfileOrdering {
    containment_ordering(is_subset(left, right), is_subset(right, left))
}

/// Order two restriction sets: *more* entries is narrower.
fn superset_ordering<T: PartialEq>(left: &[T], right: &[T]) -> ProfileOrdering {
    containment_ordering(is_subset(right, left), is_subset(left, right))
}

/// A versioned sandbox profile.
///
/// Profiles are minimum contracts: a deployment may narrow one, but adding a
/// capability needs a new plan revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProfile {
    id: String,
    version: u32,
    filesystem: FilesystemAccess,
    tool_network: ToolWorkloadEgress,
}

impl SandboxProfile {
    /// Declare a profile.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid identifier.
    pub fn new(
        id: &str,
        version: u32,
        filesystem: FilesystemAccess,
        tool_network: ToolWorkloadEgress,
    ) -> Result<Self, SandboxError> {
        bounded(id, "profile_id")?;
        Ok(Self {
            id: id.to_owned(),
            version,
            filesystem,
            tool_network,
        })
    }

    /// Profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Profile version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The filesystem the profile grants.
    #[must_use]
    pub const fn filesystem(&self) -> FilesystemAccess {
        self.filesystem
    }

    /// The tool-workload egress the profile grants.
    #[must_use]
    pub const fn tool_network(&self) -> ToolWorkloadEgress {
        self.tool_network
    }

    /// Compare against another profile.
    #[must_use]
    pub fn compare(&self, other: &Self) -> ProfileOrdering {
        let filesystem = value_ordering(self.filesystem, other.filesystem);
        let network = value_ordering(self.tool_network.access(), other.tool_network.access());
        filesystem.combine(network)
    }
}

/// Which allowlist an entry belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AllowlistClass {
    /// An executable the workload may run.
    Executable,
    /// An interpreter the workload may run.
    Interpreter,
    /// A tool the workload may call.
    Tool,
    /// An MCP server the workload may reach.
    McpServer,
    /// A companion process the workload may start.
    Companion,
}

impl AllowlistClass {
    /// Every class.
    pub const ALL: [Self; 5] = [
        Self::Executable,
        Self::Interpreter,
        Self::Tool,
        Self::McpServer,
        Self::Companion,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Interpreter => "interpreter",
            Self::Tool => "tool",
            Self::McpServer => "mcp_server",
            Self::Companion => "companion",
        }
    }
}

/// One allowlisted subject and the class it is allowlisted for.
///
/// The class travels with the name, so an entry cannot be declared into the
/// wrong list by argument order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AllowlistEntry {
    class: AllowlistClass,
    name: SandboxName,
}

impl AllowlistEntry {
    /// Allowlist one subject.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid name.
    pub fn new(class: AllowlistClass, name: &str) -> Result<Self, SandboxError> {
        Ok(Self {
            class,
            name: SandboxName::new(name).map_err(|error| SandboxError::Field {
                field: "allowlist_entry",
                error,
            })?,
        })
    }

    /// The class this entry is allowlisted for.
    #[must_use]
    pub const fn class(&self) -> AllowlistClass {
        self.class
    }

    /// The allowlisted name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// The executable, interpreter, tool, MCP and companion allowlists.
///
/// A class with no entries permits nothing: the empty allowlist is the closed
/// one, so an omitted class cannot read as "anything goes".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionAllowlists {
    entries: Vec<AllowlistEntry>,
}

impl ExecutionAllowlists {
    /// Declare the allowlists.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`]
    /// and [`SandboxError::DuplicateEntry`] when one subject is allowlisted
    /// twice for the same class.
    pub fn declare(entries: &[AllowlistEntry]) -> Result<Self, SandboxError> {
        if entries.len() > MAX_SANDBOX_ENTRIES {
            return Err(SandboxError::TooManyEntries {
                field: "allowlists",
                max: MAX_SANDBOX_ENTRIES,
                requested: entries.len(),
            });
        }
        let mut collected: Vec<AllowlistEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            if collected.contains(entry) {
                return Err(SandboxError::DuplicateEntry {
                    field: "allowlists",
                });
            }
            collected.push(entry.clone());
        }
        Ok(Self { entries: collected })
    }

    /// Every entry, of every class.
    #[must_use]
    pub fn as_slice(&self) -> &[AllowlistEntry] {
        &self.entries
    }

    /// The entries of one class.
    #[must_use]
    pub fn class(&self, class: AllowlistClass) -> Vec<&AllowlistEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.class == class)
            .collect()
    }

    fn compare(&self, other: &Self) -> ProfileOrdering {
        subset_ordering(&self.entries, &other.entries)
    }
}

/// The exact process class allowed to receive a credential.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProcessClass {
    /// The trusted provider adapter.
    ProviderAdapter,
    /// A model-directed tool process.
    ToolProcess,
    /// An MCP server process.
    McpServer,
    /// A companion process.
    Companion,
    /// An extension worker.
    ExtensionWorker,
}

impl ProcessClass {
    /// Every class.
    pub const ALL: [Self; 5] = [
        Self::ProviderAdapter,
        Self::ToolProcess,
        Self::McpServer,
        Self::Companion,
        Self::ExtensionWorker,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderAdapter => "provider_adapter",
            Self::ToolProcess => "tool_process",
            Self::McpServer => "mcp_server",
            Self::Companion => "companion",
            Self::ExtensionWorker => "extension_worker",
        }
    }
}

/// A credential the spec permits, and the one process class allowed to receive
/// it.
///
/// The descriptor names a credential; it never carries its value, so a spec is
/// not a secret. The recipient is one class rather than a set, so "deliver to
/// whichever process asks" is not expressible.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialDescriptor {
    name: SandboxName,
    recipient: ProcessClass,
}

impl CredentialDescriptor {
    /// Describe one credential delivery.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid name.
    pub fn new(name: &str, recipient: ProcessClass) -> Result<Self, SandboxError> {
        Ok(Self {
            name: SandboxName::new(name).map_err(|error| SandboxError::Field {
                field: "credential_descriptor",
                error,
            })?,
            recipient,
        })
    }

    /// The credential's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The only process class allowed to receive it.
    #[must_use]
    pub const fn recipient(&self) -> ProcessClass {
        self.recipient
    }
}

/// Every credential descriptor of one spec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialDescriptors {
    descriptors: Vec<CredentialDescriptor>,
}

impl CredentialDescriptors {
    /// Declare the descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`]
    /// and [`SandboxError::DuplicateEntry`] when one credential is described
    /// twice, because two recipients for one credential is not "the exact
    /// process class".
    pub fn declare(descriptors: &[CredentialDescriptor]) -> Result<Self, SandboxError> {
        if descriptors.len() > MAX_SANDBOX_ENTRIES {
            return Err(SandboxError::TooManyEntries {
                field: "credential_descriptors",
                max: MAX_SANDBOX_ENTRIES,
                requested: descriptors.len(),
            });
        }
        let mut collected: Vec<CredentialDescriptor> = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            if collected.iter().any(|held| held.name == descriptor.name) {
                return Err(SandboxError::DuplicateEntry {
                    field: "credential_descriptors",
                });
            }
            collected.push(descriptor.clone());
        }
        Ok(Self {
            descriptors: collected,
        })
    }

    /// Every descriptor.
    #[must_use]
    pub fn as_slice(&self) -> &[CredentialDescriptor] {
        &self.descriptors
    }

    fn compare(&self, other: &Self) -> ProfileOrdering {
        subset_ordering(&self.descriptors, &other.descriptors)
    }
}

/// A budget's unit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BudgetUnit {
    /// Wall-clock milliseconds.
    Milliseconds,
    /// Bytes of memory.
    MemoryBytes,
    /// Thousandths of a CPU core.
    CpuMillicores,
    /// Process identifiers.
    Processes,
    /// Open file descriptors.
    FileDescriptors,
    /// Bytes of temporary storage.
    TempBytes,
    /// Bytes of spool.
    SpoolBytes,
    /// Bytes of artifact storage.
    ArtifactBytes,
}

impl BudgetUnit {
    /// Every unit.
    pub const ALL: [Self; 8] = [
        Self::Milliseconds,
        Self::MemoryBytes,
        Self::CpuMillicores,
        Self::Processes,
        Self::FileDescriptors,
        Self::TempBytes,
        Self::SpoolBytes,
        Self::ArtifactBytes,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "milliseconds",
            Self::MemoryBytes => "memory_bytes",
            Self::CpuMillicores => "cpu_millicores",
            Self::Processes => "processes",
            Self::FileDescriptors => "file_descriptors",
            Self::TempBytes => "temp_bytes",
            Self::SpoolBytes => "spool_bytes",
            Self::ArtifactBytes => "artifact_bytes",
        }
    }

    /// The declared ceiling for this unit.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        match self {
            Self::Milliseconds => 24 * 60 * 60 * 1_000,
            Self::MemoryBytes => 64 * 1024 * 1024 * 1024,
            Self::CpuMillicores => 64_000,
            Self::Processes => 4_096,
            Self::FileDescriptors => 65_536,
            Self::TempBytes => 512 * 1024 * 1024 * 1024,
            Self::SpoolBytes => 256 * 1024 * 1024 * 1024,
            Self::ArtifactBytes => 1024 * 1024 * 1024 * 1024,
        }
    }
}

/// A bounded resource reservation.
///
/// Carries its unit, so a unitless budget is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    unit: BudgetUnit,
    quantity: u64,
}

impl Budget {
    /// Reserve a quantity in a unit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::BudgetOutOfRange`] above the unit's ceiling.
    pub const fn new(unit: BudgetUnit, quantity: u64) -> Result<Self, SandboxError> {
        if quantity > unit.ceiling() {
            return Err(SandboxError::BudgetOutOfRange {
                unit: unit.as_str(),
                max: unit.ceiling(),
                requested: quantity,
            });
        }
        Ok(Self { unit, quantity })
    }

    /// The unit.
    #[must_use]
    pub const fn unit(self) -> BudgetUnit {
        self.unit
    }

    /// The reserved quantity.
    #[must_use]
    pub const fn quantity(self) -> u64 {
        self.quantity
    }
}

/// Every quantity a [`Budgets`] set needs, named at the call site.
///
/// Each name carries its unit, and each field is filled by
/// [`Budgets::declare`] with the unit that belongs to it, so a quantity cannot
/// reach the wrong budget through a positional argument list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetQuantities {
    /// cgroup memory ceiling, in bytes.
    pub cgroup_memory_bytes: u64,
    /// cgroup CPU quota, in thousandths of a core.
    pub cgroup_cpu_millicores: u64,
    /// rlimit on processes and threads.
    pub rlimit_processes: u64,
    /// rlimit on open file descriptors.
    pub rlimit_descriptors: u64,
    /// Bounded runtime, in milliseconds.
    pub timeout_millis: u64,
    /// Temporary-storage quota, in bytes.
    pub temporary_storage_bytes: u64,
    /// Spool quota, in bytes.
    pub spool_bytes: u64,
    /// Artifact quota, in bytes.
    pub artifact_bytes: u64,
}

/// The cgroup, rlimit, timeout, temporary-storage, spool and artifact budgets.
///
/// Every category is a field rather than an entry in a list, so a spec that
/// forgot one does not compile and admission never has to guess a default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budgets {
    cgroup_memory: Budget,
    cgroup_cpu: Budget,
    rlimit_processes: Budget,
    rlimit_descriptors: Budget,
    timeout: Budget,
    temporary_storage: Budget,
    spool: Budget,
    artifact: Budget,
}

impl Budgets {
    /// Declare every budget.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::BudgetOutOfRange`] naming the first unit whose
    /// quantity exceeds its ceiling.
    pub fn declare(quantities: BudgetQuantities) -> Result<Self, SandboxError> {
        Ok(Self {
            cgroup_memory: Budget::new(BudgetUnit::MemoryBytes, quantities.cgroup_memory_bytes)?,
            cgroup_cpu: Budget::new(BudgetUnit::CpuMillicores, quantities.cgroup_cpu_millicores)?,
            rlimit_processes: Budget::new(BudgetUnit::Processes, quantities.rlimit_processes)?,
            rlimit_descriptors: Budget::new(
                BudgetUnit::FileDescriptors,
                quantities.rlimit_descriptors,
            )?,
            timeout: Budget::new(BudgetUnit::Milliseconds, quantities.timeout_millis)?,
            temporary_storage: Budget::new(
                BudgetUnit::TempBytes,
                quantities.temporary_storage_bytes,
            )?,
            spool: Budget::new(BudgetUnit::SpoolBytes, quantities.spool_bytes)?,
            artifact: Budget::new(BudgetUnit::ArtifactBytes, quantities.artifact_bytes)?,
        })
    }

    /// The cgroup memory budget.
    #[must_use]
    pub const fn cgroup_memory(&self) -> Budget {
        self.cgroup_memory
    }

    /// The cgroup CPU budget.
    #[must_use]
    pub const fn cgroup_cpu(&self) -> Budget {
        self.cgroup_cpu
    }

    /// The process rlimit.
    #[must_use]
    pub const fn rlimit_processes(&self) -> Budget {
        self.rlimit_processes
    }

    /// The descriptor rlimit.
    #[must_use]
    pub const fn rlimit_descriptors(&self) -> Budget {
        self.rlimit_descriptors
    }

    /// The bounded runtime.
    #[must_use]
    pub const fn timeout(&self) -> Budget {
        self.timeout
    }

    /// The temporary-storage quota.
    #[must_use]
    pub const fn temporary_storage(&self) -> Budget {
        self.temporary_storage
    }

    /// The spool quota.
    #[must_use]
    pub const fn spool(&self) -> Budget {
        self.spool
    }

    /// The artifact quota.
    #[must_use]
    pub const fn artifact(&self) -> Budget {
        self.artifact
    }

    /// Every budget, in a fixed order.
    #[must_use]
    pub const fn all(&self) -> [Budget; 8] {
        [
            self.cgroup_memory,
            self.cgroup_cpu,
            self.rlimit_processes,
            self.rlimit_descriptors,
            self.timeout,
            self.temporary_storage,
            self.spool,
            self.artifact,
        ]
    }

    fn compare(&self, other: &Self) -> ProfileOrdering {
        let mut ordering = ProfileOrdering::Identical;
        for (mine, theirs) in self.all().into_iter().zip(other.all()) {
            ordering = ordering.combine(value_ordering(mine.quantity(), theirs.quantity()));
        }
        ordering
    }
}

/// A kernel or execution-backend feature the host must provide, and the
/// implementations the spec accepts for it.
///
/// An accepted-implementation set that nothing compares is decoration, so
/// [`SandboxSpec::admit_on`] refuses a host whose implementation digest is not
/// in this set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredFeature {
    name: SandboxName,
    accepted_implementations: Vec<ImplementationDigest>,
}

impl RequiredFeature {
    /// Require a feature.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid name or an empty accepted
    /// set — a feature no implementation satisfies could never be admitted —
    /// and [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`].
    pub fn new(
        name: &str,
        accepted_implementations: &[ImplementationDigest],
    ) -> Result<Self, SandboxError> {
        let name = SandboxName::new(name).map_err(|error| SandboxError::Field {
            field: "required_feature",
            error,
        })?;
        if accepted_implementations.is_empty() {
            return Err(SandboxError::Field {
                field: "accepted_implementations",
                error: ValueError::Empty,
            });
        }
        if accepted_implementations.len() > MAX_SANDBOX_ENTRIES {
            return Err(SandboxError::TooManyEntries {
                field: "accepted_implementations",
                max: MAX_SANDBOX_ENTRIES,
                requested: accepted_implementations.len(),
            });
        }
        Ok(Self {
            name,
            accepted_implementations: accepted_implementations.to_vec(),
        })
    }

    /// The feature's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The implementations this spec accepts.
    #[must_use]
    pub fn accepted_implementations(&self) -> &[ImplementationDigest] {
        &self.accepted_implementations
    }

    /// Whether an offered implementation is accepted.
    #[must_use]
    pub fn accepts(&self, implementation: &ImplementationDigest) -> bool {
        self.accepted_implementations.contains(implementation)
    }
}

/// Every feature a spec requires.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredFeatures {
    features: Vec<RequiredFeature>,
}

impl RequiredFeatures {
    /// Require a non-empty set of features.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an empty set — a spec requiring no
    /// enforcement would admit on a host that enforces nothing — plus
    /// [`SandboxError::TooManyEntries`] and [`SandboxError::DuplicateEntry`].
    pub fn declare(features: &[RequiredFeature]) -> Result<Self, SandboxError> {
        if features.is_empty() {
            return Err(SandboxError::Field {
                field: "required_features",
                error: ValueError::Empty,
            });
        }
        if features.len() > MAX_SANDBOX_ENTRIES {
            return Err(SandboxError::TooManyEntries {
                field: "required_features",
                max: MAX_SANDBOX_ENTRIES,
                requested: features.len(),
            });
        }
        let mut collected: Vec<RequiredFeature> = Vec::with_capacity(features.len());
        for feature in features {
            if collected.iter().any(|held| held.name == feature.name) {
                return Err(SandboxError::DuplicateEntry {
                    field: "required_features",
                });
            }
            collected.push(feature.clone());
        }
        Ok(Self {
            features: collected,
        })
    }

    /// Every required feature.
    #[must_use]
    pub fn as_slice(&self) -> &[RequiredFeature] {
        &self.features
    }

    /// Every accepted enforcement-implementation digest, of every feature.
    pub fn implementation_digests(&self) -> impl Iterator<Item = &ImplementationDigest> {
        self.features
            .iter()
            .flat_map(RequiredFeature::accepted_implementations)
    }

    fn find(&self, name: &str) -> Option<&RequiredFeature> {
        self.features.iter().find(|feature| feature.name() == name)
    }

    /// Requiring more features, or accepting fewer implementations of a shared
    /// one, is narrower.
    fn compare(&self, other: &Self) -> ProfileOrdering {
        let mine: Vec<&str> = self.features.iter().map(RequiredFeature::name).collect();
        let theirs: Vec<&str> = other.features.iter().map(RequiredFeature::name).collect();
        let mut ordering = superset_ordering(&mine, &theirs);
        for feature in &self.features {
            if let Some(counterpart) = other.find(feature.name()) {
                ordering = ordering.combine(subset_ordering(
                    &feature.accepted_implementations,
                    &counterpart.accepted_implementations,
                ));
            }
        }
        ordering
    }
}

/// A feature a host offers, and the implementation providing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostFeature {
    name: SandboxName,
    implementation: ImplementationDigest,
}

impl HostFeature {
    /// Offer a feature.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid name.
    pub fn new(name: &str, implementation: ImplementationDigest) -> Result<Self, SandboxError> {
        Ok(Self {
            name: SandboxName::new(name).map_err(|error| SandboxError::Field {
                field: "host_feature",
                error,
            })?,
            implementation,
        })
    }

    /// The offered feature's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The implementation providing it.
    #[must_use]
    pub const fn implementation(&self) -> &ImplementationDigest {
        &self.implementation
    }
}

/// How strictly a nested tool or extension process must be contained, ordered
/// least to most.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IsolationRequirement {
    /// Inside the execution host's own boundary.
    HostBoundary,
    /// In its own child process boundary.
    SeparateChildBoundary,
    /// In a disposable stronger-isolation boundary — a microVM or an
    /// independently isolated remote executor.
    StrongerIsolation,
}

impl IsolationRequirement {
    /// Every requirement.
    pub const ALL: [Self; 3] = [
        Self::HostBoundary,
        Self::SeparateChildBoundary,
        Self::StrongerIsolation,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBoundary => "host_boundary",
            Self::SeparateChildBoundary => "separate_child_boundary",
            Self::StrongerIsolation => "stronger_isolation",
        }
    }
}

/// What the spec requires of nested tool execution and of extensions.
///
/// The optional stronger-isolation requirement is the
/// [`IsolationRequirement::StrongerIsolation`] value of either field, so
/// "stronger isolation" is a level on the same ordered axis rather than a
/// separate flag that could disagree with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedIsolation {
    nested_tools: IsolationRequirement,
    extensions: IsolationRequirement,
}

impl NestedIsolation {
    /// Require nested containment.
    #[must_use]
    pub const fn new(nested_tools: IsolationRequirement, extensions: IsolationRequirement) -> Self {
        Self {
            nested_tools,
            extensions,
        }
    }

    /// What nested tool execution requires.
    #[must_use]
    pub const fn nested_tools(&self) -> IsolationRequirement {
        self.nested_tools
    }

    /// What extensions require.
    #[must_use]
    pub const fn extensions(&self) -> IsolationRequirement {
        self.extensions
    }

    fn compare(&self, other: &Self) -> ProfileOrdering {
        // A stricter requirement is narrower, so the ordering is reversed
        // against the value order.
        value_ordering(other.nested_tools, self.nested_tools)
            .combine(value_ordering(other.extensions, self.extensions))
    }
}

/// Capabilities that must not be present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProhibitedCapabilities {
    capabilities: Vec<SandboxName>,
}

impl ProhibitedCapabilities {
    /// Prohibit a set of capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid name,
    /// [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`] and
    /// [`SandboxError::DuplicateEntry`] for a repeated capability.
    pub fn declare(capabilities: &[&str]) -> Result<Self, SandboxError> {
        Ok(Self {
            capabilities: names(capabilities, "prohibited_capabilities")?,
        })
    }

    /// Every prohibited capability.
    #[must_use]
    pub fn as_slice(&self) -> &[SandboxName] {
        &self.capabilities
    }

    /// Prohibiting more is narrower.
    fn compare(&self, other: &Self) -> ProfileOrdering {
        superset_ordering(&self.capabilities, &other.capabilities)
    }
}

/// What went wrong inside a sandbox.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ViolationClass {
    /// The workload attempted something the policy forbids.
    PolicyViolation,
    /// A budget ran out.
    BudgetExhaustion,
    /// A kernel enforcement mechanism stopped working.
    EnforcementLoss,
    /// The recorded attestation no longer matches.
    AttestationMismatch,
}

impl ViolationClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::PolicyViolation,
        Self::BudgetExhaustion,
        Self::EnforcementLoss,
        Self::AttestationMismatch,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyViolation => "policy_violation",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::EnforcementLoss => "enforcement_loss",
            Self::AttestationMismatch => "attestation_mismatch",
        }
    }

    /// What happens when this class occurs.
    ///
    /// Every class has one. None of them is "continue", because a boundary that
    /// keeps running after it was violated is not a boundary.
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::PolicyViolation => Disposition::TerminateRun,
            Self::BudgetExhaustion => Disposition::TerminateRunAndRecord,
            Self::EnforcementLoss | Self::AttestationMismatch => Disposition::Quarantine,
        }
    }
}

/// What is done about a violation.
///
/// There is deliberately no `Continue` variant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Disposition {
    /// Stop the run.
    TerminateRun,
    /// Stop the run and record the exhausted budget.
    TerminateRunAndRecord,
    /// Freeze the host; only observation, reconciliation or cancellation.
    Quarantine,
}

impl Disposition {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminateRun => "terminate_run",
            Self::TerminateRunAndRecord => "terminate_run_and_record",
            Self::Quarantine => "quarantine",
        }
    }
}

/// Every field a [`SandboxSpec`] needs, named at the call site.
///
/// A struct rather than a positional argument list: several components share a
/// shape, and a caller that transposed two of them would compile cleanly while
/// compiling the wrong boundary. Naming them removes the hazard without making
/// any field optional, and the identity fields are domain-typed so the
/// transposition is a type error rather than a convention.
///
/// The type implements no `Default`, so `..Default::default()` cannot fill a
/// field the caller never considered, and every field is required. Omitting one
/// does not compile:
///
/// ```compile_fail
/// use automonique_protocol::identity::Actor;
/// use automonique_protocol::models::ProviderAccountId;
/// use automonique_protocol::primitives::Revision;
/// use automonique_protocol::sandbox::{
///     Budgets, CredentialDescriptors, ExecutionAllowlists, NestedIsolation, PathGrants,
///     PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeatures,
///     SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
/// };
/// # fn profile() -> SandboxProfile { unreachable!() }
/// # fn policy() -> PolicyDigest { unreachable!() }
/// # fn account() -> ProviderAccountId { unreachable!() }
/// # fn workspace() -> WorkspaceContextHash { unreachable!() }
/// # fn revision() -> Revision { unreachable!() }
/// # fn grants() -> PathGrants { unreachable!() }
/// # fn allowlists() -> ExecutionAllowlists { unreachable!() }
/// # fn credentials() -> CredentialDescriptors { unreachable!() }
/// # fn budgets() -> Budgets { unreachable!() }
/// # fn features() -> RequiredFeatures { unreachable!() }
/// # fn isolation() -> NestedIsolation { unreachable!() }
/// # fn prohibited() -> ProhibitedCapabilities { unreachable!() }
/// let compiled = SandboxSpec::compile(SandboxSpecParts {
///     profile: profile(),
///     policy_digest: policy(),
///     provider_account: account(),
///     workspace_context: workspace(),
///     base_revision: revision(),
///     path_grants: grants(),
///     allowlists: allowlists(),
///     provider_control_egress: ProviderControlEgress::denied(),
///     tool_workload_egress: ToolWorkloadEgress::denied(),
///     credentials: credentials(),
///     budgets: budgets(),
///     required_features: features(),
///     nested_isolation: isolation(),
///     approval_revision: revision(),
///     prohibited_capabilities: prohibited(),
/// });
/// ```
///
/// The complete literal, which differs from the case above by exactly the
/// `actor` line, compiles:
///
/// ```no_run
/// use automonique_protocol::identity::Actor;
/// use automonique_protocol::models::ProviderAccountId;
/// use automonique_protocol::primitives::Revision;
/// use automonique_protocol::sandbox::{
///     Budgets, CredentialDescriptors, ExecutionAllowlists, NestedIsolation, PathGrants,
///     PolicyDigest, ProhibitedCapabilities, ProviderControlEgress, RequiredFeatures,
///     SandboxProfile, SandboxSpec, SandboxSpecParts, ToolWorkloadEgress, WorkspaceContextHash,
/// };
/// # fn profile() -> SandboxProfile { unreachable!() }
/// # fn policy() -> PolicyDigest { unreachable!() }
/// # fn actor() -> Actor { unreachable!() }
/// # fn account() -> ProviderAccountId { unreachable!() }
/// # fn workspace() -> WorkspaceContextHash { unreachable!() }
/// # fn revision() -> Revision { unreachable!() }
/// # fn grants() -> PathGrants { unreachable!() }
/// # fn allowlists() -> ExecutionAllowlists { unreachable!() }
/// # fn credentials() -> CredentialDescriptors { unreachable!() }
/// # fn budgets() -> Budgets { unreachable!() }
/// # fn features() -> RequiredFeatures { unreachable!() }
/// # fn isolation() -> NestedIsolation { unreachable!() }
/// # fn prohibited() -> ProhibitedCapabilities { unreachable!() }
/// let compiled = SandboxSpec::compile(SandboxSpecParts {
///     profile: profile(),
///     policy_digest: policy(),
///     actor: actor(),
///     provider_account: account(),
///     workspace_context: workspace(),
///     base_revision: revision(),
///     path_grants: grants(),
///     allowlists: allowlists(),
///     provider_control_egress: ProviderControlEgress::denied(),
///     tool_workload_egress: ToolWorkloadEgress::denied(),
///     credentials: credentials(),
///     budgets: budgets(),
///     required_features: features(),
///     nested_isolation: isolation(),
///     approval_revision: revision(),
///     prohibited_capabilities: prohibited(),
/// });
/// ```
#[derive(Clone, Debug)]
pub struct SandboxSpecParts {
    /// The profile this spec compiles from.
    pub profile: SandboxProfile,
    /// The complete policy digest.
    pub policy_digest: PolicyDigest,
    /// The acting principal, which carries its own tenant, so the spec's tenant
    /// and its actor cannot disagree.
    pub actor: Actor,
    /// The provider account.
    pub provider_account: ProviderAccountId,
    /// The workspace security-context hash.
    pub workspace_context: WorkspaceContextHash,
    /// The immutable base revision the workspace was provisioned from.
    pub base_revision: Revision,
    /// Readable and writable path grants.
    pub path_grants: PathGrants,
    /// Executable, interpreter, tool, MCP and companion allowlists.
    pub allowlists: ExecutionAllowlists,
    /// Egress for the trusted provider-control channel.
    pub provider_control_egress: ProviderControlEgress,
    /// Egress for model-directed tool traffic.
    pub tool_workload_egress: ToolWorkloadEgress,
    /// Credential descriptors and their exact recipient process class.
    pub credentials: CredentialDescriptors,
    /// cgroup, rlimit, timeout, temporary-storage, spool and artifact budgets.
    pub budgets: Budgets,
    /// Kernel and backend features, with the implementations accepted for each.
    pub required_features: RequiredFeatures,
    /// Nested tool-execution and extension isolation requirements.
    pub nested_isolation: NestedIsolation,
    /// The approval and policy revision this spec was reviewed under.
    pub approval_revision: Revision,
    /// Capabilities that must not be present.
    pub prohibited_capabilities: ProhibitedCapabilities,
}

/// An immutable compiled sandbox specification.
///
/// Every field is a constructor argument, so a spec cannot be built without
/// one, and there is no setter, so it cannot be changed after compilation:
///
/// ```compile_fail
/// use automonique_protocol::identity::Actor;
/// use automonique_protocol::sandbox::SandboxSpec;
/// # fn spec() -> SandboxSpec { unreachable!() }
/// let mut compiled = spec();
/// compiled.actor = Actor::new("globex", "mallory").unwrap();
/// ```
///
/// Reading the same field, which differs only in being a read rather than a
/// write, compiles:
///
/// ```no_run
/// use automonique_protocol::sandbox::SandboxSpec;
/// # fn spec() -> SandboxSpec { unreachable!() }
/// let compiled = spec();
/// let actor = compiled.actor();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSpec {
    profile: SandboxProfile,
    policy_digest: PolicyDigest,
    actor: Actor,
    provider_account: ProviderAccountId,
    workspace_context: WorkspaceContextHash,
    base_revision: Revision,
    path_grants: PathGrants,
    allowlists: ExecutionAllowlists,
    provider_control_egress: ProviderControlEgress,
    tool_workload_egress: ToolWorkloadEgress,
    credentials: CredentialDescriptors,
    budgets: Budgets,
    required_features: RequiredFeatures,
    nested_isolation: NestedIsolation,
    approval_revision: Revision,
    prohibited_capabilities: ProhibitedCapabilities,
}

impl SandboxSpec {
    /// Compile a specification.
    ///
    /// Every component validated itself when it was constructed, so what is
    /// left to check here is the relationship between them: a profile is a
    /// minimum contract, and a spec that granted more than its profile would be
    /// a capability added without a new plan revision.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::WidensProfile`] naming the axis on which the
    /// spec exceeds its profile.
    pub fn compile(parts: SandboxSpecParts) -> Result<Self, SandboxError> {
        if parts.tool_workload_egress.access() > parts.profile.tool_network.access() {
            return Err(SandboxError::WidensProfile {
                axis: "tool_workload_egress",
            });
        }
        if !parts.profile.filesystem.permits_read() && !parts.path_grants.is_empty() {
            return Err(SandboxError::WidensProfile {
                axis: "path_grants",
            });
        }
        if !parts.profile.filesystem.permits_write() && parts.path_grants.writable().count() > 0 {
            return Err(SandboxError::WidensProfile {
                axis: "path_grants",
            });
        }
        Ok(Self {
            profile: parts.profile,
            policy_digest: parts.policy_digest,
            actor: parts.actor,
            provider_account: parts.provider_account,
            workspace_context: parts.workspace_context,
            base_revision: parts.base_revision,
            path_grants: parts.path_grants,
            allowlists: parts.allowlists,
            provider_control_egress: parts.provider_control_egress,
            tool_workload_egress: parts.tool_workload_egress,
            credentials: parts.credentials,
            budgets: parts.budgets,
            required_features: parts.required_features,
            nested_isolation: parts.nested_isolation,
            approval_revision: parts.approval_revision,
            prohibited_capabilities: parts.prohibited_capabilities,
        })
    }

    /// The profile this spec compiled from.
    #[must_use]
    pub const fn profile(&self) -> &SandboxProfile {
        &self.profile
    }

    /// The complete policy digest.
    #[must_use]
    pub const fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    /// The owning tenant.
    ///
    /// Read from the actor, which cannot exist without one, so there is no
    /// state in which the spec's tenant and its actor's tenant differ.
    #[must_use]
    pub fn tenant(&self) -> &str {
        self.actor.tenant()
    }

    /// The acting principal.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The provider account.
    #[must_use]
    pub const fn provider_account(&self) -> &ProviderAccountId {
        &self.provider_account
    }

    /// The workspace security-context hash.
    #[must_use]
    pub const fn workspace_context(&self) -> &WorkspaceContextHash {
        &self.workspace_context
    }

    /// The immutable base revision.
    #[must_use]
    pub const fn base_revision(&self) -> Revision {
        self.base_revision
    }

    /// The readable and writable path grants.
    #[must_use]
    pub const fn path_grants(&self) -> &PathGrants {
        &self.path_grants
    }

    /// The executable, interpreter, tool, MCP and companion allowlists.
    #[must_use]
    pub const fn allowlists(&self) -> &ExecutionAllowlists {
        &self.allowlists
    }

    /// The tool allowlist.
    #[must_use]
    pub fn tool_allowlist(&self) -> Vec<&AllowlistEntry> {
        self.allowlists.class(AllowlistClass::Tool)
    }

    /// The control-plane egress policy.
    #[must_use]
    pub const fn provider_control_egress(&self) -> ProviderControlEgress {
        self.provider_control_egress
    }

    /// The tool-workload egress policy.
    #[must_use]
    pub const fn tool_workload_egress(&self) -> ToolWorkloadEgress {
        self.tool_workload_egress
    }

    /// The credential descriptors and their permitted recipient classes.
    #[must_use]
    pub fn credential_descriptors(&self) -> &[CredentialDescriptor] {
        self.credentials.as_slice()
    }

    /// The declared budgets.
    #[must_use]
    pub const fn budgets(&self) -> &Budgets {
        &self.budgets
    }

    /// The features the host must provide.
    #[must_use]
    pub fn required_features(&self) -> &[RequiredFeature] {
        self.required_features.as_slice()
    }

    /// Every accepted enforcement-implementation digest.
    pub fn enforcement_implementation_digests(
        &self,
    ) -> impl Iterator<Item = &ImplementationDigest> {
        self.required_features.implementation_digests()
    }

    /// The nested tool-execution and extension isolation requirements.
    #[must_use]
    pub const fn nested_isolation(&self) -> NestedIsolation {
        self.nested_isolation
    }

    /// The approval and policy revision.
    #[must_use]
    pub const fn approval_revision(&self) -> Revision {
        self.approval_revision
    }

    /// Capabilities that must not be present.
    #[must_use]
    pub fn prohibited_capabilities(&self) -> &[SandboxName] {
        self.prohibited_capabilities.as_slice()
    }

    /// Compare how much authority this spec grants against another.
    ///
    /// Identity — tenant, actor, provider account, workspace context — is not
    /// an axis of this order: two specs for different principals are not
    /// narrower or wider than one another, they are different subjects, which
    /// [`evaluate_reuse`] handles separately. Policy is compared structurally
    /// rather than by digest, because a new policy digest granting strictly
    /// less is exactly the narrowing the reuse rule permits.
    #[must_use]
    pub fn compare_authority(&self, other: &Self) -> ProfileOrdering {
        self.profile
            .compare(&other.profile)
            .combine(value_ordering(
                self.provider_control_egress.access(),
                other.provider_control_egress.access(),
            ))
            .combine(value_ordering(
                self.tool_workload_egress.access(),
                other.tool_workload_egress.access(),
            ))
            .combine(self.path_grants.compare(&other.path_grants))
            .combine(self.allowlists.compare(&other.allowlists))
            .combine(self.credentials.compare(&other.credentials))
            .combine(self.budgets.compare(&other.budgets))
            .combine(self.required_features.compare(&other.required_features))
            .combine(self.nested_isolation.compare(&other.nested_isolation))
            .combine(
                self.prohibited_capabilities
                    .compare(&other.prohibited_capabilities),
            )
    }

    /// Negotiate this spec against the features a host offers.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::RequiredEnforcementMissing`] naming the first
    /// absent feature, or [`SandboxError::EnforcementImplementationRejected`]
    /// when the host provides one through an implementation this spec does not
    /// accept. There is no return value representing a weaker profile, so there
    /// is no silent downgrade to reach.
    pub fn admit_on(&self, offered: &[HostFeature]) -> Result<(), SandboxError> {
        for required in self.required_features.as_slice() {
            let Some(offer) = offered
                .iter()
                .find(|candidate| candidate.name() == required.name())
            else {
                return Err(SandboxError::RequiredEnforcementMissing {
                    feature: required.name().to_owned(),
                });
            };
            if !required.accepts(offer.implementation()) {
                return Err(SandboxError::EnforcementImplementationRejected {
                    feature: required.name().to_owned(),
                    offered: offer.implementation().to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Whether an existing host may serve a new request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseOutcome {
    /// The request is identical or narrower; the host may be reused.
    Reuse,
    /// The request widens something; a new reviewed plan and host are needed.
    RequiresNewHost,
}

/// Decide whether a host running `existing` may serve `requested`.
///
/// Only identical or narrower requests reuse. Anything else — wider, or
/// incomparable — requires a new host, because an incomparable request widens
/// at least one axis. A different tenant, actor, provider account or workspace
/// context is not a narrowing at all and never reuses.
#[must_use]
pub fn evaluate_reuse(existing: &SandboxSpec, requested: &SandboxSpec) -> ReuseOutcome {
    // `is_same_as` refuses to answer across tenants rather than returning
    // `false`, so a cross-tenant pair is "not provably the same principal",
    // which is the conservative answer here and never claims sameness.
    let same_principal = existing.actor.is_same_as(&requested.actor).unwrap_or(false);
    if !same_principal
        || existing.provider_account != requested.provider_account
        || existing.workspace_context != requested.workspace_context
    {
        return ReuseOutcome::RequiresNewHost;
    }
    match requested.compare_authority(existing) {
        ProfileOrdering::Narrower | ProfileOrdering::Identical => ReuseOutcome::Reuse,
        ProfileOrdering::Wider | ProfileOrdering::Incomparable => ReuseOutcome::RequiresNewHost,
    }
}

/// A kind of Linux namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NamespaceKind {
    /// Mount namespace.
    Mount,
    /// PID namespace.
    Pid,
    /// Network namespace.
    Network,
    /// User namespace.
    User,
    /// IPC namespace.
    Ipc,
    /// UTS namespace.
    Uts,
    /// cgroup namespace.
    Cgroup,
}

impl NamespaceKind {
    /// Every kind.
    pub const ALL: [Self; 7] = [
        Self::Mount,
        Self::Pid,
        Self::Network,
        Self::User,
        Self::Ipc,
        Self::Uts,
        Self::Cgroup,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Pid => "pid",
            Self::Network => "network",
            Self::User => "user",
            Self::Ipc => "ipc",
            Self::Uts => "uts",
            Self::Cgroup => "cgroup",
        }
    }
}

/// One namespace a host actually entered, identified by kind and inode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NamespaceIdentity {
    kind: NamespaceKind,
    inode: NonZeroU64,
}

impl NamespaceIdentity {
    /// Record one namespace.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotPositive`] for inode zero, which no namespace
    /// has.
    pub const fn new(kind: NamespaceKind, inode: u64) -> Result<Self, SandboxError> {
        match NonZeroU64::new(inode) {
            Some(inode) => Ok(Self { kind, inode }),
            None => Err(SandboxError::NotPositive {
                field: "namespace_inode",
            }),
        }
    }

    /// The kind of namespace.
    #[must_use]
    pub const fn kind(self) -> NamespaceKind {
        self.kind
    }

    /// The namespace inode.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode.get()
    }
}

/// The process group a host's descendants belong to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcessGroupId(NonZeroU32);

impl ProcessGroupId {
    /// Record a process group.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotPositive`] for zero, which is not a process
    /// group but the caller's own in most kernel interfaces.
    pub const fn new(id: u32) -> Result<Self, SandboxError> {
        match NonZeroU32::new(id) {
            Some(id) => Ok(Self(id)),
            None => Err(SandboxError::NotPositive {
                field: "process_group",
            }),
        }
    }

    /// The process-group identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// The Landlock ABI a host enforced under.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct LandlockAbi(NonZeroU8);

impl LandlockAbi {
    /// Record an ABI version.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::NotPositive`] for zero, which the kernel reports
    /// when Landlock is unavailable — an attestation cannot claim it enforced
    /// under an absent ABI.
    pub const fn new(version: u8) -> Result<Self, SandboxError> {
        match NonZeroU8::new(version) {
            Some(version) => Ok(Self(version)),
            None => Err(SandboxError::NotPositive {
                field: "landlock_abi",
            }),
        }
    }

    /// The ABI version.
    #[must_use]
    pub const fn version(self) -> u8 {
        self.0.get()
    }
}

/// The Landlock ABI and ruleset a host enforced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LandlockAttestation {
    abi: LandlockAbi,
    ruleset_digest: LandlockRulesetDigest,
}

impl LandlockAttestation {
    /// Record Landlock enforcement.
    #[must_use]
    pub const fn new(abi: LandlockAbi, ruleset_digest: LandlockRulesetDigest) -> Self {
        Self {
            abi,
            ruleset_digest,
        }
    }

    /// The ABI.
    #[must_use]
    pub const fn abi(&self) -> LandlockAbi {
        self.abi
    }

    /// The ruleset digest.
    #[must_use]
    pub const fn ruleset_digest(&self) -> &LandlockRulesetDigest {
        &self.ruleset_digest
    }
}

/// An effective optional-supervisor property.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SupervisorProperty {
    /// `NoNewPrivileges` was set.
    NoNewPrivileges,
    /// The capability bounding set was restricted.
    CapabilityBounding,
    /// A restrictive umask was applied.
    RestrictiveUmask,
    /// A private temporary directory was provided.
    PrivateTmp,
    /// A private runtime directory was provided.
    PrivateRuntimeDir,
    /// A private device view was provided.
    PrivateDevices,
}

impl SupervisorProperty {
    /// Every property.
    pub const ALL: [Self; 6] = [
        Self::NoNewPrivileges,
        Self::CapabilityBounding,
        Self::RestrictiveUmask,
        Self::PrivateTmp,
        Self::PrivateRuntimeDir,
        Self::PrivateDevices,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoNewPrivileges => "no_new_privileges",
            Self::CapabilityBounding => "capability_bounding",
            Self::RestrictiveUmask => "restrictive_umask",
            Self::PrivateTmp => "private_tmp",
            Self::PrivateRuntimeDir => "private_runtime_dir",
            Self::PrivateDevices => "private_devices",
        }
    }
}

/// How a credential reached the process class entitled to it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialDelivery {
    /// A sealed inherited descriptor.
    SealedDescriptor,
    /// An equivalent one-time protected mechanism.
    OneTimeProtected,
    /// An optional supervisor credential store.
    SupervisorStore,
    /// An ordinary environment variable.
    EnvironmentVariable,
}

impl CredentialDelivery {
    /// Every mode.
    pub const ALL: [Self; 4] = [
        Self::SealedDescriptor,
        Self::OneTimeProtected,
        Self::SupervisorStore,
        Self::EnvironmentVariable,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SealedDescriptor => "sealed_descriptor",
            Self::OneTimeProtected => "one_time_protected",
            Self::SupervisorStore => "supervisor_store",
            Self::EnvironmentVariable => "environment_variable",
        }
    }
}

/// A verified external-daemon context, when the host used one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalDaemonContext {
    daemon: SandboxName,
    attested_context: ExternalDaemonDigest,
}

impl ExternalDaemonContext {
    /// Record a verified external daemon.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid daemon name.
    pub fn new(daemon: &str, attested_context: ExternalDaemonDigest) -> Result<Self, SandboxError> {
        Ok(Self {
            daemon: SandboxName::new(daemon).map_err(|error| SandboxError::Field {
                field: "external_daemon",
                error,
            })?,
            attested_context,
        })
    }

    /// The daemon's name.
    #[must_use]
    pub fn daemon(&self) -> &str {
        self.daemon.as_str()
    }

    /// The digest of the context it attested.
    #[must_use]
    pub const fn attested_context(&self) -> &ExternalDaemonDigest {
        &self.attested_context
    }
}

/// Every field an [`EnforcementAttestation`] needs, named at the call site.
///
/// Same shape as [`SandboxSpecParts`] and for the same reason: three of these
/// are digests, and a transposed pair would record a boundary that was never
/// enforced. The digests are domain-typed, so the transposition does not
/// compile.
#[derive(Clone, Debug)]
pub struct EnforcementAttestationParts<'a> {
    /// The resolved real paths the host exposed.
    pub resolved_paths: &'a [SandboxPath],
    /// The namespaces it entered.
    pub namespaces: &'a [NamespaceIdentity],
    /// The process group its descendants belong to.
    pub process_group: ProcessGroupId,
    /// The cgroup it ran under.
    pub cgroup: CgroupId,
    /// The execution backend that launched it.
    pub backend: ExecutionBackendId,
    /// The kernel and boot it ran on.
    pub kernel_boot: KernelBootId,
    /// The optional-supervisor properties that were actually effective.
    pub supervisor_properties: &'a [SupervisorProperty],
    /// The Landlock ABI and ruleset it enforced.
    pub landlock: LandlockAttestation,
    /// The seccomp filter it loaded.
    pub seccomp_digest: SeccompDigest,
    /// The egress policy it applied.
    pub egress_digest: EgressPolicyDigest,
    /// How credentials reached their entitled process class.
    pub credential_delivery: CredentialDelivery,
    /// The verified external-daemon context, when one was used.
    pub external_daemon: Option<ExternalDaemonContext>,
}

/// What a host recorded about its actual enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementAttestation {
    resolved_paths: Vec<SandboxPath>,
    namespaces: Vec<NamespaceIdentity>,
    process_group: ProcessGroupId,
    cgroup: CgroupId,
    backend: ExecutionBackendId,
    kernel_boot: KernelBootId,
    supervisor_properties: Vec<SupervisorProperty>,
    landlock: LandlockAttestation,
    seccomp_digest: SeccompDigest,
    egress_digest: EgressPolicyDigest,
    credential_delivery: CredentialDelivery,
    external_daemon: Option<ExternalDaemonContext>,
}

impl EnforcementAttestation {
    /// Every field adoption compares, in comparison order.
    pub const COMPARED_FIELDS: [&'static str; 12] = [
        "resolved_paths",
        "namespaces",
        "process_group",
        "cgroup",
        "backend",
        "kernel_boot",
        "supervisor_properties",
        "landlock",
        "seccomp_digest",
        "egress_digest",
        "credential_delivery",
        "external_daemon",
    ];

    /// Record what a host actually enforced.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::TooManyEntries`] above [`MAX_SANDBOX_ENTRIES`]
    /// and [`SandboxError::DuplicateEntry`] for a repeated path, a second
    /// namespace of one kind — a process is in exactly one namespace per kind —
    /// or a repeated supervisor property.
    pub fn record(parts: EnforcementAttestationParts<'_>) -> Result<Self, SandboxError> {
        bounded_len(parts.resolved_paths.len(), "resolved_paths")?;
        bounded_len(parts.namespaces.len(), "namespaces")?;
        bounded_len(parts.supervisor_properties.len(), "supervisor_properties")?;
        let mut resolved_paths: Vec<SandboxPath> = Vec::with_capacity(parts.resolved_paths.len());
        for path in parts.resolved_paths {
            if resolved_paths.contains(path) {
                return Err(SandboxError::DuplicateEntry {
                    field: "resolved_paths",
                });
            }
            resolved_paths.push(path.clone());
        }
        let mut namespaces: Vec<NamespaceIdentity> = Vec::with_capacity(parts.namespaces.len());
        for namespace in parts.namespaces {
            if namespaces.iter().any(|held| held.kind == namespace.kind) {
                return Err(SandboxError::DuplicateEntry {
                    field: "namespaces",
                });
            }
            namespaces.push(*namespace);
        }
        let mut supervisor_properties: Vec<SupervisorProperty> =
            Vec::with_capacity(parts.supervisor_properties.len());
        for property in parts.supervisor_properties {
            if supervisor_properties.contains(property) {
                return Err(SandboxError::DuplicateEntry {
                    field: "supervisor_properties",
                });
            }
            supervisor_properties.push(*property);
        }
        Ok(Self {
            resolved_paths,
            namespaces,
            process_group: parts.process_group,
            cgroup: parts.cgroup,
            backend: parts.backend,
            kernel_boot: parts.kernel_boot,
            supervisor_properties,
            landlock: parts.landlock,
            seccomp_digest: parts.seccomp_digest,
            egress_digest: parts.egress_digest,
            credential_delivery: parts.credential_delivery,
            external_daemon: parts.external_daemon,
        })
    }

    /// The resolved real paths.
    #[must_use]
    pub fn resolved_paths(&self) -> &[SandboxPath] {
        &self.resolved_paths
    }

    /// The namespaces entered.
    #[must_use]
    pub fn namespaces(&self) -> &[NamespaceIdentity] {
        &self.namespaces
    }

    /// The process group.
    #[must_use]
    pub const fn process_group(&self) -> ProcessGroupId {
        self.process_group
    }

    /// The cgroup.
    #[must_use]
    pub const fn cgroup(&self) -> &CgroupId {
        &self.cgroup
    }

    /// The execution backend.
    #[must_use]
    pub const fn backend(&self) -> &ExecutionBackendId {
        &self.backend
    }

    /// The kernel and boot identity.
    #[must_use]
    pub const fn kernel_boot(&self) -> &KernelBootId {
        &self.kernel_boot
    }

    /// The effective optional-supervisor properties.
    #[must_use]
    pub fn supervisor_properties(&self) -> &[SupervisorProperty] {
        &self.supervisor_properties
    }

    /// The Landlock attestation.
    #[must_use]
    pub const fn landlock(&self) -> &LandlockAttestation {
        &self.landlock
    }

    /// The Landlock ABI.
    #[must_use]
    pub const fn landlock_abi(&self) -> LandlockAbi {
        self.landlock.abi()
    }

    /// The Landlock ruleset digest.
    #[must_use]
    pub const fn landlock_ruleset_digest(&self) -> &LandlockRulesetDigest {
        self.landlock.ruleset_digest()
    }

    /// The seccomp filter digest.
    #[must_use]
    pub const fn seccomp_digest(&self) -> &SeccompDigest {
        &self.seccomp_digest
    }

    /// The egress-policy digest.
    #[must_use]
    pub const fn egress_digest(&self) -> &EgressPolicyDigest {
        &self.egress_digest
    }

    /// How credentials were delivered.
    #[must_use]
    pub const fn credential_delivery_mode(&self) -> CredentialDelivery {
        self.credential_delivery
    }

    /// The verified external-daemon context, when one was used.
    #[must_use]
    pub const fn external_daemon(&self) -> Option<&ExternalDaemonContext> {
        self.external_daemon.as_ref()
    }

    /// The first field in which the observed attestation differs from this one.
    ///
    /// The body destructures `self` exhaustively and without `..`, so a field
    /// added to the type later does not compile until it is compared here. A
    /// field adoption does not compare is a field an attacker can vary freely.
    fn first_difference(&self, observed: &Self) -> Option<&'static str> {
        let Self {
            resolved_paths,
            namespaces,
            process_group,
            cgroup,
            backend,
            kernel_boot,
            supervisor_properties,
            landlock,
            seccomp_digest,
            egress_digest,
            credential_delivery,
            external_daemon,
        } = self;
        if *resolved_paths != observed.resolved_paths {
            return Some("resolved_paths");
        }
        if *namespaces != observed.namespaces {
            return Some("namespaces");
        }
        if *process_group != observed.process_group {
            return Some("process_group");
        }
        if *cgroup != observed.cgroup {
            return Some("cgroup");
        }
        if *backend != observed.backend {
            return Some("backend");
        }
        if *kernel_boot != observed.kernel_boot {
            return Some("kernel_boot");
        }
        if *supervisor_properties != observed.supervisor_properties {
            return Some("supervisor_properties");
        }
        if *landlock != observed.landlock {
            return Some("landlock");
        }
        if *seccomp_digest != observed.seccomp_digest {
            return Some("seccomp_digest");
        }
        if *egress_digest != observed.egress_digest {
            return Some("egress_digest");
        }
        if *credential_delivery != observed.credential_delivery {
            return Some("credential_delivery");
        }
        if *external_daemon != observed.external_daemon {
            return Some("external_daemon");
        }
        None
    }
}

/// The only operations a quarantined host permits.
///
/// A closed set: there is no variant for resuming, delivering provider input or
/// starting a turn, so those are not operations that can be named, let alone
/// performed.
///
/// ```compile_fail
/// use automonique_protocol::sandbox::QuarantinedOperation;
/// let operation = QuarantinedOperation::ResumeProvider;
/// ```
///
/// A permitted operation, differing only in which one is named, compiles:
///
/// ```
/// use automonique_protocol::sandbox::QuarantinedOperation;
/// let operation = QuarantinedOperation::Observe;
/// assert_eq!(operation.as_str(), "observe");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuarantinedOperation {
    /// Bounded observation of the frozen host.
    Observe,
    /// Reconciliation of its recorded state.
    Reconcile,
    /// Cancellation of its work.
    Cancel,
}

impl QuarantinedOperation {
    /// Every permitted operation.
    pub const ALL: [Self; 3] = [Self::Observe, Self::Reconcile, Self::Cancel];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Reconcile => "reconcile",
            Self::Cancel => "cancel",
        }
    }
}

/// Why a host was quarantined.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuarantineReason {
    /// Neither a recorded nor an observed enforcement object exists.
    NothingAttested,
    /// Nothing was recorded, so an observation has nothing to be checked
    /// against.
    NoRecordedAttestation,
    /// The recorded enforcement object is not present on the host.
    NoObservedAttestation,
    /// A recorded field does not match the observed one.
    Mismatch {
        /// The field that differs.
        field: &'static str,
    },
}

impl QuarantineReason {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::NothingAttested => "nothing_attested",
            Self::NoRecordedAttestation => "no_recorded_attestation",
            Self::NoObservedAttestation => "no_observed_attestation",
            Self::Mismatch { .. } => "mismatch",
        }
    }
}

/// A frozen host, carrying the only operations it permits.
///
/// The restriction is the value, not a comment on it: a caller holding this
/// type can read the permitted set, and the set's element type has no variant
/// for anything else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuarantinedHost {
    reason: QuarantineReason,
}

impl QuarantinedHost {
    /// The operations any quarantined host permits.
    pub const PERMITTED_OPERATIONS: [QuarantinedOperation; 3] = QuarantinedOperation::ALL;

    /// Why it was quarantined.
    #[must_use]
    pub const fn reason(&self) -> QuarantineReason {
        self.reason
    }

    /// The operations this host permits.
    #[must_use]
    pub const fn permitted_operations(&self) -> [QuarantinedOperation; 3] {
        Self::PERMITTED_OPERATIONS
    }
}

/// A host whose recorded attestation matched what was observed.
///
/// It borrows the *recorded* attestation. There is no public constructor, so
/// there is no path from an observation to an adopted host that does not go
/// through [`adopt_host`] and its comparison:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::{AdoptedHost, EnforcementAttestation};
/// # fn observed() -> EnforcementAttestation { unreachable!() }
/// let host = AdoptedHost::new(&observed());
/// ```
///
/// The comparison that does produce one, differing only in going through
/// [`adopt_host`], compiles:
///
/// ```no_run
/// use automonique_protocol::sandbox::{EnforcementAttestation, adopt_host};
/// # fn observed() -> EnforcementAttestation { unreachable!() }
/// let recorded = observed();
/// let outcome = adopt_host(Some(&recorded), Some(&recorded));
/// assert!(outcome.adopted().is_some());
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdoptedHost<'a> {
    attestation: &'a EnforcementAttestation,
}

impl<'a> AdoptedHost<'a> {
    /// The recorded attestation the host was adopted against.
    #[must_use]
    pub const fn attestation(&self) -> &'a EnforcementAttestation {
        self.attestation
    }
}

/// What a reload decided about an existing host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionOutcome<'a> {
    /// The attestation matched; the host is adopted.
    Adopted(AdoptedHost<'a>),
    /// The attestation is absent or differs; the host is frozen, and the
    /// outcome carries the only operations that remain.
    Quarantined(QuarantinedHost),
}

impl<'a> AdoptionOutcome<'a> {
    /// The adopted host, when the attestation matched.
    #[must_use]
    pub const fn adopted(&self) -> Option<AdoptedHost<'a>> {
        match self {
            Self::Adopted(host) => Some(*host),
            Self::Quarantined(_) => None,
        }
    }

    /// The quarantined host, when it did not.
    #[must_use]
    pub const fn quarantined(&self) -> Option<QuarantinedHost> {
        match self {
            Self::Adopted(_) => None,
            Self::Quarantined(host) => Some(*host),
        }
    }
}

/// Adopt a host across a control-plane reload.
///
/// The recorded attestation is *compared*, never reconstructed: a reload does
/// not rebuild a boundary around a live provider, it checks the one already
/// there. Every recorded field is compared against the observed one, and the
/// first difference names itself in the quarantine reason.
#[must_use]
pub fn adopt_host<'a>(
    recorded: Option<&'a EnforcementAttestation>,
    observed: Option<&EnforcementAttestation>,
) -> AdoptionOutcome<'a> {
    let reason = match (recorded, observed) {
        (None, None) => QuarantineReason::NothingAttested,
        (None, Some(_)) => QuarantineReason::NoRecordedAttestation,
        (Some(_), None) => QuarantineReason::NoObservedAttestation,
        (Some(recorded), Some(observed)) => match recorded.first_difference(observed) {
            None => {
                return AdoptionOutcome::Adopted(AdoptedHost {
                    attestation: recorded,
                });
            }
            Some(field) => QuarantineReason::Mismatch { field },
        },
    };
    AdoptionOutcome::Quarantined(QuarantinedHost { reason })
}

/// A provider's request for authority it does not have.
///
/// Carries a class and a description. There is no accessor returning a
/// [`SandboxSpec`], so an approval cannot widen one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    class: String,
    description: String,
}

impl ApprovalRequest {
    /// Record a request.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid component.
    pub fn new(class: &str, description: &str) -> Result<Self, SandboxError> {
        bounded(class, "approval_class")?;
        bounded(description, "approval_description")?;
        Ok(Self {
            class: class.to_owned(),
            description: description.to_owned(),
        })
    }

    /// The class of authority sought.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// What is being asked for.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), SandboxError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_SANDBOX_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_SANDBOX_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(SandboxError::Field { field, error }),
        None => Ok(()),
    }
}

fn bounded_len(length: usize, field: &'static str) -> Result<(), SandboxError> {
    if length > MAX_SANDBOX_ENTRIES {
        return Err(SandboxError::TooManyEntries {
            field,
            max: MAX_SANDBOX_ENTRIES,
            requested: length,
        });
    }
    Ok(())
}

fn names(values: &[&str], field: &'static str) -> Result<Vec<SandboxName>, SandboxError> {
    bounded_len(values.len(), field)?;
    let mut collected: Vec<SandboxName> = Vec::with_capacity(values.len());
    for value in values {
        let name =
            SandboxName::new(*value).map_err(|error| SandboxError::Field { field, error })?;
        if collected.contains(&name) {
            return Err(SandboxError::DuplicateEntry { field });
        }
        collected.push(name);
    }
    Ok(collected)
}
