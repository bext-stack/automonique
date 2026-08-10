// SPDX-License-Identifier: Elastic-2.0

//! The typed release manifest and the compatibility algebra a reload evaluates.
//!
//! A manifest describes exactly one release. It does not grant authority to
//! install one: nothing here performs I/O, hashes a real artifact, selects a
//! release, spawns a generation or runs a migration.
//!
//! Version ranges reuse [`crate::codec::VersionRange`], so the protocol, event
//! and database-schema ranges share one algebra with wire negotiation rather
//! than growing a second, subtly different one.

use core::fmt;
use std::error::Error;

use crate::codec::{CodecError, MajorVersion, VersionRange};
use crate::primitives::ValueError;

/// Manifest schema revision this build writes and understands.
pub const MANIFEST_SCHEMA_REVISION: u32 = 1;

/// Highest manifest schema revision this build can interpret.
pub const MAX_SUPPORTED_MANIFEST_SCHEMA: u32 = MANIFEST_SCHEMA_REVISION;

/// Maximum UTF-8 byte length of a bounded manifest string.
pub const MAX_MANIFEST_FIELD_BYTES: usize = 128;

/// Maximum number of retained unknown fields.
pub const MAX_UNKNOWN_FIELDS: usize = 64;

/// Which artifact a digest covers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ArtifactKind {
    /// The product binary.
    Binary,
    /// The generated schema bundle.
    SchemaBundle,
    /// The compiled policy set.
    Policy,
    /// The persona content.
    Persona,
    /// A companion executable.
    Companion,
    /// A static asset bundle.
    Asset,
}

impl ArtifactKind {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::SchemaBundle => "schema_bundle",
            Self::Policy => "policy",
            Self::Persona => "persona",
            Self::Companion => "companion",
            Self::Asset => "asset",
        }
    }
}

/// Digest algorithms this build accepts.
///
/// The set is closed and deliberately excludes MD5 and SHA-1: a weakened
/// algorithm is refused at parse rather than trusted because a manifest
/// declared it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestAlgorithm {
    /// SHA-256, 32 bytes.
    Sha256,
    /// SHA-512, 64 bytes.
    Sha512,
}

impl DigestAlgorithm {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
        }
    }

    /// Expected hexadecimal length of a digest in this algorithm.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// Map a wire spelling to an accepted algorithm.
    ///
    /// Returns `None` for anything unknown or weakened, including `md5` and
    /// `sha-1`.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "sha-256" => Some(Self::Sha256),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Why a manifest was rejected.
///
/// No variant carries artifact contents, a credential value or a host path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// The manifest declares a schema revision this build cannot interpret.
    UnsupportedSchemaRevision {
        /// Highest revision this build understands.
        supported_max: u32,
        /// Revision the manifest declared.
        declared: u32,
    },
    /// A required field was absent. Nothing defaults silently.
    MissingField {
        /// The absent field.
        field: &'static str,
    },
    /// A bounded field violated the shared value rules.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A version range was invalid.
    Range {
        /// The rejected field.
        field: &'static str,
        /// Range violation.
        error: CodecError,
    },
    /// The digest algorithm is unknown or weakened.
    UnacceptableDigestAlgorithm,
    /// The digest is not the expected hexadecimal shape for its algorithm.
    MalformedDigest {
        /// Expected hexadecimal length.
        expected_len: usize,
        /// Supplied hexadecimal length.
        actual_len: usize,
    },
    /// A supplied digest did not match the declared one.
    DigestMismatch {
        /// Artifact whose digest differed. Contents never appear.
        artifact: ArtifactKind,
    },
    /// The release cannot coexist with its selected rollback target.
    RollbackIncompatible {
        /// This release's database schema range.
        release_min: u32,
        /// This release's database schema range.
        release_max: u32,
        /// The rollback target's database schema range.
        rollback_min: u32,
        /// The rollback target's database schema range.
        rollback_max: u32,
    },
    /// A field that must be a relative path was absolute.
    AbsolutePath {
        /// The rejected field.
        field: &'static str,
    },
    /// More unknown fields were supplied than may be retained.
    TooManyUnknownFields {
        /// Maximum retained.
        max: usize,
    },
}

impl ManifestError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::UnsupportedSchemaRevision { .. } => "unsupported_schema_revision",
            Self::MissingField { .. } => "missing_field",
            Self::Field { .. } => "field_invalid",
            Self::Range { .. } => "range_invalid",
            Self::UnacceptableDigestAlgorithm => "unacceptable_digest_algorithm",
            Self::MalformedDigest { .. } => "malformed_digest",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::RollbackIncompatible { .. } => "rollback_incompatible",
            Self::AbsolutePath { .. } => "absolute_path",
            Self::TooManyUnknownFields { .. } => "too_many_unknown_fields",
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaRevision {
                supported_max,
                declared,
            } => write!(
                formatter,
                "manifest schema revision {declared} exceeds the supported {supported_max}"
            ),
            Self::MissingField { field } => write!(formatter, "required field {field} is absent"),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Range { field, error } => write!(formatter, "field {field}: {error}"),
            Self::UnacceptableDigestAlgorithm => {
                formatter.write_str("digest algorithm is unknown or weakened")
            }
            Self::MalformedDigest {
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "digest is {actual_len} hex characters; expected {expected_len}"
            ),
            Self::DigestMismatch { artifact } => {
                write!(formatter, "digest mismatch for {}", artifact.as_str())
            }
            Self::RollbackIncompatible {
                release_min,
                release_max,
                rollback_min,
                rollback_max,
            } => write!(
                formatter,
                "database schema range {release_min}..={release_max} cannot coexist with \
                 the rollback target's {rollback_min}..={rollback_max}"
            ),
            Self::AbsolutePath { field } => {
                write!(formatter, "field {field} must be a relative path")
            }
            Self::TooManyUnknownFields { max } => {
                write!(formatter, "more than {max} unknown fields were supplied")
            }
        }
    }
}

impl Error for ManifestError {}

/// A content digest with its named algorithm.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactDigest {
    algorithm: DigestAlgorithm,
    hex: String,
}

impl ArtifactDigest {
    /// Validate and construct a digest.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::UnacceptableDigestAlgorithm`] for an unknown or
    /// weakened algorithm and [`ManifestError::MalformedDigest`] when the
    /// hexadecimal shape does not match the algorithm.
    pub fn new(algorithm: &str, hex: &str) -> Result<Self, ManifestError> {
        let algorithm = DigestAlgorithm::from_wire(algorithm)
            .ok_or(ManifestError::UnacceptableDigestAlgorithm)?;
        if hex.len() != algorithm.hex_len() {
            return Err(ManifestError::MalformedDigest {
                expected_len: algorithm.hex_len(),
                actual_len: hex.len(),
            });
        }
        if !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ManifestError::MalformedDigest {
                expected_len: algorithm.hex_len(),
                actual_len: hex.len(),
            });
        }
        Ok(Self {
            algorithm,
            hex: hex.to_owned(),
        })
    }

    /// Declared algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Lowercase hexadecimal digest.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Compare against a supplied digest without an early return.
    ///
    /// The comparison accumulates differences across every byte, so its timing
    /// does not reveal the position of the first differing character.
    #[must_use]
    pub fn matches(&self, supplied: &Self) -> bool {
        if self.algorithm != supplied.algorithm || self.hex.len() != supplied.hex.len() {
            return false;
        }
        let mut difference = 0_u8;
        for (left, right) in self.hex.bytes().zip(supplied.hex.bytes()) {
            difference |= left ^ right;
        }
        difference == 0
    }

    /// Verify a supplied digest for a named artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::DigestMismatch`] naming the artifact. The
    /// contents are never included.
    pub fn verify(&self, artifact: ArtifactKind, supplied: &Self) -> Result<(), ManifestError> {
        if self.matches(supplied) {
            Ok(())
        } else {
            Err(ManifestError::DigestMismatch { artifact })
        }
    }
}

/// A credential the release needs, named without its value.
///
/// There is no constructor accepting a secret: a descriptor carries a name and
/// a version and nothing else.
///
/// ```compile_fail
/// use automonique_protocol::release::CredentialDescriptor;
/// // A descriptor cannot carry the credential it describes.
/// let descriptor = CredentialDescriptor::new("database", 3, "s3cret").unwrap();
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialDescriptor {
    name: String,
    version: u32,
}

impl CredentialDescriptor {
    /// Name a credential and the version the release expects.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Field`] when the name violates the shared
    /// bounded-value rules.
    pub fn new(name: &str, version: u32) -> Result<Self, ManifestError> {
        bounded(name, "credential_name")?;
        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }

    /// Credential name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Expected credential version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// A host capability the release needs, and whether it is mandatory.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityRequirement {
    id: String,
    required: bool,
}

impl CapabilityRequirement {
    /// Declare a mandatory capability.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Field`] for an invalid identifier.
    pub fn required(id: &str) -> Result<Self, ManifestError> {
        bounded(id, "capability_id")?;
        Ok(Self {
            id: id.to_owned(),
            required: true,
        })
    }

    /// Declare an optional capability whose absence is degradation.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Field`] for an invalid identifier.
    pub fn optional(id: &str) -> Result<Self, ManifestError> {
        bounded(id, "capability_id")?;
        Ok(Self {
            id: id.to_owned(),
            required: false,
        })
    }

    /// Capability identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the capability is mandatory.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// Result of evaluating declared capabilities against what a host offers.
///
/// A refusal and a degradation are separate outcomes. A caller cannot collapse
/// them, because a satisfied evaluation and a degraded one are distinct
/// variants rather than a boolean plus a list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityOutcome {
    /// Every declared capability is present.
    Satisfied,
    /// Every mandatory capability is present; some optional ones are absent.
    Degraded {
        /// Absent optional capability identifiers, in declaration order.
        missing_optional: Vec<String>,
    },
    /// At least one mandatory capability is absent.
    Refused {
        /// Absent mandatory capability identifiers, in declaration order.
        missing_required: Vec<String>,
        /// Absent optional capability identifiers, in declaration order.
        missing_optional: Vec<String>,
    },
}

/// The SDK build a release is compatible with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkCompatibility {
    protocol: VersionRange,
    schema_digest: ArtifactDigest,
}

impl SdkCompatibility {
    /// Declare the SDK protocol range and the schema digest it was generated
    /// against.
    #[must_use]
    pub const fn new(protocol: VersionRange, schema_digest: ArtifactDigest) -> Self {
        Self {
            protocol,
            schema_digest,
        }
    }

    /// Supported SDK protocol range.
    #[must_use]
    pub const fn protocol(&self) -> VersionRange {
        self.protocol
    }

    /// Schema digest the SDK was generated against.
    #[must_use]
    pub const fn schema_digest(&self) -> &ArtifactDigest {
        &self.schema_digest
    }

    /// Whether an SDK reporting these coordinates is compatible.
    ///
    /// Answerable from the manifest alone: no SDK is loaded to decide it.
    #[must_use]
    pub fn admits(&self, sdk_protocol: MajorVersion, sdk_schema_digest: &ArtifactDigest) -> bool {
        self.protocol.accepts(sdk_protocol) && self.schema_digest.matches(sdk_schema_digest)
    }
}

/// A previously released version this release may roll back to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackTarget {
    version: String,
    database_schema: VersionRange,
}

impl RollbackTarget {
    /// Name a rollback target and its database schema range.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Field`] for an invalid version string.
    pub fn new(version: &str, database_schema: VersionRange) -> Result<Self, ManifestError> {
        bounded(version, "rollback_version")?;
        Ok(Self {
            version: version.to_owned(),
            database_schema,
        })
    }

    /// Target version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Target database schema range.
    #[must_use]
    pub const fn database_schema(&self) -> VersionRange {
        self.database_schema
    }
}

/// A validated description of exactly one release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    schema_revision: u32,
    version: String,
    source_revision: String,
    build_target: String,
    protocol: VersionRange,
    events: VersionRange,
    database_schema: VersionRange,
    sdk: SdkCompatibility,
    digests: Vec<(ArtifactKind, ArtifactDigest)>,
    capabilities: Vec<CapabilityRequirement>,
    credentials: Vec<CredentialDescriptor>,
    rollback: Option<RollbackTarget>,
    unknown_fields: Vec<(String, String)>,
}

impl ReleaseManifest {
    /// Manifest schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> u32 {
        self.schema_revision
    }

    /// Application version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Exact source revision.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Build target triple.
    #[must_use]
    pub fn build_target(&self) -> &str {
        &self.build_target
    }

    /// Supported wire protocol range.
    #[must_use]
    pub const fn protocol(&self) -> VersionRange {
        self.protocol
    }

    /// Supported event schema range.
    #[must_use]
    pub const fn events(&self) -> VersionRange {
        self.events
    }

    /// Readable database schema range.
    #[must_use]
    pub const fn database_schema(&self) -> VersionRange {
        self.database_schema
    }

    /// SDK compatibility coordinates.
    #[must_use]
    pub const fn sdk(&self) -> &SdkCompatibility {
        &self.sdk
    }

    /// Declared rollback target, if any.
    #[must_use]
    pub const fn rollback(&self) -> Option<&RollbackTarget> {
        self.rollback.as_ref()
    }

    /// Retained unknown fields, in supplied order.
    #[must_use]
    pub fn unknown_fields(&self) -> &[(String, String)] {
        &self.unknown_fields
    }

    /// Declared credential descriptors.
    #[must_use]
    pub fn credentials(&self) -> &[CredentialDescriptor] {
        &self.credentials
    }

    /// Digest declared for one artifact kind.
    #[must_use]
    pub fn digest(&self, artifact: ArtifactKind) -> Option<&ArtifactDigest> {
        self.digests
            .iter()
            .find(|(kind, _)| *kind == artifact)
            .map(|(_, digest)| digest)
    }

    /// Evaluate declared capabilities against the identifiers a host offers.
    ///
    /// An unmet mandatory capability refuses; an unmet optional one degrades.
    /// The two are never collapsed.
    #[must_use]
    pub fn evaluate_capabilities(&self, host_offers: &[&str]) -> CapabilityOutcome {
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        for capability in &self.capabilities {
            if host_offers.contains(&capability.id.as_str()) {
                continue;
            }
            if capability.required {
                missing_required.push(capability.id.clone());
            } else {
                missing_optional.push(capability.id.clone());
            }
        }
        if !missing_required.is_empty() {
            CapabilityOutcome::Refused {
                missing_required,
                missing_optional,
            }
        } else if missing_optional.is_empty() {
            CapabilityOutcome::Satisfied
        } else {
            CapabilityOutcome::Degraded { missing_optional }
        }
    }

    /// Whether this release's protocol range overlaps another's.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Range`] naming both operands when no shared
    /// version exists.
    pub fn negotiate_protocol(&self, peer: &Self) -> Result<MajorVersion, ManifestError> {
        self.protocol
            .negotiate(peer.protocol)
            .map_err(|error| ManifestError::Range {
                field: "protocol",
                error,
            })
    }
}

/// Accumulates manifest fields and enforces that none defaults silently.
#[derive(Clone, Debug, Default)]
pub struct ReleaseManifestBuilder {
    schema_revision: Option<u32>,
    version: Option<String>,
    source_revision: Option<String>,
    build_target: Option<String>,
    protocol: Option<VersionRange>,
    events: Option<VersionRange>,
    database_schema: Option<VersionRange>,
    sdk: Option<SdkCompatibility>,
    digests: Vec<(ArtifactKind, ArtifactDigest)>,
    capabilities: Vec<CapabilityRequirement>,
    credentials: Vec<CredentialDescriptor>,
    rollback: Option<RollbackTarget>,
    unknown_fields: Vec<(String, String)>,
}

impl ReleaseManifestBuilder {
    /// Start an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the manifest schema revision.
    #[must_use]
    pub const fn schema_revision(mut self, revision: u32) -> Self {
        self.schema_revision = Some(revision);
        self
    }

    /// Declare the application version.
    #[must_use]
    pub fn version(mut self, value: &str) -> Self {
        self.version = Some(value.to_owned());
        self
    }

    /// Declare the exact source revision.
    #[must_use]
    pub fn source_revision(mut self, value: &str) -> Self {
        self.source_revision = Some(value.to_owned());
        self
    }

    /// Declare the build target triple.
    #[must_use]
    pub fn build_target(mut self, value: &str) -> Self {
        self.build_target = Some(value.to_owned());
        self
    }

    /// Declare the wire protocol range.
    #[must_use]
    pub const fn protocol(mut self, range: VersionRange) -> Self {
        self.protocol = Some(range);
        self
    }

    /// Declare the event schema range.
    #[must_use]
    pub const fn events(mut self, range: VersionRange) -> Self {
        self.events = Some(range);
        self
    }

    /// Declare the database schema range.
    #[must_use]
    pub const fn database_schema(mut self, range: VersionRange) -> Self {
        self.database_schema = Some(range);
        self
    }

    /// Declare SDK compatibility.
    #[must_use]
    pub fn sdk(mut self, sdk: SdkCompatibility) -> Self {
        self.sdk = Some(sdk);
        self
    }

    /// Declare one artifact digest.
    #[must_use]
    pub fn digest(mut self, artifact: ArtifactKind, digest: ArtifactDigest) -> Self {
        self.digests.push((artifact, digest));
        self
    }

    /// Declare one capability requirement.
    #[must_use]
    pub fn capability(mut self, capability: CapabilityRequirement) -> Self {
        self.capabilities.push(capability);
        self
    }

    /// Declare one credential descriptor.
    #[must_use]
    pub fn credential(mut self, descriptor: CredentialDescriptor) -> Self {
        self.credentials.push(descriptor);
        self
    }

    /// Declare a rollback target.
    #[must_use]
    pub fn rollback(mut self, target: RollbackTarget) -> Self {
        self.rollback = Some(target);
        self
    }

    /// Retain one field this build does not understand.
    #[must_use]
    pub fn unknown_field(mut self, key: &str, value: &str) -> Self {
        self.unknown_fields.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Validate every field and construct the manifest.
    ///
    /// The schema revision is checked first: a manifest written by a future
    /// incompatible writer is refused before any other field is interpreted.
    ///
    /// # Errors
    ///
    /// Returns the first [`ManifestError`] encountered.
    pub fn build(self) -> Result<ReleaseManifest, ManifestError> {
        let schema_revision = self.schema_revision.ok_or(ManifestError::MissingField {
            field: "schema_revision",
        })?;
        if schema_revision > MAX_SUPPORTED_MANIFEST_SCHEMA {
            return Err(ManifestError::UnsupportedSchemaRevision {
                supported_max: MAX_SUPPORTED_MANIFEST_SCHEMA,
                declared: schema_revision,
            });
        }

        let version = required(self.version, "version")?;
        bounded(&version, "version")?;
        let source_revision = required(self.source_revision, "source_revision")?;
        bounded(&source_revision, "source_revision")?;
        let build_target = required(self.build_target, "build_target")?;
        bounded(&build_target, "build_target")?;
        if build_target.starts_with('/') {
            return Err(ManifestError::AbsolutePath {
                field: "build_target",
            });
        }

        let protocol = required(self.protocol, "protocol")?;
        let events = required(self.events, "events")?;
        let database_schema = required(self.database_schema, "database_schema")?;
        let sdk = required(self.sdk, "sdk")?;

        if !self
            .digests
            .iter()
            .any(|(kind, _)| *kind == ArtifactKind::Binary)
        {
            return Err(ManifestError::MissingField {
                field: "binary_digest",
            });
        }

        if let Some(target) = &self.rollback {
            // A release that cannot coexist with its selected rollback target
            // is refused here, before any handoff decision exists to make.
            if target.database_schema.negotiate(database_schema).is_err() {
                return Err(ManifestError::RollbackIncompatible {
                    release_min: database_schema.min().get(),
                    release_max: database_schema.max().get(),
                    rollback_min: target.database_schema.min().get(),
                    rollback_max: target.database_schema.max().get(),
                });
            }
        }

        if self.unknown_fields.len() > MAX_UNKNOWN_FIELDS {
            return Err(ManifestError::TooManyUnknownFields {
                max: MAX_UNKNOWN_FIELDS,
            });
        }
        for (key, value) in &self.unknown_fields {
            bounded(key, "unknown_field_key")?;
            bounded(value, "unknown_field_value")?;
        }

        Ok(ReleaseManifest {
            schema_revision,
            version,
            source_revision,
            build_target,
            protocol,
            events,
            database_schema,
            sdk,
            digests: self.digests,
            capabilities: self.capabilities,
            credentials: self.credentials,
            rollback: self.rollback,
            unknown_fields: self.unknown_fields,
        })
    }
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, ManifestError> {
    value.ok_or(ManifestError::MissingField { field })
}

fn bounded(value: &str, field: &'static str) -> Result<(), ManifestError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_MANIFEST_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_MANIFEST_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ManifestError::Field { field, error }),
        None => Ok(()),
    }
}
