// SPDX-License-Identifier: Elastic-2.0

//! The typed release manifest and the compatibility algebra a reload evaluates.
//!
//! A manifest describes exactly one release. It does not grant authority to
//! install one: nothing here performs I/O, hashes a real artifact, selects a
//! release, spawns a generation or runs a migration.
//!
//! A manifest reaches a typed value by exactly two routes:
//! [`ReleaseManifest::from_canonical_bytes`] for a manifest *document*, and
//! [`ReleaseManifestBuilder`] for a programmatic assembly. Both end in the same
//! validation, so a document and an assembly cannot disagree about what a valid
//! manifest is. The document reader is [`crate::wire::parse_canonical`]; this
//! module adds no second JSON parser.
//!
//! Every string a manifest can hold is a [`ManifestText`]. Its constructor is
//! the only way to obtain one, so the bound, the control-character rule and the
//! absolute-host-path refusal cannot be forgotten by a field added later.
//!
//! Version ranges reuse [`crate::codec::VersionRange`], so the protocol, event
//! and database-schema ranges share one algebra with wire negotiation rather
//! than growing a second, subtly different one.
//!
//! A manifest also renders back to its document form
//! ([`ReleaseManifest::to_canonical_document`]) and hashes to a
//! [`ReleaseManifest::canonical_digest`]. That digest is what
//! [`crate::release_trust_root`] binds an attestation to. Rendering is *total*:
//! every constructible manifest has exactly one canonical document, which is
//! why [`ReleaseManifestBuilder::build`] refuses the two shapes only a
//! programmatic assembly could reach — a second digest for an artifact kind, and
//! a retained unknown field named after an interpreted one. Neither can arrive
//! from a document, because the canonical reader already refuses duplicate keys.

use core::fmt;
use std::error::Error;

use crate::codec::{CodecError, MajorVersion, VersionRange};
use crate::digest::Sha256;
use crate::primitives::ValueError;
use crate::wire::{JsonValue, parse_canonical};

/// Manifest schema revision this build writes and understands.
pub const MANIFEST_SCHEMA_REVISION: u32 = 1;

/// Highest manifest schema revision this build can interpret.
pub const MAX_SUPPORTED_MANIFEST_SCHEMA: u32 = MANIFEST_SCHEMA_REVISION;

/// Maximum UTF-8 byte length of a bounded manifest string.
pub const MAX_MANIFEST_FIELD_BYTES: usize = 128;

/// Maximum number of retained unknown fields.
pub const MAX_UNKNOWN_FIELDS: usize = 64;

/// Document keys this build interprets, in canonical order.
///
/// A key outside this set is retained as an unknown field and never
/// reinterpreted. The set is public so a coverage table can be checked against
/// it rather than restated.
pub const KNOWN_MANIFEST_FIELDS: [&str; 12] = [
    "build_target",
    "capabilities",
    "credentials",
    "database_schema",
    "digests",
    "events",
    "protocol",
    "rollback",
    "schema_revision",
    "sdk",
    "source_revision",
    "version",
];

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

    /// Map a wire spelling to an artifact this build defines.
    ///
    /// Returns `None` for anything else, so a document cannot introduce an
    /// artifact kind by naming one.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "binary" => Some(Self::Binary),
            "schema_bundle" => Some(Self::SchemaBundle),
            "policy" => Some(Self::Policy),
            "persona" => Some(Self::Persona),
            "companion" => Some(Self::Companion),
            "asset" => Some(Self::Asset),
            _ => None,
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
    /// The bytes are not a canonical manifest document.
    Document {
        /// Refusal the canonical reader returned.
        error: CodecError,
    },
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
    /// A field was present with the wrong JSON type.
    FieldType {
        /// The rejected field.
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
    /// A closed enumeration received a spelling this build does not define.
    UnknownEnumValue {
        /// The rejected field.
        field: &'static str,
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
    /// A field that must be a relative value held an absolute host path.
    AbsolutePath {
        /// The rejected field.
        field: &'static str,
    },
    /// More unknown fields were supplied than may be retained.
    TooManyUnknownFields {
        /// Maximum retained.
        max: usize,
    },
    /// One artifact kind was given a digest twice.
    ///
    /// Only [`ReleaseManifestBuilder`] can reach this: a document cannot,
    /// because the canonical reader refuses duplicate object keys. A second
    /// declaration is refused rather than shadowed, so [`ReleaseManifest::digest`]
    /// and [`ReleaseManifest::to_canonical_document`] cannot disagree about
    /// which one counts.
    DuplicateArtifactDigest {
        /// Artifact declared twice. Contents never appear.
        artifact: ArtifactKind,
    },
    /// A retained unknown field was named after a field this build interprets.
    ///
    /// Only [`ReleaseManifestBuilder`] can reach this, for the same reason. Such
    /// a manifest has no document form — rendering it would emit the name twice
    /// — so it is refused at assembly instead of producing bytes the canonical
    /// reader would reject.
    UnknownFieldShadowsKnownField {
        /// The interpreted field whose name was reused.
        field: &'static str,
    },
}

impl ManifestError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Document { .. } => "malformed_document",
            Self::UnsupportedSchemaRevision { .. } => "unsupported_schema_revision",
            Self::MissingField { .. } => "missing_field",
            Self::FieldType { .. } => "field_type",
            Self::Field { .. } => "field_invalid",
            Self::Range { .. } => "range_invalid",
            Self::UnknownEnumValue { .. } => "unknown_enum_value",
            Self::UnacceptableDigestAlgorithm => "unacceptable_digest_algorithm",
            Self::MalformedDigest { .. } => "malformed_digest",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::RollbackIncompatible { .. } => "rollback_incompatible",
            Self::AbsolutePath { .. } => "absolute_path",
            Self::TooManyUnknownFields { .. } => "too_many_unknown_fields",
            Self::DuplicateArtifactDigest { .. } => "duplicate_artifact_digest",
            Self::UnknownFieldShadowsKnownField { .. } => "unknown_field_shadows_known_field",
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document { error } => {
                write!(formatter, "manifest document is not canonical: {error}")
            }
            Self::UnsupportedSchemaRevision {
                supported_max,
                declared,
            } => write!(
                formatter,
                "manifest schema revision {declared} exceeds the supported {supported_max}"
            ),
            Self::MissingField { field } => write!(formatter, "required field {field} is absent"),
            Self::FieldType { field } => {
                write!(formatter, "field {field} has the wrong JSON type")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Range { field, error } => write!(formatter, "field {field}: {error}"),
            Self::UnknownEnumValue { field } => write!(
                formatter,
                "field {field} names a value this build does not define"
            ),
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
                write!(formatter, "field {field} must not be an absolute host path")
            }
            Self::TooManyUnknownFields { max } => {
                write!(formatter, "more than {max} unknown fields were supplied")
            }
            Self::DuplicateArtifactDigest { artifact } => write!(
                formatter,
                "artifact {} was given a digest twice",
                artifact.as_str()
            ),
            Self::UnknownFieldShadowsKnownField { field } => write!(
                formatter,
                "unknown field {field} reuses the name of an interpreted field"
            ),
        }
    }
}

impl Error for ManifestError {}

/// A bounded string a manifest may hold.
///
/// Every manifest string field is this type — application version, source
/// revision, build target, credential name, capability identifier, rollback
/// version and both halves of a retained unknown field. The rules are enforced
/// by [`ManifestText::new`], which is the only way to obtain a value:
///
/// - non-empty;
/// - at most [`MAX_MANIFEST_FIELD_BYTES`] UTF-8 bytes;
/// - free of Unicode control characters;
/// - not an absolute host path.
///
/// Locating the rules in the type rather than at a call site is deliberate. A
/// field added to the manifest later is declared as a `ManifestText` and
/// therefore cannot opt out of any of them; the previous arrangement checked
/// the absolute-path rule at one call site, and every other field silently
/// missed it.
///
/// An absolute host path is a syntactic judgement made offline: a leading `/`,
/// a leading `\`, or a drive-letter prefix such as `C:\` or `C:/`. Nothing is
/// resolved, canonicalized or opened. A `~`-prefixed spelling is home-relative
/// rather than absolute and is not refused by this rule.
///
/// The inner value is private, so the constructor cannot be bypassed:
///
/// ```compile_fail
/// use automonique_protocol::release::ManifestText;
/// let text = ManifestText {
///     value: "/etc/automonique/secret.pem".to_owned(),
/// };
/// ```
///
/// The same string through the constructor — the one difference — compiles, and
/// is refused at run time instead:
///
/// ```
/// use automonique_protocol::release::ManifestText;
/// let refusal = ManifestText::new("/etc/automonique/secret.pem", "any_field")
///     .expect_err("an absolute host path is refused");
/// assert_eq!(refusal.category(), "absolute_path");
/// ```
///
/// A relative value of the same shape is accepted:
///
/// ```
/// use automonique_protocol::release::ManifestText;
/// let text = ManifestText::new("x86_64-unknown-linux-gnu", "build_target")
///     .expect("a relative value");
/// assert_eq!(text.as_str(), "x86_64-unknown-linux-gnu");
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestText {
    value: String,
}

impl ManifestText {
    /// Validate and construct a bounded manifest string.
    ///
    /// `field` names the position being filled and appears in the refusal; it
    /// is not part of the value.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Field`] when the value is empty, over
    /// [`MAX_MANIFEST_FIELD_BYTES`], or contains a control character, and
    /// [`ManifestError::AbsolutePath`] when it is an absolute host path.
    pub fn new(value: &str, field: &'static str) -> Result<Self, ManifestError> {
        let bound = if value.is_empty() {
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
        if let Some(error) = bound {
            return Err(ManifestError::Field { field, error });
        }
        if is_absolute_host_path(value) {
            return Err(ManifestError::AbsolutePath { field });
        }
        Ok(Self {
            value: value.to_owned(),
        })
    }

    /// Return the validated string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ManifestText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

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
///
/// The same call without the value — the one difference — compiles:
///
/// ```
/// use automonique_protocol::release::CredentialDescriptor;
/// let descriptor = CredentialDescriptor::new("database", 3).unwrap();
/// assert_eq!(descriptor.name(), "database");
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CredentialDescriptor {
    name: ManifestText,
    version: u32,
}

impl CredentialDescriptor {
    /// Name a credential and the version the release expects.
    ///
    /// # Errors
    ///
    /// Returns the [`ManifestText`] refusal when the name violates the shared
    /// bounded-value rules or is an absolute host path.
    pub fn new(name: &str, version: u32) -> Result<Self, ManifestError> {
        Ok(Self {
            name: ManifestText::new(name, "credential_name")?,
            version,
        })
    }

    /// Credential name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
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
    id: ManifestText,
    required: bool,
}

impl CapabilityRequirement {
    /// Declare a mandatory capability.
    ///
    /// # Errors
    ///
    /// Returns the [`ManifestText`] refusal for an invalid identifier.
    pub fn required(id: &str) -> Result<Self, ManifestError> {
        Ok(Self {
            id: ManifestText::new(id, "capability_id")?,
            required: true,
        })
    }

    /// Declare an optional capability whose absence is degradation.
    ///
    /// # Errors
    ///
    /// Returns the [`ManifestText`] refusal for an invalid identifier.
    pub fn optional(id: &str) -> Result<Self, ManifestError> {
        Ok(Self {
            id: ManifestText::new(id, "capability_id")?,
            required: false,
        })
    }

    /// Capability identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
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
    version: ManifestText,
    database_schema: VersionRange,
}

impl RollbackTarget {
    /// Name a rollback target and its database schema range.
    ///
    /// # Errors
    ///
    /// Returns the [`ManifestText`] refusal for an invalid version string.
    pub fn new(version: &str, database_schema: VersionRange) -> Result<Self, ManifestError> {
        Ok(Self {
            version: ManifestText::new(version, "rollback_version")?,
            database_schema,
        })
    }

    /// Target version.
    #[must_use]
    pub fn version(&self) -> &str {
        self.version.as_str()
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
    version: ManifestText,
    source_revision: ManifestText,
    build_target: ManifestText,
    protocol: VersionRange,
    events: VersionRange,
    database_schema: VersionRange,
    sdk: SdkCompatibility,
    digests: Vec<(ArtifactKind, ArtifactDigest)>,
    capabilities: Vec<CapabilityRequirement>,
    credentials: Vec<CredentialDescriptor>,
    rollback: Option<RollbackTarget>,
    unknown_fields: Vec<(ManifestText, JsonValue)>,
}

impl ReleaseManifest {
    /// Parse a manifest document from canonical bytes.
    ///
    /// The reader is [`crate::wire::parse_canonical`], so input that parses but
    /// is not already canonical is refused rather than normalized. Every
    /// required field is enforced here and every bound applies on the way in:
    /// the result is a fully typed manifest or there is no value at all.
    ///
    /// The schema revision is read and compared before any other field is
    /// interpreted, so a document written by a future incompatible writer is
    /// refused without this build reading the rest of it.
    ///
    /// Keys outside [`KNOWN_MANIFEST_FIELDS`] are retained verbatim as unknown
    /// fields: their structure is preserved and never reinterpreted, and at
    /// most [`MAX_UNKNOWN_FIELDS`] of them are kept. Preservation is not an
    /// exemption from the string rules, though — every string inside a retained
    /// value, at any nesting depth, must still be a valid [`ManifestText`], so
    /// an empty, over-long, control-bearing or absolute-path string is refused
    /// there exactly as it would be in a known field.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Document`] when the bytes are not a canonical
    /// JSON document, [`ManifestError::FieldType`] when a field is present with
    /// the wrong JSON type, [`ManifestError::UnknownEnumValue`] for an artifact
    /// name this build does not define, and otherwise every refusal
    /// [`ReleaseManifestBuilder::build`] can return.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ManifestError> {
        let document =
            parse_canonical(payload).map_err(|error| ManifestError::Document { error })?;
        let JsonValue::Object(entries) = &document else {
            return Err(ManifestError::FieldType { field: "manifest" });
        };

        // Read and compare the schema revision before interpreting anything
        // else, so a future writer's document is refused on its revision rather
        // than on whichever other field this build happens to disagree with.
        let schema_revision = as_unsigned(
            member(&document, "schema_revision", "schema_revision")?,
            "schema_revision",
        )?;
        if schema_revision > MAX_SUPPORTED_MANIFEST_SCHEMA {
            return Err(ManifestError::UnsupportedSchemaRevision {
                supported_max: MAX_SUPPORTED_MANIFEST_SCHEMA,
                declared: schema_revision,
            });
        }

        let mut builder = ReleaseManifestBuilder::new().schema_revision(schema_revision);

        if let Some(value) = document.get("version") {
            builder = builder.version(as_text(value, "version")?);
        }
        if let Some(value) = document.get("source_revision") {
            builder = builder.source_revision(as_text(value, "source_revision")?);
        }
        if let Some(value) = document.get("build_target") {
            builder = builder.build_target(as_text(value, "build_target")?);
        }
        if let Some(value) = document.get("protocol") {
            builder = builder.protocol(decode_range(
                value,
                "protocol",
                "protocol_min",
                "protocol_max",
            )?);
        }
        if let Some(value) = document.get("events") {
            builder = builder.events(decode_range(value, "events", "events_min", "events_max")?);
        }
        if let Some(value) = document.get("database_schema") {
            builder = builder.database_schema(decode_range(
                value,
                "database_schema",
                "database_schema_min",
                "database_schema_max",
            )?);
        }
        if let Some(value) = document.get("sdk") {
            builder = builder.sdk(decode_sdk(value)?);
        }
        if let Some(value) = document.get("digests") {
            let JsonValue::Object(declared) = value else {
                return Err(ManifestError::FieldType { field: "digests" });
            };
            for (name, spec) in declared {
                let kind = ArtifactKind::from_wire(name)
                    .ok_or(ManifestError::UnknownEnumValue { field: "digests" })?;
                builder = builder.digest(
                    kind,
                    decode_digest(spec, "digest", "digest_algorithm", "digest_hex")?,
                );
            }
        }
        if let Some(value) = document.get("capabilities") {
            let JsonValue::Array(declared) = value else {
                return Err(ManifestError::FieldType {
                    field: "capabilities",
                });
            };
            for item in declared {
                builder = builder.capability(decode_capability(item)?);
            }
        }
        if let Some(value) = document.get("credentials") {
            let JsonValue::Array(declared) = value else {
                return Err(ManifestError::FieldType {
                    field: "credentials",
                });
            };
            for item in declared {
                builder = builder.credential(decode_credential(item)?);
            }
        }
        if let Some(value) = document.get("rollback") {
            builder = builder.rollback(decode_rollback(value)?);
        }

        for (key, value) in entries {
            if KNOWN_MANIFEST_FIELDS.contains(&key.as_str()) {
                continue;
            }
            builder = builder.unknown_json_field(key, value.clone());
        }

        builder.build()
    }

    /// Manifest schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> u32 {
        self.schema_revision
    }

    /// Application version.
    #[must_use]
    pub fn version(&self) -> &str {
        self.version.as_str()
    }

    /// Exact source revision.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        self.source_revision.as_str()
    }

    /// Build target triple.
    #[must_use]
    pub fn build_target(&self) -> &str {
        self.build_target.as_str()
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
    ///
    /// The value is the JSON this build did not interpret, preserved exactly.
    #[must_use]
    pub fn unknown_fields(&self) -> &[(ManifestText, JsonValue)] {
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
                missing_required.push(capability.id.as_str().to_owned());
            } else {
                missing_optional.push(capability.id.as_str().to_owned());
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

    /// Render this manifest back to its document form.
    ///
    /// Rendering is total: every value this type can hold has exactly one
    /// canonical document, which is what makes [`Self::canonical_digest`] a
    /// function of the manifest rather than of however it happened to arrive.
    /// The two shapes that would have no document form — a repeated artifact
    /// digest and a retained field named after an interpreted one — are refused
    /// by [`ReleaseManifestBuilder::build`] instead of normalized here.
    ///
    /// A manifest read from a canonical document renders back to those exact
    /// bytes, with one spelling caveat: `capabilities` and `credentials` are
    /// always written, empty or not, because the manifest cannot record whether
    /// an absent section was omitted or spelled empty. `rollback` is written
    /// only when present, since omission is the only spelling the reader
    /// accepts for an absent one.
    ///
    /// This is a value transform. It hashes nothing, opens nothing and grants
    /// nothing.
    #[must_use]
    pub fn to_canonical_document(&self) -> JsonValue {
        let mut fields = vec![
            (
                "build_target".to_owned(),
                JsonValue::String(self.build_target.as_str().to_owned()),
            ),
            (
                "capabilities".to_owned(),
                JsonValue::Array(
                    self.capabilities
                        .iter()
                        .map(|capability| {
                            JsonValue::Object(vec![
                                (
                                    "id".to_owned(),
                                    JsonValue::String(capability.id.as_str().to_owned()),
                                ),
                                ("required".to_owned(), JsonValue::Bool(capability.required)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "credentials".to_owned(),
                JsonValue::Array(
                    self.credentials
                        .iter()
                        .map(|credential| {
                            JsonValue::Object(vec![
                                (
                                    "name".to_owned(),
                                    JsonValue::String(credential.name.as_str().to_owned()),
                                ),
                                (
                                    "version".to_owned(),
                                    JsonValue::Integer(i64::from(credential.version)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "database_schema".to_owned(),
                render_range(self.database_schema),
            ),
            (
                "digests".to_owned(),
                JsonValue::Object(
                    self.digests
                        .iter()
                        .map(|(kind, digest)| (kind.as_str().to_owned(), render_digest(digest)))
                        .collect(),
                ),
            ),
            ("events".to_owned(), render_range(self.events)),
            ("protocol".to_owned(), render_range(self.protocol)),
            (
                "schema_revision".to_owned(),
                JsonValue::Integer(i64::from(self.schema_revision)),
            ),
            (
                "sdk".to_owned(),
                JsonValue::Object(vec![
                    ("protocol".to_owned(), render_range(self.sdk.protocol())),
                    (
                        "schema_digest".to_owned(),
                        render_digest(self.sdk.schema_digest()),
                    ),
                ]),
            ),
            (
                "source_revision".to_owned(),
                JsonValue::String(self.source_revision.as_str().to_owned()),
            ),
            (
                "version".to_owned(),
                JsonValue::String(self.version.as_str().to_owned()),
            ),
        ];
        if let Some(target) = &self.rollback {
            fields.push((
                "rollback".to_owned(),
                JsonValue::Object(vec![
                    (
                        "database_schema".to_owned(),
                        render_range(target.database_schema),
                    ),
                    (
                        "version".to_owned(),
                        JsonValue::String(target.version.as_str().to_owned()),
                    ),
                ]),
            ));
        }
        for (key, value) in &self.unknown_fields {
            fields.push((key.as_str().to_owned(), value.clone()));
        }
        JsonValue::Object(fields)
    }

    /// Canonical document bytes for this manifest.
    ///
    /// [`crate::wire::JsonValue::to_canonical_bytes`] sorts keys, so the order
    /// [`Self::to_canonical_document`] assembled them in does not reach the
    /// output.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical_document().to_canonical_bytes()
    }

    /// SHA-256 over [`Self::to_canonical_bytes`].
    ///
    /// This is the digest [`crate::release_trust_root::ReleaseAttestation`]
    /// binds, and the hash is [`crate::digest::Sha256`] — written in this crate
    /// from FIPS 180-4 rather than imported, and therefore reviewable here.
    ///
    /// It covers the manifest *as this build interprets it*, not the bytes a
    /// caller supplied. The two differ exactly where the reader is permissive:
    /// a document that omits an empty `capabilities` and one that spells it
    /// reach the same manifest and therefore the same digest. A consumer that
    /// needs the received bytes pinned as well must hash those bytes itself —
    /// `automonique-sandbox`'s release boundary already does, which is why the
    /// two checks compose rather than duplicate.
    #[must_use]
    pub fn canonical_digest(&self) -> ArtifactDigest {
        ArtifactDigest {
            algorithm: DigestAlgorithm::Sha256,
            hex: Sha256::digest(&self.to_canonical_bytes()).to_hex(),
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
    unknown_fields: Vec<(String, JsonValue)>,
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

    /// Retain one string-valued field this build does not understand.
    #[must_use]
    pub fn unknown_field(self, key: &str, value: &str) -> Self {
        self.unknown_json_field(key, JsonValue::String(value.to_owned()))
    }

    /// Retain one field of any JSON shape this build does not understand.
    #[must_use]
    pub fn unknown_json_field(mut self, key: &str, value: JsonValue) -> Self {
        self.unknown_fields.push((key.to_owned(), value));
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

        let version = ManifestText::new(&required(self.version, "version")?, "version")?;
        let source_revision = ManifestText::new(
            &required(self.source_revision, "source_revision")?,
            "source_revision",
        )?;
        let build_target = ManifestText::new(
            &required(self.build_target, "build_target")?,
            "build_target",
        )?;

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

        // A second digest for one artifact kind is refused rather than
        // shadowed. `digest()` returns the first, so a shadowed second one is
        // unobservable through every accessor while still changing the value;
        // that is exactly the gap between "what a consumer decides on" and
        // "what an attestation covers" that a trust root must not have.
        for (position, (kind, _)) in self.digests.iter().enumerate() {
            if self.digests[..position]
                .iter()
                .any(|(earlier, _)| earlier == kind)
            {
                return Err(ManifestError::DuplicateArtifactDigest { artifact: *kind });
            }
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
        let mut unknown_fields = Vec::with_capacity(self.unknown_fields.len());
        for (key, value) in self.unknown_fields {
            let key = ManifestText::new(&key, "unknown_field_key")?;
            if let Some(known) = KNOWN_MANIFEST_FIELDS
                .iter()
                .copied()
                .find(|field| *field == key.as_str())
            {
                return Err(ManifestError::UnknownFieldShadowsKnownField { field: known });
            }
            validate_unknown_value(&value)?;
            unknown_fields.push((key, value));
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
            unknown_fields,
        })
    }
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, ManifestError> {
    value.ok_or(ManifestError::MissingField { field })
}

/// Render a version range in the shape [`decode_range`] reads.
fn render_range(range: VersionRange) -> JsonValue {
    JsonValue::Object(vec![
        (
            "max".to_owned(),
            JsonValue::Integer(i64::from(range.max().get())),
        ),
        (
            "min".to_owned(),
            JsonValue::Integer(i64::from(range.min().get())),
        ),
    ])
}

/// Render a digest in the shape [`decode_digest`] reads.
fn render_digest(digest: &ArtifactDigest) -> JsonValue {
    JsonValue::Object(vec![
        (
            "algorithm".to_owned(),
            JsonValue::String(digest.algorithm.as_str().to_owned()),
        ),
        ("hex".to_owned(), JsonValue::String(digest.hex.clone())),
    ])
}

/// Whether a value spells an absolute host path.
///
/// Syntactic and offline: nothing is resolved, canonicalized or opened.
fn is_absolute_host_path(value: &str) -> bool {
    match value.as_bytes() {
        [b'/', ..] | [b'\\', ..] => true,
        [drive, b':', b'/' | b'\\', ..] => drive.is_ascii_alphabetic(),
        _ => false,
    }
}

/// Apply the manifest string rules to every string inside a retained value.
///
/// An unknown field is preserved and never reinterpreted, but it is not a hole
/// in the hygiene rule: a host path nested inside one is refused exactly as a
/// known field's would be.
fn validate_unknown_value(value: &JsonValue) -> Result<(), ManifestError> {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Integer(_) => Ok(()),
        JsonValue::String(text) => {
            ManifestText::new(text, "unknown_field_value")?;
            Ok(())
        }
        JsonValue::Array(items) => items.iter().try_for_each(validate_unknown_value),
        JsonValue::Object(entries) => entries.iter().try_for_each(|(key, nested)| {
            ManifestText::new(key, "unknown_field_key")?;
            validate_unknown_value(nested)
        }),
    }
}

fn member<'a>(
    object: &'a JsonValue,
    key: &str,
    field: &'static str,
) -> Result<&'a JsonValue, ManifestError> {
    object.get(key).ok_or(ManifestError::MissingField { field })
}

fn as_object<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a JsonValue, ManifestError> {
    match value {
        JsonValue::Object(_) => Ok(value),
        _ => Err(ManifestError::FieldType { field }),
    }
}

fn as_text<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, ManifestError> {
    value.as_str().ok_or(ManifestError::FieldType { field })
}

fn as_unsigned(value: &JsonValue, field: &'static str) -> Result<u32, ManifestError> {
    let raw = value
        .as_integer()
        .ok_or(ManifestError::FieldType { field })?;
    u32::try_from(raw).map_err(|_| ManifestError::FieldType { field })
}

fn as_boolean(value: &JsonValue, field: &'static str) -> Result<bool, ManifestError> {
    match value {
        JsonValue::Bool(flag) => Ok(*flag),
        _ => Err(ManifestError::FieldType { field }),
    }
}

fn decode_major(value: &JsonValue, field: &'static str) -> Result<MajorVersion, ManifestError> {
    MajorVersion::new(as_unsigned(value, field)?)
        .map_err(|error| ManifestError::Range { field, error })
}

fn decode_range(
    value: &JsonValue,
    field: &'static str,
    min_field: &'static str,
    max_field: &'static str,
) -> Result<VersionRange, ManifestError> {
    let object = as_object(value, field)?;
    let min = decode_major(member(object, "min", min_field)?, min_field)?;
    let max = decode_major(member(object, "max", max_field)?, max_field)?;
    VersionRange::new(min, max).map_err(|error| ManifestError::Range { field, error })
}

fn decode_digest(
    value: &JsonValue,
    field: &'static str,
    algorithm_field: &'static str,
    hex_field: &'static str,
) -> Result<ArtifactDigest, ManifestError> {
    let object = as_object(value, field)?;
    let algorithm = as_text(
        member(object, "algorithm", algorithm_field)?,
        algorithm_field,
    )?;
    let hex = as_text(member(object, "hex", hex_field)?, hex_field)?;
    ArtifactDigest::new(algorithm, hex)
}

fn decode_sdk(value: &JsonValue) -> Result<SdkCompatibility, ManifestError> {
    let object = as_object(value, "sdk")?;
    let protocol = decode_range(
        member(object, "protocol", "sdk_protocol")?,
        "sdk_protocol",
        "sdk_protocol_min",
        "sdk_protocol_max",
    )?;
    let schema_digest = decode_digest(
        member(object, "schema_digest", "sdk_schema_digest")?,
        "sdk_schema_digest",
        "sdk_schema_digest_algorithm",
        "sdk_schema_digest_hex",
    )?;
    Ok(SdkCompatibility::new(protocol, schema_digest))
}

fn decode_capability(value: &JsonValue) -> Result<CapabilityRequirement, ManifestError> {
    let object = as_object(value, "capabilities")?;
    let id = as_text(member(object, "id", "capability_id")?, "capability_id")?;
    let required = as_boolean(
        member(object, "required", "capability_required")?,
        "capability_required",
    )?;
    if required {
        CapabilityRequirement::required(id)
    } else {
        CapabilityRequirement::optional(id)
    }
}

fn decode_credential(value: &JsonValue) -> Result<CredentialDescriptor, ManifestError> {
    let object = as_object(value, "credentials")?;
    let name = as_text(
        member(object, "name", "credential_name")?,
        "credential_name",
    )?;
    let version = as_unsigned(
        member(object, "version", "credential_version")?,
        "credential_version",
    )?;
    CredentialDescriptor::new(name, version)
}

fn decode_rollback(value: &JsonValue) -> Result<RollbackTarget, ManifestError> {
    let object = as_object(value, "rollback")?;
    let version = as_text(
        member(object, "version", "rollback_version")?,
        "rollback_version",
    )?;
    let database_schema = decode_range(
        member(object, "database_schema", "rollback_database_schema")?,
        "rollback_database_schema",
        "rollback_database_schema_min",
        "rollback_database_schema_max",
    )?;
    RollbackTarget::new(version, database_schema)
}
