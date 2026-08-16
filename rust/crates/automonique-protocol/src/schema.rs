// SPDX-License-Identifier: Elastic-2.0

//! Pinned upstream schema bundles and compatibility classification.
//!
//! A provider upgrade is admitted only when the diff between its pinned schema
//! and its new one classifies. `Unclassifiable` is a first-class outcome and
//! never collapses into `Compatible`: a construct these rules do not model is
//! a reason to stop, not a reason to proceed.
//!
//! Everything here is a pure function over supplied documents. Nothing fetches
//! a URL, executes a provider binary or consults a registry.
//!
//! Digests are *computed*, never taken on trust. A [`SchemaDocument`] encodes
//! itself canonically ([`SchemaDocument::canonical_bytes`]) and hashes those
//! bytes with the crate's own dependency-free SHA-256 ([`crate::digest`]), so
//! [`PinnedBundle::load`] can check a checked-in declared digest against the
//! document it claims to describe. A loaded bundle then has no digest field to
//! drift from its document: [`PinnedBundle::digest`] derives the digest on
//! demand, which makes a bundle whose digest disagrees with its content
//! unrepresentable rather than merely refused once.

use core::fmt;
use std::error::Error;

use crate::codec::{MajorVersion, VersionRange};
use crate::digest::{DigestError, Sha256, Sha256Digest};

/// Maximum UTF-8 byte length of a schema path or identifier.
pub const MAX_SCHEMA_FIELD_BYTES: usize = 512;

/// Whether unknown values of an enum may be tolerated.
///
/// Mirrors the `R1-03` decode rule: a security-sensitive enum rejects unknown
/// values, so *adding* one is breaking for every existing reader.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnumSensitivity {
    /// Unknown values are refused by readers.
    SecuritySensitive,
    /// Unknown values decode to an explicit unknown representation.
    ReadOnly,
}

/// One field in a schema document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDescriptor {
    path: String,
    required: bool,
    type_name: String,
}

impl FieldDescriptor {
    /// Describe a field.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::FieldInvalid`] for an empty or oversized path or
    /// type name.
    pub fn new(path: &str, required: bool, type_name: &str) -> Result<Self, SchemaError> {
        bounded(path, "path")?;
        bounded(type_name, "type_name")?;
        Ok(Self {
            path: path.to_owned(),
            required,
            type_name: type_name.to_owned(),
        })
    }

    /// Dotted path to the field.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the field must be present.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }

    /// Declared type name.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
}

/// One enumeration in a schema document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumDescriptor {
    path: String,
    sensitivity: EnumSensitivity,
    values: Vec<String>,
}

impl EnumDescriptor {
    /// Describe an enumeration.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::FieldInvalid`] for an invalid path or value.
    pub fn new(
        path: &str,
        sensitivity: EnumSensitivity,
        values: &[&str],
    ) -> Result<Self, SchemaError> {
        bounded(path, "path")?;
        for value in values {
            bounded(value, "enum_value")?;
        }
        let mut owned: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        owned.sort_unstable();
        owned.dedup();
        Ok(Self {
            path: path.to_owned(),
            sensitivity,
            values: owned,
        })
    }

    /// Dotted path to the enumeration.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether unknown values may be tolerated.
    #[must_use]
    pub const fn sensitivity(&self) -> EnumSensitivity {
        self.sensitivity
    }

    /// Declared values, sorted and deduplicated.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

/// A modelled view of one upstream schema document.
///
/// `unmodelled` carries constructs these rules do not understand. A change
/// there is the source of an [`VerdictKind::Unclassifiable`] verdict, which is
/// what keeps the classifier honest about its own coverage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaDocument {
    fields: Vec<FieldDescriptor>,
    enums: Vec<EnumDescriptor>,
    message_kinds: Vec<String>,
    endpoints: Vec<String>,
    unmodelled: Vec<(String, String)>,
}

impl SchemaDocument {
    /// Build a document from its modelled parts.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::FieldInvalid`] for an invalid identifier.
    pub fn new(
        fields: Vec<FieldDescriptor>,
        enums: Vec<EnumDescriptor>,
        message_kinds: &[&str],
        endpoints: &[&str],
        unmodelled: &[(&str, &str)],
    ) -> Result<Self, SchemaError> {
        for kind in message_kinds {
            bounded(kind, "message_kind")?;
        }
        for endpoint in endpoints {
            bounded(endpoint, "endpoint")?;
        }
        for (key, value) in unmodelled {
            bounded(key, "unmodelled_key")?;
            bounded(value, "unmodelled_value")?;
        }
        let mut fields = fields;
        fields.sort_by(|left, right| left.path.cmp(&right.path));
        let mut enums = enums;
        enums.sort_by(|left, right| left.path.cmp(&right.path));
        let mut kinds: Vec<String> = message_kinds.iter().map(|k| (*k).to_owned()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        let mut routes: Vec<String> = endpoints.iter().map(|e| (*e).to_owned()).collect();
        routes.sort_unstable();
        routes.dedup();
        let mut extras: Vec<(String, String)> = unmodelled
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        extras.sort();
        Ok(Self {
            fields,
            enums,
            message_kinds: kinds,
            endpoints: routes,
            unmodelled: extras,
        })
    }

    /// The exact bytes this document is digested over.
    ///
    /// The encoding is canonical and injective: every section is preceded by
    /// its element count and every string by its byte length, both as
    /// big-endian `u64`, so no two different documents share an encoding and no
    /// concatenation of parts can be mistaken for a different split of the same
    /// text. Construction already sorts and deduplicates every section, so the
    /// encoding depends on the document's content and never on the order its
    /// parts were supplied in.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        push_text(&mut bytes, CANONICAL_ENCODING);
        push_count(&mut bytes, self.fields.len());
        for field in &self.fields {
            push_text(&mut bytes, &field.path);
            push_text(&mut bytes, &field.type_name);
            bytes.push(u8::from(field.required));
        }
        push_count(&mut bytes, self.enums.len());
        for entry in &self.enums {
            push_text(&mut bytes, &entry.path);
            bytes.push(match entry.sensitivity {
                EnumSensitivity::SecuritySensitive => 1,
                EnumSensitivity::ReadOnly => 0,
            });
            push_count(&mut bytes, entry.values.len());
            for value in &entry.values {
                push_text(&mut bytes, value);
            }
        }
        push_count(&mut bytes, self.message_kinds.len());
        for kind in &self.message_kinds {
            push_text(&mut bytes, kind);
        }
        push_count(&mut bytes, self.endpoints.len());
        for endpoint in &self.endpoints {
            push_text(&mut bytes, endpoint);
        }
        push_count(&mut bytes, self.unmodelled.len());
        for (key, value) in &self.unmodelled {
            push_text(&mut bytes, key);
            push_text(&mut bytes, value);
        }
        bytes
    }

    /// The SHA-256 digest of [`Self::canonical_bytes`].
    ///
    /// This is the digest a pinned bundle must declare.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256::digest(&self.canonical_bytes())
    }
}

/// Why a bundle, registry or descriptor was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaError {
    /// The digest computed from the document did not match the declared one.
    ///
    /// Both are named so an operator can repin without recomputing by hand.
    DigestMismatch {
        /// The digest the bundle declared.
        declared: Sha256Digest,
        /// The digest computed from the document the bundle carries.
        computed: Sha256Digest,
    },
    /// A declared digest was not a canonical `sha256:` spelling.
    DigestMalformed {
        /// Which part of the spelling was wrong.
        error: DigestError,
    },
    /// Two bundles claim overlapping binary version ranges for one provider.
    OverlappingRanges {
        /// The provider whose ranges collide.
        provider: String,
    },
    /// A bounded identifier was empty, oversized or contained a control.
    FieldInvalid {
        /// The rejected field.
        field: &'static str,
    },
}

impl SchemaError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::DigestMalformed { .. } => "digest_malformed",
            Self::OverlappingRanges { .. } => "overlapping_ranges",
            Self::FieldInvalid { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch { declared, computed } => write!(
                formatter,
                "document digest is {computed}, but the bundle declared {declared}"
            ),
            Self::DigestMalformed { error } => write!(formatter, "declared digest: {error}"),
            Self::OverlappingRanges { provider } => write!(
                formatter,
                "provider {provider} has two bundles with overlapping version ranges"
            ),
            Self::FieldInvalid { field } => write!(formatter, "field {field} is invalid"),
        }
    }
}

impl Error for SchemaError {}

/// A checked-in schema bundle pinned to a binary version range.
///
/// The bundle stores no digest. [`Self::digest`] recomputes it from the
/// document, so the two can never disagree after loading; the declared digest
/// exists only as the checked-in claim [`Self::load`] verifies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedBundle {
    provider: String,
    binary_versions: VersionRange,
    document: SchemaDocument,
}

impl PinnedBundle {
    /// Load a bundle, verifying the document against its declared digest.
    ///
    /// `declared_digest` is the checked-in pin, in canonical
    /// `sha256:<64 lowercase hex digits>` form. It is compared against the
    /// digest computed from `document` here and now: a bundle whose document
    /// has changed since it was pinned does not load. There is no parameter
    /// through which a caller can supply the computed digest, so the two are
    /// never trusted independently.
    ///
    /// ```
    /// use automonique_protocol::codec::{MajorVersion, VersionRange};
    /// use automonique_protocol::schema::{PinnedBundle, SchemaDocument};
    ///
    /// let document = SchemaDocument::new(vec![], vec![], &["turn_started"], &[], &[])?;
    /// let declared = document.digest().to_string();
    /// let bundle = PinnedBundle::load(
    ///     "codex",
    ///     VersionRange::exact(MajorVersion::FIRST),
    ///     &declared,
    ///     document,
    /// )?;
    /// assert_eq!(bundle.digest().to_string(), declared);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Handing `load` a digest the caller computed itself does not compile:
    /// there is no fifth parameter to put it in. The only difference from the
    /// case above is that extra argument.
    ///
    /// ```compile_fail,E0061
    /// use automonique_protocol::codec::{MajorVersion, VersionRange};
    /// use automonique_protocol::schema::{PinnedBundle, SchemaDocument};
    ///
    /// let document = SchemaDocument::new(vec![], vec![], &["turn_started"], &[], &[])?;
    /// let declared = document.digest().to_string();
    /// let bundle = PinnedBundle::load(
    ///     "codex",
    ///     VersionRange::exact(MajorVersion::FIRST),
    ///     &declared,
    ///     &declared,
    ///     document,
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::DigestMalformed`] when `declared_digest` is not a
    /// canonical `sha256:` spelling, [`SchemaError::DigestMismatch`] when it
    /// does not describe `document`, and [`SchemaError::FieldInvalid`] for an
    /// empty or oversized provider.
    pub fn load(
        provider: &str,
        binary_versions: VersionRange,
        declared_digest: &str,
        document: SchemaDocument,
    ) -> Result<Self, SchemaError> {
        bounded(provider, "provider")?;
        let declared: Sha256Digest = declared_digest
            .parse()
            .map_err(|error| SchemaError::DigestMalformed { error })?;
        let computed = document.digest();
        if declared != computed {
            return Err(SchemaError::DigestMismatch { declared, computed });
        }
        Ok(Self {
            provider: provider.to_owned(),
            binary_versions,
            document,
        })
    }

    /// The provider this bundle describes.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The binary versions this bundle is asserted to cover.
    #[must_use]
    pub const fn binary_versions(&self) -> VersionRange {
        self.binary_versions
    }

    /// The document's digest, recomputed from the document.
    ///
    /// Deriving rather than storing is what makes a bundle whose digest
    /// disagrees with its content unrepresentable.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.document.digest()
    }

    /// The modelled schema.
    #[must_use]
    pub const fn document(&self) -> &SchemaDocument {
        &self.document
    }
}

/// What a version lookup found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution<'a> {
    /// A bundle covers this version.
    Pinned(&'a PinnedBundle),
    /// No bundle covers this version.
    ///
    /// Explicitly not a nearest neighbour: guessing which pinned schema applies
    /// to an unpinned binary is how a schema drift goes unnoticed.
    Unpinned,
}

/// Bundles indexed by provider and binary version range.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BundleRegistry {
    bundles: Vec<PinnedBundle>,
}

impl BundleRegistry {
    /// Start an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bundles: Vec::new(),
        }
    }

    /// Add a bundle.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::OverlappingRanges`] when another bundle for the
    /// same provider already claims an overlapping range, so a lookup can never
    /// silently choose between two answers.
    pub fn insert(&mut self, bundle: PinnedBundle) -> Result<(), SchemaError> {
        if self.bundles.iter().any(|existing| {
            existing.provider == bundle.provider
                && existing
                    .binary_versions
                    .negotiate(bundle.binary_versions)
                    .is_ok()
        }) {
            return Err(SchemaError::OverlappingRanges {
                provider: bundle.provider.clone(),
            });
        }
        self.bundles.push(bundle);
        Ok(())
    }

    /// Find the bundle covering one provider binary version.
    #[must_use]
    pub fn resolve(&self, provider: &str, version: MajorVersion) -> Resolution<'_> {
        self.bundles
            .iter()
            .find(|bundle| bundle.provider == provider && bundle.binary_versions.accepts(version))
            .map_or(Resolution::Unpinned, Resolution::Pinned)
    }
}

/// One difference the classifier found.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Change {
    path: String,
    reason: &'static str,
}

impl Change {
    /// The schema path that changed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Why the change was classified as it was.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

/// The three possible classifications.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerdictKind {
    /// Purely additive.
    Compatible,
    /// A removal, narrowing, new requirement or new refused enum value.
    Breaking,
    /// The diff contains a construct these rules do not model.
    Unclassifiable,
}

impl VerdictKind {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Breaking => "breaking",
            Self::Unclassifiable => "unclassifiable",
        }
    }
}

/// A classification and the changes that justified it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verdict {
    kind: VerdictKind,
    evidence: Vec<Change>,
}

impl Verdict {
    /// The classification.
    #[must_use]
    pub const fn kind(&self) -> VerdictKind {
        self.kind
    }

    /// The changes that justified it, in canonical order.
    ///
    /// A `Breaking` or `Unclassifiable` verdict always names at least one
    /// change; only a `Compatible` verdict may be empty, and only when the two
    /// documents are identical.
    #[must_use]
    pub fn evidence(&self) -> &[Change] {
        &self.evidence
    }
}

/// Classify a schema upgrade.
///
/// Precedence is `Breaking` over `Unclassifiable` over `Compatible`. A definite
/// breakage is the more actionable answer, and an unmodelled construct must
/// never be reported as compatible.
#[must_use]
pub fn classify(previous: &SchemaDocument, next: &SchemaDocument) -> Verdict {
    let mut breaking = Vec::new();
    let mut unclassifiable = Vec::new();
    let mut additive = Vec::new();

    for old in &previous.fields {
        match next.fields.iter().find(|new| new.path == old.path) {
            None => breaking.push(change(&old.path, "field removed")),
            Some(new) => {
                if new.type_name != old.type_name {
                    breaking.push(change(&old.path, "field type changed"));
                }
                if new.required && !old.required {
                    breaking.push(change(&old.path, "field became required"));
                } else if old.required && !new.required {
                    additive.push(change(&old.path, "field became optional"));
                }
            }
        }
    }
    for new in &next.fields {
        if !previous.fields.iter().any(|old| old.path == new.path) {
            if new.is_required() {
                breaking.push(change(&new.path, "required field added"));
            } else {
                additive.push(change(&new.path, "optional field added"));
            }
        }
    }

    for old in &previous.enums {
        match next.enums.iter().find(|new| new.path == old.path) {
            None => breaking.push(change(&old.path, "enum removed")),
            Some(new) => {
                for value in &old.values {
                    if !new.values.contains(value) {
                        breaking.push(change(&old.path, "enum value removed"));
                    }
                }
                for value in &new.values {
                    if !old.values.contains(value) {
                        match old.sensitivity {
                            // An existing reader fails closed on this value, so
                            // adding it is not compatible merely because it is
                            // an addition.
                            EnumSensitivity::SecuritySensitive => breaking.push(change(
                                &old.path,
                                "value added to a security-sensitive enum",
                            )),
                            EnumSensitivity::ReadOnly => {
                                additive.push(change(&old.path, "value added to a read-only enum"));
                            }
                        }
                    }
                }
                if new.sensitivity != old.sensitivity {
                    breaking.push(change(&old.path, "enum sensitivity changed"));
                }
            }
        }
    }
    for new in &next.enums {
        if !previous.enums.iter().any(|old| old.path == new.path) {
            additive.push(change(&new.path, "enum added"));
        }
    }

    classify_names(
        &previous.message_kinds,
        &next.message_kinds,
        "message kind",
        &mut breaking,
        &mut additive,
    );
    classify_names(
        &previous.endpoints,
        &next.endpoints,
        "endpoint",
        &mut breaking,
        &mut additive,
    );

    if previous.unmodelled != next.unmodelled {
        for (key, _) in previous
            .unmodelled
            .iter()
            .filter(|entry| !next.unmodelled.contains(entry))
        {
            unclassifiable.push(change(key, "unmodelled construct changed or removed"));
        }
        for (key, _) in next
            .unmodelled
            .iter()
            .filter(|entry| !previous.unmodelled.contains(entry))
        {
            unclassifiable.push(change(key, "unmodelled construct added or changed"));
        }
    }

    let (kind, mut evidence) = if breaking.is_empty() {
        if unclassifiable.is_empty() {
            (VerdictKind::Compatible, additive)
        } else {
            (VerdictKind::Unclassifiable, unclassifiable)
        }
    } else {
        (VerdictKind::Breaking, breaking)
    };
    evidence.sort();
    evidence.dedup();
    Verdict { kind, evidence }
}

fn classify_names(
    previous: &[String],
    next: &[String],
    noun: &'static str,
    breaking: &mut Vec<Change>,
    additive: &mut Vec<Change>,
) {
    for old in previous {
        if !next.contains(old) {
            breaking.push(Change {
                path: old.clone(),
                reason: if noun == "endpoint" {
                    "endpoint removed"
                } else {
                    "message kind removed"
                },
            });
        }
    }
    for new in next {
        if !previous.contains(new) {
            additive.push(Change {
                path: new.clone(),
                reason: if noun == "endpoint" {
                    "endpoint added"
                } else {
                    "message kind added"
                },
            });
        }
    }
}

fn change(path: &str, reason: &'static str) -> Change {
    Change {
        path: path.to_owned(),
        reason,
    }
}

/// Names the encoding a digest is taken over, so a digest of these bytes cannot
/// be confused with a digest of some other structure that happens to serialize
/// the same way.
const CANONICAL_ENCODING: &str = "automonique.schema.document/v1";

fn push_count(bytes: &mut Vec<u8>, count: usize) {
    bytes.extend_from_slice(&(count as u64).to_be_bytes());
}

fn push_text(bytes: &mut Vec<u8>, value: &str) {
    push_count(bytes, value.len());
    bytes.extend_from_slice(value.as_bytes());
}

fn bounded(value: &str, field: &'static str) -> Result<(), SchemaError> {
    // This module's error carries no violation class, so the class is
    // dropped rather than translated — as it always was.
    crate::primitives::bounded_value(value, MAX_SCHEMA_FIELD_BYTES)
        .map_err(|_| SchemaError::FieldInvalid { field })
}
