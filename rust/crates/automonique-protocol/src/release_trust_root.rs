// SPDX-License-Identifier: Elastic-2.0

//! The typed release trust root: every check a signed release needs except the
//! signature check itself.
//!
//! # What this module is, in one paragraph
//!
//! A release manifest ([`crate::release::ReleaseManifest`]) says what a release
//! is. It does not say who vouched for it. This module models the missing half:
//! a pinned [`TrustedKeySet`], a [`ReleaseAttestation`] that binds a manifest
//! digest to a key and an algorithm, and [`verify_attestation`], which walks a
//! fixed state machine from the attestation to a closed [`AttestationVerdict`].
//! Everything on that walk is implemented and tested. The final step — checking
//! that the signature bytes are a valid signature over
//! [`ReleaseAttestation::signing_payload`] — is not, and cannot be here.
//!
//! # No input reaches [`AttestationVerdict::Verified`]
//!
//! This is not a caution, a default or a policy. It is the type system:
//! `Verified` carries a [`SignatureProof`], and `SignatureProof` is
//! **uninhabited**. No expression in this crate — or in any crate that depends
//! on it — has that type, so the variant cannot be constructed by
//! [`verify_attestation`], by a test, or by a caller who would like to. The
//! same holds for [`ReleaseTrustDecision::Admit`], which carries the same proof.
//! A well-formed attestation whose key is trusted, whose algorithm is allowed
//! and whose manifest digest agrees reaches
//! [`AttestationVerdict::Unverifiable`] with
//! [`UnverifiableReason::NoCryptoBackend`], and a caller that maps that verdict
//! to a decision gets [`TrustRefusal::NoTrustRoot`].
//!
//! Two independent things are missing, and both must be supplied before any
//! signature can be checked:
//!
//! 1. **A verification primitive.** This crate declares no dependencies and
//!    forbids `unsafe`. It implements SHA-256 from FIPS 180-4 in
//!    [`crate::digest`] because a hash is a short, reviewable transform; an
//!    Ed25519 or ECDSA verifier is not, and hand-rolling one here would trade a
//!    missing check for a wrong one.
//! 2. **Key material.** A [`TrustedKey`] is a *name* and an *algorithm*. It
//!    carries no public key, because a key set that is data this module accepts
//!    is not a trust root — it is one more input an attacker can supply. Where
//!    the material comes from and how it is pinned is the reviewed decision this
//!    module deliberately does not make.
//!
//! So the seam is narrow but it is not a one-liner, and this module does not
//! claim it is. What it does claim is that no *other* check remains: key-set
//! membership, the algorithm allowlist, per-key algorithm agreement, manifest
//! digest agreement, every bound and every grammar are done here, once, in a
//! fixed order, with a typed refusal each.
//!
//! # The verification state machine
//!
//! [`verify_attestation`] evaluates in this order and returns at the first
//! failure. The order is part of the contract, so a caller reasoning about a
//! refusal knows what was and was not reached:
//!
//! | Step | Check | Refusal |
//! | ---- | ----- | ------- |
//! | 0 | the attestation is well formed | [`AttestationVerdict::Malformed`] (document route only) |
//! | 1 | the algorithm is one the key set allows at all | [`AttestationVerdict::DisallowedAlgorithm`] |
//! | 2 | the key id names a key in the set | [`AttestationVerdict::UnknownKey`] |
//! | 3 | the algorithm is *that key's* algorithm | [`AttestationVerdict::KeyAlgorithmMismatch`] |
//! | 4 | the bound digest is the manifest's canonical digest | [`AttestationVerdict::ManifestDigestMismatch`] |
//! | 5 | the signature verifies | [`AttestationVerdict::Unverifiable`] — the seam |
//!
//! Step 1 before step 2 is deliberate: an algorithm the trust root does not
//! admit is refused whether or not the key exists, so a caller cannot learn key
//! membership by varying the algorithm. Step 3 exists separately from step 1
//! because an attacker who can pick the algorithm for a *known* key is
//! attacking algorithm confusion, not the allowlist.
//!
//! # This module grants no execution authority
//!
//! There is no `AdmittedRelease`, no launch type and no I/O. Nothing here reads
//! a file, opens a socket or spawns anything. A [`ReleaseTrustDecision`] is a
//! value; today the only value it can take is a refusal.
//!
//! # The wiring a later slice will do, and that this one does not
//!
//! `automonique-sandbox`'s `RunnerAdmissionSealer::issue_release_candidate`
//! currently refuses every `ReleaseBoundaryCandidate` with
//! `RunnerAdmissionError::MissingIndependentReleaseReview`, unconditionally.
//! The slice that consumes this module would:
//!
//! 1. carry an attestation document alongside the manifest bytes it already
//!    binds, parse it with [`ReleaseAttestation::from_canonical_bytes`], and
//!    keep the parse refusal typed;
//! 2. verify it against a key set pinned in that crate — not read from data —
//!    with [`verify_attestation`];
//! 3. map the verdict with [`ReleaseTrustDecision::from_verdict`] and refuse on
//!    anything that is not `Admit`, which today is everything.
//!
//! That wiring changes no behaviour: `Refuse { reason: NoTrustRoot }` is exactly
//! the refusal the sealer already returns. It is worth doing anyway, because it
//! replaces an unconditional refusal with one that names *which* check failed —
//! but it is a separate, separately reviewed change, and it is not in this file.
//!
//! One thing that wiring must not lose: the sandbox pins the SHA-256 of the
//! exact manifest *bytes* it received, while
//! [`crate::release::ReleaseManifest::canonical_digest`] covers the manifest as
//! this build interprets it. Those are different statements and a release
//! boundary wants both. They compose; neither replaces the other.
//!
//! # Worked example — the honest path
//!
//! ```
//! use automonique_protocol::release::{ArtifactKind, ArtifactDigest, ReleaseManifestBuilder,
//!     SdkCompatibility};
//! use automonique_protocol::codec::{MajorVersion, VersionRange};
//! use automonique_protocol::release_trust_root::{
//!     AttestationVerdict, ReleaseAttestation, ReleaseTrustDecision, TrustRefusal, TrustedKey,
//!     TrustedKeySet, UnverifiableReason, verify_attestation,
//! };
//!
//! let one = MajorVersion::new(1).unwrap();
//! let range = VersionRange::new(one, one).unwrap();
//! let hex = "aa".repeat(32);
//! let manifest = ReleaseManifestBuilder::new()
//!     .schema_revision(1)
//!     .version("0.1.0")
//!     .source_revision("6f1c2f")
//!     .build_target("x86_64-unknown-linux-gnu")
//!     .protocol(range)
//!     .events(range)
//!     .database_schema(range)
//!     .sdk(SdkCompatibility::new(range, ArtifactDigest::new("sha-256", &hex).unwrap()))
//!     .digest(ArtifactKind::Binary, ArtifactDigest::new("sha-256", &hex).unwrap())
//!     .build()
//!     .unwrap();
//!
//! let keys = TrustedKeySet::new([TrustedKey::new("release-2026-a", "ed25519").unwrap()]).unwrap();
//! // Every field valid, the key trusted, the algorithm allowed, the digest
//! // the manifest's own.
//! let attestation = ReleaseAttestation::new(
//!     manifest.canonical_digest(),
//!     "release-2026-a",
//!     "ed25519",
//!     &"7c".repeat(64),
//! )
//! .unwrap();
//!
//! let verdict = verify_attestation(&manifest, &attestation, &keys);
//! assert_eq!(
//!     verdict,
//!     AttestationVerdict::Unverifiable { reason: UnverifiableReason::NoCryptoBackend }
//! );
//! assert_eq!(
//!     ReleaseTrustDecision::from_verdict(verdict),
//!     ReleaseTrustDecision::Refuse { reason: TrustRefusal::NoTrustRoot }
//! );
//! ```
//!
//! There is no expression of type [`SignatureProof`], so the success arm cannot
//! be written:
//!
//! ```compile_fail
//! use automonique_protocol::release_trust_root::{AttestationVerdict, SignatureProof};
//! // `SignatureProof` is uninhabited and has no constructor.
//! let minted = AttestationVerdict::Verified(SignatureProof::new());
//! ```
//!
//! A trust root is pinned in a build, not parsed from data, so there is no
//! document reader for one:
//!
//! ```compile_fail
//! use automonique_protocol::release_trust_root::TrustedKeySet;
//! let keys = TrustedKeySet::from_canonical_bytes(b"{}").unwrap();
//! ```
//!
//! A trusted key names a key; it cannot carry one:
//!
//! ```compile_fail
//! use automonique_protocol::release_trust_root::TrustedKey;
//! let key = TrustedKey::new("release-2026-a", "ed25519", "d75a980182b10ab7").unwrap();
//! ```
//!
//! The same call without the material — the one difference — compiles:
//!
//! ```
//! use automonique_protocol::release_trust_root::TrustedKey;
//! let key = TrustedKey::new("release-2026-a", "ed25519").unwrap();
//! assert_eq!(key.id().as_str(), "release-2026-a");
//! ```

use core::fmt;
use std::error::Error;

use crate::codec::CodecError;
use crate::primitives::ValueError;
use crate::release::{ArtifactDigest, DigestAlgorithm, ManifestError, ReleaseManifest};
use crate::wire::{JsonValue, parse_canonical};

/// Stable schema name of the attestation document form.
pub const RELEASE_ATTESTATION_SCHEMA_V1: &str = "automonique.release-attestation/v1";

/// Maximum number of keys one trust root may pin.
///
/// A release trust root is a short, reviewed list. A set that needs more than
/// this many keys is a signal that the pinning story has drifted, and the bound
/// makes that a refusal rather than a shrug.
pub const MAX_TRUSTED_KEYS: usize = 16;

/// Maximum UTF-8 byte length of a key identifier.
pub const MAX_KEY_ID_BYTES: usize = 64;

/// Maximum size of an attestation document.
pub const MAX_ATTESTATION_DOCUMENT_BYTES: usize = 4096;

/// Document keys an attestation may carry, in canonical order.
///
/// The set is closed and, unlike a manifest's, has no unknown-field retention:
/// a signature over a field this build cannot interpret is a statement about
/// something unknown, and a trust root must not report such a thing as checked.
pub const KNOWN_ATTESTATION_FIELDS: [&str; 5] = [
    "algorithm",
    "key_id",
    "manifest_digest",
    "schema",
    "signature",
];

/// Signature algorithms a release attestation may name.
///
/// The set is closed. It excludes RSA with PKCS#1 v1.5 and every "none"-style
/// spelling, and it names one curve per family so an attestation cannot select
/// parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032), 64-byte signature.
    Ed25519,
    /// ECDSA over NIST P-256 with SHA-256, fixed-width `r || s`.
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }

    /// Map a wire spelling to an algorithm this build names.
    ///
    /// Returns `None` for anything else, including `none`, `rsa-pkcs1-sha256`
    /// and any capitalized variant of an accepted spelling.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256-sha256" => Some(Self::EcdsaP256Sha256),
            _ => None,
        }
    }

    /// Exact hexadecimal length of a signature in this algorithm.
    ///
    /// Both accepted algorithms use a 64-byte fixed-width signature, so this
    /// width does not distinguish them; the per-key algorithm check does. The
    /// ECDSA width is the `r || s` encoding rather than DER, because DER is
    /// variable-length and admits several encodings of one signature — a
    /// malleability this build refuses to carry rather than normalize.
    #[must_use]
    pub const fn signature_hex_len(self) -> usize {
        match self {
            Self::Ed25519 | Self::EcdsaP256Sha256 => 128,
        }
    }
}

/// Why a trust-root value was rejected.
///
/// No variant carries signature bytes, key material or a host path. A key
/// identifier may appear: it is a public, bounded, grammar-checked name, and a
/// refusal that cannot say which key it means is not actionable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustRootError {
    /// The bytes are not a canonical attestation document.
    Document {
        /// Refusal the canonical reader returned.
        error: CodecError,
    },
    /// The document exceeded the defensive size bound.
    DocumentTooLarge {
        /// Maximum accepted byte length.
        max: usize,
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
    /// The document carried a key outside [`KNOWN_ATTESTATION_FIELDS`].
    UnknownField,
    /// The document did not declare [`RELEASE_ATTESTATION_SCHEMA_V1`].
    UnsupportedSchema,
    /// A key identifier violated the shared bounded-value rules.
    KeyIdBounds {
        /// Violation class.
        error: ValueError,
    },
    /// A key identifier used a character outside its grammar.
    KeyIdCharacter,
    /// The algorithm is not one [`SignatureAlgorithm::from_wire`] names.
    UnknownAlgorithm,
    /// The signature is not the exact width its algorithm fixes.
    SignatureLength {
        /// Expected hexadecimal length.
        expected_len: usize,
        /// Supplied hexadecimal length.
        actual_len: usize,
    },
    /// The signature is not lowercase hexadecimal.
    SignatureCharacter,
    /// The bound manifest digest is not a valid digest.
    ManifestDigest {
        /// Refusal the release protocol returned.
        error: ManifestError,
    },
    /// The bound manifest digest names an algorithm this build cannot recompute.
    ///
    /// [`ReleaseManifest::canonical_digest`] is SHA-256, so an attestation
    /// bound with SHA-512 could never be compared against anything. It is
    /// refused at construction rather than reaching a verdict that would look
    /// like a mismatch.
    UnsupportedManifestDigestAlgorithm,
    /// A trust root with no keys trusts nothing and would refuse everything for
    /// the wrong reason.
    NoTrustedKeys,
    /// One key identifier was pinned twice, which makes "the trusted key" a
    /// question with two answers.
    DuplicateTrustedKeyId {
        /// The repeated identifier.
        key_id: KeyId,
    },
    /// More keys were pinned than [`MAX_TRUSTED_KEYS`] allows.
    TooManyTrustedKeys {
        /// Maximum accepted.
        max: usize,
    },
}

impl TrustRootError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Document { .. } => "malformed_document",
            Self::DocumentTooLarge { .. } => "document_too_large",
            Self::MissingField { .. } => "missing_field",
            Self::FieldType { .. } => "field_type",
            Self::UnknownField => "unknown_field",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::KeyIdBounds { .. } => "key_id_invalid",
            Self::KeyIdCharacter => "key_id_character",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::SignatureLength { .. } => "signature_length",
            Self::SignatureCharacter => "signature_character",
            Self::ManifestDigest { .. } => "manifest_digest_invalid",
            Self::UnsupportedManifestDigestAlgorithm => "unsupported_manifest_digest_algorithm",
            Self::NoTrustedKeys => "no_trusted_keys",
            Self::DuplicateTrustedKeyId { .. } => "duplicate_trusted_key_id",
            Self::TooManyTrustedKeys { .. } => "too_many_trusted_keys",
        }
    }
}

impl fmt::Display for TrustRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document { error } => {
                write!(formatter, "attestation document is not canonical: {error}")
            }
            Self::DocumentTooLarge { max } => {
                write!(formatter, "attestation document exceeds {max} bytes")
            }
            Self::MissingField { field } => write!(formatter, "required field {field} is absent"),
            Self::FieldType { field } => write!(formatter, "field {field} has the wrong JSON type"),
            Self::UnknownField => {
                formatter.write_str("attestation carries a field this build does not interpret")
            }
            Self::UnsupportedSchema => write!(
                formatter,
                "attestation does not declare {RELEASE_ATTESTATION_SCHEMA_V1}"
            ),
            Self::KeyIdBounds { error } => write!(formatter, "key id: {error}"),
            Self::KeyIdCharacter => {
                formatter.write_str("key id contains a character outside its grammar")
            }
            Self::UnknownAlgorithm => {
                formatter.write_str("signature algorithm is not one this build names")
            }
            Self::SignatureLength {
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "signature is {actual_len} hex characters; expected {expected_len}"
            ),
            Self::SignatureCharacter => {
                formatter.write_str("signature is not lowercase hexadecimal")
            }
            Self::ManifestDigest { error } => write!(formatter, "manifest digest: {error}"),
            Self::UnsupportedManifestDigestAlgorithm => {
                formatter.write_str("manifest digest algorithm is one this build cannot recompute")
            }
            Self::NoTrustedKeys => formatter.write_str("trust root pins no keys"),
            Self::DuplicateTrustedKeyId { key_id } => {
                write!(formatter, "key id {key_id} is pinned twice")
            }
            Self::TooManyTrustedKeys { max } => {
                write!(formatter, "trust root pins more than {max} keys")
            }
        }
    }
}

impl Error for TrustRootError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Document { error } => Some(error),
            Self::ManifestDigest { error } => Some(error),
            _ => None,
        }
    }
}

/// A public identifier for a signing key.
///
/// An identifier begins with an ASCII lowercase letter and otherwise contains
/// only lowercase letters, digits, `.`, `_` or `-`, within
/// [`MAX_KEY_ID_BYTES`]. The grammar is narrow on purpose: an identifier is
/// compared, logged and rendered, and a value that could hold a path separator,
/// a control character or mixed case would make those three disagree.
///
/// The inner value is private, so the constructor cannot be bypassed:
///
/// ```compile_fail
/// use automonique_protocol::release_trust_root::KeyId;
/// let id = KeyId("../../etc/keys".to_owned());
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId(String);

impl KeyId {
    /// Validate and construct a key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError::KeyIdBounds`] when the value is empty or over
    /// [`MAX_KEY_ID_BYTES`], and [`TrustRootError::KeyIdCharacter`] when it
    /// leaves the grammar.
    pub fn new(value: &str) -> Result<Self, TrustRootError> {
        if value.is_empty() {
            return Err(TrustRootError::KeyIdBounds {
                error: ValueError::Empty,
            });
        }
        if value.len() > MAX_KEY_ID_BYTES {
            return Err(TrustRootError::KeyIdBounds {
                error: ValueError::TooLong {
                    max_bytes: MAX_KEY_ID_BYTES,
                    actual_bytes: value.len(),
                },
            });
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(TrustRootError::KeyIdCharacter);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One key a trust root pins: a name and the algorithm it signs with.
///
/// There is deliberately no key material here. A trusted key in this model
/// answers "is this signer one we accept, and with what algorithm", which is a
/// question about the *set*. It does not answer "does this signature check
/// out", which needs bytes this type does not carry and a primitive this crate
/// does not link. Both are named in the module documentation as the seam.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrustedKey {
    id: KeyId,
    algorithm: SignatureAlgorithm,
}

impl TrustedKey {
    /// Pin one key identifier and the algorithm it is trusted for.
    ///
    /// # Errors
    ///
    /// Returns the [`KeyId`] refusal for an invalid identifier and
    /// [`TrustRootError::UnknownAlgorithm`] for an algorithm outside
    /// [`SignatureAlgorithm::from_wire`].
    pub fn new(id: &str, algorithm: &str) -> Result<Self, TrustRootError> {
        Ok(Self {
            id: KeyId::new(id)?,
            algorithm: SignatureAlgorithm::from_wire(algorithm)
                .ok_or(TrustRootError::UnknownAlgorithm)?,
        })
    }

    /// Key identifier.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    /// Algorithm this key is trusted for, and only for.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// The pinned set of keys a release attestation may name.
///
/// The set is the trust root. It is constructed in a build from values a
/// reviewer chose; it is not parsed from a document, because a trust root a
/// caller can supply is not one — see the module-level `compile_fail` example
/// pinning the absence of a reader.
///
/// Keys are held sorted by identifier, so [`Self::key_ids`],
/// [`Self::algorithms`] and [`Self::to_canonical_document`] do not depend on
/// the order a caller happened to list them in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedKeySet {
    keys: Vec<TrustedKey>,
}

impl TrustedKeySet {
    /// Validate and pin a key set.
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError::NoTrustedKeys`] for an empty set,
    /// [`TrustRootError::DuplicateTrustedKeyId`] when one identifier is pinned
    /// twice, and [`TrustRootError::TooManyTrustedKeys`] beyond
    /// [`MAX_TRUSTED_KEYS`].
    pub fn new(keys: impl IntoIterator<Item = TrustedKey>) -> Result<Self, TrustRootError> {
        let mut ordered: Vec<TrustedKey> = Vec::new();
        for key in keys {
            if ordered.len() == MAX_TRUSTED_KEYS {
                return Err(TrustRootError::TooManyTrustedKeys {
                    max: MAX_TRUSTED_KEYS,
                });
            }
            ordered.push(key);
        }
        if ordered.is_empty() {
            return Err(TrustRootError::NoTrustedKeys);
        }
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(TrustRootError::DuplicateTrustedKeyId {
                key_id: pair[0].id.clone(),
            });
        }
        Ok(Self { keys: ordered })
    }

    /// Pinned keys, in identifier order.
    #[must_use]
    pub fn keys(&self) -> &[TrustedKey] {
        &self.keys
    }

    /// Pinned identifiers, in order.
    #[must_use]
    pub fn key_ids(&self) -> Vec<&KeyId> {
        self.keys.iter().map(TrustedKey::id).collect()
    }

    /// Algorithms this set admits at all, deduplicated and in a fixed order.
    ///
    /// The allowlist is derived from the pinned keys rather than configured
    /// beside them, so it cannot drift out of agreement with them.
    #[must_use]
    pub fn algorithms(&self) -> Vec<SignatureAlgorithm> {
        let mut found: Vec<SignatureAlgorithm> =
            self.keys.iter().map(TrustedKey::algorithm).collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Whether any pinned key signs with this algorithm.
    #[must_use]
    pub fn allows_algorithm(&self, algorithm: SignatureAlgorithm) -> bool {
        self.keys.iter().any(|key| key.algorithm == algorithm)
    }

    /// Look up one pinned key.
    ///
    /// The lookup is an ordinary comparison. A key identifier is a public name,
    /// not a secret, so nothing here needs the timing discipline
    /// [`ArtifactDigest::matches`] applies to digests.
    #[must_use]
    pub fn key(&self, id: &KeyId) -> Option<&TrustedKey> {
        self.keys.iter().find(|key| &key.id == id)
    }

    /// Render the pinned set as a canonical document, for review and logging.
    ///
    /// The rendering is deterministic and carries no key material, because
    /// there is none to carry.
    #[must_use]
    pub fn to_canonical_document(&self) -> JsonValue {
        JsonValue::Array(
            self.keys
                .iter()
                .map(|key| {
                    JsonValue::Object(vec![
                        (
                            "algorithm".to_owned(),
                            JsonValue::String(key.algorithm.as_str().to_owned()),
                        ),
                        (
                            "key_id".to_owned(),
                            JsonValue::String(key.id.as_str().to_owned()),
                        ),
                    ])
                })
                .collect(),
        )
    }
}

/// Opaque signature bytes, in lowercase hexadecimal.
///
/// The value is carried and rendered; it is never interpreted. This build
/// checks its grammar and its exact width and nothing else, because anything
/// more would require the primitive that is missing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttestationSignature {
    hex: String,
}

impl AttestationSignature {
    /// Validate signature hexadecimal against the width its algorithm fixes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError::SignatureLength`] when the width is wrong and
    /// [`TrustRootError::SignatureCharacter`] when a character is not lowercase
    /// hexadecimal.
    pub fn new(algorithm: SignatureAlgorithm, hex: &str) -> Result<Self, TrustRootError> {
        let expected_len = algorithm.signature_hex_len();
        if hex.len() != expected_len {
            return Err(TrustRootError::SignatureLength {
                expected_len,
                actual_len: hex.len(),
            });
        }
        if !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TrustRootError::SignatureCharacter);
        }
        Ok(Self {
            hex: hex.to_owned(),
        })
    }

    /// Lowercase hexadecimal signature.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

/// A claim that one manifest was signed by one key.
///
/// The claim is fully validated and completely unchecked: every field is
/// well-formed, and no part of the assertion the signature makes has been
/// tested. Constructing one authorizes nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAttestation {
    manifest_digest: ArtifactDigest,
    key_id: KeyId,
    algorithm: SignatureAlgorithm,
    signature: AttestationSignature,
}

impl ReleaseAttestation {
    /// Bind a manifest digest to a key identifier, an algorithm and a signature.
    ///
    /// The digest must be SHA-256, which is what
    /// [`ReleaseManifest::canonical_digest`] produces and the only algorithm
    /// this build can recompute; see
    /// [`TrustRootError::UnsupportedManifestDigestAlgorithm`].
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError::UnsupportedManifestDigestAlgorithm`], the
    /// [`KeyId`] refusals, [`TrustRootError::UnknownAlgorithm`] and the
    /// [`AttestationSignature`] refusals.
    pub fn new(
        manifest_digest: ArtifactDigest,
        key_id: &str,
        algorithm: &str,
        signature_hex: &str,
    ) -> Result<Self, TrustRootError> {
        if manifest_digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(TrustRootError::UnsupportedManifestDigestAlgorithm);
        }
        let key_id = KeyId::new(key_id)?;
        let algorithm =
            SignatureAlgorithm::from_wire(algorithm).ok_or(TrustRootError::UnknownAlgorithm)?;
        let signature = AttestationSignature::new(algorithm, signature_hex)?;
        Ok(Self {
            manifest_digest,
            key_id,
            algorithm,
            signature,
        })
    }

    /// Read an attestation document from canonical bytes.
    ///
    /// The reader is [`crate::wire::parse_canonical`], so input that parses but
    /// is not already canonical is refused rather than normalized, and every
    /// refusal [`Self::new`] can return applies here too. A key outside
    /// [`KNOWN_ATTESTATION_FIELDS`] is refused: an attestation is not a place
    /// to retain something uninterpreted.
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError::DocumentTooLarge`],
    /// [`TrustRootError::Document`], [`TrustRootError::UnsupportedSchema`],
    /// [`TrustRootError::UnknownField`], [`TrustRootError::MissingField`],
    /// [`TrustRootError::FieldType`], [`TrustRootError::ManifestDigest`] and
    /// every refusal [`Self::new`] can return.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, TrustRootError> {
        if payload.len() > MAX_ATTESTATION_DOCUMENT_BYTES {
            return Err(TrustRootError::DocumentTooLarge {
                max: MAX_ATTESTATION_DOCUMENT_BYTES,
            });
        }
        let document =
            parse_canonical(payload).map_err(|error| TrustRootError::Document { error })?;
        let JsonValue::Object(entries) = &document else {
            return Err(TrustRootError::FieldType {
                field: "attestation",
            });
        };

        // The schema is read before anything else, so a document written to a
        // different contract is refused on its identity rather than on
        // whichever field this build happens to disagree with.
        if text(member(&document, "schema", "schema")?, "schema")? != RELEASE_ATTESTATION_SCHEMA_V1
        {
            return Err(TrustRootError::UnsupportedSchema);
        }
        if entries
            .iter()
            .any(|(key, _)| !KNOWN_ATTESTATION_FIELDS.contains(&key.as_str()))
        {
            return Err(TrustRootError::UnknownField);
        }

        let digest_object = object(
            member(&document, "manifest_digest", "manifest_digest")?,
            "manifest_digest",
        )?;
        let manifest_digest = ArtifactDigest::new(
            text(
                member(digest_object, "algorithm", "manifest_digest_algorithm")?,
                "manifest_digest_algorithm",
            )?,
            text(
                member(digest_object, "hex", "manifest_digest_hex")?,
                "manifest_digest_hex",
            )?,
        )
        .map_err(|error| TrustRootError::ManifestDigest { error })?;

        Self::new(
            manifest_digest,
            text(member(&document, "key_id", "key_id")?, "key_id")?,
            text(member(&document, "algorithm", "algorithm")?, "algorithm")?,
            text(member(&document, "signature", "signature")?, "signature")?,
        )
    }

    /// Manifest digest this attestation claims to cover.
    #[must_use]
    pub const fn manifest_digest(&self) -> &ArtifactDigest {
        &self.manifest_digest
    }

    /// Identifier of the key that supposedly signed.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Algorithm the signature claims to use.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The opaque signature.
    #[must_use]
    pub const fn signature(&self) -> &AttestationSignature {
        &self.signature
    }

    /// The exact bytes a reviewed backend must verify the signature over.
    ///
    /// This is the other half of the seam, and it is specified here rather than
    /// left for the backend to invent. The payload is a canonical document
    /// carrying the schema name, the algorithm, the key identifier and the
    /// manifest digest — and *not* the signature, which cannot cover itself.
    ///
    /// The schema member is domain separation. Without it, a signature over
    /// some other document that happened to share this shape would also verify
    /// here; with it, a signer's intent is bound to this contract.
    ///
    /// Nothing in this build consumes the payload — [`verify_attestation`]
    /// computes it and hands it to a seam that ignores it — but it is computed
    /// on the real path rather than only in a test, so the bytes are exercised
    /// by every verification.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        JsonValue::Object(self.signed_fields()).to_canonical_bytes()
    }

    /// Render the attestation as a canonical document.
    ///
    /// This is [`Self::signing_payload`]'s document plus the signature, and it
    /// is what [`Self::from_canonical_bytes`] reads back.
    #[must_use]
    pub fn to_canonical_document(&self) -> JsonValue {
        let mut fields = self.signed_fields();
        fields.push((
            "signature".to_owned(),
            JsonValue::String(self.signature.hex.clone()),
        ));
        JsonValue::Object(fields)
    }

    /// Canonical document bytes.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical_document().to_canonical_bytes()
    }

    /// The members the signature covers, without the signature itself.
    fn signed_fields(&self) -> Vec<(String, JsonValue)> {
        vec![
            (
                "algorithm".to_owned(),
                JsonValue::String(self.algorithm.as_str().to_owned()),
            ),
            (
                "key_id".to_owned(),
                JsonValue::String(self.key_id.as_str().to_owned()),
            ),
            (
                "manifest_digest".to_owned(),
                JsonValue::Object(vec![
                    (
                        "algorithm".to_owned(),
                        JsonValue::String(self.manifest_digest.algorithm().as_str().to_owned()),
                    ),
                    (
                        "hex".to_owned(),
                        JsonValue::String(self.manifest_digest.hex().to_owned()),
                    ),
                ]),
            ),
            (
                "schema".to_owned(),
                JsonValue::String(RELEASE_ATTESTATION_SCHEMA_V1.to_owned()),
            ),
        ]
    }
}

/// Evidence that a signature was checked and accepted by a reviewed backend.
///
/// **This type is uninhabited.** It has no variants, no constructor and no
/// value, in this crate or any other. It exists so that
/// [`AttestationVerdict::Verified`] and [`ReleaseTrustDecision::Admit`] are
/// unreachable *by construction* rather than by convention: a future change
/// that intends to mint trust cannot do it by editing one `if` — it has to give
/// this type an inhabitant, which is a visible, reviewable act.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureProof(NoBackend);

/// The uninhabited payload of [`SignatureProof`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum NoBackend {}

/// Why a well-formed, trusted, digest-agreeing attestation still was not
/// verified.
///
/// One variant today, because there is one seam.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnverifiableReason {
    /// This build links no signature-verification primitive, and a
    /// [`TrustedKey`] carries no key material. Both are required; neither is
    /// present.
    NoCryptoBackend,
}

impl UnverifiableReason {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCryptoBackend => "no_crypto_backend",
        }
    }
}

/// The closed outcome of [`verify_attestation`].
///
/// Exactly one arm is success-shaped and it is unreachable; see
/// [`SignatureProof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationVerdict {
    /// The signature was checked and accepted. Unreachable today.
    Verified(SignatureProof),
    /// Every check this build can perform passed, and the signature check is
    /// not one of them.
    Unverifiable {
        /// What is missing.
        reason: UnverifiableReason,
    },
    /// The attestation named a key the trust root does not pin.
    UnknownKey {
        /// The unrecognized identifier.
        key_id: KeyId,
    },
    /// The attestation named an algorithm no pinned key signs with.
    DisallowedAlgorithm {
        /// The refused algorithm.
        algorithm: SignatureAlgorithm,
    },
    /// The key is pinned, but for a different algorithm than the attestation
    /// claims.
    KeyAlgorithmMismatch {
        /// The pinned key.
        key_id: KeyId,
        /// Algorithm the trust root pins for it.
        trusted: SignatureAlgorithm,
        /// Algorithm the attestation claimed.
        presented: SignatureAlgorithm,
    },
    /// The bound digest is not the presented manifest's canonical digest.
    ///
    /// No digest is carried: a refusal that echoed both would invite a caller
    /// to "fix" the attestation to match whatever manifest it was handed.
    ManifestDigestMismatch,
    /// The attestation document could not be read.
    Malformed {
        /// The parse refusal.
        error: TrustRootError,
    },
}

impl AttestationVerdict {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Verified(_) => "verified",
            Self::Unverifiable { .. } => "unverifiable",
            Self::UnknownKey { .. } => "unknown_key",
            Self::DisallowedAlgorithm { .. } => "disallowed_algorithm",
            Self::KeyAlgorithmMismatch { .. } => "key_algorithm_mismatch",
            Self::ManifestDigestMismatch => "manifest_digest_mismatch",
            Self::Malformed { .. } => "malformed",
        }
    }
}

/// Why a release was refused, at the granularity a sealer acts on.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrustRefusal {
    /// Every structural check passed and the signature was never checked.
    ///
    /// This is the refusal `automonique-sandbox` already returns unconditionally
    /// as `MissingIndependentReleaseReview`.
    NoTrustRoot,
    /// The attestation named a key the trust root does not pin.
    UnknownKey,
    /// The attestation named an algorithm the trust root does not admit.
    DisallowedAlgorithm,
    /// The pinned key does not sign with the claimed algorithm.
    KeyAlgorithmMismatch,
    /// The attestation covers a different manifest.
    ManifestDigestMismatch,
    /// The attestation document could not be read.
    MalformedAttestation,
}

impl TrustRefusal {
    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTrustRoot => "no_trust_root",
            Self::UnknownKey => "unknown_key",
            Self::DisallowedAlgorithm => "disallowed_algorithm",
            Self::KeyAlgorithmMismatch => "key_algorithm_mismatch",
            Self::ManifestDigestMismatch => "manifest_digest_mismatch",
            Self::MalformedAttestation => "malformed_attestation",
        }
    }
}

/// What a sealer does with a verdict.
///
/// [`Self::Admit`] carries the same uninhabited [`SignatureProof`] as
/// [`AttestationVerdict::Verified`], so a decision cannot be widened by
/// mapping: if the verdict cannot be a success, neither can the decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseTrustDecision {
    /// The release may proceed. Unreachable today.
    Admit(SignatureProof),
    /// The release is refused.
    Refuse {
        /// Which check refused it.
        reason: TrustRefusal,
    },
}

impl ReleaseTrustDecision {
    /// Map a verdict to the decision a sealer acts on.
    ///
    /// Total and mechanical: every non-success verdict becomes a named refusal,
    /// and the one success verdict is unconstructible, so this function returns
    /// [`Self::Refuse`] for every value that can be passed to it.
    #[must_use]
    pub fn from_verdict(verdict: AttestationVerdict) -> Self {
        match verdict {
            AttestationVerdict::Verified(proof) => Self::Admit(proof),
            AttestationVerdict::Unverifiable { .. } => Self::Refuse {
                reason: TrustRefusal::NoTrustRoot,
            },
            AttestationVerdict::UnknownKey { .. } => Self::Refuse {
                reason: TrustRefusal::UnknownKey,
            },
            AttestationVerdict::DisallowedAlgorithm { .. } => Self::Refuse {
                reason: TrustRefusal::DisallowedAlgorithm,
            },
            AttestationVerdict::KeyAlgorithmMismatch { .. } => Self::Refuse {
                reason: TrustRefusal::KeyAlgorithmMismatch,
            },
            AttestationVerdict::ManifestDigestMismatch => Self::Refuse {
                reason: TrustRefusal::ManifestDigestMismatch,
            },
            AttestationVerdict::Malformed { .. } => Self::Refuse {
                reason: TrustRefusal::MalformedAttestation,
            },
        }
    }

    /// Whether this decision admits the release.
    ///
    /// Always `false` today, and the type — not this function — is why.
    #[must_use]
    pub const fn admits(&self) -> bool {
        matches!(self, Self::Admit(_))
    }
}

/// Verify an attestation against a manifest and a pinned key set.
///
/// The state machine is the table in the module documentation. Every check up
/// to the signature is performed here; the signature check is
/// [`signature_seam`], which reports what is missing instead of guessing.
///
/// No input produces [`AttestationVerdict::Verified`]. That is not a property
/// of this function's body — it is a property of [`SignatureProof`], which has
/// no values, so no body could return it. Changing that requires giving the
/// proof type an inhabitant.
#[must_use]
pub fn verify_attestation(
    manifest: &ReleaseManifest,
    attestation: &ReleaseAttestation,
    keys: &TrustedKeySet,
) -> AttestationVerdict {
    if !keys.allows_algorithm(attestation.algorithm) {
        return AttestationVerdict::DisallowedAlgorithm {
            algorithm: attestation.algorithm,
        };
    }
    let Some(key) = keys.key(&attestation.key_id) else {
        return AttestationVerdict::UnknownKey {
            key_id: attestation.key_id.clone(),
        };
    };
    if key.algorithm != attestation.algorithm {
        return AttestationVerdict::KeyAlgorithmMismatch {
            key_id: key.id.clone(),
            trusted: key.algorithm,
            presented: attestation.algorithm,
        };
    }
    // `ArtifactDigest::matches` accumulates across every byte rather than
    // returning at the first difference.
    if !manifest
        .canonical_digest()
        .matches(&attestation.manifest_digest)
    {
        return AttestationVerdict::ManifestDigestMismatch;
    }
    signature_seam(&attestation.signing_payload(), &attestation.signature, key)
}

/// Verify an attestation *document* against a manifest and a pinned key set.
///
/// The document route exists so a malformed attestation is a verdict rather
/// than an unrepresentable state: a caller receiving bytes gets the same closed
/// outcome as one holding a typed attestation, and
/// [`AttestationVerdict::Malformed`] is reachable exactly here.
#[must_use]
pub fn verify_attestation_document(
    manifest: &ReleaseManifest,
    payload: &[u8],
    keys: &TrustedKeySet,
) -> AttestationVerdict {
    match ReleaseAttestation::from_canonical_bytes(payload) {
        Ok(attestation) => verify_attestation(manifest, &attestation, keys),
        Err(error) => AttestationVerdict::Malformed { error },
    }
}

/// The signature check. This is the seam, and it is the whole of it.
///
/// A reviewed backend would verify `payload` against `signature` using the
/// public key belonging to `key`. This build has neither the verifier nor the
/// key material, so it says so. It does not return a success it cannot justify,
/// and it could not: [`AttestationVerdict::Verified`] needs a
/// [`SignatureProof`], and no such value exists.
///
/// The arguments are named and typed as the real call would take them, so the
/// change that lands a backend is confined to this function's body plus the key
/// material a [`TrustedKey`] would then carry.
fn signature_seam(
    _payload: &[u8],
    _signature: &AttestationSignature,
    _key: &TrustedKey,
) -> AttestationVerdict {
    AttestationVerdict::Unverifiable {
        reason: UnverifiableReason::NoCryptoBackend,
    }
}

fn member<'a>(
    object: &'a JsonValue,
    key: &str,
    field: &'static str,
) -> Result<&'a JsonValue, TrustRootError> {
    object
        .get(key)
        .ok_or(TrustRootError::MissingField { field })
}

fn object<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a JsonValue, TrustRootError> {
    match value {
        JsonValue::Object(_) => Ok(value),
        _ => Err(TrustRootError::FieldType { field }),
    }
}

fn text<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, TrustRootError> {
    value.as_str().ok_or(TrustRootError::FieldType { field })
}
