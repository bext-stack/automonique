// SPDX-License-Identifier: Elastic-2.0

//! Strict release-manifest input binding without execution authority.
//!
//! The release protocol currently authenticates document shape and declared
//! digests, but it has no signature, trusted key, or release-store handle.
//! This module therefore creates only a [`ReleaseBoundaryCandidate`]. A
//! candidate binds all inputs needed by the fixed descriptor-closure fixture,
//! while [`crate::RunnerAdmissionSealer::issue_release_candidate`] always
//! refuses it until a separate independently reviewed trust root exists.

use std::error::Error;
use std::fmt;

use automonique_protocol::release::{
    ArtifactKind, DigestAlgorithm, ManifestError, ReleaseManifest,
};
use automonique_protocol::sandbox::ImplementationDigest;
use sha2::{Digest as _, Sha256};

use crate::RunnerBinding;

const MAX_RELEASE_MANIFEST_BYTES: usize = 1024 * 1024;

/// Exact caller-declared coordinates to compare with one canonical release
/// manifest.
///
/// These values are declarations, not a trust root. Constructing this type can
/// never authorize execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBoundaryParts {
    manifest_sha256: ImplementationDigest,
    helper_sha256: ImplementationDigest,
    bwrap_sha256: ImplementationDigest,
    fixture_sha256: ImplementationDigest,
    binding: RunnerBinding,
}

impl ReleaseBoundaryParts {
    /// Bind the exact release document, descriptor helper, fixed boundary
    /// installer, inert fixture, and runner subject declared by a caller.
    #[must_use]
    pub const fn new(
        manifest_sha256: ImplementationDigest,
        helper_sha256: ImplementationDigest,
        bwrap_sha256: ImplementationDigest,
        fixture_sha256: ImplementationDigest,
        binding: RunnerBinding,
    ) -> Self {
        Self {
            manifest_sha256,
            helper_sha256,
            bwrap_sha256,
            fixture_sha256,
            binding,
        }
    }
}

/// A structurally valid, completely bound, but unauthenticated release input.
///
/// There is intentionally no `ReviewedRelease` or launch-success type in this
/// crate. The candidate digest is useful for review/audit correlation only; it
/// is not an authorization credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBoundaryCandidate {
    manifest_sha256: ImplementationDigest,
    helper_sha256: ImplementationDigest,
    bwrap_sha256: ImplementationDigest,
    fixture_sha256: ImplementationDigest,
    binding: RunnerBinding,
    candidate_sha256: ImplementationDigest,
}

impl ReleaseBoundaryCandidate {
    /// Parse and strictly bind one canonical manifest candidate.
    ///
    /// The manifest's sole `companion` digest is treated as the descriptor
    /// helper declaration. Unknown manifest fields are refused because this
    /// version cannot safely assign them security meaning. The fixed fixture
    /// must also be the executable named by the runner binding.
    ///
    /// This verifies consistency, not provenance. A caller that supplies both
    /// bytes and matching hashes still receives no execution authority.
    pub fn from_canonical_manifest(
        manifest_bytes: &[u8],
        parts: ReleaseBoundaryParts,
    ) -> Result<Self, ReleaseBoundaryError> {
        if manifest_bytes.len() > MAX_RELEASE_MANIFEST_BYTES {
            return Err(ReleaseBoundaryError::ManifestTooLarge);
        }
        let manifest = ReleaseManifest::from_canonical_bytes(manifest_bytes)
            .map_err(ReleaseBoundaryError::Manifest)?;
        if !manifest.unknown_fields().is_empty() {
            return Err(ReleaseBoundaryError::UnknownManifestFields);
        }

        let actual_manifest_sha256 = implementation_sha256(manifest_bytes);
        if actual_manifest_sha256 != parts.manifest_sha256 {
            return Err(ReleaseBoundaryError::ManifestDigestMismatch);
        }

        let helper = manifest
            .digest(ArtifactKind::Companion)
            .ok_or(ReleaseBoundaryError::MissingHelperDigest)?;
        if helper.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ReleaseBoundaryError::UnsupportedHelperDigestAlgorithm);
        }
        if format!("sha256:{}", helper.hex()) != parts.helper_sha256.to_string() {
            return Err(ReleaseBoundaryError::HelperDigestMismatch);
        }

        if parts.helper_sha256 == parts.bwrap_sha256
            || parts.helper_sha256 == parts.fixture_sha256
            || parts.bwrap_sha256 == parts.fixture_sha256
        {
            return Err(ReleaseBoundaryError::AliasedExecutableDigests);
        }
        if parts.binding.provider_executable_digest() != &parts.fixture_sha256 {
            return Err(ReleaseBoundaryError::FixtureBindingMismatch);
        }

        let candidate_sha256 = implementation_sha256(
            format!(
                "schema=automonique.sandbox.release-boundary-candidate/v1\nmanifest={}\nhelper={}\nbwrap={}\nfixture={}\nrunner={}\nrun={}\nworkspace={}\nprovider={}\n",
                parts.manifest_sha256,
                parts.helper_sha256,
                parts.bwrap_sha256,
                parts.fixture_sha256,
                parts.binding.runner_id(),
                parts.binding.run_id(),
                parts.binding.workspace_root_digest(),
                parts.binding.provider_executable_digest(),
            )
            .as_bytes(),
        );
        Ok(Self {
            manifest_sha256: parts.manifest_sha256,
            helper_sha256: parts.helper_sha256,
            bwrap_sha256: parts.bwrap_sha256,
            fixture_sha256: parts.fixture_sha256,
            binding: parts.binding,
            candidate_sha256,
        })
    }

    /// Digest of the exact canonical manifest bytes.
    #[must_use]
    pub const fn manifest_sha256(&self) -> &ImplementationDigest {
        &self.manifest_sha256
    }

    /// Manifest-declared descriptor helper digest.
    #[must_use]
    pub const fn helper_sha256(&self) -> &ImplementationDigest {
        &self.helper_sha256
    }

    /// Declared digest of the fixed boundary installer.
    #[must_use]
    pub const fn bwrap_sha256(&self) -> &ImplementationDigest {
        &self.bwrap_sha256
    }

    /// Declared digest of the inert fixture executable.
    #[must_use]
    pub const fn fixture_sha256(&self) -> &ImplementationDigest {
        &self.fixture_sha256
    }

    /// Exact one-use runner subject the candidate would bind after review.
    #[must_use]
    pub const fn binding(&self) -> &RunnerBinding {
        &self.binding
    }

    /// Correlation digest over every candidate coordinate.
    #[must_use]
    pub const fn candidate_sha256(&self) -> &ImplementationDigest {
        &self.candidate_sha256
    }
}

/// Strict release candidate refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseBoundaryError {
    /// The input exceeded the defensive document bound.
    ManifestTooLarge,
    /// The release protocol refused the canonical document.
    Manifest(ManifestError),
    /// This strict security consumer does not interpret extension fields.
    UnknownManifestFields,
    /// The declared manifest digest did not cover the supplied bytes.
    ManifestDigestMismatch,
    /// The release did not declare the descriptor helper as its companion.
    MissingHelperDigest,
    /// The descriptor helper pin must use SHA-256, matching the runner helper.
    UnsupportedHelperDigestAlgorithm,
    /// The manifest companion and declared helper differed.
    HelperDigestMismatch,
    /// Two executables shared a digest, indicating a transposed/aliased input.
    AliasedExecutableDigests,
    /// The runner's executable subject was not the exact inert fixture.
    FixtureBindingMismatch,
}

impl fmt::Display for ReleaseBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestTooLarge => formatter.write_str("release manifest exceeded byte bound"),
            Self::Manifest(error) => write!(formatter, "release manifest refused: {error}"),
            Self::UnknownManifestFields => {
                formatter.write_str("release manifest contains uninterpreted fields")
            }
            Self::ManifestDigestMismatch => formatter.write_str("manifest digest mismatched"),
            Self::MissingHelperDigest => {
                formatter.write_str("release manifest has no companion helper digest")
            }
            Self::UnsupportedHelperDigestAlgorithm => {
                formatter.write_str("release helper digest is not SHA-256")
            }
            Self::HelperDigestMismatch => formatter.write_str("release helper digest mismatched"),
            Self::AliasedExecutableDigests => {
                formatter.write_str("release boundary executable digests are aliased")
            }
            Self::FixtureBindingMismatch => {
                formatter.write_str("runner executable is not the fixed fixture")
            }
        }
    }
}

impl Error for ReleaseBoundaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            _ => None,
        }
    }
}

fn implementation_sha256(bytes: &[u8]) -> ImplementationDigest {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    ImplementationDigest::parse(&value).expect("SHA-256 output has the protocol digest shape")
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::wire::JsonValue;

    const HELPER_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const BINARY_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SDK_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn field(name: &str, value: JsonValue) -> (String, JsonValue) {
        (name.to_owned(), value)
    }

    fn text(value: &str) -> JsonValue {
        JsonValue::String(value.to_owned())
    }

    fn range(min: i64, max: i64) -> JsonValue {
        JsonValue::Object(vec![
            field("min", JsonValue::Integer(min)),
            field("max", JsonValue::Integer(max)),
        ])
    }

    fn digest(hex: &str) -> JsonValue {
        JsonValue::Object(vec![
            field("algorithm", text("sha-256")),
            field("hex", text(hex)),
        ])
    }

    fn manifest(extra: Option<(&str, JsonValue)>) -> Vec<u8> {
        let mut fields = vec![
            field("build_target", text("x86_64-unknown-linux-gnu")),
            field("capabilities", JsonValue::Array(Vec::new())),
            field("credentials", JsonValue::Array(Vec::new())),
            field("database_schema", range(1, 1)),
            field(
                "digests",
                JsonValue::Object(vec![
                    field("binary", digest(BINARY_HEX)),
                    field("companion", digest(HELPER_HEX)),
                ]),
            ),
            field("events", range(1, 1)),
            field("protocol", range(1, 1)),
            field("schema_revision", JsonValue::Integer(1)),
            field(
                "sdk",
                JsonValue::Object(vec![
                    field("protocol", range(1, 1)),
                    field("schema_digest", digest(SDK_HEX)),
                ]),
            ),
            field("source_revision", text("release-source")),
            field("version", text("0.1.0")),
        ];
        if let Some((name, value)) = extra {
            fields.push(field(name, value));
        }
        JsonValue::Object(fields).to_canonical_bytes()
    }

    fn typed(hex: &str) -> ImplementationDigest {
        ImplementationDigest::parse(&format!("sha256:{hex}")).expect("typed digest")
    }

    fn candidate_parts(bytes: &[u8]) -> ReleaseBoundaryParts {
        let fixture = typed(&"55".repeat(32));
        ReleaseBoundaryParts::new(
            implementation_sha256(bytes),
            typed(HELPER_HEX),
            typed(&"44".repeat(32)),
            fixture.clone(),
            RunnerBinding::new(
                "runner-release",
                "run-release",
                typed(&"66".repeat(32)),
                fixture,
            )
            .expect("binding"),
        )
    }

    #[test]
    fn strict_candidate_binds_every_coordinate_deterministically() {
        let bytes = manifest(None);
        let first =
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, candidate_parts(&bytes))
                .expect("consistent candidate");
        let second =
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, candidate_parts(&bytes))
                .expect("same candidate");
        assert_eq!(first, second);

        let mut changed = candidate_parts(&bytes);
        changed.binding = RunnerBinding::new(
            "runner-release",
            "different-run",
            typed(&"66".repeat(32)),
            typed(&"55".repeat(32)),
        )
        .expect("changed binding");
        let changed = ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, changed)
            .expect("consistent changed candidate");
        assert_ne!(first.candidate_sha256(), changed.candidate_sha256());
    }

    #[test]
    fn caller_matching_its_own_manifest_still_cannot_mint_authority() {
        let bytes = manifest(None);
        let candidate =
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, candidate_parts(&bytes))
                .expect("consistent candidate");
        let report = crate::runner_admission_tests::observed_report();
        let mut sealer =
            crate::RunnerAdmissionSealer::from_observed_report(&report).expect("observed issuer");
        let plan = crate::runner_admission_tests::runner_plan(&report);
        assert!(matches!(
            sealer.issue_release_candidate(&plan, &candidate),
            Err(crate::RunnerAdmissionError::MissingIndependentReleaseReview)
        ));
    }

    #[test]
    fn manifest_and_helper_mutations_fail_closed() {
        let bytes = manifest(None);
        let mut wrong_manifest = candidate_parts(&bytes);
        wrong_manifest.manifest_sha256 = typed(&"77".repeat(32));
        assert!(matches!(
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, wrong_manifest),
            Err(ReleaseBoundaryError::ManifestDigestMismatch)
        ));

        let mut wrong_helper = candidate_parts(&bytes);
        wrong_helper.helper_sha256 = typed(&"77".repeat(32));
        assert!(matches!(
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, wrong_helper),
            Err(ReleaseBoundaryError::HelperDigestMismatch)
        ));

        let extended = manifest(Some(("future_security", text("unreviewed"))));
        assert!(matches!(
            ReleaseBoundaryCandidate::from_canonical_manifest(
                &extended,
                candidate_parts(&extended)
            ),
            Err(ReleaseBoundaryError::UnknownManifestFields)
        ));
    }

    #[test]
    fn transposed_executables_and_wider_provider_fail_closed() {
        let bytes = manifest(None);
        let mut alias = candidate_parts(&bytes);
        alias.bwrap_sha256 = alias.helper_sha256.clone();
        assert!(matches!(
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, alias),
            Err(ReleaseBoundaryError::AliasedExecutableDigests)
        ));

        let mut wider = candidate_parts(&bytes);
        wider.binding = RunnerBinding::new(
            "runner-release",
            "run-release",
            typed(&"66".repeat(32)),
            typed(&"77".repeat(32)),
        )
        .expect("wider provider");
        assert!(matches!(
            ReleaseBoundaryCandidate::from_canonical_manifest(&bytes, wider),
            Err(ReleaseBoundaryError::FixtureBindingMismatch)
        ));
    }
}
