// SPDX-License-Identifier: Elastic-2.0

//! What this build is, answered by the build itself.
//!
//! A deployed binary that cannot name the revision it was compiled from cannot
//! be signed off against one, and every record written about it says what the
//! deployment answered but never which revision answered. The usual remedy — a
//! manifest laid down beside the binary — holds for exactly as long as nobody
//! replaces the binary without replacing the manifest, which is a property of a
//! deployment procedure rather than of the artifact.
//!
//! So the revision travels *inside* the artifact. [`BuildIdentity::current`]
//! reads compile-time literals placed by this crate's build script; it opens no
//! file, reads no environment variable at run time, and cannot be made to
//! disagree with the bytes around it.
//!
//! # `unknown` is an answer
//!
//! Three provenances are honest and one is forbidden. A build may be
//! [`Provenance::Declared`] by a pipeline that knows the commit, observed
//! [`Provenance::Committed`] from a clean checkout, observed
//! [`Provenance::Modified`] over uncommitted changes, or
//! [`Provenance::Unknown`] where there is no git metadata to read — a release
//! tarball, a vendored build. What must never happen is a build inventing a
//! plausible-looking revision to fill the gap, because a wrong attribution is
//! believed while a missing one is investigated.
//!
//! Only `Declared` and `Committed` name a commit the binary corresponds to, and
//! only those produce an [`BuildIdentity::attributable_revision`]. A `Modified`
//! build still reports the `HEAD` its changes sat on, because that is worth
//! knowing, but it never counts as a revision the build can be held to.

/// The one spelling of the declaration variable, shared with `build.rs`.
mod declaration;

pub use declaration::DECLARED_REVISION_VARIABLE;

/// Schema token every surface that reports a build identity declares.
///
/// One constant so the command line, the web entry's authenticated surface and
/// any reader of either cannot drift into describing the same three fields
/// under two names.
pub const BUILD_IDENTITY_SCHEMA: &str = "automonique.build-identity/v1";

/// How a build's source revision was established.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Provenance {
    /// The pipeline that ran the build stated the revision it was building.
    Declared,
    /// Observed from a checkout with no uncommitted changes.
    Committed,
    /// Observed from a checkout that had uncommitted changes.
    ///
    /// The revision is the commit those changes sat on. The binary is not that
    /// commit, and nothing here pretends otherwise.
    Modified,
    /// No revision could be established, and none was invented.
    Unknown,
}

impl Provenance {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Committed => "committed",
            Self::Modified => "modified",
            Self::Unknown => "unknown",
        }
    }

    /// Read a provenance back from its wire spelling.
    ///
    /// An unrecognised token is [`Provenance::Unknown`] rather than an error: a
    /// reader that does not understand what a build claimed has not learned the
    /// build's revision, which is exactly what `Unknown` says.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "declared" => Self::Declared,
            "committed" => Self::Committed,
            "modified" => Self::Modified,
            _ => Self::Unknown,
        }
    }
}

/// The source revision and build target compiled into this binary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BuildIdentity {
    revision: Option<&'static str>,
    provenance: Provenance,
    build_target: &'static str,
}

impl BuildIdentity {
    /// The identity of the binary executing this call.
    ///
    /// Every value is a literal the build script placed at compile time, so
    /// this answer is available before any configuration is read and stays
    /// correct however the binary is later moved, renamed or deployed.
    #[must_use]
    pub fn current() -> Self {
        Self::from_parts(
            env!("AUTOMONIQUE_BUILD_SOURCE_REVISION"),
            Provenance::from_wire(env!("AUTOMONIQUE_BUILD_PROVENANCE")),
            env!("AUTOMONIQUE_BUILD_TARGET"),
        )
    }

    /// The commit this build was made from, when there is one to name.
    ///
    /// Present for a modified build too — it is the commit the uncommitted
    /// changes sat on. Use [`BuildIdentity::attributable_revision`] for the
    /// stricter question.
    #[must_use]
    pub const fn source_revision(&self) -> Option<&'static str> {
        self.revision
    }

    /// The revision this build can be held to, if any.
    ///
    /// `Some` only for [`Provenance::Declared`] and [`Provenance::Committed`].
    /// A modified tree and an unknown environment both answer `None`, and a
    /// caller that has to name what it accepted must read `None` as "cannot be
    /// signed off" rather than as "probably the one at `HEAD`".
    #[must_use]
    pub const fn attributable_revision(&self) -> Option<&'static str> {
        match self.provenance {
            Provenance::Declared | Provenance::Committed => self.revision,
            Provenance::Modified | Provenance::Unknown => None,
        }
    }

    /// How the revision was established.
    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// The target triple this build was compiled for.
    #[must_use]
    pub const fn build_target(&self) -> &'static str {
        self.build_target
    }

    /// Render this identity as the one document every surface publishes.
    ///
    /// One renderer rather than one per surface. `automonique build-identity
    /// --json`, the web entry's `--build-identity --json` and its
    /// `GET /api/build` all call this, so a field added for one of them cannot
    /// be missing from the others, and a reader written against either is a
    /// reader written against all of them.
    ///
    /// A revision that could not be established is `null`, never an omitted
    /// key: a reader has to be told that the build does not know, not left to
    /// decide whether the field was dropped in transit.
    #[must_use]
    pub fn to_json_document(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": BUILD_IDENTITY_SCHEMA,
            "source_revision": self.revision,
            "provenance": self.provenance.as_str(),
            "build_target": self.build_target,
        }))
        .unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Render this identity as the one report a caller on the host reads.
    ///
    /// The same three facts as [`BuildIdentity::to_json_document`], in the same
    /// order, spelled for a person. A build with no revision prints `unknown`
    /// here for the same reason the document carries `null`.
    #[must_use]
    pub fn to_report(&self, subject: &str) -> String {
        format!(
            "{subject} build identity\n  source revision: {}\n  provenance: {}\n  build target: {}\n",
            self.revision.unwrap_or("unknown"),
            self.provenance.as_str(),
            self.build_target,
        )
    }

    /// Reduce a revision and a provenance to the answer they jointly support.
    ///
    /// Two independent literals can disagree — a malformed revision under a
    /// confident provenance, or a revision beside a provenance of `unknown`.
    /// Either way the pair is not evidence, so it collapses to the answer that
    /// claims least.
    fn from_parts(
        revision: &'static str,
        provenance: Provenance,
        build_target: &'static str,
    ) -> Self {
        let coherent = is_revision(revision) && !matches!(provenance, Provenance::Unknown);
        Self {
            revision: coherent.then_some(revision),
            provenance: if coherent {
                provenance
            } else {
                Provenance::Unknown
            },
            build_target,
        }
    }
}

/// Whether a string is a full lowercase-hexadecimal git object name.
fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{BUILD_IDENTITY_SCHEMA, BuildIdentity, Provenance, is_revision};

    const REVISION: &str = "39747eaf63f32ad43e3cb045b36bd6fbaed46cf6";

    fn observed(revision: &'static str, provenance: Provenance) -> BuildIdentity {
        BuildIdentity::from_parts(revision, provenance, "x86_64-unknown-linux-gnu")
    }

    #[test]
    fn this_build_reports_a_coherent_identity() {
        let identity = BuildIdentity::current();
        match identity.provenance() {
            Provenance::Declared | Provenance::Committed => {
                let revision = identity.attributable_revision().expect("a named revision");
                assert!(is_revision(revision), "{revision}");
            }
            Provenance::Modified => {
                assert!(is_revision(
                    identity.source_revision().expect("the head it sat on")
                ));
                assert_eq!(identity.attributable_revision(), None);
            }
            // The build environment had no revision to offer. That is a
            // supported outcome, and the one thing it must never do is offer a
            // revision anyway.
            Provenance::Unknown => assert_eq!(identity.source_revision(), None),
        }
    }

    #[test]
    fn a_modified_build_names_its_head_but_is_not_attributable() {
        let identity = observed(REVISION, Provenance::Modified);
        assert_eq!(identity.source_revision(), Some(REVISION));
        assert_eq!(identity.attributable_revision(), None);
    }

    #[test]
    fn the_document_and_the_report_carry_the_same_four_facts() {
        let identity = observed(REVISION, Provenance::Committed);

        let document: serde_json::Value =
            serde_json::from_slice(&identity.to_json_document()).expect("JSON document");
        assert_eq!(document["schema"], BUILD_IDENTITY_SCHEMA);
        assert_eq!(document["source_revision"], REVISION);
        assert_eq!(document["provenance"], "committed");
        assert_eq!(document["build_target"], "x86_64-unknown-linux-gnu");

        let report = identity.to_report("automonique");
        assert!(
            report.starts_with("automonique build identity\n"),
            "{report}"
        );
        for fact in [
            REVISION,
            "provenance: committed",
            "build target: x86_64-unknown-linux-gnu",
        ] {
            assert!(report.contains(fact), "{report}");
        }
    }

    #[test]
    fn an_unknown_build_publishes_a_null_revision_and_prints_unknown() {
        let identity = observed("", Provenance::Unknown);

        let document: serde_json::Value =
            serde_json::from_slice(&identity.to_json_document()).expect("JSON document");
        // Null, not absent. A reader must be told the build does not know,
        // rather than left to guess whether the field went missing in transit.
        assert!(document["source_revision"].is_null(), "{document}");
        assert_eq!(document["provenance"], "unknown");

        assert!(
            identity
                .to_report("automonique")
                .contains("source revision: unknown"),
            "{}",
            identity.to_report("automonique")
        );
    }

    #[test]
    fn a_declared_or_committed_build_is_attributable() {
        for provenance in [Provenance::Declared, Provenance::Committed] {
            let identity = observed(REVISION, provenance);
            assert_eq!(identity.attributable_revision(), Some(REVISION));
            assert_eq!(identity.provenance(), provenance);
        }
    }

    #[test]
    fn a_malformed_revision_is_reduced_to_unknown() {
        for candidate in [
            "",
            "not-a-revision",
            "39747EAF63F32AD43E3CB045B36BD6FBAED46CF6",
            "39747eaf63f32ad43e3cb045b36bd6fbaed46cf",
        ] {
            let identity = observed(candidate, Provenance::Committed);
            assert_eq!(identity.provenance(), Provenance::Unknown);
            assert_eq!(identity.source_revision(), None);
            assert_eq!(identity.attributable_revision(), None);
        }
    }

    #[test]
    fn a_revision_under_an_unknown_provenance_is_not_published() {
        let identity = observed(REVISION, Provenance::Unknown);
        assert_eq!(identity.source_revision(), None);
        assert_eq!(identity.attributable_revision(), None);
    }

    #[test]
    fn provenance_round_trips_and_an_unrecognised_token_claims_nothing() {
        for provenance in [
            Provenance::Declared,
            Provenance::Committed,
            Provenance::Modified,
            Provenance::Unknown,
        ] {
            assert_eq!(Provenance::from_wire(provenance.as_str()), provenance);
        }
        assert_eq!(Provenance::from_wire("Committed"), Provenance::Unknown);
        assert_eq!(Provenance::from_wire("almost-clean"), Provenance::Unknown);
    }
}
