// SPDX-License-Identifier: Elastic-2.0

//! How much ceremony a launch needs on this host, composed from three sources.
//!
//! The lattice, the composition and the fail-closed rule all live in
//! `automonique_policy::approval`, which performs no IO and can therefore be
//! enumerated exhaustively by test. This module is the daemon's half: it reads
//! the one configured source off disk, measures the other two, and hands the
//! three to that crate.
//!
//! ```text
//! schema=automonique.approvals/v1
//! requirement=approval_required
//! end=automonique.approvals/v1
//! ```
//!
//! # An absent file means [`ApprovalRequirement::Allowed`], not "disabled"
//!
//! Approval composition is not an external surface that can be left
//! unconfigured: every launch passes the gate, so an unconfigured daemon still
//! has to compose something. The neutral answer is the loosest *configured*
//! requirement, which is the one that leaves the decision entirely to the other
//! two sources — the host's measurement and the call. It is emphatically not
//! "no gate": a host that cannot enforce the sandbox still forbids, because
//! that source is measured rather than read. A present-but-invalid file refuses
//! startup, exactly as the credential gates do.
//!
//! # Why the file cannot loosen anything
//!
//! The value read here is one of three inputs to a join on a total order, so
//! the strongest thing this file can do is *tighten*. There is deliberately no
//! spelling that overrides the host measurement, no "force" key and no
//! per-command exemption list: the absence of a loosening vocabulary is what
//! makes the composed requirement provable rather than audited.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use automonique_policy::approval::ApprovalRequirement;

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "approvals/approvals.conf";
/// Exact first line of an approval configuration.
const CONFIG_HEADER: &str = "schema=automonique.approvals/v1";
/// Exact final line of a complete approval configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.approvals/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;

/// What a deployment that configured nothing asks for on its own.
///
/// The loosest requirement, because this source is the only settable one and a
/// default that tightened would be a policy nobody chose. The measured host
/// source is unaffected by it.
pub const DEFAULT_APPROVAL_REQUIREMENT: ApprovalRequirement = ApprovalRequirement::Allowed;

/// Why a present approval configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`ApprovalPolicyConfig::load`].
#[derive(Debug)]
pub enum ApprovalPolicyConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// `requirement` is absent or is not one of the lattice's three spellings.
    RequirementInvalid,
}

impl fmt::Display for ApprovalPolicyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => formatter
                .write_str("approval configuration is not a private owner-only regular file"),
            Self::Unreadable => formatter.write_str("approval configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("approval configuration frame is malformed or truncated")
            }
            Self::RequirementInvalid => {
                formatter.write_str("approval configuration requirement is invalid")
            }
        }
    }
}

impl std::error::Error for ApprovalPolicyConfigError {}

impl ApprovalPolicyConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "approval_config_insecure",
            Self::Unreadable => "approval_config_unreadable",
            Self::Malformed => "approval_config_malformed",
            Self::RequirementInvalid => "approval_config_requirement_invalid",
        }
    }
}

/// One deployment's standing approval requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalPolicyConfig {
    requirement: ApprovalRequirement,
}

impl ApprovalPolicyConfig {
    /// Where the configuration lives beneath a private state directory.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// What the operator's configuration asks for.
    #[must_use]
    pub const fn requirement(self) -> ApprovalRequirement {
        self.requirement
    }

    /// The configured requirement, defaulting to
    /// [`DEFAULT_APPROVAL_REQUIREMENT`] when nothing is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalPolicyConfigError`] for a present file that is
    /// insecure, unreadable, or malformed. An absent file is never an error.
    pub fn requirement_or_default(
        state_dir: &Path,
    ) -> Result<ApprovalRequirement, ApprovalPolicyConfigError> {
        Ok(
            Self::load(state_dir)?
                .map_or(DEFAULT_APPROVAL_REQUIREMENT, |config| config.requirement),
        )
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalPolicyConfigError`] naming which part of a present
    /// file was refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, ApprovalPolicyConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ApprovalPolicyConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(ApprovalPolicyConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| ApprovalPolicyConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| ApprovalPolicyConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, ApprovalPolicyConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(ApprovalPolicyConfigError::Malformed);
        }
        let mut requirement: Option<ApprovalRequirement> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(ApprovalPolicyConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(ApprovalPolicyConfigError::Malformed)?;
            match key {
                "requirement" if requirement.is_none() => {
                    requirement = Some(
                        ApprovalRequirement::from_spelling(value)
                            .ok_or(ApprovalPolicyConfigError::RequirementInvalid)?,
                    );
                }
                _ => return Err(ApprovalPolicyConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(ApprovalPolicyConfigError::Malformed);
        }
        Ok(Some(Self {
            requirement: requirement.ok_or(ApprovalPolicyConfigError::RequirementInvalid)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalPolicyConfig, ApprovalRequirement, DEFAULT_APPROVAL_REQUIREMENT, MAX_CONFIG_BYTES,
    };

    const FRAME: &str = "schema=automonique.approvals/v1\n\
                         requirement=approval_required\n\
                         end=automonique.approvals/v1\n";

    fn category(text: &str) -> &'static str {
        ApprovalPolicyConfig::parse(text)
            .expect_err("a refused frame")
            .category()
    }

    #[test]
    fn a_complete_frame_carries_the_requirement() {
        let config = ApprovalPolicyConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        assert_eq!(config.requirement(), ApprovalRequirement::ApprovalRequired);
    }

    #[test]
    fn every_lattice_spelling_is_configurable() {
        for requirement in ApprovalRequirement::ALL {
            let frame = format!(
                "schema=automonique.approvals/v1\n\
                 requirement={}\n\
                 end=automonique.approvals/v1\n",
                requirement.as_str()
            );
            assert_eq!(
                ApprovalPolicyConfig::parse(&frame)
                    .expect("a complete frame")
                    .expect("a present configuration")
                    .requirement(),
                requirement
            );
        }
    }

    #[test]
    fn an_absent_file_resolves_to_the_loosest_configured_requirement() {
        let directory = tempfile::tempdir().expect("a temporary state directory");
        assert!(
            ApprovalPolicyConfig::load(directory.path())
                .expect("an absent file is not an error")
                .is_none()
        );
        assert_eq!(
            ApprovalPolicyConfig::requirement_or_default(directory.path())
                .expect("the default requirement"),
            DEFAULT_APPROVAL_REQUIREMENT,
        );
        assert_eq!(DEFAULT_APPROVAL_REQUIREMENT, ApprovalRequirement::Allowed);
    }

    #[test]
    fn a_configured_requirement_wins_over_the_default() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ApprovalPolicyConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only permissions");
        assert_eq!(
            ApprovalPolicyConfig::requirement_or_default(directory.path())
                .expect("the configured requirement"),
            ApprovalRequirement::ApprovalRequired,
        );
    }

    #[test]
    fn a_malformed_frame_names_what_was_refused() {
        assert_eq!(
            category("schema=automonique.approvals/v2\n"),
            "approval_config_malformed"
        );
        assert_eq!(
            category("schema=automonique.approvals/v1\nrequirement=allowed\n"),
            "approval_config_malformed",
            "a frame without its terminator is truncated",
        );
        assert_eq!(
            category(
                "schema=automonique.approvals/v1\nforce=allowed\nend=automonique.approvals/v1\n"
            ),
            "approval_config_malformed",
            "an unknown key is a refusal, not a value to ignore",
        );
        assert_eq!(
            category(
                "schema=automonique.approvals/v1\n\
                 requirement=allowed\n\
                 requirement=forbidden\n\
                 end=automonique.approvals/v1\n"
            ),
            "approval_config_malformed",
            "a duplicate key has no precedence rule",
        );
        assert_eq!(
            category("schema=automonique.approvals/v1\nend=automonique.approvals/v1\ntrailing\n"),
            "approval_config_malformed",
        );
    }

    #[test]
    fn a_present_frame_must_name_a_lattice_value() {
        assert_eq!(
            category("schema=automonique.approvals/v1\nend=automonique.approvals/v1\n"),
            "approval_config_requirement_invalid",
            "a frame that names no requirement configures nothing",
        );
        for value in ["", "Allowed", "none", "required", "off", "bypass"] {
            assert_eq!(
                category(&format!(
                    "schema=automonique.approvals/v1\n\
                     requirement={value}\n\
                     end=automonique.approvals/v1\n"
                )),
                "approval_config_requirement_invalid",
                "{value:?} is not a requirement this lattice spells",
            );
        }
    }

    #[test]
    fn a_world_readable_file_refuses_startup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ApprovalPolicyConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("relaxed permissions");
        assert_eq!(
            ApprovalPolicyConfig::load(directory.path())
                .expect_err("an insecure file is refused")
                .category(),
            "approval_config_insecure",
        );
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_read() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ApprovalPolicyConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        let padding = usize::try_from(MAX_CONFIG_BYTES).expect("a ceiling that fits a usize");
        std::fs::write(&path, "#".repeat(padding + 1)).expect("an oversized configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only permissions");
        assert_eq!(
            ApprovalPolicyConfig::load(directory.path())
                .expect_err("an oversized file is refused")
                .category(),
            "approval_config_insecure",
        );
    }
}
