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
//! ttl_ms=3600000
//! reminder_percent=50
//! escalation_percent=80
//! end=automonique.approvals/v1
//! ```
//!
//! Every key but `requirement` is optional and defaults to a compiled value.
//! There is deliberately no spelling for "no expiry": a proposal that can never
//! time out is a question the sweep could never reach, and the ladder is a
//! fraction of a bounded lifetime rather than a schedule of its own.
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

/// Narrowest lifetime a proposal may be configured with.
///
/// A minute is already short for a question a person has to read and answer;
/// anything below it would expire proposals faster than an operator could act,
/// which is a denial dressed as a timeout.
const MIN_TTL_MS: i64 = 60 * 1_000;

/// Widest lifetime a proposal may be configured with.
///
/// A week. Past that the proposal outlives the state it was bound to in every
/// practical sense — the program, the prompt and the working directory have all
/// had time to move — and #20's drift check would refuse it anyway.
const MAX_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// How long one proposal stays answerable when nothing is configured.
pub const DEFAULT_APPROVAL_TTL_MS: i64 = 60 * 60 * 1_000;

/// Fraction of the lifetime at which the first reminder is staged.
pub const DEFAULT_REMINDER_PERCENT: u8 = 50;

/// Fraction of the lifetime at which the escalation notice is staged.
pub const DEFAULT_ESCALATION_PERCENT: u8 = 80;

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
    /// `ttl_ms` is not a positive integer inside the admitted range.
    LifetimeInvalid,
    /// A ladder percentage is outside `1..=99`, or the reminder does not come
    /// strictly before the escalation.
    LadderInvalid,
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
            Self::LifetimeInvalid => {
                formatter.write_str("approval configuration lifetime is outside the admitted range")
            }
            Self::LadderInvalid => formatter
                .write_str("approval configuration reminder ladder is empty or out of order"),
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
            Self::LifetimeInvalid => "approval_config_lifetime_invalid",
            Self::LadderInvalid => "approval_config_ladder_invalid",
        }
    }
}

/// One deployment's standing approval requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalPolicyConfig {
    requirement: ApprovalRequirement,
    ttl_ms: i64,
    reminder_percent: u8,
    escalation_percent: u8,
}

/// The lifetime and reminder ladder one lane's proposals are raised under.
///
/// Carried as one value rather than three loose numbers so a caller cannot pair
/// a lifetime with somebody else's ladder, and validated at construction so a
/// consumer never has to re-check the ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalLifetime {
    ttl_ms: i64,
    reminder_percent: u8,
    escalation_percent: u8,
}

impl ApprovalLifetime {
    /// The compiled default: an hour, reminded at half and escalated at 80%.
    pub const DEFAULT: Self = Self {
        ttl_ms: DEFAULT_APPROVAL_TTL_MS,
        reminder_percent: DEFAULT_REMINDER_PERCENT,
        escalation_percent: DEFAULT_ESCALATION_PERCENT,
    };

    /// How long a proposal stays answerable.
    #[must_use]
    pub const fn ttl_ms(self) -> i64 {
        self.ttl_ms
    }

    /// The instant one proposal raised at `requested_at_ms` stops being
    /// answerable.
    ///
    /// Saturating, so a clock near the end of the representable range produces
    /// a deadline the store will still admit rather than a wrapped one.
    #[must_use]
    pub const fn expires_at(self, requested_at_ms: i64) -> i64 {
        requested_at_ms.saturating_add(self.ttl_ms)
    }

    /// The instant the reminder rung is due for one proposal.
    #[must_use]
    pub const fn reminder_at(self, requested_at_ms: i64) -> i64 {
        self.rung_at(requested_at_ms, self.reminder_percent)
    }

    /// The instant the escalation rung is due for one proposal.
    #[must_use]
    pub const fn escalation_at(self, requested_at_ms: i64) -> i64 {
        self.rung_at(requested_at_ms, self.escalation_percent)
    }

    const fn rung_at(self, requested_at_ms: i64, percent: u8) -> i64 {
        // Percentages are bounded to 1..=99 at construction, so the product
        // cannot overflow a lifetime that is itself bounded to a week.
        requested_at_ms.saturating_add(self.ttl_ms / 100 * percent as i64)
    }
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

    /// The lifetime and ladder this configuration sets.
    #[must_use]
    pub const fn lifetime(self) -> ApprovalLifetime {
        ApprovalLifetime {
            ttl_ms: self.ttl_ms,
            reminder_percent: self.reminder_percent,
            escalation_percent: self.escalation_percent,
        }
    }

    /// The configured lifetime, defaulting to [`ApprovalLifetime::DEFAULT`]
    /// when nothing is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalPolicyConfigError`] for a present file that is
    /// insecure, unreadable, or malformed. An absent file is never an error.
    pub fn lifetime_or_default(
        state_dir: &Path,
    ) -> Result<ApprovalLifetime, ApprovalPolicyConfigError> {
        Ok(Self::load(state_dir)?.map_or(ApprovalLifetime::DEFAULT, Self::lifetime))
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
        let mut ttl_ms: Option<i64> = None;
        let mut reminder_percent: Option<u8> = None;
        let mut escalation_percent: Option<u8> = None;
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
                "ttl_ms" if ttl_ms.is_none() => {
                    let parsed = value
                        .parse::<i64>()
                        .map_err(|_| ApprovalPolicyConfigError::LifetimeInvalid)?;
                    if !(MIN_TTL_MS..=MAX_TTL_MS).contains(&parsed) {
                        return Err(ApprovalPolicyConfigError::LifetimeInvalid);
                    }
                    ttl_ms = Some(parsed);
                }
                "reminder_percent" if reminder_percent.is_none() => {
                    reminder_percent = Some(percent(value)?);
                }
                "escalation_percent" if escalation_percent.is_none() => {
                    escalation_percent = Some(percent(value)?);
                }
                _ => return Err(ApprovalPolicyConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(ApprovalPolicyConfigError::Malformed);
        }
        let reminder_percent = reminder_percent.unwrap_or(DEFAULT_REMINDER_PERCENT);
        let escalation_percent = escalation_percent.unwrap_or(DEFAULT_ESCALATION_PERCENT);
        // A ladder whose rungs are level or inverted is not a ladder. Refusing
        // it is cheaper than deciding at runtime which of two notices a
        // proposal should have received first.
        if reminder_percent >= escalation_percent {
            return Err(ApprovalPolicyConfigError::LadderInvalid);
        }
        Ok(Some(Self {
            requirement: requirement.ok_or(ApprovalPolicyConfigError::RequirementInvalid)?,
            ttl_ms: ttl_ms.unwrap_or(DEFAULT_APPROVAL_TTL_MS),
            reminder_percent,
            escalation_percent,
        }))
    }
}

/// Parse one ladder percentage, which must leave room on both sides.
///
/// Zero would fire a notice the instant a proposal is raised, and a hundred
/// would fire it at the deadline, where the expiry notice already is.
fn percent(value: &str) -> Result<u8, ApprovalPolicyConfigError> {
    let parsed = value
        .parse::<u8>()
        .map_err(|_| ApprovalPolicyConfigError::LadderInvalid)?;
    if !(1..=99).contains(&parsed) {
        return Err(ApprovalPolicyConfigError::LadderInvalid);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalLifetime, ApprovalPolicyConfig, ApprovalRequirement, DEFAULT_APPROVAL_REQUIREMENT,
        DEFAULT_APPROVAL_TTL_MS, MAX_CONFIG_BYTES,
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
    fn the_lifetime_defaults_and_its_ladder_is_ordered() {
        let config = ApprovalPolicyConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        let lifetime = config.lifetime();
        assert_eq!(lifetime, ApprovalLifetime::DEFAULT);
        assert_eq!(lifetime.ttl_ms(), DEFAULT_APPROVAL_TTL_MS);
        // The rungs are strictly inside the lifetime and strictly ordered, so a
        // proposal is reminded, then escalated, then expired — never two at
        // once and never out of order.
        let raised = 1_000;
        assert!(lifetime.reminder_at(raised) > raised);
        assert!(lifetime.reminder_at(raised) < lifetime.escalation_at(raised));
        assert!(lifetime.escalation_at(raised) < lifetime.expires_at(raised));
        assert_eq!(
            lifetime.expires_at(raised),
            raised + DEFAULT_APPROVAL_TTL_MS
        );
        // A clock at the end of the representable range yields a deadline the
        // store will still admit rather than a wrapped one.
        assert_eq!(lifetime.expires_at(i64::MAX), i64::MAX);
    }

    #[test]
    fn a_configured_lifetime_and_ladder_replace_the_defaults() {
        let config = ApprovalPolicyConfig::parse(
            "schema=automonique.approvals/v1\n\
             requirement=approval_required\n\
             ttl_ms=600000\n\
             reminder_percent=25\n\
             escalation_percent=75\n\
             end=automonique.approvals/v1\n",
        )
        .expect("a complete frame")
        .expect("a present configuration");
        let lifetime = config.lifetime();
        assert_eq!(lifetime.ttl_ms(), 600_000);
        assert_eq!(lifetime.reminder_at(0), 150_000);
        assert_eq!(lifetime.escalation_at(0), 450_000);
        assert_eq!(lifetime.expires_at(0), 600_000);
    }

    #[test]
    fn a_lifetime_outside_the_admitted_range_is_refused() {
        for value in ["0", "-1", "59999", "604800001", "", "3600000.0", "abc"] {
            assert_eq!(
                category(&format!(
                    "schema=automonique.approvals/v1\n\
                     requirement=allowed\n\
                     ttl_ms={value}\n\
                     end=automonique.approvals/v1\n"
                )),
                "approval_config_lifetime_invalid",
                "{value:?} is not a lifetime a proposal can be raised under",
            );
        }
        // There is no spelling for "never expires": the key is a number or it
        // is refused, and the range has no open end.
        assert_eq!(
            category(
                "schema=automonique.approvals/v1\n\
                 requirement=allowed\n\
                 ttl_ms=never\n\
                 end=automonique.approvals/v1\n"
            ),
            "approval_config_lifetime_invalid",
        );
    }

    #[test]
    fn a_ladder_that_is_level_or_inverted_is_refused() {
        for (reminder, escalation) in [("50", "50"), ("80", "50"), ("99", "1")] {
            assert_eq!(
                category(&format!(
                    "schema=automonique.approvals/v1\n\
                     requirement=allowed\n\
                     reminder_percent={reminder}\n\
                     escalation_percent={escalation}\n\
                     end=automonique.approvals/v1\n"
                )),
                "approval_config_ladder_invalid",
                "{reminder}/{escalation} is not an ordered ladder",
            );
        }
        for value in ["0", "100", "255", "256", "-1", ""] {
            assert_eq!(
                category(&format!(
                    "schema=automonique.approvals/v1\n\
                     requirement=allowed\n\
                     reminder_percent={value}\n\
                     end=automonique.approvals/v1\n"
                )),
                "approval_config_ladder_invalid",
                "{value:?} leaves no room on one side",
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
