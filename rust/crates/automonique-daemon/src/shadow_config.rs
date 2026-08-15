// SPDX-License-Identifier: Elastic-2.0

//! Which scopes run suppressed, and whose messages the harness compares against.
//!
//! Both are properties of one installation. Which scopes an operator wants in
//! shadow is an operational choice that changes week to week, and the reference
//! bot's identity is a private deployment coordinate that must never appear in
//! shipped source. They live in the same strict frame
//! [`crate::manage_config::ManageConfig`] uses, read from the same private state
//! directory as the credentials.
//!
//! ```text
//! schema=automonique.shadow/v1
//! scope_mode=slack-ticket-routing:shadow
//! scope_mode=telegram-conversation:primary
//! legacy_bot_user=U0EXAMPLE
//! end=automonique.shadow/v1
//! ```
//!
//! # Absent means unchanged, never guessed
//!
//! An absent file is [`Ok(None)`], every scope is [`ShadowMode::Primary`], and
//! no observer is built. That is the whole point of the default: installing this
//! milestone must not change what a daemon does until an operator says so.
//!
//! A scope the file does not name is likewise `Primary`. A *present* file with a
//! misspelled mode is refused rather than defaulted, because the failure mode of
//! guessing is a scope that keeps executing while an operator believes it
//! suppressed — which is the one outcome a shadow harness must never produce.
//!
//! # Why the observed identity is configuration
//!
//! The reference bot's user id is a private identifier of one deployment.
//! Hard-coding it would publish it, and would make the harness wrong for every
//! other installation. It is read here and nowhere else, and the grammar is the
//! opaque-identifier charset so a value carrying a quote or a newline cannot
//! reach a payload or a log line intact.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::shadow::ShadowMode;

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "shadow/shadow.conf";
/// Exact first line of a shadow configuration.
const CONFIG_HEADER: &str = "schema=automonique.shadow/v1";
/// Exact final line of a complete shadow configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.shadow/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 8_192;
/// Longest scope name admitted.
const MAX_SCOPE_BYTES: usize = 128;
/// Longest observed-identity value admitted.
const MAX_IDENTITY_BYTES: usize = 128;
/// Most scopes one file may name.
const MAX_SCOPES: usize = 64;

/// The database the harness records into, beneath the private state directory.
pub const SHADOW_DATABASE_NAME: &str = "shadow-comparisons.sqlite3";

/// A refusal while reading the shadow configuration.
#[derive(Debug, Eq, PartialEq)]
pub enum ShadowConfigError {
    /// The file is not a private owner-only regular file.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed or truncated.
    Malformed,
    /// The frame sets no key, which configures nothing.
    Empty,
    /// A scope name is empty, over-long or outside the opaque charset.
    ScopeInvalid,
    /// A mode is not one this build defines.
    ModeInvalid,
    /// The observed identity is empty, over-long or outside the charset.
    IdentityInvalid,
    /// The frame names more scopes than this build admits.
    TooManyScopes,
}

impl ShadowConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "shadow_config_insecure",
            Self::Unreadable => "shadow_config_unreadable",
            Self::Malformed => "shadow_config_malformed",
            Self::Empty => "shadow_config_empty",
            Self::ScopeInvalid => "shadow_config_scope_invalid",
            Self::ModeInvalid => "shadow_config_mode_invalid",
            Self::IdentityInvalid => "shadow_config_identity_invalid",
            Self::TooManyScopes => "shadow_config_too_many_scopes",
        }
    }
}

impl fmt::Display for ShadowConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => {
                formatter.write_str("shadow configuration is not a private owner-only regular file")
            }
            Self::Unreadable => formatter.write_str("shadow configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("shadow configuration frame is malformed or truncated")
            }
            Self::Empty => formatter.write_str("shadow configuration sets no key"),
            Self::ScopeInvalid => formatter.write_str("shadow configuration scope is invalid"),
            Self::ModeInvalid => formatter.write_str("shadow configuration mode is invalid"),
            Self::IdentityInvalid => {
                formatter.write_str("shadow configuration observed identity is invalid")
            }
            Self::TooManyScopes => {
                formatter.write_str("shadow configuration names too many scopes")
            }
        }
    }
}

impl std::error::Error for ShadowConfigError {}

/// One installation's shadow-mode selections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShadowConfig {
    scopes: Vec<(String, ShadowMode)>,
    legacy_bot_user: Option<String>,
}

impl ShadowConfig {
    /// Where the configuration lives beneath a private state directory.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// Where the harness records, beneath a private state directory.
    #[must_use]
    pub fn database_path(state_dir: &Path) -> PathBuf {
        state_dir.join(SHADOW_DATABASE_NAME)
    }

    /// The mode one scope runs in.
    ///
    /// A scope the file does not name is [`ShadowMode::Primary`]: enabling this
    /// milestone changes nothing until a scope is named.
    #[must_use]
    pub fn mode(&self, scope: &str) -> ShadowMode {
        self.scopes
            .iter()
            .find(|(name, _)| name == scope)
            .map_or(ShadowMode::Primary, |(_, mode)| *mode)
    }

    /// Every scope the file names, in declaration order.
    #[must_use]
    pub fn scopes(&self) -> &[(String, ShadowMode)] {
        &self.scopes
    }

    /// The reference bot's identity, when one is configured.
    ///
    /// Absent means the observer is not built and no comparison target exists —
    /// which is a fact about this installation, not a defect.
    #[must_use]
    pub fn legacy_bot_user(&self) -> Option<&str> {
        self.legacy_bot_user.as_deref()
    }

    /// Whether any scope is suppressed.
    #[must_use]
    pub fn any_shadow(&self) -> bool {
        self.scopes.iter().any(|(_, mode)| mode.is_shadow())
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`ShadowConfigError`] naming which part of a present file was
    /// refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, ShadowConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ShadowConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(ShadowConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| ShadowConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| ShadowConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, ShadowConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(ShadowConfigError::Malformed);
        }
        let mut scopes: Vec<(String, ShadowMode)> = Vec::new();
        let mut legacy_bot_user: Option<String> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(ShadowConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(ShadowConfigError::Malformed)?;
            match key {
                "scope_mode" => {
                    let (scope, mode) =
                        value.split_once(':').ok_or(ShadowConfigError::Malformed)?;
                    if !is_opaque(scope, MAX_SCOPE_BYTES) {
                        return Err(ShadowConfigError::ScopeInvalid);
                    }
                    if scopes.iter().any(|(name, _)| name == scope) {
                        // A repeated scope has no precedence rule, and choosing
                        // one silently would decide whether effects happen.
                        return Err(ShadowConfigError::Malformed);
                    }
                    if scopes.len() >= MAX_SCOPES {
                        return Err(ShadowConfigError::TooManyScopes);
                    }
                    let mode =
                        ShadowMode::from_spelling(mode).ok_or(ShadowConfigError::ModeInvalid)?;
                    scopes.push((scope.to_owned(), mode));
                }
                "legacy_bot_user" if legacy_bot_user.is_none() => {
                    if !is_opaque(value, MAX_IDENTITY_BYTES) {
                        return Err(ShadowConfigError::IdentityInvalid);
                    }
                    legacy_bot_user = Some(value.to_owned());
                }
                _ => return Err(ShadowConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(ShadowConfigError::Malformed);
        }
        if scopes.is_empty() && legacy_bot_user.is_none() {
            return Err(ShadowConfigError::Empty);
        }
        Ok(Some(Self {
            scopes,
            legacy_bot_user,
        }))
    }
}

/// Non-empty, bounded, and drawn from the opaque-identifier charset.
fn is_opaque(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{ShadowConfig, ShadowConfigError};
    use crate::shadow::ShadowMode;

    const FRAME: &str = "schema=automonique.shadow/v1\n\
                         scope_mode=slack-ticket-routing:shadow\n\
                         scope_mode=telegram-conversation:primary\n\
                         legacy_bot_user=U0EXAMPLE\n\
                         end=automonique.shadow/v1\n";

    fn category(text: &str) -> &'static str {
        ShadowConfig::parse(text)
            .expect_err("a refused frame")
            .category()
    }

    #[test]
    fn a_complete_frame_carries_every_scope_and_the_observed_identity() {
        let config = ShadowConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        assert_eq!(config.mode("slack-ticket-routing"), ShadowMode::Shadow);
        assert_eq!(config.mode("telegram-conversation"), ShadowMode::Primary);
        assert_eq!(config.legacy_bot_user(), Some("U0EXAMPLE"));
        assert!(config.any_shadow());
        assert_eq!(config.scopes().len(), 2);
    }

    #[test]
    fn an_unnamed_scope_stays_primary() {
        let config = ShadowConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        assert_eq!(config.mode("github-issue-actions"), ShadowMode::Primary);
    }

    #[test]
    fn an_absent_file_leaves_every_scope_primary() {
        let directory = tempfile::tempdir().expect("a temporary state directory");
        assert!(
            ShadowConfig::load(directory.path())
                .expect("an absent file is not an error")
                .is_none()
        );
        assert_eq!(
            ShadowConfig::default().mode("slack-ticket-routing"),
            ShadowMode::Primary
        );
    }

    #[test]
    fn a_private_file_on_disk_loads() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ShadowConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only permissions");
        let config = ShadowConfig::load(directory.path())
            .expect("a private file loads")
            .expect("a present configuration");
        assert_eq!(config.mode("slack-ticket-routing"), ShadowMode::Shadow);
    }

    #[test]
    fn a_world_readable_file_refuses_startup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ShadowConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("relaxed permissions");
        assert_eq!(
            ShadowConfig::load(directory.path())
                .expect_err("an insecure file is refused")
                .category(),
            "shadow_config_insecure"
        );
    }

    #[test]
    fn a_misspelled_mode_is_refused_rather_than_defaulted() {
        assert_eq!(
            category(
                "schema=automonique.shadow/v1\n\
                 scope_mode=slack-ticket-routing:shadowy\n\
                 end=automonique.shadow/v1\n"
            ),
            "shadow_config_mode_invalid",
        );
    }

    #[test]
    fn a_repeated_scope_has_no_precedence_rule() {
        assert_eq!(
            category(
                "schema=automonique.shadow/v1\n\
                 scope_mode=slack-ticket-routing:shadow\n\
                 scope_mode=slack-ticket-routing:primary\n\
                 end=automonique.shadow/v1\n"
            ),
            "shadow_config_malformed",
        );
    }

    #[test]
    fn a_malformed_frame_names_what_was_refused() {
        assert_eq!(
            category("schema=automonique.shadow/v2\n"),
            "shadow_config_malformed"
        );
        assert_eq!(
            category("schema=automonique.shadow/v1\nscope_mode=a:shadow\n"),
            "shadow_config_malformed",
            "a frame without its terminator is truncated",
        );
        assert_eq!(
            category("schema=automonique.shadow/v1\nmode=shadow\nend=automonique.shadow/v1\n"),
            "shadow_config_malformed",
            "an unknown key is a refusal, not a value to ignore",
        );
        assert_eq!(
            category(
                "schema=automonique.shadow/v1\nscope_mode=slack-ticket-routing\nend=automonique.shadow/v1\n"
            ),
            "shadow_config_malformed",
            "a scope with no mode names nothing",
        );
        assert_eq!(
            category("schema=automonique.shadow/v1\nend=automonique.shadow/v1\n"),
            "shadow_config_empty",
            "a frame that configures nothing is a mistake, not a disabled surface",
        );
    }

    #[test]
    fn an_identity_outside_the_opaque_charset_is_refused() {
        for value in ["", "U0 EXAMPLE", "U0\nEXAMPLE", "U0\"EXAMPLE"] {
            assert_eq!(
                ShadowConfig::parse(&format!(
                    "schema=automonique.shadow/v1\n\
                     legacy_bot_user={value}\n\
                     end=automonique.shadow/v1\n"
                ))
                .expect_err("refused"),
                if value.contains('\n') {
                    ShadowConfigError::Malformed
                } else {
                    ShadowConfigError::IdentityInvalid
                },
                "{value:?} must not reach a comparison record"
            );
        }
    }

    #[test]
    fn a_scope_outside_the_opaque_charset_is_refused() {
        assert_eq!(
            category(
                "schema=automonique.shadow/v1\n\
                 scope_mode=slack ticket routing:shadow\n\
                 end=automonique.shadow/v1\n"
            ),
            "shadow_config_scope_invalid",
        );
    }

    #[test]
    fn an_identity_only_frame_configures_the_observer_without_suppressing_anything() {
        let config = ShadowConfig::parse(
            "schema=automonique.shadow/v1\n\
             legacy_bot_user=U0EXAMPLE\n\
             end=automonique.shadow/v1\n",
        )
        .expect("a complete frame")
        .expect("a present configuration");
        assert!(!config.any_shadow());
        assert_eq!(config.legacy_bot_user(), Some("U0EXAMPLE"));
    }
}
