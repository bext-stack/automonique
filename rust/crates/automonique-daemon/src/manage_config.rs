// SPDX-License-Identifier: Elastic-2.0

//! The deployment's Manage console: where it lives and which app identity
//! addresses its key-value surface.
//!
//! Both values are properties of one installation, not of the product. They
//! used to be constants in shipped source, which made a private deployment
//! address readable by anyone who could read the repository and made the code
//! wrong for every other deployment. They are configuration now, in the same
//! strict frame [`crate::ticket_intake::FleetConfig`] and [`crate::slack`] use,
//! and read from the same private state directory as the credentials.
//!
//! ```text
//! schema=automonique.manage/v1
//! url=https://manage.example.test/
//! platform_url=https://ai-operations.example.test/
//! profile_app=example-manage-app
//! end=automonique.manage/v1
//! ```
//!
//! # Absent means off, never guessed
//!
//! An absent file is [`Ok(None)`] and disables both surfaces independently: the
//! approval card is posted without its "Open Manage" button, and the
//! site-profile read model is never attached, so it answers with the
//! not-attached refusal it already had. Neither one invents an address. A
//! present-but-invalid file is refused rather than ignored, because a typo in a
//! URL that a message links to should surface at startup and not as a link
//! nobody can follow.
//!
//! # Why the URL charset is narrow
//!
//! [`ManageUrl`] is embedded in a Slack Block Kit payload. A value carrying a
//! quote, a backslash or a control character would be a value that edits the
//! surrounding JSON, so those are refused at the boundary rather than escaped
//! later by whoever remembers to.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "manage/manage.conf";
/// Exact first line of a Manage configuration.
const CONFIG_HEADER: &str = "schema=automonique.manage/v1";
/// Exact final line of a complete Manage configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.manage/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;
/// Longest console URL admitted.
const MAX_URL_BYTES: usize = 512;
/// Longest app identity admitted.
const MAX_PROFILE_APP_BYTES: usize = 128;

/// An origin an operator-facing message may link to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManageUrl(String);

impl ManageUrl {
    /// Admit one `https://` URL that is safe to embed in a JSON payload.
    ///
    /// # Errors
    ///
    /// Returns [`ManageConfigError::UrlInvalid`] for anything that is not an
    /// `https://` URL within [`MAX_URL_BYTES`], or that carries a character
    /// which would edit the payload it is embedded in.
    pub fn new(value: &str) -> Result<Self, ManageConfigError> {
        if !value.starts_with("https://")
            || value.len() > MAX_URL_BYTES
            || value.len() <= "https://".len()
        {
            return Err(ManageConfigError::UrlInvalid);
        }
        if value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ManageConfigError::UrlInvalid);
        }
        if value.contains(['"', '\\', '<', '>']) {
            return Err(ManageConfigError::UrlInvalid);
        }
        Ok(Self(value.to_owned()))
    }

    /// The configured URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The app identity Manage's key-value surface answers for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManageProfileApp(String);

impl ManageProfileApp {
    /// Admit one opaque app identity.
    ///
    /// # Errors
    ///
    /// Returns [`ManageConfigError::ProfileAppInvalid`] for an empty,
    /// over-long, or non-opaque identity. The charset is deliberately narrower
    /// than the header grammar: this value is sent as a request header, and a
    /// header value is not a place to discover that a configuration file
    /// contained a newline.
    pub fn new(value: &str) -> Result<Self, ManageConfigError> {
        if value.is_empty() || value.len() > MAX_PROFILE_APP_BYTES {
            return Err(ManageConfigError::ProfileAppInvalid);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ManageConfigError::ProfileAppInvalid);
        }
        Ok(Self(value.to_owned()))
    }

    /// The configured identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a present Manage configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`ManageConfig::load`].
#[derive(Debug)]
pub enum ManageConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// The frame is well formed but configures nothing.
    Empty,
    /// `url` is not an `https://` origin this daemon may put in a message.
    UrlInvalid,
    /// `profile_app` is empty, over-long, or not an opaque identity.
    ProfileAppInvalid,
}

impl fmt::Display for ManageConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => {
                formatter.write_str("Manage configuration is not a private owner-only regular file")
            }
            Self::Unreadable => formatter.write_str("Manage configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("Manage configuration frame is malformed or truncated")
            }
            Self::Empty => formatter.write_str("Manage configuration sets no key"),
            Self::UrlInvalid => formatter.write_str("Manage configuration url is invalid"),
            Self::ProfileAppInvalid => {
                formatter.write_str("Manage configuration profile_app is invalid")
            }
        }
    }
}

impl std::error::Error for ManageConfigError {}

impl ManageConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "manage_config_insecure",
            Self::Unreadable => "manage_config_unreadable",
            Self::Malformed => "manage_config_malformed",
            Self::Empty => "manage_config_empty",
            Self::UrlInvalid => "manage_config_url_invalid",
            Self::ProfileAppInvalid => "manage_config_profile_app_invalid",
        }
    }
}

/// One deployment's Manage coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManageConfig {
    url: Option<ManageUrl>,
    platform_url: Option<ManageUrl>,
    profile_app: Option<ManageProfileApp>,
}

impl ManageConfig {
    /// Where the configuration lives beneath a private state directory.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// The console URL an operator-facing message may link to, if configured.
    #[must_use]
    pub const fn url(&self) -> Option<&ManageUrl> {
        self.url.as_ref()
    }

    /// The AI Operations authority used to validate platform bearer tokens.
    /// When absent, callers may retain the version-one `url` behavior.
    #[must_use]
    pub const fn platform_url(&self) -> Option<&ManageUrl> {
        self.platform_url.as_ref()
    }

    /// The app identity the site-profile read model addresses, if configured.
    #[must_use]
    pub const fn profile_app(&self) -> Option<&ManageProfileApp> {
        self.profile_app.as_ref()
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`ManageConfigError`] naming which part of a present file was
    /// refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, ManageConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ManageConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(ManageConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| ManageConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| ManageConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, ManageConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(ManageConfigError::Malformed);
        }
        let mut url: Option<ManageUrl> = None;
        let mut platform_url: Option<ManageUrl> = None;
        let mut profile_app: Option<ManageProfileApp> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(ManageConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(ManageConfigError::Malformed)?;
            match key {
                "url" if url.is_none() => {
                    url = Some(ManageUrl::new(value)?);
                }
                "platform_url" if platform_url.is_none() => {
                    platform_url = Some(ManageUrl::new(value)?);
                }
                "profile_app" if profile_app.is_none() => {
                    profile_app = Some(ManageProfileApp::new(value)?);
                }
                _ => return Err(ManageConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(ManageConfigError::Malformed);
        }
        if url.is_none() && platform_url.is_none() && profile_app.is_none() {
            return Err(ManageConfigError::Empty);
        }
        Ok(Some(Self {
            url,
            platform_url,
            profile_app,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{ManageConfig, ManageProfileApp, ManageUrl};

    const FRAME: &str = "schema=automonique.manage/v1\n\
                         url=https://manage.example.test/\n\
                         platform_url=https://ai-operations.example.test/\n\
                         profile_app=example-manage-app\n\
                         end=automonique.manage/v1\n";

    fn category(text: &str) -> &'static str {
        ManageConfig::parse(text)
            .expect_err("a refused frame")
            .category()
    }

    #[test]
    fn a_complete_frame_carries_both_values() {
        let config = ManageConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        assert_eq!(
            config.url().map(ManageUrl::as_str),
            Some("https://manage.example.test/")
        );
        assert_eq!(
            config.platform_url().map(ManageUrl::as_str),
            Some("https://ai-operations.example.test/")
        );
        assert_eq!(
            config.profile_app().map(ManageProfileApp::as_str),
            Some("example-manage-app")
        );
    }

    #[test]
    fn each_key_is_independently_optional() {
        let url_only = ManageConfig::parse(
            "schema=automonique.manage/v1\n\
             url=https://manage.example.test/\n\
             end=automonique.manage/v1\n",
        )
        .expect("a url-only frame")
        .expect("a present configuration");
        assert!(url_only.url().is_some());
        assert!(url_only.platform_url().is_none());
        assert!(url_only.profile_app().is_none());

        let app_only = ManageConfig::parse(
            "schema=automonique.manage/v1\n\
             profile_app=example-manage-app\n\
             end=automonique.manage/v1\n",
        )
        .expect("an app-only frame")
        .expect("a present configuration");
        assert!(app_only.url().is_none());
        assert!(app_only.platform_url().is_none());
        assert!(app_only.profile_app().is_some());

        let platform_only = ManageConfig::parse(
            "schema=automonique.manage/v1\n\
             platform_url=https://ai-operations.example.test/\n\
             end=automonique.manage/v1\n",
        )
        .expect("a platform-only frame")
        .expect("a present configuration");
        assert!(platform_only.url().is_none());
        assert!(platform_only.platform_url().is_some());
        assert!(platform_only.profile_app().is_none());
    }

    #[test]
    fn an_absent_file_is_not_an_error() {
        let directory = tempfile::tempdir().expect("a temporary state directory");
        assert!(
            ManageConfig::load(directory.path())
                .expect("an absent file is not an error")
                .is_none()
        );
    }

    #[test]
    fn a_private_file_on_disk_loads_both_values() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ManageConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only permissions");
        let config = ManageConfig::load(directory.path())
            .expect("a private file loads")
            .expect("a present configuration");
        assert_eq!(
            config.url().map(ManageUrl::as_str),
            Some("https://manage.example.test/")
        );
        assert_eq!(
            config.platform_url().map(ManageUrl::as_str),
            Some("https://ai-operations.example.test/")
        );
        assert_eq!(
            config.profile_app().map(ManageProfileApp::as_str),
            Some("example-manage-app")
        );
    }

    #[test]
    fn a_malformed_frame_names_what_was_refused() {
        assert_eq!(
            category("schema=automonique.manage/v2\n"),
            "manage_config_malformed"
        );
        assert_eq!(
            category("schema=automonique.manage/v1\nurl=https://manage.example.test/\n"),
            "manage_config_malformed",
            "a frame without its terminator is truncated",
        );
        assert_eq!(
            category(
                "schema=automonique.manage/v1\nconsole=https://manage.example.test/\nend=automonique.manage/v1\n"
            ),
            "manage_config_malformed",
            "an unknown key is a refusal, not a value to ignore",
        );
        assert_eq!(
            category(
                "schema=automonique.manage/v1\n\
                 url=https://manage.example.test/\n\
                 url=https://other.example.test/\n\
                 end=automonique.manage/v1\n"
            ),
            "manage_config_malformed",
            "a duplicate key has no precedence rule",
        );
        assert_eq!(
            category("schema=automonique.manage/v1\nend=automonique.manage/v1\ntrailing\n"),
            "manage_config_malformed",
        );
        assert_eq!(
            category("schema=automonique.manage/v1\nend=automonique.manage/v1\n"),
            "manage_config_empty",
            "a frame that configures nothing is a mistake, not a disabled surface",
        );
    }

    #[test]
    fn a_url_that_could_edit_the_message_it_is_embedded_in_is_refused() {
        for value in [
            "http://manage.example.test/",
            "https://",
            "manage.example.test",
            "https://manage.example.test/\"},{\"x\":\"y",
            "https://manage.example.test/ ",
            "https://manage.example.test/<script>",
        ] {
            assert!(
                ManageUrl::new(value).is_err(),
                "{value} must not reach a Block Kit payload"
            );
        }
        assert!(ManageUrl::new("https://manage.example.test/").is_ok());
    }

    #[test]
    fn a_profile_app_outside_the_opaque_charset_is_refused() {
        for value in ["", "app id", "app\nid", "app:id"] {
            assert!(
                ManageProfileApp::new(value).is_err(),
                "{value:?} must not reach a request header"
            );
        }
        assert!(ManageProfileApp::new("example-manage-app").is_ok());
    }

    #[test]
    fn an_invalid_value_is_reported_as_the_key_it_came_from() {
        assert_eq!(
            category(
                "schema=automonique.manage/v1\nurl=http://manage.example.test/\nend=automonique.manage/v1\n"
            ),
            "manage_config_url_invalid",
        );
        assert_eq!(
            category("schema=automonique.manage/v1\nprofile_app=\nend=automonique.manage/v1\n"),
            "manage_config_profile_app_invalid",
        );
    }

    #[test]
    fn a_world_readable_file_refuses_startup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = ManageConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("relaxed permissions");
        assert_eq!(
            ManageConfig::load(directory.path())
                .expect_err("an insecure file is refused")
                .category(),
            "manage_config_insecure",
        );
    }
}
