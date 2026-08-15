// SPDX-License-Identifier: Elastic-2.0

//! Which tenant this deployment's durable memory is keyed by.
//!
//! Every row in the agent memory store carries a tenant, and every read
//! addresses one. The value is a property of an installation rather than of the
//! product — it used to be a constant in shipped source, which both published a
//! private name and made the code wrong for any second deployment — so it is
//! configuration, in the same strict frame the credential gates use.
//!
//! ```text
//! schema=automonique.memory/v1
//! tenant=primary
//! end=automonique.memory/v1
//! ```
//!
//! # An absent file means [`DEFAULT_MEMORY_TENANT`], not "disabled"
//!
//! Memory is not an external surface that can be left unconfigured: a daemon
//! with no configuration still has to read and write somewhere, so this is the
//! one gate in the daemon whose absent state is a default rather than an off
//! switch. A present-but-invalid file still refuses startup.
//!
//! # The default does not migrate anything
//!
//! The tenant is part of every durable key. A deployment whose rows were
//! written under another tenant must set `tenant=` **before** upgrading;
//! starting under the default would not lose those rows, but it would address a
//! different, empty tenant and look exactly like data loss to the operator.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "memory/memory.conf";
/// Exact first line of a memory configuration.
const CONFIG_HEADER: &str = "schema=automonique.memory/v1";
/// Exact final line of a complete memory configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.memory/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;
/// Longest tenant admitted.
const MAX_TENANT_BYTES: usize = 64;

/// The tenant a deployment that configured none is keyed by.
pub const DEFAULT_MEMORY_TENANT: &str = "primary";

/// Why a present memory configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`MemoryConfig::load`].
#[derive(Debug)]
pub enum MemoryConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// `tenant` is absent, empty, over-long, or outside the durable-key
    /// charset.
    TenantInvalid,
}

impl fmt::Display for MemoryConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => {
                formatter.write_str("memory configuration is not a private owner-only regular file")
            }
            Self::Unreadable => formatter.write_str("memory configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("memory configuration frame is malformed or truncated")
            }
            Self::TenantInvalid => formatter.write_str("memory configuration tenant is invalid"),
        }
    }
}

impl std::error::Error for MemoryConfigError {}

impl MemoryConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "memory_config_insecure",
            Self::Unreadable => "memory_config_unreadable",
            Self::Malformed => "memory_config_malformed",
            Self::TenantInvalid => "memory_config_tenant_invalid",
        }
    }
}

/// One deployment's memory tenant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryConfig {
    tenant: String,
}

impl MemoryConfig {
    /// Where the configuration lives beneath a private state directory.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// The configured tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The tenant this deployment's memory is keyed by, defaulting to
    /// [`DEFAULT_MEMORY_TENANT`] when nothing is configured.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryConfigError`] for a present file that is insecure,
    /// unreadable, or malformed. An absent file is never an error.
    pub fn tenant_or_default(state_dir: &Path) -> Result<String, MemoryConfigError> {
        Ok(Self::load(state_dir)?.map_or_else(
            || String::from(DEFAULT_MEMORY_TENANT),
            |config| config.tenant,
        ))
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`MemoryConfigError`] naming which part of a present file was
    /// refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, MemoryConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(MemoryConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(MemoryConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| MemoryConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| MemoryConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, MemoryConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(MemoryConfigError::Malformed);
        }
        let mut tenant: Option<String> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(MemoryConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(MemoryConfigError::Malformed)?;
            match key {
                "tenant" if tenant.is_none() => {
                    if !is_tenant(value) {
                        return Err(MemoryConfigError::TenantInvalid);
                    }
                    tenant = Some(value.to_owned());
                }
                _ => return Err(MemoryConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(MemoryConfigError::Malformed);
        }
        Ok(Some(Self {
            tenant: tenant.ok_or(MemoryConfigError::TenantInvalid)?,
        }))
    }
}

/// A tenant is an opaque durable key segment, so its charset is the narrow one.
fn is_tenant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TENANT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MEMORY_TENANT, MemoryConfig};

    const FRAME: &str = "schema=automonique.memory/v1\n\
                         tenant=example-tenant\n\
                         end=automonique.memory/v1\n";

    fn category(text: &str) -> &'static str {
        MemoryConfig::parse(text)
            .expect_err("a refused frame")
            .category()
    }

    #[test]
    fn a_complete_frame_carries_the_tenant() {
        let config = MemoryConfig::parse(FRAME)
            .expect("a complete frame")
            .expect("a present configuration");
        assert_eq!(config.tenant(), "example-tenant");
    }

    #[test]
    fn an_absent_file_resolves_to_the_neutral_default() {
        let directory = tempfile::tempdir().expect("a temporary state directory");
        assert!(
            MemoryConfig::load(directory.path())
                .expect("an absent file is not an error")
                .is_none()
        );
        assert_eq!(
            MemoryConfig::tenant_or_default(directory.path()).expect("the default tenant"),
            DEFAULT_MEMORY_TENANT,
        );
    }

    #[test]
    fn a_configured_tenant_wins_over_the_default() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = MemoryConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only permissions");
        assert_eq!(
            MemoryConfig::tenant_or_default(directory.path()).expect("the configured tenant"),
            "example-tenant",
        );
    }

    #[test]
    fn a_malformed_frame_names_what_was_refused() {
        assert_eq!(
            category("schema=automonique.memory/v2\n"),
            "memory_config_malformed"
        );
        assert_eq!(
            category("schema=automonique.memory/v1\ntenant=example-tenant\n"),
            "memory_config_malformed",
            "a frame without its terminator is truncated",
        );
        assert_eq!(
            category(
                "schema=automonique.memory/v1\nowner=example-tenant\nend=automonique.memory/v1\n"
            ),
            "memory_config_malformed",
            "an unknown key is a refusal, not a value to ignore",
        );
        assert_eq!(
            category(
                "schema=automonique.memory/v1\n\
                 tenant=one\n\
                 tenant=two\n\
                 end=automonique.memory/v1\n"
            ),
            "memory_config_malformed",
            "a duplicate key has no precedence rule",
        );
        assert_eq!(
            category("schema=automonique.memory/v1\nend=automonique.memory/v1\ntrailing\n"),
            "memory_config_malformed",
        );
    }

    #[test]
    fn a_present_frame_must_name_a_valid_tenant() {
        assert_eq!(
            category("schema=automonique.memory/v1\nend=automonique.memory/v1\n"),
            "memory_config_tenant_invalid",
            "a frame that names no tenant configures nothing",
        );
        for value in [
            "",
            "Upper",
            "with space",
            "with_underscore",
            &"t".repeat(65),
        ] {
            assert_eq!(
                category(&format!(
                    "schema=automonique.memory/v1\ntenant={value}\nend=automonique.memory/v1\n"
                )),
                "memory_config_tenant_invalid",
                "{value:?} is not a durable key segment",
            );
        }
    }

    #[test]
    fn a_world_readable_file_refuses_startup() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary state directory");
        let path = MemoryConfig::path(directory.path());
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the config directory");
        std::fs::write(&path, FRAME).expect("the configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("relaxed permissions");
        assert_eq!(
            MemoryConfig::load(directory.path())
                .expect_err("an insecure file is refused")
                .category(),
            "memory_config_insecure",
        );
    }
}
