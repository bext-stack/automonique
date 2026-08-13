// SPDX-License-Identifier: Elastic-2.0

//! Telegram host configuration and durable bot-lease lifecycle.
//!
//! The daemon can now load an explicit operator-written bot configuration and
//! own the durable per-bot poller lease beneath its generation fence — the
//! exact state the admin protocol spells `lease_owned_no_client`. HTTP remains
//! deliberately unavailable: no client is constructed, no request is sent, and
//! the loaded token is validated and then dropped, so the daemon holds no
//! unused secret in memory. Enabling live polling is a separate, explicit
//! future step that requires an admin-protocol extension; nothing here
//! silently upgrades into it.
//!
//! # Configuration file
//!
//! `<state>/automonique/telegram/bot.conf`, line-oriented with an explicit
//! header and terminator so a truncated write is a refusal, not a partial
//! configuration:
//!
//! ```text
//! schema=automonique.telegram-bot/v1
//! bot_id=123456
//! token=123456:redacted-example-value
//! end=automonique.telegram-bot/v1
//! ```
//!
//! The file must be a private regular file (owner-only permissions, owned by
//! the daemon's effective user). The token's leading numeric component must
//! equal `bot_id`, which catches a pasted token for a different bot. An absent
//! file means Telegram is deliberately not configured and the daemon stays in
//! `disabled_no_client`; a present-but-invalid or present-but-insecure file
//! refuses daemon startup rather than being ignored, because ignoring it would
//! hide an operator error behind an honest-looking disabled state.

use automonique_protocol::admin::TelegramState;
use automonique_store::Store;
use automonique_transport_runtime::{
    OpaqueBotToken, RuntimeError, StoreTelegramDurableSink, SystemClock, TelegramHostState,
    TelegramLeaseCoordinator,
};
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "telegram/bot.conf";
/// Exact first line of a bot configuration.
const CONFIG_HEADER: &str = "schema=automonique.telegram-bot/v1";
/// Exact final line of a complete bot configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.telegram-bot/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;

/// Why a present Telegram configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`TelegramBotConfig::load`].
#[derive(Debug)]
pub(crate) enum TelegramConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// `bot_id` is absent, not a positive integer, or oversized.
    BotIdInvalid,
    /// The token failed the transport runtime's bounds or charset, or its
    /// leading numeric component does not match `bot_id`.
    TokenInvalid,
}

impl fmt::Display for TelegramConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => formatter
                .write_str("telegram bot configuration is not a private owner-only regular file"),
            Self::Unreadable => formatter.write_str("telegram bot configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("telegram bot configuration frame is malformed or truncated")
            }
            Self::BotIdInvalid => {
                formatter.write_str("telegram bot configuration bot_id is invalid")
            }
            Self::TokenInvalid => formatter
                .write_str("telegram bot configuration token is invalid or does not match bot_id"),
        }
    }
}

impl std::error::Error for TelegramConfigError {}

/// A validated bot configuration. The token was checked and dropped.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TelegramBotConfig {
    bot_id: i64,
}

impl TelegramBotConfig {
    /// Exact configured bot identity.
    pub(crate) const fn bot_id(&self) -> i64 {
        self.bot_id
    }

    /// Configuration file location beneath `state_dir`.
    pub(crate) fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    pub(crate) fn load(state_dir: &Path) -> Result<Option<Self>, TelegramConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(TelegramConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(TelegramConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| TelegramConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| TelegramConfigError::Malformed)?;
        Self::parse(text)
    }

    fn parse(text: &str) -> Result<Option<Self>, TelegramConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(TelegramConfigError::Malformed);
        }
        let mut bot_id: Option<i64> = None;
        let mut token: Option<OpaqueBotToken> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(TelegramConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(TelegramConfigError::Malformed)?;
            match key {
                "bot_id" if bot_id.is_none() => {
                    let parsed = value
                        .parse::<i64>()
                        .map_err(|_| TelegramConfigError::BotIdInvalid)?;
                    if parsed <= 0 {
                        return Err(TelegramConfigError::BotIdInvalid);
                    }
                    bot_id = Some(parsed);
                }
                "token" if token.is_none() => {
                    token = Some(
                        OpaqueBotToken::new(value.as_bytes().to_vec())
                            .map_err(|_| TelegramConfigError::TokenInvalid)?,
                    );
                }
                _ => return Err(TelegramConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(TelegramConfigError::Malformed);
        }
        let bot_id = bot_id.ok_or(TelegramConfigError::BotIdInvalid)?;
        let _token = token.ok_or(TelegramConfigError::TokenInvalid)?;
        // The token's leading numeric component must name the same bot. The
        // comparison runs on the raw line rather than the opaque type so the
        // secret is not re-exposed through a new accessor.
        let expected_prefix = format!("{bot_id}:");
        let token_line = text
            .lines()
            .find_map(|line| line.strip_prefix("token="))
            .ok_or(TelegramConfigError::TokenInvalid)?;
        if !token_line.starts_with(&expected_prefix) {
            return Err(TelegramConfigError::TokenInvalid);
        }
        // `_token` drops here: validated, never retained, best-effort zeroed
        // by its own Drop.
        Ok(Some(Self { bot_id }))
    }
}

/// Telegram host capability state, now able to own the durable bot lease.
pub(crate) enum TelegramHost {
    /// No configuration file exists; no lease is owned, nothing can poll.
    Disabled,
    /// A configured bot's durable poller lease is owned beneath the daemon's
    /// generation fence. HTTP remains deliberately unavailable.
    LeaseOwned {
        coordinator: Box<TelegramLeaseCoordinator<SystemClock>>,
    },
}

impl TelegramHost {
    /// Load configuration and, when present, acquire the durable bot lease.
    ///
    /// The sink opens a second store connection on the daemon's database so
    /// lease custody does not share the admin connection; SQLite serializes
    /// the two through its own locking, exactly as the transport runtime's
    /// lifecycle tests exercise.
    pub(crate) fn open(
        state_dir: &Path,
        database_path: &Path,
        generation_id: &str,
        holder_id: &str,
        authority_lease_epoch: u64,
        ttl_ms: i64,
    ) -> Result<Self, TelegramHostError> {
        let Some(config) = TelegramBotConfig::load(state_dir).map_err(TelegramHostError::Config)?
        else {
            return Ok(Self::Disabled);
        };
        let store = Store::open(database_path).map_err(|_| TelegramHostError::StoreUnavailable)?;
        let sink = StoreTelegramDurableSink::new(store, SystemClock);
        let mut coordinator =
            TelegramLeaseCoordinator::disabled(sink, authority_lease_epoch, ttl_ms)
                .map_err(TelegramHostError::Runtime)?;
        coordinator
            .acquire_no_client(config.bot_id(), generation_id, holder_id)
            .map_err(TelegramHostError::Runtime)?;
        Ok(Self::LeaseOwned {
            coordinator: Box::new(coordinator),
        })
    }

    /// Truthful admin-protocol state and, when owned, the lease's epoch.
    pub(crate) fn status(&self) -> (TelegramState, Option<u64>) {
        match self {
            Self::Disabled => (TelegramState::DisabledNoClient, None),
            Self::LeaseOwned { coordinator } => match coordinator.state() {
                TelegramHostState::LeaseOwnedNoClient(lease) => {
                    (TelegramState::LeaseOwnedNoClient, Some(lease.epoch))
                }
                TelegramHostState::DisabledNoClient => (TelegramState::DisabledNoClient, None),
            },
        }
    }

    /// Renew the owned lease; a no-op when Telegram is not configured.
    ///
    /// Called on the daemon's renewal cadence. A renewal failure is returned
    /// rather than swallowed: an expired bot lease under a live daemon means
    /// durable state moved beneath us, which is exactly what fencing exists to
    /// surface.
    pub(crate) fn renew(&mut self) -> Result<(), TelegramHostError> {
        match self {
            Self::Disabled => Ok(()),
            Self::LeaseOwned { coordinator } => coordinator
                .renew()
                .map(|_| ())
                .map_err(TelegramHostError::Runtime),
        }
    }

    /// Release the owned lease on clean shutdown; a no-op when disabled.
    pub(crate) fn release(&mut self) -> Result<(), TelegramHostError> {
        match self {
            Self::Disabled => Ok(()),
            Self::LeaseOwned { coordinator } => {
                coordinator.release().map_err(TelegramHostError::Runtime)
            }
        }
    }
}

/// Why the Telegram host could not reach or maintain its configured state.
#[derive(Debug)]
pub(crate) enum TelegramHostError {
    /// The configuration file is present but refused.
    Config(TelegramConfigError),
    /// The second store connection could not be opened.
    StoreUnavailable,
    /// Lease acquisition, renewal, or release was refused.
    Runtime(RuntimeError),
}

impl fmt::Display for TelegramHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "telegram configuration refused: {error}"),
            Self::StoreUnavailable => {
                formatter.write_str("telegram lease store connection unavailable")
            }
            Self::Runtime(error) => {
                write!(formatter, "telegram lease lifecycle refused: {error:?}")
            }
        }
    }
}

impl std::error::Error for TelegramHostError {}

impl TelegramHostError {
    /// Stable machine-readable category for the daemon's error surface.
    pub(crate) const fn category(&self) -> &'static str {
        match self {
            Self::Config(TelegramConfigError::Insecure) => "telegram_config_insecure",
            Self::Config(TelegramConfigError::Unreadable) => "telegram_config_unreadable",
            Self::Config(TelegramConfigError::Malformed) => "telegram_config_malformed",
            Self::Config(TelegramConfigError::BotIdInvalid) => "telegram_config_bot_id",
            Self::Config(TelegramConfigError::TokenInvalid) => "telegram_config_token",
            Self::StoreUnavailable => "telegram_store_unavailable",
            Self::Runtime(_) => "telegram_lease_refused",
        }
    }
}
