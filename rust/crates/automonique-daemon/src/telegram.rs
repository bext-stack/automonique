// SPDX-License-Identifier: Elastic-2.0

//! Telegram host configuration, durable bot-lease lifecycle, and the gate that
//! decides whether this daemon may talk to Telegram at all.
//!
//! # Two states, and the one line that separates them
//!
//! A configured bot always means the same thing at startup: load the explicit
//! operator-written configuration and own the durable per-bot poller lease
//! beneath the generation fence. What that lease is *used* for is decided by a
//! second, independent piece of configuration — the allowlist:
//!
//! - **No `allow=` line.** Exactly the state this module has always had. The
//!   token is validated and dropped, no HTTP client is constructed, no request
//!   is prepared, and the daemon holds no unused secret in memory. This is the
//!   admin protocol's `lease_owned_no_client`.
//! - **At least one `allow=` line.** The operator has named who may command the
//!   bot, which is the only configuration that makes a control surface
//!   meaningful. The token is retained in memory (redacted in every rendering,
//!   never logged, never echoed), two clients are constructed, and one worker
//!   thread long-polls beneath the same lease. This is the admin protocol's
//!   `polling_live`, and a host in it never reports a no-client state.
//!
//! The gate is that shape on purpose. A token alone is a credential nobody has
//! been authorized to use, and
//! [`AllowedUsers::new`](automonique_transport_runtime::AllowedUsers::new)
//! refuses an empty list precisely because a control surface reachable by
//! nobody is a configuration mistake. So the daemon cannot drift into live
//! polling: enabling it takes an operator writing down a user id.
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
//! admin=7654321
//! allow=1234567
//! allow=-1001234567890:7654321
//! end=automonique.telegram-bot/v1
//! ```
//!
//! `allow=` may repeat and takes two forms. A bare user id is that user's
//! private chat with the bot, where Telegram's chat id and user id are the same
//! number. The `chat:user` form names one user in one group. Both forms are
//! needed because the transport's access policy admits an exact chat/actor
//! pair — a user allowed in their own chat is not thereby allowed to command
//! the bot from a group somebody added it to — while the control gate is keyed
//! on the user alone.
//!
//! # Who is an administrator
//!
//! `admin=` may repeat and takes the same two forms as `allow=`. It names the
//! **administrators**: the operators who may spend a provider call, work a
//! ticket, and decide who else may be here at all. An administrator is
//! implicitly allowed, so an `admin=` line alone is enough to make a bot live.
//!
//! Administrators exist *only* here. Nothing at runtime can promote anybody:
//! the `/admin` command adds and removes non-admin **members**, which live in a
//! durable roster beside this file, and the composition in
//! [`crate::telegram_bridge::OperatorRoster`] has no path that puts a member in
//! the admin set. Revoking an administrator means editing this file and
//! restarting, which is the correct cost for the one authority a compromised
//! chat must not be able to grant itself.
//!
//! **A configuration with no `admin=` line at all treats every allowed user as
//! an administrator.** That is the back-compatible reading and it is deliberate:
//! every deployment written before this key existed says `allow=` and means
//! "these are my operators", and introducing a key whose absence silently
//! demoted all of them to read-only would break a working host on upgrade with
//! no diagnostic. An owner who wants two tiers opts in by naming at least one
//! administrator, and from that moment `allow=` means "allowed, not admin".
//!
//! The file must be a private regular file (owner-only permissions, owned by
//! the daemon's effective user). The token's leading numeric component must
//! equal `bot_id`, which catches a pasted token for a different bot. An absent
//! file means Telegram is deliberately not configured and the daemon stays in
//! `disabled_no_client`; a present-but-invalid or present-but-insecure file
//! refuses daemon startup rather than being ignored, because ignoring it would
//! hide an operator error behind an honest-looking disabled state.
//!
//! # The token, once it is retained
//!
//! Retention is best-effort hygiene, exactly as far as
//! [`OpaqueBotToken`] can carry it: the value is redacted in `Debug`, is only
//! borrowed at the two HTTP boundaries that must spend it, and is zeroed when
//! dropped. The configuration text it was read from is a plain `String` this
//! module cannot zero, which is the same limit the validate-and-drop path
//! already had. Nothing in this crate renders, logs or replies with it.

use crate::manage_config::ManageConfig;
use crate::run_lane::SocketRunLane;
use crate::telegram_bridge::{
    BridgeParts, HostFacts, OperatorRoster, StoreControlSurface, TelegramControlBridge,
};
use automonique_protocol::admin::{ExecutionState, TelegramState};
use automonique_store::Store;
use automonique_transport_runtime::{
    CancellationToken, MAX_ALLOWED_USERS, OpaqueBotToken, PollerLease, RuntimeError,
    StoreTelegramDurableSink, SystemClock, TelegramHostState, TelegramHttpsClient,
    TelegramLeaseCoordinator,
};
use automonique_transports::{TelegramBotId, TelegramPrincipal};
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "telegram/bot.conf";
/// Exact first line of a bot configuration.
const CONFIG_HEADER: &str = "schema=automonique.telegram-bot/v1";
/// Exact final line of a complete bot configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.telegram-bot/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;
/// Most `allow=` entries one configuration may carry.
///
/// The control gate refuses a longer list anyway; refusing here means a
/// pathological file is rejected while it is being read rather than after.
const MAX_ALLOW_ENTRIES: usize = MAX_ALLOWED_USERS;
/// Most `admin=` entries one configuration may carry.
///
/// The same bound, for the same reason. It is a separate constant because the
/// two lists are separate authorities, and a future decision to bound
/// administrators more tightly should not have to be argued out of a shared
/// name.
const MAX_ADMIN_ENTRIES: usize = MAX_ALLOWED_USERS;

/// Long-poll timeout this host asks Telegram for, in seconds.
///
/// Deliberately short. The runtime refuses a poll whose deadline — the timeout
/// plus its own transport margin — reaches the bot lease's expiry, and this
/// daemon renews that lease on the serve loop's cadence. A poll must therefore
/// fit inside the *worst-case* remaining lease, which is one renewal interval,
/// not one whole TTL. [`crate`] asserts that relationship at compile time.
pub(crate) const TELEGRAM_LONG_POLL_SECONDS: u16 = 3;

/// The concrete bridge this host runs on its worker thread.
///
/// Two clients, not one: an outbound reply must never queue behind a long poll,
/// and each client owns its own connection pool.
type LiveBridge = TelegramControlBridge<
    TelegramHttpsClient,
    TelegramHttpsClient,
    StoreTelegramDurableSink<SystemClock>,
    StoreControlSurface,
    SocketRunLane,
>;

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
    /// An `allow=` entry is not a chat/user pair the transport policy and the
    /// control gate both admit, or there are more of them than either accepts.
    AllowlistInvalid,
    /// An `admin=` entry is not a chat/user pair both admit, or there are more
    /// of them than either accepts.
    ///
    /// Separate from [`Self::AllowlistInvalid`] because the two lines mean
    /// different things and an operator staring at a refused startup needs to
    /// know which one they mistyped.
    AdminlistInvalid,
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
            Self::AllowlistInvalid => {
                formatter.write_str("telegram bot configuration allowlist is invalid")
            }
            Self::AdminlistInvalid => {
                formatter.write_str("telegram bot configuration admin list is invalid")
            }
        }
    }
}

impl std::error::Error for TelegramConfigError {}

/// A validated bot configuration and what it authorizes.
#[derive(Debug)]
pub(crate) struct TelegramBotConfig {
    bot_id: i64,
    enablement: TelegramEnablement,
}

/// What a validated configuration permits.
///
/// The two variants are the whole gate. Only [`Self::Live`] holds a credential,
/// and it can only be built from a configuration that named at least one user.
#[derive(Debug)]
pub(crate) enum TelegramEnablement {
    /// A bot is configured and its lease is worth owning, but nobody is
    /// authorized to command it. The token was validated and dropped.
    LeaseOnly,
    /// An operator authorized specific users, so the credential is retained and
    /// live control is composable.
    Live(Box<LiveControl>),
}

/// Everything live control needs, and nothing that does not belong to it.
///
/// Three tokens because inbound polling, immediate outbound control, and
/// background question answers each own one for their own lifetime. All are
/// the same credential, independently constructed because the opaque type is
/// deliberately not cloneable, and all are redacted, borrow-only and zeroed on
/// drop.
#[derive(Debug)]
pub(crate) struct LiveControl {
    /// The configured operator roster, from which the transport policy and the
    /// tiered control gate are both composed — together with whatever the
    /// durable member roster holds at the time.
    roster: OperatorRoster,
    /// Credential the long poll spends.
    inbound_token: OpaqueBotToken,
    /// Credential replies and the menu spend.
    outbound_token: OpaqueBotToken,
    /// Credential background question answers spend.
    question_outbound_token: OpaqueBotToken,
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
        let mut allow: Vec<(i64, i64)> = Vec::new();
        let mut admin: Vec<(i64, i64)> = Vec::new();
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
                // The two repeatable keys. Repetition is the point: an operator
                // authorizes a second person by adding a line, not by editing
                // one, and a duplicate is idempotent rather than a refusal.
                "allow" => {
                    if allow.len() >= MAX_ALLOW_ENTRIES {
                        return Err(TelegramConfigError::AllowlistInvalid);
                    }
                    allow.push(parse_allow_entry(value)?);
                }
                "admin" => {
                    if admin.len() >= MAX_ADMIN_ENTRIES {
                        return Err(TelegramConfigError::AdminlistInvalid);
                    }
                    admin.push(
                        parse_allow_entry(value)
                            .map_err(|_| TelegramConfigError::AdminlistInvalid)?,
                    );
                }
                // An unknown key still refuses startup. A configuration this
                // build cannot fully understand may be granting an authority it
                // would silently drop, and dropping authority quietly is the
                // failure this whole module is shaped to avoid.
                _ => return Err(TelegramConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(TelegramConfigError::Malformed);
        }
        let bot_id = bot_id.ok_or(TelegramConfigError::BotIdInvalid)?;
        let token = token.ok_or(TelegramConfigError::TokenInvalid)?;
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
        // An administrator is implicitly allowed, so a configuration that names
        // only administrators is as live as one that names only allowed users.
        let enablement = if allow.is_empty() && admin.is_empty() {
            // THE GATE, CLOSED. The token drops here: validated, never
            // retained, best-effort zeroed by its own `Drop`. What follows
            // holds no credential, so what follows cannot reach Telegram.
            drop(token);
            TelegramEnablement::LeaseOnly
        } else {
            TelegramEnablement::Live(Box::new(LiveControl::new(
                bot_id, &allow, &admin, token, token_line,
            )?))
        };
        Ok(Some(Self { bot_id, enablement }))
    }
}

impl LiveControl {
    /// Compose the authority models the `admin=` and `allow=` lists define.
    ///
    /// They are separate objects because they answer separate questions, and an
    /// inbound message must satisfy all of them: the transport policy decides
    /// whether an update becomes durable work at all, the allowed set decides
    /// whether its text is parsed as a command, and the admin set decides
    /// whether *that* command may run. Deriving all three from one roster is
    /// what keeps them from ever disagreeing about who the operators are.
    ///
    /// THE BACK-COMPATIBLE READING, IN ONE LINE. When no `admin=` appears, the
    /// administrators are every allowed user. See this module's own note on why
    /// the absence of a key must not demote a deployment that predates it.
    fn new(
        bot_id: i64,
        allow: &[(i64, i64)],
        admin: &[(i64, i64)],
        inbound_token: OpaqueBotToken,
        token_line: &str,
    ) -> Result<Self, TelegramConfigError> {
        let mut principals = Vec::with_capacity(allow.len() + admin.len());
        for (chat_id, actor_id) in admin.iter().chain(allow) {
            principals.push(
                TelegramPrincipal::new(*chat_id, *actor_id)
                    .map_err(|_| TelegramConfigError::AllowlistInvalid)?,
            );
        }
        let configured: Vec<i64> = admin
            .iter()
            .chain(allow)
            .map(|(_, actor_id)| *actor_id)
            .collect();
        let admins: Vec<i64> = if admin.is_empty() {
            configured.clone()
        } else {
            admin.iter().map(|(_, actor_id)| *actor_id).collect()
        };
        let roster = OperatorRoster::new(
            TelegramBotId::new(bot_id).map_err(|_| TelegramConfigError::BotIdInvalid)?,
            principals,
            configured,
            admins,
        )
        .map_err(|_| {
            if admin.is_empty() {
                TelegramConfigError::AllowlistInvalid
            } else {
                TelegramConfigError::AdminlistInvalid
            }
        })?;
        // The second copy is the same credential for the outbound transport,
        // rebuilt from the same validated line rather than cloned — the opaque
        // type deliberately offers no `Clone`.
        let outbound_token = OpaqueBotToken::new(token_line.as_bytes().to_vec())
            .map_err(|_| TelegramConfigError::TokenInvalid)?;
        let question_outbound_token = OpaqueBotToken::new(token_line.as_bytes().to_vec())
            .map_err(|_| TelegramConfigError::TokenInvalid)?;
        Ok(Self {
            roster,
            inbound_token,
            outbound_token,
            question_outbound_token,
        })
    }
}

/// Parse one `allow=` value into an exact chat/actor pair.
///
/// A bare user id is that user's private chat with the bot, where Telegram
/// gives the chat the same numeric id as the user. Anything else must name both
/// coordinates, because a group chat's id is not derivable from a member's and
/// guessing one would silently authorize the wrong conversation.
fn parse_allow_entry(value: &str) -> Result<(i64, i64), TelegramConfigError> {
    let (chat_id, actor_id) = match value.split_once(':') {
        Some((chat, actor)) => (
            chat.parse::<i64>()
                .map_err(|_| TelegramConfigError::AllowlistInvalid)?,
            actor
                .parse::<i64>()
                .map_err(|_| TelegramConfigError::AllowlistInvalid)?,
        ),
        None => {
            let actor = value
                .parse::<i64>()
                .map_err(|_| TelegramConfigError::AllowlistInvalid)?;
            (actor, actor)
        }
    };
    if chat_id == 0 || actor_id <= 0 {
        return Err(TelegramConfigError::AllowlistInvalid);
    }
    Ok((chat_id, actor_id))
}

/// Everything [`TelegramHost::open`] needs, as one value.
///
/// A struct rather than eight positional arguments: half of them are paths and
/// two of them are identifiers, and a caller that transposed a pair would still
/// compile.
pub(crate) struct TelegramHostParams<'a> {
    /// Private state directory holding the bot configuration.
    pub(crate) state_dir: &'a Path,
    /// The daemon's main database, which carries the bot lease and the status.
    pub(crate) database_path: &'a Path,
    /// The runs read model a `/runs` reply lists from, and that a `/run` waits
    /// on.
    pub(crate) run_index_path: &'a Path,
    /// The support ticket store a `/tickets` or `/ticket` reply reads.
    ///
    /// Named even on a host whose support intake is disabled, where the file
    /// never appears and both commands answer that ticket tracking is not
    /// enabled. Nothing here creates it: the intake gate is the only writer, and
    /// [`StoreControlSurface::with_support_tickets`] only remembers the path.
    pub(crate) support_tickets_path: &'a Path,
    /// The durable roster of members an administrator added from a chat.
    ///
    /// Named on every host, created by none of them at startup: the first
    /// `/admin add` is the only thing that brings the file into existence, and
    /// a host whose administrators never add anybody never has one.
    pub(crate) operator_members_path: &'a Path,
    /// This daemon's own admin endpoint, which a `/run` submits and starts
    /// through. See [`crate::run_lane`] for why the poller thread is a client
    /// of the daemon it belongs to.
    pub(crate) admin_socket: &'a Path,
    /// Generation this daemon holds.
    pub(crate) generation_id: &'a str,
    /// This daemon's instance identity.
    pub(crate) holder_id: &'a str,
    /// The generation lease epoch that authorizes the bot lease.
    pub(crate) authority_lease_epoch: u64,
    /// Bot lease TTL.
    pub(crate) ttl_ms: i64,
    /// What the startup probe measured about sandboxed execution.
    pub(crate) execution_state: ExecutionState,
}

/// Telegram host capability state.
pub(crate) enum TelegramHost {
    /// No configuration file exists; no lease is owned, nothing can poll.
    Disabled,
    /// A configured bot's durable poller lease is owned beneath the daemon's
    /// generation fence, and nobody is authorized to command the bot. HTTP
    /// remains deliberately unavailable: no client exists and the token was
    /// dropped.
    LeaseOwned {
        coordinator: Box<TelegramLeaseCoordinator<SystemClock>>,
    },
    /// The same owned lease, plus an authorized operator list — so a bridge is
    /// composed and one worker thread polls beneath the lease.
    Live {
        coordinator: Box<TelegramLeaseCoordinator<SystemClock>>,
        control: Box<PollerControl>,
    },
}

/// The worker thread's half of a live host.
///
/// The lease is *published* here rather than owned: the coordinator on the serve
/// thread stays the only thing that renews or releases it, and each renewal
/// replaces this value so the poller's next iteration reads the current expiry.
/// That keeps lease custody exactly where it already was and gives the worker no
/// authority it could accidentally extend.
pub(crate) struct PollerControl {
    /// The current lease, republished by the serve thread on every renewal.
    lease: Arc<Mutex<PollerLease>>,
    /// Set by the serve thread at shutdown, read between poll iterations.
    stop: Arc<AtomicBool>,
    /// Held because `poll_once` requires one, and never fired.
    ///
    /// Cancelling would abandon an in-flight long poll before its batch could
    /// commit, which is the opposite of what shutdown wants: the stop flag lets
    /// the poll finish and advance the durable offset, and the transport's own
    /// timeout is what bounds the wait.
    cancellation: CancellationToken,
    /// The composed bridge, until [`TelegramHost::start`] moves it onto its
    /// thread. `Some` between `open` and the first `start`, which is why a
    /// daemon that is opened and dropped without serving never issues a request.
    prepared: Option<Box<LiveBridge>>,
    /// The worker, joined before the bot lease is released.
    worker: Option<JoinHandle<()>>,
}

impl PollerControl {
    /// Whether a started poller has ended.
    ///
    /// A bridge returns only fail-closed — an unresolvable ambiguous commit, or
    /// a serve thread that stopped republishing the lease — and when it does it
    /// takes the client and both credentials with it, because the thread's
    /// closure owned them. So this answers a question about what this host still
    /// holds, which is what its reported state has to be built from.
    ///
    /// False before [`TelegramHost::start`], when the bridge is composed and
    /// parked: the client exists and is about to poll. Nothing can observe the
    /// host in that window, because `serve` starts the poller before it accepts
    /// a connection.
    fn stopped(&self) -> bool {
        self.prepared.is_none() && self.worker.as_ref().is_some_and(JoinHandle::is_finished)
    }
}

/// Last-resort custody, for a host that was dropped without being released.
///
/// [`TelegramHost::release`] is the ordered path and the only one that also
/// releases the lease; this exists so a process unwinding out of `serve` cannot
/// leave a thread polling and committing under a generation nobody is holding
/// any more. It is not a substitute for the ordered path — it cannot release the
/// lease, because by the time a field is dropped the coordinator beside it may
/// already be gone.
impl Drop for PollerControl {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl TelegramHost {
    /// Load configuration and, when present, acquire the durable bot lease.
    ///
    /// The sink opens a second store connection on the daemon's database so
    /// lease custody does not share the admin connection; SQLite serializes
    /// the two through its own locking, exactly as the transport runtime's
    /// lifecycle tests exercise. A live host opens two more — one for the
    /// poller's own durable sink and one for the read surface — for the reason
    /// [`crate::execute`]'s workers open their own: a thread that borrowed the
    /// serve loop's handle would either need a lock around every admin request
    /// or would race one.
    ///
    /// Nothing is dialled here. A live configuration is *composed* and then
    /// parked; [`Self::start`] is what puts it on a thread.
    ///
    /// `slack` is taken by value rather than by reference in the params, because
    /// a composed Slack client is *moved* into the bridge that will spend it. A
    /// host with no Telegram configuration drops it here, which is exactly
    /// right: nothing would ever have called it, and the credential should not
    /// outlive the surface that could.
    #[cfg(test)]
    pub(crate) fn open(
        params: &TelegramHostParams<'_>,
        slack: crate::slack::SlackHost,
    ) -> Result<Self, TelegramHostError> {
        Self::open_with_ticket_gates(
            params,
            slack,
            Arc::new(Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
        )
    }

    pub(crate) fn open_with_ticket_gates(
        params: &TelegramHostParams<'_>,
        slack: crate::slack::SlackHost,
        ticket_gates: Arc<Mutex<crate::telegram_bridge::TicketGateRegistry>>,
    ) -> Result<Self, TelegramHostError> {
        let Some(config) =
            TelegramBotConfig::load(params.state_dir).map_err(TelegramHostError::Config)?
        else {
            return Ok(Self::Disabled);
        };
        let store =
            Store::open(params.database_path).map_err(|_| TelegramHostError::StoreUnavailable)?;
        let sink = StoreTelegramDurableSink::new(store, SystemClock);
        let mut coordinator =
            TelegramLeaseCoordinator::disabled(sink, params.authority_lease_epoch, params.ttl_ms)
                .map_err(TelegramHostError::Runtime)?;
        let lease = coordinator
            .acquire_no_client(config.bot_id(), params.generation_id, params.holder_id)
            .map_err(TelegramHostError::Runtime)?
            .clone();
        let coordinator = Box::new(coordinator);
        let TelegramBotConfig {
            bot_id,
            enablement: TelegramEnablement::Live(live),
        } = config
        else {
            return Ok(Self::LeaseOwned { coordinator });
        };
        let bridge = Self::compose(params, bot_id, *live, slack, ticket_gates)?;
        Ok(Self::Live {
            coordinator,
            control: Box::new(PollerControl {
                lease: Arc::new(Mutex::new(lease)),
                stop: Arc::new(AtomicBool::new(false)),
                cancellation: CancellationToken::new(),
                prepared: Some(Box::new(bridge)),
                worker: None,
            }),
        })
    }

    /// Build the live bridge over its own durable handles and two clients.
    fn compose(
        params: &TelegramHostParams<'_>,
        bot_id: i64,
        live: LiveControl,
        slack: crate::slack::SlackHost,
        ticket_gates: Arc<Mutex<crate::telegram_bridge::TicketGateRegistry>>,
    ) -> Result<LiveBridge, TelegramHostError> {
        let manage =
            ManageConfig::load(params.state_dir).map_err(TelegramHostError::ManageConfig)?;
        let memory_tenant = crate::memory_config::MemoryConfig::tenant_or_default(params.state_dir)
            .map_err(TelegramHostError::MemoryConfig)?;
        let surface = StoreControlSurface::open(
            params.database_path,
            params.run_index_path,
            HostFacts {
                generation_id: params.generation_id.to_owned(),
                holder_id: params.holder_id.to_owned(),
                lease_epoch: params.authority_lease_epoch,
                bot_id,
                execution_state: params.execution_state,
            },
        )
        .map_err(|_| TelegramHostError::SurfaceUnavailable)?
        .with_support_tickets(params.support_tickets_path)
        .with_operator_members(params.operator_members_path)
        .with_prism_sites(Path::new(crate::site_inventory::NGINX_SITES_ENABLED))
        .with_provider_state(params.state_dir);
        let surface = match manage.as_ref().and_then(ManageConfig::profile_app) {
            Some(profile_app) => surface.with_manage_profiles(profile_app.clone()),
            None => surface,
        };
        let poller_store =
            Store::open(params.database_path).map_err(|_| TelegramHostError::StoreUnavailable)?;
        // The lane opens successfully on a deployment that has not configured
        // `/run` at all and refuses every one with `not configured`; only an
        // unopenable read model is a startup refusal, because a lane that could
        // not observe a run would report every one of them as unavailable.
        let lane =
            SocketRunLane::open(params.state_dir, params.admin_socket, params.run_index_path)
                .map_err(|_| TelegramHostError::SurfaceUnavailable)?;
        let ticket_actions = crate::ticket_intake::FleetConfig::load(params.state_dir)
            .map_err(|_| TelegramHostError::SurfaceUnavailable)?
            .map(|config| {
                Box::new(config.into_action_client())
                    as Box<dyn crate::telegram_bridge::TicketActionSurface + Send>
            });
        let email_actions = crate::ticket_intake::FleetConfig::load(params.state_dir)
            .map_err(|_| TelegramHostError::SurfaceUnavailable)?
            .map(|config| {
                Box::new(config.into_action_client())
                    as Box<dyn crate::telegram_bridge::EmailActionSurface + Send>
            });
        let github = crate::github::GitHubHost::load(params.state_dir)
            .map_err(TelegramHostError::GitHubConfig)?
            .into_surface();
        let github_actions = crate::github::GitHubHost::load(params.state_dir)
            .map_err(TelegramHostError::GitHubConfig)?
            .into_action_surface();
        let improvements = Some(
            crate::improvements::ImprovementCoordinator::open_default(params.state_dir)
                .map_err(|_| TelegramHostError::SurfaceUnavailable)?,
        );
        let planning_repo =
            automonique_github_connector::RepoTarget::parse("bext-stack", "automonique-plans")
                .expect("fixed planning repository");
        let source_repo =
            automonique_github_connector::RepoTarget::parse("bext-stack", "automonique")
                .expect("fixed source repository");
        let improvement_github = Some(
            crate::improvement_github::ImprovementGitHubBroker::production(
                planning_repo,
                source_repo,
                "main",
                "main",
            )
            .map_err(|_| TelegramHostError::SurfaceUnavailable)?,
        );
        let improvement_worker =
            crate::improvement_worker::ImprovementWorker::load(params.state_dir)
                .map_err(|_| TelegramHostError::SurfaceUnavailable)?;
        TelegramControlBridge::new_with_ticket_gates(
            BridgeParts {
                client: TelegramHttpsClient::new(),
                outbound: TelegramHttpsClient::new(),
                question_outbound: TelegramHttpsClient::new(),
                sink: StoreTelegramDurableSink::new(poller_store, SystemClock),
                surface,
                lane,
                // `None` on a host with no `slack.conf`, which is what makes
                // `/slack` and `/say` answer that Slack is not configured rather
                // than fail. A refused configuration never reaches here: it failed
                // startup before this host was opened.
                slack: slack.into_surface(),
                github,
                github_actions,
                improvements,
                improvement_github,
                improvement_worker,
                ticket_actions,
                email_actions,
                memory: Some(Box::new(
                    crate::telegram_bridge::StoreMemorySurface::open(
                        &params.state_dir.join("agent-memory.sqlite3"),
                        bot_id,
                        &memory_tenant,
                    )
                    .map_err(|_| TelegramHostError::SurfaceUnavailable)?,
                )),
                roster: live.roster,
                inbound_token: live.inbound_token,
                outbound_token: live.outbound_token,
                question_outbound_token: live.question_outbound_token,
                long_poll_seconds: TELEGRAM_LONG_POLL_SECONDS,
            },
            ticket_gates,
        )
        .map_err(TelegramHostError::Runtime)
    }

    /// Put a composed bridge on its own thread. Idempotent, and a no-op unless
    /// this host is live.
    ///
    /// Called by [`crate::Daemon::serve`] and not by `open`, so a daemon that
    /// was opened and never served — which several tests and every refused
    /// startup do — has never sent a byte to Telegram.
    ///
    /// A thread that cannot be spawned is a startup refusal rather than a
    /// silently degraded host: the operator asked for live control by writing
    /// down who may use it, and a daemon that quietly answers nobody would be
    /// the dishonest state this module exists to avoid.
    pub(crate) fn start(&mut self) -> Result<(), TelegramHostError> {
        let Self::Live { control, .. } = self else {
            return Ok(());
        };
        let Some(mut bridge) = control.prepared.take() else {
            return Ok(());
        };
        let lease = Arc::clone(&control.lease);
        let stop = Arc::clone(&control.stop);
        let cancellation = control.cancellation.clone();
        let worker = std::thread::Builder::new()
            .name(String::from("automonique-telegram"))
            .spawn(move || {
                // The menu is published before the first poll so an operator
                // who opens the chat sees the vocabulary the bot will answer.
                bridge.publish_menu(&cancellation);
                bridge.run(&lease, &stop, &cancellation);
            })
            .map_err(|_| TelegramHostError::PollerUnavailable)?;
        control.worker = Some(worker);
        Ok(())
    }

    /// Truthful admin-protocol state and, when owned, the lease's epoch.
    ///
    /// The three host states map one-to-one onto the three protocol states, and
    /// that is the whole point of the mapping: a host holding a client reports
    /// `polling_live` and never a no-client state. This field is the only place
    /// an operator can read whether their bot is answering, so it says what is
    /// true rather than what is convenient.
    ///
    /// The epoch is read from the coordinator rather than remembered here, so a
    /// lease the coordinator no longer holds cannot be reported as owned.
    ///
    /// Reporting `polling_live` from a [`Self::Live`] host whose thread has not
    /// started yet would be premature, and cannot happen: the client is
    /// constructed at open, [`crate::Daemon::serve`] calls [`Self::start`]
    /// before it accepts a single connection, and no status can be requested
    /// until it does.
    ///
    /// Reporting it from a host whose poller has *stopped* would be worse — it
    /// would tell an operator their bot is answering when nothing is listening —
    /// so a live host that lost its poller reports the no-client state, which by
    /// then is exactly true: the thread that ended owned the client and both
    /// credentials, and dropped them on its way out. See
    /// [`PollerControl::stopped`].
    pub(crate) fn status(&self) -> (TelegramState, Option<u64>) {
        let (coordinator, owned) = match self {
            Self::Disabled => return (TelegramState::DisabledNoClient, None),
            Self::LeaseOwned { coordinator } => (coordinator, TelegramState::LeaseOwnedNoClient),
            Self::Live {
                coordinator,
                control,
            } => (
                coordinator,
                if control.stopped() {
                    TelegramState::LeaseOwnedNoClient
                } else {
                    TelegramState::PollingLive
                },
            ),
        };
        match coordinator.state() {
            TelegramHostState::LeaseOwnedNoClient(lease) => (owned, Some(lease.epoch)),
            // The lease was released, so this host owns nothing to poll with
            // whatever it still holds a client for.
            TelegramHostState::DisabledNoClient => (TelegramState::DisabledNoClient, None),
        }
    }

    /// Whether a Telegram operator could decide an approval right now.
    ///
    /// Exactly [`TelegramState::PollingLive`], which is the one state in which
    /// this host holds both the bot lease and a client bound to it. A
    /// configured bot whose poller has stopped is not a decision surface, and
    /// the status this reads already makes that distinction for the operator's
    /// benefit; the approval policy reads the same answer rather than a second
    /// one.
    pub(crate) fn poller_live(&self) -> bool {
        matches!(self.status().0, TelegramState::PollingLive)
    }

    /// Renew the owned lease; a no-op when Telegram is not configured.
    ///
    /// Called on the daemon's renewal cadence. A renewal failure is returned
    /// rather than swallowed: an expired bot lease under a live daemon means
    /// durable state moved beneath us, which is exactly what fencing exists to
    /// surface.
    ///
    /// A live host also republishes the renewed lease, because the poller's next
    /// iteration must see the new expiry — the runtime refuses a poll whose
    /// deadline reaches it.
    pub(crate) fn renew(&mut self) -> Result<(), TelegramHostError> {
        match self {
            Self::Disabled => Ok(()),
            Self::LeaseOwned { coordinator } => coordinator
                .renew()
                .map(|_| ())
                .map_err(TelegramHostError::Runtime),
            Self::Live {
                coordinator,
                control,
            } => {
                let renewed = coordinator
                    .renew()
                    .map_err(TelegramHostError::Runtime)?
                    .clone();
                // A poisoned mutex means the worker panicked while cloning the
                // lease. The worker's own loop treats that as terminal and
                // stops, so there is nothing to publish to.
                if let Ok(mut published) = control.lease.lock() {
                    *published = renewed;
                }
                Ok(())
            }
        }
    }

    /// Release the owned lease on clean shutdown; a no-op when disabled.
    ///
    /// A live host stops and joins its worker *first*. The order is the same one
    /// [`crate::Daemon::serve`] uses for its execution lane and for the same
    /// reason: the poller writes to durable state this generation owns and holds
    /// the very lease being released, so returning while it still polls would
    /// leave a committer running under authority nobody holds.
    pub(crate) fn release(&mut self) -> Result<(), TelegramHostError> {
        self.stop_polling();
        match self {
            Self::Disabled => Ok(()),
            Self::LeaseOwned { coordinator } | Self::Live { coordinator, .. } => {
                coordinator.release().map_err(TelegramHostError::Runtime)
            }
        }
    }

    /// Ask the worker to finish its in-flight poll, then join it.
    ///
    /// Blocks for at most one long poll plus the transport's own allowance. The
    /// in-flight request is deliberately not cancelled: letting it complete is
    /// what commits its batch and advances the durable offset, so the updates it
    /// already fetched are not re-delivered to a successor.
    fn stop_polling(&mut self) {
        let Self::Live { control, .. } = self else {
            return;
        };
        control.stop.store(true, Ordering::Release);
        control.prepared = None;
        if let Some(worker) = control.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Why the Telegram host could not reach or maintain its configured state.
#[derive(Debug)]
pub(crate) enum TelegramHostError {
    /// The configuration file is present but refused.
    Config(TelegramConfigError),
    /// A present GitHub read configuration was refused.
    GitHubConfig(crate::github::GitHubConfigError),
    /// A present Manage configuration was refused.
    ManageConfig(crate::manage_config::ManageConfigError),
    /// A present memory configuration was refused.
    MemoryConfig(crate::memory_config::MemoryConfigError),
    /// The second store connection could not be opened.
    StoreUnavailable,
    /// The poller's read surface could not open its own durable handles.
    SurfaceUnavailable,
    /// The poller thread could not be started.
    PollerUnavailable,
    /// Lease acquisition, renewal, or release was refused.
    Runtime(RuntimeError),
}

impl fmt::Display for TelegramHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "telegram configuration refused: {error}"),
            Self::GitHubConfig(error) => write!(formatter, "{error}"),
            Self::ManageConfig(error) => write!(formatter, "{error}"),
            Self::MemoryConfig(error) => write!(formatter, "{error}"),
            Self::StoreUnavailable => {
                formatter.write_str("telegram lease store connection unavailable")
            }
            Self::SurfaceUnavailable => {
                formatter.write_str("telegram control read surface unavailable")
            }
            Self::PollerUnavailable => formatter.write_str("telegram poller thread unavailable"),
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
            Self::Config(TelegramConfigError::AllowlistInvalid) => "telegram_config_allowlist",
            Self::Config(TelegramConfigError::AdminlistInvalid) => "telegram_config_adminlist",
            Self::GitHubConfig(error) => error.category(),
            Self::ManageConfig(error) => error.category(),
            Self::MemoryConfig(error) => error.category(),
            Self::StoreUnavailable => "telegram_store_unavailable",
            Self::SurfaceUnavailable => "telegram_surface_unavailable",
            Self::PollerUnavailable => "telegram_poller_unavailable",
            Self::Runtime(_) => "telegram_lease_refused",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_transport_runtime::{CommandKind, CommandTier, OperatorAuthority};
    use automonique_transports::TelegramAccessPolicy;
    use std::os::unix::fs::PermissionsExt as _;

    /// A private state tree with a live generation, ready to open a host from.
    ///
    /// Nothing here starts a poller. Every assertion below is on a *composed*
    /// host, which is what keeps this module's tests free of the network: the
    /// client exists, and [`TelegramHost::start`] — the only thing that would
    /// send a request — is never called.
    struct HostFixture {
        _root: tempfile::TempDir,
        state_dir: PathBuf,
        database_path: PathBuf,
        run_index_path: PathBuf,
        support_tickets_path: PathBuf,
        operator_members_path: PathBuf,
        admin_socket: PathBuf,
        lease_epoch: u64,
    }

    impl HostFixture {
        /// Build the tree, writing `bot.conf` only when one is given.
        fn new(bot_conf: Option<&str>) -> Self {
            let root = tempfile::tempdir().expect("temporary root");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private root");
            let state_dir = root.path().join("state");
            std::fs::create_dir(&state_dir).expect("state directory");
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
                .expect("private state");
            if let Some(body) = bot_conf {
                let telegram_dir = state_dir.join("telegram");
                std::fs::create_dir(&telegram_dir).expect("telegram directory");
                std::fs::set_permissions(&telegram_dir, std::fs::Permissions::from_mode(0o700))
                    .expect("private telegram directory");
                let path = telegram_dir.join("bot.conf");
                std::fs::write(&path, body).expect("configuration written");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("private configuration");
            }
            let database_path = state_dir.join("automonique.sqlite3");
            let run_index_path = state_dir.join("run-index.sqlite3");
            // Named and never created: composing a host must not bring a ticket
            // store into existence on a tree whose intake is disabled.
            let support_tickets_path = state_dir.join(crate::SUPPORT_TICKETS_NAME);
            // Named and never created, for the same reason: composing a host
            // must not bring a member roster into existence on a tree whose
            // administrators have never added anybody.
            let operator_members_path = state_dir.join(crate::OPERATOR_MEMBERS_NAME);
            let admin_socket = state_dir.join("admin.sock");
            let mut store = Store::open(&database_path).expect("store opens");
            let lease = store
                .acquire_generation_lease(automonique_store::LeaseRequest {
                    generation_id: crate::GENERATION_ID,
                    holder_id: "telegram-host-fixture",
                    now_ms: crate::unix_millis().expect("clock"),
                    ttl_ms: 600_000,
                })
                .expect("generation lease");
            Self {
                _root: root,
                state_dir,
                database_path,
                run_index_path,
                support_tickets_path,
                operator_members_path,
                admin_socket,
                lease_epoch: lease.epoch,
            }
        }

        fn params(&self) -> TelegramHostParams<'_> {
            TelegramHostParams {
                state_dir: &self.state_dir,
                database_path: &self.database_path,
                run_index_path: &self.run_index_path,
                support_tickets_path: &self.support_tickets_path,
                operator_members_path: &self.operator_members_path,
                admin_socket: &self.admin_socket,
                generation_id: crate::GENERATION_ID,
                holder_id: "telegram-host-fixture",
                authority_lease_epoch: self.lease_epoch,
                ttl_ms: crate::TELEGRAM_LEASE_TTL_MS,
                execution_state: ExecutionState::SandboxUnavailableNoLane,
            }
        }
    }

    /// An unconfigured host says so, and owns nothing.
    #[test]
    fn an_absent_configuration_reports_the_disabled_state() {
        let fixture = HostFixture::new(None);
        let host = TelegramHost::open(&fixture.params(), crate::slack::SlackHost::Disabled)
            .expect("host opens");
        assert!(matches!(host, TelegramHost::Disabled));
        assert_eq!(host.status(), (TelegramState::DisabledNoClient, None));
    }

    /// THE GATE, REPORTED. A configured bot with nobody authorized owns its
    /// lease and truthfully says no client exists.
    #[test]
    fn a_host_without_an_allowlist_reports_the_no_client_state() {
        let fixture = HostFixture::new(Some(&config(&[])));
        let mut host = TelegramHost::open(&fixture.params(), crate::slack::SlackHost::Disabled)
            .expect("host opens");
        assert!(matches!(host, TelegramHost::LeaseOwned { .. }));
        let (state, epoch) = host.status();
        assert_eq!(state, TelegramState::LeaseOwnedNoClient);
        assert!(epoch.expect("an owned lease reports its epoch") >= 1);
        host.release().expect("clean release");
    }

    /// The other side of the gate, and the assertion the protocol variant
    /// exists for: a host holding a client reports `polling_live` with the epoch
    /// of the lease that fences it, and never a no-client state.
    #[test]
    fn a_host_with_an_allowlist_reports_polling_live_with_its_epoch() {
        let fixture = HostFixture::new(Some(&config(&["7654321"])));
        let mut host = TelegramHost::open(&fixture.params(), crate::slack::SlackHost::Disabled)
            .expect("host opens");
        let TelegramHost::Live { control, .. } = &host else {
            panic!("an allowlisted configuration must compose a live host")
        };
        // Composed and parked: no request has been issued by this test.
        assert!(control.worker.is_none());
        assert!(control.prepared.is_some());

        let (state, epoch) = host.status();
        assert_eq!(state, TelegramState::PollingLive);
        assert!(epoch.expect("a live poller reports its epoch") >= 1);
        // The pairing the protocol enforces is the one this host produces.
        assert!(
            automonique_protocol::admin::DaemonStatus::new(
                automonique_protocol::admin::AdminInstanceId::new("daemon-telegram-fixture")
                    .expect("instance"),
                automonique_protocol::admin::DaemonState::Ready,
                fixture.lease_epoch,
                0,
                0,
                0,
                0,
                true,
            )
            .and_then(|status| status.with_telegram(state, epoch))
            .is_ok(),
            "the admin status must admit the pair this host reports"
        );

        host.release().expect("clean release");
        // Released, the host owns nothing to poll with, and says that instead of
        // reporting a lease it no longer holds.
        assert_eq!(host.status(), (TelegramState::DisabledNoClient, None));
    }

    /// A poller that stopped fail-closed must not leave the status claiming the
    /// bot is answering. The thread owned the client and the credentials, so by
    /// the time it has ended the no-client state is exactly true.
    #[test]
    fn a_stopped_poller_is_reported_as_holding_no_client() {
        let fixture = HostFixture::new(Some(&config(&["7654321"])));
        let mut host = TelegramHost::open(&fixture.params(), crate::slack::SlackHost::Disabled)
            .expect("host opens");
        let TelegramHost::Live { control, .. } = &mut host else {
            panic!("an allowlisted configuration must compose a live host")
        };
        // Exactly what a returning worker does: the bridge it owned — both
        // clients and both credentials — is dropped, and its handle is finished.
        control.prepared = None;
        let ended = std::thread::spawn(|| {});
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ended.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the fixture worker never ended"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        control.worker = Some(ended);

        let (state, epoch) = host.status();
        assert_eq!(state, TelegramState::LeaseOwnedNoClient);
        assert!(epoch.expect("the lease is still owned") >= 1);
        host.release().expect("clean release");
    }

    /// A configuration with the given `allow=` lines spliced in.
    fn config(allow: &[&str]) -> String {
        tiered_config(&[], allow)
    }

    /// A configuration with both key kinds spliced in, in that order.
    fn tiered_config(admin: &[&str], allow: &[&str]) -> String {
        let mut lines = vec![
            String::from("schema=automonique.telegram-bot/v1"),
            String::from("bot_id=123456"),
            String::from("token=123456:AAExampleExampleExampleExample"),
        ];
        lines.extend(admin.iter().map(|entry| format!("admin={entry}")));
        lines.extend(allow.iter().map(|entry| format!("allow={entry}")));
        lines.push(String::from("end=automonique.telegram-bot/v1"));
        lines.push(String::new());
        lines.join("\n")
    }

    /// The live control one configuration composes, or a panic.
    fn live_control(text: &str) -> LiveControl {
        let parsed = TelegramBotConfig::parse(text)
            .expect("valid configuration")
            .expect("present configuration");
        match parsed.enablement {
            TelegramEnablement::Live(live) => *live,
            TelegramEnablement::LeaseOnly => {
                panic!("this configuration must enable live control")
            }
        }
    }

    /// The two authority models one configuration composes with no members.
    fn composed(text: &str) -> (TelegramAccessPolicy, OperatorAuthority) {
        live_control(text).roster.compose(&[]).expect("composes")
    }

    /// BACK-COMPAT, THE WHOLE POINT. A configuration written before `admin=`
    /// existed keeps every authority it had: its allowed users are its
    /// administrators, so upgrading a single-tier deployment does not silently
    /// demote everybody who was running it to read-only.
    #[test]
    fn a_configuration_with_no_admin_line_treats_every_allowed_user_as_an_admin() {
        let (_policy, authority) = composed(&config(&["7654321", "1234567"]));
        assert_eq!(authority.allowed().as_slice(), [1_234_567, 7_654_321]);
        assert_eq!(
            authority.admins().as_slice(),
            [1_234_567, 7_654_321],
            "with no admin= line, every allowed user is an administrator"
        );
        for user_id in [1_234_567, 7_654_321] {
            assert_eq!(authority.tier_of(user_id), Some(CommandTier::Admin));
            assert!(authority.may(user_id, CommandKind::Run));
            assert!(authority.may(user_id, CommandKind::Admin));
        }
    }

    /// The opt-in. One `admin=` line splits the configured users into two
    /// tiers, and the `allow=` half stops being administrators.
    #[test]
    fn one_admin_line_demotes_the_allow_list_to_members() {
        let (composed_policy, authority) = composed(&tiered_config(&["7654321"], &["1234567"]));
        assert_eq!(authority.allowed().as_slice(), [1_234_567, 7_654_321]);
        assert_eq!(authority.admins().as_slice(), [7_654_321]);
        assert!(authority.is_admin(7_654_321));
        assert!(!authority.is_admin(1_234_567));
        assert!(
            authority.authorize(1_234_567),
            "an allow= user is still allowed; they are simply not an administrator"
        );
        // An administrator is implicitly allowed at the transport too: both
        // lines contribute their principal.
        assert_eq!(
            composed_policy,
            policy(&[(1_234_567, 1_234_567), (7_654_321, 7_654_321)])
        );

        assert!(authority.may(7_654_321, CommandKind::Run));
        assert!(!authority.may(1_234_567, CommandKind::Run));
        assert!(authority.may(1_234_567, CommandKind::Status));
    }

    /// An administrator alone is a complete configuration: they are implicitly
    /// allowed, so the gate opens without a single `allow=` line.
    #[test]
    fn an_admin_line_alone_enables_live_control() {
        let (composed_policy, authority) = composed(&tiered_config(&["7654321"], &[]));
        assert_eq!(authority.allowed().as_slice(), [7_654_321]);
        assert_eq!(authority.admins().as_slice(), [7_654_321]);
        assert_eq!(composed_policy, policy(&[(7_654_321, 7_654_321)]));
    }

    /// The group form works for an administrator too, and still names exactly
    /// one user in exactly one chat.
    #[test]
    fn an_administrator_may_be_named_in_one_group() {
        let (composed_policy, authority) =
            composed(&tiered_config(&["-1001234567890:7654321"], &[]));
        assert_eq!(authority.admins().as_slice(), [7_654_321]);
        assert_eq!(composed_policy, policy(&[(-1_001_234_567_890, 7_654_321)]));
        assert_ne!(composed_policy, policy(&[(7_654_321, 7_654_321)]));
    }

    /// The admin list has the same grammar as the allowlist and its own
    /// refusal, so an operator who mistyped one is told which.
    #[test]
    fn malformed_admin_entries_refuse_the_configuration() {
        for entry in ["", "0", "-7", "7:0", "seven", "1:2:3", "7:"] {
            assert!(
                matches!(
                    TelegramBotConfig::parse(&tiered_config(&[entry], &[])),
                    Err(TelegramConfigError::AdminlistInvalid)
                ),
                "admin={entry} must be refused as an admin list problem"
            );
        }
    }

    #[test]
    fn an_oversized_admin_list_is_refused_while_it_is_read() {
        let entries: Vec<String> = (1..=MAX_ADMIN_ENTRIES + 1)
            .map(|id| id.to_string())
            .collect();
        let borrowed: Vec<&str> = entries.iter().map(String::as_str).collect();
        assert!(matches!(
            TelegramBotConfig::parse(&tiered_config(&borrowed, &[])),
            Err(TelegramConfigError::AdminlistInvalid)
        ));
    }

    /// Adding a key did not open the door to others. An unknown key still
    /// refuses startup, because a configuration this build cannot fully read
    /// may be granting authority it would silently drop.
    #[test]
    fn an_unknown_key_still_refuses_the_configuration() {
        for line in ["owner=7654321", "admins=7654321", "allowed=7", "admin"] {
            let text = format!(
                "schema=automonique.telegram-bot/v1\n\
                 bot_id=123456\n\
                 token=123456:AAExampleExampleExampleExample\n\
                 admin=7654321\n\
                 {line}\n\
                 end=automonique.telegram-bot/v1\n"
            );
            assert!(
                matches!(
                    TelegramBotConfig::parse(&text),
                    Err(TelegramConfigError::Malformed)
                ),
                "{line} must refuse startup"
            );
        }
    }

    /// A duplicate is idempotent across both keys, and a user named on both
    /// lines is an administrator — the wider authority wins, because the owner
    /// wrote it down.
    #[test]
    fn a_user_named_on_both_lines_is_an_administrator() {
        let (composed_policy, authority) =
            composed(&tiered_config(&["7654321"], &["7654321", "7654321"]));
        assert_eq!(authority.allowed().as_slice(), [7_654_321]);
        assert_eq!(authority.admins().as_slice(), [7_654_321]);
        assert_eq!(composed_policy, policy(&[(7_654_321, 7_654_321)]));
    }

    /// THE GATE. A configured bot with nobody authorized keeps exactly the
    /// behaviour this module shipped with: the token is validated and dropped,
    /// and no value that could reach Telegram survives the parse.
    #[test]
    fn a_configuration_without_an_allowlist_retains_no_credential() {
        let parsed = TelegramBotConfig::parse(&config(&[]))
            .expect("valid configuration")
            .expect("present configuration");
        assert_eq!(parsed.bot_id(), 123_456);
        assert!(matches!(&parsed.enablement, TelegramEnablement::LeaseOnly));
    }

    /// The other side of the same gate: one authorized user is enough to
    /// retain the credential and compose both authority models.
    #[test]
    fn one_allowed_user_enables_live_control_for_that_user_only() {
        let (composed_policy, authority) = composed(&config(&["7654321"]));
        assert_eq!(authority.allowed().as_slice(), [7_654_321]);
        // A bare id is that user's private chat, and it authorizes exactly that
        // pair — the policy compares by its whole membership, so an equal policy
        // is the same membership.
        assert_eq!(composed_policy, policy(&[(7_654_321, 7_654_321)]));
        assert_ne!(composed_policy, policy(&[(-1_001, 7_654_321)]));
    }

    /// The policy an `allow=` list should have produced.
    fn policy(principals: &[(i64, i64)]) -> TelegramAccessPolicy {
        TelegramAccessPolicy::new(
            TelegramBotId::new(123_456).expect("bot id"),
            principals
                .iter()
                .map(|(chat, actor)| TelegramPrincipal::new(*chat, *actor).expect("principal")),
        )
        .expect("policy")
    }

    /// The group form authorizes exactly one user in exactly one chat, and the
    /// control gate still keys on the user.
    #[test]
    fn the_group_form_authorizes_one_pair() {
        let (composed_policy, authority) =
            composed(&config(&["-1001234567890:7654321", "7654321"]));
        assert_eq!(authority.allowed().as_slice(), [7_654_321]);
        assert_eq!(
            composed_policy,
            policy(&[(-1_001_234_567_890, 7_654_321), (7_654_321, 7_654_321)])
        );
    }

    #[test]
    fn malformed_allow_entries_refuse_the_configuration() {
        for entry in ["", "0", "-7", "7:0", "seven", "1:2:3", "7:"] {
            assert!(
                matches!(
                    TelegramBotConfig::parse(&config(&[entry])),
                    Err(TelegramConfigError::AllowlistInvalid)
                ),
                "allow={entry} must be refused"
            );
        }
    }

    #[test]
    fn an_oversized_allowlist_is_refused_while_it_is_read() {
        let entries: Vec<String> = (1..=MAX_ALLOW_ENTRIES + 1)
            .map(|id| id.to_string())
            .collect();
        let borrowed: Vec<&str> = entries.iter().map(String::as_str).collect();
        assert!(matches!(
            TelegramBotConfig::parse(&config(&borrowed)),
            Err(TelegramConfigError::AllowlistInvalid)
        ));
    }

    /// The credential is never rendered, in either state.
    #[test]
    fn no_rendering_of_a_configuration_contains_the_token() {
        let parsed = TelegramBotConfig::parse(&config(&["7654321"]))
            .expect("valid configuration")
            .expect("present configuration");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("AAExampleExampleExampleExample"));
        assert!(rendered.contains("<redacted>"));
    }

    /// The long poll must fit inside the worst-case remaining bot lease, which
    /// is one renewal interval rather than one whole TTL.
    #[test]
    fn the_long_poll_fits_inside_one_renewal_interval() {
        let deadline_ms = i64::from(TELEGRAM_LONG_POLL_SECONDS) * 1_000
            + automonique_transport_runtime::TELEGRAM_HTTP_LEASE_MARGIN_MS;
        let renewal_ms = i64::try_from(crate::LEASE_RENEW_INTERVAL.as_millis()).expect("interval");
        assert!(
            deadline_ms < renewal_ms,
            "a poll deadline of {deadline_ms}ms cannot fit a {renewal_ms}ms renewal interval"
        );
        assert!(renewal_ms < crate::TELEGRAM_LEASE_TTL_MS);
    }
}
