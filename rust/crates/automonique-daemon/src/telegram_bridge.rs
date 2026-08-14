// SPDX-License-Identifier: Elastic-2.0

//! The bridge between one Telegram poll and this daemon's read surfaces.
//!
//! [`TelegramControlBridge`] is the only place in this product where an inbound
//! Telegram message becomes an answer. It owns four injected seams — an HTTP
//! client for `getUpdates`, an outbound client for `sendMessage`/`setMyCommands`,
//! the durable sink that commits offsets, a [`ControlSurface`] that can read
//! what this daemon holds, and a [`RunLane`] that can carry out one `/run` — and
//! nothing else. Every one of them is a trait, so the whole dispatch table is
//! exercised in tests with no network, no daemon and no provider at all.
//!
//! # Two commands here are effects
//!
//! Every other command on this surface is a read. `/run` composes a document,
//! submits it to custody, starts a contained attempt and waits for it, and the
//! reply is what that run wrote. Two consequences follow and are worth stating
//! together: the dispatch that answers a `/run` blocks for the length of the run
//! (see [`crate::run_lane`]), and the reply carries *provider output*, which is
//! why [`bounded_reply`] is a transport bound applied to it rather than a
//! renderer.
//!
//! `/work` is the second, and it is the first command whose effect is *durable
//! here*: it reads one recorded support ticket, composes a work instruction from
//! it ([`crate::ticket_work`]), puts that through the same lane a `/run` goes
//! through, and stores what comes back as that ticket's draft answer. Three
//! things are deliberately true of it:
//!
//! - **It sends nothing to anybody.** The draft is a row in this host's own
//!   ticket store. No fleet call, no support thread, no requester. A surface
//!   that posts a draft is a later, owner-gated wave, and this build has none.
//! - **Its reply is small.** A confirmation naming the ticket, the draft's size
//!   and the lifecycle it reached — not the draft. An operator reads the draft
//!   deliberately, from a view built for it, rather than having a customer-facing
//!   answer land in a chat as a side effect of asking for one.
//! - **It blocks exactly as `/run` does**, for exactly the same reason.
//!
//! # Durable first, answer second
//!
//! One iteration is `poll_once` — which reads the offset, issues the long poll,
//! parses, and commits every disposition in one transaction — and only then a
//! dispatch over what was committed. A crash between the two loses the *reply*,
//! never the record: the offset already moved, so Telegram will not redeliver,
//! and the operator sees no answer rather than two effects. That is the safe
//! direction for a surface whose commands are effects, and it is why the commit
//! is not deferred until after the reply lands.
//!
//! A commit the sink reports as a `duplicate` is not dispatched at all. That
//! receipt means the offset had already advanced past this batch, so its
//! commands were answered by whoever committed them first.
//!
//! # Why the response body is parsed twice
//!
//! [`TelegramPoller::poll_once`] returns counts, not messages: the durable
//! update it commits keeps a scope and its content, and deliberately drops the
//! sender. Dispatch needs the sender — [`authorize_and_parse`] is keyed on the
//! Telegram user id — so this module captures the exact response bytes at the
//! HTTP seam ([`CapturingClient`]) and re-runs the same pure parser over them
//! after the commit succeeds. Two parses of identical bytes under an identical
//! policy cannot disagree, and the alternative — widening the transport
//! runtime's durable record to carry actor identity into the store — would put
//! a sender's coordinates in a table that has no need of them.
//!
//! # Nothing here crashes the daemon
//!
//! A malformed update, a refused reply, a send failure, an unreadable status,
//! and a lost lease are all counted and stepped over. The one condition that
//! stops the loop is [`RuntimeError::CommitReconciliationRequired`], because a
//! poller holding an unresolved ambiguous commit is fail-closed by construction
//! and every further poll would return the same error forever.
//!
//! # What is counted is not yet reported
//!
//! [`BridgeTotals`] accumulates content-free categories in memory. This crate
//! has no logging sink and the admin status has no field for poller health, so
//! these counters are observable to tests and to nothing else. That is a real
//! gap, named here rather than papered over with a `println!`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use automonique_protocol::admin::ExecutionState;
use automonique_store::Store;
use automonique_store::operator_members::{
    MemberDisposition, OperatorMemberError, OperatorMemberStore,
};
use automonique_store::run_index::{RunIndex, RunIndexRecord};
use automonique_store::support_tickets::{
    SupportTicketError, SupportTicketStore, TicketLifecycle, TicketRecord,
};
use automonique_transport_runtime::{
    AdminDirective, AllowedUsers, CancellationToken, ControlCommand, HttpFailure,
    MAX_ALLOWED_USERS, MAX_SEND_MESSAGE_TEXT_UNITS, OpaqueBotToken, OperatorAuthority, PollOutcome,
    PollerLease, RuntimeError, SendMessageRequest, SetMyCommandsRequest, TelegramBotCommand,
    TelegramDurableSink, TelegramHttpClient, TelegramHttpPlan, TelegramHttpResponse,
    TelegramOutbound, TelegramOutboundClient, TelegramOutboundPlan, TelegramPoller,
    authorize_and_parse_tiered, command_manifest, help_text,
};
use automonique_transports::{
    TelegramAccessPolicy, TelegramBotId, TelegramDisposition, TelegramIngress, TelegramInputKind,
    TelegramPrincipal, parse_telegram_updates,
};

/// How long the worker waits after a refused poll before trying again.
///
/// A healthy poll already blocks for the long-poll timeout, so this delay only
/// applies to failures — a lost lease, an unavailable network, an unreadable
/// store — where retrying immediately would spin.
const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Granularity at which a backing-off worker re-reads its stop flag.
const BACKOFF_SLICE: Duration = Duration::from_millis(25);

/// How many runs one `/runs` reply lists.
pub const RUNS_LISTED: usize = 10;

/// How many tickets one `/tickets` reply lists.
pub const TICKETS_LISTED: usize = 10;

/// Longest run identity echoed into a reply, in bytes.
///
/// A run id is operator content from an admin submission rather than anything a
/// Telegram sender chose, but a listing still has to fit one message, and ten
/// unbounded identities would not.
pub const MAX_LISTED_RUN_ID_BYTES: usize = 48;

/// Longest fleet issue id one *listed* ticket carries, in bytes.
///
/// The store admits an id four times this long, and a detail reply prints it
/// whole. A listing may not: ten rows of full-width fields would not fit one
/// message, and an operator reading the list is reading it to find the id they
/// will then ask about, which a marked truncation still tells them.
pub const MAX_LISTED_TICKET_ID_BYTES: usize = 40;

/// Longest ticket title one listed row carries, in bytes.
pub const MAX_LISTED_TICKET_TITLE_BYTES: usize = 72;

/// Longest tenant name one listed row carries, in bytes.
pub const MAX_LISTED_TENANT_BYTES: usize = 32;

/// The whole answer to a ticket command on a host with no ticket store.
///
/// Not a refusal. Nothing failed: this daemon was never configured to read a
/// support fleet, so there is no ticket to have. Saying "unavailable" would send
/// an operator looking for a fault that does not exist.
pub const TICKETS_NOT_ENABLED: &str =
    "Ticket tracking is not enabled on this daemon, so no tickets are recorded.";

/// The answer when a ticket store holds nothing at all.
pub const NO_TICKETS_RECORDED: &str = "No tickets recorded.";

/// The answer for a reference this host has no ticket for.
///
/// Content-free, like every refusal on this surface: it names no id, so the
/// reply cannot be used to make the bot repeat a sender's text into a chat, and
/// it reads the same for a mistyped id as for one the board never carried.
pub const TICKET_NOT_FOUND: &str = "No ticket is recorded for that reference.";

/// The answer for a `/work` on a ticket that has already been answered or has
/// been closed.
///
/// Not a fault and not a refusal of the operator: the lattice has no step left
/// to `answered`, which is exactly what stops a second run from overwriting the
/// draft somebody may already have sent.
pub const TICKET_ALREADY_WORKED: &str =
    "That ticket has already been answered or closed, so nothing was run and no draft was stored.";

/// The answer for a `/work` whose run produced nothing storable.
///
/// The run happened and its record is under `/runs`; what it wrote was empty, or
/// was nothing but whitespace once the control characters a draft may not carry
/// were taken out.
pub const TICKET_DRAFT_EMPTY: &str =
    "The run completed but wrote nothing that could be stored as a draft.";

/// The configured half of this host's operator list, and how it composes with
/// the durable half.
///
/// Three sets, from two places, and they are kept in one value because a
/// composition that updated one and forgot another is exactly the bug this type
/// exists to make impossible:
///
/// - **principals** — the exact chat/actor pairs `bot.conf` wrote down. The
///   transport's own gate, which decides whether an update becomes work at all.
/// - **configured** — the user ids of those pairs. Allowed by configuration,
///   and not removable from a chat.
/// - **admins** — the `admin=` half of them, or *all* of them on a
///   configuration that names no administrators at all. See
///   [`crate::telegram`] for why that reading is the back-compatible one.
///
/// [`Self::compose`] adds the durable member roster to the first two and leaves
/// the third alone. That asymmetry is the security property of the whole
/// feature: **nothing at runtime can widen the admin set.** A member added from
/// a chat becomes a principal and an allowed user, and can never become an
/// administrator, because this method has no path that puts them in that list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRoster {
    bot_id: TelegramBotId,
    principals: Vec<TelegramPrincipal>,
    configured: Vec<i64>,
    admins: Vec<i64>,
}

/// Why an operator roster could not be built or composed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterError {
    /// No user is configured at all, so nobody could command the bot.
    Empty,
    /// The composed operator list is over the control gate's own ceiling.
    ///
    /// Raised by [`OperatorRoster::compose`] rather than by a store: the
    /// durable roster has its own capacity, but the *union* of configuration
    /// and roster is what the gate must hold, and only this type can see both.
    TooMany,
    /// An id is not a positive Telegram user id, or a pair is not a chat.
    InvalidPrincipal,
    /// An administrator is not among the configured users.
    AdminNotConfigured,
}

impl RosterError {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Empty => "roster_empty",
            Self::TooMany => "roster_too_many",
            Self::InvalidPrincipal => "roster_invalid_principal",
            Self::AdminNotConfigured => "roster_admin_not_configured",
        }
    }
}

impl fmt::Display for RosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "operator roster refused: {}", self.category())
    }
}

impl std::error::Error for RosterError {}

impl OperatorRoster {
    /// Build the configured roster.
    ///
    /// # Errors
    ///
    /// Returns [`RosterError::Empty`] when no user is configured,
    /// [`RosterError::InvalidPrincipal`] for an id that is not a positive
    /// Telegram user id, [`RosterError::TooMany`] beyond the control gate's
    /// ceiling, and [`RosterError::AdminNotConfigured`] for an administrator
    /// who is not among the configured users — which would be an owner who had
    /// locked themselves out.
    pub fn new(
        bot_id: TelegramBotId,
        principals: impl IntoIterator<Item = TelegramPrincipal>,
        configured: impl IntoIterator<Item = i64>,
        admins: impl IntoIterator<Item = i64>,
    ) -> Result<Self, RosterError> {
        let principals: Vec<TelegramPrincipal> = principals.into_iter().collect();
        let configured = sorted_ids(configured)?;
        let admins = sorted_ids(admins)?;
        if principals.is_empty() || configured.is_empty() {
            return Err(RosterError::Empty);
        }
        if configured.len() > MAX_ALLOWED_USERS {
            return Err(RosterError::TooMany);
        }
        if admins.iter().any(|id| !configured.contains(id)) {
            return Err(RosterError::AdminNotConfigured);
        }
        Ok(Self {
            bot_id,
            principals,
            configured,
            admins,
        })
    }

    /// The users configuration alone admits.
    #[must_use]
    pub fn configured(&self) -> &[i64] {
        &self.configured
    }

    /// The administrators, which only configuration can name.
    #[must_use]
    pub fn admins(&self) -> &[i64] {
        &self.admins
    }

    /// Whether configuration names this user as an administrator.
    #[must_use]
    pub fn is_admin(&self, user_id: i64) -> bool {
        self.admins.binary_search(&user_id).is_ok()
    }

    /// Whether configuration admits this user at all.
    #[must_use]
    pub fn is_configured(&self, user_id: i64) -> bool {
        self.configured.binary_search(&user_id).is_ok()
    }

    /// Compose the transport policy and the tiered gate for one member set.
    ///
    /// A member is given their *private chat* with the bot, which is the pair
    /// Telegram gives a one-to-one conversation. They are deliberately not
    /// added to any group chat the configuration named: an administrator adding
    /// somebody as a member has said they may talk to this bot, not that they
    /// may talk to it from inside a room they were never in.
    ///
    /// # Errors
    ///
    /// Returns [`RosterError::TooMany`] when the union overruns the control
    /// gate's ceiling or the transport policy's, [`RosterError::InvalidPrincipal`]
    /// for a member id that is not a positive user id, and
    /// [`RosterError::AdminNotConfigured`] if the two composed sets could ever
    /// disagree — which they cannot, and the check stays as the proof.
    pub fn compose(
        &self,
        members: &[i64],
    ) -> Result<(TelegramAccessPolicy, OperatorAuthority), RosterError> {
        let mut allowed = self.configured.clone();
        let mut principals = self.principals.clone();
        for member in sorted_ids(members.iter().copied())? {
            if allowed.binary_search(&member).is_ok() {
                // Already admitted by configuration. The durable roster is
                // allowed to name somebody the operator later wrote into
                // `bot.conf`; the union is the answer, not a conflict.
                continue;
            }
            principals.push(
                TelegramPrincipal::new(member, member)
                    .map_err(|_| RosterError::InvalidPrincipal)?,
            );
            allowed.push(member);
        }
        allowed.sort_unstable();
        allowed.dedup();
        if allowed.len() > MAX_ALLOWED_USERS {
            return Err(RosterError::TooMany);
        }
        let policy =
            TelegramAccessPolicy::new(self.bot_id, principals).map_err(|_| RosterError::TooMany)?;
        let authority = OperatorAuthority::new(
            AllowedUsers::new(allowed).map_err(|_| RosterError::TooMany)?,
            AllowedUsers::new(self.admins.iter().copied())
                .map_err(|_| RosterError::AdminNotConfigured)?,
        )
        .map_err(|_| RosterError::AdminNotConfigured)?;
        Ok((policy, authority))
    }
}

/// Sort, de-duplicate and validate one set of user ids.
fn sorted_ids(ids: impl IntoIterator<Item = i64>) -> Result<Vec<i64>, RosterError> {
    let mut ids: Vec<i64> = ids.into_iter().collect();
    if ids.iter().any(|id| *id <= 0) {
        return Err(RosterError::InvalidPrincipal);
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// What one roster mutation did to durable state.
///
/// Every variant is a complete answer an administrator can act on, and only two
/// of them changed a row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberChange {
    /// The user is now a member.
    Added,
    /// The user already was one. Nothing changed.
    AlreadyMember,
    /// The user is no longer a member.
    Removed,
    /// The user was not one. Nothing changed.
    NotAMember,
    /// The roster is at capacity, so nothing was added and nobody was evicted.
    RosterFull,
}

impl MemberChange {
    /// Whether this change moved a durable row.
    #[must_use]
    pub const fn mutated(self) -> bool {
        matches!(self, Self::Added | Self::Removed)
    }

    const fn from_disposition(disposition: MemberDisposition) -> Self {
        match disposition {
            MemberDisposition::Added => Self::Added,
            MemberDisposition::AlreadyMember => Self::AlreadyMember,
            MemberDisposition::Removed => Self::Removed,
            MemberDisposition::NotAMember => Self::NotAMember,
        }
    }
}

/// Why a read surface could not answer.
///
/// One variant on purpose. The command being answered already says which read
/// was attempted, and a surface that distinguished "the store failed" from "the
/// generation moved" in a *reply* would be telling an operator something the
/// admin socket answers properly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceRefusal {
    /// The daemon could not truthfully answer from durable state right now.
    Unavailable,
}

impl SurfaceRefusal {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Unavailable => "surface_unavailable",
        }
    }

    /// The fixed reply an operator receives.
    #[must_use]
    pub const fn operator_reply(self) -> &'static str {
        match self {
            Self::Unavailable => "That reading is unavailable right now.",
        }
    }
}

/// The daemon reads a Telegram operator may ask for.
///
/// Every answer is rendered text and every one may refuse. An implementation
/// must read its *own* durable handles: the production one runs on the poller
/// thread and shares nothing with the serve loop.
pub trait ControlSurface {
    /// This daemon's status snapshot, rendered for an operator.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when durable state cannot be read
    /// or when the generation this daemon holds has moved beneath it.
    fn status_text(&mut self) -> Result<String, SurfaceRefusal>;

    /// The most recent runs, rendered as a compact list.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when the index cannot be read.
    fn runs_text(&mut self) -> Result<String, SurfaceRefusal>;

    /// The most recently tracked support tickets, rendered as a compact list.
    ///
    /// A host with no ticket store answers [`TICKETS_NOT_ENABLED`], which is a
    /// fact and not a refusal: nothing failed, this daemon was simply never
    /// pointed at a support fleet, and an operator told "unavailable" would go
    /// looking for a fault that does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when a store this host *does*
    /// have cannot be opened or read.
    fn tickets_text(&mut self) -> Result<String, SurfaceRefusal>;

    /// One tracked support ticket, named by its fleet issue id.
    ///
    /// A reference naming no recorded ticket is answered [`TICKET_NOT_FOUND`]
    /// rather than refused: "nothing here matches that" is the true answer, and
    /// it is the same answer whether the id was mistyped, was longer than the
    /// store's own ceiling, or names a ticket this host never saw.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when a store this host *does*
    /// have cannot be opened or read.
    fn ticket_text(&mut self, ticket_ref: &str) -> Result<String, SurfaceRefusal>;

    /// The work instruction one recorded ticket becomes, or the whole answer
    /// when there is nothing to work.
    ///
    /// This is the gate a `/work` passes *before* a run is started, and it is
    /// deliberately the only place that decides whether one should be: a ticket
    /// nobody recorded, a host that tracks none, and a ticket that can no longer
    /// reach `answered` are all answered here, so no contained run is spent
    /// producing a draft that could not be stored.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when a store this host *does*
    /// have cannot be opened or read.
    fn ticket_work_order(&mut self, ticket_ref: &str) -> Result<WorkLookup, SurfaceRefusal>;

    /// Store one draft answer against a ticket and advance its lifecycle.
    ///
    /// The one write on this surface. It stores locally and sends nothing: see
    /// this module's own note on `/work`.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when the store cannot be written.
    /// A store that refuses the draft on its own terms — the ticket moved to a
    /// lifecycle with no step left while the run was in flight — is
    /// [`DraftOutcome::Refused`] rather than an error, because nothing failed.
    fn record_ticket_draft(
        &mut self,
        ticket_ref: &str,
        draft: &str,
    ) -> Result<DraftOutcome, SurfaceRefusal>;

    /// The user ids of every member an administrator has added at runtime.
    ///
    /// A host with no member roster answers with an empty list, which is a fact
    /// and not a refusal: it has administrators and configured users and nobody
    /// else. Nothing here creates a roster — reading who is a member must not
    /// bring a database into existence.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when a roster this host *does*
    /// have cannot be opened or read.
    fn member_ids(&mut self) -> Result<Vec<i64>, SurfaceRefusal>;

    /// Add one non-admin member, durably.
    ///
    /// The caller has already refused the ids that configuration owns; this
    /// records the ones it does not. Adding somebody who is already a member is
    /// [`MemberChange::AlreadyMember`] rather than an error, and a full roster
    /// is [`MemberChange::RosterFull`] rather than an eviction.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when the roster cannot be opened
    /// or written.
    fn add_member(&mut self, user_id: i64) -> Result<MemberChange, SurfaceRefusal>;

    /// Revoke one non-admin member, durably.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when the roster cannot be opened
    /// or written.
    fn remove_member(&mut self, user_id: i64) -> Result<MemberChange, SurfaceRefusal>;
}

/// What a `/work` found when it looked the ticket up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkLookup {
    /// A ticket that can still be worked, and the instruction composed from it.
    Order(WorkOrder),
    /// There is nothing to work, and this fixed sentence is the whole answer.
    Answer(&'static str),
}

/// One ticket, ready to be run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkOrder {
    /// The ticket's durable fleet identifier, which the confirmation names.
    ///
    /// Taken from the stored row rather than echoed from the sender's message:
    /// the two are equal by construction — the lookup is exact — and reading it
    /// from the row means no reply on this path carries a byte a sender chose.
    pub fleet_issue_id: String,
    /// The bounded work instruction, composed by [`crate::ticket_work`].
    pub task: String,
}

/// What the store did with one draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DraftOutcome {
    /// Stored, and the ticket advanced.
    Recorded {
        /// Characters of the draft that was stored.
        draft_chars: usize,
        /// The lifecycle the ticket now carries.
        lifecycle: TicketLifecycle,
    },
    /// Nothing was stored, and this fixed sentence is the whole answer.
    Refused(&'static str),
}

/// A command this vocabulary can spell and this build cannot yet perform.
///
/// Each variant names the *missing surface*, not the command, because that is
/// what a reader has to go and build. Nothing here fakes an effect: a reply from
/// this enum is the whole outcome of the command that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// `/cancel`: the admin protocol has no cancel verb to route to the
    /// host-wide dispatcher this daemon already owns.
    CancelVerb,
    /// `/approve`, `/deny`: the approval ledger records decisions made over the
    /// admin socket, and nothing routes one from a chat.
    ApprovalWiring,
}

impl Unavailable {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::CancelVerb => "cancel_verb_absent",
            Self::ApprovalWiring => "approval_wiring_absent",
        }
    }

    /// The fixed reply an operator receives.
    ///
    /// Every string says the same three things: it did not happen, why the
    /// surface is missing, and where the capability does exist today.
    #[must_use]
    pub const fn operator_reply(self) -> &'static str {
        match self {
            Self::CancelVerb => {
                "Not available yet. This build has no cancel command on the admin protocol, so nothing was cancelled."
            }
            Self::ApprovalWiring => {
                "Not available yet. This build records approval decisions over the admin socket only, so nothing was decided."
            }
        }
    }

    /// The reply for one parsed command, or `None` when the command is answered
    /// for real.
    ///
    /// Exhaustive on [`ControlCommand`]: a command added to the vocabulary
    /// cannot reach this dispatch without a reader deciding which of the two it
    /// is.
    #[must_use]
    pub const fn for_command(command: &ControlCommand) -> Option<Self> {
        match command {
            ControlCommand::Help
            | ControlCommand::Status
            | ControlCommand::Runs
            | ControlCommand::Tickets
            | ControlCommand::Ticket { .. }
            | ControlCommand::Work { .. }
            | ControlCommand::Admin { .. }
            | ControlCommand::Run { .. } => None,
            ControlCommand::Cancel { .. } => Some(Self::CancelVerb),
            ControlCommand::Approve { .. } | ControlCommand::Deny { .. } => {
                Some(Self::ApprovalWiring)
            }
        }
    }
}

/// Why a `/run` produced no answer.
///
/// Every variant is an outcome an operator can read as a fact about their own
/// request. There is deliberately no variant for "the execute lane refused with
/// `lane_saturated` rather than `containment_unavailable`": that distinction is
/// a *daemon* fact, the admin socket answers it properly, and a chat reply that
/// carried it would be leaking the shape of the host to whoever can type in the
/// chat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunFailure {
    /// This deployment has no provider, or no destination policy, so no
    /// document could be composed. Nothing was submitted.
    NotConfigured,
    /// The task text is empty or larger than a prompt slot carries.
    TaskRejected,
    /// The daemon refused the submission or the start. No attempt exists and
    /// nothing was recorded.
    Refused,
    /// The run reached a terminal state that is not a completion.
    Failed,
    /// The run exceeded its own deadline and its tree was killed.
    TimedOut,
    /// The run was cancelled.
    Cancelled,
    /// The run completed and left no answer where it was told to write one.
    NoAnswer,
    /// This lane could not carry the request through, or could not observe what
    /// happened to it. It says nothing about whether a run is live.
    Unavailable,
}

impl RunFailure {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::NotConfigured => "run_not_configured",
            Self::TaskRejected => "run_task_rejected",
            Self::Refused => "run_refused",
            Self::Failed => "run_failed",
            Self::TimedOut => "run_timed_out",
            Self::Cancelled => "run_cancelled",
            Self::NoAnswer => "run_no_answer",
            Self::Unavailable => "run_unavailable",
        }
    }

    /// The reply an operator receives.
    ///
    /// Each one says what happened to *their* request and, where there is one, a
    /// thing they can do. None of them quotes a path, a run identity or any part
    /// of the message that produced it.
    #[must_use]
    pub const fn operator_reply(self) -> &'static str {
        match self {
            Self::NotConfigured => {
                "Not configured. This daemon has no provider or no egress destinations, so nothing was submitted."
            }
            Self::TaskRejected => "That task is empty or too long, so nothing was submitted.",
            Self::Refused => "Refused. Nothing was started; the admin socket says why.",
            Self::Failed => "The run failed. Its record is under /runs.",
            Self::TimedOut => "The run hit its deadline and was stopped.",
            Self::Cancelled => "The run was cancelled.",
            Self::NoAnswer => "The run completed but wrote no answer.",
            Self::Unavailable => "That could not be carried out right now.",
        }
    }
}

/// The lane that turns one task string into one contained run and its answer.
///
/// A seam for the same reason [`ControlSurface`] is one: the whole dispatch
/// table is exercised in tests with no daemon, no socket and no provider. An
/// implementation must own its own handles — the production one runs on the
/// poller thread and shares nothing with the serve loop.
pub trait RunLane {
    /// Compose, submit, start and await one run, and answer with what it wrote.
    ///
    /// This blocks for the length of the run. See [`crate::run_lane`] for what
    /// that costs and why this slice pays it.
    ///
    /// # Errors
    ///
    /// Returns the [`RunFailure`] that names the outcome. Every one of them is
    /// a complete answer: a refusal started nothing, and a failure is a run
    /// whose record exists.
    fn run(&mut self, task: &str) -> Result<String, RunFailure>;
}

/// What one poll-and-dispatch iteration did. Content-free by construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchReport {
    /// Updates the parser produced from the committed batch.
    pub updates: usize,
    /// Commands answered from a read surface or the help registry.
    pub answered: usize,
    /// Commands refused as unavailable in this build.
    pub unavailable: usize,
    /// `/run` commands that were carried out and answered with what the run
    /// wrote.
    pub runs_answered: usize,
    /// `/run` commands that reached a typed failure instead of an answer.
    pub runs_failed: usize,
    /// `/work` commands that stored a draft against a ticket.
    ///
    /// Counted apart from [`Self::runs_answered`] even though a `/work` spends a
    /// run: the two say different things, and a host that worked three tickets
    /// and answered no `/run` should not read as the reverse.
    pub tickets_worked: usize,
    /// `/work` commands that stored nothing, for any reason.
    pub ticket_work_failed: usize,
    /// `/admin` commands that moved a durable roster row.
    ///
    /// Counted apart from [`Self::answered`] because it is the only number here
    /// that says *who may command this daemon changed*, which is worth being
    /// able to read on its own.
    pub member_mutations: usize,
    /// Messages the command layer refused, including an unauthorized sender the
    /// transport policy admitted.
    pub refused: usize,
    /// Senders the transport access policy denied, each answered once.
    pub denied_senders: usize,
    /// Updates that carry no command for this build: callbacks, and updates the
    /// parser classified as unsupported.
    pub ignored: usize,
    /// Replies accepted by the outbound seam.
    pub sent: usize,
    /// Replies the outbound bounds refused before any I/O.
    pub send_refused: usize,
    /// Replies the outbound seam failed to deliver.
    pub send_failed: usize,
    /// Whether the sink reported this batch as an already-committed duplicate,
    /// in which case nothing above was dispatched.
    pub duplicate: bool,
}

impl DispatchReport {
    fn add(&mut self, other: Self) {
        self.updates += other.updates;
        self.answered += other.answered;
        self.unavailable += other.unavailable;
        self.runs_answered += other.runs_answered;
        self.runs_failed += other.runs_failed;
        self.tickets_worked += other.tickets_worked;
        self.ticket_work_failed += other.ticket_work_failed;
        self.member_mutations += other.member_mutations;
        self.refused += other.refused;
        self.denied_senders += other.denied_senders;
        self.ignored += other.ignored;
        self.sent += other.sent;
        self.send_refused += other.send_refused;
        self.send_failed += other.send_failed;
        self.duplicate |= other.duplicate;
    }
}

/// Everything one bridge has done since it was built.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeTotals {
    /// Summed dispatch work.
    pub dispatch: DispatchReport,
    /// Polls that committed.
    pub polls: usize,
    /// Polls the runtime refused, for any reason.
    pub poll_failures: usize,
    /// Committed responses this module could not re-parse. Always zero unless
    /// the transport parser is not a function of its inputs.
    pub reparse_failures: usize,
    /// Times the operator roster was recomposed from durable state.
    pub roster_refreshes: usize,
    /// Times a recomposition was refused and the previous one stayed in force.
    ///
    /// Fail-closed in the direction that matters: a refused refresh leaves the
    /// *narrower* previously-composed list in place, so an unreadable roster
    /// never widens who may command this daemon.
    pub roster_refresh_failures: usize,
    /// Whether the advertised command menu was published.
    pub menu_published: bool,
}

/// Records the exact bytes of each response on their way to the poller.
///
/// The wrapper parses nothing and decides nothing: it hands the response
/// through unchanged and keeps a copy for the dispatch that follows a
/// successful commit. Holding one poll's body is the same operator content the
/// poller is already holding, and it is replaced on the next poll.
pub struct CapturingClient<C> {
    inner: C,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl<C> CapturingClient<C> {
    /// Wrap one client and hand back the slot its bodies land in.
    #[must_use]
    pub fn new(inner: C) -> (Self, Arc<Mutex<Option<Vec<u8>>>>) {
        let captured = Arc::new(Mutex::new(None));
        (
            Self {
                inner,
                captured: Arc::clone(&captured),
            },
            captured,
        )
    }
}

impl<C> TelegramHttpClient for CapturingClient<C>
where
    C: TelegramHttpClient,
{
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        let response = self.inner.execute(plan, cancellation)?;
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(response.body.clone());
        }
        Ok(response)
    }
}

/// The seams one bridge is composed from.
pub struct BridgeParts<C, O, S, R, L> {
    /// Inbound `getUpdates` transport.
    pub client: C,
    /// Outbound `sendMessage`/`setMyCommands` transport.
    pub outbound: O,
    /// Durable offset and disposition sink.
    pub sink: S,
    /// The daemon reads this bridge may answer from.
    pub surface: R,
    /// The lane one `/run` is carried out through.
    pub lane: L,
    /// The configured operator roster, from which both authority models — the
    /// transport's chat/actor policy and the tiered control gate — are composed
    /// together with whatever the durable member roster holds.
    pub roster: OperatorRoster,
    /// Credential spent by the inbound transport.
    pub inbound_token: OpaqueBotToken,
    /// Credential spent by the outbound transport.
    pub outbound_token: OpaqueBotToken,
    /// Long-poll timeout, which the host bounds against its bot-lease TTL.
    pub long_poll_seconds: u16,
}

/// One bot's polling loop and its dispatch table.
pub struct TelegramControlBridge<C, O, S, R, L> {
    poller: TelegramPoller<CapturingClient<C>, S>,
    captured: Arc<Mutex<Option<Vec<u8>>>>,
    outbound: O,
    surface: R,
    lane: L,
    policy: TelegramAccessPolicy,
    roster: OperatorRoster,
    authority: OperatorAuthority,
    bot_id: i64,
    outbound_token: OpaqueBotToken,
    totals: BridgeTotals,
    menu_attempted: bool,
    terminal: Option<&'static str>,
}

impl<C, O, S, R, L> TelegramControlBridge<C, O, S, R, L>
where
    C: TelegramHttpClient,
    O: TelegramOutboundClient,
    S: TelegramDurableSink,
    R: ControlSurface,
    L: RunLane,
{
    /// Compose one bridge over its four seams.
    ///
    /// The composition here is the *configured* one: configuration alone, with
    /// no member from the durable roster. That is deliberate rather than lazy —
    /// composing at startup means reading a database, and a bridge that refused
    /// to exist because a roster file was momentarily unreadable would take a
    /// daemon's whole control surface down over a list of members it can widen
    /// on its next breath. [`Self::poll_and_dispatch`] refreshes before it
    /// polls, so no update is ever answered under the narrow list.
    ///
    /// # Errors
    ///
    /// Returns whatever [`TelegramPoller::new`] refuses, which is a long-poll
    /// timeout outside the runtime's bounds, or
    /// [`RuntimeError::InvalidConfiguration`] for a roster that cannot compose
    /// its own configuration.
    pub fn new(parts: BridgeParts<C, O, S, R, L>) -> Result<Self, RuntimeError> {
        let BridgeParts {
            client,
            outbound,
            sink,
            surface,
            lane,
            roster,
            inbound_token,
            outbound_token,
            long_poll_seconds,
        } = parts;
        let (policy, authority) = roster
            .compose(&[])
            .map_err(|_| RuntimeError::InvalidConfiguration("operator_roster"))?;
        let bot_id = policy.bot_id().get();
        let (client, captured) = CapturingClient::new(client);
        let poller = TelegramPoller::new(
            client,
            sink,
            policy.clone(),
            inbound_token,
            long_poll_seconds,
        )?;
        Ok(Self {
            poller,
            captured,
            outbound,
            surface,
            lane,
            policy,
            roster,
            authority,
            bot_id,
            outbound_token,
            totals: BridgeTotals::default(),
            menu_attempted: false,
            terminal: None,
        })
    }

    /// Who may command this bot right now, at which tier.
    #[must_use]
    pub const fn authority(&self) -> &OperatorAuthority {
        &self.authority
    }

    /// Recompose both authority models from the durable member roster.
    ///
    /// Called before every poll and again immediately after a mutation, so an
    /// `/admin add` is in force for the rest of the batch it appeared in and an
    /// `/admin remove` revokes within the same breath. A daemon is never
    /// restarted to change who may use it.
    ///
    /// One thing does *not* take effect until the next poll, and it cannot: the
    /// transport policy in force for a batch is the one it was fetched under,
    /// so a message a brand-new member sent before they were added stays denied.
    /// Re-parsing an already-committed batch under a wider policy would answer a
    /// command whose durable disposition says it was refused.
    ///
    /// Every refusal leaves the previous composition in force. That is the
    /// fail-closed direction: the previous list is the narrower one for an
    /// addition and — deliberately — the wider one for a removal, so a
    /// revocation that could not be composed is followed by a store that no
    /// longer holds the member and a next poll that recomposes without them.
    /// The durable write is what revokes; this is only what publishes it early.
    ///
    /// Returns whether the composition changed hands.
    pub fn refresh_operators(&mut self) -> bool {
        let Ok(members) = self.surface.member_ids() else {
            self.totals.roster_refresh_failures += 1;
            return false;
        };
        let Ok((policy, authority)) = self.roster.compose(&members) else {
            self.totals.roster_refresh_failures += 1;
            return false;
        };
        if policy == self.policy && authority == self.authority {
            return false;
        }
        // The poller's policy and this bridge's must move together or the
        // re-parse after a commit would disagree with the parse that produced
        // it. A poller holding an ambiguous commit refuses, and then neither
        // moves.
        if self.poller.set_policy(policy.clone()).is_err() {
            self.totals.roster_refresh_failures += 1;
            return false;
        }
        self.policy = policy;
        self.authority = authority;
        self.totals.roster_refreshes += 1;
        true
    }

    /// Everything this bridge has done so far.
    #[must_use]
    pub const fn totals(&self) -> BridgeTotals {
        self.totals
    }

    /// Why this bridge stopped polling, when it did.
    #[must_use]
    pub const fn terminal(&self) -> Option<&'static str> {
        self.terminal
    }

    /// Publish the advertised command menu, at most once per bridge.
    ///
    /// Attempted once and never retried: the menu is the client-side affordance
    /// for a vocabulary that works whether or not Telegram is displaying it, and
    /// a menu publication that retried forever would be a background request
    /// loop nobody asked for. A failure is counted and the bot still answers
    /// every command in the registry.
    ///
    /// Returns whether the menu was published on this call.
    pub fn publish_menu(&mut self, cancellation: &CancellationToken) -> bool {
        if self.menu_attempted {
            return false;
        }
        self.menu_attempted = true;
        let mut commands = Vec::with_capacity(command_manifest().len());
        for entry in command_manifest() {
            match TelegramBotCommand::new(entry.name, entry.description) {
                Ok(command) => commands.push(command),
                // The registry is a compile-time table inside this workspace, so
                // this arm is unreachable in practice. It is still an arm rather
                // than an unwrap: a menu is cosmetic, and refusing to poll
                // because a description grew too long would be absurd.
                Err(_) => return false,
            }
        }
        let Ok(request) = SetMyCommandsRequest::new(commands) else {
            return false;
        };
        let mut report = DispatchReport::default();
        self.send_outbound(
            TelegramOutbound::SetMyCommands(request),
            cancellation,
            &mut report,
        );
        self.totals.dispatch.add(report);
        self.totals.menu_published = report.sent == 1;
        self.totals.menu_published
    }

    /// Poll once and answer whatever the commit admitted.
    ///
    /// # Errors
    ///
    /// Returns the runtime's refusal for the poll itself. A dispatch that goes
    /// wrong after the commit is counted in the returned report, never raised:
    /// the durable work already happened, and reporting it as a poll failure
    /// would make a caller retry a batch that is committed.
    pub fn poll_and_dispatch(
        &mut self,
        lease: &PollerLease,
        now_ms: i64,
        cancellation: &CancellationToken,
    ) -> Result<DispatchReport, RuntimeError> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = None;
        }
        // Before the request, never after: the policy an update is admitted
        // under has to be the one it was fetched under, and this is the only
        // point in the cycle where nothing is in flight.
        self.refresh_operators();
        let outcome = self.poller.poll_once(lease, now_ms, cancellation)?;
        self.totals.polls += 1;
        let report = self.dispatch_committed(&outcome, cancellation);
        self.totals.dispatch.add(report);
        Ok(report)
    }

    /// Answer everything one committed batch admitted.
    ///
    /// Every path here is infallible on purpose: the durable work is already
    /// done, so there is nothing left that a caller could usefully retry.
    fn dispatch_committed(
        &mut self,
        outcome: &PollOutcome,
        cancellation: &CancellationToken,
    ) -> DispatchReport {
        let mut report = DispatchReport {
            duplicate: outcome.duplicate,
            ..DispatchReport::default()
        };
        // A duplicate receipt says this exact batch was already committed at
        // this offset. Its commands were answered then; answering them again
        // would be this bridge's own at-least-once delivery.
        if outcome.duplicate {
            return report;
        }
        let body = self
            .captured
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .unwrap_or_default();
        if body.is_empty() {
            return report;
        }
        let Ok(parsed) = parse_telegram_updates(&body, outcome.previous_offset, &self.policy)
        else {
            // The poller parsed these exact bytes under this exact policy a
            // moment ago. Reaching here means the parser is not a function of
            // its inputs, which is worth counting and is not worth crashing a
            // control plane over.
            self.totals.reparse_failures += 1;
            return report;
        };
        report.updates = parsed.updates().len();
        for update in parsed.updates() {
            let answer = self.answer_for(update);
            self.deliver(answer, cancellation, &mut report);
        }
        report
    }

    /// Poll until the stop flag is set.
    ///
    /// The flag is read between iterations and never mid-poll: an in-flight long
    /// poll is allowed to finish so its batch commits and its offset advances.
    /// The transport's own timeout is what bounds how long that takes.
    pub fn run(
        &mut self,
        lease: &Arc<Mutex<PollerLease>>,
        stop: &AtomicBool,
        cancellation: &CancellationToken,
    ) {
        while !stop.load(Ordering::Acquire) {
            let Ok(now_ms) = crate::unix_millis() else {
                self.totals.poll_failures += 1;
                back_off(stop);
                continue;
            };
            let Ok(current) = lease.lock().map(|lease| lease.clone()) else {
                // The serve thread panicked while publishing a renewed lease.
                // Polling under a lease nobody is renewing is exactly what
                // fencing exists to stop.
                self.terminal = Some("lease_unpublishable");
                return;
            };
            match self.poll_and_dispatch(&current, now_ms, cancellation) {
                Ok(_) => {}
                Err(RuntimeError::CommitReconciliationRequired { .. }) => {
                    // The poller is fail-closed from here on: every further
                    // poll returns this same error until the exact retained
                    // batch is resolved, and resolving it across a restart
                    // needs host-side durable storage of the pending batch that
                    // this slice does not add. Stopping is the honest end.
                    self.totals.poll_failures += 1;
                    self.terminal = Some("commit_reconciliation_required");
                    return;
                }
                Err(_) => {
                    self.totals.poll_failures += 1;
                    back_off(stop);
                }
            }
        }
    }

    /// Decide what one update earns, without sending anything.
    fn answer_for(&mut self, update: &TelegramIngress) -> Answer {
        let Some(principal) = update.principal() else {
            return Answer::Ignore;
        };
        if update.kind() != TelegramInputKind::Message {
            // A callback carries no operator command in this build, and
            // acknowledging one needs `answerCallbackQuery`, which the outbound
            // vocabulary deliberately cannot spell.
            return Answer::Ignore;
        }
        match update.disposition() {
            TelegramDisposition::Denied => Answer::DeniedSender {
                chat_id: principal.chat_id(),
            },
            TelegramDisposition::IgnoredUnsupported => Answer::Ignore,
            TelegramDisposition::Admitted => {
                let Some(text) = update.content() else {
                    return Answer::Ignore;
                };
                // Bound as a statement so the gate's borrow of `self` ends
                // before a rendered answer needs `self` mutably.
                let parsed =
                    authorize_and_parse_tiered(&self.authority, principal.actor_id(), text);
                match parsed {
                    Err(refusal) => Answer::Refused {
                        chat_id: principal.chat_id(),
                        text: refusal.operator_reply().to_owned(),
                    },
                    Ok(ControlCommand::Run { task }) => {
                        let chat_id = principal.chat_id();
                        // The one command whose answer is an effect. It blocks
                        // this thread for the length of the run; see
                        // `crate::run_lane` for what that costs.
                        match self.lane.run(task.as_str()) {
                            Ok(answer) => Answer::RunAnswered {
                                chat_id,
                                text: bounded_reply(&answer),
                            },
                            Err(failure) => Answer::RunFailed {
                                chat_id,
                                text: failure.operator_reply().to_owned(),
                            },
                        }
                    }
                    Ok(ControlCommand::Work { ticket_ref }) => {
                        let chat_id = principal.chat_id();
                        // The second command whose answer is an effect, and the
                        // first whose effect is durable here. It blocks this
                        // thread for the length of the run it spends.
                        match work_ticket(&mut self.surface, &mut self.lane, ticket_ref.as_str()) {
                            Ok(text) => Answer::TicketWorked { chat_id, text },
                            Err(text) => Answer::TicketWorkFailed { chat_id, text },
                        }
                    }
                    Ok(ControlCommand::Admin { directive }) => {
                        let chat_id = principal.chat_id();
                        // The tier gate above is the whole authorization for
                        // this: only an administrator's `/admin` reaches here.
                        let (text, mutated) = self.administer(directive);
                        Answer::Administered {
                            chat_id,
                            text,
                            mutated,
                        }
                    }
                    Ok(command) => match Unavailable::for_command(&command) {
                        Some(unavailable) => Answer::Unavailable {
                            chat_id: principal.chat_id(),
                            text: unavailable.operator_reply().to_owned(),
                        },
                        None => Answer::Answered {
                            chat_id: principal.chat_id(),
                            text: self.render(&command),
                        },
                    },
                }
            }
        }
    }

    /// Render the answer to a command this build performs.
    fn render(&mut self, command: &ControlCommand) -> String {
        let refused = |refusal: SurfaceRefusal| refusal.operator_reply().to_owned();
        match command {
            ControlCommand::Help => help_text(),
            ControlCommand::Status => self.surface.status_text().unwrap_or_else(refused),
            ControlCommand::Runs => self.surface.runs_text().unwrap_or_else(refused),
            ControlCommand::Tickets => self.surface.tickets_text().unwrap_or_else(refused),
            ControlCommand::Ticket { ticket_ref } => self
                .surface
                .ticket_text(ticket_ref.as_str())
                .unwrap_or_else(refused),
            // `answer_for` carried these out before `render` was reached;
            // answering them here would be a second dispatch table over
            // commands whose answers are effects.
            ControlCommand::Run { .. }
            | ControlCommand::Work { .. }
            | ControlCommand::Admin { .. } => String::new(),
            // `Unavailable::for_command` decided these before `render` was
            // reached. Answering them here would be a second dispatch table.
            ControlCommand::Cancel { .. }
            | ControlCommand::Approve { .. }
            | ControlCommand::Deny { .. } => Unavailable::for_command(command)
                .map_or_else(String::new, |unavailable| {
                    unavailable.operator_reply().to_owned()
                }),
        }
    }

    /// Carry out one `/admin` directive, and say whether it moved a row.
    ///
    /// Only an administrator reaches here — the tier gate in
    /// [`Self::answer_for`] is the whole authorization, decided before the
    /// directive was parsed. What is left is the *shape* of the roster, and this
    /// is where the one rule that keeps the tiers apart is enforced: an id that
    /// configuration owns is never written to the durable roster, in either
    /// direction. An administrator cannot be added (they already outrank the
    /// list), cannot be removed (only the file that named them can do that), and
    /// a configured `allow=` user cannot be revoked from a chat either — the
    /// owner wrote them down, and a member store that could delete them would be
    /// a second opinion about a configuration file.
    fn administer(&mut self, directive: AdminDirective) -> (String, bool) {
        match directive {
            AdminDirective::List => self.administer_list(),
            AdminDirective::Add { user_id } => self.administer_add(user_id.get()),
            AdminDirective::Remove { user_id } => self.administer_remove(user_id.get()),
        }
    }

    fn administer_add(&mut self, target: i64) -> (String, bool) {
        if self.roster.is_admin(target) {
            return (
                format!(
                    "User {target} is an administrator, set in this host's bot \
                     configuration. Nothing changed."
                ),
                false,
            );
        }
        if self.roster.is_configured(target) {
            return (
                format!(
                    "User {target} is already allowed by this host's bot \
                     configuration. Nothing changed."
                ),
                false,
            );
        }
        let Ok(members) = self.surface.member_ids() else {
            return (surface_unavailable(), false);
        };
        // The union of configuration and roster is what the control gate must
        // hold, and only this bridge can see both — so the ceiling is checked
        // *before* a row is written rather than discovered by a recomposition
        // that fails after one is.
        if !members.contains(&target) {
            let mut prospective = members;
            prospective.push(target);
            if self.roster.compose(&prospective).is_err() {
                return (
                    format!(
                        "The operator list is full at {MAX_ALLOWED_USERS} users, so user \
                         {target} was not added and nobody was removed."
                    ),
                    false,
                );
            }
        }
        let Ok(change) = self.surface.add_member(target) else {
            return (surface_unavailable(), false);
        };
        let text = match change {
            MemberChange::Added => format!(
                "Added member {target}. They may use the read commands; runs, \
                 tickets work and user management stay with administrators."
            ),
            MemberChange::AlreadyMember => {
                format!("User {target} is already a member. Nothing changed.")
            }
            MemberChange::RosterFull => format!(
                "The member roster is full, so user {target} was not added and \
                 nobody was removed."
            ),
            // The store answers a removal vocabulary to a removal only.
            MemberChange::Removed | MemberChange::NotAMember => surface_unavailable(),
        };
        self.settle(change, text)
    }

    fn administer_remove(&mut self, target: i64) -> (String, bool) {
        if self.roster.is_admin(target) {
            return (
                format!(
                    "User {target} is an administrator. Administrators are set in this \
                     host's bot configuration and cannot be removed from a chat. \
                     Nothing changed."
                ),
                false,
            );
        }
        if self.roster.is_configured(target) {
            return (
                format!(
                    "User {target} is allowed by this host's bot configuration and \
                     cannot be removed from a chat. Nothing changed."
                ),
                false,
            );
        }
        let Ok(change) = self.surface.remove_member(target) else {
            return (surface_unavailable(), false);
        };
        let text = match change {
            MemberChange::Removed => {
                format!("Removed member {target}. They can no longer command this bot.")
            }
            MemberChange::NotAMember => {
                format!("User {target} is not a member. Nothing changed.")
            }
            MemberChange::Added | MemberChange::AlreadyMember | MemberChange::RosterFull => {
                surface_unavailable()
            }
        };
        self.settle(change, text)
    }

    /// Publish a mutation immediately, so the change is in force for the rest
    /// of this batch rather than at the next poll.
    fn settle(&mut self, change: MemberChange, text: String) -> (String, bool) {
        if change.mutated() {
            self.refresh_operators();
        }
        (text, change.mutated())
    }

    fn administer_list(&mut self) -> (String, bool) {
        let Ok(members) = self.surface.member_ids() else {
            return (surface_unavailable(), false);
        };
        // Ids and nothing else. This host knows no names, and a reply that
        // invented one would be describing a person it has never seen.
        let configured: Vec<i64> = self
            .roster
            .configured()
            .iter()
            .copied()
            .filter(|id| !self.roster.is_admin(*id))
            .collect();
        (
            bounded_text(&format!(
                "Operators (Telegram user ids)\n\
                 administrators: {}\n\
                 allowed by configuration: {}\n\
                 members added here: {}",
                id_list(self.roster.admins()),
                id_list(&configured),
                id_list(&members),
            )),
            false,
        )
    }

    /// Send one decided answer and count what happened to it.
    fn deliver(
        &mut self,
        answer: Answer,
        cancellation: &CancellationToken,
        report: &mut DispatchReport,
    ) {
        let (chat_id, text) = match answer {
            Answer::Ignore => {
                report.ignored += 1;
                return;
            }
            Answer::DeniedSender { chat_id } => {
                report.denied_senders += 1;
                (chat_id, UNAUTHORIZED_REPLY.to_owned())
            }
            Answer::Refused { chat_id, text } => {
                report.refused += 1;
                (chat_id, text)
            }
            Answer::Unavailable { chat_id, text } => {
                report.unavailable += 1;
                (chat_id, text)
            }
            Answer::Answered { chat_id, text } => {
                report.answered += 1;
                (chat_id, text)
            }
            Answer::RunAnswered { chat_id, text } => {
                report.answered += 1;
                report.runs_answered += 1;
                (chat_id, text)
            }
            Answer::RunFailed { chat_id, text } => {
                report.unavailable += 1;
                report.runs_failed += 1;
                (chat_id, text)
            }
            Answer::TicketWorked { chat_id, text } => {
                report.answered += 1;
                report.tickets_worked += 1;
                (chat_id, text)
            }
            Answer::TicketWorkFailed { chat_id, text } => {
                report.unavailable += 1;
                report.ticket_work_failed += 1;
                (chat_id, text)
            }
            Answer::Administered {
                chat_id,
                text,
                mutated,
            } => {
                report.answered += 1;
                if mutated {
                    report.member_mutations += 1;
                }
                (chat_id, text)
            }
        };
        let Ok(request) = SendMessageRequest::new(chat_id, text, None) else {
            report.send_refused += 1;
            return;
        };
        self.send_outbound(TelegramOutbound::SendMessage(request), cancellation, report);
    }

    /// Issue one outbound call, counting its outcome.
    ///
    /// The credential is borrowed for exactly the length of the plan and is
    /// never rendered: the plan's own `Debug` redacts it, and every failure this
    /// counts is a closed category carrying no borrowed input.
    fn send_outbound(
        &mut self,
        request: TelegramOutbound,
        cancellation: &CancellationToken,
        report: &mut DispatchReport,
    ) {
        let Ok(plan) = TelegramOutboundPlan::new(self.bot_id, request, &self.outbound_token) else {
            report.send_refused += 1;
            return;
        };
        match self.outbound.send(&plan, cancellation) {
            Ok(_) => report.sent += 1,
            Err(_) => report.send_failed += 1,
        }
    }
}

/// The fixed answer an unauthorized sender receives.
///
/// It is [`automonique_transport_runtime::CommandRefusal::Unauthorized`]'s own
/// reply, reached without parsing a byte of their message — the transport policy
/// denied their principal, so this bridge never held their text at all.
///
/// Answering an unauthorized sender at all is a deliberate trade: it makes the
/// bot say one fixed literal to anyone who finds it. The alternative, silence,
/// leaves an operator who mistyped their own user id with a bot that appears
/// broken, and this product would rather be refused than ignored.
const UNAUTHORIZED_REPLY: &str = "Not authorized.";

/// One decided answer, before anything is sent.
enum Answer {
    /// Nothing to say, and nobody to say it to.
    Ignore,
    /// A sender the transport access policy denied.
    DeniedSender { chat_id: i64 },
    /// A message the command layer refused.
    Refused { chat_id: i64, text: String },
    /// A command this build cannot perform.
    Unavailable { chat_id: i64, text: String },
    /// A command this build answered.
    Answered { chat_id: i64, text: String },
    /// A `/run` that produced an answer.
    RunAnswered { chat_id: i64, text: String },
    /// A `/run` that produced a typed failure.
    RunFailed { chat_id: i64, text: String },
    /// A `/work` that stored a draft against its ticket.
    TicketWorked { chat_id: i64, text: String },
    /// A `/work` that stored nothing.
    TicketWorkFailed { chat_id: i64, text: String },
    /// An `/admin` that was carried out, and whether it moved a roster row.
    Administered {
        chat_id: i64,
        text: String,
        mutated: bool,
    },
}

/// The reply for a durable surface that could not be read or written.
fn surface_unavailable() -> String {
    SurfaceRefusal::Unavailable.operator_reply().to_owned()
}

/// One list of Telegram user ids, or `none`.
///
/// `none` rather than an empty line: a roster reply an operator reads to decide
/// who to revoke has to distinguish "nobody" from "the line is missing".
fn id_list(ids: &[i64]) -> String {
    if ids.is_empty() {
        return String::from("none");
    }
    ids.iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Work one ticket: look it up, run the instruction it composes, store the
/// answer as its draft.
///
/// A free function over the two seams rather than a method on the bridge, so the
/// whole sequence can be driven against the *production* surface and the
/// *production* run lane in a test that has no Telegram transport at all —
/// which is the only way the durable half of `/work` gets a proof under real
/// containment. The bridge calls exactly this.
///
/// The order is the point. The lookup happens first and decides, on its own,
/// whether a run should be spent: a ticket that cannot reach `answered` costs no
/// run. The run happens second. The store write happens third and is checked
/// again, because the run took minutes and the ticket may have been closed
/// underneath it.
///
/// # Errors
///
/// Returns the operator-facing sentence for a `/work` that stored nothing. Every
/// one of them is a complete answer: either no run was started, or one was and
/// its outcome is named. Nothing here is retried and nothing is sent anywhere.
pub fn work_ticket<S, L>(surface: &mut S, lane: &mut L, ticket_ref: &str) -> Result<String, String>
where
    S: ControlSurface + ?Sized,
    L: RunLane + ?Sized,
{
    let unavailable = |refusal: SurfaceRefusal| refusal.operator_reply().to_owned();
    let order = match surface.ticket_work_order(ticket_ref).map_err(unavailable)? {
        WorkLookup::Order(order) => order,
        WorkLookup::Answer(answer) => return Err(answer.to_owned()),
    };
    // The same lane a `/run` goes through, under the same gates. An unconfigured
    // deployment answers `NotConfigured` here exactly as it does there.
    let answer = lane
        .run(&order.task)
        .map_err(|failure| failure.operator_reply().to_owned())?;
    let Some(draft) = crate::ticket_work::storable_draft(&answer) else {
        return Err(String::from(TICKET_DRAFT_EMPTY));
    };
    match surface
        .record_ticket_draft(ticket_ref, &draft)
        .map_err(unavailable)?
    {
        DraftOutcome::Recorded {
            draft_chars,
            lifecycle,
        } => Ok(format!(
            "Worked ticket {}; draft stored ({draft_chars} chars); lifecycle -> {}. \
             Nothing was sent to anyone.",
            order.fleet_issue_id,
            lifecycle.as_str(),
        )),
        DraftOutcome::Refused(answer) => Err(answer.to_owned()),
    }
}

/// Longest `/run` answer one reply carries, in UTF-16 units.
///
/// Deliberately below [`MAX_SEND_MESSAGE_TEXT_UNITS`] rather than equal to it,
/// so [`TRUNCATION_MARK`] and any future framing still fit inside the transport's
/// own ceiling. An answer at the limit is sent; one over it is cut and marked.
pub const MAX_RUN_ANSWER_UNITS: usize = MAX_SEND_MESSAGE_TEXT_UNITS - 64;

/// What a truncated answer ends with.
///
/// Marked rather than silent: an operator reading a provider's answer has to be
/// able to tell "this is the whole thing" from "this is the part that fit".
pub const TRUNCATION_MARK: &str = "\n[…truncated]";

/// Fit one run's answer into a single reply.
///
/// [`bounded_text`] plus one thing: an answer that came back empty becomes a
/// fixed sentence, because a run that wrote nothing is a fact about the run and
/// an empty message is not sendable anyway. Every other reply on this surface is
/// rendered from durable state and is never empty, which is why they use
/// [`bounded_text`] directly and do not carry this sentence.
fn bounded_reply(answer: &str) -> String {
    let text = bounded_text(answer);
    if text.trim().is_empty() {
        return String::from("The run completed but its answer was empty.");
    }
    text
}

/// Fit any reply into one Telegram message.
///
/// Two things happen here and no more: control characters the transport refuses
/// are replaced, and the text is cut to [`MAX_RUN_ANSWER_UNITS`] UTF-16 units at
/// a character boundary, marked with [`TRUNCATION_MARK`] when it was cut.
/// Nothing is reformatted and nothing is interpreted — the bytes are a
/// provider's answer or a fleet's own words, and this is a transport bound, not
/// a renderer.
///
/// The unit is UTF-16 because that is the unit Telegram counts in and the one
/// [`SendMessageRequest`] validates against; counting bytes or characters here
/// would let an answer of astral-plane text be refused after this function said
/// it fit.
fn bounded_text(answer: &str) -> String {
    let mut text = String::with_capacity(answer.len());
    let mut units = 0_usize;
    let mut truncated = false;
    for character in answer.chars() {
        // The transport refuses every control character but tab and newline, so
        // one that reached here is replaced rather than allowed to turn a real
        // answer into a refused send.
        let character = if character.is_control() && !matches!(character, '\n' | '\t') {
            ' '
        } else {
            character
        };
        let width = character.len_utf16();
        if units + width > MAX_RUN_ANSWER_UNITS {
            truncated = true;
            break;
        }
        text.push(character);
        units += width;
    }
    if truncated {
        text.push_str(TRUNCATION_MARK);
    }
    text
}

/// Wait out one retry interval, giving up early when the host asks to stop.
fn back_off(stop: &AtomicBool) {
    let mut waited = Duration::ZERO;
    while waited < RETRY_BACKOFF {
        if stop.load(Ordering::Acquire) {
            return;
        }
        thread::sleep(BACKOFF_SLICE);
        waited += BACKOFF_SLICE;
    }
}

/// The unchanging facts about the host a status reply names.
///
/// Each one was established before the poller existed — the generation this
/// daemon holds, the epoch it holds it under, the bot it is configured for, and
/// what the startup probe measured about sandboxed execution — so none of them
/// has to be re-derived on a worker thread that could only guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostFacts {
    /// Generation this daemon holds.
    pub generation_id: String,
    /// This daemon's instance identity, which is the generation's holder.
    pub holder_id: String,
    /// The generation lease epoch this daemon is fenced under.
    pub lease_epoch: u64,
    /// The configured bot.
    pub bot_id: i64,
    /// What the startup probe measured about sandboxed execution.
    pub execution_state: ExecutionState,
}

/// The production [`ControlSurface`], over its own store connections.
///
/// Every handle is opened by this type and belongs to the poller thread, which
/// is the same discipline the execution lane's workers follow: a worker that
/// borrowed the serve loop's handles would either need a lock around every admin
/// request or would race one. SQLite serializes the connections itself.
pub struct StoreControlSurface {
    store: Store,
    run_index: RunIndex,
    tickets: TicketReads,
    members: MemberRoster,
    facts: HostFacts,
}

/// This surface's handle on the durable member roster.
///
/// Lazy for the same reason [`TicketReads`] is, and asymmetric in one way that
/// matters: a *read* never creates the database and a *write* does. A host that
/// has never had a member has no file, and answering "who are the members" must
/// not conjure one; but the first `/admin add` on that host has to be able to
/// record one, and there is no other writer that would have created it.
enum MemberRoster {
    /// No roster path was attached, so this host manages no members.
    Detached,
    /// A path was attached and nothing is open yet.
    Unopened(PathBuf),
    /// An open connection to the roster.
    Open(Box<OperatorMemberStore>),
}

/// This surface's own read connection to the support ticket store.
///
/// Its own, for the reason the other two handles are: the intake worker writes
/// to that database from a different thread, and a reader that borrowed its
/// connection would serialize a chat reply behind a fleet poll.
///
/// Opened lazily rather than at composition, because the daemon composes this
/// bridge *before* the support intake gate opens — and therefore creates — the
/// ticket store. A surface that decided "enabled" at composition would answer
/// "not enabled" for the whole life of a process whose intake is running.
enum TicketReads {
    /// No ticket store path was attached, so this host offers no ticket reads.
    Detached,
    /// A path was attached and nothing is open yet.
    Unopened(PathBuf),
    /// An open read connection to the ticket store.
    Open(Box<SupportTicketStore>),
}

impl StoreControlSurface {
    /// Open one surface's own connections.
    ///
    /// The support ticket store is not among them: it is attached separately by
    /// [`Self::with_support_tickets`], because a host with no support fleet has
    /// no such database and must not be given an empty one.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceRefusal::Unavailable`] when either database could not be
    /// opened.
    pub fn open(
        database_path: &Path,
        run_index_path: &Path,
        facts: HostFacts,
    ) -> Result<Self, SurfaceRefusal> {
        let store = Store::open(database_path).map_err(|_| SurfaceRefusal::Unavailable)?;
        let run_index = RunIndex::open(run_index_path).map_err(|_| SurfaceRefusal::Unavailable)?;
        Ok(Self {
            store,
            run_index,
            tickets: TicketReads::Detached,
            members: MemberRoster::Detached,
            facts,
        })
    }

    /// Point this surface at the host's durable member roster.
    ///
    /// The path is remembered and nothing is opened or created. A surface with
    /// no roster attached reports no members and refuses to record one, which
    /// is the right answer for a host that was never given somewhere to put
    /// them.
    #[must_use]
    pub fn with_operator_members(mut self, operator_members_path: &Path) -> Self {
        self.members = MemberRoster::Unopened(operator_members_path.to_path_buf());
        self
    }

    /// Point this surface at the host's support ticket store.
    ///
    /// The path is remembered and nothing is opened: see [`TicketReads`] for why
    /// the connection cannot be made here. Attaching a path to a host whose
    /// intake is disabled is harmless and is what the daemon does — the file
    /// never appears, and every ticket command answers
    /// [`TICKETS_NOT_ENABLED`].
    #[must_use]
    pub fn with_support_tickets(mut self, support_tickets_path: &Path) -> Self {
        self.tickets = TicketReads::Unopened(support_tickets_path.to_path_buf());
        self
    }

    /// The facts this surface reports as unchanging.
    #[must_use]
    pub const fn facts(&self) -> &HostFacts {
        &self.facts
    }

    /// This host's ticket store, opening it on first use.
    ///
    /// `Ok(None)` is the enabled/not-enabled answer and never a fault: no path
    /// was attached, or the intake gate never created the database. Absence is
    /// re-checked on every call rather than remembered, so a surface cannot keep
    /// saying "not enabled" about a host that has since recorded its first
    /// ticket.
    ///
    /// Nothing here creates the file. [`SupportTicketStore::open`] would, which
    /// is exactly what a read surface must not do: an empty store conjured on a
    /// host with no support fleet would answer "no tickets recorded" to a
    /// question whose true answer is "this daemon does not track tickets".
    fn ticket_store(&mut self) -> Result<Option<&mut SupportTicketStore>, SurfaceRefusal> {
        let path = match &self.tickets {
            TicketReads::Detached => return Ok(None),
            TicketReads::Open(store) => store.path().to_path_buf(),
            TicketReads::Unopened(path) => path.clone(),
        };
        if !path.is_file() {
            // The store was removed, or was never created. Either way this host
            // has no tickets to report, and a connection it may still hold is
            // one to a file nobody can reach.
            self.tickets = TicketReads::Unopened(path);
            return Ok(None);
        }
        if let TicketReads::Unopened(path) = &self.tickets {
            let opened = SupportTicketStore::open(path).map_err(|_| SurfaceRefusal::Unavailable)?;
            self.tickets = TicketReads::Open(Box::new(opened));
        }
        match &mut self.tickets {
            TicketReads::Open(store) => Ok(Some(store)),
            // Unreachable: the arm above just replaced every other state.
            TicketReads::Detached | TicketReads::Unopened(_) => Err(SurfaceRefusal::Unavailable),
        }
    }

    /// This host's member roster.
    ///
    /// `create` is the whole difference between the read path and the write
    /// path: a read of a host that has never had a member answers `Ok(None)`
    /// and leaves the filesystem alone, while the first addition brings the
    /// database into existence. Neither ever invents a member.
    fn member_store(
        &mut self,
        create: bool,
    ) -> Result<Option<&mut OperatorMemberStore>, SurfaceRefusal> {
        let path = match &self.members {
            MemberRoster::Detached => return Ok(None),
            MemberRoster::Open(store) => store.path().to_path_buf(),
            MemberRoster::Unopened(path) => path.clone(),
        };
        if !path.is_file() {
            // Removed, or never created. A handle this surface may still hold
            // is one to a file nobody can reach.
            self.members = MemberRoster::Unopened(path.clone());
            if !create {
                return Ok(None);
            }
        }
        if let MemberRoster::Unopened(path) = &self.members {
            let opened =
                OperatorMemberStore::open(path).map_err(|_| SurfaceRefusal::Unavailable)?;
            self.members = MemberRoster::Open(Box::new(opened));
        }
        match &mut self.members {
            MemberRoster::Open(store) => Ok(Some(store)),
            // Unreachable: the arm above just replaced every other state.
            MemberRoster::Detached | MemberRoster::Unopened(_) => Err(SurfaceRefusal::Unavailable),
        }
    }
}

impl ControlSurface for StoreControlSurface {
    /// The durable status snapshot, rendered from what the snapshot itself says.
    ///
    /// Nothing is derived here that the serve loop derives differently. The
    /// admin status reports a `ready`/`failed` daemon state that also depends on
    /// an in-flight reconciliation the serve thread holds in memory; this reply
    /// reports the snapshot's own counts and lets an operator read the same
    /// evidence, so the two surfaces cannot contradict each other about a word
    /// only one of them can compute.
    ///
    /// A generation that has moved is a refusal rather than a snapshot: reading
    /// durable state a successor now owns and calling it this daemon's status
    /// would be the exact failure the fence exists to prevent.
    fn status_text(&mut self) -> Result<String, SurfaceRefusal> {
        let now_ms = crate::unix_millis().map_err(|_| SurfaceRefusal::Unavailable)?;
        let snapshot = self
            .store
            .status_snapshot_at(&self.facts.generation_id, now_ms)
            .map_err(|_| SurfaceRefusal::Unavailable)?;
        let generation = snapshot.generation().ok_or(SurfaceRefusal::Unavailable)?;
        if generation.holder_id() != self.facts.holder_id
            || generation.lease_epoch() != self.facts.lease_epoch
            || generation.lease_expires_ms() <= now_ms
        {
            return Err(SurfaceRefusal::Unavailable);
        }
        let paused = self
            .store
            .intake_paused(&self.facts.generation_id, now_ms)
            .map_err(|_| SurfaceRefusal::Unavailable)?
            .is_some();
        let remaining_ms = generation.lease_expires_ms().saturating_sub(now_ms);
        Ok(format!(
            "Automonique status\n\
             generation {} epoch {} held by {}\n\
             lease expires in {}s\n\
             intake paused: {}\n\
             events {} | inbox pending {} | outbox pending {} | runs running {}\n\
             reconciliation pending {} | outbox ambiguous {}\n\
             telegram bot {} | pollers live {} | expired {}\n\
             execution: {}",
            self.facts.generation_id,
            self.facts.lease_epoch,
            self.facts.holder_id,
            remaining_ms / 1_000,
            if paused { "yes" } else { "no" },
            snapshot.event_cursor(),
            snapshot.inbox_pending(),
            snapshot.outbox_pending(),
            snapshot.runs_running(),
            snapshot.runs_reconciliation_pending(),
            snapshot.outbox_in_flight_ambiguous(),
            self.facts.bot_id,
            snapshot.telegram_pollers_live(),
            snapshot.telegram_pollers_expired(),
            self.facts.execution_state.as_str(),
        ))
    }

    /// The newest [`RUNS_LISTED`] index rows, newest first.
    ///
    /// The listing is the read model's own, not an observation of any spool: the
    /// state each row carries is the last one a writer reported, exactly as the
    /// Runs API serves it.
    fn runs_text(&mut self) -> Result<String, SurfaceRefusal> {
        let Some(range) = self
            .run_index
            .retained_range()
            .map_err(|_| SurfaceRefusal::Unavailable)?
        else {
            return Ok(String::from("No runs recorded."));
        };
        // The cursor is exclusive and must not exceed what is retained, so the
        // newest page is the window ending at the last row.
        let listed = u64::try_from(RUNS_LISTED).map_err(|_| SurfaceRefusal::Unavailable)?;
        let cursor = range.last.saturating_sub(listed);
        let page = self
            .run_index
            .page(cursor, RUNS_LISTED)
            .map_err(|_| SurfaceRefusal::Unavailable)?;
        if page.entries.is_empty() {
            return Ok(String::from("No runs recorded."));
        }
        let mut text = format!("Recent runs ({} of {}):", page.entries.len(), range.last);
        for record in page.entries.iter().rev() {
            text.push('\n');
            text.push_str(&run_line(record));
        }
        Ok(text)
    }

    /// The newest [`TICKETS_LISTED`] tracked tickets, newest first.
    ///
    /// The listing is the store's own record of the fleet board, not a look at
    /// the board: every field is what the intake worker last recorded, and the
    /// lifecycle beside it is what *this host* has done about the ticket, which
    /// the fleet's own status does not say.
    fn tickets_text(&mut self) -> Result<String, SurfaceRefusal> {
        let Some(store) = self.ticket_store()? else {
            return Ok(String::from(TICKETS_NOT_ENABLED));
        };
        let Some(range) = store
            .retained_range()
            .map_err(|_| SurfaceRefusal::Unavailable)?
        else {
            return Ok(String::from(NO_TICKETS_RECORDED));
        };
        // The cursor is exclusive and must not exceed what is retained, so the
        // newest page is the window ending at the last row.
        let listed = u64::try_from(TICKETS_LISTED).map_err(|_| SurfaceRefusal::Unavailable)?;
        let cursor = range.last.saturating_sub(listed);
        let page = store
            .page(cursor, TICKETS_LISTED)
            .map_err(|_| SurfaceRefusal::Unavailable)?;
        if page.tickets.is_empty() {
            return Ok(String::from(NO_TICKETS_RECORDED));
        }
        let mut text = format!("Recent tickets ({} of {}):", page.tickets.len(), range.last);
        for record in page.tickets.iter().rev() {
            text.push('\n');
            text.push_str(&ticket_line(record));
        }
        Ok(bounded_text(&text))
    }

    /// One recorded ticket, or the fixed sentence for one nobody recorded.
    ///
    /// A malformed reference is answered exactly as an unrecorded one. The
    /// command layer's grammar is wider than the store's — it admits 128 bytes
    /// where the store admits 120 — and a surface that turned that overhang into
    /// "unavailable" would report a fault for a reference that simply names no
    /// ticket.
    fn ticket_text(&mut self, ticket_ref: &str) -> Result<String, SurfaceRefusal> {
        let Some(store) = self.ticket_store()? else {
            return Ok(String::from(TICKETS_NOT_ENABLED));
        };
        match store.ticket(ticket_ref) {
            Ok(Some(record)) => Ok(bounded_text(&ticket_detail(&record))),
            Ok(None) | Err(SupportTicketError::InvalidField(_)) => {
                Ok(String::from(TICKET_NOT_FOUND))
            }
            Err(_) => Err(SurfaceRefusal::Unavailable),
        }
    }

    /// The gate, and the composition, in one read.
    ///
    /// A malformed reference is answered exactly as an unrecorded one, for the
    /// reason [`Self::ticket_text`] gives: the command layer's grammar is wider
    /// than the store's, and an overhang is a reference that names no ticket
    /// rather than a fault.
    fn ticket_work_order(&mut self, ticket_ref: &str) -> Result<WorkLookup, SurfaceRefusal> {
        let Some(store) = self.ticket_store()? else {
            return Ok(WorkLookup::Answer(TICKETS_NOT_ENABLED));
        };
        let record = match store.ticket(ticket_ref) {
            Ok(Some(record)) => record,
            Ok(None) | Err(SupportTicketError::InvalidField(_)) => {
                return Ok(WorkLookup::Answer(TICKET_NOT_FOUND));
            }
            Err(_) => return Err(SurfaceRefusal::Unavailable),
        };
        // Asked here so no run is spent on a ticket whose draft could not be
        // stored. The store asks it again at the write, because minutes pass.
        if !record.lifecycle.may_reach(TicketLifecycle::Answered) {
            return Ok(WorkLookup::Answer(TICKET_ALREADY_WORKED));
        }
        Ok(WorkLookup::Order(WorkOrder {
            fleet_issue_id: record.fleet_issue_id.clone(),
            task: crate::ticket_work::work_instruction(&record),
        }))
    }

    /// The one durable write this surface performs.
    ///
    /// The instant is this host's clock, read here rather than passed in, for
    /// the same reason every other durable write in this daemon reads it at the
    /// point of writing: the caller has been inside a run for minutes and an
    /// instant it captured before that would be a lie about when the draft was
    /// produced.
    fn record_ticket_draft(
        &mut self,
        ticket_ref: &str,
        draft: &str,
    ) -> Result<DraftOutcome, SurfaceRefusal> {
        let now_ms = crate::unix_millis().map_err(|_| SurfaceRefusal::Unavailable)?;
        let Some(store) = self.ticket_store()? else {
            return Ok(DraftOutcome::Refused(TICKETS_NOT_ENABLED));
        };
        match store.record_draft(ticket_ref, draft, now_ms) {
            Ok(receipt) => Ok(DraftOutcome::Recorded {
                draft_chars: draft.chars().count(),
                lifecycle: receipt.lifecycle,
            }),
            // The ticket moved while the run was in flight: somebody closed it,
            // or a second `/work` got there first. Nothing failed, and nothing
            // was stored.
            Err(SupportTicketError::IllegalTransition { .. }) => {
                Ok(DraftOutcome::Refused(TICKET_ALREADY_WORKED))
            }
            Err(SupportTicketError::NotFound(_)) => Ok(DraftOutcome::Refused(TICKET_NOT_FOUND)),
            Err(_) => Err(SurfaceRefusal::Unavailable),
        }
    }

    fn member_ids(&mut self) -> Result<Vec<i64>, SurfaceRefusal> {
        let Some(store) = self.member_store(false)? else {
            return Ok(Vec::new());
        };
        store.member_ids().map_err(|_| SurfaceRefusal::Unavailable)
    }

    /// The one write on this surface that changes who may command the daemon.
    ///
    /// The instant is this host's clock, read at the point of writing for the
    /// reason every other durable write in this daemon reads it there.
    fn add_member(&mut self, user_id: i64) -> Result<MemberChange, SurfaceRefusal> {
        let now_ms = crate::unix_millis().map_err(|_| SurfaceRefusal::Unavailable)?;
        let Some(store) = self.member_store(true)? else {
            return Err(SurfaceRefusal::Unavailable);
        };
        match store.add_member(user_id, now_ms) {
            Ok(disposition) => Ok(MemberChange::from_disposition(disposition)),
            // A full roster is an answer, not a fault: nothing was added and,
            // as the store's own contract says, nobody was evicted.
            Err(OperatorMemberError::RosterFull { .. }) => Ok(MemberChange::RosterFull),
            Err(_) => Err(SurfaceRefusal::Unavailable),
        }
    }

    fn remove_member(&mut self, user_id: i64) -> Result<MemberChange, SurfaceRefusal> {
        // `create: false`: revoking somebody from a host that has no roster is
        // already true, and creating a database to record that would be an
        // effect nobody asked for.
        let Some(store) = self.member_store(false)? else {
            return Ok(MemberChange::NotAMember);
        };
        match store.remove_member(user_id) {
            Ok(disposition) => Ok(MemberChange::from_disposition(disposition)),
            Err(_) => Err(SurfaceRefusal::Unavailable),
        }
    }
}

/// One run's line in a `/runs` reply.
fn run_line(record: &RunIndexRecord) -> String {
    format!(
        "#{} {} {} seq {}",
        record.submission_id,
        bounded_run_id(&record.run_id),
        record.spool_state.as_str(),
        record.last_sequence
    )
}

/// A run identity bounded to what one reply can carry.
///
/// Truncation is marked, because a silently shortened identity is one an
/// operator would paste back into the admin socket and be refused for.
fn bounded_run_id(run_id: &str) -> String {
    bounded_field(run_id, MAX_LISTED_RUN_ID_BYTES)
}

/// One listed field, cut at a character boundary and marked when it was cut.
fn bounded_field(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut cut = max_bytes;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &value[..cut])
}

/// One listed field that the fleet is allowed to leave empty.
///
/// An empty tenant or requester is a real state of a real ticket — the store
/// admits it because the connector does — and printing nothing would silently
/// shift every field after it.
fn listed_field(value: &str, max_bytes: usize) -> String {
    if value.is_empty() {
        return String::from(EMPTY_FIELD);
    }
    bounded_field(value, max_bytes)
}

/// The same substitution for a detail reply, which prints its fields whole.
fn or_dash(value: &str) -> &str {
    if value.is_empty() { EMPTY_FIELD } else { value }
}

/// What an empty fleet field is printed as.
const EMPTY_FIELD: &str = "-";

/// One ticket's line in a `/tickets` reply.
///
/// The fleet issue id leads because it is the reference an operator types back
/// into `/ticket`. The two states are printed as a pair and always in the same
/// order — this host's lifecycle first, the fleet's own status second — because
/// they are different claims by different owners and a reader has to be able to
/// tell which is which.
fn ticket_line(record: &TicketRecord) -> String {
    format!(
        "#{} {} {}/{} {} — {}",
        record.ticket_id,
        bounded_field(&record.fleet_issue_id, MAX_LISTED_TICKET_ID_BYTES),
        record.lifecycle.as_str(),
        bounded_field(&record.fleet_status, MAX_LISTED_TENANT_BYTES),
        listed_field(&record.tenant_name, MAX_LISTED_TENANT_BYTES),
        bounded_field(&record.title, MAX_LISTED_TICKET_TITLE_BYTES),
    )
}

/// Whether a ticket carries a draft answer, and how big it is.
///
/// The size, never the text. A detail reply is what an operator asks for to see
/// where a ticket stands, and a customer-facing draft arriving in a chat because
/// somebody typed `/ticket` is exactly the accident `/work`'s own small reply
/// exists to avoid. The store reports the size without loading the draft at all,
/// so this line costs nothing to render.
fn draft_line(record: &TicketRecord) -> String {
    match (record.draft_answer_bytes, record.draft_answer_at_ms) {
        (Some(bytes), Some(at_ms)) => format!("draft {bytes} bytes, recorded {at_ms}ms"),
        _ => String::from("draft none"),
    }
}

/// One ticket's detail reply.
///
/// Fields the fleet owns are printed verbatim and whole — that is what a detail
/// view is for, and the store's own ceilings already keep them inside one
/// message — while [`bounded_text`] remains the backstop that keeps the reply
/// sendable no matter what the row holds.
///
/// The two observation instants are this host's, printed as the Unix
/// milliseconds they are stored as. Rendering them as dates would need a
/// calendar this crate does not carry, and inventing a format for a value an
/// operator can already correlate against the fleet's own timestamps would be a
/// second opinion about a number with one.
fn ticket_detail(record: &TicketRecord) -> String {
    format!(
        "Ticket {}\n\
         {}\n\
         tenant {} | site {}\n\
         fleet status {} | priority {} | source {}\n\
         lifecycle {} | revision {} | comments {}\n\
         requested by {}\n\
         {}\n\
         fleet created {} | fleet updated {}\n\
         first seen {}ms | last synced {}ms | row #{}",
        record.fleet_issue_id,
        record.title,
        or_dash(&record.tenant_name),
        record.site_label.as_deref().unwrap_or(EMPTY_FIELD),
        record.fleet_status,
        record.priority,
        or_dash(&record.source),
        record.lifecycle.as_str(),
        record.revision,
        record.comment_count,
        or_dash(&record.requested_by),
        draft_line(record),
        record.created_at,
        record.updated_at,
        record.first_seen_ms,
        record.last_synced_ms,
        record.ticket_id,
    )
}
