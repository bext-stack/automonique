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
//! # One command here is an effect
//!
//! Every other command on this surface is a read. `/run` composes a document,
//! submits it to custody, starts a contained attempt and waits for it, and the
//! reply is what that run wrote. Two consequences follow and are worth stating
//! together: the dispatch that answers a `/run` blocks for the length of the run
//! (see [`crate::run_lane`]), and the reply carries *provider output*, which is
//! why [`bounded_reply`] is a transport bound applied to it rather than a
//! renderer.
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

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use automonique_protocol::admin::ExecutionState;
use automonique_store::Store;
use automonique_store::run_index::{RunIndex, RunIndexRecord};
use automonique_transport_runtime::{
    AllowedUsers, CancellationToken, ControlCommand, HttpFailure, MAX_SEND_MESSAGE_TEXT_UNITS,
    OpaqueBotToken, PollOutcome, PollerLease, RuntimeError, SendMessageRequest,
    SetMyCommandsRequest, TelegramBotCommand, TelegramDurableSink, TelegramHttpClient,
    TelegramHttpPlan, TelegramHttpResponse, TelegramOutbound, TelegramOutboundClient,
    TelegramOutboundPlan, TelegramPoller, authorize_and_parse, command_manifest, help_text,
};
use automonique_transports::{
    TelegramAccessPolicy, TelegramDisposition, TelegramIngress, TelegramInputKind,
    parse_telegram_updates,
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

/// Longest run identity echoed into a reply, in bytes.
///
/// A run id is operator content from an admin submission rather than anything a
/// Telegram sender chose, but a listing still has to fit one message, and ten
/// unbounded identities would not.
pub const MAX_LISTED_RUN_ID_BYTES: usize = 48;

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
/// Both answers are rendered text and both may refuse. An implementation must
/// read its *own* durable handles: the production one runs on the poller thread
/// and shares nothing with the serve loop.
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
    /// The transport access policy: which chat/actor pairs create work.
    pub policy: TelegramAccessPolicy,
    /// The control gate: which Telegram users may command this bot.
    pub allowed: AllowedUsers,
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
    allowed: AllowedUsers,
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
    /// # Errors
    ///
    /// Returns whatever [`TelegramPoller::new`] refuses, which is a long-poll
    /// timeout outside the runtime's bounds.
    pub fn new(parts: BridgeParts<C, O, S, R, L>) -> Result<Self, RuntimeError> {
        let BridgeParts {
            client,
            outbound,
            sink,
            surface,
            lane,
            policy,
            allowed,
            inbound_token,
            outbound_token,
            long_poll_seconds,
        } = parts;
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
            allowed,
            bot_id,
            outbound_token,
            totals: BridgeTotals::default(),
            menu_attempted: false,
            terminal: None,
        })
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
                let parsed = authorize_and_parse(&self.allowed, principal.actor_id(), text);
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
            // `answer_for` carried this one out through the run lane before
            // `render` was reached; answering it here would be a second
            // dispatch table over a command whose answer is an effect.
            ControlCommand::Run { .. } => String::new(),
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
/// Three things happen here and no more: control characters the transport
/// refuses are replaced, the text is cut to [`MAX_RUN_ANSWER_UNITS`] UTF-16
/// units at a character boundary, and an empty result becomes a fixed sentence.
/// Nothing is reformatted and nothing is interpreted — the bytes are a
/// provider's answer and this is a transport bound, not a renderer.
///
/// The unit is UTF-16 because that is the unit Telegram counts in and the one
/// [`SendMessageRequest`] validates against; counting bytes or characters here
/// would let an answer of astral-plane text be refused after this function said
/// it fit.
fn bounded_reply(answer: &str) -> String {
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
    if text.trim().is_empty() {
        return String::from("The run completed but its answer was empty.");
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
/// Both handles are opened by this type and belong to the poller thread, which
/// is the same discipline the execution lane's workers follow: a worker that
/// borrowed the serve loop's handles would either need a lock around every admin
/// request or would race one. SQLite serializes the two connections itself.
pub struct StoreControlSurface {
    store: Store,
    run_index: RunIndex,
    facts: HostFacts,
}

impl StoreControlSurface {
    /// Open one surface's own connections.
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
            facts,
        })
    }

    /// The facts this surface reports as unchanging.
    #[must_use]
    pub const fn facts(&self) -> &HostFacts {
        &self.facts
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
    if run_id.len() <= MAX_LISTED_RUN_ID_BYTES {
        return run_id.to_owned();
    }
    let mut cut = MAX_LISTED_RUN_ID_BYTES;
    while cut > 0 && !run_id.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &run_id[..cut])
}
