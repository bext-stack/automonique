// SPDX-License-Identifier: Elastic-2.0

//! `/run`, end to end: one task string becomes one contained provider run, and
//! its answer comes back.
//!
//! [`SocketRunLane`] is the production [`RunLane`](crate::telegram_bridge::RunLane)
//! — the seam the Telegram bridge calls when an authorized operator types
//! `/run <task>`. It owns the whole sequence and nothing else:
//!
//! 1. [`crate::compose`] turns the task into a document, a prompt and an answer
//!    path;
//! 2. the prompt is written to this daemon's protected slot directory, because
//!    the document routes its prompt through a slot and carries no bytes;
//! 3. the document is submitted to durable custody over this daemon's own admin
//!    socket, and then started over the execute lane on the same socket;
//! 4. the run's read-model row is watched until it is terminal;
//! 5. on a completion the answer file is read out of the run's workspace, and
//!    on anything else a typed refusal is returned.
//!
//! # Why a socket, when the daemon is right there
//!
//! The execution lane lives on the serve thread and is not shared. This lane
//! runs on the Telegram poller's thread, which is the same discipline
//! [`crate::telegram_bridge::StoreControlSurface`] and [`crate::execute`]'s
//! workers already follow: a thread that borrowed the serve loop's handles would
//! either need a lock around every admin request or would race one.
//!
//! So `/run` is a *client* of this daemon, over the same local socket an
//! operator's CLI uses, under the same peer check. Two consequences worth
//! stating: a `/run` is admitted by exactly the gates a CLI submission is
//! admitted by — intake pause, generation health, custody, the execute lane's
//! own eight — and there is no second path into execution that a reviewer would
//! have to audit separately.
//!
//! The wait in step 4 deliberately does **not** use the socket. It reads the run
//! index directly, on this lane's own connection, so a run that takes minutes
//! does not spend those minutes issuing requests at a single-threaded serve
//! loop.
//!
//! # What this costs, named rather than hidden
//!
//! [`RunLane::run`](crate::telegram_bridge::RunLane::run) is **synchronous**:
//! the poller thread is inside it from the moment the operator's `/run` is
//! dispatched until the run is terminal or [`RUN_DEADLINE`] elapses. For that
//! window this bot answers nothing else — not `/status`, not `/help`. Nothing is
//! lost, because the poll offset was committed before dispatch and Telegram
//! redelivers nothing, but an operator who sends `/status` during a long run
//! waits for the run.
//!
//! That is a real cost and the honest one for this slice: the alternative is a
//! reply keyed to a run identity and delivered from a worker, which needs an
//! outbound path that outlives the dispatch that created it. Until that exists,
//! a `/run` is one command that takes as long as it takes.
//!
//! # What this lane does **not** establish
//!
//! - **It does not run a provider.** It runs the program the composed document
//!   names. Whether a real provider honours `HTTPS_PROXY`, writes its final
//!   message where it was told, and completes a model round trip under this
//!   containment is an owner-run, paid, networked proof.
//! - **It does not retry.** One task is one document is one attempt. A refusal
//!   is reported, never re-attempted under a different shape.
//! - **It holds no run.** After a terminal state the lane keeps nothing: the
//!   durable record is the run's own spool and index row, and the answer is a
//!   file in the run's workspace that outlives this call.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use automonique_protocol::admin::{AdminRequest, AdminResponse, SubmittedRunSpec};
use automonique_protocol::approval_api::{
    ApprovalDecision, ApprovalDisposition, ApprovalKey, ApprovalRefusal, ApprovalRequest,
    ApprovalResponse, DecideRequest, Decider,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::execute_api::{
    CancelRequestRef, CancelRunOutcome, ExecuteRefusal, ExecuteRequest, ExecuteResponse,
};
use automonique_protocol::tools::RunId;
use automonique_slack_connector::{ChannelId, MessageBlocks, MessageTs};
use automonique_store::provider_deployments::{
    DeploymentRegistration, ProviderDeployments, RouteClass,
};
use automonique_store::run_index::{RunIndex, RunSpoolState};

use automonique_transport_runtime::{
    BudgetedMethod, CallPriority, CancellationToken, EditMessageTextRequest, OpaqueBotToken,
    SendMessageDraftRequest, SendMessageRequest, TelegramCallBudget, TelegramOutbound,
    TelegramOutboundClient, TelegramOutboundPlan,
};

use crate::compose::{
    ComposeRefusal, Composition, CompositionInputs, ManagedSessionMode, ProviderConfig,
    ProviderRunProfile, compose, compose_managed, compose_with_profile, read_answer,
};
use crate::progress_hub::ProgressHub;
use crate::telegram_bridge::{
    ApprovalDecisionAnswer, ApprovalDecisionFailure, QuestionProfile, QuestionRuntime, RunFailure,
    RunLane, RunProgressView, TelegramApiOutcome, telegram_api_outcome, with_budget,
};

/// Optional provider configuration used only for ordinary conversation.
///
/// Absence is a deliberate fallback to the primary Codex provider. A malformed
/// present file is also refused and falls back, matching the primary config's
/// current fail-closed load behavior without taking `/status` down.
pub const CONVERSATION_PROVIDER_CONFIG_NAME: &str = "conversation-provider";
pub const PROVIDER_DEPLOYMENTS_NAME: &str = "provider-deployments.sqlite3";
const PRIMARY_DEPLOYMENT: &str = "primary";
const CONVERSATION_DEPLOYMENT: &str = "conversation";

/// How long one `/run` waits for its run to reach a terminal state.
///
/// Deliberately above the composed document's own timeout, which the backend
/// enforces by killing the tree: a run that hits its own deadline reaches
/// `timed_out` and is reported as such, and this bound exists only for the case
/// where the row never moves at all — a worker that died between the answer and
/// the advance. Reaching *this* deadline is therefore a statement about the
/// daemon, not about the run, and it is answered as [`RunFailure::Unavailable`].
pub const RUN_DEADLINE: Duration = Duration::from_secs(360);

/// How often the run's read-model row is re-read while waiting.
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Read deadline on one admin exchange.
///
/// The two requests this lane issues are both bounded work on the serve thread
/// — a durable insert and the execute lane's gates — so a socket that has gone
/// quiet for this long is a daemon that is not answering rather than one that is
/// thinking.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Prefix of every run identity this lane composes.
pub const RUN_ID_PREFIX: &str = "tgrun";

/// The one thing that stops a `/run` lane from opening.
///
/// One variant, because there is one input this lane cannot answer without: a
/// lane that could not observe a run's read-model row would report every run as
/// unavailable, which is worse than not existing. Everything else a deployment
/// might not have configured is a refusal *per request*, not a lane that
/// refuses to exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunIndexUnavailable;

impl core::fmt::Display for RunIndexUnavailable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the run read model could not be opened")
    }
}

impl std::error::Error for RunIndexUnavailable {}

/// Shortest interval between two snapshots on the `editMessageText` fallback.
///
/// The draft method replaces a *composing* indicator, which costs a chat
/// nothing; editing a real message is visible to everyone in it, so the
/// fallback is deliberately slower than the budget alone would allow. Three
/// seconds is the number the plan pins and it is a policy choice, not a
/// Telegram bound.
pub const FALLBACK_EDIT_INTERVAL_MS: i64 = 3_000;

/// What one lane may draw a run's progress into.
///
/// A seam for the reason every other seam here is one: the whole streaming
/// decision — claim a token, send a draft, notice a rejection, fall back — is
/// exercisable from a fixed clock with no network. The production
/// implementation is [`TelegramDraftSink`].
pub trait DraftSink: Send {
    /// Show `snapshot` as this chat's current progress.
    ///
    /// Never returns a failure a caller must handle: a snapshot that could not
    /// be drawn is a snapshot the next one replaces. What it does report is
    /// whether anything was sent, which is what a test asserts on.
    fn draft(&mut self, chat_id: i64, snapshot: &str, now_ms: i64) -> bool;
}

/// The Slack thread that requested one provider-backed action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackProgressTarget {
    pub channel: ChannelId,
    pub thread_ts: MessageTs,
}

/// Transport seam for one Slack progress stream.
pub trait SlackProgressSink: Send {
    fn begin(&mut self, target: &SlackProgressTarget, now_ms: i64) -> bool;
    fn progress(
        &mut self,
        target: &SlackProgressTarget,
        frames: &[automonique_protocol::progress_api::ProgressFrame],
        now_ms: i64,
    );
    /// True when the stream delivered the final receipt and no duplicate post
    /// is needed.
    fn finish(
        &mut self,
        target: &SlackProgressTarget,
        text: &str,
        blocks: Option<MessageBlocks>,
        now_ms: i64,
    ) -> bool;
}

struct SlackProgressStream {
    hub: Arc<ProgressHub>,
    sink: Box<dyn SlackProgressSink>,
    target: Option<SlackProgressTarget>,
    cursor: u64,
    active: bool,
}

/// The production draft transport: a budgeted Telegram client with a fallback.
///
/// # The latch
///
/// `sendMessageDraft` needs a Bot API this build cannot check for at startup
/// without spending a call on a chat nobody asked about. So the first rejection
/// *is* the check: an `ok:false` on the draft path latches "drafts unsupported"
/// for the life of this process and every later snapshot goes through
/// `editMessageText` instead. A rejection is never retried, because a method
/// that does not exist will not start existing between two snapshots.
///
/// # The fallback's own message
///
/// Editing text needs a message to edit, so the first fallback snapshot sends
/// one — directly, not through the durable outbox. That is the whole reason
/// drafts are never staged: a progress indicator that a restart re-delivered
/// would be a stale snapshot arriving after the answer it was describing. The
/// final answer still travels the outbox, exactly as before.
pub struct TelegramDraftSink {
    client: Box<dyn TelegramOutboundClient + Send>,
    token: OpaqueBotToken,
    bot_id: i64,
    budget: Arc<Mutex<TelegramCallBudget>>,
    /// Set by the first `ok:false` on the draft path, never cleared.
    drafts_unsupported: bool,
    /// The message the fallback is editing, and the chat it lives in.
    edited: Option<(i64, i64)>,
    /// When the fallback last sent anything, for its own throttle.
    last_edit_ms: Option<i64>,
    /// Never fired. A draft is not worth cancelling; the run's own
    /// cancellation is what ends the run.
    cancellation: CancellationToken,
}

impl TelegramDraftSink {
    /// Compose a sink over one bot's credential and its shared call budget.
    #[must_use]
    pub fn new(
        client: Box<dyn TelegramOutboundClient + Send>,
        token: OpaqueBotToken,
        bot_id: i64,
        budget: Arc<Mutex<TelegramCallBudget>>,
    ) -> Self {
        Self {
            client,
            token,
            bot_id,
            budget,
            drafts_unsupported: false,
            edited: None,
            last_edit_ms: None,
            cancellation: CancellationToken::new(),
        }
    }

    /// Whether this process has latched the draft method as unavailable.
    #[must_use]
    pub const fn drafts_unsupported(&self) -> bool {
        self.drafts_unsupported
    }

    /// Issue one already-validated request, if the budget admits it.
    ///
    /// Every streaming call is [`CallPriority::Ephemeral`], which is what keeps
    /// it behind the configured headroom and therefore incapable of delaying the
    /// final answer.
    fn send(&mut self, request: TelegramOutbound, now_ms: i64) -> Option<TelegramApiOutcome> {
        let method = BudgetedMethod::of(&request);
        let chat_id = request.chat_id();
        with_budget(&self.budget, |budget| {
            budget.claim(method, chat_id, CallPriority::Ephemeral, now_ms)
        })
        .ok()?;
        let plan = TelegramOutboundPlan::new(self.bot_id, request, &self.token).ok()?;
        match self.client.send(&plan, &self.cancellation) {
            Ok(response) => Some(telegram_api_outcome(&response)),
            // A transport failure says nothing about whether the method exists,
            // so it neither latches the fallback nor is retried: the next
            // snapshot is the retry, and it carries newer words.
            Err(_) => None,
        }
    }
}

impl DraftSink for TelegramDraftSink {
    fn draft(&mut self, chat_id: i64, snapshot: &str, now_ms: i64) -> bool {
        if !self.drafts_unsupported {
            let Ok(request) = SendMessageDraftRequest::new(chat_id, snapshot) else {
                return false;
            };
            match self.send(TelegramOutbound::SendMessageDraft(request), now_ms) {
                Some(TelegramApiOutcome::Accepted { .. }) => return true,
                // THE LATCH. Telegram said this method is not one it will serve
                // here, and it will say so again for every snapshot of every
                // run. Falling through to the fallback below means this run
                // still streams rather than waiting for a restart.
                Some(TelegramApiOutcome::Rejected { .. }) => self.drafts_unsupported = true,
                Some(TelegramApiOutcome::Unreadable) | None => return false,
            }
        }
        if self
            .last_edit_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < FALLBACK_EDIT_INTERVAL_MS)
        {
            return false;
        }
        // A message in the wrong chat is not this run's progress message: a lane
        // reused for a second conversation starts a fresh one.
        let existing = self
            .edited
            .filter(|(existing_chat, _)| *existing_chat == chat_id);
        let sent = match existing {
            Some((_, message_id)) => {
                let Ok(request) = EditMessageTextRequest::new(chat_id, message_id, snapshot) else {
                    return false;
                };
                matches!(
                    self.send(TelegramOutbound::EditMessageText(request), now_ms),
                    Some(TelegramApiOutcome::Accepted { .. })
                )
            }
            None => {
                let Ok(request) = SendMessageRequest::new(chat_id, snapshot, None) else {
                    return false;
                };
                match self.send(TelegramOutbound::SendMessage(request), now_ms) {
                    Some(TelegramApiOutcome::Accepted {
                        message_id: Some(message_id),
                    }) => {
                        self.edited = Some((chat_id, message_id));
                        true
                    }
                    // Telegram accepted a message and did not name it, which
                    // leaves nothing to edit. The next snapshot opens a fresh
                    // one rather than editing a message this build cannot name.
                    _ => false,
                }
            }
        };
        if sent {
            self.last_edit_ms = Some(now_ms);
        }
        sent
    }
}

/// One lane's live streaming apparatus, when a deployment has one.
struct DraftStream {
    hub: Arc<ProgressHub>,
    sink: Box<dyn DraftSink>,
    /// The chat the run in flight is being watched from, set per run.
    target: Option<i64>,
}

/// What a lane holds between being composed and learning the call budget.
///
/// The Telegram host composes a lane before the bridge that owns the budget
/// exists, and the bridge exists before the execution lane that owns the hub.
/// So the credential is handed over first and the sink is assembled last, in
/// [`RunLane::attach_streaming`], when both halves are finally available.
pub struct DraftTransport {
    /// This lane's own outbound client. Its own, not the bridge's: a draft sent
    /// from a run's thread must never queue behind a reply.
    pub client: Box<dyn TelegramOutboundClient + Send>,
    /// The same bot credential, independently constructed as every other copy
    /// in this daemon is — the opaque type is deliberately not cloneable.
    pub token: OpaqueBotToken,
    /// The bot the credential names.
    pub bot_id: i64,
}

/// The production `/run` lane.
///
/// Everything it needs is resolved once, at [`SocketRunLane::open`], and never
/// re-read: the provider configuration and whether any brokered destination is
/// configured. That matches [`crate::execute::ExecutionLane::open`]'s own
/// discipline — what a run is admitted against is the policy this daemon
/// started with, not whatever a file said at the instant a message arrived — and
/// it means an owner who edits either file gets the new answer by restarting the
/// daemon, which is the same instant every other policy here takes effect.
pub struct SocketRunLane {
    state_dir: PathBuf,
    admin_socket: PathBuf,
    /// This lane's own read-model connection. Opened here, used only here.
    run_index: RunIndex,
    /// The configured provider, or `None` for a deployment that has not been
    /// configured for `/run` at all.
    provider: Option<ProviderConfig>,
    /// Smaller no-tools provider preferred only for ordinary conversation.
    conversation_provider: Option<ProviderConfig>,
    /// A present but malformed conversation configuration fails closed instead
    /// of silently spending the primary provider.
    conversation_provider_refused: bool,
    /// Durable per-deployment failures, cooldowns and ordered fallback ranks.
    provider_deployments: Option<ProviderDeployments>,
    provider_deployments_refused: bool,
    /// Whether this deployment resolves any brokered destination. A composed
    /// document declares `brokered_named`, so without one it cannot be admitted.
    egress_configured: bool,
    /// What this host offers a document's enforcement negotiation, measured
    /// once, exactly as the execution lane measures it.
    offered: Vec<automonique_protocol::sandbox::HostFeature>,
    /// Distinguishes two runs composed inside one millisecond.
    sequence: u64,
    /// Live progress rendering, when a deployment composed one.
    ///
    /// `None` until [`RunLane::attach_streaming`] is called, and on every host
    /// with no execution lane to stream from. A lane without it behaves exactly
    /// as it did before drafts existed.
    drafts: Option<DraftStream>,
    /// The credential half of streaming, waiting for the budget half.
    pending_transport: Option<DraftTransport>,
    /// Independently rendered Slack stream for this lane's current action.
    slack_progress: Option<SlackProgressStream>,
}

impl SocketRunLane {
    /// Open one lane over this daemon's own state directory and admin socket.
    ///
    /// A deployment with no provider configuration, an unreadable one, or no
    /// destination policy opens successfully and refuses every `/run` with
    /// [`RunFailure::NotConfigured`]. That is deliberate: a bot that fails to
    /// start because `/run` is unconfigured would take `/status` and `/runs`
    /// down with it.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexUnavailable`] when the run index could not be opened.
    pub fn open(
        state_dir: &Path,
        admin_socket: &Path,
        run_index_path: &Path,
    ) -> Result<Self, RunIndexUnavailable> {
        let run_index = RunIndex::open(run_index_path).map_err(|_| RunIndexUnavailable)?;
        // Both policies fail closed: an unreadable file is the same answer as
        // an absent one, which is that `/run` is not configured here.
        let provider = ProviderConfig::load(&state_dir.join(crate::compose::PROVIDER_CONFIG_NAME))
            .unwrap_or_default();
        let conversation_provider =
            ProviderConfig::load(&state_dir.join(CONVERSATION_PROVIDER_CONFIG_NAME));
        let mut conversation_provider_refused = conversation_provider.is_err();
        let conversation_provider = conversation_provider.unwrap_or_default();
        let (mut provider_deployments, mut provider_deployments_refused) =
            if provider.is_some() || conversation_provider.is_some() {
                match ProviderDeployments::open(state_dir.join(PROVIDER_DEPLOYMENTS_NAME)) {
                    Ok(deployments) => (Some(deployments), false),
                    Err(_) => (None, true),
                }
            } else {
                (None, false)
            };
        if let Some(deployments) = provider_deployments.as_mut()
            && provider.is_some()
            && deployments
                .register(DeploymentRegistration {
                    deployment_id: PRIMARY_DEPLOYMENT,
                    provider_kind: "codex",
                    primary_rank: Some(1),
                    context_window_rank: Some(0),
                })
                .is_err()
        {
            provider_deployments = None;
            provider_deployments_refused = true;
        }
        if let Some(deployments) = provider_deployments.as_mut()
            && conversation_provider.is_some()
            && deployments
                .register(DeploymentRegistration {
                    deployment_id: CONVERSATION_DEPLOYMENT,
                    provider_kind: "conversation",
                    primary_rank: Some(0),
                    context_window_rank: Some(1),
                })
                .is_err()
        {
            provider_deployments = None;
            provider_deployments_refused = true;
            conversation_provider_refused = true;
        }
        let egress_configured =
            !crate::egress::load_destinations(&state_dir.join(crate::EGRESS_DESTINATIONS_NAME))
                .unwrap_or_default()
                .is_empty();
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            admin_socket: admin_socket.to_path_buf(),
            run_index,
            provider,
            conversation_provider,
            conversation_provider_refused,
            provider_deployments,
            provider_deployments_refused,
            egress_configured,
            offered: crate::execute::offered_host_features(),
            sequence: 0,
            drafts: None,
            pending_transport: None,
            slack_progress: None,
        })
    }

    /// Hand this lane the credential it will draw drafts with.
    ///
    /// Nothing streams from this alone: the sink is assembled in
    /// [`RunLane::attach_streaming`], when the hub and the call budget exist.
    /// A lane that is never given one streams nothing and is otherwise
    /// unchanged, which is every deployment with no Telegram credential.
    pub fn with_draft_transport(&mut self, transport: DraftTransport) {
        self.pending_transport = Some(transport);
    }

    /// Install a hub and a sink directly.
    ///
    /// The seam a test drives, and the assembly path
    /// [`RunLane::attach_streaming`] takes once both halves have arrived.
    pub fn with_drafts(&mut self, hub: Arc<ProgressHub>, sink: Box<dyn DraftSink>) {
        self.drafts = Some(DraftStream {
            hub,
            sink,
            target: None,
        });
    }

    pub fn with_slack_progress(&mut self, hub: Arc<ProgressHub>, sink: Box<dyn SlackProgressSink>) {
        self.slack_progress = Some(SlackProgressStream {
            hub,
            sink,
            target: None,
            cursor: 0,
            active: false,
        });
    }

    /// Whether this lane could compose anything at all.
    #[must_use]
    pub const fn configured(&self) -> bool {
        self.provider.is_some() && self.egress_configured
    }

    /// A fresh run identity.
    ///
    /// Wall-clock milliseconds plus a per-lane counter, so two runs composed
    /// inside one millisecond still differ and a run started after a restart
    /// cannot collide with one started before it. The identity names a cgroup, a
    /// directory and a prompt slot, so it carries only the bytes those accept.
    fn next_run_id(&mut self) -> Result<String, RunFailure> {
        let now_ms = crate::unix_millis().map_err(|_| RunFailure::Unavailable)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(format!(
            "{RUN_ID_PREFIX}-{}-{}",
            now_ms.unsigned_abs(),
            self.sequence
        ))
    }

    /// Place the composed prompt in this daemon's protected slot directory.
    ///
    /// "Protected" is exactly what the surrounding state directory protects:
    /// private mode, owned by this user, never echoed. The file is written
    /// `0o600` under a directory this creates `0o700` when it is absent, and it
    /// is removed again once the run is terminal — operator content does not
    /// outlive the run that consumed it.
    fn place_prompt(&self, composition: &Composition) -> Result<PathBuf, RunFailure> {
        let directory = self.state_dir.join(crate::execute::PROMPTS_DIRECTORY);
        match fs::create_dir(&directory) {
            Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| RunFailure::Unavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RunFailure::Unavailable),
        }
        let path = directory.join(composition.prompt_slot());
        fs::write(&path, composition.prompt()).map_err(|_| RunFailure::Unavailable)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RunFailure::Unavailable)?;
        Ok(path)
    }

    /// Submit the composed document to durable custody.
    ///
    /// The idempotency key is the run identity, which this lane just minted and
    /// which no other submission can hold — so a `replay` receipt here would
    /// mean the identity was not fresh, and is treated as this daemon's own
    /// failure rather than as an accepted run.
    fn submit(&self, composition: &Composition) -> Result<u64, RunFailure> {
        let submission =
            SubmittedRunSpec::sealed(composition.document().to_vec(), composition.run_id())
                .map_err(|_| RunFailure::Unavailable)?;
        let request = AdminRequest::submit_run(
            RequestId::new(composition.run_id()).map_err(|_| RunFailure::Unavailable)?,
            submission,
        );
        let payload = request
            .to_message()
            .map_err(|_| RunFailure::Unavailable)?
            .to_canonical_bytes();
        let response = AdminResponse::from_canonical_bytes(&self.exchange(&payload)?)
            .map_err(|_| RunFailure::Unavailable)?;
        match response {
            AdminResponse::RunAccepted {
                submission_id,
                replay: false,
                ..
            } => Ok(submission_id),
            // Every other answer is a refusal of the submission itself: intake
            // paused, a degraded generation, a document custody would not hold.
            // None of them is something this lane can act on, and all of them
            // mean nothing was started.
            _ => Err(RunFailure::Refused),
        }
    }

    /// Start the submitted run through the execute lane.
    fn start(&self, composition: &Composition) -> Result<(), RunFailure> {
        let request = ExecuteRequest::ExecuteRun {
            request_id: RequestId::new(composition.run_id())
                .map_err(|_| RunFailure::Unavailable)?,
            run_id: RunId::new(composition.run_id()).map_err(|_| RunFailure::Unavailable)?,
        };
        let payload = request
            .to_message()
            .map_err(|_| RunFailure::Unavailable)?
            .to_canonical_bytes();
        let response = ExecuteResponse::from_canonical_bytes(&self.exchange(&payload)?)
            .map_err(|_| RunFailure::Unavailable)?;
        match response {
            ExecuteResponse::Accepted { .. } => Ok(()),
            // The execute lane's refusals are typed and every one of them means
            // no attempt exists and nothing was recorded. They are collapsed to
            // one word here for the same reason `SurfaceRefusal` has one
            // variant: a chat reply that distinguished "this host cannot enforce
            // the sandbox" from "the lane is saturated" would be telling an
            // operator something the admin socket answers properly.
            ExecuteResponse::Refused { .. } => Err(RunFailure::Refused),
            // A start request cannot be answered with a cancellation result.
            // The correlation identifier already matched, so this is a peer
            // answering a different question, not a stale reply.
            ExecuteResponse::Cancelled { .. } => Err(RunFailure::Unavailable),
        }
    }

    /// Ask the execute lane to cancel one run's live attempt.
    ///
    /// Over the same socket the bridge already starts runs on, and therefore
    /// through the same `Daemon::cancel_run` the CLI reaches: one function, one
    /// fence, one ledger. The bridge holds no handle to the daemon or its
    /// attempt host — it runs on the poller thread and shares nothing with the
    /// serve loop — so this round-trip *is* the in-process call, made the only
    /// way this seam allows.
    fn cancel(&self, run_ref: &str, request_ref: &str) -> Result<CancelRunOutcome, RunFailure> {
        let request = ExecuteRequest::CancelRun {
            request_id: RequestId::new(request_ref).map_err(|_| RunFailure::Unavailable)?,
            run_id: RunId::new(run_ref).map_err(|_| RunFailure::Refused)?,
            request_ref: CancelRequestRef::new(request_ref).map_err(|_| RunFailure::Unavailable)?,
            // This surface watches no events, so the truthful claim about what
            // it had observed is none. See `ExecuteRequest::CancelRun`.
            observed_sequence: 0,
        };
        let payload = request
            .to_message()
            .map_err(|_| RunFailure::Unavailable)?
            .to_canonical_bytes();
        let response = ExecuteResponse::from_canonical_bytes(&self.exchange(&payload)?)
            .map_err(|_| RunFailure::Unavailable)?;
        match response {
            ExecuteResponse::Cancelled { outcome, .. } => Ok(outcome),
            // Unlike `start`, the refusals are *not* collapsed to one word
            // here: the two an operator can act on — the run is unknown, and
            // it has no live attempt — are different facts about their own
            // request, and telling them apart is the difference between "check
            // the reference" and "it already stopped".
            ExecuteResponse::Refused { refusal, .. } => Err(match refusal {
                ExecuteRefusal::UnknownRun => RunFailure::Refused,
                ExecuteRefusal::NoLiveAttempt => RunFailure::Failed,
                _ => RunFailure::Unavailable,
            }),
            ExecuteResponse::Accepted { .. } => Err(RunFailure::Unavailable),
        }
    }

    /// Watch one run's read-model row until it is terminal, streaming as it goes.
    ///
    /// The row is this lane's evidence and the only thing it waits on. A row
    /// that never moves is [`RunFailure::Unavailable`] rather than a failure of
    /// the run: the attempt may well have finished, and saying it failed would
    /// be inventing an outcome.
    ///
    /// # The streaming seam
    ///
    /// This loop already wakes every [`POLL_INTERVAL`], so the progress stream
    /// is drained here and nowhere else — no timer, no second thread, no async.
    /// Each pass folds whatever the hub has retained past this view's cursor
    /// into one bounded snapshot ([`RunProgressView`] does the folding and the
    /// UTF-16 truncation) and offers it to the sink, which decides whether the
    /// budget admits sending it. A snapshot that is skipped is not lost: the
    /// next one is a superset, because a draft replaces rather than appends.
    ///
    /// Nothing here can fail the run. Every streaming outcome — no target, no
    /// hub, an empty fold, a refused token, a rejected method — leaves the wait
    /// exactly as it was.
    fn await_terminal(
        &mut self,
        submission_id: u64,
        run_id: &str,
    ) -> Result<RunSpoolState, RunFailure> {
        let submission_id = i64::try_from(submission_id).map_err(|_| RunFailure::Unavailable)?;
        let deadline = Instant::now() + RUN_DEADLINE;
        let mut view = RunProgressView::new();
        loop {
            let record = self
                .run_index
                .entry(submission_id)
                .map_err(|_| RunFailure::Unavailable)?
                .ok_or(RunFailure::Unavailable)?;
            if record.spool_state.is_terminal() {
                return Ok(record.spool_state);
            }
            self.stream_progress(&mut view, run_id);
            if Instant::now() >= deadline {
                return Err(RunFailure::Unavailable);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Fold one pass of the live stream and offer the snapshot to the sink.
    fn stream_progress(&mut self, view: &mut RunProgressView, run_id: &str) {
        // A clock this process cannot read is a budget it cannot account
        // against, and drawing a draft anyway would be spending an untracked
        // call. Skipping one snapshot costs nothing.
        let Ok(now_ms) = crate::unix_millis() else {
            return;
        };
        if let Some(stream) = self.drafts.as_mut()
            && let Some(chat_id) = stream.target
            && let Some(snapshot) = view.poll(&stream.hub, run_id)
        {
            stream.sink.draft(chat_id, &snapshot, now_ms);
        }
        self.stream_slack_progress(run_id, now_ms);
    }

    fn begin_slack_progress(&mut self) {
        let Some(stream) = self.slack_progress.as_mut() else {
            return;
        };
        let Some(target) = stream.target.as_ref() else {
            return;
        };
        let Ok(now_ms) = crate::unix_millis() else {
            return;
        };
        stream.cursor = 0;
        stream.active = stream.sink.begin(target, now_ms);
    }

    fn stream_slack_progress(&mut self, run_id: &str, now_ms: i64) {
        let Some(stream) = self.slack_progress.as_mut() else {
            return;
        };
        if !stream.active {
            return;
        }
        let Some(target) = stream.target.as_ref() else {
            return;
        };
        let frames = stream.hub.frames_after(run_id, stream.cursor);
        if let Some(last) = frames.last() {
            stream.cursor = last.sequence();
            stream.sink.progress(target, &frames, now_ms);
        }
    }

    /// Ask the approval lane to record one operator decision.
    ///
    /// Over the same socket the bridge already starts and cancels runs on, and
    /// therefore through the same `Daemon::record_decision` the CLI reaches:
    /// one function, one fence, one ledger, one audit record. The bridge holds
    /// no handle to the daemon — it runs on the poller thread and shares
    /// nothing with the serve loop — so this round-trip *is* the in-process
    /// call, made the only way this seam allows.
    ///
    /// The refusals are not collapsed to one word. Each of the four an operator
    /// can act on is a different next step: check the reference, accept the
    /// answer that stands, raise a fresh proposal, or retry.
    fn decide(
        &self,
        request_key: &str,
        granted: bool,
        decider: &str,
    ) -> Result<ApprovalDecisionAnswer, ApprovalDecisionFailure> {
        let request = ApprovalRequest::DecideRequest {
            request_id: RequestId::new(format!("approval-{request_key}"))
                .map_err(|_| ApprovalDecisionFailure::Invalid)?,
            decision: DecideRequest::new(
                ApprovalKey::new(request_key).map_err(|_| ApprovalDecisionFailure::Invalid)?,
                if granted {
                    ApprovalDecision::Granted
                } else {
                    ApprovalDecision::Denied
                },
                Decider::new(decider).map_err(|_| ApprovalDecisionFailure::Invalid)?,
            ),
        };
        let payload = request
            .to_message()
            .map_err(|_| ApprovalDecisionFailure::Unavailable)?
            .to_canonical_bytes();
        let response = self
            .exchange(&payload)
            .map_err(|_| ApprovalDecisionFailure::Unavailable)?;
        match ApprovalResponse::from_canonical_bytes(&response)
            .map_err(|_| ApprovalDecisionFailure::Unavailable)?
        {
            ApprovalResponse::Recorded { receipt, .. } => Ok(match receipt.disposition() {
                ApprovalDisposition::Recorded => ApprovalDecisionAnswer::Recorded,
                ApprovalDisposition::AlreadyRecorded => ApprovalDecisionAnswer::AlreadyRecorded,
            }),
            ApprovalResponse::Refused { refusal, .. } => Err(match refusal {
                ApprovalRefusal::UnknownRequest | ApprovalRefusal::UnknownApproval => {
                    ApprovalDecisionFailure::Unknown
                }
                ApprovalRefusal::AlreadyDecided => ApprovalDecisionFailure::AlreadyDecided,
                ApprovalRefusal::RequestExpired => ApprovalDecisionFailure::Expired,
                ApprovalRefusal::InvalidField => ApprovalDecisionFailure::Invalid,
                ApprovalRefusal::CursorOutOfRange | ApprovalRefusal::LedgerFull => {
                    ApprovalDecisionFailure::Unavailable
                }
            }),
            // A conflict or a read answer to a decision is this daemon
            // answering a question nobody asked, which says nothing about the
            // decision and is therefore the same word as a dropped connection.
            ApprovalResponse::Conflict { .. }
            | ApprovalResponse::ApprovalList { .. }
            | ApprovalResponse::ApprovalDetail { .. } => Err(ApprovalDecisionFailure::Unavailable),
        }
    }

    /// Issue one bounded request on this daemon's admin socket.
    fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, RunFailure> {
        let mut stream = UnixStream::connect(&self.admin_socket).map_err(unavailable)?;
        stream
            .set_read_timeout(Some(EXCHANGE_TIMEOUT))
            .map_err(unavailable)?;
        stream
            .set_write_timeout(Some(EXCHANGE_TIMEOUT))
            .map_err(unavailable)?;
        let mut frame = Vec::new();
        encode_frame(payload, &mut frame).map_err(unavailable)?;
        stream.write_all(&frame).map_err(unavailable)?;

        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).map_err(unavailable)?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(unavailable)?;
        if length > crate::MAX_ADMIN_PAYLOAD_BYTES {
            return Err(RunFailure::Unavailable);
        }
        let mut response = vec![0_u8; length + 4];
        response[..4].copy_from_slice(&prefix);
        stream.read_exact(&mut response[4..]).map_err(unavailable)?;
        let FrameDecode::Frame { payload, .. } = decode_frame(&response).map_err(unavailable)?
        else {
            return Err(RunFailure::Unavailable);
        };
        Ok(payload.to_vec())
    }
}

/// Every failure on the way to a run is the same word.
///
/// A socket that would not connect, a frame that would not encode, a response
/// that would not decode: none of them says anything about whether a run is
/// live, which is exactly what [`RunFailure::Unavailable`] means.
fn unavailable<E>(_error: E) -> RunFailure {
    RunFailure::Unavailable
}

impl RunLane for SocketRunLane {
    fn run(&mut self, task: &str) -> Result<String, RunFailure> {
        self.run_with_profile(task, ProviderRunProfile::Standard)
    }

    fn run_agentic_scratchpad(&mut self, task: &str) -> Result<String, RunFailure> {
        self.run_with_profile(task, ProviderRunProfile::AgenticScratchpad)
    }

    fn cancel_run(
        &mut self,
        run_ref: &str,
        request_ref: &str,
    ) -> Result<CancelRunOutcome, RunFailure> {
        self.cancel(run_ref, request_ref)
    }

    fn decide_approval(
        &mut self,
        request_key: &str,
        granted: bool,
        decider: &str,
    ) -> Result<ApprovalDecisionAnswer, ApprovalDecisionFailure> {
        self.decide(request_key, granted, decider)
    }

    fn run_question(&mut self, task: &str, profile: QuestionProfile) -> Result<String, RunFailure> {
        let run_profile = match profile {
            QuestionProfile::Conversation => ProviderRunProfile::FastConversation,
            QuestionProfile::OperationalLookup => ProviderRunProfile::FastConversation,
            QuestionProfile::Operational => ProviderRunProfile::IntelligentQuestion,
            QuestionProfile::WebResearch => ProviderRunProfile::WebResearch,
        };
        self.run_with_profile(task, run_profile)
    }

    /// The last half. Both the hub and the budget arrive here, so this is where
    /// the sink is finally assembled.
    ///
    /// A lane that was never given a credential takes the hub and still streams
    /// nothing, which is exactly right for a deployment that has none — and is
    /// why this is not a refusal.
    fn attach_streaming(&mut self, hub: Arc<ProgressHub>, budget: Arc<Mutex<TelegramCallBudget>>) {
        if let Some(stream) = self.drafts.as_mut() {
            stream.hub = hub;
            return;
        }
        if let Some(transport) = self.pending_transport.take() {
            let sink =
                TelegramDraftSink::new(transport.client, transport.token, transport.bot_id, budget);
            self.with_drafts(hub, Box::new(sink));
        }
    }

    fn set_draft_target(&mut self, chat_id: Option<i64>) {
        if let Some(stream) = self.drafts.as_mut() {
            stream.target = chat_id;
        }
    }

    fn set_slack_progress_target(&mut self, target: Option<SlackProgressTarget>) {
        if let Some(stream) = self.slack_progress.as_mut() {
            stream.target = target;
            stream.cursor = 0;
            stream.active = false;
        }
    }

    fn finish_slack_progress(&mut self, text: &str, blocks: Option<MessageBlocks>) -> bool {
        let Some(stream) = self.slack_progress.as_mut() else {
            return false;
        };
        if !stream.active {
            return false;
        }
        let Some(target) = stream.target.as_ref() else {
            return false;
        };
        let Ok(now_ms) = crate::unix_millis() else {
            return false;
        };
        let delivered = stream.sink.finish(target, text, blocks, now_ms);
        stream.active = false;
        delivered
    }

    fn attach_slack_progress(&mut self, hub: Arc<ProgressHub>, sink: Box<dyn SlackProgressSink>) {
        self.with_slack_progress(hub, sink);
    }

    fn question_runtime(&self, profile: QuestionProfile) -> QuestionRuntime {
        if matches!(
            profile,
            QuestionProfile::Conversation | QuestionProfile::OperationalLookup
        ) {
            if self.conversation_provider_refused {
                return QuestionRuntime::conversation_provider_refused();
            }
            if self.conversation_provider.is_some() {
                return QuestionRuntime::deepseek_flash(profile);
            }
        }
        QuestionRuntime::codex(profile)
    }
}

impl SocketRunLane {
    /// Execute or recover one deterministic managed run.
    ///
    /// `run_id` is derived from the durable inbox idempotency key by the
    /// managed worker. Reusing it never starts a second provider attempt: a
    /// ready/running/terminal read-model row is resumed from its exact state.
    pub fn run_managed(
        &mut self,
        run_id: &str,
        task: &str,
        mode: ManagedSessionMode<'_>,
    ) -> Result<String, RunFailure> {
        let provider = self.provider.clone().ok_or(RunFailure::NotConfigured)?;
        let inputs = CompositionInputs {
            state_dir: &self.state_dir,
            run_id,
            provider: &provider,
            offered_features: &self.offered,
            egress_configured: self.egress_configured,
        };
        let composition = compose_managed(task, &inputs, mode).map_err(RunFailure::from_compose)?;
        let slot = self.place_prompt(&composition)?;
        let outcome = self.execute_managed(&composition);
        let _ = fs::remove_file(&slot);
        outcome
    }

    fn execute_managed(&mut self, composition: &Composition) -> Result<String, RunFailure> {
        let existing = self
            .run_index
            .by_run_id(composition.run_id())
            .map_err(|_| RunFailure::Unavailable)?
            .into_iter()
            .last();
        let (submission_id, state) = match existing {
            Some(record) => (
                u64::try_from(record.submission_id).map_err(|_| RunFailure::Unavailable)?,
                record.spool_state,
            ),
            None => (self.submit(composition)?, RunSpoolState::Ready),
        };
        match state {
            RunSpoolState::Ready => self.start(composition)?,
            RunSpoolState::Running => {}
            RunSpoolState::Completed => return self.managed_answer(composition),
            RunSpoolState::TimedOut => return Err(RunFailure::TimedOut),
            RunSpoolState::Cancelled => return Err(RunFailure::Cancelled),
            RunSpoolState::Failed => return Err(RunFailure::Failed),
        }
        match self.await_terminal(submission_id, composition.run_id())? {
            RunSpoolState::Completed => self.managed_answer(composition),
            RunSpoolState::TimedOut => Err(RunFailure::TimedOut),
            RunSpoolState::Cancelled => Err(RunFailure::Cancelled),
            RunSpoolState::Failed => Err(RunFailure::Failed),
            RunSpoolState::Ready | RunSpoolState::Running => Err(RunFailure::Unavailable),
        }
    }

    fn managed_answer(&self, composition: &Composition) -> Result<String, RunFailure> {
        read_answer(composition.answer_path()).ok_or(RunFailure::NoAnswer)
    }

    fn run_with_profile(
        &mut self,
        task: &str,
        profile: ProviderRunProfile,
    ) -> Result<String, RunFailure> {
        if self.provider_deployments_refused {
            return Err(RunFailure::Unavailable);
        }
        if profile == ProviderRunProfile::FastConversation && self.conversation_provider_refused {
            return Err(RunFailure::NotConfigured);
        }
        let (selected, deployment_id) = if profile == ProviderRunProfile::FastConversation {
            let routed = crate::unix_millis().ok().and_then(|now_ms| {
                self.provider_deployments
                    .as_ref()
                    .and_then(|deployments| deployments.select(RouteClass::Primary, now_ms).ok())
                    .flatten()
                    .map(|deployment| deployment.deployment_id)
            });
            match routed.as_deref() {
                Some(CONVERSATION_DEPLOYMENT) => (
                    self.conversation_provider
                        .as_ref()
                        .or(self.provider.as_ref()),
                    Some(CONVERSATION_DEPLOYMENT),
                ),
                Some(PRIMARY_DEPLOYMENT) => (self.provider.as_ref(), Some(PRIMARY_DEPLOYMENT)),
                _ => (
                    self.conversation_provider
                        .as_ref()
                        .or(self.provider.as_ref()),
                    None,
                ),
            }
        } else {
            (self.provider.as_ref(), Some(PRIMARY_DEPLOYMENT))
        };
        let Some(provider) = selected.cloned() else {
            return Err(RunFailure::NotConfigured);
        };
        let outcome = self.run_selected_provider(task, profile, &provider);
        let Some(deployment_id) = deployment_id else {
            return outcome;
        };
        let Ok(now_ms) = crate::unix_millis() else {
            return outcome;
        };
        let Some(deployments) = self.provider_deployments.as_mut() else {
            return outcome;
        };
        match &outcome {
            Ok(_) => {
                let _ = deployments.record_success(deployment_id);
                outcome
            }
            Err(_) => {
                let tripped = deployments
                    .record_failure(deployment_id, now_ms)
                    .ok()
                    .is_some_and(|record| record.cooldown_until_ms > now_ms);
                if !tripped || profile != ProviderRunProfile::FastConversation {
                    return outcome;
                }
                let fallback_id = deployments
                    .select(RouteClass::Primary, now_ms)
                    .ok()
                    .flatten()
                    .map(|record| record.deployment_id);
                let fallback = match fallback_id.as_deref() {
                    Some(PRIMARY_DEPLOYMENT) if deployment_id != PRIMARY_DEPLOYMENT => {
                        self.provider.clone()
                    }
                    Some(CONVERSATION_DEPLOYMENT) if deployment_id != CONVERSATION_DEPLOYMENT => {
                        self.conversation_provider.clone()
                    }
                    _ => None,
                };
                let Some(fallback) = fallback else {
                    return outcome;
                };
                let fallback_outcome = self.run_selected_provider(task, profile, &fallback);
                if let Some(fallback_id) = fallback_id
                    && let Some(deployments) = self.provider_deployments.as_mut()
                {
                    match &fallback_outcome {
                        Ok(_) => {
                            let _ = deployments.record_success(&fallback_id);
                        }
                        Err(_) => {
                            let _ = deployments.record_failure(&fallback_id, now_ms);
                        }
                    }
                }
                fallback_outcome
            }
        }
    }

    fn run_selected_provider(
        &mut self,
        task: &str,
        profile: ProviderRunProfile,
        provider: &ProviderConfig,
    ) -> Result<String, RunFailure> {
        let run_id = self.next_run_id()?;
        let inputs = CompositionInputs {
            state_dir: &self.state_dir,
            run_id: &run_id,
            provider,
            offered_features: &self.offered,
            egress_configured: self.egress_configured,
        };
        // Skill-only releases hot-reload by moving one verified `current`
        // symlink. Reopening it for every run means an already-running daemon
        // sees the new approved instructions on its next task, while a damaged
        // bundle fails closed instead of silently dropping behavior.
        let task = match crate::skill_runtime::load_active(&self.state_dir) {
            Ok(Some(skills)) => format!(
                "[approved_skills manifest={}]{}\n[/approved_skills]\n\n[user_task]\n{}\n[/user_task]",
                skills.manifest_digest, skills.instructions, task
            ),
            Ok(None) => task.to_owned(),
            Err(_) => return Err(RunFailure::Unavailable),
        };
        let composition = match profile {
            ProviderRunProfile::Standard => compose(&task, &inputs),
            ProviderRunProfile::FastConversation
            | ProviderRunProfile::IntelligentQuestion
            | ProviderRunProfile::WebResearch
            | ProviderRunProfile::AgenticScratchpad => {
                compose_with_profile(&task, &inputs, profile)
            }
        }
        .map_err(RunFailure::from_compose)?;

        // The slot exists before the document that names it is submitted, so
        // there is no window in which a started run resolves an absent prompt.
        let slot = self.place_prompt(&composition)?;
        let outcome = self.execute(&composition);
        // The prompt is operator content and the run that consumed it has
        // ended. Removing it is best effort: a slot this lane could not remove
        // is a file in a private directory, not a leak of anything the run did
        // not already carry.
        let _ = fs::remove_file(&slot);
        outcome
    }
}

impl SocketRunLane {
    /// Everything after the prompt is durable: submit, start, wait, read.
    ///
    /// Split out so [`RunLane::run`] has exactly one place that removes the
    /// slot, on every path including a refusal.
    fn execute(&mut self, composition: &Composition) -> Result<String, RunFailure> {
        let submission_id = self.submit(composition)?;
        self.start(composition)?;
        self.begin_slack_progress();
        // The run identity is the hub's key as well as the cgroup's and the
        // workspace's, which is what lets the wait below draw this run's own
        // frames and nobody else's.
        let run_id = composition.run_id().to_owned();
        match self.await_terminal(submission_id, &run_id)? {
            RunSpoolState::Completed => {
                read_answer(composition.answer_path()).ok_or(RunFailure::NoAnswer)
            }
            RunSpoolState::TimedOut => Err(RunFailure::TimedOut),
            RunSpoolState::Cancelled => Err(RunFailure::Cancelled),
            // `Failed` is the workload's own nonzero exit, a fatal signal, a
            // refused launch, or a supervisor failure — the backend records one
            // word for all four and this lane has no more than that word.
            RunSpoolState::Failed => Err(RunFailure::Failed),
            // Not terminal, so `await_terminal` cannot have returned it.
            RunSpoolState::Ready | RunSpoolState::Running => Err(RunFailure::Unavailable),
        }
    }
}

impl RunFailure {
    /// Map one composition refusal onto the word an operator receives.
    ///
    /// Only the two an operator can act on are distinguished. Everything else —
    /// a provider binary that cannot be hashed, a host that enforces nothing, a
    /// document this build composed and cannot submit — is the deployment's
    /// problem rather than the sender's, and is reported as unavailable rather
    /// than as advice they cannot use.
    #[must_use]
    pub const fn from_compose(refusal: ComposeRefusal) -> Self {
        match refusal {
            ComposeRefusal::NotConfigured => Self::NotConfigured,
            ComposeRefusal::TaskRejected => Self::TaskRejected,
            ComposeRefusal::ProviderUnreadable
            | ComposeRefusal::HostUnenforceable
            | ComposeRefusal::IdentityRejected
            | ComposeRefusal::DocumentRejected => Self::Unavailable,
        }
    }
}
