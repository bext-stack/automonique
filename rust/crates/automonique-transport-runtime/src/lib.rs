// SPDX-License-Identifier: Elastic-2.0

//! Fenced Telegram polling orchestration and its bounded HTTPS boundary.
//!
//! This crate prepares one typed `getUpdates` request and coordinates an
//! HTTP executor with an atomic durable sink. The concrete HTTPS client is
//! deliberately limited to Telegram's exact `getUpdates` endpoint; hosts must
//! still acquire and renew the durable poller lease before invoking it.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use automonique_transports::{
    MAX_TELEGRAM_RESPONSE_BYTES, MAX_TELEGRAM_UPDATES, TelegramAccessPolicy, TelegramDisposition,
    TelegramError, TelegramIngress, TelegramInputKind, parse_telegram_updates,
};
use sha2::{Digest, Sha256};

mod https_client;
mod slack_sink;
mod store_sink;
mod telegram_control;

pub use https_client::{
    MAX_BOT_COMMAND_DESCRIPTION_CHARS, MAX_BOT_COMMAND_NAME_CHARS, MAX_BOT_COMMANDS,
    MAX_SEND_MESSAGE_TEXT_UNITS, OutboundRefusal, SendMessageRequest, SetMyCommandsRequest,
    TelegramBotCommand, TelegramHttpsClient, TelegramOutbound, TelegramOutboundClient,
    TelegramOutboundPlan,
};
pub use slack_sink::{
    SlackDurableReceipt, SlackSinkFailure, StoreSlackDurableSink, slack_content_digest,
};
pub use store_sink::{Clock, ClockFailure, StoreTelegramDurableSink, SystemClock};
pub use telegram_control::{
    ADMIN_HELP_MARK, AdminDirective, AllowedUsers, AllowlistError, ArgumentShape, COMMAND_COUNT,
    ChannelName, CommandKind, CommandManifestEntry, CommandRefusal, CommandSpec, CommandTier,
    ControlCommand, ControlRef, MAX_ALLOWED_USERS, MAX_BOT_SUFFIX_BYTES, MAX_CHANNEL_NAME_BYTES,
    MAX_COMMAND_NAME_BYTES, MAX_COMMAND_TEXT_BYTES, MAX_CONTROL_REF_BYTES, MAX_RUN_TASK_BYTES,
    MAX_SAY_TEXT_BYTES, MAX_USER_ID_BYTES, OperatorAuthority, OperatorUserId, RunTask, SayText,
    authorize_and_parse, authorize_and_parse_tiered, command_manifest, help_text, parse_command,
};

const MAX_LEASE_ID_BYTES: usize = 256;
const MAX_LONG_POLL_SECONDS: u16 = 50;
/// Lease headroom beyond Telegram's server-side long-poll timeout.
///
/// The concrete HTTPS client has a smaller three-second transport allowance,
/// leaving two seconds for the host to observe completion before lease expiry.
pub const TELEGRAM_HTTP_LEASE_MARGIN_MS: i64 = 5_000;

/// Opaque bot credential carried only to the injected HTTP boundary.
pub struct OpaqueBotToken(Vec<u8>);

impl OpaqueBotToken {
    /// Construct a bounded nonempty token.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, RuntimeError> {
        let secret = secret.into();
        if secret.is_empty()
            || secret.len() > 256
            || !secret
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
        {
            return Err(RuntimeError::InvalidConfiguration("bot_token"));
        }
        Ok(Self(secret))
    }

    fn is_present(&self) -> bool {
        !self.0.is_empty()
    }
}

/// Deliberate, short-lived credential view for an HTTP implementation.
///
/// The callback shape prevents accidental `Debug`/`Clone` propagation. An
/// implementation can still copy the bytes, so HTTP clients are trusted
/// credential consumers and must be reviewed as such.
pub struct TelegramAuthorization<'a>(&'a [u8]);

impl TelegramAuthorization<'_> {
    pub fn with_secret<R>(&self, consume: impl FnOnce(&[u8]) -> R) -> R {
        consume(self.0)
    }
}

impl fmt::Debug for TelegramAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TelegramAuthorization(<redacted>)")
    }
}

impl fmt::Debug for OpaqueBotToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueBotToken(<redacted>)")
    }
}

impl Drop for OpaqueBotToken {
    fn drop(&mut self) {
        // Best-effort hygiene only. Rust does not guarantee that an optimizer
        // preserves these dead stores; production secret custody must supply a
        // reviewed non-elidable secret container at this boundary.
        self.0.fill(0);
    }
}

/// Typed HTTP verb; no arbitrary method string enters the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Post,
}

/// Typed Telegram target; it contains no URL or credential material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelegramTarget {
    GetUpdates,
}

/// Closed request body for Telegram `getUpdates`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetUpdatesBody {
    pub offset: u64,
    pub limit: usize,
    pub timeout_seconds: u16,
}

/// Exact request plan passed to an injected HTTP implementation.
pub struct TelegramHttpPlan<'a> {
    pub method: HttpMethod,
    pub target: TelegramTarget,
    pub bot_id: i64,
    pub body: GetUpdatesBody,
    authorization: &'a OpaqueBotToken,
}

impl TelegramHttpPlan<'_> {
    /// Whether an opaque authorization capability is present.
    #[must_use]
    pub fn has_authorization(&self) -> bool {
        self.authorization.is_present()
    }

    /// Borrow the credential only at the trusted HTTP boundary.
    #[must_use]
    pub fn authorization(&self) -> TelegramAuthorization<'_> {
        TelegramAuthorization(&self.authorization.0)
    }
}

impl fmt::Debug for TelegramHttpPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramHttpPlan")
            .field("method", &self.method)
            .field("target", &self.target)
            .field("bot_id", &self.bot_id)
            .field("body", &self.body)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

/// Bounded HTTP response returned by the injected client.
#[derive(Clone, Eq, PartialEq)]
pub struct TelegramHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Host monotonic wall-clock observation after the complete response.
    pub completed_ms: i64,
}

impl fmt::Debug for TelegramHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramHttpResponse")
            .field("status", &self.status)
            .field("completed_ms", &self.completed_ms)
            .field(
                "body",
                &format_args!("<redacted:{} bytes>", self.body.len()),
            )
            .finish()
    }
}

/// Closed failures from the HTTP execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpFailure {
    Unavailable,
    TimedOut,
    Cancelled,
    ResponseTooLarge,
    UnexpectedStatus,
    UnexpectedContentType,
}

/// An HTTP implementation consumes only the typed plan and cancellation flag.
pub trait TelegramHttpClient {
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure>;
}

/// Exact renewable single-poller authority supplied by the durable owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollerLease {
    pub bot_id: i64,
    pub generation_id: String,
    pub holder_id: String,
    pub epoch: u64,
    pub expires_ms: i64,
}

impl PollerLease {
    pub fn new(
        bot_id: i64,
        generation_id: impl Into<String>,
        holder_id: impl Into<String>,
        epoch: u64,
        expires_ms: i64,
    ) -> Result<Self, RuntimeError> {
        let generation_id = generation_id.into();
        let holder_id = holder_id.into();
        if bot_id <= 0
            || !valid_id(&generation_id)
            || !valid_id(&holder_id)
            || epoch == 0
            || expires_ms < 0
        {
            return Err(RuntimeError::InvalidConfiguration("poller_lease"));
        }
        Ok(Self {
            bot_id,
            generation_id,
            holder_id,
            epoch,
            expires_ms,
        })
    }
}

/// Offset observation bound to the exact poller lease epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetReceipt {
    pub bot_id: i64,
    pub lease_epoch: u64,
    pub next_offset: u64,
}

/// Durable disposition passed to the atomic sink.
#[derive(Clone, Eq, PartialEq)]
pub enum DurableDisposition {
    Admitted { content: Vec<u8> },
    Denied,
    IgnoredUnsupported,
}

impl fmt::Debug for DurableDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admitted { content } => formatter
                .debug_struct("Admitted")
                .field(
                    "content",
                    &format_args!("<redacted:{} bytes>", content.len()),
                )
                .finish(),
            Self::Denied => formatter.write_str("Denied"),
            Self::IgnoredUnsupported => formatter.write_str("IgnoredUnsupported"),
        }
    }
}

/// One parsed update in an atomic durable commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTelegramUpdate {
    pub update_id: u64,
    pub source_key: String,
    pub scope: String,
    pub kind: TelegramInputKind,
    pub disposition: DurableDisposition,
}

/// One complete batch sent to the durable sink exactly once per poll attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTelegramBatch {
    pub bot_id: i64,
    pub expected_offset: u64,
    pub next_offset: u64,
    pub received_ms: i64,
    pub updates: Vec<DurableTelegramUpdate>,
    pub digest: [u8; 32],
}

impl DurableTelegramBatch {
    /// Construct a canonical batch and bind its digest to every coordinate and disposition.
    pub fn new(
        bot_id: i64,
        expected_offset: u64,
        next_offset: u64,
        received_ms: i64,
        updates: Vec<DurableTelegramUpdate>,
    ) -> Result<Self, RuntimeError> {
        if bot_id <= 0
            || received_ms < 0
            || updates.len() > MAX_TELEGRAM_UPDATES
            || next_offset < expected_offset
            || (updates.is_empty() && next_offset != expected_offset)
        {
            return Err(RuntimeError::InvalidConfiguration("telegram_batch"));
        }
        let mut batch = Self {
            bot_id,
            expected_offset,
            next_offset,
            received_ms,
            updates,
            digest: [0; 32],
        };
        batch.digest = telegram_batch_digest(&batch);
        Ok(batch)
    }
}

/// Durable, full-fidelity state that a host must store before acknowledging a
/// post-commit ambiguity. It contains admitted message content and must be
/// protected like the ingress table; `Debug` deliberately reveals only the
/// digest and coordinates.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingCommit {
    batch: DurableTelegramBatch,
}

impl PendingCommit {
    /// Reconstruct host-persisted ambiguity state after a process restart.
    pub fn restore(batch: DurableTelegramBatch) -> Result<Self, RuntimeError> {
        if batch.bot_id <= 0
            || batch.received_ms < 0
            || batch.updates.len() > MAX_TELEGRAM_UPDATES
            || batch.next_offset < batch.expected_offset
            || telegram_batch_digest(&batch) != batch.digest
        {
            return Err(RuntimeError::InvalidConfiguration("pending_commit"));
        }
        Ok(Self { batch })
    }

    #[must_use]
    pub fn batch(&self) -> &DurableTelegramBatch {
        &self.batch
    }
}

impl fmt::Debug for PendingCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingCommit")
            .field("bot_id", &self.batch.bot_id)
            .field("expected_offset", &self.batch.expected_offset)
            .field("next_offset", &self.batch.next_offset)
            .field("digest", &self.batch.digest)
            .finish_non_exhaustive()
    }
}

/// Exact sink acknowledgement checked before returning a committed outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableCommitReceipt {
    pub bot_id: i64,
    pub lease_epoch: u64,
    pub next_offset: u64,
    pub disposition_count: usize,
    pub batch_digest: [u8; 32],
    pub duplicate: bool,
}

/// Closed durable-sink failures, including an intentionally ambiguous commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkFailure {
    StaleLease,
    Conflict,
    Unavailable,
    AmbiguousCommit,
}

/// Store adapter seam. Implementations validate the same lease on read and
/// commit and commit every disposition plus offset in one transaction.
pub trait TelegramDurableSink {
    fn read_offset(
        &mut self,
        lease: &PollerLease,
        now_ms: i64,
    ) -> Result<OffsetReceipt, SinkFailure>;

    /// Commit while independently observing that the exact lease remains live
    /// before `commit_before_ms` and fencing its epoch in the same transaction.
    /// An implementation may return an exact digest-bound duplicate receipt
    /// after expiry, but expiry must prevent every new mutation.
    fn commit_batch(
        &mut self,
        lease: &PollerLease,
        batch: &DurableTelegramBatch,
        commit_before_ms: i64,
    ) -> Result<DurableCommitReceipt, SinkFailure>;
}

/// Cooperative cancellation shared with the long-poll executor.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Successfully committed poll result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollOutcome {
    pub previous_offset: u64,
    pub next_offset: u64,
    pub disposition_count: usize,
    pub duplicate: bool,
}

/// Disabled or lease-owning Telegram host state. Neither state can perform HTTP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelegramHostState {
    DisabledNoClient,
    LeaseOwnedNoClient(PollerLease),
}

/// Store-backed lease lifecycle for a future trusted Telegram HTTP host.
pub struct TelegramLeaseCoordinator<C> {
    sink: StoreTelegramDurableSink<C>,
    authority_lease_epoch: u64,
    ttl_ms: i64,
    state: TelegramHostState,
    pending_commit: Option<PendingCommit>,
}

impl<C> TelegramLeaseCoordinator<C>
where
    C: Clock,
{
    /// Construct the default state. It owns no bot lease and cannot poll.
    pub fn disabled(
        sink: StoreTelegramDurableSink<C>,
        authority_lease_epoch: u64,
        ttl_ms: i64,
    ) -> Result<Self, RuntimeError> {
        if authority_lease_epoch == 0 || ttl_ms <= 0 {
            return Err(RuntimeError::InvalidConfiguration("telegram_lease"));
        }
        Ok(Self {
            sink,
            authority_lease_epoch,
            ttl_ms,
            state: TelegramHostState::DisabledNoClient,
            pending_commit: None,
        })
    }

    #[must_use]
    pub const fn state(&self) -> &TelegramHostState {
        &self.state
    }

    /// Explicitly acquire a configured bot lease without enabling polling.
    pub fn acquire_no_client(
        &mut self,
        bot_id: i64,
        generation_id: &str,
        holder_id: &str,
    ) -> Result<&PollerLease, RuntimeError> {
        if !matches!(self.state, TelegramHostState::DisabledNoClient) {
            return Err(RuntimeError::InvalidConfiguration("telegram_lease_owned"));
        }
        let lease = self
            .sink
            .acquire_poller_lease(
                bot_id,
                generation_id,
                holder_id,
                self.authority_lease_epoch,
                self.ttl_ms,
            )
            .map_err(RuntimeError::Sink)?;
        self.state = TelegramHostState::LeaseOwnedNoClient(lease);
        match &self.state {
            TelegramHostState::LeaseOwnedNoClient(lease) => Ok(lease),
            TelegramHostState::DisabledNoClient => unreachable!("assigned owned state"),
        }
    }

    /// Renew the exact owned lease without changing its epoch or owner.
    pub fn renew(&mut self) -> Result<&PollerLease, RuntimeError> {
        let TelegramHostState::LeaseOwnedNoClient(lease) = &self.state else {
            return Err(RuntimeError::InvalidConfiguration("telegram_lease_absent"));
        };
        let renewed = self
            .sink
            .renew_poller_lease(lease, self.authority_lease_epoch, self.ttl_ms)
            .map_err(RuntimeError::Sink)?;
        if renewed.bot_id != lease.bot_id
            || renewed.generation_id != lease.generation_id
            || renewed.holder_id != lease.holder_id
            || renewed.epoch != lease.epoch
        {
            return Err(RuntimeError::SinkReceiptMismatch);
        }
        self.state = TelegramHostState::LeaseOwnedNoClient(renewed);
        match &self.state {
            TelegramHostState::LeaseOwnedNoClient(lease) => Ok(lease),
            TelegramHostState::DisabledNoClient => unreachable!("assigned owned state"),
        }
    }

    /// Restore a crash-preserved ambiguous commit before shutdown or polling.
    pub fn restore_pending_commit(&mut self, pending: PendingCommit) -> Result<(), RuntimeError> {
        let TelegramHostState::LeaseOwnedNoClient(lease) = &self.state else {
            return Err(RuntimeError::InvalidConfiguration("telegram_lease_absent"));
        };
        if self.pending_commit.is_some() || pending.batch.bot_id != lease.bot_id {
            return Err(RuntimeError::InvalidConfiguration("pending_commit"));
        }
        self.pending_commit = Some(pending);
        Ok(())
    }

    /// Resolve the exact pending batch through the durable sink without HTTP.
    pub fn resolve_pending_commit(&mut self) -> Result<DurableCommitReceipt, RuntimeError> {
        let TelegramHostState::LeaseOwnedNoClient(lease) = &self.state else {
            return Err(RuntimeError::InvalidConfiguration("telegram_lease_absent"));
        };
        let pending = self
            .pending_commit
            .as_ref()
            .ok_or(RuntimeError::InvalidConfiguration("pending_commit"))?;
        let receipt = self
            .sink
            .commit_batch(lease, pending.batch(), lease.expires_ms)
            .map_err(RuntimeError::Sink)?;
        validate_commit_receipt(lease, pending.batch(), &receipt)?;
        self.pending_commit = None;
        Ok(receipt)
    }

    /// Release only after any ambiguous pending commit has been exactly resolved.
    pub fn release(&mut self) -> Result<(), RuntimeError> {
        if let Some(pending) = &self.pending_commit {
            return Err(RuntimeError::CommitReconciliationRequired {
                bot_id: pending.batch.bot_id,
                next_offset: pending.batch.next_offset,
                batch_digest: pending.batch.digest,
            });
        }
        let TelegramHostState::LeaseOwnedNoClient(lease) = &self.state else {
            return Ok(());
        };
        self.sink
            .release_poller_lease(lease)
            .map_err(RuntimeError::Sink)?;
        self.state = TelegramHostState::DisabledNoClient;
        Ok(())
    }

    /// Recover the sink only after clean release and reconciliation.
    pub fn into_sink(self) -> Result<StoreTelegramDurableSink<C>, RuntimeError> {
        if self.pending_commit.is_some()
            || !matches!(self.state, TelegramHostState::DisabledNoClient)
        {
            return Err(RuntimeError::InvalidConfiguration("telegram_shutdown"));
        }
        Ok(self.sink)
    }
}

/// Stable, content-free runtime refusal.
#[derive(Debug)]
pub enum RuntimeError {
    InvalidConfiguration(&'static str),
    LeaseMismatch,
    LeaseExpired,
    Cancelled,
    Http(HttpFailure),
    UnexpectedHttpStatus,
    Parse(TelegramError),
    ParserContract,
    Sink(SinkFailure),
    CommitReconciliationRequired {
        bot_id: i64,
        next_offset: u64,
        batch_digest: [u8; 32],
    },
    SinkReceiptMismatch,
}

impl RuntimeError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::LeaseMismatch => "lease_mismatch",
            Self::LeaseExpired => "lease_expired",
            Self::Cancelled => "cancelled",
            Self::Http(_) => "http",
            Self::UnexpectedHttpStatus => "unexpected_http_status",
            Self::Parse(_) => "telegram_parse",
            Self::ParserContract => "telegram_parser_contract",
            Self::Sink(_) => "durable_sink",
            Self::CommitReconciliationRequired { .. } => "commit_reconciliation_required",
            Self::SinkReceiptMismatch => "sink_receipt_mismatch",
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Telegram poll refused: {}", self.category())
    }
}

impl Error for RuntimeError {}

/// One configured Telegram polling state machine.
pub struct TelegramPoller<C, S> {
    client: C,
    sink: S,
    policy: TelegramAccessPolicy,
    token: OpaqueBotToken,
    long_poll_seconds: u16,
    pending_commit: Option<PendingCommit>,
}

impl<C, S> TelegramPoller<C, S>
where
    C: TelegramHttpClient,
    S: TelegramDurableSink,
{
    pub fn new(
        client: C,
        sink: S,
        policy: TelegramAccessPolicy,
        token: OpaqueBotToken,
        long_poll_seconds: u16,
    ) -> Result<Self, RuntimeError> {
        if long_poll_seconds == 0 || long_poll_seconds > MAX_LONG_POLL_SECONDS {
            return Err(RuntimeError::InvalidConfiguration("long_poll_seconds"));
        }
        Ok(Self {
            client,
            sink,
            policy,
            token,
            long_poll_seconds,
            pending_commit: None,
        })
    }

    /// Replace the access policy under which further polls admit work.
    ///
    /// A host whose operator list can change at runtime — one where an
    /// administrator adds a member from a chat — has to be able to widen the
    /// policy without dropping the poller, because rebuilding it would mean
    /// re-acquiring the bot lease and re-reading the durable offset to add one
    /// row to an allowlist.
    ///
    /// Two things are refused rather than accommodated. **A different bot**:
    /// the policy's identity is bound into every scope this poller has already
    /// committed, and changing it would make one durable stream describe two
    /// bots. **A pending ambiguous commit**: that batch was parsed under the
    /// policy in force when it was fetched, and resolving it under a different
    /// one would commit dispositions the parse never produced.
    ///
    /// The new policy takes effect on the *next* poll. An update already fetched
    /// under the old one keeps the disposition it was parsed with, which is the
    /// only answer that keeps the durable record and the reply consistent.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConfiguration`] for either refusal.
    pub fn set_policy(&mut self, policy: TelegramAccessPolicy) -> Result<(), RuntimeError> {
        if policy.bot_id().get() != self.policy.bot_id().get() || self.pending_commit.is_some() {
            return Err(RuntimeError::InvalidConfiguration("policy"));
        }
        self.policy = policy;
        Ok(())
    }

    /// Restore exact durable ambiguity state before any further HTTP request.
    pub fn restore_pending_commit(&mut self, pending: PendingCommit) -> Result<(), RuntimeError> {
        if self.pending_commit.is_some()
            || pending.batch.bot_id != self.policy.bot_id().get()
            || telegram_batch_digest(&pending.batch) != pending.batch.digest
        {
            return Err(RuntimeError::InvalidConfiguration("pending_commit"));
        }
        self.pending_commit = Some(pending);
        Ok(())
    }

    /// Move ambiguity state to the durable host during shutdown/checkpointing.
    #[must_use]
    pub fn take_pending_commit(&mut self) -> Option<PendingCommit> {
        self.pending_commit.take()
    }

    /// Execute one read-request-parse-atomic-commit cycle.
    pub fn poll_once(
        &mut self,
        lease: &PollerLease,
        now_ms: i64,
        cancellation: &CancellationToken,
    ) -> Result<PollOutcome, RuntimeError> {
        if let Some(pending) = &self.pending_commit {
            let batch = pending.batch();
            return Err(RuntimeError::CommitReconciliationRequired {
                bot_id: batch.bot_id,
                next_offset: batch.next_offset,
                batch_digest: batch.digest,
            });
        }
        if now_ms < 0 {
            return Err(RuntimeError::InvalidConfiguration("now_ms"));
        }
        if lease.bot_id != self.policy.bot_id().get() {
            return Err(RuntimeError::LeaseMismatch);
        }
        let poll_deadline_ms = now_ms
            .checked_add(i64::from(self.long_poll_seconds) * 1_000)
            .and_then(|deadline| deadline.checked_add(TELEGRAM_HTTP_LEASE_MARGIN_MS))
            .ok_or(RuntimeError::InvalidConfiguration("long_poll_deadline"))?;
        if lease.expires_ms <= poll_deadline_ms {
            return Err(RuntimeError::LeaseExpired);
        }
        check_cancelled(cancellation)?;
        let offset = self
            .sink
            .read_offset(lease, now_ms)
            .map_err(RuntimeError::Sink)?;
        if offset.bot_id != lease.bot_id || offset.lease_epoch != lease.epoch {
            return Err(RuntimeError::SinkReceiptMismatch);
        }
        check_cancelled(cancellation)?;
        let plan = TelegramHttpPlan {
            method: HttpMethod::Post,
            target: TelegramTarget::GetUpdates,
            bot_id: lease.bot_id,
            body: GetUpdatesBody {
                offset: offset.next_offset,
                limit: MAX_TELEGRAM_UPDATES,
                timeout_seconds: self.long_poll_seconds,
            },
            authorization: &self.token,
        };
        let response = self
            .client
            .execute(&plan, cancellation)
            .map_err(RuntimeError::Http)?;
        check_cancelled(cancellation)?;
        if response.completed_ms < now_ms || response.completed_ms >= lease.expires_ms {
            return Err(RuntimeError::LeaseExpired);
        }
        if response.status != 200 {
            return Err(RuntimeError::UnexpectedHttpStatus);
        }
        if response.body.len() > MAX_TELEGRAM_RESPONSE_BYTES {
            return Err(RuntimeError::Http(HttpFailure::ResponseTooLarge));
        }
        let parsed = parse_telegram_updates(&response.body, offset.next_offset, &self.policy)
            .map_err(RuntimeError::Parse)?;
        let updates = parsed
            .updates()
            .iter()
            .map(normalize_update)
            .collect::<Result<Vec<_>, _>>()?;
        let batch = DurableTelegramBatch::new(
            lease.bot_id,
            offset.next_offset,
            parsed.next_offset(),
            now_ms,
            updates,
        )?;
        check_cancelled(cancellation)?;
        let receipt = match self.sink.commit_batch(lease, &batch, lease.expires_ms) {
            Ok(receipt) => receipt,
            Err(SinkFailure::AmbiguousCommit) => {
                let error = RuntimeError::CommitReconciliationRequired {
                    bot_id: batch.bot_id,
                    next_offset: batch.next_offset,
                    batch_digest: batch.digest,
                };
                self.pending_commit = Some(PendingCommit { batch });
                return Err(error);
            }
            Err(other) => return Err(RuntimeError::Sink(other)),
        };
        if validate_commit_receipt(lease, &batch, &receipt).is_err() {
            let error = RuntimeError::CommitReconciliationRequired {
                bot_id: batch.bot_id,
                next_offset: batch.next_offset,
                batch_digest: batch.digest,
            };
            self.pending_commit = Some(PendingCommit { batch });
            return Err(error);
        }
        Ok(PollOutcome {
            previous_offset: batch.expected_offset,
            next_offset: receipt.next_offset,
            disposition_count: receipt.disposition_count,
            duplicate: receipt.duplicate,
        })
    }

    /// Resolve one ambiguous atomic commit by replaying the exact retained
    /// batch without issuing another Telegram request.
    ///
    /// The host must durably preserve `CommitReconciliationRequired` across a
    /// poller restart; this in-process orchestrator intentionally owns no
    /// database. Until resolution, `poll_once` remains fail-closed.
    pub fn reconcile_commit(
        &mut self,
        lease: &PollerLease,
        now_ms: i64,
    ) -> Result<PollOutcome, RuntimeError> {
        let pending = self
            .pending_commit
            .as_ref()
            .ok_or(RuntimeError::InvalidConfiguration(
                "pending_commit_reconciliation",
            ))?;
        let batch = pending.batch();
        if now_ms < batch.received_ms {
            return Err(RuntimeError::LeaseExpired);
        }
        let receipt = self
            .sink
            .commit_batch(lease, batch, lease.expires_ms)
            .map_err(|error| match error {
                SinkFailure::AmbiguousCommit => RuntimeError::CommitReconciliationRequired {
                    bot_id: batch.bot_id,
                    next_offset: batch.next_offset,
                    batch_digest: batch.digest,
                },
                other => RuntimeError::Sink(other),
            })?;
        validate_commit_receipt(lease, batch, &receipt)?;
        let outcome = PollOutcome {
            previous_offset: batch.expected_offset,
            next_offset: receipt.next_offset,
            disposition_count: receipt.disposition_count,
            duplicate: receipt.duplicate,
        };
        self.pending_commit = None;
        Ok(outcome)
    }

    /// Recover owned components for inspection or replacement in tests/hosts.
    pub fn into_parts(self) -> (C, S) {
        (self.client, self.sink)
    }
}

fn validate_commit_receipt(
    lease: &PollerLease,
    batch: &DurableTelegramBatch,
    receipt: &DurableCommitReceipt,
) -> Result<(), RuntimeError> {
    if receipt.bot_id != batch.bot_id
        || receipt.lease_epoch != lease.epoch
        || receipt.next_offset != batch.next_offset
        || receipt.disposition_count != batch.updates.len()
        || receipt.batch_digest != batch.digest
    {
        Err(RuntimeError::SinkReceiptMismatch)
    } else {
        Ok(())
    }
}

fn telegram_batch_digest(batch: &DurableTelegramBatch) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"automonique.telegram.batch/v1\0");
    hasher.update(batch.bot_id.to_be_bytes());
    hasher.update(batch.expected_offset.to_be_bytes());
    hasher.update(batch.next_offset.to_be_bytes());
    hasher.update(batch.received_ms.to_be_bytes());
    hasher.update((batch.updates.len() as u64).to_be_bytes());
    for update in &batch.updates {
        hasher.update(update.update_id.to_be_bytes());
        hash_field(&mut hasher, update.source_key.as_bytes());
        hash_field(&mut hasher, update.scope.as_bytes());
        hasher.update([match update.kind {
            TelegramInputKind::Message => 1,
            TelegramInputKind::Callback => 2,
            TelegramInputKind::Unsupported => 3,
        }]);
        match &update.disposition {
            DurableDisposition::Admitted { content } => {
                hasher.update([1]);
                hash_field(&mut hasher, content);
            }
            DurableDisposition::Denied => hasher.update([2]),
            DurableDisposition::IgnoredUnsupported => hasher.update([3]),
        }
    }
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), RuntimeError> {
    if cancellation.is_cancelled() {
        Err(RuntimeError::Cancelled)
    } else {
        Ok(())
    }
}

fn normalize_update(update: &TelegramIngress) -> Result<DurableTelegramUpdate, RuntimeError> {
    let disposition = match (update.disposition(), update.content()) {
        (TelegramDisposition::Admitted, Some(content)) if !content.is_empty() => {
            DurableDisposition::Admitted {
                content: content.as_bytes().to_vec(),
            }
        }
        (TelegramDisposition::Denied, None) => DurableDisposition::Denied,
        (TelegramDisposition::IgnoredUnsupported, None) => DurableDisposition::IgnoredUnsupported,
        _ => return Err(RuntimeError::ParserContract),
    };
    Ok(DurableTelegramUpdate {
        update_id: update.update_id(),
        source_key: update.source_key().to_owned(),
        scope: update.scope().to_owned(),
        kind: update.kind(),
        disposition,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_LEASE_ID_BYTES && !value.chars().any(char::is_control)
}
