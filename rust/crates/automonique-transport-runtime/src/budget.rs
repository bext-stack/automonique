// SPDX-License-Identifier: Elastic-2.0

//! A deterministic call budget for one Telegram bot.
//!
//! # What this is for
//!
//! Telegram publishes three rate ceilings and enforces them with `429`s: roughly
//! thirty calls a second for the whole bot, roughly one message a second in one
//! chat, and roughly twenty messages a minute in one group. This module is the
//! arithmetic that keeps this product inside them *before* a call is issued,
//! and the durable pause that keeps it out of the way once Telegram has said
//! `429` anyway.
//!
//! # Why the clock is injected
//!
//! There is no timer thread here, no async runtime and nothing that sleeps.
//! Every method takes `now_ms` from its caller, and the caller is always a loop
//! that was going to look at the clock regardless — the poller's own iteration,
//! the outbox drain, the run lane's fifty-millisecond wait. A budget that owned
//! a timer would be a fourth thread whose only job is to decrement counters
//! that nobody reads between decrements.
//!
//! That also makes the whole of this file exercisable from a fixed clock: every
//! test below picks its own instants, and none of them sleeps.
//!
//! # Two priorities, and the rule that separates them
//!
//! - [`CallPriority::Durable`] is everything a person asked for: an outbox
//!   intent, a reaction, the command menu, the long poll itself.
//! - [`CallPriority::Ephemeral`] is streaming: a draft snapshot that the next
//!   snapshot replaces, and that nobody will miss if it is skipped.
//!
//! **A durable claim is never refused for want of tokens.** It debits every
//! bucket it touches, saturating at zero, and the only thing that can refuse it
//! is a live whole-bot pause. **An ephemeral claim is refused unless every
//! bucket it touches would still hold its configured headroom afterwards.**
//!
//! That asymmetry is the design, not a shortcut. Telegram's `429` is the
//! authority on how much durable traffic is too much, and this product answers
//! it durably (see [`TelegramCallBudget::note_rate_limited`]); refusing an
//! operator's reply locally because a counter said so would drop a message that
//! Telegram would have accepted. What the budget owes the product is the
//! opposite guarantee: that *streaming* can never be the reason a final answer
//! is late. Since ephemeral claims stop at the headroom line and durable claims
//! are refused only by the pause — which no ephemeral claim can cause, because
//! a draft that would exceed the budget is never sent — draft starvation of a
//! durable reply is not a state this type can reach. [`tests`] asserts it.
//!
//! # Arithmetic
//!
//! Tokens are integers. One call costs [`TOKEN_SCALE`] units, and each bucket's
//! refill is expressed as whole units per millisecond, so a bucket never loses
//! a fraction of a token to truncation and two hosts replaying the same instants
//! reach the same answer. The scale is chosen so that all three production
//! rates divide exactly; the assertions below are compile-time.
//!
//! # For the Slack connector
//!
//! [`TokenBucket`] and [`BucketSpec`] carry nothing Telegram-shaped. Slack's own
//! budget lifts them out of this file unchanged and instantiates its own scopes
//! and tiers; what stays here is the Telegram scope selection, the method
//! vocabulary and the pause.

use std::collections::BTreeMap;
use std::fmt;

use crate::https_client::TelegramOutbound;

// ------------------------------------------------------------- generic core

/// Integer units one call costs.
///
/// Divisible by 1000 and by 3, which is what makes thirty-per-second,
/// one-per-second and twenty-per-minute all express as whole units per
/// millisecond.
pub const TOKEN_SCALE: u64 = 3_000_000;

/// One bucket's shape: how many calls, over how long.
///
/// Refusal-first at construction: a rate that does not divide into whole units
/// per millisecond is not representable, so a bucket cannot silently drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketSpec {
    capacity: u64,
    refill_per_ms: u64,
}

impl BucketSpec {
    /// Whether `calls` over `window_ms` refills in whole units per millisecond.
    #[must_use]
    pub const fn is_exact(calls: u64, window_ms: u64) -> bool {
        window_ms != 0
            && calls != 0
            && (calls * TOKEN_SCALE).is_multiple_of(window_ms)
            && (calls * TOKEN_SCALE) / window_ms != 0
    }

    /// Build one bucket shape, or `None` when the rate is not exact.
    #[must_use]
    pub const fn new(calls: u64, window_ms: u64) -> Option<Self> {
        if !Self::is_exact(calls, window_ms) {
            return None;
        }
        Some(Self {
            capacity: calls * TOKEN_SCALE,
            refill_per_ms: (calls * TOKEN_SCALE) / window_ms,
        })
    }

    /// Build one bucket shape from a rate a `const` assertion has verified.
    ///
    /// The zero fallback is unreachable for every call site in this file — each
    /// is guarded by its own `const _: () = assert!(BucketSpec::is_exact(..))` —
    /// and it exists so this stays a total function rather than a `panic!`.
    #[must_use]
    const fn exact(calls: u64, window_ms: u64) -> Self {
        match Self::new(calls, window_ms) {
            Some(spec) => spec,
            None => Self {
                capacity: 0,
                refill_per_ms: 0,
            },
        }
    }

    /// Whole calls this bucket holds when full.
    #[must_use]
    pub const fn capacity_calls(self) -> u64 {
        self.capacity / TOKEN_SCALE
    }
}

/// One deterministic token bucket over an injected clock.
///
/// Carries no vocabulary of its own: it is the arithmetic, and the scopes that
/// use it decide what a token means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenBucket {
    spec: BucketSpec,
    tokens: u64,
    observed_ms: i64,
}

impl TokenBucket {
    /// A full bucket, as of `now_ms`.
    #[must_use]
    pub const fn full(spec: BucketSpec, now_ms: i64) -> Self {
        Self {
            spec,
            tokens: spec.capacity,
            observed_ms: now_ms,
        }
    }

    /// Bring the bucket up to `now_ms`.
    ///
    /// A clock that moved backwards refills nothing and does not rewind the
    /// observation: a host whose wall clock stepped back would otherwise get a
    /// bucket that refills twice over the same interval.
    fn refill(&mut self, now_ms: i64) {
        let elapsed = now_ms.saturating_sub(self.observed_ms);
        if elapsed <= 0 {
            return;
        }
        let gained =
            u128::from(elapsed.unsigned_abs()).saturating_mul(u128::from(self.spec.refill_per_ms));
        let tokens = u128::from(self.tokens)
            .saturating_add(gained)
            .min(u128::from(self.spec.capacity));
        // The `min` above bounds this by `capacity`, which is a `u64`.
        self.tokens = u64::try_from(tokens).unwrap_or(self.spec.capacity);
        self.observed_ms = now_ms;
    }

    /// Units held at `now_ms`, without spending any.
    #[must_use]
    pub fn available(&mut self, now_ms: i64) -> u64 {
        self.refill(now_ms);
        self.tokens
    }

    /// Whether one call plus `headroom_calls` of slack is available.
    #[must_use]
    pub fn admits(&mut self, headroom_calls: u64, now_ms: i64) -> bool {
        let required = TOKEN_SCALE.saturating_mul(headroom_calls.saturating_add(1));
        self.available(now_ms) >= required
    }

    /// Spend one call, saturating at empty.
    pub fn debit(&mut self, now_ms: i64) {
        self.refill(now_ms);
        self.tokens = self.tokens.saturating_sub(TOKEN_SCALE);
    }

    /// Whether the bucket is full at `now_ms`, and therefore remembers nothing.
    #[must_use]
    pub fn is_full(&mut self, now_ms: i64) -> bool {
        self.available(now_ms) == self.spec.capacity
    }
}

// --------------------------------------------------------- telegram vocabulary

/// Whether a claim is something a person is waiting for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallPriority {
    /// An operator's own traffic: outbox intents, reactions, menus, the poll.
    Durable,
    /// A draft snapshot the next snapshot replaces.
    Ephemeral,
}

/// Every priority, for exhaustiveness.
pub const ALL_CALL_PRIORITIES: [CallPriority; 2] = [CallPriority::Durable, CallPriority::Ephemeral];

impl CallPriority {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// The closed set of Telegram calls a claim may be made for.
///
/// It mirrors the private `WireMethod` in
/// [`crate::https_client`](crate) one for one, including `getUpdates`: a budget
/// that did not account the long poll would be a budget that under-counts by one
/// call every few seconds forever. The mirroring is asserted rather than
/// assumed — see `budget_methods_mirror_every_wire_method`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetedMethod {
    /// The inbound long poll.
    GetUpdates,
    /// One message to one chat.
    SendMessage,
    /// The fixed acknowledgement reaction.
    SetMessageReaction,
    /// The advertised command menu.
    SetMyCommands,
    /// One pressed inline button, acknowledged.
    AnswerCallbackQuery,
    /// One message's inline keyboard, replaced or stripped.
    EditMessageReplyMarkup,
    /// One streaming draft snapshot.
    SendMessageDraft,
    /// One streaming snapshot on the fallback path.
    EditMessageText,
}

/// Every budgeted method, for exhaustiveness.
pub const ALL_BUDGETED_METHODS: [BudgetedMethod; 8] = [
    BudgetedMethod::GetUpdates,
    BudgetedMethod::SendMessage,
    BudgetedMethod::SetMessageReaction,
    BudgetedMethod::SetMyCommands,
    BudgetedMethod::AnswerCallbackQuery,
    BudgetedMethod::EditMessageReplyMarkup,
    BudgetedMethod::SendMessageDraft,
    BudgetedMethod::EditMessageText,
];

impl BudgetedMethod {
    /// Telegram's own method name. Carries no credential.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetUpdates => "getUpdates",
            Self::SendMessage => "sendMessage",
            Self::SetMessageReaction => "setMessageReaction",
            Self::SetMyCommands => "setMyCommands",
            Self::AnswerCallbackQuery => "answerCallbackQuery",
            Self::EditMessageReplyMarkup => "editMessageReplyMarkup",
            Self::SendMessageDraft => "sendMessageDraft",
            Self::EditMessageText => "editMessageText",
        }
    }

    /// The method one validated outbound request will be issued as.
    #[must_use]
    pub const fn of(request: &TelegramOutbound) -> Self {
        match request {
            TelegramOutbound::SendMessage(_) => Self::SendMessage,
            TelegramOutbound::SetMessageReaction(_) => Self::SetMessageReaction,
            TelegramOutbound::SetMyCommands(_) => Self::SetMyCommands,
            TelegramOutbound::AnswerCallbackQuery(_) => Self::AnswerCallbackQuery,
            TelegramOutbound::EditMessageReplyMarkup(_) => Self::EditMessageReplyMarkup,
            TelegramOutbound::SendMessageDraft(_) => Self::SendMessageDraft,
            TelegramOutbound::EditMessageText(_) => Self::EditMessageText,
        }
    }
}

/// Why one claim was refused.
///
/// Content-free: a refusal names the ceiling it met and never the chat, the
/// text or the credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetRefusal {
    /// A whole-bot pause is live until its deadline.
    Paused {
        /// The instant polling and sending may resume.
        resume_after_ms: i64,
    },
    /// The bot-wide per-second ceiling has no ephemeral headroom.
    Global,
    /// This chat's own ceiling has no ephemeral headroom.
    Chat,
    /// This group's per-minute ceiling has no ephemeral headroom.
    Group,
    /// More chats are being tracked than this budget retains, and an ephemeral
    /// claim for an untracked one cannot be shown to be within its ceiling.
    Untracked,
}

/// Every refusal, for exhaustiveness.
pub const ALL_BUDGET_REFUSALS: [BudgetRefusal; 5] = [
    BudgetRefusal::Paused { resume_after_ms: 0 },
    BudgetRefusal::Global,
    BudgetRefusal::Chat,
    BudgetRefusal::Group,
    BudgetRefusal::Untracked,
];

impl BudgetRefusal {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::Paused { .. } => "transport_paused",
            Self::Global => "global_rate",
            Self::Chat => "chat_rate",
            Self::Group => "group_rate",
            Self::Untracked => "untracked_chat",
        }
    }
}

impl fmt::Display for BudgetRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Telegram call refused: {}", self.category())
    }
}

impl std::error::Error for BudgetRefusal {}

// ------------------------------------------------------------------ constants

/// Calls a bot may make in one second, across every chat.
pub const GLOBAL_CALLS: u64 = 30;
const GLOBAL_WINDOW_MS: u64 = 1_000;

/// Calls one chat absorbs as a burst, refilling at one a second.
///
/// Telegram's documented ceiling is the sustained rate; the burst is what makes
/// a reply that follows a reaction inside the same millisecond legal, which is
/// exactly the pair this bridge already sends.
pub const CHAT_BURST_CALLS: u64 = 4;
const CHAT_WINDOW_MS: u64 = 4_000;

/// Messages one group absorbs in a minute.
pub const GROUP_CALLS: u64 = 20;
const GROUP_WINDOW_MS: u64 = 60_000;

/// Whole calls the global bucket must still hold for a draft to be sent.
pub const GLOBAL_EPHEMERAL_HEADROOM: u64 = 10;
/// Whole calls a chat's bucket must still hold for a draft to be sent.
pub const CHAT_EPHEMERAL_HEADROOM: u64 = 2;
/// Whole calls a group's bucket must still hold for a draft to be sent.
pub const GROUP_EPHEMERAL_HEADROOM: u64 = 5;

const _: () = assert!(BucketSpec::is_exact(GLOBAL_CALLS, GLOBAL_WINDOW_MS));
const _: () = assert!(BucketSpec::is_exact(CHAT_BURST_CALLS, CHAT_WINDOW_MS));
const _: () = assert!(BucketSpec::is_exact(GROUP_CALLS, GROUP_WINDOW_MS));
// Headroom that met or exceeded a bucket's whole capacity would refuse every
// draft forever, which is a budget with the streaming turned off rather than a
// budget with headroom.
const _: () = assert!(GLOBAL_EPHEMERAL_HEADROOM < GLOBAL_CALLS);
const _: () = assert!(CHAT_EPHEMERAL_HEADROOM < CHAT_BURST_CALLS);
const _: () = assert!(GROUP_EPHEMERAL_HEADROOM < GROUP_CALLS);

/// Chats whose ceilings this budget remembers at once.
///
/// A bound rather than a map that grows with the number of chats a bot has ever
/// answered. A bucket at full capacity remembers nothing, so it is dropped
/// first; when every retained chat still owes something, a durable claim is
/// still made — Telegram's `429` remains the authority — and an ephemeral one is
/// refused, because a draft this budget cannot prove is within its chat's
/// ceiling is exactly the call worth skipping.
pub const MAX_TRACKED_CHATS: usize = 256;

/// Longest whole-bot pause one `429` may impose, in milliseconds.
///
/// The same 300-second ceiling the HTTPS client already clamps `retry-after` to,
/// restated here because a pause may also be restored from a durable row that a
/// different build wrote.
pub const MAX_PAUSE_MS: i64 = 300_000;

// -------------------------------------------------------------- the budget

/// What one chat owes.
#[derive(Clone, Copy, Debug)]
struct ChatBuckets {
    chat: TokenBucket,
    /// Present only for a group or supergroup, whose id Telegram makes negative.
    group: Option<TokenBucket>,
}

/// One bot's whole call budget.
///
/// Deterministic: two budgets fed the same claims at the same instants reach the
/// same state. Holds no credential, no client and no clock.
#[derive(Clone, Debug)]
pub struct TelegramCallBudget {
    global: TokenBucket,
    chats: BTreeMap<i64, ChatBuckets>,
    paused_until_ms: Option<i64>,
}

impl TelegramCallBudget {
    /// A budget with every bucket full, as of `now_ms`.
    #[must_use]
    pub fn new(now_ms: i64) -> Self {
        Self {
            global: TokenBucket::full(BucketSpec::exact(GLOBAL_CALLS, GLOBAL_WINDOW_MS), now_ms),
            chats: BTreeMap::new(),
            paused_until_ms: None,
        }
    }

    /// Record that Telegram refused the whole bot for `retry_after_ms`.
    ///
    /// Returns the instant traffic may resume, which is what a host persists.
    /// A pause is only ever extended: a second `429` arriving with a shorter
    /// interval than one already in force says nothing about the longer one.
    pub fn note_rate_limited(&mut self, retry_after_ms: u64, now_ms: i64) -> i64 {
        let delay = i64::try_from(retry_after_ms)
            .unwrap_or(MAX_PAUSE_MS)
            .clamp(1, MAX_PAUSE_MS);
        let deadline = now_ms.saturating_add(delay);
        self.restore_pause(deadline);
        self.paused_until_ms.unwrap_or(deadline)
    }

    /// Reinstate a pause a previous process wrote down.
    ///
    /// Called at startup with whatever the durable row holds, which is what
    /// makes a restart honour a `429` the previous generation received rather
    /// than walking straight back into it.
    pub fn restore_pause(&mut self, resume_after_ms: i64) {
        if resume_after_ms <= 0 {
            return;
        }
        self.paused_until_ms = Some(match self.paused_until_ms {
            Some(existing) => existing.max(resume_after_ms),
            None => resume_after_ms,
        });
    }

    /// The live pause deadline, if the bot is paused at `now_ms`.
    #[must_use]
    pub fn paused_until(&self, now_ms: i64) -> Option<i64> {
        self.paused_until_ms.filter(|deadline| *deadline > now_ms)
    }

    /// Chats whose ceilings are currently remembered. For metrics and tests.
    #[must_use]
    pub fn tracked_chats(&self) -> usize {
        self.chats.len()
    }

    /// Claim one call, debiting every ceiling it counts against.
    ///
    /// `chat_id` is `None` for a method that addresses no chat — the command
    /// menu, a callback acknowledgement, the long poll — which counts against
    /// the bot-wide ceiling only.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetRefusal::Paused`] while a whole-bot pause is live, for
    /// either priority. Returns one of the ceiling refusals for an
    /// [`CallPriority::Ephemeral`] claim without headroom. An
    /// [`CallPriority::Durable`] claim is never refused for want of tokens: see
    /// this module's own note on why.
    pub fn claim(
        &mut self,
        method: BudgetedMethod,
        chat_id: Option<i64>,
        priority: CallPriority,
        now_ms: i64,
    ) -> Result<(), BudgetRefusal> {
        let _ = method;
        if let Some(resume_after_ms) = self.paused_until(now_ms) {
            return Err(BudgetRefusal::Paused { resume_after_ms });
        }
        let chat_id = chat_id.filter(|id| *id != 0);
        match priority {
            CallPriority::Durable => {
                self.global.debit(now_ms);
                if let Some(chat_id) = chat_id {
                    // A durable claim for an untracked chat with no room left to
                    // track it is still made; it simply goes unremembered.
                    if let Some(buckets) = self.entry(chat_id, now_ms) {
                        buckets.chat.debit(now_ms);
                        if let Some(group) = buckets.group.as_mut() {
                            group.debit(now_ms);
                        }
                    }
                }
                Ok(())
            }
            CallPriority::Ephemeral => {
                if !self.global.admits(GLOBAL_EPHEMERAL_HEADROOM, now_ms) {
                    return Err(BudgetRefusal::Global);
                }
                if let Some(chat_id) = chat_id {
                    let Some(buckets) = self.entry(chat_id, now_ms) else {
                        return Err(BudgetRefusal::Untracked);
                    };
                    if !buckets.chat.admits(CHAT_EPHEMERAL_HEADROOM, now_ms) {
                        return Err(BudgetRefusal::Chat);
                    }
                    if let Some(group) = buckets.group.as_mut()
                        && !group.admits(GROUP_EPHEMERAL_HEADROOM, now_ms)
                    {
                        return Err(BudgetRefusal::Group);
                    }
                    buckets.chat.debit(now_ms);
                    if let Some(group) = buckets.group.as_mut() {
                        group.debit(now_ms);
                    }
                }
                self.global.debit(now_ms);
                Ok(())
            }
        }
    }

    /// The buckets for one chat, tracking it if there is room.
    ///
    /// `None` only when the retention bound is reached and every retained chat
    /// still owes something.
    fn entry(&mut self, chat_id: i64, now_ms: i64) -> Option<&mut ChatBuckets> {
        if !self.chats.contains_key(&chat_id) && self.chats.len() >= MAX_TRACKED_CHATS {
            // A full bucket carries no debt, so forgetting it changes no future
            // answer. Nothing else is evicted: a chat that still owes tokens is
            // the one whose ceiling is doing work.
            self.chats
                .retain(|_, buckets| !buckets.chat.is_full(now_ms));
            if self.chats.len() >= MAX_TRACKED_CHATS {
                return None;
            }
        }
        Some(self.chats.entry(chat_id).or_insert_with(|| ChatBuckets {
            chat: TokenBucket::full(BucketSpec::exact(CHAT_BURST_CALLS, CHAT_WINDOW_MS), now_ms),
            // Telegram gives every group and supergroup a negative id, and the
            // per-minute ceiling is theirs alone.
            group: (chat_id < 0).then(|| {
                TokenBucket::full(BucketSpec::exact(GROUP_CALLS, GROUP_WINDOW_MS), now_ms)
            }),
        }))
    }
}

// ------------------------------------------------------------- Slack budget

/// Slack methods used by native streaming and its message-edit fallback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SlackBudgetedMethod {
    ChatStartStream,
    ChatAppendStream,
    ChatStopStream,
    ChatPostMessage,
    ChatUpdate,
}

pub const ALL_SLACK_BUDGETED_METHODS: [SlackBudgetedMethod; 5] = [
    SlackBudgetedMethod::ChatStartStream,
    SlackBudgetedMethod::ChatAppendStream,
    SlackBudgetedMethod::ChatStopStream,
    SlackBudgetedMethod::ChatPostMessage,
    SlackBudgetedMethod::ChatUpdate,
];

impl SlackBudgetedMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChatStartStream => "chat.startStream",
            Self::ChatAppendStream => "chat.appendStream",
            Self::ChatStopStream => "chat.stopStream",
            Self::ChatPostMessage => "chat.postMessage",
            Self::ChatUpdate => "chat.update",
        }
    }

    const fn spec(self) -> BucketSpec {
        match self {
            // Slack documents start/stop as Tier 2 (20+ per minute), append as
            // Tier 4 (100+), and message writes as a special tier. The minimum
            // published values are the conservative values used here.
            Self::ChatStartStream | Self::ChatStopStream => BucketSpec::exact(20, 60_000),
            Self::ChatAppendStream => BucketSpec::exact(100, 60_000),
            Self::ChatPostMessage | Self::ChatUpdate => BucketSpec::exact(60, 60_000),
        }
    }

    const fn headroom(self) -> u64 {
        match self {
            Self::ChatAppendStream => 20,
            Self::ChatStartStream | Self::ChatStopStream => 4,
            Self::ChatPostMessage | Self::ChatUpdate => 10,
        }
    }

    const fn is_channel_message(self) -> bool {
        matches!(self, Self::ChatPostMessage | Self::ChatUpdate)
    }
}

const _: () = assert!(BucketSpec::is_exact(20, 60_000));
const _: () = assert!(BucketSpec::is_exact(100, 60_000));
const _: () = assert!(BucketSpec::is_exact(60, 60_000));

/// Why an ephemeral Slack call was skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackBudgetRefusal {
    Paused { resume_after_ms: i64 },
    Method,
    Channel,
    Untracked,
}

/// One workspace's per-method Slack budget.
///
/// Slack scopes a `429` to the same method in the same workspace. Consequently
/// pauses live beside method buckets instead of freezing the whole client.
#[derive(Clone, Debug)]
pub struct SlackCallBudget {
    methods: BTreeMap<SlackBudgetedMethod, TokenBucket>,
    paused_until_ms: BTreeMap<SlackBudgetedMethod, i64>,
    channels: BTreeMap<String, TokenBucket>,
}

impl SlackCallBudget {
    #[must_use]
    pub fn new(now_ms: i64) -> Self {
        let methods = ALL_SLACK_BUDGETED_METHODS
            .into_iter()
            .map(|method| (method, TokenBucket::full(method.spec(), now_ms)))
            .collect();
        Self {
            methods,
            paused_until_ms: BTreeMap::new(),
            channels: BTreeMap::new(),
        }
    }

    pub fn note_rate_limited(
        &mut self,
        method: SlackBudgetedMethod,
        retry_after_ms: u64,
        now_ms: i64,
    ) -> i64 {
        let delay = i64::try_from(retry_after_ms)
            .unwrap_or(MAX_PAUSE_MS)
            .clamp(1, MAX_PAUSE_MS);
        let deadline = now_ms.saturating_add(delay);
        self.paused_until_ms
            .entry(method)
            .and_modify(|existing| *existing = (*existing).max(deadline))
            .or_insert(deadline);
        self.paused_until_ms[&method]
    }

    #[must_use]
    pub fn paused_until(&self, method: SlackBudgetedMethod, now_ms: i64) -> Option<i64> {
        self.paused_until_ms
            .get(&method)
            .copied()
            .filter(|deadline| *deadline > now_ms)
    }

    pub fn claim(
        &mut self,
        method: SlackBudgetedMethod,
        channel: Option<&str>,
        priority: CallPriority,
        now_ms: i64,
    ) -> Result<(), SlackBudgetRefusal> {
        if let Some(resume_after_ms) = self.paused_until(method, now_ms) {
            return Err(SlackBudgetRefusal::Paused { resume_after_ms });
        }
        let bucket = self.methods.get_mut(&method).expect("closed method set");
        if priority == CallPriority::Ephemeral && !bucket.admits(method.headroom(), now_ms) {
            return Err(SlackBudgetRefusal::Method);
        }
        if method.is_channel_message() {
            let channel = channel.filter(|value| !value.is_empty());
            if let Some(channel) = channel {
                if !self.channels.contains_key(channel) && self.channels.len() >= MAX_TRACKED_CHATS
                {
                    self.channels.retain(|_, bucket| !bucket.is_full(now_ms));
                    if self.channels.len() >= MAX_TRACKED_CHATS {
                        return Err(SlackBudgetRefusal::Untracked);
                    }
                }
                let channel_bucket = self.channels.entry(channel.to_owned()).or_insert_with(|| {
                    TokenBucket::full(BucketSpec::exact(CHAT_BURST_CALLS, CHAT_WINDOW_MS), now_ms)
                });
                if priority == CallPriority::Ephemeral
                    && !channel_bucket.admits(CHAT_EPHEMERAL_HEADROOM, now_ms)
                {
                    return Err(SlackBudgetRefusal::Channel);
                }
                channel_bucket.debit(now_ms);
            }
        }
        bucket.debit(now_ms);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https_client::{
        ALL_WIRE_METHOD_NAMES, EditMessageTextRequest, SendMessageDraftRequest, SendMessageRequest,
    };

    const T0: i64 = 1_700_000_000_000;
    const PRIVATE_CHAT: i64 = 7_654_321;
    const GROUP_CHAT: i64 = -1_002_003_004;

    fn budget() -> TelegramCallBudget {
        TelegramCallBudget::new(T0)
    }

    #[test]
    fn slack_streaming_preserves_method_headroom_for_final_calls() {
        let mut budget = SlackCallBudget::new(T0);
        for _ in 0..80 {
            budget
                .claim(
                    SlackBudgetedMethod::ChatAppendStream,
                    Some("C0RESERVED"),
                    CallPriority::Ephemeral,
                    T0,
                )
                .expect("tier-four capacity before headroom");
        }
        assert_eq!(
            budget.claim(
                SlackBudgetedMethod::ChatAppendStream,
                Some("C0RESERVED"),
                CallPriority::Ephemeral,
                T0,
            ),
            Err(SlackBudgetRefusal::Method)
        );
        budget
            .claim(
                SlackBudgetedMethod::ChatStopStream,
                Some("C0RESERVED"),
                CallPriority::Durable,
                T0,
            )
            .expect("the final stop is durable");
    }

    #[test]
    fn a_slack_retry_after_pauses_only_the_same_method() {
        let mut budget = SlackCallBudget::new(T0);
        let deadline = budget.note_rate_limited(SlackBudgetedMethod::ChatAppendStream, 30_000, T0);
        assert_eq!(deadline, T0 + 30_000);
        assert_eq!(
            budget.claim(
                SlackBudgetedMethod::ChatAppendStream,
                Some("C0RESERVED"),
                CallPriority::Ephemeral,
                T0 + 1,
            ),
            Err(SlackBudgetRefusal::Paused {
                resume_after_ms: deadline
            })
        );
        budget
            .claim(
                SlackBudgetedMethod::ChatStopStream,
                Some("C0RESERVED"),
                CallPriority::Durable,
                T0 + 1,
            )
            .expect("a different method/workspace window remains available");
    }

    #[test]
    fn slack_fallback_edits_share_one_per_channel_bucket() {
        let mut budget = SlackCallBudget::new(T0);
        budget
            .claim(
                SlackBudgetedMethod::ChatPostMessage,
                Some("C0RESERVED"),
                CallPriority::Ephemeral,
                T0,
            )
            .expect("fallback post");
        budget
            .claim(
                SlackBudgetedMethod::ChatUpdate,
                Some("C0RESERVED"),
                CallPriority::Ephemeral,
                T0,
            )
            .expect("fallback edit within the bounded burst");
        assert_eq!(budget.channels.len(), 1);
    }

    #[test]
    fn budget_methods_mirror_every_wire_method() {
        let budgeted: Vec<&str> = ALL_BUDGETED_METHODS
            .iter()
            .map(|method| method.as_str())
            .collect();
        let mut sorted = budgeted.clone();
        sorted.sort_unstable();
        let mut wire: Vec<&str> = ALL_WIRE_METHOD_NAMES.to_vec();
        wire.sort_unstable();
        assert_eq!(
            sorted, wire,
            "every request path the client can render must be budgeted, and no other"
        );
        // Names are distinct, so the mirror above is a bijection rather than a
        // set that happens to be the same size.
        sorted.dedup();
        assert_eq!(sorted.len(), ALL_BUDGETED_METHODS.len());
        assert_eq!(ALL_CALL_PRIORITIES.len(), 2);
        assert_eq!(ALL_BUDGET_REFUSALS.len(), 5);
        for refusal in ALL_BUDGET_REFUSALS {
            assert!(!refusal.category().is_empty());
        }
        for priority in ALL_CALL_PRIORITIES {
            assert!(!priority.as_str().is_empty());
        }
    }

    #[test]
    fn every_outbound_request_names_its_own_method() {
        let send = TelegramOutbound::SendMessage(
            SendMessageRequest::new(PRIVATE_CHAT, "hi", None).expect("message"),
        );
        assert_eq!(BudgetedMethod::of(&send), BudgetedMethod::SendMessage);
        assert_eq!(BudgetedMethod::of(&send).as_str(), send.method_name());

        let draft = TelegramOutbound::SendMessageDraft(
            SendMessageDraftRequest::new(PRIVATE_CHAT, "working").expect("draft"),
        );
        assert_eq!(BudgetedMethod::of(&draft), BudgetedMethod::SendMessageDraft);
        assert_eq!(BudgetedMethod::of(&draft).as_str(), draft.method_name());

        let edit = TelegramOutbound::EditMessageText(
            EditMessageTextRequest::new(PRIVATE_CHAT, 31, "working").expect("edit"),
        );
        assert_eq!(BudgetedMethod::of(&edit), BudgetedMethod::EditMessageText);
        assert_eq!(BudgetedMethod::of(&edit).as_str(), edit.method_name());
    }

    #[test]
    fn every_production_rate_refills_in_whole_units() {
        for (calls, window_ms) in [
            (GLOBAL_CALLS, GLOBAL_WINDOW_MS),
            (CHAT_BURST_CALLS, CHAT_WINDOW_MS),
            (GROUP_CALLS, GROUP_WINDOW_MS),
        ] {
            let spec = BucketSpec::new(calls, window_ms).expect("an exact production rate");
            assert_eq!(spec.capacity_calls(), calls);
            // One whole window refills one whole capacity, exactly.
            let mut bucket = TokenBucket::full(spec, T0);
            for _ in 0..calls {
                bucket.debit(T0);
            }
            assert_eq!(bucket.available(T0), 0);
            assert_eq!(
                bucket.available(T0 + i64::try_from(window_ms).expect("window fits")),
                calls * TOKEN_SCALE
            );
        }
        // A rate that would truncate is not representable at all.
        assert_eq!(BucketSpec::new(7, 1_000_000_000), None);
        assert_eq!(BucketSpec::new(0, 1_000), None);
        assert_eq!(BucketSpec::new(1, 0), None);
    }

    #[test]
    fn a_durable_claim_is_never_refused_for_want_of_tokens() {
        let mut budget = budget();
        // Far past every ceiling this bot has, inside one millisecond.
        for _ in 0..500 {
            budget
                .claim(
                    BudgetedMethod::SendMessage,
                    Some(GROUP_CHAT),
                    CallPriority::Durable,
                    T0,
                )
                .expect("a durable claim answers to Telegram's 429, not to a local counter");
        }
        // And the debt is real: nothing ephemeral gets through afterwards.
        assert_eq!(
            budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(GROUP_CHAT),
                CallPriority::Ephemeral,
                T0,
            ),
            Err(BudgetRefusal::Global)
        );
    }

    #[test]
    fn an_ephemeral_claim_stops_at_the_global_headroom_line() {
        let mut budget = budget();
        // Each draft addresses its own chat, so only the global ceiling binds.
        let admitted = (0..GLOBAL_CALLS + 5)
            .filter(|index| {
                budget
                    .claim(
                        BudgetedMethod::SendMessageDraft,
                        Some(1_000 + i64::try_from(*index).expect("index fits")),
                        CallPriority::Ephemeral,
                        T0,
                    )
                    .is_ok()
            })
            .count();
        assert_eq!(
            u64::try_from(admitted).expect("count fits"),
            GLOBAL_CALLS - GLOBAL_EPHEMERAL_HEADROOM,
            "drafts must stop with the configured headroom still unspent"
        );
        assert_eq!(
            u64::from(budget.global.available(T0) >= TOKEN_SCALE * GLOBAL_EPHEMERAL_HEADROOM),
            1
        );
    }

    #[test]
    fn streaming_can_never_starve_a_final_reply() {
        let mut budget = budget();
        // A pathological run: a draft attempted every millisecond for a minute,
        // in the same group the answer will land in.
        for step in 0..60_000 {
            let _ = budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(GROUP_CHAT),
                CallPriority::Ephemeral,
                T0 + step,
            );
        }
        // The final answer, and the reaction and keyboard strip beside it, all
        // still go: an ephemeral claim cannot pause the bot, and a durable claim
        // is refused by nothing else.
        for method in [
            BudgetedMethod::SendMessage,
            BudgetedMethod::SetMessageReaction,
            BudgetedMethod::EditMessageReplyMarkup,
        ] {
            budget
                .claim(method, Some(GROUP_CHAT), CallPriority::Durable, T0 + 60_000)
                .expect("a final reply is never starved by streaming");
        }
        // And the group's own per-minute ceiling bounded the streaming while it
        // ran. A budget that starts full has a minute's worth of burst in hand
        // before the refill rate is the only thing left, so one minute admits at
        // most one capacity plus one window — never an unbounded flood.
        let mut fresh = TelegramCallBudget::new(T0);
        let drafts = (0..60_000)
            .filter(|step| {
                fresh
                    .claim(
                        BudgetedMethod::SendMessageDraft,
                        Some(GROUP_CHAT),
                        CallPriority::Ephemeral,
                        T0 + step,
                    )
                    .is_ok()
            })
            .count();
        assert!(
            u64::try_from(drafts).expect("count fits") <= 2 * GROUP_CALLS,
            "a group drew {drafts} drafts in its first minute"
        );
        // The second minute has no burst left, so it is the sustained rate
        // alone — and that rate is the group's own ceiling.
        let second_minute = (60_000..120_000)
            .filter(|step| {
                fresh
                    .claim(
                        BudgetedMethod::SendMessageDraft,
                        Some(GROUP_CHAT),
                        CallPriority::Ephemeral,
                        T0 + step,
                    )
                    .is_ok()
            })
            .count();
        assert!(
            u64::try_from(second_minute).expect("count fits") <= GROUP_CALLS,
            "a group drew {second_minute} drafts in a sustained minute"
        );
    }

    #[test]
    fn a_chat_refills_at_one_call_a_second_after_its_burst() {
        let mut budget = budget();
        for _ in 0..CHAT_BURST_CALLS - CHAT_EPHEMERAL_HEADROOM {
            budget
                .claim(
                    BudgetedMethod::SendMessageDraft,
                    Some(PRIVATE_CHAT),
                    CallPriority::Ephemeral,
                    T0,
                )
                .expect("the burst is spendable at once");
        }
        assert_eq!(
            budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(PRIVATE_CHAT),
                CallPriority::Ephemeral,
                T0,
            ),
            Err(BudgetRefusal::Chat)
        );
        // One second later exactly one more draft has been earned.
        budget
            .claim(
                BudgetedMethod::SendMessageDraft,
                Some(PRIVATE_CHAT),
                CallPriority::Ephemeral,
                T0 + 1_000,
            )
            .expect("one call a second");
        assert_eq!(
            budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(PRIVATE_CHAT),
                CallPriority::Ephemeral,
                T0 + 1_000,
            ),
            Err(BudgetRefusal::Chat)
        );
    }

    /// A group has two ceilings over it, and the tighter one has to be the one
    /// that binds. At one draft a second the chat bucket keeps up exactly — its
    /// sustained rate *is* one a second — so every refusal that appears is the
    /// group's own per-minute ceiling and nothing else.
    #[test]
    fn a_group_meets_its_own_per_minute_ceiling_before_the_chats() {
        let mut budget = budget();
        let mut admitted = 0_u64;
        let mut group_refusals = 0_u64;
        for step in 0..60_i64 {
            match budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(GROUP_CHAT),
                CallPriority::Ephemeral,
                T0 + step * 1_000,
            ) {
                Ok(()) => admitted += 1,
                Err(BudgetRefusal::Group) => group_refusals += 1,
                Err(other) => panic!("the group ceiling must bind first, not {other:?}"),
            }
        }
        assert!(group_refusals > 0, "the group ceiling never bound");
        assert!(
            admitted <= 2 * GROUP_CALLS,
            "a group admitted {admitted} drafts in a minute"
        );
        // And the group's answer is still yes to the durable reply the run ends
        // with, which is the whole point of refusing the drafts.
        budget
            .claim(
                BudgetedMethod::SendMessage,
                Some(GROUP_CHAT),
                CallPriority::Durable,
                T0 + 60_000,
            )
            .expect("the final answer is not a draft");
    }

    #[test]
    fn a_pause_gates_every_priority_including_the_long_poll() {
        let mut budget = budget();
        let deadline = budget.note_rate_limited(12_000, T0);
        assert_eq!(deadline, T0 + 12_000);
        assert_eq!(budget.paused_until(T0), Some(deadline));
        for priority in ALL_CALL_PRIORITIES {
            for method in ALL_BUDGETED_METHODS {
                assert_eq!(
                    budget.claim(method, Some(PRIVATE_CHAT), priority, T0 + 11_999),
                    Err(BudgetRefusal::Paused {
                        resume_after_ms: deadline
                    }),
                    "{} at {} must wait out the pause",
                    method.as_str(),
                    priority.as_str()
                );
            }
        }
        // At the deadline the bot is free again, and the poll is the first thing
        // through.
        assert_eq!(budget.paused_until(deadline), None);
        budget
            .claim(
                BudgetedMethod::GetUpdates,
                None,
                CallPriority::Durable,
                deadline,
            )
            .expect("the pause ends at its deadline");
    }

    #[test]
    fn a_pause_is_extended_and_never_shortened() {
        let mut budget = budget();
        assert_eq!(budget.note_rate_limited(30_000, T0), T0 + 30_000);
        // A shorter interval arriving second says nothing about the longer one.
        assert_eq!(budget.note_rate_limited(1_000, T0), T0 + 30_000);
        assert_eq!(budget.note_rate_limited(60_000, T0), T0 + 60_000);
        // Telegram's own ceiling, and a value no header could have produced.
        let mut clamped = TelegramCallBudget::new(T0);
        assert_eq!(clamped.note_rate_limited(u64::MAX, T0), T0 + MAX_PAUSE_MS);
        let mut floored = TelegramCallBudget::new(T0);
        assert_eq!(floored.note_rate_limited(0, T0), T0 + 1);
        // A restored deadline from a durable row behaves identically.
        let mut restored = TelegramCallBudget::new(T0);
        restored.restore_pause(T0 + 5_000);
        restored.restore_pause(T0 + 1_000);
        assert_eq!(restored.paused_until(T0), Some(T0 + 5_000));
        restored.restore_pause(-1);
        assert_eq!(restored.paused_until(T0), Some(T0 + 5_000));
    }

    #[test]
    fn the_tracked_chat_map_is_bounded_and_drops_only_settled_chats() {
        let mut budget = budget();
        // Three calls each, so every chat still owes something a second later —
        // a bucket that has settled back to full is one the map may forget.
        for index in 0..MAX_TRACKED_CHATS {
            for _ in 0..3 {
                budget
                    .claim(
                        BudgetedMethod::SendMessage,
                        Some(i64::try_from(index).expect("index fits") + 1),
                        CallPriority::Durable,
                        T0,
                    )
                    .expect("durable");
            }
        }
        assert_eq!(budget.tracked_chats(), MAX_TRACKED_CHATS);
        // One second on, the bot-wide bucket is full again but every retained
        // chat still owes a token, so a new chat cannot be tracked and its draft
        // is refused rather than guessed at.
        assert_eq!(
            budget.claim(
                BudgetedMethod::SendMessageDraft,
                Some(999_999),
                CallPriority::Ephemeral,
                T0 + 1_000,
            ),
            Err(BudgetRefusal::Untracked)
        );
        // The durable claim for the same untracked chat is still made.
        budget
            .claim(
                BudgetedMethod::SendMessage,
                Some(999_999),
                CallPriority::Durable,
                T0 + 1_000,
            )
            .expect("durable");
        // Once the retained chats have settled they are forgotten, and the map
        // never exceeds its bound.
        budget
            .claim(
                BudgetedMethod::SendMessage,
                Some(888_888),
                CallPriority::Durable,
                T0 + 10_000,
            )
            .expect("durable");
        assert!(budget.tracked_chats() <= MAX_TRACKED_CHATS);
    }

    #[test]
    fn a_clock_that_steps_backwards_refills_nothing() {
        let mut bucket = TokenBucket::full(BucketSpec::exact(GLOBAL_CALLS, GLOBAL_WINDOW_MS), T0);
        for _ in 0..GLOBAL_CALLS {
            bucket.debit(T0);
        }
        assert_eq!(bucket.available(T0 - 60_000), 0);
        // And the observation did not rewind, so the same interval is not
        // refilled twice when the clock recovers.
        assert_eq!(
            bucket.available(T0 + 100),
            100 * (GLOBAL_CALLS * TOKEN_SCALE / GLOBAL_WINDOW_MS)
        );
    }

    #[test]
    fn a_method_with_no_chat_counts_only_against_the_bot() {
        let mut budget = budget();
        for method in [
            BudgetedMethod::GetUpdates,
            BudgetedMethod::SetMyCommands,
            BudgetedMethod::AnswerCallbackQuery,
        ] {
            budget
                .claim(method, None, CallPriority::Durable, T0)
                .expect("durable");
        }
        assert_eq!(budget.tracked_chats(), 0);
        // A chat id of zero addresses no chat and is treated the same way.
        budget
            .claim(
                BudgetedMethod::SendMessage,
                Some(0),
                CallPriority::Durable,
                T0,
            )
            .expect("durable");
        assert_eq!(budget.tracked_chats(), 0);
    }
}
