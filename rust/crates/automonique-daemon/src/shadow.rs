// SPDX-License-Identifier: Elastic-2.0

//! Effect suppression: recording decorators that decide and never do.
//!
//! Every externally visible effect in this daemon already passes through a
//! narrow injected trait — [`crate::slack::SlackTicketPoster`] for Slack,
//! [`crate::telegram_bridge::TicketActionSurface`] for support-backend ticket
//! mutations — so shadow mode needs no new architecture. It needs one recording
//! decorator per trait and a per-scope flag that selects it, which is what this
//! module is.
//!
//! # The property this module exists to guarantee
//!
//! **A shadow decorator performs no external effect.** Not "usually", not
//! "unless a code path was missed": every method here either records an
//! [`IntendedActionEnvelope`] and returns a synthetic answer, or records the
//! deliberate silence. None of them holds a client, a token or a socket — the
//! types make that unrepresentable, because a decorator with no inner surface
//! has nothing to call. `tests/shadow_zero_effect.rs` asserts it from the
//! outside as well, driving the real router and proving a spying fake surface
//! received nothing.
//!
//! A shadow harness whose shadow half can still post is worse than no harness,
//! because it converts a *missing* gate into a *false* one.
//!
//! # Synthetic answers, and why they are shaped like the real ones
//!
//! [`ShadowTicketSurface::confirm_ticket`] answers with an approved receipt even
//! though nothing was confirmed. That is deliberate. The comparison this harness
//! feeds is between the two engines' *decision streams*, so a decorator that
//! answered failure where production answers success would make the router take
//! a different branch and would record a divergence the harness itself caused.
//! The synthetic receipts model the outcome the real surface would have
//! returned, and every synthetic identifier is spelled so it cannot be mistaken
//! for a real one ([`SYNTHETIC_PREFIX`]).
//!
//! The one exception is the modal: a Slack modal is a synchronous UI affordance
//! rather than a durable effect, and there is no envelope kind for it. Shadow
//! mode records the suppression as an explicit [`IntendedAction::no_action`] and
//! returns the refusal the trait already defaults to, so a suppressed modal is
//! diffable rather than invisible.
//!
//! # Correlation, and the reference engine's side
//!
//! [`LegacyObserver`] records what the reference bot published on shared
//! surfaces as `engine=legacy-observed`. Its identity is configuration
//! ([`crate::shadow_config`]), never a literal, and the ingest taps *upstream*
//! of the Slack event filter that drops bot-authored messages — otherwise the
//! one engine the harness exists to compare against would be filtered out before
//! it was ever seen.
//!
//! A legacy message carries no source key of ours, so it is correlated by
//! channel and thread timestamp to the inbound event that provoked it. A message
//! with no correlation is reported [`Observation::Uncorrelated`] rather than
//! filed under a guessed key: an envelope attributed to the wrong source event
//! would be a false comparison, which is worse than a missing one.
//!
//! # There is no ambient clock in a test
//!
//! [`ShadowClock`] is either the host clock or a fixed value. A replay under a
//! fixed clock produces byte-identical envelopes, which is what makes the
//! golden-trace corpus deterministic.

use automonique_protocol::parity::{
    ActionKind, IntendedAction, IntendedActionEnvelope, ParityEngine, ParityError,
};
use automonique_store::shadow_comparisons::{
    IntendedActionRecord, ShadowComparisonStore, ShadowError,
};
use automonique_support_connector::{
    TicketDecision, TicketDecisionOutcome, TicketDecisionReceipt, TicketDispatchReceipt,
    TicketJobStatus, TicketStatus, TicketWorkspace,
};

use crate::slack::SlackTicketPoster;
use crate::telegram_bridge::TicketActionSurface;

/// Prefix every synthetic identifier a shadow decorator mints carries.
///
/// A synthetic value must be unmistakable. An operator reading a recorded
/// envelope, or a later comparison, has to be able to tell at a glance that no
/// job by this name exists anywhere.
pub const SYNTHETIC_PREFIX: &str = "shadow-synthetic-";

/// Largest number of thread correlations one observer retains.
///
/// A refusing ceiling rather than an evicting one, matching the durable side:
/// an observer that silently forgot a correlation would start attributing the
/// reference engine's messages to nothing.
pub const MAX_CORRELATIONS: usize = 4_096;

/// Which implementations one scope is built with.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ShadowMode {
    /// The production surfaces. Effects happen.
    ///
    /// The default, and deliberately so: an unconfigured daemon must behave
    /// exactly as it did before this module existed.
    #[default]
    Primary,
    /// The recording decorators. No effect leaves the process.
    Shadow,
}

impl ShadowMode {
    /// Stable machine-oriented spelling, and the configuration file's grammar.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Shadow => "shadow",
        }
    }

    /// Map a configured spelling onto a mode this build defines.
    ///
    /// Unknown spellings are refused by the caller rather than defaulted here:
    /// a typo that silently selected `primary` would leave a scope executing
    /// when an operator believed it suppressed.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "primary" => Some(Self::Primary),
            "shadow" => Some(Self::Shadow),
            _ => None,
        }
    }

    /// Whether this mode suppresses effects.
    #[must_use]
    pub const fn is_shadow(self) -> bool {
        matches!(self, Self::Shadow)
    }
}

/// Where a recorded envelope goes.
///
/// A trait so the hermetic tests and the golden-trace replay can record into
/// memory while the daemon records into its sibling database, with no code path
/// differing between the two.
pub trait EnvelopeSink {
    /// Take custody of one envelope.
    ///
    /// # Errors
    ///
    /// Returns the sink's own refusal. A sink that is full refuses; nothing
    /// here evicts.
    fn record(&mut self, envelope: &IntendedActionEnvelope) -> Result<(), SinkError>;
}

/// A refusal from an envelope sink.
#[derive(Debug)]
pub enum SinkError {
    /// The durable store refused the record.
    Store(ShadowError),
    /// The sink holds its capacity.
    Full {
        /// Capacity of the sink that refused.
        capacity: usize,
    },
}

impl SinkError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Store(error) => error.category(),
            Self::Full { .. } => "sink_full",
        }
    }
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "shadow store refused envelope: {error}"),
            Self::Full { capacity } => {
                write!(formatter, "envelope sink holds its capacity of {capacity}")
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// An in-memory sink, for hermetic replay and for tests.
#[derive(Debug, Default)]
pub struct MemorySink {
    envelopes: Vec<IntendedActionEnvelope>,
    capacity: Option<usize>,
}

impl MemorySink {
    /// An unbounded in-process sink.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            envelopes: Vec::new(),
            capacity: None,
        }
    }

    /// A sink that refuses past `capacity`.
    #[must_use]
    pub const fn with_capacity(capacity: usize) -> Self {
        Self {
            envelopes: Vec::new(),
            capacity: Some(capacity),
        }
    }

    /// Everything recorded, in record order.
    #[must_use]
    pub fn envelopes(&self) -> &[IntendedActionEnvelope] {
        &self.envelopes
    }

    /// Take the recorded envelopes, leaving the sink empty.
    #[must_use]
    pub fn take(&mut self) -> Vec<IntendedActionEnvelope> {
        std::mem::take(&mut self.envelopes)
    }
}

impl EnvelopeSink for MemorySink {
    fn record(&mut self, envelope: &IntendedActionEnvelope) -> Result<(), SinkError> {
        if let Some(capacity) = self.capacity
            && self.envelopes.len() >= capacity
        {
            return Err(SinkError::Full { capacity });
        }
        self.envelopes.push(envelope.clone());
        Ok(())
    }
}

/// A sink that writes to the durable shadow-comparison database.
#[derive(Debug)]
pub struct DurableSink {
    store: ShadowComparisonStore,
}

impl DurableSink {
    /// Wrap an opened store.
    #[must_use]
    pub const fn new(store: ShadowComparisonStore) -> Self {
        Self { store }
    }

    /// The store beneath, for reads.
    #[must_use]
    pub const fn store(&self) -> &ShadowComparisonStore {
        &self.store
    }
}

impl EnvelopeSink for DurableSink {
    fn record(&mut self, envelope: &IntendedActionEnvelope) -> Result<(), SinkError> {
        let bytes = envelope.to_canonical_bytes();
        let digest = envelope.content_digest().to_hex();
        self.store
            .record_intended_action(IntendedActionRecord {
                scope: envelope.scope(),
                source_key: envelope.source_key(),
                engine: envelope.engine().as_str(),
                sequence: i64::from(envelope.sequence()),
                envelope: &bytes,
                envelope_digest: &digest,
                observed_at_ms: envelope.observed_at_ms(),
            })
            .map(|_| ())
            .map_err(SinkError::Store)
    }
}

/// The clock an envelope's `observed_at_ms` comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowClock {
    /// The host clock, in epoch milliseconds.
    Host,
    /// A fixed value, so a replay is byte-identical.
    Fixed(i64),
}

impl ShadowClock {
    fn now_ms(self) -> i64 {
        match self {
            Self::Host => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
                .unwrap_or(0),
            Self::Fixed(value) => value,
        }
    }
}

/// The shared state every decorator on one scope records through.
///
/// Holds the scope, the source key currently being handled, the next sequence
/// number for that key, and the sink. It performs no IO of its own beyond
/// handing the envelope to the sink.
#[derive(Debug)]
pub struct ShadowRecorder<S> {
    scope: String,
    engine: ParityEngine,
    source_key: Option<String>,
    sequence: u32,
    clock: ShadowClock,
    sink: S,
    refusals: usize,
}

impl<S: EnvelopeSink> ShadowRecorder<S> {
    /// Start recording one scope's decisions.
    #[must_use]
    pub fn new(scope: &str, engine: ParityEngine, clock: ShadowClock, sink: S) -> Self {
        Self {
            scope: scope.to_owned(),
            engine,
            source_key: None,
            sequence: 0,
            clock,
            sink,
            refusals: 0,
        }
    }

    /// Begin the decisions provoked by one inbound event.
    ///
    /// Resets the sequence, so envelope `n` is always "the *n*th thing this
    /// engine decided for this event" rather than a process-lifetime counter
    /// that could never line up between two engines.
    pub fn begin_source(&mut self, source_key: &str) {
        self.source_key = Some(source_key.to_owned());
        self.sequence = 0;
    }

    /// The scope being recorded.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The sink beneath.
    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    /// The sink beneath, mutably.
    pub const fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// How many envelopes this recorder could not record.
    ///
    /// Counted rather than propagated: a decorator's whole job is to *not*
    /// change what the engine decides, so a full sink must not turn into a
    /// refusal the router sees and branches on. The count is the operator's
    /// signal that a recording gap exists.
    #[must_use]
    pub const fn refusals(&self) -> usize {
        self.refusals
    }

    /// Record one intended action against the current source key.
    ///
    /// Returns `false` when nothing was recorded — because no source key is
    /// open, because the action could not be built, or because the sink
    /// refused. Never propagates, for the reason [`Self::refusals`] gives.
    pub fn record(&mut self, action: Result<IntendedAction, ParityError>) -> bool {
        let Some(source_key) = self.source_key.clone() else {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        };
        let Ok(action) = action else {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        };
        let envelope = IntendedActionEnvelope::new(
            &self.scope,
            &source_key,
            self.engine,
            self.sequence,
            action,
            self.clock.now_ms(),
        );
        let Ok(envelope) = envelope else {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        };
        if self.sink.record(&envelope).is_err() {
            self.refusals = self.refusals.saturating_add(1);
            return false;
        }
        self.sequence = self.sequence.saturating_add(1);
        true
    }
}

/// A [`SlackTicketPoster`] that decides and never posts.
///
/// It holds no client. There is no field through which a Slack call could be
/// made, which is the strongest form the zero-effect property can take.
#[derive(Debug)]
pub struct ShadowPoster<S> {
    recorder: ShadowRecorder<S>,
}

impl<S: EnvelopeSink> ShadowPoster<S> {
    /// Wrap a recorder as a Slack poster.
    #[must_use]
    pub const fn new(recorder: ShadowRecorder<S>) -> Self {
        Self { recorder }
    }

    /// The recorder beneath.
    #[must_use]
    pub const fn recorder(&self) -> &ShadowRecorder<S> {
        &self.recorder
    }

    /// The recorder beneath, mutably.
    pub const fn recorder_mut(&mut self) -> &mut ShadowRecorder<S> {
        &mut self.recorder
    }
}

impl<S: EnvelopeSink> SlackTicketPoster for ShadowPoster<S> {
    fn begin_source(&mut self, source_key: &str) {
        self.recorder.begin_source(source_key);
    }

    fn post_thread(
        &mut self,
        channel: &automonique_slack_connector::ChannelId,
        parent: &automonique_slack_connector::MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        self.recorder.record(IntendedAction::new(
            ActionKind::SlackThreadReply,
            vec![channel.to_string(), parent.to_string(), text.to_owned()],
        ));
        Ok(())
    }

    fn post_channel(
        &mut self,
        channel: &automonique_slack_connector::ChannelId,
        text: &str,
    ) -> Result<(), ()> {
        self.recorder.record(IntendedAction::new(
            ActionKind::SlackChannelPost,
            vec![channel.to_string(), text.to_owned()],
        ));
        Ok(())
    }

    fn post_approval_card(
        &mut self,
        channel: &automonique_slack_connector::ChannelId,
        parent: &automonique_slack_connector::MessageTs,
        receipt: &TicketDispatchReceipt,
        _manage_url: Option<&crate::manage_config::ManageUrl>,
    ) -> Result<(), ()> {
        // Overridden rather than inherited: the trait's default renders a card
        // as a thread reply, which would record the wrong action kind and make
        // an approval card indistinguishable from an ordinary reply in the
        // comparison.
        self.recorder.record(IntendedAction::new(
            ActionKind::SlackApprovalCard,
            vec![
                channel.to_string(),
                parent.to_string(),
                receipt.job_id.clone(),
                receipt.issue_url.clone(),
                receipt.issue_title.clone(),
            ],
        ));
        Ok(())
    }

    fn open_reject_modal(
        &mut self,
        _trigger_id: &str,
        _job_id: &str,
        _channel: &automonique_slack_connector::ChannelId,
        _message_ts: &automonique_slack_connector::MessageTs,
    ) -> Result<(), ()> {
        self.recorder
            .record(IntendedAction::no_action("shadow-modal-suppressed"));
        Err(())
    }

    fn update_decision(
        &mut self,
        channel: &automonique_slack_connector::ChannelId,
        message_ts: &automonique_slack_connector::MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        self.recorder.record(IntendedAction::new(
            ActionKind::SlackDecisionUpdate,
            vec![channel.to_string(), message_ts.to_string(), text.to_owned()],
        ));
        Ok(())
    }

    fn publish_home(
        &mut self,
        _user: &automonique_slack_connector::UserId,
        _is_admin: bool,
        _pending_count: usize,
    ) -> Result<(), ()> {
        self.recorder
            .record(IntendedAction::no_action("shadow-home-suppressed"));
        Err(())
    }
}

/// A [`TicketActionSurface`] that decides and never mutates.
///
/// Like [`ShadowPoster`] it holds no client. Its answers are synthetic and
/// shaped like the real ones, for the reason the module documentation gives.
#[derive(Debug)]
pub struct ShadowTicketSurface<S> {
    recorder: ShadowRecorder<S>,
}

impl<S: EnvelopeSink> ShadowTicketSurface<S> {
    /// Wrap a recorder as a ticket surface.
    #[must_use]
    pub const fn new(recorder: ShadowRecorder<S>) -> Self {
        Self { recorder }
    }

    /// The recorder beneath.
    #[must_use]
    pub const fn recorder(&self) -> &ShadowRecorder<S> {
        &self.recorder
    }

    /// The recorder beneath, mutably.
    pub const fn recorder_mut(&mut self) -> &mut ShadowRecorder<S> {
        &mut self.recorder
    }

    /// A synthetic job identity, derived from the coordinates it stands for.
    ///
    /// Deterministic, so a replay of one trace mints the same identity twice,
    /// and prefixed so it cannot be mistaken for a real job.
    fn synthetic_job_id(issue_url: &str, source_key: &str) -> String {
        let mut hasher = automonique_protocol::digest::Sha256::new();
        hasher.update(issue_url.as_bytes());
        hasher.update(b"\0");
        hasher.update(source_key.as_bytes());
        let hex = hasher.finish().to_hex();
        format!("{SYNTHETIC_PREFIX}{}", &hex[..24])
    }

    fn synthetic_receipt(issue_url: &str, job_id: String, approved: bool) -> TicketDispatchReceipt {
        TicketDispatchReceipt {
            issue_id: format!("{SYNTHETIC_PREFIX}issue"),
            issue_url: issue_url.to_owned(),
            issue_title: String::from("shadow-mode dispatch"),
            project_label: format!("{SYNTHETIC_PREFIX}project"),
            site_label: None,
            workspace: TicketWorkspace::InstanceDefault,
            job_id,
            job_status: if approved {
                TicketJobStatus::Pending
            } else {
                TicketJobStatus::PendingApproval
            },
            duplicate: false,
            approved,
        }
    }
}

impl<S: EnvelopeSink> TicketActionSurface for ShadowTicketSurface<S> {
    fn dispatch_ticket(
        &mut self,
        issue_url: &str,
        source_key: &str,
    ) -> Result<TicketDispatchReceipt, String> {
        self.recorder.record(IntendedAction::new(
            ActionKind::TicketDispatch,
            vec![issue_url.to_owned(), source_key.to_owned()],
        ));
        Ok(Self::synthetic_receipt(
            issue_url,
            Self::synthetic_job_id(issue_url, source_key),
            false,
        ))
    }

    fn confirm_ticket(
        &mut self,
        issue_url: &str,
        source_key: &str,
    ) -> Result<TicketDispatchReceipt, String> {
        self.recorder.record(IntendedAction::new(
            ActionKind::TicketConfirm,
            vec![issue_url.to_owned(), source_key.to_owned()],
        ));
        // Approved, because production would be: an answer that failed here
        // would send the router down its failure branch and record a divergence
        // the harness itself caused. Nothing was confirmed anywhere.
        Ok(Self::synthetic_receipt(
            issue_url,
            Self::synthetic_job_id(issue_url, source_key),
            true,
        ))
    }

    fn decide_ticket(
        &mut self,
        job_id: &str,
        source_key: &str,
        _decision_key: &str,
        _actor_key: &str,
        decision: TicketDecision,
    ) -> Result<TicketDecisionReceipt, String> {
        let (spelling, reason, outcome) = match &decision {
            TicketDecision::Approve => (
                "approve",
                String::from("no-reason-required"),
                TicketDecisionOutcome::Approved,
            ),
            TicketDecision::Reject { reason } => {
                ("reject", reason.clone(), TicketDecisionOutcome::Rejected)
            }
        };
        self.recorder.record(IntendedAction::new(
            ActionKind::TicketDecision,
            vec![
                job_id.to_owned(),
                source_key.to_owned(),
                String::from(spelling),
                reason,
            ],
        ));
        Ok(TicketDecisionReceipt {
            job_id: job_id.to_owned(),
            job_status: match outcome {
                TicketDecisionOutcome::Approved => TicketJobStatus::Pending,
                TicketDecisionOutcome::Rejected => TicketJobStatus::Cancelled,
            },
            decision: outcome,
            duplicate: false,
        })
    }

    fn ticket_status(&mut self, job_id: &str) -> Result<TicketStatus, String> {
        // A read, not a mutation, and one this decorator cannot answer honestly
        // because it holds no backend. It records nothing — a status read is not
        // an intended *action* — and reports the synthetic job as pending.
        Ok(TicketStatus {
            issue_id: format!("{SYNTHETIC_PREFIX}issue"),
            issue_url: String::from("https://example.invalid/shadow"),
            issue_title: String::from("shadow-mode status"),
            job_id: job_id.to_owned(),
            job_status: TicketJobStatus::PendingApproval,
            result: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        })
    }
}

/// What the observer did with one reference-engine message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// Recorded as `engine=legacy-observed` under a correlated source key.
    Recorded,
    /// No inbound event correlates with this message's thread.
    ///
    /// Nothing was recorded. Filing it under a guessed key would produce a
    /// comparison against the wrong source event, which is a worse failure than
    /// a missing one.
    Uncorrelated,
    /// The correlation existed and the sink refused the record.
    Refused,
}

/// One message the reference engine published on a shared Slack surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMessage {
    /// Channel it was published to.
    pub channel: String,
    /// The thread it belongs to, or its own timestamp when it starts one.
    pub thread_ts: String,
    /// Whether it was posted inside an existing thread.
    pub in_thread: bool,
    /// The message text.
    pub text: String,
}

/// Records what the reference engine published, as the other half of a
/// comparison.
#[derive(Debug)]
pub struct LegacyObserver<S> {
    recorder: ShadowRecorder<S>,
    correlations: Vec<((String, String), String)>,
}

impl<S: EnvelopeSink> LegacyObserver<S> {
    /// Start observing one scope.
    ///
    /// The recorder's engine is forced to [`ParityEngine::LegacyObserved`] by
    /// construction, so an observer cannot be built that files the reference
    /// engine's messages as the candidate's.
    #[must_use]
    pub fn new(scope: &str, clock: ShadowClock, sink: S) -> Self {
        Self {
            recorder: ShadowRecorder::new(scope, ParityEngine::LegacyObserved, clock, sink),
            correlations: Vec::new(),
        }
    }

    /// The recorder beneath.
    #[must_use]
    pub const fn recorder(&self) -> &ShadowRecorder<S> {
        &self.recorder
    }

    /// The recorder beneath, mutably.
    pub const fn recorder_mut(&mut self) -> &mut ShadowRecorder<S> {
        &mut self.recorder
    }

    /// Bind one thread to the inbound event that opened it.
    ///
    /// Called when the daemon accepts an inbound event, so a later message from
    /// the reference engine in the same thread can be attributed to it. Refuses
    /// past [`MAX_CORRELATIONS`] rather than evicting.
    pub fn correlate(&mut self, channel: &str, thread_ts: &str, source_key: &str) -> bool {
        let key = (channel.to_owned(), thread_ts.to_owned());
        if let Some(existing) = self
            .correlations
            .iter_mut()
            .find(|(recorded, _)| *recorded == key)
        {
            existing.1 = source_key.to_owned();
            return true;
        }
        if self.correlations.len() >= MAX_CORRELATIONS {
            return false;
        }
        self.correlations.push((key, source_key.to_owned()));
        true
    }

    /// How many thread correlations are retained.
    #[must_use]
    pub fn correlation_count(&self) -> usize {
        self.correlations.len()
    }

    /// Record one message the reference engine published.
    pub fn observe(&mut self, message: &LegacyMessage) -> Observation {
        let key = (message.channel.clone(), message.thread_ts.clone());
        let Some((_, source_key)) = self
            .correlations
            .iter()
            .find(|(recorded, _)| *recorded == key)
        else {
            return Observation::Uncorrelated;
        };
        let source_key = source_key.clone();
        self.recorder.begin_source(&source_key);
        let action = if message.in_thread {
            IntendedAction::new(
                ActionKind::SlackThreadReply,
                vec![
                    message.channel.clone(),
                    message.thread_ts.clone(),
                    message.text.clone(),
                ],
            )
        } else {
            IntendedAction::new(
                ActionKind::SlackChannelPost,
                vec![message.channel.clone(), message.text.clone()],
            )
        };
        if self.recorder.record(action) {
            Observation::Recorded
        } else {
            Observation::Refused
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorder() -> ShadowRecorder<MemorySink> {
        ShadowRecorder::new(
            "slack-ticket-routing",
            ParityEngine::ShadowCandidate,
            ShadowClock::Fixed(1_700_000_000_000),
            MemorySink::new(),
        )
    }

    #[test]
    fn a_mode_spelling_outside_the_closed_set_is_not_a_mode() {
        assert_eq!(
            ShadowMode::from_spelling("shadow"),
            Some(ShadowMode::Shadow)
        );
        assert_eq!(
            ShadowMode::from_spelling("primary"),
            Some(ShadowMode::Primary)
        );
        assert_eq!(ShadowMode::from_spelling("shadowy"), None);
        assert_eq!(ShadowMode::default(), ShadowMode::Primary);
    }

    #[test]
    fn a_recorder_with_no_open_source_records_nothing() {
        let mut recorder = recorder();
        assert!(!recorder.record(IntendedAction::no_action("idle")));
        assert!(recorder.sink().envelopes().is_empty());
        assert_eq!(recorder.refusals(), 1);
    }

    #[test]
    fn sequences_restart_at_each_source_key() {
        let mut recorder = recorder();
        recorder.begin_source("slack:T:event:A");
        assert!(recorder.record(IntendedAction::no_action("one")));
        assert!(recorder.record(IntendedAction::no_action("two")));
        recorder.begin_source("slack:T:event:B");
        assert!(recorder.record(IntendedAction::no_action("three")));
        let sequences: Vec<u32> = recorder
            .sink()
            .envelopes()
            .iter()
            .map(automonique_protocol::parity::IntendedActionEnvelope::sequence)
            .collect();
        assert_eq!(sequences, vec![0, 1, 0]);
    }

    #[test]
    fn a_full_sink_is_counted_rather_than_propagated() {
        let mut recorder = ShadowRecorder::new(
            "slack-ticket-routing",
            ParityEngine::ShadowCandidate,
            ShadowClock::Fixed(0),
            MemorySink::with_capacity(1),
        );
        recorder.begin_source("slack:T:event:A");
        assert!(recorder.record(IntendedAction::no_action("one")));
        assert!(!recorder.record(IntendedAction::no_action("two")));
        assert_eq!(recorder.refusals(), 1);
        assert_eq!(recorder.sink().envelopes().len(), 1);
    }

    #[test]
    fn a_fixed_clock_makes_two_recordings_byte_identical() {
        let mut first = recorder();
        first.begin_source("slack:T:event:A");
        first.record(IntendedAction::no_action("quiet"));
        let mut second = recorder();
        second.begin_source("slack:T:event:A");
        second.record(IntendedAction::no_action("quiet"));
        assert_eq!(
            first.sink().envelopes()[0].to_canonical_bytes(),
            second.sink().envelopes()[0].to_canonical_bytes()
        );
    }

    #[test]
    fn a_synthetic_job_identity_is_deterministic_and_unmistakable() {
        let first = ShadowTicketSurface::<MemorySink>::synthetic_job_id("https://x/1", "k");
        let second = ShadowTicketSurface::<MemorySink>::synthetic_job_id("https://x/1", "k");
        let other = ShadowTicketSurface::<MemorySink>::synthetic_job_id("https://x/2", "k");
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(first.starts_with(SYNTHETIC_PREFIX));
    }

    #[test]
    fn the_ticket_surface_records_a_dispatch_and_returns_an_unapproved_receipt() {
        let mut surface = ShadowTicketSurface::new(recorder());
        surface.recorder_mut().begin_source("slack:T:event:A");
        let receipt = surface
            .dispatch_ticket("https://example.invalid/issues/1", "slack:T:event:A")
            .expect("synthetic receipt");
        assert!(!receipt.approved);
        assert_eq!(receipt.job_status, TicketJobStatus::PendingApproval);
        let envelopes = surface.recorder().sink().envelopes();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].action().kind(), ActionKind::TicketDispatch);
    }

    #[test]
    fn a_confirmation_answers_approved_so_the_router_takes_the_same_branch() {
        let mut surface = ShadowTicketSurface::new(recorder());
        surface.recorder_mut().begin_source("slack:T:event:A");
        let receipt = surface
            .confirm_ticket("https://example.invalid/issues/1", "slack:T:event:A")
            .expect("synthetic receipt");
        assert!(receipt.approved);
        assert_eq!(
            surface.recorder().sink().envelopes()[0].action().kind(),
            ActionKind::TicketConfirm
        );
    }

    #[test]
    fn a_rejection_records_its_reason() {
        let mut surface = ShadowTicketSurface::new(recorder());
        surface.recorder_mut().begin_source("slack:T:event:A");
        let decision = TicketDecision::reject("out of scope").expect("valid reason");
        let receipt = surface
            .decide_ticket("job-1", "slack:T:event:A", "d1", "a1", decision)
            .expect("synthetic receipt");
        assert_eq!(receipt.decision, TicketDecisionOutcome::Rejected);
        let action = surface.recorder().sink().envelopes()[0].action().clone();
        assert_eq!(action.kind(), ActionKind::TicketDecision);
        assert_eq!(action.value("decision"), Some("reject"));
        assert_eq!(action.value("reason"), Some("out of scope"));
    }

    #[test]
    fn a_status_read_records_no_intended_action() {
        let mut surface = ShadowTicketSurface::new(recorder());
        surface.recorder_mut().begin_source("slack:T:event:A");
        let _ = surface.ticket_status("job-1").expect("synthetic status");
        assert!(surface.recorder().sink().envelopes().is_empty());
    }

    #[test]
    fn an_uncorrelated_reference_message_is_reported_not_guessed() {
        let mut observer = LegacyObserver::new(
            "slack-ticket-routing",
            ShadowClock::Fixed(0),
            MemorySink::new(),
        );
        let message = LegacyMessage {
            channel: String::from("C0"),
            thread_ts: String::from("1700000000.000100"),
            in_thread: true,
            text: String::from("on it"),
        };
        assert_eq!(observer.observe(&message), Observation::Uncorrelated);
        assert!(observer.recorder().sink().envelopes().is_empty());
    }

    #[test]
    fn a_correlated_reference_message_records_as_the_reference_engine() {
        let mut observer = LegacyObserver::new(
            "slack-ticket-routing",
            ShadowClock::Fixed(0),
            MemorySink::new(),
        );
        assert!(observer.correlate("C0", "1700000000.000100", "slack:T:event:A"));
        let message = LegacyMessage {
            channel: String::from("C0"),
            thread_ts: String::from("1700000000.000100"),
            in_thread: true,
            text: String::from("on it"),
        };
        assert_eq!(observer.observe(&message), Observation::Recorded);
        let envelope = &observer.recorder().sink().envelopes()[0];
        assert_eq!(envelope.engine(), ParityEngine::LegacyObserved);
        assert_eq!(envelope.source_key(), "slack:T:event:A");
        assert_eq!(envelope.action().kind(), ActionKind::SlackThreadReply);
    }

    #[test]
    fn a_top_level_reference_message_records_as_a_channel_post() {
        let mut observer = LegacyObserver::new(
            "slack-ticket-routing",
            ShadowClock::Fixed(0),
            MemorySink::new(),
        );
        observer.correlate("C0", "1700000000.000100", "slack:T:event:A");
        let message = LegacyMessage {
            channel: String::from("C0"),
            thread_ts: String::from("1700000000.000100"),
            in_thread: false,
            text: String::from("announcement"),
        };
        assert_eq!(observer.observe(&message), Observation::Recorded);
        assert_eq!(
            observer.recorder().sink().envelopes()[0].action().kind(),
            ActionKind::SlackChannelPost
        );
    }

    #[test]
    fn correlations_refuse_past_their_ceiling_rather_than_evicting() {
        let mut observer = LegacyObserver::new(
            "slack-ticket-routing",
            ShadowClock::Fixed(0),
            MemorySink::new(),
        );
        for index in 0..MAX_CORRELATIONS {
            assert!(observer.correlate("C0", &format!("{index}"), "slack:T:event:A"));
        }
        assert!(!observer.correlate("C0", "overflow", "slack:T:event:B"));
        assert_eq!(observer.correlation_count(), MAX_CORRELATIONS);
        // The first correlation is still there, which is what "refuses rather
        // than evicts" means.
        assert!(observer.correlate("C0", "0", "slack:T:event:A"));
    }
}
