// SPDX-License-Identifier: Elastic-2.0

//! The domain journal: events, aggregate revisions, action receipts and replay.
//!
//! # What replay enforces, and the one thing it cannot
//!
//! Replay may rebuild a projection or explain history. Four properties are
//! enforced by types and each is pinned by a compile-fail below, every one of
//! them paired with a passing case differing only in the rejected construct:
//!
//! 1. **Replay grants no second channel.** [`Journal::replay`] takes one
//!    argument, the projection. There is no parameter through which an effect,
//!    outbox, notification or transport could be handed in.
//! 2. **The callback interface cannot be widened.** [`Projection::apply`] takes
//!    `&mut self` and `&DomainEvent`; an implementer that asks for a handle
//!    alongside the event does not implement the trait.
//! 3. **Replay grants no write access either.** `apply` receives a *shared*
//!    event borrow, so an implementer cannot ask to mutate what it is shown,
//!    and [`Journal::replay`] itself takes `&self`.
//! 4. **This crate hands out no effect sink.** [`Outbox`]'s field is private
//!    and it has no constructor, so one cannot be obtained here. Two routes are
//!    pinned: naming the field, and `Outbox::default()`. That those two fail is
//!    measured; that no *other* route exists is read off the `impl` block,
//!    which no test can do for a method nobody has written.
//!
//! Together: *replay hands a projection nothing it did not already own.*
//!
//! ## The named limit: projection-owned handles
//!
//! Not enforced, and irreducible in safe Rust: **a projection can bring its own
//! handle.** Rust has no effect system. A projection owns its fields, so one
//! constructed holding a channel, socket or file handle can use it inside
//! `apply`, because it brought it, and no signature can prevent that. This
//! module must not be read as claiming a projection is pure; the enforced
//! property is the four points above, and "no effect happens during replay" is
//! a discipline on the caller, not a guarantee of this API.
//!
//! `tests/journal.rs::replay_purity` demonstrates that limit with a working
//! counterexample rather than asserting it away, so the claim here and the
//! measurable behaviour cannot drift apart.
//!
//! A projection over replay compiles, and `replay` takes it alone:
//!
//! ```
//! use automonique_protocol::journal::{Journal, Projection, DomainEvent};
//! # use automonique_protocol::journal::{AggregateId, DomainEventPayload, EventSchemaVersion};
//! # use automonique_protocol::primitives::{EpochMillis, Revision};
//! #[derive(Default)]
//! struct Counter(usize);
//! impl Projection for Counter {
//!     fn apply(&mut self, _event: &DomainEvent) { self.0 += 1; }
//! }
//!
//! let mut journal = Journal::new();
//! let aggregate = AggregateId::new("work", "w-1").unwrap();
//! let event = DomainEvent::new(
//!     1, aggregate, Revision::FIRST, EventSchemaVersion::new(1).unwrap(),
//!     EpochMillis::from_millis(0), "created",
//!     DomainEventPayload::text("work/w-1").unwrap(),
//! ).unwrap();
//! journal.append(event).unwrap();
//!
//! let mut counter = Counter::default();
//! journal.replay(&mut counter);
//! assert_eq!(counter.0, 1);
//! ```
//!
//! Handing `replay` anything alongside the projection does not compile. The
//! only difference from the case above is the second argument:
//!
//! ```compile_fail
//! use automonique_protocol::journal::{Journal, Projection, DomainEvent};
//! #[derive(Default)]
//! struct Counter(usize);
//! impl Projection for Counter {
//!     fn apply(&mut self, _event: &DomainEvent) { self.0 += 1; }
//! }
//!
//! let journal = Journal::new();
//! let mut counter = Counter::default();
//! let mut sink: Vec<String> = Vec::new();
//! journal.replay(&mut counter, &mut sink);
//! ```
//!
//! A projection may implement the interface as declared:
//!
//! ```
//! use automonique_protocol::journal::{DomainEvent, Projection};
//! struct Emitter;
//! impl Projection for Emitter {
//!     fn apply(&mut self, _event: &DomainEvent) {}
//! }
//! ```
//!
//! It may not widen it to receive a handle. The only difference from the case
//! above is the extra parameter:
//!
//! ```compile_fail
//! use automonique_protocol::journal::{DomainEvent, Outbox, Projection};
//! struct Emitter;
//! impl Projection for Emitter {
//!     fn apply(&mut self, _event: &DomainEvent, _outbox: &mut Outbox) {}
//! }
//! ```
//!
//! It may not ask to mutate what it is shown either. The only difference from
//! the implementable case is `&mut`:
//!
//! ```compile_fail
//! use automonique_protocol::journal::{DomainEvent, Projection};
//! struct Rewriter;
//! impl Projection for Rewriter {
//!     fn apply(&mut self, _event: &mut DomainEvent) {}
//! }
//! ```
//!
//! Obtaining an effect handle from this crate inside a projection does not
//! compile either, by either route. Naming the field:
//!
//! ```compile_fail
//! use automonique_protocol::journal::{DomainEvent, Outbox, Projection};
//! struct Emitter;
//! impl Projection for Emitter {
//!     fn apply(&mut self, _event: &DomainEvent) {
//!         // `Outbox` has a private field and no constructor: an effect
//!         // cannot be obtained here, so replay cannot emit one.
//!         let mut outbox = Outbox { pending: Vec::new() };
//!         outbox.enqueue("notify");
//!     }
//! }
//! ```
//!
//! A type this crate does hand out constructs the ordinary way:
//!
//! ```
//! use automonique_protocol::journal::Journal;
//! let journal = Journal::default();
//! assert!(journal.events().is_empty());
//! ```
//!
//! [`Outbox`] does not. The only difference from the case above is the type:
//!
//! ```compile_fail
//! use automonique_protocol::journal::Outbox;
//! let outbox = Outbox::default();
//! assert!(outbox.pending().is_empty());
//! ```

use core::fmt;
use std::error::Error;

use crate::codec::VersionRange;
use crate::primitives::{EpochMillis, Revision, ValueError};

/// Maximum UTF-8 byte length of a journal identifier.
pub const MAX_JOURNAL_FIELD_BYTES: usize = 128;

/// Maximum UTF-8 byte length of one domain-event payload.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 4 * 1024;

/// Which aggregate an event belongs to.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AggregateId {
    kind: String,
    id: String,
}

impl AggregateId {
    /// Name an aggregate by kind and identity.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an invalid component.
    pub fn new(kind: &str, id: &str) -> Result<Self, JournalError> {
        bounded(kind, "aggregate_kind")?;
        bounded(id, "aggregate_id")?;
        Ok(Self {
            kind: kind.to_owned(),
            id: id.to_owned(),
        })
    }

    /// Aggregate kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Aggregate identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// The typed target of an action.
///
/// A target is owned and bounded. The ledger never stores an unvalidated raw
/// string, while the string-taking recording methods remain as ergonomic
/// adapters for existing callers.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionTarget(String);

impl ActionTarget {
    /// Validate and own an action target.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an empty, over-long or control
    /// character bearing target.
    pub fn new(value: &str) -> Result<Self, JournalError> {
        bounded(value, "target")?;
        Ok(Self(value.to_owned()))
    }

    /// Stable target spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded domain-event payload.
///
/// The newtype keeps event data distinct from event kinds and other journal
/// strings. Payload text is owned, non-empty, single-line and bounded by
/// [`MAX_EVENT_PAYLOAD_BYTES`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DomainEventPayload(String);

impl DomainEventPayload {
    /// Validate and own textual event data.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an empty, over-long or control
    /// character bearing payload.
    pub fn text(value: &str) -> Result<Self, JournalError> {
        bounded_to(value, "event_payload", MAX_EVENT_PAYLOAD_BYTES)?;
        Ok(Self(value.to_owned()))
    }

    /// Payload text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The version of the event schema an event was written with.
///
/// Versioned independently of database schema: a reader declares an event
/// decode range separately from its table range, so the two evolve apart.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventSchemaVersion(u32);

impl EventSchemaVersion {
    /// Construct a non-zero event schema version.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] when `value` is zero.
    pub const fn new(value: u32) -> Result<Self, JournalError> {
        if value == 0 {
            return Err(JournalError::Field {
                field: "event_schema_version",
                error: ValueError::Empty,
            });
        }
        Ok(Self(value))
    }

    /// The version number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Why a journal, receipt or cursor operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalError {
    /// A global event identifier did not strictly increase.
    EventIdNotIncreasing {
        /// Last accepted identifier.
        last: u64,
        /// Offered identifier.
        offered: u64,
    },
    /// An aggregate revision was not the exact successor of the current one.
    RevisionConflict {
        /// Revision the append had to produce.
        expected: u64,
        /// Revision it offered.
        observed: u64,
    },
    /// The current aggregate revision has no representable successor.
    RevisionExhausted {
        /// Current, last representable revision.
        current: u64,
        /// Revision the append offered.
        observed: u64,
    },
    /// An event's schema version lies outside the reader's decode range.
    EventSchemaOutOfRange {
        /// Lowest decodable version.
        supported_min: u32,
        /// Highest decodable version.
        supported_max: u32,
        /// Version the event declared.
        offered: u32,
    },
    /// One idempotency key was reused for a different target.
    IdempotencyConflict {
        /// The target already recorded under this key.
        recorded_target: ActionTarget,
        /// The target offered.
        offered_target: ActionTarget,
    },
    /// One idempotency key was reused for a different payload.
    ///
    /// Separate from [`JournalError::IdempotencyConflict`] because the two say
    /// different things to a caller: the same target with a changed payload is a
    /// changed request, not a misaddressed one.
    IdempotencyPayloadConflict {
        /// The payload already recorded under this key.
        recorded_payload: ActionPayload,
        /// The payload offered.
        offered_payload: ActionPayload,
    },
    /// A cursor was moved backwards.
    CursorWentBackwards {
        /// Current position.
        current: u64,
        /// Offered position.
        offered: u64,
    },
    /// A retained range was declared with its end below its start.
    InvertedRetainedRange {
        /// Lowest offered position.
        from: u64,
        /// Highest offered position.
        to: u64,
    },
    /// A bounded identifier was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl JournalError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::EventIdNotIncreasing { .. } => "event_id_not_increasing",
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::RevisionExhausted { .. } => "revision_exhausted",
            Self::EventSchemaOutOfRange { .. } => "event_schema_out_of_range",
            Self::IdempotencyConflict { .. } => "idempotency_conflict",
            Self::IdempotencyPayloadConflict { .. } => "idempotency_payload_conflict",
            Self::CursorWentBackwards { .. } => "cursor_went_backwards",
            Self::InvertedRetainedRange { .. } => "inverted_retained_range",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventIdNotIncreasing { last, offered } => write!(
                formatter,
                "event id {offered} does not increase past {last}"
            ),
            Self::RevisionConflict { expected, observed } => write!(
                formatter,
                "expected revision {expected}, observed {observed}"
            ),
            Self::RevisionExhausted { current, observed } => write!(
                formatter,
                "revision {current} has no successor; observed {observed}"
            ),
            Self::EventSchemaOutOfRange {
                supported_min,
                supported_max,
                offered,
            } => write!(
                formatter,
                "event schema {offered} is outside the decodable range \
                 {supported_min}..={supported_max}"
            ),
            Self::IdempotencyConflict {
                recorded_target,
                offered_target,
            } => write!(
                formatter,
                "idempotency key already targets {recorded_target}; cannot retarget \
                 to {offered_target}"
            ),
            Self::IdempotencyPayloadConflict {
                recorded_payload,
                offered_payload,
            } => write!(
                formatter,
                "idempotency key already recorded {recorded_payload}; cannot replace \
                 it with {offered_payload}"
            ),
            Self::CursorWentBackwards { current, offered } => write!(
                formatter,
                "cursor cannot move from {current} back to {offered}"
            ),
            Self::InvertedRetainedRange { from, to } => write!(
                formatter,
                "retained range {from}..={to} ends below where it starts"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for JournalError {}

/// One authoritative state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvent {
    event_id: u64,
    aggregate: AggregateId,
    revision: Revision,
    schema_version: EventSchemaVersion,
    at: EpochMillis,
    kind: String,
    payload: DomainEventPayload,
}

impl DomainEvent {
    /// Record an authoritative transition.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an invalid kind.
    pub fn new(
        event_id: u64,
        aggregate: AggregateId,
        revision: Revision,
        schema_version: EventSchemaVersion,
        at: EpochMillis,
        kind: &str,
        payload: DomainEventPayload,
    ) -> Result<Self, JournalError> {
        bounded(kind, "event_kind")?;
        Ok(Self {
            event_id,
            aggregate,
            revision,
            schema_version,
            at,
            kind: kind.to_owned(),
            payload,
        })
    }

    /// Globally ordered identifier.
    #[must_use]
    pub const fn event_id(&self) -> u64 {
        self.event_id
    }

    /// The aggregate this event belongs to.
    #[must_use]
    pub const fn aggregate(&self) -> &AggregateId {
        &self.aggregate
    }

    /// The aggregate revision this event produced.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// The event schema version.
    #[must_use]
    pub const fn schema_version(&self) -> EventSchemaVersion {
        self.schema_version
    }

    /// When the transition occurred.
    #[must_use]
    pub const fn at(&self) -> EpochMillis {
        self.at
    }

    /// The event kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The bounded typed event data.
    #[must_use]
    pub const fn payload(&self) -> &DomainEventPayload {
        &self.payload
    }

    /// Whether a reader declaring `range` may decode this event.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::EventSchemaOutOfRange`]. Fails closed: an event
    /// from outside the range is never decoded on a best-effort basis.
    pub fn decodable_within(&self, range: VersionRange) -> Result<(), JournalError> {
        let offered = self.schema_version.get();
        if offered < range.min().get() || offered > range.max().get() {
            return Err(JournalError::EventSchemaOutOfRange {
                supported_min: range.min().get(),
                supported_max: range.max().get(),
                offered,
            });
        }
        Ok(())
    }
}

/// Validate the revision one append must produce.
///
/// `None` denotes an aggregate with no events, whose first append must produce
/// [`Revision::FIRST`]. A known revision must advance by exactly one. Exhaustion
/// is refused explicitly rather than panicking or wrapping.
///
/// # Errors
///
/// Returns [`JournalError::RevisionConflict`] for a representable
/// non-successor and [`JournalError::RevisionExhausted`] when `current` is the
/// last representable revision.
pub fn validate_revision_successor(
    current: Option<Revision>,
    observed: Revision,
) -> Result<(), JournalError> {
    let expected = match current {
        None => Revision::FIRST,
        Some(current) => current
            .checked_next()
            .map_err(|_| JournalError::RevisionExhausted {
                current: current.get(),
                observed: observed.get(),
            })?,
    };
    if observed != expected {
        return Err(JournalError::RevisionConflict {
            expected: expected.get(),
            observed: observed.get(),
        });
    }
    Ok(())
}

/// Something rebuilt by reading history.
///
/// The only argument is a shared borrow of one event. A projection is passed no
/// transport, no store and no effect handle, and the signature cannot be
/// widened to receive one: an implementation that takes a second parameter, or
/// that asks for the event by `&mut`, does not implement this trait. The
/// module-level compile-fail cases pin both.
///
/// That is a statement about what this trait hands over, not about what an
/// implementation may already hold — see the named limit in the module
/// documentation.
pub trait Projection {
    /// Fold one event into the projection.
    fn apply(&mut self, event: &DomainEvent);
}

/// An effect sink.
///
/// Deliberately unconstructable: the field is private and there is no
/// constructor, no `Default` and no `From`. A [`Projection`] therefore cannot
/// obtain one from this crate, so replay hands out no way to emit. The
/// module-level compile-fail cases pin two routes — naming the private field,
/// and `Outbox::default()` — rather than only the first; that there is no third
/// is read off this `impl` block rather than pinned by a test.
///
/// That is a statement about what replay confers, not about what a projection
/// may already own: a projection that closes over its own channel or file
/// handle can still use it, and no Rust signature can stop that.
///
/// Stated rather than implied: nothing in this workspace constructs an `Outbox`
/// today, so this type is a declared boundary rather than a load-bearing part
/// of a delivery path. A transaction layer that legitimately owns effects will
/// receive one from the store, which is why nothing here hands them out.
#[derive(Debug)]
pub struct Outbox {
    pending: Vec<String>,
}

impl Outbox {
    /// Queue an effect. Reachable only from a caller that already holds one.
    pub fn enqueue(&mut self, destination: &str) {
        self.pending.push(destination.to_owned());
    }

    /// Pending destinations.
    #[must_use]
    pub fn pending(&self) -> &[String] {
        &self.pending
    }
}

/// The globally ordered event log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Journal {
    events: Vec<DomainEvent>,
}

impl Journal {
    /// Start an empty journal.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Append one event.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::EventIdNotIncreasing`] when the global order
    /// would not strictly increase, and [`JournalError::RevisionConflict`] when
    /// the revision is not the exact successor of the aggregate's current one.
    pub fn append(&mut self, event: DomainEvent) -> Result<(), JournalError> {
        if let Some(last) = self.events.last()
            && event.event_id() <= last.event_id()
        {
            return Err(JournalError::EventIdNotIncreasing {
                last: last.event_id(),
                offered: event.event_id(),
            });
        }
        let current = self
            .events
            .iter()
            .rfind(|existing| existing.aggregate() == event.aggregate())
            .map(DomainEvent::revision);
        validate_revision_successor(current, event.revision())?;
        self.events.push(event);
        Ok(())
    }

    /// Events in global order.
    #[must_use]
    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    /// The current revision of one aggregate.
    #[must_use]
    pub fn revision_of(&self, aggregate: &AggregateId) -> Option<Revision> {
        self.events
            .iter()
            .rfind(|event| event.aggregate() == aggregate)
            .map(DomainEvent::revision)
    }

    /// Rebuild a projection from history.
    ///
    /// Takes a projection and nothing else, by `&self`. There is no parameter
    /// through which an effect, outbox, notification or transport could be
    /// supplied, and the journal is read rather than drained: every event stays
    /// where it was and the same replay run again observes the same events.
    ///
    /// The projection is shown each event once, in global order, and is shown
    /// nothing else. What it does with them is its own business — see the named
    /// limit in the module documentation.
    pub fn replay<P: Projection>(&self, projection: &mut P) {
        for event in &self.events {
            projection.apply(event);
        }
    }
}

/// The closed set of terminal outcomes a mutation may report.
///
/// Transport failure and operation failure are separate variants: a caller that
/// received [`ActionOutcome::Unknown`] does not know whether the effect
/// happened, while [`ActionOutcome::Rejected`] says it did not.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActionOutcome {
    /// Durably accepted; completion follows.
    Accepted,
    /// Durably completed.
    Completed,
    /// The operation was refused. The effect did not happen.
    Rejected,
    /// The expected revision did not match.
    Conflict,
    /// Transport failed; whether the effect happened is unknown.
    Unknown,
    /// The caller's cursor is outside retention.
    ResyncRequired,
}

impl ActionOutcome {
    /// Every outcome, for exhaustiveness checks.
    pub const ALL: [Self; 6] = [
        Self::Accepted,
        Self::Completed,
        Self::Rejected,
        Self::Conflict,
        Self::Unknown,
        Self::ResyncRequired,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
            Self::ResyncRequired => "resync_required",
        }
    }

    /// Whether the outcome states that the effect did not happen.
    ///
    /// [`ActionOutcome::Unknown`] answers `false` because it does not know;
    /// treating it as a failure is how a duplicate effect gets issued.
    #[must_use]
    pub const fn states_no_effect(self) -> bool {
        matches!(self, Self::Rejected | Self::Conflict)
    }
}

/// What an action carried, reduced to a digest.
///
/// Absence is its own value rather than an empty digest. "This action carried
/// nothing" and "this action carried something whose digest is empty" are
/// different requests, and one spelling standing for both is how a changed
/// request slips back through under an old key. [`ActionPayload::digest`]
/// refuses an empty string, so the ambiguous value is unrepresentable rather
/// than merely discouraged.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionPayload(Option<String>);

impl ActionPayload {
    /// The payload of an action that carried none.
    #[must_use]
    pub const fn absent() -> Self {
        Self(None)
    }

    /// The payload of an action that carried one, named by its digest.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an empty, over-long or control
    /// character bearing digest.
    pub fn digest(digest: &str) -> Result<Self, JournalError> {
        bounded(digest, "payload_digest")?;
        Ok(Self(Some(digest.to_owned())))
    }

    /// The digest, when there is one.
    #[must_use]
    pub fn as_digest(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl fmt::Display for ActionPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(digest) => write!(formatter, "payload {digest}"),
            None => formatter.write_str("no payload"),
        }
    }
}

/// The durable record of one accepted mutation.
///
/// Owns every field. There is no lifetime parameter, so a receipt cannot borrow
/// from a connection and therefore stays queryable after the client that
/// requested it has gone.
///
/// A recorded receipt outlives the connection that produced it:
///
/// ```
/// use automonique_protocol::journal::{ActionLedger, ActionOutcome, ActionReceipt};
/// let receipt: ActionReceipt;
/// {
///     // This scope stands in for a live client connection.
///     let mut connection = ActionLedger::new();
///     receipt = connection
///         .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Completed)
///         .unwrap();
/// }
/// assert_eq!(receipt.target(), "work/w-1");
/// ```
///
/// A receipt type that borrows from a live connection cannot be written down at
/// all, which is stronger than one particular borrow failing to outlive one
/// particular scope. A session may hold a recorded receipt:
///
/// ```
/// use automonique_protocol::journal::{ActionLedger, ActionOutcome, ActionReceipt};
/// struct Session {
///     receipt: ActionReceipt,
/// }
///
/// let session = {
///     let mut connection = ActionLedger::new();
///     Session {
///         receipt: connection
///             .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Completed)
///             .unwrap(),
///     }
/// };
/// assert_eq!(session.receipt.target(), "work/w-1");
/// ```
///
/// Declaring that receipt as borrowing from the connection does not compile:
/// `ActionReceipt` takes no lifetime argument, so `ActionReceipt<'connection>`
/// names nothing. The only difference from the case above is that lifetime:
///
/// ```compile_fail
/// use automonique_protocol::journal::ActionReceipt;
/// struct Session<'connection> {
///     receipt: ActionReceipt<'connection>,
/// }
///
/// fn target_of<'session>(session: &'session Session<'_>) -> &'session str {
///     session.receipt.target()
/// }
/// let _ = target_of;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReceipt {
    action_id: String,
    target: ActionTarget,
    idempotency_key: String,
    expected_revision: Option<Revision>,
    payload: ActionPayload,
    outcome: ActionOutcome,
}

impl ActionReceipt {
    /// The action identity.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// The target's stable spelling.
    ///
    /// Retained as the ergonomic string view used by existing callers. Use
    /// [`ActionReceipt::typed_target`] when the target must remain typed.
    #[must_use]
    pub fn target(&self) -> &str {
        self.target.as_str()
    }

    /// The typed action target.
    #[must_use]
    pub const fn typed_target(&self) -> &ActionTarget {
        &self.target
    }

    /// The idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// The revision the caller asserted.
    #[must_use]
    pub const fn expected_revision(&self) -> Option<Revision> {
        self.expected_revision
    }

    /// What the action carried.
    #[must_use]
    pub const fn payload(&self) -> &ActionPayload {
        &self.payload
    }

    /// The terminal outcome.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        self.outcome
    }
}

/// Receipts recorded against idempotency keys.
///
/// A recorded receipt is readable:
///
/// ```
/// use automonique_protocol::journal::{ActionLedger, ActionOutcome};
/// let mut ledger = ActionLedger::new();
/// ledger
///     .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
///     .unwrap();
/// let recorded = ledger.find("key-1").unwrap();
/// assert_eq!(recorded.target(), "work/w-1");
/// ```
///
/// It is not writable through this API: the ledger hands out no `&mut` to a
/// recorded receipt and [`ActionReceipt`] exposes no setter, so retargeting or
/// re-outcoming one in place has no route — reusing a key has to go back
/// through [`ActionLedger::record`], where divergence is a typed conflict. The
/// compile-fail below pins the obvious route, `find_mut`; it pins that one name
/// rather than the absence of every accessor a future edit might add.
///
/// The residual is exact and irreducible: a mutable accessor under another
/// name, paired with a setter on [`ActionReceipt`], would reopen in-place
/// retargeting, and both would have to be written *into this module*, because
/// Rust's privacy boundary is the module — nothing declared here can be
/// protected from code added here, and no test can observe the absence of a
/// method nobody has written. Outside this module the fields are unreachable
/// and the property holds by type. Inside it, the property is review's.
///
/// The only difference from the case above is `find_mut`, which does not exist:
///
/// ```compile_fail
/// use automonique_protocol::journal::{ActionLedger, ActionOutcome};
/// let mut ledger = ActionLedger::new();
/// ledger
///     .record("a-1", "work/w-1", "key-1", None, ActionOutcome::Accepted)
///     .unwrap();
/// let recorded = ledger.find_mut("key-1").unwrap();
/// assert_eq!(recorded.target(), "work/w-1");
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActionLedger {
    receipts: Vec<ActionReceipt>,
}

impl ActionLedger {
    /// Start an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Record a mutation that carries no payload, idempotently by key.
    ///
    /// Replaying a key against the same target returns the identical receipt.
    /// Equivalent to [`ActionLedger::record_with_payload`] with
    /// [`ActionPayload::absent`].
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::IdempotencyConflict`] when a key is reused for a
    /// different target — neither an overwrite nor a second execution —
    /// [`JournalError::IdempotencyPayloadConflict`] when the key was recorded
    /// carrying a payload, since this call offers none, and
    /// [`JournalError::Field`] for an invalid identifier.
    pub fn record(
        &mut self,
        action_id: &str,
        target: &str,
        idempotency_key: &str,
        expected_revision: Option<Revision>,
        outcome: ActionOutcome,
    ) -> Result<ActionReceipt, JournalError> {
        self.record_target(
            action_id,
            ActionTarget::new(target)?,
            idempotency_key,
            expected_revision,
            outcome,
        )
    }

    /// Record a payload-free mutation against an already validated target.
    ///
    /// # Errors
    ///
    /// Returns the same typed idempotency and field errors as
    /// [`ActionLedger::record`].
    pub fn record_target(
        &mut self,
        action_id: &str,
        target: ActionTarget,
        idempotency_key: &str,
        expected_revision: Option<Revision>,
        outcome: ActionOutcome,
    ) -> Result<ActionReceipt, JournalError> {
        self.record_target_with_payload(
            action_id,
            target,
            idempotency_key,
            expected_revision,
            ActionPayload::absent(),
            outcome,
        )
    }

    /// Record a mutation and what it carried, idempotently by key.
    ///
    /// Idempotency is exact in both directions. Replaying a key against the
    /// same target *and* the same payload returns the identical receipt;
    /// changing either is a typed conflict rather than an overwrite or a second
    /// execution.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::IdempotencyConflict`] when a key is reused for a
    /// different target, [`JournalError::IdempotencyPayloadConflict`] when it is
    /// reused for a different payload, and [`JournalError::Field`] for an
    /// invalid identifier.
    pub fn record_with_payload(
        &mut self,
        action_id: &str,
        target: &str,
        idempotency_key: &str,
        expected_revision: Option<Revision>,
        payload: ActionPayload,
        outcome: ActionOutcome,
    ) -> Result<ActionReceipt, JournalError> {
        self.record_target_with_payload(
            action_id,
            ActionTarget::new(target)?,
            idempotency_key,
            expected_revision,
            payload,
            outcome,
        )
    }

    /// Record a mutation against an already validated target.
    ///
    /// This is the typed core of the ledger. The string-taking methods are
    /// validation adapters and store exactly the same [`ActionTarget`].
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::IdempotencyConflict`] when a key is reused for a
    /// different target, [`JournalError::IdempotencyPayloadConflict`] when it is
    /// reused for a different payload, and [`JournalError::Field`] for an
    /// invalid action identity or idempotency key.
    pub fn record_target_with_payload(
        &mut self,
        action_id: &str,
        target: ActionTarget,
        idempotency_key: &str,
        expected_revision: Option<Revision>,
        payload: ActionPayload,
        outcome: ActionOutcome,
    ) -> Result<ActionReceipt, JournalError> {
        bounded(action_id, "action_id")?;
        bounded(idempotency_key, "idempotency_key")?;

        if let Some(existing) = self
            .receipts
            .iter()
            .find(|receipt| receipt.idempotency_key == idempotency_key)
        {
            if existing.target != target {
                return Err(JournalError::IdempotencyConflict {
                    recorded_target: existing.target.clone(),
                    offered_target: target,
                });
            }
            if existing.payload != payload {
                return Err(JournalError::IdempotencyPayloadConflict {
                    recorded_payload: existing.payload.clone(),
                    offered_payload: payload,
                });
            }
            return Ok(existing.clone());
        }

        let receipt = ActionReceipt {
            action_id: action_id.to_owned(),
            target,
            idempotency_key: idempotency_key.to_owned(),
            expected_revision,
            payload,
            outcome,
        };
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Look a receipt up by idempotency key.
    ///
    /// Available after the requesting client has disconnected, because the
    /// ledger owns the receipt outright.
    #[must_use]
    pub fn find(&self, idempotency_key: &str) -> Option<&ActionReceipt> {
        self.receipts
            .iter()
            .find(|receipt| receipt.idempotency_key == idempotency_key)
    }
}

/// The window of positions a topic still retains, inclusive at both ends.
///
/// A window that ends below where it starts retains nothing, and judging a
/// cursor against one would answer a question about a range that does not
/// exist. [`RetainedRange::new`] refuses it, so no such window can be built and
/// handed to a cursor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RetainedRange {
    first: u64,
    last: u64,
}

impl RetainedRange {
    /// Declare what a topic still retains.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::InvertedRetainedRange`] when `last` is below
    /// `first`.
    pub const fn new(first: u64, last: u64) -> Result<Self, JournalError> {
        if last < first {
            return Err(JournalError::InvertedRetainedRange {
                from: first,
                to: last,
            });
        }
        Ok(Self { first, last })
    }

    /// Lowest position still retained.
    #[must_use]
    pub const fn first(self) -> u64 {
        self.first
    }

    /// Highest position still retained.
    #[must_use]
    pub const fn last(self) -> u64 {
        self.last
    }

    /// The position a consumer that has received everything retained holds
    /// next: one past [`RetainedRange::last`].
    ///
    /// A cursor names the boundary *before* the next event it will receive, so
    /// the positions a topic can resume a consumer at are
    /// `first ..= caught_up` — one more position than the window retains. This
    /// is the off-by-one that separates "resumable" from "retained", and it is
    /// named here rather than left implicit in a comparison.
    ///
    /// Saturates: a window ending at `u64::MAX` reports `u64::MAX`, which is
    /// still the highest position any cursor can hold, so nothing is
    /// misclassified and nothing overflows.
    #[must_use]
    pub const fn caught_up(self) -> u64 {
        self.last.saturating_add(1)
    }
}

/// Where a consumer may resume on a topic.
///
/// Closed: there is no third answer, so a consumer that has fallen out of
/// retention cannot be served a silent partial stream or an empty success.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CursorResume {
    /// Live delivery may begin at this position.
    Live {
        /// First position the consumer will receive.
        from: u64,
    },
    /// The cursor is outside retention; a bounded snapshot is required first.
    ResyncRequired {
        /// Lowest position still retained.
        snapshot_from: u64,
        /// Highest position still retained.
        snapshot_to: u64,
    },
}

impl CursorResume {
    /// The terminal outcome this decision reports to the caller.
    ///
    /// A resync reports [`ActionOutcome::ResyncRequired`]. Live delivery is not
    /// a terminal outcome and reports none.
    #[must_use]
    pub const fn outcome(self) -> Option<ActionOutcome> {
        match self {
            Self::Live { .. } => None,
            Self::ResyncRequired { .. } => Some(ActionOutcome::ResyncRequired),
        }
    }
}

/// A durable consumer position, keyed by consumer identity and topic.
///
/// [`JournalCursor::position`] is the next position the consumer will receive.
/// It moves only through [`JournalCursor::advance_to`]:
///
/// ```
/// use automonique_protocol::journal::JournalCursor;
/// let mut cursor = JournalCursor::new("projector", "work", 10).unwrap();
/// cursor.advance_to(12).unwrap();
/// assert_eq!(cursor.position(), 12);
/// ```
///
/// The field itself is private and [`JournalCursor::advance_to`] is the only
/// method that writes it, so no route to a rewind exists that does not produce
/// the typed error. The compile-fail below pins the direct-write route; it pins
/// that route rather than the absence of every setter a future edit might add.
///
/// The residual is exact and irreducible, and is the same one [`ActionLedger`]
/// carries: an unchecked `set_position` would have to be written into this
/// module, module privacy cannot defend a module against itself, and no test
/// can observe the absence of a method nobody has written. Outside this module
/// the position moves only forward, by type.
///
/// The only difference from the case above is writing the position directly:
///
/// ```compile_fail
/// use automonique_protocol::journal::JournalCursor;
/// let mut cursor = JournalCursor::new("projector", "work", 10).unwrap();
/// cursor.position = 12;
/// assert_eq!(cursor.position(), 12);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCursor {
    consumer: String,
    topic: String,
    position: u64,
}

impl JournalCursor {
    /// Record a consumer position.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Field`] for an invalid identifier.
    pub fn new(consumer: &str, topic: &str, position: u64) -> Result<Self, JournalError> {
        bounded(consumer, "consumer")?;
        bounded(topic, "topic")?;
        Ok(Self {
            consumer: consumer.to_owned(),
            topic: topic.to_owned(),
            position,
        })
    }

    /// The consumer this position belongs to.
    #[must_use]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    /// The topic this position is kept on.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Current position: the next position the consumer will receive.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Where this consumer may resume, given what the topic still retains.
    ///
    /// The resumable positions are exactly
    /// `retained.first() ..= retained.caught_up()`. Anything outside that set
    /// yields [`CursorResume::ResyncRequired`] carrying bounded snapshot
    /// coordinates — never a silent partial stream and never an empty success.
    /// There are three regions and each has a different failure to avoid:
    ///
    /// - **Below `first`** — the cursor has fallen off the back of retention.
    ///   The positions it is waiting for have been discarded, so streaming from
    ///   here would silently skip them. Resync.
    /// - **`first ..= caught_up`** — resumable. `caught_up` is `last + 1`, the
    ///   ordinary state of a consumer that has received everything: resyncing
    ///   it would demand a snapshot of history it already has, forever.
    /// - **Above `caught_up`** — the cursor names a position the topic has
    ///   never reached. That is not caught up, it is ahead: streaming from here
    ///   would silently skip every position between `caught_up` and the cursor
    ///   once those are written. It is reachable after a topic is truncated or
    ///   rebuilt behind a durable cursor, so it is classified rather than
    ///   assumed away. Resync.
    ///
    /// The one place this differs from reading "outside the retained range"
    /// literally is `caught_up` itself, which is outside the retained window
    /// and is nonetheless live. That is forced: a cursor names the boundary
    /// before the next event it will receive, so the resumable set is always
    /// one larger than the retained set, whichever end the convention is
    /// anchored to. `plan/contracts/R1-12.md` records it as amendment A2.
    ///
    /// Not consistent with `event::resolve_subscription`, which classifies only
    /// the below-window case and returns live for everything above. That module
    /// is outside this item's lease; the divergence is recorded in the evidence
    /// rather than fixed here or copied.
    #[must_use]
    pub const fn resume_within(&self, retained: RetainedRange) -> CursorResume {
        if self.position < retained.first() || self.position > retained.caught_up() {
            CursorResume::ResyncRequired {
                snapshot_from: retained.first(),
                snapshot_to: retained.last(),
            }
        } else {
            CursorResume::Live {
                from: self.position,
            }
        }
    }

    /// Move forward.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::CursorWentBackwards`].
    pub fn advance_to(&mut self, position: u64) -> Result<(), JournalError> {
        if position < self.position {
            return Err(JournalError::CursorWentBackwards {
                current: self.position,
                offered: position,
            });
        }
        self.position = position;
        Ok(())
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), JournalError> {
    bounded_to(value, field, MAX_JOURNAL_FIELD_BYTES)
}

fn bounded_to(value: &str, field: &'static str, max_bytes: usize) -> Result<(), JournalError> {
    crate::primitives::bounded_value(value, max_bytes)
        .map_err(|error| JournalError::Field { field, error })
}
