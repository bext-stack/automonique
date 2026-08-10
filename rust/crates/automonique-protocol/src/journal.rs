// SPDX-License-Identifier: Elastic-2.0

//! The domain journal: events, aggregate revisions, action receipts and replay.
//!
//! Replay may rebuild a projection or explain history. It may never drain an
//! outbox or repeat an effect, and that is enforced by reachability rather than
//! by convention: [`Outbox`] has no public constructor, so a replay callback
//! cannot obtain one.
//!
//! A projection over replay compiles:
//!
//! ```
//! use automonique_protocol::journal::{Journal, Projection, DomainEvent};
//! # use automonique_protocol::journal::{AggregateId, EventSchemaVersion};
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
//! ).unwrap();
//! journal.append(event).unwrap();
//!
//! let mut counter = Counter::default();
//! journal.replay(&mut counter);
//! assert_eq!(counter.0, 1);
//! ```
//!
//! Reaching an effect from inside one does not:
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

use core::fmt;
use std::error::Error;

use crate::codec::VersionRange;
use crate::primitives::{EpochMillis, Revision, ValueError};

/// Maximum UTF-8 byte length of a journal identifier.
pub const MAX_JOURNAL_FIELD_BYTES: usize = 128;

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
    /// An event's schema version lies outside the reader's decode range.
    EventSchemaOutOfRange {
        /// Lowest decodable version.
        supported_min: u32,
        /// Highest decodable version.
        supported_max: u32,
        /// Version the event declared.
        offered: u32,
    },
    /// One idempotency key was reused for a different target or payload.
    IdempotencyConflict {
        /// The target already recorded under this key.
        recorded_target: String,
        /// The target offered.
        offered_target: String,
    },
    /// A cursor was moved backwards.
    CursorWentBackwards {
        /// Current position.
        current: u64,
        /// Offered position.
        offered: u64,
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
            Self::EventSchemaOutOfRange { .. } => "event_schema_out_of_range",
            Self::IdempotencyConflict { .. } => "idempotency_conflict",
            Self::CursorWentBackwards { .. } => "cursor_went_backwards",
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
            Self::CursorWentBackwards { current, offered } => write!(
                formatter,
                "cursor cannot move from {current} back to {offered}"
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
    ) -> Result<Self, JournalError> {
        bounded(kind, "event_kind")?;
        Ok(Self {
            event_id,
            aggregate,
            revision,
            schema_version,
            at,
            kind: kind.to_owned(),
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

/// Something rebuilt by reading history.
///
/// The only argument is a borrowed event. A projection has no transport, no
/// store and no effect handle, because none is passed to it.
pub trait Projection {
    /// Fold one event into the projection.
    fn apply(&mut self, event: &DomainEvent);
}

/// An effect sink.
///
/// Deliberately unconstructable: the field is private and there is no
/// constructor, no `Default` and no `From`. A [`Projection`] therefore cannot
/// obtain one, so replay cannot emit. This is the mechanism behind "replay is
/// side-effect-free"; a comment saying so would be the thing that gets
/// violated.
///
/// A transaction layer that legitimately owns effects will receive one from
/// the store, which is why nothing here hands them out.
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
        let expected = self
            .events
            .iter()
            .rfind(|existing| existing.aggregate() == event.aggregate())
            .map_or(Revision::FIRST.get(), |latest| latest.revision().get() + 1);
        if event.revision().get() != expected {
            return Err(JournalError::RevisionConflict {
                expected,
                observed: event.revision().get(),
            });
        }
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
    /// Takes a projection and nothing else. There is no parameter through which
    /// an effect, outbox, notification or transport could be supplied.
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

/// The durable record of one accepted mutation.
///
/// Owns every field. There is no lifetime parameter, so a receipt cannot borrow
/// from a connection and therefore stays queryable after the client that
/// requested it has gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReceipt {
    action_id: String,
    target: String,
    idempotency_key: String,
    expected_revision: Option<Revision>,
    outcome: ActionOutcome,
}

impl ActionReceipt {
    /// The action identity.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// The typed target.
    #[must_use]
    pub fn target(&self) -> &str {
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

    /// The terminal outcome.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        self.outcome
    }
}

/// Receipts recorded against idempotency keys.
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

    /// Record a mutation, idempotently by key.
    ///
    /// Replaying a key against the same target returns the identical receipt.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::IdempotencyConflict`] when a key is reused for a
    /// different target — a second execution, not an overwrite — and
    /// [`JournalError::Field`] for an invalid identifier.
    pub fn record(
        &mut self,
        action_id: &str,
        target: &str,
        idempotency_key: &str,
        expected_revision: Option<Revision>,
        outcome: ActionOutcome,
    ) -> Result<ActionReceipt, JournalError> {
        bounded(action_id, "action_id")?;
        bounded(target, "target")?;
        bounded(idempotency_key, "idempotency_key")?;

        if let Some(existing) = self
            .receipts
            .iter()
            .find(|receipt| receipt.idempotency_key == idempotency_key)
        {
            if existing.target != target {
                return Err(JournalError::IdempotencyConflict {
                    recorded_target: existing.target.clone(),
                    offered_target: target.to_owned(),
                });
            }
            return Ok(existing.clone());
        }

        let receipt = ActionReceipt {
            action_id: action_id.to_owned(),
            target: target.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            expected_revision,
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

/// A durable consumer position, keyed by consumer identity and topic.
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

    /// Current position.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
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
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_JOURNAL_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_JOURNAL_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(JournalError::Field { field, error }),
        None => Ok(()),
    }
}
