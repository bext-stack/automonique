// SPDX-License-Identifier: Elastic-2.0

//! Cross-surface interaction values.
//!
//! One typed vocabulary serves the CLI, TUI, dashboard, desktop and messaging
//! clients: queued composer input with durable identity, retry lineage,
//! idempotent stop and undo, checkpoints, compression lineage, per-turn context
//! usage, and read-only projections. A presentation shortcut cannot become a new
//! authority, because every action a projection offers names the authority it
//! requires and only [`authorize`] produces an [`AuthorizedIntent`].
//!
//! The five request kinds are distinct types, so no surface can turn one into
//! another:
//!
//! ```
//! use automonique_protocol::interaction::{CancelRequest, CancelScope, RequestRef};
//! let cancel = CancelRequest::new(RequestRef::new("r-1").unwrap(), CancelScope::Turn);
//! let _kept: CancelRequest = cancel;
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::interaction::{CancelRequest, CancelScope, RequestRef, SteerRequest};
//! let cancel = CancelRequest::new(RequestRef::new("r-1").unwrap(), CancelScope::Turn);
//! // A cancel is not a steer.
//! let _steer: SteerRequest = cancel;
//! ```
//!
//! Steering carries a bounded payload, not an in-memory prompt string:
//!
//! ```
//! use automonique_protocol::interaction::{SteerRequest, SteerText};
//! let steer = SteerRequest::new(SteerText::new("prefer the smaller diff").unwrap());
//! assert_eq!(steer.text().as_str(), "prefer the smaller diff");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::interaction::SteerRequest;
//! // A prompt string is not a steer request.
//! let steer: SteerRequest = String::from("prefer the smaller diff");
//! ```
//!
//! This module defines values only. It renders nothing, parses no surface
//! syntax, reads no clock, performs no I/O and runs no compression.

use core::fmt;
use std::error::Error;

use crate::primitives::{BoundedString, EpochMillis, OpaqueId, Revision, ValueError};

/// Maximum UTF-8 byte length of an interaction identifier.
pub const MAX_INTERACTION_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of bounded interaction text.
pub const MAX_INTERACTION_TEXT_BYTES: usize = 4096;

/// Maximum number of items in one composer queue.
pub const MAX_QUEUED_ITEMS: usize = 256;

/// Maximum number of protected facts one compression may declare.
pub const MAX_PROTECTED_FACTS: usize = 64;

/// Maximum number of parameters one command invocation may carry.
pub const MAX_COMMAND_PARAMETERS: usize = 32;

/// Maximum number of actions one projection may offer.
pub const MAX_PROJECTION_ACTIONS: usize = 64;

/// Maximum number of namespaced entries one extension projection may carry.
pub const MAX_PROJECTION_ENTRIES: usize = 64;

/// Maximum number of checkpoints one log may hold.
pub const MAX_CHECKPOINTS: usize = 512;

/// Bounded, control-free interaction text.
pub type InteractionText = BoundedString<MAX_INTERACTION_TEXT_BYTES>;

/// Bounded steering text.
pub type SteerText = InteractionText;

macro_rules! interaction_domain {
    ($domain:ident, $alias:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $domain;

        impl crate::primitives::IdDomain for $domain {}

        #[doc = $doc]
        pub type $alias = OpaqueId<$domain, MAX_INTERACTION_ID_BYTES>;
    };
}

interaction_domain!(
    QueueItemDomain,
    QueueItemId,
    "Durable identity of one queued composer item."
);
interaction_domain!(
    SessionDomain,
    SessionRef,
    "The session a queued item or checkpoint belongs to."
);
interaction_domain!(AttemptDomain, AttemptRef, "One attempt at a turn.");
interaction_domain!(TurnDomain, TurnRef, "One turn whose context was assembled.");
interaction_domain!(
    RequestDomain,
    RequestRef,
    "The identity an idempotent intent is keyed by."
);
interaction_domain!(
    ContentDigestDomain,
    ContentDigest,
    "A content-addressed digest."
);
interaction_domain!(
    TranscriptEntryDomain,
    TranscriptEntryId,
    "One authoritative transcript entry."
);
interaction_domain!(
    ExtensionDomain,
    ExtensionId,
    "A plugin or widget extension namespace."
);
interaction_domain!(
    CommandDomain,
    CommandId,
    "A registry command identifier shared by every surface."
);

/// Why an interaction value was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InteractionError {
    /// One transcript entry identity was appended twice.
    DuplicateTranscriptEntry {
        /// The repeated identity.
        id: String,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A bounded collection exceeded its ceiling.
    TooMany {
        /// The rejected collection.
        field: &'static str,
        /// Maximum accepted count.
        max: usize,
        /// Supplied count.
        actual: usize,
    },
    /// A queue was built with no items, so it claims an order it does not have.
    QueueEmpty,
    /// A durable identity occurred more than once.
    DuplicateIdentity {
        /// Which collection.
        field: &'static str,
        /// The repeated identity.
        identity: String,
    },
    /// An operation named an identity that is not present.
    UnknownIdentity {
        /// Which collection.
        field: &'static str,
        /// The absent identity.
        identity: String,
    },
    /// A queued item belongs to a different session than the queue.
    SessionMismatch {
        /// The queue's session.
        expected: String,
        /// The item's session.
        actual: String,
    },
    /// Queue positions did not strictly increase.
    PositionNotMonotonic {
        /// The preceding position.
        previous: u32,
        /// The position that did not advance.
        requested: u32,
    },
    /// A position addressed a slot the queue does not have.
    PositionOutOfRange {
        /// How many items the queue holds.
        length: usize,
        /// The requested position.
        requested: u32,
    },
    /// Position arithmetic left the representable range.
    PositionOverflow,
    /// An undo named a target that cannot be reversed.
    NotReversible {
        /// The target class.
        target: UndoTargetKind,
    },
    /// A restore named a checkpoint the log does not hold.
    UnknownCheckpoint {
        /// The requested digest.
        digest: String,
    },
    /// A restore named a known digest at the wrong revision.
    CheckpointRevisionMismatch {
        /// The recorded revision.
        recorded: u64,
        /// The requested revision.
        requested: u64,
    },
    /// A transcript range ended before it began.
    RangeInverted {
        /// The range start.
        from: u64,
        /// The range end.
        to: u64,
    },
    /// An append did not advance the transcript revision.
    RevisionNotAdvancing {
        /// The last recorded revision.
        last: u64,
        /// The revision offered.
        requested: u64,
    },
    /// A compression named a transcript range the transcript does not cover.
    UnknownTranscriptRange {
        /// The range start.
        from: u64,
        /// The range end.
        to: u64,
    },
    /// A per-turn usage breakdown omitted a component class.
    MissingComponentClass {
        /// The absent class.
        class: ContextComponentClass,
    },
    /// A per-turn usage breakdown repeated a component class.
    DuplicateComponentClass {
        /// The repeated class.
        class: ContextComponentClass,
    },
    /// A namespaced projection addressed another extension's namespace.
    ForeignNamespace {
        /// The extension that owns the projection.
        owner: String,
        /// The namespace the key named.
        requested: String,
    },
    /// An action was invoked without the authority it names.
    AuthorityRequired {
        /// The authority the action requires.
        authority: RequiredAuthority,
    },
}

impl InteractionError {
    /// Every stable category this module can produce.
    ///
    /// Published as a constant so generated SDK fixtures can enforce the same
    /// edges without duplicating hidden policy.
    pub const CATEGORIES: [&'static str; 20] = [
        "duplicate_transcript_entry",
        "field_invalid",
        "too_many",
        "queue_empty",
        "duplicate_identity",
        "unknown_identity",
        "session_mismatch",
        "position_not_monotonic",
        "position_out_of_range",
        "position_overflow",
        "not_reversible",
        "unknown_checkpoint",
        "checkpoint_revision_mismatch",
        "range_inverted",
        "revision_not_advancing",
        "unknown_transcript_range",
        "missing_component_class",
        "duplicate_component_class",
        "foreign_namespace",
        "authority_required",
    ];

    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::DuplicateTranscriptEntry { .. } => "duplicate_transcript_entry",
            Self::Field { .. } => "field_invalid",
            Self::TooMany { .. } => "too_many",
            Self::QueueEmpty => "queue_empty",
            Self::DuplicateIdentity { .. } => "duplicate_identity",
            Self::UnknownIdentity { .. } => "unknown_identity",
            Self::SessionMismatch { .. } => "session_mismatch",
            Self::PositionNotMonotonic { .. } => "position_not_monotonic",
            Self::PositionOutOfRange { .. } => "position_out_of_range",
            Self::PositionOverflow => "position_overflow",
            Self::NotReversible { .. } => "not_reversible",
            Self::UnknownCheckpoint { .. } => "unknown_checkpoint",
            Self::CheckpointRevisionMismatch { .. } => "checkpoint_revision_mismatch",
            Self::RangeInverted { .. } => "range_inverted",
            Self::RevisionNotAdvancing { .. } => "revision_not_advancing",
            Self::UnknownTranscriptRange { .. } => "unknown_transcript_range",
            Self::MissingComponentClass { .. } => "missing_component_class",
            Self::DuplicateComponentClass { .. } => "duplicate_component_class",
            Self::ForeignNamespace { .. } => "foreign_namespace",
            Self::AuthorityRequired { .. } => "authority_required",
        }
    }
}

impl fmt::Display for InteractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTranscriptEntry { id } => write!(
                formatter,
                "transcript entry {id} is already recorded; appending it again \
                 would give one identity two digests"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::TooMany { field, max, actual } => {
                write!(
                    formatter,
                    "{field} holds {actual} entries; maximum is {max}"
                )
            }
            Self::QueueEmpty => formatter.write_str("a composer queue holds no items"),
            Self::DuplicateIdentity { field, identity } => {
                write!(formatter, "{field} repeats the identity {identity}")
            }
            Self::UnknownIdentity { field, identity } => {
                write!(formatter, "{field} does not hold the identity {identity}")
            }
            Self::SessionMismatch { expected, actual } => write!(
                formatter,
                "queued item belongs to session {actual}, not {expected}"
            ),
            Self::PositionNotMonotonic {
                previous,
                requested,
            } => write!(
                formatter,
                "queue position {requested} does not advance past {previous}"
            ),
            Self::PositionOutOfRange { length, requested } => write!(
                formatter,
                "position {requested} is outside a queue of {length} items"
            ),
            Self::PositionOverflow => formatter.write_str("queue position arithmetic overflowed"),
            Self::NotReversible { target } => write!(
                formatter,
                "a {} is not reversible; undo cannot name one",
                target.as_str()
            ),
            Self::UnknownCheckpoint { digest } => {
                write!(formatter, "no checkpoint is recorded at digest {digest}")
            }
            Self::CheckpointRevisionMismatch {
                recorded,
                requested,
            } => write!(
                formatter,
                "checkpoint is recorded at revision {recorded}, not {requested}"
            ),
            Self::RangeInverted { from, to } => {
                write!(formatter, "transcript range {from}..={to} is inverted")
            }
            Self::RevisionNotAdvancing { last, requested } => write!(
                formatter,
                "transcript revision {requested} does not advance past {last}"
            ),
            Self::UnknownTranscriptRange { from, to } => write!(
                formatter,
                "the transcript does not cover the range {from}..={to}"
            ),
            Self::MissingComponentClass { class } => write!(
                formatter,
                "context usage omits the {} component class",
                class.as_str()
            ),
            Self::DuplicateComponentClass { class } => write!(
                formatter,
                "context usage repeats the {} component class",
                class.as_str()
            ),
            Self::ForeignNamespace { owner, requested } => write!(
                formatter,
                "extension {owner} cannot address the namespace {requested}"
            ),
            Self::AuthorityRequired { authority } => write!(
                formatter,
                "the action requires the {} authority",
                authority.as_str()
            ),
        }
    }
}

impl Error for InteractionError {}

/// A client surface.
///
/// One vocabulary serves all of them; nothing here is per-surface syntax.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SurfaceKind {
    /// A one-shot or scripted command line.
    Cli,
    /// An interactive terminal client.
    Tui,
    /// A browser dashboard.
    Dashboard,
    /// A desktop client.
    Desktop,
    /// A messaging client such as a chat bridge.
    Messaging,
}

impl SurfaceKind {
    /// Every surface, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::Cli,
        Self::Tui,
        Self::Dashboard,
        Self::Desktop,
        Self::Messaging,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Tui => "tui",
            Self::Dashboard => "dashboard",
            Self::Desktop => "desktop",
            Self::Messaging => "messaging",
        }
    }
}

/// A monotonic position within a composer queue.
///
/// A position is an **ordering key**, not an index. [`InputQueue::new`] requires
/// only that positions strictly increase, so `0, 7, 9` is as valid a queue as
/// `0, 1, 2` and the item storing position `7` sits at rank `1`. The two
/// coincide in every queue [`InputQueue::reorder`] returns, because reordering
/// renumbers densely from [`QueuePosition::FIRST`].
///
/// [`ReorderRequest::to`] is the one place the type carries a **rank** instead:
/// a destination names a 0-based slot in the receiving queue's current order, so
/// it is bounded by that queue's length rather than by the positions its items
/// store.
///
/// Every advance is checked; there is no wrapping successor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueuePosition(u32);

impl QueuePosition {
    /// The first position in any queue.
    pub const FIRST: Self = Self(0);

    /// The last representable position.
    pub const MAX: Self = Self(u32::MAX);

    /// Build a position.
    #[must_use]
    pub const fn new(position: u32) -> Self {
        Self(position)
    }

    /// The position as a primitive.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next position.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::PositionOverflow`] rather than wrapping.
    pub const fn checked_next(self) -> Result<Self, InteractionError> {
        match self.0.checked_add(1) {
            Some(next) => Ok(Self(next)),
            None => Err(InteractionError::PositionOverflow),
        }
    }
}

/// A steering instruction for work already in flight.
///
/// The payload is bounded text with its own type, so a steer is never an edit
/// of a prompt string a surface happens to be holding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SteerRequest {
    text: SteerText,
}

impl SteerRequest {
    /// Record a steering instruction.
    #[must_use]
    pub const fn new(text: SteerText) -> Self {
        Self { text }
    }

    /// The bounded instruction.
    #[must_use]
    pub const fn text(&self) -> &SteerText {
        &self.text
    }
}

/// The lineage an attempt carries.
///
/// Holds the original attempt and the immediate predecessor. It holds no
/// evidence, so a retry has nothing to address, replace or invalidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptLineage {
    original: AttemptRef,
    predecessor: AttemptRef,
}

impl AttemptLineage {
    /// The lineage of a first attempt, which is its own original.
    #[must_use]
    pub fn root(attempt: AttemptRef) -> Self {
        Self {
            original: attempt.clone(),
            predecessor: attempt,
        }
    }

    /// The first attempt in the chain.
    #[must_use]
    pub const fn original(&self) -> &AttemptRef {
        &self.original
    }

    /// The attempt immediately before the successor.
    #[must_use]
    pub const fn predecessor(&self) -> &AttemptRef {
        &self.predecessor
    }
}

/// A retry, naming the attempt it derives from and the successor it produces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryRequest {
    lineage: AttemptLineage,
    successor: AttemptRef,
    reason: InteractionText,
}

impl RetryRequest {
    /// Derive a successor attempt from an existing lineage.
    #[must_use]
    pub const fn derive(
        lineage: AttemptLineage,
        successor: AttemptRef,
        reason: InteractionText,
    ) -> Self {
        Self {
            lineage,
            successor,
            reason,
        }
    }

    /// The first attempt in the chain.
    #[must_use]
    pub const fn original(&self) -> &AttemptRef {
        self.lineage.original()
    }

    /// The attempt this retry derives from.
    #[must_use]
    pub const fn predecessor(&self) -> &AttemptRef {
        self.lineage.predecessor()
    }

    /// The successor attempt this retry produces.
    #[must_use]
    pub const fn successor(&self) -> &AttemptRef {
        &self.successor
    }

    /// Why the retry was requested.
    #[must_use]
    pub const fn reason(&self) -> &InteractionText {
        &self.reason
    }

    /// The lineage the successor attempt carries.
    ///
    /// The original is preserved and the immediate predecessor becomes this
    /// retry's successor, so a retry of a retry records both.
    #[must_use]
    pub fn successor_lineage(&self) -> AttemptLineage {
        AttemptLineage {
            original: self.lineage.original.clone(),
            predecessor: self.successor.clone(),
        }
    }
}

/// A move of one identified queue item to an explicit destination rank.
///
/// The destination is a 0-based rank in the receiving queue's current order —
/// the slot the item lands in — and never one of the positions that queue's
/// items happen to store. [`QueuePosition`] records why the two can differ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReorderRequest {
    item: QueueItemId,
    to: QueuePosition,
}

impl ReorderRequest {
    /// Name the item to move and the rank it goes to.
    #[must_use]
    pub const fn new(item: QueueItemId, to: QueuePosition) -> Self {
        Self { item, to }
    }

    /// The item being moved.
    #[must_use]
    pub const fn item(&self) -> &QueueItemId {
        &self.item
    }

    /// The destination rank: a 0-based slot in the receiving queue's order.
    #[must_use]
    pub const fn to(&self) -> QueuePosition {
        self.to
    }
}

/// What a stop reaches.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CancelScope {
    /// The turn currently running.
    Turn,
    /// The tool call currently running.
    Tool,
    /// Everything still queued.
    Queue,
}

impl CancelScope {
    /// Every scope, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Turn, Self::Tool, Self::Queue];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Turn => "turn",
            Self::Tool => "tool",
            Self::Queue => "queue",
        }
    }
}

/// A stop, keyed by request identity so repeating it is not a second effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelRequest {
    request: RequestRef,
    scope: CancelScope,
}

impl CancelRequest {
    /// Record a stop.
    #[must_use]
    pub const fn new(request: RequestRef, scope: CancelScope) -> Self {
        Self { request, scope }
    }

    /// The identity this stop is idempotent by.
    #[must_use]
    pub const fn request(&self) -> &RequestRef {
        &self.request
    }

    /// What the stop reaches.
    #[must_use]
    pub const fn scope(&self) -> CancelScope {
        self.scope
    }
}

/// A class of thing an undo may name.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UndoTargetKind {
    /// A file edit the run applied.
    FileEdit,
    /// A queued composer item not yet dispatched.
    QueuedInput,
    /// A checkpoint restore.
    CheckpointRestore,
    /// A committed transcript entry, which is authoritative evidence.
    TranscriptEntry,
    /// An effect outside the workspace, such as a message already sent.
    ExternalEffect,
}

impl UndoTargetKind {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::FileEdit,
        Self::QueuedInput,
        Self::CheckpointRestore,
        Self::TranscriptEntry,
        Self::ExternalEffect,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileEdit => "file_edit",
            Self::QueuedInput => "queued_input",
            Self::CheckpointRestore => "checkpoint_restore",
            Self::TranscriptEntry => "transcript_entry",
            Self::ExternalEffect => "external_effect",
        }
    }

    /// Whether this class can be reversed at all.
    ///
    /// A transcript entry and an external effect cannot: reversing the first
    /// would rewrite authoritative evidence, and the second has already left.
    #[must_use]
    pub const fn is_reversible(self) -> bool {
        matches!(
            self,
            Self::FileEdit | Self::QueuedInput | Self::CheckpointRestore
        )
    }
}

/// The exact thing an undo reverses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UndoTarget {
    kind: UndoTargetKind,
    identity: InteractionText,
}

impl UndoTarget {
    /// Name a target.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::NotReversible`] when the class cannot be
    /// reversed, so an irreversible target never reaches an undo.
    pub fn new(kind: UndoTargetKind, identity: InteractionText) -> Result<Self, InteractionError> {
        if !kind.is_reversible() {
            return Err(InteractionError::NotReversible { target: kind });
        }
        Ok(Self { kind, identity })
    }

    /// The target class.
    #[must_use]
    pub const fn kind(&self) -> UndoTargetKind {
        self.kind
    }

    /// The exact target named.
    #[must_use]
    pub const fn identity(&self) -> &InteractionText {
        &self.identity
    }
}

/// An undo, keyed by request identity and naming the exact target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UndoRequest {
    request: RequestRef,
    target: UndoTarget,
}

impl UndoRequest {
    /// Record an undo.
    #[must_use]
    pub const fn new(request: RequestRef, target: UndoTarget) -> Self {
        Self { request, target }
    }

    /// The identity this undo is idempotent by.
    #[must_use]
    pub const fn request(&self) -> &RequestRef {
        &self.request
    }

    /// The target being reversed.
    #[must_use]
    pub const fn target(&self) -> &UndoTarget {
        &self.target
    }
}

/// What a queued composer item asks for.
///
/// Five distinct payload types. None is a mutation of another, and none is a
/// string a surface edited in place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// Steer work already in flight.
    Steer(SteerRequest),
    /// Retry an attempt.
    Retry(RetryRequest),
    /// Move an item to an explicit position.
    Reorder(ReorderRequest),
    /// Stop running work.
    Cancel(CancelRequest),
    /// Reverse a named target.
    Undo(UndoRequest),
}

impl RequestKind {
    /// Every kind's stable spelling, for coverage checks.
    pub const KINDS: [&'static str; 5] = ["steer", "retry", "reorder", "cancel", "undo"];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Steer(_) => "steer",
            Self::Retry(_) => "retry",
            Self::Reorder(_) => "reorder",
            Self::Cancel(_) => "cancel",
            Self::Undo(_) => "undo",
        }
    }
}

/// One durably identified queued composer item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedInput {
    id: QueueItemId,
    session: SessionRef,
    position: QueuePosition,
    request: RequestKind,
}

impl QueuedInput {
    /// Record a queued item.
    #[must_use]
    pub const fn new(
        id: QueueItemId,
        session: SessionRef,
        position: QueuePosition,
        request: RequestKind,
    ) -> Self {
        Self {
            id,
            session,
            position,
            request,
        }
    }

    /// The item's own opaque identity.
    #[must_use]
    pub const fn id(&self) -> &QueueItemId {
        &self.id
    }

    /// The session that owns the item.
    #[must_use]
    pub const fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The item's monotonic position.
    #[must_use]
    pub const fn position(&self) -> QueuePosition {
        self.position
    }

    /// What the item asks for.
    #[must_use]
    pub const fn request(&self) -> &RequestKind {
        &self.request
    }
}

/// A non-empty composer queue owned by one session.
///
/// Every operation returns a new queue, so an ordering is a value rather than a
/// mutable buffer a surface shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputQueue {
    session: SessionRef,
    items: Vec<QueuedInput>,
}

impl InputQueue {
    /// Build a queue from durable items.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::QueueEmpty`] for no items,
    /// [`InteractionError::TooMany`] above [`MAX_QUEUED_ITEMS`],
    /// [`InteractionError::SessionMismatch`] for an item owned elsewhere,
    /// [`InteractionError::PositionNotMonotonic`] for positions that do not
    /// strictly increase, and [`InteractionError::DuplicateIdentity`] for a
    /// repeated identity.
    ///
    /// Positions must increase but need not be dense, so an item's stored
    /// position is an ordering key rather than its rank in the queue.
    pub fn new(session: SessionRef, items: Vec<QueuedInput>) -> Result<Self, InteractionError> {
        if items.is_empty() {
            return Err(InteractionError::QueueEmpty);
        }
        if items.len() > MAX_QUEUED_ITEMS {
            return Err(InteractionError::TooMany {
                field: "queued_items",
                max: MAX_QUEUED_ITEMS,
                actual: items.len(),
            });
        }
        let mut previous: Option<QueuePosition> = None;
        for (index, item) in items.iter().enumerate() {
            if item.session != session {
                return Err(InteractionError::SessionMismatch {
                    expected: session.as_str().to_owned(),
                    actual: item.session.as_str().to_owned(),
                });
            }
            if let Some(previous) = previous
                && item.position <= previous
            {
                return Err(InteractionError::PositionNotMonotonic {
                    previous: previous.get(),
                    requested: item.position.get(),
                });
            }
            previous = Some(item.position);
            if items[..index].iter().any(|earlier| earlier.id == item.id) {
                return Err(InteractionError::DuplicateIdentity {
                    field: "queued_items",
                    identity: item.id.as_str().to_owned(),
                });
            }
        }
        Ok(Self { session, items })
    }

    /// The owning session.
    #[must_use]
    pub const fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The items in queue order.
    #[must_use]
    pub fn items(&self) -> &[QueuedInput] {
        &self.items
    }

    /// The identities the queue holds, in order.
    #[must_use]
    pub fn identities(&self) -> Vec<QueueItemId> {
        self.items.iter().map(|item| item.id.clone()).collect()
    }

    /// Append an item at the next checked position.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::TooMany`] above [`MAX_QUEUED_ITEMS`],
    /// [`InteractionError::DuplicateIdentity`] for a repeated identity, and
    /// [`InteractionError::PositionOverflow`] when the next position is not
    /// representable.
    pub fn append(&self, id: QueueItemId, request: RequestKind) -> Result<Self, InteractionError> {
        if self.items.len() >= MAX_QUEUED_ITEMS {
            return Err(InteractionError::TooMany {
                field: "queued_items",
                max: MAX_QUEUED_ITEMS,
                actual: self.items.len() + 1,
            });
        }
        if self.items.iter().any(|item| item.id == id) {
            return Err(InteractionError::DuplicateIdentity {
                field: "queued_items",
                identity: id.as_str().to_owned(),
            });
        }
        let position = match self.items.last() {
            Some(last) => last.position.checked_next()?,
            None => QueuePosition::FIRST,
        };
        let mut items = self.items.clone();
        items.push(QueuedInput {
            id,
            session: self.session.clone(),
            position,
            request,
        });
        Ok(Self {
            session: self.session.clone(),
            items,
        })
    }

    /// Move one identified item to an explicit destination rank.
    ///
    /// [`ReorderRequest::to`] is a 0-based rank in this queue's current order,
    /// so exactly `0..self.items().len()` is addressable: a two-item queue has
    /// ranks `0` and `1` whatever positions its items store.
    ///
    /// The result holds exactly the identities the receiver held: reordering
    /// cannot invent, drop or duplicate one. Every item in the result is
    /// renumbered densely from [`QueuePosition::FIRST`], so rank and stored
    /// position coincide in the queue returned.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::UnknownIdentity`] when the queue does not
    /// hold the named item, [`InteractionError::PositionOutOfRange`] for a
    /// destination at or past the queue's length, and
    /// [`InteractionError::PositionOverflow`] when renumbering is not
    /// representable.
    pub fn reorder(&self, request: &ReorderRequest) -> Result<Self, InteractionError> {
        let Some(from) = self.items.iter().position(|item| item.id == request.item) else {
            return Err(InteractionError::UnknownIdentity {
                field: "queued_items",
                identity: request.item.as_str().to_owned(),
            });
        };
        let requested = request.to.get();
        let Ok(to) = usize::try_from(requested) else {
            return Err(InteractionError::PositionOutOfRange {
                length: self.items.len(),
                requested,
            });
        };
        if to >= self.items.len() {
            return Err(InteractionError::PositionOutOfRange {
                length: self.items.len(),
                requested,
            });
        }
        let mut items = self.items.clone();
        let moved = items.remove(from);
        items.insert(to, moved);
        let mut position = QueuePosition::FIRST;
        let mut renumbered = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            if index > 0 {
                position = position.checked_next()?;
            }
            renumbered.push(QueuedInput {
                id: item.id,
                session: item.session,
                position,
                request: item.request,
            });
        }
        Ok(Self {
            session: self.session.clone(),
            items: renumbered,
        })
    }
}

/// Whether an idempotent intent was seen for the first time.
///
/// The effect is the same either way; only the delivery differs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Delivery {
    /// The request identity had not been recorded before.
    FirstObservation,
    /// An identical request identity was already recorded.
    Replay,
    /// The request identity was reused for a different intent.
    ///
    /// Distinct from [`Delivery::Replay`]: the recorded effect is returned
    /// unchanged, and the caller is told its intent was not the one recorded.
    RequestIdentityCollision,
}

impl Delivery {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstObservation => "first_observation",
            Self::Replay => "replay",
            Self::RequestIdentityCollision => "request_identity_collision",
        }
    }
}

/// What an idempotent intent achieved.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IntentEffect {
    /// Running work was stopped at the named scope.
    Stopped(CancelScope),
    /// The named class of target was reversed.
    Reversed(UndoTargetKind),
}

/// The typed outcome of submitting an idempotent intent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IntentOutcome {
    effect: IntentEffect,
    delivery: Delivery,
}

impl IntentOutcome {
    /// What the intent achieved.
    #[must_use]
    pub const fn effect(self) -> IntentEffect {
        self.effect
    }

    /// Whether this submission was the first observation.
    #[must_use]
    pub const fn delivery(self) -> Delivery {
        self.delivery
    }
}

/// The record of idempotent intents already observed.
///
/// Keyed by request identity: a repeated request returns the recorded outcome
/// instead of adding a second effect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IntentLedger {
    recorded: Vec<(RequestRef, IntentEffect)>,
}

impl IntentLedger {
    /// Start an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recorded: Vec::new(),
        }
    }

    /// Submit a stop.
    #[must_use]
    pub fn submit_cancel(&mut self, request: &CancelRequest) -> IntentOutcome {
        self.record(&request.request, IntentEffect::Stopped(request.scope))
    }

    /// Submit an undo.
    #[must_use]
    pub fn submit_undo(&mut self, request: &UndoRequest) -> IntentOutcome {
        self.record(
            &request.request,
            IntentEffect::Reversed(request.target.kind),
        )
    }

    /// How many distinct effects the ledger holds.
    #[must_use]
    pub fn effect_count(&self) -> usize {
        self.recorded.len()
    }

    /// The effects recorded, in submission order.
    #[must_use]
    pub fn effects(&self) -> Vec<IntentEffect> {
        self.recorded.iter().map(|(_, effect)| *effect).collect()
    }

    /// Record one intent, replaying only an identical one.
    ///
    /// A request identity names one request. Reusing it for a different intent
    /// is a collision rather than a replay: answering an undo with the stop
    /// recorded earlier would drop the undo and report success for it.
    fn record(&mut self, request: &RequestRef, effect: IntentEffect) -> IntentOutcome {
        if let Some((_, recorded)) = self
            .recorded
            .iter()
            .find(|(identity, _)| identity == request)
        {
            return IntentOutcome {
                effect: *recorded,
                delivery: if *recorded == effect {
                    Delivery::Replay
                } else {
                    Delivery::RequestIdentityCollision
                },
            };
        }
        self.recorded.push((request.clone(), effect));
        IntentOutcome {
            effect,
            delivery: Delivery::FirstObservation,
        }
    }
}

/// The exact checkpoint a restore names.
///
/// Both a content-addressed digest and a revision are constructor arguments, so
/// an unqualified "latest" is not expressible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRef {
    digest: ContentDigest,
    revision: Revision,
}

impl CheckpointRef {
    /// Name a checkpoint exactly.
    #[must_use]
    pub const fn new(digest: ContentDigest, revision: Revision) -> Self {
        Self { digest, revision }
    }

    /// The content-addressed digest.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// The revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// A recorded restore point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    session: SessionRef,
    reference: CheckpointRef,
    label: InteractionText,
    created_at: EpochMillis,
}

impl Checkpoint {
    /// The owning session.
    #[must_use]
    pub const fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The exact reference this checkpoint answers to.
    #[must_use]
    pub const fn reference(&self) -> &CheckpointRef {
        &self.reference
    }

    /// The human-readable label.
    #[must_use]
    pub const fn label(&self) -> &InteractionText {
        &self.label
    }

    /// The instant the caller supplied.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }
}

/// The create operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCheckpoint {
    session: SessionRef,
    reference: CheckpointRef,
    label: InteractionText,
    created_at: EpochMillis,
}

impl CreateCheckpoint {
    /// Stable operation name.
    pub const OPERATION: &'static str = "checkpoint.create";

    /// Describe a checkpoint to create.
    #[must_use]
    pub const fn new(
        session: SessionRef,
        reference: CheckpointRef,
        label: InteractionText,
        created_at: EpochMillis,
    ) -> Self {
        Self {
            session,
            reference,
            label,
            created_at,
        }
    }

    /// The exact reference the checkpoint will answer to.
    #[must_use]
    pub const fn reference(&self) -> &CheckpointRef {
        &self.reference
    }
}

/// The list operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListCheckpoints {
    session: SessionRef,
    limit: usize,
}

impl ListCheckpoints {
    /// Stable operation name.
    pub const OPERATION: &'static str = "checkpoint.list";

    /// Describe a listing.
    #[must_use]
    pub const fn new(session: SessionRef, limit: usize) -> Self {
        Self { session, limit }
    }

    /// The session whose checkpoints are listed.
    #[must_use]
    pub const fn session(&self) -> &SessionRef {
        &self.session
    }

    /// How many entries the caller wants at most.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

/// The restore operation.
///
/// A restore names an exact digest and revision:
///
/// ```
/// use automonique_protocol::interaction::{CheckpointRef, ContentDigest, RestoreCheckpoint};
/// use automonique_protocol::primitives::Revision;
/// let digest = ContentDigest::new("sha256:aa").unwrap();
/// let restore = RestoreCheckpoint::new(CheckpointRef::new(digest, Revision::FIRST));
/// assert_eq!(restore.target().revision(), Revision::FIRST);
/// ```
///
/// and an unqualified target is not expressible:
///
/// ```compile_fail
/// use automonique_protocol::interaction::RestoreCheckpoint;
/// let restore = RestoreCheckpoint::latest();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreCheckpoint {
    target: CheckpointRef,
}

impl RestoreCheckpoint {
    /// Stable operation name.
    pub const OPERATION: &'static str = "checkpoint.restore";

    /// Name the exact checkpoint to restore.
    #[must_use]
    pub const fn new(target: CheckpointRef) -> Self {
        Self { target }
    }

    /// The exact checkpoint targeted.
    #[must_use]
    pub const fn target(&self) -> &CheckpointRef {
        &self.target
    }
}

/// The checkpoints recorded for a set of sessions.
///
/// A create takes a [`CreateCheckpoint`] and a restore takes a
/// [`RestoreCheckpoint`], so one operation cannot stand in for another:
///
/// ```
/// use automonique_protocol::interaction::{
///     CheckpointLog, CheckpointRef, ContentDigest, CreateCheckpoint, InteractionText,
///     RestoreCheckpoint, SessionRef,
/// };
/// use automonique_protocol::primitives::{EpochMillis, Revision};
/// let mut log = CheckpointLog::new();
/// let session = SessionRef::new("s-1").unwrap();
/// let reference = CheckpointRef::new(ContentDigest::new("sha256:aa").unwrap(), Revision::FIRST);
/// log.record(CreateCheckpoint::new(
///     session,
///     reference.clone(),
///     InteractionText::new("before edit").unwrap(),
///     EpochMillis::EPOCH,
/// ))
/// .unwrap();
/// log.restore(&RestoreCheckpoint::new(reference)).unwrap();
/// ```
///
/// ```compile_fail
/// use automonique_protocol::interaction::{
///     CheckpointLog, CheckpointRef, ContentDigest, CreateCheckpoint, InteractionText, SessionRef,
/// };
/// use automonique_protocol::primitives::{EpochMillis, Revision};
/// let mut log = CheckpointLog::new();
/// let session = SessionRef::new("s-1").unwrap();
/// let reference = CheckpointRef::new(ContentDigest::new("sha256:aa").unwrap(), Revision::FIRST);
/// let create = CreateCheckpoint::new(
///     session,
///     reference,
///     InteractionText::new("before edit").unwrap(),
///     EpochMillis::EPOCH,
/// );
/// log.restore(&create).unwrap();
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckpointLog {
    checkpoints: Vec<Checkpoint>,
}

impl CheckpointLog {
    /// Start an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
        }
    }

    /// Record a checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::TooMany`] above [`MAX_CHECKPOINTS`] and
    /// [`InteractionError::DuplicateIdentity`] for a repeated digest.
    pub fn record(&mut self, create: CreateCheckpoint) -> Result<(), InteractionError> {
        if self.checkpoints.len() >= MAX_CHECKPOINTS {
            return Err(InteractionError::TooMany {
                field: "checkpoints",
                max: MAX_CHECKPOINTS,
                actual: self.checkpoints.len() + 1,
            });
        }
        if self
            .checkpoints
            .iter()
            .any(|checkpoint| checkpoint.reference.digest == create.reference.digest)
        {
            return Err(InteractionError::DuplicateIdentity {
                field: "checkpoints",
                identity: create.reference.digest.as_str().to_owned(),
            });
        }
        self.checkpoints.push(Checkpoint {
            session: create.session,
            reference: create.reference,
            label: create.label,
            created_at: create.created_at,
        });
        Ok(())
    }

    /// List the checkpoints of one session.
    #[must_use]
    pub fn list(&self, request: &ListCheckpoints) -> Vec<&Checkpoint> {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.session == request.session)
            .take(request.limit)
            .collect()
    }

    /// Resolve an exact restore target.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::UnknownCheckpoint`] when the digest is not
    /// recorded, and [`InteractionError::CheckpointRevisionMismatch`] when the
    /// digest is recorded at another revision.
    pub fn restore(&self, request: &RestoreCheckpoint) -> Result<&Checkpoint, InteractionError> {
        let Some(checkpoint) = self
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.reference.digest == request.target.digest)
        else {
            return Err(InteractionError::UnknownCheckpoint {
                digest: request.target.digest.as_str().to_owned(),
            });
        };
        if checkpoint.reference.revision != request.target.revision {
            return Err(InteractionError::CheckpointRevisionMismatch {
                recorded: checkpoint.reference.revision.get(),
                requested: request.target.revision.get(),
            });
        }
        Ok(checkpoint)
    }
}

/// One authoritative transcript entry.
///
/// Every field is read-only:
///
/// ```
/// use automonique_protocol::interaction::{ContentDigest, TranscriptEntry, TranscriptEntryId};
/// use automonique_protocol::primitives::Revision;
/// let entry = TranscriptEntry::new(
///     TranscriptEntryId::new("e-1").unwrap(),
///     Revision::FIRST,
///     ContentDigest::new("sha256:original").unwrap(),
/// );
/// assert_eq!(entry.digest().as_str(), "sha256:original");
/// ```
///
/// so a recorded entry cannot be rewritten in place:
///
/// ```compile_fail
/// use automonique_protocol::interaction::{ContentDigest, TranscriptEntry, TranscriptEntryId};
/// use automonique_protocol::primitives::Revision;
/// let mut entry = TranscriptEntry::new(
///     TranscriptEntryId::new("e-1").unwrap(),
///     Revision::FIRST,
///     ContentDigest::new("sha256:original").unwrap(),
/// );
/// entry.digest = ContentDigest::new("sha256:rewritten").unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEntry {
    id: TranscriptEntryId,
    revision: Revision,
    digest: ContentDigest,
}

impl TranscriptEntry {
    /// Record an entry.
    #[must_use]
    pub const fn new(id: TranscriptEntryId, revision: Revision, digest: ContentDigest) -> Self {
        Self {
            id,
            revision,
            digest,
        }
    }

    /// The entry identity.
    #[must_use]
    pub const fn id(&self) -> &TranscriptEntryId {
        &self.id
    }

    /// The entry revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// The entry's content digest.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// An append-only transcript.
///
/// The only way to add an entry is [`Transcript::append`], which refuses a
/// revision that does not advance. There is no remove, no replace and no
/// mutable accessor, so no value in this module rewrites an entry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transcript {
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    /// Start an empty transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an entry.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::RevisionNotAdvancing`] when the revision is
    /// not strictly greater than the last recorded one, which is what makes a
    /// rewrite of an existing revision unavailable.
    pub fn append(&mut self, entry: TranscriptEntry) -> Result<(), InteractionError> {
        if let Some(last) = self.entries.last()
            && entry.revision <= last.revision
        {
            return Err(InteractionError::RevisionNotAdvancing {
                last: last.revision.get(),
                requested: entry.revision.get(),
            });
        }
        // A repeated entry identity would let one id hold two conflicting
        // digests, which is a rewrite wearing an append's clothes.
        if self.entries.iter().any(|existing| existing.id == entry.id) {
            return Err(InteractionError::DuplicateTranscriptEntry {
                id: entry.id.as_str().to_owned(),
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// The recorded entries, in revision order.
    #[must_use]
    pub fn entries(&self) -> &[TranscriptEntry] {
        &self.entries
    }
}

/// A closed range of transcript revisions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TranscriptRange {
    from: Revision,
    to: Revision,
}

impl TranscriptRange {
    /// Build a range.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::RangeInverted`] when the end precedes the
    /// start.
    pub const fn new(from: Revision, to: Revision) -> Result<Self, InteractionError> {
        if to.get() < from.get() {
            return Err(InteractionError::RangeInverted {
                from: from.get(),
                to: to.get(),
            });
        }
        Ok(Self { from, to })
    }

    /// The first revision covered.
    #[must_use]
    pub const fn from(self) -> Revision {
        self.from
    }

    /// The last revision covered.
    #[must_use]
    pub const fn to(self) -> Revision {
        self.to
    }
}

/// Whether a compression's output was checked against its protected facts.
///
/// Three-valued, so "unverified" is stated rather than inferred from absence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationStatus {
    /// Every protected fact was found in the output.
    Verified,
    /// A protected fact was missing from the output.
    Rejected,
    /// Verification has not run.
    NotRun,
}

impl VerificationStatus {
    /// Every status, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Verified, Self::Rejected, Self::NotRun];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::NotRun => "not_run",
        }
    }
}

/// Every field a [`CompressionOperation`] needs, named at the call site.
///
/// A struct rather than a positional list: four of these are strings, and a
/// caller that transposes a prompt digest and an output digest would compile
/// cleanly while recording the wrong lineage. No field is optional.
#[derive(Clone, Debug)]
pub struct CompressionParts<'a> {
    /// The transcript range compressed.
    pub source: TranscriptRange,
    /// The provider that ran the compression.
    pub compressor_provider: &'a str,
    /// The model that ran the compression.
    pub compressor_model: &'a str,
    /// The prompt or template digest.
    pub prompt_digest: ContentDigest,
    /// The digest of the produced summary.
    pub output_digest: ContentDigest,
    /// The facts the compression had to preserve.
    pub protected_facts: &'a [&'a str],
    /// Whether the output was checked against those facts.
    pub verification: VerificationStatus,
}

/// The durable record of one compression.
///
/// It describes a derived view. It holds no [`TranscriptEntry`] and offers no
/// accessor returning one, so a compression is never an edit of the transcript
/// it summarises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionOperation {
    source: TranscriptRange,
    compressor_provider: String,
    compressor_model: String,
    prompt_digest: ContentDigest,
    output_digest: ContentDigest,
    protected_facts: Vec<String>,
    verification: VerificationStatus,
}

impl CompressionOperation {
    /// Record a compression.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::Field`] for an invalid or absent component,
    /// and [`InteractionError::TooMany`] above [`MAX_PROTECTED_FACTS`].
    pub fn record(parts: CompressionParts<'_>) -> Result<Self, InteractionError> {
        bounded(parts.compressor_provider, "compressor_provider")?;
        bounded(parts.compressor_model, "compressor_model")?;
        if parts.protected_facts.is_empty() {
            return Err(InteractionError::Field {
                field: "protected_facts",
                error: ValueError::Empty,
            });
        }
        if parts.protected_facts.len() > MAX_PROTECTED_FACTS {
            return Err(InteractionError::TooMany {
                field: "protected_facts",
                max: MAX_PROTECTED_FACTS,
                actual: parts.protected_facts.len(),
            });
        }
        for fact in parts.protected_facts {
            bounded(fact, "protected_fact")?;
        }
        Ok(Self {
            source: parts.source,
            compressor_provider: parts.compressor_provider.to_owned(),
            compressor_model: parts.compressor_model.to_owned(),
            prompt_digest: parts.prompt_digest,
            output_digest: parts.output_digest,
            protected_facts: parts
                .protected_facts
                .iter()
                .map(|fact| (*fact).to_owned())
                .collect(),
            verification: parts.verification,
        })
    }

    /// The transcript range compressed.
    #[must_use]
    pub const fn source(&self) -> TranscriptRange {
        self.source
    }

    /// The provider that ran the compression.
    #[must_use]
    pub fn compressor_provider(&self) -> &str {
        &self.compressor_provider
    }

    /// The model that ran the compression.
    #[must_use]
    pub fn compressor_model(&self) -> &str {
        &self.compressor_model
    }

    /// The prompt or template digest.
    #[must_use]
    pub const fn prompt_digest(&self) -> &ContentDigest {
        &self.prompt_digest
    }

    /// The digest of the produced summary.
    #[must_use]
    pub const fn output_digest(&self) -> &ContentDigest {
        &self.output_digest
    }

    /// The facts the compression had to preserve.
    #[must_use]
    pub fn protected_facts(&self) -> &[String] {
        &self.protected_facts
    }

    /// Whether the output was checked against those facts.
    #[must_use]
    pub const fn verification(&self) -> VerificationStatus {
        self.verification
    }
}

/// A derived view of a transcript range.
///
/// Carries the range it derives from and its own digest. It carries no
/// transcript entry, so publishing a view never displaces one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedView {
    source: TranscriptRange,
    digest: ContentDigest,
    verification: VerificationStatus,
}

impl DerivedView {
    /// The range this view derives from.
    #[must_use]
    pub const fn source(&self) -> TranscriptRange {
        self.source
    }

    /// The view's own digest.
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    /// Whether the compression that produced it was verified.
    #[must_use]
    pub const fn verification(&self) -> VerificationStatus {
        self.verification
    }
}

/// Derive a view from a transcript and a recorded compression.
///
/// The transcript is borrowed, not consumed, and the returned value is a new
/// [`DerivedView`]: the authoritative entries survive the call unchanged.
///
/// # Errors
///
/// Returns [`InteractionError::UnknownTranscriptRange`] when the transcript
/// does not hold both endpoints of the compression's source range.
pub fn derive_view(
    transcript: &Transcript,
    compression: &CompressionOperation,
) -> Result<DerivedView, InteractionError> {
    let range = compression.source;
    let holds = |revision: Revision| {
        transcript
            .entries
            .iter()
            .any(|entry| entry.revision == revision)
    };
    if !holds(range.from) || !holds(range.to) {
        return Err(InteractionError::UnknownTranscriptRange {
            from: range.from.get(),
            to: range.to.get(),
        });
    }
    Ok(DerivedView {
        source: range,
        digest: compression.output_digest.clone(),
        verification: compression.verification,
    })
}

/// A class of context component, measured per turn.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContextComponentClass {
    /// System and tenant policy.
    SystemPolicy,
    /// Repository and workspace rules.
    Rules,
    /// Activated skills.
    Skills,
    /// Retrieved memory.
    Memory,
    /// Tool definitions.
    Tools,
    /// MCP server definitions.
    Mcp,
    /// Attached files and images.
    Attachments,
    /// The conversation itself.
    Conversation,
}

impl ContextComponentClass {
    /// Every class a per-turn breakdown must cover.
    pub const ALL: [Self; 8] = [
        Self::SystemPolicy,
        Self::Rules,
        Self::Skills,
        Self::Memory,
        Self::Tools,
        Self::Mcp,
        Self::Attachments,
        Self::Conversation,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemPolicy => "system_policy",
            Self::Rules => "rules",
            Self::Skills => "skills",
            Self::Memory => "memory",
            Self::Tools => "tools",
            Self::Mcp => "mcp",
            Self::Attachments => "attachments",
            Self::Conversation => "conversation",
        }
    }

    /// This class's index in [`ContextComponentClass::ALL`].
    ///
    /// Total, so a per-turn breakdown can be stored as a fixed array and looked
    /// up without a fallback that could quietly answer for the wrong class.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::SystemPolicy => 0,
            Self::Rules => 1,
            Self::Skills => 2,
            Self::Memory => 3,
            Self::Tools => 4,
            Self::Mcp => 5,
            Self::Attachments => 6,
            Self::Conversation => 7,
        }
    }
}

/// A locally estimated token count.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EstimatedTokens(u64);

impl EstimatedTokens {
    /// Record an estimate.
    #[must_use]
    pub const fn new(tokens: u64) -> Self {
        Self(tokens)
    }

    /// The estimated count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A token count the provider reported.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReportedTokens(u64);

impl ReportedTokens {
    /// Record a provider-reported count.
    #[must_use]
    pub const fn new(tokens: u64) -> Self {
        Self(tokens)
    }

    /// The reported count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a provider-reported count is absent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MissingCountReason {
    /// The response carried no usage block.
    ProviderDidNotReport,
    /// The turn has not finished.
    TurnIncomplete,
    /// The provider reported a total but no per-class breakdown.
    NotBrokenDownByProvider,
}

impl MissingCountReason {
    /// Every reason, for coverage checks.
    pub const ALL: [Self; 3] = [
        Self::ProviderDidNotReport,
        Self::TurnIncomplete,
        Self::NotBrokenDownByProvider,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderDidNotReport => "provider_did_not_report",
            Self::TurnIncomplete => "turn_incomplete",
            Self::NotBrokenDownByProvider => "not_broken_down_by_provider",
        }
    }
}

/// A provider-reported count, or its explicit absence.
///
/// The absent case carries a reason, and no accessor substitutes an estimate
/// for it:
///
/// ```
/// use automonique_protocol::interaction::{ReportedCount, ReportedTokens};
/// let reported = ReportedCount::Reported(ReportedTokens::new(120));
/// assert_eq!(reported.tokens(), Some(120));
/// ```
///
/// ```compile_fail
/// use automonique_protocol::interaction::{EstimatedTokens, ReportedCount};
/// // An estimate cannot occupy the provider-reported slot.
/// let reported = ReportedCount::Reported(EstimatedTokens::new(120));
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportedCount {
    /// The provider reported this many tokens.
    Reported(ReportedTokens),
    /// The provider reported nothing, for this reason.
    Absent(MissingCountReason),
}

impl ReportedCount {
    /// The reported count, or `None` when the provider reported nothing.
    #[must_use]
    pub const fn tokens(self) -> Option<u64> {
        match self {
            Self::Reported(tokens) => Some(tokens.get()),
            Self::Absent(_) => None,
        }
    }

    /// Why the count is absent, when it is.
    #[must_use]
    pub const fn missing_reason(self) -> Option<MissingCountReason> {
        match self {
            Self::Reported(_) => None,
            Self::Absent(reason) => Some(reason),
        }
    }
}

/// One component class's share of a turn's context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentUsage {
    class: ContextComponentClass,
    estimated: Option<EstimatedTokens>,
    reported: ReportedCount,
}

impl ComponentUsage {
    /// Record one class's usage.
    #[must_use]
    pub const fn new(
        class: ContextComponentClass,
        estimated: Option<EstimatedTokens>,
        reported: ReportedCount,
    ) -> Self {
        Self {
            class,
            estimated,
            reported,
        }
    }

    /// The class measured.
    #[must_use]
    pub const fn class(self) -> ContextComponentClass {
        self.class
    }

    /// The local estimate, which is independently nullable.
    #[must_use]
    pub const fn estimated(self) -> Option<EstimatedTokens> {
        self.estimated
    }

    /// The provider-reported count or its reasoned absence.
    #[must_use]
    pub const fn reported(self) -> ReportedCount {
        self.reported
    }
}

/// The sum of provider-reported counts and the classes that had none.
///
/// Unreported classes are named rather than filled in from the estimate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedTotal {
    reported_tokens: u128,
    unreported: Vec<ContextComponentClass>,
}

impl ReportedTotal {
    /// The sum of the provider-reported counts.
    #[must_use]
    pub const fn reported_tokens(&self) -> u128 {
        self.reported_tokens
    }

    /// The classes the provider reported nothing for.
    #[must_use]
    pub fn unreported(&self) -> &[ContextComponentClass] {
        &self.unreported
    }
}

/// One turn's context usage, broken down over every component class.
///
/// Completeness is established at construction, so lookup is total.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnContextUsage {
    turn: TurnRef,
    components: [ComponentUsage; 8],
}

impl TurnContextUsage {
    /// Build a per-turn breakdown.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::DuplicateComponentClass`] for a repeated
    /// class and [`InteractionError::MissingComponentClass`] for an absent one.
    pub fn new(turn: TurnRef, supplied: &[ComponentUsage]) -> Result<Self, InteractionError> {
        for (index, usage) in supplied.iter().enumerate() {
            if supplied[..index]
                .iter()
                .any(|earlier| earlier.class == usage.class)
            {
                return Err(InteractionError::DuplicateComponentClass { class: usage.class });
            }
        }
        let mut missing = None;
        let components: [ComponentUsage; 8] = core::array::from_fn(|index| {
            let class = ContextComponentClass::ALL[index];
            match supplied.iter().find(|usage| usage.class == class) {
                Some(usage) => *usage,
                None => {
                    if missing.is_none() {
                        missing = Some(class);
                    }
                    ComponentUsage {
                        class,
                        estimated: None,
                        reported: ReportedCount::Absent(MissingCountReason::ProviderDidNotReport),
                    }
                }
            }
        });
        if let Some(class) = missing {
            return Err(InteractionError::MissingComponentClass { class });
        }
        Ok(Self { turn, components })
    }

    /// The turn measured.
    #[must_use]
    pub const fn turn(&self) -> &TurnRef {
        &self.turn
    }

    /// Every class's usage, in the canonical class order.
    #[must_use]
    pub const fn components(&self) -> &[ComponentUsage; 8] {
        &self.components
    }

    /// One class's usage.
    ///
    /// Total: every class is present by construction.
    #[must_use]
    pub const fn component(&self, class: ContextComponentClass) -> ComponentUsage {
        self.components[class.index()]
    }

    /// Sum the provider-reported counts and name the classes without one.
    #[must_use]
    pub fn reported_total(&self) -> ReportedTotal {
        let mut reported_tokens = 0_u128;
        let mut unreported = Vec::new();
        for usage in &self.components {
            match usage.reported.tokens() {
                Some(tokens) => reported_tokens += u128::from(tokens),
                None => unreported.push(usage.class),
            }
        }
        ReportedTotal {
            reported_tokens,
            unreported,
        }
    }
}

/// The authority an action requires before any surface may perform it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RequiredAuthority {
    /// Read observed state only.
    Observe,
    /// Enqueue composer input.
    Compose,
    /// Stop running work.
    Interrupt,
    /// Reverse an applied effect.
    Reverse,
    /// Create or restore a checkpoint.
    Checkpoint,
    /// Approve authority the run does not already hold.
    Approve,
}

impl RequiredAuthority {
    /// Every authority, for coverage checks.
    pub const ALL: [Self; 6] = [
        Self::Observe,
        Self::Compose,
        Self::Interrupt,
        Self::Reverse,
        Self::Checkpoint,
        Self::Approve,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Compose => "compose",
            Self::Interrupt => "interrupt",
            Self::Reverse => "reverse",
            Self::Checkpoint => "checkpoint",
            Self::Approve => "approve",
        }
    }
}

/// One bounded command parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandParameter {
    name: InteractionText,
    value: InteractionText,
}

impl CommandParameter {
    /// Record a parameter.
    #[must_use]
    pub const fn new(name: InteractionText, value: InteractionText) -> Self {
        Self { name, value }
    }

    /// The parameter name.
    #[must_use]
    pub const fn name(&self) -> &InteractionText {
        &self.name
    }

    /// The parameter value.
    #[must_use]
    pub const fn value(&self) -> &InteractionText {
        &self.value
    }
}

/// A registry command invoked from a surface.
///
/// A command is named by its registry identifier and bounded parameters:
///
/// ```
/// use automonique_protocol::interaction::{CommandId, CommandInvocation, SurfaceKind};
/// let invocation = CommandInvocation::new(
///     CommandId::new("automonique.interaction.undo").unwrap(),
///     SurfaceKind::Cli,
///     Vec::new(),
/// )
/// .unwrap();
/// assert_eq!(invocation.command().as_str(), "automonique.interaction.undo");
/// ```
///
/// and there is no per-surface parsing, alias table or regular expression to
/// reach:
///
/// ```compile_fail
/// use automonique_protocol::interaction::CommandInvocation;
/// let invocation = CommandInvocation::parse("/undo");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    command: CommandId,
    surface: SurfaceKind,
    parameters: Vec<CommandParameter>,
}

impl CommandInvocation {
    /// Record an invocation.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::TooMany`] above [`MAX_COMMAND_PARAMETERS`]
    /// and [`InteractionError::DuplicateIdentity`] for a repeated parameter
    /// name.
    pub fn new(
        command: CommandId,
        surface: SurfaceKind,
        parameters: Vec<CommandParameter>,
    ) -> Result<Self, InteractionError> {
        if parameters.len() > MAX_COMMAND_PARAMETERS {
            return Err(InteractionError::TooMany {
                field: "command_parameters",
                max: MAX_COMMAND_PARAMETERS,
                actual: parameters.len(),
            });
        }
        for (index, parameter) in parameters.iter().enumerate() {
            if parameters[..index]
                .iter()
                .any(|earlier| earlier.name == parameter.name)
            {
                return Err(InteractionError::DuplicateIdentity {
                    field: "command_parameters",
                    identity: parameter.name.as_str().to_owned(),
                });
            }
        }
        Ok(Self {
            command,
            surface,
            parameters,
        })
    }

    /// The registry command identifier.
    #[must_use]
    pub const fn command(&self) -> &CommandId {
        &self.command
    }

    /// The surface the invocation came from.
    #[must_use]
    pub const fn surface(&self) -> SurfaceKind {
        self.surface
    }

    /// The bounded parameters.
    #[must_use]
    pub fn parameters(&self) -> &[CommandParameter] {
        &self.parameters
    }
}

/// One action a projection offers.
///
/// It names the command it invokes and the authority it requires. It carries no
/// callable, so offering an action is not performing one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionAction {
    command: CommandId,
    authority: RequiredAuthority,
    label: InteractionText,
}

impl ProjectionAction {
    /// Offer an action.
    #[must_use]
    pub const fn new(
        command: CommandId,
        authority: RequiredAuthority,
        label: InteractionText,
    ) -> Self {
        Self {
            command,
            authority,
            label,
        }
    }

    /// The command the action invokes.
    #[must_use]
    pub const fn command(&self) -> &CommandId {
        &self.command
    }

    /// The authority the action requires.
    #[must_use]
    pub const fn authority(&self) -> RequiredAuthority {
        self.authority
    }

    /// The presentation label.
    #[must_use]
    pub const fn label(&self) -> &InteractionText {
        &self.label
    }
}

/// A command permitted to run because its authority was granted.
///
/// Only [`authorize`] produces one:
///
/// ```
/// use automonique_protocol::interaction::{
///     CommandId, InteractionText, ProjectionAction, RequiredAuthority, authorize,
/// };
/// let action = ProjectionAction::new(
///     CommandId::new("automonique.interaction.stop").unwrap(),
///     RequiredAuthority::Interrupt,
///     InteractionText::new("Stop").unwrap(),
/// );
/// let intent = authorize(&action, &[RequiredAuthority::Interrupt]).unwrap();
/// assert_eq!(intent.authority(), RequiredAuthority::Interrupt);
/// ```
///
/// so a presentation shortcut cannot fabricate one:
///
/// ```compile_fail
/// use automonique_protocol::interaction::{AuthorizedIntent, CommandId, RequiredAuthority};
/// let intent = AuthorizedIntent {
///     command: CommandId::new("automonique.interaction.stop").unwrap(),
///     authority: RequiredAuthority::Interrupt,
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedIntent {
    command: CommandId,
    authority: RequiredAuthority,
}

impl AuthorizedIntent {
    /// The command permitted to run.
    #[must_use]
    pub const fn command(&self) -> &CommandId {
        &self.command
    }

    /// The authority that permitted it.
    #[must_use]
    pub const fn authority(&self) -> RequiredAuthority {
        self.authority
    }
}

/// Authorize an offered action against the authorities actually granted.
///
/// # Errors
///
/// Returns [`InteractionError::AuthorityRequired`] naming the authority the
/// action declares when it was not granted.
pub fn authorize(
    action: &ProjectionAction,
    granted: &[RequiredAuthority],
) -> Result<AuthorizedIntent, InteractionError> {
    if !granted.contains(&action.authority) {
        return Err(InteractionError::AuthorityRequired {
            authority: action.authority,
        });
    }
    Ok(AuthorizedIntent {
        command: action.command.clone(),
        authority: action.authority,
    })
}

/// A read-only view of observed interaction state.
///
/// It exposes what was observed:
///
/// ```
/// use automonique_protocol::interaction::{SessionRef, SurfaceKind, SurfaceProjection};
/// let projection = SurfaceProjection::new(
///     SurfaceKind::Tui,
///     SessionRef::new("s-1").unwrap(),
///     Vec::new(),
///     Vec::new(),
/// )
/// .unwrap();
/// assert_eq!(projection.surface(), SurfaceKind::Tui);
/// ```
///
/// and carries no method that changes it:
///
/// ```compile_fail
/// use automonique_protocol::interaction::{SessionRef, SurfaceKind, SurfaceProjection};
/// let mut projection = SurfaceProjection::new(
///     SurfaceKind::Tui,
///     SessionRef::new("s-1").unwrap(),
///     Vec::new(),
///     Vec::new(),
/// )
/// .unwrap();
/// projection.set_surface(SurfaceKind::Cli);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceProjection {
    surface: SurfaceKind,
    session: SessionRef,
    observed: Vec<QueueItemId>,
    actions: Vec<ProjectionAction>,
}

impl SurfaceProjection {
    /// Project observed state onto a surface.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::TooMany`] above [`MAX_QUEUED_ITEMS`]
    /// observed items or [`MAX_PROJECTION_ACTIONS`] actions.
    pub fn new(
        surface: SurfaceKind,
        session: SessionRef,
        observed: Vec<QueueItemId>,
        actions: Vec<ProjectionAction>,
    ) -> Result<Self, InteractionError> {
        if observed.len() > MAX_QUEUED_ITEMS {
            return Err(InteractionError::TooMany {
                field: "observed_items",
                max: MAX_QUEUED_ITEMS,
                actual: observed.len(),
            });
        }
        if actions.len() > MAX_PROJECTION_ACTIONS {
            return Err(InteractionError::TooMany {
                field: "projection_actions",
                max: MAX_PROJECTION_ACTIONS,
                actual: actions.len(),
            });
        }
        Ok(Self {
            surface,
            session,
            observed,
            actions,
        })
    }

    /// Project a queue onto a surface.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::TooMany`] above
    /// [`MAX_PROJECTION_ACTIONS`].
    pub fn of_queue(
        surface: SurfaceKind,
        queue: &InputQueue,
        actions: Vec<ProjectionAction>,
    ) -> Result<Self, InteractionError> {
        Self::new(surface, queue.session.clone(), queue.identities(), actions)
    }

    /// The surface this projection is for.
    #[must_use]
    pub const fn surface(&self) -> SurfaceKind {
        self.surface
    }

    /// The session observed.
    #[must_use]
    pub const fn session(&self) -> &SessionRef {
        &self.session
    }

    /// The queue identities observed, in order.
    #[must_use]
    pub fn observed(&self) -> &[QueueItemId] {
        &self.observed
    }

    /// The actions offered, each naming its required authority.
    #[must_use]
    pub fn actions(&self) -> &[ProjectionAction] {
        &self.actions
    }
}

/// A key inside one extension's namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacedKey {
    extension: ExtensionId,
    key: InteractionText,
}

impl NamespacedKey {
    /// Name a key inside an extension's namespace.
    #[must_use]
    pub const fn new(extension: ExtensionId, key: InteractionText) -> Self {
        Self { extension, key }
    }

    /// The owning extension.
    #[must_use]
    pub const fn extension(&self) -> &ExtensionId {
        &self.extension
    }

    /// The key within that namespace.
    #[must_use]
    pub const fn key(&self) -> &InteractionText {
        &self.key
    }
}

/// A projection owned by one plugin or widget extension.
///
/// Every read and write names a [`NamespacedKey`], and a key belonging to
/// another extension is refused rather than resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacedProjection {
    owner: ExtensionId,
    projection: SurfaceProjection,
    entries: Vec<(NamespacedKey, InteractionText)>,
}

impl NamespacedProjection {
    /// Namespace a projection to one extension.
    #[must_use]
    pub const fn new(owner: ExtensionId, projection: SurfaceProjection) -> Self {
        Self {
            owner,
            projection,
            entries: Vec::new(),
        }
    }

    /// Add one namespaced entry.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::ForeignNamespace`] when the key belongs to
    /// another extension, [`InteractionError::TooMany`] above
    /// [`MAX_PROJECTION_ENTRIES`], and
    /// [`InteractionError::DuplicateIdentity`] for a repeated key.
    pub fn with_entry(
        mut self,
        key: NamespacedKey,
        value: InteractionText,
    ) -> Result<Self, InteractionError> {
        self.check_namespace(&key)?;
        if self.entries.len() >= MAX_PROJECTION_ENTRIES {
            return Err(InteractionError::TooMany {
                field: "projection_entries",
                max: MAX_PROJECTION_ENTRIES,
                actual: self.entries.len() + 1,
            });
        }
        if self.entries.iter().any(|(recorded, _)| *recorded == key) {
            return Err(InteractionError::DuplicateIdentity {
                field: "projection_entries",
                identity: key.key.as_str().to_owned(),
            });
        }
        self.entries.push((key, value));
        Ok(self)
    }

    /// Read one namespaced entry.
    ///
    /// # Errors
    ///
    /// Returns [`InteractionError::ForeignNamespace`] when the key belongs to
    /// another extension. A key inside the namespace that was never written
    /// yields `Ok(None)`, so a cross-namespace read is refused rather than
    /// reported as absent.
    pub fn read(&self, key: &NamespacedKey) -> Result<Option<&InteractionText>, InteractionError> {
        self.check_namespace(key)?;
        Ok(self
            .entries
            .iter()
            .find(|(recorded, _)| recorded == key)
            .map(|(_, value)| value))
    }

    /// The owning extension.
    #[must_use]
    pub const fn owner(&self) -> &ExtensionId {
        &self.owner
    }

    /// The read-only projection this namespace wraps.
    #[must_use]
    pub const fn projection(&self) -> &SurfaceProjection {
        &self.projection
    }

    /// The namespaced entries.
    #[must_use]
    pub fn entries(&self) -> &[(NamespacedKey, InteractionText)] {
        &self.entries
    }

    fn check_namespace(&self, key: &NamespacedKey) -> Result<(), InteractionError> {
        if key.extension == self.owner {
            return Ok(());
        }
        Err(InteractionError::ForeignNamespace {
            owner: self.owner.as_str().to_owned(),
            requested: key.extension.as_str().to_owned(),
        })
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), InteractionError> {
    crate::primitives::bounded_value(value, MAX_INTERACTION_TEXT_BYTES)
        .map_err(|error| InteractionError::Field { field, error })
}
