// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native Batch control API: declare which submissions a batch
//! tracks, report where each of them has got to, and read both back.
//!
//! `docs/product-plan/requirements/state-and-protocols.md` § Operator client
//! protocol is the rule every response here obeys — "Responses distinguish
//! `accepted`, `completed`, `rejected`, `conflict`, `unknown` and
//! `resync_required` so a UI cannot mistake transport failure for operation
//! failure" — reused from [`crate::journal::ActionOutcome`] rather than
//! restated, with [`BatchResponse::outcome`] saying which four of the six this
//! protocol produces and [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] saying which
//! two it cannot.
//!
//! # What this surface does, stated before what it looks like
//!
//! **It records a batch's declared membership and each member's last-reported
//! progress, and serves them back.** That is the whole of it, and the honesty of
//! the slice depends on saying so:
//!
//! - **It submits nothing.** [`RegisterBatch`] carries member *keys* and no
//!   RunSpec document. Registering a batch writes no row to the run submission
//!   log, reserves no run identity and takes custody of nothing. A registered
//!   batch causes no run to exist, and `tests/batch_live.rs` asserts exactly
//!   that against the live Runs lane.
//! - **It schedules nothing and runs nothing.** There is no executor in this
//!   build. [`ConcurrencyPolicy`] travels because the batch declared it; nothing
//!   counts what is in flight and nothing throttles anything. A
//!   `bounded_parallel` ceiling is a recorded intention.
//! - **A member's progress is a caller's claim, not a reading.**
//!   [`AdvanceMember`] says what a writer *observed*; the durable run index is
//!   the true binding from a submission to the state its run reached, and this
//!   lane never joins it. What an accepted advance establishes is that somebody
//!   said so, at a sequence that did not go backwards, along a legal lattice.
//! - **Nothing here verifies authority.** The daemon's `SO_PEERCRED` check is
//!   the authentication; this protocol has no actor field at all, because a
//!   recorded name that gates nothing is [`crate::approval_api::Decider`]'s
//!   trade and a batch has no equivalent question to answer.
//!
//! # The rolled-up batch state travels on the detail read, and is never stored
//!
//! `automonique_store::batch_registry` deliberately has no `state` column, and
//! says why: [`crate::batch_runner::roll_up`] is a total function of the member
//! states, so a column would be a second copy of an answer that can drift from
//! what it summarizes, with no decoder to catch the drift.
//!
//! This lane serves the derived answer anyway, on [`BatchDetailResult`], for the
//! reason the store gives for *not* storing it: the members are the one durable
//! copy, and the rollup is computed beside them from the very slice being
//! served. A client therefore gets the derived state without re-deriving it, and
//! without the derivation ever being persisted.
//!
//! The carried state is not a field a caller supplies. [`BatchDetailResult::new`]
//! computes it with [`roll_up`], and [`BatchDetailResult::from_body`] recomputes
//! it on decode and refuses a body whose carried state contradicts its own
//! members — the discipline [`crate::batch_runner::BatchProgress`] holds for a
//! document, applied to a response. A daemon that fabricated `completed` over
//! members that say otherwise cannot get that answer past its own decoder.
//!
//! # The vocabularies are `batch_runner`'s, reused rather than re-spelled
//!
//! [`ConcurrencyPolicy`], [`MemberProgress`], [`BatchState`], [`BatchId`],
//! [`BatchMemberKey`], [`BatchLabel`] and [`roll_up`] all come from
//! [`crate::batch_runner`] — the same crate, so this is a `use` and not a copy.
//! That module is the authority for what a batch *is*; this one is the authority
//! for how a client asks about one. A word cannot drift between them because
//! there is only one word.
//!
//! Two spellings are this lane's own and are stated rather than assumed: a
//! member's value is carried as `state`, exactly as
//! [`crate::batch_runner::BatchMember`] carries it, and a batch's rollup is
//! carried as `state` too. They never share an object — the batch's sits beside
//! the `members` array, each member's sits inside one — which is the same
//! arrangement `batch_runner`'s progress document already uses.
//!
//! # Divergences, named rather than approximated
//!
//! - **This lane admits fewer members per batch than the model or the store.**
//!   [`MAX_BATCH_CONTROL_MEMBERS`] is half of
//!   [`crate::batch_runner::MAX_BATCH_MEMBERS`], because a maximal registration
//!   of 256 maximal keys is about 66 KiB and the local socket reads 64 KiB. The
//!   store's ceiling bounds a database write and this one bounds a wire frame,
//!   so the smaller of the two is the one a client sees; they are not reconciled
//!   and must not be, exactly as [`crate::approval_api::MAX_APPROVAL_PAGE_ITEMS`]
//!   is not reconciled with the ledger's own page bound.
//! - **`resync_required` is unreachable.** The registry has no prune — nothing
//!   deletes a batch — so no cursor can fall out of retention. A cursor above
//!   everything recorded is [`BatchRefusal::CursorOutOfRange`], which says
//!   something true.
//! - **Capacity is a refusal, never an eviction.** [`BatchRefusal::RegistryFull`]
//!   is the honest consequence of keeping every batch forever.
//! - **There is no deregistration and no re-registration.** The registry has
//!   neither, because a second registration would reset member rows a writer may
//!   already have advanced. A repeated identity is
//!   [`BatchRefusal::AlreadyRegistered`], never an overwrite.
//! - **A member is never removed and never added.** The membership is fixed at
//!   registration, which is what makes `roll_up` over it mean anything.
//! - **HTTP is absent.** These are protocol values framed by [`crate::codec`] on
//!   the same canonical-JSON envelope [`crate::admin`] uses, under a separate
//!   protocol name so the admin lane's closed kind set stays closed.

use core::fmt;
use std::error::Error;

use crate::batch_runner::{
    BatchError, BatchId, BatchLabel, BatchMemberKey, BatchState, ConcurrencyKind,
    ConcurrencyPolicy, MAX_BATCH_ID_BYTES, MAX_BATCH_LABEL_BYTES, MAX_BATCH_MEMBER_KEY_BYTES,
    MAX_BATCH_MEMBERS, MemberProgress, roll_up,
};
use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId, SupportedProtocol,
    VersionRange, decode_security_enum,
};
use crate::journal::ActionOutcome;
use crate::primitives::{EpochMillis, ValueError};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native Batch control API.
///
/// Dotted rather than hyphenated: [`crate::codec::ProtocolName`]'s grammar
/// admits lowercase letters, digits and dots and nothing else, so
/// `automonique.batch-control` is not a name this envelope can carry. The
/// separator is the only thing that changed.
///
/// Distinct from [`crate::batch_runner::BATCH_SCHEMA_V1`]'s
/// `automonique.batch/v1` on purpose: that identifies a batch *document*, this
/// identifies the control lane that carries requests about one, and giving them
/// one spelling would let a client admit either shape under the other's name.
pub const BATCH_CONTROL_PROTOCOL: &str = "automonique.batch.control";

/// Stable schema identifier for the version-one batch control surface.
pub const BATCH_CONTROL_API_SCHEMA_V1: &str = "automonique.batch.control/v1";

/// Maximum canonical message bytes this protocol will assemble or admit.
pub const MAX_BATCH_CONTROL_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum members one batch may declare *through this lane*.
///
/// Half of [`MAX_BATCH_MEMBERS`], and derived rather than chosen: a maximal
/// registration of 256 keys of [`MAX_BATCH_MEMBER_KEY_BYTES`] escapes to about
/// 66 KiB, which does not fit the 64 KiB frame the local socket reads under. The
/// compile-time assertions below are the derivation.
///
/// A dataset larger than this is not a larger batch here; it is not registrable
/// through this surface, which is a real limit of the transport rather than a
/// configuration. `automonique_store::batch_registry` still holds 256, and the
/// two ceilings are deliberately not reconciled: the store's bounds a database
/// write and this one bounds a wire frame.
pub const MAX_BATCH_CONTROL_MEMBERS: usize = 128;

/// Maximum batches one listing page may carry.
///
/// Thirty-two, for the reason [`crate::approval_api::MAX_APPROVAL_PAGE_ITEMS`]
/// serves thirty-two: a batch row carries two maximal identifiers. Well below
/// `automonique_store::batch_registry::MAX_BATCH_PAGE`, which is five hundred
/// and twelve, and not reconciled with it for the reason given in the module
/// documentation.
///
/// A page bound is not a paging hint. [`BatchListPage::new`] refuses a longer
/// vector rather than truncating it, because a truncated page that still answers
/// `complete` is a silent drop.
pub const MAX_BATCH_PAGE_ITEMS: usize = 32;

/// The two outcomes this protocol can never report.
///
/// `unknown` names a transport failure, and a transport failure is the *absence*
/// of a message, so no message can carry it. `resync_required` names a cursor
/// outside retention, and nothing is ever removed from the batch registry — an
/// unrecorded cursor is [`BatchRefusal::CursorOutOfRange`] instead, which says
/// something true. A reader that receives one of these on this protocol is
/// reading a response this build did not write.
pub const OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES: [ActionOutcome; 2] =
    [ActionOutcome::Unknown, ActionOutcome::ResyncRequired];

/// A bounded field costs at most two canonical bytes per source byte, because a
/// quote or a backslash escapes to two, plus the pair of quotes around it.
const MEMBER_KEY_ENCODED_BYTES: usize = 2 * MAX_BATCH_MEMBER_KEY_BYTES + 2;

/// Worst-case canonical bytes of one member view beside its key.
///
/// The six quoted member names and their punctuation (77: fifty-two name bytes,
/// twelve quote bytes, six colons, five commas and two braces), the longest
/// progress spelling quoted (13), four twenty-digit integers (80), and the comma
/// that separates the entry from the next — one hundred and seventy-one, rounded
/// up.
const MEMBER_VIEW_OVERHEAD_BYTES: usize = 192;

/// Worst-case canonical bytes of one listed batch row beside its two identifiers.
const BATCH_ROW_OVERHEAD_BYTES: usize = 256;

/// A batch row carries two maximal bounded strings: its identity and its label.
const BATCH_ROW_FIELD_BYTES: usize = 2 * (2 * MAX_BATCH_ID_BYTES + 2);

/// Worst-case canonical bytes of a body scaffold, excluding its repeated items.
const BODY_SCAFFOLD_BYTES: usize =
    2 * MAX_BATCH_ID_BYTES + 2 * MAX_BATCH_LABEL_BYTES + BATCH_ROW_OVERHEAD_BYTES + 256;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 480;

const _: () = assert!(
    MAX_BATCH_CONTROL_MEMBERS <= MAX_BATCH_MEMBERS,
    "this lane cannot admit a membership the batch model itself refuses"
);

const _: () = assert!(
    MAX_BATCH_CONTROL_MEMBERS * (MEMBER_KEY_ENCODED_BYTES + 1)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_BATCH_CONTROL_CANONICAL_BYTES,
    "a maximal batch registration must fit one batch control frame"
);

const _: () = assert!(
    MAX_BATCH_CONTROL_MEMBERS * (MEMBER_KEY_ENCODED_BYTES + MEMBER_VIEW_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_BATCH_CONTROL_CANONICAL_BYTES,
    "a maximal batch detail must fit one batch control frame"
);

const _: () = assert!(
    MAX_BATCH_PAGE_ITEMS * (BATCH_ROW_FIELD_BYTES + BATCH_ROW_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_BATCH_CONTROL_CANONICAL_BYTES,
    "a maximal batch listing page must fit one batch control frame"
);

/// A refusal while constructing, encoding or decoding a Batch control value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a member progress,
    /// concurrency kind or batch state this build does not define. Those fail
    /// closed rather than decoding to a default.
    Codec(CodecError),
    /// The batch model itself refused the value.
    ///
    /// Every refusal that is a property of *a batch* rather than of this
    /// transport is [`crate::batch_runner`]'s to make and travels verbatim: an
    /// empty membership, a repeated member, an incoherent concurrency ceiling,
    /// and a carried batch state its own members do not roll up to. Restating
    /// them here would create a second authority for one vocabulary.
    Model(BatchError),
    /// The message kind is not part of this closed protocol version.
    UnknownKind,
    /// A body was not the exact shape defined for its kind.
    InvalidBody,
    /// A counter cannot be represented by the integer-only wire codec.
    CounterOutOfRange {
        /// Field that was outside the wire range.
        field: &'static str,
    },
    /// A bounded identifier was empty, over-long or control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// A membership was larger than [`MAX_BATCH_CONTROL_MEMBERS`].
    ///
    /// This lane's own ceiling rather than the model's: see
    /// [`MAX_BATCH_CONTROL_MEMBERS`] for why the two differ and why they are not
    /// reconciled.
    MembershipTooLarge {
        /// Most members this lane carries.
        max_members: usize,
        /// Members the caller supplied.
        actual_members: usize,
    },
    /// A requested page size was zero or above [`MAX_BATCH_PAGE_ITEMS`].
    PageSizeOutOfRange {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Size the caller asked for.
        requested: usize,
    },
    /// A page carried more batches than [`MAX_BATCH_PAGE_ITEMS`].
    PageTooLarge {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Batches the caller supplied.
        actual_items: usize,
    },
    /// A page carried more batches than the query it answers asked for.
    PageAboveRequestedSize {
        /// Size the query asked for.
        requested: usize,
        /// Batches the page carried.
        actual_items: usize,
    },
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A revision was zero, which is a row no writer produced.
    ///
    /// Registration writes revision one, and every accepted advance writes one
    /// higher, so zero names a row this product could not have written.
    UnwrittenRevision,
    /// A durable timestamp was before the epoch, which the registry cannot hold.
    TimeBeforeEpoch {
        /// Field that carried the impossible instant.
        field: &'static str,
    },
    /// A reported sequence disagrees with the progress it accompanies.
    ///
    /// `unsubmitted` and `ready` mean zero spool events and carry a zero
    /// sequence; every other progress carries at least one. A property of the
    /// request alone, so it is judged here rather than left to the store.
    SequenceCoupling {
        /// Progress the writer reported.
        progress: MemberProgress,
        /// Sequence the writer reported beside it.
        last_sequence: u64,
    },
    /// A membership was not the ordinals `0..n` in order.
    ///
    /// Registration is the only writer of ordinals and writes exactly that, so a
    /// gap, a repeat or a step backwards names a membership nobody declared —
    /// and a rollup over it would summarize the wrong set.
    MembersOutOfOrder {
        /// Position, from zero, at which the ordinals stopped being contiguous.
        position: usize,
    },
    /// An advance receipt described a row registration wrote rather than one an
    /// advance produced.
    ///
    /// Registration is the only writer of revision one and it always writes
    /// `unsubmitted`, and the lattice has no edge back to `unsubmitted`, so an
    /// advance receipt below revision two — or one claiming that progress — names
    /// a row no accepted advance could have left behind.
    NotAnAdvance {
        /// Progress the receipt claimed.
        progress: MemberProgress,
        /// Revision the receipt claimed.
        revision: u64,
    },
    /// A page claimed rows follow without a cursor, or a cursor without rows
    /// following.
    ContinuationIncoherent,
    /// A continuation cursor did not reach the last row on the page.
    ContinuationRewinds,
    /// Page rows did not strictly increase by durable row identity.
    PageOutOfOrder,
    /// A conflict named a durable revision equal to the expected one, which is
    /// agreement rather than a conflict.
    ConflictWithoutDisagreement,
}

impl BatchApiError {
    /// Stable category suitable for logs and refusal metrics.
    ///
    /// Prefixed `batch_control_` rather than `batch_`, because
    /// [`crate::batch_runner`] already owns the `batch_` prefix for the document
    /// model — and a [`Self::Model`] refusal keeps that module's own spelling,
    /// which is how a metric says the batch was wrong rather than the frame.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Model(error) => error.category(),
            Self::UnknownKind => "batch_control_unknown_kind",
            Self::InvalidBody => "batch_control_invalid_body",
            Self::CounterOutOfRange { .. } => "batch_control_counter_out_of_range",
            Self::Field { .. } => "batch_control_invalid_field",
            Self::MembershipTooLarge { .. } => "batch_control_membership_too_large",
            Self::PageSizeOutOfRange { .. } => "batch_control_page_size_out_of_range",
            Self::PageTooLarge { .. } => "batch_control_page_too_large",
            Self::PageAboveRequestedSize { .. } => "batch_control_page_above_requested_size",
            Self::UnwrittenRow { .. } => "batch_control_unwritten_row",
            Self::UnwrittenRevision => "batch_control_unwritten_revision",
            Self::TimeBeforeEpoch { .. } => "batch_control_time_before_epoch",
            Self::SequenceCoupling { .. } => "batch_control_sequence_coupling",
            Self::MembersOutOfOrder { .. } => "batch_control_members_out_of_order",
            Self::NotAnAdvance { .. } => "batch_control_not_an_advance",
            Self::ContinuationIncoherent => "batch_control_continuation_incoherent",
            Self::ContinuationRewinds => "batch_control_continuation_rewinds",
            Self::PageOutOfOrder => "batch_control_page_out_of_order",
            Self::ConflictWithoutDisagreement => "batch_control_conflict_without_disagreement",
        }
    }
}

impl fmt::Display for BatchApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "batch codec refused message: {error}"),
            Self::Model(error) => write!(formatter, "{error}"),
            Self::UnknownKind => formatter.write_str("batch control message kind is not defined"),
            Self::InvalidBody => formatter.write_str("batch control message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(formatter, "batch counter {field} is outside the wire range")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::MembershipTooLarge {
                max_members,
                actual_members,
            } => write!(
                formatter,
                "membership carries {actual_members} members; this lane carries {max_members}"
            ),
            Self::PageSizeOutOfRange {
                max_items,
                requested,
            } => write!(
                formatter,
                "page size {requested} is outside 1..={max_items}"
            ),
            Self::PageTooLarge {
                max_items,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} batches; maximum is {max_items}"
            ),
            Self::PageAboveRequestedSize {
                requested,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} batches; the query asked for {requested}"
            ),
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::UnwrittenRevision => {
                formatter.write_str("revision zero names a row no writer produced")
            }
            Self::TimeBeforeEpoch { field } => write!(formatter, "{field} is before the epoch"),
            Self::SequenceCoupling {
                progress,
                last_sequence,
            } => write!(
                formatter,
                "member progress {progress} does not admit last_sequence {last_sequence}"
            ),
            Self::MembersOutOfOrder { position } => write!(
                formatter,
                "member {position} does not carry the ordinal its position declares"
            ),
            Self::NotAnAdvance { progress, revision } => write!(
                formatter,
                "an advance cannot leave a member {progress} at revision {revision}"
            ),
            Self::ContinuationIncoherent => {
                formatter.write_str("a page's continuation marker and cursor disagree")
            }
            Self::ContinuationRewinds => {
                formatter.write_str("a continuation cursor does not reach the end of its page")
            }
            Self::PageOutOfOrder => {
                formatter.write_str("page rows do not strictly increase by entry")
            }
            Self::ConflictWithoutDisagreement => {
                formatter.write_str("a revision conflict named the revision the caller expected")
            }
        }
    }
}

impl Error for BatchApiError {}

impl From<CodecError> for BatchApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<BatchError> for BatchApiError {
    fn from(value: BatchError) -> Self {
        Self::Model(value)
    }
}

/// A durable listing position: the batch a listing resumes *after*.
///
/// Zero starts at the beginning. This is the registry's own exclusive cursor
/// rather than a translated one — it pages by `entry_id` and reports the last one
/// it served — so no coordinate is converted between the wire and the table and
/// there is no off-by-one to re-derive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchCursor(u64);

impl BatchCursor {
    /// The beginning of the listing.
    pub const START: Self = Self(0);

    /// Name a listing position.
    #[must_use]
    pub const fn new(position: u64) -> Self {
        Self(position)
    }

    /// The entry this cursor resumes after.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0
    }
}

/// How many batches one listing asks for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchPageSize(usize);

impl BatchPageSize {
    /// The largest page this protocol serves.
    pub const MAX: Self = Self(MAX_BATCH_PAGE_ITEMS);

    /// Ask for a bounded number of batches.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::PageSizeOutOfRange`] for zero — a page that
    /// admits nothing cannot make progress — or for a size above
    /// [`MAX_BATCH_PAGE_ITEMS`].
    pub const fn new(items: usize) -> Result<Self, BatchApiError> {
        if items == 0 || items > MAX_BATCH_PAGE_ITEMS {
            return Err(BatchApiError::PageSizeOutOfRange {
                max_items: MAX_BATCH_PAGE_ITEMS,
                requested: items,
            });
        }
        Ok(Self(items))
    }

    /// The requested size.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// One batch presented for durable registration.
///
/// There is no timestamp field and no initial-progress field, and both absences
/// are deliberate. The daemon stamps the instant from its own clock, exactly as
/// it does for an automation transition — a caller-supplied instant would let a
/// client date a registration to whenever it liked. And registration always
/// writes every member `unsubmitted`, because a batch that has just been declared
/// has submitted nothing; a caller that has already submitted a member registers
/// first and advances second.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterBatch {
    batch_id: BatchId,
    label: Option<BatchLabel>,
    concurrency: ConcurrencyPolicy,
    members: Vec<BatchMemberKey>,
}

impl RegisterBatch {
    /// Declare a batch.
    ///
    /// The membership is kept in declaration order and is never sorted and never
    /// deduplicated: the order becomes the members' ordinals, because
    /// [`ConcurrencyPolicy::Sequential`] *names* it, and a repeated key is
    /// refused rather than collapsed because a caller that named a submission
    /// twice believes it asked for something it did not.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::Model`] carrying [`BatchError::EmptyBatch`] for
    /// a batch with no member, [`BatchError::DuplicateMember`] for a repeated
    /// key, and [`BatchError::ConcurrencyCeilingZero`] or
    /// [`BatchError::ConcurrencyCeilingUnreachable`] for an incoherent policy —
    /// the ceiling is re-checked here rather than assumed, because
    /// [`ConcurrencyPolicy::BoundedParallel`] is publicly constructible.
    /// Returns [`BatchApiError::MembershipTooLarge`] above
    /// [`MAX_BATCH_CONTROL_MEMBERS`].
    pub fn new(
        batch_id: BatchId,
        label: Option<BatchLabel>,
        concurrency: ConcurrencyPolicy,
        members: Vec<BatchMemberKey>,
    ) -> Result<Self, BatchApiError> {
        let concurrency = validated_concurrency(concurrency)?;
        bounded_membership(members.len())?;
        let mut ordered: Vec<&BatchMemberKey> = members.iter().collect();
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(BatchApiError::Model(BatchError::DuplicateMember {
                key: pair[0].clone(),
            }));
        }
        Ok(Self {
            batch_id,
            label,
            concurrency,
            members,
        })
    }

    /// The durable batch identity. The unique key.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// The operator-supplied label, when there is one. Recorded verbatim.
    #[must_use]
    pub const fn label(&self) -> Option<&BatchLabel> {
        self.label.as_ref()
    }

    /// The declared concurrency policy. Recorded, never enforced.
    #[must_use]
    pub const fn concurrency(&self) -> ConcurrencyPolicy {
        self.concurrency
    }

    /// The member keys, in declaration order, which becomes their ordinals.
    #[must_use]
    pub fn members(&self) -> &[BatchMemberKey] {
        &self.members
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            ("concurrency".to_owned(), concurrency_body(self.concurrency)),
            (
                "label".to_owned(),
                match &self.label {
                    Some(label) => JsonValue::String(label.as_str().to_owned()),
                    None => JsonValue::Null,
                },
            ),
            (
                "members".to_owned(),
                JsonValue::Array(
                    self.members
                        .iter()
                        .map(|key| JsonValue::String(key.as_str().to_owned()))
                        .collect(),
                ),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(body, &["batch_id", "concurrency", "label", "members"])?;
        let JsonValue::Array(items) = body.get("members").ok_or(BatchApiError::InvalidBody)? else {
            return Err(BatchApiError::InvalidBody);
        };
        bounded_membership(items.len())?;
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            members.push(member_key(
                item.as_str().ok_or(BatchApiError::InvalidBody)?,
            )?);
        }
        Self::new(
            batch_id(&required_string(body, "batch_id")?)?,
            optional_label(body)?,
            concurrency_from_body(body.get("concurrency").ok_or(BatchApiError::InvalidBody)?)?,
            members,
        )
    }
}

/// One writer's report that a member has moved.
///
/// What this presents is a *claim*. The run index is the true binding from a
/// submission to the state its run reached; this says what a writer observed
/// after reading it, and no transaction spans the two.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvanceMember {
    batch_id: BatchId,
    member_key: BatchMemberKey,
    expected_revision: u64,
    progress: MemberProgress,
    last_sequence: u64,
}

impl AdvanceMember {
    /// Report one member's progress.
    ///
    /// The sequence coupling is judged here, before any frame is spent and
    /// before any durable row is read, exactly as
    /// `automonique_store::batch_registry` judges it before reading the row: a
    /// caller that reports `ready` at a non-zero sequence is describing a run
    /// index row that cannot exist, whatever revision the member is at.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::UnwrittenRevision`] for a zero expected revision
    /// and [`BatchApiError::SequenceCoupling`] when the sequence disagrees with
    /// the progress beside it.
    pub fn new(
        batch_id: BatchId,
        member_key: BatchMemberKey,
        expected_revision: u64,
        progress: MemberProgress,
        last_sequence: u64,
    ) -> Result<Self, BatchApiError> {
        if expected_revision == 0 {
            return Err(BatchApiError::UnwrittenRevision);
        }
        if progress.has_not_started() != (last_sequence == 0) {
            return Err(BatchApiError::SequenceCoupling {
                progress,
                last_sequence,
            });
        }
        Ok(Self {
            batch_id,
            member_key,
            expected_revision,
            progress,
            last_sequence,
        })
    }

    /// The batch the member belongs to.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// The member whose row is being advanced, scoped to the batch.
    #[must_use]
    pub const fn member_key(&self) -> &BatchMemberKey {
        &self.member_key
    }

    /// Durable revision the caller believes it is advancing.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Progress the writer observed. A claim, never a reading.
    #[must_use]
    pub const fn progress(&self) -> MemberProgress {
        self.progress
    }

    /// Highest spool sequence the writer observed.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            (
                "expected_revision".to_owned(),
                integer("expected_revision", self.expected_revision)?,
            ),
            (
                "last_sequence".to_owned(),
                integer("last_sequence", self.last_sequence)?,
            ),
            (
                "member_key".to_owned(),
                JsonValue::String(self.member_key.as_str().to_owned()),
            ),
            (
                "state".to_owned(),
                JsonValue::String(self.progress.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(
            body,
            &[
                "batch_id",
                "expected_revision",
                "last_sequence",
                "member_key",
                "state",
            ],
        )?;
        Self::new(
            batch_id(&required_string(body, "batch_id")?)?,
            member_key(&required_string(body, "member_key")?)?,
            unsigned(body, "expected_revision")?,
            decode_security_enum::<MemberProgress>(&required_string(body, "state")?)?,
            unsigned(body, "last_sequence")?,
        )
    }
}

/// A bounded request for one page of every registered batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListBatches {
    since: BatchCursor,
    page_size: BatchPageSize,
}

impl ListBatches {
    /// Ask for one page.
    #[must_use]
    pub const fn new(since: BatchCursor, page_size: BatchPageSize) -> Self {
        Self { since, page_size }
    }

    /// The entry this listing resumes after.
    #[must_use]
    pub const fn since(self) -> BatchCursor {
        self.since
    }

    /// How many batches this listing asks for.
    #[must_use]
    pub const fn page_size(self) -> BatchPageSize {
        self.page_size
    }

    fn to_body(self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            ("since".to_owned(), integer("since", self.since.position())?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(body, &["page_size", "since"])?;
        Ok(Self::new(
            BatchCursor::new(unsigned(body, "since")?),
            page_size(body)?,
        ))
    }
}

/// What one accepted registration established.
///
/// This is `automonique_store::batch_registry::BatchReceipt` on the wire, plus
/// the identity it is about — the store's receipt omits it because its caller
/// supplied it, and a correlated answer travelling on its own cannot rely on
/// that.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceiptView {
    entry_id: u64,
    batch_id: BatchId,
    member_count: usize,
    revision: u64,
    created_at: EpochMillis,
}

impl BatchReceiptView {
    /// Record what one accepted registration established.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::UnwrittenRow`] for a zero `entry_id`,
    /// [`BatchApiError::UnwrittenRevision`] for a zero revision,
    /// [`BatchApiError::Model`] carrying [`BatchError::EmptyBatch`] for a batch
    /// that wrote no member, [`BatchApiError::MembershipTooLarge`] above
    /// [`MAX_BATCH_CONTROL_MEMBERS`], and [`BatchApiError::TimeBeforeEpoch`] for
    /// an instant the registry's `created_at_ms >= 0` constraint cannot hold.
    pub fn new(
        entry_id: u64,
        batch_id: BatchId,
        member_count: usize,
        revision: u64,
        created_at: EpochMillis,
    ) -> Result<Self, BatchApiError> {
        if entry_id == 0 {
            return Err(BatchApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision == 0 {
            return Err(BatchApiError::UnwrittenRevision);
        }
        bounded_membership(member_count)?;
        if created_at.as_millis() < 0 {
            return Err(BatchApiError::TimeBeforeEpoch {
                field: "created_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            batch_id,
            member_count,
            revision,
            created_at,
        })
    }

    /// Row identity, monotonic in registration order. The pagination key.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// The batch this receipt is about.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// Members written, all at `unsubmitted`, at ordinals `0..member_count`.
    #[must_use]
    pub const fn member_count(&self) -> usize {
        self.member_count
    }

    /// Revision the batch row now carries.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The instant the durable row records.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(self.created_at.as_millis()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            (
                "member_count".to_owned(),
                integer("member_count", self.member_count as u64)?,
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(
            body,
            &[
                "batch_id",
                "created_at_ms",
                "entry_id",
                "member_count",
                "revision",
            ],
        )?;
        Self::new(
            unsigned(body, "entry_id")?,
            batch_id(&required_string(body, "batch_id")?)?,
            count(body, "member_count")?,
            unsigned(body, "revision")?,
            EpochMillis::from_millis(signed(body, "created_at_ms")?),
        )
    }
}

/// What one accepted advance established.
///
/// This is `automonique_store::batch_registry::MemberReceipt` on the wire, plus
/// the coordinates it is about. The `revision` is the fencing value the *next*
/// advance of this member must expect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberReceiptView {
    batch_id: BatchId,
    member_key: BatchMemberKey,
    ordinal: u32,
    progress: MemberProgress,
    last_sequence: u64,
    revision: u64,
    updated_at: EpochMillis,
}

impl MemberReceiptView {
    /// Record what one accepted advance established.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::NotAnAdvance`] for a revision below two or a
    /// claimed `unsubmitted` — registration is the only writer of either, and the
    /// lattice has no edge back to `unsubmitted` —
    /// [`BatchApiError::SequenceCoupling`] when the recorded sequence disagrees
    /// with the recorded progress, [`BatchApiError::MembersOutOfOrder`] for an
    /// ordinal outside the membership this lane carries, and
    /// [`BatchApiError::TimeBeforeEpoch`].
    pub fn new(parts: MemberReceiptParts) -> Result<Self, BatchApiError> {
        let MemberReceiptParts {
            batch_id,
            member_key,
            ordinal,
            progress,
            last_sequence,
            revision,
            updated_at,
        } = parts;
        if revision < 2 || progress == MemberProgress::Unsubmitted {
            return Err(BatchApiError::NotAnAdvance { progress, revision });
        }
        member_invariants(ordinal, progress, last_sequence, updated_at)?;
        Ok(Self {
            batch_id,
            member_key,
            ordinal,
            progress,
            last_sequence,
            revision,
            updated_at,
        })
    }

    /// The batch the advanced member belongs to.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// The advanced member.
    #[must_use]
    pub const fn member_key(&self) -> &BatchMemberKey {
        &self.member_key
    }

    /// Position of the member in its batch's declaration order.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Progress the row now records.
    #[must_use]
    pub const fn progress(&self) -> MemberProgress {
        self.progress
    }

    /// Sequence the row now records.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Revision the row now carries. The next advance must expect this.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Instant the row now records.
    #[must_use]
    pub const fn updated_at(&self) -> EpochMillis {
        self.updated_at
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            (
                "last_sequence".to_owned(),
                integer("last_sequence", self.last_sequence)?,
            ),
            (
                "member_key".to_owned(),
                JsonValue::String(self.member_key.as_str().to_owned()),
            ),
            (
                "ordinal".to_owned(),
                integer("ordinal", u64::from(self.ordinal))?,
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "state".to_owned(),
                JsonValue::String(self.progress.as_str().to_owned()),
            ),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(self.updated_at.as_millis()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(
            body,
            &[
                "batch_id",
                "last_sequence",
                "member_key",
                "ordinal",
                "revision",
                "state",
                "updated_at_ms",
            ],
        )?;
        Self::new(MemberReceiptParts {
            batch_id: batch_id(&required_string(body, "batch_id")?)?,
            member_key: member_key(&required_string(body, "member_key")?)?,
            ordinal: ordinal(body)?,
            progress: decode_security_enum::<MemberProgress>(&required_string(body, "state")?)?,
            last_sequence: unsigned(body, "last_sequence")?,
            revision: unsigned(body, "revision")?,
            updated_at: EpochMillis::from_millis(signed(body, "updated_at_ms")?),
        })
    }
}

/// The seven coordinates one advance receipt carries.
///
/// A parameter object rather than seven positional arguments: two bounded
/// identifiers sit beside one another, and a transposed pair would type-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberReceiptParts {
    /// The batch the advanced member belongs to.
    pub batch_id: BatchId,
    /// The advanced member.
    pub member_key: BatchMemberKey,
    /// Position of the member in its batch's declaration order.
    pub ordinal: u32,
    /// Progress the row now records.
    pub progress: MemberProgress,
    /// Sequence the row now records.
    pub last_sequence: u64,
    /// Revision the row now carries.
    pub revision: u64,
    /// Instant the row now records.
    pub updated_at: EpochMillis,
}

/// One validated `batches` row, as a listing or a detail read reports it.
///
/// There is no rolled-up batch state here, and deliberately so: a listing carries
/// batch rows and not their members, so it has nothing to roll up *from*. The
/// derived state is served only where the members that justify it travel beside
/// it, which is [`BatchDetailResult`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRecordView {
    entry_id: u64,
    batch_id: BatchId,
    label: Option<BatchLabel>,
    concurrency: ConcurrencyPolicy,
    created_at: EpochMillis,
    revision: u64,
}

impl BatchRecordView {
    /// Record one batch row, refusing every row this product could not have
    /// written.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::UnwrittenRow`], [`BatchApiError::UnwrittenRevision`],
    /// [`BatchApiError::TimeBeforeEpoch`], or [`BatchApiError::Model`] for an
    /// incoherent concurrency policy.
    pub fn new(
        entry_id: u64,
        batch_id: BatchId,
        label: Option<BatchLabel>,
        concurrency: ConcurrencyPolicy,
        created_at: EpochMillis,
        revision: u64,
    ) -> Result<Self, BatchApiError> {
        if entry_id == 0 {
            return Err(BatchApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision == 0 {
            return Err(BatchApiError::UnwrittenRevision);
        }
        if created_at.as_millis() < 0 {
            return Err(BatchApiError::TimeBeforeEpoch {
                field: "created_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            batch_id,
            label,
            concurrency: validated_concurrency(concurrency)?,
            created_at,
            revision,
        })
    }

    /// Row identity, monotonic in registration order.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// Durable batch identity.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// The operator-supplied label, when the batch was given one.
    #[must_use]
    pub const fn label(&self) -> Option<&BatchLabel> {
        self.label.as_ref()
    }

    /// The declared concurrency policy. Recorded, never enforced.
    #[must_use]
    pub const fn concurrency(&self) -> ConcurrencyPolicy {
        self.concurrency
    }

    /// When the batch was registered.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }

    /// Revision the batch row carries.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            ("concurrency".to_owned(), concurrency_body(self.concurrency)),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(self.created_at.as_millis()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            (
                "label".to_owned(),
                match &self.label {
                    Some(label) => JsonValue::String(label.as_str().to_owned()),
                    None => JsonValue::Null,
                },
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(
            body,
            &[
                "batch_id",
                "concurrency",
                "created_at_ms",
                "entry_id",
                "label",
                "revision",
            ],
        )?;
        Self::new(
            unsigned(body, "entry_id")?,
            batch_id(&required_string(body, "batch_id")?)?,
            optional_label(body)?,
            concurrency_from_body(body.get("concurrency").ok_or(BatchApiError::InvalidBody)?)?,
            EpochMillis::from_millis(signed(body, "created_at_ms")?),
            unsigned(body, "revision")?,
        )
    }
}

/// One validated `batch_members` row, as a detail read reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberView {
    key: BatchMemberKey,
    ordinal: u32,
    progress: MemberProgress,
    last_sequence: u64,
    revision: u64,
    updated_at: EpochMillis,
}

impl MemberView {
    /// Record one member row.
    ///
    /// The two cross-column invariants the registry re-derives on every read are
    /// re-derived here, because a wire value is read by clients the registry
    /// never sees: a progress that has not started and a zero `last_sequence`
    /// imply each other, and `unsubmitted` implies revision one, because
    /// registration is the only writer of `unsubmitted` and it always writes one.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::UnwrittenRevision`],
    /// [`BatchApiError::SequenceCoupling`] and
    /// [`BatchApiError::TimeBeforeEpoch`].
    pub fn new(
        key: BatchMemberKey,
        ordinal: u32,
        progress: MemberProgress,
        last_sequence: u64,
        revision: u64,
        updated_at: EpochMillis,
    ) -> Result<Self, BatchApiError> {
        if revision == 0 || (progress == MemberProgress::Unsubmitted && revision != 1) {
            return Err(BatchApiError::UnwrittenRevision);
        }
        member_invariants(ordinal, progress, last_sequence, updated_at)?;
        Ok(Self {
            key,
            ordinal,
            progress,
            last_sequence,
            revision,
            updated_at,
        })
    }

    /// The submission this member names.
    #[must_use]
    pub const fn key(&self) -> &BatchMemberKey {
        &self.key
    }

    /// Position in the batch's declaration order, from zero.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// The last progress a writer reported. Never a reading of a run.
    #[must_use]
    pub const fn progress(&self) -> MemberProgress {
        self.progress
    }

    /// The last sequence a writer reported.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Revision the row carries. An advance of this member must expect it.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// When the last report was recorded.
    #[must_use]
    pub const fn updated_at(&self) -> EpochMillis {
        self.updated_at
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        Ok(JsonValue::Object(vec![
            (
                "key".to_owned(),
                JsonValue::String(self.key.as_str().to_owned()),
            ),
            (
                "last_sequence".to_owned(),
                integer("last_sequence", self.last_sequence)?,
            ),
            (
                "ordinal".to_owned(),
                integer("ordinal", u64::from(self.ordinal))?,
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "state".to_owned(),
                JsonValue::String(self.progress.as_str().to_owned()),
            ),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(self.updated_at.as_millis()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(
            body,
            &[
                "key",
                "last_sequence",
                "ordinal",
                "revision",
                "state",
                "updated_at_ms",
            ],
        )?;
        Self::new(
            member_key(&required_string(body, "key")?)?,
            ordinal(body)?,
            decode_security_enum::<MemberProgress>(&required_string(body, "state")?)?,
            unsigned(body, "last_sequence")?,
            unsigned(body, "revision")?,
            EpochMillis::from_millis(signed(body, "updated_at_ms")?),
        )
    }
}

/// Whether a page is the end of the listing.
///
/// Closed, and carried explicitly rather than inferred from `entries.len() <
/// page_size`. A short page is not the same statement as a last page, and a
/// client that inferred "done" from a short page would stop early.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchContinuation {
    /// More rows may follow; resume after this cursor.
    More(BatchCursor),
    /// The listing reached the end of the registry.
    Complete,
}

impl BatchContinuation {
    /// The cursor to resume after, when there is one.
    #[must_use]
    pub const fn cursor(self) -> Option<BatchCursor> {
        match self {
            Self::More(cursor) => Some(cursor),
            Self::Complete => None,
        }
    }

    /// Whether more rows may follow.
    #[must_use]
    pub const fn has_more(self) -> bool {
        matches!(self, Self::More(_))
    }
}

/// One bounded page of batch rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchListPage {
    entries: Vec<BatchRecordView>,
    continuation: BatchContinuation,
}

impl BatchListPage {
    /// Assemble a page.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::PageTooLarge`] above [`MAX_BATCH_PAGE_ITEMS`],
    /// [`BatchApiError::PageOutOfOrder`] when rows do not strictly increase by
    /// `entry_id` — a listing is ordered by that identity, and a repeat or a step
    /// backwards means the next page would re-serve or skip — and
    /// [`BatchApiError::ContinuationRewinds`] when a continuation cursor does not
    /// reach the last row on the page.
    pub fn new(
        entries: Vec<BatchRecordView>,
        continuation: BatchContinuation,
    ) -> Result<Self, BatchApiError> {
        if entries.len() > MAX_BATCH_PAGE_ITEMS {
            return Err(BatchApiError::PageTooLarge {
                max_items: MAX_BATCH_PAGE_ITEMS,
                actual_items: entries.len(),
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[1].entry_id() <= pair[0].entry_id())
        {
            return Err(BatchApiError::PageOutOfOrder);
        }
        if let (Some(cursor), Some(last)) = (continuation.cursor(), entries.last())
            && cursor.position() < last.entry_id()
        {
            return Err(BatchApiError::ContinuationRewinds);
        }
        Ok(Self {
            entries,
            continuation,
        })
    }

    /// The batch rows, in registration order.
    #[must_use]
    pub fn entries(&self) -> &[BatchRecordView] {
        &self.entries
    }

    /// Whether more rows may follow, and from where.
    #[must_use]
    pub const fn continuation(&self) -> BatchContinuation {
        self.continuation
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for record in &self.entries {
            entries.push(record.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            ("batches".to_owned(), JsonValue::Array(entries)),
            (
                "more".to_owned(),
                JsonValue::Bool(self.continuation.has_more()),
            ),
            (
                "next_cursor".to_owned(),
                match self.continuation.cursor() {
                    Some(cursor) => integer("next_cursor", cursor.position())?,
                    None => JsonValue::Null,
                },
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(body, &["batches", "more", "next_cursor"])?;
        let more = match body.get("more") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(BatchApiError::InvalidBody),
        };
        let continuation = match (more, body.get("next_cursor")) {
            (true, Some(JsonValue::Integer(_))) => {
                BatchContinuation::More(BatchCursor::new(unsigned(body, "next_cursor")?))
            }
            (false, Some(JsonValue::Null)) => BatchContinuation::Complete,
            (true, Some(JsonValue::Null)) | (false, Some(JsonValue::Integer(_))) => {
                return Err(BatchApiError::ContinuationIncoherent);
            }
            _ => return Err(BatchApiError::InvalidBody),
        };
        let JsonValue::Array(items) = body.get("batches").ok_or(BatchApiError::InvalidBody)? else {
            return Err(BatchApiError::InvalidBody);
        };
        if items.len() > MAX_BATCH_PAGE_ITEMS {
            return Err(BatchApiError::PageTooLarge {
                max_items: MAX_BATCH_PAGE_ITEMS,
                actual_items: items.len(),
            });
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            entries.push(BatchRecordView::from_body(item)?);
        }
        Self::new(entries, continuation)
    }
}

/// One batch, its whole membership, and what that membership rolls up to.
///
/// The batch-level state is **not** a field a caller supplies: [`Self::new`]
/// derives it with [`roll_up`] over the members it is given, and
/// [`Self::from_body`] re-derives it on decode and refuses a body whose carried
/// state contradicts its own members. That is the same discipline
/// [`crate::batch_runner::BatchProgress`] holds for a document, and it is the
/// reason serving a derived answer over a store that deliberately does not
/// persist one is safe: the derivation travels beside its own evidence, and a
/// reader checks it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDetailResult {
    batch: BatchRecordView,
    members: Vec<MemberView>,
    state: BatchState,
}

impl BatchDetailResult {
    /// Assemble one batch's detail and derive its rolled-up state.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::Model`] carrying [`BatchError::EmptyBatch`] for
    /// a batch with no member — registration refuses to produce one, so a
    /// membership that is empty is a row nothing here wrote —
    /// [`BatchApiError::MembershipTooLarge`] above [`MAX_BATCH_CONTROL_MEMBERS`],
    /// and [`BatchApiError::MembersOutOfOrder`] when the members are not the
    /// ordinals `0..n` in order.
    pub fn new(batch: BatchRecordView, members: Vec<MemberView>) -> Result<Self, BatchApiError> {
        bounded_membership(members.len())?;
        for (position, member) in members.iter().enumerate() {
            let expected = u32::try_from(position)
                .map_err(|_| BatchApiError::MembersOutOfOrder { position })?;
            if member.ordinal() != expected {
                return Err(BatchApiError::MembersOutOfOrder { position });
            }
        }
        let state = rolled_up(&members)?;
        Ok(Self {
            batch,
            members,
            state,
        })
    }

    /// The batch row.
    #[must_use]
    pub const fn batch(&self) -> &BatchRecordView {
        &self.batch
    }

    /// Its members, ordinal `0..n`, oldest position first.
    #[must_use]
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }

    /// The rolled-up batch state, derived from the members beside it.
    ///
    /// Never stored anywhere. See the module documentation on why the registry
    /// has no such column and why this answer is still safe to serve.
    #[must_use]
    pub const fn rolled_up_state(&self) -> BatchState {
        self.state
    }

    fn to_body(&self) -> Result<JsonValue, BatchApiError> {
        let mut members = Vec::with_capacity(self.members.len());
        for member in &self.members {
            members.push(member.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            ("batch".to_owned(), self.batch.to_body()?),
            ("members".to_owned(), JsonValue::Array(members)),
            (
                "state".to_owned(),
                JsonValue::String(self.state.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchApiError> {
        exact_fields(body, &["batch", "members", "state"])?;
        let JsonValue::Array(items) = body.get("members").ok_or(BatchApiError::InvalidBody)? else {
            return Err(BatchApiError::InvalidBody);
        };
        bounded_membership(items.len())?;
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            members.push(MemberView::from_body(item)?);
        }
        let mut ordered: Vec<&BatchMemberKey> = members.iter().map(MemberView::key).collect();
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(BatchApiError::Model(BatchError::DuplicateMember {
                key: pair[0].clone(),
            }));
        }
        let detail = Self::new(
            BatchRecordView::from_body(body.get("batch").ok_or(BatchApiError::InvalidBody)?)?,
            members,
        )?;
        // The carried state is checked against the rollup of the members beside
        // it rather than trusted, so a response that disagrees with itself is
        // refused instead of believed.
        let carried = decode_security_enum::<BatchState>(&required_string(body, "state")?)?;
        if carried != detail.state {
            return Err(BatchApiError::Model(BatchError::RollupContradictsMembers {
                carried,
                derived: detail.state,
            }));
        }
        Ok(detail)
    }
}

/// Why a batch control operation was refused.
///
/// Closed, and every variant is one word. A refusal carries no field name, no
/// stored text and no echo of the caller's payload: a refusal category is a
/// metric label and an operator-facing word, not a diagnostic channel for the
/// bytes that were sent.
///
/// A stale expected revision is deliberately *not* here. It is
/// [`BatchResponse::Conflict`], which the plan's vocabulary distinguishes from a
/// rejection precisely because a caller retries the two differently: a conflict
/// is retried against the durable revision the answer carries, and a rejection is
/// not retried at all until the request changes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchRefusal {
    /// No batch is registered under that identity.
    UnknownBatch,
    /// The batch is registered and declares no such member.
    ///
    /// Distinct from [`Self::UnknownBatch`] because the two are fixed
    /// differently: one is a batch nobody registered, the other is a key the
    /// batch never named and never will, since the membership is fixed at
    /// registration.
    UnknownMember,
    /// That batch identity is already registered.
    ///
    /// Never an overwrite: a re-registration would reset member rows a writer
    /// may already have advanced, and silently discarding a batch's recorded
    /// progress is the one thing the registry exists to prevent.
    AlreadyRegistered,
    /// A batch named no member, which is a unit with nothing in it.
    EmptyBatch,
    /// A batch named more members than this lane carries.
    TooManyMembers,
    /// A batch named one member key twice. Refused, never collapsed.
    DuplicateMember,
    /// A concurrency ceiling was zero or above what a batch could reach.
    ///
    /// One word for both couplings: a ceiling that admits nothing and a ceiling
    /// that can never bind are the same mistake — a policy whose number says
    /// something the batch cannot do — and are fixed the same way.
    ConcurrencyCeiling,
    /// The reported progress does not follow the durable one along the lattice.
    IllegalTransition,
    /// A reported sequence disagrees with the progress it accompanies.
    SequenceCoupling,
    /// The reported sequence does not advance past the durable one.
    SequenceRegression,
    /// A page was requested from a cursor above everything recorded.
    CursorOutOfRange,
    /// The registry holds its full capacity of batches.
    ///
    /// Registration is refused rather than evicting an older batch, and there is
    /// no prune to make room: forgetting a batch would strand the only durable
    /// record of what it declared.
    RegistryFull,
    /// A supplied field was outside the durable registry's grammar.
    InvalidField,
}

impl BatchRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 13] = [
        Self::UnknownBatch,
        Self::UnknownMember,
        Self::AlreadyRegistered,
        Self::EmptyBatch,
        Self::TooManyMembers,
        Self::DuplicateMember,
        Self::ConcurrencyCeiling,
        Self::IllegalTransition,
        Self::SequenceCoupling,
        Self::SequenceRegression,
        Self::CursorOutOfRange,
        Self::RegistryFull,
        Self::InvalidField,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownBatch => "unknown_batch",
            Self::UnknownMember => "unknown_member",
            Self::AlreadyRegistered => "already_registered",
            Self::EmptyBatch => "empty_batch",
            Self::TooManyMembers => "too_many_members",
            Self::DuplicateMember => "duplicate_member",
            Self::ConcurrencyCeiling => "concurrency_ceiling",
            Self::IllegalTransition => "illegal_transition",
            Self::SequenceCoupling => "sequence_coupling",
            Self::SequenceRegression => "sequence_regression",
            Self::CursorOutOfRange => "cursor_out_of_range",
            Self::RegistryFull => "registry_full",
            Self::InvalidField => "invalid_field",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|refusal| refusal.as_str() == value)
    }
}

impl fmt::Display for BatchRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl crate::codec::SecuritySensitiveEnum for BatchRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated request on the Batch control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchRequest {
    /// Declare one batch and its whole membership.
    RegisterBatch {
        /// Correlation identifier.
        request_id: RequestId,
        /// The batch to register.
        registration: RegisterBatch,
    },
    /// Report that one member moved.
    AdvanceMember {
        /// Correlation identifier.
        request_id: RequestId,
        /// The report.
        advance: AdvanceMember,
    },
    /// One bounded page of every registered batch.
    ListBatches {
        /// Correlation identifier.
        request_id: RequestId,
        /// Cursor and page size.
        query: ListBatches,
    },
    /// One batch, its members, and their rollup.
    BatchDetail {
        /// Correlation identifier.
        request_id: RequestId,
        /// Batch to read.
        batch_id: BatchId,
    },
}

impl BatchRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::RegisterBatch { request_id, .. }
            | Self::AdvanceMember { request_id, .. }
            | Self::ListBatches { request_id, .. }
            | Self::BatchDetail { request_id, .. } => request_id,
        }
    }

    /// Whether this request would change durable state.
    ///
    /// Reads and the two writes travel the same lane, and the daemon fences all
    /// of them the same way, so this exists for callers that log or meter the
    /// difference rather than for anything that decides it.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::RegisterBatch { .. } | Self::AdvanceMember { .. }
        )
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, BatchApiError> {
        match self {
            Self::RegisterBatch {
                request_id,
                registration,
            } => Ok(Message::new(
                envelope(request_id.clone(), "register_batch")?,
                registration.to_body(),
            )),
            Self::AdvanceMember {
                request_id,
                advance,
            } => Ok(Message::new(
                envelope(request_id.clone(), "advance_member")?,
                advance.to_body()?,
            )),
            Self::ListBatches { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "list_batches")?,
                query.to_body()?,
            )),
            Self::BatchDetail {
                request_id,
                batch_id,
            } => Ok(Message::new(
                envelope(request_id.clone(), "batch_detail")?,
                JsonValue::Object(vec![(
                    "batch_id".to_owned(),
                    JsonValue::String(batch_id.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, BatchApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "register_batch" => Ok(Self::RegisterBatch {
                request_id,
                registration: RegisterBatch::from_body(message.body())?,
            }),
            "advance_member" => Ok(Self::AdvanceMember {
                request_id,
                advance: AdvanceMember::from_body(message.body())?,
            }),
            "list_batches" => Ok(Self::ListBatches {
                request_id,
                query: ListBatches::from_body(message.body())?,
            }),
            "batch_detail" => {
                exact_fields(message.body(), &["batch_id"])?;
                Ok(Self::BatchDetail {
                    request_id,
                    batch_id: batch_id(&required_string(message.body(), "batch_id")?)?,
                })
            }
            _ => Err(BatchApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the Batch control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchResponse {
    /// One batch and its whole membership are durable.
    Registered {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the write established.
        receipt: BatchReceiptView,
    },
    /// One member's row moved.
    MemberAdvanced {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the write established.
        receipt: MemberReceiptView,
    },
    /// One page of batches.
    BatchList {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The page.
        page: BatchListPage,
    },
    /// One batch in full, with the state its members roll up to.
    BatchDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The batch, its members, and their rollup.
        detail: BatchDetailResult,
    },
    /// The caller's expected revision did not match the durable one. Nothing
    /// was written.
    Conflict {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Revision the caller believed it was advancing.
        expected_revision: u64,
        /// Revision the durable row carries. Retry against this one.
        durable_revision: u64,
    },
    /// The operation was refused. Nothing was written and nothing was read.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: BatchRefusal,
    },
}

impl BatchResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Registered { request_id, .. }
            | Self::MemberAdvanced { request_id, .. }
            | Self::BatchList { request_id, .. }
            | Self::BatchDetail { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A delivered read is `completed`: there is no later completion to wait
    /// for. A durable write is `accepted` rather than `completed`, and the
    /// distinction is the honest one — the rows *are* committed, and what they
    /// record has not taken effect and cannot: registering a batch submits
    /// nothing, and advancing a member runs nothing. `accepted` says "recorded";
    /// `completed` would say the batch progressed, which would be a claim about
    /// an executor this release does not contain.
    ///
    /// See [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] for the two this protocol
    /// cannot produce and why.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Registered { .. } | Self::MemberAdvanced { .. } => ActionOutcome::Accepted,
            Self::BatchList { .. } | Self::BatchDetail { .. } => ActionOutcome::Completed,
            Self::Conflict { .. } => ActionOutcome::Conflict,
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Build the answer to a listing from the rows a store produced.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::PageAboveRequestedSize`] for a page longer than
    /// the query asked for, which would look perfectly well-formed to a client
    /// and would silently contradict the question it asked.
    pub fn listing(
        request_id: RequestId,
        query: ListBatches,
        page: BatchListPage,
    ) -> Result<Self, BatchApiError> {
        if page.entries().len() > query.page_size().get() {
            return Err(BatchApiError::PageAboveRequestedSize {
                requested: query.page_size().get(),
                actual_items: page.entries().len(),
            });
        }
        Ok(Self::BatchList { request_id, page })
    }

    /// Report a stale expected revision.
    ///
    /// # Errors
    ///
    /// Returns [`BatchApiError::UnwrittenRevision`] for a zero on either side,
    /// and [`BatchApiError::ConflictWithoutDisagreement`] when the two revisions
    /// agree — which is not a conflict, and answering one would tell a caller to
    /// retry with the revision it already used.
    pub fn conflict(
        request_id: RequestId,
        expected_revision: u64,
        durable_revision: u64,
    ) -> Result<Self, BatchApiError> {
        if expected_revision == 0 || durable_revision == 0 {
            return Err(BatchApiError::UnwrittenRevision);
        }
        if expected_revision == durable_revision {
            return Err(BatchApiError::ConflictWithoutDisagreement);
        }
        Ok(Self::Conflict {
            request_id,
            expected_revision,
            durable_revision,
        })
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, BatchApiError> {
        match self {
            Self::Registered {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "batch_registered")?,
                receipt.to_body()?,
            )),
            Self::MemberAdvanced {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "member_advanced")?,
                receipt.to_body()?,
            )),
            Self::BatchList { request_id, page } => Ok(Message::new(
                envelope(request_id.clone(), "batch_list_result")?,
                page.to_body()?,
            )),
            Self::BatchDetail { request_id, detail } => Ok(Message::new(
                envelope(request_id.clone(), "batch_detail_result")?,
                detail.to_body()?,
            )),
            Self::Conflict {
                request_id,
                expected_revision,
                durable_revision,
            } => Ok(Message::new(
                envelope(request_id.clone(), "revision_conflict")?,
                JsonValue::Object(vec![
                    (
                        "durable_revision".to_owned(),
                        integer("durable_revision", *durable_revision)?,
                    ),
                    (
                        "expected_revision".to_owned(),
                        integer("expected_revision", *expected_revision)?,
                    ),
                ]),
            )),
            Self::Refused {
                request_id,
                refusal,
            } => Ok(Message::new(
                envelope(request_id.clone(), "refused")?,
                JsonValue::Object(vec![(
                    "refusal".to_owned(),
                    JsonValue::String(refusal.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a response against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, BatchApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "batch_registered" => Ok(Self::Registered {
                request_id,
                receipt: BatchReceiptView::from_body(message.body())?,
            }),
            "member_advanced" => Ok(Self::MemberAdvanced {
                request_id,
                receipt: MemberReceiptView::from_body(message.body())?,
            }),
            "batch_list_result" => Ok(Self::BatchList {
                request_id,
                page: BatchListPage::from_body(message.body())?,
            }),
            "batch_detail_result" => Ok(Self::BatchDetail {
                request_id,
                detail: BatchDetailResult::from_body(message.body())?,
            }),
            "revision_conflict" => {
                exact_fields(message.body(), &["durable_revision", "expected_revision"])?;
                Self::conflict(
                    request_id,
                    unsigned(message.body(), "expected_revision")?,
                    unsigned(message.body(), "durable_revision")?,
                )
            }
            "refused" => {
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<BatchRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(BatchApiError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, BatchApiError> {
    Ok(Envelope::new(
        ProtocolName::new(BATCH_CONTROL_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, BatchApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(BATCH_CONTROL_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

/// The rollup of a member list, refusing the empty one.
///
/// One authority: [`roll_up`] is `batch_runner`'s, and its `None` for an empty
/// slice becomes [`BatchError::EmptyBatch`] exactly as that module's own
/// `rolled_up` helper makes it — an empty batch has no state, and inventing one
/// would answer `completed` for a batch that never ran.
fn rolled_up(members: &[MemberView]) -> Result<BatchState, BatchApiError> {
    let progresses: Vec<MemberProgress> = members.iter().map(MemberView::progress).collect();
    roll_up(&progresses).ok_or(BatchApiError::Model(BatchError::EmptyBatch))
}

/// Re-check the ceiling a concurrency policy carries.
///
/// [`ConcurrencyPolicy::BoundedParallel`] is publicly constructible with a
/// struct literal, so a value that never went through
/// [`ConcurrencyPolicy::bounded_parallel`] may carry a ceiling that admits
/// nothing or one no batch could reach. The refusal is the model's own.
fn validated_concurrency(policy: ConcurrencyPolicy) -> Result<ConcurrencyPolicy, BatchApiError> {
    match policy {
        ConcurrencyPolicy::Sequential => Ok(policy),
        ConcurrencyPolicy::BoundedParallel { max_in_flight } => {
            ConcurrencyPolicy::bounded_parallel(max_in_flight).map_err(BatchApiError::Model)
        }
    }
}

/// The membership bound both directions share.
///
/// One reader for the registration, the receipt and the detail, so the three
/// cannot disagree about how large a membership this lane carries.
const fn bounded_membership(members: usize) -> Result<(), BatchApiError> {
    if members == 0 {
        return Err(BatchApiError::Model(BatchError::EmptyBatch));
    }
    if members > MAX_BATCH_CONTROL_MEMBERS {
        return Err(BatchApiError::MembershipTooLarge {
            max_members: MAX_BATCH_CONTROL_MEMBERS,
            actual_members: members,
        });
    }
    Ok(())
}

/// The invariants every member-shaped value re-derives.
///
/// The sequence coupling and the instant, plus an ordinal within the membership
/// this lane carries. Shared by the advance receipt and the detail view so the
/// two cannot disagree about which rows are believable.
const fn member_invariants(
    ordinal: u32,
    progress: MemberProgress,
    last_sequence: u64,
    updated_at: EpochMillis,
) -> Result<(), BatchApiError> {
    if ordinal as usize >= MAX_BATCH_CONTROL_MEMBERS {
        return Err(BatchApiError::MembersOutOfOrder {
            position: ordinal as usize,
        });
    }
    if progress.has_not_started() != (last_sequence == 0) {
        return Err(BatchApiError::SequenceCoupling {
            progress,
            last_sequence,
        });
    }
    if updated_at.as_millis() < 0 {
        return Err(BatchApiError::TimeBeforeEpoch {
            field: "updated_at_ms",
        });
    }
    Ok(())
}

fn concurrency_body(policy: ConcurrencyPolicy) -> JsonValue {
    JsonValue::Object(vec![
        (
            "kind".to_owned(),
            JsonValue::String(policy.kind().as_str().to_owned()),
        ),
        (
            "max_in_flight".to_owned(),
            match policy.declared_ceiling() {
                Some(ceiling) => JsonValue::Integer(i64::from(ceiling)),
                None => JsonValue::Null,
            },
        ),
    ])
}

/// Decode a concurrency policy, failing closed on an unknown kind.
///
/// The kind and the ceiling imply each other: exactly one of the two words
/// carries a number, and a `bounded_parallel` without one — or a `sequential`
/// with one — is a policy this build cannot mean.
fn concurrency_from_body(body: &JsonValue) -> Result<ConcurrencyPolicy, BatchApiError> {
    exact_fields(body, &["kind", "max_in_flight"])?;
    let kind = decode_security_enum::<ConcurrencyKind>(&required_string(body, "kind")?)?;
    match (kind, body.get("max_in_flight")) {
        (ConcurrencyKind::Sequential, Some(JsonValue::Null)) => Ok(ConcurrencyPolicy::Sequential),
        (ConcurrencyKind::BoundedParallel, Some(JsonValue::Integer(ceiling))) => {
            let ceiling = u32::try_from(*ceiling).map_err(|_| BatchApiError::InvalidBody)?;
            ConcurrencyPolicy::bounded_parallel(ceiling).map_err(BatchApiError::Model)
        }
        _ => Err(BatchApiError::InvalidBody),
    }
}

fn batch_id(value: &str) -> Result<BatchId, BatchApiError> {
    BatchId::new(value).map_err(|error| BatchApiError::Field {
        field: "batch_id",
        error,
    })
}

fn member_key(value: &str) -> Result<BatchMemberKey, BatchApiError> {
    BatchMemberKey::new(value).map_err(|error| BatchApiError::Field {
        field: "member_key",
        error,
    })
}

fn optional_label(body: &JsonValue) -> Result<Option<BatchLabel>, BatchApiError> {
    match body.get("label") {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => {
            Ok(Some(BatchLabel::new(value.clone()).map_err(|error| {
                BatchApiError::Field {
                    field: "label",
                    error,
                }
            })?))
        }
        _ => Err(BatchApiError::InvalidBody),
    }
}

/// The page size a listing body declares, judged against this protocol's bound.
fn page_size(body: &JsonValue) -> Result<BatchPageSize, BatchApiError> {
    BatchPageSize::new(usize::try_from(unsigned(body, "page_size")?).map_err(|_| {
        BatchApiError::PageSizeOutOfRange {
            max_items: MAX_BATCH_PAGE_ITEMS,
            requested: MAX_BATCH_PAGE_ITEMS.saturating_add(1),
        }
    })?)
}

fn ordinal(body: &JsonValue) -> Result<u32, BatchApiError> {
    u32::try_from(unsigned(body, "ordinal")?).map_err(|_| BatchApiError::MembersOutOfOrder {
        position: MAX_BATCH_CONTROL_MEMBERS,
    })
}

fn count(body: &JsonValue, field: &'static str) -> Result<usize, BatchApiError> {
    usize::try_from(unsigned(body, field)?).map_err(|_| BatchApiError::MembershipTooLarge {
        max_members: MAX_BATCH_CONTROL_MEMBERS,
        actual_members: MAX_BATCH_CONTROL_MEMBERS.saturating_add(1),
    })
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, BatchApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| BatchApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, BatchApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(BatchApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| BatchApiError::InvalidBody)
}

fn signed(body: &JsonValue, field: &'static str) -> Result<i64, BatchApiError> {
    body.get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(BatchApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, BatchApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(BatchApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), BatchApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(BatchApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(BatchApiError::InvalidBody);
    }
    Ok(())
}
