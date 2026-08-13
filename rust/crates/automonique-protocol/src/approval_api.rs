// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native Approval decision API: record that somebody answered
//! an approval question, and read the answers back.
//!
//! `docs/product-plan/requirements/state-and-protocols.md` § Operator client
//! protocol is the rule every response here obeys — "Responses distinguish
//! `accepted`, `completed`, `rejected`, `conflict`, `unknown` and
//! `resync_required` so a UI cannot mistake transport failure for operation
//! failure" — reused from [`crate::journal::ActionOutcome`] rather than
//! restated, with [`ApprovalResponse::outcome`] saying which four of the six
//! this protocol produces and [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] saying
//! which two it cannot.
//!
//! # What this surface does, stated before what it looks like
//!
//! **It records that a decision was made, by whom, about what, durably, and
//! serves those records back.** That is the whole of it, and the honesty of the
//! slice depends on saying so:
//!
//! - **Nothing here enforces the decision.** A `granted` record permits nothing
//!   that was not already permitted, and a `denied` record stops nothing. **A
//!   recorded approval does not allow any action today, because no executor in
//!   this build consults it**: there is no scheduler, no launcher and no
//!   provider turn that reads a row from this ledger before acting. It is
//!   written now so that a gate, when one lands, reads a durable decision rather
//!   than inventing one.
//! - **Nothing here verifies authority.** [`RecordApproval::decider`] names who
//!   answered and is recorded verbatim. The daemon's `SO_PEERCRED` check is the
//!   authentication; this string is not a capability, exactly as
//!   [`crate::command_registry`] already says of its
//!   `ApprovalPolicy::OperatorConfirmation` — a *client-side* obligation the
//!   daemon cannot observe — and as [`crate::admin::IntakePause`] says of the
//!   intake switch.
//! - **Nothing here binds a decision to a live session.** That binding is
//!   `automonique_store::provider_journal`'s `provider_approvals` table, keyed
//!   on `(session_id, approval_key)` and refused unless that session is open.
//!   This lane is the cross-cutting decision record; that row is the
//!   per-session binding. Neither is the other, and no transaction spans them.
//! - **Nothing here decides which decision governs.** A subject may carry a
//!   grant and, later, a denial. [`ApprovalsBySubject`] returns them in the
//!   order they were recorded and stops there. "The decision in force" is a
//!   policy this protocol deliberately does not spell.
//!
//! # Write-once, so there is no update and no delete
//!
//! `automonique_store::approval_ledger` has exactly one writer and it either
//! inserts a new row or touches nothing at all: an approval that can be edited
//! in place is not evidence of anything. This protocol therefore has
//! [`RecordApproval`] and no second mutation. Reversing a decision is a **new**
//! `approval_key` naming the same subject, and both rows survive.
//!
//! That is also why [`ApprovalRecordView`] carries `revision` and refuses
//! anything but `1`: the durable column is pinned by a database `CHECK`, and a
//! client that decodes a record can therefore see for itself that the row it is
//! reading was never amended.
//!
//! # The three answers a recording can earn, and the conflict's shape
//!
//! The ledger answers three ways, and so does this lane:
//!
//! - the key is new — [`ApprovalResponse::Recorded`] carrying
//!   [`ApprovalDisposition::Recorded`];
//! - the key is present with the same subject, decision and decider — the same
//!   response carrying [`ApprovalDisposition::AlreadyRecorded`], because an
//!   exact replay writes nothing and must never degrade into a refusal;
//! - the key is present with any of those three differing —
//!   [`ApprovalResponse::Conflict`].
//!
//! The conflict is a response arm rather than an [`ApprovalRefusal`] word for
//! the reason [`crate::automation_api`]'s revision conflict is: the plan's
//! vocabulary distinguishes `conflict` from `rejected` precisely because a
//! caller retries the two differently. It carries the coordinates the durable
//! row records, so a caller learns what it collided with without a second read
//! — which is what `ApprovalLedgerError::Conflict` already carries, and which
//! [`ApprovalRequest::ApprovalDetail`] on the same key would return anyway.
//!
//! # The decision vocabulary, and where its authority comes from
//!
//! [`ApprovalDecision`] is two-valued and closed: `granted` and `denied`. There
//! is no `pending` and no `expired` — a decision nobody made has no row.
//!
//! The pin is a literal one, and the gap is named rather than glossed. This
//! crate does not depend on `automonique-store`, so the agreement with the
//! ledger's `CHECK (decision IN ('granted', 'denied'))` is asserted by test
//! rather than derived by the compiler. Of the two words, `denied` is already
//! this crate's own spelling for a refusal —
//! [`crate::sandbox::NetworkAccess::Denied`] and
//! [`crate::connector_conformance::DispositionOutcome::Denied`] both render it —
//! while `granted` appears here first, matching the column
//! `automonique_store::provider_journal` already writes for the same human
//! answer. A disagreement between the two columns would be a bug that only
//! surfaced much later as an unreadable row, so `tests/approval_api.rs` pins
//! both spellings from this side.
//!
//! # Divergences, named rather than approximated
//!
//! - **`resync_required` is unreachable.** The ledger has no prune — forgetting
//!   a `denied` row would let the denied thing be presented again as a fresh,
//!   undecided request — so no cursor can fall out of retention. A cursor above
//!   everything recorded is [`ApprovalRefusal::CursorOutOfRange`], which says
//!   something true, rather than "the rows you wanted are gone", which would
//!   not be.
//! - **Capacity is a refusal, never an eviction.**
//!   [`ApprovalRefusal::LedgerFull`] is the honest consequence of keeping every
//!   decision forever.
//! - **HTTP is absent.** These are protocol values framed by [`crate::codec`]
//!   on the same canonical-JSON envelope [`crate::admin`] uses, under a
//!   separate protocol name so the admin lane's closed kind set stays closed.

use core::fmt;
use std::error::Error;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_security_enum,
};
use crate::journal::ActionOutcome;
use crate::primitives::{EpochMillis, ValueError};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native Approval decision API.
pub const APPROVAL_PROTOCOL: &str = "automonique.approval";

/// Stable schema identifier for the version-one decision surface.
pub const APPROVAL_API_SCHEMA_V1: &str = "automonique.approval/v1";

/// Maximum canonical message bytes this protocol will assemble or admit.
pub const MAX_APPROVAL_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of an approval key, subject or decider.
///
/// The durable identifier grammar this product uses, spelled once in
/// [`crate::automation`] rather than a second time here, and the same bound
/// `automonique_store::approval_ledger::MAX_IDENTIFIER_BYTES` stores these three
/// columns under. A value this protocol admits is a value that ledger holds; the
/// agreement is asserted by test, because this crate does not depend on that one.
pub const MAX_APPROVAL_API_FIELD_BYTES: usize = crate::automation::MAX_AUTOMATION_FIELD_BYTES;

/// Maximum decisions one listing page may carry.
///
/// Thirty-two, for the reason [`crate::automation_api`] serves thirty-two: a
/// decision row carries *three* maximal identifiers where a run summary carries
/// one. The number is derived from the frame arithmetic below and not chosen;
/// see [`RECORD_OVERHEAD_BYTES`].
///
/// Well below `automonique_store::approval_ledger::MAX_APPROVAL_PAGE`, which is
/// five hundred and twelve. The store's ceiling bounds a database read and this
/// one bounds a wire frame, so the smaller of the two is the one a client sees;
/// they are not reconciled and must not be.
///
/// A page bound is not a paging hint. [`ApprovalListPage::new`] refuses a longer
/// vector rather than truncating it, because a truncated page that still answers
/// `complete` is a silent drop.
pub const MAX_APPROVAL_PAGE_ITEMS: usize = 32;

/// The two outcomes this protocol can never report.
///
/// `unknown` names a transport failure, and a transport failure is the *absence*
/// of a message, so no message can carry it. `resync_required` names a cursor
/// outside retention, and nothing is ever removed from the approval ledger — an
/// unrecorded cursor is [`ApprovalRefusal::CursorOutOfRange`] instead, which
/// says something true. A reader that receives one of these on this protocol is
/// reading a response this build did not write.
pub const OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES: [ActionOutcome; 2] =
    [ActionOutcome::Unknown, ActionOutcome::ResyncRequired];

/// Worst-case canonical bytes of one record, excluding its three identifiers.
///
/// The seven quoted key names and their punctuation (92: sixty-three key bytes,
/// twenty-one bytes of quotes and colons, six commas and two braces), three
/// twenty-digit integers (60), the longest quoted decision spelling (9), and the
/// quote pairs around the three string members (6) — one hundred and sixty-seven,
/// rounded up.
const RECORD_OVERHEAD_BYTES: usize = 192;

/// Worst-case canonical bytes of a page scaffold, excluding its items.
const BODY_SCAFFOLD_BYTES: usize = 256;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 480;

/// A bounded field costs at most two canonical bytes per source byte, because a
/// quote or a backslash escapes to two.
const FIELD_ENCODED_BYTES: usize = 2 * MAX_APPROVAL_API_FIELD_BYTES;

/// One record carries three of them: the key, the subject, and the decider.
const RECORD_FIELDS: usize = 3;

const _: () = assert!(
    MAX_APPROVAL_PAGE_ITEMS * (RECORD_FIELDS * FIELD_ENCODED_BYTES + RECORD_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_APPROVAL_CANONICAL_BYTES,
    "a maximal approval listing page must fit one approval frame"
);

const _: () = assert!(
    RECORD_FIELDS * FIELD_ENCODED_BYTES
        + RECORD_OVERHEAD_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_APPROVAL_CANONICAL_BYTES,
    "a maximal approval detail view must fit one approval frame"
);

/// A conflict body carries two maximal identifiers rather than three: the
/// recorded subject and the recorded decider, and never the key, which the
/// caller supplied and already holds.
const _: () = assert!(
    2 * FIELD_ENCODED_BYTES + RECORD_OVERHEAD_BYTES + BODY_SCAFFOLD_BYTES + ENVELOPE_OVERHEAD_BYTES
        <= MAX_APPROVAL_CANONICAL_BYTES,
    "a maximal approval conflict must fit one approval frame"
);

/// A refusal while constructing, encoding or decoding an Approval API value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a decision, disposition or
    /// refusal word this build does not define. Those fail closed rather than
    /// decoding to a default.
    Codec(CodecError),
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
    /// A requested page size was zero or above [`MAX_APPROVAL_PAGE_ITEMS`].
    PageSizeOutOfRange {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Size the caller asked for.
        requested: usize,
    },
    /// A page carried more records than [`MAX_APPROVAL_PAGE_ITEMS`].
    PageTooLarge {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Records the caller supplied.
        actual_items: usize,
    },
    /// A page carried more records than the query it answers asked for.
    PageAboveRequestedSize {
        /// Size the query asked for.
        requested: usize,
        /// Records the page carried.
        actual_items: usize,
    },
    /// A subject listing carried a decision recorded against another subject.
    PageOutsideSubject,
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A write-once row claimed a revision other than one.
    ///
    /// The ledger pins the column to `1` with a database `CHECK` and has no
    /// update path at all, so any other value names a row this product could not
    /// have written.
    RowAmended {
        /// Revision the row claimed.
        revision: u64,
    },
    /// A durable timestamp was before the epoch, which the ledger cannot hold.
    TimeBeforeEpoch {
        /// Field that carried the impossible instant.
        field: &'static str,
    },
    /// A page claimed rows follow without a cursor, or a cursor without rows
    /// following.
    ContinuationIncoherent,
    /// A continuation cursor did not reach the last row on the page.
    ContinuationRewinds,
    /// Page records did not strictly increase by durable row identity.
    PageOutOfOrder,
    /// A conflict named a field on which the presented and recorded decisions
    /// agree, which is a replay rather than a conflict.
    ConflictWithoutDisagreement,
}

impl ApprovalApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "approval_unknown_kind",
            Self::InvalidBody => "approval_invalid_body",
            Self::CounterOutOfRange { .. } => "approval_counter_out_of_range",
            Self::Field { .. } => "approval_invalid_field",
            Self::PageSizeOutOfRange { .. } => "approval_page_size_out_of_range",
            Self::PageTooLarge { .. } => "approval_page_too_large",
            Self::PageAboveRequestedSize { .. } => "approval_page_above_requested_size",
            Self::PageOutsideSubject => "approval_page_outside_subject",
            Self::UnwrittenRow { .. } => "approval_unwritten_row",
            Self::RowAmended { .. } => "approval_row_amended",
            Self::TimeBeforeEpoch { .. } => "approval_time_before_epoch",
            Self::ContinuationIncoherent => "approval_continuation_incoherent",
            Self::ContinuationRewinds => "approval_continuation_rewinds",
            Self::PageOutOfOrder => "approval_page_out_of_order",
            Self::ConflictWithoutDisagreement => "approval_conflict_without_disagreement",
        }
    }
}

impl fmt::Display for ApprovalApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "approval codec refused message: {error}"),
            Self::UnknownKind => formatter.write_str("approval message kind is not defined"),
            Self::InvalidBody => formatter.write_str("approval message body is invalid"),
            Self::CounterOutOfRange { field } => write!(
                formatter,
                "approval counter {field} is outside the wire range"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
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
                "page carries {actual_items} decisions; maximum is {max_items}"
            ),
            Self::PageAboveRequestedSize {
                requested,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} decisions; the query asked for {requested}"
            ),
            Self::PageOutsideSubject => {
                formatter.write_str("a page carries a decision recorded against another subject")
            }
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::RowAmended { revision } => write!(
                formatter,
                "revision {revision} names an amended write-once row"
            ),
            Self::TimeBeforeEpoch { field } => write!(formatter, "{field} is before the epoch"),
            Self::ContinuationIncoherent => {
                formatter.write_str("a page's continuation marker and cursor disagree")
            }
            Self::ContinuationRewinds => {
                formatter.write_str("a continuation cursor does not reach the end of its page")
            }
            Self::PageOutOfOrder => {
                formatter.write_str("page records do not strictly increase by entry")
            }
            Self::ConflictWithoutDisagreement => {
                formatter.write_str("a conflict named a field the two decisions agree on")
            }
        }
    }
}

impl Error for ApprovalApiError {}

impl From<CodecError> for ApprovalApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// What a decider answered.
///
/// Two variants, two spellings, and the set is closed. See the module
/// documentation for exactly where the authority for these two words comes from
/// and where the pin has to be a literal one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalDecision {
    /// The subject was approved.
    Granted,
    /// The subject was refused.
    Denied,
}

impl ApprovalDecision {
    /// Both decisions. The set is closed: there is no third.
    pub const ALL: [Self; 2] = [Self::Granted, Self::Denied];

    /// Stable lowercase wire spelling, and the exact text the ledger stores.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|decision| decision.as_str() == value)
    }

    /// Whether this decision was an approval.
    ///
    /// As weak a claim as the row it comes from: it says somebody was recorded
    /// as approving the subject, never that the subject was permitted to happen.
    /// Nothing in this build gates on it.
    #[must_use]
    pub const fn grants(self) -> bool {
        matches!(self, Self::Granted)
    }
}

impl fmt::Display for ApprovalDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ApprovalDecision {
    const FIELD: &'static str = "decision";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Decode a decision spelling, failing closed on an unknown one.
///
/// One authority: this is [`ApprovalDecision::from_spelling`] behind the shared
/// fail-closed decoder, so a caller judging an operator's word and a decoder
/// judging a frame cannot disagree about which two words exist.
///
/// # Errors
///
/// Returns [`CodecError::UnknownEnumValue`] for a spelling this build does not
/// define.
pub fn decode_decision(value: &str) -> Result<ApprovalDecision, ApprovalApiError> {
    Ok(decode_security_enum::<ApprovalDecision>(value)?)
}

/// Whether a recording wrote its row or found it already there.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalDisposition {
    /// The decision was new and is now durable.
    Recorded,
    /// The exact decision was already durable. Nothing changed.
    AlreadyRecorded,
}

impl ApprovalDisposition {
    /// Both dispositions, in canonical order.
    pub const ALL: [Self; 2] = [Self::Recorded, Self::AlreadyRecorded];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|disposition| disposition.as_str() == value)
    }

    /// Whether this call is the one that wrote the row.
    #[must_use]
    pub const fn wrote(self) -> bool {
        matches!(self, Self::Recorded)
    }
}

impl fmt::Display for ApprovalDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ApprovalDisposition {
    const FIELD: &'static str = "disposition";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Which of a recording's three identity fields a conflict is about.
///
/// The ledger compares subject, decision and decider in that order and reports
/// the first difference, so a conflict names one field rather than a set. The
/// order is a property of that comparison and is mirrored here by
/// [`ApprovalResponse::conflict`], which *derives* the field rather than
/// accepting a caller's claim about it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConflictField {
    /// The key was recorded describing something else.
    Subject,
    /// The key was recorded with the other answer.
    Decision,
    /// The key was recorded as answered by somebody else.
    Decider,
}

impl ConflictField {
    /// Every field, in the order the ledger compares them.
    pub const ALL: [Self; 3] = [Self::Subject, Self::Decision, Self::Decider];

    /// Stable lowercase wire spelling, and the ledger's own field name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Decision => "decision",
            Self::Decider => "decider",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == value)
    }
}

impl fmt::Display for ConflictField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ConflictField {
    const FIELD: &'static str = "field";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// The durable idempotency identity of one decision, unique host-wide.
///
/// Non-empty, at most [`MAX_APPROVAL_API_FIELD_BYTES`], and control-free:
/// exactly the grammar `automonique_store::approval_ledger` stores under, so
/// this type admits every key that ledger can hold and no more.
///
/// It is opaque. This protocol never parses it, derives nothing from it and
/// gives it no structure — two keys are the same decision or they are not.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalKey(String);

impl ApprovalKey {
    /// Longest key this protocol carries.
    pub const MAX_BYTES: usize = MAX_APPROVAL_API_FIELD_BYTES;

    /// Validate and construct a key.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ApprovalApiError> {
        let value = value.as_ref();
        bounded(value, "approval_key")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApprovalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A bounded *name* for what was decided.
///
/// A command identifier, an effect name, a digest — never the thing itself.
/// Anything larger has to be named by a digest recorded elsewhere, which is the
/// same trade the durable ledger makes and the reason it stores a subject beside
/// the key at all: an approval whose only description is an opaque key answers
/// "was this decided" and never "what was decided".
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalSubject(String);

impl ApprovalSubject {
    /// Longest subject this protocol carries.
    pub const MAX_BYTES: usize = MAX_APPROVAL_API_FIELD_BYTES;

    /// Validate and construct a subject.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ApprovalApiError> {
        let value = value.as_ref();
        bounded(value, "subject")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated subject.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApprovalSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Who answered.
///
/// Recorded, never verified. This module cannot tell an operator from a runbook
/// from a typo, and does not claim to: the local transport establishes that the
/// peer is this user, and this string says which person or runbook behind that
/// user made the call. It is worth recording for exactly that reason and no
/// stronger one.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Decider(String);

impl Decider {
    /// Longest decider this protocol carries.
    pub const MAX_BYTES: usize = MAX_APPROVAL_API_FIELD_BYTES;

    /// Validate and construct a decider.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::Field`] for an empty, over-long or
    /// control-bearing value. Empty is refused rather than read as "nobody":
    /// an unattributed decision is the one this product does not offer a
    /// spelling for.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ApprovalApiError> {
        let value = value.as_ref();
        bounded(value, "decider")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated decider.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Decider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A durable listing position: the entry a listing resumes *after*.
///
/// Zero starts at the beginning. This is the ledger's own exclusive cursor
/// rather than a translated one — it pages by `entry_id` and reports the last
/// one it served — so no coordinate is converted between the wire and the table
/// and there is no off-by-one to re-derive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalCursor(u64);

impl ApprovalCursor {
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

/// How many records one listing asks for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalPageSize(usize);

impl ApprovalPageSize {
    /// The largest page this protocol serves.
    pub const MAX: Self = Self(MAX_APPROVAL_PAGE_ITEMS);

    /// Ask for a bounded number of records.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::PageSizeOutOfRange`] for zero — a page that
    /// admits nothing cannot make progress — or for a size above
    /// [`MAX_APPROVAL_PAGE_ITEMS`].
    pub const fn new(items: usize) -> Result<Self, ApprovalApiError> {
        if items == 0 || items > MAX_APPROVAL_PAGE_ITEMS {
            return Err(ApprovalApiError::PageSizeOutOfRange {
                max_items: MAX_APPROVAL_PAGE_ITEMS,
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

/// One approval decision presented for durable recording.
///
/// There is no timestamp field, and its absence is deliberate: the daemon stamps
/// the instant from its own clock, exactly as it does for an automation
/// transition. A caller-supplied instant on the wire would let a client date a
/// decision to whenever it liked, and the durable row is the evidence.
///
/// This is the only mutation on this protocol. There is no update and no delete,
/// because the ledger has neither; see the module documentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordApproval {
    approval_key: ApprovalKey,
    subject: ApprovalSubject,
    decision: ApprovalDecision,
    decider: Decider,
}

impl RecordApproval {
    /// Present one decision.
    #[must_use]
    pub const fn new(
        approval_key: ApprovalKey,
        subject: ApprovalSubject,
        decision: ApprovalDecision,
        decider: Decider,
    ) -> Self {
        Self {
            approval_key,
            subject,
            decision,
            decider,
        }
    }

    /// The idempotency identity this decision is recorded under.
    #[must_use]
    pub const fn approval_key(&self) -> &ApprovalKey {
        &self.approval_key
    }

    /// What was decided.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// What was answered.
    #[must_use]
    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }

    /// Who answered. Recorded, never verified.
    #[must_use]
    pub const fn decider(&self) -> &Decider {
        &self.decider
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "approval_key".to_owned(),
                JsonValue::String(self.approval_key.as_str().to_owned()),
            ),
            (
                "decider".to_owned(),
                JsonValue::String(self.decider.as_str().to_owned()),
            ),
            (
                "decision".to_owned(),
                JsonValue::String(self.decision.as_str().to_owned()),
            ),
            (
                "subject".to_owned(),
                JsonValue::String(self.subject.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(body, &["approval_key", "decider", "decision", "subject"])?;
        Ok(Self::new(
            ApprovalKey::new(required_string(body, "approval_key")?)?,
            ApprovalSubject::new(required_string(body, "subject")?)?,
            decode_decision(&required_string(body, "decision")?)?,
            Decider::new(required_string(body, "decider")?)?,
        ))
    }
}

/// A bounded request for one page of every recorded decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListApprovals {
    since: ApprovalCursor,
    page_size: ApprovalPageSize,
}

impl ListApprovals {
    /// Ask for one page.
    #[must_use]
    pub const fn new(since: ApprovalCursor, page_size: ApprovalPageSize) -> Self {
        Self { since, page_size }
    }

    /// The entry this listing resumes after.
    #[must_use]
    pub const fn since(self) -> ApprovalCursor {
        self.since
    }

    /// How many records this listing asks for.
    #[must_use]
    pub const fn page_size(self) -> ApprovalPageSize {
        self.page_size
    }

    fn to_body(self) -> Result<JsonValue, ApprovalApiError> {
        Ok(JsonValue::Object(vec![
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            ("since".to_owned(), integer("since", self.since.position())?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(body, &["page_size", "since"])?;
        Ok(Self::new(
            ApprovalCursor::new(unsigned(body, "since")?),
            page_size(body)?,
        ))
    }
}

/// A bounded request for the decisions recorded against one subject.
///
/// This is a subject's decision history: a grant and the later denial that
/// reconsidered it are two records here, in the order they were recorded. Which
/// of them governs is not this protocol's answer.
///
/// The cursor is a position in the whole listing rather than in the matching
/// subset, exactly as the ledger judges it: a filter that excluded the row a
/// cursor names must not turn a resumable cursor into a refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalsBySubject {
    subject: ApprovalSubject,
    since: ApprovalCursor,
    page_size: ApprovalPageSize,
}

impl ApprovalsBySubject {
    /// Ask for one page of one subject's decisions.
    #[must_use]
    pub const fn new(
        subject: ApprovalSubject,
        since: ApprovalCursor,
        page_size: ApprovalPageSize,
    ) -> Self {
        Self {
            subject,
            since,
            page_size,
        }
    }

    /// The subject whose decisions are asked for.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// The entry this listing resumes after.
    #[must_use]
    pub const fn since(&self) -> ApprovalCursor {
        self.since
    }

    /// How many records this listing asks for.
    #[must_use]
    pub const fn page_size(&self) -> ApprovalPageSize {
        self.page_size
    }

    fn to_body(&self) -> Result<JsonValue, ApprovalApiError> {
        Ok(JsonValue::Object(vec![
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            ("since".to_owned(), integer("since", self.since.position())?),
            (
                "subject".to_owned(),
                JsonValue::String(self.subject.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(body, &["page_size", "since", "subject"])?;
        Ok(Self::new(
            ApprovalSubject::new(required_string(body, "subject")?)?,
            ApprovalCursor::new(unsigned(body, "since")?),
            page_size(body)?,
        ))
    }
}

/// What one recording established, and whether this call is what established it.
///
/// This is `automonique_store::approval_ledger::ApprovalReceipt` on the wire,
/// plus the key it is about — the store's receipt omits it because its caller
/// supplied it, and a correlated answer travelling on its own cannot rely on
/// that.
///
/// There is no `revision` here, and its absence is deliberate: a caller has
/// nothing to fence against, because no second write to this row exists. The
/// stored column is reported on [`ApprovalRecordView`], where a reader can see
/// that it is one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalReceiptView {
    entry_id: u64,
    approval_key: ApprovalKey,
    decision: ApprovalDecision,
    disposition: ApprovalDisposition,
    decided_at: EpochMillis,
}

impl ApprovalReceiptView {
    /// Record what one accepted recording established.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::UnwrittenRow`] for a zero `entry_id` and
    /// [`ApprovalApiError::TimeBeforeEpoch`] for an instant the ledger's
    /// `decided_at_ms >= 0` constraint cannot hold.
    pub fn new(
        entry_id: u64,
        approval_key: ApprovalKey,
        decision: ApprovalDecision,
        disposition: ApprovalDisposition,
        decided_at: EpochMillis,
    ) -> Result<Self, ApprovalApiError> {
        if entry_id == 0 {
            return Err(ApprovalApiError::UnwrittenRow { field: "entry_id" });
        }
        if decided_at.as_millis() < 0 {
            return Err(ApprovalApiError::TimeBeforeEpoch {
                field: "decided_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            approval_key,
            decision,
            disposition,
            decided_at,
        })
    }

    /// Row identity, monotonic in recording order. The pagination key.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// The key this receipt is about.
    #[must_use]
    pub const fn approval_key(&self) -> &ApprovalKey {
        &self.approval_key
    }

    /// The decision the durable row records.
    #[must_use]
    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }

    /// Whether this call wrote the row or found it.
    #[must_use]
    pub const fn disposition(&self) -> ApprovalDisposition {
        self.disposition
    }

    /// The instant the durable row records.
    ///
    /// On an [`ApprovalDisposition::AlreadyRecorded`] answer this is the *first*
    /// recording's instant, not this call's. A replay writes nothing, including
    /// the clock.
    #[must_use]
    pub const fn decided_at(&self) -> EpochMillis {
        self.decided_at
    }

    fn to_body(&self) -> Result<JsonValue, ApprovalApiError> {
        Ok(JsonValue::Object(vec![
            (
                "approval_key".to_owned(),
                JsonValue::String(self.approval_key.as_str().to_owned()),
            ),
            (
                "decided_at_ms".to_owned(),
                JsonValue::Integer(self.decided_at.as_millis()),
            ),
            (
                "decision".to_owned(),
                JsonValue::String(self.decision.as_str().to_owned()),
            ),
            (
                "disposition".to_owned(),
                JsonValue::String(self.disposition.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(
            body,
            &[
                "approval_key",
                "decided_at_ms",
                "decision",
                "disposition",
                "entry_id",
            ],
        )?;
        Self::new(
            unsigned(body, "entry_id")?,
            ApprovalKey::new(required_string(body, "approval_key")?)?,
            decode_decision(&required_string(body, "decision")?)?,
            decode_security_enum::<ApprovalDisposition>(&required_string(body, "disposition")?)?,
            EpochMillis::from_millis(signed(body, "decided_at_ms")?),
        )
    }
}

/// One validated `approval_decisions` row, as a listing or a detail read reports
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRecordView {
    entry_id: u64,
    approval_key: ApprovalKey,
    subject: ApprovalSubject,
    decision: ApprovalDecision,
    decider: Decider,
    decided_at: EpochMillis,
    revision: u64,
}

impl ApprovalRecordView {
    /// Record one decision, refusing every row this product could not have
    /// written.
    ///
    /// The two cross-column invariants the ledger re-derives on every read are
    /// re-derived here, because a wire value is read by clients the ledger never
    /// sees: the row identity is written, and the revision is one — anything
    /// else names a row amended by a second writer, and a reader must not
    /// silently accept it as an amended decision.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::UnwrittenRow`],
    /// [`ApprovalApiError::RowAmended`] or
    /// [`ApprovalApiError::TimeBeforeEpoch`].
    pub fn new(parts: ApprovalRecordParts) -> Result<Self, ApprovalApiError> {
        let ApprovalRecordParts {
            entry_id,
            approval_key,
            subject,
            decision,
            decider,
            decided_at,
            revision,
        } = parts;
        if entry_id == 0 {
            return Err(ApprovalApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision != 1 {
            return Err(ApprovalApiError::RowAmended { revision });
        }
        if decided_at.as_millis() < 0 {
            return Err(ApprovalApiError::TimeBeforeEpoch {
                field: "decided_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            approval_key,
            subject,
            decision,
            decider,
            decided_at,
            revision,
        })
    }

    /// Row identity, monotonic in recording order.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// Durable idempotency identity.
    #[must_use]
    pub const fn approval_key(&self) -> &ApprovalKey {
        &self.approval_key
    }

    /// What was decided.
    #[must_use]
    pub const fn subject(&self) -> &ApprovalSubject {
        &self.subject
    }

    /// What was answered.
    #[must_use]
    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }

    /// Who was recorded as answering.
    #[must_use]
    pub const fn decider(&self) -> &Decider {
        &self.decider
    }

    /// When the decision was recorded as made.
    #[must_use]
    pub const fn decided_at(&self) -> EpochMillis {
        self.decided_at
    }

    /// Always `1`. Write-once rows have no second revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether the recorded decision was an approval.
    ///
    /// See [`ApprovalDecision::grants`] for how little that establishes: nothing
    /// in this build reads it before acting.
    #[must_use]
    pub const fn grants(&self) -> bool {
        self.decision.grants()
    }

    fn to_body(&self) -> Result<JsonValue, ApprovalApiError> {
        Ok(JsonValue::Object(vec![
            (
                "approval_key".to_owned(),
                JsonValue::String(self.approval_key.as_str().to_owned()),
            ),
            (
                "decided_at_ms".to_owned(),
                JsonValue::Integer(self.decided_at.as_millis()),
            ),
            (
                "decider".to_owned(),
                JsonValue::String(self.decider.as_str().to_owned()),
            ),
            (
                "decision".to_owned(),
                JsonValue::String(self.decision.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "subject".to_owned(),
                JsonValue::String(self.subject.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(
            body,
            &[
                "approval_key",
                "decided_at_ms",
                "decider",
                "decision",
                "entry_id",
                "revision",
                "subject",
            ],
        )?;
        Self::new(ApprovalRecordParts {
            entry_id: unsigned(body, "entry_id")?,
            approval_key: ApprovalKey::new(required_string(body, "approval_key")?)?,
            subject: ApprovalSubject::new(required_string(body, "subject")?)?,
            decision: decode_decision(&required_string(body, "decision")?)?,
            decider: Decider::new(required_string(body, "decider")?)?,
            decided_at: EpochMillis::from_millis(signed(body, "decided_at_ms")?),
            revision: unsigned(body, "revision")?,
        })
    }
}

/// The seven columns one decision row carries.
///
/// A parameter object rather than seven positional arguments: three bounded
/// strings sit beside one another, and a transposed pair would type-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRecordParts {
    /// Row identity, monotonic in recording order.
    pub entry_id: u64,
    /// Durable idempotency identity.
    pub approval_key: ApprovalKey,
    /// What was decided.
    pub subject: ApprovalSubject,
    /// What was answered.
    pub decision: ApprovalDecision,
    /// Who was recorded as answering.
    pub decider: Decider,
    /// When the decision was recorded as made.
    pub decided_at: EpochMillis,
    /// Always `1`; anything else is a row a second writer produced.
    pub revision: u64,
}

/// The coordinates a durable row records, as a conflict reports them.
///
/// The key is deliberately absent: a conflict answers a recording that named it,
/// so the caller already holds it, and repeating it would be an echo rather than
/// information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedApproval {
    /// Row the durable decision occupies.
    pub entry_id: u64,
    /// Subject the durable row records.
    pub subject: ApprovalSubject,
    /// Decision the durable row records.
    pub decision: ApprovalDecision,
    /// Decider the durable row records.
    pub decider: Decider,
}

/// Whether a page is the end of the listing.
///
/// Closed, and carried explicitly rather than inferred from `entries.len() <
/// page_size`. A short page is not the same statement as a last page: a subject
/// filter can exclude every row in a scanned window and still leave rows behind
/// it, and a client that inferred "done" from a short page would stop early.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalContinuation {
    /// More rows may follow; resume after this cursor.
    More(ApprovalCursor),
    /// The listing reached the end of the ledger.
    Complete,
}

impl ApprovalContinuation {
    /// The cursor to resume after, when there is one.
    #[must_use]
    pub const fn cursor(self) -> Option<ApprovalCursor> {
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

/// One bounded page of decision records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalListPage {
    entries: Vec<ApprovalRecordView>,
    continuation: ApprovalContinuation,
}

impl ApprovalListPage {
    /// Assemble a page.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::PageTooLarge`] above
    /// [`MAX_APPROVAL_PAGE_ITEMS`], [`ApprovalApiError::PageOutOfOrder`] when
    /// records do not strictly increase by `entry_id` — a listing is ordered by
    /// that identity, and a repeat or a step backwards means the next page would
    /// re-serve or skip — and [`ApprovalApiError::ContinuationRewinds`] when a
    /// continuation cursor does not reach the last row on the page.
    ///
    /// An empty page carrying [`ApprovalContinuation::More`] is accepted: a
    /// subject filter may exclude every row in one scanned window while rows
    /// remain behind it.
    pub fn new(
        entries: Vec<ApprovalRecordView>,
        continuation: ApprovalContinuation,
    ) -> Result<Self, ApprovalApiError> {
        if entries.len() > MAX_APPROVAL_PAGE_ITEMS {
            return Err(ApprovalApiError::PageTooLarge {
                max_items: MAX_APPROVAL_PAGE_ITEMS,
                actual_items: entries.len(),
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[1].entry_id() <= pair[0].entry_id())
        {
            return Err(ApprovalApiError::PageOutOfOrder);
        }
        if let (Some(cursor), Some(last)) = (continuation.cursor(), entries.last())
            && cursor.position() < last.entry_id()
        {
            return Err(ApprovalApiError::ContinuationRewinds);
        }
        Ok(Self {
            entries,
            continuation,
        })
    }

    /// The records, in recording order.
    #[must_use]
    pub fn entries(&self) -> &[ApprovalRecordView] {
        &self.entries
    }

    /// Whether more rows may follow, and from where.
    #[must_use]
    pub const fn continuation(&self) -> ApprovalContinuation {
        self.continuation
    }

    fn to_body(&self) -> Result<JsonValue, ApprovalApiError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for record in &self.entries {
            entries.push(record.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            ("approvals".to_owned(), JsonValue::Array(entries)),
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

    fn from_body(body: &JsonValue) -> Result<Self, ApprovalApiError> {
        exact_fields(body, &["approvals", "more", "next_cursor"])?;
        let more = match body.get("more") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(ApprovalApiError::InvalidBody),
        };
        let continuation = match (more, body.get("next_cursor")) {
            (true, Some(JsonValue::Integer(_))) => {
                ApprovalContinuation::More(ApprovalCursor::new(unsigned(body, "next_cursor")?))
            }
            (false, Some(JsonValue::Null)) => ApprovalContinuation::Complete,
            (true, Some(JsonValue::Null)) | (false, Some(JsonValue::Integer(_))) => {
                return Err(ApprovalApiError::ContinuationIncoherent);
            }
            _ => return Err(ApprovalApiError::InvalidBody),
        };
        let JsonValue::Array(items) = body.get("approvals").ok_or(ApprovalApiError::InvalidBody)?
        else {
            return Err(ApprovalApiError::InvalidBody);
        };
        if items.len() > MAX_APPROVAL_PAGE_ITEMS {
            return Err(ApprovalApiError::PageTooLarge {
                max_items: MAX_APPROVAL_PAGE_ITEMS,
                actual_items: items.len(),
            });
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            entries.push(ApprovalRecordView::from_body(item)?);
        }
        Self::new(entries, continuation)
    }
}

/// Why an approval operation was refused.
///
/// Closed, and every variant is one word. A refusal carries no field name, no
/// stored text and no echo of the caller's payload: a refusal category is a
/// metric label and an operator-facing word, not a diagnostic channel for the
/// bytes that were sent.
///
/// A key recorded with a different answer is deliberately *not* here. It is
/// [`ApprovalResponse::Conflict`], which the plan's vocabulary distinguishes
/// from a rejection precisely because a caller retries the two differently — and
/// a conflicting reuse must never be retried at all, because the ledger has no
/// update path and a genuinely changed decision is a new key.
///
/// There is no `already_recorded` refusal either: an exact replay is a
/// *success*, [`ApprovalResponse::Recorded`] carrying
/// [`ApprovalDisposition::AlreadyRecorded`]. A caller that lost the answer to
/// its first recording and retries it gets the first answer back.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalRefusal {
    /// No decision is recorded under that key.
    ///
    /// This is not "the subject behind the key was refused". An unrecorded
    /// decision and a `denied` one are different answers, and this protocol only
    /// ever makes the true one.
    UnknownApproval,
    /// A page was requested from a cursor above everything recorded.
    CursorOutOfRange,
    /// The ledger holds its full capacity of decisions.
    ///
    /// Recording is refused rather than evicting an older decision, and there is
    /// no prune to make room: forgetting a `denied` row would let the denied
    /// thing be presented again as a fresh, undecided request. An exact replay
    /// is unaffected, because a replay writes nothing.
    LedgerFull,
    /// A supplied field was outside the durable ledger's grammar.
    InvalidField,
}

impl ApprovalRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 4] = [
        Self::UnknownApproval,
        Self::CursorOutOfRange,
        Self::LedgerFull,
        Self::InvalidField,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownApproval => "unknown_approval",
            Self::CursorOutOfRange => "cursor_out_of_range",
            Self::LedgerFull => "ledger_full",
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

impl fmt::Display for ApprovalRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ApprovalRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated request on the Approval decision API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalRequest {
    /// Record one decision, write-once. The only mutation this protocol has.
    RecordApproval {
        /// Correlation identifier.
        request_id: RequestId,
        /// The decision to record.
        decision: RecordApproval,
    },
    /// One bounded page of every decision.
    ListApprovals {
        /// Correlation identifier.
        request_id: RequestId,
        /// Cursor and page size.
        query: ListApprovals,
    },
    /// One decision in full.
    ApprovalDetail {
        /// Correlation identifier.
        request_id: RequestId,
        /// Key to read.
        approval_key: ApprovalKey,
    },
    /// One bounded page of one subject's decisions.
    ApprovalsBySubject {
        /// Correlation identifier.
        request_id: RequestId,
        /// Subject, cursor and page size.
        query: ApprovalsBySubject,
    },
}

impl ApprovalRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::RecordApproval { request_id, .. }
            | Self::ListApprovals { request_id, .. }
            | Self::ApprovalDetail { request_id, .. }
            | Self::ApprovalsBySubject { request_id, .. } => request_id,
        }
    }

    /// Whether this request would change durable state.
    ///
    /// Reads and the one write travel the same lane, and the daemon fences both
    /// the same way, so this exists for callers that log or meter the difference
    /// rather than for anything that decides it.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(self, Self::RecordApproval { .. })
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, ApprovalApiError> {
        match self {
            Self::RecordApproval {
                request_id,
                decision,
            } => Ok(Message::new(
                envelope(request_id.clone(), "record_approval")?,
                decision.to_body(),
            )),
            Self::ListApprovals { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "list_approvals")?,
                query.to_body()?,
            )),
            Self::ApprovalDetail {
                request_id,
                approval_key,
            } => Ok(Message::new(
                envelope(request_id.clone(), "approval_detail")?,
                JsonValue::Object(vec![(
                    "approval_key".to_owned(),
                    JsonValue::String(approval_key.as_str().to_owned()),
                )]),
            )),
            Self::ApprovalsBySubject { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "approvals_by_subject")?,
                query.to_body()?,
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ApprovalApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "record_approval" => Ok(Self::RecordApproval {
                request_id,
                decision: RecordApproval::from_body(message.body())?,
            }),
            "list_approvals" => Ok(Self::ListApprovals {
                request_id,
                query: ListApprovals::from_body(message.body())?,
            }),
            "approval_detail" => {
                exact_fields(message.body(), &["approval_key"])?;
                Ok(Self::ApprovalDetail {
                    request_id,
                    approval_key: ApprovalKey::new(required_string(
                        message.body(),
                        "approval_key",
                    )?)?,
                })
            }
            "approvals_by_subject" => Ok(Self::ApprovalsBySubject {
                request_id,
                query: ApprovalsBySubject::from_body(message.body())?,
            }),
            _ => Err(ApprovalApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the Approval decision API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalResponse {
    /// One decision is durable. The receipt says whether this call wrote it.
    Recorded {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the durable row holds.
        receipt: ApprovalReceiptView,
    },
    /// One page of decisions.
    ApprovalList {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The page.
        page: ApprovalListPage,
    },
    /// One decision in full.
    ApprovalDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The record.
        record: ApprovalRecordView,
    },
    /// The key is recorded with a different decision. Nothing was written, and
    /// nothing ever will be for this key.
    Conflict {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// First of subject, decision and decider that differs.
        field: ConflictField,
        /// What the durable row records.
        recorded: RecordedApproval,
    },
    /// The operation was refused. Nothing was written and nothing was read.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: ApprovalRefusal,
    },
}

impl ApprovalResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Recorded { request_id, .. }
            | Self::ApprovalList { request_id, .. }
            | Self::ApprovalDetail { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A delivered read is `completed`: there is no later completion to wait
    /// for. A durable decision is `accepted` rather than `completed`, on a fresh
    /// recording and on a replay alike, and the distinction is the honest one —
    /// the row *is* committed, but what the row records has not taken effect and
    /// cannot: no executor consults it. `accepted` says "recorded"; `completed`
    /// would say the decision took effect, which would be a claim about a
    /// component this release does not contain.
    ///
    /// See [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] for the two this protocol
    /// cannot produce and why.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Recorded { .. } => ActionOutcome::Accepted,
            Self::ApprovalList { .. } | Self::ApprovalDetail { .. } => ActionOutcome::Completed,
            Self::Conflict { .. } => ActionOutcome::Conflict,
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Build the answer to a whole-ledger listing from the rows a store
    /// produced.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::PageAboveRequestedSize`] for a page longer
    /// than the query asked for, which would look perfectly well-formed to a
    /// client and would silently contradict the question it asked.
    pub fn listing(
        request_id: RequestId,
        query: ListApprovals,
        page: ApprovalListPage,
    ) -> Result<Self, ApprovalApiError> {
        if page.entries().len() > query.page_size().get() {
            return Err(ApprovalApiError::PageAboveRequestedSize {
                requested: query.page_size().get(),
                actual_items: page.entries().len(),
            });
        }
        Ok(Self::ApprovalList { request_id, page })
    }

    /// Build the answer to a subject listing from the rows a store produced.
    ///
    /// This is the enforcement the module exists for: a page longer than the
    /// query asked for, or carrying a decision recorded against a *different*
    /// subject, is refused here rather than served.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::PageAboveRequestedSize`] or
    /// [`ApprovalApiError::PageOutsideSubject`].
    pub fn subject_listing(
        request_id: RequestId,
        query: &ApprovalsBySubject,
        page: ApprovalListPage,
    ) -> Result<Self, ApprovalApiError> {
        if page.entries().len() > query.page_size().get() {
            return Err(ApprovalApiError::PageAboveRequestedSize {
                requested: query.page_size().get(),
                actual_items: page.entries().len(),
            });
        }
        if page
            .entries()
            .iter()
            .any(|record| record.subject() != query.subject())
        {
            return Err(ApprovalApiError::PageOutsideSubject);
        }
        Ok(Self::ApprovalList { request_id, page })
    }

    /// Report a key recorded with a different decision.
    ///
    /// The differing field is **derived** here rather than asserted by the
    /// caller: the three identity fields are compared in the order the ledger
    /// compares them and the first difference is the one reported, so this
    /// answer cannot name a field the two decisions agree on. That is a stronger
    /// guarantee than [`crate::automation_api`]'s revision conflict can offer,
    /// and it is available because both sides are in hand at the answering end.
    ///
    /// The decoder cannot re-derive it, because a conflict carries only the
    /// recorded side — repeating the caller's own payload back would be an echo
    /// rather than information. [`ApprovalResponse::from_canonical_bytes`]
    /// therefore validates what a decoder can: a closed field spelling, a
    /// written row identity, and bounded coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalApiError::UnwrittenRow`] for a zero `entry_id` and
    /// [`ApprovalApiError::ConflictWithoutDisagreement`] when the presented and
    /// recorded decisions agree on all three fields — which is an exact replay,
    /// and answering a conflict would tell a caller its decision collided with
    /// itself.
    pub fn conflict(
        request_id: RequestId,
        presented: &RecordApproval,
        recorded: RecordedApproval,
    ) -> Result<Self, ApprovalApiError> {
        if recorded.entry_id == 0 {
            return Err(ApprovalApiError::UnwrittenRow { field: "entry_id" });
        }
        let field = if recorded.subject != *presented.subject() {
            ConflictField::Subject
        } else if recorded.decision != presented.decision() {
            ConflictField::Decision
        } else if recorded.decider != *presented.decider() {
            ConflictField::Decider
        } else {
            return Err(ApprovalApiError::ConflictWithoutDisagreement);
        };
        Ok(Self::Conflict {
            request_id,
            field,
            recorded,
        })
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, ApprovalApiError> {
        match self {
            Self::Recorded {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "approval_recorded")?,
                receipt.to_body()?,
            )),
            Self::ApprovalList { request_id, page } => Ok(Message::new(
                envelope(request_id.clone(), "approval_list_result")?,
                page.to_body()?,
            )),
            Self::ApprovalDetail { request_id, record } => Ok(Message::new(
                envelope(request_id.clone(), "approval_detail_result")?,
                record.to_body()?,
            )),
            Self::Conflict {
                request_id,
                field,
                recorded,
            } => Ok(Message::new(
                envelope(request_id.clone(), "approval_conflict")?,
                JsonValue::Object(vec![
                    (
                        "entry_id".to_owned(),
                        integer("entry_id", recorded.entry_id)?,
                    ),
                    (
                        "field".to_owned(),
                        JsonValue::String(field.as_str().to_owned()),
                    ),
                    (
                        "recorded_decider".to_owned(),
                        JsonValue::String(recorded.decider.as_str().to_owned()),
                    ),
                    (
                        "recorded_decision".to_owned(),
                        JsonValue::String(recorded.decision.as_str().to_owned()),
                    ),
                    (
                        "recorded_subject".to_owned(),
                        JsonValue::String(recorded.subject.as_str().to_owned()),
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
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ApprovalApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "approval_recorded" => Ok(Self::Recorded {
                request_id,
                receipt: ApprovalReceiptView::from_body(message.body())?,
            }),
            "approval_list_result" => Ok(Self::ApprovalList {
                request_id,
                page: ApprovalListPage::from_body(message.body())?,
            }),
            "approval_detail_result" => Ok(Self::ApprovalDetail {
                request_id,
                record: ApprovalRecordView::from_body(message.body())?,
            }),
            "approval_conflict" => {
                exact_fields(
                    message.body(),
                    &[
                        "entry_id",
                        "field",
                        "recorded_decider",
                        "recorded_decision",
                        "recorded_subject",
                    ],
                )?;
                let entry_id = unsigned(message.body(), "entry_id")?;
                if entry_id == 0 {
                    return Err(ApprovalApiError::UnwrittenRow { field: "entry_id" });
                }
                Ok(Self::Conflict {
                    request_id,
                    field: decode_security_enum::<ConflictField>(&required_string(
                        message.body(),
                        "field",
                    )?)?,
                    recorded: RecordedApproval {
                        entry_id,
                        subject: ApprovalSubject::new(required_string(
                            message.body(),
                            "recorded_subject",
                        )?)?,
                        decision: decode_decision(&required_string(
                            message.body(),
                            "recorded_decision",
                        )?)?,
                        decider: Decider::new(required_string(
                            message.body(),
                            "recorded_decider",
                        )?)?,
                    },
                })
            }
            "refused" => {
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<ApprovalRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(ApprovalApiError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, ApprovalApiError> {
    Ok(Envelope::new(
        ProtocolName::new(APPROVAL_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, ApprovalApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(APPROVAL_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

fn bounded(value: &str, field: &'static str) -> Result<(), ApprovalApiError> {
    let error = if value.is_empty() {
        ValueError::Empty
    } else if value.len() > MAX_APPROVAL_API_FIELD_BYTES {
        ValueError::TooLong {
            max_bytes: MAX_APPROVAL_API_FIELD_BYTES,
            actual_bytes: value.len(),
        }
    } else if value.chars().any(char::is_control) {
        ValueError::ControlCharacter
    } else {
        return Ok(());
    };
    Err(ApprovalApiError::Field { field, error })
}

/// The page size a listing body declares, judged against this protocol's bound.
///
/// Shared by both listing decoders so the two cannot disagree about the range.
fn page_size(body: &JsonValue) -> Result<ApprovalPageSize, ApprovalApiError> {
    ApprovalPageSize::new(usize::try_from(unsigned(body, "page_size")?).map_err(|_| {
        ApprovalApiError::PageSizeOutOfRange {
            max_items: MAX_APPROVAL_PAGE_ITEMS,
            requested: MAX_APPROVAL_PAGE_ITEMS.saturating_add(1),
        }
    })?)
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, ApprovalApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| ApprovalApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, ApprovalApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ApprovalApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| ApprovalApiError::InvalidBody)
}

fn signed(body: &JsonValue, field: &'static str) -> Result<i64, ApprovalApiError> {
    body.get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ApprovalApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, ApprovalApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(ApprovalApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), ApprovalApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(ApprovalApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(ApprovalApiError::InvalidBody);
    }
    Ok(())
}
