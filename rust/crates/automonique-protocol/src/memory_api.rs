// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native workspace-memory control protocol: record that a
//! memory item was captured under a workspace, correct one with another, and
//! read the records back.
//!
//! `docs/product-plan/requirements/context-memory-and-learning.md` describes
//! "typed, tenant-scoped stores" whose writes are "revisioned proposals" and
//! whose corrections "supersede", and `automonique_store::context_memory` is the
//! durable half of one of those stores — `workspace_memory` — holding one row per
//! `(workspace, memory_key)` binding a label, a content digest and a trust class.
//! This module is the typed control protocol over exactly that shape, and over
//! nothing wider.
//!
//! # What this surface does, stated before what it looks like
//!
//! **It records that a memory item was captured under a workspace, at a declared
//! trust class, binding the content named by a digest — and serves those records
//! back.** That is the whole of it:
//!
//! - **It stores no memory.** [`ContentDigest`] *names* content; the content
//!   lives elsewhere, and no request or response on this protocol has a field
//!   through which content could travel. That is the durable store's trade and it
//!   is the sharper one here: the requirement puts memory content under
//!   sensitivity, visibility, retention and legal-hold rules this protocol
//!   implements none of, so carrying the bytes would claim a custody it cannot
//!   honour.
//! - **It retrieves nothing and ranks nothing.** [`ListMemory`] serves a
//!   workspace's items in recording order. There is no query, no score, no
//!   embedding, no citation and no filter beyond the workspace the rows are
//!   partitioned by. A listing is not a search.
//! - **It learns nothing.** No candidate memory, no proposal, no review, no
//!   consolidation, no curator.
//! - **It enforces no trust class.** A [`MemoryDetailView`] that reports
//!   `untrusted` stops nothing from putting that memory into a prompt, and one
//!   that reports `actor_supplied` permits nothing. Precedence is enforced
//!   structurally in [`crate::context`], where memory enters a manifest as
//!   [`SuppliedClass::Memory`](crate::context::SuppliedClass::Memory) and the
//!   manifest's policy slot cannot receive a supplied component at all. These
//!   values are written beside that boundary, never in front of it.
//! - **It verifies no capture.** A label and a digest are carried exactly as
//!   supplied. Nothing here recomputes a digest over content it never sees, and
//!   nothing here claims the digest is the digest *of* anything.
//!
//! # This is a model, and no wire lane serves it yet
//!
//! Every value here is constructible and none is reachable from a socket. There
//! is no admin routing — [`crate::admin`]'s closed kind set does not mention this
//! protocol — no daemon handler, and no generated SDK surface. Those are later
//! slices, in the order [`crate::batch_runner`] landed before
//! [`crate::batch_api`]: the model first, the lane after. What this module fixes
//! now is the shape a lane would carry, so the lane cannot invent one.
//!
//! # Write-once, and the one amendment
//!
//! The recorded binding — label, digest, trust class — is **write-once**, exactly
//! as `automonique_store::context_memory` writes it, and the two mutations here
//! are the two that store offers and no others:
//!
//! - [`MemoryRequest::RecordMemory`] inserts a new item or finds an identical
//!   one. A `(workspace, memory_key)` presented with a *differing* binding is
//!   [`MemoryResponse::Conflict`], and no retry of it can ever succeed: a memory
//!   that genuinely changed is a new key.
//! - [`MemoryRequest::SupersedeMemory`] stamps one item as corrected by another
//!   in the same workspace. It is one-way and one-time: naming the same
//!   replacement again is a replay, [`MemoryResponse::Superseded`] carrying
//!   [`MemoryDisposition::AlreadyRecorded`]; naming a different one is
//!   [`MemoryRefusal::AlreadySuperseded`].
//!
//! There is no update and no delete, because that store has neither.
//! [`crate::context::MemoryEntry`]'s `supersede_with` "returns a new value rather
//! than mutating, so the corrected entry stays addressable and the audit trail
//! survives", and refuses to re-point an entry that already names a replacement
//! with `ContextError::AlreadySuperseded`; this protocol is the same two moves on
//! the wire.
//!
//! ## The supersession stamp is on the item, not beside it
//!
//! [`MemoryDetailView`] carries the stamp — the replacement it names and when —
//! and a listing serves the same view a detail read does. A listing that omitted
//! the stamp would let a reader mistake a corrected item for a current one, and a
//! listing that *hid* corrected items would make a correction look like a
//! deletion. The coupling is enforced rather than described: `revision` is `1`
//! with no stamp or `2` with a whole one, and every other combination is
//! [`MemoryApiError::SupersessionIncoherent`] — the same coupling the store's
//! database `CHECK` pins, re-derived here because a wire value is read by clients
//! that never see the table.
//!
//! # The trust vocabulary, and the missing fourth class
//!
//! [`MemoryTrust`] wraps [`crate::context::TrustClass`] rather than re-spelling
//! it: its [`as_str`](MemoryTrust::as_str) delegates, so the two cannot drift, and
//! there is no second list of words in this file to keep in step.
//!
//! **`policy` is absent, and its absence is the point.**
//! [`TrustClass::Policy`](crate::context::TrustClass::Policy) is documented in
//! [`crate::context`] as "Tenant or system policy. Only a policy component may
//! carry this", and memory is not one: it enters a manifest as
//! [`SuppliedClass::Memory`](crate::context::SuppliedClass::Memory), and
//! [`SuppliedComponent::new`](crate::context::SuppliedComponent::new) refuses
//! policy trust to any supplied component. The requirement states the rule twice
//! — a lower-trust document "cannot override system, tenant, sandbox or approval
//! policy", and "prompt injection can only propose lower-trust memory and cannot
//! promote itself to policy". So a memory item at policy trust is not a value
//! this protocol can hold: [`MemoryTrust::new`] refuses it, no [`RecordMemory`]
//! can be constructed carrying it, and `"policy"` on the wire is
//! [`MemoryApiError::PolicyTrustRefused`].
//!
//! Two divergences, named rather than glossed:
//!
//! - [`SuppliedComponent::new`](crate::context::SuppliedComponent::new) *lowers*
//!   a requested policy trust to `actor_supplied` and proceeds; this protocol
//!   refuses. Lowering is a manifest-assembly decision that stays visible in the
//!   manifest a client renders, whereas a durable row that quietly said
//!   `actor_supplied` when its writer said `policy` would be a permanent record
//!   of a claim nobody made. The caller decides what a rejected promotion
//!   becomes.
//! - `"policy"` is refused by its own name rather than as an unknown word,
//!   because it is not unknown: it is a word this build defines and this
//!   protocol will not accept for a memory. [`decode_memory_trust`] compares
//!   against [`crate::context::TrustClass`]'s own spelling rather than a literal,
//!   so a rename there changes this refusal with it.
//!
//! # Conflict, refusal, and which is which
//!
//! `docs/product-plan/requirements/state-and-protocols.md` § Operator client
//! protocol distinguishes `conflict` from `rejected` precisely because a caller
//! retries the two differently, and this protocol splits them on that rule:
//!
//! - a **conflict** is a collision with a durable binding the caller can inspect.
//!   [`MemoryResponse::Conflict`] carries the coordinates the *recorded* row
//!   holds — the row, its label, its digest, its trust class — so a caller learns
//!   what it collided with without a second read, and never an echo of the
//!   payload it just sent.
//! - a **refusal** is everything a retry cannot fix.
//!   [`MemoryRefusal::AlreadySuperseded`] is here rather than in the conflict arm
//!   because a supersession is one-way and one-time: unlike a revision conflict
//!   there is no current version to re-read and retry against, and the
//!   replacement already recorded is what [`MemoryRequest::MemoryDetail`]'s
//!   supersession stamp names. That is one deliberate divergence from
//!   `automonique_store::context_memory`, whose `AlreadySuperseded` error carries
//!   the recorded replacement inline; the wire answer says `rejected` and points
//!   at the read that has it.
//!
//! ## Where the model stops and the daemon starts
//!
//! [`MemoryRefusal::UnknownReplacement`] is a refusal this model can *express* and
//! cannot *decide*. Whether the replacement a [`SupersedeMemory`] names is
//! recorded in that workspace is a fact about a database, and nothing in this
//! crate reaches one. What the model settles is the shape of the answer and the
//! two things it can judge from the request alone: a replacement that names the
//! item itself is [`MemoryApiError::SelfSupersession`] at construction, and a
//! malformed key is [`MemoryApiError::Field`]. The absent-replacement case is the
//! daemon's to answer, against the store's own
//! `ContextMemoryError::NotFound("replacement")`, and the word is reserved here
//! so the lane cannot invent a different one.
//!
//! # Divergences from the durable store, named
//!
//! - **No timestamps on the wire in either direction.** A recording carries no
//!   `created_at_ms` and a supersession carries no `superseded_at_ms`: the daemon
//!   stamps both from its own clock, exactly as [`crate::approval_api`] does. The
//!   store takes caller-supplied instants because its caller *is* the daemon; a
//!   client-supplied instant would let a client date a capture to whenever it
//!   liked, and the durable row is the evidence.
//! - **`resync_required` is unreachable.** That store has no prune and no
//!   deletion, so no cursor can fall out of retention. A cursor above everything
//!   recorded is [`MemoryRefusal::CursorOutOfRange`], which says something true,
//!   rather than "the rows you wanted are gone", which would not be. See
//!   [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`].
//! - **Capacity is a refusal, never an eviction.**
//!   [`MemoryRefusal::StoreFull`] is the honest consequence of keeping every
//!   captured item: forgetting a row would not delete the memory, it would only
//!   destroy the record of how far that memory was ever meant to be trusted.
//! - **A page is bounded twice, and the two are not reconciled.**
//!   [`MAX_MEMORY_PAGE_ITEMS`] bounds a wire frame; the store's
//!   `MAX_MEMORY_PAGE` bounds a database read. The smaller is the one a client
//!   sees.
//! - **The workspace is not a tenant, and not a path.** It partitions the row
//!   space and nothing more: nothing here resolves it to a directory, and two
//!   tenants using the same workspace name share a row space until the tenant
//!   becomes a column.
//!
//! # What this protocol is not, named part by part
//!
//! The epic is large and this is one control slice of it. None of the following
//! is modelled here, and no value implies any of it exists:
//!
//! - **The context manifest.** No `ContextManifest` assembly, no component
//!   ordering, no precedence evaluation, no policy revision, no budgets, no
//!   caching, no compression lineage. A memory item is not a manifest component;
//!   it is what one would be assembled from.
//! - **Redaction.** No redaction outcome travels on this protocol, so a reader
//!   must not treat a served item as scanned.
//! - **Retrieval.** No search, no ranking, no authorization filter, no citation,
//!   no vector or full-text index, and no external-provider adapter.
//! - **The other five memory stores.** No user profile, team, task or episodic
//!   memory, and no store-kind field, so a caller cannot use these values to
//!   stand in for one of the others.
//! - **The classifications.** No provenance, confidence, sensitivity, visibility,
//!   expiry, review date or legal hold. [`crate::context::MemoryEntry`] requires
//!   all of them; nothing here carries one, which is why no value here may be
//!   presented as a complete memory entry.
//! - **Deletion.** No delete request, no tombstone, no retention sweep. Deletion
//!   runs through retention and legal-hold rules nothing here can evaluate, so
//!   this protocol offers no way to try.
//! - **The learning loop and the learning-journey graph.** No proposal, no
//!   sandboxed trial, no auto-accept, no skills, no archive or restore, and no
//!   traversal. A supersession stamp is one link between two items; walking a
//!   chain of them is the caller's walk.
//! - **Attribution.** No actor, no tenant and no reason travels with a recording
//!   or a supersession. Recording one would be an authority claim nothing checks.
//! - **HTTP.** These are protocol values framed by [`crate::codec`] on the same
//!   canonical-JSON envelope [`crate::admin`] uses, under a separate protocol
//!   name so the admin lane's closed kind set stays closed.

use core::fmt;
use std::error::Error;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_security_enum,
};
use crate::context::{MAX_CONTEXT_FIELD_BYTES, TrustClass};
use crate::journal::ActionOutcome;
use crate::primitives::{EpochMillis, ValueError};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native workspace-memory control API.
pub const MEMORY_PROTOCOL: &str = "automonique.memory";

/// Stable schema identifier for the version-one memory control surface.
pub const MEMORY_API_SCHEMA_V1: &str = "automonique.memory/v1";

/// Maximum canonical message bytes this protocol will assemble or admit.
pub const MAX_MEMORY_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of a workspace, memory key, replacement key or
/// label.
///
/// Defined *as* [`crate::context::MAX_CONTEXT_FIELD_BYTES`] rather than as a
/// second number that happens to match it. These are context fields — a
/// workspace is the opaque name
/// [`ContextReference::Workspace`](crate::context::ContextReference::Workspace)
/// carries — so a bound of this protocol's own would either refuse values the
/// rest of the product considers well-formed or admit values
/// `automonique_store::context_memory` would reject.
pub const MAX_MEMORY_API_FIELD_BYTES: usize = MAX_CONTEXT_FIELD_BYTES;

/// Exact character count of a lowercase hexadecimal SHA-256 content digest.
///
/// The durable column's grammar. Note that [`crate::context`]'s own digests are
/// opaque labels written `"sha256:…"`; this field is narrower on purpose, and a
/// caller carrying a prefixed digest strips the prefix before presenting it.
pub const MEMORY_DIGEST_CHARS: usize = 64;

/// Maximum memory items one listing page may carry.
///
/// Twelve, and the number is derived from the frame arithmetic below rather than
/// chosen: an item view carries *four* maximal fields — workspace, key, label and
/// the replacement a supersession names — at the 512-byte context bound, where an
/// approval record carries three at 256, so this page is a quarter the size of
/// [`crate::approval_api`]'s and the assertion still leaves headroom.
///
/// Well below `automonique_store::context_memory::MAX_MEMORY_PAGE`, which is five
/// hundred and twelve. That ceiling bounds a database read and this one bounds a
/// wire frame; they are not reconciled and must not be.
///
/// A page bound is not a paging hint. [`MemoryListPage::new`] refuses a longer
/// vector rather than truncating it, because a truncated page that still answers
/// `complete` is a silent drop.
pub const MAX_MEMORY_PAGE_ITEMS: usize = 12;

/// The two outcomes this protocol can never report.
///
/// `unknown` names a transport failure, and a transport failure is the *absence*
/// of a message, so no message can carry it. `resync_required` names a cursor
/// outside retention, and the durable memory store has neither a prune nor a
/// deletion — an unrecorded cursor is [`MemoryRefusal::CursorOutOfRange`]
/// instead, which says something true. A reader that receives one of these on
/// this protocol is reading a response this build did not write.
pub const OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES: [ActionOutcome; 2] =
    [ActionOutcome::Unknown, ActionOutcome::ResyncRequired];

/// Worst-case canonical bytes of one item view, excluding its four bounded
/// fields.
///
/// The ten quoted key names and their punctuation (148: one hundred and seven key
/// bytes, thirty bytes of quotes and colons, nine commas and two braces), four
/// twenty-digit integers (80), the quoted digest (66), the longest quoted trust
/// spelling (16), and the quote pairs around the four bounded members (8) — three
/// hundred and eighteen, rounded up.
const ITEM_OVERHEAD_BYTES: usize = 384;

/// Worst-case canonical bytes of a page scaffold, excluding its items.
const BODY_SCAFFOLD_BYTES: usize = 256;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 480;

/// A bounded field costs at most two canonical bytes per source byte, because a
/// quote or a backslash escapes to two.
const FIELD_ENCODED_BYTES: usize = 2 * MAX_MEMORY_API_FIELD_BYTES;

/// One item view carries four of them: workspace, key, label and the replacement
/// a supersession names.
const ITEM_FIELDS: usize = 4;

const _: () = assert!(
    MAX_MEMORY_PAGE_ITEMS * (ITEM_FIELDS * FIELD_ENCODED_BYTES + ITEM_OVERHEAD_BYTES)
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_MEMORY_CANONICAL_BYTES,
    "a maximal memory listing page must fit one memory frame"
);

const _: () = assert!(
    ITEM_FIELDS * FIELD_ENCODED_BYTES
        + ITEM_OVERHEAD_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_MEMORY_CANONICAL_BYTES,
    "a maximal memory detail view must fit one memory frame"
);

/// A supersession receipt carries three maximal fields: the workspace, the
/// corrected key and the replacement.
const _: () = assert!(
    3 * FIELD_ENCODED_BYTES + ITEM_OVERHEAD_BYTES + BODY_SCAFFOLD_BYTES + ENVELOPE_OVERHEAD_BYTES
        <= MAX_MEMORY_CANONICAL_BYTES,
    "a maximal supersession receipt must fit one memory frame"
);

/// A conflict body carries one maximal field — the recorded label — and never the
/// workspace or key, which the caller supplied and already holds. Budgeted at two
/// for headroom.
const _: () = assert!(
    2 * FIELD_ENCODED_BYTES + ITEM_OVERHEAD_BYTES + BODY_SCAFFOLD_BYTES + ENVELOPE_OVERHEAD_BYTES
        <= MAX_MEMORY_CANONICAL_BYTES,
    "a maximal memory conflict must fit one memory frame"
);

/// A refusal while constructing, encoding or decoding a memory control value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a trust, disposition,
    /// conflict-field or refusal word this build does not define. Those fail
    /// closed rather than decoding to a default.
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
    /// A bounded field was empty, over-long or control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// A content digest was not exactly [`MEMORY_DIGEST_CHARS`] lowercase
    /// hexadecimal digits.
    ///
    /// Uppercase is refused rather than folded, so one digest has exactly one
    /// wire spelling and a byte comparison of two values means what it looks
    /// like.
    Digest {
        /// Field that carried the malformed digest.
        field: &'static str,
    },
    /// A memory was presented at policy trust.
    ///
    /// Supplied content is never policy however it asks to be labelled; see the
    /// module documentation for the two rules this enforces and the one
    /// divergence from [`crate::context::SuppliedComponent`].
    PolicyTrustRefused,
    /// A requested page size was zero or above [`MAX_MEMORY_PAGE_ITEMS`].
    PageSizeOutOfRange {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Size the caller asked for.
        requested: usize,
    },
    /// A page carried more items than [`MAX_MEMORY_PAGE_ITEMS`].
    PageTooLarge {
        /// Largest page this protocol serves.
        max_items: usize,
        /// Items the caller supplied.
        actual_items: usize,
    },
    /// A page carried more items than the query it answers asked for.
    PageAboveRequestedSize {
        /// Size the query asked for.
        requested: usize,
        /// Items the page carried.
        actual_items: usize,
    },
    /// A listing carried an item recorded in another workspace.
    ///
    /// The workspace is the whole of this store's scope, so a page that crossed
    /// it would let one project's lesson answer another project's listing.
    PageOutsideWorkspace,
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A row claimed a revision the durable table cannot hold.
    ///
    /// A memory row is `1` while it stands as recorded and `2` once it is
    /// superseded; a database `CHECK` admits no third value, so anything else
    /// names a row this product could not have written.
    RevisionUnknown {
        /// Revision the row claimed.
        revision: u64,
    },
    /// A row's revision and its supersession stamp disagree.
    ///
    /// A reader must not accept a half-stamped row as a correction, nor a
    /// revision-two row with nothing recorded as correcting it.
    SupersessionIncoherent,
    /// A supersession named the item it corrects as its own replacement.
    SelfSupersession,
    /// A durable timestamp was before the epoch, which the store cannot hold.
    TimeBeforeEpoch {
        /// Field that carried the impossible instant.
        field: &'static str,
    },
    /// A page claimed rows follow without a cursor, or a cursor without rows
    /// following.
    ContinuationIncoherent,
    /// A continuation cursor did not reach the last row on the page.
    ContinuationRewinds,
    /// Page items did not strictly increase by durable row identity.
    PageOutOfOrder,
    /// A conflict named a field on which the presented and recorded bindings
    /// agree, which is a replay rather than a conflict.
    ConflictWithoutDisagreement,
}

impl MemoryApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "memory_unknown_kind",
            Self::InvalidBody => "memory_invalid_body",
            Self::CounterOutOfRange { .. } => "memory_counter_out_of_range",
            Self::Field { .. } => "memory_invalid_field",
            Self::Digest { .. } => "memory_invalid_digest",
            Self::PolicyTrustRefused => "memory_policy_trust_refused",
            Self::PageSizeOutOfRange { .. } => "memory_page_size_out_of_range",
            Self::PageTooLarge { .. } => "memory_page_too_large",
            Self::PageAboveRequestedSize { .. } => "memory_page_above_requested_size",
            Self::PageOutsideWorkspace => "memory_page_outside_workspace",
            Self::UnwrittenRow { .. } => "memory_unwritten_row",
            Self::RevisionUnknown { .. } => "memory_revision_unknown",
            Self::SupersessionIncoherent => "memory_supersession_incoherent",
            Self::SelfSupersession => "memory_self_supersession",
            Self::TimeBeforeEpoch { .. } => "memory_time_before_epoch",
            Self::ContinuationIncoherent => "memory_continuation_incoherent",
            Self::ContinuationRewinds => "memory_continuation_rewinds",
            Self::PageOutOfOrder => "memory_page_out_of_order",
            Self::ConflictWithoutDisagreement => "memory_conflict_without_disagreement",
        }
    }
}

impl fmt::Display for MemoryApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "memory codec refused message: {error}"),
            Self::UnknownKind => formatter.write_str("memory message kind is not defined"),
            Self::InvalidBody => formatter.write_str("memory message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "memory counter {field} is outside the wire range"
                )
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Digest { field } => write!(
                formatter,
                "{field} is not {MEMORY_DIGEST_CHARS} lowercase hexadecimal digits"
            ),
            Self::PolicyTrustRefused => {
                formatter.write_str("a memory item may not carry policy trust")
            }
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
                "page carries {actual_items} items; maximum is {max_items}"
            ),
            Self::PageAboveRequestedSize {
                requested,
                actual_items,
            } => write!(
                formatter,
                "page carries {actual_items} items; the query asked for {requested}"
            ),
            Self::PageOutsideWorkspace => {
                formatter.write_str("a page carries an item recorded in another workspace")
            }
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::RevisionUnknown { revision } => write!(
                formatter,
                "revision {revision} names a row the memory table cannot hold"
            ),
            Self::SupersessionIncoherent => {
                formatter.write_str("a row's revision and its supersession stamp disagree")
            }
            Self::SelfSupersession => {
                formatter.write_str("a supersession named the corrected item as its replacement")
            }
            Self::TimeBeforeEpoch { field } => write!(formatter, "{field} is before the epoch"),
            Self::ContinuationIncoherent => {
                formatter.write_str("a page's continuation marker and cursor disagree")
            }
            Self::ContinuationRewinds => {
                formatter.write_str("a continuation cursor does not reach the end of its page")
            }
            Self::PageOutOfOrder => {
                formatter.write_str("page items do not strictly increase by entry")
            }
            Self::ConflictWithoutDisagreement => {
                formatter.write_str("a conflict named a field the two bindings agree on")
            }
        }
    }
}

impl Error for MemoryApiError {}

impl From<CodecError> for MemoryApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// How far a recorded memory item may be trusted.
///
/// Three values, ordered least to most trusted, and the set is closed. This is
/// [`crate::context::TrustClass`] with its policy member excluded structurally
/// rather than a second vocabulary that happens to agree with it:
/// [`MemoryTrust::as_str`] delegates to that enum's own spelling, so a rename
/// there travels here and no literal in this file can drift from it.
///
/// Nothing here promotes. There is no method that raises a trust class, because
/// "a component may never be promoted".
/// `Hash` is deliberately absent, because [`crate::context::TrustClass`] does
/// not derive it and a hash of this wrapper would have to be spelled by hand
/// over a value whose ordering is the product's, not this module's.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemoryTrust(TrustClass);

impl MemoryTrust {
    /// Model output and retrieved documents.
    pub const UNTRUSTED: Self = Self(TrustClass::Untrusted);
    /// Provider-specific rule files, labelled as compatibility inputs.
    pub const COMPATIBILITY: Self = Self(TrustClass::Compatibility);
    /// Content the actor supplied directly, including workspace rules discovered
    /// in the shared `AGENTS.md` format.
    pub const ACTOR_SUPPLIED: Self = Self(TrustClass::ActorSupplied);

    /// Every trust a memory item may carry, least to most trusted.
    ///
    /// Three, where [`crate::context::TrustClass::ALL`] is four. The difference
    /// is exactly [`TrustClass::Policy`](crate::context::TrustClass::Policy), and
    /// it is the whole point of this type.
    pub const ALL: [Self; 3] = [Self::UNTRUSTED, Self::COMPATIBILITY, Self::ACTOR_SUPPLIED];

    /// Admit a trust class for a memory item.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::PolicyTrustRefused`] for
    /// [`TrustClass::Policy`](crate::context::TrustClass::Policy). Supplied
    /// content is never policy however it asks to be labelled, and this protocol
    /// refuses the claim rather than quietly lowering it; see the module
    /// documentation.
    pub const fn new(class: TrustClass) -> Result<Self, MemoryApiError> {
        if matches!(class, TrustClass::Policy) {
            return Err(MemoryApiError::PolicyTrustRefused);
        }
        Ok(Self(class))
    }

    /// The context trust class this value carries.
    #[must_use]
    pub const fn class(self) -> TrustClass {
        self.0
    }

    /// Stable lowercase wire spelling, and the exact text the store records.
    ///
    /// Delegated rather than restated, so this protocol and
    /// [`crate::context`] cannot disagree about a word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0.as_str()
    }

    /// Parse the exact stable spelling, or nothing.
    ///
    /// `"policy"` parses to `None` here like any word outside the three. The wire
    /// decoder separates the two cases: see [`decode_memory_trust`].
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        TrustClass::from_spelling(value).and_then(|class| Self::new(class).ok())
    }
}

impl fmt::Display for MemoryTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for MemoryTrust {
    const FIELD: &'static str = "trust_class";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Decode a trust spelling, failing closed on a word this build does not define
/// and by name on the one it defines but will not accept.
///
/// The policy comparison is against
/// [`TrustClass::Policy`](crate::context::TrustClass::Policy)'s own spelling
/// rather than a literal, so a rename in [`crate::context`] changes this refusal
/// with it.
///
/// # Errors
///
/// Returns [`MemoryApiError::PolicyTrustRefused`] for `"policy"` and
/// [`CodecError::UnknownEnumValue`] for any other undefined spelling.
pub fn decode_memory_trust(value: &str) -> Result<MemoryTrust, MemoryApiError> {
    if value == TrustClass::Policy.as_str() {
        return Err(MemoryApiError::PolicyTrustRefused);
    }
    Ok(decode_security_enum::<MemoryTrust>(value)?)
}

/// Whether a write wrote its row or found it already there.
///
/// The same two words `automonique_store::context_memory::MemoryDisposition`
/// stores and [`crate::approval_api::ApprovalDisposition`] renders, spelled once
/// per lane because neither crate depends on the other and this one must not
/// import another lane's control vocabulary. `tests/memory_api.rs` asserts the
/// agreement rather than assuming it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryDisposition {
    /// The fact was new and is now durable.
    Recorded,
    /// The exact fact was already durable. Nothing changed.
    AlreadyRecorded,
}

impl MemoryDisposition {
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

impl fmt::Display for MemoryDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for MemoryDisposition {
    const FIELD: &'static str = "disposition";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Which of a recording's three binding fields a conflict is about.
///
/// `automonique_store::context_memory` compares label, digest and trust class in
/// that order and reports the first difference, so a conflict names one field
/// rather than a set. The order is a property of that comparison and is mirrored
/// by [`MemoryResponse::conflict`], which *derives* the field rather than
/// accepting a caller's claim about it. The three spellings are the store's own
/// column names.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryConflictField {
    /// The key was recorded describing something else.
    Label,
    /// The key was recorded binding other content.
    ContentDigest,
    /// The key was recorded at a different trust.
    TrustClass,
}

impl MemoryConflictField {
    /// Every field, in the order the store compares them.
    pub const ALL: [Self; 3] = [Self::Label, Self::ContentDigest, Self::TrustClass];

    /// Stable lowercase wire spelling, and the store's own column name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::ContentDigest => "content_digest",
            Self::TrustClass => "trust_class",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.as_str() == value)
    }
}

impl fmt::Display for MemoryConflictField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for MemoryConflictField {
    const FIELD: &'static str = "field";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// The workspace a memory item belongs to, and the only scope it has.
///
/// The named-workspace identity
/// [`ContextReference::Workspace`](crate::context::ContextReference::Workspace)
/// carries: an opaque name, not a path. Nothing here resolves it to a directory,
/// and it is not a tenant; see the module documentation.
///
/// Two workspaces recording the same key hold two independent items, and neither
/// can read, collide with or supersede the other's.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryWorkspace(String);

impl MemoryWorkspace {
    /// Longest workspace this protocol carries.
    pub const MAX_BYTES: usize = MAX_MEMORY_API_FIELD_BYTES;

    /// Validate and construct a workspace name.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        let value = value.as_ref();
        bounded(value, "workspace")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated workspace name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemoryWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The durable idempotency identity of one memory item, unique *within* a
/// workspace.
///
/// Not host-wide: the key alone names nothing, and every request that carries one
/// carries the workspace beside it. That is the requirement's "Rules from
/// parent/home directories never leak into unrelated projects" written into a
/// key.
///
/// It is opaque. This protocol never parses it, derives nothing from it and gives
/// it no structure — two keys are the same item or they are not.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryKey(String);

impl MemoryKey {
    /// Longest key this protocol carries.
    pub const MAX_BYTES: usize = MAX_MEMORY_API_FIELD_BYTES;

    /// Validate and construct a memory key.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Field`] reporting `memory_key` for an empty,
    /// over-long or control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        Self::named(value.as_ref(), "memory_key")
    }

    /// Validate and construct a key in its role as a replacement.
    ///
    /// The same grammar and the same type; only the field a refusal names
    /// differs, so a caller that presented a malformed replacement is not told
    /// its `memory_key` was wrong.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Field`] reporting `replacement_key`.
    pub fn replacement(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        Self::named(value.as_ref(), "replacement_key")
    }

    fn named(value: &str, field: &'static str) -> Result<Self, MemoryApiError> {
        bounded(value, field)?;
        Ok(Self(value.to_owned()))
    }

    /// The validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemoryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A bounded *name* for what was captured.
///
/// Part of the recorded binding: the same key describing a different memory is a
/// conflict, not a correction. It is a name and never the memory itself — an item
/// whose only description were an opaque key would answer "was this captured" and
/// never "what was captured".
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryLabel(String);

impl MemoryLabel {
    /// Longest label this protocol carries.
    pub const MAX_BYTES: usize = MAX_MEMORY_API_FIELD_BYTES;

    /// Validate and construct a label.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Field`] for an empty, over-long or
    /// control-bearing value.
    pub fn new(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        let value = value.as_ref();
        bounded(value, "label")?;
        Ok(Self(value.to_owned()))
    }

    /// The validated label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MemoryLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A lowercase hexadecimal SHA-256 naming the content a memory item binds.
///
/// Exactly [`MEMORY_DIGEST_CHARS`] characters, and never the content: this
/// protocol carries no field a memory's bytes could travel in, and does not claim
/// the digest is the digest *of* anything it has seen.
///
/// Uppercase is refused rather than folded, so one digest has exactly one wire
/// spelling and a byte comparison of two values means what it looks like.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Exact character count this type admits.
    pub const CHARS: usize = MEMORY_DIGEST_CHARS;

    /// Validate and construct a content digest.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Digest`] for anything but exactly
    /// [`MEMORY_DIGEST_CHARS`] lowercase hexadecimal digits.
    pub fn new(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        Self::named(value.as_ref(), "content_digest")
    }

    /// Validate and construct a digest in its role as a conflict's recorded side.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::Digest`] reporting `recorded_digest`.
    pub fn recorded(value: impl AsRef<str>) -> Result<Self, MemoryApiError> {
        Self::named(value.as_ref(), "recorded_digest")
    }

    fn named(value: &str, field: &'static str) -> Result<Self, MemoryApiError> {
        if value.len() != MEMORY_DIGEST_CHARS
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(MemoryApiError::Digest { field });
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A durable listing position: the entry a listing resumes *after*.
///
/// Zero starts at the beginning. This is the store's own exclusive cursor rather
/// than a translated one — it pages by `entry_id` and reports the last one it
/// served — so no coordinate is converted between the wire and the table and
/// there is no off-by-one to re-derive.
///
/// The cursor is a position in the whole store's recording order, not in one
/// workspace's subset, exactly as the store judges it: a row another workspace
/// occupies must not turn a resumable cursor into a refusal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryCursor(u64);

impl MemoryCursor {
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

/// How many items one listing asks for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryPageSize(usize);

impl MemoryPageSize {
    /// The largest page this protocol serves.
    pub const MAX: Self = Self(MAX_MEMORY_PAGE_ITEMS);

    /// Ask for a bounded number of items.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::PageSizeOutOfRange`] for zero — a page that
    /// admits nothing cannot make progress — or for a size above
    /// [`MAX_MEMORY_PAGE_ITEMS`].
    pub const fn new(items: usize) -> Result<Self, MemoryApiError> {
        if items == 0 || items > MAX_MEMORY_PAGE_ITEMS {
            return Err(MemoryApiError::PageSizeOutOfRange {
                max_items: MAX_MEMORY_PAGE_ITEMS,
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

/// One memory item presented for durable recording, write-once.
///
/// There is no timestamp field, and its absence is deliberate: the daemon stamps
/// the capture instant from its own clock. A caller-supplied instant on the wire
/// would let a client date a capture to whenever it liked, and the durable row is
/// the evidence.
///
/// There is no content field either, and that absence is the module's central
/// claim: this protocol binds content by digest and never carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordMemory {
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
    label: MemoryLabel,
    content_digest: ContentDigest,
    trust: MemoryTrust,
}

impl RecordMemory {
    /// Present one memory item.
    ///
    /// A policy trust is unrepresentable here rather than rejected here: the
    /// refusal lives in [`MemoryTrust::new`], so no value of this type can exist
    /// carrying one.
    #[must_use]
    pub const fn new(
        workspace: MemoryWorkspace,
        memory_key: MemoryKey,
        label: MemoryLabel,
        content_digest: ContentDigest,
        trust: MemoryTrust,
    ) -> Self {
        Self {
            workspace,
            memory_key,
            label,
            content_digest,
            trust,
        }
    }

    /// The workspace this item belongs to.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The idempotency identity within that workspace.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    /// What was captured.
    #[must_use]
    pub const fn label(&self) -> &MemoryLabel {
        &self.label
    }

    /// The content this item binds without carrying.
    #[must_use]
    pub const fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    /// How far the captured content may be trusted. Recorded, never enforced.
    #[must_use]
    pub const fn trust(&self) -> MemoryTrust {
        self.trust
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "content_digest".to_owned(),
                JsonValue::String(self.content_digest.as_str().to_owned()),
            ),
            (
                "label".to_owned(),
                JsonValue::String(self.label.as_str().to_owned()),
            ),
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            (
                "trust_class".to_owned(),
                JsonValue::String(self.trust.as_str().to_owned()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(
            body,
            &[
                "content_digest",
                "label",
                "memory_key",
                "trust_class",
                "workspace",
            ],
        )?;
        Ok(Self::new(
            MemoryWorkspace::new(required_string(body, "workspace")?)?,
            MemoryKey::new(required_string(body, "memory_key")?)?,
            MemoryLabel::new(required_string(body, "label")?)?,
            ContentDigest::new(required_string(body, "content_digest")?)?,
            decode_memory_trust(&required_string(body, "trust_class")?)?,
        ))
    }
}

/// One correction presented for durable stamping.
///
/// Both keys name items in the same workspace. A replacement recorded elsewhere
/// is absent rather than borrowed: this protocol has no cross-workspace edge and
/// no field through which one could be requested.
///
/// There is no timestamp, for the reason [`RecordMemory`] has none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersedeMemory {
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
    replacement_key: MemoryKey,
}

impl SupersedeMemory {
    /// Present one correction.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::SelfSupersession`] when the replacement names
    /// the item it corrects. That is the one thing about a supersession this
    /// model can settle without a database; whether the replacement *exists* is
    /// [`MemoryRefusal::UnknownReplacement`] and the daemon's to answer.
    pub fn new(
        workspace: MemoryWorkspace,
        memory_key: MemoryKey,
        replacement_key: MemoryKey,
    ) -> Result<Self, MemoryApiError> {
        if replacement_key == memory_key {
            return Err(MemoryApiError::SelfSupersession);
        }
        Ok(Self {
            workspace,
            memory_key,
            replacement_key,
        })
    }

    /// The workspace both items belong to.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The item being corrected.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    /// The item that corrects it.
    #[must_use]
    pub const fn replacement_key(&self) -> &MemoryKey {
        &self.replacement_key
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            (
                "replacement_key".to_owned(),
                JsonValue::String(self.replacement_key.as_str().to_owned()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(body, &["memory_key", "replacement_key", "workspace"])?;
        Self::new(
            MemoryWorkspace::new(required_string(body, "workspace")?)?,
            MemoryKey::new(required_string(body, "memory_key")?)?,
            MemoryKey::replacement(required_string(body, "replacement_key")?)?,
        )
    }
}

/// A bounded request for one page of one workspace's memory items.
///
/// Superseded items are listed like any other. This is a record of what was
/// captured, not a view of what is current, and a listing that hid corrected
/// items would make a correction look like a deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListMemory {
    workspace: MemoryWorkspace,
    cursor: MemoryCursor,
    page_size: MemoryPageSize,
}

impl ListMemory {
    /// Ask for one page.
    #[must_use]
    pub const fn new(
        workspace: MemoryWorkspace,
        cursor: MemoryCursor,
        page_size: MemoryPageSize,
    ) -> Self {
        Self {
            workspace,
            cursor,
            page_size,
        }
    }

    /// The workspace whose items are asked for.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The entry this listing resumes after.
    #[must_use]
    pub const fn cursor(&self) -> MemoryCursor {
        self.cursor
    }

    /// How many items this listing asks for.
    #[must_use]
    pub const fn page_size(&self) -> MemoryPageSize {
        self.page_size
    }

    fn to_body(&self) -> Result<JsonValue, MemoryApiError> {
        Ok(JsonValue::Object(vec![
            (
                "cursor".to_owned(),
                integer("cursor", self.cursor.position())?,
            ),
            (
                "page_size".to_owned(),
                integer("page_size", self.page_size.get() as u64)?,
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(body, &["cursor", "page_size", "workspace"])?;
        Ok(Self::new(
            MemoryWorkspace::new(required_string(body, "workspace")?)?,
            MemoryCursor::new(unsigned(body, "cursor")?),
            page_size(body)?,
        ))
    }
}

/// A bounded request for one memory item in full.
///
/// `(workspace, memory_key)` is the whole coordinate. The same key recorded in
/// another workspace is a different item, and this read will not mention it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDetail {
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
}

impl MemoryDetail {
    /// Ask for one item.
    #[must_use]
    pub const fn new(workspace: MemoryWorkspace, memory_key: MemoryKey) -> Self {
        Self {
            workspace,
            memory_key,
        }
    }

    /// The workspace to read in.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The key to read.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(body, &["memory_key", "workspace"])?;
        Ok(Self::new(
            MemoryWorkspace::new(required_string(body, "workspace")?)?,
            MemoryKey::new(required_string(body, "memory_key")?)?,
        ))
    }
}

/// What one recording established, and whether this call is what established it.
///
/// The coordinates travel back with it — the store's own receipt omits them
/// because its caller supplied them, and a correlated answer travelling on its
/// own cannot rely on that.
///
/// There is no `revision` here: a fresh recording is always revision one, and a
/// caller has nothing to fence against because the binding has no second write.
/// The stored revision is reported on [`MemoryDetailView`], where a reader can see
/// for itself whether the item has since been corrected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryReceiptView {
    entry_id: u64,
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
    disposition: MemoryDisposition,
    created_at: EpochMillis,
}

impl MemoryReceiptView {
    /// Record what one accepted recording established.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::UnwrittenRow`] for a zero `entry_id` and
    /// [`MemoryApiError::TimeBeforeEpoch`] for an instant the store's
    /// `created_at_ms >= 0` constraint cannot hold.
    pub fn new(
        entry_id: u64,
        workspace: MemoryWorkspace,
        memory_key: MemoryKey,
        disposition: MemoryDisposition,
        created_at: EpochMillis,
    ) -> Result<Self, MemoryApiError> {
        if entry_id == 0 {
            return Err(MemoryApiError::UnwrittenRow { field: "entry_id" });
        }
        if created_at.as_millis() < 0 {
            return Err(MemoryApiError::TimeBeforeEpoch {
                field: "created_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            workspace,
            memory_key,
            disposition,
            created_at,
        })
    }

    /// Row identity, monotonic in recording order. The pagination key.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// The workspace this receipt is about.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The key this receipt is about.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    /// Whether this call wrote the row or found it.
    #[must_use]
    pub const fn disposition(&self) -> MemoryDisposition {
        self.disposition
    }

    /// The capture instant the durable row records.
    ///
    /// On a [`MemoryDisposition::AlreadyRecorded`] answer this is the *first*
    /// recording's instant, not this call's. A replay writes nothing, including
    /// the clock.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }

    fn to_body(&self) -> Result<JsonValue, MemoryApiError> {
        Ok(JsonValue::Object(vec![
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(self.created_at.as_millis()),
            ),
            (
                "disposition".to_owned(),
                JsonValue::String(self.disposition.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(
            body,
            &[
                "created_at_ms",
                "disposition",
                "entry_id",
                "memory_key",
                "workspace",
            ],
        )?;
        Self::new(
            unsigned(body, "entry_id")?,
            MemoryWorkspace::new(required_string(body, "workspace")?)?,
            MemoryKey::new(required_string(body, "memory_key")?)?,
            decode_security_enum::<MemoryDisposition>(&required_string(body, "disposition")?)?,
            EpochMillis::from_millis(signed(body, "created_at_ms")?),
        )
    }
}

/// What one supersession established, and whether this call is what established
/// it.
///
/// The revision is carried because it is the property that makes the write-once
/// discipline checkable from outside: a stamped row is revision two and there is
/// no third state. It is also *validated* — this build's table has exactly two
/// states, so a supersession receipt claiming any other revision names a row this
/// product could not have written. That is a deliberate divergence from
/// `automonique_store::context_memory::SupersessionReceipt`, which reports the
/// revision without judging it so a later schema's third state would still be
/// reportable; on the wire, admitting an unknown revision would mean admitting a
/// row from a build this one cannot read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersessionReceiptView {
    entry_id: u64,
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
    replacement_key: MemoryKey,
    disposition: MemoryDisposition,
    superseded_at: EpochMillis,
    revision: u64,
}

impl SupersessionReceiptView {
    /// The revision a stamped row carries, and the only one this view admits.
    pub const SUPERSEDED_REVISION: u64 = 2;

    /// Record what one accepted supersession established.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::UnwrittenRow`] for a zero `entry_id`,
    /// [`MemoryApiError::SelfSupersession`] when the replacement names the
    /// corrected item, [`MemoryApiError::RevisionUnknown`] for any revision but
    /// [`SUPERSEDED_REVISION`](Self::SUPERSEDED_REVISION), and
    /// [`MemoryApiError::TimeBeforeEpoch`] for an impossible instant.
    pub fn new(parts: SupersessionReceiptParts) -> Result<Self, MemoryApiError> {
        let SupersessionReceiptParts {
            entry_id,
            workspace,
            memory_key,
            replacement_key,
            disposition,
            superseded_at,
            revision,
        } = parts;
        if entry_id == 0 {
            return Err(MemoryApiError::UnwrittenRow { field: "entry_id" });
        }
        if replacement_key == memory_key {
            return Err(MemoryApiError::SelfSupersession);
        }
        if revision != Self::SUPERSEDED_REVISION {
            return Err(MemoryApiError::RevisionUnknown { revision });
        }
        if superseded_at.as_millis() < 0 {
            return Err(MemoryApiError::TimeBeforeEpoch {
                field: "superseded_at_ms",
            });
        }
        Ok(Self {
            entry_id,
            workspace,
            memory_key,
            replacement_key,
            disposition,
            superseded_at,
            revision,
        })
    }

    /// Row identity of the corrected item.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// The workspace both items belong to.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// The item that was corrected.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    /// The item that corrects it.
    #[must_use]
    pub const fn replacement_key(&self) -> &MemoryKey {
        &self.replacement_key
    }

    /// Whether this call stamped the row or found it already stamped with the
    /// same replacement.
    #[must_use]
    pub const fn disposition(&self) -> MemoryDisposition {
        self.disposition
    }

    /// The supersession instant the durable row records.
    ///
    /// On a [`MemoryDisposition::AlreadyRecorded`] answer this is the first
    /// stamp's instant.
    #[must_use]
    pub const fn superseded_at(&self) -> EpochMillis {
        self.superseded_at
    }

    /// Always [`SUPERSEDED_REVISION`](Self::SUPERSEDED_REVISION).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn to_body(&self) -> Result<JsonValue, MemoryApiError> {
        Ok(JsonValue::Object(vec![
            (
                "disposition".to_owned(),
                JsonValue::String(self.disposition.as_str().to_owned()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            (
                "replacement_key".to_owned(),
                JsonValue::String(self.replacement_key.as_str().to_owned()),
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "superseded_at_ms".to_owned(),
                JsonValue::Integer(self.superseded_at.as_millis()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(
            body,
            &[
                "disposition",
                "entry_id",
                "memory_key",
                "replacement_key",
                "revision",
                "superseded_at_ms",
                "workspace",
            ],
        )?;
        Self::new(SupersessionReceiptParts {
            entry_id: unsigned(body, "entry_id")?,
            workspace: MemoryWorkspace::new(required_string(body, "workspace")?)?,
            memory_key: MemoryKey::new(required_string(body, "memory_key")?)?,
            replacement_key: MemoryKey::replacement(required_string(body, "replacement_key")?)?,
            disposition: decode_security_enum::<MemoryDisposition>(&required_string(
                body,
                "disposition",
            )?)?,
            superseded_at: EpochMillis::from_millis(signed(body, "superseded_at_ms")?),
            revision: unsigned(body, "revision")?,
        })
    }
}

/// The seven members one supersession receipt carries.
///
/// A parameter object rather than seven positional arguments: three bounded
/// strings sit beside one another, and a transposed pair would type-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersessionReceiptParts {
    /// Row identity of the corrected item.
    pub entry_id: u64,
    /// The workspace both items belong to.
    pub workspace: MemoryWorkspace,
    /// The item that was corrected.
    pub memory_key: MemoryKey,
    /// The item that corrects it.
    pub replacement_key: MemoryKey,
    /// Whether this call stamped the row or found it stamped.
    pub disposition: MemoryDisposition,
    /// When the durable supersession was stamped.
    pub superseded_at: EpochMillis,
    /// Always `2`; anything else names a row the table cannot hold.
    pub revision: u64,
}

/// The stamp a corrected item carries.
///
/// Present exactly when the item's revision is two. Naming the replacement is
/// what lets a reader tell a current item from a corrected one, and the instant
/// is what lets a reader order two corrections.
///
/// It says a correction was *recorded*. It does not say the correction is right,
/// that anything stopped using the superseded memory, or who asked for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersessionStamp {
    /// The item in this workspace that corrected this one.
    pub replacement_key: MemoryKey,
    /// When the supersession was stamped.
    pub superseded_at: EpochMillis,
}

/// One validated memory item, as a listing or a detail read reports it.
///
/// The same view serves both. A listing that reported less than a detail read
/// would let a reader who paged rather than read mistake a corrected item for a
/// current one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryDetailView {
    entry_id: u64,
    workspace: MemoryWorkspace,
    memory_key: MemoryKey,
    label: MemoryLabel,
    content_digest: ContentDigest,
    trust: MemoryTrust,
    created_at: EpochMillis,
    supersession: Option<SupersessionStamp>,
    revision: u64,
}

impl MemoryDetailView {
    /// The revision an item carries while it stands as recorded.
    pub const RECORDED_REVISION: u64 = 1;
    /// The revision an item carries once it is superseded.
    pub const SUPERSEDED_REVISION: u64 = 2;

    /// Record one item, refusing every row this product could not have written.
    ///
    /// The cross-column invariants the store re-derives on every read are
    /// re-derived here, because a wire value is read by clients the store never
    /// sees: the row identity is written, the revision is one of the two the
    /// table admits, the revision and the stamp agree, and a replacement never
    /// names the item it corrects.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::UnwrittenRow`],
    /// [`MemoryApiError::RevisionUnknown`],
    /// [`MemoryApiError::SupersessionIncoherent`],
    /// [`MemoryApiError::SelfSupersession`] or
    /// [`MemoryApiError::TimeBeforeEpoch`].
    pub fn new(parts: MemoryItemParts) -> Result<Self, MemoryApiError> {
        let MemoryItemParts {
            entry_id,
            workspace,
            memory_key,
            label,
            content_digest,
            trust,
            created_at,
            supersession,
            revision,
        } = parts;
        if entry_id == 0 {
            return Err(MemoryApiError::UnwrittenRow { field: "entry_id" });
        }
        if revision != Self::RECORDED_REVISION && revision != Self::SUPERSEDED_REVISION {
            return Err(MemoryApiError::RevisionUnknown { revision });
        }
        if (revision == Self::SUPERSEDED_REVISION) != supersession.is_some() {
            return Err(MemoryApiError::SupersessionIncoherent);
        }
        if created_at.as_millis() < 0 {
            return Err(MemoryApiError::TimeBeforeEpoch {
                field: "created_at_ms",
            });
        }
        if let Some(stamp) = &supersession {
            if stamp.replacement_key == memory_key {
                return Err(MemoryApiError::SelfSupersession);
            }
            if stamp.superseded_at.as_millis() < 0 {
                return Err(MemoryApiError::TimeBeforeEpoch {
                    field: "superseded_at_ms",
                });
            }
        }
        Ok(Self {
            entry_id,
            workspace,
            memory_key,
            label,
            content_digest,
            trust,
            created_at,
            supersession,
            revision,
        })
    }

    /// Row identity, monotonic in recording order across every workspace.
    #[must_use]
    pub const fn entry_id(&self) -> u64 {
        self.entry_id
    }

    /// The workspace this item belongs to.
    #[must_use]
    pub const fn workspace(&self) -> &MemoryWorkspace {
        &self.workspace
    }

    /// Durable idempotency identity within that workspace.
    #[must_use]
    pub const fn memory_key(&self) -> &MemoryKey {
        &self.memory_key
    }

    /// What was captured.
    #[must_use]
    pub const fn label(&self) -> &MemoryLabel {
        &self.label
    }

    /// The content this item binds without carrying.
    #[must_use]
    pub const fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    /// How far the captured content may be trusted. Reported, never enforced.
    #[must_use]
    pub const fn trust(&self) -> MemoryTrust {
        self.trust
    }

    /// When the memory was recorded as captured.
    #[must_use]
    pub const fn created_at(&self) -> EpochMillis {
        self.created_at
    }

    /// The correction recorded against this item, if any.
    ///
    /// `None` does not mean the memory is still accurate; it means nothing has
    /// been recorded as correcting it.
    #[must_use]
    pub const fn supersession(&self) -> Option<&SupersessionStamp> {
        self.supersession.as_ref()
    }

    /// Whether a correction has been recorded against this item.
    #[must_use]
    pub const fn is_superseded(&self) -> bool {
        self.supersession.is_some()
    }

    /// `1` while the item stands as recorded, `2` once it is superseded.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn to_body(&self) -> Result<JsonValue, MemoryApiError> {
        let (superseded_by, superseded_at) = match &self.supersession {
            Some(stamp) => (
                JsonValue::String(stamp.replacement_key.as_str().to_owned()),
                JsonValue::Integer(stamp.superseded_at.as_millis()),
            ),
            None => (JsonValue::Null, JsonValue::Null),
        };
        Ok(JsonValue::Object(vec![
            (
                "content_digest".to_owned(),
                JsonValue::String(self.content_digest.as_str().to_owned()),
            ),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(self.created_at.as_millis()),
            ),
            ("entry_id".to_owned(), integer("entry_id", self.entry_id)?),
            (
                "label".to_owned(),
                JsonValue::String(self.label.as_str().to_owned()),
            ),
            (
                "memory_key".to_owned(),
                JsonValue::String(self.memory_key.as_str().to_owned()),
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            ("superseded_at_ms".to_owned(), superseded_at),
            ("superseded_by".to_owned(), superseded_by),
            (
                "trust_class".to_owned(),
                JsonValue::String(self.trust.as_str().to_owned()),
            ),
            (
                "workspace".to_owned(),
                JsonValue::String(self.workspace.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(
            body,
            &[
                "content_digest",
                "created_at_ms",
                "entry_id",
                "label",
                "memory_key",
                "revision",
                "superseded_at_ms",
                "superseded_by",
                "trust_class",
                "workspace",
            ],
        )?;
        // A half-stamped row is refused rather than read as unstamped: the
        // store writes both columns or neither, so one of each is a second
        // writer's work and a reader must not accept it as a correction.
        let supersession = match (body.get("superseded_by"), body.get("superseded_at_ms")) {
            (Some(JsonValue::Null), Some(JsonValue::Null)) => None,
            (Some(JsonValue::String(_)), Some(JsonValue::Integer(_))) => Some(SupersessionStamp {
                replacement_key: MemoryKey::replacement(required_string(body, "superseded_by")?)?,
                superseded_at: EpochMillis::from_millis(signed(body, "superseded_at_ms")?),
            }),
            (Some(JsonValue::Null), Some(JsonValue::Integer(_)))
            | (Some(JsonValue::String(_)), Some(JsonValue::Null)) => {
                return Err(MemoryApiError::SupersessionIncoherent);
            }
            _ => return Err(MemoryApiError::InvalidBody),
        };
        Self::new(MemoryItemParts {
            entry_id: unsigned(body, "entry_id")?,
            workspace: MemoryWorkspace::new(required_string(body, "workspace")?)?,
            memory_key: MemoryKey::new(required_string(body, "memory_key")?)?,
            label: MemoryLabel::new(required_string(body, "label")?)?,
            content_digest: ContentDigest::new(required_string(body, "content_digest")?)?,
            trust: decode_memory_trust(&required_string(body, "trust_class")?)?,
            created_at: EpochMillis::from_millis(signed(body, "created_at_ms")?),
            supersession,
            revision: unsigned(body, "revision")?,
        })
    }
}

/// The nine members one memory item view carries.
///
/// A parameter object rather than nine positional arguments: four bounded strings
/// sit beside one another, and a transposed pair would type-check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryItemParts {
    /// Row identity, monotonic in recording order.
    pub entry_id: u64,
    /// The workspace this item belongs to.
    pub workspace: MemoryWorkspace,
    /// Durable idempotency identity within that workspace.
    pub memory_key: MemoryKey,
    /// What was captured.
    pub label: MemoryLabel,
    /// The content this item binds without carrying.
    pub content_digest: ContentDigest,
    /// How far the captured content may be trusted.
    pub trust: MemoryTrust,
    /// When the memory was recorded as captured.
    pub created_at: EpochMillis,
    /// The correction recorded against this item, if any.
    pub supersession: Option<SupersessionStamp>,
    /// `1` unstamped, `2` stamped; the stamp and this value must agree.
    pub revision: u64,
}

/// The binding a durable row records, as a conflict reports it.
///
/// The workspace and the key are deliberately absent: a conflict answers a
/// recording that named both, so the caller already holds them, and repeating
/// them would be an echo rather than information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedMemory {
    /// Row the durable item occupies.
    pub entry_id: u64,
    /// Label the durable row records.
    pub label: MemoryLabel,
    /// Content digest the durable row records.
    pub content_digest: ContentDigest,
    /// Trust class the durable row records.
    pub trust: MemoryTrust,
}

/// Whether a page is the end of the listing.
///
/// Closed, and carried explicitly rather than inferred from `entries.len() <
/// page_size`. A short page is not the same statement as a last page: a workspace
/// filter can exclude every row in a scanned window and still leave rows behind
/// it, and a client that inferred "done" from a short page would stop early.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryContinuation {
    /// More rows may follow; resume after this cursor.
    More(MemoryCursor),
    /// The listing reached the end of the store.
    Complete,
}

impl MemoryContinuation {
    /// The cursor to resume after, when there is one.
    #[must_use]
    pub const fn cursor(self) -> Option<MemoryCursor> {
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

/// One bounded page of memory items.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryListPage {
    entries: Vec<MemoryDetailView>,
    continuation: MemoryContinuation,
}

impl MemoryListPage {
    /// Assemble a page.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::PageTooLarge`] above [`MAX_MEMORY_PAGE_ITEMS`],
    /// [`MemoryApiError::PageOutOfOrder`] when items do not strictly increase by
    /// `entry_id` — a listing is ordered by that identity, and a repeat or a step
    /// backwards means the next page would re-serve or skip — and
    /// [`MemoryApiError::ContinuationRewinds`] when a continuation cursor does
    /// not reach the last row on the page.
    ///
    /// An empty page carrying [`MemoryContinuation::More`] is accepted: the
    /// workspace filter may exclude every row in one scanned window while rows
    /// remain behind it.
    pub fn new(
        entries: Vec<MemoryDetailView>,
        continuation: MemoryContinuation,
    ) -> Result<Self, MemoryApiError> {
        if entries.len() > MAX_MEMORY_PAGE_ITEMS {
            return Err(MemoryApiError::PageTooLarge {
                max_items: MAX_MEMORY_PAGE_ITEMS,
                actual_items: entries.len(),
            });
        }
        if entries
            .windows(2)
            .any(|pair| pair[1].entry_id() <= pair[0].entry_id())
        {
            return Err(MemoryApiError::PageOutOfOrder);
        }
        if let (Some(cursor), Some(last)) = (continuation.cursor(), entries.last())
            && cursor.position() < last.entry_id()
        {
            return Err(MemoryApiError::ContinuationRewinds);
        }
        Ok(Self {
            entries,
            continuation,
        })
    }

    /// The items, in recording order, corrected ones included.
    #[must_use]
    pub fn entries(&self) -> &[MemoryDetailView] {
        &self.entries
    }

    /// Whether more rows may follow, and from where.
    #[must_use]
    pub const fn continuation(&self) -> MemoryContinuation {
        self.continuation
    }

    fn to_body(&self) -> Result<JsonValue, MemoryApiError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for item in &self.entries {
            entries.push(item.to_body()?);
        }
        Ok(JsonValue::Object(vec![
            ("memories".to_owned(), JsonValue::Array(entries)),
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

    fn from_body(body: &JsonValue) -> Result<Self, MemoryApiError> {
        exact_fields(body, &["memories", "more", "next_cursor"])?;
        let more = match body.get("more") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(MemoryApiError::InvalidBody),
        };
        let continuation = match (more, body.get("next_cursor")) {
            (true, Some(JsonValue::Integer(_))) => {
                MemoryContinuation::More(MemoryCursor::new(unsigned(body, "next_cursor")?))
            }
            (false, Some(JsonValue::Null)) => MemoryContinuation::Complete,
            (true, Some(JsonValue::Null)) | (false, Some(JsonValue::Integer(_))) => {
                return Err(MemoryApiError::ContinuationIncoherent);
            }
            _ => return Err(MemoryApiError::InvalidBody),
        };
        let JsonValue::Array(items) = body.get("memories").ok_or(MemoryApiError::InvalidBody)?
        else {
            return Err(MemoryApiError::InvalidBody);
        };
        if items.len() > MAX_MEMORY_PAGE_ITEMS {
            return Err(MemoryApiError::PageTooLarge {
                max_items: MAX_MEMORY_PAGE_ITEMS,
                actual_items: items.len(),
            });
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            entries.push(MemoryDetailView::from_body(item)?);
        }
        Self::new(entries, continuation)
    }
}

/// Why a memory operation was refused.
///
/// Closed, and every variant is one word. A refusal carries no field name, no
/// stored text and no echo of the caller's payload: a refusal category is a
/// metric label and an operator-facing word, not a diagnostic channel for the
/// bytes that were sent.
///
/// A key recorded with a *differing binding* is deliberately not here. It is
/// [`MemoryResponse::Conflict`], which the plan's vocabulary distinguishes from a
/// rejection precisely because a caller retries the two differently — and a
/// conflicting reuse must never be retried at all, because the binding is
/// write-once and a memory that genuinely changed is a new key.
///
/// There is no `already_recorded` refusal either: an exact replay is a *success*,
/// [`MemoryResponse::Recorded`] or [`MemoryResponse::Superseded`] carrying
/// [`MemoryDisposition::AlreadyRecorded`]. A caller that lost the answer to its
/// first write and retries it gets the first answer back.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryRefusal {
    /// No item is recorded under that key *in that workspace*.
    ///
    /// The same key may be recorded in another workspace and this answer will
    /// not mention it, which is the whole point of the scope.
    UnknownMemory,
    /// The replacement a supersession named is not recorded in that workspace.
    ///
    /// A correction that points at nothing is not a correction, and one naming a
    /// row in another workspace is a cross-workspace edge the store does not
    /// admit. Callers record the replacement first. This model reserves the word;
    /// the daemon decides the fact — see the module documentation.
    UnknownReplacement,
    /// The item was already superseded by a *different* replacement.
    ///
    /// A supersession extends the history, it never rewrites it. Naming the same
    /// replacement again is not this refusal; it is a replay.
    AlreadySuperseded,
    /// A page was requested from a cursor above everything recorded.
    CursorOutOfRange,
    /// The store holds its full capacity of memory items.
    ///
    /// Recording is refused rather than evicting an older item, and there is no
    /// prune. Replays, supersessions and reads are unaffected, because none of
    /// them adds a row.
    StoreFull,
    /// A supplied field was outside the durable store's grammar.
    InvalidField,
}

impl MemoryRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 6] = [
        Self::UnknownMemory,
        Self::UnknownReplacement,
        Self::AlreadySuperseded,
        Self::CursorOutOfRange,
        Self::StoreFull,
        Self::InvalidField,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMemory => "unknown_memory",
            Self::UnknownReplacement => "unknown_replacement",
            Self::AlreadySuperseded => "already_superseded",
            Self::CursorOutOfRange => "cursor_out_of_range",
            Self::StoreFull => "store_full",
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

impl fmt::Display for MemoryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for MemoryRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated request on the memory control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryRequest {
    /// Record one memory item, write-once.
    RecordMemory {
        /// Correlation identifier.
        request_id: RequestId,
        /// The item to record.
        item: RecordMemory,
    },
    /// Stamp one item as corrected by another in the same workspace.
    SupersedeMemory {
        /// Correlation identifier.
        request_id: RequestId,
        /// The correction.
        correction: SupersedeMemory,
    },
    /// One bounded page of one workspace's items.
    ListMemory {
        /// Correlation identifier.
        request_id: RequestId,
        /// Workspace, cursor and page size.
        query: ListMemory,
    },
    /// One item in full.
    MemoryDetail {
        /// Correlation identifier.
        request_id: RequestId,
        /// Workspace and key to read.
        query: MemoryDetail,
    },
}

impl MemoryRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::RecordMemory { request_id, .. }
            | Self::SupersedeMemory { request_id, .. }
            | Self::ListMemory { request_id, .. }
            | Self::MemoryDetail { request_id, .. } => request_id,
        }
    }

    /// Whether this request would change durable state.
    ///
    /// Two of the four do, and they are the two mutations
    /// `automonique_store::context_memory` offers. Reads and writes would travel
    /// the same lane and a daemon would fence both the same way, so this exists
    /// for callers that log or meter the difference rather than for anything that
    /// decides it.
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::RecordMemory { .. } | Self::SupersedeMemory { .. }
        )
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal is
    /// outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, MemoryApiError> {
        match self {
            Self::RecordMemory { request_id, item } => Ok(Message::new(
                envelope(request_id.clone(), "record_memory")?,
                item.to_body(),
            )),
            Self::SupersedeMemory {
                request_id,
                correction,
            } => Ok(Message::new(
                envelope(request_id.clone(), "supersede_memory")?,
                correction.to_body(),
            )),
            Self::ListMemory { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "list_memory")?,
                query.to_body()?,
            )),
            Self::MemoryDetail { request_id, query } => Ok(Message::new(
                envelope(request_id.clone(), "memory_detail")?,
                query.to_body(),
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, MemoryApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "record_memory" => Ok(Self::RecordMemory {
                request_id,
                item: RecordMemory::from_body(message.body())?,
            }),
            "supersede_memory" => Ok(Self::SupersedeMemory {
                request_id,
                correction: SupersedeMemory::from_body(message.body())?,
            }),
            "list_memory" => Ok(Self::ListMemory {
                request_id,
                query: ListMemory::from_body(message.body())?,
            }),
            "memory_detail" => Ok(Self::MemoryDetail {
                request_id,
                query: MemoryDetail::from_body(message.body())?,
            }),
            _ => Err(MemoryApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the memory control API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryResponse {
    /// One item is durable. The receipt says whether this call wrote it.
    Recorded {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the durable row holds.
        receipt: MemoryReceiptView,
    },
    /// One correction is durable. The receipt says whether this call stamped it.
    Superseded {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// What the durable row holds.
        receipt: SupersessionReceiptView,
    },
    /// One page of a workspace's items.
    MemoryList {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The page.
        page: MemoryListPage,
    },
    /// One item in full, supersession stamp included.
    MemoryDetail {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// The item.
        item: MemoryDetailView,
    },
    /// The key is recorded with a different binding. Nothing was written, and
    /// nothing ever will be for this key.
    Conflict {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// First of label, digest and trust that differs.
        field: MemoryConflictField,
        /// What the durable row records.
        recorded: RecordedMemory,
    },
    /// The operation was refused. Nothing was written and nothing was read.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: MemoryRefusal,
    },
}

impl MemoryResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Recorded { request_id, .. }
            | Self::Superseded { request_id, .. }
            | Self::MemoryList { request_id, .. }
            | Self::MemoryDetail { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A delivered read is `completed`: there is no later completion to wait for.
    /// A durable write is `accepted` rather than `completed`, on a fresh write and
    /// on a replay alike, and the distinction is the honest one — the row *is*
    /// committed, but what the row records has not taken effect and cannot: no
    /// prompt assembler in this build consults it, and the trust class it carries
    /// gates nothing. `accepted` says "recorded"; `completed` would say the
    /// memory took effect, which would be a claim about a component this release
    /// does not contain.
    ///
    /// See [`OUTCOMES_THIS_PROTOCOL_NEVER_PRODUCES`] for the two this protocol
    /// cannot produce and why.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Recorded { .. } | Self::Superseded { .. } => ActionOutcome::Accepted,
            Self::MemoryList { .. } | Self::MemoryDetail { .. } => ActionOutcome::Completed,
            Self::Conflict { .. } => ActionOutcome::Conflict,
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Build the answer to a listing from the rows a store produced.
    ///
    /// This is the enforcement the module exists for: a page longer than the
    /// query asked for, or carrying an item recorded in a *different* workspace,
    /// is refused here rather than served. Either answer would look perfectly
    /// well-formed to a client and would silently contradict the question it
    /// asked — and a page that crossed the workspace would leak one project's
    /// memory into another project's listing, which is the one boundary this
    /// store has.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::PageAboveRequestedSize`] or
    /// [`MemoryApiError::PageOutsideWorkspace`].
    pub fn listing(
        request_id: RequestId,
        query: &ListMemory,
        page: MemoryListPage,
    ) -> Result<Self, MemoryApiError> {
        if page.entries().len() > query.page_size().get() {
            return Err(MemoryApiError::PageAboveRequestedSize {
                requested: query.page_size().get(),
                actual_items: page.entries().len(),
            });
        }
        if page
            .entries()
            .iter()
            .any(|item| item.workspace() != query.workspace())
        {
            return Err(MemoryApiError::PageOutsideWorkspace);
        }
        Ok(Self::MemoryList { request_id, page })
    }

    /// Report a key recorded with a different binding.
    ///
    /// The differing field is **derived** here rather than asserted by the
    /// caller: the three binding fields are compared in the order
    /// `automonique_store::context_memory` compares them and the first difference
    /// is the one reported, so this answer cannot name a field the two bindings
    /// agree on.
    ///
    /// The decoder cannot re-derive it, because a conflict carries only the
    /// recorded side — repeating the caller's own payload back would be an echo
    /// rather than information. [`MemoryResponse::from_canonical_bytes`]
    /// therefore validates what a decoder can: a closed field spelling, a written
    /// row identity, and bounded coordinates.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryApiError::UnwrittenRow`] for a zero `entry_id` and
    /// [`MemoryApiError::ConflictWithoutDisagreement`] when the presented and
    /// recorded bindings agree on all three fields — which is an exact replay,
    /// and answering a conflict would tell a caller its item collided with
    /// itself.
    pub fn conflict(
        request_id: RequestId,
        presented: &RecordMemory,
        recorded: RecordedMemory,
    ) -> Result<Self, MemoryApiError> {
        if recorded.entry_id == 0 {
            return Err(MemoryApiError::UnwrittenRow { field: "entry_id" });
        }
        let field = if recorded.label != *presented.label() {
            MemoryConflictField::Label
        } else if recorded.content_digest != *presented.content_digest() {
            MemoryConflictField::ContentDigest
        } else if recorded.trust != presented.trust() {
            MemoryConflictField::TrustClass
        } else {
            return Err(MemoryApiError::ConflictWithoutDisagreement);
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
    /// Returns a typed refusal if a counter or a compile-time envelope literal is
    /// outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, MemoryApiError> {
        match self {
            Self::Recorded {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "memory_recorded")?,
                receipt.to_body()?,
            )),
            Self::Superseded {
                request_id,
                receipt,
            } => Ok(Message::new(
                envelope(request_id.clone(), "memory_superseded")?,
                receipt.to_body()?,
            )),
            Self::MemoryList { request_id, page } => Ok(Message::new(
                envelope(request_id.clone(), "memory_list_result")?,
                page.to_body()?,
            )),
            Self::MemoryDetail { request_id, item } => Ok(Message::new(
                envelope(request_id.clone(), "memory_detail_result")?,
                item.to_body()?,
            )),
            Self::Conflict {
                request_id,
                field,
                recorded,
            } => Ok(Message::new(
                envelope(request_id.clone(), "memory_conflict")?,
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
                        "recorded_digest".to_owned(),
                        JsonValue::String(recorded.content_digest.as_str().to_owned()),
                    ),
                    (
                        "recorded_label".to_owned(),
                        JsonValue::String(recorded.label.as_str().to_owned()),
                    ),
                    (
                        "recorded_trust".to_owned(),
                        JsonValue::String(recorded.trust.as_str().to_owned()),
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
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, MemoryApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "memory_recorded" => Ok(Self::Recorded {
                request_id,
                receipt: MemoryReceiptView::from_body(message.body())?,
            }),
            "memory_superseded" => Ok(Self::Superseded {
                request_id,
                receipt: SupersessionReceiptView::from_body(message.body())?,
            }),
            "memory_list_result" => Ok(Self::MemoryList {
                request_id,
                page: MemoryListPage::from_body(message.body())?,
            }),
            "memory_detail_result" => Ok(Self::MemoryDetail {
                request_id,
                item: MemoryDetailView::from_body(message.body())?,
            }),
            "memory_conflict" => {
                exact_fields(
                    message.body(),
                    &[
                        "entry_id",
                        "field",
                        "recorded_digest",
                        "recorded_label",
                        "recorded_trust",
                    ],
                )?;
                let entry_id = unsigned(message.body(), "entry_id")?;
                if entry_id == 0 {
                    return Err(MemoryApiError::UnwrittenRow { field: "entry_id" });
                }
                Ok(Self::Conflict {
                    request_id,
                    field: decode_security_enum::<MemoryConflictField>(&required_string(
                        message.body(),
                        "field",
                    )?)?,
                    recorded: RecordedMemory {
                        entry_id,
                        label: MemoryLabel::new(required_string(
                            message.body(),
                            "recorded_label",
                        )?)?,
                        content_digest: ContentDigest::recorded(required_string(
                            message.body(),
                            "recorded_digest",
                        )?)?,
                        trust: decode_memory_trust(&required_string(
                            message.body(),
                            "recorded_trust",
                        )?)?,
                    },
                })
            }
            "refused" => {
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<MemoryRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(MemoryApiError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, MemoryApiError> {
    Ok(Envelope::new(
        ProtocolName::new(MEMORY_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, MemoryApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(MEMORY_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

/// The grammar every bounded field on this protocol shares.
///
/// Non-empty, at most [`MAX_MEMORY_API_FIELD_BYTES`] bytes, no control
/// characters: the grammar [`crate::context`] applies to every context field, at
/// the same ceiling.
fn bounded(value: &str, field: &'static str) -> Result<(), MemoryApiError> {
    let error = if value.is_empty() {
        ValueError::Empty
    } else if value.len() > MAX_MEMORY_API_FIELD_BYTES {
        ValueError::TooLong {
            max_bytes: MAX_MEMORY_API_FIELD_BYTES,
            actual_bytes: value.len(),
        }
    } else if value.chars().any(char::is_control) {
        ValueError::ControlCharacter
    } else {
        return Ok(());
    };
    Err(MemoryApiError::Field { field, error })
}

/// The page size a listing body declares, judged against this protocol's bound.
fn page_size(body: &JsonValue) -> Result<MemoryPageSize, MemoryApiError> {
    MemoryPageSize::new(usize::try_from(unsigned(body, "page_size")?).map_err(|_| {
        MemoryApiError::PageSizeOutOfRange {
            max_items: MAX_MEMORY_PAGE_ITEMS,
            requested: MAX_MEMORY_PAGE_ITEMS.saturating_add(1),
        }
    })?)
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, MemoryApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| MemoryApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, MemoryApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(MemoryApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| MemoryApiError::InvalidBody)
}

fn signed(body: &JsonValue, field: &'static str) -> Result<i64, MemoryApiError> {
    body.get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(MemoryApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, MemoryApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(MemoryApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), MemoryApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(MemoryApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(MemoryApiError::InvalidBody);
    }
    Ok(())
}
