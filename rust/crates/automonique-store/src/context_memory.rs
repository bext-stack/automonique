// SPDX-License-Identifier: Elastic-2.0

//! Durable custody of workspace-scoped memory items: that a memory was
//! captured, what trust class it carries, and which content it binds.
//!
//! `docs/product-plan/requirements/context-memory-and-learning.md` lists
//! "memory snapshots and retrieved session evidence" among the ordered, hashed
//! components every turn's `ContextManifest` persists, and says of every
//! component that it "has source, trust class, byte/token cap, redaction result
//! and content digest". `automonique_protocol::context` models all of that as
//! values: `SuppliedComponent` carries a `TrustClass` and a digest,
//! `MemoryEntry` carries provenance and classifications, `CandidateMemory` and
//! `LearningProposal` carry suggestions. Every one of them lives in memory.
//! Restart the process and no record survives that any memory was ever
//! captured, which makes "memory" a property of one process's heap.
//!
//! This module is the durable half of one slice of that epic. One row per
//! memory item:
//!
//! ```text
//! (workspace, memory_key) -> (label, content_digest, trust_class, created_at_ms)
//! ```
//!
//! and it answers a recording three ways and only three ways:
//!
//! - the pair is new: the item is recorded, [`MemoryDisposition::Recorded`];
//! - the pair is present with the *same* label, digest and trust class: it is an
//!   exact replay, [`MemoryDisposition::AlreadyRecorded`], and not one byte of
//!   the durable row changes;
//! - the pair is present with any of those three differing:
//!   [`ContextMemoryError::Conflict`] naming the first field that differs, and
//!   nothing is written.
//!
//! There is no IO here, no clock and no protocol dependency. Callers supply
//! every identifier and timestamp, so retries stay deterministic and tests do
//! not depend on an ambient clock.
//!
//! # What a row establishes, and what it does not
//!
//! **A row is evidence that a memory item was captured under a workspace, at a
//! declared trust class, binding the content named by `content_digest`.** That
//! is the whole of it. In particular:
//!
//! - **It does not store the memory.** `content_digest` names content; the
//!   content lives elsewhere. This is the trade [`crate::provider_journal`] and
//!   [`crate::slack_ingress`] already make for values they bind without storing,
//!   and it is the sharper choice here: the requirement puts memory content
//!   under sensitivity, visibility, retention and legal-hold rules that this
//!   module implements none of, so holding the bytes would be claiming a custody
//!   it cannot honour. A digest is a claim about content, not the content.
//! - **It does not enforce the trust class.** A row recorded `untrusted` does
//!   not stop anything from putting that memory into a prompt, and an
//!   `actor_supplied` row permits nothing. Precedence — "a lower-trust
//!   repository or retrieved document can supply task context but cannot
//!   override system, tenant, sandbox or approval policy" — is enforced
//!   structurally in `automonique_protocol::context`, where memory is a
//!   `SuppliedComponent` and the manifest's policy slot cannot receive one. The
//!   row is written beside that boundary, never in front of it.
//! - **It does not retrieve, rank or learn.** Nothing here searches, scores,
//!   embeds, consolidates or proposes. See the list of unbuilt parts below.
//! - **It does not verify the capture.** `label` and `content_digest` are
//!   recorded exactly as supplied; this module cannot recompute a digest over
//!   content it never sees, and does not claim the digest is the digest *of*
//!   anything.
//!
//! # Write-once, and why a correction is a new key
//!
//! The recorded binding — `label`, `content_digest`, `trust_class`,
//! `created_at_ms` — is **write-once**. There is no update path for any of it:
//! [`ContextMemoryStore::record`] either inserts a new row or touches nothing at
//! all.
//!
//! That follows the requirement rather than a preference. The memory model says
//! "Corrections supersede; deletion follows retention/legal-hold rules", and
//! `automonique_protocol::context::MemoryEntry::supersede_with` implements
//! exactly that shape in values: it "returns a new value rather than mutating,
//! so the corrected entry stays addressable and the audit trail survives". A
//! memory item whose digest could be rewritten in place would let the record of
//! what was actually captured disappear into the record of what somebody later
//! wished had been captured, and the epic's exit gate asks that every memory
//! mutation be "inspectable, reversible where promised" — neither is possible
//! over a row that can be edited to look like it always said something else.
//!
//! So [`crate::approval_ledger`]'s write-once discipline is the analogue this
//! module follows, and not [`crate::automation_store`]'s revision-checked
//! update. The distinction between them is whether the durable row is a *record
//! of an event* or a *description of current state*: an automation's enablement
//! is state, and moving it along a lattice is the point; a captured memory is an
//! event, and the corrected version of it is a different event. Correcting a
//! memory is therefore a **new** row under a new `memory_key`, and the old row
//! stays exactly as it was.
//!
//! ## The one amendment: a supersession stamp
//!
//! Write-once here means the *binding* is write-once, not that the row is frozen
//! forever, because a supersession that nothing records leaves a reader unable
//! to tell a current memory from a corrected one. `MemoryEntry` carries
//! `superseded_by` for that reason, and refuses to re-point an entry that
//! already names a replacement, "because that would rewrite the supersession
//! history rather than extend it" — its `ContextError::AlreadySuperseded`.
//!
//! [`ContextMemoryStore::supersede`] is the durable form of that one move, and
//! it is deliberately the *only* mutation this module offers:
//!
//! - it writes `superseded_by` and `superseded_at_ms`, and nothing else;
//! - it is one-way. A stamped row is never unstamped, and there is no method
//!   that would;
//! - it is one-time. Naming the same replacement again is an exact replay,
//!   [`MemoryDisposition::AlreadyRecorded`], writing nothing; naming a
//!   *different* one is [`ContextMemoryError::AlreadySuperseded`], writing
//!   nothing;
//! - the replacement must already be recorded **in the same workspace**, because
//!   a correction that names nothing is not a correction, and one that names a
//!   row in another workspace is a cross-workspace edge this store does not
//!   admit. Callers record the replacement first.
//!
//! The `revision` column is what makes this a property of the table rather than
//! a promise of this file: a database CHECK pins it to `1` or `2`, couples `1`
//! to an unstamped row and `2` to a stamped one, and admits no third value — so
//! the row has exactly one possible second write and no third. Anything else
//! stored there is [`ContextMemoryError::Corrupt`].
//!
//! What this does *not* record is who superseded the item or why. Attribution
//! and cause belong to the typed memory service the requirement describes, whose
//! writes are "revisioned proposals governed by actor/tenant policy"; recording
//! an actor here would be an authority claim nothing checks, the same refusal
//! [`crate::automation_store`] makes about an approved-effect scope.
//!
//! # The trust vocabulary, and the missing fourth class
//!
//! [`MemoryTrust`] is three-valued and closed: `untrusted`, `compatibility` and
//! `actor_supplied`, ordered least to most trusted, exactly the declaration
//! order and exactly the spellings of
//! `automonique_protocol::context::TrustClass`.
//!
//! **`policy` is absent, and its absence is the point.** `TrustClass::Policy` is
//! documented there as "Tenant or system policy. Only a policy component may
//! carry this", and memory is not one: it enters a manifest as
//! `SuppliedClass::Memory`, and `SuppliedComponent::new` refuses policy trust to
//! any supplied component. The requirement states the same rule twice — a
//! lower-trust document "cannot override system, tenant, sandbox or approval
//! policy", and "prompt injection can only propose lower-trust memory and cannot
//! promote itself to policy". A memory item at policy trust is therefore not a
//! value this module can hold: the enum has no such variant, and a stored
//! `'policy'` string is [`ContextMemoryError::Corrupt`], refused by a column
//! CHECK on the way in and by the read path if it got in anyway.
//!
//! There is one deliberate divergence from the protocol worth naming rather than
//! glossing. `SuppliedComponent::new` *lowers* a requested `Policy` to
//! `ActorSupplied` and proceeds; this module cannot be handed one at all. That
//! is not this module being stricter for its own sake: lowering is a
//! manifest-assembly decision that stays visible in the manifest a client
//! renders, whereas a durable row that quietly said `actor_supplied` when its
//! writer said `policy` would be a permanent record of a claim nobody made. The
//! caller decides what a rejected promotion becomes; the store does not decide
//! it for them by writing something else down.
//!
//! ## How far this pin reaches
//!
//! The pin is a literal one, and the gap in it is stated exactly. This crate
//! does not depend on `automonique-protocol` — its dependencies are `nix` and
//! `rusqlite` — so no compile-time link exists and the agreement has to be
//! asserted rather than derived. The authority for these three words, the order
//! they are in, and the absence of a fourth is
//! `automonique_protocol::context::TrustClass` together with
//! `SuppliedClass::Memory`, whose `as_str` is the `"memory"` component-class
//! word this module's rows are the durable half of. `tests/context_memory.rs`
//! pins the spellings from the other side, so a rename in either place fails a
//! test rather than landing.
//!
//! # Workspace scope
//!
//! `memory_key` is unique **within a workspace**, not host-wide. Two workspaces
//! recording the same key hold two independent items, and neither can read,
//! collide with or supersede the other's. That is the requirement's "Rules from
//! parent/home directories never leak into unrelated projects" written into a
//! key: a store where `memory_key` were globally unique would let one project's
//! lesson answer another project's lookup.
//!
//! `workspace` is the named-workspace identity
//! `automonique_protocol::context::ContextReference::Workspace` carries — a
//! `ContextLabel`, an opaque name — and **not** a `WorkspacePath`. Nothing here
//! resolves it to a directory, and the discovery bound the requirement puts on
//! project rules is the resolver's rule, not this table's. What the column does
//! is partition the row space; what it does not do is prove that two callers
//! saying `"acme/api"` mean the same directory.
//!
//! It is also not a tenant. The requirement's memory model is "typed,
//! tenant-scoped stores", and this slice implements one of the six —
//! `workspace_memory` — with no tenant column at all. The honest consequence:
//! two tenants that use the same workspace name share a row space here, so a
//! deployment with more than one tenant needs the tenant folded into the
//! workspace name it presents, or this table split per tenant, until the tenant
//! becomes a column.
//!
//! # What this module is not, named part by part
//!
//! The epic is large and this is one durable slice of it. None of the following
//! is built here, and no row implies any of it exists:
//!
//! - **The context manifest.** No `ContextManifest`, no component ordering, no
//!   precedence evaluation, no policy revision, no `SuppliedComponent` rows. A
//!   memory item is not a manifest component; it is what one would be assembled
//!   from.
//! - **Budgets, caching and compression.** No byte/token caps, no estimated or
//!   provider-reported token accounting, no prompt-cache telemetry, no
//!   compression lineage, no protected facts, no verification status, no forks.
//! - **Redaction.** No `RedactionOutcome` column, no secret scan, no
//!   materialization. The requirement gives every component a redaction result;
//!   this row does not carry one, so a reader must not treat a stored item as
//!   scanned.
//! - **Retrieval.** No FTS5 index, no authorization filters, no
//!   surrounding-message navigation, no citations, no semantic or vector search,
//!   and no external-provider adapters (Honcho, Mem0, RetainDB or any other).
//!   [`ContextMemoryStore::page`] lists a workspace's rows in recording order;
//!   it is not a search.
//! - **The other five memory stores.** No `user_profile`, `team_memory`,
//!   `task_memory` or `episodic_index`, and no external provider records. There
//!   is no store-kind column, so a caller cannot use these rows to stand in for
//!   one of the others.
//! - **The classifications.** No provenance, confidence, sensitivity,
//!   visibility, expiry or review date, and no legal hold. The protocol requires
//!   all of them on a `MemoryEntry`; this table records none of them, which is
//!   why nothing here may be presented as a complete memory entry.
//! - **Deletion.** No delete, no tombstone, no retention sweep, no prune. The
//!   requirement routes deletion through retention and legal-hold rules this
//!   module cannot evaluate, so it offers no way to try.
//! - **The learning loop.** No `LearningProposal`, no candidate memories, no
//!   review policy, no sandboxed trial, no auto-accept, no skills of any kind,
//!   and no curator: no use/view/patch counts, no staleness, no archive,
//!   restore, pin, back up or consolidation.
//! - **The learning-journey graph.** No nodes, no edges, no revisioned graph of
//!   memories, sessions, corrections and outcomes. [`MemoryItem::superseded_by`]
//!   is a single link between two rows of this one table, and reconstructing a
//!   chain from it is the caller's walk; it is not a graph service and there is
//!   no traversal here.
//!
//! # Bounds
//!
//! `workspace`, `memory_key` and `label` share the grammar
//! `automonique_protocol::context`'s own `bounded` applies to every context
//! field: non-empty, at most [`MAX_MEMORY_FIELD_BYTES`] bytes, no control
//! characters.
//!
//! That bound is `512`, deliberately wider than the `256` bytes
//! [`crate::approval_ledger`] and [`crate::automation_store`] use. Those are the
//! store's own default for names it mints; these three are protocol context
//! fields, and `MAX_CONTEXT_FIELD_BYTES` is `512`, so a narrower bound here
//! would refuse a `ContextLabel` the protocol accepts — the store would drop
//! values the rest of the product considers well-formed.
//!
//! `content_digest` is exactly [`CONTENT_DIGEST_CHARS`] lowercase hexadecimal
//! digits: a bare SHA-256, the spelling [`crate::run_submissions`],
//! [`crate::provider_journal`] and [`crate::slack_ingress`] already store.
//! Uppercase is refused rather than folded, so one digest has exactly one stored
//! spelling and a byte comparison of two rows means what it looks like. Note
//! that the protocol's digests are opaque `ContextLabel`s written `"sha256:c"`;
//! this column is narrower on purpose, and a caller carrying a prefixed digest
//! strips the prefix before recording it.
//!
//! # Capacity, and the absence of a prune
//!
//! Capacity is [`ContextMemoryError::StoreFull`], never an eviction, and there
//! is no prune. [`crate::cancel_ledger`] has one and states its cost; here that
//! cost is not payable, because a memory item is evidence of what a turn was
//! assembled from. Forgetting the row would not delete the memory — the content
//! it binds lives elsewhere — it would only destroy the record of its trust
//! class, leaving content in circulation with nothing durable saying how far it
//! was ever meant to be trusted.
//!
//! [`MAX_MEMORY_ITEMS`] is therefore a hard ceiling on the lifetime of one
//! database file, not a high-water mark. A full store refuses new items while
//! still replaying, superseding and reading every item it holds, because none of
//! those adds a row.
//!
//! # Storage discipline
//!
//! The store owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::approval_ledger`],
//! [`crate::automation_store`] and [`crate::run_index`] do. Every mutation is
//! one immediate transaction, so a reader after a crash sees the whole row or no
//! row. Every read re-validates the row it loaded rather than trusting the
//! database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only context memory schema this build can read and write.
pub const CONTEXT_MEMORY_SCHEMA_VERSION: u32 = 1;

/// Largest number of memory items any store will hold.
///
/// Nothing deletes from this table and there is no prune, so this is a hard
/// ceiling on the lifetime of one database file rather than a high-water mark.
/// Superseding an item frees no room, which is the honest consequence of keeping
/// the corrected item addressable.
pub const MAX_MEMORY_ITEMS: usize = 65_536;

/// Longest accepted `workspace`, `memory_key` or `label`, in bytes.
///
/// The grammar `automonique_protocol::context` applies to every context field:
/// non-empty, at most this many bytes, no control characters. The number is that
/// crate's `MAX_CONTEXT_FIELD_BYTES`, not the 256-byte default the rest of this
/// store uses for names it mints; see the module documentation for why a
/// narrower bound here would refuse values the protocol accepts.
pub const MAX_MEMORY_FIELD_BYTES: usize = 512;

/// Exact character count of a lowercase hex SHA-256 content digest.
pub const CONTENT_DIGEST_CHARS: usize = 64;

/// Largest page [`ContextMemoryStore::page`] will return.
pub const MAX_MEMORY_PAGE: usize = 512;

/// Schema v1.
///
/// The invariants a second writer must not be able to break are database
/// constraints: one row per `(workspace, memory_key)`, the closed three-word
/// trust vocabulary with no policy spelling in it, a 64-character lowercase hex
/// digest, a non-negative capture instant, and the coupling that gives a row
/// exactly two possible states — recorded at revision one with no supersession,
/// or superseded at revision two with both supersession columns present.
///
/// Every comparison inside the coupling CHECK is guarded by an `IS NOT NULL` on
/// the same nullable column first. A CHECK that evaluates to NULL passes in
/// SQLite, so a comparison reached with a NULL operand is a constraint that
/// silently admits the row it was written to refuse.
///
/// The identifier grammar, the length bound and the rule that a replacement is
/// neither the item itself nor a row in another workspace are deliberately *not*
/// database constraints: they are enforced on write and re-checked on every
/// read, so a row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE memory_items (
    entry_id INTEGER PRIMARY KEY,
    workspace TEXT NOT NULL,
    memory_key TEXT NOT NULL,
    label TEXT NOT NULL,
    content_digest TEXT NOT NULL CHECK (
        length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'
    ),
    trust_class TEXT NOT NULL CHECK (
        trust_class IN ('untrusted', 'compatibility', 'actor_supplied')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    superseded_by TEXT,
    superseded_at_ms INTEGER,
    revision INTEGER NOT NULL CHECK (revision IN (1, 2)),
    UNIQUE (workspace, memory_key),
    CHECK (
        (revision = 1 AND superseded_by IS NULL AND superseded_at_ms IS NULL)
        OR
        (revision = 2
         AND superseded_by IS NOT NULL AND length(superseded_by) > 0
         AND superseded_at_ms IS NOT NULL AND superseded_at_ms >= 0)
    )
) STRICT;

CREATE INDEX memory_items_by_workspace ON memory_items(workspace, entry_id);
"#;

/// A context memory error with stable refusal categories.
#[derive(Debug)]
pub enum ContextMemoryError {
    /// The store path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The schema is absent from a non-empty database, or unsupported.
    SchemaVersion {
        /// Version found in the database.
        found: u32,
        /// Version this build implements.
        supported: u32,
    },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A recorded `(workspace, memory_key)` was presented with a different
    /// binding.
    ///
    /// Nothing was written, and nothing ever will be for this key: the binding
    /// is write-once, and a memory that has genuinely changed is a new key. The
    /// recorded binding travels with the refusal so a caller learns what it
    /// collided with without a second read.
    Conflict {
        /// First field that differs: `label`, `content_digest` or
        /// `trust_class`.
        field: &'static str,
        /// Row the durable item occupies.
        entry_id: i64,
        /// Label the durable row records.
        recorded_label: String,
        /// Content digest the durable row records.
        recorded_digest: String,
        /// Trust class the durable row records.
        recorded_trust: MemoryTrust,
    },
    /// The referenced durable row does not exist: `item` or `replacement`.
    NotFound(&'static str),
    /// A superseded item was presented with a different replacement.
    ///
    /// Nothing was written. A supersession is stamped once and never
    /// re-pointed, because re-pointing rewrites the supersession history rather
    /// than extending it; the protocol's `ContextError::AlreadySuperseded`
    /// refuses the same move over values.
    AlreadySuperseded {
        /// Row the durable item occupies.
        entry_id: i64,
        /// Replacement the durable row already names.
        recorded_replacement: String,
        /// When the durable supersession was stamped.
        recorded_at_ms: i64,
    },
    /// A page was requested from a cursor above everything recorded.
    ///
    /// An empty page is a different answer and is never reported this way.
    CursorOutOfRange {
        /// Cursor the caller presented.
        supplied: u64,
        /// Highest `entry_id` recorded, or zero when the store is empty.
        retained_last: u64,
    },
    /// The store holds its full capacity of memory items.
    ///
    /// Recording is refused rather than evicting an older item, and there is no
    /// prune. Replays, supersessions and reads are unaffected, because none of
    /// them adds a row.
    StoreFull {
        /// Capacity of the handle that refused.
        capacity: usize,
    },
    /// A stored row violates an invariant this API could only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private store.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl ContextMemoryError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::NotFound(_) => "not_found",
            Self::AlreadySuperseded { .. } => "already_superseded",
            Self::CursorOutOfRange { .. } => "cursor_out_of_range",
            Self::StoreFull { .. } => "store_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for ContextMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "context memory path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "context memory schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                entry_id,
                recorded_label,
                recorded_digest,
                recorded_trust,
            } => write!(
                formatter,
                "memory_key is already recorded at row {entry_id}: {recorded_label} \
                 binding {recorded_digest} at trust {}; {field} differs",
                recorded_trust.as_str()
            ),
            Self::NotFound(row) => write!(formatter, "durable row not found: {row}"),
            Self::AlreadySuperseded {
                entry_id,
                recorded_replacement,
                recorded_at_ms,
            } => write!(
                formatter,
                "row {entry_id} was superseded by {recorded_replacement} at \
                 {recorded_at_ms} and cannot be superseded again"
            ),
            Self::CursorOutOfRange {
                supplied,
                retained_last,
            } => write!(
                formatter,
                "cursor {supplied} is above the retained entry_id {retained_last}"
            ),
            Self::StoreFull { capacity } => {
                write!(formatter, "context memory holds its capacity of {capacity}")
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "context memory filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for ContextMemoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ContextMemoryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for ContextMemoryError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one context memory operation.
pub type Kept<T> = Result<T, ContextMemoryError>;

/// How far a memory item may be trusted.
///
/// Three variants, three spellings, ordered least to most trusted, and the set
/// is closed. There is deliberately no `policy`: memory reaches a manifest as
/// `automonique_protocol::context::SuppliedClass::Memory`, and supplied content
/// is never policy however it asks to be labelled. The module documentation
/// states exactly how far the pin to that crate's `TrustClass` reaches, where it
/// has to be a literal one, and why this module refuses a policy claim rather
/// than quietly lowering it.
///
/// The ordering is the protocol's declaration order, so `<` means "less
/// trusted". Nothing here promotes: there is no method that raises a trust
/// class, because "a component may never be promoted".
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryTrust {
    /// Model output and retrieved documents.
    Untrusted,
    /// Provider-specific rule files, labelled as compatibility inputs.
    Compatibility,
    /// Content the actor supplied directly, including workspace rules
    /// discovered in the shared `AGENTS.md` format.
    ActorSupplied,
}

impl MemoryTrust {
    /// Every class this store admits, least to most trusted, for coverage
    /// checks.
    pub const ALL: [Self; 3] = [Self::Untrusted, Self::Compatibility, Self::ActorSupplied];

    /// Stable machine-oriented spelling, and the exact stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Compatibility => "compatibility",
            Self::ActorSupplied => "actor_supplied",
        }
    }

    /// Parse the exact stored text, or nothing.
    ///
    /// `"policy"` parses to `None` like any other unknown word, which is what
    /// makes a smuggled policy row corruption rather than a fourth class.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|trust| trust.as_str() == value)
    }
}

impl fmt::Display for MemoryTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One memory item presented for durable recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryItemRecord<'a> {
    /// Workspace the item belongs to. Half of the unique key, and the only
    /// scope: an item is invisible to every other workspace.
    pub workspace: &'a str,
    /// Bounded opaque idempotency identity chosen by the caller. The other half
    /// of the unique key, unique within `workspace` and not host-wide.
    pub memory_key: &'a str,
    /// Bounded opaque name for what was captured. Part of the replay identity:
    /// the same key describing a different memory is a conflict, not a
    /// correction.
    pub label: &'a str,
    /// Lowercase hex SHA-256 of the memory's content. Never the content itself,
    /// which this module does not store; see the module documentation.
    pub content_digest: &'a str,
    /// How far the captured content may be trusted. Recorded, never enforced.
    pub trust: MemoryTrust,
    /// When the memory was captured, in caller-supplied milliseconds.
    ///
    /// Not part of the replay identity: a retry naturally carries a later
    /// clock, so a differing timestamp is an exact replay and never rewrites the
    /// recorded one. A caller that lost the answer to its first `record` and
    /// retries it should get the first answer back, not a refusal reporting a
    /// clock it never controlled.
    pub created_at_ms: i64,
}

/// One correction presented for durable stamping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupersessionRequest<'a> {
    /// Workspace both items belong to. A replacement in another workspace is
    /// [`ContextMemoryError::NotFound`], never a cross-workspace edge.
    pub workspace: &'a str,
    /// Item being corrected.
    pub memory_key: &'a str,
    /// Item that corrects it. Must already be recorded in the same workspace,
    /// and must not be `memory_key` itself.
    pub replacement_key: &'a str,
    /// When, in caller-supplied milliseconds.
    ///
    /// Not part of the replay identity, for the same reason
    /// [`MemoryItemRecord::created_at_ms`] is not.
    pub superseded_at_ms: i64,
}

/// How the store answered one write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryDisposition {
    /// The fact was new and is now durable.
    Recorded,
    /// The exact fact was already durable. Nothing changed.
    AlreadyRecorded,
}

impl MemoryDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }
}

impl fmt::Display for MemoryDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Durable identity of one recorded or replayed memory item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryReceipt {
    /// Row identity of the durable item. The pagination key.
    pub entry_id: i64,
    /// Whether this call wrote the row or found it.
    pub disposition: MemoryDisposition,
    /// The capture instant the durable row records.
    ///
    /// On a [`MemoryDisposition::AlreadyRecorded`] answer this is the *first*
    /// recording's instant, not the one this call supplied.
    pub created_at_ms: i64,
}

/// Durable identity of one stamped or replayed supersession.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupersessionReceipt {
    /// Row identity of the corrected item.
    pub entry_id: i64,
    /// Whether this call stamped the row or found it already stamped with the
    /// same replacement.
    pub disposition: MemoryDisposition,
    /// The supersession instant the durable row records. On a
    /// [`MemoryDisposition::AlreadyRecorded`] answer this is the first stamp's
    /// instant.
    pub superseded_at_ms: i64,
    /// Revision the row now carries, which is always `2`.
    ///
    /// Reported rather than assumed, so a caller that logs it keeps saying
    /// something true if a later schema gives the row a third state.
    pub revision: u64,
}

/// Validated `memory_items` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryItem {
    /// Row identity, monotonic in recording order across every workspace.
    pub entry_id: i64,
    /// Workspace the item belongs to.
    pub workspace: String,
    /// Durable idempotency identity, unique within `workspace`.
    pub memory_key: String,
    /// Bounded name for what was captured.
    pub label: String,
    /// Lowercase hex SHA-256 of the content this row binds without storing.
    pub content_digest: String,
    /// How far the captured content may be trusted. Recorded, never enforced.
    pub trust: MemoryTrust,
    /// When the memory was recorded as captured.
    pub created_at_ms: i64,
    /// Which item in this workspace corrected this one, if any.
    ///
    /// `None` does not mean the memory is still accurate; it means nothing has
    /// been recorded as correcting it.
    pub superseded_by: Option<String>,
    /// When the supersession was stamped. `Some` exactly when
    /// [`MemoryItem::superseded_by`] is.
    pub superseded_at_ms: Option<i64>,
    /// `1` while the item stands as recorded, `2` once it is superseded. There
    /// is no third value; anything else is corruption.
    pub revision: u64,
}

impl MemoryItem {
    /// Whether a correction has been recorded against this item.
    #[must_use]
    pub const fn is_superseded(&self) -> bool {
        self.superseded_by.is_some()
    }
}

/// One bounded page of a workspace's items, ordered by `entry_id`, oldest first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPage {
    /// Rows above the requested cursor, oldest first.
    pub entries: Vec<MemoryItem>,
    /// Cursor to present for the next page, or `None` when this page is the end
    /// of the query.
    ///
    /// Set only when a further matching row was seen, so an exhausted listing is
    /// distinguishable from one that merely filled its page.
    pub next_cursor: Option<u64>,
}

/// The window of `entry_id` values this store still holds, across every
/// workspace.
///
/// `first` is `1` in this release and in every release that keeps the no-prune
/// rule. It is reported rather than assumed so a caller keeps saying something
/// true if that ever changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedMemoryRange {
    /// Lowest `entry_id` still recorded.
    pub first: u64,
    /// Highest `entry_id` recorded.
    pub last: u64,
}

/// Durable, workspace-scoped custody of memory items.
#[derive(Debug)]
pub struct ContextMemoryStore {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl ContextMemoryStore {
    /// Open or initialize a store inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group and
    /// other access. Existing paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_MEMORY_ITEMS`].
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::InsecurePath`] for an unsafe path,
    /// [`ContextMemoryError::SchemaVersion`] for a foreign or future database,
    /// and the underlying I/O or SQLite failure otherwise.
    pub fn open(path: impl AsRef<Path>) -> Kept<Self> {
        Self::open_with_capacity(path, MAX_MEMORY_ITEMS)
    }

    /// Open a store with a lowered capacity.
    ///
    /// `capacity` must be between one and [`MAX_MEMORY_ITEMS`]. It is a property
    /// of this handle, not of the database: opening an existing store under a
    /// capacity below its row count refuses further recordings with
    /// [`ContextMemoryError::StoreFull`] while replays, supersessions and reads
    /// keep working, because none of those adds a row.
    ///
    /// # Errors
    ///
    /// As [`ContextMemoryStore::open`], plus
    /// [`ContextMemoryError::InvalidField`] for a capacity outside the range.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Kept<Self> {
        if capacity == 0 || capacity > MAX_MEMORY_ITEMS {
            return Err(ContextMemoryError::InvalidField("capacity"));
        }
        let path = path.as_ref();
        secure_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        secure_path(path)?;

        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, open_flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(ContextMemoryError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Item capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one memory item, write-once.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never half of one.
    ///
    /// The lookup precedes the capacity check, so an exact replay is still
    /// answered [`MemoryDisposition::AlreadyRecorded`] in a full store — a
    /// replay writes nothing and must never degrade into a refusal. A
    /// conflicting reuse is likewise [`ContextMemoryError::Conflict`] rather
    /// than [`ContextMemoryError::StoreFull`], because the reuse is a caller bug
    /// regardless of how full the store is.
    ///
    /// A superseded item still replays: the binding is what is compared, and a
    /// correction recorded later is a separate durable fact that does not make
    /// the original recording disagree with itself.
    ///
    /// The three identity fields are compared in declaration order and the first
    /// difference is the one reported, so a conflict names one field rather than
    /// a set.
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::InvalidField`] for a malformed field,
    /// [`ContextMemoryError::Conflict`] for a key presented with a different
    /// binding, [`ContextMemoryError::StoreFull`] at capacity, and
    /// [`ContextMemoryError::Corrupt`] when the existing row it must compare
    /// against is not one this API could have written.
    pub fn record(&mut self, item: MemoryItemRecord<'_>) -> Kept<MemoryReceipt> {
        validate_field(item.workspace, "workspace")?;
        validate_field(item.memory_key, "memory_key")?;
        validate_field(item.label, "label")?;
        validate_digest(item.content_digest, "content_digest")?;
        validate_time(item.created_at_ms, "created_at_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(durable) = read_item(&transaction, item.workspace, item.memory_key)? {
            return replay_or_conflict(&durable, &item);
        }
        let live = count_items(&transaction)?;
        if live >= self.capacity {
            return Err(ContextMemoryError::StoreFull {
                capacity: self.capacity,
            });
        }
        transaction.execute(
            "INSERT INTO memory_items
             (workspace, memory_key, label, content_digest, trust_class,
              created_at_ms, superseded_by, superseded_at_ms, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, 1)",
            params![
                item.workspace,
                item.memory_key,
                item.label,
                item.content_digest,
                item.trust.as_str(),
                item.created_at_ms,
            ],
        )?;
        let entry_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(MemoryReceipt {
            entry_id,
            disposition: MemoryDisposition::Recorded,
            created_at_ms: item.created_at_ms,
        })
    }

    /// Stamp one item as corrected by another in the same workspace.
    ///
    /// The only mutation this module offers, and it writes exactly two columns.
    /// The binding recorded by [`ContextMemoryStore::record`] is never touched:
    /// after a supersession the corrected item still reads back with the label,
    /// digest, trust class and instant it was captured with.
    ///
    /// One immediate transaction, and the guard is repeated in the `UPDATE`
    /// itself, so a row that moved between the read and the write cannot be
    /// stamped twice even if a caller reached here having read revision one.
    ///
    /// Stamping the same replacement again is an exact replay,
    /// [`MemoryDisposition::AlreadyRecorded`], and writes nothing. Naming a
    /// different one is [`ContextMemoryError::AlreadySuperseded`] and also
    /// writes nothing: a supersession extends the history, it never rewrites it.
    ///
    /// What this call establishes is that a correction was recorded. It does not
    /// establish that the correction is right, that anything stopped using the
    /// superseded memory, or who asked for it; see the module documentation.
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::InvalidField`] for a malformed field or a
    /// replacement naming the item itself, [`ContextMemoryError::NotFound`] when
    /// the item or its replacement is not recorded in this workspace,
    /// [`ContextMemoryError::AlreadySuperseded`] for a differing replacement,
    /// and [`ContextMemoryError::Corrupt`] when the stored row is not one this
    /// API could have written.
    pub fn supersede(&mut self, request: SupersessionRequest<'_>) -> Kept<SupersessionReceipt> {
        validate_field(request.workspace, "workspace")?;
        validate_field(request.memory_key, "memory_key")?;
        validate_field(request.replacement_key, "replacement_key")?;
        validate_time(request.superseded_at_ms, "superseded_at_ms")?;
        if request.replacement_key == request.memory_key {
            return Err(ContextMemoryError::InvalidField("replacement_key"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let durable = read_item(&transaction, request.workspace, request.memory_key)?
            .ok_or(ContextMemoryError::NotFound("item"))?;
        if let Some(recorded) = durable.superseded_by.as_deref() {
            let recorded_at_ms = durable
                .superseded_at_ms
                .ok_or_else(|| corrupt("supersession"))?;
            if recorded != request.replacement_key {
                return Err(ContextMemoryError::AlreadySuperseded {
                    entry_id: durable.entry_id,
                    recorded_replacement: recorded.to_owned(),
                    recorded_at_ms,
                });
            }
            return Ok(SupersessionReceipt {
                entry_id: durable.entry_id,
                disposition: MemoryDisposition::AlreadyRecorded,
                superseded_at_ms: recorded_at_ms,
                revision: durable.revision,
            });
        }
        // The replacement is read, not merely named: a correction that points at
        // nothing is not a correction, and the workspace is part of the lookup
        // so a replacement recorded elsewhere is absent rather than borrowed.
        if read_item(&transaction, request.workspace, request.replacement_key)?.is_none() {
            return Err(ContextMemoryError::NotFound("replacement"));
        }
        let changed = transaction.execute(
            "UPDATE memory_items
             SET superseded_by = ?2, superseded_at_ms = ?3, revision = 2
             WHERE entry_id = ?1 AND revision = 1 AND superseded_by IS NULL",
            params![
                durable.entry_id,
                request.replacement_key,
                request.superseded_at_ms,
            ],
        )?;
        if changed != 1 {
            // The row was read inside this immediate transaction, so nothing
            // else can have stamped it; a disagreement means the stored row is
            // not what this API writes.
            return Err(corrupt("supersession"));
        }
        transaction.commit()?;
        Ok(SupersessionReceipt {
            entry_id: durable.entry_id,
            disposition: MemoryDisposition::Recorded,
            superseded_at_ms: request.superseded_at_ms,
            revision: 2,
        })
    }

    /// The validated item one key holds in one workspace, if any.
    ///
    /// `None` means nothing was recorded under this key *in this workspace*. The
    /// same key may be recorded in another workspace and this answer will not
    /// mention it, which is the whole point of the scope.
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::InvalidField`] for a malformed field and
    /// [`ContextMemoryError::Corrupt`] for a row this API could not have
    /// written.
    pub fn item(&self, workspace: &str, memory_key: &str) -> Kept<Option<MemoryItem>> {
        validate_field(workspace, "workspace")?;
        validate_field(memory_key, "memory_key")?;
        read_item(&self.connection, workspace, memory_key)
    }

    /// One bounded page of a workspace's items, ordered by `entry_id`, oldest
    /// first.
    ///
    /// `cursor` names the row to resume *after*; pass `0` to start at the
    /// beginning, and to advance, pass [`MemoryPage::next_cursor`]. `limit` must
    /// be between one and [`MAX_MEMORY_PAGE`].
    ///
    /// Superseded items are listed like any other. This is a record of what was
    /// captured, not a view of what is current, and a listing that hid corrected
    /// items would make the correction look like a deletion.
    ///
    /// The cursor is judged against the whole store, not against one workspace's
    /// subset: a cursor is a position in the listing order, and a row another
    /// workspace occupies must not turn a resumable cursor into a refusal.
    ///
    /// The workspace filter is an equality on an opaque column rather than a
    /// membership test over a closed vocabulary, so there is no spelling a
    /// corrupt row could fall outside of to be silently dropped from a listing. A
    /// row this workspace selects is validated like any other and refused as
    /// [`ContextMemoryError::Corrupt`] if it is not one this API wrote; a row
    /// another workspace selects was never this query's answer.
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::InvalidField`] for a malformed workspace or
    /// a limit outside its range, [`ContextMemoryError::CursorOutOfRange`] for a
    /// cursor above everything recorded, and [`ContextMemoryError::Corrupt`] for
    /// a row this API could not have written.
    pub fn page(&self, workspace: &str, cursor: u64, limit: usize) -> Kept<MemoryPage> {
        validate_field(workspace, "workspace")?;
        if limit == 0 || limit > MAX_MEMORY_PAGE {
            return Err(ContextMemoryError::InvalidField("limit"));
        }
        let after = to_db_u64(cursor, "cursor")?;
        let page = i64::try_from(limit).map_err(|_| ContextMemoryError::InvalidField("limit"))?;
        let lookahead = page
            .checked_add(1)
            .ok_or(ContextMemoryError::InvalidField("limit"))?;

        let transaction = self.connection.unchecked_transaction()?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(entry_id), 0) FROM memory_items",
            [],
            |row| row.get(0),
        )?;
        let retained_last = from_db_u64(highest, "entry_id").map_err(|_| corrupt("entry_id"))?;
        if cursor > retained_last {
            return Err(ContextMemoryError::CursorOutOfRange {
                supplied: cursor,
                retained_last,
            });
        }

        let mut statement = transaction.prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM memory_items
             WHERE entry_id > ?1 AND workspace = ?3
             ORDER BY entry_id LIMIT ?2"
        ))?;
        let mut entries = Vec::new();
        {
            let rows = statement.query_map(params![after, lookahead, workspace], raw_item)?;
            for raw in rows {
                entries.push(validated_item(raw?)?);
            }
        }
        drop(statement);
        transaction.rollback()?;

        let next_cursor = if entries.len() > limit {
            entries.truncate(limit);
            let last = entries.last().ok_or_else(|| corrupt("entry_id"))?.entry_id;
            Some(from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?)
        } else {
            None
        };
        Ok(MemoryPage {
            entries,
            next_cursor,
        })
    }

    /// The window of `entry_id` values this store holds, or `None` when empty.
    ///
    /// Host-wide across every workspace, because `entry_id` is: it describes the
    /// database file, not one workspace's slice of it.
    ///
    /// An empty store has no retained window, and reporting `(0, 0)` would name a
    /// row no writer produced.
    ///
    /// # Errors
    ///
    /// Returns [`ContextMemoryError::Corrupt`] for a stored bound outside the
    /// representable range.
    pub fn retained_range(&self) -> Kept<Option<RetainedMemoryRange>> {
        let bounds: (Option<i64>, Option<i64>) = self.connection.query_row(
            "SELECT MIN(entry_id), MAX(entry_id) FROM memory_items",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        match bounds {
            (Some(first), Some(last)) => {
                let first = checked_row_id(first, "entry_id")?;
                let last = checked_row_id(last, "entry_id")?;
                if last < first {
                    return Err(corrupt("entry_id"));
                }
                Ok(Some(RetainedMemoryRange {
                    first: from_db_u64(first, "entry_id").map_err(|_| corrupt("entry_id"))?,
                    last: from_db_u64(last, "entry_id").map_err(|_| corrupt("entry_id"))?,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(corrupt("entry_id")),
        }
    }

    /// Count durable memory items across every workspace.
    ///
    /// This is the number capacity is judged against, which is why it is not
    /// workspace-scoped: the ceiling belongs to the database file.
    ///
    /// # Errors
    ///
    /// Returns the SQLite failure, or [`ContextMemoryError::Corrupt`] for a
    /// count outside the representable range.
    pub fn item_count(&self) -> Kept<usize> {
        count_items(&self.connection)
    }
}

/// Answer a key that is already recorded: exact replay, or the first field that
/// differs.
///
/// `created_at_ms` is not compared; see [`MemoryItemRecord::created_at_ms`] for
/// why a later clock on a retry is a replay rather than a conflict.
fn replay_or_conflict(
    durable: &MemoryItem,
    presented: &MemoryItemRecord<'_>,
) -> Kept<MemoryReceipt> {
    let differing = if durable.label != presented.label {
        Some("label")
    } else if durable.content_digest != presented.content_digest {
        Some("content_digest")
    } else if durable.trust != presented.trust {
        Some("trust_class")
    } else {
        None
    };
    if let Some(field) = differing {
        return Err(ContextMemoryError::Conflict {
            field,
            entry_id: durable.entry_id,
            recorded_label: durable.label.clone(),
            recorded_digest: durable.content_digest.clone(),
            recorded_trust: durable.trust,
        });
    }
    Ok(MemoryReceipt {
        entry_id: durable.entry_id,
        disposition: MemoryDisposition::AlreadyRecorded,
        created_at_ms: durable.created_at_ms,
    })
}

struct RawItem {
    entry_id: i64,
    workspace: String,
    memory_key: String,
    label: String,
    content_digest: String,
    trust_class: String,
    created_at_ms: i64,
    superseded_by: Option<String>,
    superseded_at_ms: Option<i64>,
    revision: i64,
}

const ITEM_COLUMNS: &str = "entry_id, workspace, memory_key, label, content_digest, \
                            trust_class, created_at_ms, superseded_by, superseded_at_ms, \
                            revision";

fn raw_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawItem> {
    Ok(RawItem {
        entry_id: row.get(0)?,
        workspace: row.get(1)?,
        memory_key: row.get(2)?,
        label: row.get(3)?,
        content_digest: row.get(4)?,
        trust_class: row.get(5)?,
        created_at_ms: row.get(6)?,
        superseded_by: row.get(7)?,
        superseded_at_ms: row.get(8)?,
        revision: row.get(9)?,
    })
}

/// Re-derive a [`MemoryItem`] from a stored row, refusing anything this API
/// could not have written.
///
/// The trust vocabulary is closed here as well as in the column CHECK, because a
/// CHECK protects the table from a second writer while this function protects
/// callers from a row that got in anyway. The same goes for `revision` and the
/// supersession coupling: this API writes an unstamped row at revision one or a
/// fully stamped row at revision two, so every other combination is a second
/// writer's work and a reader must not accept a half-stamped row as a
/// correction.
fn validated_item(raw: RawItem) -> Kept<MemoryItem> {
    let trust =
        MemoryTrust::from_spelling(&raw.trust_class).ok_or_else(|| corrupt("trust_class"))?;
    let revision = from_db_u64(raw.revision, "revision").map_err(|_| corrupt("revision"))?;
    if revision != 1 && revision != 2 {
        return Err(corrupt("revision"));
    }
    let memory_key = checked_field(raw.memory_key, "memory_key")?;
    let (superseded_by, superseded_at_ms) = match (raw.superseded_by, raw.superseded_at_ms) {
        (None, None) if revision == 1 => (None, None),
        (Some(replacement), Some(at_ms)) if revision == 2 => {
            let replacement = checked_field(replacement, "superseded_by")?;
            if replacement == memory_key {
                return Err(corrupt("superseded_by"));
            }
            (
                Some(replacement),
                Some(checked_time(at_ms, "superseded_at_ms")?),
            )
        }
        _ => return Err(corrupt("supersession")),
    };
    Ok(MemoryItem {
        entry_id: checked_row_id(raw.entry_id, "entry_id")?,
        workspace: checked_field(raw.workspace, "workspace")?,
        memory_key,
        label: checked_field(raw.label, "label")?,
        content_digest: checked_digest(raw.content_digest, "content_digest")?,
        trust,
        created_at_ms: checked_time(raw.created_at_ms, "created_at_ms")?,
        superseded_by,
        superseded_at_ms,
        revision,
    })
}

fn read_item(
    connection: &Connection,
    workspace: &str,
    memory_key: &str,
) -> Kept<Option<MemoryItem>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {ITEM_COLUMNS} FROM memory_items
                 WHERE workspace = ?1 AND memory_key = ?2"
            ),
            [workspace, memory_key],
            raw_item,
        )
        .optional()?;
    raw.map(validated_item).transpose()
}

fn count_items(connection: &Connection) -> Kept<usize> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM memory_items", [], |row| row.get(0))?;
    usize::try_from(count).map_err(|_| corrupt("item_count"))
}

fn secure_path(path: &Path) -> Kept<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ContextMemoryError::Io(io),
        other => ContextMemoryError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Kept<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == CONTEXT_MEMORY_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(ContextMemoryError::SchemaVersion {
            found: version,
            supported: CONTEXT_MEMORY_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(ContextMemoryError::SchemaVersion {
            found: 0,
            supported: CONTEXT_MEMORY_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", CONTEXT_MEMORY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// The grammar a workspace, a memory key and a label share.
///
/// Identical to the one `automonique_protocol::context`'s `bounded` applies to
/// every context field, at the same ceiling.
fn validate_field(value: &str, field: &'static str) -> Kept<()> {
    if value.is_empty()
        || value.len() > MAX_MEMORY_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ContextMemoryError::InvalidField(field));
    }
    Ok(())
}

/// Exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is refused rather than folded, so one digest has exactly one stored
/// spelling and a byte comparison of two rows means what it looks like.
fn validate_digest(value: &str, field: &'static str) -> Kept<()> {
    if value.len() != CONTENT_DIGEST_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContextMemoryError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Kept<()> {
    if value < 0 {
        return Err(ContextMemoryError::InvalidField(field));
    }
    Ok(())
}

fn checked_field(value: String, field: &'static str) -> Kept<String> {
    validate_field(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_digest(value: String, field: &'static str) -> Kept<String> {
    validate_digest(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Kept<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Kept<i64> {
    if value <= 0 {
        return Err(corrupt(field));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt(field: &'static str) -> ContextMemoryError {
    ContextMemoryError::Corrupt(field)
}

fn to_db_u64(value: u64, field: &'static str) -> Kept<i64> {
    i64::try_from(value).map_err(|_| ContextMemoryError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Kept<u64> {
    u64::try_from(value).map_err(|_| ContextMemoryError::InvalidField(field))
}
