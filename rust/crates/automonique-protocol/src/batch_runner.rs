// SPDX-License-Identifier: Elastic-2.0

//! The batch runner's typed model: a bounded set of run submissions tracked as
//! one unit.
//!
//! `docs/product-plan/requirements/models-media-and-execution.md` names the item —
//! "**Batch runner:** bounded parallel datasets, per-record profile/tools/
//! workspace/media, checkpoint/resume and structured output" — and
//! `docs/product-plan/requirements/models-media-and-execution.md` § Batch,
//! evaluation and trajectories says what it does: "Automonique can run a dataset
//! of prompts/tasks with bounded concurrency, per-record model/tools/profile/
//! workspace/image, resumable checkpoints and structured outputs."
//!
//! Two further rules govern every type here:
//!
//! - `docs/product-plan/requirements/verification-and-rollout.md` § 15 — "Batch
//!   runs resume by stable record identity, never double-complete" — which is
//!   why a member is named by its submission idempotency key and why
//!   [`BatchPlan::new`] refuses a repeated one; and
//! - `docs/product-plan/requirements/operations-and-governance.md` § Admission
//!   — "Automonique never accepts unbounded work it cannot retain" — which is
//!   why [`MAX_BATCH_MEMBERS`] is a real ceiling and why
//!   [`ConcurrencyPolicy`] has no unbounded variant.
//!
//! `docs/product-plan/requirements/external-capability-ledger.md` records the
//! capability as "Batch processing | Resumable dataset runner with bounded
//! concurrency | research | automonique-runner", which is the owner this model
//! describes work *for*; see "Lease" below.
//!
//! # What this slice is
//!
//! Values, and one total function over them. Nothing here schedules, submits,
//! runs, resumes or checkpoints anything:
//!
//! - a [`BatchPlan`] says *which submissions would be tracked together and under
//!   what concurrency ceiling*. It holds no RunSpec document, opens no socket
//!   and reaches no store;
//! - a [`MemberProgress`] is a caller's recorded claim about one member, not a
//!   reading. This model cannot know a member's true run state — that binding
//!   is the durable run index's job, the `run_submissions` row joined to the
//!   runner's spool that [`crate::runs_api::RunSummary`] reports. A batch that
//!   answered from its own memory would be a second source of truth;
//! - [`roll_up`] derives a batch-level state from member states by a documented
//!   total function, and [`BatchProgress::from_canonical_bytes`] refuses a
//!   document whose carried state contradicts it.
//!
//! There is no executor. The fan-out that would turn a plan into submissions,
//! the checkpoint that would make a batch resumable, and the structured-output
//! merge R15-01 also names are later slices; none is representable here and no
//! field through which one could be requested exists.
//!
//! # Divergences from the plan's batch runner
//!
//! Named rather than silently approximated:
//!
//! - **Per-record profile, tools, workspace, model and media are absent.**
//!   R15-01 asks for them. A member here is a key and nothing else, because
//!   `automonique_runner`'s `RunSpec` is not importable from this dependency-free
//!   crate and inventing a second per-record specification would create a
//!   projection nothing has agreed to. Per-record variation lives in the RunSpec
//!   each submission already carries; the batch names the submission, not its
//!   contents.
//! - **Checkpoint and resume are absent.** "Resume by stable record identity" is
//!   satisfied *in part* by making the member key that identity, which is what
//!   makes resume expressible later. The checkpoint record itself — what was
//!   completed, at which durable position, under which release — is not modelled,
//!   so nothing here can be resumed from.
//! - **Structured output and its deterministic merge are absent.** A member
//!   carries a state, not a result. There is no output field to merge.
//! - **No transport.** These are documents, not messages: canonical JSON on
//!   [`crate::wire`], with no [`crate::codec::Envelope`], no protocol name and no
//!   request/response pair. [`crate::admin`] routes three protocols and this is
//!   not a fourth; a batch document is something a later lane would *carry*, and
//!   claiming a lane that does not exist would be the drift this crate refuses.
//! - **No actor, tenant, consent or redaction.**
//!   `docs/product-plan/requirements/goals-and-invariants.md` requires that
//!   "Batch, trajectory and evaluation systems use scrubbed, policy-approved data
//!   and cannot replay historical side effects". This model has no data to
//!   scrub and no actor to authorize, so it makes no claim in either direction —
//!   a plan being constructible here is not a plan being admissible anywhere.
//! - **A dataset ceiling, not a dataset.** [`MAX_BATCH_MEMBERS`] bounds one
//!   *document*. A dataset larger than it is not representable as one batch,
//!   which is a real limit of this shape rather than a configuration.
//! - These values sit in `automonique-protocol` beside [`crate::runs_api`],
//!   whose run vocabulary they reuse.
//!
//! # The seam this leaves open
//!
//! A daemon that ran batches needs three things this module deliberately does
//! not have: the submission fan-out that turns [`BatchPlan::members`] into
//! accepted RunSpec documents, the join that replaces a caller-supplied
//! [`MemberProgress`] with the run index's own answer, and the durable
//! checkpoint that makes the whole thing resumable. Until then every value here
//! is constructible and nothing here is reachable from a socket.

use core::fmt;
use std::error::Error;

use crate::admin::MAX_RUN_SUBMISSION_KEY_BYTES;
use crate::codec::{CodecError, SecuritySensitiveEnum, decode_security_enum};
use crate::primitives::{BoundedString, IdDomain, OpaqueId, ValueError};
use crate::runs_api::RunState;
use crate::wire::{JsonValue, parse_canonical};

/// Stable schema identifier for the version-one batch documents.
pub const BATCH_SCHEMA_V1: &str = "automonique.batch/v1";

/// Maximum members one batch may track.
///
/// A ceiling on one document, not on a dataset. A larger dataset is not a larger
/// batch here; it is not representable, which
/// `docs/product-plan/requirements/operations-and-governance.md`'s "Automonique
/// never accepts unbounded work it cannot retain" prefers to a document that
/// grows without limit.
pub const MAX_BATCH_MEMBERS: usize = 256;

/// Maximum UTF-8 bytes of a batch identity.
pub const MAX_BATCH_ID_BYTES: usize = 128;

/// Maximum UTF-8 bytes of an operator-supplied batch label.
pub const MAX_BATCH_LABEL_BYTES: usize = 128;

/// Maximum UTF-8 bytes of a member key.
///
/// Defined *as* [`crate::admin::MAX_RUN_SUBMISSION_KEY_BYTES`] rather than as a
/// second number that happens to match it. A member key is the idempotency key
/// of the submission it names, so a key this batch admits and the admin lane
/// refuses would be a batch that could never be submitted.
pub const MAX_BATCH_MEMBER_KEY_BYTES: usize = MAX_RUN_SUBMISSION_KEY_BYTES;

/// Maximum canonical bytes of one batch document.
pub const MAX_BATCH_CANONICAL_BYTES: usize = 128 * 1024;

/// The spelling for a member no submission has been recorded for.
///
/// Held apart from [`RunState`]'s six spellings, which this module reuses rather
/// than restates. `tests/batch_runner.rs` proves it collides with none of them.
const UNSUBMITTED: &str = "unsubmitted";

/// Worst-case canonical bytes of one member key, quoted and escaped.
///
/// Two canonical bytes per source byte, because a quote or a backslash escapes
/// to two, plus the surrounding quotes.
const MEMBER_KEY_ENCODED_BYTES: usize = 2 * MAX_BATCH_MEMBER_KEY_BYTES + 2;

/// Worst-case canonical bytes of one progress entry beyond its key.
///
/// The `key` and `state` member names, the longest state spelling quoted, the
/// braces, colons and the comma that separates the entry from the next.
const PROGRESS_ENTRY_OVERHEAD_BYTES: usize = 48;

/// Worst-case canonical bytes of a document scaffold, excluding its members.
///
/// The batch identity and label at their escaped worst case, the schema and
/// rolled-up state spellings, the concurrency object and the punctuation.
const DOCUMENT_SCAFFOLD_BYTES: usize = 2 * MAX_BATCH_ID_BYTES + 2 * MAX_BATCH_LABEL_BYTES + 256;

const _: () = assert!(
    MAX_BATCH_MEMBERS * (MEMBER_KEY_ENCODED_BYTES + PROGRESS_ENTRY_OVERHEAD_BYTES)
        + DOCUMENT_SCAFFOLD_BYTES
        <= MAX_BATCH_CANONICAL_BYTES,
    "a maximal batch progress document must fit the canonical ceiling"
);

const _: () = assert!(
    MAX_BATCH_MEMBERS * (MEMBER_KEY_ENCODED_BYTES + 1) + DOCUMENT_SCAFFOLD_BYTES
        <= MAX_BATCH_CANONICAL_BYTES,
    "a maximal batch plan document must fit the canonical ceiling"
);

/// A refusal while constructing, encoding or decoding a batch value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchError {
    /// The canonical JSON codec refused the document.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a member state or
    /// concurrency kind this build does not define. Those fail closed rather
    /// than decoding to a default.
    Codec(CodecError),
    /// A bounded identifier, key or label was empty, over-long or
    /// control-bearing.
    Field {
        /// Field that was refused.
        field: &'static str,
        /// Why it was refused.
        error: ValueError,
    },
    /// A batch named no member, which is a unit with nothing in it.
    EmptyBatch,
    /// A batch named more members than [`MAX_BATCH_MEMBERS`].
    TooManyMembers {
        /// Most members one batch tracks.
        max_members: usize,
        /// Members the caller supplied.
        actual_members: usize,
    },
    /// A batch named one member key twice.
    DuplicateMember {
        /// The repeated key.
        key: BatchMemberKey,
    },
    /// A concurrency ceiling was zero, which admits no work at all.
    ConcurrencyCeilingZero,
    /// A concurrency ceiling was above what a batch could ever place in flight.
    ConcurrencyCeilingUnreachable {
        /// Most members one batch tracks.
        max_members: usize,
        /// Ceiling the caller asked for.
        requested: u32,
    },
    /// A document was not the exact shape defined for its kind.
    InvalidBody,
    /// A document declared a schema this build does not serve.
    UnknownSchema,
    /// A document was longer than [`MAX_BATCH_CANONICAL_BYTES`].
    DocumentTooLarge {
        /// Largest document this model admits.
        max_bytes: usize,
        /// Bytes the caller supplied.
        actual_bytes: usize,
    },
    /// A progress view did not carry one entry per plan member.
    ProgressIncomplete {
        /// Members the plan names.
        expected: usize,
        /// Entries the view carried.
        actual: usize,
    },
    /// A progress entry named a different member than the plan does there.
    ProgressMemberMismatch {
        /// Position, from zero, at which the two disagree.
        position: usize,
    },
    /// A document carried a batch state its own members do not roll up to.
    RollupContradictsMembers {
        /// State the document claimed.
        carried: BatchState,
        /// State [`roll_up`] derives from the members beside it.
        derived: BatchState,
    },
}

impl BatchError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Field { .. } => "batch_invalid_field",
            Self::EmptyBatch => "batch_empty",
            Self::TooManyMembers { .. } => "batch_too_many_members",
            Self::DuplicateMember { .. } => "batch_duplicate_member",
            Self::ConcurrencyCeilingZero => "batch_concurrency_ceiling_zero",
            Self::ConcurrencyCeilingUnreachable { .. } => "batch_concurrency_ceiling_unreachable",
            Self::InvalidBody => "batch_invalid_body",
            Self::UnknownSchema => "batch_unknown_schema",
            Self::DocumentTooLarge { .. } => "batch_document_too_large",
            Self::ProgressIncomplete { .. } => "batch_progress_incomplete",
            Self::ProgressMemberMismatch { .. } => "batch_progress_member_mismatch",
            Self::RollupContradictsMembers { .. } => "batch_rollup_contradicts_members",
        }
    }
}

impl fmt::Display for BatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "batch codec refused document: {error}"),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::EmptyBatch => formatter.write_str("a batch names no member"),
            Self::TooManyMembers {
                max_members,
                actual_members,
            } => write!(
                formatter,
                "batch names {actual_members} members; maximum is {max_members}"
            ),
            Self::DuplicateMember { key } => write!(formatter, "batch names member {key} twice"),
            Self::ConcurrencyCeilingZero => {
                formatter.write_str("a concurrency ceiling admits at least one member in flight")
            }
            Self::ConcurrencyCeilingUnreachable {
                max_members,
                requested,
            } => write!(
                formatter,
                "concurrency ceiling {requested} is above the {max_members} members a batch can hold"
            ),
            Self::InvalidBody => formatter.write_str("batch document is invalid"),
            Self::UnknownSchema => formatter.write_str("batch document declares an unknown schema"),
            Self::DocumentTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "batch document is {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::ProgressIncomplete { expected, actual } => write!(
                formatter,
                "progress carries {actual} entries for a plan of {expected} members"
            ),
            Self::ProgressMemberMismatch { position } => write!(
                formatter,
                "progress entry {position} names a member the plan does not have there"
            ),
            Self::RollupContradictsMembers { carried, derived } => write!(
                formatter,
                "document claims batch state {carried}; its members roll up to {derived}"
            ),
        }
    }
}

impl Error for BatchError {}

impl From<CodecError> for BatchError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// The domain of a batch identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchDomain;

impl IdDomain for BatchDomain {}

/// The domain of a batch member key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchMemberDomain;

impl IdDomain for BatchMemberDomain {}

/// One batch, as an identity.
///
/// Bounded and branded: a batch identity is not a member key, and the compiler
/// says so rather than a review.
///
/// ```compile_fail
/// use automonique_protocol::batch_runner::{BatchId, BatchMemberKey};
/// let batch = BatchId::new("nightly-eval").unwrap();
/// let member: BatchMemberKey = batch;
/// ```
pub type BatchId = OpaqueId<BatchDomain, MAX_BATCH_ID_BYTES>;

/// One member of a batch, named by the idempotency key of its submission.
///
/// The key is the whole reference. This model carries no RunSpec document and no
/// digest of one: `automonique_runner`'s `RunSpec` is not importable here, and a
/// key is what
/// `docs/product-plan/requirements/verification-and-rollout.md` § 15 means by
/// "stable record identity".
pub type BatchMemberKey = OpaqueId<BatchMemberDomain, MAX_BATCH_MEMBER_KEY_BYTES>;

/// A bounded, operator-supplied name for one batch.
pub type BatchLabel = BoundedString<MAX_BATCH_LABEL_BYTES>;

/// Which concurrency policy a batch declared.
///
/// Carried apart from [`ConcurrencyPolicy`] so the wire spelling is a closed
/// vocabulary of two words and the ceiling travels beside it rather than inside
/// the word. This is the shape [`crate::automation::OverlapPolicy`] uses.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConcurrencyKind {
    /// One member at a time, in the order the plan declares.
    Sequential,
    /// Up to a declared ceiling at a time, in no declared order.
    BoundedParallel,
}

impl ConcurrencyKind {
    /// Every kind, in canonical order.
    pub const ALL: [Self; 2] = [Self::Sequential, Self::BoundedParallel];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::BoundedParallel => "bounded_parallel",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

impl fmt::Display for ConcurrencyKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ConcurrencyKind {
    const FIELD: &'static str = "kind";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// How many members of a batch may be in flight, and in what order.
///
/// There is deliberately no variant meaning "unbounded": the only variant that
/// admits more than one member in flight carries a declared ceiling, a ceiling
/// of zero is refused rather than read as "no limit", and a ceiling above
/// [`MAX_BATCH_MEMBERS`] is refused because no batch could reach it — a ceiling
/// that can never bind is an unbounded policy with a number written on it. This
/// is the discipline [`crate::automation::OverlapPolicy`] holds for occurrences,
/// applied to members.
///
/// [`Self::Sequential`] and `BoundedParallel { max_in_flight: 1 }` are not two
/// spellings of one policy: sequential also fixes the order to the plan's,
/// bounded-parallel declares none.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConcurrencyPolicy {
    /// One member at a time, in the order the plan declares.
    Sequential,
    /// Up to `max_in_flight` members at a time, in no declared order.
    BoundedParallel {
        /// How many members may be in flight together.
        max_in_flight: u32,
    },
}

impl ConcurrencyPolicy {
    /// A bounded parallelism.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::ConcurrencyCeilingZero`] for a zero ceiling, which
    /// would be a batch that never starts rather than a batch without limit, and
    /// [`BatchError::ConcurrencyCeilingUnreachable`] above [`MAX_BATCH_MEMBERS`].
    pub const fn bounded_parallel(max_in_flight: u32) -> Result<Self, BatchError> {
        if max_in_flight == 0 {
            return Err(BatchError::ConcurrencyCeilingZero);
        }
        if max_in_flight as usize > MAX_BATCH_MEMBERS {
            return Err(BatchError::ConcurrencyCeilingUnreachable {
                max_members: MAX_BATCH_MEMBERS,
                requested: max_in_flight,
            });
        }
        Ok(Self::BoundedParallel { max_in_flight })
    }

    /// Which kind this is.
    #[must_use]
    pub const fn kind(self) -> ConcurrencyKind {
        match self {
            Self::Sequential => ConcurrencyKind::Sequential,
            Self::BoundedParallel { .. } => ConcurrencyKind::BoundedParallel,
        }
    }

    /// The declared ceiling, when the policy declares one.
    #[must_use]
    pub const fn declared_ceiling(self) -> Option<u32> {
        match self {
            Self::Sequential => None,
            Self::BoundedParallel { max_in_flight } => Some(max_in_flight),
        }
    }

    /// How many members this policy could place in flight over `member_count`.
    ///
    /// A pure total function of the policy and a count. A ceiling above the
    /// membership binds at the membership, so a plan's headroom is reported as
    /// what it is worth rather than as what it says, and a zero count answers
    /// zero rather than one.
    #[must_use]
    pub const fn effective_in_flight(self, member_count: usize) -> usize {
        if member_count == 0 {
            return 0;
        }
        match self {
            Self::Sequential => 1,
            Self::BoundedParallel { max_in_flight } => {
                let ceiling = max_in_flight as usize;
                if ceiling < member_count {
                    ceiling
                } else {
                    member_count
                }
            }
        }
    }

    fn to_body(self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "kind".to_owned(),
                JsonValue::String(self.kind().as_str().to_owned()),
            ),
            (
                "max_in_flight".to_owned(),
                match self.declared_ceiling() {
                    Some(ceiling) => JsonValue::Integer(i64::from(ceiling)),
                    None => JsonValue::Null,
                },
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchError> {
        exact_fields(body, &["kind", "max_in_flight"])?;
        let kind = decode_security_enum::<ConcurrencyKind>(&required_string(body, "kind")?)?;
        match (kind, body.get("max_in_flight")) {
            (ConcurrencyKind::Sequential, Some(JsonValue::Null)) => Ok(Self::Sequential),
            (ConcurrencyKind::BoundedParallel, Some(JsonValue::Integer(ceiling))) => {
                let ceiling = u32::try_from(*ceiling).map_err(|_| BatchError::InvalidBody)?;
                Self::bounded_parallel(ceiling)
            }
            _ => Err(BatchError::InvalidBody),
        }
    }
}

/// Position of a run state in [`MemberProgress::ALL`].
///
/// The match is exhaustive, so a variant added to [`RunState`] fails to compile
/// here rather than dropping out of the array unnoticed and becoming a spelling
/// this model silently refuses.
const fn progress_slot(state: RunState) -> usize {
    match state {
        RunState::Ready => 1,
        RunState::Running => 2,
        RunState::Completed => 3,
        RunState::Failed => 4,
        RunState::Cancelled => 5,
        RunState::TimedOut => 6,
    }
}

const _: () = assert!(
    MemberProgress::ALL.len() == RunState::ALL.len() + 1,
    "member progress is every run state plus the unsubmitted one"
);

const _: () = {
    let mut index = 0;
    while index < RunState::ALL.len() {
        assert!(
            progress_slot(RunState::ALL[index]) == index + 1,
            "MemberProgress::ALL must follow RunState::ALL after the unsubmitted slot"
        );
        index += 1;
    }
};

/// Where one member of a batch has got to.
///
/// Seven values: the six [`RunState`]s the runner's spool defines, reused rather
/// than re-spelled, plus the one state a run vocabulary cannot express — a
/// member the batch names for which no submission has been recorded at all.
/// [`RunState::Ready`] is not that state: `ready` means the daemon holds a
/// document and no event has arrived, which presumes a submission happened.
///
/// A value of this type is a claim, recorded by whoever read the durable run
/// index. It is not a reading, and this model has no way to check one; see the
/// module note on why the run index owns that binding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemberProgress {
    /// No submission has been recorded for this member.
    Unsubmitted,
    /// The run index reports this state for the member's run.
    Run(RunState),
}

impl MemberProgress {
    /// Every value, unsubmitted first and then [`RunState::ALL`] in its order.
    pub const ALL: [Self; 7] = [
        Self::Unsubmitted,
        Self::Run(RunState::Ready),
        Self::Run(RunState::Running),
        Self::Run(RunState::Completed),
        Self::Run(RunState::Failed),
        Self::Run(RunState::Cancelled),
        Self::Run(RunState::TimedOut),
    ];

    /// Stable lowercase wire spelling.
    ///
    /// Six of the seven come straight from [`RunState::as_str`], so this module
    /// cannot disagree with [`crate::runs_api`] about a word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsubmitted => UNSUBMITTED,
            Self::Run(state) => state.as_str(),
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        if value == UNSUBMITTED {
            return Some(Self::Unsubmitted);
        }
        RunState::from_spelling(value).map(Self::Run)
    }

    /// The run state, when a submission was recorded.
    #[must_use]
    pub const fn run_state(self) -> Option<RunState> {
        match self {
            Self::Unsubmitted => None,
            Self::Run(state) => Some(state),
        }
    }

    /// Whether this member has ended.
    ///
    /// Delegates to [`RunState::is_terminal`]. `unsubmitted` is not terminal: a
    /// member that was never submitted has not finished, it has not begun.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Unsubmitted => false,
            Self::Run(state) => state.is_terminal(),
        }
    }

    /// Whether this member has yet to begin producing events.
    ///
    /// `unsubmitted` and `ready` are the two values that carry no evidence any
    /// work started.
    #[must_use]
    pub const fn has_not_started(self) -> bool {
        matches!(self, Self::Unsubmitted | Self::Run(RunState::Ready))
    }

    /// Whether this member ended without completing its work.
    ///
    /// `failed` and `timed_out` are both ends the batch did not get a result
    /// from; `cancelled` is not one, because a cancellation is a decision rather
    /// than a loss.
    #[must_use]
    pub const fn is_lost(self) -> bool {
        matches!(self, Self::Run(RunState::Failed | RunState::TimedOut))
    }
}

impl fmt::Display for MemberProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for MemberProgress {
    const FIELD: &'static str = "state";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Where a whole batch has got to.
///
/// A closed rollup of six words, derived from the members by [`roll_up`] and
/// never set independently: [`BatchProgress::observe`] computes it and
/// [`BatchProgress::from_canonical_bytes`] refuses a document that carries a
/// different one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BatchState {
    /// No member has begun: every one is unsubmitted or merely accepted.
    Pending,
    /// Work is under way: some member is running, or some has ended while
    /// others have not.
    Running,
    /// Every member ended and every one completed.
    Completed,
    /// Every member ended and at least one failed or timed out.
    Failed,
    /// Every member ended and every one was cancelled.
    Cancelled,
    /// Every member ended, none failed or timed out, and the results are neither
    /// all completions nor all cancellations.
    Mixed,
}

impl BatchState {
    /// Every state, in canonical order.
    pub const ALL: [Self; 6] = [
        Self::Pending,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::Mixed,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Mixed => "mixed",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// Whether the batch has ended.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Mixed
        )
    }
}

impl fmt::Display for BatchState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for BatchState {
    const FIELD: &'static str = "state";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Derive one batch state from its members' states.
///
/// # The rule
///
/// A pure total function of the member slice, in this precedence:
///
/// 1. an empty slice answers `None`. An empty batch has no state, and
///    inventing one would answer `completed` for a batch that never ran —
///    "every member ended" and "every member completed" are both vacuously true
///    of nothing. [`BatchPlan::new`] refuses to produce an empty batch, so the
///    `None` arm is unreachable through the plan types and reachable through
///    this function, which is why it is stated rather than assumed away;
/// 2. **every member terminal** — [`MemberProgress::is_terminal`] for all — then:
///    1. any member `failed` or `timed_out` → [`BatchState::Failed`]. A batch
///       that lost a member did not succeed, whatever the others did;
///    2. else every member `completed` → [`BatchState::Completed`];
///    3. else every member `cancelled` → [`BatchState::Cancelled`];
///    4. else → [`BatchState::Mixed`], which is therefore exactly one case:
///       ended, nothing lost, and both completions and cancellations present;
/// 3. **not every member terminal**, then:
///    1. every member [`MemberProgress::has_not_started`] — `unsubmitted` or
///       `ready` — → [`BatchState::Pending`];
///    2. else → [`BatchState::Running`].
///
/// The answer depends only on *which* member states are present, not on their
/// order or how many times each occurs. `tests/batch_runner.rs` proves both: the
/// truth table is enumerated over all 127 non-empty subsets of the seven member
/// states, and permuting or repeating a subset's members is shown not to change
/// the answer.
#[must_use]
pub fn roll_up(members: &[MemberProgress]) -> Option<BatchState> {
    if members.is_empty() {
        return None;
    }
    if members.iter().all(|member| member.is_terminal()) {
        if members.iter().any(|member| member.is_lost()) {
            return Some(BatchState::Failed);
        }
        if members
            .iter()
            .all(|member| *member == MemberProgress::Run(RunState::Completed))
        {
            return Some(BatchState::Completed);
        }
        if members
            .iter()
            .all(|member| *member == MemberProgress::Run(RunState::Cancelled))
        {
            return Some(BatchState::Cancelled);
        }
        return Some(BatchState::Mixed);
    }
    if members.iter().all(|member| member.has_not_started()) {
        return Some(BatchState::Pending);
    }
    Some(BatchState::Running)
}

/// A bounded set of submissions tracked as one unit.
///
/// The membership is held in declaration order, because
/// [`ConcurrencyPolicy::Sequential`] names that order. It is never sorted and
/// never deduplicated: a repeated key is refused, not collapsed, because a
/// caller that named a submission twice believes it asked for something it did
/// not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPlan {
    id: BatchId,
    label: Option<BatchLabel>,
    members: Vec<BatchMemberKey>,
    concurrency: ConcurrencyPolicy,
}

impl BatchPlan {
    /// Declare a batch.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::EmptyBatch`] for a batch with no member,
    /// [`BatchError::TooManyMembers`] above [`MAX_BATCH_MEMBERS`], and
    /// [`BatchError::DuplicateMember`] for a repeated key.
    pub fn new(
        id: BatchId,
        label: Option<BatchLabel>,
        members: Vec<BatchMemberKey>,
        concurrency: ConcurrencyPolicy,
    ) -> Result<Self, BatchError> {
        if members.is_empty() {
            return Err(BatchError::EmptyBatch);
        }
        if members.len() > MAX_BATCH_MEMBERS {
            return Err(BatchError::TooManyMembers {
                max_members: MAX_BATCH_MEMBERS,
                actual_members: members.len(),
            });
        }
        let mut ordered: Vec<&BatchMemberKey> = members.iter().collect();
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(BatchError::DuplicateMember {
                key: pair[0].clone(),
            });
        }
        Ok(Self {
            id,
            label,
            members,
            concurrency,
        })
    }

    /// The batch identity.
    #[must_use]
    pub const fn id(&self) -> &BatchId {
        &self.id
    }

    /// The operator-supplied label, when there is one.
    #[must_use]
    pub const fn label(&self) -> Option<&BatchLabel> {
        self.label.as_ref()
    }

    /// The member keys, in declaration order.
    #[must_use]
    pub fn members(&self) -> &[BatchMemberKey] {
        &self.members
    }

    /// The declared concurrency policy.
    #[must_use]
    pub const fn concurrency(&self) -> ConcurrencyPolicy {
        self.concurrency
    }

    /// How many members this plan's policy could place in flight.
    #[must_use]
    pub const fn effective_in_flight(&self) -> usize {
        self.concurrency.effective_in_flight(self.members.len())
    }

    /// Stable schema identifier for this document version.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        BATCH_SCHEMA_V1
    }

    /// The document body, with keys the canonical encoder will sort.
    #[must_use]
    pub fn to_document(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.id.as_str().to_owned()),
            ),
            ("concurrency".to_owned(), self.concurrency.to_body()),
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
            (
                "schema".to_owned(),
                JsonValue::String(BATCH_SCHEMA_V1.to_owned()),
            ),
        ])
    }

    /// The canonical bytes of this plan.
    ///
    /// Deterministic: [`JsonValue::to_canonical_bytes`] sorts object keys, and
    /// the member array keeps declaration order because the policy names it. A
    /// maximal plan fits [`MAX_BATCH_CANONICAL_BYTES`] by the compile-time
    /// assertion above.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_document().to_canonical_bytes()
    }

    /// Decode a plan from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::DocumentTooLarge`] above
    /// [`MAX_BATCH_CANONICAL_BYTES`], [`BatchError::Codec`] for non-canonical
    /// JSON or an unknown concurrency kind, [`BatchError::UnknownSchema`] for a
    /// schema this build does not serve, [`BatchError::InvalidBody`] for a body
    /// that is not exact, and every refusal [`Self::new`] makes.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, BatchError> {
        Self::from_document(&parse_bounded(payload)?)
    }

    /// Decode a plan from a parsed document.
    ///
    /// # Errors
    ///
    /// See [`Self::from_canonical_bytes`].
    pub fn from_document(body: &JsonValue) -> Result<Self, BatchError> {
        exact_fields(
            body,
            &["batch_id", "concurrency", "label", "members", "schema"],
        )?;
        expect_schema(body)?;
        let id = BatchId::new(required_string(body, "batch_id")?).map_err(|error| {
            BatchError::Field {
                field: "batch_id",
                error,
            }
        })?;
        let label = match body.get("label") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(value)) => Some(BatchLabel::new(value.clone()).map_err(
                |error| BatchError::Field {
                    field: "label",
                    error,
                },
            )?),
            _ => return Err(BatchError::InvalidBody),
        };
        let JsonValue::Array(items) = body.get("members").ok_or(BatchError::InvalidBody)? else {
            return Err(BatchError::InvalidBody);
        };
        if items.len() > MAX_BATCH_MEMBERS {
            return Err(BatchError::TooManyMembers {
                max_members: MAX_BATCH_MEMBERS,
                actual_members: items.len(),
            });
        }
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            let spelling = item.as_str().ok_or(BatchError::InvalidBody)?;
            members.push(
                BatchMemberKey::new(spelling).map_err(|error| BatchError::Field {
                    field: "member_key",
                    error,
                })?,
            );
        }
        let concurrency =
            ConcurrencyPolicy::from_body(body.get("concurrency").ok_or(BatchError::InvalidBody)?)?;
        Self::new(id, label, members, concurrency)
    }
}

/// One member of a batch, with the state a reader recorded for it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BatchMember {
    key: BatchMemberKey,
    progress: MemberProgress,
}

impl BatchMember {
    /// Record one member's state.
    #[must_use]
    pub const fn new(key: BatchMemberKey, progress: MemberProgress) -> Self {
        Self { key, progress }
    }

    /// The submission this member names.
    #[must_use]
    pub const fn key(&self) -> &BatchMemberKey {
        &self.key
    }

    /// Where the member has got to.
    #[must_use]
    pub const fn progress(&self) -> MemberProgress {
        self.progress
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "key".to_owned(),
                JsonValue::String(self.key.as_str().to_owned()),
            ),
            (
                "state".to_owned(),
                JsonValue::String(self.progress.as_str().to_owned()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, BatchError> {
        exact_fields(body, &["key", "state"])?;
        Ok(Self::new(
            BatchMemberKey::new(required_string(body, "key")?).map_err(|error| {
                BatchError::Field {
                    field: "member_key",
                    error,
                }
            })?,
            decode_security_enum::<MemberProgress>(&required_string(body, "state")?)?,
        ))
    }
}

/// Where every member of one batch has got to, and what that rolls up to.
///
/// The batch-level state is not a field a caller supplies. It is derived by
/// [`roll_up`] at construction and re-derived on decode, so a document cannot
/// claim `completed` over members that say otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchProgress {
    batch_id: BatchId,
    members: Vec<BatchMember>,
    state: BatchState,
}

impl BatchProgress {
    /// Record a reading of every member of `plan`.
    ///
    /// The entries must line up with [`BatchPlan::members`] one for one and in
    /// order. A short list is refused rather than padded and a re-ordered one is
    /// refused rather than matched by key, because both are readers that lost
    /// track of which member they were reporting — and a progress view that
    /// silently dropped a member would under-report a batch that has one
    /// outstanding.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::ProgressIncomplete`] when the entry count differs
    /// from the plan's membership and [`BatchError::ProgressMemberMismatch`]
    /// when an entry names a different member than the plan does at that
    /// position.
    pub fn observe(plan: &BatchPlan, members: Vec<BatchMember>) -> Result<Self, BatchError> {
        if members.len() != plan.members().len() {
            return Err(BatchError::ProgressIncomplete {
                expected: plan.members().len(),
                actual: members.len(),
            });
        }
        for (position, (entry, expected)) in members.iter().zip(plan.members()).enumerate() {
            if entry.key() != expected {
                return Err(BatchError::ProgressMemberMismatch { position });
            }
        }
        let state = rolled_up(&members)?;
        Ok(Self {
            batch_id: plan.id().clone(),
            members,
            state,
        })
    }

    /// The batch this reading is of.
    #[must_use]
    pub const fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    /// The members, in the plan's declaration order.
    #[must_use]
    pub fn members(&self) -> &[BatchMember] {
        &self.members
    }

    /// The derived batch state.
    #[must_use]
    pub const fn state(&self) -> BatchState {
        self.state
    }

    /// Stable schema identifier for this document version.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        BATCH_SCHEMA_V1
    }

    /// The document body, with keys the canonical encoder will sort.
    #[must_use]
    pub fn to_document(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "batch_id".to_owned(),
                JsonValue::String(self.batch_id.as_str().to_owned()),
            ),
            (
                "members".to_owned(),
                JsonValue::Array(self.members.iter().map(BatchMember::to_body).collect()),
            ),
            (
                "schema".to_owned(),
                JsonValue::String(BATCH_SCHEMA_V1.to_owned()),
            ),
            (
                "state".to_owned(),
                JsonValue::String(self.state.as_str().to_owned()),
            ),
        ])
    }

    /// The canonical bytes of this reading.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_document().to_canonical_bytes()
    }

    /// Decode a reading from canonical bytes.
    ///
    /// The carried batch state is checked against [`roll_up`] over the members
    /// beside it rather than trusted, so a document that disagrees with itself is
    /// refused instead of believed.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::DocumentTooLarge`], [`BatchError::Codec`] for
    /// non-canonical JSON or an unknown member-state spelling,
    /// [`BatchError::UnknownSchema`], [`BatchError::InvalidBody`],
    /// [`BatchError::EmptyBatch`], [`BatchError::TooManyMembers`],
    /// [`BatchError::DuplicateMember`] and
    /// [`BatchError::RollupContradictsMembers`].
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, BatchError> {
        Self::from_document(&parse_bounded(payload)?)
    }

    /// Decode a reading from a parsed document.
    ///
    /// # Errors
    ///
    /// See [`Self::from_canonical_bytes`].
    pub fn from_document(body: &JsonValue) -> Result<Self, BatchError> {
        exact_fields(body, &["batch_id", "members", "schema", "state"])?;
        expect_schema(body)?;
        let batch_id = BatchId::new(required_string(body, "batch_id")?).map_err(|error| {
            BatchError::Field {
                field: "batch_id",
                error,
            }
        })?;
        let JsonValue::Array(items) = body.get("members").ok_or(BatchError::InvalidBody)? else {
            return Err(BatchError::InvalidBody);
        };
        if items.len() > MAX_BATCH_MEMBERS {
            return Err(BatchError::TooManyMembers {
                max_members: MAX_BATCH_MEMBERS,
                actual_members: items.len(),
            });
        }
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            members.push(BatchMember::from_body(item)?);
        }
        let mut ordered: Vec<&BatchMemberKey> = members.iter().map(BatchMember::key).collect();
        ordered.sort_unstable();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(BatchError::DuplicateMember {
                key: pair[0].clone(),
            });
        }
        let derived = rolled_up(&members)?;
        let carried = decode_security_enum::<BatchState>(&required_string(body, "state")?)?;
        if carried != derived {
            return Err(BatchError::RollupContradictsMembers { carried, derived });
        }
        Ok(Self {
            batch_id,
            members,
            state: derived,
        })
    }
}

/// The rollup of a member list, refusing the empty one.
fn rolled_up(members: &[BatchMember]) -> Result<BatchState, BatchError> {
    let progresses: Vec<MemberProgress> = members.iter().map(BatchMember::progress).collect();
    roll_up(&progresses).ok_or(BatchError::EmptyBatch)
}

/// Parse canonical JSON within the document ceiling.
fn parse_bounded(payload: &[u8]) -> Result<JsonValue, BatchError> {
    if payload.len() > MAX_BATCH_CANONICAL_BYTES {
        return Err(BatchError::DocumentTooLarge {
            max_bytes: MAX_BATCH_CANONICAL_BYTES,
            actual_bytes: payload.len(),
        });
    }
    Ok(parse_canonical(payload)?)
}

/// Refuse a document that does not declare exactly [`BATCH_SCHEMA_V1`].
fn expect_schema(body: &JsonValue) -> Result<(), BatchError> {
    if required_string(body, "schema")? == BATCH_SCHEMA_V1 {
        Ok(())
    } else {
        Err(BatchError::UnknownSchema)
    }
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, BatchError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(BatchError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), BatchError> {
    let JsonValue::Object(entries) = body else {
        return Err(BatchError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(BatchError::InvalidBody);
    }
    Ok(())
}
