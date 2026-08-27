// SPDX-License-Identifier: Elastic-2.0

//! Generate TypeScript from a Rust-owned schema description.
//!
//! The module has two halves that share one emitter.
//!
//! The first is the `R1-11` spike ([`hostile_slice`], [`emit_typescript`]),
//! kept because its verdict in `generated/VERDICT.md` and its negative
//! typecheck cases are the evidence the second half rests on. Its slice is
//! deliberately hostile rather than representative.
//!
//! The second is a maintained description of part of the shipped protocol
//! ([`generated_files`]), regenerated into `generated/` and held to a drift
//! gate in `tests/codegen.rs`.
//!
//! # What the maintained half covers
//!
//! Only a **read** surface, and only these schemas:
//!
//! - `automonique.doctor/v1` from the crate root: [`crate::ReportStatus`],
//!   [`crate::CheckStatus`], [`crate::FindingCode`], [`crate::FindingMessage`],
//!   [`crate::DoctorReason`], [`crate::DoctorCheck`], [`crate::DoctorReportV1`].
//! - The `status` read of `automonique.admin` from [`crate::admin`]:
//!   [`crate::admin::AdminInstanceId`], [`crate::admin::DaemonState`],
//!   [`crate::admin::TelegramState`], [`crate::admin::ExecutionState`],
//!   [`crate::admin::OperationalMetric`], [`crate::admin::OperationalStatus`],
//!   [`crate::admin::DaemonStatus`].
//!
//! - The command surface of `automonique.admin` from [`crate::admin`]: the
//!   requests a client builds ([`crate::admin::AdminCommand::Status`],
//!   [`crate::admin::AdminCommand::SubmitRun`],
//!   [`crate::admin::AdminCommand::PauseIntake`],
//!   [`crate::admin::AdminCommand::ResumeIntake`] and
//!   [`crate::admin::AdminCommand::Shutdown`]) and the receipts it decodes
//!   ([`crate::admin::AdminResponse::RunAccepted`],
//!   [`crate::admin::AdminResponse::IntakePaused`],
//!   [`crate::admin::AdminResponse::IntakeResumed`],
//!   [`crate::admin::AdminResponse::Refused`] and
//!   [`crate::admin::AdminResponse::ShutdownAccepted`]).
//!
//! - The whole read surface of `automonique.runs` from [`crate::runs_api`]:
//!   both requests ([`crate::runs_api::RunsRequest::ListRuns`] and
//!   [`crate::runs_api::RunsRequest::RunDetail`]) and all four answers
//!   ([`crate::runs_api::RunsResponse::RunList`],
//!   [`crate::runs_api::RunsResponse::RunDetail`],
//!   [`crate::runs_api::RunsResponse::Resync`] and
//!   [`crate::runs_api::RunsResponse::Refused`]), with the bodies they nest —
//!   [`crate::runs_api::RunSummary`] and
//!   [`crate::runs_api::RunLifecycleEvent`] — and the six closed vocabularies
//!   they carry.
//!
//! - The whole control surface of `automonique.automation` from
//!   [`crate::automation_api`]: all four requests
//!   ([`crate::automation_api::AutomationRequest::RegisterAutomation`],
//!   [`crate::automation_api::AutomationRequest::SetEnablement`],
//!   [`crate::automation_api::AutomationRequest::ListAutomations`] and
//!   [`crate::automation_api::AutomationRequest::AutomationDetail`]) and all
//!   five answers ([`crate::automation_api::AutomationResponse::Accepted`],
//!   [`crate::automation_api::AutomationResponse::AutomationList`],
//!   [`crate::automation_api::AutomationResponse::AutomationDetail`],
//!   [`crate::automation_api::AutomationResponse::Conflict`] and
//!   [`crate::automation_api::AutomationResponse::Refused`]), with the record
//!   body they nest and the two closed vocabularies they carry.
//!
//! - The whole decision surface of `automonique.approval` from
//!   [`crate::approval_api`]: all four requests
//!   ([`crate::approval_api::ApprovalRequest::RecordApproval`],
//!   [`crate::approval_api::ApprovalRequest::ListApprovals`],
//!   [`crate::approval_api::ApprovalRequest::ApprovalDetail`] and
//!   [`crate::approval_api::ApprovalRequest::ApprovalsBySubject`]) and all five
//!   answers ([`crate::approval_api::ApprovalResponse::Recorded`],
//!   [`crate::approval_api::ApprovalResponse::ApprovalList`],
//!   [`crate::approval_api::ApprovalResponse::ApprovalDetail`],
//!   [`crate::approval_api::ApprovalResponse::Conflict`] and
//!   [`crate::approval_api::ApprovalResponse::Refused`]), with the record body
//!   they nest and the four closed vocabularies they carry.
//!
//! - The whole control surface of `automonique.batch.control` from
//!   [`crate::batch_api`]: all four requests
//!   ([`crate::batch_api::BatchRequest::RegisterBatch`],
//!   [`crate::batch_api::BatchRequest::AdvanceMember`],
//!   [`crate::batch_api::BatchRequest::ListBatches`] and
//!   [`crate::batch_api::BatchRequest::BatchDetail`]) and all six answers
//!   ([`crate::batch_api::BatchResponse::Registered`],
//!   [`crate::batch_api::BatchResponse::MemberAdvanced`],
//!   [`crate::batch_api::BatchResponse::BatchList`],
//!   [`crate::batch_api::BatchResponse::BatchDetail`],
//!   [`crate::batch_api::BatchResponse::Conflict`] and
//!   [`crate::batch_api::BatchResponse::Refused`]), with the two row bodies they
//!   nest, the discriminated concurrency policy all three of those carry, and
//!   the four closed vocabularies — three of which are
//!   [`crate::batch_runner`]'s rather than that lane's, reused rather than
//!   re-spelled.
//!
//! # What it does not cover
//!
//! Everything else in the crate, including: `RunSpec` and the run surface,
//! `sandbox`, `release`, `provider`, `models`, `tools`, `interaction`,
//! `journal`, `context`, `namespace`, `connector`, `compat`, `event`, `host`,
//! `identity` and `workspace`. The rich `automation` model is absent too: only
//! the two vocabularies `automation_api` borrows from it —
//! [`crate::automation::EnablementState`] and
//! [`crate::automation::AutomationActor`] — reach the generated surface, plus
//! the schedule *rendering* the control API carries as a bounded string
//! (`once@<ms>` or `every@<ms>`); a trigger, an action and the cron form do
//! not, because the control API carries none of them. Within `admin`, the synthetic
//! intake, the reconciliation and outbox commands, and the evidence bodies
//! their responses carry are all absent — as is the `status_result` body
//! decoder, whose *types* `admin-status.ts` carries without a decoder that
//! builds them. A generated surface that quietly ignored those kinds would be
//! indistinguishable from one that understood them, so the command surface
//! names them: a defined kind it does not decode is a distinct outcome from a
//! kind this protocol version does not define, and `tests/codegen.rs` proves
//! both lists against the Rust encoders themselves.
//!
//! There is **no transport**. These files build and read canonical payload
//! bytes; the length-delimited framing in [`crate::codec`] is deliberately
//! outside them, because a client that framed a payload the socket layer also
//! frames would be refused, and this package has no socket layer to own that
//! decision.
//!
//! Cross-field invariants are also out of scope. The generated types hold each
//! field's own shape and bounds; rules that relate two fields — a healthy
//! doctor check carrying no reason, a lease-owning Telegram state requiring a
//! poller epoch, an operational projection whose queue counts must sum to the
//! aggregate, a declared digest that names the document beside it — are
//! enforced only by the Rust constructors and by the daemon that answers.
//!
//! The Runs API brings a longer list of these, and naming it is the point: a
//! generated decoder that accepted a page the Rust decoder refuses is a real
//! gap, not a detail. These `automonique.runs` rules relate two fields, and the
//! generated surface does *not* apply them:
//!
//! - `more` agreeing with `next_cursor`
//!   ([`crate::runs_api::RunsApiError::ContinuationIncoherent`]);
//! - a continuation cursor advancing past the page ([`ContinuationRewinds`]);
//! - summaries strictly increasing by submission identity ([`PageOutOfOrder`]);
//! - lifecycle sequences strictly *increasing* ([`LifecycleOutOfOrder`] — the
//!   same variant also names a sequence of zero, which the generated surface
//!   does refuse, because that is one field's own bound);
//! - no carried sequence above `last_sequence`
//!   ([`LifecycleAboveLastSequence`]);
//! - at most one terminal event, last ([`TerminalEventNotLast`]) and only for a
//!   terminal state ([`TerminalEventContradictsState`]);
//! - the declared coverage matching what is carried ([`CoverageIncoherent`]);
//!   and
//! - a resync window that does not end before it starts ([`InvalidBody`]).
//!
//! That list is not a promise: `tests/codegen.rs` carries one payload per rule
//! in the corpus section `rust_only_refusals`, and the TypeScript runner asserts
//! each one *decodes*. So the gap is measured from both sides — a rule the Rust
//! constructors stopped enforcing fails there, and a rule the generator learns
//! fails there too, until the entry moves to `decode_refusals`. A client that
//! must be sure of these reads them from the daemon that enforced them.
//!
//! `automonique.automation` brings the same list, and one exception that runs
//! the other way. The **request** side of the enablement/cause coupling *is*
//! generated: `paused` and `archived` require a stated cause and `enabled`
//! refuses one, which [`crate::automation_api::SetEnablement::new`] decides
//! before a socket is opened, and a builder that sent an incoherent pair would
//! spend a frame to be told what it could have known. It is the one cross-field
//! rule here that a client can apply to a value it is holding rather than to a
//! message it received, so it is the one that crosses. The generated encoder
//! refuses both halves under
//! [`CauseRequired`](crate::automation_api::AutomationApiError::CauseRequired)
//! and
//! [`CauseForbidden`](crate::automation_api::AutomationApiError::CauseForbidden).
//!
//! Every *decoded* relation stays outside, and `tests/codegen.rs` measures each
//! one in `rust_only_refusals` exactly as it does for the Runs API:
//!
//! - a decoded record's state and cause implying each other (the same two
//!   variants, met on the way in rather than on the way out);
//! - a withdrawn row implying revision two or above
//!   ([`WithdrawnAtFirstRevision`]);
//! - page records strictly increasing by durable row identity
//!   ([`PageOutOfOrder`](crate::automation_api::AutomationApiError::PageOutOfOrder));
//! - `more` agreeing with `next_cursor` ([`ContinuationIncoherent`]) and a
//!   continuation cursor reaching the last row it served
//!   ([`ContinuationRewinds`](crate::automation_api::AutomationApiError::ContinuationRewinds));
//!   and
//! - a conflict naming two revisions that disagree
//!   ([`ConflictWithoutDisagreement`]).
//!
//! `automonique.approval` brings a shorter list than either, and one rule that
//! crosses for a reason worth stating. The **write-once revision** *is*
//! generated: `approval_decisions.revision` is pinned to `1` by a database
//! `CHECK` and the ledger has no update path, so "revision is one" is a bound on
//! one field's own value rather than a relation between two, and a generated
//! reader can hold it exactly as it holds a byte length. It is emitted as a
//! bounded integer whose minimum and maximum are both one, refused under
//! [`RowAmended`](crate::approval_api::ApprovalApiError::RowAmended) — the same
//! category
//! [`ApprovalRecordView::new`](crate::approval_api::ApprovalRecordView::new)
//! answers. A client can therefore see for itself that the row it decoded was
//! never amended, which is the whole point of storing the column.
//!
//! What stays outside is what stays outside everywhere: relations between two
//! fields of a decoded message, measured in `rust_only_refusals` —
//!
//! - page records strictly increasing by durable row identity
//!   ([`PageOutOfOrder`](crate::approval_api::ApprovalApiError::PageOutOfOrder));
//!   and
//! - `more` agreeing with `next_cursor`
//!   ([`ContinuationIncoherent`](crate::approval_api::ApprovalApiError::ContinuationIncoherent))
//!   and a continuation cursor reaching the last row it served
//!   ([`ContinuationRewinds`](crate::approval_api::ApprovalApiError::ContinuationRewinds)).
//!
//! Three of that lane's refusals are deliberately *not* on the list, because
//! they are not decoder rules on the Rust side either and a gap list that
//! claimed them would be describing a gap that does not exist:
//! [`PageAboveRequestedSize`](crate::approval_api::ApprovalApiError::PageAboveRequestedSize)
//! and
//! [`PageOutsideSubject`](crate::approval_api::ApprovalApiError::PageOutsideSubject)
//! relate an answer to the *query* it answers, which no decoder holds; and
//! [`ConflictWithoutDisagreement`](crate::approval_api::ApprovalApiError::ConflictWithoutDisagreement)
//! is derived by
//! [`ApprovalResponse::conflict`](crate::approval_api::ApprovalResponse::conflict)
//! at the answering end, where both sides are in hand, and cannot be re-derived
//! from a conflict frame that carries only the recorded side.
//!
//! `automonique.batch.control` brings a longer list than the approval lane and
//! two rules that cross. The **advance receipt's revision** is one: registration
//! is the only writer of revision one, so "an advance's revision is at least
//! two" is a bound on one field's own value, emitted as a bounded integer of
//! domain `2..` and refused under
//! [`NotAnAdvance`](crate::batch_api::BatchApiError::NotAnAdvance) — the same
//! category
//! [`MemberReceiptView::new`](crate::batch_api::MemberReceiptView::new) answers.
//! The **concurrency coupling** is the other, and it crosses in both directions:
//! exactly one of the two words carries a ceiling, which the generated union
//! makes unrepresentable in the type checker and the generated encoder and
//! decoder both refuse at runtime, under the same categories
//! [`concurrency_from_body`](crate::batch_api) and
//! [`ConcurrencyPolicy::bounded_parallel`](crate::batch_runner::ConcurrencyPolicy::bounded_parallel)
//! report.
//!
//! What stays outside is every relation between two fields of a decoded batch
//! message, and this lane has more of them than any other, because a batch *is*
//! a relation between its members:
//!
//! - the carried rollup agreeing with the members beside it
//!   ([`RollupContradictsMembers`](crate::batch_runner::BatchError::RollupContradictsMembers)) —
//!   the rule that makes serving a derived state safe, held by the Rust decoder
//!   and by nothing here;
//! - a membership that is the ordinals `0..n` in order
//!   ([`MembersOutOfOrder`](crate::batch_api::BatchApiError::MembersOutOfOrder) —
//!   the same variant also names an ordinal outside this lane's membership,
//!   which the generated surface *does* refuse, because that is one field's own
//!   bound);
//! - a member key named twice
//!   ([`DuplicateMember`](crate::batch_runner::BatchError::DuplicateMember));
//! - a detail carrying no member at all
//!   ([`EmptyBatch`](crate::batch_runner::BatchError::EmptyBatch) — the empty
//!   *registration* is refused on the way out, because a builder holds the list);
//! - a reported sequence agreeing with the progress beside it
//!   ([`SequenceCoupling`](crate::batch_api::BatchApiError::SequenceCoupling)),
//!   on a request and on a decoded row alike;
//! - an `unsubmitted` member at a revision other than one, and an advance
//!   receipt claiming `unsubmitted`
//!   ([`UnwrittenRevision`](crate::batch_api::BatchApiError::UnwrittenRevision)
//!   and [`NotAnAdvance`](crate::batch_api::BatchApiError::NotAnAdvance)'s other
//!   half);
//! - page rows strictly increasing by durable row identity, `more` agreeing with
//!   `next_cursor`, and a continuation cursor reaching the last row it served;
//!   and
//! - a conflict naming two revisions that agree
//!   ([`ConflictWithoutDisagreement`](crate::batch_api::BatchApiError::ConflictWithoutDisagreement)).
//!
//! [`WithdrawnAtFirstRevision`]: crate::automation_api::AutomationApiError::WithdrawnAtFirstRevision
//! [`ContinuationIncoherent`]: crate::automation_api::AutomationApiError::ContinuationIncoherent
//! [`ConflictWithoutDisagreement`]: crate::automation_api::AutomationApiError::ConflictWithoutDisagreement
//!
//! [`ContinuationRewinds`]: crate::runs_api::RunsApiError::ContinuationRewinds
//! [`PageOutOfOrder`]: crate::runs_api::RunsApiError::PageOutOfOrder
//! [`LifecycleOutOfOrder`]: crate::runs_api::RunsApiError::LifecycleOutOfOrder
//! [`LifecycleAboveLastSequence`]: crate::runs_api::RunsApiError::LifecycleAboveLastSequence
//! [`TerminalEventNotLast`]: crate::runs_api::RunsApiError::TerminalEventNotLast
//! [`TerminalEventContradictsState`]: crate::runs_api::RunsApiError::TerminalEventContradictsState
//! [`CoverageIncoherent`]: crate::runs_api::RunsApiError::CoverageIncoherent
//! [`InvalidBody`]: crate::runs_api::RunsApiError::InvalidBody
//!
//! Regenerate with the command in [`REGENERATE_COMMAND`].
//!
//! Determinism is a property of this module: every collection is emitted in
//! sorted order and nothing time-dependent, host-dependent or randomly ordered
//! reaches the output. A generator that embeds a build time cannot satisfy the
//! zero-diff regeneration rule, so there is no way to ask this one for a
//! timestamp.

use core::fmt::Write as _;

use crate::admin::{
    AdminError, DaemonState, ENDPOINT_MATURITY, ExecutionState, Maturity, OperationalMetric,
    TelegramState,
};
use crate::approval_api::{
    ApprovalApiError, ApprovalDecision, ApprovalDisposition, ApprovalRefusal, ConflictField,
};
use crate::automation::EnablementState;
use crate::automation_api::{
    AutomationApiError, AutomationRefusal, ENABLEMENT_STATES, requires_cause,
};
use crate::batch_api::{BatchApiError, BatchRefusal};
use crate::batch_runner::{BatchError, BatchState, ConcurrencyKind, MemberProgress};
use crate::codec::CodecError;
use crate::digest::Sha256;
use crate::event::{Authority, EventKind, MAX_RETRY_AFTER_MS, RetryCategory, StepStatus};
use crate::platform::{
    FreshnessState, PlatformAction, PlatformMethod, PlatformTransport, ReceiptOutcome,
    ResourceAuthority, ResourceKind,
};
use crate::platform_v2::{
    CheckoutKind, HostSetupKind, WorkContextAvailability, WorkContextKind, WorkContextLifecycle,
    WorkContextRelationKind, WorkContextTargetKind,
};
use crate::platform_v2_lineage::{
    ExternalWorkProvider, ExternalWorkState, LineageFreshnessState, OrchestrationKind,
    WorkspaceIntentConflict,
};
use crate::platform_v2_review::{
    AttentionOriginKind, AttentionReason, AttentionState, CheckState, CommentAgentState,
    ConflictState, DeliveryState, DiffChangeKind, DiffSide, MergeReadiness, PreviewKind,
    PullRequestState, ReviewActionKind, ReviewAuthentication, ReviewAuthorityKind, ReviewDecision,
    ReviewFreshnessState, ReviewProposalKind, ReviewReceiptOutcome, ReviewReconciliation,
    WorktreeFileState,
};
use crate::primitives::ValueError;
use crate::progress_api::{StreamMessageKind, StreamRefusal};
use crate::provenance::MAX_PROVENANCE_ID_BYTES;
use crate::runs_api::{
    LIFECYCLE_AUTHORITIES, LifecycleCoverage, RunState, RunsApiError, RunsRefusal, SpoolEventKind,
    SubmissionState,
};
use crate::schema::EnumSensitivity;
use crate::{CheckStatus, ReportStatus};

/// A branded identifier domain in the generated surface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BrandedId {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
    /// Grammar the whole value must match, in JavaScript regular expression
    /// source without delimiters. See [`BoundedString::pattern`].
    pub pattern: Option<String>,
}

/// A bounded string field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundedString {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
    /// Grammar the whole value must match, in JavaScript regular expression
    /// source without delimiters.
    ///
    /// The emitter wraps it in a Unicode-mode literal, so it must not contain
    /// an unescaped `/`. `None` emits a length check only, which is what the
    /// spike slice uses.
    pub pattern: Option<String>,
}

/// A bounded integer field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundedInteger {
    /// TypeScript type name.
    pub name: String,
    /// Inclusive minimum.
    pub min: i64,
    /// Inclusive maximum.
    pub max: i64,
}

/// One variant of a discriminated union.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnionVariant {
    /// Discriminant value.
    pub tag: String,
    /// Payload field name and TypeScript type, or `None` for a payload-free
    /// variant.
    pub payload: Option<(String, String)>,
}

/// A discriminated union.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Union {
    /// TypeScript type name.
    pub name: String,
    /// Discriminant property name.
    pub discriminant: String,
    /// Variants, emitted in sorted order.
    pub variants: Vec<UnionVariant>,
}

/// An enumeration and how unknown values are treated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedEnum {
    /// TypeScript type name.
    pub name: String,
    /// Whether unknown values are refused or retained.
    pub sensitivity: EnumSensitivity,
    /// Declared values.
    pub values: Vec<String>,
    /// Declaration order, when the wire sorts a set of these into it.
    ///
    /// The generated `_VALUES` table is emitted sorted, because sorting is what
    /// makes the output a pure function of a set. That order is not the wire's:
    /// `RunStateFilter::only` canonicalizes into `RunState::ALL` order, which is
    /// the enum's declaration order. A surface that encodes such a set carries
    /// the second order too, or it cannot reproduce the Rust bytes.
    pub wire_order: Option<Vec<String>>,
}

/// The slice of protocol surface this spike generates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpikeSchema {
    /// Branded identifier domains.
    pub branded_ids: Vec<BrandedId>,
    /// Bounded strings.
    pub bounded_strings: Vec<BoundedString>,
    /// Bounded integers.
    pub bounded_integers: Vec<BoundedInteger>,
    /// Discriminated unions.
    pub unions: Vec<Union>,
    /// Enumerations.
    pub enums: Vec<GeneratedEnum>,
}

/// The deliberately hard slice this spike is judged on.
///
/// Chosen to contain the constructs codegen most often loses, not the
/// constructs it handles easily: exact const bounds, two branded domains, a
/// union with a payload-free variant, both enum sensitivities, and an
/// optional-versus-nullable distinction.
#[must_use]
pub fn hostile_slice() -> SpikeSchema {
    SpikeSchema {
        branded_ids: vec![
            BrandedId {
                name: "SessionId".to_owned(),
                max_bytes: 128,
                pattern: None,
            },
            BrandedId {
                name: "TurnId".to_owned(),
                max_bytes: 64,
                pattern: None,
            },
        ],
        bounded_strings: vec![BoundedString {
            name: "MessageKind".to_owned(),
            max_bytes: 64,
            pattern: None,
        }],
        bounded_integers: vec![BoundedInteger {
            name: "Sequence".to_owned(),
            min: 0,
            max: i64::MAX,
        }],
        unions: vec![Union {
            name: "TurnOutcome".to_owned(),
            discriminant: "kind".to_owned(),
            variants: vec![
                UnionVariant {
                    tag: "cancelled".to_owned(),
                    payload: None,
                },
                UnionVariant {
                    tag: "completed".to_owned(),
                    payload: Some(("text".to_owned(), "string".to_owned())),
                },
                UnionVariant {
                    tag: "failed".to_owned(),
                    payload: Some(("reason".to_owned(), "string".to_owned())),
                },
            ],
        }],
        enums: vec![
            GeneratedEnum {
                name: "ApprovalDecision".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: vec!["allow".to_owned(), "deny".to_owned()],
                wire_order: None,
            },
            GeneratedEnum {
                name: "RunState".to_owned(),
                sensitivity: EnumSensitivity::ReadOnly,
                values: vec!["done".to_owned(), "running".to_owned()],
                wire_order: None,
            },
        ],
    }
}

/// Emit TypeScript for a slice.
///
/// Output is a pure function of the input: collections are sorted, and no
/// clock, environment or allocation address reaches the text.
#[must_use]
pub fn emit_typescript(schema: &SpikeSchema) -> String {
    let mut out = String::new();
    out.push_str("// SPDX-License-Identifier: Apache-2.0\n\n");
    out.push_str("// GENERATED by automonique_protocol::codegen — do not edit by hand.\n");
    out.push_str("// Regenerate with: cargo test -p automonique-protocol --test codegen\n");
    out.push_str("//\n");
    out.push_str("// Rust is the wire source of truth. Hand-written SDK code may add\n");
    out.push_str("// ergonomics; it may not redefine anything in this file.\n\n");

    out.push_str("const encoder = new TextEncoder();\n");
    out.push_str("function byteLength(value: string): number {\n");
    out.push_str("  return encoder.encode(value).length;\n");
    out.push_str("}\n\n");
    out.push_str("function isWellFormedUnicode(value: string): boolean {\n");
    out.push_str("  for (let index = 0; index < value.length; index += 1) {\n");
    out.push_str("    const codeUnit = value.charCodeAt(index);\n");
    out.push_str("    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {\n");
    out.push_str("      const next = value.charCodeAt(index + 1);\n");
    out.push_str("      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;\n");
    out.push_str("      index += 1;\n");
    out.push_str("    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {\n");
    out.push_str("      return false;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  return true;\n");
    out.push_str("}\n\n");
    out.push_str("export class ValidationError extends Error {\n");
    // Keep the output executable by runtimes that implement TypeScript by
    // erasing types only. Constructor parameter properties require a transform
    // and are rejected by Node's strip-only loader.
    out.push_str("  readonly field: string;\n");
    out.push_str("  readonly violation: string;\n");
    out.push_str("  constructor(field: string, violation: string) {\n");
    out.push_str("    super(`${field}: ${violation}`);\n");
    out.push_str("    this.name = \"ValidationError\";\n");
    out.push_str("    this.field = field;\n");
    out.push_str("    this.violation = violation;\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    let mut branded = schema.branded_ids.clone();
    branded.sort();
    for id in &branded {
        emit_branded_id(&mut out, id);
    }

    let mut strings = schema.bounded_strings.clone();
    strings.sort();
    for bounded in &strings {
        emit_bounded_string(&mut out, bounded);
    }

    let mut integers = schema.bounded_integers.clone();
    integers.sort();
    for integer in &integers {
        emit_bounded_integer(&mut out, integer);
    }

    let mut unions = schema.unions.clone();
    unions.sort();
    for union in &unions {
        emit_union(&mut out, union);
    }

    let mut enums = schema.enums.clone();
    enums.sort_by(|left, right| left.name.cmp(&right.name));
    for generated in &enums {
        emit_enum(&mut out, generated);
    }

    // An event this build has never seen must survive decoding with its bounded
    // payload intact. Optional and nullable are distinct: `note` may be absent,
    // `detail` may be present-and-null.
    out.push_str(
        "\nexport interface KnownEvent {\n  \
         readonly kind: \"turn_completed\";\n  \
         readonly note?: string;\n  \
         readonly detail: string | null;\n\
         }\n\
         \n\
         export type DecodedEvent =\n  \
         | {readonly known: true; readonly event: KnownEvent}\n  \
         | {readonly known: false; readonly kind: string; readonly payload: string};\n\
         \n\
         export const MAX_UNKNOWN_EVENT_BYTES = 4096;\n\
         \n\
         export function decodeEvent(kind: string, payload: string): DecodedEvent {\n  \
         if (kind === \"turn_completed\") {\n    \
         return {known: true, event: {kind, detail: null}};\n  \
         }\n  \
         if (byteLength(payload) > MAX_UNKNOWN_EVENT_BYTES) {\n    \
         throw new ValidationError(\"event\", \"unknown_payload_too_large\");\n  \
         }\n  \
         return {known: false, kind, payload};\n\
         }\n",
    );

    out
}

// ---------------------------------------------------------------------------
// Shared emitters
//
// Both halves of this module go through these, which is what keeps a bound
// from being spelled one way in the spike and another way in the maintained
// surface.
// ---------------------------------------------------------------------------

/// Emit the checked constructor shared by branded identifiers and bounded
/// strings.
///
/// Length is measured in UTF-8 bytes because that is what the Rust bound
/// measures; `value.length` counts UTF-16 code units and would accept a
/// multibyte string the daemon refuses.
fn emit_checked_string(out: &mut String, name: &str, max_bytes: usize, pattern: Option<&str>) {
    let _ = writeln!(
        out,
        "export type {name} = string & {{readonly __brand: \"{name}\"}};"
    );
    let _ = writeln!(out, "export const {name}_MAX_BYTES = {max_bytes};");
    if let Some(pattern) = pattern {
        let _ = writeln!(out, "export const {name}_PATTERN = /{pattern}/u;");
    }
    let _ = writeln!(out, "export function {name}(value: string): {name} {{");
    let _ = writeln!(
        out,
        "  if (value.length === 0) throw new ValidationError(\"{name}\", \"empty\");"
    );
    let _ = writeln!(
        out,
        "  if (!isWellFormedUnicode(value)) throw new ValidationError(\"{name}\", \"invalid_character\");"
    );
    let _ = writeln!(
        out,
        "  if (byteLength(value) > {max_bytes}) throw new ValidationError(\"{name}\", \"too_long\");"
    );
    if pattern.is_some() {
        let _ = writeln!(
            out,
            "  if (!{name}_PATTERN.test(value)) throw new ValidationError(\"{name}\", \
             \"invalid_character\");"
        );
    }
    let _ = writeln!(out, "  return value as {name};");
    out.push_str("}\n");
}

/// Emit one branded identifier domain.
fn emit_branded_id(out: &mut String, id: &BrandedId) {
    let _ = writeln!(
        out,
        "\n/** Branded identifier, at most {} UTF-8 bytes. */",
        id.max_bytes
    );
    emit_checked_string(out, &id.name, id.max_bytes, id.pattern.as_deref());
}

/// Emit one bounded string field.
fn emit_bounded_string(out: &mut String, bounded: &BoundedString) {
    let _ = writeln!(
        out,
        "\n/** Bounded string, at most {} UTF-8 bytes. */",
        bounded.max_bytes
    );
    emit_checked_string(
        out,
        &bounded.name,
        bounded.max_bytes,
        bounded.pattern.as_deref(),
    );
}

/// Emit one bounded integer field.
///
/// The carrier is `bigint`: the wire is signed 64-bit and a JavaScript
/// `number` silently loses values above 2^53.
fn emit_bounded_integer(out: &mut String, integer: &BoundedInteger) {
    let BoundedInteger { name, min, max } = integer;
    let _ = writeln!(out, "\n/** Bounded integer in [{min}, {max}]. */");
    let _ = writeln!(
        out,
        "export type {name} = bigint & {{readonly __brand: \"{name}\"}};"
    );
    let _ = writeln!(out, "export const {name}_MIN = {min}n;");
    let _ = writeln!(out, "export const {name}_MAX = {max}n;");
    let _ = writeln!(out, "export function {name}(value: bigint): {name} {{");
    let _ = writeln!(
        out,
        "  if (typeof value !== \"bigint\" || value < {min}n || value > {max}n) throw new ValidationError(\"{name}\", \
         \"out_of_range\");"
    );
    let _ = writeln!(out, "  return value as {name};");
    out.push_str("}\n");
}

/// Emit one discriminated union and its exhaustiveness helper.
fn emit_union(out: &mut String, union: &Union) {
    let mut variants = union.variants.clone();
    variants.sort();
    let _ = write!(out, "\nexport type {} =", union.name);
    for variant in &variants {
        let payload = variant
            .payload
            .as_ref()
            .map_or_else(String::new, |(field, ty)| {
                format!("; readonly {field}: {ty}")
            });
        let _ = write!(
            out,
            "\n  | {{readonly {discriminant}: \"{tag}\"{payload}}}",
            discriminant = union.discriminant,
            tag = variant.tag
        );
    }
    out.push_str(";\n");
    // An exhaustiveness helper: a missing variant makes `never` fail.
    let _ = write!(
        out,
        "\nexport function assertNever{name}(value: never): never {{\n  \
         throw new ValidationError(\"{name}\", `unhandled variant: ${{JSON.stringify(value)}}`);\n\
         }}\n",
        name = union.name
    );
}

/// Emit one enumeration and the decoder its sensitivity demands.
fn emit_enum(out: &mut String, generated: &GeneratedEnum) {
    let mut values = generated.values.clone();
    values.sort();
    let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
    let _ = write!(
        out,
        "\nexport type {name} = {union};\n\
         export const {name}_VALUES: readonly {name}[] = [{list}];\n",
        name = generated.name,
        union = literals.join(" | "),
        list = literals.join(", ")
    );
    if let Some(order) = &generated.wire_order {
        let ordered: Vec<String> = order.iter().map(|value| format!("\"{value}\"")).collect();
        let _ = write!(
            out,
            "/**\n \
             * Declaration order, which is the order the wire carries a set of these in.\n \
             *\n \
             * `{name}_VALUES` is sorted, because a sorted table is what makes this file a\n \
             * pure function of a set. The wire is not sorted that way: the Rust\n \
             * constructor canonicalizes a filter into the order below, so a request built\n \
             * from any other order would encode different bytes.\n \
             */\n\
             export const {name}_WIRE_ORDER: readonly {name}[] = [{list}];\n",
            name = generated.name,
            list = ordered.join(", ")
        );
    }
    match generated.sensitivity {
        EnumSensitivity::SecuritySensitive => {
            let _ = write!(
                out,
                "/** Security-sensitive: an undefined value is refused. */\n\
                 export function decode{name}(value: string): {name} {{\n  \
                 if (!({name}_VALUES as readonly string[]).includes(value)) {{\n    \
                 throw new ValidationError(\"{name}\", \"unknown_enum_value\");\n  \
                 }}\n  \
                 return value as {name};\n\
                 }}\n",
                name = generated.name
            );
        }
        EnumSensitivity::ReadOnly => {
            let _ = write!(
                out,
                "/** Read-only: an undefined value is retained, never given meaning. */\n\
                 export type {name}OrUnknown =\n  \
                 | {{readonly known: true; readonly value: {name}}}\n  \
                 | {{readonly known: false; readonly spelling: string}};\n\
                 export function decode{name}(value: string): {name}OrUnknown {{\n  \
                 return ({name}_VALUES as readonly string[]).includes(value)\n    \
                 ? {{known: true, value: value as {name}}}\n    \
                 : {{known: false, spelling: value}};\n\
                 }}\n",
                name = generated.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Maintained read surface
// ---------------------------------------------------------------------------

/// Environment variable that turns the drift gate into a regeneration.
pub const REGENERATE_ENV: &str = "AUTOMONIQUE_PROTOCOL_REGENERATE";

/// The exact command that rewrites the checked-in generated files.
///
/// It is emitted into every generated file, so a reader who finds one stale
/// does not have to guess. `tests/codegen.rs` asserts the two stay the same
/// command.
pub const REGENERATE_COMMAND: &str =
    "AUTOMONIQUE_PROTOCOL_REGENERATE=1 cargo test -p automonique-protocol --test codegen";

/// Repository-relative directory the generated files are written to.
pub const GENERATED_DIRECTORY: &str = "sdk/typescript/packages/protocol/generated";

/// Extension the generated modules are written with.
///
/// Held apart from the names below so that each name stays a bare stem. It
/// belongs to the target language rather than to any one schema.
const MODULE_EXTENSION: &str = ".ts";

/// Shared helpers every other generated module imports.
pub const RUNTIME_MODULE: &str = "runtime";

/// Re-exports the maintained modules as one import surface.
pub const BARREL_MODULE: &str = "index";

/// The `automonique.doctor/v1` report read surface.
pub const DOCTOR_MODULE: &str = "doctor";

/// The `automonique.admin` status read surface.
pub const ADMIN_STATUS_MODULE: &str = "admin-status";

/// The `automonique.admin` command surface.
pub const ADMIN_COMMAND_MODULE: &str = "admin-command";

/// The `automonique.runs` read surface.
pub const RUNS_MODULE: &str = "runs";

/// The `automonique.automation` control surface.
pub const AUTOMATION_MODULE: &str = "automation";

/// The `automonique.approval` decision surface.
pub const APPROVAL_MODULE: &str = "approval";

/// The `automonique.batch.control` registration surface.
pub const BATCH_MODULE: &str = "batch";

/// The `automonique.progress/v1` frame surface.
pub const PROGRESS_MODULE: &str = "progress";

/// The federated `automonique.platform/v1` client contract.
pub const PLATFORM_MODULE: &str = "platform";
/// Negotiated `automonique.platform/v2` work-context read contract.
pub const WORK_CONTEXT_MODULE: &str = "work-context";
/// Platform v2 typed review and attention sub-contract.
pub const REVIEW_CONTEXT_MODULE: &str = "review-context";
/// Platform negotiation and major-two envelope codecs.
pub const PLATFORM_V2_TRANSPORT_MODULE: &str = "platform-v2-transport";
/// Generated mobile authentication and authorization module stem.
pub const MOBILE_AUTH_MODULE: &str = "mobile-auth";

/// Lowest mobile protocol version this build speaks.
pub const MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION: u16 = 1;

/// Highest mobile protocol version this build speaks.
///
/// Held apart from the `MobileProtocolVersion` value domain on purpose. The
/// domain says which numbers the wire can carry, so an unknown-but-well-formed
/// version decodes and is then *negotiated away*; this pair says which of them
/// this build actually implements. Collapsing the two — the `1..1` domain this
/// surface shipped with — made every version but the current one a malformed
/// value, so a server that advertised `[1, 2]` was refused by a client that
/// would have been perfectly happy to keep speaking `1`.
///
/// Widening the protocol is this constant plus the code that speaks the new
/// version. Nothing else has to learn a second spelling.
pub const MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION: u16 = 1;

/// Maximum protocol versions one discovery document may advertise.
pub const MAX_MOBILE_PROTOCOL_VERSIONS: usize = 8;

/// Smallest mobile protocol version the discovery wire can carry.
///
/// Zero names no version, so the domain starts at one whatever this build
/// happens to speak.
pub const MIN_MOBILE_PROTOCOL_VERSION_VALUE: u16 = 1;

/// Largest mobile protocol version the discovery wire can carry.
///
/// The advertised list is a `u16` sequence, so this is the domain rather than a
/// policy: a value outside it is malformed, not merely unsupported.
pub const MAX_MOBILE_PROTOCOL_VERSION_VALUE: u16 = u16::MAX;

/// Every mobile protocol version this build speaks, ascending.
///
/// This is exactly what a server advertises in `supported_versions` and exactly
/// what a client intersects an advertisement against, so neither side can hold
/// a different idea of the same fact.
#[must_use]
pub fn supported_mobile_protocol_versions() -> Vec<u16> {
    (MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION..=MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION).collect()
}

/// The file one module is written to.
#[must_use]
pub fn module_file_name(module: &str) -> String {
    format!("{module}{MODULE_EXTENSION}")
}

fn module_specifier(module: &str) -> String {
    format!("{module}.js")
}

/// TypeScript name of the branded counter every wire integer uses.
const WIRE_COUNTER: &str = "WireCounter";

/// Grammar for a value that must not contain a Unicode control character.
///
/// `\p{Cc}` is exactly the category `char::is_control` tests in Rust.
const NO_CONTROL_CHARACTERS: &str = "^[^\\p{Cc}]+$";

/// Whether a decoded value may be absent, and how.
///
/// Optional and nullable are different wire facts and the generated types keep
/// them different: an optional field may be missing from the object, a nullable
/// field is always present and may be `null`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// Always present, never `null`.
    Required,
    /// May be absent from the object.
    Optional,
    /// Always present, possibly `null`.
    Nullable,
}

/// One field of a generated interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    /// Wire field name, kept in the wire's own spelling.
    pub name: String,
    /// TypeScript type, before any nullability suffix.
    pub type_name: String,
    /// How the field may be absent.
    pub presence: Presence,
}

/// A generated object type mirroring one wire body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    /// TypeScript type name.
    pub name: String,
    /// One-line description emitted above the declaration.
    pub doc: String,
    /// Fields, emitted in sorted order.
    pub fields: Vec<Field>,
}

/// The value of a generated module-level constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantValue {
    /// A byte or item limit, emitted as a `number`.
    Count(usize),
    /// A stable protocol string, emitted as a string literal.
    Text(String),
    /// A closed list of wire spellings, emitted as a `readonly string[]`.
    ///
    /// Unlike every other collection in this module the order is *kept*: these
    /// are derived from a Rust array whose order is itself the declaration
    /// order, and sorting them would be sorting a fact rather than a
    /// presentation. Determinism is not at risk — the Rust side produces one
    /// order — and the emitted list is a subset of a vocabulary the module also
    /// carries sorted, so a reader can tell the two apart.
    Words(Vec<String>),
}

/// A generated module-level constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constant {
    /// TypeScript binding name.
    pub name: String,
    /// One-line description emitted above the binding.
    pub doc: String,
    /// The value.
    pub value: ConstantValue,
}

/// Names one generated module takes from another.
///
/// Type-only names are held apart from value names because the generated files
/// are executed by runtimes that implement TypeScript by erasing types: a type
/// imported as a value leaves a binding behind that does not exist at runtime.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModuleImport {
    /// Module stem, such as [`ADMIN_STATUS_MODULE`].
    pub module: String,
    /// Value names, emitted in sorted order.
    pub values: Vec<String>,
    /// Type-only names, emitted in sorted order with the `type` modifier.
    pub types: Vec<String>,
}

/// How one request body field's value reaches the wire.
///
/// Every variant carries the refusal category the Rust peer answers for a bad
/// value of that field, rather than sharing one "invalid body" spelling. The
/// categories genuinely differ — a page size outside its range and a cursor
/// above the wire's integer ceiling are different faults with different
/// spellings — and a client told the wrong one cannot act on it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequestValue {
    /// A checked string type generated in this module.
    ///
    /// Its constructor is re-applied when the request is built, so an untyped
    /// caller — the only kind a brand cannot reach, since brands erase at
    /// runtime — is refused rather than allowed to put an overlong value on
    /// the wire.
    Checked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// Opaque bytes carried as lowercase hexadecimal under a byte bound.
    HexBytes {
        /// Generated constant naming the bound, in raw rather than hex bytes.
        max_bytes_constant: String,
        /// Refusal category answered above the bound.
        oversize_category: String,
    },
    /// A checked string that is always present and may be `null`.
    ///
    /// Absent and present-and-null are different wire facts: the Rust decoder
    /// refuses a body missing the key and accepts one carrying an explicit
    /// null, so the generated body type is `T | null` rather than `T?`.
    NullableChecked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// A branded bounded integer, carried as a JSON integer.
    Integer {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A branded bounded integer whose two bounds are *different* faults.
    ///
    /// [`Self::Integer`] answers one category for a value outside its domain,
    /// which is right where the Rust constructor does: `PageSize::new` returns
    /// the same error for zero and for a size above the page bound. A revision
    /// is not like that — zero names a row no writer produced, and a value
    /// above the wire's signed ceiling is a counter the integer-only codec
    /// cannot carry — and a caller told the first when it made the second
    /// cannot act on what it was told.
    RangedInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered below the type's minimum.
        below_category: String,
        /// Category answered above the type's maximum.
        above_category: String,
    },
    /// A closed vocabulary carried as one wire spelling.
    ///
    /// The generated decoder is re-applied on the way out, because a brand
    /// exists only in the type checker: an untyped caller reaches the builder
    /// with any string at all, and this is where an undefined spelling is
    /// stopped rather than put on the wire.
    Enum {
        /// Generated enumeration type.
        type_name: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
    /// A branded bounded integer that is always present and may be `null`.
    ///
    /// Absent and present-and-null are different wire facts, and the Rust
    /// decoder refuses a body missing the key. The generated body type is
    /// therefore `T | null` rather than `T?`.
    NullableInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A nested exact object encoded by a [`BodyObject`] in this module.
    Object {
        /// Generated object type and encoder stem.
        type_name: String,
    },
    /// A nested exact object that is always present and may be `null`.
    NullableObject {
        /// Generated object type and encoder stem.
        type_name: String,
    },
    /// A bounded, possibly empty array of nested exact objects.
    ObjectArray {
        /// Generated object type and encoder stem.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
    },
    /// A nested body whose discriminant decides whether it carries a payload.
    ///
    /// The generated input is the union [`DiscriminatedBody`] declares, and the
    /// encoder it emits is what turns that union into the two-key wire object.
    /// The refusal categories live on the body rather than here, because the
    /// same encoder serves every request that carries one.
    Discriminated {
        /// Generated union type, whose encoder this field calls.
        type_name: String,
    },
    /// A bounded array of checked strings, in the order the caller supplied.
    ///
    /// The order is kept rather than sorted: a batch's declaration order
    /// becomes its members' ordinals, so sorting here would silently renumber
    /// them.
    CheckedArray {
        /// Generated checked-string type of each item.
        type_name: String,
        /// Category answered for an item the constructor refuses.
        refusal_category: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
        /// Category answered for a list that names nothing.
        empty_category: String,
    },
    /// A set of enum spellings canonicalized into declaration order, or `null`.
    NullableEnumSet {
        /// Generated enumeration type.
        type_name: String,
        /// Generated constant carrying the declaration order.
        order_constant: String,
        /// Category answered for a set that admits nothing.
        empty_category: String,
        /// Category answered for a set naming one value twice.
        repeat_category: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
}

/// One field of a request body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestField {
    /// Wire key, in the wire's own spelling.
    pub name: String,
    /// Field name on the generated body interface.
    ///
    /// It differs from [`Self::name`] where the wire spelling names the
    /// encoding rather than the value: a caller supplies `document`, and the
    /// wire carries `document_hex`.
    pub input_name: String,
    /// How the value reaches the wire.
    pub value: RequestValue,
}

impl RequestField {
    /// The TypeScript type a caller supplies, derived from the value kind.
    fn input_type(&self) -> String {
        match &self.value {
            RequestValue::Checked { type_name, .. }
            | RequestValue::Integer { type_name, .. }
            | RequestValue::RangedInteger { type_name, .. }
            | RequestValue::Discriminated { type_name }
            | RequestValue::Object { type_name }
            | RequestValue::Enum { type_name, .. } => type_name.clone(),
            RequestValue::CheckedArray { type_name, .. }
            | RequestValue::ObjectArray { type_name, .. } => {
                format!("readonly {type_name}[]")
            }
            RequestValue::HexBytes { .. } => "Uint8Array".to_owned(),
            RequestValue::NullableChecked { type_name, .. }
            | RequestValue::NullableInteger { type_name, .. }
            | RequestValue::NullableObject { type_name } => format!("{type_name} | null"),
            RequestValue::NullableEnumSet { type_name, .. } => {
                format!("readonly {type_name}[] | null")
            }
        }
    }

    /// Whether the value is read into a local before the entries are built.
    ///
    /// TypeScript discards the narrowing of a property access inside a closure
    /// created after it, and keeps the narrowing of a `const`. Every nullable
    /// field is tested against `null` and then used inside a refusal wrapper,
    /// so every nullable field needs the local.
    const fn needs_local(&self) -> bool {
        matches!(
            self.value,
            RequestValue::NullableChecked { .. }
                | RequestValue::NullableInteger { .. }
                | RequestValue::NullableObject { .. }
                | RequestValue::NullableEnumSet { .. }
        )
    }
}

/// A rule relating one request field's value to whether another may be present.
///
/// The one cross-field rule the generated surface applies, and it applies only
/// on the way *out*: `automonique.automation` requires a stated cause for a
/// withdrawal and refuses one for a resume, which is a property of the request
/// alone. A client holds both halves before it sends anything, so refusing here
/// costs nothing and saves a round trip; the same relation met while *decoding*
/// is a statement about a peer's message and stays with the Rust decoder that
/// owns it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FieldCoupling {
    /// Body field whose value decides, named by its input name.
    pub deciding_field: String,
    /// Body field it governs, named by its input name. Always nullable.
    pub governed_field: String,
    /// Generated constant listing the deciding values that require the
    /// governed one.
    pub requiring_constant: String,
    /// Category answered when the governed value is required and absent.
    pub required_category: String,
    /// Category answered when it is present and admitted by nothing.
    pub forbidden_category: String,
}

/// One request a client can build.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestCommand {
    /// Wire message kind.
    pub kind: String,
    /// TypeScript name stem, such as `SubmitRun`.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Body fields. An empty list is an empty object on the wire, which is
    /// what the Rust decoder requires of a command that carries no arguments.
    pub fields: Vec<RequestField>,
    /// A rule relating two of those fields, applied before any is encoded.
    pub coupling: Option<FieldCoupling>,
}

/// Cross-field validation generated before one request is encoded.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequestValidation {
    /// Exactly one of two nullable fields must be non-null.
    ExactlyOneNonNull {
        left: String,
        right: String,
        refusal_category: String,
    },
    /// A closed action vocabulary fixes the authority of a nested target.
    ActionAuthority {
        action_field: String,
        target_field: String,
        action_authorities: Vec<(String, String)>,
        refusal_category: String,
    },
    /// One dedicated request field must name an exact authority and resource kind.
    ExactCoordinate {
        field: String,
        authority: String,
        kind: String,
        refusal_category: String,
    },
}

/// How one response body field is decoded.
///
/// As with [`RequestValue`], each variant that can be refused carries the
/// category the Rust decoder answers for that field: a submission identity of
/// zero is an unwritten row, an acceptance instant below the epoch is a time
/// refusal, and an undefined state spelling is an enum refusal — three
/// spellings a single "invalid body" would erase.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResponseValue {
    /// A checked string type generated in or imported into this module.
    Checked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// A checked string that is always present and may be `null`.
    ///
    /// The absence of a value is a fact this carries rather than loses: a
    /// resumed automation has no cause, and a reader that folded `null` into
    /// the empty string would have invented a withdrawal with no reason given,
    /// which is the one shape [`crate::automation_api::PauseReason`] refuses to
    /// spell.
    NullableChecked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// A bounded integer type generated in or imported into this module.
    Integer {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
        /// Whether the Rust decoder converts to `u64` before the domain bound.
        ///
        /// Where it does, a negative value is refused as an invalid body
        /// *before* the domain is consulted, and only a non-negative value can
        /// reach the domain's own refusal. The two categories differ — a
        /// submission identity of `-1` is a malformed body, and one of `0` is
        /// an unwritten row — so a reader that applied the domain bound first
        /// would report the wrong one for every negative value.
        unsigned: bool,
    },
    /// A bounded integer whose two bounds are *different* faults.
    ///
    /// [`Self::Integer`] answers one category for a value outside its domain,
    /// which is right where one Rust refusal covers both ends. A member count
    /// is not like that — zero is a batch with nothing in it, and a count above
    /// this lane's ceiling is a membership the transport cannot carry — and the
    /// two are the batch model's refusal and this lane's respectively.
    RangedInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered below the type's minimum.
        below_category: String,
        /// Category answered above the type's maximum.
        above_category: String,
        /// Whether the Rust decoder converts to `u64` before the domain bound.
        unsigned: bool,
    },
    /// A bounded integer that is always present and may be `null`.
    NullableInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A boolean, which the wire carries as `true` or `false` and nothing else.
    Bool,
    /// A closed enumeration, refused rather than retained when undefined.
    Enum {
        /// Generated enumeration type.
        type_name: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
    /// A bounded array of closed enumeration spellings.
    EnumArray {
        /// Generated enumeration type of each item.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
    /// A bounded array of checked strings.
    CheckedArray {
        /// Generated checked-string type of each item.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
        /// Category answered when an item fails its checked-string constructor.
        refusal_category: String,
    },
    /// A bounded array of checked integers.
    IntegerArray {
        /// Generated bounded-integer type of each item.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
        /// Category answered when an item falls outside the integer domain.
        refusal_category: String,
        /// Whether negative wire integers are malformed before domain validation.
        unsigned: bool,
    },
    /// One exact protocol literal, typed as the generated constant.
    ExactString {
        /// TypeScript type, normally `typeof SOME_CONSTANT`.
        type_name: String,
        /// Generated constant carrying the only accepted spelling.
        expected_constant: String,
        /// Category answered when the spelling differs.
        mismatch_category: String,
    },
    /// A nested body decoded by a [`BodyObject`] declared on the same surface.
    Object {
        /// Generated object type.
        type_name: String,
    },
    /// A nested body that is always present and may be `null`.
    NullableObject {
        /// Generated object type.
        type_name: String,
    },
    /// A bounded array of nested bodies.
    ObjectArray {
        /// Generated object type of each item.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
    },
}

/// One field of a response body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResponseField {
    /// Wire key.
    pub name: String,
    /// How it is decoded.
    pub value: ResponseValue,
}

/// A nested wire body that is not itself a message.
///
/// A run summary is carried inside a listing page, inside a detail view, and
/// nowhere on its own. It gets its own type and its own exact-field decoder so
/// the two carriers share one reading of it rather than each spelling the body
/// out again.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BodyObject {
    /// TypeScript type name.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Fields, emitted in sorted order.
    pub fields: Vec<ResponseField>,
}

/// One standalone exact JSON document and whether clients may encode it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JsonDocument {
    /// The exact object schema.
    pub body: BodyObject,
    /// Whether the generated surface emits an encoder as well as a decoder.
    pub encode: bool,
}

/// Exact JSON request/response documents carried directly over HTTP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonSurface {
    /// Refusal category for missing, additional, duplicated, or mistyped fields.
    pub invalid_body_category: String,
    /// Standalone documents emitted in dependency-safe order.
    pub documents: Vec<JsonDocument>,
}

/// Schema-specific generated validator/codec implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedImplementation {
    WorkContext,
    ReviewContext,
    PlatformV2Transport,
}

/// A nested wire body whose discriminant decides its payload.
///
/// One object with two keys — a closed word and a value that is present for
/// exactly one of the words — read as a TypeScript discriminated union rather
/// than as a struct with a nullable field. The two shapes are not the same
/// claim: `{kind: "sequential", max_in_flight: null}` invites a reader to ask
/// what a sequential policy's ceiling is, and the union says there is no such
/// question.
///
/// The generated encoder and decoder both refuse the two incoherent
/// combinations — a bare word carrying a payload, a carrying word without one —
/// because the Rust decoder does, and because a caller that supplied either
/// asked for something this protocol cannot mean.
///
/// The shape is deliberately narrow: any number of payload-free words and
/// exactly one that carries the payload. A second carrying word would need a
/// second payload type and a different emitted decoder, and `tests/codegen.rs`
/// holds the generator to the shape it actually emits.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiscriminatedBody {
    /// TypeScript name of the union.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Wire key carrying the discriminant.
    pub tag_field: String,
    /// Generated enumeration that closes the discriminant.
    pub tag_type: String,
    /// Category answered for a word this build does not define.
    pub unknown_tag_category: String,
    /// Wire key carrying the payload, `null` under every payload-free word.
    pub payload_field: String,
    /// Generated bounded-integer type of the payload.
    pub payload_type: String,
    /// Category answered below the payload's minimum.
    pub payload_below_category: String,
    /// Category answered above the payload's maximum.
    pub payload_above_category: String,
    /// Largest value the Rust decoder converts the payload through before it
    /// judges the domain.
    ///
    /// The ceiling is a `u32` in Rust and the wire is signed 64-bit, so a value
    /// outside the narrower width is a malformed body rather than a domain
    /// refusal — a distinction a decoder that applied the domain first would
    /// report the wrong category for.
    pub payload_wire_max: i64,
    /// Words that carry no payload, emitted in sorted order.
    pub bare_tags: Vec<String>,
    /// The one word that carries the payload.
    pub carrying_tag: String,
    /// Category for a body that is not the exact shape, or whose two keys
    /// disagree.
    pub invalid_body_category: String,
}

/// One response a client can decode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResponseDecoder {
    /// Wire message kind.
    pub kind: String,
    /// TypeScript name of the decoded object type.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Body fields. The correlation identifier is not among them: it lives in
    /// the envelope, and every decoded response carries it.
    pub fields: Vec<ResponseField>,
}

/// A request-building and response-decoding surface for one protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSurface {
    /// Single capitalized word naming the surface, such as `Admin`.
    ///
    /// It names the shared encoder, the response union and the constants, so
    /// the whole surface can be found from any one of them.
    pub name: String,
    /// Generated constant carrying the protocol name.
    pub protocol_constant: String,
    /// The protocol name itself, for the prose that names it.
    pub protocol: String,
    /// Major protocol version these helpers speak, and the only one they admit.
    pub version: u32,
    /// Generated constant carrying the maximum canonical message bytes.
    pub max_message_bytes_constant: String,
    /// Optional request-specific ceiling when responses may be larger.
    ///
    /// When absent, requests use [`Self::max_message_bytes_constant`].
    pub request_max_message_bytes_constant: Option<String>,
    /// The branded correlation-identifier type.
    pub request_id_type: String,
    /// Refusal categories, pinned to the Rust `category()` spellings.
    pub categories: Vec<Constant>,
    /// Category for a body that is not the exact shape its kind defines.
    pub invalid_body_category: String,
    /// Category for a message kind this protocol version does not define.
    pub unknown_kind_category: String,
    /// Category for a canonical payload above the transport's ceiling.
    pub oversize_category: String,
    /// Category for an envelope field that breaks the bounded-value rules.
    pub field_invalid_category: String,
    /// Category for an envelope field that breaks its own grammar.
    pub field_grammar_category: String,
    /// Discriminated nested bodies, emitted before the objects that carry them.
    pub discriminated_bodies: Vec<DiscriminatedBody>,
    /// Nested bodies the requests and responses carry, emitted in name order.
    pub body_objects: Vec<BodyObject>,
    /// Requests, emitted in kind order.
    pub requests: Vec<RequestCommand>,
    /// Kinds this protocol version defines that no generated builder produces.
    pub request_kinds_not_generated: Vec<String>,
    /// Cross-field request checks keyed by request kind.
    pub request_validations: Vec<(String, RequestValidation)>,
    /// Request kind to successful response kind pairs for a correlated client.
    ///
    /// Empty on surfaces that do not publish a request/response client union.
    pub request_response_kinds: Vec<(String, String)>,
    /// Responses, emitted in kind order.
    pub responses: Vec<ResponseDecoder>,
    /// Kinds this protocol version defines that no generated decoder reads.
    ///
    /// These are answered with their own union arm rather than a refusal: a
    /// client that received one was not sent something undefined, and telling
    /// it otherwise would be a lie it might act on.
    pub response_kinds_not_decoded: Vec<String>,
}

/// One generated TypeScript file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneratedModule {
    /// File name within [`GENERATED_DIRECTORY`].
    pub file_name: String,
    /// One-line description emitted into the banner.
    pub doc: String,
    /// Rust path this module is derived from, emitted into the banner.
    pub source: String,
    /// Names taken from sibling generated modules, emitted in sorted order.
    ///
    /// A name is declared in exactly one module and imported everywhere else:
    /// the barrel re-exports every module with `export *`, and two modules
    /// exporting one name would make it ambiguous for every consumer.
    pub imports: Vec<ModuleImport>,
    /// Verbatim TypeScript emitted before the schema-derived declarations.
    ///
    /// This is the escape hatch for [`RUNTIME_MODULE`], whose contents are fixed
    /// prose rather than a description of a wire shape. It is empty in every
    /// other module, and a test holds it that way.
    pub preamble: String,
    /// Module-level constants.
    pub constants: Vec<Constant>,
    /// Branded identifier domains.
    pub branded_ids: Vec<BrandedId>,
    /// Bounded strings.
    pub bounded_strings: Vec<BoundedString>,
    /// Bounded integers.
    pub bounded_integers: Vec<BoundedInteger>,
    /// Enumerations.
    pub enums: Vec<GeneratedEnum>,
    /// Discriminated unions.
    pub unions: Vec<Union>,
    /// Object types.
    pub interfaces: Vec<Interface>,
    /// Exact standalone JSON documents carried without a protocol envelope.
    pub json_surface: Option<JsonSurface>,
    /// The request builders and response decoders this module carries.
    pub command_surface: Option<CommandSurface>,
    /// Validator/codecs whose cross-field invariants exceed declarative field
    /// shapes while remaining generated from the Rust contract.
    pub implementation: Option<GeneratedImplementation>,
}

/// A required field.
fn required(name: &str, type_name: &str) -> Field {
    Field {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        presence: Presence::Required,
    }
}

/// A field that is always present and may be `null`.
fn nullable(name: &str, type_name: &str) -> Field {
    Field {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        presence: Presence::Nullable,
    }
}

/// A required counter field.
fn counter(name: &str) -> Field {
    required(name, WIRE_COUNTER)
}

/// The declared [`ReportStatus`] spellings, pinned to the Rust wire strings.
///
/// The `match` is the point of the closure: a status added to [`ReportStatus`]
/// makes this function fail to compile, so the generated union cannot narrow
/// silently while every test still passes.
fn report_status_values() -> Vec<String> {
    [
        ReportStatus::Healthy,
        ReportStatus::Degraded,
        ReportStatus::Failed,
    ]
    .into_iter()
    .map(|status| match status {
        ReportStatus::Healthy | ReportStatus::Degraded | ReportStatus::Failed => {
            status.as_str().to_owned()
        }
    })
    .collect()
}

/// The declared [`CheckStatus`] spellings, pinned to the Rust wire strings.
fn check_status_values() -> Vec<String> {
    [
        CheckStatus::Healthy,
        CheckStatus::Finding,
        CheckStatus::Unavailable,
    ]
    .into_iter()
    .map(|status| match status {
        CheckStatus::Healthy | CheckStatus::Finding | CheckStatus::Unavailable => {
            status.as_str().to_owned()
        }
    })
    .collect()
}

/// The declared [`DaemonState`] spellings, pinned to the Rust wire strings.
fn daemon_state_values() -> Vec<String> {
    [
        DaemonState::Starting,
        DaemonState::Ready,
        DaemonState::Draining,
        DaemonState::Stopped,
        DaemonState::Failed,
    ]
    .into_iter()
    .map(|state| match state {
        DaemonState::Starting
        | DaemonState::Ready
        | DaemonState::Draining
        | DaemonState::Stopped
        | DaemonState::Failed => state.as_str().to_owned(),
    })
    .collect()
}

/// The canonical [`ExecutionState`] spellings and their decode-only aliases.
///
/// Status is a read surface, so the generated TypeScript enum describes every
/// value its decoder accepts. The first two values come from the Rust enum;
/// the final two are the rolling-upgrade aliases admitted by
/// `ExecutionState::parse` and never emitted by `ExecutionState::as_str`.
fn execution_state_values() -> Vec<String> {
    let mut values: Vec<String> = [
        ExecutionState::SandboxUnavailableLaneWired,
        ExecutionState::SandboxEnforceableLaneWired,
    ]
    .into_iter()
    .map(|state| match state {
        ExecutionState::SandboxUnavailableLaneWired
        | ExecutionState::SandboxEnforceableLaneWired => state.as_str().to_owned(),
    })
    .collect();
    values.extend(
        ["sandbox_unavailable_no_lane", "sandbox_enforceable_no_lane"]
            .into_iter()
            .map(str::to_owned),
    );
    values
}

/// The declared [`Maturity`] spellings, pinned to the Rust wire strings.
fn maturity_values() -> Vec<String> {
    Maturity::ALL
        .into_iter()
        .map(|maturity| match maturity {
            Maturity::Experimental | Maturity::Stable | Maturity::Deprecated => {
                maturity.as_str().to_owned()
            }
        })
        .collect()
}

/// The endpoints [`ENDPOINT_MATURITY`] declares at one maturity.
///
/// Three lists rather than one table of pairs, because a `readonly string[]` is
/// a shape this generator already emits and a list of tuples is not. Nothing is
/// lost: the three partition the table, and a client that wants the pair reads
/// which list a name is in.
///
/// Order is the table's, which is lane order rather than alphabetical, and it is
/// kept for the reason [`ConstantValue::Words`] keeps every order it is given —
/// it is a fact about the declaration rather than a presentation of a set.
fn endpoints_at(maturity: Maturity) -> Vec<String> {
    ENDPOINT_MATURITY
        .iter()
        .filter(|(_, declared)| *declared == maturity)
        .map(|(endpoint, _)| (*endpoint).to_owned())
        .collect()
}

/// The declared [`TelegramState`] spellings, pinned to the Rust wire strings.
fn telegram_state_values() -> Vec<String> {
    [
        TelegramState::DisabledNoClient,
        TelegramState::LeaseOwnedNoClient,
        TelegramState::PollingLive,
    ]
    .into_iter()
    .map(|state| match state {
        TelegramState::DisabledNoClient
        | TelegramState::LeaseOwnedNoClient
        | TelegramState::PollingLive => state.as_str().to_owned(),
    })
    .collect()
}

/// The [`OperationalMetric`] arms, pinned to the Rust discriminant spellings.
///
/// The unavailable arm carries an explicit `null`, not a zero. Substituting
/// zero for missing evidence is the mistake the Rust type exists to prevent,
/// and a generated type that widened `value` to a plain counter would hand it
/// straight back.
fn operational_metric_variants() -> Vec<UnionVariant> {
    [
        OperationalMetric::Measured(0),
        OperationalMetric::Unavailable,
    ]
    .into_iter()
    .map(|metric| {
        let payload = match metric {
            OperationalMetric::Measured(_) => WIRE_COUNTER,
            OperationalMetric::Unavailable => "null",
        };
        UnionVariant {
            tag: metric.state().to_owned(),
            payload: Some(("value".to_owned(), payload.to_owned())),
        }
    })
    .collect()
}

/// The shared runtime helpers, which are prose rather than a wire shape.
fn runtime_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(RUNTIME_MODULE),
        doc: "Helpers the generated modules share.".to_owned(),
        source: "automonique_protocol::codegen".to_owned(),
        preamble: r#"// The canonical JSON codec is not generated twice.
//
// `src/canonical.ts` mirrors `wire.rs` byte for byte and is held to that claim
// by the cross-language corpus in `tests/cross_language.rs`, in both
// directions. A second copy emitted here would be a second thing to keep
// right, and the copy that drifted would be the one nothing measured. This
// line is the whole of the generated tree's dependency on hand-written code:
// every other generated module imports from this file and from nothing else.
export {
  WireError,
  decodeFrameWithLimit,
  decodeMessageAdmitted,
  encodeFrameWithLimit,
  encodeMessage,
  isWellFormedUnicode,
  parseCanonical,
  toCanonicalBytes,
  type JsonValue,
} from "../src/canonical.js";

import {isWellFormedUnicode, type JsonValue} from "../src/canonical.js";

const encoder = new TextEncoder();

/** UTF-8 byte length, which is the unit every protocol bound is stated in. */
export function byteLength(value: string): number {
  return encoder.encode(value).length;
}

/** A value a generated constructor refused, and why. */
export class ValidationError extends Error {
  readonly field: string;
  readonly violation: string;
  constructor(field: string, violation: string) {
    super(`${field}: ${violation}`);
    this.name = "ValidationError";
    this.field = field;
    this.violation = violation;
  }
}

/**
 * Whether an object carries exactly the named fields and no others.
 *
 * The Rust decoders refuse a body with a missing or unexpected key rather
 * than ignoring it. The generated `_FIELDS` arrays are what let a reader
 * apply the same rule.
 */
export function hasExactFields(
  value: Readonly<Record<string, unknown>>,
  fields: readonly string[],
): boolean {
  return (
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

/**
 * A refusal under the stable category the Rust peer reports for it.
 *
 * `ValidationError` says a value this program built is wrong; this says a
 * message was refused, under the spelling the daemon's own logs and refusal
 * metrics use. Keeping the category rather than a sentence is what lets a
 * cross-language fixture assert that both implementations refused the same
 * input for the same reason.
 */
export class RefusalError extends Error {
  readonly category: string;
  constructor(category: string, detail: string) {
    super(`${category}: ${detail}`);
    this.name = "RefusalError";
    this.category = category;
  }
}

/**
 * Run a validating step, reporting the category the Rust peer would report.
 *
 * The generated constructors refuse a value with a `ValidationError`, which is
 * the right error for a caller who built one. Inside an encoder or a decoder
 * the same refusal is a message-level one, and the peer names it with a
 * category; this is where the first becomes the second without losing what was
 * wrong.
 */
export function refuse<T>(category: string, action: () => T): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof ValidationError) {
      throw new RefusalError(category, error.message);
    }
    throw error;
  }
}

/**
 * Refuse an envelope field the way the shared codec does.
 *
 * The codec settles the bounded-value rules before it judges a grammar, and
 * reports the two under different categories: an empty, overlong or
 * control-bearing value is a bounded-value refusal, and only a value that
 * cleared those rules can be refused for its grammar. A single category here
 * would tell a peer its identifier was the wrong shape when the length was
 * what was wrong.
 */
export function refuseField<T>(
  boundsCategory: string,
  grammarCategory: string,
  action: () => T,
): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof ValidationError) {
      const category = error.violation === "invalid_character" ? grammarCategory : boundsCategory;
      throw new RefusalError(category, error.message);
    }
    throw error;
  }
}

/**
 * Refuse a bounded integer, naming which end of the range it fell off.
 *
 * `refuse` reports one category for a value the constructor rejected, which is
 * right where the Rust constructor reports one: a page size of zero and a page
 * size above the bound are the same refusal there. Where the two ends are
 * different faults — a revision of zero names a row no writer produced, a
 * revision above the wire's ceiling is a counter the codec cannot carry — this
 * reports the one the peer would.
 */
export function rangedInteger<T>(
  value: bigint,
  min: bigint,
  belowCategory: string,
  aboveCategory: string,
  make: (value: bigint) => T,
): T {
  try {
    return make(value);
  } catch (error) {
    if (error instanceof ValidationError) {
      throw new RefusalError(value < min ? belowCategory : aboveCategory, error.message);
    }
    throw error;
  }
}

/** A rule relating one field's value to whether another may be present. */
export interface CouplingRule {
  /** Wire name of the field whose value decides. */
  readonly deciding: string;
  /** Wire name of the field it governs. */
  readonly governed: string;
  /** Deciding values that require the governed one. */
  readonly requiring: readonly string[];
  /** Category for a governed value that is required and absent. */
  readonly required: string;
  /** Category for one that is present and admitted by nothing. */
  readonly forbidden: string;
}

/**
 * Apply a coupling before a frame is spent on a request that cannot be right.
 *
 * The Rust constructor decides this too, and so does the durable store behind
 * it, in its own API and in a database `CHECK`. Three checks that cannot
 * disagree are worth more than one: this one refuses a malformed request
 * without opening a socket, and the others refuse a malformed row without
 * trusting this one.
 */
export function coupledField<T>(
  decidingValue: string,
  governedValue: T | null,
  rule: CouplingRule,
): T | null {
  const requires = rule.requiring.includes(decidingValue);
  if (requires && governedValue === null) {
    throw new RefusalError(
      rule.required,
      `${rule.deciding} ${decidingValue} requires a stated ${rule.governed}`,
    );
  }
  if (!requires && governedValue !== null) {
    throw new RefusalError(
      rule.forbidden,
      `${rule.deciding} ${decidingValue} admits no ${rule.governed}`,
    );
  }
  return governedValue;
}

/** Lowercase hexadecimal, two digits per byte. */
export function hexEncode(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Bound an opaque byte string before it is encoded.
 *
 * The two categories are distinct because the Rust constructor's are: a
 * document over the ceiling and an empty one are different faults, and a
 * submitter told only "invalid" cannot tell which it made.
 */
export function boundedBytes(
  value: Uint8Array,
  maxBytes: number,
  oversizeCategory: string,
  emptyCategory: string,
): Uint8Array {
  if (value.length > maxBytes) {
    throw new RefusalError(
      oversizeCategory,
      `${value.length} bytes; maximum is ${maxBytes}`,
    );
  }
  if (value.length === 0) throw new RefusalError(emptyCategory, "empty document");
  return value;
}

/**
 * Bound a list before its items are encoded, keeping the order it was given in.
 *
 * The length is judged before any item is validated, which is the order the
 * Rust constructors judge it in: a membership above the ceiling is refused for
 * being too long, not for whatever its hundred-and-twenty-ninth key turns out
 * to be. The two ends carry different categories because they are different
 * faults — a unit with nothing in it, and a unit larger than the frame can
 * carry — and they are the model's refusal and the transport's respectively.
 *
 * Nothing is sorted and nothing is deduplicated. Where a list's order is its
 * items' ordinals, sorting would silently renumber them.
 */
export function boundedItems<T>(
  values: readonly T[],
  maxItems: number,
  oversizeCategory: string,
  emptyCategory: string,
): readonly T[] {
  if (values.length > maxItems) {
    throw new RefusalError(
      oversizeCategory,
      `${values.length} items; maximum is ${maxItems}`,
    );
  }
  if (values.length === 0) throw new RefusalError(emptyCategory, "empty list");
  return values;
}

/** Refuse an untyped request object whose own enumerable keys are not exact. */
export function exactInputFields(
  value: object,
  fields: readonly string[],
  category: string,
): void {
  if (value === null || Array.isArray(value)) {
    throw new RefusalError(category, "request body is not an object");
  }
  const found = Object.keys(value);
  if (
    found.length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw new RefusalError(category, "request body fields are not exact");
  }
}

/**
 * Read a body whose key set must be exactly `fields`.
 *
 * The Rust decoders refuse a body with a missing or unexpected key rather than
 * ignoring it, so a body carrying one more field than it should is refused
 * here too. The returned map is what the field readers below take, so a
 * decoder cannot read a field it did not first declare.
 */
export function exactFields(
  body: JsonValue,
  fields: readonly string[],
  category: string,
): ReadonlyMap<string, JsonValue> {
  if (body.kind !== "object") throw new RefusalError(category, "body is not an object");
  const found = new Map<string, JsonValue>();
  for (const [key, value] of body.entries) {
    if (found.has(key)) throw new RefusalError(category, `duplicate field ${key}`);
    found.set(key, value);
  }
  if (found.size !== fields.length || !fields.every((field) => found.has(field))) {
    throw new RefusalError(category, "body is not the exact shape for its kind");
  }
  return found;
}

/** A string field, refused when absent or of another JSON type. */
export function bodyString(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): string {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "string") {
    throw new RefusalError(category, `${name} is not a string`);
  }
  return value.value;
}

/** An integer field, refused when absent or of another JSON type. */
export function bodyInteger(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "integer") {
    throw new RefusalError(category, `${name} is not an integer`);
  }
  return value.value;
}

/** A boolean field. The wire carries `true` or `false` and nothing else. */
export function bodyBool(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): boolean {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "bool") {
    throw new RefusalError(category, `${name} is not a boolean`);
  }
  return value.value;
}

/**
 * An integer field the Rust decoder reads through `u64`.
 *
 * A negative value is refused here, before any domain bound is applied, because
 * that is the order the Rust decoders settle it in: `unsigned()` converts and
 * fails as a malformed body, and only a non-negative value ever reaches the
 * domain's own refusal. A reader that let the domain judge the sign would
 * report "unwritten row" for a submission identity of `-1`, which is a
 * different and wrong statement about what the peer sent.
 */
export function bodyUnsigned(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "integer") {
    throw new RefusalError(category, `${name} is not an integer`);
  }
  if (value.value < 0n) throw new RefusalError(category, `${name} is negative`);
  return value.value;
}

/** Read one integer array member. */
export function jsonInteger(value: JsonValue, category: string): bigint {
  if (value.kind !== "integer") throw new RefusalError(category, "array member is not an integer");
  return value.value;
}

/** Read one non-negative integer array member. */
export function jsonUnsigned(value: JsonValue, category: string): bigint {
  const integer = jsonInteger(value, category);
  if (integer < 0n) throw new RefusalError(category, "array member is negative");
  return integer;
}

/**
 * A string field that is always present and may be `null`.
 *
 * Absent and present-and-null are different wire facts, as they are for an
 * integer. A row with no cause carries `null`, and a reader that read the key's
 * absence as the same thing would accept a body Rust refuses.
 */
export function bodyStringOrNull(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): string | null {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  if (value.kind === "null") return null;
  if (value.kind !== "string") {
    throw new RefusalError(category, `${name} is neither a string nor null`);
  }
  return value.value;
}

/**
 * An integer field that is always present and may be `null`.
 *
 * Absent and present-and-null are different wire facts. The Rust decoders
 * refuse a body missing the key and accept one carrying an explicit null, so a
 * reader that treated the two alike would admit a body Rust refuses.
 */
export function bodyIntegerOrNull(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint | null {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  if (value.kind === "null") return null;
  if (value.kind !== "integer") {
    throw new RefusalError(category, `${name} is neither an integer nor null`);
  }
  return value.value;
}

/** A field carrying a nested body, handed to that body's own decoder. */
export function bodyValue(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): JsonValue {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  return value;
}

/** A nested body that is always present and may be `null`. */
export function bodyValueOrNull(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): JsonValue | null {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  return value.kind === "null" ? null : value;
}

/** Retain one string only when it is the exact protocol literal expected. */
export function exactString<T extends string>(
  value: string,
  expected: T,
  category: string,
  field: string,
): T {
  if (value !== expected) throw new RefusalError(category, `${field} is incompatible`);
  return expected;
}

/**
 * A bounded array field.
 *
 * The length is judged before any item is read, exactly as the Rust decoders
 * judge it: a page above its ceiling is refused for being too long, not for
 * whatever its sixty-fifth item turns out to be. The two refusals carry
 * different categories, so the order matters to the peer as well as here.
 */
export function bodyArray(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
  maxItems: number,
  oversizeCategory: string,
): readonly JsonValue[] {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "array") {
    throw new RefusalError(category, `${name} is not an array`);
  }
  if (value.items.length > maxItems) {
    throw new RefusalError(
      oversizeCategory,
      `${name} carries ${value.items.length} items; maximum is ${maxItems}`,
    );
  }
  return value.items;
}

/** A bounded array whose every member must be a string. */
export function bodyStrings(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
  maxItems: number,
  oversizeCategory: string,
): readonly string[] {
  return bodyArray(fields, name, category, maxItems, oversizeCategory).map((value) => {
    if (value.kind !== "string") {
      throw new RefusalError(category, `${name} contains a non-string member`);
    }
    return value.value;
  });
}

/** Apply a reader to a nullable field, keeping `null` the distinct fact it is. */
export function mapNullable<T, U>(value: T | null, read: (value: T) => U): U | null {
  return value === null ? null : read(value);
}

/** How a set of enum spellings is canonicalized before it reaches the wire. */
export interface EnumSetRules {
  /** Declaration order, which is the order the wire carries. */
  readonly order: readonly string[];
  /** Category for a set that admits nothing. */
  readonly empty: string;
  /** Category for a set naming one value twice. */
  readonly repeat: string;
  /** Category for a spelling this build does not define. */
  readonly unknown: string;
}

/**
 * Canonicalize a set of enum spellings the way the Rust constructor does.
 *
 * Sorted into declaration order, so a set built in any order encodes
 * identically. An empty set and a repeated value are refused rather than
 * quietly accepted: both mean the caller asked for something other than what it
 * believes it asked for, and an empty filter in particular admits nothing that
 * any listing could ever answer.
 *
 * A spelling outside the order is refused too. A brand exists only in the type
 * checker, so this is the only place an untyped caller's undefined state can be
 * stopped before it reaches the wire.
 */
export function orderedEnumSet<T extends string>(
  values: readonly T[],
  rules: EnumSetRules,
): readonly T[] {
  if (values.length === 0) throw new RefusalError(rules.empty, "a filter admits no value");
  const found: {readonly at: number; readonly value: T}[] = [];
  for (const value of values) {
    const at = rules.order.indexOf(value);
    if (at < 0) throw new RefusalError(rules.unknown, value);
    found.push({at, value});
  }
  found.sort((left, right) => left.at - right.at);
  let previous = -1;
  for (const entry of found) {
    if (entry.at === previous) throw new RefusalError(rules.repeat, entry.value);
    previous = entry.at;
  }
  return found.map((entry) => entry.value);
}
"#
        .to_owned(),
        ..GeneratedModule::default()
    }
}

fn platform_v2_transport_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(PLATFORM_V2_TRANSPORT_MODULE),
        doc: "Strict Platform negotiation and major-two envelope codecs.".to_owned(),
        source: "automonique_protocol::platform_v2_transport".to_owned(),
        constants: vec![
            Constant {
                name: "PLATFORM_NEGOTIATION_PROTOCOL".to_owned(),
                doc: "Protocol used only for Platform major negotiation.".to_owned(),
                value: ConstantValue::Text(
                    crate::platform_v2_transport::PLATFORM_NEGOTIATION_PROTOCOL.to_owned(),
                ),
            },
            Constant {
                name: "PLATFORM_NEGOTIATION_MAJOR".to_owned(),
                doc: "Negotiation protocol major.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::PLATFORM_NEGOTIATION_MAJOR as usize,
                ),
            },
            Constant {
                name: "PLATFORM_V2_MAJOR".to_owned(),
                doc: "Structured Platform protocol major.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::PLATFORM_V2_MAJOR as usize,
                ),
            },
            Constant {
                name: "MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical negotiation request bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical negotiation response bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical Platform v2 request bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical Platform v2 response bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_transport::MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
                ),
            },
        ],
        implementation: Some(GeneratedImplementation::PlatformV2Transport),
        ..GeneratedModule::default()
    }
}

/// The `automonique.doctor/v1` report read surface.
fn doctor_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(DOCTOR_MODULE),
        doc: "The doctor report a client reads, and nothing it may write.".to_owned(),
        source: "automonique_protocol (crate root)".to_owned(),
        constants: vec![
            Constant {
                name: "DOCTOR_REPORT_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one report.".to_owned(),
                value: ConstantValue::Text(crate::DOCTOR_REPORT_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "MAX_DOCTOR_CHECKS".to_owned(),
                doc: "Maximum number of checks one report may carry.".to_owned(),
                value: ConstantValue::Count(crate::MAX_DOCTOR_CHECKS),
            },
        ],
        bounded_strings: vec![
            BoundedString {
                name: "FindingCode".to_owned(),
                max_bytes: crate::MAX_FINDING_CODE_BYTES,
                pattern: Some("^[a-z][a-z0-9._-]*$".to_owned()),
            },
            BoundedString {
                name: "FindingMessage".to_owned(),
                max_bytes: crate::MAX_FINDING_MESSAGE_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        enums: vec![
            GeneratedEnum {
                name: "CheckStatus".to_owned(),
                // Refusing an undefined severity is the conservative reading:
                // a client that retained one would have to decide what it
                // means, and the safe-looking guess is the wrong one.
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: check_status_values(),
                wire_order: None,
            },
            GeneratedEnum {
                name: "ReportStatus".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: report_status_values(),
                wire_order: None,
            },
        ],
        interfaces: vec![
            Interface {
                name: "DoctorReason".to_owned(),
                doc: "Why one check is not healthy: a stable code and a bounded explanation."
                    .to_owned(),
                fields: vec![
                    required("code", "FindingCode"),
                    required("message", "FindingMessage"),
                ],
            },
            Interface {
                name: "DoctorCheck".to_owned(),
                doc: "One check outcome. Whether a reason is required follows from the status, \
                      which only the Rust constructor enforces."
                    .to_owned(),
                fields: vec![
                    required("code", "FindingCode"),
                    nullable("reason", "DoctorReason"),
                    required("status", "CheckStatus"),
                ],
            },
            Interface {
                name: "DoctorReportV1".to_owned(),
                doc: "A whole report. Checks arrive sorted by code, with no code repeated."
                    .to_owned(),
                fields: vec![
                    required("checks", "readonly DoctorCheck[]"),
                    required("schema", "typeof DOCTOR_REPORT_SCHEMA_V1"),
                    required("status", "ReportStatus"),
                ],
            },
        ],
        ..GeneratedModule::default()
    }
}

/// The `automonique.admin` status read surface.
fn admin_status_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(ADMIN_STATUS_MODULE),
        doc: "The status snapshot the local admin socket answers with.".to_owned(),
        source: "automonique_protocol::admin".to_owned(),
        constants: vec![
            Constant {
                name: "ADMIN_CAPABILITY".to_owned(),
                doc: "What this build's local endpoints can do, as one monotonic integer. A \
                      client compares it against the number it was written for; it never \
                      assumes the two must be equal."
                    .to_owned(),
                value: ConstantValue::Count(
                    usize::try_from(crate::admin::ADMIN_CAPABILITY)
                        .expect("the capability integer fits a usize"),
                ),
            },
            Constant {
                name: "ADMIN_PROTOCOL".to_owned(),
                doc: "Stable protocol name for local daemon administration.".to_owned(),
                value: ConstantValue::Text(crate::admin::ADMIN_PROTOCOL.to_owned()),
            },
            Constant {
                name: "DEPRECATED_ENDPOINTS".to_owned(),
                doc: "Endpoints still served and going away. New clients use their \
                      replacements."
                    .to_owned(),
                value: ConstantValue::Words(endpoints_at(Maturity::Deprecated)),
            },
            Constant {
                name: "EXPERIMENTAL_ENDPOINTS".to_owned(),
                doc: "Endpoints that may change shape or disappear. Depend on one \
                      deliberately."
                    .to_owned(),
                value: ConstantValue::Words(endpoints_at(Maturity::Experimental)),
            },
            Constant {
                name: "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes the local admin transport accepts."
                    .to_owned(),
                value: ConstantValue::Count(crate::admin::MAX_ADMIN_CANONICAL_BYTES),
            },
            Constant {
                name: "STABLE_ENDPOINTS".to_owned(),
                doc: "Endpoints that will not change shape incompatibly. A removal is a \
                      deprecation first and a capability bump second."
                    .to_owned(),
                value: ConstantValue::Words(endpoints_at(Maturity::Stable)),
            },
        ],
        branded_ids: vec![BrandedId {
            name: "AdminInstanceId".to_owned(),
            max_bytes: crate::admin::MAX_INSTANCE_ID_BYTES,
            pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
        }],
        bounded_integers: vec![BoundedInteger {
            // Every counter in this surface is a `u64` the wire refuses above
            // the signed ceiling, so one branded carrier covers all of them.
            name: WIRE_COUNTER.to_owned(),
            min: 0,
            max: i64::MAX,
        }],
        enums: vec![
            GeneratedEnum {
                name: "DaemonState".to_owned(),
                // `DaemonState::parse` refuses an undefined spelling with
                // `AdminError::UnknownState`; the generated decoder matches it.
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: daemon_state_values(),
                wire_order: None,
            },
            GeneratedEnum {
                name: "ExecutionState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: execution_state_values(),
                wire_order: None,
            },
            GeneratedEnum {
                name: "Maturity".to_owned(),
                // A client decides whether to depend on an endpoint from this.
                // Retaining a spelling this build does not define would mean
                // guessing how much of a promise the endpoint is.
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: maturity_values(),
                wire_order: None,
            },
            GeneratedEnum {
                name: "TelegramState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: telegram_state_values(),
                wire_order: None,
            },
        ],
        unions: vec![Union {
            name: "OperationalMetric".to_owned(),
            discriminant: "state".to_owned(),
            variants: operational_metric_variants(),
        }],
        interfaces: vec![
            Interface {
                name: "DurableStateCounts".to_owned(),
                doc: "What the daemon's durable stores hold, counted while the status was \
                      answered. Each field is one read of one store and they are not one \
                      transaction; a store that could not be counted is `unavailable`, never \
                      zero. `automation_scheduler_workers` reads the worker with custody of \
                      the automation registry and the scheduler core rather than a store: one \
                      on its thread, zero when it stopped on a fault, `unavailable` when none \
                      was composed."
                    .to_owned(),
                fields: vec![
                    required("approvals_recorded", "OperationalMetric"),
                    required("automation_scheduler_workers", "OperationalMetric"),
                    required("automations_registered", "OperationalMetric"),
                    required("open_tenure_epoch", "OperationalMetric"),
                    required("open_tenures", "OperationalMetric"),
                    required("runs_registered", "OperationalMetric"),
                    required("tenures_recorded", "OperationalMetric"),
                ],
            },
            Interface {
                name: "OperationalStatus".to_owned(),
                doc: "The low-cardinality projection observed in the same status transaction."
                    .to_owned(),
                fields: vec![
                    counter("observed_ms"),
                    counter("outbox_dead_lettered"),
                    counter("outbox_delivered"),
                    counter("outbox_in_flight_ambiguous"),
                    counter("outbox_in_flight_live"),
                    counter("outbox_oldest_ready_age_ms"),
                    counter("outbox_pending_delayed"),
                    counter("outbox_pending_ready"),
                    required("provider_available", "OperationalMetric"),
                    counter("reconciliation_pending"),
                    required("sandbox_launch_refusals", "OperationalMetric"),
                    required("telegram_offset_lag", "OperationalMetric"),
                    counter("telegram_pollers_expired"),
                    counter("telegram_pollers_live"),
                ],
            },
            Interface {
                name: "DaemonStatus".to_owned(),
                doc: "One consistent snapshot. `operational` and `durable_state` are always \
                      present; only `telegram_poller_epoch` may be null. `capability` is the \
                      answering daemon's, which is not necessarily this client's \
                      `ADMIN_CAPABILITY`."
                    .to_owned(),
                fields: vec![
                    required("accepting_intake", "boolean"),
                    counter("capability"),
                    required("durable_state", "DurableStateCounts"),
                    counter("event_cursor"),
                    required("execution_state", "ExecutionState"),
                    counter("generation"),
                    counter("inbox_pending"),
                    required("instance_id", "AdminInstanceId"),
                    required("intake_paused", "boolean"),
                    required("operational", "OperationalStatus"),
                    counter("outbox_pending"),
                    counter("running"),
                    required("state", "DaemonState"),
                    nullable("telegram_poller_epoch", WIRE_COUNTER),
                    required("telegram_state", "TelegramState"),
                ],
            },
        ],
        ..GeneratedModule::default()
    }
}

/// A refusal category, pinned to the Rust spelling a peer reports.
fn category(name: &str, doc: &str, error: &AdminError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A request field whose value is a checked string.
fn checked_field(name: &str, type_name: &str, refusal_category: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
        },
    }
}

/// A response field carrying a durable row identity.
fn row_id_field(name: &str, refusal_category: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: DURABLE_ROW_ID.to_owned(),
            refusal_category: refusal_category.to_owned(),
            // The admin lane reports one category for both faults, so reading
            // the sign separately would change nothing a peer can observe.
            unsigned: false,
        },
    }
}

/// TypeScript name of the branded durable row identity.
const DURABLE_ROW_ID: &str = "DurableRowId";

/// The `automonique.admin` command surface: what a client sends, and what it
/// can read back.
fn admin_command_module() -> GeneratedModule {
    let digest_hex_digits = crate::digest::DIGEST_BYTES * 2;
    let digest_algorithm = crate::digest::ALGORITHM;
    GeneratedModule {
        file_name: module_file_name(ADMIN_COMMAND_MODULE),
        doc: "The admin commands a client builds and the receipts it decodes.".to_owned(),
        source: "automonique_protocol::admin".to_owned(),
        imports: vec![ModuleImport {
            module: ADMIN_STATUS_MODULE.to_owned(),
            values: vec![
                "ADMIN_PROTOCOL".to_owned(),
                "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
            ],
            types: Vec::new(),
        }],
        constants: vec![Constant {
            name: "MAX_SUBMITTED_RUN_SPEC_BYTES".to_owned(),
            doc: "Maximum raw RunSpec document bytes this lane carries. The wire spends twice \
                  this, because the document travels hex-encoded."
                .to_owned(),
            value: ConstantValue::Count(crate::admin::MAX_SUBMITTED_RUN_SPEC_BYTES),
        }],
        bounded_strings: vec![
            BoundedString {
                name: "AdminRefusalCategory".to_owned(),
                max_bytes: crate::admin::MAX_ADMIN_REFUSAL_CATEGORY_BYTES,
                pattern: Some("^[a-z0-9_]+$".to_owned()),
            },
            BoundedString {
                name: "IntakeActor".to_owned(),
                max_bytes: crate::admin::MAX_INTAKE_ACTOR_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "IntakeReason".to_owned(),
                max_bytes: crate::admin::MAX_INTAKE_REASON_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "RequestId".to_owned(),
                max_bytes: crate::codec::MAX_REQUEST_ID_BYTES,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
            BoundedString {
                name: "RunId".to_owned(),
                max_bytes: crate::tools::MAX_TOOL_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "RunSubmissionKey".to_owned(),
                max_bytes: crate::admin::MAX_RUN_SUBMISSION_KEY_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // The canonical spelling is the algorithm name, a colon and the
                // hex body, which is the only spelling `Sha256Digest::from_str`
                // accepts: uppercase is refused rather than folded, so one
                // digest has one spelling on this wire.
                name: "SpecDigest".to_owned(),
                max_bytes: digest_algorithm.len() + 1 + digest_hex_digits,
                pattern: Some(format!(
                    "^{digest_algorithm}:[0-9a-f]{{{digest_hex_digits}}}$"
                )),
            },
        ],
        bounded_integers: vec![BoundedInteger {
            // A durable row identity starts at one: the Rust encoder refuses
            // zero rather than reporting an unwritten row as committed.
            name: DURABLE_ROW_ID.to_owned(),
            min: 1,
            max: i64::MAX,
        }],
        command_surface: Some(CommandSurface {
            name: "Admin".to_owned(),
            protocol_constant: "ADMIN_PROTOCOL".to_owned(),
            protocol: crate::admin::ADMIN_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: None,
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                category(
                    "ADMIN_DOCUMENT_TOO_LARGE",
                    "A carried RunSpec document is larger than one admin frame can hold.",
                    &AdminError::DocumentTooLarge {
                        max_bytes: 0,
                        actual_bytes: 0,
                    },
                ),
                category(
                    "ADMIN_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &AdminError::InvalidBody,
                ),
                category(
                    "ADMIN_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &AdminError::UnknownKind,
                ),
                Constant {
                    // The envelope's own fields are judged by the shared codec
                    // rather than by this protocol, so its categories are the
                    // ones a peer receives for them. Both are pinned to
                    // `CodecError::category` rather than spelled here.
                    name: "WIRE_FIELD_GRAMMAR".to_owned(),
                    doc: "An envelope field cleared the bounded-value rules and broke its own \
                          grammar."
                        .to_owned(),
                    value: ConstantValue::Text(
                        CodecError::Grammar {
                            field: "request_id",
                        }
                        .category()
                        .to_owned(),
                    ),
                },
                Constant {
                    name: "WIRE_FIELD_INVALID".to_owned(),
                    doc: "An envelope field was empty, too long, or carried a control character."
                        .to_owned(),
                    value: ConstantValue::Text(
                        CodecError::Field {
                            field: "request_id",
                            error: ValueError::Empty,
                        }
                        .category()
                        .to_owned(),
                    ),
                },
                Constant {
                    // This one is not an `AdminError`: it is the spelling both
                    // ends of the shipped transport report for a payload above
                    // the ceiling, before any message is built or parsed. The
                    // protocol crate has no constant for it, so nothing pins
                    // it; `automonique-daemon` and `automonique-cli` are where
                    // it is written.
                    name: "ADMIN_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above the ceiling the local transport accepts."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "ADMIN_INVALID_BODY".to_owned(),
            unknown_kind_category: "ADMIN_UNKNOWN_KIND".to_owned(),
            oversize_category: "ADMIN_FRAME_SIZE".to_owned(),
            field_invalid_category: "WIRE_FIELD_INVALID".to_owned(),
            field_grammar_category: "WIRE_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: Vec::new(),
            body_objects: Vec::new(),
            requests: vec![
                RequestCommand {
                    kind: "status".to_owned(),
                    name: "Status".to_owned(),
                    doc: "Read a consistent daemon status snapshot.".to_owned(),
                    fields: Vec::new(),
                    coupling: None,
                },
                RequestCommand {
                    kind: "metrics".to_owned(),
                    name: "Metrics".to_owned(),
                    doc: "Read a Prometheus metrics snapshot.".to_owned(),
                    fields: Vec::new(),
                    coupling: None,
                },
                RequestCommand {
                    kind: "submit_run".to_owned(),
                    name: "SubmitRun".to_owned(),
                    doc: "Take durable custody of one canonical RunSpec document. Acceptance is \
                          custody, not execution."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "document_hex".to_owned(),
                            input_name: "document".to_owned(),
                            value: RequestValue::HexBytes {
                                max_bytes_constant: "MAX_SUBMITTED_RUN_SPEC_BYTES".to_owned(),
                                oversize_category: "ADMIN_DOCUMENT_TOO_LARGE".to_owned(),
                            },
                        },
                        checked_field("idempotency_key", "RunSubmissionKey", "ADMIN_INVALID_BODY"),
                        checked_field("spec_digest", "SpecDigest", "ADMIN_INVALID_BODY"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "pause_intake".to_owned(),
                    name: "PauseIntake".to_owned(),
                    doc: "Durably close intake for this generation, naming the deciding operator \
                          and the cause."
                        .to_owned(),
                    fields: vec![
                        checked_field("actor", "IntakeActor", "ADMIN_INVALID_BODY"),
                        checked_field("reason", "IntakeReason", "ADMIN_INVALID_BODY"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "resume_intake".to_owned(),
                    name: "ResumeIntake".to_owned(),
                    doc: "Reopen intake, naming the operator who decided to.".to_owned(),
                    fields: vec![checked_field("actor", "IntakeActor", "ADMIN_INVALID_BODY")],
                    coupling: None,
                },
                RequestCommand {
                    kind: "shutdown".to_owned(),
                    name: "Shutdown".to_owned(),
                    doc: "Stop intake and request an orderly shutdown.".to_owned(),
                    fields: Vec::new(),
                    coupling: None,
                },
            ],
            request_kinds_not_generated: vec![
                "fail_reconciliation".to_owned(),
                "generations".to_owned(),
                "inspect_outbox".to_owned(),
                "inspect_reconciliation".to_owned(),
                "reconcile_outbox".to_owned(),
                "reload".to_owned(),
                "rollback".to_owned(),
                "reload_status".to_owned(),
                "submit_synthetic".to_owned(),
            ],
            request_validations: Vec::new(),
            request_response_kinds: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "intake_paused".to_owned(),
                    name: "IntakePaused".to_owned(),
                    doc: "Intake is durably closed for this generation. The decision outlives \
                          the process."
                        .to_owned(),
                    fields: vec![
                        row_id_field("pause_id", "ADMIN_INVALID_BODY"),
                        row_id_field("revision", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "intake_resumed".to_owned(),
                    name: "IntakeResumed".to_owned(),
                    doc: "A durable pause was closed and intake reopened. The pause row is \
                          retained, not deleted."
                        .to_owned(),
                    fields: vec![
                        row_id_field("pause_id", "ADMIN_INVALID_BODY"),
                        row_id_field("revision", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "Refused".to_owned(),
                    doc: "The request was definitely refused before a successful mutation."
                        .to_owned(),
                    fields: vec![ResponseField {
                        name: "category".to_owned(),
                        value: ResponseValue::Checked {
                            type_name: "AdminRefusalCategory".to_owned(),
                            refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                        },
                    }],
                },
                ResponseDecoder {
                    kind: "run_accepted".to_owned(),
                    name: "RunAccepted".to_owned(),
                    doc: "One RunSpec document is durably held. Custody is all this reports: it \
                          is not an admission decision and not a launch."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "replay".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "run_id".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "RunId".to_owned(),
                                refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "spec_digest".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "SpecDigest".to_owned(),
                                refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                            },
                        },
                        row_id_field("submission_id", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "shutdown_accepted".to_owned(),
                    name: "ShutdownAccepted".to_owned(),
                    doc: "The daemon accepted an orderly-shutdown request and closed intake."
                        .to_owned(),
                    fields: Vec::new(),
                },
            ],
            response_kinds_not_decoded: vec![
                "generations_result".to_owned(),
                "outbox_inspected".to_owned(),
                "outbox_reconciled".to_owned(),
                "reconciliation_failed".to_owned(),
                "reconciliation_inspected".to_owned(),
                "reload_succeeded".to_owned(),
                "reload_accepted".to_owned(),
                "rollback_succeeded".to_owned(),
                "rollback_accepted".to_owned(),
                "reload_status_result".to_owned(),
                "metrics_result".to_owned(),
                "status_result".to_owned(),
                "synthetic_accepted".to_owned(),
            ],
        }),
        ..GeneratedModule::default()
    }
}

// ---------------------------------------------------------------------------
// The `automonique.runs` read surface
//
// The six closed vocabularies below are each built by mapping the Rust array
// through an exhaustive `match`. The `match` is the whole point: a variant
// added to any of these enums fails to compile here rather than dropping out of
// the generated union while every test still passes. Two of them —
// `RunState` and `SpoolEventKind` — mirror vocabularies this dependency-free
// crate cannot import, and `tests/runs_api.rs` pins those against the sibling
// crate's own source; this file inherits that pin by reading the mirror.
// ---------------------------------------------------------------------------

/// The declared [`RunState`] spellings, pinned to the Rust wire strings.
fn run_state_values() -> Vec<String> {
    RunState::ALL
        .into_iter()
        .map(|state| match state {
            RunState::Ready
            | RunState::Running
            | RunState::Completed
            | RunState::Failed
            | RunState::Cancelled
            | RunState::TimedOut => state.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`SubmissionState`] spellings, pinned to the Rust wire strings.
fn submission_state_values() -> Vec<String> {
    SubmissionState::ALL
        .into_iter()
        .map(|state| match state {
            SubmissionState::Accepted => state.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`SpoolEventKind`] spellings, pinned to the Rust wire strings.
fn spool_event_kind_values() -> Vec<String> {
    SpoolEventKind::ALL
        .into_iter()
        .map(|kind| match kind {
            SpoolEventKind::Started
            | SpoolEventKind::AdapterEvent
            | SpoolEventKind::SimulationEvent
            | SpoolEventKind::CancelRequested
            | SpoolEventKind::Terminal => kind.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`LifecycleCoverage`] spellings, pinned to the Rust wire
/// strings.
fn lifecycle_coverage_values() -> Vec<String> {
    LifecycleCoverage::ALL
        .into_iter()
        .map(|coverage| match coverage {
            LifecycleCoverage::Complete | LifecycleCoverage::Truncated => {
                coverage.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`RunsRefusal`] spellings, pinned to the Rust wire strings.
fn runs_refusal_values() -> Vec<String> {
    RunsRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            RunsRefusal::UnknownRun => refusal.as_str().to_owned(),
        })
        .collect()
}

/// The authorities a lifecycle event may carry.
///
/// Taken from [`LIFECYCLE_AUTHORITIES`] rather than from a spelling table of
/// its own, exactly as `runs_api` takes it: the spool's authority and this
/// crate's are the same two words, and writing them down a third time would be
/// a third thing to keep right.
fn lifecycle_authority_values() -> Vec<String> {
    LIFECYCLE_AUTHORITIES
        .into_iter()
        .map(|authority| match authority {
            Authority::Authoritative | Authority::Synthetic => authority.as_str().to_owned(),
        })
        .collect()
}

/// A refusal category, pinned to the spelling the Runs API reports for it.
fn runs_category(name: &str, doc: &str, error: &RunsApiError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A security-sensitive enumeration of the Runs API.
fn runs_enum(name: &str, values: Vec<String>, wire_order: Option<Vec<String>>) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        // Every vocabulary on this lane is a `SecuritySensitiveEnum` in Rust,
        // whose decoder answers `unknown_enum_value` rather than a default. A
        // generated reader that retained an undefined state would have to decide
        // what it means, and would decide wrong.
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order,
    }
}

/// A response or nested-body field carrying a closed vocabulary.
fn enum_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Enum {
            type_name: type_name.to_owned(),
            unknown_category: "RUNS_UNKNOWN_ENUM_VALUE".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded integer.
///
/// `unsigned` mirrors which Rust reader the field goes through: `unsigned()`
/// converts to `u64` and refuses a negative as an invalid body before the
/// domain is consulted, while an instant is read as a signed integer and
/// refused by the domain itself. Getting this wrong reports the domain's
/// category for a malformed body.
fn runs_integer_field(
    name: &str,
    type_name: &str,
    refusal_category: &str,
    unsigned: bool,
) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
            unsigned,
        },
    }
}

/// TypeScript name of the branded acceptance instant.
const EPOCH_MILLIS: &str = "EpochMillis";

/// TypeScript name of the branded listing position.
const RUN_CURSOR: &str = "RunCursor";

/// The `automonique.runs` read surface: what a client asks, and what it decodes.
fn runs_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(RUNS_MODULE),
        doc: "The native Runs API read surface: list runs, read one run, turn a page.".to_owned(),
        source: "automonique_protocol::runs_api".to_owned(),
        // A name is declared in exactly one module. `RequestId`, `RunId`,
        // `SpecDigest` and `DurableRowId` are wire vocabularies rather than
        // admin ones — a run identity is the same domain on both lanes — so
        // this module reads them from where they are declared rather than
        // declaring a second, separately-drifting copy.
        imports: vec![ModuleImport {
            module: ADMIN_COMMAND_MODULE.to_owned(),
            values: vec![
                DURABLE_ROW_ID.to_owned(),
                "RequestId".to_owned(),
                "RunId".to_owned(),
                "SpecDigest".to_owned(),
            ],
            types: Vec::new(),
        }],
        constants: vec![
            Constant {
                name: "MAX_LIFECYCLE_EVENTS".to_owned(),
                doc: "Maximum lifecycle events one detail view may carry.".to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_LIFECYCLE_EVENTS),
            },
            Constant {
                name: "MAX_RUNS_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes this protocol will assemble or admit."
                    .to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_RUNS_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_RUN_PAGE_ITEMS".to_owned(),
                doc: "Maximum summaries one listing page may carry. A page bound is not a paging \
                      hint: a longer page is refused rather than truncated, because a truncated \
                      page that still answered `complete` is the silent drop the retention rule \
                      forbids."
                    .to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_RUN_PAGE_ITEMS),
            },
            Constant {
                name: "RUNS_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one read surface.".to_owned(),
                value: ConstantValue::Text(crate::runs_api::RUNS_API_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "RUNS_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the native Runs API.".to_owned(),
                value: ConstantValue::Text(crate::runs_api::RUNS_PROTOCOL.to_owned()),
            },
        ],
        branded_ids: vec![
            BrandedId {
                name: "CausationId".to_owned(),
                max_bytes: MAX_PROVENANCE_ID_BYTES,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
            BrandedId {
                name: "CorrelationId".to_owned(),
                max_bytes: MAX_PROVENANCE_ID_BYTES,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
            BrandedId {
                name: "TraceId".to_owned(),
                max_bytes: MAX_PROVENANCE_ID_BYTES,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                // The store's `accepted_at_ms >= 0` constraint and the spool's
                // unsigned millisecond field are what this bound is: an instant
                // before the epoch is one neither can hold, and the Rust
                // constructors refuse it rather than storing it.
                name: EPOCH_MILLIS.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                // Zero is the value the spool's status reports when a run has
                // *no* events, so it is a valid highest-sequence and an invalid
                // event sequence. The two are separate types for that reason.
                name: "LastSequence".to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "PageSize".to_owned(),
                min: 1,
                max: i64::try_from(crate::runs_api::MAX_RUN_PAGE_ITEMS)
                    .expect("the page bound is within the wire range"),
            },
            BoundedInteger {
                name: RUN_CURSOR.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "SpoolSequence".to_owned(),
                min: 1,
                max: i64::MAX,
            },
        ],
        enums: vec![
            runs_enum("Authority", lifecycle_authority_values(), None),
            runs_enum("LifecycleCoverage", lifecycle_coverage_values(), None),
            // The only vocabulary whose declaration order reaches the wire: a
            // state filter is canonicalized into it.
            runs_enum("RunState", run_state_values(), Some(run_state_values())),
            runs_enum("RunsRefusal", runs_refusal_values(), None),
            runs_enum("SpoolEventKind", spool_event_kind_values(), None),
            runs_enum("SubmissionState", submission_state_values(), None),
        ],
        command_surface: Some(CommandSurface {
            name: "Runs".to_owned(),
            protocol_constant: "RUNS_PROTOCOL".to_owned(),
            protocol: crate::runs_api::RUNS_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_RUNS_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: None,
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                runs_category(
                    "RUNS_COUNTER_OUT_OF_RANGE",
                    "A counter is outside the range the integer-only wire codec carries.",
                    &RunsApiError::CounterOutOfRange { field: "since" },
                ),
                runs_category(
                    "RUNS_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &RunsApiError::InvalidBody,
                ),
                runs_category(
                    "RUNS_INVALID_FIELD",
                    "A bounded identifier was empty, over-long or control-bearing.",
                    &RunsApiError::Field {
                        field: "run_id",
                        error: ValueError::Empty,
                    },
                ),
                runs_category(
                    "RUNS_LIFECYCLE_OUT_OF_ORDER",
                    "A lifecycle sequence was zero, which names a run with no events rather \
                     than an event.",
                    &RunsApiError::LifecycleOutOfOrder,
                ),
                runs_category(
                    "RUNS_LIFECYCLE_TOO_LONG",
                    "A view carried more lifecycle events than one view holds.",
                    &RunsApiError::LifecycleTooLong {
                        max_events: 0,
                        actual_events: 0,
                    },
                ),
                runs_category(
                    "RUNS_PAGE_SIZE_OUT_OF_RANGE",
                    "A requested page size was zero — a page that admits nothing cannot make \
                     progress — or above the largest page this protocol serves.",
                    &RunsApiError::PageSizeOutOfRange {
                        max_items: 0,
                        requested: 0,
                    },
                ),
                runs_category(
                    "RUNS_PAGE_TOO_LARGE",
                    "A page carried more summaries than one page holds.",
                    &RunsApiError::PageTooLarge {
                        max_items: 0,
                        actual_items: 0,
                    },
                ),
                runs_category(
                    "RUNS_STATE_FILTER_EMPTY",
                    "A state filter admitted nothing, which no listing could ever answer.",
                    &RunsApiError::StateFilterEmpty,
                ),
                runs_category(
                    "RUNS_STATE_FILTER_REPEATS",
                    "A state filter named one state twice, which is a caller that believes it \
                     asked for something it did not.",
                    &RunsApiError::StateFilterRepeats {
                        state: RunState::Ready,
                    },
                ),
                runs_category(
                    "RUNS_TIME_BEFORE_EPOCH",
                    "A durable instant was before the epoch, which the store cannot hold.",
                    &RunsApiError::TimeBeforeEpoch {
                        field: "accepted_at_ms",
                    },
                ),
                runs_category(
                    "RUNS_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &RunsApiError::UnknownKind,
                ),
                runs_category(
                    "RUNS_UNWRITTEN_ROW",
                    "A durable row identity was zero, which names a row no writer produced.",
                    &RunsApiError::UnwrittenRow {
                        field: "submission_id",
                    },
                ),
                // The three below are the shared codec's own categories, which
                // this protocol reports unchanged: `RunsApiError::Codec`
                // delegates to them rather than restating them. They are spelled
                // with this lane's prefix because one name has one declaring
                // module, and `admin-command.ts` already declares its own pair
                // of the same two spellings.
                runs_category(
                    "RUNS_FIELD_GRAMMAR",
                    "An envelope field cleared the bounded-value rules and broke its own \
                     grammar.",
                    &RunsApiError::Codec(CodecError::Grammar {
                        field: "request_id",
                    }),
                ),
                runs_category(
                    "RUNS_FIELD_INVALID",
                    "An envelope field was empty, too long, or carried a control character.",
                    &RunsApiError::Codec(CodecError::Field {
                        field: "request_id",
                        error: ValueError::Empty,
                    }),
                ),
                runs_category(
                    "RUNS_UNKNOWN_ENUM_VALUE",
                    "A state, event kind, authority, coverage, submission state or refusal this \
                     build does not define. Every vocabulary on this lane fails closed.",
                    &RunsApiError::Codec(CodecError::UnknownEnumValue { field: "state" }),
                ),
                Constant {
                    // Unlike the admin lane's, nothing pins this one: no shipped
                    // transport carries `automonique.runs` yet, so no peer
                    // reports a spelling for a payload above the ceiling. The
                    // spelling is the admin transport's, which is what a Runs
                    // transport would inherit; until one exists this is a claim
                    // about the future rather than a mirror of the present, and
                    // it says so rather than looking like the others.
                    name: "RUNS_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above this protocol's ceiling. No shipped \
                          transport carries this protocol yet, so nothing pins this spelling; it \
                          is the one the local admin transport reports for the same fault."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "RUNS_INVALID_BODY".to_owned(),
            unknown_kind_category: "RUNS_UNKNOWN_KIND".to_owned(),
            oversize_category: "RUNS_FRAME_SIZE".to_owned(),
            field_invalid_category: "RUNS_FIELD_INVALID".to_owned(),
            field_grammar_category: "RUNS_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: Vec::new(),
            body_objects: vec![
                BodyObject {
                    name: "RunLifecycleEvent".to_owned(),
                    doc: "One durable lifecycle event, as the runner's spool exposes it. The \
                          payload bytes and the chained digest are deliberately absent: a detail \
                          view carries the skeleton, and payload retrieval stays on the \
                          subscribe lane."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field("at_ms", EPOCH_MILLIS, "RUNS_TIME_BEFORE_EPOCH", false),
                        enum_field("authority", "Authority"),
                        enum_field("kind", "SpoolEventKind"),
                        runs_integer_field(
                            "sequence",
                            "SpoolSequence",
                            "RUNS_LIFECYCLE_OUT_OF_ORDER",
                            true,
                        ),
                    ],
                },
                BodyObject {
                    name: "RunSummary".to_owned(),
                    doc: "One run, as a listing reports it. `state` is the runner spool's and \
                          `submission_state` is the store's: they answer different questions, \
                          and both travel so neither can be mistaken for the other."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field(
                            "accepted_at_ms",
                            EPOCH_MILLIS,
                            "RUNS_TIME_BEFORE_EPOCH",
                            false,
                        ),
                        ResponseField {
                            name: "run_id".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "RunId".to_owned(),
                                refusal_category: "RUNS_INVALID_FIELD".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "spec_digest".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "SpecDigest".to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        enum_field("state", "RunState"),
                        runs_integer_field(
                            "submission_id",
                            DURABLE_ROW_ID,
                            "RUNS_UNWRITTEN_ROW",
                            true,
                        ),
                        enum_field("submission_state", "SubmissionState"),
                    ],
                },
            ],
            requests: vec![
                RequestCommand {
                    kind: "list_runs".to_owned(),
                    name: "ListRuns".to_owned(),
                    doc: "Ask for one bounded page of runs. `states` is null for no filter, \
                          which is a different request from one naming every state; `since` is \
                          null to begin at the oldest position still retained, never at position \
                          one."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "PageSize".to_owned(),
                                refusal_category: "RUNS_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::NullableInteger {
                                type_name: RUN_CURSOR.to_owned(),
                                refusal_category: "RUNS_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "states".to_owned(),
                            input_name: "states".to_owned(),
                            value: RequestValue::NullableEnumSet {
                                type_name: "RunState".to_owned(),
                                order_constant: "RunState_WIRE_ORDER".to_owned(),
                                empty_category: "RUNS_STATE_FILTER_EMPTY".to_owned(),
                                repeat_category: "RUNS_STATE_FILTER_REPEATS".to_owned(),
                                unknown_category: "RUNS_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "run_detail".to_owned(),
                    name: "RunDetail".to_owned(),
                    doc: "Read one run in full: its summary and its lifecycle skeleton.".to_owned(),
                    fields: vec![checked_field("run_id", "RunId", "RUNS_INVALID_FIELD")],
                    coupling: None,
                },
            ],
            // This protocol version defines exactly the two requests above.
            // `tests/codegen.rs` proves the list against the Rust encoders
            // themselves rather than against this claim.
            request_kinds_not_generated: Vec::new(),
            request_validations: Vec::new(),
            request_response_kinds: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "run_list_result".to_owned(),
                    name: "RunListPage".to_owned(),
                    doc: "One bounded page of run summaries. `more` is carried explicitly rather \
                          than inferred from a short page: a state filter can exclude every row \
                          in a scanned window and still leave rows behind it."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "more".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "next_cursor".to_owned(),
                            value: ResponseValue::NullableInteger {
                                type_name: RUN_CURSOR.to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "runs".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "RunSummary".to_owned(),
                                max_items_constant: "MAX_RUN_PAGE_ITEMS".to_owned(),
                                oversize_category: "RUNS_PAGE_TOO_LARGE".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "run_detail_result".to_owned(),
                    name: "RunDetailView".to_owned(),
                    doc: "One run in full. `coverage` says whether the carried lifecycle is the \
                          whole log, because a bounded list with no statement about what it \
                          omits is a partial stream presented as a whole one."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "causation_id".to_owned(),
                            value: ResponseValue::NullableChecked {
                                type_name: "CausationId".to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "correlation_id".to_owned(),
                            value: ResponseValue::NullableChecked {
                                type_name: "CorrelationId".to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        enum_field("coverage", "LifecycleCoverage"),
                        runs_integer_field(
                            "last_sequence",
                            "LastSequence",
                            "RUNS_INVALID_BODY",
                            true,
                        ),
                        ResponseField {
                            name: "lifecycle".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "RunLifecycleEvent".to_owned(),
                                max_items_constant: "MAX_LIFECYCLE_EVENTS".to_owned(),
                                oversize_category: "RUNS_LIFECYCLE_TOO_LONG".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "summary".to_owned(),
                            value: ResponseValue::Object {
                                type_name: "RunSummary".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "trace_id".to_owned(),
                            value: ResponseValue::NullableChecked {
                                type_name: "TraceId".to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "resync_required".to_owned(),
                    name: "RunsResync".to_owned(),
                    doc: "The caller's cursor is outside retention. It carries the window a \
                          bounded snapshot must cover and never carries rows, because a cursor \
                          outside retention receives this answer rather than a silent partial \
                          stream."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field("snapshot_from", RUN_CURSOR, "RUNS_INVALID_BODY", true),
                        runs_integer_field("snapshot_to", RUN_CURSOR, "RUNS_INVALID_BODY", true),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "RunsRefused".to_owned(),
                    doc: "The query was refused and nothing was read. The vocabulary is \
                          deliberately small: this slice models no actor, so it names no \
                          authorization refusal it could not have decided."
                        .to_owned(),
                    fields: vec![enum_field("refusal", "RunsRefusal")],
                },
            ],
            // Every kind this protocol version answers with is decoded above.
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

// ---------------------------------------------------------------------------
// The `automonique.automation` control surface
//
// Two closed vocabularies, both borrowed rather than re-spelled: `automation_api`
// itself takes `EnablementState` from `crate::automation` instead of writing a
// second set of enablement words down, and this module takes it from
// `automation_api`. The exhaustive `match` in each function below is what makes
// a fourth state a compile error here rather than a spelling that quietly falls
// out of the generated union.
// ---------------------------------------------------------------------------

/// The declared [`EnablementState`] spellings, pinned to the Rust wire strings.
fn enablement_state_values() -> Vec<String> {
    ENABLEMENT_STATES
        .into_iter()
        .map(|state| match state {
            EnablementState::Enabled | EnablementState::Paused | EnablementState::Archived => {
                state.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`AutomationRefusal`] spellings, pinned to the Rust wire
/// strings.
fn automation_refusal_values() -> Vec<String> {
    AutomationRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            AutomationRefusal::UnknownAutomation
            | AutomationRefusal::AlreadyRegistered
            | AutomationRefusal::IllegalTransition
            | AutomationRefusal::CauseRequired
            | AutomationRefusal::CauseForbidden
            | AutomationRefusal::CursorOutOfRange
            | AutomationRefusal::RegistryFull
            | AutomationRefusal::InvalidField => refusal.as_str().to_owned(),
        })
        .collect()
}

/// The states a transition to which must state a cause.
///
/// Derived by asking [`requires_cause`] rather than by listing two words: that
/// function is an exhaustive `match` written so a fourth state cannot default
/// into "no cause required", which is the direction that loses evidence. The
/// generated list inherits the property.
fn states_requiring_cause() -> Vec<String> {
    ENABLEMENT_STATES
        .into_iter()
        .filter(|state| requires_cause(*state))
        .map(|state| state.as_str().to_owned())
        .collect()
}

/// A refusal category, pinned to the spelling the Automation API reports.
fn automation_category(name: &str, doc: &str, error: &AutomationApiError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A security-sensitive enumeration of the Automation API.
fn automation_enum(
    name: &str,
    values: Vec<String>,
    wire_order: Option<Vec<String>>,
) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        // Both vocabularies fail closed in Rust: `decode_enablement` answers
        // `UnknownEnumValue` for a word this build does not define, and
        // `AutomationRefusal` is a `SecuritySensitiveEnum`. A generated reader
        // that retained an undefined enablement would have to decide whether an
        // automation it cannot name a state for may fire.
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order,
    }
}

/// A response or nested-body field carrying one of this lane's vocabularies.
fn automation_enum_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Enum {
            type_name: type_name.to_owned(),
            unknown_category: "AUTOMATION_UNKNOWN_ENUM_VALUE".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded string.
fn automation_checked_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: "AUTOMATION_INVALID_FIELD".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded integer.
///
/// `unsigned` mirrors which Rust reader the field goes through, exactly as it
/// does on the Runs lane: a row identity and a revision are read through
/// `unsigned()`, which refuses a negative as a malformed body before the domain
/// is consulted, while a durable instant is read signed and refused by the
/// domain itself for being before the epoch.
fn automation_integer_field(
    name: &str,
    type_name: &str,
    refusal_category: &str,
    unsigned: bool,
) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
            unsigned,
        },
    }
}

/// TypeScript name of the branded automation identity.
const AUTOMATION_ID: &str = "AutomationId";

/// TypeScript name of the narrower identity a registration accepts.
///
/// A scheduled identity is bounded by the occurrence key it must derive rather
/// than by the registry grammar, so the register builder re-applies this brand
/// and not [`AUTOMATION_ID`]; a detail read still takes the wider one, because
/// a row registered before schedules existed is still readable.
const SCHEDULED_AUTOMATION_ID: &str = "ScheduledAutomationId";

/// TypeScript name of the serialization scope.
const AUTOMATION_SCOPE: &str = "AutomationScope";

/// TypeScript name of the occurrence prompt.
const AUTOMATION_PROMPT: &str = "AutomationPrompt";

/// TypeScript name of the canonical schedule rendering.
const AUTOMATION_SCHEDULE: &str = "AutomationSchedule";

/// The two schedule forms this lane carries, as one grammar.
///
/// `once@` followed by a non-negative canonical decimal, or `every@` followed
/// by a positive one: no sign, no leading zero, at most nineteen digits. The
/// cron form is outside it, so a generated builder refuses it before a frame
/// is spent — under this lane's invalid-schedule category rather than Rust's
/// typed unsupported one, which is the one place the two sides spell the same
/// refusal differently and is documented beside the corpus.
const SCHEDULE_RENDERING: &str = "^(once@(0|[1-9][0-9]{0,18})|every@[1-9][0-9]{0,18})$";

/// Free text under the durable submit lane's task rule: anything but NUL.
const NO_NUL: &str = "^[^\\u0000]+$";

/// TypeScript name of the branded listing position.
const AUTOMATION_CURSOR: &str = "AutomationCursor";

/// TypeScript name of the withdrawal reason.
const PAUSE_REASON: &str = "PauseReason";

/// The twelve columns one `automations` row carries, as a reader decodes them.
///
/// One list, used twice: a record travels inside a listing page and as the
/// whole of a detail answer's body but its prompt, and the two readings cannot
/// be allowed to drift into disagreeing about a column. The Rust side has the
/// same shape for the same reason — `AutomationRecordView::from_members` is
/// what both go through.
///
/// The job columns are nullable on the wire because a row registered before
/// schedules existed carries none; that they are null *together* is a
/// cross-field rule the Rust constructor holds and this surface does not, and
/// `tests/codegen.rs` records that gap as a rust-only refusal.
fn automation_record_fields() -> Vec<ResponseField> {
    vec![
        automation_checked_field("actor", "AutomationActor"),
        automation_checked_field("automation_id", AUTOMATION_ID),
        ResponseField {
            name: "cause".to_owned(),
            value: ResponseValue::NullableChecked {
                type_name: PAUSE_REASON.to_owned(),
                refusal_category: "AUTOMATION_INVALID_FIELD".to_owned(),
            },
        },
        automation_integer_field(
            "created_at_ms",
            EPOCH_MILLIS,
            "AUTOMATION_TIME_BEFORE_EPOCH",
            false,
        ),
        automation_enum_field("enablement", "EnablementState"),
        automation_integer_field("entry_id", DURABLE_ROW_ID, "AUTOMATION_UNWRITTEN_ROW", true),
        ResponseField {
            name: "last_fired_at_ms".to_owned(),
            value: ResponseValue::NullableInteger {
                type_name: EPOCH_MILLIS.to_owned(),
                refusal_category: "AUTOMATION_TIME_BEFORE_EPOCH".to_owned(),
            },
        },
        ResponseField {
            name: "next_fire_at_ms".to_owned(),
            value: ResponseValue::NullableInteger {
                type_name: EPOCH_MILLIS.to_owned(),
                refusal_category: "AUTOMATION_TIME_BEFORE_EPOCH".to_owned(),
            },
        },
        automation_integer_field(
            "revision",
            DURABLE_ROW_ID,
            "AUTOMATION_UNWRITTEN_REVISION",
            true,
        ),
        ResponseField {
            name: "schedule".to_owned(),
            value: ResponseValue::NullableChecked {
                type_name: AUTOMATION_SCHEDULE.to_owned(),
                refusal_category: "AUTOMATION_INVALID_SCHEDULE".to_owned(),
            },
        },
        ResponseField {
            name: "scope".to_owned(),
            value: ResponseValue::NullableChecked {
                type_name: AUTOMATION_SCOPE.to_owned(),
                refusal_category: "AUTOMATION_INVALID_FIELD".to_owned(),
            },
        },
        automation_integer_field(
            "updated_at_ms",
            EPOCH_MILLIS,
            "AUTOMATION_TIME_BEFORE_EPOCH",
            false,
        ),
    ]
}

/// A detail answer's body: the record's twelve columns and the prompt.
fn automation_detail_fields() -> Vec<ResponseField> {
    let mut fields = automation_record_fields();
    let position = fields
        .iter()
        .position(|field| field.name.as_str() > "prompt")
        .unwrap_or(fields.len());
    fields.insert(
        position,
        ResponseField {
            name: "prompt".to_owned(),
            value: ResponseValue::NullableChecked {
                type_name: AUTOMATION_PROMPT.to_owned(),
                refusal_category: "AUTOMATION_INVALID_FIELD".to_owned(),
            },
        },
    );
    fields
}

/// The `automonique.automation` control surface: what an operator asks, and
/// what it decodes.
fn automation_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(AUTOMATION_MODULE),
        doc: "The native Automation control surface: register an automation job — a canonical \
              schedule, a serialization scope and a bounded prompt — move it along the \
              enablement lattice, and read back what an operator decided and when the job last \
              fired and next fires."
            .to_owned(),
        source: "automonique_protocol::automation_api".to_owned(),
        // A name is declared in exactly one module. A correlation identifier, a
        // durable row identity and a durable instant are wire vocabularies
        // rather than one lane's, so this module reads them from where they are
        // already declared. `EpochMillis` living in `runs.ts` is an accident of
        // which surface landed first, and a second copy here would be a second
        // thing to keep right — which is precisely what the duplicate-name gate
        // in `tests/codegen.rs` exists to stop.
        imports: vec![
            ModuleImport {
                module: ADMIN_COMMAND_MODULE.to_owned(),
                // The minimum travels with the type: a ranged refusal asks
                // which end of the range a value fell off, and the answer is
                // the declaring module's constant rather than a literal `1n`
                // retyped here.
                values: vec![
                    DURABLE_ROW_ID.to_owned(),
                    format!("{DURABLE_ROW_ID}_MIN"),
                    "RequestId".to_owned(),
                ],
                types: Vec::new(),
            },
            ModuleImport {
                module: RUNS_MODULE.to_owned(),
                values: vec![EPOCH_MILLIS.to_owned()],
                types: Vec::new(),
            },
        ],
        constants: vec![
            Constant {
                name: "AUTOMATION_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one control surface.".to_owned(),
                value: ConstantValue::Text(
                    crate::automation_api::AUTOMATION_API_SCHEMA_V1.to_owned(),
                ),
            },
            Constant {
                name: "AUTOMATION_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the native Automation control API.".to_owned(),
                value: ConstantValue::Text(crate::automation_api::AUTOMATION_PROTOCOL.to_owned()),
            },
            Constant {
                name: "ENABLEMENT_STATES_REQUIRING_CAUSE".to_owned(),
                doc: "The states a transition to which must state a cause. A withdrawal an \
                      operator cannot safely resume from is the one this product does not offer \
                      a spelling for, so `paused` and `archived` require a reason and `enabled` \
                      admits none."
                    .to_owned(),
                value: ConstantValue::Words(states_requiring_cause()),
            },
            Constant {
                name: "MAX_AUTOMATION_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes this protocol will assemble or admit."
                    .to_owned(),
                value: ConstantValue::Count(crate::automation_api::MAX_AUTOMATION_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_AUTOMATION_PAGE_ITEMS".to_owned(),
                doc: "Maximum automations one listing page may carry. Twenty-four rather than the \
                      sixty-four the Runs API serves, because an automation row carries four \
                      maximal bounded strings — identity, actor, cause and scope — where a run \
                      summary carries one. A longer page is refused rather than truncated: a \
                      truncated page that still answered `complete` is a silent drop."
                    .to_owned(),
                value: ConstantValue::Count(crate::automation_api::MAX_AUTOMATION_PAGE_ITEMS),
            },
        ],
        branded_ids: vec![
            BrandedId {
                // Deliberately *not* the `DurableId` grammar, which additionally
                // forbids whitespace. The registry stores any non-empty, bounded,
                // control-free identifier, and a wire type stricter than the table
                // would make a stored row unreadable through the only surface that
                // serves it.
                name: AUTOMATION_ID.to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_API_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BrandedId {
                // The same grammar at the narrower bound a registration
                // applies: the occurrence key derived from the identity must
                // fit the durable submit lane's key bound.
                name: SCHEDULED_AUTOMATION_ID.to_owned(),
                max_bytes: crate::automation_api::MAX_SCHEDULED_AUTOMATION_ID_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        bounded_strings: vec![
            BoundedString {
                name: "AutomationActor".to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_API_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // Empty is refused rather than read as "no reason given": the
                // absence of a cause is `null`, and the two are different facts.
                name: PAUSE_REASON.to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_API_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // The durable submit lane's scope grammar, at the scheduler
                // core's narrower identifier ceiling: an occurrence's scope is
                // admitted by both.
                name: AUTOMATION_SCOPE.to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_SCOPE_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // Prose, not an identifier: a newline is text and only NUL is
                // refused, which is the durable submit lane's task rule.
                name: AUTOMATION_PROMPT.to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_PROMPT_BYTES,
                pattern: Some(NO_NUL.to_owned()),
            },
            BoundedString {
                name: AUTOMATION_SCHEDULE.to_owned(),
                max_bytes: crate::automation_api::MAX_AUTOMATION_SCHEDULE_BYTES,
                pattern: Some(SCHEDULE_RENDERING.to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                // Zero is the beginning of the listing rather than the absence
                // of a cursor: this lane carries the store's own exclusive
                // cursor, so there is no coordinate to convert and no
                // off-by-one to re-derive.
                name: AUTOMATION_CURSOR.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "AutomationPageSize".to_owned(),
                min: 1,
                max: i64::try_from(crate::automation_api::MAX_AUTOMATION_PAGE_ITEMS)
                    .expect("the page bound is within the wire range"),
            },
        ],
        enums: vec![
            automation_enum("AutomationRefusal", automation_refusal_values(), None),
            // The declaration order reaches the wire: a state filter is
            // canonicalized into it, and a filter built in any other order must
            // encode the same bytes.
            automation_enum(
                "EnablementState",
                enablement_state_values(),
                Some(enablement_state_values()),
            ),
        ],
        command_surface: Some(CommandSurface {
            name: "Automation".to_owned(),
            protocol_constant: "AUTOMATION_PROTOCOL".to_owned(),
            protocol: crate::automation_api::AUTOMATION_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_AUTOMATION_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: None,
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                automation_category(
                    "AUTOMATION_CAUSE_FORBIDDEN",
                    "A cause was supplied for a state that admits none.",
                    &AutomationApiError::CauseForbidden {
                        state: EnablementState::Enabled,
                    },
                ),
                automation_category(
                    "AUTOMATION_CAUSE_REQUIRED",
                    "A withdrawal was requested with no stated cause.",
                    &AutomationApiError::CauseRequired {
                        state: EnablementState::Paused,
                    },
                ),
                automation_category(
                    "AUTOMATION_COUNTER_OUT_OF_RANGE",
                    "A counter is outside the range the integer-only wire codec carries.",
                    &AutomationApiError::CounterOutOfRange {
                        field: "expected_revision",
                    },
                ),
                automation_category(
                    "AUTOMATION_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &AutomationApiError::InvalidBody,
                ),
                automation_category(
                    "AUTOMATION_INVALID_FIELD",
                    "A bounded identifier, actor, cause, scope or prompt was empty, over-long or \
                     control-bearing — or an identity too long to derive an occurrence key from.",
                    &AutomationApiError::Field {
                        field: "automation_id",
                        error: ValueError::Empty,
                    },
                ),
                automation_category(
                    "AUTOMATION_INVALID_SCHEDULE",
                    "A schedule was not one canonical `once@<ms>` or `every@<ms>` rendering. \
                     Rust additionally refuses a canonical cron rendering under its own \
                     `automation_unsupported_schedule`; this surface's grammar excludes cron \
                     outright and reports it here.",
                    &AutomationApiError::InvalidSchedule,
                ),
                automation_category(
                    "AUTOMATION_PAGE_SIZE_OUT_OF_RANGE",
                    "A requested page size was zero — a page that admits nothing cannot make \
                     progress — or above the largest page this protocol serves.",
                    &AutomationApiError::PageSizeOutOfRange {
                        max_items: 0,
                        requested: 0,
                    },
                ),
                automation_category(
                    "AUTOMATION_PAGE_TOO_LARGE",
                    "A page carried more automations than one page holds.",
                    &AutomationApiError::PageTooLarge {
                        max_items: 0,
                        actual_items: 0,
                    },
                ),
                automation_category(
                    "AUTOMATION_STATE_FILTER_EMPTY",
                    "An enablement filter admitted nothing, which no listing could ever answer.",
                    &AutomationApiError::StateFilterEmpty,
                ),
                automation_category(
                    "AUTOMATION_STATE_FILTER_REPEATS",
                    "An enablement filter named one state twice, which is a caller that believes \
                     it asked for something it did not.",
                    &AutomationApiError::StateFilterRepeats {
                        state: EnablementState::Paused,
                    },
                ),
                automation_category(
                    "AUTOMATION_TIME_BEFORE_EPOCH",
                    "A durable instant was before the epoch, which the store cannot hold.",
                    &AutomationApiError::TimeBeforeEpoch {
                        field: "updated_at_ms",
                    },
                ),
                automation_category(
                    "AUTOMATION_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &AutomationApiError::UnknownKind,
                ),
                automation_category(
                    "AUTOMATION_UNWRITTEN_REVISION",
                    "A revision was zero. Registration writes revision one and every accepted \
                     transition writes one higher, so zero names nothing.",
                    &AutomationApiError::UnwrittenRevision,
                ),
                automation_category(
                    "AUTOMATION_UNWRITTEN_ROW",
                    "A durable row identity was zero, which names a row no writer produced.",
                    &AutomationApiError::UnwrittenRow { field: "entry_id" },
                ),
                // The three below are the shared codec's own categories, which
                // this protocol reports unchanged. They carry this lane's prefix
                // because one name has one declaring module.
                automation_category(
                    "AUTOMATION_FIELD_GRAMMAR",
                    "An envelope field cleared the bounded-value rules and broke its own grammar.",
                    &AutomationApiError::Codec(CodecError::Grammar {
                        field: "request_id",
                    }),
                ),
                automation_category(
                    "AUTOMATION_FIELD_INVALID",
                    "An envelope field was empty, too long, or carried a control character.",
                    &AutomationApiError::Codec(CodecError::Field {
                        field: "request_id",
                        error: ValueError::Empty,
                    }),
                ),
                automation_category(
                    "AUTOMATION_UNKNOWN_ENUM_VALUE",
                    "An enablement state or refusal this build does not define. Both \
                     vocabularies on this lane fail closed.",
                    &AutomationApiError::Codec(CodecError::UnknownEnumValue {
                        field: "enablement",
                    }),
                ),
                Constant {
                    // As on the Runs lane, nothing pins this one: no shipped
                    // transport carries `automonique.automation` yet, so no peer
                    // reports a spelling for a payload above the ceiling.
                    name: "AUTOMATION_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above this protocol's ceiling. No shipped transport \
                          carries this protocol yet, so nothing pins this spelling; it is the one \
                          the local admin transport reports for the same fault."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "AUTOMATION_INVALID_BODY".to_owned(),
            unknown_kind_category: "AUTOMATION_UNKNOWN_KIND".to_owned(),
            oversize_category: "AUTOMATION_FRAME_SIZE".to_owned(),
            field_invalid_category: "AUTOMATION_FIELD_INVALID".to_owned(),
            field_grammar_category: "AUTOMATION_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: Vec::new(),
            body_objects: vec![BodyObject {
                name: "AutomationRecord".to_owned(),
                doc: "One validated `automations` row. `actor` is the last operator to change \
                      enablement, or the registrant while the row is still at revision one; \
                      `cause` is present exactly when the state is withdrawn, which only the Rust \
                      constructor enforces. `schedule` and `scope` are present together for a \
                      row registered with a job and null together for one registered before \
                      jobs existed; `next_fire_at_ms` is the instant the next occurrence is due \
                      and `last_fired_at_ms` the scheduled instant of the last one submitted, \
                      both null when there is none. There is no history: a resume overwrites \
                      the cause of the pause it resumed."
                    .to_owned(),
                fields: automation_record_fields(),
            }],
            requests: vec![
                RequestCommand {
                    kind: "register_automation".to_owned(),
                    name: "RegisterAutomation".to_owned(),
                    doc: "Declare one automation job, enabled, at revision one: a canonical \
                          schedule (`once@<ms>` or `every@<ms>`), the scope every occurrence is \
                          serialized under, and the prompt every occurrence submits. The initial \
                          enablement is not a field: an operator who wants a paused automation \
                          registers it and pauses it, and the pause then carries the cause it \
                          owes. The identity is bounded by the occurrence key it must derive, \
                          which is narrower than the identity a detail read accepts."
                        .to_owned(),
                    fields: vec![
                        checked_field("actor", "AutomationActor", "AUTOMATION_INVALID_FIELD"),
                        checked_field(
                            "automation_id",
                            SCHEDULED_AUTOMATION_ID,
                            "AUTOMATION_INVALID_FIELD",
                        ),
                        checked_field("prompt", AUTOMATION_PROMPT, "AUTOMATION_INVALID_FIELD"),
                        checked_field(
                            "schedule",
                            AUTOMATION_SCHEDULE,
                            "AUTOMATION_INVALID_SCHEDULE",
                        ),
                        checked_field("scope", AUTOMATION_SCOPE, "AUTOMATION_INVALID_FIELD"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "set_enablement".to_owned(),
                    name: "SetEnablement".to_owned(),
                    doc: "Move one automation along the enablement lattice, fencing on the \
                          revision the caller believes it is moving. The daemon's scheduler \
                          worker reads the row on its next tick: a paused or archived automation \
                          has its queued occurrence cancelled and no further one derived, and an \
                          occurrence already submitted as a run completes on its own."
                        .to_owned(),
                    fields: vec![
                        checked_field("actor", "AutomationActor", "AUTOMATION_INVALID_FIELD"),
                        checked_field("automation_id", AUTOMATION_ID, "AUTOMATION_INVALID_FIELD"),
                        RequestField {
                            name: "cause".to_owned(),
                            input_name: "cause".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: PAUSE_REASON.to_owned(),
                                refusal_category: "AUTOMATION_INVALID_FIELD".to_owned(),
                            },
                        },
                        RequestField {
                            name: "expected_revision".to_owned(),
                            input_name: "expected_revision".to_owned(),
                            value: RequestValue::RangedInteger {
                                type_name: DURABLE_ROW_ID.to_owned(),
                                below_category: "AUTOMATION_UNWRITTEN_REVISION".to_owned(),
                                above_category: "AUTOMATION_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "target".to_owned(),
                            input_name: "target".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "EnablementState".to_owned(),
                                unknown_category: "AUTOMATION_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                    ],
                    coupling: Some(FieldCoupling {
                        deciding_field: "target".to_owned(),
                        governed_field: "cause".to_owned(),
                        requiring_constant: "ENABLEMENT_STATES_REQUIRING_CAUSE".to_owned(),
                        required_category: "AUTOMATION_CAUSE_REQUIRED".to_owned(),
                        forbidden_category: "AUTOMATION_CAUSE_FORBIDDEN".to_owned(),
                    }),
                },
                RequestCommand {
                    kind: "list_automations".to_owned(),
                    name: "ListAutomations".to_owned(),
                    doc: "Ask for one bounded page of automations. `states` is null for no \
                          filter, which is a different request from one naming every state; \
                          `since` is the entry this listing resumes *after*, and zero is the \
                          beginning rather than the absence of a cursor."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "AutomationPageSize".to_owned(),
                                refusal_category: "AUTOMATION_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::Integer {
                                type_name: AUTOMATION_CURSOR.to_owned(),
                                refusal_category: "AUTOMATION_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "states".to_owned(),
                            input_name: "states".to_owned(),
                            value: RequestValue::NullableEnumSet {
                                type_name: "EnablementState".to_owned(),
                                order_constant: "EnablementState_WIRE_ORDER".to_owned(),
                                empty_category: "AUTOMATION_STATE_FILTER_EMPTY".to_owned(),
                                repeat_category: "AUTOMATION_STATE_FILTER_REPEATS".to_owned(),
                                unknown_category: "AUTOMATION_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "automation_detail".to_owned(),
                    name: "AutomationDetail".to_owned(),
                    doc: "Read one automation in full.".to_owned(),
                    fields: vec![checked_field(
                        "automation_id",
                        AUTOMATION_ID,
                        "AUTOMATION_INVALID_FIELD",
                    )],
                    coupling: None,
                },
            ],
            // This protocol version defines exactly the four requests above.
            // `tests/codegen.rs` proves the list against the Rust encoders
            // themselves rather than against this claim.
            request_kinds_not_generated: Vec::new(),
            request_validations: Vec::new(),
            request_response_kinds: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "automation_accepted".to_owned(),
                    name: "AutomationAccepted".to_owned(),
                    doc: "One durable write landed. `accepted` rather than `completed`, and the \
                          distinction is the honest one: the row is committed, and what it \
                          authorizes happens later and elsewhere — on the scheduler worker's \
                          next tick, as a run with its own durable outcome."
                        .to_owned(),
                    fields: vec![
                        automation_checked_field("automation_id", AUTOMATION_ID),
                        automation_enum_field("enablement", "EnablementState"),
                        automation_integer_field(
                            "entry_id",
                            DURABLE_ROW_ID,
                            "AUTOMATION_UNWRITTEN_ROW",
                            true,
                        ),
                        automation_integer_field(
                            "revision",
                            DURABLE_ROW_ID,
                            "AUTOMATION_UNWRITTEN_REVISION",
                            true,
                        ),
                        automation_integer_field(
                            "updated_at_ms",
                            EPOCH_MILLIS,
                            "AUTOMATION_TIME_BEFORE_EPOCH",
                            false,
                        ),
                    ],
                },
                ResponseDecoder {
                    kind: "automation_list_result".to_owned(),
                    name: "AutomationListPage".to_owned(),
                    doc: "One bounded page of automation records. `more` is carried explicitly \
                          rather than inferred from a short page: an enablement filter can \
                          exclude every row in a scanned window and still leave rows behind it."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "automations".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "AutomationRecord".to_owned(),
                                max_items_constant: "MAX_AUTOMATION_PAGE_ITEMS".to_owned(),
                                oversize_category: "AUTOMATION_PAGE_TOO_LARGE".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "more".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "next_cursor".to_owned(),
                            value: ResponseValue::NullableInteger {
                                type_name: AUTOMATION_CURSOR.to_owned(),
                                refusal_category: "AUTOMATION_INVALID_BODY".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "automation_detail_result".to_owned(),
                    name: "AutomationDetailView".to_owned(),
                    // The body is a record plus its prompt: unlike a run
                    // detail, there is no wrapper key. The record fields come
                    // from the same list the nested body object is built from,
                    // so the two readings cannot drift apart.
                    doc: "One automation in full. The body is a record with no wrapper, plus the \
                          one column a listing omits: `prompt`, the task every occurrence \
                          submits, present exactly when the record carries a job — which only \
                          the Rust constructor enforces."
                        .to_owned(),
                    fields: automation_detail_fields(),
                },
                ResponseDecoder {
                    kind: "revision_conflict".to_owned(),
                    name: "AutomationConflict".to_owned(),
                    doc: "The caller's expected revision did not match the durable one and \
                          nothing was written. A conflict is not a rejection: a caller retries \
                          the two differently, which is why the plan's vocabulary separates them."
                        .to_owned(),
                    fields: vec![
                        automation_integer_field(
                            "durable_revision",
                            DURABLE_ROW_ID,
                            "AUTOMATION_UNWRITTEN_REVISION",
                            true,
                        ),
                        automation_integer_field(
                            "expected_revision",
                            DURABLE_ROW_ID,
                            "AUTOMATION_UNWRITTEN_REVISION",
                            true,
                        ),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "AutomationRefused".to_owned(),
                    doc: "The operation was refused. Nothing was written and nothing was read. A \
                          stale expected revision is deliberately not among these words: that is \
                          a conflict."
                        .to_owned(),
                    fields: vec![automation_enum_field("refusal", "AutomationRefusal")],
                },
            ],
            // Every kind this protocol version answers with is decoded above.
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

// ---------------------------------------------------------------------------
// The `automonique.approval` decision surface
//
// Four closed vocabularies, every one of them fail-closed on both sides of the
// wire. The exhaustive `match` in each function below is what makes a third
// decision word, a third disposition or a fourth conflict field a compile error
// here rather than a spelling that quietly falls out of the generated union —
// which on this lane matters more than on most, because the words being dropped
// would be the ones that say whether somebody approved something.
// ---------------------------------------------------------------------------

/// The declared [`ApprovalDecision`] spellings, pinned to the Rust wire strings.
///
/// `granted` and `denied`, and the set is closed: there is no `pending` and no
/// `expired`, because a decision nobody made has no row. The `match` is written
/// out rather than mapped so a third answer cannot appear on the wire without
/// this file being asked about it.
fn approval_decision_values() -> Vec<String> {
    ApprovalDecision::ALL
        .into_iter()
        .map(|decision| match decision {
            ApprovalDecision::Granted | ApprovalDecision::Denied => decision.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`ApprovalDisposition`] spellings, pinned to the Rust wire
/// strings.
fn approval_disposition_values() -> Vec<String> {
    ApprovalDisposition::ALL
        .into_iter()
        .map(|disposition| match disposition {
            ApprovalDisposition::Recorded | ApprovalDisposition::AlreadyRecorded => {
                disposition.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`ConflictField`] spellings, pinned to the Rust wire strings.
fn conflict_field_values() -> Vec<String> {
    ConflictField::ALL
        .into_iter()
        .map(|field| match field {
            ConflictField::Subject | ConflictField::Decision | ConflictField::Decider => {
                field.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`ApprovalRefusal`] spellings, pinned to the Rust wire strings.
fn approval_refusal_values() -> Vec<String> {
    ApprovalRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            ApprovalRefusal::UnknownApproval
            | ApprovalRefusal::CursorOutOfRange
            | ApprovalRefusal::LedgerFull
            | ApprovalRefusal::InvalidField
            | ApprovalRefusal::UnknownRequest
            | ApprovalRefusal::AlreadyDecided
            | ApprovalRefusal::RequestExpired => refusal.as_str().to_owned(),
        })
        .collect()
}

/// A refusal category, pinned to the spelling the Approval API reports.
fn approval_category(name: &str, doc: &str, error: &ApprovalApiError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A security-sensitive enumeration of the Approval API.
///
/// All four are [`SecuritySensitiveEnum`](crate::codec::SecuritySensitiveEnum)
/// in Rust and all four fail closed here. A reader that retained an undefined
/// decision would have to decide what an unnameable answer to an approval
/// question means, and every available guess is wrong: treating it as a grant
/// invents permission, and treating it as a denial invents a refusal nobody
/// made.
fn approval_enum(name: &str, values: Vec<String>) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        // No set of these reaches the wire, so no declaration order has to
        // travel with them: this lane's listings filter by subject rather than
        // by vocabulary.
        wire_order: None,
    }
}

/// A response or nested-body field carrying one of this lane's vocabularies.
fn approval_enum_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Enum {
            type_name: type_name.to_owned(),
            unknown_category: "APPROVAL_UNKNOWN_ENUM_VALUE".to_owned(),
        },
    }
}

/// A response or nested-body field carrying one of this lane's bounded strings.
fn approval_checked_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: "APPROVAL_INVALID_FIELD".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded integer.
///
/// `unsigned` mirrors which Rust reader the field goes through, exactly as it
/// does on the Runs and Automation lanes: a row identity and a revision are read
/// through `unsigned()`, which refuses a negative as a malformed body before the
/// domain is consulted, while the decision instant is read signed and refused by
/// the domain itself for being before the epoch.
fn approval_integer_field(
    name: &str,
    type_name: &str,
    refusal_category: &str,
    unsigned: bool,
) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
            unsigned,
        },
    }
}

/// TypeScript name of the branded decision identity.
const APPROVAL_KEY: &str = "ApprovalKey";

/// TypeScript name of the bounded name for what was decided.
const APPROVAL_SUBJECT: &str = "ApprovalSubject";

/// TypeScript name of the bounded name for who answered.
const DECIDER: &str = "Decider";

/// TypeScript name of the branded listing position.
const APPROVAL_CURSOR: &str = "ApprovalCursor";

/// TypeScript name of the write-once revision, whose domain is `1..=1`.
const APPROVAL_REVISION: &str = "ApprovalRevision";

/// The seven columns one `approval_decisions` row carries, as a reader decodes
/// them.
///
/// One list, used twice: a record travels inside a listing page and *as* a
/// detail answer's whole body, and the two readings cannot be allowed to drift
/// into disagreeing about a column. The Rust side has the same shape for the
/// same reason — [`ApprovalRecordView::from_body`] is what both go through.
///
/// [`ApprovalRecordView::from_body`]: crate::approval_api::ApprovalRecordView
fn approval_record_fields() -> Vec<ResponseField> {
    vec![
        approval_checked_field("approval_key", APPROVAL_KEY),
        approval_integer_field(
            "decided_at_ms",
            EPOCH_MILLIS,
            "APPROVAL_TIME_BEFORE_EPOCH",
            false,
        ),
        approval_checked_field("decider", DECIDER),
        approval_enum_field("decision", "ApprovalDecision"),
        approval_integer_field("entry_id", DURABLE_ROW_ID, "APPROVAL_UNWRITTEN_ROW", true),
        // The write-once pin, and the one cross-language rule this lane hands a
        // client that the Automation lane could not: `1..=1` is a bound on one
        // field's own value, so a decoder can see for itself that the row was
        // never amended.
        approval_integer_field("revision", APPROVAL_REVISION, "APPROVAL_ROW_AMENDED", true),
        approval_checked_field("subject", APPROVAL_SUBJECT),
    ]
}

/// The `automonique.approval` decision surface: what an operator records, and
/// what it reads back.
fn approval_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(APPROVAL_MODULE),
        doc: "The native Approval decision surface: record that somebody answered an approval \
              question, durably, and read the answers back. Nothing here enforces a decision, \
              verifies who made it, or binds it to a session."
            .to_owned(),
        source: "automonique_protocol::approval_api".to_owned(),
        // A name is declared in exactly one module. A correlation identifier, a
        // durable row identity and a durable instant are wire vocabularies
        // rather than one lane's, so this module reads them from where they are
        // already declared rather than emitting a fourth copy.
        imports: vec![
            ModuleImport {
                module: ADMIN_COMMAND_MODULE.to_owned(),
                values: vec![DURABLE_ROW_ID.to_owned(), "RequestId".to_owned()],
                types: Vec::new(),
            },
            ModuleImport {
                module: RUNS_MODULE.to_owned(),
                values: vec![EPOCH_MILLIS.to_owned()],
                types: Vec::new(),
            },
        ],
        constants: vec![
            Constant {
                name: "APPROVAL_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one decision surface.".to_owned(),
                value: ConstantValue::Text(crate::approval_api::APPROVAL_API_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "APPROVAL_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the native Approval decision API.".to_owned(),
                value: ConstantValue::Text(crate::approval_api::APPROVAL_PROTOCOL.to_owned()),
            },
            Constant {
                name: "MAX_APPROVAL_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes this protocol will assemble or admit."
                    .to_owned(),
                value: ConstantValue::Count(crate::approval_api::MAX_APPROVAL_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_APPROVAL_PAGE_ITEMS".to_owned(),
                doc:
                    "Maximum decisions one listing page may carry. Thirty-two, because a decision \
                      row carries three maximal identifiers where a run summary carries one; the \
                      number is derived from this protocol's frame arithmetic rather than chosen. \
                      Well below the durable ledger's own read ceiling, which bounds a database \
                      read rather than a wire frame — the smaller of the two is the one a client \
                      sees, and they are not reconciled. A longer page is refused rather than \
                      truncated: a truncated page that still answered `complete` is a silent drop."
                        .to_owned(),
                value: ConstantValue::Count(crate::approval_api::MAX_APPROVAL_PAGE_ITEMS),
            },
        ],
        branded_ids: vec![BrandedId {
            // The ledger's own grammar: non-empty, bounded, control-free, and
            // nothing more. This protocol never parses a key, derives nothing
            // from it and gives it no structure, so a wire type stricter than
            // the table would make a stored row unreadable through the only
            // surface that serves it.
            name: APPROVAL_KEY.to_owned(),
            max_bytes: crate::approval_api::MAX_APPROVAL_API_FIELD_BYTES,
            pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
        }],
        bounded_strings: vec![
            BoundedString {
                // A name for what was decided — a command identifier, an effect
                // name, a digest — never the thing itself.
                name: APPROVAL_SUBJECT.to_owned(),
                max_bytes: crate::approval_api::MAX_APPROVAL_API_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // Recorded, never verified: the local transport establishes that
                // the peer is this user, and this string says which person or
                // runbook behind that user made the call. Empty is refused
                // rather than read as "nobody", because an unattributed decision
                // is the one this product does not offer a spelling for.
                name: DECIDER.to_owned(),
                max_bytes: crate::approval_api::MAX_APPROVAL_API_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                // Zero is the beginning of the listing rather than the absence
                // of a cursor: this lane carries the ledger's own exclusive
                // cursor, so there is no coordinate to convert and no
                // off-by-one to re-derive.
                name: APPROVAL_CURSOR.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "ApprovalPageSize".to_owned(),
                min: 1,
                max: i64::try_from(crate::approval_api::MAX_APPROVAL_PAGE_ITEMS)
                    .expect("the page bound is within the wire range"),
            },
            BoundedInteger {
                // A domain of exactly one value, which is what write-once means
                // on the wire. The ledger pins the column with a database
                // `CHECK` and has no update path at all, so any other value
                // names a row this product could not have written — and a client
                // that decodes a record can therefore see for itself that the
                // row it is reading was never amended.
                name: APPROVAL_REVISION.to_owned(),
                min: 1,
                max: 1,
            },
        ],
        enums: vec![
            // `generated/spike.ts` declares an `ApprovalDecision` of its own,
            // spelled `allow`/`deny`. It is the R1-11 spike's invented
            // vocabulary rather than this product's, and the two never meet: the
            // barrel deliberately does not re-export the spike, so no consumer
            // can reach both names, and nothing imports the spike except its own
            // runtime check.
            approval_enum("ApprovalDecision", approval_decision_values()),
            approval_enum("ApprovalDisposition", approval_disposition_values()),
            // Named for its lane rather than `ConflictField`: the barrel
            // re-exports every module flat, and a name that generic would claim
            // a word four other protocols could want.
            approval_enum("ApprovalConflictField", conflict_field_values()),
            approval_enum("ApprovalRefusal", approval_refusal_values()),
        ],
        command_surface: Some(CommandSurface {
            name: "Approval".to_owned(),
            protocol_constant: "APPROVAL_PROTOCOL".to_owned(),
            protocol: crate::approval_api::APPROVAL_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_APPROVAL_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: None,
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                approval_category(
                    "APPROVAL_COUNTER_OUT_OF_RANGE",
                    "A counter is outside the range the integer-only wire codec carries.",
                    &ApprovalApiError::CounterOutOfRange { field: "since" },
                ),
                approval_category(
                    "APPROVAL_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &ApprovalApiError::InvalidBody,
                ),
                approval_category(
                    "APPROVAL_INVALID_FIELD",
                    "A bounded key, subject or decider was empty, over-long or control-bearing.",
                    &ApprovalApiError::Field {
                        field: "approval_key",
                        error: ValueError::Empty,
                    },
                ),
                approval_category(
                    "APPROVAL_PAGE_SIZE_OUT_OF_RANGE",
                    "A requested page size was zero — a page that admits nothing cannot make \
                     progress — or above the largest page this protocol serves.",
                    &ApprovalApiError::PageSizeOutOfRange {
                        max_items: 0,
                        requested: 0,
                    },
                ),
                approval_category(
                    "APPROVAL_PAGE_TOO_LARGE",
                    "A page carried more decisions than one page holds.",
                    &ApprovalApiError::PageTooLarge {
                        max_items: 0,
                        actual_items: 0,
                    },
                ),
                approval_category(
                    "APPROVAL_ROW_AMENDED",
                    "A write-once row claimed a revision other than one. The ledger pins the \
                     column with a database CHECK and has no update path, so any other value \
                     names a row this product could not have written.",
                    &ApprovalApiError::RowAmended { revision: 2 },
                ),
                approval_category(
                    "APPROVAL_TIME_BEFORE_EPOCH",
                    "A durable instant was before the epoch, which the ledger cannot hold.",
                    &ApprovalApiError::TimeBeforeEpoch {
                        field: "decided_at_ms",
                    },
                ),
                approval_category(
                    "APPROVAL_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &ApprovalApiError::UnknownKind,
                ),
                approval_category(
                    "APPROVAL_UNWRITTEN_ROW",
                    "A durable row identity was zero, which names a row no writer produced.",
                    &ApprovalApiError::UnwrittenRow { field: "entry_id" },
                ),
                // The three below are the shared codec's own categories, which
                // this protocol reports unchanged. They carry this lane's prefix
                // because one name has one declaring module.
                approval_category(
                    "APPROVAL_FIELD_GRAMMAR",
                    "An envelope field cleared the bounded-value rules and broke its own grammar.",
                    &ApprovalApiError::Codec(CodecError::Grammar {
                        field: "request_id",
                    }),
                ),
                approval_category(
                    "APPROVAL_FIELD_INVALID",
                    "An envelope field was empty, too long, or carried a control character.",
                    &ApprovalApiError::Codec(CodecError::Field {
                        field: "request_id",
                        error: ValueError::Empty,
                    }),
                ),
                approval_category(
                    "APPROVAL_UNKNOWN_ENUM_VALUE",
                    "A decision, disposition, conflict field or refusal this build does not \
                     define. All four vocabularies on this lane fail closed: every guess at an \
                     unnameable answer to an approval question is wrong.",
                    &ApprovalApiError::Codec(CodecError::UnknownEnumValue { field: "decision" }),
                ),
                Constant {
                    // As on the Runs and Automation lanes, nothing pins this
                    // one: no shipped transport carries `automonique.approval`
                    // yet, so no peer reports a spelling for a payload above the
                    // ceiling.
                    name: "APPROVAL_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above this protocol's ceiling. No shipped transport \
                          carries this protocol yet, so nothing pins this spelling; it is the one \
                          the local admin transport reports for the same fault."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "APPROVAL_INVALID_BODY".to_owned(),
            unknown_kind_category: "APPROVAL_UNKNOWN_KIND".to_owned(),
            oversize_category: "APPROVAL_FRAME_SIZE".to_owned(),
            field_invalid_category: "APPROVAL_FIELD_INVALID".to_owned(),
            field_grammar_category: "APPROVAL_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: Vec::new(),
            body_objects: vec![BodyObject {
                name: "ApprovalRecord".to_owned(),
                doc: "One validated `approval_decisions` row. `revision` is always one and this \
                      type refuses anything else: the row is write-once, so there is no update \
                      and no delete, and reversing a decision is a new key naming the same \
                      subject with both rows surviving."
                    .to_owned(),
                fields: approval_record_fields(),
            }],
            requests: vec![
                RequestCommand {
                    kind: "approval_detail".to_owned(),
                    name: "ApprovalDetail".to_owned(),
                    doc: "Read one decision in full, by the key it was recorded under.".to_owned(),
                    fields: vec![checked_field(
                        "approval_key",
                        APPROVAL_KEY,
                        "APPROVAL_INVALID_FIELD",
                    )],
                    coupling: None,
                },
                RequestCommand {
                    kind: "approvals_by_subject".to_owned(),
                    name: "ApprovalsBySubject".to_owned(),
                    doc: "Ask for one bounded page of the decisions recorded against one subject, \
                          in the order they were recorded. A grant and the later denial that \
                          reconsidered it are two records here; which of them governs is not this \
                          protocol's answer. The cursor is a position in the whole listing rather \
                          than in the matching subset, exactly as the ledger judges it."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "ApprovalPageSize".to_owned(),
                                refusal_category: "APPROVAL_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::Integer {
                                type_name: APPROVAL_CURSOR.to_owned(),
                                refusal_category: "APPROVAL_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        checked_field("subject", APPROVAL_SUBJECT, "APPROVAL_INVALID_FIELD"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "decide_request".to_owned(),
                    name: "DecideRequest".to_owned(),
                    doc: "Answer one durable approval proposal. Deliberately narrower than \
                          `record_approval`: there is no subject, because the subject is what \
                          the proposal already binds and a decision that carried one would let \
                          a caller assert what it was deciding about. There is no instant \
                          either, for the reason `record_approval` has none. This is the lane \
                          every operator surface converges on, and the decision it records is \
                          the one a launch is admitted against."
                        .to_owned(),
                    fields: vec![
                        checked_field("decider", DECIDER, "APPROVAL_INVALID_FIELD"),
                        RequestField {
                            name: "decision".to_owned(),
                            input_name: "decision".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "ApprovalDecision".to_owned(),
                                unknown_category: "APPROVAL_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                        checked_field("request_key", APPROVAL_KEY, "APPROVAL_INVALID_FIELD"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "list_approvals".to_owned(),
                    name: "ListApprovals".to_owned(),
                    doc: "Ask for one bounded page of every recorded decision. `since` is the \
                          entry this listing resumes *after*, and zero is the beginning rather \
                          than the absence of a cursor."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "ApprovalPageSize".to_owned(),
                                refusal_category: "APPROVAL_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::Integer {
                                type_name: APPROVAL_CURSOR.to_owned(),
                                refusal_category: "APPROVAL_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "record_approval".to_owned(),
                    name: "RecordApproval".to_owned(),
                    doc: "Record one decision, write-once. The only mutation this protocol has: \
                          there is no update and no delete, because the ledger has neither. The \
                          instant is not a field either — the daemon stamps it from its own \
                          clock, because a caller-supplied one would let a client date a decision \
                          to whenever it liked and the durable row is the evidence."
                        .to_owned(),
                    fields: vec![
                        checked_field("approval_key", APPROVAL_KEY, "APPROVAL_INVALID_FIELD"),
                        checked_field("decider", DECIDER, "APPROVAL_INVALID_FIELD"),
                        RequestField {
                            name: "decision".to_owned(),
                            input_name: "decision".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "ApprovalDecision".to_owned(),
                                unknown_category: "APPROVAL_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                        checked_field("subject", APPROVAL_SUBJECT, "APPROVAL_INVALID_FIELD"),
                    ],
                    coupling: None,
                },
            ],
            // This protocol version defines exactly the five requests above.
            // `tests/codegen.rs` proves the list against the Rust encoders
            // themselves rather than against this claim.
            request_kinds_not_generated: Vec::new(),
            request_validations: Vec::new(),
            request_response_kinds: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "approval_conflict".to_owned(),
                    name: "ApprovalConflict".to_owned(),
                    doc: "The key is recorded with a different decision. Nothing was written, and \
                          nothing ever will be for this key: the ledger has no update path, and a \
                          genuinely changed decision is a new key. The recorded coordinates \
                          travel with the answer so a caller learns what it collided with without \
                          a second read; the key is deliberately absent, because the caller \
                          supplied it and already holds it."
                        .to_owned(),
                    fields: vec![
                        approval_integer_field(
                            "entry_id",
                            DURABLE_ROW_ID,
                            "APPROVAL_UNWRITTEN_ROW",
                            true,
                        ),
                        // Which of the three the two decisions differ on. The
                        // answering end derives it by comparing them in the
                        // order the ledger compares them; a decoder cannot
                        // re-derive it, because a conflict carries only the
                        // recorded side. What a decoder can hold is that the
                        // spelling is one of the three, and it does.
                        approval_enum_field("field", "ApprovalConflictField"),
                        approval_checked_field("recorded_decider", DECIDER),
                        approval_enum_field("recorded_decision", "ApprovalDecision"),
                        approval_checked_field("recorded_subject", APPROVAL_SUBJECT),
                    ],
                },
                ResponseDecoder {
                    kind: "approval_detail_result".to_owned(),
                    name: "ApprovalDetailView".to_owned(),
                    // The body *is* a record: no wrapper key, nothing nested
                    // beside it. The fields come from the same list the nested
                    // body object is built from, so the two readings cannot
                    // drift apart.
                    doc: "One decision in full. The body is a record with no wrapper: what a \
                          listing carries in an array is what a detail read answers on its own."
                        .to_owned(),
                    fields: approval_record_fields(),
                },
                ResponseDecoder {
                    kind: "approval_list_result".to_owned(),
                    name: "ApprovalListPage".to_owned(),
                    doc: "One bounded page of decision records. `more` is carried explicitly \
                          rather than inferred from a short page: a subject filter can exclude \
                          every row in a scanned window and still leave rows behind it, so a \
                          client that inferred `done` from a short page would stop early."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "approvals".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "ApprovalRecord".to_owned(),
                                max_items_constant: "MAX_APPROVAL_PAGE_ITEMS".to_owned(),
                                oversize_category: "APPROVAL_PAGE_TOO_LARGE".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "more".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "next_cursor".to_owned(),
                            value: ResponseValue::NullableInteger {
                                type_name: APPROVAL_CURSOR.to_owned(),
                                refusal_category: "APPROVAL_INVALID_BODY".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "approval_recorded".to_owned(),
                    name: "ApprovalReceipt".to_owned(),
                    doc: "One decision is durable, and the disposition says whether this call is \
                          what made it so. `accepted` rather than `completed`, on a fresh \
                          recording and on an exact replay alike: the row is committed, but what \
                          it records has not taken effect and cannot, because no executor in this \
                          build consults the ledger before acting. On an `already_recorded` \
                          answer the instant is the *first* recording's — a replay writes \
                          nothing, including the clock. There is no revision here, because a \
                          caller has nothing to fence against: no second write to this row exists."
                        .to_owned(),
                    fields: vec![
                        approval_checked_field("approval_key", APPROVAL_KEY),
                        approval_integer_field(
                            "decided_at_ms",
                            EPOCH_MILLIS,
                            "APPROVAL_TIME_BEFORE_EPOCH",
                            false,
                        ),
                        approval_enum_field("decision", "ApprovalDecision"),
                        approval_enum_field("disposition", "ApprovalDisposition"),
                        approval_integer_field(
                            "entry_id",
                            DURABLE_ROW_ID,
                            "APPROVAL_UNWRITTEN_ROW",
                            true,
                        ),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "ApprovalRefused".to_owned(),
                    doc: "The operation was refused. Nothing was written and nothing was read. A \
                          key recorded with a different answer is deliberately not among these \
                          words: that is a conflict, which a caller retries differently — and an \
                          exact replay is not among them either, because a replay is a success \
                          carrying `already_recorded`."
                        .to_owned(),
                    fields: vec![approval_enum_field("refusal", "ApprovalRefusal")],
                },
            ],
            // Every kind this protocol version answers with is decoded above.
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

// ---------------------------------------------------------------------------
// The `automonique.batch.control` registration surface
//
// Three of the four vocabularies below are `batch_runner`'s rather than this
// lane's: a batch document and a batch control message use one set of words,
// because there is one set of words. The `match`es are written out for the same
// reason they are on every other lane — a state added to `RunState` reaches
// `MemberProgress` automatically in Rust, and this file is where that silent
// widening is turned into a compile error.
// ---------------------------------------------------------------------------

/// The declared [`ConcurrencyKind`] spellings, pinned to the Rust wire strings.
fn concurrency_kind_values() -> Vec<String> {
    ConcurrencyKind::ALL
        .into_iter()
        .map(|kind| match kind {
            ConcurrencyKind::Sequential | ConcurrencyKind::BoundedParallel => {
                kind.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`MemberProgress`] spellings, pinned to the Rust wire strings.
///
/// Seven: the six [`RunState`]s the runner's spool defines, reused rather than
/// re-spelled, and the one a run vocabulary cannot express — a member for which
/// no submission has been recorded at all. The inner `match` is exhaustive over
/// [`RunState`] as well, so a seventh run state cannot widen this vocabulary
/// without this file being asked about it.
fn member_progress_values() -> Vec<String> {
    MemberProgress::ALL
        .into_iter()
        .map(|progress| match progress {
            MemberProgress::Unsubmitted
            | MemberProgress::Run(
                RunState::Ready
                | RunState::Running
                | RunState::Completed
                | RunState::Failed
                | RunState::Cancelled
                | RunState::TimedOut,
            ) => progress.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`BatchState`] spellings, pinned to the Rust wire strings.
fn batch_state_values() -> Vec<String> {
    BatchState::ALL
        .into_iter()
        .map(|state| match state {
            BatchState::Pending
            | BatchState::Running
            | BatchState::Completed
            | BatchState::Failed
            | BatchState::Cancelled
            | BatchState::Mixed => state.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`BatchRefusal`] spellings, pinned to the Rust wire strings.
fn batch_refusal_values() -> Vec<String> {
    BatchRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            BatchRefusal::UnknownBatch
            | BatchRefusal::UnknownMember
            | BatchRefusal::AlreadyRegistered
            | BatchRefusal::EmptyBatch
            | BatchRefusal::TooManyMembers
            | BatchRefusal::DuplicateMember
            | BatchRefusal::ConcurrencyCeiling
            | BatchRefusal::IllegalTransition
            | BatchRefusal::SequenceCoupling
            | BatchRefusal::SequenceRegression
            | BatchRefusal::CursorOutOfRange
            | BatchRefusal::RegistryFull
            | BatchRefusal::InvalidField => refusal.as_str().to_owned(),
        })
        .collect()
}

/// A refusal category, pinned to the spelling the Batch control API reports.
fn batch_category(name: &str, doc: &str, error: &BatchApiError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A security-sensitive enumeration of the Batch control API.
///
/// All four are [`SecuritySensitiveEnum`](crate::codec::SecuritySensitiveEnum)
/// in Rust and all four fail closed here. A reader that retained an undefined
/// member progress would have to decide what an unnameable answer means for the
/// rollup over it, and both available guesses are wrong: counting it as
/// finished invents a completion, and counting it as outstanding invents work
/// still to do.
fn batch_enum(name: &str, values: Vec<String>) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        // No set of these reaches the wire: this lane carries one word per
        // field and never a filter over a vocabulary.
        wire_order: None,
    }
}

/// A response or nested-body field carrying one of this lane's vocabularies.
fn batch_enum_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Enum {
            type_name: type_name.to_owned(),
            unknown_category: "BATCH_UNKNOWN_ENUM_VALUE".to_owned(),
        },
    }
}

/// A response or nested-body field carrying one of this lane's identifiers.
fn batch_checked_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: "BATCH_INVALID_FIELD".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded integer.
///
/// `unsigned` mirrors which Rust reader the field goes through, exactly as it
/// does on the three lanes before this one: an ordinal, a revision and a row
/// identity are read through `unsigned()`, which refuses a negative as a
/// malformed body before the domain is consulted, while a durable instant is
/// read signed and refused by the domain itself for being before the epoch.
fn batch_integer_field(
    name: &str,
    type_name: &str,
    refusal_category: &str,
    unsigned: bool,
) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
            unsigned,
        },
    }
}

/// TypeScript name of the branded batch identity.
const BATCH_ID: &str = "BatchId";

/// TypeScript name of the branded member key, which is a submission's own
/// idempotency key.
const BATCH_MEMBER_KEY: &str = "BatchMemberKey";

/// TypeScript name of the bounded operator-supplied label.
const BATCH_LABEL: &str = "BatchLabel";

/// TypeScript name of the branded listing position.
const BATCH_CURSOR: &str = "BatchCursor";

/// TypeScript name of the durable revision a registration or a read reports.
const BATCH_REVISION: &str = "BatchRevision";

/// TypeScript name of the declared concurrency ceiling.
const CONCURRENCY_CEILING: &str = "ConcurrencyCeiling";

/// TypeScript name of the member's position in its batch's declaration order.
const MEMBER_ORDINAL: &str = "MemberOrdinal";

/// TypeScript name of the discriminated concurrency policy.
const BATCH_CONCURRENCY: &str = "BatchConcurrency";

/// The six columns one `batch_members` row carries, as a reader decodes them.
fn batch_member_fields() -> Vec<ResponseField> {
    vec![
        batch_checked_field("key", BATCH_MEMBER_KEY),
        batch_integer_field("last_sequence", "LastSequence", "BATCH_INVALID_BODY", true),
        batch_integer_field(
            "ordinal",
            MEMBER_ORDINAL,
            "BATCH_MEMBERS_OUT_OF_ORDER",
            true,
        ),
        batch_integer_field("revision", BATCH_REVISION, "BATCH_UNWRITTEN_REVISION", true),
        batch_enum_field("state", "MemberProgress"),
        batch_integer_field(
            "updated_at_ms",
            EPOCH_MILLIS,
            "BATCH_TIME_BEFORE_EPOCH",
            false,
        ),
    ]
}

/// The six columns one `batches` row carries, as a reader decodes them.
///
/// One list, used twice: a batch row travels inside a listing page and inside a
/// detail read's `batch` key, and the two readings cannot be allowed to drift
/// into disagreeing about a column. The Rust side has the same shape for the
/// same reason — `BatchRecordView::from_body` is what both go through.
fn batch_record_fields() -> Vec<ResponseField> {
    vec![
        batch_checked_field("batch_id", BATCH_ID),
        ResponseField {
            name: "concurrency".to_owned(),
            value: ResponseValue::Object {
                type_name: BATCH_CONCURRENCY.to_owned(),
            },
        },
        batch_integer_field(
            "created_at_ms",
            EPOCH_MILLIS,
            "BATCH_TIME_BEFORE_EPOCH",
            false,
        ),
        batch_integer_field("entry_id", DURABLE_ROW_ID, "BATCH_UNWRITTEN_ROW", true),
        ResponseField {
            name: "label".to_owned(),
            value: ResponseValue::NullableChecked {
                type_name: BATCH_LABEL.to_owned(),
                refusal_category: "BATCH_INVALID_FIELD".to_owned(),
            },
        },
        batch_integer_field("revision", BATCH_REVISION, "BATCH_UNWRITTEN_REVISION", true),
    ]
}

/// The `automonique.batch.control` surface: what a batch declares, what a
/// writer reports about one member, and what a reader gets back.
fn batch_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(BATCH_MODULE),
        doc: "The native Batch control surface: declare which submissions a batch tracks, report \
              where each of them has got to, and read both back. It submits nothing, schedules \
              nothing and runs nothing: a declared concurrency policy is a recorded intention, \
              and a member's progress is a writer's claim rather than a reading of a run."
            .to_owned(),
        source: "automonique_protocol::batch_api".to_owned(),
        // A correlation identifier, a durable row identity, a durable instant
        // and a spool sequence are wire vocabularies rather than one lane's, so
        // this module reads them from where they are already declared. The
        // sequence in particular: a member's `last_sequence` *is* the runs
        // lane's, because the number a writer reports here is the one it read
        // there.
        imports: vec![
            ModuleImport {
                module: ADMIN_COMMAND_MODULE.to_owned(),
                values: vec![DURABLE_ROW_ID.to_owned(), "RequestId".to_owned()],
                types: Vec::new(),
            },
            ModuleImport {
                module: RUNS_MODULE.to_owned(),
                values: vec![EPOCH_MILLIS.to_owned(), "LastSequence".to_owned()],
                types: Vec::new(),
            },
        ],
        constants: vec![
            Constant {
                name: "BATCH_CONTROL_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one batch control surface."
                    .to_owned(),
                value: ConstantValue::Text(
                    crate::batch_api::BATCH_CONTROL_API_SCHEMA_V1.to_owned(),
                ),
            },
            Constant {
                name: "BATCH_CONTROL_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the native Batch control API. Dotted rather than \
                      hyphenated, because the envelope's protocol grammar admits lowercase \
                      letters, digits and dots and nothing else — and distinct from the batch \
                      *document* schema, so a client cannot admit either shape under the other's \
                      name."
                    .to_owned(),
                value: ConstantValue::Text(crate::batch_api::BATCH_CONTROL_PROTOCOL.to_owned()),
            },
            Constant {
                name: "MAX_BATCH_CONTROL_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes this protocol will assemble or admit."
                    .to_owned(),
                value: ConstantValue::Count(crate::batch_api::MAX_BATCH_CONTROL_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_BATCH_CONTROL_MEMBERS".to_owned(),
                doc: "Maximum members one batch may declare *through this lane*. Half the batch \
                      model's own ceiling, and derived rather than chosen: a maximal registration \
                      of 256 maximal keys is about 66 KiB and the local socket reads 64 KiB. The \
                      durable registry still holds 256; the two are deliberately not reconciled, \
                      because that ceiling bounds a database write and this one bounds a wire \
                      frame, and the smaller of the two is the one a client sees."
                    .to_owned(),
                value: ConstantValue::Count(crate::batch_api::MAX_BATCH_CONTROL_MEMBERS),
            },
            Constant {
                name: "MAX_BATCH_PAGE_ITEMS".to_owned(),
                doc: "Maximum batches one listing page may carry. Thirty-two, because a batch row \
                      carries two maximal identifiers; the number is derived from this protocol's \
                      frame arithmetic rather than chosen. A longer page is refused rather than \
                      truncated: a truncated page that still answered `complete` is a silent drop."
                    .to_owned(),
                value: ConstantValue::Count(crate::batch_api::MAX_BATCH_PAGE_ITEMS),
            },
        ],
        branded_ids: vec![
            BrandedId {
                // The registry's own grammar: non-empty, bounded, control-free,
                // and nothing more. This protocol parses no identity and
                // derives nothing from one, so a wire type stricter than the
                // table would make a stored row unreadable through the only
                // surface that serves it.
                name: BATCH_ID.to_owned(),
                max_bytes: crate::batch_runner::MAX_BATCH_ID_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BrandedId {
                // The idempotency key of the submission this member names,
                // bounded by what the admin lane admits for one: a key this
                // batch admitted and that lane refused would be a batch that
                // could never be submitted.
                name: BATCH_MEMBER_KEY.to_owned(),
                max_bytes: crate::batch_runner::MAX_BATCH_MEMBER_KEY_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        bounded_strings: vec![BoundedString {
            // Operator-supplied and recorded verbatim. Absent is a fact rather
            // than an empty string: a batch with no label carries null, and
            // empty is refused.
            name: BATCH_LABEL.to_owned(),
            max_bytes: crate::batch_runner::MAX_BATCH_LABEL_BYTES,
            pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
        }],
        bounded_integers: vec![
            BoundedInteger {
                // Zero is the beginning of the listing rather than the absence
                // of a cursor: this lane carries the registry's own exclusive
                // cursor, so there is no coordinate to convert.
                name: BATCH_CURSOR.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "BatchPageSize".to_owned(),
                min: 1,
                max: i64::try_from(crate::batch_api::MAX_BATCH_PAGE_ITEMS)
                    .expect("the page bound is within the wire range"),
            },
            BoundedInteger {
                // Registration writes one and every accepted advance writes one
                // higher, so zero names a row this product could not have
                // written.
                name: BATCH_REVISION.to_owned(),
                min: 1,
                max: i64::MAX,
            },
            BoundedInteger {
                // An advance receipt's revision, which is a *stricter* domain
                // than a row's: registration is the only writer of revision
                // one, so an advance that claimed it would name a row no
                // accepted advance could have left behind. The second half of
                // that Rust rule — an advance cannot claim `unsubmitted` — is a
                // relation between two fields and stays with the Rust decoder.
                name: "AdvancedRevision".to_owned(),
                min: 2,
                max: i64::MAX,
            },
            BoundedInteger {
                // A ceiling of zero admits nothing, and one above the batch
                // model's own membership can never bind — an unbounded policy
                // with a number written on it. The two are different refusals
                // and the generated decoder reports them separately.
                name: CONCURRENCY_CEILING.to_owned(),
                min: 1,
                max: i64::try_from(crate::batch_runner::MAX_BATCH_MEMBERS)
                    .expect("the membership ceiling is within the wire range"),
            },
            BoundedInteger {
                // A position in the declaration order, from zero. The ordinals
                // being `0..n` in order is what makes a rollup over them mean
                // anything; that they are contiguous is a relation between
                // members and stays with the Rust decoder, but that each one is
                // inside the membership this lane carries is a bound on its own
                // value.
                name: MEMBER_ORDINAL.to_owned(),
                min: 0,
                max: i64::try_from(crate::batch_api::MAX_BATCH_CONTROL_MEMBERS - 1)
                    .expect("the ordinal ceiling is within the wire range"),
            },
            BoundedInteger {
                name: "MemberCount".to_owned(),
                min: 1,
                max: i64::try_from(crate::batch_api::MAX_BATCH_CONTROL_MEMBERS)
                    .expect("the membership ceiling is within the wire range"),
            },
        ],
        enums: vec![
            batch_enum("ConcurrencyKind", concurrency_kind_values()),
            batch_enum("MemberProgress", member_progress_values()),
            batch_enum("BatchState", batch_state_values()),
            batch_enum("BatchRefusal", batch_refusal_values()),
        ],
        command_surface: Some(CommandSurface {
            name: "Batch".to_owned(),
            protocol_constant: "BATCH_CONTROL_PROTOCOL".to_owned(),
            protocol: crate::batch_api::BATCH_CONTROL_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_BATCH_CONTROL_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: None,
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                batch_category(
                    "BATCH_COUNTER_OUT_OF_RANGE",
                    "A counter is outside the range the integer-only wire codec carries.",
                    &BatchApiError::CounterOutOfRange { field: "since" },
                ),
                batch_category(
                    "BATCH_INVALID_BODY",
                    "A body was not the exact shape defined for its kind, which includes a \
                     concurrency policy whose two keys contradict each other.",
                    &BatchApiError::InvalidBody,
                ),
                batch_category(
                    "BATCH_INVALID_FIELD",
                    "A bounded identity, member key or label was empty, over-long or \
                     control-bearing.",
                    &BatchApiError::Field {
                        field: "batch_id",
                        error: ValueError::Empty,
                    },
                ),
                batch_category(
                    "BATCH_MEMBERS_OUT_OF_ORDER",
                    "A member carried an ordinal outside the membership this lane admits.",
                    &BatchApiError::MembersOutOfOrder { position: 0 },
                ),
                batch_category(
                    "BATCH_MEMBERSHIP_TOO_LARGE",
                    "A membership was larger than this lane carries. The transport's ceiling \
                     rather than the registry's, and the two are not reconciled.",
                    &BatchApiError::MembershipTooLarge {
                        max_members: 0,
                        actual_members: 0,
                    },
                ),
                batch_category(
                    "BATCH_NOT_AN_ADVANCE",
                    "An advance receipt described a row registration wrote rather than one an \
                     advance produced.",
                    &BatchApiError::NotAnAdvance {
                        progress: MemberProgress::Unsubmitted,
                        revision: 1,
                    },
                ),
                batch_category(
                    "BATCH_PAGE_SIZE_OUT_OF_RANGE",
                    "A requested page size was zero — a page that admits nothing cannot make \
                     progress — or above the largest page this protocol serves.",
                    &BatchApiError::PageSizeOutOfRange {
                        max_items: 0,
                        requested: 0,
                    },
                ),
                batch_category(
                    "BATCH_PAGE_TOO_LARGE",
                    "A page carried more batches than one page holds.",
                    &BatchApiError::PageTooLarge {
                        max_items: 0,
                        actual_items: 0,
                    },
                ),
                batch_category(
                    "BATCH_TIME_BEFORE_EPOCH",
                    "A durable instant was before the epoch, which the registry cannot hold.",
                    &BatchApiError::TimeBeforeEpoch {
                        field: "created_at_ms",
                    },
                ),
                batch_category(
                    "BATCH_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &BatchApiError::UnknownKind,
                ),
                batch_category(
                    "BATCH_UNWRITTEN_REVISION",
                    "A revision was zero, which names a row no writer produced: registration \
                     writes one and every accepted advance writes one higher.",
                    &BatchApiError::UnwrittenRevision,
                ),
                batch_category(
                    "BATCH_UNWRITTEN_ROW",
                    "A durable row identity was zero, which names a row no writer produced.",
                    &BatchApiError::UnwrittenRow { field: "entry_id" },
                ),
                // The three below are the batch *model*'s categories, which
                // this lane reports unchanged: they are properties of a batch
                // rather than of this transport, and restating them here would
                // create a second authority for one vocabulary. They keep the
                // model's own `batch_` prefix for exactly that reason.
                batch_category(
                    "BATCH_CONCURRENCY_CEILING_UNREACHABLE",
                    "A concurrency ceiling above what a batch could ever place in flight, which \
                     is an unbounded policy with a number written on it.",
                    &BatchApiError::Model(BatchError::ConcurrencyCeilingUnreachable {
                        max_members: 0,
                        requested: 0,
                    }),
                ),
                batch_category(
                    "BATCH_CONCURRENCY_CEILING_ZERO",
                    "A concurrency ceiling of zero, which admits no work at all rather than \
                     meaning `no limit`.",
                    &BatchApiError::Model(BatchError::ConcurrencyCeilingZero),
                ),
                batch_category(
                    "BATCH_EMPTY_BATCH",
                    "A batch named no member, which is a unit with nothing in it. An empty batch \
                     has no rolled-up state either, because `completed` over nothing would be \
                     vacuously true.",
                    &BatchApiError::Model(BatchError::EmptyBatch),
                ),
                // And these three are the shared codec's own, reported
                // unchanged under this lane's prefix because one name has one
                // declaring module.
                batch_category(
                    "BATCH_FIELD_GRAMMAR",
                    "An envelope field cleared the bounded-value rules and broke its own grammar.",
                    &BatchApiError::Codec(CodecError::Grammar {
                        field: "request_id",
                    }),
                ),
                batch_category(
                    "BATCH_FIELD_INVALID",
                    "An envelope field was empty, too long, or carried a control character.",
                    &BatchApiError::Codec(CodecError::Field {
                        field: "request_id",
                        error: ValueError::Empty,
                    }),
                ),
                batch_category(
                    "BATCH_UNKNOWN_ENUM_VALUE",
                    "A concurrency kind, member progress, batch state or refusal this build does \
                     not define. All four vocabularies fail closed: a member state nobody can \
                     name has no safe reading, and the rollup over it would be a claim about work \
                     this build cannot describe.",
                    &BatchApiError::Codec(CodecError::UnknownEnumValue { field: "state" }),
                ),
                Constant {
                    // As on the three lanes before this one, nothing pins this
                    // spelling: the local admin transport reports it for the
                    // same fault, and this protocol's own frames are read under
                    // that transport's ceiling.
                    name: "BATCH_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above this protocol's ceiling. It is the spelling \
                          the local admin transport reports for the same fault."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "BATCH_INVALID_BODY".to_owned(),
            unknown_kind_category: "BATCH_UNKNOWN_KIND".to_owned(),
            oversize_category: "BATCH_FRAME_SIZE".to_owned(),
            field_invalid_category: "BATCH_FIELD_INVALID".to_owned(),
            field_grammar_category: "BATCH_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: vec![DiscriminatedBody {
                name: BATCH_CONCURRENCY.to_owned(),
                doc: "How many members of a batch may be in flight, and in what order. Recorded, \
                      never enforced: nothing in this build counts what is in flight. There is \
                      deliberately no word meaning `unbounded` — the only word that admits more \
                      than one member carries a declared ceiling — and `sequential` is not \
                      `bounded_parallel` with a ceiling of one, because sequential also fixes the \
                      order to the declaration's and bounded parallelism declares none."
                    .to_owned(),
                tag_field: "kind".to_owned(),
                tag_type: "ConcurrencyKind".to_owned(),
                unknown_tag_category: "BATCH_UNKNOWN_ENUM_VALUE".to_owned(),
                payload_field: "max_in_flight".to_owned(),
                payload_type: CONCURRENCY_CEILING.to_owned(),
                payload_below_category: "BATCH_CONCURRENCY_CEILING_ZERO".to_owned(),
                payload_above_category: "BATCH_CONCURRENCY_CEILING_UNREACHABLE".to_owned(),
                payload_wire_max: i64::from(u32::MAX),
                bare_tags: vec!["sequential".to_owned()],
                carrying_tag: "bounded_parallel".to_owned(),
                invalid_body_category: "BATCH_INVALID_BODY".to_owned(),
            }],
            body_objects: vec![
                BodyObject {
                    name: "BatchMemberRecord".to_owned(),
                    doc: "One validated `batch_members` row. `state` is the last progress a \
                          writer reported and never a reading of a run: the durable run index is \
                          the true binding from a submission to the state its run reached, and \
                          this lane never joins it."
                        .to_owned(),
                    fields: batch_member_fields(),
                },
                BodyObject {
                    name: "BatchRecord".to_owned(),
                    doc: "One validated `batches` row. There is no rolled-up state here and \
                          deliberately so: a listing carries batch rows and not their members, so \
                          it has nothing to roll up *from*."
                        .to_owned(),
                    fields: batch_record_fields(),
                },
            ],
            requests: vec![
                RequestCommand {
                    kind: "advance_member".to_owned(),
                    name: "AdvanceMember".to_owned(),
                    doc: "Report that one member moved. What this presents is a claim: it says \
                          what a writer observed after reading the run index, and no transaction \
                          spans the two. The revision is the fence — the value the last accepted \
                          write left behind — and a stale one is answered with a conflict rather \
                          than a refusal, because the two are retried differently."
                        .to_owned(),
                    fields: vec![
                        checked_field("batch_id", BATCH_ID, "BATCH_INVALID_FIELD"),
                        RequestField {
                            name: "expected_revision".to_owned(),
                            input_name: "expected_revision".to_owned(),
                            value: RequestValue::Integer {
                                type_name: BATCH_REVISION.to_owned(),
                                refusal_category: "BATCH_UNWRITTEN_REVISION".to_owned(),
                            },
                        },
                        RequestField {
                            name: "last_sequence".to_owned(),
                            input_name: "last_sequence".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "LastSequence".to_owned(),
                                refusal_category: "BATCH_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        checked_field("member_key", BATCH_MEMBER_KEY, "BATCH_INVALID_FIELD"),
                        RequestField {
                            name: "state".to_owned(),
                            input_name: "state".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "MemberProgress".to_owned(),
                                unknown_category: "BATCH_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "batch_detail".to_owned(),
                    name: "BatchDetail".to_owned(),
                    doc: "Read one batch, its whole membership, and the state that membership \
                          rolls up to."
                        .to_owned(),
                    fields: vec![checked_field("batch_id", BATCH_ID, "BATCH_INVALID_FIELD")],
                    coupling: None,
                },
                RequestCommand {
                    kind: "list_batches".to_owned(),
                    name: "ListBatches".to_owned(),
                    doc: "Ask for one bounded page of every registered batch. `since` is the \
                          entry this listing resumes *after*, and zero is the beginning rather \
                          than the absence of a cursor."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "BatchPageSize".to_owned(),
                                refusal_category: "BATCH_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::Integer {
                                type_name: BATCH_CURSOR.to_owned(),
                                refusal_category: "BATCH_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "register_batch".to_owned(),
                    name: "RegisterBatch".to_owned(),
                    doc: "Declare one batch and its whole membership. It submits nothing: the \
                          members are submission *keys*, no RunSpec document travels here, and a \
                          registered batch causes no run to exist. The membership is fixed at \
                          registration and every member starts `unsubmitted`, so there is no \
                          initial-progress field; there is no instant field either, because the \
                          daemon stamps it from its own clock rather than letting a caller date a \
                          registration to whenever it liked."
                        .to_owned(),
                    fields: vec![
                        checked_field("batch_id", BATCH_ID, "BATCH_INVALID_FIELD"),
                        RequestField {
                            name: "concurrency".to_owned(),
                            input_name: "concurrency".to_owned(),
                            value: RequestValue::Discriminated {
                                type_name: BATCH_CONCURRENCY.to_owned(),
                            },
                        },
                        RequestField {
                            name: "label".to_owned(),
                            input_name: "label".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: BATCH_LABEL.to_owned(),
                                refusal_category: "BATCH_INVALID_FIELD".to_owned(),
                            },
                        },
                        RequestField {
                            name: "members".to_owned(),
                            input_name: "members".to_owned(),
                            value: RequestValue::CheckedArray {
                                type_name: BATCH_MEMBER_KEY.to_owned(),
                                refusal_category: "BATCH_INVALID_FIELD".to_owned(),
                                max_items_constant: "MAX_BATCH_CONTROL_MEMBERS".to_owned(),
                                oversize_category: "BATCH_MEMBERSHIP_TOO_LARGE".to_owned(),
                                empty_category: "BATCH_EMPTY_BATCH".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
            ],
            // This protocol version defines exactly the four requests above.
            // `tests/codegen.rs` proves the list against the Rust encoders
            // themselves rather than against this claim.
            request_kinds_not_generated: Vec::new(),
            request_validations: Vec::new(),
            request_response_kinds: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "batch_detail_result".to_owned(),
                    name: "BatchDetailView".to_owned(),
                    doc: "One batch, its whole membership, and what that membership rolls up to. \
                          The rolled-up state is never stored: the durable registry has no such \
                          column, because the rollup is a total function of the member states and \
                          a column would be a second copy of an answer that can drift. It travels \
                          here because the members that justify it travel beside it — and the \
                          Rust decoder re-derives it and refuses a body whose carried state \
                          contradicts its own members, which is a relation between two fields and \
                          therefore one this file does not hold."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "batch".to_owned(),
                            value: ResponseValue::Object {
                                type_name: "BatchRecord".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "members".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "BatchMemberRecord".to_owned(),
                                max_items_constant: "MAX_BATCH_CONTROL_MEMBERS".to_owned(),
                                oversize_category: "BATCH_MEMBERSHIP_TOO_LARGE".to_owned(),
                            },
                        },
                        batch_enum_field("state", "BatchState"),
                    ],
                },
                ResponseDecoder {
                    kind: "batch_list_result".to_owned(),
                    name: "BatchListPage".to_owned(),
                    doc: "One bounded page of batch rows, in registration order. `more` is \
                          carried explicitly rather than inferred from a short page: a short page \
                          is not the same statement as a last page, and a client that inferred \
                          `done` from one would stop early."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "batches".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "BatchRecord".to_owned(),
                                max_items_constant: "MAX_BATCH_PAGE_ITEMS".to_owned(),
                                oversize_category: "BATCH_PAGE_TOO_LARGE".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "more".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "next_cursor".to_owned(),
                            value: ResponseValue::NullableInteger {
                                type_name: BATCH_CURSOR.to_owned(),
                                refusal_category: "BATCH_INVALID_BODY".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "batch_registered".to_owned(),
                    name: "BatchReceipt".to_owned(),
                    doc: "One batch and its whole membership are durable. `accepted` rather than \
                          `completed`: the rows are committed, and what they record has not taken \
                          effect and cannot, because registering a batch submits nothing. Every \
                          member was written `unsubmitted`, at ordinals `0..member_count`."
                        .to_owned(),
                    fields: vec![
                        batch_checked_field("batch_id", BATCH_ID),
                        batch_integer_field(
                            "created_at_ms",
                            EPOCH_MILLIS,
                            "BATCH_TIME_BEFORE_EPOCH",
                            false,
                        ),
                        batch_integer_field(
                            "entry_id",
                            DURABLE_ROW_ID,
                            "BATCH_UNWRITTEN_ROW",
                            true,
                        ),
                        ResponseField {
                            name: "member_count".to_owned(),
                            value: ResponseValue::RangedInteger {
                                type_name: "MemberCount".to_owned(),
                                below_category: "BATCH_EMPTY_BATCH".to_owned(),
                                above_category: "BATCH_MEMBERSHIP_TOO_LARGE".to_owned(),
                                unsigned: true,
                            },
                        },
                        batch_integer_field(
                            "revision",
                            BATCH_REVISION,
                            "BATCH_UNWRITTEN_REVISION",
                            true,
                        ),
                    ],
                },
                ResponseDecoder {
                    kind: "member_advanced".to_owned(),
                    name: "MemberReceipt".to_owned(),
                    doc: "One member's row moved. The revision is the fencing value the *next* \
                          advance of this member must expect, and it is at least two: \
                          registration is the only writer of revision one, so an advance receipt \
                          below that names a row no accepted advance could have left behind."
                        .to_owned(),
                    fields: vec![
                        batch_checked_field("batch_id", BATCH_ID),
                        batch_integer_field(
                            "last_sequence",
                            "LastSequence",
                            "BATCH_INVALID_BODY",
                            true,
                        ),
                        batch_checked_field("member_key", BATCH_MEMBER_KEY),
                        batch_integer_field(
                            "ordinal",
                            MEMBER_ORDINAL,
                            "BATCH_MEMBERS_OUT_OF_ORDER",
                            true,
                        ),
                        batch_integer_field(
                            "revision",
                            "AdvancedRevision",
                            "BATCH_NOT_AN_ADVANCE",
                            true,
                        ),
                        batch_enum_field("state", "MemberProgress"),
                        batch_integer_field(
                            "updated_at_ms",
                            EPOCH_MILLIS,
                            "BATCH_TIME_BEFORE_EPOCH",
                            false,
                        ),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "BatchRefused".to_owned(),
                    doc: "The operation was refused. Nothing was written and nothing was read. A \
                          stale expected revision is deliberately not among these words: that is \
                          a conflict, which a caller retries against the durable revision the \
                          answer carries, where a refusal is not retried at all until the request \
                          changes."
                        .to_owned(),
                    fields: vec![batch_enum_field("refusal", "BatchRefusal")],
                },
                ResponseDecoder {
                    kind: "revision_conflict".to_owned(),
                    name: "BatchRevisionConflict".to_owned(),
                    doc: "The caller's expected revision did not match the durable one and \
                          nothing was written. Retry against `durable_revision`. Two revisions \
                          that agree would be agreement rather than a conflict, and the Rust \
                          constructor refuses to answer one — a relation between two fields, and \
                          therefore not a rule this file holds."
                        .to_owned(),
                    fields: vec![
                        batch_integer_field(
                            "durable_revision",
                            BATCH_REVISION,
                            "BATCH_UNWRITTEN_REVISION",
                            true,
                        ),
                        batch_integer_field(
                            "expected_revision",
                            BATCH_REVISION,
                            "BATCH_UNWRITTEN_REVISION",
                            true,
                        ),
                    ],
                },
            ],
            // Every kind this protocol version answers with is decoded above.
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

/// The declared [`EventKind`] spellings, pinned to the Rust wire strings.
///
/// Read off `EventKind::ALL`, whose own length is a compile-time array bound —
/// a kind added to the enum and left out of the table fails to compile there
/// rather than silently narrowing the generated union here.
fn event_kind_values() -> Vec<String> {
    EventKind::ALL
        .into_iter()
        .map(|kind| kind.as_str().to_owned())
        .collect()
}

/// The declared [`StepStatus`] spellings, pinned to the Rust wire strings.
fn step_status_values() -> Vec<String> {
    StepStatus::ALL
        .into_iter()
        .map(|status| match status {
            StepStatus::Pending
            | StepStatus::InProgress
            | StepStatus::Completed
            | StepStatus::Error => status.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`RetryCategory`] spellings, pinned to the Rust wire strings.
fn retry_category_values() -> Vec<String> {
    RetryCategory::ALL
        .into_iter()
        .map(|category| match category {
            RetryCategory::RateLimited
            | RetryCategory::Overloaded
            | RetryCategory::Timeout
            | RetryCategory::Transport
            | RetryCategory::Rejected
            | RetryCategory::Internal => category.as_str().to_owned(),
        })
        .collect()
}

/// A closed progress vocabulary, refused rather than retained when undefined.
fn progress_enum(name: &str, values: Vec<String>) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        // Every one of these is a `SecuritySensitiveEnum` in Rust. A client that
        // retained an undefined step status would have to decide whether the
        // step is still running, and the reassuring guess is the wrong one.
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order: None,
    }
}

/// The `automonique.progress/v1` frame surface and its live stream.
///
/// Two shapes that travel together and version apart. A [`ProgressFrame`] is
/// what a run *produced* and also travels as a runner spool payload, where no
/// subscriber exists; a stream message is what one subscriber is *told*, and it
/// carries a frame inside it. That is why the module declares two protocol
/// names rather than one.
///
/// There is no command surface, for the reason [`doctor_module`] has none: the
/// one request on this schema is a `subscribe`, and it does not travel the
/// admin envelope this generator's request builders emit. The subscribe body is
/// declared as an interface a client encodes itself.
///
/// [`ProgressFrame`]: crate::progress_api::ProgressFrame
fn progress_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(PROGRESS_MODULE),
        doc: "One normalized progress frame, as every surface renders a live run from.".to_owned(),
        source: "automonique_protocol::progress_api".to_owned(),
        // A name is declared in exactly one module. `Authority`, `EpochMillis`
        // and `SpoolSequence` are the Runs lane's declarations of the *same*
        // domains — a frame's sequence is a spool sequence, not a second kind
        // of number — `RunId` is the admin lane's, and `WireCounter` is the
        // admin status lane's, which is where the capability integer the
        // greeting carries is also declared. Re-declaring any of them would
        // make the name ambiguous through the barrel and give the surface two
        // copies to drift apart.
        imports: vec![
            ModuleImport {
                module: ADMIN_COMMAND_MODULE.to_owned(),
                values: vec!["RunId".to_owned()],
                types: Vec::new(),
            },
            ModuleImport {
                module: ADMIN_STATUS_MODULE.to_owned(),
                values: vec![WIRE_COUNTER.to_owned()],
                types: Vec::new(),
            },
            ModuleImport {
                module: RUNS_MODULE.to_owned(),
                values: vec![
                    "Authority".to_owned(),
                    EPOCH_MILLIS.to_owned(),
                    "SpoolSequence".to_owned(),
                ],
                types: Vec::new(),
            },
        ],
        constants: vec![
            Constant {
                name: "MAX_PROGRESS_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical bytes of one encoded frame. It is inside the runner \
                      spool's own payload ceiling, because a frame is stored as one spool \
                      event's payload."
                    .to_owned(),
                value: ConstantValue::Count(crate::progress_api::MAX_PROGRESS_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_PROGRESS_STREAM_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical bytes of one encoded stream message: one frame plus \
                      its envelope."
                    .to_owned(),
                value: ConstantValue::Count(
                    crate::progress_api::MAX_PROGRESS_STREAM_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_RETRY_AFTER_MS".to_owned(),
                doc: "Longest wait a retry context may advertise. A delay past it is refused \
                      rather than clamped: a wait nobody will sit through is a refusal wearing a \
                      promise."
                    .to_owned(),
                value: ConstantValue::Count(
                    usize::try_from(MAX_RETRY_AFTER_MS).expect("the retry ceiling fits a usize"),
                ),
            },
            Constant {
                name: "MAX_SUBSCRIBE_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical bytes of one subscription request. A peer that sent \
                      anything approaching a frame's size did not send a subscription."
                    .to_owned(),
                value: ConstantValue::Count(crate::progress_api::MAX_SUBSCRIBE_CANONICAL_BYTES),
            },
            Constant {
                name: "PROGRESS_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one frame.".to_owned(),
                value: ConstantValue::Text(crate::progress_api::PROGRESS_API_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "PROGRESS_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the normalized progress stream.".to_owned(),
                value: ConstantValue::Text(crate::progress_api::PROGRESS_PROTOCOL.to_owned()),
            },
            Constant {
                name: "PROGRESS_STREAM_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the live stream transport. Separate from the \
                      frame's own name, because a build can grow a stream message without \
                      changing a single frame."
                    .to_owned(),
                value: ConstantValue::Text(
                    crate::progress_api::PROGRESS_STREAM_PROTOCOL.to_owned(),
                ),
            },
            Constant {
                name: "PROGRESS_STREAM_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one stream message.".to_owned(),
                value: ConstantValue::Text(
                    crate::progress_api::PROGRESS_STREAM_SCHEMA_V1.to_owned(),
                ),
            },
        ],
        bounded_strings: vec![BoundedString {
            name: "ProgressText".to_owned(),
            max_bytes: crate::progress_api::MAX_PROGRESS_TEXT_BYTES,
            // One step looser than the crate's usual no-control-character rule:
            // a newline and a tab are content in a model's prose and in a tool's
            // output, and every other control character is an instruction to
            // some renderer rather than a character to show.
            pattern: Some("^(?:[^\\p{Cc}]|[\\n\\t])+$".to_owned()),
        }],
        bounded_integers: vec![
            BoundedInteger {
                // Counted from one: attempt zero names an attempt nobody made.
                name: "RetryAttempt".to_owned(),
                min: 1,
                max: i64::from(u32::MAX),
            },
            BoundedInteger {
                name: "RetryAfterMillis".to_owned(),
                min: 0,
                max: i64::try_from(MAX_RETRY_AFTER_MS).expect("the retry ceiling fits the wire"),
            },
            BoundedInteger {
                // Zero is admitted here and refused by `SpoolSequence`, and the
                // difference is the whole point: this is an *exclusive* cursor —
                // the last sequence a subscriber received — so zero is what a
                // subscriber that has received nothing truthfully reports, and a
                // window that retains nothing reports as a pair of them.
                name: "ProgressCursor".to_owned(),
                min: 0,
                max: i64::MAX,
            },
        ],
        enums: vec![
            progress_enum("EventKind", event_kind_values()),
            progress_enum("RetryCategory", retry_category_values()),
            progress_enum("StepStatus", step_status_values()),
            progress_enum("StreamMessageKind", stream_message_kind_values()),
            progress_enum("StreamRefusal", stream_refusal_values()),
        ],
        interfaces: vec![
            Interface {
                name: "RetryContext".to_owned(),
                doc: "Why a warning or a fault might be tried again, and when. A wait is present \
                      only on a retryable context; the Rust constructor refuses the other \
                      combination."
                    .to_owned(),
                fields: vec![
                    required("attempt", "RetryAttempt"),
                    required("category", "RetryCategory"),
                    nullable("retry_after_ms", "RetryAfterMillis"),
                    required("retryable", "boolean"),
                ],
            },
            Interface {
                name: "ProgressBody".to_owned(),
                doc: "What one frame says beyond its kind. Every member is present and may be \
                      null; which of them a kind requires and which it forbids is a cross-field \
                      rule only the Rust constructor applies."
                    .to_owned(),
                fields: vec![
                    nullable("retry", "RetryContext"),
                    nullable("step", "StepStatus"),
                    nullable("text", "ProgressText"),
                ],
            },
            Interface {
                name: "ProgressFrame".to_owned(),
                doc: "One normalized progress event. `sequence` is the runner spool's own \
                      position, which is what makes it a resumption cursor rather than a counter."
                    .to_owned(),
                fields: vec![
                    required("at_ms", EPOCH_MILLIS),
                    required("authority", "Authority"),
                    required("body", "ProgressBody"),
                    required("kind", "EventKind"),
                    required("run_id", "RunId"),
                    required("sequence", "SpoolSequence"),
                ],
            },
            Interface {
                name: "SubscribeRequest".to_owned(),
                doc: "What one subscriber asks for. `cursor` is exclusive — the last sequence \
                      this subscriber received — so a subscriber that has received nothing \
                      sends zero."
                    .to_owned(),
                fields: vec![
                    required("cursor", "ProgressCursor"),
                    required("run_id", "RunId"),
                ],
            },
            Interface {
                name: "StreamGreeting".to_owned(),
                doc: "What the endpoint is, written before it reads a request byte, so a \
                      client decides whether it understands the endpoint without disclosing \
                      what it wanted."
                    .to_owned(),
                fields: vec![required("capability", WIRE_COUNTER)],
            },
            Interface {
                name: "StreamLive".to_owned(),
                doc: "Delivery begins. `from` is the first sequence this subscriber will \
                      receive: its cursor plus one."
                    .to_owned(),
                fields: vec![required("from", "SpoolSequence")],
            },
            Interface {
                name: "StreamResync".to_owned(),
                doc: "The cursor is below what is retained. Both coordinates are zero when the \
                      endpoint retains nothing at all for the attempt, and the durable spool is \
                      then the only record there is."
                    .to_owned(),
                fields: vec![
                    required("snapshot_from", "ProgressCursor"),
                    required("snapshot_to", "ProgressCursor"),
                ],
            },
            Interface {
                name: "StreamStop".to_owned(),
                doc: "How a live stream ended, carried by both `lagged` and `retired`. \
                      `delivered_through` is the last sequence this subscriber actually \
                      received, which is the cursor it reconnects with."
                    .to_owned(),
                fields: vec![required("delivered_through", "ProgressCursor")],
            },
            Interface {
                name: "StreamRefused".to_owned(),
                doc: "Why a subscription was refused. The category is a closed spelling and \
                      carries nothing the peer supplied."
                    .to_owned(),
                fields: vec![required("category", "StreamRefusal")],
            },
        ],
        unions: vec![Union {
            name: "StreamMessage".to_owned(),
            discriminant: "kind".to_owned(),
            variants: stream_message_variants(),
        }],
        ..GeneratedModule::default()
    }
}

/// The declared [`StreamMessageKind`] spellings, pinned to the Rust strings.
///
/// [`StreamMessageKind`]: crate::progress_api::StreamMessageKind
fn stream_message_kind_values() -> Vec<String> {
    StreamMessageKind::ALL
        .into_iter()
        .map(|kind| match kind {
            StreamMessageKind::Greeting
            | StreamMessageKind::Live
            | StreamMessageKind::ResyncRequired
            | StreamMessageKind::Frame
            | StreamMessageKind::Lagged
            | StreamMessageKind::Retired
            | StreamMessageKind::Refused => kind.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`StreamRefusal`] spellings, pinned to the Rust strings.
///
/// [`StreamRefusal`]: crate::progress_api::StreamRefusal
fn stream_refusal_values() -> Vec<String> {
    StreamRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            StreamRefusal::SubscriberLimit
            | StreamRefusal::MalformedRequest
            | StreamRefusal::FieldInvalid
            | StreamRefusal::Internal => refusal.as_str().to_owned(),
        })
        .collect()
}

fn platform_values<T: Copy>(values: &[T], spelling: impl Fn(T) -> &'static str) -> Vec<String> {
    values
        .iter()
        .copied()
        .map(|value| spelling(value).to_owned())
        .collect()
}

const PLATFORM_INVALID_BODY: &str = "PLATFORM_INVALID_BODY";
const PLATFORM_VALUE_INVALID: &str = "PLATFORM_VALUE_INVALID";

fn platform_checked(type_name: &str) -> ResponseValue {
    ResponseValue::Checked {
        type_name: type_name.to_owned(),
        refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
    }
}

fn platform_nullable_checked(type_name: &str) -> ResponseValue {
    ResponseValue::NullableChecked {
        type_name: type_name.to_owned(),
        refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
    }
}

fn platform_enum(type_name: &str) -> ResponseValue {
    ResponseValue::Enum {
        type_name: type_name.to_owned(),
        unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
    }
}

fn platform_revision() -> ResponseValue {
    ResponseValue::Integer {
        type_name: "PlatformRevision".to_owned(),
        refusal_category: PLATFORM_INVALID_BODY.to_owned(),
        unsigned: true,
    }
}

fn platform_epoch_millis() -> ResponseValue {
    ResponseValue::Integer {
        type_name: "PlatformEpochMillis".to_owned(),
        refusal_category: PLATFORM_INVALID_BODY.to_owned(),
        unsigned: false,
    }
}

fn platform_object(type_name: &str) -> ResponseValue {
    ResponseValue::Object {
        type_name: type_name.to_owned(),
    }
}

fn platform_field(name: &str, value: ResponseValue) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value,
    }
}

fn platform_client_session_fields() -> Vec<RequestField> {
    vec![
        RequestField {
            name: "client".to_owned(),
            input_name: "client".to_owned(),
            value: RequestValue::Checked {
                type_name: "ClientId".to_owned(),
                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
            },
        },
        RequestField {
            name: "session".to_owned(),
            input_name: "session".to_owned(),
            value: RequestValue::Object {
                type_name: "DecodedResourceCoordinate".to_owned(),
            },
        },
    ]
}

fn platform_request_checked(name: &str, type_name: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
        },
    }
}

fn platform_request_integer(name: &str, type_name: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
        },
    }
}

fn platform_request_object(name: &str, type_name: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Object {
            type_name: type_name.to_owned(),
        },
    }
}

fn platform_exact_coordinate_validation(
    request_kind: &str,
    field: &str,
    kind: &str,
) -> (String, RequestValidation) {
    (
        request_kind.to_owned(),
        RequestValidation::ExactCoordinate {
            field: field.to_owned(),
            authority: ResourceAuthority::Automonique.as_str().to_owned(),
            kind: kind.to_owned(),
            refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
        },
    )
}

fn platform_body_object(name: &str, doc: &str, fields: Vec<ResponseField>) -> BodyObject {
    BodyObject {
        name: name.to_owned(),
        doc: doc.to_owned(),
        fields,
    }
}

fn platform_response(
    kind: &str,
    name: &str,
    doc: &str,
    fields: Vec<ResponseField>,
) -> ResponseDecoder {
    ResponseDecoder {
        kind: kind.to_owned(),
        name: name.to_owned(),
        doc: doc.to_owned(),
        fields,
    }
}

/// Server-owned mobile credential and actor-authorization vocabulary.
fn mobile_auth_json_surface() -> JsonSurface {
    const INVALID: &str = "MOBILE_AUTH_INVALID_BODY";
    const VALUE: &str = "MOBILE_AUTH_VALUE_INVALID";
    let field = |name: &str, value: ResponseValue| ResponseField {
        name: name.to_owned(),
        value,
    };
    let checked = |name: &str| ResponseValue::Checked {
        type_name: name.to_owned(),
        refusal_category: VALUE.to_owned(),
    };
    let integer = |name: &str| ResponseValue::Integer {
        type_name: name.to_owned(),
        refusal_category: VALUE.to_owned(),
        unsigned: true,
    };
    let exact = |type_name: &str, expected: &str, mismatch: &str| ResponseValue::ExactString {
        type_name: type_name.to_owned(),
        expected_constant: expected.to_owned(),
        mismatch_category: mismatch.to_owned(),
    };
    let document = |name: &str, doc: &str, encode: bool, fields: Vec<ResponseField>| JsonDocument {
        body: BodyObject {
            name: name.to_owned(),
            doc: doc.to_owned(),
            fields,
        },
        encode,
    };

    JsonSurface {
        invalid_body_category: INVALID.to_owned(),
        documents: vec![
            document(
                "MobileLimits",
                "Server-negotiated per-credential mobile ceilings.",
                true,
                vec![
                    field("max_follow_up_bytes", integer("MobileFollowUpBytes")),
                    field("max_page_events", integer("MobilePageEvents")),
                ],
            ),
            document(
                "MobileAuthorization",
                "Complete actor authorization admitted before Platform access.",
                false,
                vec![
                    field(
                        "actions",
                        ResponseValue::EnumArray {
                            type_name: "MobileAction".to_owned(),
                            max_items_constant: "MAX_MOBILE_ACTIONS".to_owned(),
                            oversize_category: VALUE.to_owned(),
                            unknown_category: VALUE.to_owned(),
                        },
                    ),
                    field("actor", checked("MobileActor")),
                    field("authorization_revision", integer("MobileRevision")),
                    field("credential_id", checked("MobileCredentialId")),
                    field("credential_revision", integer("MobileRevision")),
                    field("expires_at_ms", integer("MobileEpochMillis")),
                    field("issued_at_ms", integer("MobileEpochMillis")),
                    field(
                        "limits",
                        ResponseValue::Object {
                            type_name: "MobileLimits".to_owned(),
                        },
                    ),
                    field(
                        "schema",
                        exact(
                            "typeof MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_MISMATCH",
                        ),
                    ),
                    field("server_identity", checked("MobileServerIdentity")),
                    field(
                        "session_scope",
                        ResponseValue::CheckedArray {
                            type_name: "MobileSessionId".to_owned(),
                            max_items_constant: "MAX_MOBILE_SESSIONS".to_owned(),
                            oversize_category: VALUE.to_owned(),
                            refusal_category: VALUE.to_owned(),
                        },
                    ),
                ],
            ),
            document(
                "MobileDiscovery",
                "HTTPS-origin-bound discovery document.",
                false,
                vec![
                    field(
                        "credential_inventory_endpoint",
                        checked("MobileCredentialInventoryEndpoint"),
                    ),
                    field(
                        "credential_revoke_endpoint",
                        checked("MobileCredentialRevokeEndpoint"),
                    ),
                    field("origin", checked("MobileHttpsOrigin")),
                    field(
                        "operator_provision_endpoint",
                        checked("MobileOperatorProvisionEndpoint"),
                    ),
                    field(
                        "pairing_create_endpoint",
                        checked("MobilePairingCreateEndpoint"),
                    ),
                    field(
                        "pairing_exchange_endpoint",
                        checked("MobilePairingExchangeEndpoint"),
                    ),
                    field("platform_endpoint", checked("MobilePlatformEndpoint")),
                    field(
                        "protocol",
                        exact(
                            "typeof MOBILE_AUTH_PROTOCOL",
                            "MOBILE_AUTH_PROTOCOL",
                            "MOBILE_AUTH_PROTOCOL_MISMATCH",
                        ),
                    ),
                    field(
                        "schema",
                        exact(
                            "typeof MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_MISMATCH",
                        ),
                    ),
                    field("server_identity", checked("MobileServerIdentity")),
                    field(
                        "supported_versions",
                        ResponseValue::IntegerArray {
                            type_name: "MobileProtocolVersion".to_owned(),
                            max_items_constant: "MAX_MOBILE_PROTOCOL_VERSIONS".to_owned(),
                            oversize_category: VALUE.to_owned(),
                            refusal_category: VALUE.to_owned(),
                            unsigned: true,
                        },
                    ),
                ],
            ),
            document(
                "MobilePairingOffer",
                "Copy-safe origin and identity-bound one-time pairing offer.",
                false,
                vec![
                    field(
                        "exchange_endpoint",
                        checked("MobilePairingExchangeEndpoint"),
                    ),
                    field("expires_at_ms", integer("MobileEpochMillis")),
                    field("origin", checked("MobileHttpsOrigin")),
                    field("pairing_id", checked("MobilePairingId")),
                    field("pairing_token", checked("MobilePairingToken")),
                    field(
                        "schema",
                        exact(
                            "typeof MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_MISMATCH",
                        ),
                    ),
                    field("server_identity", checked("MobileServerIdentity")),
                ],
            ),
            document(
                "MobilePairingExchangeRequest",
                "Strict one-time pairing exchange proof.",
                true,
                vec![
                    field("pairing_id", checked("MobilePairingId")),
                    field("pairing_token", checked("MobilePairingToken")),
                    field("server_identity", checked("MobileServerIdentity")),
                ],
            ),
            document(
                "MobileCredentialInventoryRequest",
                "Bounded operator credential inventory page request.",
                true,
                vec![
                    field(
                        "cursor",
                        ResponseValue::NullableChecked {
                            type_name: "MobileCredentialId".to_owned(),
                            refusal_category: VALUE.to_owned(),
                        },
                    ),
                    field("page_size", integer("MobileCredentialPageSize")),
                ],
            ),
            document(
                "MobileCredentialRevokeRequest",
                "Operator revocation of one exact credential family.",
                true,
                vec![field("credential_id", checked("MobileCredentialId"))],
            ),
            document(
                "MobileCredentialSummary",
                "Secret-free operator inventory projection for one credential family.",
                false,
                vec![
                    field(
                        "authorization",
                        ResponseValue::Object {
                            type_name: "MobileAuthorization".to_owned(),
                        },
                    ),
                    field("refresh_expires_at_ms", integer("MobileEpochMillis")),
                    field(
                        "revoked_at_ms",
                        ResponseValue::NullableInteger {
                            type_name: "MobileEpochMillis".to_owned(),
                            refusal_category: VALUE.to_owned(),
                        },
                    ),
                ],
            ),
            document(
                "MobileCredentialInventory",
                "Bounded secret-free operator credential inventory page.",
                false,
                vec![
                    field(
                        "credentials",
                        ResponseValue::ObjectArray {
                            type_name: "MobileCredentialSummary".to_owned(),
                            max_items_constant: "MAX_MOBILE_CREDENTIAL_PAGE_SIZE".to_owned(),
                            oversize_category: VALUE.to_owned(),
                        },
                    ),
                    field(
                        "next_cursor",
                        ResponseValue::NullableChecked {
                            type_name: "MobileCredentialId".to_owned(),
                            refusal_category: VALUE.to_owned(),
                        },
                    ),
                    field(
                        "schema",
                        exact(
                            "typeof MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_MISMATCH",
                        ),
                    ),
                ],
            ),
            document(
                "IssuedMobileCredentials",
                "Rotating scoped credentials and their admitted authorization.",
                false,
                vec![
                    field("access_token", checked("MobileAccessToken")),
                    field(
                        "authorization",
                        ResponseValue::Object {
                            type_name: "MobileAuthorization".to_owned(),
                        },
                    ),
                    field("refresh_token", checked("MobileRefreshToken")),
                ],
            ),
            document(
                "MobileOperatorProvisionRequest",
                "Scope an operator explicitly provisions to one mobile client.",
                true,
                vec![
                    field(
                        "actions",
                        ResponseValue::EnumArray {
                            type_name: "MobileAction".to_owned(),
                            max_items_constant: "MAX_MOBILE_ACTIONS".to_owned(),
                            oversize_category: VALUE.to_owned(),
                            unknown_category: VALUE.to_owned(),
                        },
                    ),
                    field(
                        "limits",
                        ResponseValue::Object {
                            type_name: "MobileLimits".to_owned(),
                        },
                    ),
                    field(
                        "session_scope",
                        ResponseValue::CheckedArray {
                            type_name: "MobileSessionId".to_owned(),
                            max_items_constant: "MAX_MOBILE_SESSIONS".to_owned(),
                            oversize_category: VALUE.to_owned(),
                            refusal_category: VALUE.to_owned(),
                        },
                    ),
                ],
            ),
            document(
                "MobileRefreshRequest",
                "Origin-pinned refresh or revocation request.",
                true,
                vec![
                    field("refresh_token", checked("MobileRefreshToken")),
                    field("server_identity", checked("MobileServerIdentity")),
                ],
            ),
            document(
                "MobileRevocation",
                "Confirmation that revocation completed server-side.",
                false,
                vec![
                    field("revoked", ResponseValue::Bool),
                    field(
                        "schema",
                        exact(
                            "typeof MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_V1",
                            "MOBILE_AUTH_SCHEMA_MISMATCH",
                        ),
                    ),
                ],
            ),
            document(
                "MobileError",
                "Strict bounded mobile lifecycle refusal.",
                false,
                vec![field("error", checked("MobileErrorCode"))],
            ),
        ],
    }
}

fn mobile_auth_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(MOBILE_AUTH_MODULE),
        doc: "Origin-bound mobile discovery, scoped credential lifecycle, and actor authorization values."
            .to_owned(),
        source: "automonique_protocol::codegen::mobile_auth_module".to_owned(),
        constants: vec![
            Constant {
                name: "MOBILE_AUTH_PROTOCOL".to_owned(),
                doc: "Stable mobile authentication protocol name.".to_owned(),
                value: ConstantValue::Text("automonique.mobile-auth".to_owned()),
            },
            Constant {
                name: "MOBILE_AUTH_SCHEMA_V1".to_owned(),
                doc: "Stable version-one mobile authentication schema.".to_owned(),
                value: ConstantValue::Text("automonique.mobile-auth/v1".to_owned()),
            },
            Constant {
                name: "MOBILE_AUTH_MEDIA_TYPE".to_owned(),
                doc: "Exact media type for mobile lifecycle documents.".to_owned(),
                value: ConstantValue::Text(
                    "application/vnd.automonique.mobile-auth.v1+json".to_owned(),
                ),
            },
            Constant {
                name: "MOBILE_AUTH_INVALID_BODY".to_owned(),
                doc: "A mobile lifecycle document was not its exact bounded schema.".to_owned(),
                value: ConstantValue::Text("mobile_auth_invalid_body".to_owned()),
            },
            Constant {
                name: "MOBILE_AUTH_VALUE_INVALID".to_owned(),
                doc: "A mobile lifecycle field fell outside its value domain.".to_owned(),
                value: ConstantValue::Text("mobile_auth_value_invalid".to_owned()),
            },
            Constant {
                name: "MOBILE_AUTH_SCHEMA_MISMATCH".to_owned(),
                doc: "A mobile lifecycle document names another schema.".to_owned(),
                value: ConstantValue::Text("mobile_auth_schema_mismatch".to_owned()),
            },
            Constant {
                name: "MOBILE_AUTH_PROTOCOL_MISMATCH".to_owned(),
                doc: "A discovery document names another protocol.".to_owned(),
                value: ConstantValue::Text("mobile_auth_protocol_mismatch".to_owned()),
            },
            Constant {
                name: "MOBILE_PROTOCOL_UNSUPPORTED".to_owned(),
                doc: "No advertised protocol version is one this build speaks.".to_owned(),
                value: ConstantValue::Text("mobile_protocol_unsupported".to_owned()),
            },
            Constant {
                name: "MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION".to_owned(),
                doc: "Lowest mobile protocol version this build speaks.".to_owned(),
                value: ConstantValue::Count(usize::from(MIN_SUPPORTED_MOBILE_PROTOCOL_VERSION)),
            },
            Constant {
                name: "MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION".to_owned(),
                doc: "Highest mobile protocol version this build speaks.".to_owned(),
                value: ConstantValue::Count(usize::from(MAX_SUPPORTED_MOBILE_PROTOCOL_VERSION)),
            },
            Constant {
                name: "MAX_MOBILE_HTTP_BODY_BYTES".to_owned(),
                doc: "Maximum accepted mobile lifecycle response body.".to_owned(),
                value: ConstantValue::Count(65_536),
            },
            Constant {
                name: "MAX_MOBILE_PROTOCOL_VERSIONS".to_owned(),
                doc: "Maximum protocol versions in discovery.".to_owned(),
                value: ConstantValue::Count(MAX_MOBILE_PROTOCOL_VERSIONS),
            },
            Constant {
                name: "MAX_MOBILE_ACTIONS".to_owned(),
                doc: "Maximum independently granted mobile actions.".to_owned(),
                value: ConstantValue::Count(4),
            },
            Constant {
                name: "MAX_MOBILE_SESSIONS".to_owned(),
                doc: "Maximum exact session identifiers in one credential scope.".to_owned(),
                value: ConstantValue::Count(100),
            },
            Constant {
                name: "MAX_MOBILE_PAGE_EVENTS".to_owned(),
                doc: "Maximum negotiated event-page ceiling.".to_owned(),
                value: ConstantValue::Count(512),
            },
            Constant {
                name: "MAX_MOBILE_FOLLOW_UP_BYTES".to_owned(),
                doc: "Maximum negotiated UTF-8 follow-up bytes.".to_owned(),
                value: ConstantValue::Count(65_536),
            },
            Constant {
                name: "MAX_MOBILE_CREDENTIAL_PAGE_SIZE".to_owned(),
                doc: "Maximum secret-free credential summaries in one operator page.".to_owned(),
                value: ConstantValue::Count(100),
            },
            Constant {
                name: "MOBILE_PAIRING_TTL_MILLIS".to_owned(),
                doc: "Absolute maximum lifetime of a one-time pairing offer.".to_owned(),
                value: ConstantValue::Count(300_000),
            },
        ],
        branded_ids: vec![
            BrandedId {
                name: "MobileCredentialId".to_owned(),
                max_bytes: 46,
                pattern: Some("^mc_[A-Za-z0-9_-]{43}$".to_owned()),
            },
            BrandedId {
                name: "MobilePairingId".to_owned(),
                max_bytes: 46,
                pattern: Some("^pi_[A-Za-z0-9_-]{43}$".to_owned()),
            },
            BrandedId {
                name: "MobileSessionId".to_owned(),
                max_bytes: 256,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
        ],
        bounded_strings: vec![
            BoundedString {
                name: "MobileActor".to_owned(),
                max_bytes: 256,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
            BoundedString {
                name: "MobileAccessToken".to_owned(),
                max_bytes: 46,
                pattern: Some("^ma_[A-Za-z0-9_-]{43}$".to_owned()),
            },
            BoundedString {
                name: "MobileRefreshToken".to_owned(),
                max_bytes: 46,
                pattern: Some("^mr_[A-Za-z0-9_-]{43}$".to_owned()),
            },
            BoundedString {
                name: "MobilePairingToken".to_owned(),
                max_bytes: 46,
                pattern: Some("^mp_[A-Za-z0-9_-]{43}$".to_owned()),
            },
            BoundedString {
                name: "MobileServerIdentity".to_owned(),
                max_bytes: 71,
                pattern: Some("^sha256:[0-9a-f]{64}$".to_owned()),
            },
            BoundedString {
                name: "MobileHttpsOrigin".to_owned(),
                max_bytes: 2048,
                pattern: Some("^https:\\/\\/[^\\/?#@]+$".to_owned()),
            },
            BoundedString {
                name: "MobilePlatformEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some("^https:\\/\\/[^?#@]+\\/api\\/platform$".to_owned()),
            },
            BoundedString {
                name: "MobileOperatorProvisionEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some(
                    "^https:\\/\\/[^?#@]+\\/api\\/mobile\\/operator-provision$".to_owned(),
                ),
            },
            BoundedString {
                name: "MobilePairingCreateEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some("^https:\\/\\/[^?#@]+\\/api\\/mobile\\/pairings$".to_owned()),
            },
            BoundedString {
                name: "MobilePairingExchangeEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some(
                    "^https:\\/\\/[^?#@]+\\/api\\/mobile\\/pairings\\/exchange$".to_owned(),
                ),
            },
            BoundedString {
                name: "MobileCredentialInventoryEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some(
                    "^https:\\/\\/[^?#@]+\\/api\\/mobile\\/credentials\\/list$".to_owned(),
                ),
            },
            BoundedString {
                name: "MobileCredentialRevokeEndpoint".to_owned(),
                max_bytes: 2048,
                pattern: Some(
                    "^https:\\/\\/[^?#@]+\\/api\\/mobile\\/credentials\\/revoke$".to_owned(),
                ),
            },
            BoundedString {
                name: "MobileErrorCode".to_owned(),
                max_bytes: 64,
                pattern: Some("^[a-z][a-z0-9_]{0,63}$".to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                name: "MobileEpochMillis".to_owned(),
                min: 0,
                max: 9_007_199_254_740_991,
            },
            BoundedInteger {
                name: "MobileRevision".to_owned(),
                min: 1,
                max: 9_007_199_254_740_991,
            },
            BoundedInteger {
                name: "MobilePageEvents".to_owned(),
                min: 1,
                max: 512,
            },
            BoundedInteger {
                name: "MobileFollowUpBytes".to_owned(),
                min: 1,
                max: 65_536,
            },
            BoundedInteger {
                name: "MobileProtocolVersion".to_owned(),
                min: i64::from(MIN_MOBILE_PROTOCOL_VERSION_VALUE),
                max: i64::from(MAX_MOBILE_PROTOCOL_VERSION_VALUE),
            },
            BoundedInteger {
                name: "MobileCredentialPageSize".to_owned(),
                min: 1,
                max: 100,
            },
        ],
        enums: vec![GeneratedEnum {
            name: "MobileAction".to_owned(),
            sensitivity: EnumSensitivity::SecuritySensitive,
            values: vec![
                "attach".to_owned(),
                "decide_approval".to_owned(),
                "follow_up".to_owned(),
                "stop_run".to_owned(),
            ],
            wire_order: None,
        }],
        json_surface: Some(mobile_auth_json_surface()),
        ..GeneratedModule::default()
    }
}

/// The shared platform identities and service descriptions.
fn platform_module() -> GeneratedModule {
    let security_enum = |name: &str, values: Vec<String>| GeneratedEnum {
        name: name.to_owned(),
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order: None,
    };
    GeneratedModule {
        file_name: module_file_name(PLATFORM_MODULE),
        doc: "Federated resource identity, freshness, cursor, action, receipt, and service types."
            .to_owned(),
        source: "automonique_protocol::platform".to_owned(),
        constants: vec![
            Constant {
                name: "MAX_CAPABILITY_METHODS".to_owned(),
                doc: "Maximum methods advertised by one endpoint.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_CAPABILITY_METHODS),
            },
            Constant {
                name: "MAX_CAPABILITY_TRANSPORTS".to_owned(),
                doc: "Maximum transport projections advertised by one endpoint.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_CAPABILITY_TRANSPORTS),
            },
            Constant {
                name: "MAX_SNAPSHOT_RESOURCES".to_owned(),
                doc: "Maximum resources carried by one snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_SNAPSHOT_RESOURCES),
            },
            Constant {
                name: "MAX_SUBSCRIPTION_EVENTS".to_owned(),
                doc: "Maximum ordered events carried by one subscription page.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_SUBSCRIPTION_EVENTS),
            },
            Constant {
                name: "MAX_SESSION_HISTORY_EVENTS".to_owned(),
                doc: "Maximum sanitized events carried by one history page.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_SESSION_HISTORY_EVENTS),
            },
            Constant {
                name: "MAX_SESSION_COMMAND_APPROVALS".to_owned(),
                doc: "Maximum pending approvals carried by one session command-state read."
                    .to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_SESSION_COMMAND_APPROVALS),
            },
            Constant {
                name: "CONTROL_LEASE_TTL_MILLIS".to_owned(),
                doc: "Lifetime of one exclusive interactive control lease.".to_owned(),
                value: ConstantValue::Count(
                    usize::try_from(crate::platform::CONTROL_LEASE_TTL_MILLIS)
                        .expect("positive control lease TTL"),
                ),
            },
            Constant {
                name: "MAX_PLATFORM_PARAMETER_BYTES".to_owned(),
                doc: "Largest free-form platform action parameter.".to_owned(),
                value: ConstantValue::Count(crate::platform::MAX_PLATFORM_PARAMETER_BYTES),
            },
            Constant {
                name: "MAX_PLATFORM_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical Platform response bytes.".to_owned(),
                value: ConstantValue::Count(crate::platform_api::MAX_PLATFORM_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_PLATFORM_REQUEST_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical Platform request bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_api::MAX_PLATFORM_REQUEST_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "PLATFORM_PROTOCOL".to_owned(),
                doc: "Stable platform protocol name.".to_owned(),
                value: ConstantValue::Text(crate::platform::PLATFORM_PROTOCOL.to_owned()),
            },
            Constant {
                name: "PLATFORM_SCHEMA_V1".to_owned(),
                doc: "Stable version-one schema identifier.".to_owned(),
                value: ConstantValue::Text(crate::platform::PLATFORM_SCHEMA_V1.to_owned()),
            },
        ],
        branded_ids: [
            "ClientId",
            "ControlLeaseId",
            "IdempotencyKey",
            "PlatformRequestId",
            "ReceiptId",
            "ResourceId",
        ]
        .into_iter()
        .map(|name| BrandedId {
            name: name.to_owned(),
            max_bytes: if name == "PlatformRequestId" {
                crate::codec::MAX_REQUEST_ID_BYTES
            } else {
                crate::platform::MAX_PLATFORM_FIELD_BYTES
            },
            pattern: Some(if name == "PlatformRequestId" {
                "^[A-Za-z0-9._:-]+$".to_owned()
            } else {
                NO_CONTROL_CHARACTERS.to_owned()
            }),
        })
        .collect(),
        bounded_strings: vec![
            BoundedString {
                name: "CursorTopic".to_owned(),
                max_bytes: crate::platform::MAX_PLATFORM_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "PlatformText".to_owned(),
                max_bytes: crate::platform::MAX_PLATFORM_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "PlatformParameter".to_owned(),
                max_bytes: crate::platform::MAX_PLATFORM_PARAMETER_BYTES,
                pattern: Some("^[^\\u0000]+$".to_owned()),
            },
            BoundedString {
                name: "SessionHistoryText".to_owned(),
                max_bytes: crate::platform::MAX_SESSION_HISTORY_TEXT_BYTES,
                pattern: Some("^[^\\u0000]+$".to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                name: "PlatformEpochMillis".to_owned(),
                min: i64::MIN,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "PlatformRevision".to_owned(),
                min: 1,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "SessionHistoryCursor".to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "SessionHistoryLimit".to_owned(),
                min: 1,
                max: i64::try_from(crate::platform::MAX_SESSION_HISTORY_EVENTS)
                    .expect("history limit"),
            },
        ],
        enums: vec![
            security_enum(
                "FreshnessState",
                platform_values(&FreshnessState::ALL, FreshnessState::as_str),
            ),
            security_enum(
                "PlatformAction",
                platform_values(&PlatformAction::ALL, PlatformAction::as_str),
            ),
            security_enum(
                "PlatformMethod",
                platform_values(&PlatformMethod::ALL, PlatformMethod::as_str),
            ),
            security_enum(
                "SessionApprovalDecision",
                platform_values(
                    &crate::platform::SessionApprovalDecision::ALL,
                    crate::platform::SessionApprovalDecision::as_str,
                ),
            ),
            security_enum(
                "PlatformTransport",
                platform_values(&PlatformTransport::ALL, PlatformTransport::as_str),
            ),
            security_enum(
                "ReceiptOutcome",
                platform_values(&ReceiptOutcome::ALL, ReceiptOutcome::as_str),
            ),
            security_enum(
                "ResourceAuthority",
                platform_values(&ResourceAuthority::ALL, ResourceAuthority::as_str),
            ),
            security_enum(
                "ResourceKind",
                platform_values(&ResourceKind::ALL, ResourceKind::as_str),
            ),
            security_enum(
                "SessionHistoryEvidence",
                platform_values(
                    &crate::platform::SessionHistoryEvidence::ALL,
                    crate::platform::SessionHistoryEvidence::as_str,
                ),
            ),
            security_enum(
                "SessionHistoryRole",
                platform_values(
                    &crate::platform::SessionHistoryRole::ALL,
                    crate::platform::SessionHistoryRole::as_str,
                ),
            ),
            security_enum(
                "SessionHistoryToolState",
                platform_values(
                    &crate::platform::SessionHistoryToolState::ALL,
                    crate::platform::SessionHistoryToolState::as_str,
                ),
            ),
            security_enum(
                "SessionHistoryRunState",
                platform_values(
                    &crate::platform::SessionHistoryRunState::ALL,
                    crate::platform::SessionHistoryRunState::as_str,
                ),
            ),
            security_enum(
                "SessionHistoryUnknownSource",
                platform_values(
                    &crate::platform::SessionHistoryUnknownSource::ALL,
                    crate::platform::SessionHistoryUnknownSource::as_str,
                ),
            ),
        ],
        interfaces: vec![
            Interface {
                name: "ActionReceipt".to_owned(),
                doc: "Durable result of one idempotent action.".to_owned(),
                fields: vec![
                    required("action", "PlatformAction"),
                    nullable("explanation", "PlatformText"),
                    required("id", "ReceiptId"),
                    required("outcome", "ReceiptOutcome"),
                    required("recorded_at", "PlatformEpochMillis"),
                    required("revision", "PlatformRevision"),
                    required("target", "ResourceCoordinate"),
                ],
            },
            Interface {
                name: "Capabilities".to_owned(),
                doc: "Methods and transport projections supported by an endpoint.".to_owned(),
                fields: vec![
                    required("methods", "readonly PlatformMethod[]"),
                    required("protocol", "typeof PLATFORM_PROTOCOL"),
                    required("schema", "typeof PLATFORM_SCHEMA_V1"),
                    required("transports", "readonly PlatformTransport[]"),
                ],
            },
            Interface {
                name: "ExecuteRequest".to_owned(),
                doc: "The only general mutation request in the public contract.".to_owned(),
                fields: vec![
                    required("action", "PlatformAction"),
                    nullable("client", "ClientId"),
                    nullable("expected_revision", "PlatformRevision"),
                    required("idempotency_key", "IdempotencyKey"),
                    nullable("parameter", "PlatformParameter"),
                    required("target", "ResourceCoordinate"),
                ],
            },
            Interface {
                name: "Freshness".to_owned(),
                doc: "Revision and observation time attached to a projection.".to_owned(),
                fields: vec![
                    required("observed_at", "PlatformEpochMillis"),
                    required("revision", "PlatformRevision"),
                    required("state", "FreshnessState"),
                ],
            },
            Interface {
                name: "PlatformCursor".to_owned(),
                doc: "Resume coordinate within one authority-owned topic.".to_owned(),
                fields: vec![
                    required("authority", "ResourceAuthority"),
                    required("sequence", "PlatformRevision"),
                    required("topic", "CursorTopic"),
                ],
            },
            Interface {
                name: "ResourceCoordinate".to_owned(),
                doc: "Authority-qualified resource identity.".to_owned(),
                fields: vec![
                    required("authority", "ResourceAuthority"),
                    required("id", "ResourceId"),
                    required("kind", "ResourceKind"),
                ],
            },
            Interface {
                name: "ResourceRecord".to_owned(),
                doc: "One bounded, freshness-qualified resource projection.".to_owned(),
                fields: vec![
                    required("freshness", "Freshness"),
                    required("resource", "ResourceCoordinate"),
                    required("summary", "PlatformText"),
                ],
            },
            Interface {
                name: "Snapshot".to_owned(),
                doc: "Bounded point-in-time resource collection and resume cursor.".to_owned(),
                fields: vec![
                    required("cursor", "PlatformCursor"),
                    required("resources", "readonly ResourceRecord[]"),
                ],
            },
            Interface {
                name: "PlatformEvent".to_owned(),
                doc: "One ordered resource change after a snapshot cursor.".to_owned(),
                fields: vec![
                    required("cursor", "PlatformCursor"),
                    required("resource", "ResourceRecord"),
                ],
            },
            Interface {
                name: "Subscription".to_owned(),
                doc: "One bounded, gap-free event page.".to_owned(),
                fields: vec![
                    required("cursor", "PlatformCursor"),
                    required("events", "readonly PlatformEvent[]"),
                ],
            },
            Interface {
                name: "SessionRecord".to_owned(),
                doc: "One attachable session and its optional owning run.".to_owned(),
                fields: vec![
                    required("attachable", "boolean"),
                    required("controllable", "boolean"),
                    nullable("run", "ResourceCoordinate"),
                    required("session", "ResourceRecord"),
                ],
            },
            Interface {
                name: "SessionList".to_owned(),
                doc: "One bounded session page and its resume cursor.".to_owned(),
                fields: vec![
                    required("cursor", "PlatformCursor"),
                    required("sessions", "readonly SessionRecord[]"),
                ],
            },
            Interface {
                name: "SessionCommandTarget".to_owned(),
                doc: "One session-owned command target and its exact revision.".to_owned(),
                fields: vec![
                    required("revision", "PlatformRevision"),
                    required("target", "ResourceCoordinate"),
                ],
            },
            Interface {
                name: "SessionCommandState".to_owned(),
                doc: "Minimal sanitized revision fences for session-bound commands.".to_owned(),
                fields: vec![
                    required("pending_approvals", "readonly SessionCommandTarget[]"),
                    nullable("run", "SessionCommandTarget"),
                    required("session", "ResourceRecord"),
                ],
            },
            Interface {
                name: "Attachment".to_owned(),
                doc: "Observation-only session attachment.".to_owned(),
                fields: vec![
                    required("client", "ClientId"),
                    required("cursor", "PlatformCursor"),
                    required("session", "ResourceCoordinate"),
                ],
            },
            Interface {
                name: "ControlLease".to_owned(),
                doc: "Short exclusive authority to steer one session.".to_owned(),
                fields: vec![
                    required("client", "ClientId"),
                    required("expires_at", "PlatformEpochMillis"),
                    required("id", "ControlLeaseId"),
                    required("revision", "PlatformRevision"),
                    required("session", "ResourceCoordinate"),
                ],
            },
        ],
        command_surface: Some(CommandSurface {
            name: "Platform".to_owned(),
            protocol_constant: "PLATFORM_PROTOCOL".to_owned(),
            protocol: crate::platform::PLATFORM_PROTOCOL.to_owned(),
            version: 1,
            max_message_bytes_constant: "MAX_PLATFORM_CANONICAL_BYTES".to_owned(),
            request_max_message_bytes_constant: Some(
                "MAX_PLATFORM_REQUEST_CANONICAL_BYTES".to_owned(),
            ),
            request_id_type: "PlatformRequestId".to_owned(),
            categories: vec![
                Constant {
                    name: PLATFORM_INVALID_BODY.to_owned(),
                    doc: "The response body is not the exact shape its kind defines.".to_owned(),
                    value: ConstantValue::Text("platform_invalid_body".to_owned()),
                },
                Constant {
                    name: PLATFORM_VALUE_INVALID.to_owned(),
                    doc: "A bounded Platform value or closed vocabulary was refused.".to_owned(),
                    value: ConstantValue::Text("platform_value_invalid".to_owned()),
                },
                Constant {
                    name: "PLATFORM_UNKNOWN_KIND".to_owned(),
                    doc: "The message kind is not defined by Platform v1.".to_owned(),
                    value: ConstantValue::Text("platform_unknown_kind".to_owned()),
                },
                Constant {
                    name: "PLATFORM_FRAME_TOO_LARGE".to_owned(),
                    doc: "The canonical response exceeds its transport ceiling.".to_owned(),
                    value: ConstantValue::Text("frame_too_large".to_owned()),
                },
                Constant {
                    name: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                    doc: "A request integer is outside the signed canonical wire range.".to_owned(),
                    value: ConstantValue::Text("platform_counter_out_of_range".to_owned()),
                },
                Constant {
                    name: "PLATFORM_FIELD_INVALID".to_owned(),
                    doc: "An envelope field violates its shared bounded-value rules.".to_owned(),
                    value: ConstantValue::Text("field_invalid".to_owned()),
                },
                Constant {
                    name: "PLATFORM_FIELD_GRAMMAR".to_owned(),
                    doc: "An envelope field violates its grammar.".to_owned(),
                    value: ConstantValue::Text("field_grammar".to_owned()),
                },
            ],
            invalid_body_category: PLATFORM_INVALID_BODY.to_owned(),
            unknown_kind_category: "PLATFORM_UNKNOWN_KIND".to_owned(),
            oversize_category: "PLATFORM_FRAME_TOO_LARGE".to_owned(),
            field_invalid_category: "PLATFORM_FIELD_INVALID".to_owned(),
            field_grammar_category: "PLATFORM_FIELD_GRAMMAR".to_owned(),
            discriminated_bodies: Vec::new(),
            body_objects: vec![
                platform_body_object(
                    "DecodedFreshness",
                    "Strictly decoded revision and observation time.",
                    vec![
                        platform_field("observed_at", platform_epoch_millis()),
                        platform_field("revision", platform_revision()),
                        platform_field("state", platform_enum("FreshnessState")),
                    ],
                ),
                platform_body_object(
                    "DecodedPlatformCursor",
                    "Strictly decoded resume coordinate.",
                    vec![
                        platform_field("authority", platform_enum("ResourceAuthority")),
                        platform_field("sequence", platform_revision()),
                        platform_field("topic", platform_checked("CursorTopic")),
                    ],
                ),
                platform_body_object(
                    "DecodedResourceCoordinate",
                    "Strictly decoded authority-qualified resource identity.",
                    vec![
                        platform_field("authority", platform_enum("ResourceAuthority")),
                        platform_field("id", platform_checked("ResourceId")),
                        platform_field("kind", platform_enum("ResourceKind")),
                    ],
                ),
                platform_body_object(
                    "DecodedResourceRecord",
                    "Strictly decoded bounded resource projection.",
                    vec![
                        platform_field("freshness", platform_object("DecodedFreshness")),
                        platform_field("resource", platform_object("DecodedResourceCoordinate")),
                        platform_field("summary", platform_checked("PlatformText")),
                    ],
                ),
                platform_body_object(
                    "DecodedPlatformEvent",
                    "Strictly decoded ordered resource change.",
                    vec![
                        platform_field("cursor", platform_object("DecodedPlatformCursor")),
                        platform_field("resource", platform_object("DecodedResourceRecord")),
                    ],
                ),
                platform_body_object(
                    "DecodedSessionRecord",
                    "Strictly decoded attachable session projection.",
                    vec![
                        platform_field("attachable", ResponseValue::Bool),
                        platform_field("controllable", ResponseValue::Bool),
                        platform_field(
                            "run",
                            ResponseValue::NullableObject {
                                type_name: "DecodedResourceCoordinate".to_owned(),
                            },
                        ),
                        platform_field("session", platform_object("DecodedResourceRecord")),
                    ],
                ),
                platform_body_object(
                    "DecodedSessionCommandTarget",
                    "Strictly decoded session-owned target and revision fence.",
                    vec![
                        platform_field("revision", platform_revision()),
                        platform_field("target", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_body_object(
                    "DecodedHistoryMessage",
                    "One sanitized authoritative message.",
                    vec![
                        platform_field("at", platform_epoch_millis()),
                        platform_field(
                            "cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field("evidence", platform_enum("SessionHistoryEvidence")),
                        platform_field("role", platform_enum("SessionHistoryRole")),
                        platform_field("text", platform_checked("SessionHistoryText")),
                        platform_field("truncated", ResponseValue::Bool),
                    ],
                ),
                platform_body_object(
                    "DecodedHistoryToolState",
                    "One sanitized public tool state without input or output.",
                    vec![
                        platform_field("at", platform_epoch_millis()),
                        platform_field(
                            "cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field("evidence", platform_enum("SessionHistoryEvidence")),
                        platform_field("label", platform_nullable_checked("SessionHistoryText")),
                        platform_field("state", platform_enum("SessionHistoryToolState")),
                        platform_field("truncated", ResponseValue::Bool),
                    ],
                ),
                platform_body_object(
                    "DecodedHistoryRunState",
                    "One closed public run state.",
                    vec![
                        platform_field("at", platform_epoch_millis()),
                        platform_field(
                            "cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field("state", platform_enum("SessionHistoryRunState")),
                    ],
                ),
                platform_body_object(
                    "DecodedHistoryUnknown",
                    "A forward-compatible source marker with no opaque payload.",
                    vec![
                        platform_field("at", platform_epoch_millis()),
                        platform_field(
                            "cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field("source", platform_enum("SessionHistoryUnknownSource")),
                    ],
                ),
            ],
            requests: vec![
                RequestCommand {
                    kind: "capabilities".to_owned(),
                    name: "PlatformCapabilities".to_owned(),
                    doc: "Read the exact Platform protocol, schema, methods, and transports."
                        .to_owned(),
                    fields: Vec::new(),
                    coupling: None,
                },
                RequestCommand {
                    kind: "snapshot".to_owned(),
                    name: "PlatformSnapshot".to_owned(),
                    doc: "Read one bounded point-in-time resource collection.".to_owned(),
                    fields: vec![RequestField {
                        name: "resources".to_owned(),
                        input_name: "resources".to_owned(),
                        value: RequestValue::ObjectArray {
                            type_name: "DecodedResourceCoordinate".to_owned(),
                            max_items_constant: "MAX_SNAPSHOT_RESOURCES".to_owned(),
                            oversize_category: PLATFORM_VALUE_INVALID.to_owned(),
                        },
                    }],
                    coupling: None,
                },
                RequestCommand {
                    kind: "subscribe".to_owned(),
                    name: "PlatformSubscribe".to_owned(),
                    doc: "Resume the bounded event stream from an optional cursor.".to_owned(),
                    fields: vec![RequestField {
                        name: "cursor".to_owned(),
                        input_name: "cursor".to_owned(),
                        value: RequestValue::NullableObject {
                            type_name: "DecodedPlatformCursor".to_owned(),
                        },
                    }],
                    coupling: None,
                },
                RequestCommand {
                    kind: "execute".to_owned(),
                    name: "PlatformExecute".to_owned(),
                    doc: "Request one authority-bound idempotent Platform action.".to_owned(),
                    fields: vec![
                        RequestField {
                            name: "client".to_owned(),
                            input_name: "client".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: "ClientId".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "action".to_owned(),
                            input_name: "action".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "PlatformAction".to_owned(),
                                unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "expected_revision".to_owned(),
                            input_name: "expected_revision".to_owned(),
                            value: RequestValue::NullableInteger {
                                type_name: "PlatformRevision".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "idempotency_key".to_owned(),
                            input_name: "idempotency_key".to_owned(),
                            value: RequestValue::Checked {
                                type_name: "IdempotencyKey".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "parameter".to_owned(),
                            input_name: "parameter".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: "PlatformParameter".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "target".to_owned(),
                            input_name: "target".to_owned(),
                            value: RequestValue::Object {
                                type_name: "DecodedResourceCoordinate".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "get_receipt".to_owned(),
                    name: "PlatformGetReceipt".to_owned(),
                    doc: "Read one receipt by exactly one durable coordinate.".to_owned(),
                    fields: vec![
                        RequestField {
                            name: "client".to_owned(),
                            input_name: "client".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: "ClientId".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "id".to_owned(),
                            input_name: "id".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: "ReceiptId".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "idempotency_key".to_owned(),
                            input_name: "idempotency_key".to_owned(),
                            value: RequestValue::NullableChecked {
                                type_name: "IdempotencyKey".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_command_state".to_owned(),
                    name: "PlatformSessionCommandState".to_owned(),
                    doc: "Read the bounded revision fences for one exact session.".to_owned(),
                    fields: vec![RequestField {
                        name: "session".to_owned(),
                        input_name: "session".to_owned(),
                        value: RequestValue::Object {
                            type_name: "DecodedResourceCoordinate".to_owned(),
                        },
                    }],
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_follow_up".to_owned(),
                    name: "PlatformSessionFollowUp".to_owned(),
                    doc: "Submit bounded follow-up text against one exact session revision."
                        .to_owned(),
                    fields: vec![
                        platform_request_checked("client", "ClientId"),
                        platform_request_integer("expected_session_revision", "PlatformRevision"),
                        platform_request_checked("idempotency_key", "IdempotencyKey"),
                        platform_request_object("session", "DecodedResourceCoordinate"),
                        platform_request_checked("text", "PlatformParameter"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_run_stop".to_owned(),
                    name: "PlatformSessionRunStop".to_owned(),
                    doc: "Stop the exact run owned by one exact fenced session.".to_owned(),
                    fields: vec![
                        platform_request_checked("client", "ClientId"),
                        platform_request_integer("expected_run_revision", "PlatformRevision"),
                        platform_request_integer("expected_session_revision", "PlatformRevision"),
                        platform_request_checked("idempotency_key", "IdempotencyKey"),
                        platform_request_object("run", "DecodedResourceCoordinate"),
                        platform_request_object("session", "DecodedResourceCoordinate"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_approval_decision".to_owned(),
                    name: "PlatformSessionApprovalDecision".to_owned(),
                    doc: "Decide an exact pending approval owned by one exact fenced session."
                        .to_owned(),
                    fields: vec![
                        platform_request_object("approval", "DecodedResourceCoordinate"),
                        platform_request_checked("client", "ClientId"),
                        RequestField {
                            name: "decision".to_owned(),
                            input_name: "decision".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "SessionApprovalDecision".to_owned(),
                                unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        platform_request_integer("expected_approval_revision", "PlatformRevision"),
                        platform_request_integer("expected_session_revision", "PlatformRevision"),
                        platform_request_checked("idempotency_key", "IdempotencyKey"),
                        platform_request_object("session", "DecodedResourceCoordinate"),
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "list_sessions".to_owned(),
                    name: "PlatformListSessions".to_owned(),
                    doc: "Read one bounded page of attachable sessions.".to_owned(),
                    fields: vec![
                        RequestField {
                            name: "authority".to_owned(),
                            input_name: "authority".to_owned(),
                            value: RequestValue::Enum {
                                type_name: "ResourceAuthority".to_owned(),
                                unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        },
                        RequestField {
                            name: "cursor".to_owned(),
                            input_name: "cursor".to_owned(),
                            value: RequestValue::NullableObject {
                                type_name: "DecodedPlatformCursor".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "attach".to_owned(),
                    name: "PlatformAttach".to_owned(),
                    doc: "Attach one client as an observer of one exact session.".to_owned(),
                    fields: platform_client_session_fields(),
                    coupling: None,
                },
                RequestCommand {
                    kind: "detach".to_owned(),
                    name: "PlatformDetach".to_owned(),
                    doc: "Detach one client from one exact session.".to_owned(),
                    fields: platform_client_session_fields(),
                    coupling: None,
                },
                RequestCommand {
                    kind: "claim_control".to_owned(),
                    name: "PlatformClaimControl".to_owned(),
                    doc: "Claim short exclusive control over one exact session.".to_owned(),
                    fields: {
                        let mut fields = platform_client_session_fields();
                        fields.push(RequestField {
                            name: "idempotency_key".to_owned(),
                            input_name: "idempotency_key".to_owned(),
                            value: RequestValue::Checked {
                                type_name: "IdempotencyKey".to_owned(),
                                refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        });
                        fields
                    },
                    coupling: None,
                },
                RequestCommand {
                    kind: "release_control".to_owned(),
                    name: "PlatformReleaseControl".to_owned(),
                    doc: "Release one exact control lease under an idempotency key.".to_owned(),
                    fields: {
                        let mut fields = platform_client_session_fields();
                        fields.extend([
                            RequestField {
                                name: "idempotency_key".to_owned(),
                                input_name: "idempotency_key".to_owned(),
                                value: RequestValue::Checked {
                                    type_name: "IdempotencyKey".to_owned(),
                                    refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                                },
                            },
                            RequestField {
                                name: "lease".to_owned(),
                                input_name: "lease".to_owned(),
                                value: RequestValue::Checked {
                                    type_name: "ControlLeaseId".to_owned(),
                                    refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                                },
                            },
                        ]);
                        fields
                    },
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_history_snapshot".to_owned(),
                    name: "PlatformSessionHistorySnapshot".to_owned(),
                    doc: "Read the first retained history page for one exact session.".to_owned(),
                    fields: vec![
                        RequestField {
                            name: "limit".to_owned(),
                            input_name: "limit".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "SessionHistoryLimit".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "session".to_owned(),
                            input_name: "session".to_owned(),
                            value: RequestValue::Object {
                                type_name: "DecodedResourceCoordinate".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
                RequestCommand {
                    kind: "session_history_page".to_owned(),
                    name: "PlatformSessionHistoryPage".to_owned(),
                    doc: "Resume history strictly after an exclusive cursor.".to_owned(),
                    fields: vec![
                        RequestField {
                            name: "after".to_owned(),
                            input_name: "after".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "limit".to_owned(),
                            input_name: "limit".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "SessionHistoryLimit".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "session".to_owned(),
                            input_name: "session".to_owned(),
                            value: RequestValue::Object {
                                type_name: "DecodedResourceCoordinate".to_owned(),
                            },
                        },
                    ],
                    coupling: None,
                },
            ],
            request_kinds_not_generated: Vec::new(),
            request_validations: vec![
                (
                    "execute".to_owned(),
                    RequestValidation::ActionAuthority {
                        action_field: "action".to_owned(),
                        target_field: "target".to_owned(),
                        action_authorities: PlatformAction::ALL
                            .into_iter()
                            .map(|action| {
                                (
                                    action.as_str().to_owned(),
                                    action.authority().as_str().to_owned(),
                                )
                            })
                            .collect(),
                        refusal_category: PLATFORM_VALUE_INVALID.to_owned(),
                    },
                ),
                (
                    "get_receipt".to_owned(),
                    RequestValidation::ExactlyOneNonNull {
                        left: "id".to_owned(),
                        right: "idempotency_key".to_owned(),
                        refusal_category: PLATFORM_INVALID_BODY.to_owned(),
                    },
                ),
                platform_exact_coordinate_validation("session_command_state", "session", "session"),
                platform_exact_coordinate_validation("session_follow_up", "session", "session"),
                platform_exact_coordinate_validation("session_run_stop", "session", "session"),
                platform_exact_coordinate_validation("session_run_stop", "run", "run"),
                platform_exact_coordinate_validation(
                    "session_approval_decision",
                    "session",
                    "session",
                ),
                platform_exact_coordinate_validation(
                    "session_approval_decision",
                    "approval",
                    "approval",
                ),
            ],
            request_response_kinds: vec![
                ("capabilities".to_owned(), "capabilities_result".to_owned()),
                ("snapshot".to_owned(), "snapshot_result".to_owned()),
                ("subscribe".to_owned(), "subscription_result".to_owned()),
                ("execute".to_owned(), "receipt_result".to_owned()),
                ("get_receipt".to_owned(), "receipt_result".to_owned()),
                (
                    "session_command_state".to_owned(),
                    "session_command_state_result".to_owned(),
                ),
                ("session_follow_up".to_owned(), "receipt_result".to_owned()),
                ("session_run_stop".to_owned(), "receipt_result".to_owned()),
                (
                    "session_approval_decision".to_owned(),
                    "receipt_result".to_owned(),
                ),
                ("list_sessions".to_owned(), "sessions_result".to_owned()),
                ("attach".to_owned(), "attached".to_owned()),
                ("detach".to_owned(), "detached".to_owned()),
                ("claim_control".to_owned(), "control_claimed".to_owned()),
                ("release_control".to_owned(), "control_released".to_owned()),
                (
                    "session_history_snapshot".to_owned(),
                    "session_history_result".to_owned(),
                ),
                (
                    "session_history_page".to_owned(),
                    "session_history_result".to_owned(),
                ),
            ],
            responses: vec![
                platform_response(
                    "capabilities_result",
                    "PlatformCapabilitiesResult",
                    "Capabilities returned by the admitted Platform v1 peer.",
                    vec![
                        platform_field(
                            "methods",
                            ResponseValue::EnumArray {
                                type_name: "PlatformMethod".to_owned(),
                                max_items_constant: "MAX_CAPABILITY_METHODS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                                unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        ),
                        platform_field(
                            "protocol",
                            ResponseValue::ExactString {
                                type_name: "typeof PLATFORM_PROTOCOL".to_owned(),
                                expected_constant: "PLATFORM_PROTOCOL".to_owned(),
                                mismatch_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field(
                            "schema",
                            ResponseValue::ExactString {
                                type_name: "typeof PLATFORM_SCHEMA_V1".to_owned(),
                                expected_constant: "PLATFORM_SCHEMA_V1".to_owned(),
                                mismatch_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field(
                            "transports",
                            ResponseValue::EnumArray {
                                type_name: "PlatformTransport".to_owned(),
                                max_items_constant: "MAX_CAPABILITY_TRANSPORTS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                                unknown_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        ),
                    ],
                ),
                platform_response(
                    "snapshot_result",
                    "PlatformSnapshotResult",
                    "A bounded point-in-time Platform resource collection.",
                    vec![
                        platform_field("cursor", platform_object("DecodedPlatformCursor")),
                        platform_field(
                            "resources",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedResourceRecord".to_owned(),
                                max_items_constant: "MAX_SNAPSHOT_RESOURCES".to_owned(),
                                oversize_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        ),
                    ],
                ),
                platform_response(
                    "subscription_result",
                    "PlatformSubscriptionResult",
                    "A bounded, gap-free Platform event page.",
                    vec![
                        platform_field("cursor", platform_object("DecodedPlatformCursor")),
                        platform_field(
                            "events",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedPlatformEvent".to_owned(),
                                max_items_constant: "MAX_SUBSCRIPTION_EVENTS".to_owned(),
                                oversize_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        ),
                    ],
                ),
                platform_response(
                    "receipt_result",
                    "PlatformReceiptResult",
                    "A durable idempotent-action receipt.",
                    vec![
                        platform_field("action", platform_enum("PlatformAction")),
                        platform_field("explanation", platform_nullable_checked("PlatformText")),
                        platform_field("id", platform_checked("ReceiptId")),
                        platform_field("outcome", platform_enum("ReceiptOutcome")),
                        platform_field("recorded_at", platform_epoch_millis()),
                        platform_field("revision", platform_revision()),
                        platform_field("target", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_response(
                    "sessions_result",
                    "PlatformSessionsResult",
                    "One bounded attachable-session page.",
                    vec![
                        platform_field("cursor", platform_object("DecodedPlatformCursor")),
                        platform_field(
                            "sessions",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedSessionRecord".to_owned(),
                                max_items_constant: "MAX_SNAPSHOT_RESOURCES".to_owned(),
                                oversize_category: PLATFORM_VALUE_INVALID.to_owned(),
                            },
                        ),
                    ],
                ),
                platform_response(
                    "session_command_state_result",
                    "PlatformSessionCommandStateResult",
                    "Minimal sanitized revision fences for session-bound commands.",
                    vec![
                        platform_field(
                            "pending_approvals",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedSessionCommandTarget".to_owned(),
                                max_items_constant: "MAX_SESSION_COMMAND_APPROVALS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field(
                            "run",
                            ResponseValue::NullableObject {
                                type_name: "DecodedSessionCommandTarget".to_owned(),
                            },
                        ),
                        platform_field("session", platform_object("DecodedResourceRecord")),
                    ],
                ),
                platform_response(
                    "attached",
                    "PlatformAttachedResult",
                    "An observation-only session attachment.",
                    vec![
                        platform_field("client", platform_checked("ClientId")),
                        platform_field("cursor", platform_object("DecodedPlatformCursor")),
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_response(
                    "detached",
                    "PlatformDetachedResult",
                    "A completed observation-only session detachment.",
                    vec![
                        platform_field("client", platform_checked("ClientId")),
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_response(
                    "control_claimed",
                    "PlatformControlClaimedResult",
                    "A short exclusive interactive control lease.",
                    vec![
                        platform_field("client", platform_checked("ClientId")),
                        platform_field("expires_at", platform_epoch_millis()),
                        platform_field("id", platform_checked("ControlLeaseId")),
                        platform_field("revision", platform_revision()),
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_response(
                    "control_released",
                    "PlatformControlReleasedResult",
                    "A completed release of an exact control lease.",
                    vec![
                        platform_field("client", platform_checked("ClientId")),
                        platform_field("lease", platform_checked("ControlLeaseId")),
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                    ],
                ),
                platform_response(
                    "session_history_result",
                    "PlatformSessionHistoryResult",
                    "One strict, exclusive-cursor history page.",
                    vec![
                        platform_field(
                            "applied_limit",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryLimit".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field(
                            "from_cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field("has_more", ResponseValue::Bool),
                        platform_field(
                            "messages",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedHistoryMessage".to_owned(),
                                max_items_constant: "MAX_SESSION_HISTORY_EVENTS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field(
                            "requested_limit",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryLimit".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field(
                            "run_states",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedHistoryRunState".to_owned(),
                                max_items_constant: "MAX_SESSION_HISTORY_EVENTS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                        platform_field(
                            "terminal_cursor",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field(
                            "tool_states",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedHistoryToolState".to_owned(),
                                max_items_constant: "MAX_SESSION_HISTORY_EVENTS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                        platform_field(
                            "unknown_events",
                            ResponseValue::ObjectArray {
                                type_name: "DecodedHistoryUnknown".to_owned(),
                                max_items_constant: "MAX_SESSION_HISTORY_EVENTS".to_owned(),
                                oversize_category: PLATFORM_INVALID_BODY.to_owned(),
                            },
                        ),
                    ],
                ),
                platform_response(
                    "session_history_resync",
                    "PlatformSessionHistoryResync",
                    "Explicit retention refusal with no partial page.",
                    vec![
                        platform_field("session", platform_object("DecodedResourceCoordinate")),
                        platform_field(
                            "snapshot_from",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                        platform_field(
                            "snapshot_to",
                            ResponseValue::Integer {
                                type_name: "SessionHistoryCursor".to_owned(),
                                refusal_category: "PLATFORM_COUNTER_OUT_OF_RANGE".to_owned(),
                                unsigned: true,
                            },
                        ),
                    ],
                ),
                platform_response(
                    "refused",
                    "PlatformRefusedResult",
                    "A typed Platform refusal that never implies success.",
                    vec![
                        platform_field("explanation", platform_checked("PlatformText")),
                        platform_field("outcome", platform_enum("ReceiptOutcome")),
                    ],
                ),
            ],
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

/// Platform v2 work-context identities and bounded query/page types.
fn work_context_module() -> GeneratedModule {
    let security_enum = |name: &str, values: Vec<String>| GeneratedEnum {
        name: name.to_owned(),
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order: None,
    };
    GeneratedModule {
        file_name: module_file_name(WORK_CONTEXT_MODULE),
        doc: "Negotiated Platform v2 project, host, checkout, workspace, session, and pane types."
            .to_owned(),
        source: "automonique_protocol::platform_v2".to_owned(),
        constants: vec![
            Constant {
                name: "MAX_PLATFORM_VERSION_OFFERS".to_owned(),
                doc: "Maximum advertised Platform protocol versions.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2::MAX_PLATFORM_VERSION_OFFERS),
            },
            Constant {
                name: "MAX_WORK_CONTEXT_PAGE_ITEMS".to_owned(),
                doc: "Maximum records returned by one filtered page.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2::MAX_WORK_CONTEXT_PAGE_ITEMS),
            },
            Constant {
                name: "MAX_WORK_CONTEXT_RELATIONS".to_owned(),
                doc: "Maximum structured relations carried by one record.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2::MAX_WORK_CONTEXT_RELATIONS),
            },
            Constant {
                name: "MAX_LINEAGE_RECORDS".to_owned(),
                doc: "Maximum lineage records carried by one bounded projection.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_lineage::MAX_LINEAGE_RECORDS,
                ),
            },
            Constant {
                name: "MIN_PLATFORM_VERSION".to_owned(),
                doc: "Lowest Platform major version this contract negotiates.".to_owned(),
                value: ConstantValue::Count(usize::from(crate::platform_v2::MIN_PLATFORM_VERSION)),
            },
            Constant {
                name: "MAX_PLATFORM_VERSION".to_owned(),
                doc: "Highest Platform major version this contract negotiates.".to_owned(),
                value: ConstantValue::Count(usize::from(crate::platform_v2::MAX_PLATFORM_VERSION)),
            },
            Constant {
                name: "MAX_PLATFORM_VERSION_NUMBER".to_owned(),
                doc: "Largest future Platform major admitted in a bounded offer.".to_owned(),
                value: ConstantValue::Count(usize::from(
                    crate::platform_v2::MAX_PLATFORM_VERSION_NUMBER,
                )),
            },
            Constant {
                name: "PLATFORM_SCHEMA_V2".to_owned(),
                doc: "Stable version-two work-context schema identifier.".to_owned(),
                value: ConstantValue::Text(crate::platform_v2::PLATFORM_SCHEMA_V2.to_owned()),
            },
            Constant {
                name: "PLATFORM_NEGOTIATION_SCHEMA_V1".to_owned(),
                doc: "Stable version-negotiation document schema identifier.".to_owned(),
                value: ConstantValue::Text(
                    crate::platform_v2_api::PLATFORM_NEGOTIATION_SCHEMA_V1.to_owned(),
                ),
            },
            Constant {
                name: "MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical version-negotiation document bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_api::MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical work-context query bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_api::MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical work-context page bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_api::MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "WORK_CONTEXT_KIND_WIRE_ORDER".to_owned(),
                doc: "Canonical work-context kind set order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &WorkContextKind::ALL,
                    WorkContextKind::as_str,
                )),
            },
            Constant {
                name: "WORK_CONTEXT_LIFECYCLE_WIRE_ORDER".to_owned(),
                doc: "Canonical lifecycle filter order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &WorkContextLifecycle::ALL,
                    WorkContextLifecycle::as_str,
                )),
            },
            Constant {
                name: "WORK_CONTEXT_RELATION_KIND_WIRE_ORDER".to_owned(),
                doc: "Canonical structured relation order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &WorkContextRelationKind::ALL,
                    WorkContextRelationKind::as_str,
                )),
            },
            Constant {
                name: "WORK_CONTEXT_TARGET_KIND_WIRE_ORDER".to_owned(),
                doc: "Canonical relation target identity order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &WorkContextTargetKind::ALL,
                    WorkContextTargetKind::as_str,
                )),
            },
            Constant {
                name: "V1_RESOURCE_AUTHORITY_WIRE_ORDER".to_owned(),
                doc: "Platform v1 resource-authority declaration order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &ResourceAuthority::ALL,
                    ResourceAuthority::as_str,
                )),
            },
            Constant {
                name: "V1_RESOURCE_KIND_WIRE_ORDER".to_owned(),
                doc: "Platform v1 resource-kind declaration order.".to_owned(),
                value: ConstantValue::Words(platform_values(
                    &ResourceKind::ALL,
                    ResourceKind::as_str,
                )),
            },
        ],
        branded_ids: [
            "AttemptWorkspaceId",
            "BaseSelectorId",
            "BranchSelectorId",
            "CheckoutId",
            "ExternalWorkKey",
            "ExternalWorkAuthorityId",
            "ExternalWorkScope",
            "HostSetupId",
            "OrchestrationDecisionGateId",
            "OrchestrationDispatchId",
            "OrchestrationHeartbeatId",
            "OrchestrationQuestionId",
            "OrchestrationRunId",
            "OrchestrationTaskId",
            "OrchestrationWorkerId",
            "PaneId",
            "ProjectId",
            "UserWorkspaceId",
            "WorkContextCursor",
            "WorkSessionId",
            "WorkspaceIntentId",
        ]
        .into_iter()
        .map(|name| BrandedId {
            name: name.to_owned(),
            max_bytes: if matches!(
                name,
                "AttemptWorkspaceId"
                    | "CheckoutId"
                    | "HostSetupId"
                    | "PaneId"
                    | "ProjectId"
                    | "UserWorkspaceId"
                    | "WorkContextCursor"
                    | "WorkSessionId"
            ) {
                crate::platform_v2::MAX_WORK_CONTEXT_FIELD_BYTES
            } else {
                crate::platform_v2_lineage::MAX_LINEAGE_FIELD_BYTES
            },
            pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
        })
        .collect(),
        bounded_strings: vec![
            BoundedString {
                name: "LineageMessage".to_owned(),
                max_bytes: crate::platform_v2_lineage::MAX_LINEAGE_MESSAGE_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "WorkContextLabel".to_owned(),
                max_bytes: crate::platform_v2::MAX_WORK_CONTEXT_LABEL_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                name: "LineageStaleAfterMs".to_owned(),
                min: 1,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "LineageObservedAtMs".to_owned(),
                min: 1,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "PlatformVersionNumber".to_owned(),
                min: i64::from(crate::platform_v2::MIN_PLATFORM_VERSION),
                max: i64::from(crate::platform_v2::MAX_PLATFORM_VERSION_NUMBER),
            },
            BoundedInteger {
                name: "SupportedPlatformVersionNumber".to_owned(),
                min: i64::from(crate::platform_v2::MIN_PLATFORM_VERSION),
                max: i64::from(crate::platform_v2::MAX_PLATFORM_VERSION),
            },
            BoundedInteger {
                name: "WorkContextPageLimit".to_owned(),
                min: 1,
                max: i64::try_from(crate::platform_v2::MAX_WORK_CONTEXT_PAGE_ITEMS)
                    .expect("work-context page limit"),
            },
            BoundedInteger {
                name: "WorkContextRevision".to_owned(),
                min: 1,
                max: i64::MAX,
            },
        ],
        enums: vec![
            security_enum(
                "CheckoutKind",
                platform_values(&CheckoutKind::ALL, CheckoutKind::as_str),
            ),
            security_enum(
                "ExternalWorkProvider",
                platform_values(&ExternalWorkProvider::ALL, ExternalWorkProvider::as_str),
            ),
            security_enum(
                "ExternalWorkState",
                platform_values(&ExternalWorkState::ALL, ExternalWorkState::as_str),
            ),
            security_enum(
                "HostSetupKind",
                platform_values(&HostSetupKind::ALL, HostSetupKind::as_str),
            ),
            security_enum(
                "LineageFreshnessState",
                platform_values(
                    &LineageFreshnessState::ALL,
                    LineageFreshnessState::as_str,
                ),
            ),
            security_enum(
                "OrchestrationKind",
                platform_values(&OrchestrationKind::ALL, OrchestrationKind::as_str),
            ),
            security_enum(
                "WorkContextKind",
                platform_values(&WorkContextKind::ALL, WorkContextKind::as_str),
            ),
            security_enum(
                "WorkContextAvailability",
                platform_values(
                    &WorkContextAvailability::ALL,
                    WorkContextAvailability::as_str,
                ),
            ),
            security_enum(
                "WorkContextLifecycle",
                platform_values(&WorkContextLifecycle::ALL, WorkContextLifecycle::as_str),
            ),
            security_enum(
                "WorkContextRelationKind",
                platform_values(
                    &WorkContextRelationKind::ALL,
                    WorkContextRelationKind::as_str,
                ),
            ),
            security_enum(
                "WorkContextTargetKind",
                platform_values(&WorkContextTargetKind::ALL, WorkContextTargetKind::as_str),
            ),
            security_enum(
                "WorkspaceIntentConflict",
                platform_values(
                    &WorkspaceIntentConflict::ALL,
                    WorkspaceIntentConflict::as_str,
                ),
            ),
        ],
        unions: vec![
            Union {
                name: "LineageStatus".to_owned(),
                discriminant: "kind".to_owned(),
                variants: vec![
                    UnionVariant { tag: "blocked".to_owned(), payload: Some(("reason".to_owned(), "LineageMessage".to_owned())) },
                    UnionVariant { tag: "done".to_owned(), payload: Some(("outcome".to_owned(), "LineageMessage".to_owned())) },
                    UnionVariant { tag: "waiting".to_owned(), payload: Some(("reason".to_owned(), "LineageMessage".to_owned())) },
                    UnionVariant { tag: "working".to_owned(), payload: None },
                ],
            },
            Union {
                name: "OrchestrationIdentity".to_owned(),
                discriminant: "kind".to_owned(),
                variants: vec![
                    UnionVariant { tag: "decision_gate".to_owned(), payload: Some(("id".to_owned(), "OrchestrationDecisionGateId".to_owned())) },
                    UnionVariant { tag: "dispatch".to_owned(), payload: Some(("id".to_owned(), "OrchestrationDispatchId".to_owned())) },
                    UnionVariant { tag: "heartbeat".to_owned(), payload: Some(("id".to_owned(), "OrchestrationHeartbeatId".to_owned())) },
                    UnionVariant { tag: "question".to_owned(), payload: Some(("id".to_owned(), "OrchestrationQuestionId".to_owned())) },
                    UnionVariant { tag: "run".to_owned(), payload: Some(("id".to_owned(), "OrchestrationRunId".to_owned())) },
                    UnionVariant { tag: "task".to_owned(), payload: Some(("id".to_owned(), "OrchestrationTaskId".to_owned())) },
                    UnionVariant { tag: "worker".to_owned(), payload: Some(("id".to_owned(), "OrchestrationWorkerId".to_owned())) },
                ],
            },
            Union {
                name: "WorkspaceIntent".to_owned(),
                discriminant: "kind".to_owned(),
                variants: vec![
                    UnionVariant { tag: "create".to_owned(), payload: Some(("request".to_owned(), "WorkspaceCreateIntent".to_owned())) },
                    UnionVariant { tag: "resume".to_owned(), payload: Some(("request".to_owned(), "WorkspaceResumeIntent".to_owned())) },
                ],
            },
            Union {
                name: "WorkspaceIntentOutcome".to_owned(),
                discriminant: "kind".to_owned(),
                variants: vec![
                    UnionVariant { tag: "accepted".to_owned(), payload: None },
                    UnionVariant { tag: "conflict".to_owned(), payload: Some(("conflict".to_owned(), "WorkspaceIntentConflict".to_owned())) },
                    UnionVariant { tag: "created".to_owned(), payload: Some(("workspace".to_owned(), "UserWorkspaceId".to_owned())) },
                    UnionVariant { tag: "resumed".to_owned(), payload: Some(("workspace".to_owned(), "UserWorkspaceId".to_owned())) },
                    UnionVariant { tag: "unknown".to_owned(), payload: None },
                ],
            },
            Union {
                name: "WorkContextIdentity".to_owned(),
                discriminant: "kind".to_owned(),
                variants: vec![
                UnionVariant {
                    tag: "attempt_workspace".to_owned(),
                    payload: Some(("id".to_owned(), "AttemptWorkspaceId".to_owned())),
                },
                UnionVariant {
                    tag: "checkout".to_owned(),
                    payload: Some(("id".to_owned(), "CheckoutId".to_owned())),
                },
                UnionVariant {
                    tag: "host_setup".to_owned(),
                    payload: Some(("id".to_owned(), "HostSetupId".to_owned())),
                },
                UnionVariant {
                    tag: "pane".to_owned(),
                    payload: Some(("id".to_owned(), "PaneId".to_owned())),
                },
                UnionVariant {
                    tag: "platform_session".to_owned(),
                    payload: Some(("resource".to_owned(), "ResourceCoordinate".to_owned())),
                },
                UnionVariant {
                    tag: "project".to_owned(),
                    payload: Some(("id".to_owned(), "ProjectId".to_owned())),
                },
                UnionVariant {
                    tag: "repository".to_owned(),
                    payload: Some(("resource".to_owned(), "ResourceCoordinate".to_owned())),
                },
                UnionVariant {
                    tag: "session".to_owned(),
                    payload: Some(("id".to_owned(), "WorkSessionId".to_owned())),
                },
                UnionVariant {
                    tag: "user_workspace".to_owned(),
                    payload: Some(("id".to_owned(), "UserWorkspaceId".to_owned())),
                },
                ],
            },
        ],
        interfaces: vec![
            Interface {
                name: "ExternalWorkIdentity".to_owned(),
                doc: "Provider-qualified external identity; provider, scope, and key are one indivisible identity.".to_owned(),
                fields: vec![
                    required("authority", "ExternalWorkAuthorityId"),
                    required("key", "ExternalWorkKey"),
                    required("provider", "ExternalWorkProvider"),
                    required("scope", "ExternalWorkScope"),
                ],
            },
            Interface {
                name: "ExternalWorkItem".to_owned(),
                doc: "External work projection bound to, but never identified as, a user workspace.".to_owned(),
                fields: vec![
                    required("freshness", "LineageFreshness"),
                    required("identity", "ExternalWorkIdentity"),
                    nullable("latest_useful_message", "LatestUsefulMessage"),
                    nullable("moved_to", "ExternalWorkIdentity"),
                    required("origin", "LineageOrigin"),
                    required("revision", "WorkContextRevision"),
                    required("state", "ExternalWorkState"),
                    required("workspace", "UserWorkspaceId"),
                ],
            },
            Interface {
                name: "LatestUsefulMessage".to_owned(),
                doc: "Latest bounded operator-useful text, separate from identity and authority.".to_owned(),
                fields: vec![required("observed_at_ms", "LineageObservedAtMs"), required("text", "LineageMessage")],
            },
            Interface {
                name: "LineageFreshness".to_owned(),
                doc: "Explicit source observation and staleness declaration; clients do not infer freshness from status.".to_owned(),
                fields: vec![
                    required("observed_at_ms", "LineageObservedAtMs"),
                    required("stale_after_ms", "LineageStaleAfterMs"),
                    required("state", "LineageFreshnessState"),
                ],
            },
            Interface {
                name: "LineageOrigin".to_owned(),
                doc: "Exact path-free origin coordinate for attention jumps.".to_owned(),
                fields: vec![
                    nullable("attempt", "AttemptWorkspaceId"),
                    nullable("pane", "PaneId"),
                    nullable("session", "WorkSessionId"),
                    required("workspace", "UserWorkspaceId"),
                ],
            },
            Interface {
                name: "LineageProjection".to_owned(),
                doc: "Bounded records for one exact user workspace; identities remain in separate domains.".to_owned(),
                fields: vec![
                    required("external_work_items", "readonly ExternalWorkItem[]"),
                    required("orchestration", "readonly OrchestrationRecord[]"),
                    required("schema", "typeof PLATFORM_SCHEMA_V2"),
                    required("workspace", "UserWorkspaceId"),
                ],
            },
            Interface {
                name: "NegotiatedPlatform".to_owned(),
                doc: "Highest shared Platform version and truthful work-context availability."
                    .to_owned(),
                fields: vec![
                    required(
                        "schema",
                        "typeof PLATFORM_SCHEMA_V1 | typeof PLATFORM_SCHEMA_V2",
                    ),
                    required("version", "SupportedPlatformVersionNumber"),
                    required("work_context", "WorkContextAvailability"),
                ],
            },
            Interface {
                name: "PlatformVersionOffer".to_owned(),
                doc: "Bounded set of Platform versions supported by one peer.".to_owned(),
                fields: vec![
                    required("schema", "typeof PLATFORM_NEGOTIATION_SCHEMA_V1"),
                    required("versions", "readonly PlatformVersionNumber[]"),
                ],
            },
            Interface {
                name: "OrchestrationRecord".to_owned(),
                doc: "Internal lineage node with a typed parent and explicit workspace binding.".to_owned(),
                fields: vec![
                    nullable("external_work", "ExternalWorkIdentity"),
                    required("freshness", "LineageFreshness"),
                    required("identity", "OrchestrationIdentity"),
                    nullable("latest_useful_message", "LatestUsefulMessage"),
                    required("origin", "LineageOrigin"),
                    nullable("parent", "OrchestrationIdentity"),
                    required("revision", "WorkContextRevision"),
                    required("status", "LineageStatus"),
                    required("workspace", "UserWorkspaceId"),
                ],
            },
            Interface {
                name: "WorkContextAttributes".to_owned(),
                doc: "Kind-specific host or checkout classification; never a host path.".to_owned(),
                fields: vec![
                    nullable("checkout", "CheckoutKind"),
                    nullable("host_setup", "HostSetupKind"),
                ],
            },
            Interface {
                name: "WorkContextRelation".to_owned(),
                doc: "One bounded typed graph edge; identity is never parsed from summary text."
                    .to_owned(),
                fields: vec![
                    required("kind", "WorkContextRelationKind"),
                    required("target", "WorkContextIdentity"),
                ],
            },
            Interface {
                name: "WorkContextRecord".to_owned(),
                doc: "One revisioned work-context node with bounded structured relations."
                    .to_owned(),
                fields: vec![
                    required("attributes", "WorkContextAttributes"),
                    required("identity", "WorkContextIdentity"),
                    required("label", "WorkContextLabel"),
                    required("lifecycle", "WorkContextLifecycle"),
                    required("relations", "readonly WorkContextRelation[]"),
                    required("revision", "WorkContextRevision"),
                ],
            },
            Interface {
                name: "WorkContextQuery".to_owned(),
                doc: "Filtered cursor query bounded independently of total inventory.".to_owned(),
                fields: vec![
                    nullable("after", "WorkContextCursor"),
                    required("kinds", "readonly WorkContextKind[]"),
                    required("lifecycles", "readonly WorkContextLifecycle[]"),
                    required("limit", "WorkContextPageLimit"),
                    nullable("parent", "WorkContextIdentity"),
                    nullable("project", "ProjectId"),
                    required("schema", "typeof PLATFORM_SCHEMA_V2"),
                ],
            },
            Interface {
                name: "WorkContextPage".to_owned(),
                doc: "One bounded page; next_cursor is present exactly when more records exist."
                    .to_owned(),
                fields: vec![
                    nullable("after", "WorkContextCursor"),
                    required("has_more", "boolean"),
                    required("items", "readonly WorkContextRecord[]"),
                    nullable("next_cursor", "WorkContextCursor"),
                    required("requested_limit", "WorkContextPageLimit"),
                    required("schema", "typeof PLATFORM_SCHEMA_V2"),
                ],
            },
            Interface {
                name: "WorkContextResync".to_owned(),
                doc: "Explicit replacement outcome for an expired or filter-mismatched cursor."
                    .to_owned(),
                fields: vec![
                    required("expired_after", "WorkContextCursor"),
                    required("outcome", "\"resync_required\""),
                    required("schema", "typeof PLATFORM_SCHEMA_V2"),
                ],
            },
            Interface {
                name: "WorkspaceCreateIntent".to_owned(),
                doc: "Create intent using opaque registry selectors rather than host paths or branch names.".to_owned(),
                fields: vec![
                    required("base_selector", "BaseSelectorId"),
                    required("branch_selector", "BranchSelectorId"),
                    required("external_work", "ExternalWorkIdentity"),
                    required("intent_id", "WorkspaceIntentId"),
                    required("task", "OrchestrationTaskId"),
                ],
            },
            Interface {
                name: "WorkspaceResumeIntent".to_owned(),
                doc: "Resume intent fenced by exact workspace revision.".to_owned(),
                fields: vec![
                    required("expected_revision", "WorkContextRevision"),
                    required("intent_id", "WorkspaceIntentId"),
                    required("task", "OrchestrationTaskId"),
                    required("workspace", "UserWorkspaceId"),
                ],
            },
        ],
        imports: vec![ModuleImport {
            module: PLATFORM_MODULE.to_owned(),
            values: vec![
                "IdempotencyKey".to_owned(),
                "PLATFORM_SCHEMA_V1".to_owned(),
                "ReceiptId".to_owned(),
                "ResourceId".to_owned(),
                "decodeReceiptOutcome".to_owned(),
                "decodeResourceAuthority".to_owned(),
                "decodeResourceKind".to_owned(),
            ],
            types: vec![
                "ReceiptOutcome".to_owned(),
                "ResourceAuthority".to_owned(),
                "ResourceCoordinate".to_owned(),
            ],
        }],
        implementation: Some(GeneratedImplementation::WorkContext),
        ..GeneratedModule::default()
    }
}

/// Platform v2 review/attention/check/PR projections and scoped actions.
fn review_context_module() -> GeneratedModule {
    let security_enum = |name: &str, values: Vec<String>| GeneratedEnum {
        name: name.to_owned(),
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order: None,
    };
    GeneratedModule {
        file_name: module_file_name(REVIEW_CONTEXT_MODULE),
        doc: "Bounded Platform v2 review, attention, check, and pull-request contract.".to_owned(),
        source: "automonique_protocol::platform_v2_review".to_owned(),
        constants: vec![
            Constant {
                name: "PLATFORM_REVIEW_SCHEMA_V1".to_owned(),
                doc: "Stable Platform v2 review sub-contract schema.".to_owned(),
                value: ConstantValue::Text(
                    crate::platform_v2_review::PLATFORM_REVIEW_SCHEMA_V1.to_owned(),
                ),
            },
            Constant {
                name: "MAX_REVIEW_FIELD_BYTES".to_owned(),
                doc: "Maximum opaque identifier or short field bytes.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_FIELD_BYTES),
            },
            Constant {
                name: "MAX_REVIEW_PATH_BYTES".to_owned(),
                doc: "Maximum repository-relative display path bytes.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_PATH_BYTES),
            },
            Constant {
                name: "MAX_REVIEW_TEXT_BYTES".to_owned(),
                doc: "Maximum persisted comment text bytes.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_TEXT_BYTES),
            },
            Constant {
                name: "MAX_REVIEW_HUNK_PREVIEW_BYTES".to_owned(),
                doc: "Maximum sanitized hunk preview bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_review::MAX_REVIEW_HUNK_PREVIEW_BYTES,
                ),
            },
            Constant {
                name: "MAX_REVIEW_FILES".to_owned(),
                doc: "Maximum files in one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_FILES),
            },
            Constant {
                name: "MAX_REVIEW_HUNKS_PER_FILE".to_owned(),
                doc: "Maximum hunks retained for one file.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_HUNKS_PER_FILE),
            },
            Constant {
                name: "MAX_REVIEW_HUNKS".to_owned(),
                doc: "Maximum hunks across one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_HUNKS),
            },
            Constant {
                name: "MAX_REVIEW_COMMENTS".to_owned(),
                doc: "Maximum anchored comments in one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_COMMENTS),
            },
            Constant {
                name: "MAX_REVIEW_CHECKS".to_owned(),
                doc: "Maximum check projections in one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_CHECKS),
            },
            Constant {
                name: "MAX_REVIEW_PROPOSALS".to_owned(),
                doc: "Maximum typed proposals in one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_PROPOSALS),
            },
            Constant {
                name: "MAX_REVIEW_PROPOSAL_FILES".to_owned(),
                doc: "Maximum file identities in one typed proposal.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_PROPOSAL_FILES),
            },
            Constant {
                name: "MAX_REVIEW_ATTENTION_EVENTS".to_owned(),
                doc: "Maximum source attention events in one review snapshot.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_ATTENTION_EVENTS),
            },
            Constant {
                name: "MAX_REVIEW_UNREAD".to_owned(),
                doc: "Maximum authoritative unread count.".to_owned(),
                value: ConstantValue::Count(crate::platform_v2_review::MAX_REVIEW_UNREAD as usize),
            },
            Constant {
                name: "MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical review snapshot bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_review_api::MAX_REVIEW_SNAPSHOT_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_REVIEW_ACTION_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical scoped review action bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_review_api::MAX_REVIEW_ACTION_CANONICAL_BYTES,
                ),
            },
            Constant {
                name: "MAX_REVIEW_RECEIPT_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical review receipt bytes.".to_owned(),
                value: ConstantValue::Count(
                    crate::platform_v2_review_api::MAX_REVIEW_RECEIPT_CANONICAL_BYTES,
                ),
            },
        ],
        enums: vec![
            security_enum(
                "AttentionOriginKind",
                platform_values(&AttentionOriginKind::ALL, AttentionOriginKind::as_str),
            ),
            security_enum(
                "AttentionReason",
                platform_values(&AttentionReason::ALL, AttentionReason::as_str),
            ),
            security_enum(
                "AttentionState",
                platform_values(&AttentionState::ALL, AttentionState::as_str),
            ),
            security_enum(
                "CheckState",
                platform_values(&CheckState::ALL, CheckState::as_str),
            ),
            security_enum(
                "CommentAgentState",
                platform_values(&CommentAgentState::ALL, CommentAgentState::as_str),
            ),
            security_enum(
                "ConflictState",
                platform_values(&ConflictState::ALL, ConflictState::as_str),
            ),
            security_enum(
                "DeliveryState",
                platform_values(&DeliveryState::ALL, DeliveryState::as_str),
            ),
            security_enum(
                "DiffChangeKind",
                platform_values(&DiffChangeKind::ALL, DiffChangeKind::as_str),
            ),
            security_enum(
                "DiffSide",
                platform_values(&DiffSide::ALL, DiffSide::as_str),
            ),
            security_enum(
                "MergeReadiness",
                platform_values(&MergeReadiness::ALL, MergeReadiness::as_str),
            ),
            security_enum(
                "PreviewKind",
                platform_values(&PreviewKind::ALL, PreviewKind::as_str),
            ),
            security_enum(
                "PullRequestState",
                platform_values(&PullRequestState::ALL, PullRequestState::as_str),
            ),
            security_enum(
                "ReviewActionKind",
                platform_values(&ReviewActionKind::ALL, ReviewActionKind::as_str),
            ),
            security_enum(
                "ReviewAuthentication",
                platform_values(&ReviewAuthentication::ALL, ReviewAuthentication::as_str),
            ),
            security_enum(
                "ReviewAuthorityKind",
                platform_values(&ReviewAuthorityKind::ALL, ReviewAuthorityKind::as_str),
            ),
            security_enum(
                "ReviewDecision",
                platform_values(&ReviewDecision::ALL, ReviewDecision::as_str),
            ),
            security_enum(
                "ReviewFreshnessState",
                platform_values(&ReviewFreshnessState::ALL, ReviewFreshnessState::as_str),
            ),
            security_enum(
                "ReviewProposalKind",
                platform_values(&ReviewProposalKind::ALL, ReviewProposalKind::as_str),
            ),
            security_enum(
                "ReviewReceiptOutcome",
                platform_values(&ReviewReceiptOutcome::ALL, ReviewReceiptOutcome::as_str),
            ),
            security_enum(
                "ReviewReconciliation",
                platform_values(&ReviewReconciliation::ALL, ReviewReconciliation::as_str),
            ),
            security_enum(
                "WorktreeFileState",
                platform_values(&WorktreeFileState::ALL, WorktreeFileState::as_str),
            ),
        ],
        imports: vec![
            ModuleImport {
                module: RUNTIME_MODULE.to_owned(),
                values: vec![
                    "RefusalError".to_owned(),
                    "byteLength".to_owned(),
                    "isWellFormedUnicode".to_owned(),
                    "parseCanonical".to_owned(),
                    "toCanonicalBytes".to_owned(),
                ],
                types: vec!["JsonValue".to_owned()],
            },
            ModuleImport {
                module: WORK_CONTEXT_MODULE.to_owned(),
                values: vec!["validateWorkContextIdentity".to_owned()],
                types: vec!["WorkContextIdentity".to_owned()],
            },
        ],
        implementation: Some(GeneratedImplementation::ReviewContext),
        ..GeneratedModule::default()
    }
}

/// The stream message arms, each carrying its body under one shared key.
///
/// Written as a match over the closed kind set rather than a list, so a kind
/// added to the vocabulary fails to compile here instead of quietly generating
/// a union that cannot represent it.
fn stream_message_variants() -> Vec<UnionVariant> {
    StreamMessageKind::ALL
        .into_iter()
        .map(|kind| {
            let body = match kind {
                StreamMessageKind::Greeting => "StreamGreeting",
                StreamMessageKind::Live => "StreamLive",
                StreamMessageKind::ResyncRequired => "StreamResync",
                StreamMessageKind::Frame => "ProgressFrame",
                // One shape for both endings: they differ in what they mean and
                // in what a client does next, not in what they carry.
                StreamMessageKind::Lagged | StreamMessageKind::Retired => "StreamStop",
                StreamMessageKind::Refused => "StreamRefused",
            };
            UnionVariant {
                tag: kind.as_str().to_owned(),
                payload: Some(("body".to_owned(), body.to_owned())),
            }
        })
        .collect()
}

/// Every maintained module, in file-name order.
#[must_use]
pub fn maintained_modules() -> Vec<GeneratedModule> {
    let mut modules = vec![
        runtime_module(),
        doctor_module(),
        admin_status_module(),
        admin_command_module(),
        runs_module(),
        automation_module(),
        approval_module(),
        batch_module(),
        mobile_auth_module(),
        platform_module(),
        platform_v2_transport_module(),
        work_context_module(),
        review_context_module(),
        progress_module(),
    ];
    modules.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    modules
}

/// The runtime symbols a module's declarations need, as `(values, types)` in
/// sorted order.
///
/// Derived from what is about to be emitted rather than listed by hand, so a
/// module cannot import a helper it stopped using or miss one it started. Types
/// are separated from values because the generated files are run by TypeScript
/// implementations that only erase types: a type imported as a value leaves a
/// binding behind that does not exist.
fn response_runtime_imports(value: &ResponseValue, names: &mut Vec<&'static str>) {
    match value {
        ResponseValue::Bool => names.push("bodyBool"),
        ResponseValue::Checked { .. } | ResponseValue::Enum { .. } => {
            names.extend(["bodyString", "refuse"]);
        }
        ResponseValue::EnumArray { .. } | ResponseValue::CheckedArray { .. } => {
            names.extend(["bodyStrings", "refuse"]);
        }
        ResponseValue::IntegerArray { unsigned, .. } => names.extend([
            "bodyArray",
            if *unsigned {
                "jsonUnsigned"
            } else {
                "jsonInteger"
            },
            "refuse",
        ]),
        ResponseValue::ExactString { .. } => {
            names.extend(["bodyString", "exactString"]);
        }
        ResponseValue::NullableChecked { .. } => {
            names.extend(["bodyStringOrNull", "mapNullable", "refuse"]);
        }
        ResponseValue::Integer { unsigned, .. } => names.extend([
            if *unsigned {
                "bodyUnsigned"
            } else {
                "bodyInteger"
            },
            "refuse",
        ]),
        ResponseValue::RangedInteger { unsigned, .. } => names.extend([
            if *unsigned {
                "bodyUnsigned"
            } else {
                "bodyInteger"
            },
            "rangedInteger",
        ]),
        ResponseValue::NullableInteger { .. } => {
            names.extend(["bodyIntegerOrNull", "mapNullable", "refuse"]);
        }
        ResponseValue::Object { .. } => names.push("bodyValue"),
        ResponseValue::NullableObject { .. } => {
            names.extend(["bodyValueOrNull", "mapNullable"]);
        }
        ResponseValue::ObjectArray { .. } => names.push("bodyArray"),
    }
}

fn runtime_imports(module: &GeneratedModule) -> (Vec<&'static str>, Vec<&'static str>) {
    let measures_bytes = !module.branded_ids.is_empty() || !module.bounded_strings.is_empty();
    let mut refuses_values = measures_bytes
        || !module.bounded_integers.is_empty()
        || !module.enums.is_empty()
        || !module.unions.is_empty();
    let mut names = Vec::new();
    let mut types = Vec::new();

    if module.implementation == Some(GeneratedImplementation::WorkContext) {
        names.extend([
            "RefusalError",
            "bodyArray",
            "bodyBool",
            "bodyInteger",
            "bodyString",
            "bodyStringOrNull",
            "bodyValue",
            "bodyValueOrNull",
            "exactFields",
            "exactInputFields",
            "parseCanonical",
            "refuse",
            "toCanonicalBytes",
        ]);
        types.push("JsonValue");
        refuses_values = true;
    }

    if let Some(surface) = &module.command_surface {
        // A surface always refuses something: an oversized payload on the way
        // out, an undefined kind on the way in.
        names.extend(["RefusalError", "refuseField"]);
        refuses_values = true;
        let request_fields = || surface.requests.iter().flat_map(|request| &request.fields);
        if !surface.requests.is_empty() {
            names.extend(["encodeMessage", "exactInputFields"]);
            types.push("JsonValue");
        }
        for field in request_fields() {
            match &field.value {
                RequestValue::Checked { .. }
                | RequestValue::NullableChecked { .. }
                | RequestValue::Integer { .. }
                | RequestValue::NullableInteger { .. }
                | RequestValue::Enum { .. } => names.push("refuse"),
                RequestValue::RangedInteger { .. } => names.push("rangedInteger"),
                RequestValue::HexBytes { .. } => {
                    names.extend(["boundedBytes", "hexEncode", "refuse"]);
                }
                RequestValue::CheckedArray { .. } => names.extend(["boundedItems", "refuse"]),
                // The encoder the field calls is declared in this module; the
                // helpers it needs are pulled in with the body below.
                RequestValue::Discriminated { .. } => {}
                RequestValue::NullableEnumSet { .. } => names.push("orderedEnumSet"),
                RequestValue::Object { .. }
                | RequestValue::NullableObject { .. }
                | RequestValue::ObjectArray { .. } => {}
            }
        }
        if !surface.discriminated_bodies.is_empty() {
            names.extend([
                "bodyIntegerOrNull",
                "bodyString",
                "exactFields",
                "rangedInteger",
                "refuse",
            ]);
            types.push("JsonValue");
        }
        if surface
            .requests
            .iter()
            .any(|request| request.coupling.is_some())
        {
            names.push("coupledField");
        }
        if !surface.responses.is_empty() {
            names.extend(["decodeMessageAdmitted", "exactFields", "refuse"]);
            types.push("JsonValue");
        }
        if !surface.body_objects.is_empty() {
            names.extend(["exactFields", "exactInputFields"]);
            types.push("JsonValue");
        }
        for field in surface
            .responses
            .iter()
            .flat_map(|response| &response.fields)
            .chain(
                surface
                    .body_objects
                    .iter()
                    .flat_map(|object| &object.fields),
            )
        {
            response_runtime_imports(&field.value, &mut names);
        }
    }

    if let Some(surface) = &module.json_surface {
        refuses_values = true;
        names.extend(["RefusalError", "exactFields", "exactInputFields"]);
        types.push("JsonValue");
        for field in surface
            .documents
            .iter()
            .flat_map(|document| &document.body.fields)
        {
            response_runtime_imports(&field.value, &mut names);
        }
    }

    if refuses_values {
        names.push("ValidationError");
    }
    if measures_bytes {
        names.extend(["byteLength", "isWellFormedUnicode"]);
    }
    names.sort_unstable();
    names.dedup();
    types.sort_unstable();
    types.dedup();
    (names, types)
}

/// Emit the import lines one module opens with.
fn emit_imports(out: &mut String, module: &GeneratedModule) {
    let mut lines: Vec<(String, Vec<String>, Vec<String>)> = module
        .imports
        .iter()
        .map(|import| {
            (
                module_specifier(&import.module),
                import.values.clone(),
                import.types.clone(),
            )
        })
        .collect();
    let (values, types) = runtime_imports(module);
    if !values.is_empty() || !types.is_empty() {
        lines.push((
            module_specifier(RUNTIME_MODULE),
            values.iter().map(|name| (*name).to_owned()).collect(),
            types.iter().map(|name| (*name).to_owned()).collect(),
        ));
    }
    lines.sort();
    if !lines.is_empty() {
        out.push('\n');
    }
    for (file_name, values, types) in &lines {
        let mut values = values.clone();
        values.sort();
        let mut types = types.clone();
        types.sort();
        let named: Vec<String> = values
            .into_iter()
            .chain(types.into_iter().map(|name| format!("type {name}")))
            .collect();
        let _ = writeln!(
            out,
            "import {{{names}}} from \"./{file_name}\";",
            names = named.join(", ")
        );
    }
}

/// Emit the header every generated file opens with.
///
/// The Apache-2.0 identifier is the licence of the SDK tree these files land
/// in, not of the Elastic-2.0 crate that writes them.
fn emit_banner(out: &mut String, source: &str, doc: &str) {
    out.push_str("// SPDX-License-Identifier: Apache-2.0\n\n");
    out.push_str("// GENERATED by automonique_protocol::codegen — do not edit by hand.\n");
    let _ = writeln!(out, "// Regenerate with: {REGENERATE_COMMAND}");
    out.push_str("//\n");
    let _ = writeln!(out, "// Source of truth: {source}");
    let _ = writeln!(out, "// {doc}");
    out.push_str("//\n");
    out.push_str("// Rust is the wire source of truth. Hand-written SDK code may add\n");
    out.push_str("// ergonomics; it may not redefine anything in this file.\n");
}

/// The digest identifying the schema this generated surface was emitted from.
///
/// Computed over the emitted maintained modules rather than over the
/// [`GeneratedModule`] description structs, because the emitter is a total
/// function of the description: every construct the schema declares that
/// reaches the surface reaches this digest. A hand-written canonical encoder
/// of the description types would be a second source of truth, and would go
/// quietly stale the first time a descriptor gained a field nobody remembered
/// to encode there — a digest that stops moving is worse than no digest,
/// because a stale one is believed.
///
/// The barrel is excluded from the input for the obvious reason: it carries
/// the digest.
///
/// Each module contributes `name \n byte length \n contents`. The length
/// prefix is what makes the encoding injective — without it a file name
/// ending in a newline could reproduce another surface's byte stream.
fn schema_digest(modules: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    for (file_name, contents) in modules {
        hasher.update(file_name.as_bytes());
        hasher.update(b"\n");
        hasher.update(contents.len().to_string().as_bytes());
        hasher.update(b"\n");
        hasher.update(contents.as_bytes());
    }
    hasher.finish().to_hex()
}

/// Emit the barrel that makes the maintained surface one import.
///
/// `spike.ts` is deliberately absent. It is evidence for a decision rather
/// than shipped surface, and its own `ValidationError` would collide with the
/// runtime module's.
///
/// The barrel also carries the schema digest, split into algorithm and hex the
/// way [`crate::release::ArtifactDigest`] takes them, so a released SDK can
/// declare the surface it was generated against without a second computation.
fn emit_barrel(modules: &[GeneratedModule], digest: &str, platform_v1_digest: &str) -> String {
    let mut out = String::new();
    emit_banner(
        &mut out,
        "automonique_protocol::codegen",
        "Every maintained module, re-exported as one import surface.",
    );
    out.push('\n');
    let mut names: Vec<String> = modules
        .iter()
        .map(|module| module_specifier(module.file_name.trim_end_matches(MODULE_EXTENSION)))
        .collect();
    names.sort_unstable();
    for name in names {
        let _ = writeln!(out, "export * from \"./{name}\";");
    }
    out.push('\n');
    out.push_str("// The digest of the surface re-exported above. It identifies the schema\n");
    out.push_str("// these files were generated from; it is not a checksum of this file.\n");
    let _ = writeln!(
        out,
        "export const SCHEMA_DIGEST_ALGORITHM = \"{algorithm}\";",
        algorithm = crate::digest::ALGORITHM
    );
    let _ = writeln!(out, "export const SCHEMA_DIGEST = \"{digest}\";");
    out.push_str("\n// The exact generated Platform v1 module digest. A package that advertises\n");
    out.push_str("// protocolRange/schema v1 uses this pin, not the aggregate surface digest.\n");
    let _ = writeln!(
        out,
        "export const PLATFORM_V1_SCHEMA_DIGEST = \"{platform_v1_digest}\";"
    );
    out
}

/// Emit one interface and, when the wire body has an exact field set, the
/// array that names it.
fn emit_interface(out: &mut String, interface: &Interface) {
    let mut fields = interface.fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let _ = writeln!(out, "\n/** {} */", interface.doc);
    let _ = writeln!(out, "export interface {} {{", interface.name);
    for field in &fields {
        let (optional, type_name) = match field.presence {
            Presence::Required => ("", field.type_name.clone()),
            Presence::Optional => ("?", field.type_name.clone()),
            Presence::Nullable => ("", format!("{} | null", field.type_name)),
        };
        let _ = writeln!(
            out,
            "  readonly {name}{optional}: {type_name};",
            name = field.name
        );
    }
    out.push_str("}\n");

    // The Rust decoders refuse a body whose key set is not exactly this one.
    // An optional field would make the array a superset of what the wire
    // carries, so a module with one gets no array rather than a misleading one.
    if fields
        .iter()
        .any(|field| field.presence == Presence::Optional)
    {
        return;
    }
    let _ = writeln!(
        out,
        "export const {}_FIELDS: readonly string[] = [",
        interface.name
    );
    for field in &fields {
        let _ = writeln!(out, "  \"{}\",", field.name);
    }
    out.push_str("];\n");
}

// ---------------------------------------------------------------------------
// Command surface
// ---------------------------------------------------------------------------

/// The constant naming one wire kind, qualified by the surface that defines it.
///
/// Two protocols may spell one kind the same way and mean different things:
/// `automonique.admin` and `automonique.runs` both answer `refused`, and the
/// bodies differ. The barrel re-exports every module with `export *`, so an
/// unqualified `REFUSED_RESPONSE_KIND` in each would be ambiguous for every
/// consumer — which is exactly what the duplicate-name gate in
/// `tests/codegen.rs` reported when this surface was first generated.
fn kind_constant(surface: &CommandSurface, kind: &str, role: &str) -> String {
    format!(
        "{surface}_{kind}_{role}_KIND",
        surface = surface.name.to_uppercase(),
        kind = kind.to_uppercase(),
        role = role.to_uppercase()
    )
}

/// Emit one module-level or surface-level constant.
fn emit_constant(out: &mut String, constant: &Constant) {
    let _ = writeln!(out, "\n/** {} */", constant.doc);
    match &constant.value {
        ConstantValue::Count(value) => {
            let _ = writeln!(out, "export const {} = {value};", constant.name);
        }
        ConstantValue::Text(value) => {
            let _ = writeln!(out, "export const {} = \"{value}\";", constant.name);
        }
        ConstantValue::Words(values) => {
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let _ = writeln!(
                out,
                "export const {name}: readonly string[] = [{list}];",
                name = constant.name,
                list = literals.join(", ")
            );
        }
    }
}

/// Emit a `readonly string[]` of wire names.
fn emit_name_list(out: &mut String, name: &str, doc: &str, values: &[String]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {name}: readonly string[] = [");
    for value in &sorted {
        let _ = writeln!(out, "  \"{value}\",");
    }
    out.push_str("];\n");
}

/// Emit the shared request encoder.
///
/// Framing is excluded and says so: these bytes are one canonical payload, and
/// the length prefix belongs to whatever writes them to a socket. A client that
/// framed them here and again at the transport would be refused by a daemon
/// reading a length that is not a length.
fn emit_request_encoder(out: &mut String, surface: &CommandSurface) {
    let CommandSurface {
        name,
        protocol,
        protocol_constant,
        request_id_type,
        oversize_category,
        field_invalid_category,
        field_grammar_category,
        ..
    } = surface;
    let max_message_bytes_constant = surface
        .request_max_message_bytes_constant
        .as_ref()
        .unwrap_or(&surface.max_message_bytes_constant);
    let version = version_constant(surface);
    let _ = write!(
        out,
        "\n/**\n \
         * Build one canonical request payload for `{protocol}`, version {major}.\n \
         *\n \
         * The length-delimited framing this protocol travels under is not applied\n \
         * here: these are payload bytes, and the prefix belongs to the transport\n \
         * that writes them. This package has no transport.\n \
         *\n \
         * The correlation identifier is re-validated rather than trusted, because a\n \
         * brand exists only in the type checker and an untyped caller reaches this\n \
         * function with anything at all.\n \
         */\n\
         export function encode{name}Request(\n  \
         request_id: {request_id_type},\n  \
         kind: string,\n  \
         entries: readonly (readonly [string, JsonValue])[],\n\
         ): Uint8Array {{\n  \
         const payload = encodeMessage({{\n    \
         envelope: {{\n      \
         protocol: {protocol_constant},\n      \
         version: {version},\n      \
         requestId: refuseField({field_invalid_category}, {field_grammar_category}, () =>\n        \
         {request_id_type}(request_id),\n      \
         ),\n      \
         kind,\n    \
         }},\n    \
         body: {{kind: \"object\", entries}},\n  \
         }});\n  \
         if (payload.length > {max_message_bytes_constant}) {{\n    \
         throw new RefusalError(\n      \
         {oversize_category},\n      \
         `canonical payload is ${{payload.length}} bytes; maximum is \
         ${{{max_message_bytes_constant}}}`,\n    \
         );\n  \
         }}\n  \
         return payload;\n\
         }}\n",
        major = surface.version,
    );
}

/// Emit one request: its kind, its body type, and the builder that encodes it.
fn emit_request(out: &mut String, surface: &CommandSurface, request: &RequestCommand) {
    let RequestCommand {
        kind,
        name,
        doc,
        fields,
        coupling: _,
    } = request;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let kind_constant = kind_constant(surface, kind, "request");
    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {kind_constant} = \"{kind}\";");

    if !fields.is_empty() {
        let _ = writeln!(out, "export interface {name}Body {{");
        for field in &fields {
            let _ = writeln!(
                out,
                "  readonly {input}: {type_name};",
                input = field.input_name,
                type_name = field.input_type()
            );
        }
        out.push_str("}\n");
        emit_name_list(
            out,
            &format!("{name}Body_FIELDS"),
            "The exact key set this command's wire body carries.",
            &fields
                .iter()
                .map(|field| field.name.clone())
                .collect::<Vec<_>>(),
        );
        emit_name_list(
            out,
            &format!("{name}Body_INPUT_FIELDS"),
            "The exact key set accepted by this generated TypeScript builder.",
            &fields
                .iter()
                .map(|field| field.input_name.clone())
                .collect::<Vec<_>>(),
        );
    }

    let argument = if fields.is_empty() {
        String::new()
    } else {
        format!(", body: {name}Body")
    };
    let _ = writeln!(
        out,
        "\nexport function encode{name}(request_id: {request_id}{argument}): Uint8Array {{",
        request_id = surface.request_id_type
    );
    if fields.is_empty() {
        // A command with no arguments carries an empty object, which is what
        // the Rust decoder requires: it refuses a nonempty body for these
        // kinds rather than ignoring what it does not expect.
        let _ = writeln!(
            out,
            "  return encode{surface}Request(request_id, {kind_constant}, []);\n}}",
            surface = surface.name
        );
        return;
    }
    let _ = writeln!(
        out,
        "  exactInputFields(body, {name}Body_INPUT_FIELDS, {});",
        surface.invalid_body_category
    );
    for (_, validation) in surface
        .request_validations
        .iter()
        .filter(|(request_kind, _)| request_kind == kind)
    {
        match validation {
            RequestValidation::ExactlyOneNonNull {
                left,
                right,
                refusal_category,
            } => {
                let _ = writeln!(
                    out,
                    "  if ((body.{left} === null) === (body.{right} === null)) {{\n    throw new RefusalError({refusal_category}, \"exactly one of {left} and {right} is required\");\n  }}"
                );
            }
            RequestValidation::ActionAuthority {
                action_field,
                target_field,
                action_authorities,
                refusal_category,
            } => {
                let _ = writeln!(
                    out,
                    "  const expectedAuthority = (() => {{\n    switch (body.{action_field}) {{"
                );
                let mut mappings = action_authorities.clone();
                mappings.sort();
                for (action, authority) in mappings {
                    let _ = writeln!(out, "      case \"{action}\": return \"{authority}\";");
                }
                let _ = writeln!(
                    out,
                    "      default: throw new RefusalError({refusal_category}, \"action is not defined\");\n    }}\n  }})();"
                );
                let _ = writeln!(
                    out,
                    "  if (body.{target_field}.authority !== expectedAuthority) {{\n    throw new RefusalError({refusal_category}, \"action and target authority disagree\");\n  }}"
                );
            }
            RequestValidation::ExactCoordinate {
                field,
                authority,
                kind,
                refusal_category,
            } => {
                let _ = writeln!(
                    out,
                    "  if (body.{field}.authority !== \"{authority}\" || body.{field}.kind !== \"{kind}\") {{\n    throw new RefusalError({refusal_category}, \"{field} is not the required command coordinate\");\n  }}"
                );
            }
        }
    }
    // A nullable field is read into a local before it is tested. TypeScript
    // discards the narrowing of a property access inside a closure created
    // after it — `body.since` is `RunCursor | null` again inside the arrow the
    // refusal wrapper takes — while the narrowing of a `const` survives. Without
    // this the generated file does not typecheck, which is how the package
    // typecheck found it.
    let nullable: Vec<&RequestField> = fields.iter().filter(|field| field.needs_local()).collect();
    for field in &nullable {
        // A governed field is bound through its coupling rather than read
        // straight off the body, so the rule is applied before any value is
        // encoded: a request that cannot be right does not spend a frame
        // finding out. Both are `const` locals, so the narrowing survives into
        // the closures below either way.
        match &request.coupling {
            Some(coupling) if coupling.governed_field == field.input_name => {
                let _ = writeln!(
                    out,
                    "  const {governed} = coupledField(body.{deciding}, body.{governed}, {{\n    \
                     deciding: \"{deciding}\",\n    governed: \"{governed}\",\n    requiring: \
                     {requiring},\n    required: {required},\n    forbidden: {forbidden},\n  }});",
                    governed = coupling.governed_field,
                    deciding = coupling.deciding_field,
                    requiring = coupling.requiring_constant,
                    required = coupling.required_category,
                    forbidden = coupling.forbidden_category,
                );
            }
            _ => {
                let _ = writeln!(
                    out,
                    "  const {input} = body.{input};",
                    input = field.input_name
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "  return encode{surface}Request(request_id, {kind_constant}, [",
        surface = surface.name
    );
    for field in &fields {
        let input = &field.input_name;
        // The nullable fields read the local bound above; the rest read `body`
        // directly, which keeps every other surface's output unchanged.
        let source = if nullable.iter().any(|other| other.name == field.name) {
            String::new()
        } else {
            "body.".to_owned()
        };
        let input = &format!("{source}{input}");
        let entry = match &field.value {
            RequestValue::Checked {
                type_name,
                refusal_category,
            } => format!(
                "{{kind: \"string\", value: refuse({refusal_category}, () => \
                 {type_name}({input}))}}"
            ),
            RequestValue::HexBytes {
                max_bytes_constant,
                oversize_category,
            } => format!(
                "{{kind: \"string\", value: refuse({invalid}, () => \
                 hexEncode(boundedBytes({input}, {max_bytes_constant}, {oversize_category}, \
                 {invalid})))}}",
                invalid = surface.invalid_body_category,
            ),
            RequestValue::NullableChecked {
                type_name,
                refusal_category,
            } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : {{kind: \
                 \"string\", value: refuse({refusal_category}, () => {type_name}({input}))}}"
            ),
            RequestValue::Integer {
                type_name,
                refusal_category,
            } => format!(
                "{{kind: \"integer\", value: refuse({refusal_category}, () => \
                 {type_name}({input}))}}"
            ),
            RequestValue::RangedInteger {
                type_name,
                below_category,
                above_category,
            } => format!(
                "{{kind: \"integer\", value: rangedInteger({input}, {type_name}_MIN, \
                 {below_category}, {above_category}, {type_name})}}"
            ),
            RequestValue::Enum {
                type_name,
                unknown_category,
            } => format!(
                "{{kind: \"string\", value: refuse({unknown_category}, () => \
                 decode{type_name}({input}))}}"
            ),
            RequestValue::NullableInteger {
                type_name,
                refusal_category,
            } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : {{kind: \
                 \"integer\", value: refuse({refusal_category}, () => {type_name}({input}))}}"
            ),
            RequestValue::Object { type_name } => {
                format!("encode{type_name}({input})")
            }
            RequestValue::NullableObject { type_name } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : encode{type_name}({input})"
            ),
            RequestValue::ObjectArray {
                type_name,
                max_items_constant,
                oversize_category,
            } => format!(
                "((): JsonValue => {{\n        if ({input}.length > {max_items_constant}) {{\n          \
                 throw new RefusalError({oversize_category}, `${{{input}.length}} items; maximum \
                 is ${{{max_items_constant}}}`);\n        }}\n        return {{kind: \"array\", \
                 items: {input}.map(encode{type_name})}};\n      }})()"
            ),
            RequestValue::Discriminated { type_name } => format!("encode{type_name}({input})"),
            RequestValue::CheckedArray {
                type_name,
                refusal_category,
                max_items_constant,
                oversize_category,
                empty_category,
            } => format!(
                "{{\n        kind: \"array\",\n        items: boundedItems({input}, \
                 {max_items_constant}, {oversize_category}, {empty_category}).map(\n          \
                 (value): JsonValue => ({{kind: \"string\", value: refuse({refusal_category}, () \
                 => {type_name}(value))}}),\n        ),\n      }}"
            ),
            RequestValue::NullableEnumSet {
                order_constant,
                empty_category,
                repeat_category,
                unknown_category,
                ..
            } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : {{\n            \
                 kind: \"array\",\n            items: orderedEnumSet({input}, {{\n              \
                 order: {order_constant},\n              empty: {empty_category},\n              \
                 repeat: {repeat_category},\n              unknown: {unknown_category},\n            \
                 }}).map((value): JsonValue => ({{kind: \"string\", value}})),\n          }}"
            ),
        };
        let _ = writeln!(out, "    [\"{name}\", {entry}],", name = field.name);
    }
    out.push_str("  ]);\n}\n");
}

/// Emit the closed request union and request-to-success-response correlation map.
fn emit_correlated_request_surface(out: &mut String, surface: &CommandSurface) {
    if surface.request_response_kinds.is_empty() {
        return;
    }
    let request_by_kind: std::collections::BTreeMap<&str, &RequestCommand> = surface
        .requests
        .iter()
        .map(|request| (request.kind.as_str(), request))
        .collect();
    let mut mappings = surface.request_response_kinds.clone();
    mappings.sort();
    let union = format!("{}Request", surface.name);
    let mut arms = Vec::with_capacity(mappings.len());
    for (kind, _) in &mappings {
        let request = request_by_kind
            .get(kind.as_str())
            .unwrap_or_else(|| panic!("response mapping names unknown request kind {kind}"));
        if request.fields.is_empty() {
            arms.push(format!("  | {{readonly method: \"{kind}\"}}"));
        } else {
            arms.push(format!(
                "  | {{readonly method: \"{kind}\"; readonly request: {}Body}}",
                request.name
            ));
        }
    }
    let _ = writeln!(
        out,
        "\n/** Every generated request this protocol admits. */\nexport type {union} =\n{};",
        arms.join("\n")
    );
    let _ = writeln!(
        out,
        "\nexport function encode{}RequestMessage(request_id: {}, request: {union}): Uint8Array {{",
        surface.name, surface.request_id_type
    );
    out.push_str("  switch (request.method) {\n");
    for (kind, _) in &mappings {
        let request = request_by_kind[kind.as_str()];
        let constant = kind_constant(surface, kind, "request");
        let fields = if request.fields.is_empty() {
            "[\"method\"]"
        } else {
            "[\"method\", \"request\"]"
        };
        let _ = writeln!(out, "    case {constant}:");
        let _ = writeln!(
            out,
            "      exactInputFields(request, {fields}, {});",
            surface.invalid_body_category
        );
        let _ = writeln!(
            out,
            "      return encode{}(request_id{});",
            request.name,
            if request.fields.is_empty() {
                String::new()
            } else {
                ", request.request".to_owned()
            }
        );
    }
    out.push_str("  }\n}\n");

    let _ = writeln!(
        out,
        "\n/** Successful response kind correlated with one request method. */\nexport function expected{}ResponseKind(method: {union}[\"method\"]): {}Response[\"kind\"] {{",
        surface.name, surface.name
    );
    out.push_str("  switch (method) {\n");
    for (request_kind, response_kind) in &mappings {
        let request_constant = kind_constant(surface, request_kind, "request");
        let response_constant = kind_constant(surface, response_kind, "response");
        let _ = writeln!(
            out,
            "    case {request_constant}: return {response_constant};"
        );
    }
    out.push_str("  }\n}\n");
}

/// Emit one nested body type and the decoder that reads it.
///
/// It takes a whole [`JsonValue`] rather than a field map, because a nested
/// body is a value inside its carrier's body rather than a message of its own.
/// Its own exact field set is applied here, so a summary carrying one key too
/// many is refused wherever it is nested.
fn emit_body_object(out: &mut String, invalid: &str, object: &BodyObject, encode: bool) {
    let BodyObject { name, doc, fields } = object;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));

    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export interface {name} {{");
    for field in &fields {
        let _ = writeln!(
            out,
            "  readonly {field_name}: {type_name};",
            field_name = field.name,
            type_name = response_field_type(&field.value)
        );
    }
    out.push_str("}\n");
    emit_name_list(
        out,
        &format!("{name}_FIELDS"),
        "The exact key set this nested body carries.",
        &fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<Vec<_>>(),
    );

    if encode {
        let _ = writeln!(
            out,
            "\nexport function encode{name}(value: {name}): JsonValue {{"
        );
        let _ = writeln!(out, "  exactInputFields(value, {name}_FIELDS, {invalid});");
        out.push_str("  return {kind: \"object\", entries: [\n");
        for field in &fields {
            let _ = writeln!(
                out,
                "    [\"{field_name}\", {value}],",
                field_name = field.name,
                value = body_object_field_writer(invalid, field)
            );
        }
        out.push_str("  ]};\n}\n");
    }

    let _ = writeln!(
        out,
        "\nexport function decode{name}(body: JsonValue): {name} {{"
    );
    let _ = writeln!(
        out,
        "  const fields = exactFields(body, {name}_FIELDS, {invalid});"
    );
    out.push_str("  return {\n");
    for field in &fields {
        let _ = writeln!(
            out,
            "    {field_name}: {value},",
            field_name = field.name,
            value = response_field_reader(invalid, field)
        );
    }
    out.push_str("  };\n}\n");
}

/// Nested object types reachable from generated request fields.
///
/// Response-only body objects need decoders, not encoders. Restricting encoder
/// emission to this transitive closure keeps generated response declarations
/// unchanged and prevents response-only nullable fields from becoming an
/// accidental request API.
fn request_body_object_types(surface: &CommandSurface) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for value in surface
        .requests
        .iter()
        .flat_map(|request| request.fields.iter().map(|field| &field.value))
    {
        match value {
            RequestValue::Object { type_name }
            | RequestValue::NullableObject { type_name }
            | RequestValue::ObjectArray { type_name, .. } => {
                names.insert(type_name.clone());
            }
            _ => {}
        }
    }

    loop {
        let mut added = false;
        for object in &surface.body_objects {
            if !names.contains(&object.name) {
                continue;
            }
            for field in &object.fields {
                let dependency = match &field.value {
                    ResponseValue::Object { type_name }
                    | ResponseValue::NullableObject { type_name }
                    | ResponseValue::ObjectArray { type_name, .. } => Some(type_name),
                    _ => None,
                };
                if let Some(dependency) = dependency {
                    added |= names.insert(dependency.clone());
                }
            }
        }
        if !added {
            return names;
        }
    }
}

/// Emit one discriminated nested body: its union, its encoder and its decoder.
///
/// The union is the point. A struct with a nullable payload would type-check a
/// program that asked a payload-free variant for its payload; this shape makes
/// that a compile error on one side of the wire and a refusal on the other.
fn emit_discriminated_body(out: &mut String, body: &DiscriminatedBody) {
    let DiscriminatedBody {
        name,
        doc,
        tag_field,
        tag_type,
        unknown_tag_category,
        payload_field,
        payload_type,
        payload_below_category,
        payload_above_category,
        payload_wire_max,
        bare_tags,
        carrying_tag,
        invalid_body_category,
    } = body;
    let mut arms: Vec<String> = bare_tags
        .iter()
        .map(|tag| format!("  | {{readonly {tag_field}: \"{tag}\"}}"))
        .chain(std::iter::once(format!(
            "  | {{readonly {tag_field}: \"{carrying_tag}\"; readonly {payload_field}: \
             {payload_type}}}"
        )))
        .collect();
    arms.sort();
    let _ = write!(
        out,
        "\n/** {doc} */\nexport type {name} =\n{arms};\n",
        arms = arms.join("\n")
    );
    emit_name_list(
        out,
        &format!("{name}_FIELDS"),
        "The exact key set this nested body carries. Both keys are always \
         present: the payload travels as an explicit null under every word that \
         declares none.",
        &[tag_field.clone(), payload_field.clone()],
    );
    let _ = write!(
        out,
        "\nexport function assertNever{name}(value: never): never {{\n  \
         throw new ValidationError(\"{name}\", `unhandled variant: ${{JSON.stringify(value)}}`);\n\
         }}\n"
    );

    // The payload is read off a cast rather than off the narrowed union,
    // because a brand exists only in the type checker: an untyped caller
    // reaches this function with a payload-free word carrying a payload, and
    // dropping it silently would encode a policy the caller did not ask for.
    let _ = write!(
        out,
        "\n/**\n \
         * Encode one `{name}`, refusing the two shapes the wire cannot mean.\n \
         *\n \
         * A word that declares no `{payload_field}` and carries one, and \
         `{carrying_tag}`\n \
         * without one, are both refused rather than repaired: each says the caller \
         asked\n \
         * for something this protocol has no way to record.\n \
         */\n\
         export function encode{name}(value: {name}): JsonValue {{\n  \
         const {tag_field} = refuse({unknown_tag_category}, () => \
         decode{tag_type}(value.{tag_field}));\n  \
         const declared: unknown = (value as {{readonly {payload_field}?: unknown}}).\
         {payload_field};\n  \
         if ({tag_field} === \"{carrying_tag}\") {{\n    \
         if (typeof declared !== \"bigint\") {{\n      \
         throw new RefusalError({invalid_body_category}, \"{carrying_tag} declares a \
         {payload_field}\");\n    \
         }}\n    \
         return {{\n      \
         kind: \"object\",\n      \
         entries: [\n        \
         [\"{tag_field}\", {{kind: \"string\", value: {tag_field}}}],\n        \
         [\n          \"{payload_field}\",\n          \
         {{\n            kind: \"integer\",\n            \
         value: rangedInteger(\n              declared,\n              {payload_type}_MIN,\n\
         {tab}{payload_below_category},\n              {payload_above_category},\n              \
         {payload_type},\n            ),\n          }},\n        ],\n      ],\n    \
         }};\n  \
         }}\n  \
         if (declared !== undefined) {{\n    \
         throw new RefusalError({invalid_body_category}, `${{{tag_field}}} declares no \
         {payload_field}`);\n  \
         }}\n  \
         return {{\n    \
         kind: \"object\",\n    \
         entries: [\n      \
         [\"{tag_field}\", {{kind: \"string\", value: {tag_field}}}],\n      \
         [\"{payload_field}\", {{kind: \"null\"}}],\n    ],\n  \
         }};\n\
         }}\n",
        // A line continuation eats the indentation that follows it, so the one
        // deep-nested argument that lands on its own source line names its
        // indent rather than writing it.
        tab = " ".repeat(14),
    );

    // The width conversion is judged before the domain, because that is the
    // order the Rust decoder settles it in: a value outside the payload's own
    // integer width is a malformed body, and only a value inside it can be
    // refused for being outside the domain.
    let _ = write!(
        out,
        "\nexport function decode{name}(body: JsonValue): {name} {{\n  \
         const fields = exactFields(body, {name}_FIELDS, {invalid_body_category});\n  \
         const {tag_field} = refuse({unknown_tag_category}, () =>\n    \
         decode{tag_type}(bodyString(fields, \"{tag_field}\", {invalid_body_category})),\n  \
         );\n  \
         const declared = bodyIntegerOrNull(fields, \"{payload_field}\", \
         {invalid_body_category});\n  \
         if ({tag_field} === \"{carrying_tag}\") {{\n    \
         if (declared === null) {{\n      \
         throw new RefusalError({invalid_body_category}, \"{carrying_tag} declares a \
         {payload_field}\");\n    \
         }}\n    \
         if (declared < 0n || declared > {payload_wire_max}n) {{\n      \
         throw new RefusalError(\n        {invalid_body_category},\n        \
         \"{payload_field} is outside the width it is carried in\",\n      \
         );\n    \
         }}\n    \
         return {{\n      \
         {tag_field},\n      \
         {payload_field}: rangedInteger(\n        declared,\n        {payload_type}_MIN,\n        \
         {payload_below_category},\n        {payload_above_category},\n        \
         {payload_type},\n      ),\n    \
         }};\n  \
         }}\n  \
         if (declared !== null) {{\n    \
         throw new RefusalError({invalid_body_category}, `${{{tag_field}}} declares no \
         {payload_field}`);\n  \
         }}\n  \
         return {{{tag_field}}};\n\
         }}\n"
    );
}

/// The TypeScript type one decoded response field has.
fn response_field_type(value: &ResponseValue) -> String {
    match value {
        ResponseValue::Checked { type_name, .. }
        | ResponseValue::Integer { type_name, .. }
        | ResponseValue::RangedInteger { type_name, .. }
        | ResponseValue::Enum { type_name, .. }
        | ResponseValue::ExactString { type_name, .. }
        | ResponseValue::Object { type_name } => type_name.clone(),
        ResponseValue::NullableChecked { type_name, .. }
        | ResponseValue::NullableInteger { type_name, .. }
        | ResponseValue::NullableObject { type_name } => format!("{type_name} | null"),
        ResponseValue::Bool => "boolean".to_owned(),
        ResponseValue::EnumArray { type_name, .. }
        | ResponseValue::CheckedArray { type_name, .. }
        | ResponseValue::IntegerArray { type_name, .. }
        | ResponseValue::ObjectArray { type_name, .. } => format!("readonly {type_name}[]"),
    }
}

/// The expression that reads one decoded response field out of a field map.
fn response_field_reader(invalid: &str, field: &ResponseField) -> String {
    let name = &field.name;
    match &field.value {
        ResponseValue::Bool => format!("bodyBool(fields, \"{name}\", {invalid})"),
        ResponseValue::Checked {
            type_name,
            refusal_category,
        } => format!(
            "refuse({refusal_category}, () => {type_name}(bodyString(fields, \"{name}\", \
             {invalid})))"
        ),
        ResponseValue::Integer {
            type_name,
            refusal_category,
            unsigned,
        } => format!(
            "refuse({refusal_category}, () => {type_name}({reader}(fields, \"{name}\", \
             {invalid})))",
            reader = if *unsigned {
                "bodyUnsigned"
            } else {
                "bodyInteger"
            }
        ),
        ResponseValue::RangedInteger {
            type_name,
            below_category,
            above_category,
            unsigned,
        } => format!(
            "rangedInteger(\n      {reader}(fields, \"{name}\", {invalid}),\n      \
             {type_name}_MIN,\n      {below_category},\n      {above_category},\n      \
             {type_name},\n    )",
            reader = if *unsigned {
                "bodyUnsigned"
            } else {
                "bodyInteger"
            }
        ),
        ResponseValue::NullableChecked {
            type_name,
            refusal_category,
        } => format!(
            "mapNullable(bodyStringOrNull(fields, \"{name}\", {invalid}), (value) =>\n      \
             refuse({refusal_category}, () => {type_name}(value)),\n    )"
        ),
        ResponseValue::NullableInteger {
            type_name,
            refusal_category,
        } => format!(
            "mapNullable(bodyIntegerOrNull(fields, \"{name}\", {invalid}), (value) =>\n      \
             refuse({refusal_category}, () => {type_name}(value)),\n    )"
        ),
        ResponseValue::Enum {
            type_name,
            unknown_category,
        } => format!(
            "refuse({unknown_category}, () => decode{type_name}(bodyString(fields, \"{name}\", \
             {invalid})))"
        ),
        ResponseValue::EnumArray {
            type_name,
            max_items_constant,
            oversize_category,
            unknown_category,
        } => format!(
            "bodyStrings(fields, \"{name}\", {invalid}, {max_items_constant}, \
             {oversize_category}).map((value) =>\n      \
             refuse({unknown_category}, () => decode{type_name}(value)),\n    )"
        ),
        ResponseValue::CheckedArray {
            type_name,
            max_items_constant,
            oversize_category,
            refusal_category,
        } => format!(
            "bodyStrings(fields, \"{name}\", {invalid}, {max_items_constant}, \
             {oversize_category}).map((value) =>\n      \
             refuse({refusal_category}, () => {type_name}(value)),\n    )"
        ),
        ResponseValue::IntegerArray {
            type_name,
            max_items_constant,
            oversize_category,
            refusal_category,
            unsigned,
        } => format!(
            "bodyArray(fields, \"{name}\", {invalid}, {max_items_constant}, \
             {oversize_category}).map((value) =>\n      \
             refuse({refusal_category}, () => {type_name}({reader}(value, {invalid}))),\n    )",
            reader = if *unsigned {
                "jsonUnsigned"
            } else {
                "jsonInteger"
            }
        ),
        ResponseValue::ExactString {
            expected_constant,
            mismatch_category,
            ..
        } => format!(
            "exactString(bodyString(fields, \"{name}\", {invalid}), {expected_constant}, \
             {mismatch_category}, \"{name}\")"
        ),
        ResponseValue::Object { type_name } => {
            format!("decode{type_name}(bodyValue(fields, \"{name}\", {invalid}))")
        }
        ResponseValue::NullableObject { type_name } => format!(
            "mapNullable(bodyValueOrNull(fields, \"{name}\", {invalid}), decode{type_name})"
        ),
        ResponseValue::ObjectArray {
            type_name,
            max_items_constant,
            oversize_category,
        } => format!(
            "bodyArray(fields, \"{name}\", {invalid}, {max_items_constant}, \
             {oversize_category}).map(\n      decode{type_name},\n    )"
        ),
    }
}

/// The expression that writes one nested exact-object field to canonical JSON.
fn body_object_field_writer(invalid: &str, field: &ResponseField) -> String {
    let input = format!("value.{}", field.name);
    match &field.value {
        ResponseValue::Bool => format!(
            "typeof {input} === \"boolean\"\n        ? {{kind: \"bool\", value: {input}}}\n        : \
             refuse({invalid}, () => {{ throw new ValidationError(\"{}\", \"not_boolean\"); }})",
            field.name
        ),
        ResponseValue::Checked {
            type_name,
            refusal_category,
        } => format!(
            "{{kind: \"string\", value: refuse({refusal_category}, () => \
             {type_name}({input}))}}"
        ),
        ResponseValue::NullableChecked {
            type_name,
            refusal_category,
        } => format!(
            "((entry) => entry === null\n        ? {{kind: \"null\"}}\n        : {{kind: \"string\", value: \
             refuse({refusal_category}, () => {type_name}(entry))}})({input})"
        ),
        ResponseValue::Integer {
            type_name,
            refusal_category,
            ..
        } => format!(
            "{{kind: \"integer\", value: refuse({refusal_category}, () => \
             {type_name}({input}))}}"
        ),
        ResponseValue::RangedInteger {
            type_name,
            below_category,
            above_category,
            ..
        } => format!(
            "{{kind: \"integer\", value: rangedInteger({input}, {type_name}_MIN, \
             {below_category}, {above_category}, {type_name})}}"
        ),
        ResponseValue::NullableInteger {
            type_name,
            refusal_category,
        } => format!(
            "((entry) => entry === null\n        ? {{kind: \"null\"}}\n        : {{kind: \"integer\", value: \
             refuse({refusal_category}, () => {type_name}(entry))}})({input})"
        ),
        ResponseValue::Enum {
            type_name,
            unknown_category,
        } => format!(
            "{{kind: \"string\", value: refuse({unknown_category}, () => \
             decode{type_name}({input}))}}"
        ),
        ResponseValue::EnumArray {
            type_name,
            max_items_constant,
            oversize_category,
            unknown_category,
        } => format!(
            "((): JsonValue => {{\n        if ({input}.length > {max_items_constant}) \
             throw new RefusalError({oversize_category}, \"array exceeds its ceiling\");\n        \
             return {{kind: \"array\", items: {input}.map((item): JsonValue => ({{kind: \
             \"string\", value: refuse({unknown_category}, () => decode{type_name}(item))}}))}};\n      \
             }})()"
        ),
        ResponseValue::CheckedArray {
            type_name,
            max_items_constant,
            oversize_category,
            refusal_category,
        } => format!(
            "((): JsonValue => {{\n        if ({input}.length > {max_items_constant}) \
             throw new RefusalError({oversize_category}, \"array exceeds its ceiling\");\n        \
             return {{kind: \"array\", items: {input}.map((item): JsonValue => ({{kind: \
             \"string\", value: refuse({refusal_category}, () => {type_name}(item))}}))}};\n      \
             }})()"
        ),
        ResponseValue::IntegerArray {
            type_name,
            max_items_constant,
            oversize_category,
            refusal_category,
            ..
        } => format!(
            "((): JsonValue => {{\n        if ({input}.length > {max_items_constant}) \
             throw new RefusalError({oversize_category}, \"array exceeds its ceiling\");\n        \
             return {{kind: \"array\", items: {input}.map((item): JsonValue => ({{kind: \
             \"integer\", value: refuse({refusal_category}, () => {type_name}(item))}}))}};\n      \
             }})()"
        ),
        ResponseValue::ExactString {
            expected_constant,
            mismatch_category,
            ..
        } => format!(
            "{{kind: \"string\", value: exactString({input}, {expected_constant}, \
             {mismatch_category}, \"{}\")}}",
            field.name
        ),
        ResponseValue::Object { type_name } => format!("encode{type_name}({input})"),
        ResponseValue::NullableObject { type_name } => {
            format!("{input} === null ? {{kind: \"null\"}} : encode{type_name}({input})")
        }
        ResponseValue::ObjectArray {
            type_name,
            max_items_constant,
            oversize_category,
        } => format!(
            "((): JsonValue => {{\n        if ({input}.length > {max_items_constant}) \
             throw new RefusalError({oversize_category}, \"array exceeds its ceiling\");\n        \
             return {{kind: \"array\", items: {input}.map(encode{type_name})}};\n      }})()"
        ),
    }
}

/// Emit one response: its kind, its decoded type, and the decoder.
///
/// The decoder takes the correlation identifier separately because it is an
/// envelope field rather than a body one. Keeping the two apart is what lets
/// the emitted `_BODY_FIELDS` array stay exactly the wire body's key set, which
/// is the set the Rust decoder requires and refuses anything else against.
fn emit_response(out: &mut String, surface: &CommandSurface, response: &ResponseDecoder) {
    let ResponseDecoder {
        kind,
        name,
        doc,
        fields,
    } = response;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let invalid = &surface.invalid_body_category;
    let request_id = &surface.request_id_type;
    let kind_constant = kind_constant(surface, kind, "response");

    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {kind_constant} = \"{kind}\";");
    let _ = writeln!(out, "export interface {name} {{");
    let mut declarations: Vec<(String, String)> = fields
        .iter()
        .map(|field| (field.name.clone(), response_field_type(&field.value)))
        .collect();
    declarations.push(("request_id".to_owned(), request_id.clone()));
    declarations.sort();
    for (field, type_name) in &declarations {
        let _ = writeln!(out, "  readonly {field}: {type_name};");
    }
    out.push_str("}\n");
    emit_name_list(
        out,
        &format!("{name}_BODY_FIELDS"),
        "The exact key set this response's wire body carries; the correlation \
         identifier is not among them, because it travels in the envelope.",
        &fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<Vec<_>>(),
    );

    let _ = writeln!(
        out,
        "\nexport function decode{name}(request_id: {request_id}, body: JsonValue): {name} {{"
    );
    let binding = if fields.is_empty() {
        ""
    } else {
        "const fields = "
    };
    let _ = writeln!(
        out,
        "  {binding}exactFields(body, {name}_BODY_FIELDS, {invalid});"
    );
    out.push_str("  return {\n");
    let mut entries: Vec<(String, String)> = fields
        .iter()
        .map(|field| (field.name.clone(), response_field_reader(invalid, field)))
        .collect();
    entries.push(("request_id".to_owned(), "request_id".to_owned()));
    entries.sort();
    for (field, value) in &entries {
        let _ = writeln!(out, "    {field}: {value},");
    }
    out.push_str("  };\n}\n");
}

/// The constant naming the major version this surface speaks.
fn version_constant(surface: &CommandSurface) -> String {
    format!("{}_PROTOCOL_VERSION", surface.name.to_uppercase())
}

/// Emit the union of decoded responses and the decoder that dispatches on kind.
fn emit_response_dispatch(out: &mut String, surface: &CommandSurface) {
    let CommandSurface {
        name,
        protocol_constant,
        request_id_type,
        max_message_bytes_constant,
        oversize_category,
        unknown_kind_category,
        field_invalid_category,
        field_grammar_category,
        ..
    } = surface;
    let screaming = name.to_uppercase();
    let undecoded_list = format!("{screaming}_RESPONSE_KINDS_NOT_DECODED");
    let undecoded_type = format!("Undecoded{name}ResponseKind");
    let guard = format!("isUndecoded{name}ResponseKind");
    let union = format!("{name}Response");
    let version = version_constant(surface);

    let mut kinds = surface.response_kinds_not_decoded.clone();
    kinds.sort();
    let literals: Vec<String> = kinds.iter().map(|kind| format!("\"{kind}\"")).collect();
    let _ = write!(
        out,
        "\n/**\n \
         * Kinds this protocol version defines that this file does not decode.\n \
         *\n \
         * They are neither refused nor guessed at: a peer that sent one sent something\n \
         * defined, and a client told otherwise might act on the lie. The body is not\n \
         * handed back, because nothing here has validated it.\n \
         */\n\
         export const {undecoded_list} = [{list}] as const;\n\
         export type {undecoded_type} = (typeof {undecoded_list})[number];\n\
         export function {guard}(value: string): value is {undecoded_type} {{\n  \
         return ({undecoded_list} as readonly string[]).includes(value);\n\
         }}\n",
        list = literals.join(", ")
    );

    let mut arms: Vec<String> = surface
        .responses
        .iter()
        .map(|response| {
            format!(
                "  | {{readonly kind: \"{kind}\"; readonly value: {name}}}",
                kind = response.kind,
                name = response.name
            )
        })
        .chain(std::iter::once(format!(
            "  | {{readonly kind: \"undecoded\"; readonly request_id: {request_id_type}; \
             readonly response_kind: {undecoded_type}}}"
        )))
        .collect();
    arms.sort();
    let _ = write!(
        out,
        "\n/** Every response this file can hand a caller. */\nexport type {union} =\n{arms};\n",
        arms = arms.join("\n")
    );
    let _ = write!(
        out,
        "\nexport function assertNever{union}(value: never): never {{\n  \
         throw new ValidationError(\"{union}\", `unhandled variant: ${{JSON.stringify(value)}}`);\n\
         }}\n"
    );

    let _ = write!(
        out,
        "\n/**\n \
         * Decode one canonical response payload.\n \
         *\n \
         * The payload is the framed transport's payload, without its length prefix.\n \
         * The envelope is admitted first and on both axes: a name this file does not\n \
         * implement and a major version outside its range are different refusals, and\n \
         * neither is downgraded into the other.\n \
         */\n\
         export function decode{union}(payload: Uint8Array): {union} {{\n  \
         if (payload.length > {max_message_bytes_constant}) {{\n    \
         throw new RefusalError(\n      \
         {oversize_category},\n      \
         `canonical payload is ${{payload.length}} bytes; maximum is \
         ${{{max_message_bytes_constant}}}`,\n    \
         );\n  \
         }}\n  \
         const message = decodeMessageAdmitted(payload, [\n    \
         {{protocol: {protocol_constant}, minVersion: {version}, maxVersion: {version}}},\n  \
         ]);\n  \
         const request_id = refuseField({field_invalid_category}, {field_grammar_category}, () =>\n    \
         {request_id_type}(message.envelope.requestId),\n  \
         );\n  \
         const kind = message.envelope.kind;\n  \
         if ({guard}(kind)) {{\n    \
         return {{kind: \"undecoded\", request_id, response_kind: kind}};\n  \
         }}\n  \
         switch (kind) {{\n"
    );
    let mut responses = surface.responses.clone();
    responses.sort();
    for response in &responses {
        let _ = write!(
            out,
            "    case {constant}:\n      \
             return {{kind: {constant}, value: decode{name}(request_id, message.body)}};\n",
            constant = kind_constant(surface, &response.kind, "response"),
            name = response.name
        );
    }
    let _ = write!(
        out,
        "    default:\n      \
         throw new RefusalError(\n        \
         {unknown_kind_category},\n        \
         \"message kind is not defined by this protocol version\",\n      \
         );\n  \
         }}\n\
         }}\n"
    );
}

/// Emit a whole command surface.
fn emit_command_surface(out: &mut String, surface: &CommandSurface) {
    let _ = writeln!(
        out,
        "\n/** The only major version of this protocol these helpers speak. */"
    );
    let _ = writeln!(
        out,
        "export const {} = {};",
        version_constant(surface),
        surface.version
    );

    let mut categories = surface.categories.clone();
    categories.sort_by(|left, right| left.name.cmp(&right.name));
    for constant in &categories {
        emit_constant(out, constant);
    }

    // Before the objects that carry them, which are themselves before the
    // messages: a batch row names the concurrency decoder, so a reader
    // following the file top to bottom meets each declaration before its use.
    let mut discriminated = surface.discriminated_bodies.clone();
    discriminated.sort_by(|left, right| left.name.cmp(&right.name));
    for body in &discriminated {
        emit_discriminated_body(out, body);
    }

    // Before the messages that carry them: a response decoder names its nested
    // decoders, and a reader following the file top to bottom meets each one
    // where it is defined rather than where it is used.
    let mut objects = surface.body_objects.clone();
    objects.sort_by(|left, right| left.name.cmp(&right.name));
    let request_object_types = request_body_object_types(surface);
    for object in &objects {
        emit_body_object(
            out,
            &surface.invalid_body_category,
            object,
            request_object_types.contains(&object.name),
        );
    }

    if !surface.requests.is_empty() {
        emit_request_encoder(out, surface);
        let mut requests = surface.requests.clone();
        requests.sort();
        for request in &requests {
            emit_request(out, surface, request);
        }
        emit_name_list(
            out,
            &format!(
                "{}_REQUEST_KINDS_NOT_GENERATED",
                surface.name.to_uppercase()
            ),
            "Command kinds this protocol version defines that no builder above \
             produces. A client needing one of these builds it by hand or waits \
             for the generator to describe it.",
            &surface.request_kinds_not_generated,
        );
        emit_correlated_request_surface(out, surface);
    }

    if !surface.responses.is_empty() {
        let mut responses = surface.responses.clone();
        responses.sort();
        for response in &responses {
            emit_response(out, surface, response);
        }
        emit_response_dispatch(out, surface);
    }
}

/// Emit the cross-field validators and standalone canonical codecs for the
/// Platform v2 work-context contract. These are generator-owned code, not an
/// SDK redefinition: the vocabularies and bounds above come from Rust and the
/// emitted implementation re-applies the same constructors and relations.
fn emit_work_context_implementation(out: &mut String) {
    out.push_str(
        r#"

const WORK_CONTEXT_INVALID_BODY = "work_context_invalid_body";
const WORK_CONTEXT_VALUE_INVALID = "work_context_value_invalid";
const WORK_CONTEXT_COUNTER_OUT_OF_RANGE = "work_context_counter_out_of_range";

function workContextRefusal(detail: string): never {
  throw new RefusalError(WORK_CONTEXT_VALUE_INVALID, detail);
}

function workContextWireUnsigned(value: bigint, maximum: bigint, field: string): bigint {
  if (value < 0n || value > maximum) {
    throw new RefusalError(WORK_CONTEXT_COUNTER_OUT_OF_RANGE, `${field} is outside its wire range`);
  }
  return value;
}

function object(entries: readonly (readonly [string, JsonValue])[]): JsonValue {
  return {kind: "object", entries};
}

function exactInput(value: object, fields: readonly string[]): void {
  exactInputFields(value as Readonly<Record<string, unknown>>, fields, WORK_CONTEXT_INVALID_BODY);
}

function parseDocument(payload: Uint8Array, maximum: number): JsonValue {
  if (payload.length > maximum) {
    throw new RefusalError("frame_too_large", `canonical document is ${payload.length} bytes; maximum is ${maximum}`);
  }
  return parseCanonical(payload);
}

function objectKind(value: JsonValue): string {
  if (value.kind !== "object") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "identity is not an object");
  const fields = new Map<string, JsonValue>();
  for (const [key, entry] of value.entries) {
    if (fields.has(key)) throw new RefusalError(WORK_CONTEXT_INVALID_BODY, `duplicate field ${key}`);
    fields.set(key, entry);
  }
  const kind = fields.get("kind");
  if (kind?.kind !== "string") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "kind is not a string");
  return kind.value;
}

function orderIndex(order: readonly string[], value: string): number {
  const index = order.indexOf(value);
  if (index < 0) workContextRefusal(`undefined ordering value ${value}`);
  return index;
}

// Rust String::cmp compares UTF-8 bytes. JavaScript's relational operators
// compare UTF-16 code units, which disagrees for some BMP/non-BMP pairs.
const WORK_CONTEXT_UTF8_ENCODER = new TextEncoder();

function compareUtf8(left: string, right: string): number {
  const leftBytes = WORK_CONTEXT_UTF8_ENCODER.encode(left);
  const rightBytes = WORK_CONTEXT_UTF8_ENCODER.encode(right);
  const shared = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function strictlyOrdered<T>(values: readonly T[], key: (value: T) => string): boolean {
  return values.every((value, index) => index === 0 || compareUtf8(key(values[index - 1]!), key(value)) < 0);
}

function validateV1Coordinate(value: ResourceCoordinate, expected: "repository" | "session"): ResourceCoordinate {
  exactInput(value, ["authority", "id", "kind"]);
  const authority = decodeResourceAuthority(value.authority);
  const kind = decodeResourceKind(value.kind);
  const id = ResourceId(value.id);
  if (kind !== expected) workContextRefusal(`v1 relation target must be ${expected}`);
  return {authority, id, kind};
}

function decodeV1Coordinate(value: JsonValue, expected: "repository" | "session"): ResourceCoordinate {
  const fields = exactFields(value, ["authority", "id", "kind"], WORK_CONTEXT_INVALID_BODY);
  return validateV1Coordinate({
    authority: decodeResourceAuthority(bodyString(fields, "authority", WORK_CONTEXT_INVALID_BODY)),
    id: ResourceId(bodyString(fields, "id", WORK_CONTEXT_INVALID_BODY)),
    kind: decodeResourceKind(bodyString(fields, "kind", WORK_CONTEXT_INVALID_BODY)),
  }, expected);
}

function v1CoordinateJson(value: ResourceCoordinate): JsonValue {
  return object([
    ["authority", {kind: "string", value: value.authority}],
    ["id", {kind: "string", value: value.id}],
    ["kind", {kind: "string", value: value.kind}],
  ]);
}

export function validateWorkContextIdentity(value: WorkContextIdentity): WorkContextIdentity {
  switch (value.kind) {
    case "attempt_workspace": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: AttemptWorkspaceId(value.id)};
    case "checkout": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: CheckoutId(value.id)};
    case "host_setup": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: HostSetupId(value.id)};
    case "pane": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: PaneId(value.id)};
    case "project": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: ProjectId(value.id)};
    case "session": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: WorkSessionId(value.id)};
    case "user_workspace": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: UserWorkspaceId(value.id)};
    case "repository": exactInput(value, ["kind", "resource"]); return {kind: value.kind, resource: validateV1Coordinate(value.resource, "repository")};
    case "platform_session": exactInput(value, ["kind", "resource"]); return {kind: value.kind, resource: validateV1Coordinate(value.resource, "session")};
    default: return assertNeverWorkContextIdentity(value);
  }
}

function decodeWorkContextIdentityValue(value: JsonValue): WorkContextIdentity {
  const kind = decodeWorkContextTargetKind(objectKind(value));
  if (kind === "repository" || kind === "platform_session") {
    const fields = exactFields(value, ["kind", "resource"], WORK_CONTEXT_INVALID_BODY);
    return validateWorkContextIdentity({
      kind,
      resource: decodeV1Coordinate(bodyValue(fields, "resource", WORK_CONTEXT_INVALID_BODY), kind === "repository" ? "repository" : "session"),
    });
  }
  const fields = exactFields(value, ["id", "kind"], WORK_CONTEXT_INVALID_BODY);
  const id = bodyString(fields, "id", WORK_CONTEXT_INVALID_BODY);
  switch (kind) {
    case "attempt_workspace": return {kind, id: AttemptWorkspaceId(id)};
    case "checkout": return {kind, id: CheckoutId(id)};
    case "host_setup": return {kind, id: HostSetupId(id)};
    case "pane": return {kind, id: PaneId(id)};
    case "project": return {kind, id: ProjectId(id)};
    case "session": return {kind, id: WorkSessionId(id)};
    case "user_workspace": return {kind, id: UserWorkspaceId(id)};
    default: workContextRefusal(`relation-only identity ${kind} was decoded without a coordinate`);
  }
}

function workContextIdentityJson(value: WorkContextIdentity): JsonValue {
  const identity = validateWorkContextIdentity(value);
  if (identity.kind === "repository" || identity.kind === "platform_session") {
    return object([
      ["kind", {kind: "string", value: identity.kind}],
      ["resource", v1CoordinateJson(identity.resource)],
    ]);
  }
  return object([
    ["id", {kind: "string", value: identity.id}],
    ["kind", {kind: "string", value: identity.kind}],
  ]);
}

function identityOrderKey(identity: WorkContextIdentity): string {
  const target = orderIndex(WORK_CONTEXT_TARGET_KIND_WIRE_ORDER, identity.kind).toString().padStart(2, "0");
  if (identity.kind === "repository" || identity.kind === "platform_session") {
    return `${target}\0${orderIndex(V1_RESOURCE_AUTHORITY_WIRE_ORDER, identity.resource.authority).toString().padStart(2, "0")}\0${orderIndex(V1_RESOURCE_KIND_WIRE_ORDER, identity.resource.kind).toString().padStart(2, "0")}\0${identity.resource.id}`;
  }
  return `${target}\0${identity.id}`;
}

function relationSource(kind: WorkContextRelationKind): WorkContextKind {
  switch (kind) {
    case "project_repository": return "project";
    case "host_setup_project": return "host_setup";
    case "checkout_project":
    case "checkout_host_setup":
    case "checkout_repository": return "checkout";
    case "user_workspace_project":
    case "user_workspace_checkout": return "user_workspace";
    case "attempt_user_workspace": return "attempt_workspace";
    case "session_attempt_workspace":
    case "session_platform_session": return "session";
    case "pane_session": return "pane";
  }
}

function relationTarget(kind: WorkContextRelationKind): WorkContextTargetKind {
  switch (kind) {
    case "project_repository":
    case "checkout_repository": return "repository";
    case "host_setup_project":
    case "checkout_project":
    case "user_workspace_project": return "project";
    case "checkout_host_setup": return "host_setup";
    case "user_workspace_checkout": return "checkout";
    case "attempt_user_workspace": return "user_workspace";
    case "session_attempt_workspace": return "attempt_workspace";
    case "session_platform_session": return "platform_session";
    case "pane_session": return "session";
  }
}

export function validateWorkContextRelation(value: WorkContextRelation): WorkContextRelation {
  exactInput(value, ["kind", "target"]);
  const kind = decodeWorkContextRelationKind(value.kind);
  const target = validateWorkContextIdentity(value.target);
  if (target.kind !== relationTarget(kind)) workContextRefusal("relation target kind is invalid");
  return {kind, target};
}

function decodeWorkContextRelationValue(value: JsonValue): WorkContextRelation {
  const fields = exactFields(value, ["kind", "target"], WORK_CONTEXT_INVALID_BODY);
  return validateWorkContextRelation({
    kind: decodeWorkContextRelationKind(bodyString(fields, "kind", WORK_CONTEXT_INVALID_BODY)),
    target: decodeWorkContextIdentityValue(bodyValue(fields, "target", WORK_CONTEXT_INVALID_BODY)),
  });
}

function relationJson(value: WorkContextRelation): JsonValue {
  const relation = validateWorkContextRelation(value);
  return object([
    ["kind", {kind: "string", value: relation.kind}],
    ["target", workContextIdentityJson(relation.target)],
  ]);
}

function relationOrderKey(value: WorkContextRelation): string {
  return `${orderIndex(WORK_CONTEXT_RELATION_KIND_WIRE_ORDER, value.kind).toString().padStart(2, "0")}\0${identityOrderKey(value.target)}`;
}

function validateWorkContextAttributes(value: WorkContextAttributes): WorkContextAttributes {
  exactInput(value, ["checkout", "host_setup"]);
  const checkout = value.checkout === null ? null : decodeCheckoutKind(value.checkout);
  const host_setup = value.host_setup === null ? null : decodeHostSetupKind(value.host_setup);
  if (checkout !== null && host_setup !== null) workContextRefusal("work-context attributes name two kinds");
  return {checkout, host_setup};
}

function decodeWorkContextAttributes(value: JsonValue): WorkContextAttributes {
  const fields = exactFields(value, ["checkout", "host_setup"], WORK_CONTEXT_INVALID_BODY);
  const checkout = bodyStringOrNull(fields, "checkout", WORK_CONTEXT_INVALID_BODY);
  const host_setup = bodyStringOrNull(fields, "host_setup", WORK_CONTEXT_INVALID_BODY);
  return validateWorkContextAttributes({
    checkout: checkout === null ? null : decodeCheckoutKind(checkout),
    host_setup: host_setup === null ? null : decodeHostSetupKind(host_setup),
  });
}

function attributesJson(value: WorkContextAttributes): JsonValue {
  const attributes = validateWorkContextAttributes(value);
  return object([
    ["checkout", attributes.checkout === null ? {kind: "null"} : {kind: "string", value: attributes.checkout}],
    ["host_setup", attributes.host_setup === null ? {kind: "null"} : {kind: "string", value: attributes.host_setup}],
  ]);
}

function lifecycleAllowed(kind: WorkContextKind, lifecycle: WorkContextLifecycle): boolean {
  switch (kind) {
    case "project":
    case "host_setup":
    case "checkout":
    case "user_workspace": return lifecycle === "active" || lifecycle === "archived";
    case "attempt_workspace": return ["preparing", "running", "hibernated", "completed", "failed", "cancelled"].includes(lifecycle);
    case "session": return ["active", "hibernated", "completed", "failed", "cancelled"].includes(lifecycle);
    case "pane": return lifecycle === "active" || lifecycle === "closed";
  }
}

function requiredRelations(kind: WorkContextKind): readonly WorkContextRelationKind[] {
  switch (kind) {
    case "project": return [];
    case "host_setup": return ["host_setup_project"];
    case "checkout": return ["checkout_project", "checkout_host_setup", "checkout_repository"];
    case "user_workspace": return ["user_workspace_project", "user_workspace_checkout"];
    case "attempt_workspace": return ["attempt_user_workspace"];
    case "session": return ["session_attempt_workspace", "session_platform_session"];
    case "pane": return ["pane_session"];
  }
}

export function validateWorkContextRecord(value: WorkContextRecord): WorkContextRecord {
  exactInput(value, ["attributes", "identity", "label", "lifecycle", "relations", "revision"]);
  const identity = validateWorkContextIdentity(value.identity);
  if (identity.kind === "repository" || identity.kind === "platform_session") workContextRefusal("relation-only identity cannot be a record");
  const kind = decodeWorkContextKind(identity.kind);
  const lifecycle = decodeWorkContextLifecycle(value.lifecycle);
  if (!lifecycleAllowed(kind, lifecycle)) workContextRefusal("lifecycle is invalid for work-context kind");
  const label = WorkContextLabel(value.label);
  const revision = WorkContextRevision(value.revision);
  const attributes = validateWorkContextAttributes(value.attributes);
  if (kind === "host_setup") {
    if (attributes.host_setup === null || attributes.checkout !== null) workContextRefusal("host setup attributes are invalid");
  } else if (kind === "checkout") {
    if (attributes.checkout === null || attributes.host_setup !== null) workContextRefusal("checkout attributes are invalid");
  } else if (attributes.checkout !== null || attributes.host_setup !== null) {
    workContextRefusal("attributes are invalid for work-context kind");
  }
  if (!Array.isArray(value.relations) || value.relations.length > MAX_WORK_CONTEXT_RELATIONS) workContextRefusal("work-context relation limit exceeded");
  const relations = value.relations.map(validateWorkContextRelation);
  if (!strictlyOrdered(relations, relationOrderKey)) workContextRefusal("work-context relations are duplicated or unordered");
  if (relations.some((relation) => relationSource(relation.kind) !== kind)) workContextRefusal("relation source kind is invalid");
  const required = requiredRelations(kind);
  for (const relationKind of WORK_CONTEXT_RELATION_KIND_WIRE_ORDER) {
    const count = relations.filter((relation) => relation.kind === relationKind).length;
    if (kind === "project" && relationKind === "project_repository") continue;
    if (required.includes(relationKind as WorkContextRelationKind)) {
      if (count !== 1) workContextRefusal("required relation is missing or repeated");
    } else if (count !== 0) {
      workContextRefusal("relation is invalid for source kind");
    }
  }
  return {attributes, identity, label, lifecycle, relations, revision};
}

function decodeWorkContextRecordValue(value: JsonValue): WorkContextRecord {
  const fields = exactFields(value, WorkContextRecord_FIELDS, WORK_CONTEXT_INVALID_BODY);
  return validateWorkContextRecord({
    attributes: decodeWorkContextAttributes(bodyValue(fields, "attributes", WORK_CONTEXT_INVALID_BODY)),
    identity: decodeWorkContextIdentityValue(bodyValue(fields, "identity", WORK_CONTEXT_INVALID_BODY)),
    label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)),
    lifecycle: decodeWorkContextLifecycle(bodyString(fields, "lifecycle", WORK_CONTEXT_INVALID_BODY)),
    relations: bodyArray(fields, "relations", WORK_CONTEXT_INVALID_BODY, MAX_WORK_CONTEXT_RELATIONS, WORK_CONTEXT_VALUE_INVALID).map(decodeWorkContextRelationValue),
    revision: WorkContextRevision(workContextWireUnsigned(bodyInteger(fields, "revision", WORK_CONTEXT_INVALID_BODY), WorkContextRevision_MAX, "revision")),
  });
}

function recordJson(value: WorkContextRecord): JsonValue {
  const record = validateWorkContextRecord(value);
  return object([
    ["attributes", attributesJson(record.attributes)],
    ["identity", workContextIdentityJson(record.identity)],
    ["label", {kind: "string", value: record.label}],
    ["lifecycle", {kind: "string", value: record.lifecycle}],
    ["relations", {kind: "array", items: record.relations.map(relationJson)}],
    ["revision", {kind: "integer", value: record.revision}],
  ]);
}

function strictEnumOrder(values: readonly string[], order: readonly string[]): boolean {
  return strictlyOrdered(values, (value) => orderIndex(order, value).toString().padStart(2, "0"));
}

export function validatePlatformVersionOffer(value: PlatformVersionOffer): PlatformVersionOffer {
  exactInput(value, PlatformVersionOffer_FIELDS);
  if (value.schema !== PLATFORM_NEGOTIATION_SCHEMA_V1) workContextRefusal("negotiation schema is incompatible");
  if (!Array.isArray(value.versions) || value.versions.length === 0 || value.versions.length > MAX_PLATFORM_VERSION_OFFERS) workContextRefusal("platform version offer is invalid");
  const versions = value.versions.map(PlatformVersionNumber);
  if (!versions.every((version, index) => index === 0 || versions[index - 1]! < version)) workContextRefusal("platform versions are repeated or unordered");
  return {schema: PLATFORM_NEGOTIATION_SCHEMA_V1, versions};
}

export function encodePlatformVersionOffer(value: PlatformVersionOffer): Uint8Array {
  const offer = validatePlatformVersionOffer(value);
  const bytes = toCanonicalBytes(object([
    ["schema", {kind: "string", value: offer.schema}],
    ["versions", {kind: "array", items: offer.versions.map((version) => ({kind: "integer", value: version}))}],
  ]));
  if (bytes.length > MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES) throw new RefusalError("frame_too_large", "negotiation document exceeds its ceiling");
  return bytes;
}

export function decodePlatformVersionOffer(payload: Uint8Array): PlatformVersionOffer {
  return refuse(WORK_CONTEXT_VALUE_INVALID, () => {
    const fields = exactFields(parseDocument(payload, MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES), PlatformVersionOffer_FIELDS, WORK_CONTEXT_INVALID_BODY);
    const schema = bodyString(fields, "schema", WORK_CONTEXT_INVALID_BODY);
    const versions = bodyArray(fields, "versions", WORK_CONTEXT_INVALID_BODY, MAX_PLATFORM_VERSION_OFFERS, WORK_CONTEXT_VALUE_INVALID).map((value) => {
      if (value.kind !== "integer") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "version is not an integer");
      return PlatformVersionNumber(workContextWireUnsigned(value.value, BigInt(MAX_PLATFORM_VERSION_NUMBER), "versions"));
    });
    return validatePlatformVersionOffer({schema: schema as typeof PLATFORM_NEGOTIATION_SCHEMA_V1, versions});
  });
}

export function validateNegotiatedPlatform(value: NegotiatedPlatform): NegotiatedPlatform {
  exactInput(value, NegotiatedPlatform_FIELDS);
  const version = SupportedPlatformVersionNumber(value.version);
  const work_context = decodeWorkContextAvailability(value.work_context);
  if (version === 1n) {
    if (value.schema !== PLATFORM_SCHEMA_V1 || work_context !== "v1_existing_resources_only") workContextRefusal("v1 negotiation result is incoherent");
    return {schema: PLATFORM_SCHEMA_V1, version, work_context};
  }
  if (version === 2n) {
    if (value.schema !== PLATFORM_SCHEMA_V2 || work_context !== "v2_structured") workContextRefusal("v2 negotiation result is incoherent");
    return {schema: PLATFORM_SCHEMA_V2, version, work_context};
  }
  workContextRefusal("selected platform version has no known schema");
}

export function encodeNegotiatedPlatform(value: NegotiatedPlatform): Uint8Array {
  const negotiated = validateNegotiatedPlatform(value);
  return toCanonicalBytes(object([
    ["schema", {kind: "string", value: negotiated.schema}],
    ["version", {kind: "integer", value: negotiated.version}],
    ["work_context", {kind: "string", value: negotiated.work_context}],
  ]));
}

export function decodeNegotiatedPlatform(payload: Uint8Array): NegotiatedPlatform {
  return refuse(WORK_CONTEXT_VALUE_INVALID, () => {
    const fields = exactFields(parseDocument(payload, MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES), NegotiatedPlatform_FIELDS, WORK_CONTEXT_INVALID_BODY);
    return validateNegotiatedPlatform({
      schema: bodyString(fields, "schema", WORK_CONTEXT_INVALID_BODY) as NegotiatedPlatform["schema"],
      version: SupportedPlatformVersionNumber(workContextWireUnsigned(bodyInteger(fields, "version", WORK_CONTEXT_INVALID_BODY), BigInt(MAX_PLATFORM_VERSION_NUMBER), "version")),
      work_context: decodeWorkContextAvailability(bodyString(fields, "work_context", WORK_CONTEXT_INVALID_BODY)),
    });
  });
}

export function negotiatePlatformVersion(clientValue: PlatformVersionOffer, serverValue: PlatformVersionOffer): NegotiatedPlatform {
  const client = validatePlatformVersionOffer(clientValue);
  const server = validatePlatformVersionOffer(serverValue);
  const version = [...client.versions].reverse().find((candidate) => candidate <= BigInt(MAX_PLATFORM_VERSION) && server.versions.includes(candidate));
  if (version === undefined) workContextRefusal("platform versions do not overlap");
  const selected = SupportedPlatformVersionNumber(version);
  return selected === 2n
    ? {schema: PLATFORM_SCHEMA_V2, version: selected, work_context: "v2_structured"}
    : {schema: PLATFORM_SCHEMA_V1, version: selected, work_context: "v1_existing_resources_only"};
}

export function verifyPlatformNegotiationTranscript(
  client: PlatformVersionOffer,
  server: PlatformVersionOffer,
  resultValue: NegotiatedPlatform,
): NegotiatedPlatform {
  const expected = negotiatePlatformVersion(client, server);
  const result = validateNegotiatedPlatform(resultValue);
  if (result.version !== expected.version || result.schema !== expected.schema || result.work_context !== expected.work_context) {
    workContextRefusal("negotiation result is not the highest common platform version");
  }
  return result;
}

export function validateWorkContextQuery(value: WorkContextQuery): WorkContextQuery {
  exactInput(value, WorkContextQuery_FIELDS);
  if (value.schema !== PLATFORM_SCHEMA_V2) workContextRefusal("work-context query schema is incompatible");
  if (!Array.isArray(value.kinds) || value.kinds.length === 0 || value.kinds.length > WORK_CONTEXT_KIND_WIRE_ORDER.length) workContextRefusal("work-context query kinds are invalid");
  const kinds = value.kinds.map(decodeWorkContextKind);
  if (!strictEnumOrder(kinds, WORK_CONTEXT_KIND_WIRE_ORDER)) workContextRefusal("work-context query kinds are repeated or unordered");
  if (!Array.isArray(value.lifecycles) || value.lifecycles.length > WORK_CONTEXT_LIFECYCLE_WIRE_ORDER.length) workContextRefusal("work-context lifecycle filters are invalid");
  const lifecycles = value.lifecycles.map(decodeWorkContextLifecycle);
  if (lifecycles.length > 0 && !strictEnumOrder(lifecycles, WORK_CONTEXT_LIFECYCLE_WIRE_ORDER)) workContextRefusal("work-context lifecycle filters are repeated or unordered");
  const after = value.after === null ? null : WorkContextCursor(value.after);
  const parent = value.parent === null ? null : validateWorkContextIdentity(value.parent);
  const project = value.project === null ? null : ProjectId(value.project);
  const limit = WorkContextPageLimit(value.limit);
  return {after, kinds, lifecycles, limit, parent, project, schema: PLATFORM_SCHEMA_V2};
}

function queryJson(value: WorkContextQuery): JsonValue {
  const query = validateWorkContextQuery(value);
  return object([
    ["after", query.after === null ? {kind: "null"} : {kind: "string", value: query.after}],
    ["kinds", {kind: "array", items: query.kinds.map((kind) => ({kind: "string", value: kind}))}],
    ["lifecycles", {kind: "array", items: query.lifecycles.map((lifecycle) => ({kind: "string", value: lifecycle}))}],
    ["limit", {kind: "integer", value: query.limit}],
    ["parent", query.parent === null ? {kind: "null"} : workContextIdentityJson(query.parent)],
    ["project", query.project === null ? {kind: "null"} : {kind: "string", value: query.project}],
    ["schema", {kind: "string", value: query.schema}],
  ]);
}

export function encodeWorkContextQuery(value: WorkContextQuery): Uint8Array {
  const bytes = toCanonicalBytes(queryJson(value));
  if (bytes.length > MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES) throw new RefusalError("frame_too_large", "work-context query exceeds its ceiling");
  return bytes;
}

export function decodeWorkContextQuery(payload: Uint8Array): WorkContextQuery {
  return refuse(WORK_CONTEXT_VALUE_INVALID, () => {
    const fields = exactFields(parseDocument(payload, MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES), WorkContextQuery_FIELDS, WORK_CONTEXT_INVALID_BODY);
    const after = bodyStringOrNull(fields, "after", WORK_CONTEXT_INVALID_BODY);
    const project = bodyStringOrNull(fields, "project", WORK_CONTEXT_INVALID_BODY);
    return validateWorkContextQuery({
      after: after === null ? null : WorkContextCursor(after),
      kinds: bodyArray(fields, "kinds", WORK_CONTEXT_INVALID_BODY, WORK_CONTEXT_KIND_WIRE_ORDER.length, WORK_CONTEXT_VALUE_INVALID).map((value) => {
        if (value.kind !== "string") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "kind filter is not a string");
        return decodeWorkContextKind(value.value);
      }),
      lifecycles: bodyArray(fields, "lifecycles", WORK_CONTEXT_INVALID_BODY, WORK_CONTEXT_LIFECYCLE_WIRE_ORDER.length, WORK_CONTEXT_VALUE_INVALID).map((value) => {
        if (value.kind !== "string") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "lifecycle filter is not a string");
        return decodeWorkContextLifecycle(value.value);
      }),
      limit: WorkContextPageLimit(workContextWireUnsigned(bodyInteger(fields, "limit", WORK_CONTEXT_INVALID_BODY), BigInt(MAX_PLATFORM_VERSION_NUMBER), "limit")),
      parent: bodyValueOrNull(fields, "parent", WORK_CONTEXT_INVALID_BODY) === null ? null : decodeWorkContextIdentityValue(bodyValue(fields, "parent", WORK_CONTEXT_INVALID_BODY)),
      project: project === null ? null : ProjectId(project),
      schema: bodyString(fields, "schema", WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2,
    });
  });
}

export function validateWorkContextPage(value: WorkContextPage): WorkContextPage {
  exactInput(value, WorkContextPage_FIELDS);
  if (value.schema !== PLATFORM_SCHEMA_V2) workContextRefusal("work-context page schema is incompatible");
  const requested_limit = WorkContextPageLimit(value.requested_limit);
  if (!Array.isArray(value.items) || BigInt(value.items.length) > requested_limit) workContextRefusal("work-context page exceeds its requested limit");
  const items = value.items.map(validateWorkContextRecord);
  if (!strictlyOrdered(items, (record) => identityOrderKey(record.identity))) workContextRefusal("work-context page identities are repeated or unordered");
  const after = value.after === null ? null : WorkContextCursor(value.after);
  const next_cursor = value.next_cursor === null ? null : WorkContextCursor(value.next_cursor);
  if (typeof value.has_more !== "boolean") workContextRefusal("has_more is not boolean");
  if (value.has_more !== (next_cursor !== null) || (value.has_more && items.length === 0) || (after !== null && after === next_cursor)) workContextRefusal("work-context page cursor is incoherent");
  return {after, has_more: value.has_more, items, next_cursor, requested_limit, schema: PLATFORM_SCHEMA_V2};
}

function pageJson(value: WorkContextPage): JsonValue {
  const page = validateWorkContextPage(value);
  return object([
    ["after", page.after === null ? {kind: "null"} : {kind: "string", value: page.after}],
    ["has_more", {kind: "bool", value: page.has_more}],
    ["items", {kind: "array", items: page.items.map(recordJson)}],
    ["next_cursor", page.next_cursor === null ? {kind: "null"} : {kind: "string", value: page.next_cursor}],
    ["requested_limit", {kind: "integer", value: page.requested_limit}],
    ["schema", {kind: "string", value: page.schema}],
  ]);
}

export function encodeWorkContextPage(value: WorkContextPage): Uint8Array {
  const bytes = toCanonicalBytes(pageJson(value));
  if (bytes.length > MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES) throw new RefusalError("frame_too_large", "work-context page exceeds its ceiling");
  return bytes;
}

export function decodeWorkContextPage(payload: Uint8Array): WorkContextPage {
  return refuse(WORK_CONTEXT_VALUE_INVALID, () => {
    const fields = exactFields(parseDocument(payload, MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES), WorkContextPage_FIELDS, WORK_CONTEXT_INVALID_BODY);
    const after = bodyStringOrNull(fields, "after", WORK_CONTEXT_INVALID_BODY);
    const next = bodyStringOrNull(fields, "next_cursor", WORK_CONTEXT_INVALID_BODY);
    return validateWorkContextPage({
      after: after === null ? null : WorkContextCursor(after),
      has_more: bodyBool(fields, "has_more", WORK_CONTEXT_INVALID_BODY),
      items: bodyArray(fields, "items", WORK_CONTEXT_INVALID_BODY, MAX_WORK_CONTEXT_PAGE_ITEMS, WORK_CONTEXT_VALUE_INVALID).map(decodeWorkContextRecordValue),
      next_cursor: next === null ? null : WorkContextCursor(next),
      requested_limit: WorkContextPageLimit(workContextWireUnsigned(bodyInteger(fields, "requested_limit", WORK_CONTEXT_INVALID_BODY), BigInt(MAX_PLATFORM_VERSION_NUMBER), "requested_limit")),
      schema: bodyString(fields, "schema", WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2,
    });
  });
}

export function validateWorkContextResync(value: WorkContextResync): WorkContextResync {
  exactInput(value, WorkContextResync_FIELDS);
  if (value.outcome !== "resync_required" || value.schema !== PLATFORM_SCHEMA_V2) workContextRefusal("work-context resync outcome is incompatible");
  return {expired_after: WorkContextCursor(value.expired_after), outcome: "resync_required", schema: PLATFORM_SCHEMA_V2};
}

export function encodeWorkContextResync(value: WorkContextResync): Uint8Array {
  const resync = validateWorkContextResync(value);
  return toCanonicalBytes(object([
    ["expired_after", {kind: "string", value: resync.expired_after}],
    ["outcome", {kind: "string", value: resync.outcome}],
    ["schema", {kind: "string", value: resync.schema}],
  ]));
}

export function decodeWorkContextResync(payload: Uint8Array): WorkContextResync {
  return refuse(WORK_CONTEXT_VALUE_INVALID, () => {
    const fields = exactFields(parseDocument(payload, MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES), WorkContextResync_FIELDS, WORK_CONTEXT_INVALID_BODY);
    return validateWorkContextResync({
      expired_after: WorkContextCursor(bodyString(fields, "expired_after", WORK_CONTEXT_INVALID_BODY)),
      outcome: bodyString(fields, "outcome", WORK_CONTEXT_INVALID_BODY) as "resync_required",
      schema: bodyString(fields, "schema", WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2,
    });
  });
}

function sameExternalWorkIdentity(left: ExternalWorkIdentity, right: ExternalWorkIdentity): boolean {
  return left.provider === right.provider && left.authority === right.authority && left.scope === right.scope && left.key === right.key;
}

function sameOrchestrationIdentity(left: OrchestrationIdentity, right: OrchestrationIdentity): boolean {
  return left.kind === right.kind && left.id === right.id;
}

function compareText(left: string, right: string): number {
  return compareUtf8(left, right);
}

function compareExternalWorkIdentity(left: ExternalWorkIdentity, right: ExternalWorkIdentity): number {
  return compareText(left.provider, right.provider)
    || compareText(left.authority, right.authority)
    || compareText(left.scope, right.scope)
    || compareText(left.key, right.key);
}

function compareOrchestrationIdentity(left: OrchestrationIdentity, right: OrchestrationIdentity): number {
  return compareText(left.kind, right.kind) || compareText(left.id, right.id);
}

export function validateExternalWorkIdentity(value: ExternalWorkIdentity): ExternalWorkIdentity {
  exactInput(value, ExternalWorkIdentity_FIELDS);
  return {
    authority: ExternalWorkAuthorityId(value.authority),
    key: ExternalWorkKey(value.key),
    provider: decodeExternalWorkProvider(value.provider),
    scope: ExternalWorkScope(value.scope),
  };
}

export function validateLineageOrigin(value: LineageOrigin): LineageOrigin {
  exactInput(value, LineageOrigin_FIELDS);
  const attempt = value.attempt === null ? null : AttemptWorkspaceId(value.attempt);
  const session = value.session === null ? null : WorkSessionId(value.session);
  const pane = value.pane === null ? null : PaneId(value.pane);
  if ((session !== null && attempt === null) || (pane !== null && session === null)) workContextRefusal("lineage origin is invalid");
  return {attempt, pane, session, workspace: UserWorkspaceId(value.workspace)};
}

function originRefines(value: LineageOrigin, parent: LineageOrigin): boolean {
  return value.workspace === parent.workspace
    && (parent.attempt === null || value.attempt === parent.attempt)
    && (parent.session === null || value.session === parent.session)
    && (parent.pane === null || value.pane === parent.pane);
}

export function validateLatestUsefulMessage(value: LatestUsefulMessage): LatestUsefulMessage {
  exactInput(value, LatestUsefulMessage_FIELDS);
  return {observed_at_ms: LineageObservedAtMs(workContextWireUnsigned(value.observed_at_ms, LineageObservedAtMs_MAX, "observed_at_ms")), text: LineageMessage(value.text)};
}

export function validateLineageFreshness(value: LineageFreshness): LineageFreshness {
  exactInput(value, LineageFreshness_FIELDS);
  return {
    observed_at_ms: LineageObservedAtMs(workContextWireUnsigned(value.observed_at_ms, LineageObservedAtMs_MAX, "observed_at_ms")),
    stale_after_ms: LineageStaleAfterMs(workContextWireUnsigned(value.stale_after_ms, LineageStaleAfterMs_MAX, "stale_after_ms")),
    state: decodeLineageFreshnessState(value.state),
  };
}

export function validateLineageStatus(value: LineageStatus): LineageStatus {
  switch (value.kind) {
    case "blocked": exactInput(value, ["kind", "reason"]); return {kind: value.kind, reason: LineageMessage(value.reason)};
    case "done": exactInput(value, ["kind", "outcome"]); return {kind: value.kind, outcome: LineageMessage(value.outcome)};
    case "waiting": exactInput(value, ["kind", "reason"]); return {kind: value.kind, reason: LineageMessage(value.reason)};
    case "working": exactInput(value, ["kind"]); return {kind: value.kind};
    default: return assertNeverLineageStatus(value);
  }
}

export function validateOrchestrationIdentity(value: OrchestrationIdentity): OrchestrationIdentity {
  switch (value.kind) {
    case "decision_gate": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationDecisionGateId(value.id)};
    case "dispatch": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationDispatchId(value.id)};
    case "heartbeat": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationHeartbeatId(value.id)};
    case "question": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationQuestionId(value.id)};
    case "run": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationRunId(value.id)};
    case "task": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationTaskId(value.id)};
    case "worker": exactInput(value, ["id", "kind"]); return {kind: value.kind, id: OrchestrationWorkerId(value.id)};
    default: return assertNeverOrchestrationIdentity(value);
  }
}

function orchestrationParentAllowed(identity: OrchestrationIdentity, parent: OrchestrationIdentity | null): boolean {
  switch (identity.kind) {
    case "run": return parent === null;
    case "task": return parent?.kind === "run" || parent?.kind === "task";
    case "dispatch": return parent?.kind === "task";
    case "worker": return parent?.kind === "dispatch";
    case "heartbeat": return parent?.kind === "worker";
    case "question": return parent?.kind === "task";
    case "decision_gate": return parent?.kind === "question" || parent?.kind === "task";
    default: return assertNeverOrchestrationIdentity(identity);
  }
}

export function validateExternalWorkItem(value: ExternalWorkItem): ExternalWorkItem {
  exactInput(value, ExternalWorkItem_FIELDS);
  const identity = validateExternalWorkIdentity(value.identity);
  const moved_to = value.moved_to === null ? null : validateExternalWorkIdentity(value.moved_to);
  const state = decodeExternalWorkState(value.state);
  const freshness = validateLineageFreshness(value.freshness);
  const latest = value.latest_useful_message === null ? null : validateLatestUsefulMessage(value.latest_useful_message);
  if ((state === "moved") !== (moved_to !== null) || (moved_to !== null && sameExternalWorkIdentity(identity, moved_to))
      || (latest !== null && latest.observed_at_ms > freshness.observed_at_ms)) {
    workContextRefusal("external work transition is invalid");
  }
  return {
    freshness,
    identity,
    latest_useful_message: latest,
    moved_to,
    origin: validateLineageOrigin(value.origin),
    revision: WorkContextRevision(workContextWireUnsigned(value.revision, WorkContextRevision_MAX, "revision")),
    state,
    workspace: UserWorkspaceId(value.workspace),
  };
}

export function validateOrchestrationRecord(value: OrchestrationRecord): OrchestrationRecord {
  exactInput(value, OrchestrationRecord_FIELDS);
  const identity = validateOrchestrationIdentity(value.identity);
  const parent = value.parent === null ? null : validateOrchestrationIdentity(value.parent);
  const freshness = validateLineageFreshness(value.freshness);
  const latest = value.latest_useful_message === null ? null : validateLatestUsefulMessage(value.latest_useful_message);
  if (!orchestrationParentAllowed(identity, parent)
      || (parent !== null && sameOrchestrationIdentity(identity, parent))
      || (latest !== null && latest.observed_at_ms > freshness.observed_at_ms)) {
    workContextRefusal("orchestration parent is invalid");
  }
  return {
    external_work: value.external_work === null ? null : validateExternalWorkIdentity(value.external_work),
    freshness,
    identity,
    latest_useful_message: latest,
    origin: validateLineageOrigin(value.origin),
    parent,
    revision: WorkContextRevision(workContextWireUnsigned(value.revision, WorkContextRevision_MAX, "revision")),
    status: validateLineageStatus(value.status),
    workspace: UserWorkspaceId(value.workspace),
  };
}

export function validateLineageProjection(value: LineageProjection): LineageProjection {
  exactInput(value, LineageProjection_FIELDS);
  if (value.schema !== PLATFORM_SCHEMA_V2) workContextRefusal("lineage projection schema is incompatible");
  if (!Array.isArray(value.external_work_items) || !Array.isArray(value.orchestration)
      || value.external_work_items.length + value.orchestration.length > MAX_LINEAGE_RECORDS) {
    workContextRefusal("lineage projection exceeds its record limit");
  }
  const workspace = UserWorkspaceId(value.workspace);
  const external_work_items = value.external_work_items.map(validateExternalWorkItem)
    .sort((left, right) => compareExternalWorkIdentity(left.identity, right.identity));
  const orchestration = value.orchestration.map(validateOrchestrationRecord)
    .sort((left, right) => compareOrchestrationIdentity(left.identity, right.identity));
  if (external_work_items.some((item) => item.workspace !== workspace)
      || orchestration.some((item) => item.workspace !== workspace)
      || external_work_items.some((item, index) => index > 0 && sameExternalWorkIdentity(external_work_items[index - 1]!.identity, item.identity))
      || orchestration.some((item, index) => index > 0 && sameOrchestrationIdentity(orchestration[index - 1]!.identity, item.identity))) {
    workContextRefusal("lineage projection is duplicated or crosses workspaces");
  }
  for (const item of external_work_items) {
    if (item.origin.workspace !== workspace) workContextRefusal("lineage origin crosses workspaces");
    if (item.moved_to !== null) { const target = external_work_items.find((candidate) => sameExternalWorkIdentity(candidate.identity, item.moved_to!)); if (target === undefined || !originRefines(target.origin, item.origin)) workContextRefusal("lineage external link is unresolved"); }
    const seen = new Set<string>(); let cursor: ExternalWorkItem | undefined = item;
    while (cursor !== undefined && cursor.moved_to !== null) { const target: ExternalWorkIdentity = cursor.moved_to; const key = `${target.provider}\u0000${target.authority}\u0000${target.scope}\u0000${target.key}`; if (seen.has(key) || sameExternalWorkIdentity(target, item.identity)) workContextRefusal("lineage external cycle"); seen.add(key); cursor = external_work_items.find((candidate) => sameExternalWorkIdentity(candidate.identity, target)); }
  }
  for (const record of orchestration) {
    if (record.origin.workspace !== workspace) workContextRefusal("lineage origin crosses workspaces");
    if (record.external_work !== null) { const target = external_work_items.find((item) => sameExternalWorkIdentity(item.identity, record.external_work!)); if (target === undefined || !originRefines(record.origin, target.origin)) workContextRefusal("lineage external link is unresolved"); }
    if (record.parent !== null) { const target = orchestration.find((item) => sameOrchestrationIdentity(item.identity, record.parent!)); if (target === undefined || !originRefines(record.origin, target.origin)) workContextRefusal("lineage parent is unresolved"); }
    const seen = new Set<string>(); let cursor: OrchestrationRecord | undefined = record;
    while (cursor !== undefined && cursor.parent !== null) { const parent: OrchestrationIdentity = cursor.parent; const key = `${parent.kind}\u0000${parent.id}`; if (seen.has(key) || sameOrchestrationIdentity(parent, record.identity)) workContextRefusal("lineage cycle"); seen.add(key); cursor = orchestration.find((item) => sameOrchestrationIdentity(item.identity, parent)); }
  }
  return {external_work_items, orchestration, schema: PLATFORM_SCHEMA_V2, workspace};
}

export function validateWorkspaceCreateIntent(value: WorkspaceCreateIntent): WorkspaceCreateIntent {
  exactInput(value, WorkspaceCreateIntent_FIELDS);
  return {
    base_selector: BaseSelectorId(value.base_selector),
    branch_selector: BranchSelectorId(value.branch_selector),
    external_work: validateExternalWorkIdentity(value.external_work),
    intent_id: WorkspaceIntentId(value.intent_id),
    task: OrchestrationTaskId(value.task),
  };
}

export function validateWorkspaceResumeIntent(value: WorkspaceResumeIntent): WorkspaceResumeIntent {
  exactInput(value, WorkspaceResumeIntent_FIELDS);
  return {
    expected_revision: WorkContextRevision(workContextWireUnsigned(value.expected_revision, WorkContextRevision_MAX, "expected_revision")),
    intent_id: WorkspaceIntentId(value.intent_id),
    task: OrchestrationTaskId(value.task),
    workspace: UserWorkspaceId(value.workspace),
  };
}

export function validateWorkspaceIntent(value: WorkspaceIntent): WorkspaceIntent {
  switch (value.kind) {
    case "create": exactInput(value, ["kind", "request"]); return {kind: value.kind, request: validateWorkspaceCreateIntent(value.request)};
    case "resume": exactInput(value, ["kind", "request"]); return {kind: value.kind, request: validateWorkspaceResumeIntent(value.request)};
    default: return assertNeverWorkspaceIntent(value);
  }
}

export function validateWorkspaceIntentOutcome(value: WorkspaceIntentOutcome): WorkspaceIntentOutcome {
  switch (value.kind) {
    case "accepted": exactInput(value, ["kind"]); return {kind: value.kind};
    case "conflict": exactInput(value, ["conflict", "kind"]); return {kind: value.kind, conflict: decodeWorkspaceIntentConflict(value.conflict)};
    case "created": exactInput(value, ["kind", "workspace"]); return {kind: value.kind, workspace: UserWorkspaceId(value.workspace)};
    case "resumed": exactInput(value, ["kind", "workspace"]); return {kind: value.kind, workspace: UserWorkspaceId(value.workspace)};
    case "unknown": exactInput(value, ["kind"]); return {kind: value.kind};
    default: return assertNeverWorkspaceIntentOutcome(value);
  }
}

function lineageJson(value: unknown): JsonValue {
  if (value === null) return {kind: "null"};
  if (typeof value === "boolean") return {kind: "bool", value};
  if (typeof value === "bigint") return {kind: "integer", value};
  if (typeof value === "string") return {kind: "string", value};
  if (Array.isArray(value)) return {kind: "array", items: value.map(lineageJson)};
  if (typeof value === "object") return object(Object.entries(value as Readonly<Record<string, unknown>>).sort(([a],[b]) => compareUtf8(a,b)).map(([key,entry]) => [key,lineageJson(entry)] as const));
  throw new ValidationError("lineage", "unsupported_json_value");
}
function lineagePlain(value: JsonValue): unknown {
  switch (value.kind) {
    case "null": return null; case "bool": case "integer": case "string": return value.value;
    case "array": return value.items.map(lineagePlain);
    case "object": return Object.fromEntries(value.entries.map(([key,entry]) => [key,lineagePlain(entry)]));
  }
}
function lineageDocument(value: unknown): Uint8Array {
  const bytes = toCanonicalBytes(lineageJson({platform_version: 2n, schema: PLATFORM_SCHEMA_V2, value}));
  if (bytes.length > MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES) throw new RefusalError("frame_too_large", "lineage document exceeds ceiling");
  return bytes;
}
function decodeLineageDocument(payload: Uint8Array): unknown {
  const value = lineagePlain(parseDocument(payload, MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES)) as Readonly<Record<string, unknown>>;
  exactInput(value as object, ["platform_version", "schema", "value"]);
  if (value.platform_version !== 2n || value.schema !== PLATFORM_SCHEMA_V2) workContextRefusal("lineage requires negotiated Platform v2");
  return value.value;
}
export function requireLineageV2(value: NegotiatedPlatform): NegotiatedPlatform {
  const negotiated = validateNegotiatedPlatform(value);
  if (negotiated.version !== 2n || negotiated.schema !== PLATFORM_SCHEMA_V2 || negotiated.work_context !== "v2_structured") {
    workContextRefusal("lineage is unavailable before Platform v2 negotiation");
  }
  return negotiated;
}
function lineageChecked<T>(operation: () => T): T {
  try { return operation(); } catch (error) {
    if (error instanceof RefusalError) throw error;
    throw new RefusalError(WORK_CONTEXT_VALUE_INVALID, "lineage value is invalid");
  }
}
export function encodeLineageProjection(negotiated: NegotiatedPlatform, value: LineageProjection): Uint8Array { return lineageChecked(() => { requireLineageV2(negotiated); return lineageDocument(validateLineageProjection(value)); }); }
export function decodeLineageProjection(negotiated: NegotiatedPlatform, payload: Uint8Array): LineageProjection { return lineageChecked(() => { requireLineageV2(negotiated); return validateLineageProjection(decodeLineageDocument(payload) as LineageProjection); }); }
export function encodeWorkspaceIntent(negotiated: NegotiatedPlatform, value: WorkspaceIntent): Uint8Array { return lineageChecked(() => { requireLineageV2(negotiated); return lineageDocument(validateWorkspaceIntent(value)); }); }
export function decodeWorkspaceIntent(negotiated: NegotiatedPlatform, payload: Uint8Array): WorkspaceIntent { return lineageChecked(() => { requireLineageV2(negotiated); return validateWorkspaceIntent(decodeLineageDocument(payload) as WorkspaceIntent); }); }
export function encodeWorkspaceIntentOutcome(negotiated: NegotiatedPlatform, value: WorkspaceIntentOutcome): Uint8Array { return lineageChecked(() => { requireLineageV2(negotiated); return lineageDocument(validateWorkspaceIntentOutcome(value)); }); }
export function decodeWorkspaceIntentOutcome(negotiated: NegotiatedPlatform, payload: Uint8Array): WorkspaceIntentOutcome { return lineageChecked(() => { requireLineageV2(negotiated); return validateWorkspaceIntentOutcome(decodeLineageDocument(payload) as WorkspaceIntentOutcome); }); }
// Platform v2 lifecycle is additive to the read contract above. All fields are
// exact and all authority arrays are already in canonical UTF-8 order.
export const MAX_AUTHORITY_GRANTS_PER_AXIS = 64;
export const MAX_MUTATION_CANONICAL_BYTES = 262144;
const LIFECYCLE_EPOCH_MAX = 9223372036854775807n;

export type AuthorityGrantId = string & {readonly __brand: "AuthorityGrantId"};
export type WorkContextRegistrySelector = string & {readonly __brand: "WorkContextRegistrySelector"};
export type MutationPreviewId = string & {readonly __brand: "MutationPreviewId"};
export type MutationApprovalId = string & {readonly __brand: "MutationApprovalId"};
export type WorkContextRequestDigest = string & {readonly __brand: "WorkContextRequestDigest"};
export type MutationPreviewDigest = string & {readonly __brand: "MutationPreviewDigest"};

function lifecycleToken(value: string, field: string): string {
  if (byteLength(value) === 0 || byteLength(value) > 128 || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value) || value.includes("..")) {
    throw new RefusalError("work_context_lifecycle_value_invalid", `${field} is not a wire-safe opaque token`);
  }
  return value;
}
export function AuthorityGrantId(value: string): AuthorityGrantId { return lifecycleToken(value, "authority_grant") as AuthorityGrantId; }
export function WorkContextRegistrySelector(value: string): WorkContextRegistrySelector { return lifecycleToken(value, "registry_selector") as WorkContextRegistrySelector; }
export function MutationPreviewId(value: string): MutationPreviewId { return WorkContextCursor(value) as unknown as MutationPreviewId; }
export function MutationApprovalId(value: string): MutationApprovalId { return WorkContextCursor(value) as unknown as MutationApprovalId; }
export function WorkContextRequestDigest(value: string): WorkContextRequestDigest {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new RefusalError("work_context_lifecycle_value_invalid", "request_digest is not canonical SHA-256");
  return value as WorkContextRequestDigest;
}
export function MutationPreviewDigest(value: string): MutationPreviewDigest {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new RefusalError("work_context_lifecycle_value_invalid", "preview_digest is not canonical SHA-256");
  return value as MutationPreviewDigest;
}

export interface LifecycleActor {readonly id: string; readonly tenant: string;}
export interface WorkContextAuthority {
  readonly credentials: readonly AuthorityGrantId[];
  readonly filesystem: readonly AuthorityGrantId[];
  readonly models: readonly AuthorityGrantId[];
  readonly network: readonly AuthorityGrantId[];
  readonly providers: readonly AuthorityGrantId[];
  readonly tools: readonly AuthorityGrantId[];
}
export interface ExpectedWorkContext {readonly identity: WorkContextIdentity; readonly revision: WorkContextRevision;}
export type ExternalParentResolution = "available" | "unavailable";
export type ResolvedParentSnapshot =
  | {readonly kind: "work_context"; readonly record: WorkContextRecord}
  | {readonly identity: WorkContextIdentity; readonly kind: "external"; readonly owning_project: ProjectId | null; readonly resolution: ExternalParentResolution; readonly revision: WorkContextRevision};
export type MutationApprovalRequirement = "not_required" | "required";
export type MutationApprovalDecision = "denied" | "granted";
export type MutationRefusalCategory = "invalid_request" | "unauthorized" | "authority_widening" | "stale_revision" | "conflict" | "preview_expired" | "approval_required" | "approval_unexpected" | "approval_mismatch" | "approval_denied" | "approval_expired" | "unknown" | "resync_required" | "unavailable";

export type WorkContextMutationIntent =
  | {readonly kind: "create_project"; readonly label: WorkContextLabel; readonly repositories: readonly ExpectedWorkContext[]}
  | {readonly kind: "create_host_setup"; readonly label: WorkContextLabel; readonly project: ExpectedWorkContext; readonly registry: WorkContextRegistrySelector; readonly setup_kind: HostSetupKind}
  | {readonly checkout_kind: CheckoutKind; readonly host_setup: ExpectedWorkContext; readonly kind: "create_checkout"; readonly label: WorkContextLabel; readonly project: ExpectedWorkContext; readonly registry: WorkContextRegistrySelector; readonly repository: ExpectedWorkContext}
  | {readonly checkout: ExpectedWorkContext; readonly kind: "create_user_workspace"; readonly label: WorkContextLabel; readonly project: ExpectedWorkContext}
  | {readonly kind: "create_attempt_workspace"; readonly label: WorkContextLabel; readonly requested_authority: WorkContextAuthority; readonly user_workspace: ExpectedWorkContext}
  | {readonly kind: "resume_attempt_workspace"; readonly requested_authority: WorkContextAuthority; readonly target: ExpectedWorkContext}
  | {readonly kind: "resume_session"; readonly requested_authority: WorkContextAuthority; readonly target: ExpectedWorkContext}
  | {readonly kind: "archive_project" | "archive_host_setup" | "archive_checkout" | "archive_user_workspace"; readonly target: ExpectedWorkContext};

export interface WorkContextMutationProposal {
  readonly actor: LifecycleActor;
  readonly actor_authority: WorkContextAuthority;
  readonly authority: ResourceAuthority;
  readonly idempotency_key: IdempotencyKey;
  readonly intent: WorkContextMutationIntent;
  readonly request_digest: WorkContextRequestDigest;
  readonly schema: typeof PLATFORM_SCHEMA_V2;
}
export interface MutationPreviewRef {readonly id: MutationPreviewId; readonly revision: WorkContextRevision;}
export interface MutationPreview {
  readonly approval: MutationApprovalRequirement;
  readonly current: WorkContextRecord | null;
  readonly effective_authority: WorkContextAuthority;
  readonly expires_at_ms: bigint;
  readonly inherited_authority: WorkContextAuthority;
  readonly issued_at_ms: bigint;
  readonly preview: MutationPreviewRef;
  readonly proposal: WorkContextMutationProposal;
  readonly resolved_parents: readonly ResolvedParentSnapshot[];
  readonly resulting: WorkContextRecord;
  readonly schema: typeof PLATFORM_SCHEMA_V2;
}
export interface MutationApproval {
  readonly decided_at_ms: bigint; readonly decided_by: LifecycleActor; readonly decision: MutationApprovalDecision;
  readonly expires_at_ms: bigint; readonly id: MutationApprovalId; readonly idempotency_key: IdempotencyKey;
  readonly preview: MutationPreviewRef; readonly preview_digest: MutationPreviewDigest; readonly request_digest: WorkContextRequestDigest;
}
export interface MutationSubmission {
  readonly approval: MutationApproval | null; readonly idempotency_key: IdempotencyKey;
  readonly preview: MutationPreviewRef; readonly preview_digest: MutationPreviewDigest; readonly request_digest: WorkContextRequestDigest;
  readonly schema: typeof PLATFORM_SCHEMA_V2; readonly submitted_at_ms: bigint;
}
export interface MutationReceipt {
  readonly approval_id: MutationApprovalId | null; readonly id: ReceiptId; readonly idempotency_key: IdempotencyKey;
  readonly outcome: "accepted" | "completed" | "conflict" | "rejected"; readonly preview: MutationPreviewRef; readonly preview_digest: MutationPreviewDigest; readonly recorded_at_ms: bigint;
  readonly request_digest: WorkContextRequestDigest; readonly resulting_revision: WorkContextRevision | null;
  readonly schema: typeof PLATFORM_SCHEMA_V2;
}
export interface MutationRefusal {
  readonly category: MutationRefusalCategory; readonly explanation: string;
  readonly request_digest: WorkContextRequestDigest | null; readonly schema: typeof PLATFORM_SCHEMA_V2;
}

const AUTHORITY_FIELDS = ["credentials", "filesystem", "models", "network", "providers", "tools"] as const;
const PROPOSAL_FIELDS = ["actor", "actor_authority", "authority", "idempotency_key", "intent", "request_digest", "schema"] as const;
const PREVIEW_FIELDS = ["approval", "current", "effective_authority", "expires_at_ms", "inherited_authority", "issued_at_ms", "preview", "proposal", "resolved_parents", "resulting", "schema"] as const;
const APPROVAL_FIELDS = ["decided_at_ms", "decided_by", "decision", "expires_at_ms", "id", "idempotency_key", "preview", "preview_digest", "request_digest"] as const;
const SUBMISSION_FIELDS = ["approval", "idempotency_key", "preview", "preview_digest", "request_digest", "schema", "submitted_at_ms"] as const;
const RECEIPT_FIELDS = ["approval_id", "id", "idempotency_key", "outcome", "preview", "preview_digest", "recorded_at_ms", "request_digest", "resulting_revision", "schema"] as const;
const REFUSAL_FIELDS = ["category", "explanation", "request_digest", "schema"] as const;

function strictUtf8(values: readonly string[]): boolean {
  const encoder = new TextEncoder();
  const compare = (left: string, right: string): number => {
    const a = encoder.encode(left); const b = encoder.encode(right); const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index += 1) { if (a[index] !== b[index]) return a[index]! - b[index]!; }
    return a.length - b.length;
  };
  return values.every((value, index) => index === 0 || compare(values[index - 1]!, value) < 0);
}
function lifecycleActorComponent(value: string, field: string): string {
  if (!isWellFormedUnicode(value) || byteLength(value) === 0 || byteLength(value) > 128 || !/^[^\p{Cc}]+$/u.test(value)) workContextRefusal(`${field} is invalid`);
  return value;
}
function validateLifecycleActor(value: LifecycleActor): LifecycleActor {
  exactInput(value, ["id", "tenant"]); return {id: lifecycleActorComponent(value.id,"actor_id"), tenant: lifecycleActorComponent(value.tenant,"tenant")};
}
function validateAuthority(value: WorkContextAuthority): WorkContextAuthority {
  exactInput(value, AUTHORITY_FIELDS);
  const axis = (items: readonly AuthorityGrantId[]): readonly AuthorityGrantId[] => {
    if (!Array.isArray(items) || items.length > MAX_AUTHORITY_GRANTS_PER_AXIS) workContextRefusal("authority grant limit exceeded");
    const checked = items.map(AuthorityGrantId); if (!strictUtf8(checked)) workContextRefusal("authority grants are repeated or unordered"); return checked;
  };
  return {credentials: axis(value.credentials), filesystem: axis(value.filesystem), models: axis(value.models), network: axis(value.network), providers: axis(value.providers), tools: axis(value.tools)};
}
function authoritySubset(value: WorkContextAuthority, ceiling: WorkContextAuthority): boolean {
  return AUTHORITY_FIELDS.every((field) => value[field].every((grant) => ceiling[field].includes(grant)));
}
function authorityEqual(left: WorkContextAuthority, right: WorkContextAuthority): boolean {
  return AUTHORITY_FIELDS.every((field) => left[field].length === right[field].length && left[field].every((grant, index) => grant === right[field][index]));
}
function authorityJson(value: WorkContextAuthority): JsonValue {
  const checked = validateAuthority(value); return object(AUTHORITY_FIELDS.map((field) => [field, {kind: "array", items: checked[field].map((grant) => ({kind: "string", value: grant}))}] as const));
}
function decodeAuthorityValue(value: JsonValue): WorkContextAuthority {
  const fields = exactFields(value, AUTHORITY_FIELDS, WORK_CONTEXT_INVALID_BODY);
  const axis = (field: typeof AUTHORITY_FIELDS[number]): readonly AuthorityGrantId[] => bodyArray(fields, field, WORK_CONTEXT_INVALID_BODY, MAX_AUTHORITY_GRANTS_PER_AXIS, WORK_CONTEXT_VALUE_INVALID).map((item) => {
    if (item.kind !== "string") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, `${field} grant is not a string`); return AuthorityGrantId(item.value);
  });
  return validateAuthority({credentials: axis("credentials"), filesystem: axis("filesystem"), models: axis("models"), network: axis("network"), providers: axis("providers"), tools: axis("tools")});
}
function expectedJson(value: ExpectedWorkContext): JsonValue { return object([["identity", workContextIdentityJson(value.identity)], ["revision", {kind: "integer", value: WorkContextRevision(value.revision)}]]); }
function decodeExpectedValue(value: JsonValue): ExpectedWorkContext {
  const fields = exactFields(value, ["identity", "revision"], WORK_CONTEXT_INVALID_BODY);
  return {identity: decodeWorkContextIdentityValue(bodyValue(fields, "identity", WORK_CONTEXT_INVALID_BODY)), revision: WorkContextRevision(workContextWireUnsigned(bodyInteger(fields, "revision", WORK_CONTEXT_INVALID_BODY), 9223372036854775807n, "revision"))};
}
function resolvedParentJson(value: ResolvedParentSnapshot): JsonValue {
  if(value.kind==="work_context") return object([["kind",{kind:"string",value:"work_context"}],["record",recordJson(value.record)]]);
  return object([["identity",workContextIdentityJson(value.identity)],["kind",{kind:"string",value:"external"}],["owning_project",value.owning_project===null?{kind:"null"}:{kind:"string",value:ProjectId(value.owning_project)}],["resolution",{kind:"string",value:value.resolution}],["revision",{kind:"integer",value:WorkContextRevision(value.revision)}]]);
}
function decodeResolvedParentValue(value: JsonValue): ResolvedParentSnapshot {
  if(value.kind!=="object")workContextRefusal("resolved parent is not an object");const loose=new Map(value.entries);const kind=loose.get("kind");if(kind?.kind!=="string")workContextRefusal("resolved parent kind is invalid");
  if(kind.value==="work_context"){const fields=exactFields(value,["kind","record"],WORK_CONTEXT_INVALID_BODY);return {kind:"work_context",record:decodeWorkContextRecordValue(bodyValue(fields,"record",WORK_CONTEXT_INVALID_BODY))};}
  if(kind.value!=="external")workContextRefusal("resolved parent kind is invalid");const fields=exactFields(value,["identity","kind","owning_project","resolution","revision"],WORK_CONTEXT_INVALID_BODY);const owner=bodyStringOrNull(fields,"owning_project",WORK_CONTEXT_INVALID_BODY);const resolution=bodyString(fields,"resolution",WORK_CONTEXT_INVALID_BODY);if(resolution!=="available"&&resolution!=="unavailable")workContextRefusal("external parent resolution is invalid");return {identity:decodeWorkContextIdentityValue(bodyValue(fields,"identity",WORK_CONTEXT_INVALID_BODY)),kind:"external",owning_project:owner===null?null:ProjectId(owner),resolution,revision:WorkContextRevision(workContextWireUnsigned(bodyInteger(fields,"revision",WORK_CONTEXT_INVALID_BODY),9223372036854775807n,"revision"))};
}
function parentExpectations(intent: WorkContextMutationIntent): readonly ExpectedWorkContext[] {
  switch(intent.kind){case "create_project":return intent.repositories;case "create_host_setup":return [intent.project];case "create_checkout":return [intent.project,intent.host_setup,intent.repository];case "create_user_workspace":return [intent.project,intent.checkout];case "create_attempt_workspace":return [intent.user_workspace];default:return [];}
}
function validateResolvedParents(intent: WorkContextMutationIntent, values: readonly ResolvedParentSnapshot[]): readonly ResolvedParentSnapshot[] {
  if(!Array.isArray(values))workContextRefusal("resolved parents are invalid");const expected=parentExpectations(intent);if(values.length!==expected.length)workContextRefusal("resolved parents do not match intent");
  const checked=values.map((value,index):ResolvedParentSnapshot=>{const target=expected[index]!;if(value.kind==="work_context"){exactInput(value,["kind","record"]);const record=validateWorkContextRecord(value.record);if(target.identity.kind==="repository"||!canonicalEqual(workContextIdentityJson(record.identity),workContextIdentityJson(target.identity))||record.revision!==target.revision)workContextRefusal("resolved parent does not match intent");return {kind:"work_context",record};}exactInput(value,["identity","kind","owning_project","resolution","revision"]);const identity=validateWorkContextIdentity(value.identity);const owner=value.owning_project===null?null:ProjectId(value.owning_project);if(identity.kind!=="repository"||value.resolution!=="available"||!canonicalEqual(workContextIdentityJson(identity),workContextIdentityJson(target.identity))||value.revision!==target.revision)workContextRefusal("external parent is unavailable or does not match intent");return {identity,kind:"external",owning_project:owner,resolution:"available",revision:WorkContextRevision(value.revision)};});
  const work=(index:number):WorkContextRecord=>{const value=checked[index];if(value?.kind!=="work_context")workContextRefusal("work-context parent snapshot is required");return value.record;};const active=(record:WorkContextRecord):void=>{if(record.lifecycle!=="active")workContextRefusal("parent lifecycle does not admit children");};const related=(record:WorkContextRecord,kind:WorkContextRelationKind,target:WorkContextIdentity):boolean=>record.relations.some((relation)=>relation.kind===kind&&canonicalEqual(workContextIdentityJson(relation.target),workContextIdentityJson(target)));
  switch(intent.kind){case "create_host_setup":active(work(0));break;case "create_checkout":{const project=work(0),host=work(1),repository=checked[2]!,selected=intent.project.identity;if(selected.kind!=="project")workContextRefusal("selected project identity is invalid");active(project);active(host);if(!related(host,"host_setup_project",selected)||!related(project,"project_repository",intent.repository.identity)||repository.kind!=="external"||(repository.owning_project!==null&&repository.owning_project!==selected.id))workContextRefusal("checkout parents cross project boundaries");break;}case "create_user_workspace":{const project=work(0),checkout=work(1);active(project);active(checkout);if(!related(checkout,"checkout_project",intent.project.identity))workContextRefusal("checkout belongs to another project");break;}case "create_attempt_workspace":active(work(0));break;default:break;}
  return checked;
}

export function validateWorkContextMutationIntent(value: WorkContextMutationIntent): WorkContextMutationIntent {
  const expectedKind = (expected: ExpectedWorkContext, kind: WorkContextTargetKind): ExpectedWorkContext => {
    const identity = validateWorkContextIdentity(expected.identity); if (identity.kind !== kind) workContextRefusal("operation target kind is invalid"); return {identity, revision: WorkContextRevision(expected.revision)};
  };
  switch (value.kind) {
    case "create_project": {
      exactInput(value, ["kind", "label", "repositories"]); const repositories = value.repositories.map((item) => expectedKind(item, "repository"));
      if (repositories.length > MAX_WORK_CONTEXT_RELATIONS || !strictlyOrdered(repositories, (item) => identityOrderKey(item.identity))) workContextRefusal("project repositories are repeated, unordered, or excessive");
      return {kind: value.kind, label: WorkContextLabel(value.label), repositories};
    }
    case "create_host_setup": exactInput(value, ["kind", "label", "project", "registry", "setup_kind"]); return {kind: value.kind, label: WorkContextLabel(value.label), project: expectedKind(value.project, "project"), registry: WorkContextRegistrySelector(value.registry), setup_kind: decodeHostSetupKind(value.setup_kind)};
    case "create_checkout": exactInput(value, ["checkout_kind", "host_setup", "kind", "label", "project", "registry", "repository"]); return {checkout_kind: decodeCheckoutKind(value.checkout_kind), host_setup: expectedKind(value.host_setup, "host_setup"), kind: value.kind, label: WorkContextLabel(value.label), project: expectedKind(value.project, "project"), registry: WorkContextRegistrySelector(value.registry), repository: expectedKind(value.repository, "repository")};
    case "create_user_workspace": exactInput(value, ["checkout", "kind", "label", "project"]); return {checkout: expectedKind(value.checkout, "checkout"), kind: value.kind, label: WorkContextLabel(value.label), project: expectedKind(value.project, "project")};
    case "create_attempt_workspace": exactInput(value, ["kind", "label", "requested_authority", "user_workspace"]); return {kind: value.kind, label: WorkContextLabel(value.label), requested_authority: validateAuthority(value.requested_authority), user_workspace: expectedKind(value.user_workspace, "user_workspace")};
    case "resume_attempt_workspace": exactInput(value, ["kind", "requested_authority", "target"]); return {kind: value.kind, requested_authority: validateAuthority(value.requested_authority), target: expectedKind(value.target, "attempt_workspace")};
    case "resume_session": exactInput(value, ["kind", "requested_authority", "target"]); return {kind: value.kind, requested_authority: validateAuthority(value.requested_authority), target: expectedKind(value.target, "session")};
    case "archive_project": case "archive_host_setup": case "archive_checkout": case "archive_user_workspace": {
      exactInput(value, ["kind", "target"]); const kind = value.kind.slice("archive_".length) as WorkContextTargetKind; return {kind: value.kind, target: expectedKind(value.target, kind)};
    }
    default: return assertNeverLifecycleIntent(value);
  }
}
function assertNeverLifecycleIntent(value: never): never { throw new RefusalError(WORK_CONTEXT_VALUE_INVALID, `unknown lifecycle intent ${(value as {kind?: unknown}).kind}`); }

function intentJson(value: WorkContextMutationIntent): JsonValue {
  const intent = validateWorkContextMutationIntent(value); const word = {kind: "string", value: intent.kind} as const;
  switch (intent.kind) {
    case "create_project": return object([["kind", word], ["label", {kind: "string", value: intent.label}], ["repositories", {kind: "array", items: intent.repositories.map(expectedJson)}]]);
    case "create_host_setup": return object([["kind", word], ["label", {kind: "string", value: intent.label}], ["project", expectedJson(intent.project)], ["registry", {kind: "string", value: intent.registry}], ["setup_kind", {kind: "string", value: intent.setup_kind}]]);
    case "create_checkout": return object([["checkout_kind", {kind: "string", value: intent.checkout_kind}], ["host_setup", expectedJson(intent.host_setup)], ["kind", word], ["label", {kind: "string", value: intent.label}], ["project", expectedJson(intent.project)], ["registry", {kind: "string", value: intent.registry}], ["repository", expectedJson(intent.repository)]]);
    case "create_user_workspace": return object([["checkout", expectedJson(intent.checkout)], ["kind", word], ["label", {kind: "string", value: intent.label}], ["project", expectedJson(intent.project)]]);
    case "create_attempt_workspace": return object([["kind", word], ["label", {kind: "string", value: intent.label}], ["requested_authority", authorityJson(intent.requested_authority)], ["user_workspace", expectedJson(intent.user_workspace)]]);
    case "resume_attempt_workspace": case "resume_session": return object([["kind", word], ["requested_authority", authorityJson(intent.requested_authority)], ["target", expectedJson(intent.target)]]);
    default: return object([["kind", word], ["target", expectedJson(intent.target)]]);
  }
}
function decodeIntentValue(value: JsonValue): WorkContextMutationIntent {
  if (value.kind !== "object") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "intent is not an object");
  const loose = new Map(value.entries); const kindValue = loose.get("kind"); if (kindValue?.kind !== "string") throw new RefusalError(WORK_CONTEXT_INVALID_BODY, "intent kind is not a string"); const kind = kindValue.value;
  const fieldsFor = (names: readonly string[]) => exactFields(value, names, WORK_CONTEXT_INVALID_BODY);
  switch (kind) {
    case "create_project": { const fields = fieldsFor(["kind", "label", "repositories"]); return validateWorkContextMutationIntent({kind, label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)), repositories: bodyArray(fields, "repositories", WORK_CONTEXT_INVALID_BODY, MAX_WORK_CONTEXT_RELATIONS, WORK_CONTEXT_VALUE_INVALID).map(decodeExpectedValue)}); }
    case "create_host_setup": { const fields = fieldsFor(["kind", "label", "project", "registry", "setup_kind"]); return validateWorkContextMutationIntent({kind, label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)), project: decodeExpectedValue(bodyValue(fields, "project", WORK_CONTEXT_INVALID_BODY)), registry: WorkContextRegistrySelector(bodyString(fields, "registry", WORK_CONTEXT_INVALID_BODY)), setup_kind: decodeHostSetupKind(bodyString(fields, "setup_kind", WORK_CONTEXT_INVALID_BODY))}); }
    case "create_checkout": { const fields = fieldsFor(["checkout_kind", "host_setup", "kind", "label", "project", "registry", "repository"]); return validateWorkContextMutationIntent({checkout_kind: decodeCheckoutKind(bodyString(fields, "checkout_kind", WORK_CONTEXT_INVALID_BODY)), host_setup: decodeExpectedValue(bodyValue(fields, "host_setup", WORK_CONTEXT_INVALID_BODY)), kind, label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)), project: decodeExpectedValue(bodyValue(fields, "project", WORK_CONTEXT_INVALID_BODY)), registry: WorkContextRegistrySelector(bodyString(fields, "registry", WORK_CONTEXT_INVALID_BODY)), repository: decodeExpectedValue(bodyValue(fields, "repository", WORK_CONTEXT_INVALID_BODY))}); }
    case "create_user_workspace": { const fields = fieldsFor(["checkout", "kind", "label", "project"]); return validateWorkContextMutationIntent({checkout: decodeExpectedValue(bodyValue(fields, "checkout", WORK_CONTEXT_INVALID_BODY)), kind, label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)), project: decodeExpectedValue(bodyValue(fields, "project", WORK_CONTEXT_INVALID_BODY))}); }
    case "create_attempt_workspace": { const fields = fieldsFor(["kind", "label", "requested_authority", "user_workspace"]); return validateWorkContextMutationIntent({kind, label: WorkContextLabel(bodyString(fields, "label", WORK_CONTEXT_INVALID_BODY)), requested_authority: decodeAuthorityValue(bodyValue(fields, "requested_authority", WORK_CONTEXT_INVALID_BODY)), user_workspace: decodeExpectedValue(bodyValue(fields, "user_workspace", WORK_CONTEXT_INVALID_BODY))}); }
    case "resume_attempt_workspace": case "resume_session": { const fields = fieldsFor(["kind", "requested_authority", "target"]); return validateWorkContextMutationIntent({kind, requested_authority: decodeAuthorityValue(bodyValue(fields, "requested_authority", WORK_CONTEXT_INVALID_BODY)), target: decodeExpectedValue(bodyValue(fields, "target", WORK_CONTEXT_INVALID_BODY))}); }
    case "archive_project": case "archive_host_setup": case "archive_checkout": case "archive_user_workspace": { const fields = fieldsFor(["kind", "target"]); return validateWorkContextMutationIntent({kind, target: decodeExpectedValue(bodyValue(fields, "target", WORK_CONTEXT_INVALID_BODY))}); }
    default: workContextRefusal("unknown lifecycle operation");
  }
}

// FIPS 180-4 SHA-256 used only for the small deterministic request binding.
function lifecycleSha256(bytes: Uint8Array): string {
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const padded = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64); padded.set(bytes); padded[bytes.length] = 0x80;
  const bitLength = BigInt(bytes.length) * 8n; for (let index = 0; index < 8; index += 1) padded[padded.length - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 0xffn);
  const h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]; const w = new Uint32Array(64); const rotate = (value: number, by: number) => (value >>> by) | (value << (32 - by));
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) { const at = offset + index * 4; w[index] = ((padded[at]! << 24) | (padded[at + 1]! << 16) | (padded[at + 2]! << 8) | padded[at + 3]!) >>> 0; }
    for (let index = 16; index < 64; index += 1) { const a = w[index - 15]!; const b = w[index - 2]!; const s0 = rotate(a,7)^rotate(a,18)^(a>>>3); const s1 = rotate(b,17)^rotate(b,19)^(b>>>10); w[index] = (w[index-16]! + s0 + w[index-7]! + s1) >>> 0; }
    let [a,b,c,d,e,f,g,z] = h;
    for (let index = 0; index < 64; index += 1) { const s1=rotate(e!,6)^rotate(e!,11)^rotate(e!,25); const ch=(e!&f!)^(~e!&g!); const t1=(z!+s1+ch+k[index]!+w[index]!)>>>0; const s0=rotate(a!,2)^rotate(a!,13)^rotate(a!,22); const maj=(a!&b!)^(a!&c!)^(b!&c!); const t2=(s0+maj)>>>0; z=g;g=f;f=e;e=(d!+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0; }
    for (const [index,value] of [a,b,c,d,e,f,g,z].entries()) h[index] = (h[index]! + value!) >>> 0;
  }
  return h.map((value) => value.toString(16).padStart(8,"0")).join("");
}
class LifecycleMaterial {
  readonly bytes: number[] = []; private encoder = new TextEncoder();
  text(value: string): void { this.number(BigInt(this.encoder.encode(value).length)); this.bytes.push(...this.encoder.encode(value)); }
  number(value: bigint): void { for (let shift = 56n; shift >= 0n; shift -= 8n) this.bytes.push(Number((value >> shift) & 0xffn)); }
  identity(value: WorkContextIdentity): void { this.text(value.kind); if ("resource" in value) { this.text(value.resource.authority); this.text(value.resource.kind); this.text(value.resource.id); } else this.text(value.id); }
  expected(value: ExpectedWorkContext): void { this.identity(value.identity); this.number(value.revision); }
  authority(value: WorkContextAuthority): void { for (const field of ["filesystem","credentials","network","tools","providers","models"] as const) { this.number(BigInt(value[field].length)); for (const grant of value[field]) this.text(grant); } }
  intent(value: WorkContextMutationIntent): void {
    this.text(value.kind);
    switch (value.kind) {
      case "create_project": this.text(value.label); this.number(BigInt(value.repositories.length)); value.repositories.forEach((item)=>this.expected(item)); break;
      case "create_host_setup": this.text(value.label); this.expected(value.project); this.text(value.setup_kind); this.text(value.registry); break;
      case "create_checkout": this.text(value.label); this.expected(value.project); this.expected(value.host_setup); this.expected(value.repository); this.text(value.checkout_kind); this.text(value.registry); break;
      case "create_user_workspace": this.text(value.label); this.expected(value.project); this.expected(value.checkout); break;
      case "create_attempt_workspace": this.text(value.label); this.expected(value.user_workspace); this.authority(value.requested_authority); break;
      case "resume_attempt_workspace": case "resume_session": this.expected(value.target); this.authority(value.requested_authority); break;
      default: this.expected(value.target);
    }
  }
}
export function lifecycleRequestDigest(value: Omit<WorkContextMutationProposal,"request_digest"|"schema">): WorkContextRequestDigest {
  const material = new LifecycleMaterial(); material.text("automonique.platform/v2/work-context-mutation-request/v1"); material.text(value.actor.tenant); material.text(value.actor.id); material.text(value.authority); material.authority(value.actor_authority); material.text(value.idempotency_key); material.intent(value.intent);
  return WorkContextRequestDigest(`sha256:${lifecycleSha256(Uint8Array.from(material.bytes))}`);
}

function actorJson(value: LifecycleActor): JsonValue { const actor = validateLifecycleActor(value); return object([["id",{kind:"string",value:actor.id}],["tenant",{kind:"string",value:actor.tenant}]]); }
function decodeActorValue(value: JsonValue): LifecycleActor { const fields=exactFields(value,["id","tenant"],WORK_CONTEXT_INVALID_BODY); return validateLifecycleActor({id:bodyString(fields,"id",WORK_CONTEXT_INVALID_BODY),tenant:bodyString(fields,"tenant",WORK_CONTEXT_INVALID_BODY)}); }
function previewRefJson(value: MutationPreviewRef): JsonValue { return object([["id",{kind:"string",value:MutationPreviewId(value.id)}],["revision",{kind:"integer",value:WorkContextRevision(value.revision)}]]); }
function decodePreviewRefValue(value: JsonValue): MutationPreviewRef { const fields=exactFields(value,["id","revision"],WORK_CONTEXT_INVALID_BODY); return {id:MutationPreviewId(bodyString(fields,"id",WORK_CONTEXT_INVALID_BODY)),revision:WorkContextRevision(bodyInteger(fields,"revision",WORK_CONTEXT_INVALID_BODY))}; }

export function validateWorkContextMutationProposal(value: WorkContextMutationProposal): WorkContextMutationProposal {
  exactInput(value, PROPOSAL_FIELDS); if(value.schema!==PLATFORM_SCHEMA_V2) workContextRefusal("lifecycle schema is incompatible");
  const proposal: WorkContextMutationProposal={actor:validateLifecycleActor(value.actor),actor_authority:validateAuthority(value.actor_authority),authority:decodeResourceAuthority(value.authority),idempotency_key:IdempotencyKey(value.idempotency_key),intent:validateWorkContextMutationIntent(value.intent),request_digest:WorkContextRequestDigest(value.request_digest),schema:PLATFORM_SCHEMA_V2};
  if(lifecycleRequestDigest(proposal)!==proposal.request_digest) workContextRefusal("request digest does not bind proposal"); return proposal;
}
function proposalJson(value: WorkContextMutationProposal): JsonValue { const proposal=validateWorkContextMutationProposal(value); return object([["actor",actorJson(proposal.actor)],["actor_authority",authorityJson(proposal.actor_authority)],["authority",{kind:"string",value:proposal.authority}],["idempotency_key",{kind:"string",value:proposal.idempotency_key}],["intent",intentJson(proposal.intent)],["request_digest",{kind:"string",value:proposal.request_digest}],["schema",{kind:"string",value:proposal.schema}]]); }
function decodeProposalValue(value: JsonValue): WorkContextMutationProposal { const fields=exactFields(value,PROPOSAL_FIELDS,WORK_CONTEXT_INVALID_BODY); const partial={actor:decodeActorValue(bodyValue(fields,"actor",WORK_CONTEXT_INVALID_BODY)),actor_authority:decodeAuthorityValue(bodyValue(fields,"actor_authority",WORK_CONTEXT_INVALID_BODY)),authority:decodeResourceAuthority(bodyString(fields,"authority",WORK_CONTEXT_INVALID_BODY)),idempotency_key:IdempotencyKey(bodyString(fields,"idempotency_key",WORK_CONTEXT_INVALID_BODY)),intent:decodeIntentValue(bodyValue(fields,"intent",WORK_CONTEXT_INVALID_BODY)),request_digest:WorkContextRequestDigest(bodyString(fields,"request_digest",WORK_CONTEXT_INVALID_BODY)),schema:bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2}; return validateWorkContextMutationProposal(partial); }
export function encodeWorkContextMutationProposal(value: WorkContextMutationProposal): Uint8Array { return lifecycleBytes(proposalJson(value)); }
export function decodeWorkContextMutationProposal(payload: Uint8Array): WorkContextMutationProposal { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>decodeProposalValue(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES))); }

function requestedAuthority(intent: WorkContextMutationIntent): WorkContextAuthority|null { return intent.kind==="create_attempt_workspace"||intent.kind==="resume_attempt_workspace"||intent.kind==="resume_session"?intent.requested_authority:null; }
function canonicalEqual(left: JsonValue, right: JsonValue): boolean { const a=toCanonicalBytes(left);const b=toCanonicalBytes(right);return a.length===b.length&&a.every((byte,index)=>byte===b[index]); }
function expectedResult(intent: WorkContextMutationIntent, current: WorkContextRecord|null, issued: WorkContextIdentity): WorkContextRecord {
  const emptyAttributes: WorkContextAttributes={checkout:null,host_setup:null};
  const created=(kind:WorkContextKind,lifecycle:WorkContextLifecycle,label:WorkContextLabel,attributes:WorkContextAttributes,relations:readonly WorkContextRelation[]):WorkContextRecord=>{if(issued.kind!==kind)workContextRefusal("issued identity has the wrong kind");return validateWorkContextRecord({attributes,identity:issued,label,lifecycle,relations,revision:WorkContextRevision(1n)});};
  switch(intent.kind){
    case "create_project": return created("project","active",intent.label,emptyAttributes,intent.repositories.map((item)=>({kind:"project_repository",target:item.identity})));
    case "create_host_setup": return created("host_setup","active",intent.label,{checkout:null,host_setup:intent.setup_kind},[{kind:"host_setup_project",target:intent.project.identity}]);
    case "create_checkout": return created("checkout","active",intent.label,{checkout:intent.checkout_kind,host_setup:null},[{kind:"checkout_project",target:intent.project.identity},{kind:"checkout_host_setup",target:intent.host_setup.identity},{kind:"checkout_repository",target:intent.repository.identity}]);
    case "create_user_workspace": return created("user_workspace","active",intent.label,emptyAttributes,[{kind:"user_workspace_project",target:intent.project.identity},{kind:"user_workspace_checkout",target:intent.checkout.identity}]);
    case "create_attempt_workspace": return created("attempt_workspace","preparing",intent.label,emptyAttributes,[{kind:"attempt_user_workspace",target:intent.user_workspace.identity}]);
    default: {
      if(current===null)workContextRefusal("mutation preview requires the current record");const target=intent.target;
      if(!canonicalEqual(workContextIdentityJson(current.identity),workContextIdentityJson(target.identity))||current.revision!==target.revision)workContextRefusal("current record does not match the expected target");
      const resumeAttempt=intent.kind==="resume_attempt_workspace";const resumeSession=intent.kind==="resume_session";const from=resumeAttempt||resumeSession?"hibernated":"active";const to=resumeAttempt?"running":resumeSession?"active":"archived";
      if(current.lifecycle!==from)workContextRefusal("lifecycle transition is invalid");return validateWorkContextRecord({...current,lifecycle:to,revision:WorkContextRevision(current.revision+1n)});
    }
  }
}
export function validateMutationPreview(value: MutationPreview): MutationPreview {
  exactInput(value,PREVIEW_FIELDS); if(value.schema!==PLATFORM_SCHEMA_V2) workContextRefusal("lifecycle schema is incompatible");
  const proposal=validateWorkContextMutationProposal(value.proposal); const current=value.current===null?null:validateWorkContextRecord(value.current); const resolved=validateResolvedParents(proposal.intent,value.resolved_parents); const resulting=validateWorkContextRecord(value.resulting); const inherited=validateAuthority(value.inherited_authority); const effective=validateAuthority(value.effective_authority); const requested=requestedAuthority(proposal.intent);
  if(value.approval!=="not_required"&&value.approval!=="required") workContextRefusal("approval requirement is invalid");
  if(value.issued_at_ms<0n||value.expires_at_ms<=value.issued_at_ms||value.expires_at_ms>LIFECYCLE_EPOCH_MAX) workContextRefusal("preview expiry is invalid");
  if(requested===null ? AUTHORITY_FIELDS.some((field)=>effective[field].length>0||inherited[field].length>0) : !authorityEqual(requested,effective)||!authoritySubset(effective,inherited)||!authoritySubset(effective,proposal.actor_authority)) workContextRefusal("effective authority widens its ceiling");
  if((proposal.intent.kind.startsWith("create_")&&current!==null)||(!proposal.intent.kind.startsWith("create_")&&current===null)) workContextRefusal("preview current record is incoherent");
  if(!canonicalEqual(recordJson(resulting),recordJson(expectedResult(proposal.intent,current,resulting.identity))))workContextRefusal("preview resulting record is incoherent");
  return {approval:value.approval,current,effective_authority:effective,expires_at_ms:value.expires_at_ms,inherited_authority:inherited,issued_at_ms:value.issued_at_ms,preview:value.preview,proposal,resolved_parents:resolved,resulting,schema:PLATFORM_SCHEMA_V2};
}
function previewJson(value: MutationPreview): JsonValue { const preview=validateMutationPreview(value); return object([["approval",{kind:"string",value:preview.approval}],["current",preview.current===null?{kind:"null"}:recordJson(preview.current)],["effective_authority",authorityJson(preview.effective_authority)],["expires_at_ms",{kind:"integer",value:preview.expires_at_ms}],["inherited_authority",authorityJson(preview.inherited_authority)],["issued_at_ms",{kind:"integer",value:preview.issued_at_ms}],["preview",previewRefJson(preview.preview)],["proposal",proposalJson(preview.proposal)],["resolved_parents",{kind:"array",items:preview.resolved_parents.map(resolvedParentJson)}],["resulting",recordJson(preview.resulting)],["schema",{kind:"string",value:preview.schema}]]); }
function decodePreviewValue(value: JsonValue): MutationPreview { const fields=exactFields(value,PREVIEW_FIELDS,WORK_CONTEXT_INVALID_BODY); const current=bodyValueOrNull(fields,"current",WORK_CONTEXT_INVALID_BODY); return validateMutationPreview({approval:bodyString(fields,"approval",WORK_CONTEXT_INVALID_BODY) as MutationApprovalRequirement,current:current===null?null:decodeWorkContextRecordValue(current),effective_authority:decodeAuthorityValue(bodyValue(fields,"effective_authority",WORK_CONTEXT_INVALID_BODY)),expires_at_ms:bodyInteger(fields,"expires_at_ms",WORK_CONTEXT_INVALID_BODY),inherited_authority:decodeAuthorityValue(bodyValue(fields,"inherited_authority",WORK_CONTEXT_INVALID_BODY)),issued_at_ms:bodyInteger(fields,"issued_at_ms",WORK_CONTEXT_INVALID_BODY),preview:decodePreviewRefValue(bodyValue(fields,"preview",WORK_CONTEXT_INVALID_BODY)),proposal:decodeProposalValue(bodyValue(fields,"proposal",WORK_CONTEXT_INVALID_BODY)),resolved_parents:bodyArray(fields,"resolved_parents",WORK_CONTEXT_INVALID_BODY,MAX_WORK_CONTEXT_RELATIONS,WORK_CONTEXT_VALUE_INVALID).map(decodeResolvedParentValue),resulting:decodeWorkContextRecordValue(bodyValue(fields,"resulting",WORK_CONTEXT_INVALID_BODY)),schema:bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2}); }
export function mutationPreviewDigest(value: MutationPreview): MutationPreviewDigest { return MutationPreviewDigest(`sha256:${lifecycleSha256(toCanonicalBytes(previewJson(value)))}`); }
function lifecycleBytes(value: JsonValue): Uint8Array { const bytes=toCanonicalBytes(value);if(bytes.length>MAX_MUTATION_CANONICAL_BYTES)throw new RefusalError("frame_too_large","mutation document exceeds its ceiling");return bytes; }
export function encodeWorkContextMutationPreview(value: MutationPreview): Uint8Array { return lifecycleBytes(previewJson(value)); }
export function decodeWorkContextMutationPreview(payload: Uint8Array): MutationPreview { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>decodePreviewValue(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES))); }

function validateMutationApproval(value: MutationApproval, preview: MutationPreview): MutationApproval { exactInput(value,APPROVAL_FIELDS);if(value.decision!=="denied"&&value.decision!=="granted")workContextRefusal("approval decision is invalid");const approval={decided_at_ms:value.decided_at_ms,decided_by:validateLifecycleActor(value.decided_by),decision:value.decision,expires_at_ms:value.expires_at_ms,id:MutationApprovalId(value.id),idempotency_key:IdempotencyKey(value.idempotency_key),preview:value.preview,preview_digest:MutationPreviewDigest(value.preview_digest),request_digest:WorkContextRequestDigest(value.request_digest)};if(approval.preview.id!==preview.preview.id||approval.preview.revision!==preview.preview.revision||approval.preview_digest!==mutationPreviewDigest(preview)||approval.request_digest!==preview.proposal.request_digest||approval.idempotency_key!==preview.proposal.idempotency_key||approval.decided_at_ms<preview.issued_at_ms||approval.expires_at_ms<=approval.decided_at_ms||approval.expires_at_ms>preview.expires_at_ms||approval.expires_at_ms>LIFECYCLE_EPOCH_MAX) workContextRefusal("approval does not bind preview");return approval; }
function approvalJson(value: MutationApproval): JsonValue { return object([["decided_at_ms",{kind:"integer",value:value.decided_at_ms}],["decided_by",actorJson(value.decided_by)],["decision",{kind:"string",value:value.decision}],["expires_at_ms",{kind:"integer",value:value.expires_at_ms}],["id",{kind:"string",value:MutationApprovalId(value.id)}],["idempotency_key",{kind:"string",value:IdempotencyKey(value.idempotency_key)}],["preview",previewRefJson(value.preview)],["preview_digest",{kind:"string",value:MutationPreviewDigest(value.preview_digest)}],["request_digest",{kind:"string",value:WorkContextRequestDigest(value.request_digest)}]]); }
function decodeApprovalValue(value: JsonValue, preview: MutationPreview): MutationApproval { const fields=exactFields(value,APPROVAL_FIELDS,WORK_CONTEXT_INVALID_BODY);return validateMutationApproval({decided_at_ms:bodyInteger(fields,"decided_at_ms",WORK_CONTEXT_INVALID_BODY),decided_by:decodeActorValue(bodyValue(fields,"decided_by",WORK_CONTEXT_INVALID_BODY)),decision:bodyString(fields,"decision",WORK_CONTEXT_INVALID_BODY) as MutationApprovalDecision,expires_at_ms:bodyInteger(fields,"expires_at_ms",WORK_CONTEXT_INVALID_BODY),id:MutationApprovalId(bodyString(fields,"id",WORK_CONTEXT_INVALID_BODY)),idempotency_key:IdempotencyKey(bodyString(fields,"idempotency_key",WORK_CONTEXT_INVALID_BODY)),preview:decodePreviewRefValue(bodyValue(fields,"preview",WORK_CONTEXT_INVALID_BODY)),preview_digest:MutationPreviewDigest(bodyString(fields,"preview_digest",WORK_CONTEXT_INVALID_BODY)),request_digest:WorkContextRequestDigest(bodyString(fields,"request_digest",WORK_CONTEXT_INVALID_BODY))},preview); }
export function encodeWorkContextMutationApproval(value: MutationApproval, preview: MutationPreview): Uint8Array { return lifecycleBytes(object([["approval",approvalJson(validateMutationApproval(value,preview))],["schema",{kind:"string",value:PLATFORM_SCHEMA_V2}]])); }
export function decodeWorkContextMutationApproval(payload: Uint8Array, preview: MutationPreview): MutationApproval { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>{const fields=exactFields(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES),["approval","schema"],WORK_CONTEXT_INVALID_BODY);if(bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY)!==PLATFORM_SCHEMA_V2)workContextRefusal("lifecycle schema is incompatible");return decodeApprovalValue(bodyValue(fields,"approval",WORK_CONTEXT_INVALID_BODY),preview);}); }

export function validateMutationSubmission(value: MutationSubmission, preview: MutationPreview): MutationSubmission { exactInput(value,SUBMISSION_FIELDS);if(value.schema!==PLATFORM_SCHEMA_V2||value.preview.id!==preview.preview.id||value.preview.revision!==preview.preview.revision||value.preview_digest!==mutationPreviewDigest(preview)||value.request_digest!==preview.proposal.request_digest||value.idempotency_key!==preview.proposal.idempotency_key||value.submitted_at_ms<preview.issued_at_ms||value.submitted_at_ms>=preview.expires_at_ms||value.submitted_at_ms>LIFECYCLE_EPOCH_MAX)workContextRefusal("submission does not bind preview");const approval=value.approval===null?null:validateMutationApproval(value.approval,preview);if(preview.approval==="required"&&(approval===null||approval.decision!=="granted"||value.submitted_at_ms>=approval.expires_at_ms))workContextRefusal("approval is absent, denied, or expired");if(preview.approval==="not_required"&&approval!==null)workContextRefusal("approval is unexpected");return {...value,approval,preview_digest:MutationPreviewDigest(value.preview_digest)}; }
export function encodeWorkContextMutationSubmission(value: MutationSubmission, preview: MutationPreview): Uint8Array { const submission=validateMutationSubmission(value,preview);return lifecycleBytes(object([["approval",submission.approval===null?{kind:"null"}:approvalJson(submission.approval)],["idempotency_key",{kind:"string",value:submission.idempotency_key}],["preview",previewRefJson(submission.preview)],["preview_digest",{kind:"string",value:submission.preview_digest}],["request_digest",{kind:"string",value:submission.request_digest}],["schema",{kind:"string",value:submission.schema}],["submitted_at_ms",{kind:"integer",value:submission.submitted_at_ms}]])); }
export function decodeWorkContextMutationSubmission(payload: Uint8Array, preview: MutationPreview): MutationSubmission { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>{const fields=exactFields(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES),SUBMISSION_FIELDS,WORK_CONTEXT_INVALID_BODY);const item=bodyValueOrNull(fields,"approval",WORK_CONTEXT_INVALID_BODY);return validateMutationSubmission({approval:item===null?null:decodeApprovalValue(item,preview),idempotency_key:IdempotencyKey(bodyString(fields,"idempotency_key",WORK_CONTEXT_INVALID_BODY)),preview:decodePreviewRefValue(bodyValue(fields,"preview",WORK_CONTEXT_INVALID_BODY)),preview_digest:MutationPreviewDigest(bodyString(fields,"preview_digest",WORK_CONTEXT_INVALID_BODY)),request_digest:WorkContextRequestDigest(bodyString(fields,"request_digest",WORK_CONTEXT_INVALID_BODY)),schema:bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2,submitted_at_ms:bodyInteger(fields,"submitted_at_ms",WORK_CONTEXT_INVALID_BODY)},preview);}); }

function validateMutationReceipt(value: MutationReceipt, submission: MutationSubmission, preview: MutationPreview): MutationReceipt {exactInput(value,RECEIPT_FIELDS);if(value.schema!==PLATFORM_SCHEMA_V2||!(value.outcome==="accepted"||value.outcome==="completed"||value.outcome==="conflict"||value.outcome==="rejected"))workContextRefusal("receipt outcome or schema is invalid");if(value.preview.id!==submission.preview.id||value.preview.revision!==submission.preview.revision||value.preview_digest!==submission.preview_digest||value.preview_digest!==mutationPreviewDigest(preview)||value.request_digest!==submission.request_digest||value.idempotency_key!==submission.idempotency_key||value.approval_id!==(submission.approval?.id??null)||value.recorded_at_ms<submission.submitted_at_ms||value.recorded_at_ms>LIFECYCLE_EPOCH_MAX)workContextRefusal("receipt does not bind submission");const expectedRevision=value.outcome==="completed"?preview.resulting.revision:null;if(value.resulting_revision!==expectedRevision)workContextRefusal("receipt resulting revision is incoherent");return {...value,preview_digest:MutationPreviewDigest(value.preview_digest)};}
export function encodeWorkContextMutationReceipt(value: MutationReceipt, submission: MutationSubmission, preview: MutationPreview): Uint8Array { const receipt=validateMutationReceipt(value,submission,preview);return lifecycleBytes(object([["approval_id",receipt.approval_id===null?{kind:"null"}:{kind:"string",value:MutationApprovalId(receipt.approval_id)}],["id",{kind:"string",value:ReceiptId(receipt.id)}],["idempotency_key",{kind:"string",value:IdempotencyKey(receipt.idempotency_key)}],["outcome",{kind:"string",value:receipt.outcome}],["preview",previewRefJson(receipt.preview)],["preview_digest",{kind:"string",value:receipt.preview_digest}],["recorded_at_ms",{kind:"integer",value:receipt.recorded_at_ms}],["request_digest",{kind:"string",value:WorkContextRequestDigest(receipt.request_digest)}],["resulting_revision",receipt.resulting_revision===null?{kind:"null"}:{kind:"integer",value:WorkContextRevision(receipt.resulting_revision)}],["schema",{kind:"string",value:PLATFORM_SCHEMA_V2}]])); }
export function decodeWorkContextMutationReceipt(payload: Uint8Array, submission: MutationSubmission, preview: MutationPreview): MutationReceipt { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>{const fields=exactFields(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES),RECEIPT_FIELDS,WORK_CONTEXT_INVALID_BODY);const approval=bodyStringOrNull(fields,"approval_id",WORK_CONTEXT_INVALID_BODY);const revision=bodyValueOrNull(fields,"resulting_revision",WORK_CONTEXT_INVALID_BODY);const outcome=bodyString(fields,"outcome",WORK_CONTEXT_INVALID_BODY) as MutationReceipt["outcome"];const receipt={approval_id:approval===null?null:MutationApprovalId(approval),id:ReceiptId(bodyString(fields,"id",WORK_CONTEXT_INVALID_BODY)),idempotency_key:IdempotencyKey(bodyString(fields,"idempotency_key",WORK_CONTEXT_INVALID_BODY)),outcome,preview:decodePreviewRefValue(bodyValue(fields,"preview",WORK_CONTEXT_INVALID_BODY)),preview_digest:MutationPreviewDigest(bodyString(fields,"preview_digest",WORK_CONTEXT_INVALID_BODY)),recorded_at_ms:bodyInteger(fields,"recorded_at_ms",WORK_CONTEXT_INVALID_BODY),request_digest:WorkContextRequestDigest(bodyString(fields,"request_digest",WORK_CONTEXT_INVALID_BODY)),resulting_revision:revision===null?null:(revision.kind==="integer"?WorkContextRevision(revision.value):workContextRefusal("resulting revision is not an integer")),schema:bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY) as typeof PLATFORM_SCHEMA_V2};return validateMutationReceipt(receipt,submission,preview);}); }

const REFUSAL_CATEGORIES: readonly MutationRefusalCategory[]=["invalid_request","unauthorized","authority_widening","stale_revision","conflict","preview_expired","approval_required","approval_unexpected","approval_mismatch","approval_denied","approval_expired","unknown","resync_required","unavailable"];
export function encodeWorkContextMutationRefusal(value: MutationRefusal): Uint8Array { exactInput(value,REFUSAL_FIELDS);if(!REFUSAL_CATEGORIES.includes(value.category)||value.schema!==PLATFORM_SCHEMA_V2)workContextRefusal("refusal is invalid");return lifecycleBytes(object([["category",{kind:"string",value:value.category}],["explanation",{kind:"string",value:WorkContextLabel(value.explanation)}],["request_digest",value.request_digest===null?{kind:"null"}:{kind:"string",value:WorkContextRequestDigest(value.request_digest)}],["schema",{kind:"string",value:value.schema}]])); }
export function decodeWorkContextMutationRefusal(payload: Uint8Array): MutationRefusal { return refuse(WORK_CONTEXT_VALUE_INVALID,()=>{const fields=exactFields(parseDocument(payload,MAX_MUTATION_CANONICAL_BYTES),REFUSAL_FIELDS,WORK_CONTEXT_INVALID_BODY);const category=bodyString(fields,"category",WORK_CONTEXT_INVALID_BODY) as MutationRefusalCategory;if(!REFUSAL_CATEGORIES.includes(category))workContextRefusal("unknown refusal category");const digest=bodyStringOrNull(fields,"request_digest",WORK_CONTEXT_INVALID_BODY);const schema=bodyString(fields,"schema",WORK_CONTEXT_INVALID_BODY);if(schema!==PLATFORM_SCHEMA_V2)workContextRefusal("lifecycle schema is incompatible");return {category,explanation:WorkContextLabel(bodyString(fields,"explanation",WORK_CONTEXT_INVALID_BODY)),request_digest:digest===null?null:WorkContextRequestDigest(digest),schema:PLATFORM_SCHEMA_V2};}); }
"#,
    );
}

/// Emit the strict validator/codec implementation for the generated review
/// sub-contract. Its declarations are driven by the Rust model and the
/// cross-language canonical corpus holds this implementation to the Rust
/// encoders and refusal categories.
fn emit_review_context_implementation(out: &mut String) {
    out.push('\n');
    let template = include_str!("platform_v2_review.typescript");
    let implementation = template
        .strip_prefix("// SPDX-License-Identifier: Elastic-2.0\n\n")
        .expect("review TypeScript template carries the product license marker");
    out.push_str(implementation);
}

/// Emit one generated file.
///
/// Output is a pure function of the input: every collection is sorted and no
/// clock, environment or allocation address reaches the text.
#[must_use]
pub fn emit_module(module: &GeneratedModule) -> String {
    let mut out = String::new();
    emit_banner(&mut out, &module.source, &module.doc);

    emit_imports(&mut out, module);

    if !module.preamble.is_empty() {
        out.push('\n');
        out.push_str(&module.preamble);
    }

    let mut constants = module.constants.clone();
    constants.sort_by(|left, right| left.name.cmp(&right.name));
    for constant in &constants {
        emit_constant(&mut out, constant);
    }

    let mut branded = module.branded_ids.clone();
    branded.sort();
    for id in &branded {
        emit_branded_id(&mut out, id);
    }

    let mut strings = module.bounded_strings.clone();
    strings.sort();
    for bounded in &strings {
        emit_bounded_string(&mut out, bounded);
    }

    let mut integers = module.bounded_integers.clone();
    integers.sort();
    for integer in &integers {
        emit_bounded_integer(&mut out, integer);
    }

    let mut enums = module.enums.clone();
    enums.sort_by(|left, right| left.name.cmp(&right.name));
    for generated in &enums {
        emit_enum(&mut out, generated);
    }

    let mut unions = module.unions.clone();
    unions.sort();
    for union in &unions {
        emit_union(&mut out, union);
    }

    let mut interfaces = module.interfaces.clone();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    for interface in &interfaces {
        emit_interface(&mut out, interface);
    }

    if module.implementation == Some(GeneratedImplementation::WorkContext) {
        emit_work_context_implementation(&mut out);
    }
    if module.implementation == Some(GeneratedImplementation::ReviewContext) {
        emit_review_context_implementation(&mut out);
    }
    if module.implementation == Some(GeneratedImplementation::PlatformV2Transport) {
        out.push('\n');
        let template = include_str!("platform_v2_transport.typescript");
        let implementation = template
            .strip_prefix("// SPDX-License-Identifier: Elastic-2.0\n\n")
            .expect("Platform v2 transport TypeScript template carries the product license marker");
        out.push_str(implementation);
    }

    if let Some(surface) = &module.json_surface {
        let mut documents = surface.documents.clone();
        documents.sort_by(|left, right| left.body.name.cmp(&right.body.name));
        for document in &documents {
            emit_body_object(
                &mut out,
                &surface.invalid_body_category,
                &document.body,
                document.encode,
            );
        }
    }

    if let Some(surface) = &module.command_surface {
        emit_command_surface(&mut out, surface);
    }

    out
}

/// Every generated file as `(file name, contents)`, in file-name order.
///
/// This is the whole of what [`GENERATED_DIRECTORY`] is allowed to contain
/// besides the spike's own output, and it is what the drift gate in
/// `tests/codegen.rs` compares the working tree against.
#[must_use]
pub fn generated_files() -> Vec<(String, String)> {
    let modules = maintained_modules();
    let mut files = maintained_files();
    let digest = schema_digest(&files);
    let (_, platform_v1_digest) = generated_platform_v1_schema_digest();
    files.push((
        module_file_name(BARREL_MODULE),
        emit_barrel(&modules, &digest, &platform_v1_digest),
    ));
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

/// The maintained modules as `(file name, contents)`, barrel excluded.
///
/// This is the digest's input, so it is one function rather than two spellings
/// of the same fold.
fn maintained_files() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = maintained_modules()
        .iter()
        .map(|module| (module.file_name.clone(), emit_module(module)))
        .collect();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

/// The schema digest the barrel carries, as `(algorithm, hex)`.
///
/// Exposed so a consumer — a release manifest, a conformance test — can ask the
/// generator for the digest rather than parsing TypeScript out of the
/// checked-in barrel.
#[must_use]
pub fn generated_schema_digest() -> (&'static str, String) {
    (crate::digest::ALGORITHM, schema_digest(&maintained_files()))
}

/// The digest of the exact generated Platform v1 module, excluding additive
/// modules from newer negotiated protocol versions.
///
/// SDK distributions that still advertise only Platform v1 use this pin. The
/// aggregate [`generated_schema_digest`] deliberately moves whenever any
/// generated module moves, including the separately negotiated v2 surface.
#[must_use]
pub fn generated_platform_v1_schema_digest() -> (&'static str, String) {
    let files = maintained_files();
    let platform_v1 = files
        .iter()
        .find(|(name, _)| name == &module_file_name(PLATFORM_MODULE))
        .expect("maintained surface carries Platform v1");
    (
        crate::digest::ALGORITHM,
        schema_digest(std::slice::from_ref(platform_v1)),
    )
}
