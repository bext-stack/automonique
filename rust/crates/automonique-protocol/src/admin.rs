// SPDX-License-Identifier: Elastic-2.0

//! Bounded local administration protocol for the Automonique daemon.
//!
//! Authentication is intentionally not represented in these messages. A local
//! server authenticates the Unix peer before it decodes a frame; putting a
//! bearer secret in the payload would make that boundary weaker and easier to
//! leak. Version one exposes only a read-only status query and an orderly
//! shutdown request, a local no-effect synthetic intake, explicit fenced
//! reconciliation paths for ambiguous synthetic runs and expired outbox
//! effects, and a durable-custody submission of one canonical RunSpec document.
//!
//! # The RunSpec document is opaque here
//!
//! This crate does not depend on `automonique-runner` and therefore cannot
//! decode, validate or interpret a RunSpec. [`SubmittedRunSpec`] carries the
//! document as bounded bytes and the digest a submitter declares for them.
//! Carrying is all it does: see that type's documentation for what a carried
//! pair does *not* establish.
//!
//! # One socket, seven protocols
//!
//! [`LocalRequest`] is what a local endpoint decodes a frame into. The local
//! socket serves this protocol, [`crate::runs_api`]'s read surface,
//! [`crate::automation_api`]'s control surface, [`crate::approval_api`]'s
//! decision surface, [`crate::batch_api`]'s batch control surface *and*
//! [`crate::execute_api`]'s execution verb, plus [`crate::platform_api`]'s
//! federated platform contract, and the
//! envelope's declared protocol name is what separates them — not a heuristic,
//! not a fallback chain, and not a widening of [`AdminCommand`]. That is the
//! arrangement `runs_api` asks for in as many words: its values travel "on the
//! same canonical-JSON envelope [`crate::admin`] uses, under a separate protocol
//! name so the admin lane's closed kind set stays closed." A run listing, an
//! automation pause, a recorded approval, a registered batch or a started run
//! is therefore not an admin command, does not appear in
//! [`crate::command_registry`]'s admin surface, and cannot reach
//! [`DaemonStatus`].
//!
//! Adding the third lane cost this module one enum arm, one match arm and one
//! frame-fit assertion, and cost the admin lane nothing at all — which is the
//! property the arrangement was chosen for. The fourth cost exactly the same
//! three lines, and so did the fifth, sixth, and seventh
//! ([`crate::execute_api`], the one lane on this socket that *starts* something),
//! which is the evidence that the property holds rather than merely having held
//! once.

use std::error::Error;
use std::fmt;

use crate::approval_api::{APPROVAL_PROTOCOL, ApprovalApiError, ApprovalRequest};
use crate::automation_api::{AUTOMATION_PROTOCOL, AutomationApiError, AutomationRequest};
use crate::batch_api::{BATCH_CONTROL_PROTOCOL, BatchApiError, BatchRequest};
use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId, SupportedProtocol,
    VersionRange,
};
use crate::digest::{Sha256, Sha256Digest};
use crate::execute_api::{EXECUTE_PROTOCOL, ExecuteApiError, ExecuteRequest};
use crate::platform::PLATFORM_PROTOCOL;
use crate::platform_api::{
    MAX_PLATFORM_REQUEST_CANONICAL_BYTES, PlatformApiError, PlatformRequestMessage,
};
use crate::provenance::{CausationId, CorrelationId, TraceId};
use crate::runs_api::{RUNS_PROTOCOL, RunsApiError, RunsRequest};
use crate::tools::RunId;
use crate::wire::{JsonValue, Message};

/// Stable protocol name for local daemon administration.
pub const ADMIN_PROTOCOL: &str = "automonique.admin";

/// Maximum canonical message bytes accepted by the local admin transport.
pub const MAX_ADMIN_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of a daemon instance identifier.
pub const MAX_INSTANCE_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a local synthetic-work scope.
pub const MAX_SYNTHETIC_SCOPE_BYTES: usize = 256;

/// Maximum UTF-8 byte length of its caller-supplied idempotency key.
///
/// The scheduler derives bounded receipt keys from this coordinate, so this
/// limit intentionally leaves room for their fixed namespace prefixes.
pub const MAX_SYNTHETIC_KEY_BYTES: usize = 128;

/// Maximum task bytes accepted by the local synthetic intake.
pub const MAX_SYNTHETIC_TASK_BYTES: usize = 8 * 1024;

/// Maximum byte length of reconciliation coordinates and reasons.
pub const MAX_RECONCILIATION_FIELD_BYTES: usize = 256;

/// Maximum stable refusal-category bytes returned to an authenticated client.
pub const MAX_ADMIN_REFUSAL_CATEGORY_BYTES: usize = 64;

/// Maximum Prometheus text bytes returned by one authenticated scrape.
pub const MAX_METRICS_EXPOSITION_BYTES: usize = 24 * 1024;

/// Maximum reload identifier bytes carried by the operator status surface.
pub const MAX_RELOAD_ID_BYTES: usize = 128;

/// Maximum recent generation tenures returned by one bounded snapshot.
pub const MAX_GENERATION_HISTORY_ENTRIES: usize = 64;

/// Maximum reload transitions returned by one bounded status response.
pub const MAX_RELOAD_TRANSITIONS: usize = 16;

const METRICS_RESPONSE_OVERHEAD_BYTES: usize = 512;
const _: () = assert!(
    2 * MAX_METRICS_EXPOSITION_BYTES + METRICS_RESPONSE_OVERHEAD_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximally escaped metrics response must fit one admin frame"
);

/// Maximum UTF-8 byte length of the actor named on an intake pause or resume.
///
/// The transport authenticates the Unix peer; this string is the operator's own
/// account of who decided, which the daemon records verbatim and never treats
/// as an authentication claim.
pub const MAX_INTAKE_ACTOR_BYTES: usize = 128;

/// Maximum UTF-8 byte length of an intake pause reason.
pub const MAX_INTAKE_REASON_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a run submission's idempotency key.
pub const MAX_RUN_SUBMISSION_KEY_BYTES: usize = 128;

/// Maximum canonical RunSpec document bytes this lane will carry.
///
/// # Arithmetic, and the ceiling this does not reach
///
/// A canonical RunSpec document is arbitrary bytes, so it travels hex-encoded
/// and occupies exactly `2 * N` bytes inside the canonical body. One
/// `submit_run` message therefore costs
///
/// ```text
/// 2 * N + SUBMIT_RUN_OVERHEAD_BYTES <= MAX_ADMIN_CANONICAL_BYTES
/// 2 * 24576 + 600 = 49752 <= 65536
/// ```
///
/// which leaves deliberate headroom rather than sitting on the boundary. The
/// runner's own `MAX_RUN_SPEC_BYTES` is the 8 MiB protocol frame ceiling —
/// about 341 times this value — so **a document this lane refuses can still be
/// a valid RunSpec.** The two limits are not reconciled and must not be: an
/// 8 MiB document cannot be hex-encoded into a 64 KiB admin frame, and no
/// widening of this constant would change that. A document above this bound is
/// [`AdminError::DocumentTooLarge`] at encode and at decode, never a truncation
/// and never a silently smaller message.
pub const MAX_SUBMITTED_RUN_SPEC_BYTES: usize = 24 * 1024;

/// Worst-case canonical bytes of one `submit_run` message, excluding the hex
/// document.
///
/// - 216 for the envelope: `{"body":`, the `kind`, `protocol` and `version`
///   members, and a maximal 128-byte `request_id`.
/// - 256 for the body scaffold: both key names, the quoted 71-byte
///   `sha256:`-spelled digest, a maximal idempotency key, and the punctuation.
/// - One further [`MAX_RUN_SUBMISSION_KEY_BYTES`] because an idempotency key
///   may be entirely quotes or backslashes, each of which JSON-escapes to two
///   bytes. Budgeting the escaped worst case is why the bound holds for keys
///   this protocol actually admits, not merely for well-behaved ones.
const SUBMIT_RUN_OVERHEAD_BYTES: usize = 216 + 256 + MAX_RUN_SUBMISSION_KEY_BYTES;

const _: () = assert!(
    2 * MAX_SUBMITTED_RUN_SPEC_BYTES + SUBMIT_RUN_OVERHEAD_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal submit_run message must fit one admin frame"
);

/// What this build's local endpoints can do, as one monotonic integer.
///
/// # Why a number rather than a version
///
/// A semantic version answers "is this newer?", which is not the question a
/// client has. The question is "can I use the thing I am about to use", and the
/// only honest form of that is a number a client compares against the number it
/// was written for. So this is not the daemon's version, not the protocol's
/// major, and not derived from either: it is a counter of *observable
/// capability*, and the changelog below is the whole of its meaning.
///
/// # When it moves
///
/// Three cases, and they are the same three every time:
///
/// - an endpoint, field, kind or vocabulary member was **added**;
/// - one was **removed** or narrowed;
/// - a behaviour a client could correctly depend on was **fixed**, which is a
///   change to what the endpoint does whatever the diff says.
///
/// It does **not** move for prose, tests, refactoring, or a performance change
/// no client can observe. A build whose capability did not move is a build a
/// client written against the previous number can use unchanged.
///
/// # Changelog
///
/// **Append-only.** An entry is written once and never edited: a client that
/// read entry 3 and shipped against it cannot be reached to be told it changed.
/// `tests/admin.rs` holds the prefix of this list fixed, so editing a landed
/// entry fails a test rather than a review. A new capability appends a line and
/// increments the constant, in the same commit as the change it describes.
///
/// - **1** — the first numbered surface: the six lanes of the local admin
///   socket (`admin`, `runs`, `automation`, `approval`, `batch`, `execute`) and
///   the live progress stream, with [`ENDPOINT_MATURITY`] as their declared
///   maturity and [`DaemonStatus::capability`] reporting this number.
/// - **2** — added the read-only `automonique.admin/metrics` endpoint.
/// - **3** — added trace, correlation and causation ids to reconciliation evidence.
/// - **4** — corrected `execution_state` to report that the execution lane is
///   wired; the former `*_no_lane` values remain decode-only aliases.
/// - **5** — added the ten-method `automonique.platform/v1` local endpoint.
/// - **6** — added generation history and reload-status reads.
/// - **7** — added authenticated generation reload execution.
/// - **8** — added authenticated rollback to the retained compatible release.
/// - **9** — added durable reload acceptance before asynchronous handoff.
pub const ADMIN_CAPABILITY: u32 = 9;

/// How much of a promise an endpoint is.
///
/// Three states, and the middle one is the only one that is a commitment.
/// Closed, because a client's decision to depend on an endpoint rests on this
/// and a spelling it did not recognise would have to be guessed at.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Maturity {
    /// May change shape or disappear without the capability integer being a
    /// warning anybody had time to act on. Depend on it deliberately.
    Experimental,
    /// Will not change shape incompatibly. A removal is a capability bump and
    /// a deprecation first.
    Stable,
    /// Still served, and going away. New clients use its replacement.
    Deprecated,
}

impl Maturity {
    /// Every maturity, from least to most committed and then out again.
    pub const ALL: [Self; 3] = [Self::Experimental, Self::Stable, Self::Deprecated];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Stable => "stable",
            Self::Deprecated => "deprecated",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|maturity| maturity.as_str() == value)
    }
}

impl fmt::Display for Maturity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Every endpoint this build serves locally, and what it promises about each.
///
/// The name is `<protocol>/<kind>` — the two coordinates that already route a
/// request, spelled as one string rather than invented. Nothing consults this
/// table to *decide* anything: it is a declaration a client reads, exactly as
/// [`ADMIN_CAPABILITY`] is, and a daemon that served an endpoint absent from it
/// would be serving something it never promised.
///
/// **Append-only, in the same sense the changelog is.** An entry's maturity may
/// move forward — experimental to stable, stable to deprecated — because that
/// is what maturity is for. An entry may not be deleted, renamed, or moved
/// backwards, and `tests/admin.rs` holds every landed row to that. Removing an
/// endpoint means marking it deprecated and bumping the capability; a row that
/// vanished would tell a client the endpoint never existed.
///
/// Every lane is still [`Maturity::Experimental`]. That is the honest reading:
/// none has yet accumulated a supported-client compatibility promise.
pub const ENDPOINT_MATURITY: &[(&str, Maturity)] = &[
    ("automonique.admin/status", Maturity::Experimental),
    ("automonique.admin/submit_synthetic", Maturity::Experimental),
    ("automonique.admin/submit_run", Maturity::Experimental),
    (
        "automonique.admin/inspect_reconciliation",
        Maturity::Experimental,
    ),
    (
        "automonique.admin/fail_reconciliation",
        Maturity::Experimental,
    ),
    ("automonique.admin/inspect_outbox", Maturity::Experimental),
    ("automonique.admin/reconcile_outbox", Maturity::Experimental),
    ("automonique.admin/pause_intake", Maturity::Experimental),
    ("automonique.admin/resume_intake", Maturity::Experimental),
    ("automonique.admin/shutdown", Maturity::Experimental),
    ("automonique.runs/list_runs", Maturity::Experimental),
    ("automonique.runs/run_detail", Maturity::Experimental),
    ("automonique.execute/execute_run", Maturity::Experimental),
    ("automonique.execute/cancel_run", Maturity::Experimental),
    (
        "automonique.automation/register_automation",
        Maturity::Experimental,
    ),
    (
        "automonique.automation/set_enablement",
        Maturity::Experimental,
    ),
    (
        "automonique.automation/list_automations",
        Maturity::Experimental,
    ),
    (
        "automonique.automation/automation_detail",
        Maturity::Experimental,
    ),
    (
        "automonique.approval/record_approval",
        Maturity::Experimental,
    ),
    (
        "automonique.approval/list_approvals",
        Maturity::Experimental,
    ),
    (
        "automonique.approval/approval_detail",
        Maturity::Experimental,
    ),
    (
        "automonique.approval/approvals_by_subject",
        Maturity::Experimental,
    ),
    (
        "automonique.approval/decide_request",
        Maturity::Experimental,
    ),
    ("automonique.batch/register_batch", Maturity::Experimental),
    ("automonique.batch/advance_member", Maturity::Experimental),
    ("automonique.batch/list_batches", Maturity::Experimental),
    ("automonique.batch/batch_detail", Maturity::Experimental),
    (
        "automonique.progress.stream/subscribe",
        Maturity::Experimental,
    ),
    ("automonique.admin/metrics", Maturity::Experimental),
    ("automonique.admin/generations", Maturity::Experimental),
    ("automonique.admin/reload", Maturity::Experimental),
    ("automonique.admin/rollback", Maturity::Experimental),
    ("automonique.admin/reload_status", Maturity::Experimental),
    ("automonique.platform/capabilities", Maturity::Experimental),
    ("automonique.platform/snapshot", Maturity::Experimental),
    ("automonique.platform/subscribe", Maturity::Experimental),
    ("automonique.platform/execute", Maturity::Experimental),
    ("automonique.platform/get_receipt", Maturity::Experimental),
    ("automonique.platform/list_sessions", Maturity::Experimental),
    ("automonique.platform/attach", Maturity::Experimental),
    ("automonique.platform/detach", Maturity::Experimental),
    ("automonique.platform/claim_control", Maturity::Experimental),
    (
        "automonique.platform/release_control",
        Maturity::Experimental,
    ),
];

/// A refusal while constructing or decoding an administration message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminError {
    /// The shared envelope or canonical JSON codec refused the message.
    Codec(CodecError),
    /// The message kind is not part of this closed protocol version.
    UnknownKind,
    /// A command body was not the exact shape defined for its kind.
    InvalidBody,
    /// A response counter cannot be represented by the integer-only wire codec.
    CounterOutOfRange {
        /// Field that was outside the wire range.
        field: &'static str,
    },
    /// The instance identifier was empty, too long, or contained a control.
    InvalidInstanceId,
    /// A security-relevant daemon state spelling was not defined by this build.
    UnknownState,
    /// A carried RunSpec document is larger than one admin frame can hold.
    ///
    /// Only lengths are reported. A document that violates this bound is never
    /// echoed, in whole or in part, by this refusal.
    DocumentTooLarge {
        /// Maximum accepted document length.
        max_bytes: usize,
        /// Length the submitter presented.
        actual_bytes: usize,
    },
}

impl AdminError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "admin_unknown_kind",
            Self::InvalidBody => "admin_invalid_body",
            Self::CounterOutOfRange { .. } => "admin_counter_out_of_range",
            Self::InvalidInstanceId => "admin_invalid_instance_id",
            Self::UnknownState => "admin_unknown_state",
            Self::DocumentTooLarge { .. } => "admin_document_too_large",
        }
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(formatter, "administration codec refused message: {error}")
            }
            Self::UnknownKind => formatter.write_str("administration message kind is not defined"),
            Self::InvalidBody => formatter.write_str("administration message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "administration counter {field} is outside the wire range"
                )
            }
            Self::InvalidInstanceId => formatter.write_str("daemon instance identifier is invalid"),
            Self::UnknownState => formatter.write_str("daemon state is not defined"),
            Self::DocumentTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "run specification document is {actual_bytes} bytes; maximum is {max_bytes}"
            ),
        }
    }
}

impl Error for AdminError {}

impl From<CodecError> for AdminError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// Opaque identifier for one daemon process generation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdminInstanceId(String);

impl AdminInstanceId {
    /// Validate and construct an instance identifier.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidInstanceId`] for empty, overlong, or
    /// control-character-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, AdminError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_INSTANCE_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(AdminError::InvalidInstanceId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle state reported by the foreground daemon.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DaemonState {
    /// Durable state is being opened and checked.
    Starting,
    /// The daemon is ready and may accept intake.
    Ready,
    /// Intake is closed while existing work drains.
    Draining,
    /// The daemon completed its orderly shutdown.
    Stopped,
    /// A required subsystem failed and operation is refused.
    Failed,
}

impl DaemonState {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, AdminError> {
        match value {
            "starting" => Ok(Self::Starting),
            "ready" => Ok(Self::Ready),
            "draining" => Ok(Self::Draining),
            "stopped" => Ok(Self::Stopped),
            "failed" => Ok(Self::Failed),
            _ => Err(AdminError::UnknownState),
        }
    }
}

/// Telegram capability state reported independently from local synthetic intake.
///
/// The three states are ordered by capability, and the boundary that matters to
/// an operator is between the second and the third: the first two both say no
/// trusted HTTP client exists, so no message can arrive and no reply can leave,
/// while the third says one does. A host must never report a no-client state
/// while holding a client — that field is the only place an operator can read
/// whether their bot is answering, and a hopeful answer there is worse than no
/// field at all.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TelegramState {
    /// No trusted HTTP client or configured bot exists; no bot lease is owned.
    DisabledNoClient,
    /// A configured bot lease is owned, but HTTP is unavailable: no client is
    /// held and no credential is retained, so nothing can arrive or leave.
    ///
    /// About what is *held*, not about what was once constructed. A host whose
    /// poller stopped and released its client is in this state as truthfully as
    /// one that never built a client at all — both mean the same thing to the
    /// operator reading it, which is that the bot is not answering.
    LeaseOwnedNoClient,
    /// A configured bot lease is owned *and* a trusted HTTP client is bound to
    /// it, so this host is the live poller for that bot.
    ///
    /// The client and the lease are acquired together, which is what makes this
    /// one state rather than two: a host that holds the lease and could talk to
    /// Telegram is exactly the host that will, for as long as it serves.
    PollingLive,
}

impl TelegramState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisabledNoClient => "disabled_no_client",
            Self::LeaseOwnedNoClient => "lease_owned_no_client",
            Self::PollingLive => "polling_live",
        }
    }

    fn parse(value: &str) -> Result<Self, AdminError> {
        match value {
            "disabled_no_client" => Ok(Self::DisabledNoClient),
            "lease_owned_no_client" => Ok(Self::LeaseOwnedNoClient),
            "polling_live" => Ok(Self::PollingLive),
            _ => Err(AdminError::InvalidBody),
        }
    }
}

/// Sandboxed-execution capability state, reported independently from intake.
///
/// Both states say the execution lane is wired. The distinction is whether the
/// host can enforce the sandbox that lane requires: an unavailable host keeps
/// the lane present but makes every start fail closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionState {
    /// The daemon's process has no delegated cgroup v2 domain or lacks another
    /// required enforcement mechanism, so the composed sandbox is
    /// unenforceable here and the wired execution lane refuses fail-closed.
    SandboxUnavailableLaneWired,
    /// The host can enforce the full composed sandbox for a launcher —
    /// delegated cgroup v2 containment, Landlock filesystem and TCP domains,
    /// and the seccomp socket filter. The wired execution lane may accept work
    /// that passes its remaining configuration and admission gates.
    SandboxEnforceableLaneWired,
}

impl ExecutionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SandboxUnavailableLaneWired => "sandbox_unavailable_lane_wired",
            Self::SandboxEnforceableLaneWired => "sandbox_enforceable_lane_wired",
        }
    }

    fn parse(value: &str) -> Result<Self, AdminError> {
        match value {
            "sandbox_unavailable_lane_wired" | "sandbox_unavailable_no_lane" => {
                Ok(Self::SandboxUnavailableLaneWired)
            }
            "sandbox_enforceable_lane_wired" | "sandbox_enforceable_no_lane" => {
                Ok(Self::SandboxEnforceableLaneWired)
            }
            _ => Err(AdminError::InvalidBody),
        }
    }
}

/// Commands admitted by the first local administration protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminCommand {
    /// Read a consistent daemon status snapshot.
    Status,
    /// Read a Prometheus text snapshot over the authenticated local socket.
    Metrics,
    /// Read the recent append-only generation tenure and handoff history.
    Generations,
    /// Hand authority to one exact, locally verified immutable release.
    Reload,
    /// Hand authority back to the retained compatible release.
    Rollback,
    /// Read one reload epoch and its append-only transitions.
    ReloadStatus,
    /// Durably enqueue a no-effect synthetic work item.
    SubmitSynthetic,
    /// Take durable custody of one canonical RunSpec document.
    ///
    /// Acceptance is custody, not execution: no variant of this protocol
    /// launches, schedules or admits a run.
    SubmitRun,
    /// Inspect the durable evidence for one ambiguously claimed run.
    InspectReconciliation,
    /// Explicitly fail one exact old run observation under the daemon's fence.
    FailReconciliation,
    /// Inspect redacted durable evidence for one outbox effect.
    InspectOutbox,
    /// Close one exact expired outbox observation as delivered or dead-lettered.
    ReconcileOutbox,
    /// Durably close intake for this generation, naming the deciding operator.
    ///
    /// Unlike [`Self::Shutdown`], this outlives the process: a paused daemon
    /// that is restarted comes back paused.
    PauseIntake,
    /// Reopen intake, naming the operator who decided to.
    ResumeIntake,
    /// Stop intake and request an orderly shutdown.
    Shutdown,
}

impl AdminCommand {
    /// Every command, for coverage checks.
    ///
    /// Published so [`ENDPOINT_MATURITY`] can be held exhaustive over this lane
    /// by a test rather than by inspection: a command added here without a row
    /// there is a surface the daemon serves and never declared.
    pub const ALL: [Self; 15] = [
        Self::Status,
        Self::Metrics,
        Self::Generations,
        Self::Reload,
        Self::Rollback,
        Self::ReloadStatus,
        Self::SubmitSynthetic,
        Self::SubmitRun,
        Self::InspectReconciliation,
        Self::FailReconciliation,
        Self::InspectOutbox,
        Self::ReconcileOutbox,
        Self::PauseIntake,
        Self::ResumeIntake,
        Self::Shutdown,
    ];

    /// Stable wire spelling of this command's message kind.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Metrics => "metrics",
            Self::Generations => "generations",
            Self::Reload => "reload",
            Self::Rollback => "rollback",
            Self::ReloadStatus => "reload_status",
            Self::SubmitSynthetic => "submit_synthetic",
            Self::SubmitRun => "submit_run",
            Self::InspectReconciliation => "inspect_reconciliation",
            Self::FailReconciliation => "fail_reconciliation",
            Self::InspectOutbox => "inspect_outbox",
            Self::ReconcileOutbox => "reconcile_outbox",
            Self::PauseIntake => "pause_intake",
            Self::ResumeIntake => "resume_intake",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Operator decision for one expired, outcome-ambiguous outbox effect.
#[derive(Clone, Eq, PartialEq)]
pub enum OutboxReconciliationDecision {
    /// External delivery was independently confirmed.
    Delivered { receipt_key: String },
    /// The effect is permanently closed without delivery.
    DeadLetter { reason: String },
}

impl fmt::Debug for OutboxReconciliationDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivered { .. } => formatter.write_str("Delivered(<redacted>)"),
            Self::DeadLetter { .. } => formatter.write_str("DeadLetter(<redacted>)"),
        }
    }
}

/// Exact old outbox evidence carried into a fenced reconciliation decision.
#[derive(Clone, Eq, PartialEq)]
pub struct OutboxReconciliation {
    outbox_id: u64,
    expected_generation_id: String,
    expected_lease_epoch: u64,
    expected_lease_token: String,
    expected_attempt: u64,
    expected_revision: u64,
    decision: OutboxReconciliationDecision,
}

impl fmt::Debug for OutboxReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxReconciliation")
            .field("outbox_id", &self.outbox_id)
            .field("expected_generation_id", &self.expected_generation_id)
            .field("expected_lease_epoch", &self.expected_lease_epoch)
            .field("expected_attempt", &self.expected_attempt)
            .field("expected_revision", &self.expected_revision)
            .field("expected_lease_token", &"<redacted>")
            .field("decision", &"<redacted>")
            .finish()
    }
}

/// Fields used to construct one exact outbox reconciliation request.
pub struct OutboxReconciliationParts {
    pub outbox_id: u64,
    pub expected_generation_id: String,
    pub expected_lease_epoch: u64,
    pub expected_lease_token: String,
    pub expected_attempt: u64,
    pub expected_revision: u64,
    pub decision: OutboxReconciliationDecision,
}

impl OutboxReconciliation {
    pub fn new(parts: OutboxReconciliationParts) -> Result<Self, AdminError> {
        let decision_value = match &parts.decision {
            OutboxReconciliationDecision::Delivered { receipt_key } => receipt_key,
            OutboxReconciliationDecision::DeadLetter { reason } => reason,
        };
        if parts.outbox_id == 0
            || parts.expected_lease_epoch == 0
            || parts.expected_attempt == 0
            || parts.expected_revision == 0
            || !valid_coordinate(
                &parts.expected_generation_id,
                MAX_RECONCILIATION_FIELD_BYTES,
            )
            || !valid_coordinate(&parts.expected_lease_token, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(decision_value, MAX_RECONCILIATION_FIELD_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            outbox_id: parts.outbox_id,
            expected_generation_id: parts.expected_generation_id,
            expected_lease_epoch: parts.expected_lease_epoch,
            expected_lease_token: parts.expected_lease_token,
            expected_attempt: parts.expected_attempt,
            expected_revision: parts.expected_revision,
            decision: parts.decision,
        })
    }

    #[must_use]
    pub const fn outbox_id(&self) -> u64 {
        self.outbox_id
    }
    #[must_use]
    pub fn expected_generation_id(&self) -> &str {
        &self.expected_generation_id
    }
    #[must_use]
    pub const fn expected_lease_epoch(&self) -> u64 {
        self.expected_lease_epoch
    }
    #[must_use]
    pub fn expected_lease_token(&self) -> &str {
        &self.expected_lease_token
    }
    #[must_use]
    pub const fn expected_attempt(&self) -> u64 {
        self.expected_attempt
    }
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    #[must_use]
    pub const fn decision(&self) -> &OutboxReconciliationDecision {
        &self.decision
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        let (decision, value_name, value) = match &self.decision {
            OutboxReconciliationDecision::Delivered { receipt_key } => {
                ("delivered", "receipt_key", receipt_key)
            }
            OutboxReconciliationDecision::DeadLetter { reason } => {
                ("dead_letter", "reason", reason)
            }
        };
        Ok(JsonValue::Object(vec![
            (
                "decision".to_owned(),
                JsonValue::String(decision.to_owned()),
            ),
            (
                "expected_attempt".to_owned(),
                integer("expected_attempt", self.expected_attempt)?,
            ),
            (
                "expected_generation_id".to_owned(),
                JsonValue::String(self.expected_generation_id.clone()),
            ),
            (
                "expected_lease_epoch".to_owned(),
                integer("expected_lease_epoch", self.expected_lease_epoch)?,
            ),
            (
                "expected_lease_token".to_owned(),
                JsonValue::String(self.expected_lease_token.clone()),
            ),
            (
                "expected_revision".to_owned(),
                integer("expected_revision", self.expected_revision)?,
            ),
            (
                "outbox_id".to_owned(),
                integer("outbox_id", self.outbox_id)?,
            ),
            (value_name.to_owned(), JsonValue::String(value.clone())),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        let decision = required_body_string(body, "decision")?;
        let (fields, decision) = match decision.as_str() {
            "delivered" => (
                [
                    "decision",
                    "expected_attempt",
                    "expected_generation_id",
                    "expected_lease_epoch",
                    "expected_lease_token",
                    "expected_revision",
                    "outbox_id",
                    "receipt_key",
                ],
                OutboxReconciliationDecision::Delivered {
                    receipt_key: required_body_string(body, "receipt_key")?,
                },
            ),
            "dead_letter" => (
                [
                    "decision",
                    "expected_attempt",
                    "expected_generation_id",
                    "expected_lease_epoch",
                    "expected_lease_token",
                    "expected_revision",
                    "outbox_id",
                    "reason",
                ],
                OutboxReconciliationDecision::DeadLetter {
                    reason: required_body_string(body, "reason")?,
                },
            ),
            _ => return Err(AdminError::InvalidBody),
        };
        exact_fields(body, &fields)?;
        Self::new(OutboxReconciliationParts {
            outbox_id: unsigned(body, "outbox_id")?,
            expected_generation_id: required_body_string(body, "expected_generation_id")?,
            expected_lease_epoch: unsigned(body, "expected_lease_epoch")?,
            expected_lease_token: required_body_string(body, "expected_lease_token")?,
            expected_attempt: unsigned(body, "expected_attempt")?,
            expected_revision: unsigned(body, "expected_revision")?,
            decision,
        })
    }
}

/// Exact old-run coordinates carried into a fail-only reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationFailure {
    run_id: u64,
    expected_generation_id: String,
    expected_lease_epoch: u64,
    expected_revision: u64,
    decision_key: String,
    reason: String,
}

impl ReconciliationFailure {
    /// Construct a bounded compare-and-set decision.
    pub fn new(
        run_id: u64,
        expected_generation_id: impl Into<String>,
        expected_lease_epoch: u64,
        expected_revision: u64,
        decision_key: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let expected_generation_id = expected_generation_id.into();
        let decision_key = decision_key.into();
        let reason = reason.into();
        if run_id == 0
            || expected_lease_epoch == 0
            || expected_revision == 0
            || !valid_coordinate(&expected_generation_id, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&decision_key, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&reason, MAX_RECONCILIATION_FIELD_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            run_id,
            expected_generation_id,
            expected_lease_epoch,
            expected_revision,
            decision_key,
            reason,
        })
    }

    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }
    #[must_use]
    pub fn expected_generation_id(&self) -> &str {
        &self.expected_generation_id
    }
    #[must_use]
    pub const fn expected_lease_epoch(&self) -> u64 {
        self.expected_lease_epoch
    }
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    #[must_use]
    pub fn decision_key(&self) -> &str {
        &self.decision_key
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "decision_key".to_owned(),
                JsonValue::String(self.decision_key.clone()),
            ),
            (
                "expected_generation_id".to_owned(),
                JsonValue::String(self.expected_generation_id.clone()),
            ),
            (
                "expected_lease_epoch".to_owned(),
                integer("expected_lease_epoch", self.expected_lease_epoch)?,
            ),
            (
                "expected_revision".to_owned(),
                integer("expected_revision", self.expected_revision)?,
            ),
            ("reason".to_owned(), JsonValue::String(self.reason.clone())),
            ("run_id".to_owned(), integer("run_id", self.run_id)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "decision_key",
                "expected_generation_id",
                "expected_lease_epoch",
                "expected_revision",
                "reason",
                "run_id",
            ],
        )?;
        Self::new(
            unsigned(body, "run_id")?,
            required_body_string(body, "expected_generation_id")?,
            unsigned(body, "expected_lease_epoch")?,
            unsigned(body, "expected_revision")?,
            required_body_string(body, "decision_key")?,
            required_body_string(body, "reason")?,
        )
    }
}

/// An operator's bounded account of who is closing intake, and why.
///
/// Neither field is authenticated. The local transport establishes that the
/// peer is this user; these strings say which person or runbook behind that
/// user made the call, and are worth recording for exactly that reason and no
/// stronger one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntakePause {
    actor: String,
    reason: String,
}

impl IntakePause {
    /// Validate a pause request.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for an empty, overlong, or
    /// control-character-bearing actor or reason. A reason is required: a pause
    /// with no stated cause is the one an operator cannot safely resume.
    pub fn new(actor: impl Into<String>, reason: impl Into<String>) -> Result<Self, AdminError> {
        let actor = actor.into();
        let reason = reason.into();
        if !valid_coordinate(&actor, MAX_INTAKE_ACTOR_BYTES)
            || !valid_coordinate(&reason, MAX_INTAKE_REASON_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self { actor, reason })
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("actor".to_owned(), JsonValue::String(self.actor.clone())),
            ("reason".to_owned(), JsonValue::String(self.reason.clone())),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["actor", "reason"])?;
        Self::new(
            required_body_string(body, "actor")?,
            required_body_string(body, "reason")?,
        )
    }
}

/// An operator's bounded account of who is reopening intake.
///
/// There is no resume reason: the durable pause already carries the cause, and
/// a second free-text field would invite restating it inconsistently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntakeResume {
    actor: String,
}

impl IntakeResume {
    /// Validate a resume request.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for an empty, overlong, or
    /// control-character-bearing actor.
    pub fn new(actor: impl Into<String>) -> Result<Self, AdminError> {
        let actor = actor.into();
        if !valid_coordinate(&actor, MAX_INTAKE_ACTOR_BYTES) {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self { actor })
    }

    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![(
            "actor".to_owned(),
            JsonValue::String(self.actor.clone()),
        )])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["actor"])?;
        Self::new(required_body_string(body, "actor")?)
    }
}

/// Bounded local work used to exercise the durable scheduler without a provider
/// or transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticSubmission {
    scope: String,
    idempotency_key: String,
    task: String,
}

impl SyntheticSubmission {
    /// Validate a synthetic intake request.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for empty, overlong, or
    /// control-character-bearing coordinates, or for an empty/overlong task.
    pub fn new(
        scope: impl Into<String>,
        idempotency_key: impl Into<String>,
        task: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let scope = scope.into();
        let idempotency_key = idempotency_key.into();
        let task = task.into();
        if !valid_coordinate(&scope, MAX_SYNTHETIC_SCOPE_BYTES)
            || !valid_coordinate(&idempotency_key, MAX_SYNTHETIC_KEY_BYTES)
            || task.is_empty()
            || task.len() > MAX_SYNTHETIC_TASK_BYTES
            || task.contains('\0')
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            scope,
            idempotency_key,
            task,
        })
    }

    /// Serialization scope used by the scheduler.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Stable caller-controlled retry key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Synthetic task text. It grants no provider or external-effect authority.
    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "idempotency_key".to_owned(),
                JsonValue::String(self.idempotency_key.clone()),
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
            ("task".to_owned(), JsonValue::String(self.task.clone())),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["idempotency_key", "scope", "task"])?;
        Self::new(
            required_body_string(body, "scope")?,
            required_body_string(body, "idempotency_key")?,
            required_body_string(body, "task")?,
        )
    }
}

/// One bounded canonical RunSpec document, the digest its submitter declares
/// for it, and a stable retry key.
///
/// # What this crate does with the document
///
/// It bounds it, hex-encodes it and hands it on. Nothing here parses a RunSpec:
/// this crate has no dependency on `automonique-runner` and could not
/// interpret one if it wanted to.
///
/// # What a carried pair does not establish
///
/// - **Not that the digest names the document.** [`Self::declared`] accepts any
///   well-formed digest for any bounded document, so an inconsistent pair is
///   representable — as it must be, because a hostile or buggy peer can put one
///   on the wire regardless of what this constructor allows. The verification
///   belongs to the daemon, which owns the durable custody and can answer a
///   correlated [`AdminResponse::Refused`] the submitter can act on; a codec
///   that refused here would instead drop the frame. [`Self::sealed`] is the
///   constructor for callers that have the bytes and want the digest to be
///   right by construction.
/// - **Not that the document is a RunSpec.** Bounded, non-empty bytes are the
///   whole of what is checked. Only a strict decoder establishes more.
/// - **Not that anything will be executed.** This message asks for durable
///   custody of a document and nothing else.
#[derive(Clone, Eq, PartialEq)]
pub struct SubmittedRunSpec {
    document: Vec<u8>,
    spec_digest: Sha256Digest,
    idempotency_key: String,
}

impl fmt::Debug for SubmittedRunSpec {
    /// The document is redacted: a RunSpec carries process arguments and
    /// environment values, which are exactly what a log must not grow.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmittedRunSpec")
            .field(
                "document",
                &format_args!("<canonical run-spec: {} bytes>", self.document.len()),
            )
            .field("spec_digest", &self.spec_digest)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

impl SubmittedRunSpec {
    /// Carry a document under the digest this crate computes for it.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::DocumentTooLarge`] above
    /// [`MAX_SUBMITTED_RUN_SPEC_BYTES`] and [`AdminError::InvalidBody`] for an
    /// empty document or an invalid idempotency key.
    pub fn sealed(
        document: Vec<u8>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let spec_digest = Sha256::digest(&document);
        Self::declared(document, spec_digest, idempotency_key)
    }

    /// Carry a document under a digest the submitter declares for it.
    ///
    /// The two are not compared here; see the type documentation.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::DocumentTooLarge`] above
    /// [`MAX_SUBMITTED_RUN_SPEC_BYTES`] and [`AdminError::InvalidBody`] for an
    /// empty document or an invalid idempotency key.
    pub fn declared(
        document: Vec<u8>,
        spec_digest: Sha256Digest,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let idempotency_key = idempotency_key.into();
        if document.len() > MAX_SUBMITTED_RUN_SPEC_BYTES {
            return Err(AdminError::DocumentTooLarge {
                max_bytes: MAX_SUBMITTED_RUN_SPEC_BYTES,
                actual_bytes: document.len(),
            });
        }
        if document.is_empty() || !valid_coordinate(&idempotency_key, MAX_RUN_SUBMISSION_KEY_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            document,
            spec_digest,
            idempotency_key,
        })
    }

    /// Canonical RunSpec document bytes, uninterpreted.
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    /// The digest the submitter declared for those bytes.
    #[must_use]
    pub const fn spec_digest(&self) -> &Sha256Digest {
        &self.spec_digest
    }

    /// Stable caller-controlled retry key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "document_hex".to_owned(),
                JsonValue::String(encode_hex(&self.document)),
            ),
            (
                "idempotency_key".to_owned(),
                JsonValue::String(self.idempotency_key.clone()),
            ),
            (
                "spec_digest".to_owned(),
                JsonValue::String(self.spec_digest.to_string()),
            ),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["document_hex", "idempotency_key", "spec_digest"])?;
        let hex = required_body_string(body, "document_hex")?;
        // The length bound is checked on the *encoded* text, before any buffer
        // is sized from it: a hostile submitter never drives an allocation.
        if hex.len() > 2 * MAX_SUBMITTED_RUN_SPEC_BYTES {
            return Err(AdminError::DocumentTooLarge {
                max_bytes: MAX_SUBMITTED_RUN_SPEC_BYTES,
                actual_bytes: hex.len() / 2,
            });
        }
        Self::declared(
            decode_hex(&hex).ok_or(AdminError::InvalidBody)?,
            parse_digest(body, "spec_digest")?,
            required_body_string(body, "idempotency_key")?,
        )
    }
}

/// A correlated local administration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRequest {
    request_id: RequestId,
    command: AdminCommand,
    reload_id: Option<String>,
    submission: Option<SyntheticSubmission>,
    reconciliation_run_id: Option<u64>,
    reconciliation_failure: Option<ReconciliationFailure>,
    outbox_id: Option<u64>,
    outbox_reconciliation: Option<OutboxReconciliation>,
    run_submission: Option<SubmittedRunSpec>,
    intake_pause: Option<IntakePause>,
    intake_resume: Option<IntakeResume>,
}

impl AdminRequest {
    /// Construct a request from a validated correlation identifier.
    #[must_use]
    pub const fn new(request_id: RequestId, command: AdminCommand) -> Self {
        Self {
            request_id,
            command,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        }
    }

    /// Construct a request to hand off to one exact immutable release.
    pub fn reload(
        request_id: RequestId,
        target_release_digest: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let target_release_digest = target_release_digest.into();
        if !valid_release_digest(&target_release_digest) {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            request_id,
            command: AdminCommand::Reload,
            reload_id: Some(target_release_digest),
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        })
    }

    /// Construct a read-only lookup of one durable reload epoch.
    pub fn reload_status(
        request_id: RequestId,
        reload_id: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let reload_id = reload_id.into();
        if !valid_coordinate(&reload_id, MAX_RELOAD_ID_BYTES) {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            request_id,
            command: AdminCommand::ReloadStatus,
            reload_id: Some(reload_id),
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        })
    }

    /// Construct a durable synthetic-intake request.
    #[must_use]
    pub const fn submit(request_id: RequestId, submission: SyntheticSubmission) -> Self {
        Self {
            request_id,
            command: AdminCommand::SubmitSynthetic,
            reload_id: None,
            submission: Some(submission),
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        }
    }

    /// Construct a durable RunSpec custody request.
    ///
    /// The request asks the daemon to verify and durably retain one document.
    /// It is not a launch request and this protocol has no launch request.
    #[must_use]
    pub const fn submit_run(request_id: RequestId, run_submission: SubmittedRunSpec) -> Self {
        Self {
            request_id,
            command: AdminCommand::SubmitRun,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: Some(run_submission),
            intake_pause: None,
            intake_resume: None,
        }
    }

    /// Construct a read-only reconciliation inspection.
    pub fn inspect_reconciliation(request_id: RequestId, run_id: u64) -> Result<Self, AdminError> {
        if run_id == 0 {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            request_id,
            command: AdminCommand::InspectReconciliation,
            reload_id: None,
            submission: None,
            reconciliation_run_id: Some(run_id),
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        })
    }

    /// Construct an exact fail-only reconciliation decision.
    #[must_use]
    pub const fn fail_reconciliation(
        request_id: RequestId,
        failure: ReconciliationFailure,
    ) -> Self {
        Self {
            request_id,
            command: AdminCommand::FailReconciliation,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: Some(failure),
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        }
    }

    pub fn inspect_outbox(request_id: RequestId, outbox_id: u64) -> Result<Self, AdminError> {
        if outbox_id == 0 {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            request_id,
            command: AdminCommand::InspectOutbox,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: Some(outbox_id),
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        })
    }

    #[must_use]
    pub const fn reconcile_outbox(
        request_id: RequestId,
        reconciliation: OutboxReconciliation,
    ) -> Self {
        Self {
            request_id,
            command: AdminCommand::ReconcileOutbox,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: Some(reconciliation),
            run_submission: None,
            intake_pause: None,
            intake_resume: None,
        }
    }

    /// Construct a durable intake-pause request.
    #[must_use]
    pub const fn pause_intake(request_id: RequestId, intake_pause: IntakePause) -> Self {
        Self {
            request_id,
            command: AdminCommand::PauseIntake,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: Some(intake_pause),
            intake_resume: None,
        }
    }

    /// Construct a durable intake-resume request.
    #[must_use]
    pub const fn resume_intake(request_id: RequestId, intake_resume: IntakeResume) -> Self {
        Self {
            request_id,
            command: AdminCommand::ResumeIntake,
            reload_id: None,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
            outbox_id: None,
            outbox_reconciliation: None,
            run_submission: None,
            intake_pause: None,
            intake_resume: Some(intake_resume),
        }
    }

    /// Correlation identifier copied into the response.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Requested command.
    #[must_use]
    pub const fn command(&self) -> AdminCommand {
        self.command
    }

    /// Reload identifier, present only for [`AdminCommand::ReloadStatus`].
    #[must_use]
    pub fn reload_id(&self) -> Option<&str> {
        (self.command == AdminCommand::ReloadStatus)
            .then_some(self.reload_id.as_deref())
            .flatten()
    }

    /// Target release digest, present only for [`AdminCommand::Reload`].
    #[must_use]
    pub fn reload_target_digest(&self) -> Option<&str> {
        (self.command == AdminCommand::Reload)
            .then_some(self.reload_id.as_deref())
            .flatten()
    }

    /// Synthetic work body, present only for [`AdminCommand::SubmitSynthetic`].
    #[must_use]
    pub const fn submission(&self) -> Option<&SyntheticSubmission> {
        self.submission.as_ref()
    }

    /// Carried RunSpec document, present only for [`AdminCommand::SubmitRun`].
    #[must_use]
    pub const fn run_submission(&self) -> Option<&SubmittedRunSpec> {
        self.run_submission.as_ref()
    }

    #[must_use]
    pub const fn reconciliation_run_id(&self) -> Option<u64> {
        self.reconciliation_run_id
    }

    #[must_use]
    pub const fn reconciliation_failure(&self) -> Option<&ReconciliationFailure> {
        self.reconciliation_failure.as_ref()
    }

    #[must_use]
    pub const fn outbox_id(&self) -> Option<u64> {
        self.outbox_id
    }

    #[must_use]
    pub const fn outbox_reconciliation(&self) -> Option<&OutboxReconciliation> {
        self.outbox_reconciliation.as_ref()
    }

    /// Pause body, present only for [`AdminCommand::PauseIntake`].
    #[must_use]
    pub const fn intake_pause(&self) -> Option<&IntakePause> {
        self.intake_pause.as_ref()
    }

    /// Resume body, present only for [`AdminCommand::ResumeIntake`].
    #[must_use]
    pub const fn intake_resume(&self) -> Option<&IntakeResume> {
        self.intake_resume.as_ref()
    }

    /// Encode this request as a canonical local-protocol message.
    ///
    /// # Errors
    ///
    /// Returns a shared codec error only if a compile-time protocol literal no
    /// longer satisfies the shared envelope grammar.
    pub fn to_message(&self) -> Result<Message, AdminError> {
        let body = match (
            self.command,
            &self.reload_id,
            &self.submission,
            self.reconciliation_run_id,
            &self.reconciliation_failure,
            self.outbox_id,
            &self.outbox_reconciliation,
            &self.run_submission,
            &self.intake_pause,
            &self.intake_resume,
        ) {
            (
                AdminCommand::Reload,
                Some(target_release_digest),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ) => JsonValue::Object(vec![(
                "target_release_digest".to_owned(),
                JsonValue::String(target_release_digest.clone()),
            )]),
            (
                AdminCommand::SubmitSynthetic,
                None,
                Some(submission),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ) => submission.to_body(),
            (
                AdminCommand::SubmitRun,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(run_submission),
                None,
                None,
            ) => run_submission.to_body(),
            (
                AdminCommand::InspectReconciliation,
                None,
                None,
                Some(run_id),
                None,
                None,
                None,
                None,
                None,
                None,
            ) => JsonValue::Object(vec![("run_id".to_owned(), integer("run_id", run_id)?)]),
            (
                AdminCommand::FailReconciliation,
                None,
                None,
                None,
                Some(failure),
                None,
                None,
                None,
                None,
                None,
            ) => failure.to_body()?,
            (
                AdminCommand::InspectOutbox,
                None,
                None,
                None,
                None,
                Some(outbox_id),
                None,
                None,
                None,
                None,
            ) => JsonValue::Object(vec![(
                "outbox_id".to_owned(),
                integer("outbox_id", outbox_id)?,
            )]),
            (
                AdminCommand::ReconcileOutbox,
                None,
                None,
                None,
                None,
                None,
                Some(reconciliation),
                None,
                None,
                None,
            ) => reconciliation.to_body()?,
            (
                AdminCommand::PauseIntake,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(intake_pause),
                None,
            ) => intake_pause.to_body(),
            (
                AdminCommand::ResumeIntake,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(intake_resume),
            ) => intake_resume.to_body(),
            (
                AdminCommand::ReloadStatus,
                Some(reload_id),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ) => JsonValue::Object(vec![(
                "reload_id".to_owned(),
                JsonValue::String(reload_id.clone()),
            )]),
            (
                AdminCommand::Status
                | AdminCommand::Metrics
                | AdminCommand::Generations
                | AdminCommand::Rollback
                | AdminCommand::Shutdown,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ) => JsonValue::Object(Vec::new()),
            _ => return Err(AdminError::InvalidBody),
        };
        Ok(Message::new(
            envelope(self.request_id.clone(), self.command.kind())?,
            body,
        ))
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown versions, unknown command kinds, and every nonempty or
    /// non-object command body.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AdminError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        match message.envelope().kind().as_str() {
            "submit_synthetic" => Ok(Self::submit(
                message.envelope().request_id().clone(),
                SyntheticSubmission::from_body(message.body())?,
            )),
            "submit_run" => Ok(Self::submit_run(
                message.envelope().request_id().clone(),
                SubmittedRunSpec::from_body(message.body())?,
            )),
            "inspect_reconciliation" => {
                exact_fields(message.body(), &["run_id"])?;
                Self::inspect_reconciliation(
                    message.envelope().request_id().clone(),
                    unsigned(message.body(), "run_id")?,
                )
            }
            "fail_reconciliation" => Ok(Self::fail_reconciliation(
                message.envelope().request_id().clone(),
                ReconciliationFailure::from_body(message.body())?,
            )),
            "inspect_outbox" => {
                exact_fields(message.body(), &["outbox_id"])?;
                Self::inspect_outbox(
                    message.envelope().request_id().clone(),
                    unsigned(message.body(), "outbox_id")?,
                )
            }
            "reconcile_outbox" => Ok(Self::reconcile_outbox(
                message.envelope().request_id().clone(),
                OutboxReconciliation::from_body(message.body())?,
            )),
            "pause_intake" => Ok(Self::pause_intake(
                message.envelope().request_id().clone(),
                IntakePause::from_body(message.body())?,
            )),
            "resume_intake" => Ok(Self::resume_intake(
                message.envelope().request_id().clone(),
                IntakeResume::from_body(message.body())?,
            )),
            "reload_status" => {
                exact_fields(message.body(), &["reload_id"])?;
                Self::reload_status(
                    message.envelope().request_id().clone(),
                    required_body_string(message.body(), "reload_id")?,
                )
            }
            "reload" => {
                exact_fields(message.body(), &["target_release_digest"])?;
                Self::reload(
                    message.envelope().request_id().clone(),
                    required_body_string(message.body(), "target_release_digest")?,
                )
            }
            "status" | "metrics" | "generations" | "rollback" | "shutdown" => {
                if !matches!(message.body(), JsonValue::Object(entries) if entries.is_empty()) {
                    return Err(AdminError::InvalidBody);
                }
                let command = match message.envelope().kind().as_str() {
                    "status" => AdminCommand::Status,
                    "metrics" => AdminCommand::Metrics,
                    "generations" => AdminCommand::Generations,
                    "rollback" => AdminCommand::Rollback,
                    _ => AdminCommand::Shutdown,
                };
                Ok(Self::new(message.envelope().request_id().clone(), command))
            }
            _ => Err(AdminError::UnknownKind),
        }
    }
}

/// A maximal Runs frame must fit the bound a local transport reads under.
///
/// The two ceilings are equal today and this states the dependency rather than
/// leaving it a coincidence: a widened `runs_api` ceiling that outgrew this one
/// would turn a legal Runs message into a `frame_size` refusal at the socket,
/// which is a size failure discovered by a peer rather than by this build.
const _: () = assert!(
    crate::runs_api::MAX_RUNS_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal runs frame must fit the local administration read bound"
);

/// A maximal Automation frame must fit the bound a local transport reads under.
///
/// The same dependency the Runs ceiling has, stated for the same reason: a
/// widened `automation_api` ceiling that outgrew this one would turn a legal
/// Automation message into a `frame_size` refusal at the socket, which is a
/// size failure discovered by a peer rather than by this build.
const _: () = assert!(
    crate::automation_api::MAX_AUTOMATION_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal automation frame must fit the local administration read bound"
);

/// A maximal Approval frame must fit the bound a local transport reads under.
///
/// The same dependency the Runs and Automation ceilings have, stated for the
/// same reason: a widened `approval_api` ceiling that outgrew this one would
/// turn a legal Approval message into a `frame_size` refusal at the socket,
/// which is a size failure discovered by a peer rather than by this build.
const _: () = assert!(
    crate::approval_api::MAX_APPROVAL_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal approval frame must fit the local administration read bound"
);

/// A maximal Batch control frame must fit the bound a local transport reads
/// under.
///
/// The same dependency the other three ceilings have, stated for the same
/// reason: a widened `batch_api` ceiling that outgrew this one would turn a
/// legal Batch message into a `frame_size` refusal at the socket, which is a
/// size failure discovered by a peer rather than by this build. It is the
/// tightest of the four, because a maximal registration carries a whole
/// membership — which is why `batch_api` derives its member ceiling from this
/// number rather than inheriting the batch model's.
const _: () = assert!(
    crate::batch_api::MAX_BATCH_CONTROL_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal batch control frame must fit the local administration read bound"
);

/// A maximal Execute frame must fit the bound a local transport reads under.
///
/// The same dependency the other four ceilings have, stated for the same
/// reason: a widened `execute_api` ceiling that outgrew this one would turn a
/// legal Execute message into a `frame_size` refusal at the socket, which is a
/// size failure discovered by a peer rather than by this build.
const _: () = assert!(
    crate::execute_api::MAX_EXECUTE_CANONICAL_BYTES <= MAX_ADMIN_CANONICAL_BYTES,
    "a maximal execute frame must fit the local administration read bound"
);

const _: () = assert!(
    MAX_PLATFORM_REQUEST_CANONICAL_BYTES <= crate::codec::MAX_FRAME_BYTES,
    "a maximal platform frame must fit the shared framing bound"
);

/// A refusal while deciding which protocol one local frame belongs to.
///
/// The six variants say *who* refused, which is the distinction a metric
/// label needs: an envelope this socket could not place at all, a well-placed
/// administration message the admin lane refused, a well-placed Runs message
/// the Runs lane refused, a well-placed Automation message the Automation lane
/// refused, a well-placed Approval message the Approval lane refused, or a
/// well-placed Batch message the Batch lane refused. Every category spelling is
/// the refusing lane's own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalRequestError {
    /// The payload is not a well-formed envelope, or names a protocol this
    /// socket does not serve. Decided before any lane read a body.
    Envelope(CodecError),
    /// The administration lane refused the message it was handed.
    Admin(AdminError),
    /// The Runs lane refused the message it was handed.
    Runs(RunsApiError),
    /// The Automation control lane refused the message it was handed.
    Automation(AutomationApiError),
    /// The Approval decision lane refused the message it was handed.
    Approval(ApprovalApiError),
    /// The Batch control lane refused the message it was handed.
    Batch(BatchApiError),
    /// The Execute lane refused the message it was handed.
    Execute(ExecuteApiError),
    /// The federated platform lane refused the message it was handed.
    Platform(PlatformApiError),
}

impl LocalRequestError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Envelope(error) => error.category(),
            Self::Admin(error) => error.category(),
            Self::Runs(error) => error.category(),
            Self::Automation(error) => error.category(),
            Self::Approval(error) => error.category(),
            Self::Batch(error) => error.category(),
            Self::Execute(error) => error.category(),
            Self::Platform(error) => error.category(),
        }
    }
}

impl fmt::Display for LocalRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(error) => write!(formatter, "local frame was not placed: {error}"),
            Self::Admin(error) => write!(formatter, "{error}"),
            Self::Runs(error) => write!(formatter, "{error}"),
            Self::Automation(error) => write!(formatter, "{error}"),
            Self::Approval(error) => write!(formatter, "{error}"),
            Self::Batch(error) => write!(formatter, "{error}"),
            Self::Execute(error) => write!(formatter, "{error}"),
            Self::Platform(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for LocalRequestError {}

/// One decoded request on a local endpoint that serves every local protocol.
///
/// # Why this is a dispatch and not a tenth admin command
///
/// A `list_runs` command inside [`AdminCommand`] would put a read of the Runs
/// surface inside the closed admin kind set, inside the generated admin command
/// registry, and inside the drift gate that pins both. The Runs API defines its
/// own envelope, its own version range, its own bounded bodies and its own
/// refusal vocabulary; re-spelling any of that here would create a second
/// authority for one wire format, and the two would drift.
///
/// So the frame's own `protocol` member decides. Each lane then admits its own
/// message independently — including its major version, which each lane owns —
/// so nothing is guessed, downgraded, or tried in sequence until something
/// parses.
///
/// The payload is parsed twice: once here to read the declared name, and once
/// by the lane that owns it. That is the cost of leaving each lane's decoder
/// the sole authority over its own bytes, on a bounded local frame of at most
/// [`MAX_ADMIN_CANONICAL_BYTES`], and it is preferred over a shape this module
/// would have to keep in agreement with two others.
/// The administration variant is boxed because an [`AdminRequest`] carries
/// every command's body inline and is several times the size of a Runs
/// request; an unboxed enum would move that much for a run listing too. One
/// allocation per decoded local frame is the cost, and a local socket decodes
/// one frame per connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalRequest {
    /// A local administration command.
    Admin(Box<AdminRequest>),
    /// A read on the native Runs API.
    Runs(RunsRequest),
    /// A control operation on the native Automation API.
    ///
    /// Boxed for the reason the administration variant is: a
    /// [`AutomationRequest`] carries three maximal bounded identifiers inline,
    /// so an unboxed arm would set this enum's size for every lane.
    Automation(Box<AutomationRequest>),
    /// A decision operation on the native Approval API.
    ///
    /// Boxed for the same reason: an [`ApprovalRequest`] carries three maximal
    /// bounded identifiers inline.
    Approval(Box<ApprovalRequest>),
    /// A control operation on the native Batch API.
    ///
    /// Boxed most of all: a [`BatchRequest`] carries a whole declared
    /// membership inline, which is the largest body any lane on this socket
    /// sends, and an unboxed arm would set this enum's size for every lane.
    Batch(Box<BatchRequest>),
    /// A request to start one run already in custody.
    ///
    /// Deliberately *not* boxed: an [`ExecuteRequest`] carries one bounded run
    /// identifier beside its correlation identifier, so it is the smallest body
    /// on this socket, and boxing it would add an allocation to buy nothing.
    Execute(ExecuteRequest),
    /// A request on the single federated operator surface.
    Platform(Box<PlatformRequestMessage>),
}

impl LocalRequest {
    /// Decode one frame payload into the lane that owns it.
    ///
    /// # Errors
    ///
    /// Returns [`LocalRequestError::Envelope`] for a payload that is not a
    /// well-formed envelope or that names a protocol this socket does not
    /// serve, and otherwise the owning lane's own refusal.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, LocalRequestError> {
        let envelope = Message::from_canonical_bytes(payload)
            .map_err(LocalRequestError::Envelope)?
            .envelope()
            .protocol()
            .as_str()
            .to_owned();
        match envelope.as_str() {
            ADMIN_PROTOCOL => AdminRequest::from_canonical_bytes(payload)
                .map(|request| Self::Admin(Box::new(request)))
                .map_err(LocalRequestError::Admin),
            RUNS_PROTOCOL => RunsRequest::from_canonical_bytes(payload)
                .map(Self::Runs)
                .map_err(LocalRequestError::Runs),
            AUTOMATION_PROTOCOL => AutomationRequest::from_canonical_bytes(payload)
                .map(|request| Self::Automation(Box::new(request)))
                .map_err(LocalRequestError::Automation),
            APPROVAL_PROTOCOL => ApprovalRequest::from_canonical_bytes(payload)
                .map(|request| Self::Approval(Box::new(request)))
                .map_err(LocalRequestError::Approval),
            BATCH_CONTROL_PROTOCOL => BatchRequest::from_canonical_bytes(payload)
                .map(|request| Self::Batch(Box::new(request)))
                .map_err(LocalRequestError::Batch),
            EXECUTE_PROTOCOL => ExecuteRequest::from_canonical_bytes(payload)
                .map(Self::Execute)
                .map_err(LocalRequestError::Execute),
            PLATFORM_PROTOCOL => PlatformRequestMessage::from_canonical_bytes(payload)
                .map(|request| Self::Platform(Box::new(request)))
                .map_err(LocalRequestError::Platform),
            _ => Err(LocalRequestError::Envelope(CodecError::UnknownProtocol)),
        }
    }

    /// The protocol name of the lane that owns this request.
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        match self {
            Self::Admin(_) => ADMIN_PROTOCOL,
            Self::Runs(_) => RUNS_PROTOCOL,
            Self::Automation(_) => AUTOMATION_PROTOCOL,
            Self::Approval(_) => APPROVAL_PROTOCOL,
            Self::Batch(_) => BATCH_CONTROL_PROTOCOL,
            Self::Execute(_) => EXECUTE_PROTOCOL,
            Self::Platform(_) => PLATFORM_PROTOCOL,
        }
    }
}

/// One consistent daemon status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonStatus {
    instance_id: AdminInstanceId,
    /// What the answering endpoint can do, as [`ADMIN_CAPABILITY`] defines it.
    ///
    /// Not a constructor argument, and deliberately: an encoder reports the
    /// capability of the build it is running, and there is no argument through
    /// which a caller could report a different one. A *decoder* carries what the
    /// peer said, which is the whole point — that number is about the daemon
    /// answering, not about the process reading the answer.
    capability: u32,
    state: DaemonState,
    generation: u64,
    event_cursor: u64,
    inbox_pending: u64,
    outbox_pending: u64,
    running: u64,
    accepting_intake: bool,
    intake_paused: bool,
    telegram_state: TelegramState,
    telegram_poller_epoch: Option<u64>,
    execution_state: ExecutionState,
    operational: Option<OperationalStatus>,
    durable_state: Option<DurableStateCounts>,
}

/// A bounded operational value that never substitutes zero for missing evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalMetric {
    Measured(u64),
    Unavailable,
}

impl OperationalMetric {
    pub fn measured(value: u64) -> Result<Self, AdminError> {
        i64::try_from(value)
            .map(|_| Self::Measured(value))
            .map_err(|_| AdminError::CounterOutOfRange {
                field: "operational_metric",
            })
    }

    #[must_use]
    pub const fn value(self) -> Option<u64> {
        match self {
            Self::Measured(value) => Some(value),
            Self::Unavailable => None,
        }
    }

    #[must_use]
    pub const fn state(self) -> &'static str {
        match self {
            Self::Measured(_) => "measured",
            Self::Unavailable => "unavailable",
        }
    }

    fn to_body(self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "state".to_owned(),
                JsonValue::String(self.state().to_owned()),
            ),
            (
                "value".to_owned(),
                match self {
                    Self::Measured(value) => integer("operational_metric", value)?,
                    Self::Unavailable => JsonValue::Null,
                },
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["state", "value"])?;
        match required_body_string(body, "state")?.as_str() {
            "measured" => Self::measured(unsigned(body, "value")?),
            "unavailable" if matches!(body.get("value"), Some(JsonValue::Null)) => {
                Ok(Self::Unavailable)
            }
            _ => Err(AdminError::InvalidBody),
        }
    }
}

/// Durable low-cardinality operational projection attached to daemon status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalStatus {
    observed_ms: u64,
    reconciliation_pending: u64,
    outbox_pending_ready: u64,
    outbox_pending_delayed: u64,
    outbox_in_flight_live: u64,
    outbox_in_flight_ambiguous: u64,
    outbox_delivered: u64,
    outbox_dead_lettered: u64,
    outbox_oldest_ready_age_ms: u64,
    telegram_pollers_live: u64,
    telegram_pollers_expired: u64,
    telegram_offset_lag: OperationalMetric,
    provider_available: OperationalMetric,
    sandbox_launch_refusals: OperationalMetric,
}

/// Named constructor inputs for [`OperationalStatus`].
pub struct OperationalStatusParts {
    pub observed_ms: u64,
    pub reconciliation_pending: u64,
    pub outbox_pending_ready: u64,
    pub outbox_pending_delayed: u64,
    pub outbox_in_flight_live: u64,
    pub outbox_in_flight_ambiguous: u64,
    pub outbox_delivered: u64,
    pub outbox_dead_lettered: u64,
    pub outbox_oldest_ready_age_ms: u64,
    pub telegram_pollers_live: u64,
    pub telegram_pollers_expired: u64,
    pub telegram_offset_lag: OperationalMetric,
    pub provider_available: OperationalMetric,
    pub sandbox_launch_refusals: OperationalMetric,
}

impl OperationalStatus {
    pub fn new(parts: OperationalStatusParts) -> Result<Self, AdminError> {
        for (field, value) in [
            ("observed_ms", parts.observed_ms),
            ("reconciliation_pending", parts.reconciliation_pending),
            ("outbox_pending_ready", parts.outbox_pending_ready),
            ("outbox_pending_delayed", parts.outbox_pending_delayed),
            ("outbox_in_flight_live", parts.outbox_in_flight_live),
            (
                "outbox_in_flight_ambiguous",
                parts.outbox_in_flight_ambiguous,
            ),
            ("outbox_delivered", parts.outbox_delivered),
            ("outbox_dead_lettered", parts.outbox_dead_lettered),
            (
                "outbox_oldest_ready_age_ms",
                parts.outbox_oldest_ready_age_ms,
            ),
            ("telegram_pollers_live", parts.telegram_pollers_live),
            ("telegram_pollers_expired", parts.telegram_pollers_expired),
        ] {
            i64::try_from(value).map_err(|_| AdminError::CounterOutOfRange { field })?;
        }
        if parts.observed_ms == 0 {
            return Err(AdminError::InvalidBody);
        }
        if matches!(parts.provider_available, OperationalMetric::Measured(value) if value > 1)
            || parts.reconciliation_pending < parts.outbox_in_flight_ambiguous
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            observed_ms: parts.observed_ms,
            reconciliation_pending: parts.reconciliation_pending,
            outbox_pending_ready: parts.outbox_pending_ready,
            outbox_pending_delayed: parts.outbox_pending_delayed,
            outbox_in_flight_live: parts.outbox_in_flight_live,
            outbox_in_flight_ambiguous: parts.outbox_in_flight_ambiguous,
            outbox_delivered: parts.outbox_delivered,
            outbox_dead_lettered: parts.outbox_dead_lettered,
            outbox_oldest_ready_age_ms: parts.outbox_oldest_ready_age_ms,
            telegram_pollers_live: parts.telegram_pollers_live,
            telegram_pollers_expired: parts.telegram_pollers_expired,
            telegram_offset_lag: parts.telegram_offset_lag,
            provider_available: parts.provider_available,
            sandbox_launch_refusals: parts.sandbox_launch_refusals,
        })
    }

    #[must_use]
    pub const fn observed_ms(&self) -> u64 {
        self.observed_ms
    }
    #[must_use]
    pub const fn reconciliation_pending(&self) -> u64 {
        self.reconciliation_pending
    }
    #[must_use]
    pub const fn outbox_pending_ready(&self) -> u64 {
        self.outbox_pending_ready
    }
    #[must_use]
    pub const fn outbox_pending_delayed(&self) -> u64 {
        self.outbox_pending_delayed
    }
    #[must_use]
    pub const fn outbox_in_flight_live(&self) -> u64 {
        self.outbox_in_flight_live
    }
    #[must_use]
    pub const fn outbox_in_flight_ambiguous(&self) -> u64 {
        self.outbox_in_flight_ambiguous
    }
    #[must_use]
    pub const fn outbox_delivered(&self) -> u64 {
        self.outbox_delivered
    }
    #[must_use]
    pub const fn outbox_dead_lettered(&self) -> u64 {
        self.outbox_dead_lettered
    }
    #[must_use]
    pub const fn outbox_oldest_ready_age_ms(&self) -> u64 {
        self.outbox_oldest_ready_age_ms
    }
    #[must_use]
    pub const fn telegram_pollers_live(&self) -> u64 {
        self.telegram_pollers_live
    }
    #[must_use]
    pub const fn telegram_pollers_expired(&self) -> u64 {
        self.telegram_pollers_expired
    }
    #[must_use]
    pub const fn telegram_offset_lag(&self) -> OperationalMetric {
        self.telegram_offset_lag
    }
    #[must_use]
    pub const fn provider_available(&self) -> OperationalMetric {
        self.provider_available
    }
    #[must_use]
    pub const fn sandbox_launch_refusals(&self) -> OperationalMetric {
        self.sandbox_launch_refusals
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "observed_ms".to_owned(),
                integer("observed_ms", self.observed_ms)?,
            ),
            (
                "outbox_dead_lettered".to_owned(),
                integer("outbox_dead_lettered", self.outbox_dead_lettered)?,
            ),
            (
                "outbox_delivered".to_owned(),
                integer("outbox_delivered", self.outbox_delivered)?,
            ),
            (
                "outbox_in_flight_ambiguous".to_owned(),
                integer(
                    "outbox_in_flight_ambiguous",
                    self.outbox_in_flight_ambiguous,
                )?,
            ),
            (
                "outbox_in_flight_live".to_owned(),
                integer("outbox_in_flight_live", self.outbox_in_flight_live)?,
            ),
            (
                "outbox_oldest_ready_age_ms".to_owned(),
                integer(
                    "outbox_oldest_ready_age_ms",
                    self.outbox_oldest_ready_age_ms,
                )?,
            ),
            (
                "outbox_pending_delayed".to_owned(),
                integer("outbox_pending_delayed", self.outbox_pending_delayed)?,
            ),
            (
                "outbox_pending_ready".to_owned(),
                integer("outbox_pending_ready", self.outbox_pending_ready)?,
            ),
            (
                "provider_available".to_owned(),
                self.provider_available.to_body()?,
            ),
            (
                "reconciliation_pending".to_owned(),
                integer("reconciliation_pending", self.reconciliation_pending)?,
            ),
            (
                "sandbox_launch_refusals".to_owned(),
                self.sandbox_launch_refusals.to_body()?,
            ),
            (
                "telegram_offset_lag".to_owned(),
                self.telegram_offset_lag.to_body()?,
            ),
            (
                "telegram_pollers_expired".to_owned(),
                integer("telegram_pollers_expired", self.telegram_pollers_expired)?,
            ),
            (
                "telegram_pollers_live".to_owned(),
                integer("telegram_pollers_live", self.telegram_pollers_live)?,
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        const FIELDS: [&str; 14] = [
            "observed_ms",
            "outbox_dead_lettered",
            "outbox_delivered",
            "outbox_in_flight_ambiguous",
            "outbox_in_flight_live",
            "outbox_oldest_ready_age_ms",
            "outbox_pending_delayed",
            "outbox_pending_ready",
            "provider_available",
            "reconciliation_pending",
            "sandbox_launch_refusals",
            "telegram_offset_lag",
            "telegram_pollers_expired",
            "telegram_pollers_live",
        ];
        exact_fields(body, &FIELDS)?;
        Self::new(OperationalStatusParts {
            observed_ms: unsigned(body, "observed_ms")?,
            reconciliation_pending: unsigned(body, "reconciliation_pending")?,
            outbox_pending_ready: unsigned(body, "outbox_pending_ready")?,
            outbox_pending_delayed: unsigned(body, "outbox_pending_delayed")?,
            outbox_in_flight_live: unsigned(body, "outbox_in_flight_live")?,
            outbox_in_flight_ambiguous: unsigned(body, "outbox_in_flight_ambiguous")?,
            outbox_delivered: unsigned(body, "outbox_delivered")?,
            outbox_dead_lettered: unsigned(body, "outbox_dead_lettered")?,
            outbox_oldest_ready_age_ms: unsigned(body, "outbox_oldest_ready_age_ms")?,
            telegram_pollers_live: unsigned(body, "telegram_pollers_live")?,
            telegram_pollers_expired: unsigned(body, "telegram_pollers_expired")?,
            telegram_offset_lag: OperationalMetric::from_body(
                body.get("telegram_offset_lag")
                    .ok_or(AdminError::InvalidBody)?,
            )?,
            provider_available: OperationalMetric::from_body(
                body.get("provider_available")
                    .ok_or(AdminError::InvalidBody)?,
            )?,
            sandbox_launch_refusals: OperationalMetric::from_body(
                body.get("sandbox_launch_refusals")
                    .ok_or(AdminError::InvalidBody)?,
            )?,
        })
    }
}

/// The durable state a daemon is holding, counted rather than assumed.
///
/// # Each field is one read of one store
///
/// These stores are separate databases and this build opens no transaction
/// across them, so two counts here may straddle a write that landed between
/// them. The projection in [`OperationalStatus`] is a different kind of value —
/// it comes from one status transaction over the main database — and the two
/// are deliberately not merged, because presenting them together would claim an
/// atomicity that does not exist.
///
/// # Why every field is an [`OperationalMetric`]
///
/// A store this daemon could not count reports
/// [`OperationalMetric::Unavailable`]. It never reports zero: zero is a fact an
/// operator would act on — nothing was registered, nothing to reconcile — and
/// "the count could not be read" is the absence of any fact at all. Substituting
/// one for the other is how a status starts lying about the state it exists to
/// describe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableStateCounts {
    approvals_recorded: OperationalMetric,
    automations_registered: OperationalMetric,
    open_tenure_epoch: OperationalMetric,
    open_tenures: OperationalMetric,
    runs_registered: OperationalMetric,
    tenures_recorded: OperationalMetric,
}

/// Named constructor inputs for [`DurableStateCounts`].
pub struct DurableStateCountsParts {
    /// Decisions in the approval ledger.
    pub approvals_recorded: OperationalMetric,
    /// Automations in the registry, in every enablement state.
    pub automations_registered: OperationalMetric,
    /// Lease epoch of the open tenure, when there is one to read.
    pub open_tenure_epoch: OperationalMetric,
    /// Open tenure rows for this daemon's generation: zero or one.
    pub open_tenures: OperationalMetric,
    /// Rows in the run index, one per accepted run submission.
    pub runs_registered: OperationalMetric,
    /// Tenures the generation audit has recorded, open and closed alike.
    pub tenures_recorded: OperationalMetric,
}

impl DurableStateCounts {
    /// Construct the counts, refusing a tenure observation that contradicts
    /// itself.
    ///
    /// A generation has at most one open tenure row, and an epoch is evidence
    /// only when that row was actually read. The three coherent readings are
    /// therefore: one open tenure at a measured epoch; no open tenure and no
    /// epoch; and an audit that could not be read, which measures neither. An
    /// epoch beside "no open tenure" would be an epoch belonging to nothing,
    /// and a measured open tenure with no epoch would be a row this daemon
    /// claims to have read without reading the one field that identifies it.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for any other pairing, including
    /// more than one open tenure and an open tenure at epoch zero, which no
    /// lease ever holds.
    pub fn new(parts: DurableStateCountsParts) -> Result<Self, AdminError> {
        if !matches!(
            (parts.open_tenures, parts.open_tenure_epoch),
            (
                OperationalMetric::Measured(1),
                OperationalMetric::Measured(1..)
            ) | (
                OperationalMetric::Measured(0) | OperationalMetric::Unavailable,
                OperationalMetric::Unavailable
            )
        ) {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            approvals_recorded: parts.approvals_recorded,
            automations_registered: parts.automations_registered,
            open_tenure_epoch: parts.open_tenure_epoch,
            open_tenures: parts.open_tenures,
            runs_registered: parts.runs_registered,
            tenures_recorded: parts.tenures_recorded,
        })
    }

    /// Decisions the approval ledger holds.
    #[must_use]
    pub const fn approvals_recorded(&self) -> OperationalMetric {
        self.approvals_recorded
    }

    /// Automations the registry holds, in every enablement state.
    #[must_use]
    pub const fn automations_registered(&self) -> OperationalMetric {
        self.automations_registered
    }

    /// Lease epoch of the open tenure, and [`OperationalMetric::Unavailable`]
    /// when no tenure is open or the audit could not be read.
    #[must_use]
    pub const fn open_tenure_epoch(&self) -> OperationalMetric {
        self.open_tenure_epoch
    }

    /// Open tenure rows for this generation: zero or one.
    #[must_use]
    pub const fn open_tenures(&self) -> OperationalMetric {
        self.open_tenures
    }

    /// Rows in the run index, one per accepted run submission.
    #[must_use]
    pub const fn runs_registered(&self) -> OperationalMetric {
        self.runs_registered
    }

    /// Tenures the generation audit has recorded, open and closed alike.
    #[must_use]
    pub const fn tenures_recorded(&self) -> OperationalMetric {
        self.tenures_recorded
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "approvals_recorded".to_owned(),
                self.approvals_recorded.to_body()?,
            ),
            (
                "automations_registered".to_owned(),
                self.automations_registered.to_body()?,
            ),
            (
                "open_tenure_epoch".to_owned(),
                self.open_tenure_epoch.to_body()?,
            ),
            ("open_tenures".to_owned(), self.open_tenures.to_body()?),
            (
                "runs_registered".to_owned(),
                self.runs_registered.to_body()?,
            ),
            (
                "tenures_recorded".to_owned(),
                self.tenures_recorded.to_body()?,
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        const FIELDS: [&str; 6] = [
            "approvals_recorded",
            "automations_registered",
            "open_tenure_epoch",
            "open_tenures",
            "runs_registered",
            "tenures_recorded",
        ];
        exact_fields(body, &FIELDS)?;
        let metric = |field: &str| -> Result<OperationalMetric, AdminError> {
            OperationalMetric::from_body(body.get(field).ok_or(AdminError::InvalidBody)?)
        };
        Self::new(DurableStateCountsParts {
            approvals_recorded: metric("approvals_recorded")?,
            automations_registered: metric("automations_registered")?,
            open_tenure_epoch: metric("open_tenure_epoch")?,
            open_tenures: metric("open_tenures")?,
            runs_registered: metric("runs_registered")?,
            tenures_recorded: metric("tenures_recorded")?,
        })
    }
}

impl DaemonStatus {
    /// Construct a snapshot, refusing counters the integer-only wire cannot carry.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::CounterOutOfRange`] for the first value above
    /// `i64::MAX`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: AdminInstanceId,
        state: DaemonState,
        generation: u64,
        event_cursor: u64,
        inbox_pending: u64,
        outbox_pending: u64,
        running: u64,
        accepting_intake: bool,
    ) -> Result<Self, AdminError> {
        for (field, value) in [
            ("generation", generation),
            ("event_cursor", event_cursor),
            ("inbox_pending", inbox_pending),
            ("outbox_pending", outbox_pending),
            ("running", running),
        ] {
            i64::try_from(value).map_err(|_| AdminError::CounterOutOfRange { field })?;
        }
        Ok(Self {
            instance_id,
            capability: ADMIN_CAPABILITY,
            state,
            generation,
            event_cursor,
            inbox_pending,
            outbox_pending,
            running,
            accepting_intake,
            intake_paused: false,
            telegram_state: TelegramState::DisabledNoClient,
            telegram_poller_epoch: None,
            execution_state: ExecutionState::SandboxUnavailableLaneWired,
            operational: None,
            durable_state: None,
        })
    }

    /// Replace the default unavailable execution observation with a measured one.
    #[must_use]
    pub const fn with_execution(mut self, execution_state: ExecutionState) -> Self {
        self.execution_state = execution_state;
        self
    }

    /// Replace the default disabled Telegram observation with an exact coherent state.
    ///
    /// The pairing is the coherence rule, and it is exhaustive over the state:
    /// the disabled state owns no lease and so has no epoch, and both states
    /// that own one must name it. A live poller is fenced by the same epoch its
    /// lease carries, so it is held to the same requirement rather than a
    /// weaker one.
    pub fn with_telegram(
        mut self,
        telegram_state: TelegramState,
        telegram_poller_epoch: Option<u64>,
    ) -> Result<Self, AdminError> {
        if !matches!(
            (telegram_state, telegram_poller_epoch),
            (TelegramState::DisabledNoClient, None)
                | (
                    TelegramState::LeaseOwnedNoClient | TelegramState::PollingLive,
                    Some(1..)
                )
        ) {
            return Err(AdminError::InvalidBody);
        }
        self.telegram_state = telegram_state;
        self.telegram_poller_epoch = telegram_poller_epoch;
        Ok(self)
    }

    /// Report the durable operator pause, refusing an incoherent pair.
    ///
    /// A pause is only meaningful if it is doing something, so `true` requires
    /// `accepting_intake` to already be false. Encoding the implication here
    /// rather than trusting each caller keeps `intake_paused` from becoming a
    /// decorative flag beside a status that still says intake is open — the
    /// same reason [`Self::with_telegram`] refuses its own incoherent pairs.
    ///
    /// The converse is deliberately not required: intake also closes for a
    /// degraded generation, so `accepting_intake == false` with no pause is an
    /// ordinary state.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for a pause reported alongside open
    /// intake.
    pub fn with_intake_pause(mut self, intake_paused: bool) -> Result<Self, AdminError> {
        if intake_paused && self.accepting_intake {
            return Err(AdminError::InvalidBody);
        }
        self.intake_paused = intake_paused;
        Ok(self)
    }

    /// Attach the projection observed in the same status transaction.
    ///
    /// The aggregate status and its operational detail must describe the same
    /// durable snapshot. Contradictory readiness or queue counts are refused
    /// rather than left for a client to interpret.
    pub fn with_operational(mut self, operational: OperationalStatus) -> Result<Self, AdminError> {
        let projected_pending = operational
            .outbox_pending_ready
            .checked_add(operational.outbox_pending_delayed)
            .ok_or(AdminError::CounterOutOfRange {
                field: "outbox_pending",
            })?;
        if projected_pending != self.outbox_pending
            || (operational.reconciliation_pending > 0
                && (self.state != DaemonState::Failed || self.accepting_intake))
            || (self.accepting_intake && self.state != DaemonState::Ready)
        {
            return Err(AdminError::InvalidBody);
        }
        self.operational = Some(operational);
        Ok(self)
    }

    /// Attach the durable-state counts read while answering this status.
    ///
    /// The one cross-check available here is the tenure: a measured open-tenure
    /// epoch is a claim about the same generation [`Self::generation`] reports,
    /// so the two must be the same number. They come from different databases —
    /// the lease from the main store, the tenure from the audit log — and a
    /// disagreement between them means those files describe different histories
    /// of this generation. That is refused rather than reported, for the reason
    /// [`Self::with_operational`] refuses its own contradictions: a client
    /// cannot be expected to arbitrate which of two durable records is the
    /// authority.
    ///
    /// The counts themselves are cross-checked against nothing, and deliberately
    /// so. Nothing in this build relates the run index, the automation registry
    /// or the approval ledger to each other or to the queue depths above, and an
    /// invented relation would refuse ordinary states.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for a measured open-tenure epoch that
    /// is not this snapshot's generation.
    pub fn with_durable_state(
        mut self,
        durable_state: DurableStateCounts,
    ) -> Result<Self, AdminError> {
        if matches!(
            durable_state.open_tenure_epoch,
            OperationalMetric::Measured(epoch) if epoch != self.generation
        ) {
            return Err(AdminError::InvalidBody);
        }
        self.durable_state = Some(durable_state);
        Ok(self)
    }

    /// Daemon instance identifier.
    #[must_use]
    pub const fn instance_id(&self) -> &AdminInstanceId {
        &self.instance_id
    }

    /// What the daemon that answered can do.
    ///
    /// [`ADMIN_CAPABILITY`] on a snapshot this process built, and the peer's own
    /// number on one it decoded. A client compares it against the number it was
    /// written for; it never compares it against its own constant and assumes
    /// they must match.
    #[must_use]
    pub const fn capability(&self) -> u32 {
        self.capability
    }

    /// Carry the capability a peer reported, rather than this build's.
    ///
    /// Private, and there is no public route to it: the only caller is
    /// [`Self::from_body`], so a snapshot this process *encodes* always reports
    /// what this process can actually do.
    const fn with_capability(mut self, capability: u32) -> Self {
        self.capability = capability;
        self
    }

    /// Lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DaemonState {
        self.state
    }

    /// Monotonic persisted daemon generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Latest durable global event position.
    #[must_use]
    pub const fn event_cursor(&self) -> u64 {
        self.event_cursor
    }

    /// Durable inbox entries awaiting admission.
    #[must_use]
    pub const fn inbox_pending(&self) -> u64 {
        self.inbox_pending
    }

    /// Durable effects awaiting delivery or reconciliation.
    #[must_use]
    pub const fn outbox_pending(&self) -> u64 {
        self.outbox_pending
    }

    /// Runs with nonterminal durable state.
    #[must_use]
    pub const fn running(&self) -> u64 {
        self.running
    }

    /// Whether new intake is currently admitted.
    #[must_use]
    pub const fn accepting_intake(&self) -> bool {
        self.accepting_intake
    }

    /// Whether a durable operator pause is closing intake.
    ///
    /// False does not mean intake is open: read [`Self::accepting_intake`] for
    /// that. This distinguishes an operator decision from a degraded
    /// generation, which are the two different reasons intake can be closed.
    #[must_use]
    pub const fn intake_paused(&self) -> bool {
        self.intake_paused
    }

    #[must_use]
    pub const fn telegram_state(&self) -> TelegramState {
        self.telegram_state
    }

    /// Measured sandboxed-execution capability of the daemon's own host.
    #[must_use]
    pub const fn execution_state(&self) -> ExecutionState {
        self.execution_state
    }

    #[must_use]
    pub const fn telegram_poller_epoch(&self) -> Option<u64> {
        self.telegram_poller_epoch
    }

    #[must_use]
    pub const fn operational(&self) -> Option<&OperationalStatus> {
        self.operational.as_ref()
    }

    /// The durable-state counts, absent only on a snapshot that was never
    /// completed and therefore cannot be encoded.
    #[must_use]
    pub const fn durable_state(&self) -> Option<&DurableStateCounts> {
        self.durable_state.as_ref()
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "accepting_intake".to_owned(),
                JsonValue::Bool(self.accepting_intake),
            ),
            (
                "capability".to_owned(),
                JsonValue::Integer(i64::from(self.capability)),
            ),
            (
                "durable_state".to_owned(),
                self.durable_state
                    .as_ref()
                    .ok_or(AdminError::InvalidBody)?
                    .to_body()?,
            ),
            (
                "event_cursor".to_owned(),
                integer("event_cursor", self.event_cursor)?,
            ),
            (
                "generation".to_owned(),
                integer("generation", self.generation)?,
            ),
            (
                "inbox_pending".to_owned(),
                integer("inbox_pending", self.inbox_pending)?,
            ),
            (
                "instance_id".to_owned(),
                JsonValue::String(self.instance_id.as_str().to_owned()),
            ),
            (
                "intake_paused".to_owned(),
                JsonValue::Bool(self.intake_paused),
            ),
            (
                "outbox_pending".to_owned(),
                integer("outbox_pending", self.outbox_pending)?,
            ),
            (
                "operational".to_owned(),
                self.operational
                    .as_ref()
                    .ok_or(AdminError::InvalidBody)?
                    .to_body()?,
            ),
            ("running".to_owned(), integer("running", self.running)?),
            (
                "state".to_owned(),
                JsonValue::String(self.state.as_str().to_owned()),
            ),
            (
                "telegram_poller_epoch".to_owned(),
                optional_integer("telegram_poller_epoch", self.telegram_poller_epoch)?,
            ),
            (
                "telegram_state".to_owned(),
                JsonValue::String(self.telegram_state.as_str().to_owned()),
            ),
            (
                "execution_state".to_owned(),
                JsonValue::String(self.execution_state.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        const FIELDS: [&str; 15] = [
            "accepting_intake",
            "capability",
            "durable_state",
            "event_cursor",
            "execution_state",
            "generation",
            "inbox_pending",
            "instance_id",
            "intake_paused",
            "outbox_pending",
            "operational",
            "running",
            "state",
            "telegram_poller_epoch",
            "telegram_state",
        ];
        let JsonValue::Object(entries) = body else {
            return Err(AdminError::InvalidBody);
        };
        if entries.len() != FIELDS.len()
            || !FIELDS
                .iter()
                .all(|field| entries.iter().any(|(name, _)| name == field))
        {
            return Err(AdminError::InvalidBody);
        }
        let accepting_intake = match body.get("accepting_intake") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AdminError::InvalidBody),
        };
        let intake_paused = match body.get("intake_paused") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AdminError::InvalidBody),
        };
        let instance_id = body
            .get("instance_id")
            .and_then(JsonValue::as_str)
            .ok_or(AdminError::InvalidBody)?;
        let capability = u32::try_from(unsigned(body, "capability")?).map_err(|_| {
            AdminError::CounterOutOfRange {
                field: "capability",
            }
        })?;
        let state = body
            .get("state")
            .and_then(JsonValue::as_str)
            .ok_or(AdminError::InvalidBody)?;
        Self::new(
            AdminInstanceId::new(instance_id)?,
            DaemonState::parse(state)?,
            unsigned(body, "generation")?,
            unsigned(body, "event_cursor")?,
            unsigned(body, "inbox_pending")?,
            unsigned(body, "outbox_pending")?,
            unsigned(body, "running")?,
            accepting_intake,
        )
        .map(|status| status.with_capability(capability))
        .and_then(|status| status.with_intake_pause(intake_paused))
        .and_then(|status| {
            status.with_telegram(
                TelegramState::parse(required_body_string(body, "telegram_state")?.as_str())?,
                optional_unsigned(body, "telegram_poller_epoch")?,
            )
        })
        .and_then(|status| {
            Ok(status.with_execution(ExecutionState::parse(
                required_body_string(body, "execution_state")?.as_str(),
            )?))
        })
        .and_then(|status| {
            status.with_operational(OperationalStatus::from_body(
                body.get("operational").ok_or(AdminError::InvalidBody)?,
            )?)
        })
        .and_then(|status| {
            status.with_durable_state(DurableStateCounts::from_body(
                body.get("durable_state").ok_or(AdminError::InvalidBody)?,
            )?)
        })
    }
}

/// Bounded durable summary used to authorize a later exact reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminReconciliationEvidence {
    run_id: u64,
    scope: String,
    generation_id: String,
    lease_epoch: u64,
    run_revision: u64,
    terminal_payload_present: bool,
    outbox_count: u64,
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
}

/// Redacted stable refusal category for a correlated admin operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRefusalCategory(String);

impl AdminRefusalCategory {
    pub fn new(value: impl Into<String>) -> Result<Self, AdminError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ADMIN_REFUSAL_CATEGORY_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AdminReconciliationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: u64,
        scope: impl Into<String>,
        generation_id: impl Into<String>,
        lease_epoch: u64,
        run_revision: u64,
        terminal_payload_present: bool,
        outbox_count: u64,
    ) -> Result<Self, AdminError> {
        let scope = scope.into();
        let generation_id = generation_id.into();
        if run_id == 0
            || lease_epoch == 0
            || run_revision == 0
            || !valid_coordinate(&scope, MAX_SYNTHETIC_SCOPE_BYTES)
            || !valid_coordinate(&generation_id, MAX_RECONCILIATION_FIELD_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        i64::try_from(outbox_count).map_err(|_| AdminError::CounterOutOfRange {
            field: "outbox_count",
        })?;
        Ok(Self {
            run_id,
            scope,
            generation_id,
            lease_epoch,
            run_revision,
            terminal_payload_present,
            outbox_count,
            trace_id: None,
            correlation_id: None,
            causation_id: None,
        })
    }

    /// Attach the complete provenance triple carried by the durable run.
    pub fn with_provenance(
        mut self,
        trace_id: impl Into<String>,
        correlation_id: impl Into<String>,
        causation_id: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let trace_id = trace_id.into();
        let correlation_id = correlation_id.into();
        let causation_id = causation_id.into();
        if TraceId::new(trace_id.clone()).is_err()
            || CorrelationId::new(correlation_id.clone()).is_err()
            || CausationId::new(causation_id.clone()).is_err()
        {
            return Err(AdminError::InvalidBody);
        }
        self.trace_id = Some(trace_id);
        self.correlation_id = Some(correlation_id);
        self.causation_id = Some(causation_id);
        Ok(self)
    }

    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
    #[must_use]
    pub const fn run_revision(&self) -> u64 {
        self.run_revision
    }
    #[must_use]
    pub const fn terminal_payload_present(&self) -> bool {
        self.terminal_payload_present
    }
    #[must_use]
    pub const fn outbox_count(&self) -> u64 {
        self.outbox_count
    }
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }
    #[must_use]
    pub fn causation_id(&self) -> Option<&str> {
        self.causation_id.as_deref()
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "causation_id".to_owned(),
                optional_string(&self.causation_id),
            ),
            (
                "correlation_id".to_owned(),
                optional_string(&self.correlation_id),
            ),
            (
                "generation_id".to_owned(),
                JsonValue::String(self.generation_id.clone()),
            ),
            (
                "lease_epoch".to_owned(),
                integer("lease_epoch", self.lease_epoch)?,
            ),
            (
                "outbox_count".to_owned(),
                integer("outbox_count", self.outbox_count)?,
            ),
            ("run_id".to_owned(), integer("run_id", self.run_id)?),
            (
                "run_revision".to_owned(),
                integer("run_revision", self.run_revision)?,
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
            (
                "terminal_payload_present".to_owned(),
                JsonValue::Bool(self.terminal_payload_present),
            ),
            ("trace_id".to_owned(), optional_string(&self.trace_id)),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "causation_id",
                "correlation_id",
                "generation_id",
                "lease_epoch",
                "outbox_count",
                "run_id",
                "run_revision",
                "scope",
                "terminal_payload_present",
                "trace_id",
            ],
        )?;
        let terminal_payload_present = match body.get("terminal_payload_present") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AdminError::InvalidBody),
        };
        let evidence = Self::new(
            unsigned(body, "run_id")?,
            required_body_string(body, "scope")?,
            required_body_string(body, "generation_id")?,
            unsigned(body, "lease_epoch")?,
            unsigned(body, "run_revision")?,
            terminal_payload_present,
            unsigned(body, "outbox_count")?,
        )?;
        match (
            optional_body_string(body, "trace_id")?,
            optional_body_string(body, "correlation_id")?,
            optional_body_string(body, "causation_id")?,
        ) {
            (None, None, None) => Ok(evidence),
            (Some(trace_id), Some(correlation_id), Some(causation_id)) => {
                evidence.with_provenance(trace_id, correlation_id, causation_id)
            }
            _ => Err(AdminError::InvalidBody),
        }
    }
}

/// Redacted durable evidence for one outbox effect. Payload bytes are never present.
#[derive(Clone, Eq, PartialEq)]
pub struct AdminOutboxEvidence {
    outbox_id: u64,
    intent_key: String,
    transport: String,
    kind: String,
    state: String,
    revision: u64,
    attempt: u64,
    lease_token: Option<String>,
    lease_generation_id: Option<String>,
    lease_holder: Option<String>,
    lease_epoch: Option<u64>,
    lease_expires_ms: Option<u64>,
    delivery_receipt_key: Option<String>,
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
}

impl fmt::Debug for AdminOutboxEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminOutboxEvidence")
            .field("outbox_id", &self.outbox_id)
            .field("intent_key", &self.intent_key)
            .field("transport", &self.transport)
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("revision", &self.revision)
            .field("attempt", &self.attempt)
            .field(
                "lease_token",
                &self.lease_token.as_ref().map(|_| "<redacted>"),
            )
            .field("lease_generation_id", &self.lease_generation_id)
            .field("lease_holder", &self.lease_holder)
            .field("lease_epoch", &self.lease_epoch)
            .field("lease_expires_ms", &self.lease_expires_ms)
            .field(
                "delivery_receipt_key",
                &self.delivery_receipt_key.as_ref().map(|_| "<redacted>"),
            )
            .field("trace_id", &self.trace_id)
            .field("correlation_id", &self.correlation_id)
            .field("causation_id", &self.causation_id)
            .finish()
    }
}

/// Fields used to validate one redacted durable outbox observation.
pub struct AdminOutboxEvidenceParts {
    pub outbox_id: u64,
    pub intent_key: String,
    pub transport: String,
    pub kind: String,
    pub state: String,
    pub revision: u64,
    pub attempt: u64,
    pub lease_token: Option<String>,
    pub lease_generation_id: Option<String>,
    pub lease_holder: Option<String>,
    pub lease_epoch: Option<u64>,
    pub lease_expires_ms: Option<u64>,
    pub delivery_receipt_key: Option<String>,
    pub trace_id: Option<String>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
}

impl AdminOutboxEvidence {
    pub fn new(parts: AdminOutboxEvidenceParts) -> Result<Self, AdminError> {
        let valid_optional = |value: &Option<String>| {
            value
                .as_deref()
                .is_none_or(|value| valid_coordinate(value, MAX_RECONCILIATION_FIELD_BYTES))
        };
        let lease_fields_present = [
            parts.lease_token.is_some(),
            parts.lease_generation_id.is_some(),
            parts.lease_holder.is_some(),
            parts.lease_epoch.is_some(),
            parts.lease_expires_ms.is_some(),
        ];
        let provenance_fields_present = [
            parts.trace_id.is_some(),
            parts.correlation_id.is_some(),
            parts.causation_id.is_some(),
        ];
        let provenance_is_complete = provenance_fields_present.iter().all(|present| *present);
        let provenance_is_absent = provenance_fields_present.iter().all(|present| !*present);
        let lease_is_complete = lease_fields_present.iter().all(|present| *present);
        let lease_is_absent = lease_fields_present.iter().all(|present| !*present);
        let state_is_coherent = match parts.state.as_str() {
            "pending" => lease_is_absent && parts.delivery_receipt_key.is_none(),
            "in_flight" => {
                lease_is_complete && parts.attempt > 0 && parts.delivery_receipt_key.is_none()
            }
            "delivered" => {
                (lease_is_complete || lease_is_absent) && parts.delivery_receipt_key.is_some()
            }
            "dead_lettered" => {
                (lease_is_complete || lease_is_absent) && parts.delivery_receipt_key.is_none()
            }
            _ => false,
        };
        if parts.outbox_id == 0
            || parts.revision == 0
            || !valid_coordinate(&parts.intent_key, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&parts.transport, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&parts.kind, MAX_RECONCILIATION_FIELD_BYTES)
            || !state_is_coherent
            || !valid_optional(&parts.lease_token)
            || !valid_optional(&parts.lease_generation_id)
            || !valid_optional(&parts.lease_holder)
            || !valid_optional(&parts.delivery_receipt_key)
            || !valid_provenance(
                parts.trace_id.as_deref(),
                parts.correlation_id.as_deref(),
                parts.causation_id.as_deref(),
            )
            || !(provenance_is_complete || provenance_is_absent)
            || parts.lease_epoch == Some(0)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            outbox_id: parts.outbox_id,
            intent_key: parts.intent_key,
            transport: parts.transport,
            kind: parts.kind,
            state: parts.state,
            revision: parts.revision,
            attempt: parts.attempt,
            lease_token: parts.lease_token,
            lease_generation_id: parts.lease_generation_id,
            lease_holder: parts.lease_holder,
            lease_epoch: parts.lease_epoch,
            lease_expires_ms: parts.lease_expires_ms,
            delivery_receipt_key: parts.delivery_receipt_key,
            trace_id: parts.trace_id,
            correlation_id: parts.correlation_id,
            causation_id: parts.causation_id,
        })
    }

    #[must_use]
    pub const fn outbox_id(&self) -> u64 {
        self.outbox_id
    }
    #[must_use]
    pub fn intent_key(&self) -> &str {
        &self.intent_key
    }
    #[must_use]
    pub fn transport(&self) -> &str {
        &self.transport
    }
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    #[must_use]
    pub fn lease_token(&self) -> Option<&str> {
        self.lease_token.as_deref()
    }
    #[must_use]
    pub fn lease_generation_id(&self) -> Option<&str> {
        self.lease_generation_id.as_deref()
    }
    #[must_use]
    pub fn lease_holder(&self) -> Option<&str> {
        self.lease_holder.as_deref()
    }
    #[must_use]
    pub const fn lease_epoch(&self) -> Option<u64> {
        self.lease_epoch
    }
    #[must_use]
    pub const fn lease_expires_ms(&self) -> Option<u64> {
        self.lease_expires_ms
    }
    #[must_use]
    pub fn delivery_receipt_key(&self) -> Option<&str> {
        self.delivery_receipt_key.as_deref()
    }
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.trace_id.as_deref()
    }
    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }
    #[must_use]
    pub fn causation_id(&self) -> Option<&str> {
        self.causation_id.as_deref()
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            ("attempt".to_owned(), integer("attempt", self.attempt)?),
            (
                "causation_id".to_owned(),
                optional_string(&self.causation_id),
            ),
            (
                "correlation_id".to_owned(),
                optional_string(&self.correlation_id),
            ),
            (
                "delivery_receipt_key".to_owned(),
                optional_string(&self.delivery_receipt_key),
            ),
            (
                "intent_key".to_owned(),
                JsonValue::String(self.intent_key.clone()),
            ),
            ("kind".to_owned(), JsonValue::String(self.kind.clone())),
            (
                "lease_epoch".to_owned(),
                optional_integer("lease_epoch", self.lease_epoch)?,
            ),
            (
                "lease_expires_ms".to_owned(),
                optional_integer("lease_expires_ms", self.lease_expires_ms)?,
            ),
            (
                "lease_generation_id".to_owned(),
                optional_string(&self.lease_generation_id),
            ),
            (
                "lease_holder".to_owned(),
                optional_string(&self.lease_holder),
            ),
            ("lease_token".to_owned(), optional_string(&self.lease_token)),
            (
                "outbox_id".to_owned(),
                integer("outbox_id", self.outbox_id)?,
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            ("state".to_owned(), JsonValue::String(self.state.clone())),
            ("trace_id".to_owned(), optional_string(&self.trace_id)),
            (
                "transport".to_owned(),
                JsonValue::String(self.transport.clone()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "attempt",
                "causation_id",
                "correlation_id",
                "delivery_receipt_key",
                "intent_key",
                "kind",
                "lease_epoch",
                "lease_expires_ms",
                "lease_generation_id",
                "lease_holder",
                "lease_token",
                "outbox_id",
                "revision",
                "state",
                "trace_id",
                "transport",
            ],
        )?;
        Self::new(AdminOutboxEvidenceParts {
            outbox_id: unsigned(body, "outbox_id")?,
            intent_key: required_body_string(body, "intent_key")?,
            transport: required_body_string(body, "transport")?,
            kind: required_body_string(body, "kind")?,
            state: required_body_string(body, "state")?,
            revision: unsigned(body, "revision")?,
            attempt: unsigned(body, "attempt")?,
            lease_token: optional_body_string(body, "lease_token")?,
            lease_generation_id: optional_body_string(body, "lease_generation_id")?,
            lease_holder: optional_body_string(body, "lease_holder")?,
            lease_epoch: optional_unsigned(body, "lease_epoch")?,
            lease_expires_ms: optional_unsigned(body, "lease_expires_ms")?,
            delivery_receipt_key: optional_body_string(body, "delivery_receipt_key")?,
            trace_id: optional_body_string(body, "trace_id")?,
            correlation_id: optional_body_string(body, "correlation_id")?,
            causation_id: optional_body_string(body, "causation_id")?,
        })
    }
}

/// One recent generation tenure on the read-only operator surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationTenureView {
    pub holder_id: String,
    pub lease_epoch: u64,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub end_kind: Option<String>,
}

impl GenerationTenureView {
    fn valid(&self) -> bool {
        valid_coordinate(&self.holder_id, MAX_RECONCILIATION_FIELD_BYTES)
            && self.lease_epoch > 0
            && self
                .ended_at_ms
                .is_none_or(|ended| ended >= self.started_at_ms)
            && matches!(
                self.end_kind.as_deref(),
                None | Some("released" | "expired" | "superseded")
            )
            && self.ended_at_ms.is_some() == self.end_kind.is_some()
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        if !self.valid() {
            return Err(AdminError::InvalidBody);
        }
        Ok(JsonValue::Object(vec![
            ("end_kind".to_owned(), optional_string(&self.end_kind)),
            (
                "ended_at_ms".to_owned(),
                optional_integer("ended_at_ms", self.ended_at_ms)?,
            ),
            (
                "holder_id".to_owned(),
                JsonValue::String(self.holder_id.clone()),
            ),
            (
                "lease_epoch".to_owned(),
                integer("lease_epoch", self.lease_epoch)?,
            ),
            (
                "started_at_ms".to_owned(),
                integer("started_at_ms", self.started_at_ms)?,
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "end_kind",
                "ended_at_ms",
                "holder_id",
                "lease_epoch",
                "started_at_ms",
            ],
        )?;
        let view = Self {
            holder_id: required_body_string(body, "holder_id")?,
            lease_epoch: unsigned(body, "lease_epoch")?,
            started_at_ms: unsigned(body, "started_at_ms")?,
            ended_at_ms: optional_unsigned(body, "ended_at_ms")?,
            end_kind: optional_body_string(body, "end_kind")?,
        };
        view.valid().then_some(view).ok_or(AdminError::InvalidBody)
    }
}

/// One recorded predecessor-to-successor observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationHandoffView {
    pub predecessor_epoch: u64,
    pub successor_epoch: u64,
    pub predecessor_end_kind: String,
    pub observed_at_ms: u64,
}

impl GenerationHandoffView {
    fn valid(&self) -> bool {
        self.predecessor_epoch > 0
            && self.successor_epoch > self.predecessor_epoch
            && matches!(
                self.predecessor_end_kind.as_str(),
                "released" | "expired" | "superseded"
            )
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        if !self.valid() {
            return Err(AdminError::InvalidBody);
        }
        Ok(JsonValue::Object(vec![
            (
                "observed_at_ms".to_owned(),
                integer("observed_at_ms", self.observed_at_ms)?,
            ),
            (
                "predecessor_end_kind".to_owned(),
                JsonValue::String(self.predecessor_end_kind.clone()),
            ),
            (
                "predecessor_epoch".to_owned(),
                integer("predecessor_epoch", self.predecessor_epoch)?,
            ),
            (
                "successor_epoch".to_owned(),
                integer("successor_epoch", self.successor_epoch)?,
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "observed_at_ms",
                "predecessor_end_kind",
                "predecessor_epoch",
                "successor_epoch",
            ],
        )?;
        let view = Self {
            predecessor_epoch: unsigned(body, "predecessor_epoch")?,
            successor_epoch: unsigned(body, "successor_epoch")?,
            predecessor_end_kind: required_body_string(body, "predecessor_end_kind")?,
            observed_at_ms: unsigned(body, "observed_at_ms")?,
        };
        view.valid().then_some(view).ok_or(AdminError::InvalidBody)
    }
}

/// Bounded recent history of the logical foreground generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationsView {
    pub generation_id: String,
    pub tenures: Vec<GenerationTenureView>,
    pub handoffs: Vec<GenerationHandoffView>,
}

impl GenerationsView {
    fn valid(&self) -> bool {
        valid_coordinate(&self.generation_id, MAX_RECONCILIATION_FIELD_BYTES)
            && self.tenures.len() <= MAX_GENERATION_HISTORY_ENTRIES
            && self.handoffs.len() <= MAX_GENERATION_HISTORY_ENTRIES
            && self.tenures.iter().all(GenerationTenureView::valid)
            && self.handoffs.iter().all(GenerationHandoffView::valid)
            && self
                .tenures
                .windows(2)
                .all(|pair| pair[0].lease_epoch < pair[1].lease_epoch)
            && self
                .handoffs
                .windows(2)
                .all(|pair| pair[0].successor_epoch < pair[1].successor_epoch)
            && self.handoffs.iter().all(|handoff| {
                self.tenures
                    .iter()
                    .any(|tenure| tenure.lease_epoch == handoff.successor_epoch)
            })
            && self.tenures.iter().enumerate().all(|(index, tenure)| {
                tenure.ended_at_ms.is_some() || index + 1 == self.tenures.len()
            })
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        if !self.valid() {
            return Err(AdminError::InvalidBody);
        }
        Ok(JsonValue::Object(vec![
            (
                "generation_id".to_owned(),
                JsonValue::String(self.generation_id.clone()),
            ),
            (
                "handoffs".to_owned(),
                JsonValue::Array(
                    self.handoffs
                        .iter()
                        .map(GenerationHandoffView::to_body)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "tenures".to_owned(),
                JsonValue::Array(
                    self.tenures
                        .iter()
                        .map(GenerationTenureView::to_body)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["generation_id", "handoffs", "tenures"])?;
        let tenures = body
            .get("tenures")
            .and_then(JsonValue::as_array)
            .ok_or(AdminError::InvalidBody)?;
        let handoffs = body
            .get("handoffs")
            .and_then(JsonValue::as_array)
            .ok_or(AdminError::InvalidBody)?;
        if tenures.len() > MAX_GENERATION_HISTORY_ENTRIES
            || handoffs.len() > MAX_GENERATION_HISTORY_ENTRIES
        {
            return Err(AdminError::InvalidBody);
        }
        let view = Self {
            generation_id: required_body_string(body, "generation_id")?,
            tenures: tenures
                .iter()
                .map(GenerationTenureView::from_body)
                .collect::<Result<Vec<_>, _>>()?,
            handoffs: handoffs
                .iter()
                .map(GenerationHandoffView::from_body)
                .collect::<Result<Vec<_>, _>>()?,
        };
        view.valid().then_some(view).ok_or(AdminError::InvalidBody)
    }
}

/// One append-only reload transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadTransitionView {
    pub revision: u64,
    pub phase: String,
    pub observed_at_ms: u64,
    pub failure_category: Option<String>,
}

impl ReloadTransitionView {
    fn valid(&self) -> bool {
        self.revision > 0
            && valid_reload_phase(&self.phase)
            && self
                .failure_category
                .as_ref()
                .is_none_or(|value| valid_coordinate(value, MAX_ADMIN_REFUSAL_CATEGORY_BYTES))
            && matches!(self.phase.as_str(), "failed" | "rolled_back")
                == self.failure_category.is_some()
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        if !self.valid() {
            return Err(AdminError::InvalidBody);
        }
        Ok(JsonValue::Object(vec![
            (
                "failure_category".to_owned(),
                optional_string(&self.failure_category),
            ),
            ("phase".to_owned(), JsonValue::String(self.phase.clone())),
            (
                "observed_at_ms".to_owned(),
                integer("observed_at_ms", self.observed_at_ms)?,
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &["failure_category", "observed_at_ms", "phase", "revision"],
        )?;
        let view = Self {
            revision: unsigned(body, "revision")?,
            phase: required_body_string(body, "phase")?,
            observed_at_ms: unsigned(body, "observed_at_ms")?,
            failure_category: optional_body_string(body, "failure_category")?,
        };
        view.valid().then_some(view).ok_or(AdminError::InvalidBody)
    }
}

/// Current state and complete bounded transition history of one reload epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadStatusView {
    pub reload_id: String,
    pub source_generation_id: String,
    pub source_lease_epoch: u64,
    pub target_generation_id: String,
    pub target_release_digest: String,
    pub phase: String,
    pub failure_category: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub terminal_at_ms: Option<u64>,
    pub revision: u64,
    pub transitions: Vec<ReloadTransitionView>,
}

impl ReloadStatusView {
    fn valid(&self) -> bool {
        let complete_history = self.transitions.first().is_some_and(|first| {
            first.revision == 1
                && first.phase == "created"
                && first.observed_at_ms == self.created_at_ms
        }) && self.transitions.last().is_some_and(|last| {
            last.revision == self.revision
                && last.phase == self.phase
                && last.observed_at_ms == self.updated_at_ms
                && last.failure_category == self.failure_category
        }) && self.transitions.windows(2).all(|pair| {
            pair[0].revision.checked_add(1) == Some(pair[1].revision)
                && pair[1].observed_at_ms >= pair[0].observed_at_ms
                && valid_reload_transition(&pair[0].phase, &pair[1].phase)
        });
        valid_coordinate(&self.reload_id, MAX_RELOAD_ID_BYTES)
            && valid_coordinate(&self.source_generation_id, MAX_RECONCILIATION_FIELD_BYTES)
            && valid_coordinate(&self.target_generation_id, MAX_RECONCILIATION_FIELD_BYTES)
            && self.source_generation_id != self.target_generation_id
            && valid_release_digest(&self.target_release_digest)
            && self.source_lease_epoch > 0
            && self.revision > 0
            && valid_reload_phase(&self.phase)
            && self.updated_at_ms >= self.created_at_ms
            && self
                .terminal_at_ms
                .is_none_or(|value| value >= self.created_at_ms)
            && self.transitions.len() <= MAX_RELOAD_TRANSITIONS
            && self.transitions.iter().all(ReloadTransitionView::valid)
            && complete_history
            && self
                .failure_category
                .as_ref()
                .is_none_or(|value| valid_coordinate(value, MAX_ADMIN_REFUSAL_CATEGORY_BYTES))
            && matches!(self.phase.as_str(), "failed" | "rolled_back")
                == self.failure_category.is_some()
            && matches!(self.phase.as_str(), "succeeded" | "failed" | "rolled_back")
                == self.terminal_at_ms.is_some()
            && self
                .terminal_at_ms
                .is_none_or(|terminal| terminal == self.updated_at_ms)
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        if !self.valid() {
            return Err(AdminError::InvalidBody);
        }
        Ok(JsonValue::Object(vec![
            (
                "created_at_ms".to_owned(),
                integer("created_at_ms", self.created_at_ms)?,
            ),
            (
                "failure_category".to_owned(),
                optional_string(&self.failure_category),
            ),
            ("phase".to_owned(), JsonValue::String(self.phase.clone())),
            (
                "reload_id".to_owned(),
                JsonValue::String(self.reload_id.clone()),
            ),
            ("revision".to_owned(), integer("revision", self.revision)?),
            (
                "source_generation_id".to_owned(),
                JsonValue::String(self.source_generation_id.clone()),
            ),
            (
                "source_lease_epoch".to_owned(),
                integer("source_lease_epoch", self.source_lease_epoch)?,
            ),
            (
                "target_generation_id".to_owned(),
                JsonValue::String(self.target_generation_id.clone()),
            ),
            (
                "target_release_digest".to_owned(),
                JsonValue::String(self.target_release_digest.clone()),
            ),
            (
                "terminal_at_ms".to_owned(),
                optional_integer("terminal_at_ms", self.terminal_at_ms)?,
            ),
            (
                "transitions".to_owned(),
                JsonValue::Array(
                    self.transitions
                        .iter()
                        .map(ReloadTransitionView::to_body)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "updated_at_ms".to_owned(),
                integer("updated_at_ms", self.updated_at_ms)?,
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "created_at_ms",
                "failure_category",
                "phase",
                "reload_id",
                "revision",
                "source_generation_id",
                "source_lease_epoch",
                "target_generation_id",
                "target_release_digest",
                "terminal_at_ms",
                "transitions",
                "updated_at_ms",
            ],
        )?;
        let transitions = body
            .get("transitions")
            .and_then(JsonValue::as_array)
            .ok_or(AdminError::InvalidBody)?;
        if transitions.len() > MAX_RELOAD_TRANSITIONS {
            return Err(AdminError::InvalidBody);
        }
        let view = Self {
            reload_id: required_body_string(body, "reload_id")?,
            source_generation_id: required_body_string(body, "source_generation_id")?,
            source_lease_epoch: unsigned(body, "source_lease_epoch")?,
            target_generation_id: required_body_string(body, "target_generation_id")?,
            target_release_digest: required_body_string(body, "target_release_digest")?,
            phase: required_body_string(body, "phase")?,
            failure_category: optional_body_string(body, "failure_category")?,
            created_at_ms: unsigned(body, "created_at_ms")?,
            updated_at_ms: unsigned(body, "updated_at_ms")?,
            terminal_at_ms: optional_unsigned(body, "terminal_at_ms")?,
            revision: unsigned(body, "revision")?,
            transitions: transitions
                .iter()
                .map(ReloadTransitionView::from_body)
                .collect::<Result<Vec<_>, _>>()?,
        };
        view.valid().then_some(view).ok_or(AdminError::InvalidBody)
    }
}

fn valid_reload_phase(value: &str) -> bool {
    matches!(
        value,
        "created"
            | "candidate_started"
            | "warm"
            | "quiescing"
            | "transferred"
            | "active_proven"
            | "draining"
            | "succeeded"
            | "failed"
            | "rolled_back"
    )
}

fn valid_reload_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("created", "candidate_started" | "failed")
            | ("candidate_started", "warm" | "failed")
            | ("warm", "quiescing" | "failed")
            | ("quiescing", "transferred" | "failed")
            | ("transferred", "active_proven" | "failed" | "rolled_back")
            | ("active_proven", "draining" | "failed" | "rolled_back")
            | ("draining", "succeeded" | "failed" | "rolled_back")
    )
}

fn valid_release_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

/// A correlated response from the local daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminResponse {
    /// Current durable status.
    Status {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Consistent status snapshot.
        status: DaemonStatus,
    },
    /// Prometheus text exposition from the same point-in-time projection.
    Metrics {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Bounded UTF-8 Prometheus text ending in a newline.
        exposition: String,
    },
    /// Recent generation tenure and handoff history.
    Generations {
        request_id: RequestId,
        generations: GenerationsView,
    },
    /// One reload epoch and its append-only history.
    ReloadStatus {
        request_id: RequestId,
        reload: ReloadStatusView,
    },
    /// The exact release completed its durable generation handoff.
    ReloadSucceeded {
        request_id: RequestId,
        reload_id: String,
    },
    /// The reload epoch is durable and the handoff is now executing.
    ReloadAccepted {
        request_id: RequestId,
        reload_id: String,
    },
    /// The retained release completed its durable generation handoff.
    RollbackSucceeded {
        request_id: RequestId,
        reload_id: String,
    },
    /// The rollback epoch is durable and the reverse handoff is now executing.
    RollbackAccepted {
        request_id: RequestId,
        reload_id: String,
    },
    /// A synthetic work item is durable, or the exact retry was replayed.
    SyntheticAccepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Durable inbox identity.
        inbox_id: u64,
        /// Whether an identical stable-key submission already existed.
        duplicate: bool,
    },
    /// One RunSpec document is durably held, or the exact retry was replayed.
    ///
    /// Custody is all this reports. It is not an admission decision, not a
    /// launch, and not a promise that the run named here will ever execute.
    RunAccepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Run identity read out of the accepted document.
        run_id: RunId,
        /// SHA-256 the daemon verified over the accepted document bytes.
        spec_digest: Sha256Digest,
        /// Durable identity of the submission row.
        submission_id: u64,
        /// Whether an identical stable-key submission already existed.
        replay: bool,
    },
    /// Durable reconciliation evidence for one run.
    ReconciliationInspected {
        request_id: RequestId,
        evidence: AdminReconciliationEvidence,
    },
    /// One explicit failure decision was committed or exactly replayed.
    ReconciliationFailed {
        request_id: RequestId,
        run_event_id: u64,
        inbox_event_id: u64,
        outbox_id: u64,
        duplicate: bool,
    },
    /// Redacted evidence for one durable outbox effect.
    OutboxInspected {
        request_id: RequestId,
        evidence: AdminOutboxEvidence,
    },
    /// An expired effect was explicitly closed, or the exact decision replayed.
    OutboxReconciled {
        request_id: RequestId,
        outbox_id: u64,
        state: String,
        revision: u64,
        duplicate: bool,
    },
    /// Intake is durably closed for this generation.
    ///
    /// The decision outlives this process. A daemon restarted after this
    /// response comes back with intake still closed.
    IntakePaused {
        request_id: RequestId,
        /// Durable identity of the pause row.
        pause_id: u64,
        /// Fencing revision an exact resume must present.
        revision: u64,
    },
    /// A durable pause was closed and intake reopened.
    IntakeResumed {
        request_id: RequestId,
        /// Durable identity of the pause row, which is retained, not deleted.
        pause_id: u64,
        /// Revision the closed pause now carries.
        revision: u64,
    },
    /// The request was definitely refused before a successful mutation.
    Refused {
        request_id: RequestId,
        category: AdminRefusalCategory,
    },
    /// The daemon accepted an orderly-shutdown request and closed intake.
    ShutdownAccepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
    },
}

impl AdminResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Status { request_id, .. }
            | Self::Metrics { request_id, .. }
            | Self::Generations { request_id, .. }
            | Self::ReloadStatus { request_id, .. }
            | Self::ReloadSucceeded { request_id, .. }
            | Self::ReloadAccepted { request_id, .. }
            | Self::RollbackSucceeded { request_id, .. }
            | Self::RollbackAccepted { request_id, .. }
            | Self::SyntheticAccepted { request_id, .. }
            | Self::RunAccepted { request_id, .. }
            | Self::ReconciliationInspected { request_id, .. }
            | Self::ReconciliationFailed { request_id, .. }
            | Self::OutboxInspected { request_id, .. }
            | Self::OutboxReconciled { request_id, .. }
            | Self::IntakePaused { request_id, .. }
            | Self::IntakeResumed { request_id, .. }
            | Self::Refused { request_id, .. }
            | Self::ShutdownAccepted { request_id } => request_id,
        }
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or compile-time envelope literal is
    /// outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, AdminError> {
        match self {
            Self::Status { request_id, status } => Ok(Message::new(
                envelope(request_id.clone(), "status_result")?,
                status.to_body()?,
            )),
            Self::Metrics {
                request_id,
                exposition,
            } => {
                if !valid_metrics_exposition(exposition) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Message::new(
                    envelope(request_id.clone(), "metrics_result")?,
                    JsonValue::Object(vec![(
                        "exposition".to_owned(),
                        JsonValue::String(exposition.clone()),
                    )]),
                ))
            }
            Self::Generations {
                request_id,
                generations,
            } => Ok(Message::new(
                envelope(request_id.clone(), "generations_result")?,
                generations.to_body()?,
            )),
            Self::ReloadStatus { request_id, reload } => Ok(Message::new(
                envelope(request_id.clone(), "reload_status_result")?,
                reload.to_body()?,
            )),
            Self::ReloadSucceeded {
                request_id,
                reload_id,
            } => {
                if !valid_coordinate(reload_id, MAX_RELOAD_ID_BYTES) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Message::new(
                    envelope(request_id.clone(), "reload_succeeded")?,
                    JsonValue::Object(vec![(
                        "reload_id".to_owned(),
                        JsonValue::String(reload_id.clone()),
                    )]),
                ))
            }
            Self::ReloadAccepted {
                request_id,
                reload_id,
            } => reload_receipt(request_id, reload_id, "reload_accepted"),
            Self::RollbackSucceeded {
                request_id,
                reload_id,
            } => {
                if !valid_coordinate(reload_id, MAX_RELOAD_ID_BYTES) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Message::new(
                    envelope(request_id.clone(), "rollback_succeeded")?,
                    JsonValue::Object(vec![(
                        "reload_id".to_owned(),
                        JsonValue::String(reload_id.clone()),
                    )]),
                ))
            }
            Self::RollbackAccepted {
                request_id,
                reload_id,
            } => reload_receipt(request_id, reload_id, "rollback_accepted"),
            Self::SyntheticAccepted {
                request_id,
                inbox_id,
                duplicate,
            } => Ok(Message::new(
                envelope(request_id.clone(), "synthetic_accepted")?,
                JsonValue::Object(vec![
                    ("duplicate".to_owned(), JsonValue::Bool(*duplicate)),
                    ("inbox_id".to_owned(), integer("inbox_id", *inbox_id)?),
                ]),
            )),
            Self::RunAccepted {
                request_id,
                run_id,
                spec_digest,
                submission_id,
                replay,
            } => {
                // A durable row identity starts at one. Zero would be an
                // unwritten row reported as accepted.
                if *submission_id == 0 {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Message::new(
                    envelope(request_id.clone(), "run_accepted")?,
                    JsonValue::Object(vec![
                        ("replay".to_owned(), JsonValue::Bool(*replay)),
                        (
                            "run_id".to_owned(),
                            JsonValue::String(run_id.as_str().to_owned()),
                        ),
                        (
                            "spec_digest".to_owned(),
                            JsonValue::String(spec_digest.to_string()),
                        ),
                        (
                            "submission_id".to_owned(),
                            integer("submission_id", *submission_id)?,
                        ),
                    ]),
                ))
            }
            Self::ReconciliationInspected {
                request_id,
                evidence,
            } => Ok(Message::new(
                envelope(request_id.clone(), "reconciliation_inspected")?,
                evidence.to_body()?,
            )),
            Self::ReconciliationFailed {
                request_id,
                run_event_id,
                inbox_event_id,
                outbox_id,
                duplicate,
            } => Ok(Message::new(
                envelope(request_id.clone(), "reconciliation_failed")?,
                JsonValue::Object(vec![
                    ("duplicate".to_owned(), JsonValue::Bool(*duplicate)),
                    (
                        "inbox_event_id".to_owned(),
                        integer("inbox_event_id", *inbox_event_id)?,
                    ),
                    ("outbox_id".to_owned(), integer("outbox_id", *outbox_id)?),
                    (
                        "run_event_id".to_owned(),
                        integer("run_event_id", *run_event_id)?,
                    ),
                ]),
            )),
            Self::OutboxInspected {
                request_id,
                evidence,
            } => Ok(Message::new(
                envelope(request_id.clone(), "outbox_inspected")?,
                evidence.to_body()?,
            )),
            Self::OutboxReconciled {
                request_id,
                outbox_id,
                state,
                revision,
                duplicate,
            } => {
                if *outbox_id == 0
                    || *revision == 0
                    || !matches!(state.as_str(), "delivered" | "dead_lettered")
                {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Message::new(
                    envelope(request_id.clone(), "outbox_reconciled")?,
                    JsonValue::Object(vec![
                        ("duplicate".to_owned(), JsonValue::Bool(*duplicate)),
                        ("outbox_id".to_owned(), integer("outbox_id", *outbox_id)?),
                        ("revision".to_owned(), integer("revision", *revision)?),
                        ("state".to_owned(), JsonValue::String(state.clone())),
                    ]),
                ))
            }
            Self::IntakePaused {
                request_id,
                pause_id,
                revision,
            }
            | Self::IntakeResumed {
                request_id,
                pause_id,
                revision,
            } => {
                // A durable row identity starts at one and a written row has a
                // revision. Zero for either would be an unwritten decision
                // reported as committed.
                if *pause_id == 0 || *revision == 0 {
                    return Err(AdminError::InvalidBody);
                }
                let kind = if matches!(self, Self::IntakePaused { .. }) {
                    "intake_paused"
                } else {
                    "intake_resumed"
                };
                Ok(Message::new(
                    envelope(request_id.clone(), kind)?,
                    JsonValue::Object(vec![
                        ("pause_id".to_owned(), integer("pause_id", *pause_id)?),
                        ("revision".to_owned(), integer("revision", *revision)?),
                    ]),
                ))
            }
            Self::Refused {
                request_id,
                category,
            } => Ok(Message::new(
                envelope(request_id.clone(), "refused")?,
                JsonValue::Object(vec![(
                    "category".to_owned(),
                    JsonValue::String(category.as_str().to_owned()),
                )]),
            )),
            Self::ShutdownAccepted { request_id } => Ok(Message::new(
                envelope(request_id.clone(), "shutdown_accepted")?,
                JsonValue::Object(Vec::new()),
            )),
        }
    }

    /// Decode and admit a response against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown response kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AdminError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "status_result" => Ok(Self::Status {
                request_id,
                status: DaemonStatus::from_body(message.body())?,
            }),
            "metrics_result" => {
                exact_fields(message.body(), &["exposition"])?;
                let exposition = required_body_string(message.body(), "exposition")?;
                if !valid_metrics_exposition(&exposition) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::Metrics {
                    request_id,
                    exposition,
                })
            }
            "generations_result" => Ok(Self::Generations {
                request_id,
                generations: GenerationsView::from_body(message.body())?,
            }),
            "reload_status_result" => Ok(Self::ReloadStatus {
                request_id,
                reload: ReloadStatusView::from_body(message.body())?,
            }),
            "reload_succeeded" => {
                exact_fields(message.body(), &["reload_id"])?;
                let reload_id = required_body_string(message.body(), "reload_id")?;
                if !valid_coordinate(&reload_id, MAX_RELOAD_ID_BYTES) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::ReloadSucceeded {
                    request_id,
                    reload_id,
                })
            }
            "reload_accepted" => {
                decode_reload_receipt(message.body()).map(|reload_id| Self::ReloadAccepted {
                    request_id,
                    reload_id,
                })
            }
            "rollback_succeeded" => {
                exact_fields(message.body(), &["reload_id"])?;
                let reload_id = required_body_string(message.body(), "reload_id")?;
                if !valid_coordinate(&reload_id, MAX_RELOAD_ID_BYTES) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::RollbackSucceeded {
                    request_id,
                    reload_id,
                })
            }
            "rollback_accepted" => {
                decode_reload_receipt(message.body()).map(|reload_id| Self::RollbackAccepted {
                    request_id,
                    reload_id,
                })
            }
            "synthetic_accepted" => {
                exact_fields(message.body(), &["duplicate", "inbox_id"])?;
                let duplicate = match message.body().get("duplicate") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                Ok(Self::SyntheticAccepted {
                    request_id,
                    inbox_id: unsigned(message.body(), "inbox_id")?,
                    duplicate,
                })
            }
            "run_accepted" => {
                exact_fields(
                    message.body(),
                    &["replay", "run_id", "spec_digest", "submission_id"],
                )?;
                let replay = match message.body().get("replay") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                let submission_id = unsigned(message.body(), "submission_id")?;
                if submission_id == 0 {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::RunAccepted {
                    request_id,
                    run_id: RunId::new(required_body_string(message.body(), "run_id")?)
                        .map_err(|_| AdminError::InvalidBody)?,
                    spec_digest: parse_digest(message.body(), "spec_digest")?,
                    submission_id,
                    replay,
                })
            }
            "reconciliation_inspected" => Ok(Self::ReconciliationInspected {
                request_id,
                evidence: AdminReconciliationEvidence::from_body(message.body())?,
            }),
            "reconciliation_failed" => {
                exact_fields(
                    message.body(),
                    &["duplicate", "inbox_event_id", "outbox_id", "run_event_id"],
                )?;
                let duplicate = match message.body().get("duplicate") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                Ok(Self::ReconciliationFailed {
                    request_id,
                    run_event_id: unsigned(message.body(), "run_event_id")?,
                    inbox_event_id: unsigned(message.body(), "inbox_event_id")?,
                    outbox_id: unsigned(message.body(), "outbox_id")?,
                    duplicate,
                })
            }
            "outbox_inspected" => Ok(Self::OutboxInspected {
                request_id,
                evidence: AdminOutboxEvidence::from_body(message.body())?,
            }),
            "outbox_reconciled" => {
                exact_fields(
                    message.body(),
                    &["duplicate", "outbox_id", "revision", "state"],
                )?;
                let duplicate = match message.body().get("duplicate") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                let state = required_body_string(message.body(), "state")?;
                let outbox_id = unsigned(message.body(), "outbox_id")?;
                let revision = unsigned(message.body(), "revision")?;
                if outbox_id == 0
                    || revision == 0
                    || !matches!(state.as_str(), "delivered" | "dead_lettered")
                {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::OutboxReconciled {
                    request_id,
                    outbox_id,
                    state,
                    revision,
                    duplicate,
                })
            }
            kind @ ("intake_paused" | "intake_resumed") => {
                exact_fields(message.body(), &["pause_id", "revision"])?;
                let pause_id = unsigned(message.body(), "pause_id")?;
                let revision = unsigned(message.body(), "revision")?;
                if pause_id == 0 || revision == 0 {
                    return Err(AdminError::InvalidBody);
                }
                Ok(if kind == "intake_paused" {
                    Self::IntakePaused {
                        request_id,
                        pause_id,
                        revision,
                    }
                } else {
                    Self::IntakeResumed {
                        request_id,
                        pause_id,
                        revision,
                    }
                })
            }
            "refused" => {
                exact_fields(message.body(), &["category"])?;
                Ok(Self::Refused {
                    request_id,
                    category: AdminRefusalCategory::new(required_body_string(
                        message.body(),
                        "category",
                    )?)?,
                })
            }
            "shutdown_accepted" => {
                if !matches!(message.body(), JsonValue::Object(entries) if entries.is_empty()) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::ShutdownAccepted { request_id })
            }
            _ => Err(AdminError::UnknownKind),
        }
    }
}

fn reload_receipt(
    request_id: &RequestId,
    reload_id: &str,
    kind: &str,
) -> Result<Message, AdminError> {
    if !valid_coordinate(reload_id, MAX_RELOAD_ID_BYTES) {
        return Err(AdminError::InvalidBody);
    }
    Ok(Message::new(
        envelope(request_id.clone(), kind)?,
        JsonValue::Object(vec![(
            "reload_id".to_owned(),
            JsonValue::String(reload_id.to_owned()),
        )]),
    ))
}

fn decode_reload_receipt(body: &JsonValue) -> Result<String, AdminError> {
    exact_fields(body, &["reload_id"])?;
    let reload_id = required_body_string(body, "reload_id")?;
    if !valid_coordinate(&reload_id, MAX_RELOAD_ID_BYTES) {
        return Err(AdminError::InvalidBody);
    }
    Ok(reload_id)
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, AdminError> {
    Ok(Envelope::new(
        ProtocolName::new(ADMIN_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, AdminError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(ADMIN_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, AdminError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| AdminError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, AdminError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(AdminError::InvalidBody)?;
    u64::try_from(value).map_err(|_| AdminError::InvalidBody)
}

fn optional_integer(field: &'static str, value: Option<u64>) -> Result<JsonValue, AdminError> {
    value.map_or(Ok(JsonValue::Null), |value| integer(field, value))
}

fn optional_unsigned(body: &JsonValue, field: &'static str) -> Result<Option<u64>, AdminError> {
    match body.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Integer(value)) => u64::try_from(*value)
            .map(Some)
            .map_err(|_| AdminError::InvalidBody),
        _ => Err(AdminError::InvalidBody),
    }
}

fn optional_string(value: &Option<String>) -> JsonValue {
    value
        .as_ref()
        .map_or(JsonValue::Null, |value| JsonValue::String(value.clone()))
}

fn optional_body_string(
    body: &JsonValue,
    field: &'static str,
) -> Result<Option<String>, AdminError> {
    match body.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => Ok(Some(value.clone())),
        _ => Err(AdminError::InvalidBody),
    }
}

/// Parse the canonical `sha256:<64 lowercase hex>` spelling of a body field.
fn parse_digest(body: &JsonValue, field: &'static str) -> Result<Sha256Digest, AdminError> {
    required_body_string(body, field)?
        .parse()
        .map_err(|_| AdminError::InvalidBody)
}

/// Lowercase hexadecimal, two digits per byte.
fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Decode lowercase hexadecimal, or refuse.
///
/// Uppercase digits are refused rather than folded, and an odd length is
/// refused rather than padded, so one byte string has exactly one accepted
/// spelling — the same rule the canonical JSON codec applies to everything
/// else on this wire.
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let mut byte = 0_u8;
        for digit in pair {
            byte = (byte << 4)
                | match digit {
                    b'0'..=b'9' => digit - b'0',
                    b'a'..=b'f' => digit - b'a' + 10,
                    _ => return None,
                };
        }
        bytes.push(byte);
    }
    Some(bytes)
}

fn valid_coordinate(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_provenance(
    trace_id: Option<&str>,
    correlation_id: Option<&str>,
    causation_id: Option<&str>,
) -> bool {
    match (trace_id, correlation_id, causation_id) {
        (None, None, None) => true,
        (Some(trace_id), Some(correlation_id), Some(causation_id)) => {
            TraceId::new(trace_id).is_ok()
                && CorrelationId::new(correlation_id).is_ok()
                && CausationId::new(causation_id).is_ok()
        }
        _ => false,
    }
}

fn valid_metrics_exposition(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_METRICS_EXPOSITION_BYTES
        && value.ends_with('\n')
        && !value.contains('\0')
        && !value.contains('\r')
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), AdminError> {
    let JsonValue::Object(entries) = body else {
        return Err(AdminError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(AdminError::InvalidBody);
    }
    Ok(())
}

fn required_body_string(body: &JsonValue, field: &'static str) -> Result<String, AdminError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(AdminError::InvalidBody)
}
