// SPDX-License-Identifier: Elastic-2.0

//! The Automonique-native Execute API: start one run that is already in
//! custody.
//!
//! [`crate::admin::AdminCommand::SubmitRun`] takes durable custody of a
//! canonical RunSpec document and stops there — its handler says so in as many
//! words. [`crate::runs_api`] reads what is held. Neither of them starts
//! anything, and neither can grow the ability to: the admin lane's kind set is
//! closed, and the Runs lane is documented as a read surface with "no mutation
//! in this module and no field through which one could be requested".
//!
//! This is that missing verb — and, since version two, its inverse.
//!
//! # Two versions, and what separates them
//!
//! Version one is `execute_run`: one request naming one run already in custody,
//! and one of two answers. Version two adds `cancel_run`, which stops an
//! attempt this daemon started.
//!
//! The lane admits **1..=2** and writes each kind at the version that
//! introduced it: `execute_run` and `execute_accepted` stay at version one, so
//! a version-one peer's bytes are unchanged and this build still admits them;
//! `cancel_run` and `cancel_result` are written at version two, so a
//! version-one peer refuses them with [`CodecError::UnsupportedVersion`] rather
//! than reading a message it has no arm for. `refused` stays at version one
//! because its body shape is the same in both and a version-one peer must be
//! able to read a refusal to the request it sent — a refusal spelling it does
//! not define still fails closed on [`decode_security_enum`], which is the
//! behaviour that matters.
//!
//! # Why cancellation is on this lane
//!
//! Cancellation is the inverse of starting, its refusals are the ones already
//! spelled here, and the alternative — an eleventh
//! [`AdminCommand`](crate::admin::AdminCommand) — would force an entry in the
//! closed admin command registry with an approval-policy annotation for an
//! operation whose authority is the socket's peer authentication, exactly as
//! `execute_run`'s is.
//!
//! What this lane still does not do is *own* cancellation. It carries the
//! request; the attempt host owns the one dispatcher over the one durable
//! ledger, and the answers here are that ledger's vocabulary rather than a
//! second one. See [`CancelRunOutcome`].
//!
//! # Why a sixth lane rather than a widened one
//!
//! [`crate::admin`] states the arrangement this module follows: the local
//! socket serves several protocols, "the envelope's declared protocol name is
//! what separates them — not a heuristic, not a fallback chain, and not a
//! widening of [`AdminCommand`](crate::admin::AdminCommand)", and adding a lane
//! costs that module "one enum arm, one match arm and one frame-fit assertion".
//!
//! There is a second, sharper reason here. Both existing lanes are pinned by
//! [`crate::codegen`]'s drift gate, which enumerates their request and response
//! kinds by encoding one message per Rust variant behind an exhaustive `match`.
//! A new variant on either enum is therefore not a local change: it is a change
//! to the generated TypeScript surface and to the checked-in corpus that gates
//! it. A lane the generated surface does not describe costs neither, and says
//! plainly what it is — the execution verb has no client-side TypeScript
//! binding in this release.
//!
//! # What an accepted answer means, and what it does not
//!
//! [`ExecuteResponse::Accepted`] is an **acknowledgement that a run was
//! started**, on [`ActionOutcome::Accepted`] rather than
//! [`ActionOutcome::Completed`]: the attempt runs after the answer is written,
//! and its outcome is observed through [`crate::runs_api`]'s read lane. Nothing
//! in this protocol carries an outcome, an exit code, or an event, because
//! nothing here waits for one.
//!
//! An accepted answer therefore establishes exactly three things: the document
//! was in custody, the daemon admitted it against a host that can enforce the
//! composed sandbox, and one contained attempt was started for it. It
//! establishes nothing about what that attempt will do.
//!
//! # What this protocol deliberately does not carry
//!
//! - **No document.** The run is named, never supplied: executing a document
//!   that was never in custody would be an intake path wearing an execution
//!   verb, and the two are gated differently.
//! - **No prompt, no credential, no grant.** Everything the attempt runs under
//!   comes from the custodied RunSpec and from the daemon's own resolution of
//!   it. A field here through which a caller could widen a launch would make
//!   this lane an authority over the sandbox, which it is not.
//! - **No second cancellation authority.** `cancel_run` carries a request to
//!   the attempt host's one dispatcher over its one durable ledger. It does not
//!   decide anything: the disposition it reports is the ledger's, and a
//!   `request_ref` presented twice is answered `already_delivered` by that
//!   ledger rather than by anything in this module.
//! - **No actor, and therefore no authorization refusal.** Like
//!   [`crate::runs_api`], this module models no actor, so [`ExecuteRefusal`]
//!   has no `not_authorized` variant: a refusal this slice cannot decide is a
//!   refusal it must not claim. The socket's peer authentication is the whole
//!   of the access control, exactly as it is for every other lane on it.

use core::fmt;
use std::error::Error;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId,
    SecuritySensitiveEnum, SupportedProtocol, VersionRange, decode_security_enum,
};
use crate::journal::ActionOutcome;
use crate::primitives::ValueError;
use crate::tools::{MAX_TOOL_FIELD_BYTES, RunId};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for the native Execute API.
pub const EXECUTE_PROTOCOL: &str = "automonique.execute";

/// Stable schema identifier for the version-one surface.
pub const EXECUTE_API_SCHEMA_V1: &str = "automonique.execute/v1";

/// Stable schema identifier for the version-two surface.
pub const EXECUTE_API_SCHEMA_V2: &str = "automonique.execute/v2";

/// The protocol version that introduced cancellation, and this build's highest.
///
/// Written as a `match` on the fallible constructor because it is the only
/// `const fn` route to a non-zero version; the `Err` arm is unreachable for a
/// literal 2 and falls back to the first version rather than panicking, since a
/// `const` panic here would be a build failure for an unreachable case.
pub const EXECUTE_CANCEL_VERSION: MajorVersion = match MajorVersion::new(2) {
    Ok(version) => version,
    Err(_) => MajorVersion::FIRST,
};

const _: () = assert!(
    EXECUTE_CANCEL_VERSION.get() == 2,
    "the cancel verb must be written at version two"
);

/// Maximum UTF-8 byte length of a cancellation `request_ref`.
///
/// Well inside the durable ledger's own 256-byte bound, so a reference this
/// protocol admits is one that ledger will store rather than one it will refuse
/// after the frame was already accepted.
pub const MAX_CANCEL_REQUEST_REF_BYTES: usize = 128;

/// Maximum canonical message bytes this protocol will assemble or admit.
///
/// Deliberately small. Every message here carries one bounded identifier and at
/// most one counter, so a ceiling the size of the other lanes' would be a
/// budget for fields this protocol does not have.
pub const MAX_EXECUTE_CANONICAL_BYTES: usize = 4 * 1024;

/// A run identifier costs at most two canonical bytes per source byte, because
/// a quote or a backslash escapes to two.
const RUN_ID_ENCODED_BYTES: usize = 2 * MAX_TOOL_FIELD_BYTES;

/// A cancellation reference costs at most two canonical bytes per source byte,
/// by the same rule.
const REQUEST_REF_ENCODED_BYTES: usize = 2 * MAX_CANCEL_REQUEST_REF_BYTES;

/// Worst-case canonical bytes of one `u64` rendered as a decimal integer.
const SEQUENCE_ENCODED_BYTES: usize = 20;

/// Worst-case canonical bytes of the envelope wrapped around one body.
///
/// The `kind`, `protocol` and `version` members plus a maximal 128-byte
/// `request_id`, budgeted at its JSON-escaped worst case.
const ENVELOPE_OVERHEAD_BYTES: usize = 472;

/// Worst-case canonical bytes of a body scaffold, excluding its identifier.
const BODY_SCAFFOLD_BYTES: usize = 256;

const _: () = assert!(
    RUN_ID_ENCODED_BYTES + BODY_SCAFFOLD_BYTES + ENVELOPE_OVERHEAD_BYTES
        <= MAX_EXECUTE_CANONICAL_BYTES,
    "a maximal execute message must fit one execute frame"
);

/// `cancel_run` is the widest body this lane assembles: a run identifier, a
/// cancellation reference and one sequence.
const _: () = assert!(
    RUN_ID_ENCODED_BYTES
        + REQUEST_REF_ENCODED_BYTES
        + SEQUENCE_ENCODED_BYTES
        + BODY_SCAFFOLD_BYTES
        + ENVELOPE_OVERHEAD_BYTES
        <= MAX_EXECUTE_CANONICAL_BYTES,
    "a maximal cancel message must fit one execute frame"
);

/// The three outcomes a request on this protocol can never report.
///
/// `completed` names an operation whose result is already known, and this lane
/// answers before the attempt ends; `conflict` names a failed expected-revision
/// check, and nothing here carries a revision; `unknown` names a transport
/// failure, which is the *absence* of a message, so no message can carry it. A
/// reader that receives one of these on this protocol is reading a response
/// this build did not write.
pub const OUTCOMES_THIS_LANE_NEVER_PRODUCES: [ActionOutcome; 3] = [
    ActionOutcome::Completed,
    ActionOutcome::Conflict,
    ActionOutcome::Unknown,
];

/// A refusal while constructing, encoding or decoding an Execute API value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteApiError {
    /// The shared envelope or canonical JSON codec refused the message.
    ///
    /// Includes [`CodecError::UnknownEnumValue`] for a refusal this build does
    /// not define, which fails closed rather than decoding to a default.
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
    /// A durable row identity was zero, which is a row that was never written.
    UnwrittenRow {
        /// Field that claimed the unwritten identity.
        field: &'static str,
    },
    /// A message kind arrived at a protocol version other than the one that
    /// introduced it.
    ///
    /// Distinct from [`CodecError::UnsupportedVersion`], which means the
    /// version is outside this build's range entirely. This one means the
    /// version is admissible and the kind does not belong to it.
    KindVersion {
        /// Kind that was carried at the wrong version.
        kind: &'static str,
        /// Version this kind is written at.
        expected: u32,
        /// Version the message declared.
        offered: u32,
    },
}

impl ExecuteApiError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "execute_unknown_kind",
            Self::InvalidBody => "execute_invalid_body",
            Self::CounterOutOfRange { .. } => "execute_counter_out_of_range",
            Self::Field { .. } => "execute_invalid_field",
            Self::UnwrittenRow { .. } => "execute_unwritten_row",
            Self::KindVersion { .. } => "execute_kind_version",
        }
    }
}

impl fmt::Display for ExecuteApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "execute codec refused message: {error}"),
            Self::UnknownKind => formatter.write_str("execute message kind is not defined"),
            Self::InvalidBody => formatter.write_str("execute message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "execute counter {field} is outside the wire range"
                )
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::UnwrittenRow { field } => {
                write!(formatter, "{field} is zero, which names an unwritten row")
            }
            Self::KindVersion {
                kind,
                expected,
                offered,
            } => write!(
                formatter,
                "execute kind {kind} is written at version {expected}, not {offered}"
            ),
        }
    }
}

impl Error for ExecuteApiError {}

impl From<CodecError> for ExecuteApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// Why one run was not started.
///
/// Closed, and every variant is a **refusal to execute**: none of them means
/// "started with less than the document asked for". The vocabulary is
/// deliberately split finely across the fail-closed gates, because an operator
/// staring at a host that will not run anything needs to know *which* gate said
/// no — an unenforceable sandbox, an undelegated cgroup domain and a missing
/// entry helper are three different repairs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExecuteRefusal {
    /// No run with that identity is in this daemon's custody.
    UnknownRun,
    /// The run is in custody but its read-model row is not `ready`: it has
    /// already been executed, or a writer has already reported it moving.
    RunNotReady,
    /// An attempt for this run is already live on this daemon.
    AlreadyExecuting,
    /// This daemon already holds as many live attempts as it admits.
    LaneSaturated,
    /// The host cannot enforce the composed sandbox, so no attempt may run.
    /// Mirrors the `sandbox_unavailable_no_lane` execution state.
    SandboxUnenforceable,
    /// The host exposes no delegated cgroup v2 domain, so no descendant-complete
    /// containment can be created and nothing runs.
    ContainmentUnavailable,
    /// The launch entry helper this daemon must spawn is not configured, or is
    /// not a deliberate absolute path.
    LaunchHelperUnavailable,
    /// The document's prompt could not be resolved to bytes this daemon holds.
    PromptUnresolvable,
    /// The provenance of the program the document pins could not be observed,
    /// or does not match the pin.
    ProviderBinaryUnverified,
    /// The admission bridge refused the custodied document against this host.
    AdmissionRefused,
    /// An operator has closed intake on this generation.
    IntakePaused,
    /// This generation is degraded and awaiting reconciliation.
    GenerationDegraded,
    /// The daemon's own durable state or filesystem preparation failed. Nothing
    /// was started, and no part of the refusal is the caller's to fix.
    ExecutionUnavailable,
    /// The run is in custody but no attempt for it is live on this daemon, so
    /// there is nothing to cancel.
    ///
    /// **This is a terminal answer, not a silent success.** The run finished,
    /// timed out, was already cancelled, or was never started; in every one of
    /// those the cancellation was not delivered, and answering `delivered`
    /// would tell an operator their command stopped something when it stopped
    /// nothing. Which terminal state it reached is the Runs lane's to report.
    NoLiveAttempt,
    /// A live attempt was found and its cancellation sink accepted no signal.
    ///
    /// Nothing was recorded, so presenting the same `request_ref` again is a
    /// real second attempt rather than a replay. Distinct from
    /// [`ExecuteRefusal::ExecutionUnavailable`] because that one says the
    /// daemon could not consult its own state, and this one says it did and the
    /// delivery failed.
    CancelNotDelivered,
}

impl ExecuteRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 15] = [
        Self::UnknownRun,
        Self::RunNotReady,
        Self::AlreadyExecuting,
        Self::LaneSaturated,
        Self::SandboxUnenforceable,
        Self::ContainmentUnavailable,
        Self::LaunchHelperUnavailable,
        Self::PromptUnresolvable,
        Self::ProviderBinaryUnverified,
        Self::AdmissionRefused,
        Self::IntakePaused,
        Self::GenerationDegraded,
        Self::ExecutionUnavailable,
        Self::NoLiveAttempt,
        Self::CancelNotDelivered,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownRun => "unknown_run",
            Self::RunNotReady => "run_not_ready",
            Self::AlreadyExecuting => "already_executing",
            Self::LaneSaturated => "lane_saturated",
            Self::SandboxUnenforceable => "sandbox_unenforceable",
            Self::ContainmentUnavailable => "containment_unavailable",
            Self::LaunchHelperUnavailable => "launch_helper_unavailable",
            Self::PromptUnresolvable => "prompt_unresolvable",
            Self::ProviderBinaryUnverified => "provider_binary_unverified",
            Self::AdmissionRefused => "admission_refused",
            Self::IntakePaused => "intake_paused",
            Self::GenerationDegraded => "generation_degraded",
            Self::ExecutionUnavailable => "execution_unavailable",
            Self::NoLiveAttempt => "no_live_attempt",
            Self::CancelNotDelivered => "cancel_not_delivered",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|refusal| refusal.as_str() == value)
    }

    /// Whether the refusal says this host cannot execute anything at all, as
    /// opposed to saying something about the run that was named.
    ///
    /// The distinction is the one a caller retries on: a host-wide refusal is
    /// not made truthful by asking again with a different run.
    #[must_use]
    pub const fn is_host_wide(self) -> bool {
        matches!(
            self,
            Self::SandboxUnenforceable
                | Self::ContainmentUnavailable
                | Self::LaunchHelperUnavailable
                | Self::IntakePaused
                | Self::GenerationDegraded
        )
    }
}

impl fmt::Display for ExecuteRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for ExecuteRefusal {
    const FIELD: &'static str = "refusal";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// Opaque, caller-chosen reference identifying one cancellation request.
///
/// This is the idempotency key the durable cancel ledger records: presenting
/// the same reference twice is one cancellation delivered once, and presenting
/// it against a different attempt or a different observed sequence is a
/// conflict. It is therefore the caller's job to mint one that is *stable
/// across its own retries* — a Telegram bridge derives it from the message
/// coordinates so a redelivered update replays, and an operator on the command
/// line supplies one.
///
/// The grammar is the durable ledger's own — non-empty, bounded, no control
/// characters — rather than a stricter one invented here. A reference this
/// protocol admits is therefore one that ledger stores, so a caller cannot get
/// a frame accepted and a write refused for the same value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CancelRequestRef(String);

impl CancelRequestRef {
    /// Maximum accepted UTF-8 byte length.
    pub const MAX_BYTES: usize = MAX_CANCEL_REQUEST_REF_BYTES;

    /// Validate and construct the reference.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Empty`] for an empty value, [`ValueError::TooLong`]
    /// past [`CancelRequestRef::MAX_BYTES`], and
    /// [`ValueError::ControlCharacter`] for a control-bearing one.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ValueError::TooLong {
                max_bytes: Self::MAX_BYTES,
                actual_bytes: value.len(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ValueError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// Return the validated spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CancelRequestRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What one cancellation request did.
///
/// This is the durable cancel ledger's vocabulary, carried rather than
/// reinterpreted. Two of its three answers are successes and the difference
/// between them matters to an operator: `delivered` means this request stopped
/// something, `already_delivered` means an earlier request with the same
/// reference did and this one changed nothing.
///
/// The ledger's fourth and fifth dispositions are not here, because they are
/// not outcomes of a cancellation — an unregistered attempt and a sink that
/// accepted nothing are [`ExecuteRefusal::NoLiveAttempt`] and
/// [`ExecuteRefusal::CancelNotDelivered`]. Keeping them out means every value
/// of this enum is a request that reached the ledger.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CancelRunOutcome {
    /// The registered sink accepted this reference and custody now holds it.
    ///
    /// Delivery evidence only. Nothing here claims a process exited, that
    /// descendants were reaped, or that the run reached a terminal state; the
    /// Runs lane is where those are observed.
    Delivered,
    /// Custody already held this exact reference. The sink was not called and
    /// nothing was written.
    AlreadyDelivered,
    /// Custody binds this reference to a different attempt or a different
    /// observed sequence. The sink was not called and nothing was written.
    ///
    /// A refusal in substance, but reported as an outcome because it is the
    /// ledger's answer about a reference rather than a refusal to consult it,
    /// and a caller needs to tell "your reference is already spoken for" from
    /// "there was nothing to cancel".
    Conflict,
}

impl CancelRunOutcome {
    /// Every outcome, in canonical order.
    pub const ALL: [Self; 3] = [Self::Delivered, Self::AlreadyDelivered, Self::Conflict];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::AlreadyDelivered => "already_delivered",
            Self::Conflict => "conflict",
        }
    }

    /// Parse the exact stable spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }

    /// Whether this cancellation is now durably recorded.
    ///
    /// True for both successes: a replay is recorded precisely because the
    /// first delivery recorded it.
    #[must_use]
    pub const fn is_recorded(self) -> bool {
        matches!(self, Self::Delivered | Self::AlreadyDelivered)
    }
}

impl fmt::Display for CancelRunOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl SecuritySensitiveEnum for CancelRunOutcome {
    const FIELD: &'static str = "outcome";

    fn from_wire(value: &str) -> Option<Self> {
        Self::from_spelling(value)
    }
}

/// A correlated request on the Execute API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteRequest {
    /// Start the run one custodied document names.
    ExecuteRun {
        /// Correlation identifier.
        request_id: RequestId,
        /// Run to start. It must already be in custody; this carries no
        /// document.
        run_id: RunId,
    },
    /// Stop the live attempt one run has. Version two.
    CancelRun {
        /// Correlation identifier.
        request_id: RequestId,
        /// Run whose live attempt is to be cancelled.
        run_id: RunId,
        /// Idempotency key for this cancellation. See [`CancelRequestRef`].
        request_ref: CancelRequestRef,
        /// The event sequence the requester had observed when it asked.
        ///
        /// The ledger's own documentation is explicit that this is *the
        /// requester's claim*: it is stored and compared on replay, and never
        /// checked against a spool. A caller that has watched no events sends
        /// zero, which is the truthful claim rather than a placeholder.
        observed_sequence: u64,
    },
}

impl ExecuteRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::ExecuteRun { request_id, .. } | Self::CancelRun { request_id, .. } => request_id,
        }
    }

    /// The run this request names.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        match self {
            Self::ExecuteRun { run_id, .. } | Self::CancelRun { run_id, .. } => run_id,
        }
    }

    /// The protocol version this request is written at.
    #[must_use]
    pub const fn version(&self) -> MajorVersion {
        match self {
            Self::ExecuteRun { .. } => MajorVersion::FIRST,
            Self::CancelRun { .. } => EXECUTE_CANCEL_VERSION,
        }
    }

    /// Encode the request as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a compile-time envelope literal is outside
    /// the protocol bounds.
    pub fn to_message(&self) -> Result<Message, ExecuteApiError> {
        match self {
            Self::ExecuteRun { request_id, run_id } => Ok(Message::new(
                envelope(request_id.clone(), "execute_run", MajorVersion::FIRST)?,
                JsonValue::Object(vec![(
                    "run_id".to_owned(),
                    JsonValue::String(run_id.as_str().to_owned()),
                )]),
            )),
            Self::CancelRun {
                request_id,
                run_id,
                request_ref,
                observed_sequence,
            } => Ok(Message::new(
                envelope(request_id.clone(), "cancel_run", EXECUTE_CANCEL_VERSION)?,
                JsonValue::Object(vec![
                    (
                        "observed_sequence".to_owned(),
                        integer("observed_sequence", *observed_sequence)?,
                    ),
                    (
                        "request_ref".to_owned(),
                        JsonValue::String(request_ref.as_str().to_owned()),
                    ),
                    (
                        "run_id".to_owned(),
                        JsonValue::String(run_id.as_str().to_owned()),
                    ),
                ]),
            )),
        }
    }

    /// Decode and admit a request against this build's supported version range.
    ///
    /// Admission is by range, but each kind is still pinned to the version that
    /// introduced it: a `cancel_run` arriving at version one is refused as
    /// [`ExecuteApiError::KindVersion`] rather than admitted, because a peer
    /// that wrote it at version one is not speaking this protocol and letting
    /// it through would make the version a decoration.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds, kinds at the wrong version, and bodies that are
    /// not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ExecuteApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        let version = message.envelope().version();
        match message.envelope().kind().as_str() {
            "execute_run" => {
                admit_kind_version("execute_run", version, MajorVersion::FIRST)?;
                exact_fields(message.body(), &["run_id"])?;
                Ok(Self::ExecuteRun {
                    request_id,
                    run_id: run_id(message.body())?,
                })
            }
            "cancel_run" => {
                admit_kind_version("cancel_run", version, EXECUTE_CANCEL_VERSION)?;
                exact_fields(
                    message.body(),
                    &["observed_sequence", "request_ref", "run_id"],
                )?;
                Ok(Self::CancelRun {
                    request_id,
                    run_id: run_id(message.body())?,
                    request_ref: CancelRequestRef::new(required_string(
                        message.body(),
                        "request_ref",
                    )?)
                    .map_err(|error| ExecuteApiError::Field {
                        field: "request_ref",
                        error,
                    })?,
                    observed_sequence: unsigned(message.body(), "observed_sequence")?,
                })
            }
            _ => Err(ExecuteApiError::UnknownKind),
        }
    }
}

/// A correlated answer on the Execute API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecuteResponse {
    /// One contained attempt was started for the named run.
    ///
    /// The attempt is live when this is written, so the answer carries no
    /// outcome; [`crate::runs_api`] is where one is observed.
    Accepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Run that was started.
        run_id: RunId,
        /// Durable identity of the custody row the attempt was started from.
        ///
        /// A run identity is not unique — two submissions may name one run —
        /// so the answer says exactly which document is running.
        submission_id: u64,
    },
    /// One cancellation request reached the durable ledger. Version two.
    ///
    /// The `outcome` says what the ledger did with it, which is not the same as
    /// what the attempt did: see [`CancelRunOutcome::Delivered`].
    Cancelled {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Run whose attempt the request named.
        run_id: RunId,
        /// What the durable cancel ledger answered.
        outcome: CancelRunOutcome,
    },
    /// Nothing was started or cancelled. No record was written.
    Refused {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Why.
        refusal: ExecuteRefusal,
    },
}

impl ExecuteResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Accepted { request_id, .. }
            | Self::Cancelled { request_id, .. }
            | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A started attempt is `accepted`, never `completed`: a completion follows
    /// it and is read elsewhere. See [`OUTCOMES_THIS_LANE_NEVER_PRODUCES`].
    ///
    /// A cancellation is `accepted` for the same reason and one more: the
    /// request reached the sink, and whether the process died is a later
    /// observation. A ledger [`CancelRunOutcome::Conflict`] is `rejected`,
    /// because nothing was delivered.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Accepted { .. } => ActionOutcome::Accepted,
            Self::Cancelled { outcome, .. } => {
                if outcome.is_recorded() {
                    ActionOutcome::Accepted
                } else {
                    ActionOutcome::Rejected
                }
            }
            Self::Refused { .. } => ActionOutcome::Rejected,
        }
    }

    /// Record that one attempt started.
    ///
    /// # Errors
    ///
    /// Returns [`ExecuteApiError::UnwrittenRow`] for a zero `submission_id`,
    /// which names a row no writer produced — durable identities start at one.
    pub fn accepted(
        request_id: RequestId,
        run_id: RunId,
        submission_id: u64,
    ) -> Result<Self, ExecuteApiError> {
        if submission_id == 0 {
            return Err(ExecuteApiError::UnwrittenRow {
                field: "submission_id",
            });
        }
        Ok(Self::Accepted {
            request_id,
            run_id,
            submission_id,
        })
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or a compile-time envelope literal
    /// is outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, ExecuteApiError> {
        match self {
            Self::Accepted {
                request_id,
                run_id,
                submission_id,
            } => Ok(Message::new(
                envelope(request_id.clone(), "execute_accepted", MajorVersion::FIRST)?,
                JsonValue::Object(vec![
                    (
                        "run_id".to_owned(),
                        JsonValue::String(run_id.as_str().to_owned()),
                    ),
                    (
                        "submission_id".to_owned(),
                        integer("submission_id", *submission_id)?,
                    ),
                ]),
            )),
            Self::Cancelled {
                request_id,
                run_id,
                outcome,
            } => Ok(Message::new(
                envelope(request_id.clone(), "cancel_result", EXECUTE_CANCEL_VERSION)?,
                JsonValue::Object(vec![
                    (
                        "outcome".to_owned(),
                        JsonValue::String(outcome.as_str().to_owned()),
                    ),
                    (
                        "run_id".to_owned(),
                        JsonValue::String(run_id.as_str().to_owned()),
                    ),
                ]),
            )),
            Self::Refused {
                request_id,
                refusal,
            } => Ok(Message::new(
                envelope(request_id.clone(), "refused", MajorVersion::FIRST)?,
                JsonValue::Object(vec![(
                    "refusal".to_owned(),
                    JsonValue::String(refusal.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a response against this build's supported version range.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds, kinds at the wrong version, and bodies that are
    /// not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ExecuteApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        let version = message.envelope().version();
        match message.envelope().kind().as_str() {
            "execute_accepted" => {
                admit_kind_version("execute_accepted", version, MajorVersion::FIRST)?;
                exact_fields(message.body(), &["run_id", "submission_id"])?;
                Self::accepted(
                    request_id,
                    run_id(message.body())?,
                    unsigned(message.body(), "submission_id")?,
                )
            }
            "cancel_result" => {
                admit_kind_version("cancel_result", version, EXECUTE_CANCEL_VERSION)?;
                exact_fields(message.body(), &["outcome", "run_id"])?;
                Ok(Self::Cancelled {
                    request_id,
                    run_id: run_id(message.body())?,
                    outcome: decode_security_enum::<CancelRunOutcome>(&required_string(
                        message.body(),
                        "outcome",
                    )?)?,
                })
            }
            "refused" => {
                admit_kind_version("refused", version, MajorVersion::FIRST)?;
                exact_fields(message.body(), &["refusal"])?;
                Ok(Self::Refused {
                    request_id,
                    refusal: decode_security_enum::<ExecuteRefusal>(&required_string(
                        message.body(),
                        "refusal",
                    )?)?,
                })
            }
            _ => Err(ExecuteApiError::UnknownKind),
        }
    }
}

fn envelope(
    request_id: RequestId,
    kind: &str,
    version: MajorVersion,
) -> Result<Envelope, ExecuteApiError> {
    Ok(Envelope::new(
        ProtocolName::new(EXECUTE_PROTOCOL)?,
        version,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, ExecuteApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(EXECUTE_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, EXECUTE_CANCEL_VERSION)?,
    ))
}

/// Refuse a kind carried at a version other than the one that introduced it.
///
/// Range admission alone would let a peer write `cancel_run` at version one and
/// have it accepted, which would make the version a decoration rather than a
/// statement. Each kind is pinned, so the envelope's version and its kind agree
/// or the message is refused.
const fn admit_kind_version(
    kind: &'static str,
    offered: MajorVersion,
    expected: MajorVersion,
) -> Result<(), ExecuteApiError> {
    if offered.get() == expected.get() {
        return Ok(());
    }
    Err(ExecuteApiError::KindVersion {
        kind,
        expected: expected.get(),
        offered: offered.get(),
    })
}

fn run_id(body: &JsonValue) -> Result<RunId, ExecuteApiError> {
    RunId::new(required_string(body, "run_id")?).map_err(|error| ExecuteApiError::Field {
        field: "run_id",
        error,
    })
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, ExecuteApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| ExecuteApiError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, ExecuteApiError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ExecuteApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| ExecuteApiError::InvalidBody)
}

fn required_string(body: &JsonValue, field: &'static str) -> Result<String, ExecuteApiError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(ExecuteApiError::InvalidBody)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), ExecuteApiError> {
    let JsonValue::Object(entries) = body else {
        return Err(ExecuteApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(ExecuteApiError::InvalidBody);
    }
    Ok(())
}
