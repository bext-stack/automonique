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
//! This is that missing verb, and it is deliberately the *whole* of it: one
//! request naming one run already in custody, and one of two answers.
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
//! - **No cancel.** Cancellation is the attempt host's, not this lane's; a
//!   `cancel` verb here would be a second authority over one durable ledger.
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

/// Maximum canonical message bytes this protocol will assemble or admit.
///
/// Deliberately small. Every message here carries one bounded identifier and at
/// most one counter, so a ceiling the size of the other lanes' would be a
/// budget for fields this protocol does not have.
pub const MAX_EXECUTE_CANONICAL_BYTES: usize = 4 * 1024;

/// A run identifier costs at most two canonical bytes per source byte, because
/// a quote or a backslash escapes to two.
const RUN_ID_ENCODED_BYTES: usize = 2 * MAX_TOOL_FIELD_BYTES;

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
}

impl ExecuteRefusal {
    /// Every refusal, in canonical order.
    pub const ALL: [Self; 13] = [
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
}

impl ExecuteRequest {
    /// Correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::ExecuteRun { request_id, .. } => request_id,
        }
    }

    /// The run this request names.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        match self {
            Self::ExecuteRun { run_id, .. } => run_id,
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
                envelope(request_id.clone(), "execute_run")?,
                JsonValue::Object(vec![(
                    "run_id".to_owned(),
                    JsonValue::String(run_id.as_str().to_owned()),
                )]),
            )),
        }
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ExecuteApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "execute_run" => {
                exact_fields(message.body(), &["run_id"])?;
                Ok(Self::ExecuteRun {
                    request_id,
                    run_id: RunId::new(required_string(message.body(), "run_id")?).map_err(
                        |error| ExecuteApiError::Field {
                            field: "run_id",
                            error,
                        },
                    )?,
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
    /// Nothing was started. No attempt exists and no record was written.
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
            Self::Accepted { request_id, .. } | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Which of the six terminal outcomes this answer reports.
    ///
    /// A started attempt is `accepted`, never `completed`: a completion follows
    /// it and is read elsewhere. See [`OUTCOMES_THIS_LANE_NEVER_PRODUCES`].
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        match self {
            Self::Accepted { .. } => ActionOutcome::Accepted,
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
                envelope(request_id.clone(), "execute_accepted")?,
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
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, ExecuteApiError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "execute_accepted" => {
                exact_fields(message.body(), &["run_id", "submission_id"])?;
                Self::accepted(
                    request_id,
                    RunId::new(required_string(message.body(), "run_id")?).map_err(|error| {
                        ExecuteApiError::Field {
                            field: "run_id",
                            error,
                        }
                    })?,
                    unsigned(message.body(), "submission_id")?,
                )
            }
            "refused" => {
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

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, ExecuteApiError> {
    Ok(Envelope::new(
        ProtocolName::new(EXECUTE_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, ExecuteApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(EXECUTE_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
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
