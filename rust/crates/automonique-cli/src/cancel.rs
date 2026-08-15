// SPDX-License-Identifier: Elastic-2.0

//! Stop one run's live attempt, over the admin socket.
//!
//! ```text
//! automonique cancel <run-id> <request-ref> [observed-sequence]
//! ```
//!
//! Unlike `automonique attempt cancel`, which speaks to a runner's own control
//! socket and needs an operator to know both that socket's path and the
//! attempt's identity, this verb names a **run** and goes to the daemon. The
//! daemon resolves the run to the attempt its custodied document declares and
//! delivers through the one host-wide dispatcher over the one durable ledger —
//! the same `Daemon::cancel_run` the Telegram `/cancel` reaches.
//!
//! # `request-ref` is required, and that is the point
//!
//! It is the idempotency key the durable ledger records. Presenting the same
//! reference twice is one cancellation delivered once; presenting it against a
//! different run, or with a different observed sequence, is a conflict and
//! delivers nothing. Minting one here — from a clock, or a counter — would make
//! every retry of a lost answer a second cancellation, so the operator supplies
//! it and owns its stability across their own retries.
//!
//! # `observed-sequence` defaults to zero, truthfully
//!
//! The ledger's own documentation is explicit that this field is *the
//! requester's claim* about what it had seen: it is stored and compared on
//! replay, and never checked against a spool. An operator typing this command
//! has watched no events through it, so the truthful claim is none, and zero is
//! that rather than a placeholder. Supply one to bind the cancellation to a
//! position you did observe — a later retry that claims a different one is then
//! a conflict rather than a replay.
//!
//! # What a delivered answer means
//!
//! That the request reached the attempt's cancellation sink exactly once and is
//! now durably recorded. **Not** that the process exited, that its descendants
//! were reaped, or that the run reached a terminal state. `automonique runs
//! detail <run-id>` is where those are observed.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::execute_api::{
    CancelRequestRef, CancelRunOutcome, ExecuteRequest, ExecuteResponse,
};
use automonique_protocol::tools::RunId;

use crate::admin_client;

/// One cancellation as argv named it.
#[derive(Clone)]
pub(crate) struct Operation {
    /// Run whose live attempt is to be stopped.
    pub run_id: OsString,
    /// Idempotency key for this cancellation.
    pub request_ref: OsString,
    /// The event sequence the operator claims to have observed, if they said.
    pub observed_sequence: Option<OsString>,
}

/// Why one cancellation produced no output.
enum CancelCliError {
    /// An operator-supplied argument is outside its grammar. Nothing was
    /// connected to or sent.
    Field(&'static str),
    /// The daemon, its transport or its socket answered something other than
    /// the cancellation that was asked for.
    Endpoint(String),
}

impl CancelCliError {
    fn category(&self) -> &str {
        match self {
            Self::Field(category) => category,
            Self::Endpoint(category) => category,
        }
    }

    /// Usage-shaped failures exit 2 like the rest of this CLI; everything the
    /// transport or the daemon decided exits 1.
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Field(_) => 2,
            Self::Endpoint(_) => 1,
        }
    }
}

/// Deliver one cancellation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let rendered = build(operation).and_then(|request| {
        let response = admin_client::execute_request(runtime, &request)
            .map_err(|error| CancelCliError::Endpoint(error.category().to_owned()))?;
        render(&request, response)
    });
    match rendered {
        Ok(text) => {
            if stdout.write_all(text.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique cancel refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Judge the arguments and build the request they name.
fn build(operation: &Operation) -> Result<ExecuteRequest, CancelCliError> {
    Ok(ExecuteRequest::CancelRun {
        request_id: admin_client::correlation("cancel")
            .map_err(|_| CancelCliError::Field("invalid_request_id"))?,
        run_id: operation
            .run_id
            .to_str()
            .and_then(|value| RunId::new(value).ok())
            .ok_or(CancelCliError::Field("invalid_run_id"))?,
        request_ref: operation
            .request_ref
            .to_str()
            .and_then(|value| CancelRequestRef::new(value).ok())
            .ok_or(CancelCliError::Field("invalid_request_ref"))?,
        observed_sequence: sequence(operation.observed_sequence.as_deref())?,
    })
}

/// The claimed sequence, or the truthful zero for an operator who did not say.
fn sequence(value: Option<&OsStr>) -> Result<u64, CancelCliError> {
    let Some(value) = value else {
        return Ok(0);
    };
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(CancelCliError::Field("invalid_observed_sequence"))
}

/// Render one answer.
///
/// The three outcomes read differently on purpose. A replay must not read as a
/// fresh cancellation, and a conflict must not read as either — it delivered
/// nothing, and an operator who cannot tell it from a success will believe a
/// run is stopping when it is not.
fn render(request: &ExecuteRequest, response: ExecuteResponse) -> Result<String, CancelCliError> {
    let ExecuteResponse::Cancelled {
        run_id, outcome, ..
    } = response
    else {
        return Err(CancelCliError::Endpoint(String::from("unexpected_answer")));
    };
    let request_ref = match request {
        ExecuteRequest::CancelRun { request_ref, .. } => request_ref.as_str(),
        ExecuteRequest::ExecuteRun { .. } => {
            return Err(CancelCliError::Endpoint(String::from("unexpected_request")));
        }
    };
    let note = match outcome {
        CancelRunOutcome::Delivered => {
            "delivered once; the run's terminal state is read with `runs detail`"
        }
        CancelRunOutcome::AlreadyDelivered => {
            "this reference had already been delivered; nothing was sent again"
        }
        CancelRunOutcome::Conflict => {
            "this reference is bound to different coordinates; nothing was sent"
        }
    };
    Ok(format!(
        "Automonique cancel: run_id={} request_ref={request_ref} outcome={} ({note})\n",
        run_id.as_str(),
        outcome.as_str(),
    ))
}
