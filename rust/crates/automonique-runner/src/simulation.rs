// SPDX-License-Identifier: Elastic-2.0

//! Deterministic, in-process simulation.
//!
//! This module is intentionally separate from [`crate::Runner`]. It does not
//! execute a command, contact a provider, provide a sandbox, or attest process
//! containment. Its explicitly synthetic events describe only a bounded
//! simulation.

use crate::{Authority, CancellationToken, Event, EventKind, Spool, SpoolError, Status};
use sha2::{Digest, Sha256};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const MAX_SIMULATION_ID_BYTES: usize = 256;
pub const MAX_SIMULATION_STEPS: usize = 256;
pub const MAX_SIMULATION_STEP_BYTES: usize = 8 * 1024;
// Leave room for the typed result envelope inside the spool's 64 KiB frame.
pub const MAX_SIMULATION_RESULT_BYTES: usize = 60 * 1024;
pub const MAX_TOTAL_SIMULATION_BYTES: usize = 1024 * 1024;
const MIN_SIMULATION_SPOOL_BYTES: u64 = 4_096;
const MAX_SIMULATION_SPOOL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulationSpecError {
    UnsupportedProtocol(u32),
    RunIdInvalid,
    SpoolPathNotAbsolute,
    TooManySteps,
    StepTooLarge,
    ResultTooLarge,
    InputTooLarge,
    FailureCodeInvalid,
    SpoolLimitInvalid,
}

impl fmt::Display for SimulationSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol(version) => {
                write!(
                    formatter,
                    "unsupported simulation protocol version {version}"
                )
            }
            Self::RunIdInvalid => formatter.write_str("simulation run_id is invalid"),
            Self::SpoolPathNotAbsolute => {
                formatter.write_str("simulation spool path is not absolute")
            }
            Self::TooManySteps => formatter.write_str("simulation step count exceeds the limit"),
            Self::StepTooLarge => formatter.write_str("a simulation step exceeds the byte limit"),
            Self::ResultTooLarge => formatter.write_str("simulation result exceeds the byte limit"),
            Self::InputTooLarge => formatter.write_str("total simulation input exceeds the limit"),
            Self::FailureCodeInvalid => {
                formatter.write_str("simulation failure code must be non-zero")
            }
            Self::SpoolLimitInvalid => {
                formatter.write_str("simulation spool limit is outside the supported range")
            }
        }
    }
}

impl std::error::Error for SimulationSpecError {}

/// One inert payload emitted as a deterministic simulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationStep(Vec<u8>);

impl SimulationStep {
    pub fn new(payload: impl Into<Vec<u8>>) -> Result<Self, SimulationSpecError> {
        let payload = payload.into();
        if payload.len() > MAX_SIMULATION_STEP_BYTES {
            return Err(SimulationSpecError::StepTooLarge);
        }
        Ok(Self(payload))
    }

    pub fn payload(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequestedOutcome {
    Success(Vec<u8>),
    Failure { code: u16, detail: Vec<u8> },
}

/// A bounded result requested from the deterministic simulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationOutcome(RequestedOutcome);

impl SimulationOutcome {
    pub fn success(output: impl Into<Vec<u8>>) -> Result<Self, SimulationSpecError> {
        let output = output.into();
        validate_result_size(&output)?;
        Ok(Self(RequestedOutcome::Success(output)))
    }

    pub fn failure(code: u16, detail: impl Into<Vec<u8>>) -> Result<Self, SimulationSpecError> {
        if code == 0 {
            return Err(SimulationSpecError::FailureCodeInvalid);
        }
        let detail = detail.into();
        validate_result_size(&detail)?;
        Ok(Self(RequestedOutcome::Failure { code, detail }))
    }
}

#[derive(Clone, Debug)]
pub struct SimulationSpecParts {
    pub protocol_version: u32,
    pub run_id: String,
    pub spool_directory: PathBuf,
    pub max_spool_bytes: u64,
    pub steps: Vec<SimulationStep>,
    pub outcome: SimulationOutcome,
}

/// Validated input for an in-process simulation, not an execution request.
#[derive(Clone, Debug)]
pub struct SimulationSpec {
    run_id: String,
    spool_directory: PathBuf,
    max_spool_bytes: u64,
    steps: Vec<SimulationStep>,
    outcome: SimulationOutcome,
    input_digest: [u8; 32],
}

impl SimulationSpec {
    pub fn new(parts: SimulationSpecParts) -> Result<Self, SimulationSpecError> {
        if parts.protocol_version != 1 {
            return Err(SimulationSpecError::UnsupportedProtocol(
                parts.protocol_version,
            ));
        }
        if parts.run_id.is_empty()
            || parts.run_id.len() > MAX_SIMULATION_ID_BYTES
            || parts.run_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(SimulationSpecError::RunIdInvalid);
        }
        if !parts.spool_directory.is_absolute()
            || parts.spool_directory.as_os_str().as_bytes().contains(&0)
        {
            return Err(SimulationSpecError::SpoolPathNotAbsolute);
        }
        if parts.steps.len() > MAX_SIMULATION_STEPS {
            return Err(SimulationSpecError::TooManySteps);
        }
        let result_len = match &parts.outcome.0 {
            RequestedOutcome::Success(output) => output.len(),
            RequestedOutcome::Failure { detail, .. } => detail.len(),
        };
        let total = parts
            .steps
            .iter()
            .try_fold(result_len, |total, step| total.checked_add(step.0.len()))
            .ok_or(SimulationSpecError::InputTooLarge)?;
        if total > MAX_TOTAL_SIMULATION_BYTES {
            return Err(SimulationSpecError::InputTooLarge);
        }
        if !(MIN_SIMULATION_SPOOL_BYTES..=MAX_SIMULATION_SPOOL_BYTES)
            .contains(&parts.max_spool_bytes)
        {
            return Err(SimulationSpecError::SpoolLimitInvalid);
        }
        let input_digest = input_digest(&parts.run_id, &parts.steps, &parts.outcome);
        Ok(Self {
            run_id: parts.run_id,
            spool_directory: parts.spool_directory,
            max_spool_bytes: parts.max_spool_bytes,
            steps: parts.steps,
            outcome: parts.outcome,
            input_digest,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn spool_directory(&self) -> &Path {
        &self.spool_directory
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulationResult {
    Succeeded { output: Vec<u8> },
    Failed { code: u16, detail: Vec<u8> },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationReceipt {
    result: SimulationResult,
    status: Status,
    events: Vec<Event>,
}

impl SimulationReceipt {
    pub const fn result(&self) -> &SimulationResult {
        &self.result
    }

    pub const fn status(&self) -> &Status {
        &self.status
    }

    /// Exact replay suffix: every event whose sequence is greater than cursor.
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

#[derive(Debug)]
pub enum SimulationError {
    Spool(SpoolError),
    HistoryMismatch,
}

impl fmt::Display for SimulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spool(error) => write!(formatter, "{error}"),
            Self::HistoryMismatch => formatter.write_str(
                "simulation spool does not match this validated input and deterministic plan",
            ),
        }
    }
}

impl std::error::Error for SimulationError {}

impl From<SpoolError> for SimulationError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

/// Inert deterministic runner. This is not a provider or sandbox runner.
#[derive(Clone, Copy, Debug, Default)]
pub struct SimulationRunner;

impl SimulationRunner {
    pub fn run(
        &self,
        spec: &SimulationSpec,
        cancellation: &CancellationToken,
        cursor: u64,
    ) -> Result<SimulationReceipt, SimulationError> {
        let mut spool = Spool::open(spec.spool_directory(), spec.run_id(), spec.max_spool_bytes)?;
        let existing = spool.events_after(0)?;
        let regular = plan(spec, false);
        let cancelled = plan(spec, true);
        let regular_matches = is_prefix(&existing, &regular.events);
        let cancelled_matches = is_prefix(&existing, &cancelled.events);
        let selected = match (regular_matches, cancelled_matches) {
            (false, false) => return Err(SimulationError::HistoryMismatch),
            (true, false) => regular,
            (false, true) => cancelled,
            (true, true) if cancellation.is_cancelled() => cancelled,
            (true, true) => regular,
        };
        for event in selected.events.iter().skip(existing.len()) {
            spool.append_at(event.kind, Authority::Synthetic, &event.payload, event.at)?;
        }
        let all_events = spool.events_after(0)?;
        if !is_exact(&all_events, &selected.events) {
            return Err(SimulationError::HistoryMismatch);
        }
        let events = spool.events_after(cursor)?;
        Ok(SimulationReceipt {
            result: selected.result,
            status: spool.status(),
            events,
        })
    }
}

#[derive(Clone)]
struct PlannedEvent {
    kind: EventKind,
    payload: Vec<u8>,
    at: u64,
}

struct Plan {
    events: Vec<PlannedEvent>,
    result: SimulationResult,
}

fn plan(spec: &SimulationSpec, cancelled: bool) -> Plan {
    let mut events = Vec::with_capacity(spec.steps.len() + 3);
    let mut started = b"automonique.simulation/v1/start\0".to_vec();
    started.extend_from_slice(&spec.input_digest);
    push_event(&mut events, EventKind::Started, started);
    if cancelled {
        push_event(
            &mut events,
            EventKind::CancelRequested,
            b"automonique.simulation/v1/cancel-requested".to_vec(),
        );
        push_event(&mut events, EventKind::Terminal, b"cancelled".to_vec());
        return Plan {
            events,
            result: SimulationResult::Cancelled,
        };
    }
    for (index, step) in spec.steps.iter().enumerate() {
        let mut payload = b"automonique.simulation/v1/step\0".to_vec();
        payload.extend_from_slice(&(index as u64).to_be_bytes());
        put_bytes(&mut payload, step.payload());
        push_event(&mut events, EventKind::SimulationEvent, payload);
    }
    let (result, terminal) = match &spec.outcome.0 {
        RequestedOutcome::Success(output) => {
            let mut payload = b"automonique.simulation/v1/success\0".to_vec();
            put_bytes(&mut payload, output);
            push_event(&mut events, EventKind::SimulationEvent, payload);
            (
                SimulationResult::Succeeded {
                    output: output.clone(),
                },
                b"completed".as_slice(),
            )
        }
        RequestedOutcome::Failure { code, detail } => {
            let mut payload = b"automonique.simulation/v1/failure\0".to_vec();
            payload.extend_from_slice(&code.to_be_bytes());
            put_bytes(&mut payload, detail);
            push_event(&mut events, EventKind::SimulationEvent, payload);
            (
                SimulationResult::Failed {
                    code: *code,
                    detail: detail.clone(),
                },
                b"failed".as_slice(),
            )
        }
    };
    push_event(&mut events, EventKind::Terminal, terminal.to_vec());
    Plan { events, result }
}

fn push_event(events: &mut Vec<PlannedEvent>, kind: EventKind, payload: Vec<u8>) {
    events.push(PlannedEvent {
        kind,
        payload,
        at: events.len() as u64 + 1,
    });
}

fn is_prefix(actual: &[Event], expected: &[PlannedEvent]) -> bool {
    actual.len() <= expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| event_matches(actual, expected))
}

fn is_exact(actual: &[Event], expected: &[PlannedEvent]) -> bool {
    actual.len() == expected.len() && is_prefix(actual, expected)
}

fn event_matches(actual: &Event, expected: &PlannedEvent) -> bool {
    actual.kind() == expected.kind
        && actual.authority() == Authority::Synthetic
        && actual.payload() == expected.payload
        && actual.at_millis() == expected.at
}

fn validate_result_size(value: &[u8]) -> Result<(), SimulationSpecError> {
    if value.len() > MAX_SIMULATION_RESULT_BYTES {
        return Err(SimulationSpecError::ResultTooLarge);
    }
    Ok(())
}

fn input_digest(run_id: &str, steps: &[SimulationStep], outcome: &SimulationOutcome) -> [u8; 32] {
    let mut encoded = b"automonique.simulation.input/v1\0".to_vec();
    put_bytes(&mut encoded, run_id.as_bytes());
    encoded.extend_from_slice(&(steps.len() as u64).to_be_bytes());
    for step in steps {
        put_bytes(&mut encoded, step.payload());
    }
    match &outcome.0 {
        RequestedOutcome::Success(output) => {
            encoded.push(1);
            put_bytes(&mut encoded, output);
        }
        RequestedOutcome::Failure { code, detail } => {
            encoded.push(2);
            encoded.extend_from_slice(&code.to_be_bytes());
            put_bytes(&mut encoded, detail);
        }
    }
    Sha256::digest(encoded).into()
}

fn put_bytes(destination: &mut Vec<u8>, value: &[u8]) {
    destination.extend_from_slice(&(value.len() as u64).to_be_bytes());
    destination.extend_from_slice(value);
}
