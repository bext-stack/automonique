// SPDX-License-Identifier: Elastic-2.0

//! Contained, journalled ownership of one JCode harness-API process.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use automonique_agents::{
    JCODE_API_SCHEMA_ID, JCODE_API_VERSION, JcodeEvent, JcodeExecutionIdentity, JcodeFrameDecoder,
    JcodeInterruptedReason, JcodeNativeAdapter, JcodeNativeEnvelope, JcodeNegotiation,
    JcodeProtocolError, JcodeRequest, JcodeTurnCollector, JcodeTurnResult, PermissionDecision,
    RunCoordinates, SessionScope, encode_jcode_request,
};
use automonique_protocol::provenance::{CausationId, CorrelationId, Provenance, TraceId};
use automonique_runner::{
    LaunchPlan, LaunchPlanError, RunContainment, SandboxedSession, spawn_sandboxed_session,
};
use automonique_store::provider_journal::{
    ApprovalDecision, ApprovalRecord, BindingRecord, CursorAdvance, FinishReason,
    MAX_REPLAY_PAYLOAD_BYTES, ProcessExit, ProcessSpawn, ProcessTermination, ProviderJournal,
    ProviderJournalError, ReplayRecordKind, ReplayStepRecord, RequestDirection,
    RequestOutcomeCommit, RequestRecord, RequestSettlement, SessionClosing, SessionClosure,
    SessionOpening, SettledOutcome, TurnCompletion, TurnOpening, TurnOutcome, TurnUsage,
};
use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "automonique/0.1";
const CLOSE_DRAIN: Duration = Duration::from_secs(10);
const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum JcodeHostError {
    InvalidField(&'static str),
    Launch(automonique_runner::LaunchError),
    LaunchPlan(LaunchPlanError),
    Io(std::io::Error),
    Protocol(JcodeProtocolError),
    Journal(ProviderJournalError),
    Containment(automonique_runner::ContainmentError),
    ProviderRefused,
    ProviderEof { incomplete_frame: bool },
    TurnAlreadyOpen,
    NoOpenTurn,
    ApprovalMismatch,
}

impl fmt::Display for JcodeHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid JCode host field: {field}"),
            Self::Launch(error) => write!(formatter, "JCode launch: {error}"),
            Self::LaunchPlan(error) => write!(formatter, "JCode launch plan: {error}"),
            Self::Io(error) => write!(formatter, "JCode I/O: {error}"),
            Self::Protocol(error) => write!(formatter, "JCode protocol: {error}"),
            Self::Journal(error) => write!(formatter, "JCode journal: {error}"),
            Self::Containment(error) => write!(formatter, "JCode containment: {error}"),
            Self::ProviderRefused => formatter.write_str("JCode refused a correlated request"),
            Self::ProviderEof { incomplete_frame } => {
                write!(
                    formatter,
                    "JCode provider EOF (incomplete frame: {incomplete_frame})"
                )
            }
            Self::TurnAlreadyOpen => formatter.write_str("a JCode turn is already open"),
            Self::NoOpenTurn => formatter.write_str("no JCode turn is open"),
            Self::ApprovalMismatch => formatter.write_str("JCode approval request mismatch"),
        }
    }
}

impl std::error::Error for JcodeHostError {}

impl From<std::io::Error> for JcodeHostError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<JcodeProtocolError> for JcodeHostError {
    fn from(value: JcodeProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<LaunchPlanError> for JcodeHostError {
    fn from(value: LaunchPlanError) -> Self {
        Self::LaunchPlan(value)
    }
}

impl From<ProviderJournalError> for JcodeHostError {
    fn from(value: ProviderJournalError) -> Self {
        Self::Journal(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeApprovalRequest {
    request_id: String,
    tool_name: String,
    description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeInputRequest {
    request_id: String,
    prompt: String,
    is_password: bool,
    tool_call_id: String,
}

impl JcodeInputRequest {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    #[must_use]
    pub const fn is_password(&self) -> bool {
        self.is_password
    }
    #[must_use]
    pub fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }
}

impl JcodeApprovalRequest {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum JcodeTurnOutcome {
    Pending,
    Completed(JcodeTurnResult),
    ApprovalRequired(JcodeApprovalRequest),
    InputRequired(JcodeInputRequest),
    Cancelled,
    InterruptedUnknown(JcodeInterruptedReason),
}

struct PendingTurn {
    turn_id: i64,
    turn_revision: u64,
    request_key: String,
    send_request_id: u64,
    occurrence_index: u64,
    replay_response: Option<Vec<u8>>,
    collector: JcodeTurnCollector,
    adapter: JcodeNativeAdapter,
    pending_approval: Option<JcodeApprovalRequest>,
    pending_approval_request_key: Option<String>,
    pending_input: Option<JcodeInputRequest>,
    pending_input_request_key: Option<String>,
    steering_request_keys: BTreeMap<u64, String>,
    cancelling: bool,
    cancel_request_key: Option<String>,
}

/// One contained JCode process, one attached provider session, serialized
/// turns, and one durable journal lineage.
pub struct JcodeSessionHost {
    logical_key: String,
    provider_session_id: String,
    process: SandboxedSession,
    reader: BufReader<std::os::unix::net::UnixStream>,
    decoder: JcodeFrameDecoder,
    incomplete_frame: bool,
    observed_events: VecDeque<JcodeEvent>,
    observed_native: VecDeque<JcodeNativeEnvelope>,
    last_event_bytes: Vec<u8>,
    negotiation: JcodeNegotiation,
    containment: Option<RunContainment>,
    journal: ProviderJournal,
    process_id: i64,
    process_revision: u64,
    session_id: i64,
    session_revision: u64,
    next_ordinal: u64,
    next_request_id: u64,
    stream_sequence: u64,
    model: Option<String>,
    pending: Option<PendingTurn>,
    closed: bool,
}

impl JcodeSessionHost {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        helper: &Path,
        plan: &LaunchPlan,
        containment: RunContainment,
        journal_path: &Path,
        logical_key: &str,
        working_dir: &Path,
        resume_session_id: Option<&str>,
        model: Option<&str>,
        expected_server: &str,
        now_ms: i64,
        startup_timeout: Duration,
    ) -> Result<Self, JcodeHostError> {
        validate_key(logical_key, "logical_key")?;
        if now_ms < 0 || !working_dir.is_absolute() {
            return Err(JcodeHostError::InvalidField("startup"));
        }
        if let Some(session_id) = resume_session_id {
            validate_key(session_id, "provider_session_id")?;
        }
        validate_key(expected_server, "expected_server")?;
        // The launch helper executes a sealed copy of the provider. JCode's
        // client then starts its shared server as a child, so `current_exe()`
        // may point at a deleted memfd. Bind the exact already-pinned on-disk
        // executable for that child unless the caller explicitly supplied the
        // same supervisor contract.
        let launch_plan = if plan
            .environment_names()
            .any(|name| name == "JCODE_SERVER_EXECUTABLE")
        {
            plan.clone()
        } else {
            plan.clone().environment(
                "JCODE_SERVER_EXECUTABLE",
                plan.program().as_os_str().as_encoded_bytes(),
            )?
        };
        let configuration_sha256 = digest(&launch_plan.encode()?);
        let identity = JcodeExecutionIdentity::pinned(
            launch_plan.program_sha256(),
            &configuration_sha256,
            expected_server,
        )?;
        let mut process = spawn_sandboxed_session(helper, &launch_plan, &containment)
            .map_err(JcodeHostError::Launch)?;
        let stream = match process.try_clone_stream() {
            Ok(stream) => stream,
            Err(error) => {
                let _ = process.kill();
                return Err(JcodeHostError::Io(error));
            }
        };
        stream.set_read_timeout(Some(startup_timeout))?;
        let mut host = StartupHost {
            process,
            reader: BufReader::new(stream),
            decoder: JcodeFrameDecoder::new(),
            incomplete_frame: false,
            next_request_id: 1,
        };
        let hello_id = host.send(&JcodeRequest::Hello {
            min_version: JCODE_API_VERSION,
            max_version: JCODE_API_VERSION,
            client: CLIENT_ID.to_owned(),
        })?;
        let hello_event = host.next_event()?;
        let negotiation = JcodeNegotiation::accept(identity, hello_id, &hello_event)?;
        let (server, capabilities) = match &hello_event {
            JcodeEvent::HelloOk {
                reply_to,
                server,
                capabilities,
            } if *reply_to == hello_id => (server.clone(), capabilities.clone()),
            JcodeEvent::Error {
                reply_to: Some(reply_to),
                ..
            } if *reply_to == hello_id => return Err(JcodeHostError::ProviderRefused),
            _ => return Err(JcodeHostError::Protocol(JcodeProtocolError::EventOrder)),
        };
        let session_request_id = match resume_session_id {
            Some(session_id) => host.send(&JcodeRequest::AttachSession {
                session_id: session_id.to_owned(),
            })?,
            None => host.send(&JcodeRequest::CreateSession {
                working_dir: Some(working_dir.to_string_lossy().into_owned()),
            })?,
        };
        let mut deferred = VecDeque::new();
        let attached_event = loop {
            let event = host.next_event()?;
            match &event {
                JcodeEvent::Attached { reply_to, .. } if *reply_to == session_request_id => {
                    break event;
                }
                JcodeEvent::Error {
                    reply_to: Some(reply_to),
                    ..
                } if *reply_to == session_request_id => {
                    return Err(JcodeHostError::ProviderRefused);
                }
                event => deferred.push_back(event.clone()),
            }
        };
        let provider_session_id = match &attached_event {
            JcodeEvent::Attached { session_id, .. } => session_id.clone(),
            _ => unreachable!("the attach loop exits only on an attached event"),
        };
        let mut startup_events = VecDeque::from([hello_event.clone()]);
        startup_events.extend(deferred);
        startup_events.push_back(attached_event.clone());
        if resume_session_id.is_some_and(|expected| expected != provider_session_id) {
            return Err(JcodeHostError::Protocol(
                JcodeProtocolError::SessionMismatch,
            ));
        }

        let mut journal = ProviderJournal::open(journal_path)?;
        super::provider_session_host::retire_orphaned_attempt(&mut journal, logical_key, now_ms)
            .map_err(|error| match error {
                super::provider_session_host::SessionHostError::Journal(error) => {
                    JcodeHostError::Journal(error)
                }
                _ => JcodeHostError::InvalidField("orphan_recovery"),
            })?;
        let spawn_key = format!("{logical_key}:{now_ms}");
        let process_receipt = journal.record_process(ProcessSpawn {
            spawn_key: &spawn_key,
            attempt_id: logical_key,
            provider_kind: "jcode",
            executable_digest: plan.program_sha256(),
            prompt_version: "provider-turn/v1",
            tool_schema_version: "jcode-api-stdio/v1",
            model_id: model.unwrap_or("provider-default"),
            force_version_change: false,
            spawned_ms: now_ms,
        })?;
        let session = journal.open_session(SessionOpening {
            process_id: process_receipt.process_id,
            provider_session_key: &provider_session_id,
            opened_ms: now_ms,
        })?;
        let capability_digest = digest(capabilities.join("\n").as_bytes());
        journal.bind_capability(BindingRecord {
            session_id: session.session_id,
            name: "jcode-harness-api",
            version: "1",
            value_digest: &capability_digest,
            bound_ms: now_ms,
        })?;
        let schema_digest = digest(server.as_bytes());
        journal.bind_schema(BindingRecord {
            session_id: session.session_id,
            name: "jcode-server",
            version: "1",
            value_digest: &schema_digest,
            bound_ms: now_ms,
        })?;
        journal.bind_capability(BindingRecord {
            session_id: session.session_id,
            name: "jcode-execution-config",
            version: JCODE_API_SCHEMA_ID,
            value_digest: &configuration_sha256,
            bound_ms: now_ms,
        })?;

        Ok(Self {
            logical_key: logical_key.to_owned(),
            provider_session_id,
            process: host.process,
            reader: host.reader,
            decoder: host.decoder,
            incomplete_frame: host.incomplete_frame,
            observed_events: startup_events,
            observed_native: VecDeque::new(),
            last_event_bytes: Vec::new(),
            negotiation,
            containment: Some(containment),
            journal,
            process_id: process_receipt.process_id,
            process_revision: process_receipt.revision,
            session_id: session.session_id,
            session_revision: session.revision,
            next_ordinal: 1,
            next_request_id: host.next_request_id,
            stream_sequence: 0,
            model: model.map(str::to_owned),
            pending: None,
            closed: false,
        })
    }

    #[must_use]
    pub fn provider_session_id(&self) -> &str {
        &self.provider_session_id
    }

    #[must_use]
    pub fn operating_system_process_id(&self) -> u32 {
        self.process.id()
    }

    /// Provider events accepted since the previous drain, in wire order.
    /// The caller may project these into the shared progress spool without
    /// reparsing provider bytes or gaining access to the protocol stream.
    pub fn take_events(&mut self) -> Vec<JcodeEvent> {
        self.observed_events.drain(..).collect()
    }

    /// Automonique-owned native envelopes accepted since the previous drain.
    pub fn take_native_envelopes(&mut self) -> Vec<JcodeNativeEnvelope> {
        self.observed_native.drain(..).collect()
    }

    pub fn begin_turn(
        &mut self,
        turn_key: &str,
        prompt: &str,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<JcodeTurnOutcome, JcodeHostError> {
        self.start_turn(turn_key, prompt, now_ms)?;
        self.poll_turn(now_ms, read_timeout)
    }

    /// Admit and send one turn without blocking for its first provider event.
    /// A supervisor can then alternate [`Self::poll_turn`] with steering and
    /// cancellation commands while retaining sole mutable ownership of the
    /// session host.
    pub fn start_turn(
        &mut self,
        turn_key: &str,
        prompt: &str,
        now_ms: i64,
    ) -> Result<(), JcodeHostError> {
        if self.closed || self.pending.is_some() {
            return Err(if self.pending.is_some() {
                JcodeHostError::TurnAlreadyOpen
            } else {
                JcodeHostError::InvalidField("closed")
            });
        }
        validate_key(turn_key, "turn_key")?;
        if prompt.is_empty() || now_ms < 0 {
            return Err(JcodeHostError::InvalidField("turn"));
        }
        let trace_id = TraceId::for_ingress("jcode_session", &self.logical_key);
        let provenance = Provenance::new(
            trace_id,
            CorrelationId::new(format!(
                "jcode-turn:{}:{}",
                self.session_id, self.next_ordinal
            ))
            .map_err(|_| JcodeHostError::InvalidField("turn_key"))?,
            CausationId::new(format!("jcode-session:{}", self.session_id))
                .map_err(|_| JcodeHostError::InvalidField("logical_key"))?,
        );
        let opening = self.journal.open_turn(TurnOpening {
            session_id: self.session_id,
            ordinal: self.next_ordinal,
            turn_key,
            opened_ms: now_ms,
            provenance: Some(&provenance),
        })?;
        let request = JcodeRequest::SendMessage {
            session_id: self.provider_session_id.clone(),
            content: prompt.to_owned(),
            images: Vec::new(),
            no_reply: false,
        };
        let request_id = self.next_request_id;
        let encoded = encode_jcode_request(request_id, &request)?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        let request_key = format!("{turn_key}:send");
        self.journal.record_request(RequestRecord {
            turn_id: opening.turn_id,
            request_key: &request_key,
            direction: RequestDirection::ToProvider,
            payload_digest: &digest(&encoded),
            canonical_payload: Some(&encoded),
            created_ms: now_ms,
        })?;
        self.journal.record_replay_step(ReplayStepRecord {
            turn_id: opening.turn_id,
            step_name: "jcode_turn",
            occurrence_index: opening.ordinal,
            kind: ReplayRecordKind::Command,
            correlation_id: &request_key,
            canonical_bytes: &encoded,
            forked_from_step_id: None,
            recorded_ms: now_ms,
        })?;
        self.process.write_all(&encoded)?;
        let coordinates = RunCoordinates::new(
            self.logical_key.clone(),
            turn_key,
            SessionScope::new("automonique", "jcode", "api-stdio")
                .map_err(|_| JcodeHostError::InvalidField("turn_coordinates"))?,
        )
        .map_err(|_| JcodeHostError::InvalidField("turn_coordinates"))?;
        let adapter = JcodeNativeAdapter::after_negotiation(
            self.negotiation.clone(),
            &coordinates,
            request_id,
            &self.provider_session_id,
        )?;
        // Bounds in `JcodeFrameDecoder` apply per turn, not to the lifetime of
        // a healthy reusable session. Every line consumed above ended with a
        // newline, so no partial frame crosses this reset.
        self.decoder = JcodeFrameDecoder::new();
        self.incomplete_frame = false;
        self.pending = Some(PendingTurn {
            turn_id: opening.turn_id,
            turn_revision: opening.revision,
            request_key,
            send_request_id: request_id,
            occurrence_index: opening.ordinal,
            replay_response: Some(Vec::new()),
            collector: JcodeTurnCollector::new(&self.provider_session_id)?,
            adapter,
            pending_approval: None,
            pending_approval_request_key: None,
            pending_input: None,
            pending_input_request_key: None,
            steering_request_keys: BTreeMap::new(),
            cancelling: false,
            cancel_request_key: None,
        });
        Ok(())
    }

    /// Consume provider events until this turn completes or pauses for an
    /// approval. The read is deadline-bounded by the caller.
    pub fn poll_turn(
        &mut self,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<JcodeTurnOutcome, JcodeHostError> {
        if self.pending.is_none() {
            return Err(JcodeHostError::NoOpenTurn);
        }
        self.reader.get_ref().set_read_timeout(Some(read_timeout))?;
        match self.drive_one(now_ms) {
            Err(JcodeHostError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(JcodeTurnOutcome::Pending)
            }
            result => result,
        }
    }

    pub fn decide_permission(
        &mut self,
        request_id: &str,
        decision: PermissionDecision,
        actor: &str,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<JcodeTurnOutcome, JcodeHostError> {
        validate_key(actor, "actor")?;
        let (turn_id, approval_request_key) = {
            let pending = self.pending.as_ref().ok_or(JcodeHostError::NoOpenTurn)?;
            let approval = pending
                .pending_approval
                .as_ref()
                .ok_or(JcodeHostError::ApprovalMismatch)?;
            if approval.request_id != request_id {
                return Err(JcodeHostError::ApprovalMismatch);
            }
            (
                pending.turn_id,
                pending
                    .pending_approval_request_key
                    .clone()
                    .ok_or(JcodeHostError::ApprovalMismatch)?,
            )
        };
        self.journal.record_approval(ApprovalRecord {
            session_id: self.session_id,
            approval_key: request_id,
            decision: match decision {
                PermissionDecision::Allow | PermissionDecision::AllowAlways => {
                    ApprovalDecision::Granted
                }
                PermissionDecision::Deny => ApprovalDecision::Denied,
            },
            deciding_actor: actor,
            decided_ms: now_ms,
        })?;
        let encoded = encode_jcode_request(
            self.next_request_id,
            &JcodeRequest::PermissionResponse {
                session_id: self.provider_session_id.clone(),
                request_id: request_id.to_owned(),
                decision,
            },
        )?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        self.process.write_all(&encoded)?;
        let response_digest = digest(&encoded);
        self.journal.settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms,
            settlement: RequestSettlement {
                request_key: &approval_request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Answered {
                    response_digest: &response_digest,
                },
            },
        })?;
        let pending = self.pending.as_mut().ok_or(JcodeHostError::NoOpenTurn)?;
        pending.collector.resolve_permission(request_id)?;
        pending.pending_approval = None;
        pending.pending_approval_request_key = None;
        self.reader.get_ref().set_read_timeout(Some(read_timeout))?;
        self.poll_turn(now_ms, read_timeout)
    }

    /// Durably answer the exact provider stdin request currently blocking the
    /// serialized turn. The journal stores only digests, never the input.
    pub fn respond_stdin(
        &mut self,
        request_id: &str,
        input: &str,
        actor: &str,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<JcodeTurnOutcome, JcodeHostError> {
        validate_key(actor, "actor")?;
        let (turn_id, input_request_key) = {
            let pending = self.pending.as_ref().ok_or(JcodeHostError::NoOpenTurn)?;
            let request = pending
                .pending_input
                .as_ref()
                .ok_or(JcodeHostError::ApprovalMismatch)?;
            if request.request_id != request_id {
                return Err(JcodeHostError::ApprovalMismatch);
            }
            (
                pending.turn_id,
                pending
                    .pending_input_request_key
                    .clone()
                    .ok_or(JcodeHostError::ApprovalMismatch)?,
            )
        };
        let encoded = encode_jcode_request(
            self.next_request_id,
            &JcodeRequest::StdinResponse {
                session_id: self.provider_session_id.clone(),
                request_id: request_id.to_owned(),
                input: input.to_owned(),
            },
        )?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        let approval_key = format!("stdin:{request_id}");
        self.journal.record_approval(ApprovalRecord {
            session_id: self.session_id,
            approval_key: &approval_key,
            decision: ApprovalDecision::Granted,
            deciding_actor: actor,
            decided_ms: now_ms,
        })?;
        self.process.write_all(&encoded)?;
        self.journal.settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms,
            settlement: RequestSettlement {
                request_key: &input_request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Answered {
                    response_digest: &digest(&encoded),
                },
            },
        })?;
        let pending = self.pending.as_mut().ok_or(JcodeHostError::NoOpenTurn)?;
        pending.collector.resolve_input(request_id)?;
        pending.pending_input = None;
        pending.pending_input_request_key = None;
        self.poll_turn(now_ms, read_timeout)
    }

    pub fn soft_interrupt(
        &mut self,
        content: &str,
        urgent: bool,
        now_ms: i64,
    ) -> Result<u64, JcodeHostError> {
        if self.pending.is_none() || content.is_empty() || now_ms < 0 {
            return Err(JcodeHostError::NoOpenTurn);
        }
        let request_id = self.next_request_id;
        let encoded = encode_jcode_request(
            request_id,
            &JcodeRequest::SoftInterrupt {
                session_id: self.provider_session_id.clone(),
                content: content.to_owned(),
                urgent,
            },
        )?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        let (turn_id, request_key) = {
            let pending = self.pending.as_ref().ok_or(JcodeHostError::NoOpenTurn)?;
            (pending.turn_id, format!("steer:{request_id}"))
        };
        self.journal.record_request(RequestRecord {
            turn_id,
            request_key: &request_key,
            direction: RequestDirection::ToProvider,
            payload_digest: &digest(&encoded),
            canonical_payload: Some(&encoded),
            created_ms: now_ms,
        })?;
        if let Err(error) = self.process.write_all(&encoded) {
            self.journal.settle_request(RequestOutcomeCommit {
                turn_id,
                now_ms,
                settlement: RequestSettlement {
                    request_key: &request_key,
                    expected_revision: 1,
                    outcome: SettledOutcome::Failed {
                        reason: "write_failed",
                    },
                },
            })?;
            return Err(JcodeHostError::Io(error));
        }
        self.pending
            .as_mut()
            .ok_or(JcodeHostError::NoOpenTurn)?
            .steering_request_keys
            .insert(request_id, request_key);
        Ok(request_id)
    }

    pub fn cancel(
        &mut self,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<JcodeTurnOutcome, JcodeHostError> {
        let pending = self.pending.as_mut().ok_or(JcodeHostError::NoOpenTurn)?;
        if pending.pending_approval.is_some() || pending.pending_input.is_some() {
            // Resolve the exact provider request before cancellation so its
            // durable request row cannot be stranded as pending.
            return Err(JcodeHostError::ApprovalMismatch);
        }
        if pending.cancelling {
            return Err(JcodeHostError::NoOpenTurn);
        }
        let request_id = self.next_request_id;
        let encoded = encode_jcode_request(
            request_id,
            &JcodeRequest::Cancel {
                session_id: self.provider_session_id.clone(),
            },
        )?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        let request_key = format!("cancel:{request_id}");
        let turn_id = self
            .pending
            .as_ref()
            .ok_or(JcodeHostError::NoOpenTurn)?
            .turn_id;
        self.journal.record_request(RequestRecord {
            turn_id,
            request_key: &request_key,
            direction: RequestDirection::ToProvider,
            payload_digest: &digest(&encoded),
            canonical_payload: Some(&encoded),
            created_ms: now_ms,
        })?;
        self.process.write_all(&encoded)?;
        let pending = self.pending.as_mut().ok_or(JcodeHostError::NoOpenTurn)?;
        pending.adapter.mark_cancellation_requested()?;
        pending.cancelling = true;
        pending.cancel_request_key = Some(request_key);
        self.poll_turn(now_ms, read_timeout)
    }

    pub fn close(mut self, now_ms: i64) -> Result<(), JcodeHostError> {
        if self.closed {
            return Ok(());
        }
        if let Some(pending) = self.pending.take() {
            self.abort_pending(pending, now_ms, "host_closed")?;
        }
        let session = self.journal.close_session(SessionClosing {
            session_id: self.session_id,
            expected_revision: self.session_revision,
            now_ms,
            closure: SessionClosure::Closed,
        })?;
        self.session_revision = session.revision;
        let _ = self.process.kill();
        let _ = self.process.wait();
        let process = self.journal.finish_process(ProcessExit {
            process_id: self.process_id,
            expected_revision: self.process_revision,
            now_ms,
            termination: ProcessTermination::Exited,
        })?;
        self.process_revision = process.revision;
        if let Some(containment) = self.containment.take() {
            containment
                .dispose(CLOSE_DRAIN)
                .map_err(JcodeHostError::Containment)?;
        }
        self.closed = true;
        Ok(())
    }

    fn drive_one(&mut self, now_ms: i64) -> Result<JcodeTurnOutcome, JcodeHostError> {
        let event = match self.next_event() {
            Ok(event) => event,
            Err(JcodeHostError::ProviderEof { incomplete_frame }) => {
                let mut pending = self.pending.take().ok_or(JcodeHostError::NoOpenTurn)?;
                let terminal = pending
                    .adapter
                    .finish_eof_with_pending_frame(incomplete_frame)?
                    .ok_or(JcodeHostError::Protocol(JcodeProtocolError::EventOrder))?;
                let reason = if incomplete_frame {
                    JcodeInterruptedReason::IncompleteFrame
                } else {
                    JcodeInterruptedReason::ProviderEof
                };
                self.observed_native.push_back(terminal);
                self.stream_sequence = self
                    .stream_sequence
                    .checked_add(1)
                    .ok_or(JcodeHostError::InvalidField("event_sequence"))?;
                self.abort_pending(pending, now_ms, "provider_eof_unknown")?;
                return Ok(JcodeTurnOutcome::InterruptedUnknown(reason));
            }
            Err(error) => return Err(error),
        };
        if let Some(pending) = self.pending.as_mut()
            && let Some(response) = pending.replay_response.as_mut()
        {
            if response.len().saturating_add(self.last_event_bytes.len())
                <= MAX_REPLAY_PAYLOAD_BYTES
            {
                response.extend_from_slice(&self.last_event_bytes);
            } else {
                pending.replay_response = None;
            }
        }
        self.observed_events.push_back(event.clone());
        let native = self
            .pending
            .as_mut()
            .ok_or(JcodeHostError::NoOpenTurn)?
            .adapter
            .observe_decoded(event.clone())?;
        self.observed_native.push_back(native);
        self.stream_sequence = self
            .stream_sequence
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("event_sequence"))?;
        let pending = self.pending.as_mut().ok_or(JcodeHostError::NoOpenTurn)?;
        if matches!(event, JcodeEvent::Error { reply_to: Some(id), .. } if id == pending.send_request_id)
        {
            let pending = self.pending.take().ok_or(JcodeHostError::NoOpenTurn)?;
            self.abort_pending(pending, now_ms, "provider_refused")?;
            return Err(JcodeHostError::ProviderRefused);
        }
        let steering_reply = match &event {
            JcodeEvent::Ok { reply_to } => Some((*reply_to, true)),
            JcodeEvent::Error {
                reply_to: Some(reply_to),
                ..
            } => Some((*reply_to, false)),
            _ => None,
        };
        if let Some((reply_to, accepted)) = steering_reply
            && let Some(request_key) = pending.steering_request_keys.remove(&reply_to)
        {
            let response_digest = digest(if accepted {
                b"ok".as_slice()
            } else {
                b"error".as_slice()
            });
            self.journal.settle_request(RequestOutcomeCommit {
                turn_id: pending.turn_id,
                now_ms,
                settlement: RequestSettlement {
                    request_key: &request_key,
                    expected_revision: 1,
                    outcome: if accepted {
                        SettledOutcome::Answered {
                            response_digest: &response_digest,
                        }
                    } else {
                        SettledOutcome::Failed {
                            reason: "provider_refused",
                        }
                    },
                },
            })?;
            return Ok(JcodeTurnOutcome::Pending);
        }
        if let JcodeEvent::PermissionRequest {
            ref request_id,
            ref tool_name,
            ref description,
            ..
        } = event
        {
            pending.collector.observe(&event)?;
            let approval = JcodeApprovalRequest {
                request_id: request_id.clone(),
                tool_name: tool_name.clone(),
                description: description.clone(),
            };
            let approval_bytes = format!(
                "{}\n{}\n{}",
                approval.request_id, approval.tool_name, approval.description
            )
            .into_bytes();
            let approval_digest = digest(&approval_bytes);
            let approval_request_key = format!("approval:{}", approval.request_id);
            self.journal.record_request(RequestRecord {
                turn_id: pending.turn_id,
                request_key: &approval_request_key,
                direction: RequestDirection::FromProvider,
                payload_digest: &approval_digest,
                canonical_payload: Some(&approval_bytes),
                created_ms: now_ms,
            })?;
            pending.pending_approval = Some(approval.clone());
            pending.pending_approval_request_key = Some(approval_request_key);
            return Ok(JcodeTurnOutcome::ApprovalRequired(approval));
        }
        if let JcodeEvent::StdinRequest {
            ref request_id,
            ref prompt,
            is_password,
            ref tool_call_id,
            ..
        } = event
        {
            pending.collector.observe(&event)?;
            let input = JcodeInputRequest {
                request_id: request_id.clone(),
                prompt: prompt.clone(),
                is_password,
                tool_call_id: tool_call_id.clone(),
            };
            let input_bytes = format!(
                "{}\n{}\n{}\n{}",
                input.request_id, input.prompt, input.is_password, input.tool_call_id
            )
            .into_bytes();
            let input_digest = digest(&input_bytes);
            let input_request_key = format!("stdin:{}", input.request_id);
            self.journal.record_request(RequestRecord {
                turn_id: pending.turn_id,
                request_key: &input_request_key,
                direction: RequestDirection::FromProvider,
                payload_digest: &input_digest,
                canonical_payload: Some(&input_bytes),
                created_ms: now_ms,
            })?;
            pending.pending_input = Some(input.clone());
            pending.pending_input_request_key = Some(input_request_key);
            return Ok(JcodeTurnOutcome::InputRequired(input));
        }
        if pending.cancelling
            && let JcodeEvent::TurnDone { ref session_id } = event
        {
            if session_id != &self.provider_session_id {
                return Err(JcodeHostError::Protocol(
                    JcodeProtocolError::SessionMismatch,
                ));
            }
            let mut pending = self.pending.take().ok_or(JcodeHostError::NoOpenTurn)?;
            if let Some(request_key) = pending.cancel_request_key.take() {
                self.journal.settle_request(RequestOutcomeCommit {
                    turn_id: pending.turn_id,
                    now_ms,
                    settlement: RequestSettlement {
                        request_key: &request_key,
                        expected_revision: 1,
                        outcome: SettledOutcome::Answered {
                            response_digest: &digest(b"turn_done"),
                        },
                    },
                })?;
            }
            self.abort_pending(pending, now_ms, "cancelled")?;
            return Ok(JcodeTurnOutcome::Cancelled);
        }
        pending.collector.observe(&event)?;
        if matches!(event, JcodeEvent::TurnDone { .. }) {
            let pending = self.pending.take().ok_or(JcodeHostError::NoOpenTurn)?;
            for request_key in pending.steering_request_keys.values() {
                self.journal.settle_request(RequestOutcomeCommit {
                    turn_id: pending.turn_id,
                    now_ms,
                    settlement: RequestSettlement {
                        request_key,
                        expected_revision: 1,
                        outcome: SettledOutcome::Failed {
                            reason: "turn_completed_before_ack",
                        },
                    },
                })?;
            }
            let result = pending.collector.finish()?;
            let response_digest = digest(result.text().as_bytes());
            if let Some(response) = pending.replay_response.as_deref()
                && !response.is_empty()
            {
                self.journal.record_replay_step(ReplayStepRecord {
                    turn_id: pending.turn_id,
                    step_name: "jcode_turn",
                    occurrence_index: pending.occurrence_index,
                    kind: ReplayRecordKind::Notification,
                    correlation_id: &pending.request_key,
                    canonical_bytes: response,
                    forked_from_step_id: None,
                    recorded_ms: now_ms,
                })?;
            }
            let settlement = [RequestSettlement {
                request_key: &pending.request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Answered {
                    response_digest: &response_digest,
                },
            }];
            let completed = self.journal.complete_turn(TurnCompletion {
                turn_id: pending.turn_id,
                expected_revision: pending.turn_revision,
                now_ms,
                outcome: TurnOutcome::Completed,
                settlements: &settlement,
                cursor: Some(CursorAdvance {
                    session_id: self.session_id,
                    stream: "events",
                    sequence: self.stream_sequence,
                    now_ms,
                }),
                usage: Some(TurnUsage {
                    gen_ai_system: "jcode",
                    request_model: self.model.as_deref(),
                    response_model: self.model.as_deref(),
                    input_tokens: result.input_tokens(),
                    cached_input_tokens: result.cache_read_input_tokens(),
                    output_tokens: result.output_tokens(),
                    finish_reason: FinishReason::Stop,
                }),
            })?;
            self.next_ordinal = completed.ordinal.saturating_add(1);
            return Ok(JcodeTurnOutcome::Completed(result));
        }
        Ok(JcodeTurnOutcome::Pending)
    }

    fn next_event(&mut self) -> Result<JcodeEvent, JcodeHostError> {
        loop {
            let mut line = Vec::new();
            let read = self.reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                return Err(JcodeHostError::ProviderEof {
                    incomplete_frame: self.incomplete_frame,
                });
            }
            if line.len() > MAX_EVENT_LINE_BYTES {
                return Err(JcodeHostError::Protocol(JcodeProtocolError::FrameTooLarge));
            }
            if !line.ends_with(b"\n") {
                self.incomplete_frame = true;
            }
            let events = self.decoder.push(&line)?;
            if events.is_empty() {
                continue;
            }
            if events.len() != 1 {
                return Err(JcodeHostError::Protocol(JcodeProtocolError::InvalidFrame));
            }
            self.last_event_bytes = line;
            return events
                .into_iter()
                .next()
                .ok_or(JcodeHostError::Protocol(JcodeProtocolError::InvalidFrame));
        }
    }

    fn abort_pending(
        &mut self,
        pending: PendingTurn,
        now_ms: i64,
        reason: &'static str,
    ) -> Result<(), JcodeHostError> {
        let mut settlements = vec![RequestSettlement {
            request_key: &pending.request_key,
            expected_revision: 1,
            outcome: SettledOutcome::Failed { reason },
        }];
        if let Some(request_key) = pending.pending_approval_request_key.as_deref() {
            settlements.push(RequestSettlement {
                request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Failed { reason },
            });
        }
        if let Some(request_key) = pending.pending_input_request_key.as_deref() {
            settlements.push(RequestSettlement {
                request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Failed { reason },
            });
        }
        if let Some(request_key) = pending.cancel_request_key.as_deref() {
            settlements.push(RequestSettlement {
                request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Failed { reason },
            });
        }
        settlements.extend(pending.steering_request_keys.values().map(|request_key| {
            RequestSettlement {
                request_key,
                expected_revision: 1,
                outcome: SettledOutcome::Failed { reason },
            }
        }));
        self.journal.complete_turn(TurnCompletion {
            turn_id: pending.turn_id,
            expected_revision: pending.turn_revision,
            now_ms,
            outcome: TurnOutcome::Aborted,
            settlements: &settlements,
            cursor: None,
            usage: None,
        })?;
        Ok(())
    }
}

impl Drop for JcodeSessionHost {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

struct StartupHost {
    process: SandboxedSession,
    reader: BufReader<std::os::unix::net::UnixStream>,
    decoder: JcodeFrameDecoder,
    incomplete_frame: bool,
    next_request_id: u64,
}

impl StartupHost {
    fn send(&mut self, request: &JcodeRequest) -> Result<u64, JcodeHostError> {
        let id = self.next_request_id;
        let encoded = encode_jcode_request(id, request)?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(JcodeHostError::InvalidField("request_id"))?;
        self.process.write_all(&encoded)?;
        Ok(id)
    }

    fn next_event(&mut self) -> Result<JcodeEvent, JcodeHostError> {
        let mut line = Vec::new();
        let read = self.reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Err(JcodeHostError::ProviderEof {
                incomplete_frame: self.incomplete_frame,
            });
        }
        if !line.ends_with(b"\n") {
            self.incomplete_frame = true;
        }
        let events = self.decoder.push(&line)?;
        if events.len() != 1 {
            return Err(JcodeHostError::Protocol(JcodeProtocolError::InvalidFrame));
        }
        events
            .into_iter()
            .next()
            .ok_or(JcodeHostError::Protocol(JcodeProtocolError::InvalidFrame))
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_key(value: &str, field: &'static str) -> Result<(), JcodeHostError> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(|character| character.is_control())
    {
        Err(JcodeHostError::InvalidField(field))
    } else {
        Ok(())
    }
}
