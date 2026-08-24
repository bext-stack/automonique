// SPDX-License-Identifier: Elastic-2.0

//! Versioned JCode harness-API framing and bounded event normalization.
//!
//! JCode is the provider execution engine; Automonique remains the authority
//! for containment, session ownership, approvals, cancellation, and durable
//! run state. This module is the pure protocol seam between them. It builds
//! typed protocol-v1 requests and decodes the additive NDJSON event contract;
//! it starts no process and grants no capability.

use std::collections::BTreeSet;
use std::fmt;

use crate::types::{RunCoordinates, validate_coordinate};
use automonique_connector_substrate::json::strict_json;
use serde::Serialize;
use serde_json::{Map, Value};

pub const JCODE_API_VERSION: u32 = 1;
pub const JCODE_API_SCHEMA_ID: &str = "jcode.harness-api/v1";
pub const JCODE_API_STDIO_ARGUMENTS: [&str; 4] =
    ["--quiet", "--no-update", "--no-selfdev", "api-stdio"];
pub const MAX_JCODE_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_JCODE_STREAM_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_JCODE_EVENTS: usize = 16_384;
pub const MAX_JCODE_TEXT_BYTES: usize = 256 * 1024;
const MAX_JCODE_FIELD_BYTES: usize = 512;

/// Capabilities required before Automonique will entrust a managed turn to the
/// engine. Additive capabilities may be present and are ignored.
pub const REQUIRED_JCODE_CAPABILITIES: [&str; 10] = [
    "sessions",
    "streaming",
    "cancellation",
    "soft_interrupt",
    "stdin_requests",
    "history",
    "model_catalog",
    "reasoning_effort",
    "usage",
    "runtime_info",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    AllowAlways,
    Deny,
}

/// The curated requests an Automonique execution host may send.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "req", rename_all = "snake_case")]
pub enum JcodeRequest {
    Hello {
        min_version: u32,
        max_version: u32,
        client: String,
    },
    CreateSession {
        #[serde(skip_serializing_if = "Option::is_none")]
        working_dir: Option<String>,
    },
    AttachSession {
        session_id: String,
    },
    SendMessage {
        session_id: String,
        content: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        images: Vec<(String, String)>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        no_reply: bool,
    },
    Cancel {
        session_id: String,
    },
    SoftInterrupt {
        session_id: String,
        content: String,
        urgent: bool,
    },
    PermissionResponse {
        session_id: String,
        request_id: String,
        decision: PermissionDecision,
    },
    StdinResponse {
        session_id: String,
        request_id: String,
        input: String,
    },
    GetHistory {
        session_id: String,
    },
    ListModels {
        session_id: String,
    },
    GetRuntimeInfo {
        session_id: String,
    },
    Ping,
}

#[derive(Serialize)]
struct ClientFrame<'a> {
    v: u32,
    id: u64,
    #[serde(flatten)]
    request: &'a JcodeRequest,
}

/// Encode one request as exactly one NDJSON frame.
pub fn encode_jcode_request(
    id: u64,
    request: &JcodeRequest,
) -> Result<Vec<u8>, JcodeProtocolError> {
    if id == 0 {
        return Err(JcodeProtocolError::InvalidField("request_id"));
    }
    validate_request(request)?;
    let mut encoded = serde_json::to_vec(&ClientFrame {
        v: JCODE_API_VERSION,
        id,
        request,
    })
    .map_err(|_| JcodeProtocolError::InvalidFrame)?;
    if encoded.len() >= MAX_JCODE_FRAME_BYTES {
        return Err(JcodeProtocolError::FrameTooLarge);
    }
    encoded.push(b'\n');
    Ok(encoded)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JcodeEvent {
    HelloOk {
        reply_to: u64,
        server: String,
        capabilities: Vec<String>,
    },
    Ok {
        reply_to: u64,
    },
    Error {
        reply_to: Option<u64>,
        code: String,
    },
    Attached {
        reply_to: u64,
        session_id: String,
        status: String,
    },
    MessageAccepted {
        session_id: String,
    },
    TextDelta {
        session_id: String,
        text: String,
    },
    ReasoningDelta {
        session_id: String,
        text: String,
    },
    ReasoningDone {
        session_id: String,
    },
    ToolStart {
        session_id: String,
        call_id: String,
        name: String,
    },
    ToolInputDelta {
        session_id: String,
        call_id: String,
    },
    ToolExec {
        session_id: String,
        call_id: String,
        name: String,
    },
    ToolDone {
        session_id: String,
        call_id: String,
        name: String,
        failed: bool,
    },
    TokenUsage {
        session_id: String,
        input: u64,
        output: u64,
        cache_read_input: Option<u64>,
    },
    PermissionRequest {
        session_id: String,
        request_id: String,
        tool_name: String,
        description: String,
    },
    StdinRequest {
        session_id: String,
        request_id: String,
        prompt: String,
        is_password: bool,
        tool_call_id: String,
    },
    SessionStatus {
        session_id: String,
        status: String,
    },
    ConnectionPhase {
        session_id: String,
        phase: String,
    },
    ModelInfo {
        session_id: String,
        provider: Option<String>,
        model: Option<String>,
        reasoning_effort: Option<String>,
    },
    TurnDone {
        session_id: String,
    },
    Pong {
        reply_to: u64,
    },
    /// Additive events are retained by safe kind only and otherwise skipped.
    Unknown {
        kind: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JcodeProtocolError {
    InvalidFrame,
    InvalidField(&'static str),
    FrameTooLarge,
    StreamTooLarge,
    TooManyEvents,
    UnsupportedVersion,
    MissingCapability,
    HandshakeRequired,
    IdentityMismatch,
    ReplyMismatch,
    SessionMismatch,
    EventOrder,
}

impl JcodeProtocolError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidFrame => "invalid_frame",
            Self::InvalidField(_) => "invalid_field",
            Self::FrameTooLarge => "frame_too_large",
            Self::StreamTooLarge => "stream_too_large",
            Self::TooManyEvents => "too_many_events",
            Self::UnsupportedVersion => "unsupported_version",
            Self::MissingCapability => "missing_capability",
            Self::HandshakeRequired => "handshake_required",
            Self::IdentityMismatch => "identity_mismatch",
            Self::ReplyMismatch => "reply_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::EventOrder => "event_order",
        }
    }
}

impl fmt::Display for JcodeProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for JcodeProtocolError {}

/// Immutable executable, configuration, schema, and reported-build identity
/// required for one contained JCode process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeExecutionIdentity {
    executable_sha256: String,
    configuration_sha256: String,
    expected_server: String,
}

impl JcodeExecutionIdentity {
    /// Bind a process to reviewed executable/configuration digests and the
    /// exact `hello_ok.server` identity expected from those bytes.
    pub fn pinned(
        executable_sha256: impl Into<String>,
        configuration_sha256: impl Into<String>,
        expected_server: impl Into<String>,
    ) -> Result<Self, JcodeProtocolError> {
        let executable_sha256 = executable_sha256.into();
        let configuration_sha256 = configuration_sha256.into();
        let expected_server = expected_server.into();
        validate_sha256(&executable_sha256, "executable_sha256")?;
        validate_sha256(&configuration_sha256, "configuration_sha256")?;
        validate_field(&expected_server, "expected_server")?;
        Ok(Self {
            executable_sha256,
            configuration_sha256,
            expected_server,
        })
    }

    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    #[must_use]
    pub fn configuration_sha256(&self) -> &str {
        &self.configuration_sha256
    }

    #[must_use]
    pub const fn schema_id(&self) -> &'static str {
        JCODE_API_SCHEMA_ID
    }

    #[must_use]
    pub fn expected_server(&self) -> &str {
        &self.expected_server
    }

    /// Exact argument vector used after the pinned executable path.
    #[must_use]
    pub const fn arguments(&self) -> [&'static str; 4] {
        JCODE_API_STDIO_ARGUMENTS
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JcodeInterruptedReason {
    ProviderEof,
    IncompleteFrame,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JcodeTerminalOutcome {
    Completed,
    Cancelled,
    ProviderFailed,
    InterruptedUnknown(JcodeInterruptedReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JcodeNativeEvent {
    Provider(JcodeEvent),
    Terminal {
        outcome: JcodeTerminalOutcome,
        provider_code: Option<String>,
    },
}

/// A successfully correlated protocol-v1 hello bound to one pinned process
/// identity. Only this type can start an adapter after process-level
/// negotiation has already completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeNegotiation {
    identity: JcodeExecutionIdentity,
}

impl JcodeNegotiation {
    pub fn accept(
        identity: JcodeExecutionIdentity,
        hello_request_id: u64,
        event: &JcodeEvent,
    ) -> Result<Self, JcodeProtocolError> {
        if hello_request_id == 0 {
            return Err(JcodeProtocolError::InvalidField("request_id"));
        }
        let JcodeEvent::HelloOk {
            reply_to,
            server,
            capabilities,
        } = event
        else {
            return Err(JcodeProtocolError::HandshakeRequired);
        };
        if *reply_to != hello_request_id {
            return Err(JcodeProtocolError::ReplyMismatch);
        }
        if server != identity.expected_server() {
            return Err(JcodeProtocolError::IdentityMismatch);
        }
        if REQUIRED_JCODE_CAPABILITIES
            .iter()
            .any(|required| !capabilities.iter().any(|actual| actual == required))
        {
            return Err(JcodeProtocolError::MissingCapability);
        }
        Ok(Self { identity })
    }

    #[must_use]
    pub const fn identity(&self) -> &JcodeExecutionIdentity {
        &self.identity
    }
}

/// One Automonique-owned envelope in exact provider read order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeNativeEnvelope {
    sequence: u64,
    run_id: String,
    turn_id: String,
    provider_session_id: Option<String>,
    identity: JcodeExecutionIdentity,
    event: JcodeNativeEvent,
}

impl JcodeNativeEnvelope {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    #[must_use]
    pub fn provider_session_id(&self) -> Option<&str> {
        self.provider_session_id.as_deref()
    }

    #[must_use]
    pub const fn identity(&self) -> &JcodeExecutionIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn event(&self) -> &JcodeNativeEvent {
        &self.event
    }
}

/// Per-turn fail-closed protocol state. It performs no process I/O: the runner
/// owns the child and feeds stdout bytes here in the order read.
pub struct JcodeNativeAdapter {
    decoder: JcodeFrameDecoder,
    identity: JcodeExecutionIdentity,
    run_id: String,
    turn_id: String,
    hello_request_id: Option<u64>,
    turn_request_id: u64,
    provider_session_id: Option<String>,
    negotiated: bool,
    accepted: bool,
    cancellation_requested: bool,
    terminal: Option<JcodeTerminalOutcome>,
    next_sequence: u64,
}

impl JcodeNativeAdapter {
    pub fn new(
        identity: JcodeExecutionIdentity,
        coordinates: &RunCoordinates,
        hello_request_id: u64,
        turn_request_id: u64,
    ) -> Result<Self, JcodeProtocolError> {
        if hello_request_id == 0 || turn_request_id == 0 || hello_request_id == turn_request_id {
            return Err(JcodeProtocolError::InvalidField("request_id"));
        }
        validate_coordinate(coordinates.run_id(), "run_id")
            .map_err(|_| JcodeProtocolError::InvalidField("run_id"))?;
        validate_coordinate(coordinates.turn_id(), "turn_id")
            .map_err(|_| JcodeProtocolError::InvalidField("turn_id"))?;
        Ok(Self {
            decoder: JcodeFrameDecoder::new(),
            identity,
            run_id: coordinates.run_id().to_owned(),
            turn_id: coordinates.turn_id().to_owned(),
            hello_request_id: Some(hello_request_id),
            turn_request_id,
            provider_session_id: None,
            negotiated: false,
            accepted: false,
            cancellation_requested: false,
            terminal: None,
            next_sequence: 1,
        })
    }

    /// Start a turn after the process owner has already completed and retained
    /// an exact [`JcodeNegotiation`].
    pub fn after_negotiation(
        negotiation: JcodeNegotiation,
        coordinates: &RunCoordinates,
        turn_request_id: u64,
        provider_session_id: &str,
    ) -> Result<Self, JcodeProtocolError> {
        if turn_request_id == 0 {
            return Err(JcodeProtocolError::InvalidField("request_id"));
        }
        validate_coordinate(coordinates.run_id(), "run_id")
            .map_err(|_| JcodeProtocolError::InvalidField("run_id"))?;
        validate_coordinate(coordinates.turn_id(), "turn_id")
            .map_err(|_| JcodeProtocolError::InvalidField("turn_id"))?;
        validate_field(provider_session_id, "session_id")?;
        Ok(Self {
            decoder: JcodeFrameDecoder::new(),
            identity: negotiation.identity,
            run_id: coordinates.run_id().to_owned(),
            turn_id: coordinates.turn_id().to_owned(),
            hello_request_id: None,
            turn_request_id,
            provider_session_id: Some(provider_session_id.to_owned()),
            negotiated: true,
            accepted: false,
            cancellation_requested: false,
            terminal: None,
            next_sequence: 1,
        })
    }

    /// Decode provider stdout and assign Automonique sequences in read order.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<JcodeNativeEnvelope>, JcodeProtocolError> {
        let events = self.decoder.push(bytes)?;
        let mut envelopes = Vec::with_capacity(events.len());
        for event in events {
            envelopes.push(self.observe(event)?);
        }
        Ok(envelopes)
    }

    /// Accept one event already produced by an upstream bounded
    /// [`JcodeFrameDecoder`]. Process owners use this when one decoder is
    /// shared across process-level negotiation and serialized turns.
    pub fn observe_decoded(
        &mut self,
        event: JcodeEvent,
    ) -> Result<JcodeNativeEnvelope, JcodeProtocolError> {
        self.observe(event)
    }

    /// Settle provider EOF once. EOF is never success: absent a prior terminal
    /// frame it becomes one explicit interrupted/unknown terminal envelope.
    pub fn finish_eof(&mut self) -> Result<Option<JcodeNativeEnvelope>, JcodeProtocolError> {
        self.finish_eof_with_pending_frame(false)
    }

    /// Settle EOF when a process owner performed bounded framing upstream and
    /// knows it retained an incomplete final frame.
    pub fn finish_eof_with_pending_frame(
        &mut self,
        upstream_pending: bool,
    ) -> Result<Option<JcodeNativeEnvelope>, JcodeProtocolError> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        let reason = if upstream_pending || self.decoder.has_pending() {
            JcodeInterruptedReason::IncompleteFrame
        } else {
            JcodeInterruptedReason::ProviderEof
        };
        let outcome = JcodeTerminalOutcome::InterruptedUnknown(reason);
        self.terminal = Some(outcome);
        Ok(Some(self.envelope(JcodeNativeEvent::Terminal {
            outcome,
            provider_code: None,
        })?))
    }

    /// Bind a supervisor-issued cancellation to the next provider terminal.
    pub fn mark_cancellation_requested(&mut self) -> Result<(), JcodeProtocolError> {
        if self.terminal.is_some() || self.cancellation_requested {
            return Err(JcodeProtocolError::EventOrder);
        }
        self.cancellation_requested = true;
        Ok(())
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<JcodeTerminalOutcome> {
        self.terminal
    }

    fn observe(&mut self, event: JcodeEvent) -> Result<JcodeNativeEnvelope, JcodeProtocolError> {
        if self.terminal.is_some() {
            return Err(JcodeProtocolError::EventOrder);
        }
        if !self.negotiated {
            let JcodeEvent::HelloOk {
                reply_to, server, ..
            } = &event
            else {
                return Err(JcodeProtocolError::HandshakeRequired);
            };
            if Some(*reply_to) != self.hello_request_id {
                return Err(JcodeProtocolError::ReplyMismatch);
            }
            if server != self.identity.expected_server() {
                return Err(JcodeProtocolError::IdentityMismatch);
            }
            self.negotiated = true;
            self.hello_request_id = None;
            return self.envelope(JcodeNativeEvent::Provider(event));
        }
        if matches!(event, JcodeEvent::HelloOk { .. }) {
            return Err(JcodeProtocolError::EventOrder);
        }

        if let Some(session_id) = event_session(&event) {
            match self.provider_session_id.as_deref() {
                Some(bound) if bound != session_id => {
                    return Err(JcodeProtocolError::SessionMismatch);
                }
                None => self.provider_session_id = Some(session_id.to_owned()),
                _ => {}
            }
        }

        let native = match &event {
            JcodeEvent::MessageAccepted { .. } => {
                if self.accepted {
                    return Err(JcodeProtocolError::EventOrder);
                }
                self.accepted = true;
                JcodeNativeEvent::Provider(event)
            }
            JcodeEvent::TurnDone { .. } => {
                if !self.accepted {
                    return Err(JcodeProtocolError::EventOrder);
                }
                let outcome = if self.cancellation_requested {
                    JcodeTerminalOutcome::Cancelled
                } else {
                    JcodeTerminalOutcome::Completed
                };
                self.terminal = Some(outcome);
                JcodeNativeEvent::Terminal {
                    outcome,
                    provider_code: None,
                }
            }
            JcodeEvent::Error {
                reply_to: Some(reply_to),
                code,
            } if *reply_to == self.turn_request_id => {
                self.terminal = Some(JcodeTerminalOutcome::ProviderFailed);
                JcodeNativeEvent::Terminal {
                    outcome: JcodeTerminalOutcome::ProviderFailed,
                    provider_code: Some(code.clone()),
                }
            }
            _ => JcodeNativeEvent::Provider(event),
        };
        self.envelope(native)
    }

    fn envelope(
        &mut self,
        event: JcodeNativeEvent,
    ) -> Result<JcodeNativeEnvelope, JcodeProtocolError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JcodeProtocolError::TooManyEvents)?;
        Ok(JcodeNativeEnvelope {
            sequence,
            run_id: self.run_id.clone(),
            turn_id: self.turn_id.clone(),
            provider_session_id: self.provider_session_id.clone(),
            identity: self.identity.clone(),
            event,
        })
    }
}

/// Incremental NDJSON decoder. Unknown additive event kinds are surfaced only
/// by their bounded schema token, matching JCode's forward-compatibility rule.
pub struct JcodeFrameDecoder {
    pending: Vec<u8>,
    total_bytes: usize,
    events: usize,
}

impl Default for JcodeFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl JcodeFrameDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
            total_bytes: 0,
            events: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<JcodeEvent>, JcodeProtocolError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or(JcodeProtocolError::StreamTooLarge)?;
        if self.total_bytes > MAX_JCODE_STREAM_BYTES {
            return Err(JcodeProtocolError::StreamTooLarge);
        }
        self.pending.extend_from_slice(bytes);
        if self.pending.len() > MAX_JCODE_FRAME_BYTES && !self.pending.contains(&b'\n') {
            return Err(JcodeProtocolError::FrameTooLarge);
        }
        let mut decoded = Vec::new();
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=newline).collect();
            if line.len() > MAX_JCODE_FRAME_BYTES {
                return Err(JcodeProtocolError::FrameTooLarge);
            }
            self.events = self
                .events
                .checked_add(1)
                .ok_or(JcodeProtocolError::TooManyEvents)?;
            if self.events > MAX_JCODE_EVENTS {
                return Err(JcodeProtocolError::TooManyEvents);
            }
            decoded.push(decode_server_frame(&line[..line.len() - 1])?);
        }
        Ok(decoded)
    }

    pub fn finish(self) -> Result<(), JcodeProtocolError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(JcodeProtocolError::InvalidFrame)
        }
    }

    const fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// One serialized turn's authority-sensitive state.
pub struct JcodeTurnCollector {
    session_id: String,
    accepted: bool,
    done: bool,
    text: String,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
    active_tools: BTreeSet<String>,
    pending_permissions: BTreeSet<String>,
    pending_inputs: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JcodeTurnResult {
    session_id: String,
    text: String,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
}

impl JcodeTurnResult {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    #[must_use]
    pub const fn input_tokens(&self) -> u64 {
        self.input_tokens
    }
    #[must_use]
    pub const fn output_tokens(&self) -> u64 {
        self.output_tokens
    }
    #[must_use]
    pub const fn cache_read_input_tokens(&self) -> u64 {
        self.cache_read_input_tokens
    }
}

impl JcodeTurnCollector {
    pub fn new(session_id: &str) -> Result<Self, JcodeProtocolError> {
        validate_field(session_id, "session_id")?;
        Ok(Self {
            session_id: session_id.to_owned(),
            accepted: false,
            done: false,
            text: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_input_tokens: 0,
            active_tools: BTreeSet::new(),
            pending_permissions: BTreeSet::new(),
            pending_inputs: BTreeSet::new(),
        })
    }

    pub fn observe(&mut self, event: &JcodeEvent) -> Result<(), JcodeProtocolError> {
        let Some(session_id) = event_session(event) else {
            return Ok(());
        };
        if session_id != self.session_id {
            return Err(JcodeProtocolError::SessionMismatch);
        }
        if self.done {
            return Err(JcodeProtocolError::EventOrder);
        }
        match event {
            JcodeEvent::MessageAccepted { .. } => self.accepted = true,
            JcodeEvent::TextDelta { text, .. } => {
                if !self.accepted {
                    return Err(JcodeProtocolError::EventOrder);
                }
                if self.text.len().saturating_add(text.len()) > MAX_JCODE_TEXT_BYTES {
                    return Err(JcodeProtocolError::StreamTooLarge);
                }
                self.text.push_str(text);
            }
            JcodeEvent::ToolStart { call_id, .. } => {
                if !self.accepted || !self.active_tools.insert(call_id.clone()) {
                    return Err(JcodeProtocolError::EventOrder);
                }
            }
            JcodeEvent::ToolInputDelta { call_id, .. } | JcodeEvent::ToolExec { call_id, .. } => {
                if !self.active_tools.contains(call_id) {
                    return Err(JcodeProtocolError::EventOrder);
                }
            }
            JcodeEvent::ToolDone { call_id, .. } => {
                if !self.active_tools.remove(call_id) {
                    return Err(JcodeProtocolError::EventOrder);
                }
            }
            JcodeEvent::TokenUsage {
                input,
                output,
                cache_read_input,
                ..
            } => {
                self.input_tokens = *input;
                self.output_tokens = *output;
                self.cache_read_input_tokens = cache_read_input.unwrap_or(0);
            }
            JcodeEvent::PermissionRequest { request_id, .. } => {
                if !self.pending_permissions.insert(request_id.clone()) {
                    return Err(JcodeProtocolError::EventOrder);
                }
            }
            JcodeEvent::StdinRequest { request_id, .. } => {
                if !self.pending_inputs.insert(request_id.clone()) {
                    return Err(JcodeProtocolError::EventOrder);
                }
            }
            JcodeEvent::TurnDone { .. } => {
                if !self.accepted
                    || !self.active_tools.is_empty()
                    || !self.pending_permissions.is_empty()
                    || !self.pending_inputs.is_empty()
                {
                    return Err(JcodeProtocolError::EventOrder);
                }
                self.done = true;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn resolve_permission(&mut self, request_id: &str) -> Result<(), JcodeProtocolError> {
        if self.pending_permissions.remove(request_id) {
            Ok(())
        } else {
            Err(JcodeProtocolError::EventOrder)
        }
    }

    pub fn resolve_input(&mut self, request_id: &str) -> Result<(), JcodeProtocolError> {
        if self.pending_inputs.remove(request_id) {
            Ok(())
        } else {
            Err(JcodeProtocolError::EventOrder)
        }
    }

    pub fn finish(self) -> Result<JcodeTurnResult, JcodeProtocolError> {
        if !self.done {
            return Err(JcodeProtocolError::EventOrder);
        }
        Ok(JcodeTurnResult {
            session_id: self.session_id,
            text: self.text,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_read_input_tokens: self.cache_read_input_tokens,
        })
    }
}

fn validate_request(request: &JcodeRequest) -> Result<(), JcodeProtocolError> {
    match request {
        JcodeRequest::Hello {
            min_version,
            max_version,
            client,
        } => {
            if *min_version != JCODE_API_VERSION || *max_version != JCODE_API_VERSION {
                return Err(JcodeProtocolError::UnsupportedVersion);
            }
            validate_field(client, "client")
        }
        JcodeRequest::CreateSession { working_dir } => {
            if working_dir.as_ref().is_some_and(|path| path.is_empty()) {
                return Err(JcodeProtocolError::InvalidField("working_dir"));
            }
            Ok(())
        }
        JcodeRequest::AttachSession { session_id }
        | JcodeRequest::Cancel { session_id }
        | JcodeRequest::GetHistory { session_id }
        | JcodeRequest::ListModels { session_id }
        | JcodeRequest::GetRuntimeInfo { session_id } => validate_field(session_id, "session_id"),
        JcodeRequest::SendMessage {
            session_id,
            content,
            images,
            ..
        } => {
            validate_field(session_id, "session_id")?;
            if content.is_empty() || content.len() > MAX_JCODE_TEXT_BYTES || !images.is_empty() {
                return Err(JcodeProtocolError::InvalidField("content"));
            }
            Ok(())
        }
        JcodeRequest::SoftInterrupt {
            session_id,
            content,
            ..
        } => {
            validate_field(session_id, "session_id")?;
            if content.is_empty() || content.len() > MAX_JCODE_TEXT_BYTES {
                return Err(JcodeProtocolError::InvalidField("content"));
            }
            Ok(())
        }
        JcodeRequest::PermissionResponse {
            session_id,
            request_id,
            ..
        } => {
            validate_field(session_id, "session_id")?;
            validate_field(request_id, "request_id")
        }
        JcodeRequest::StdinResponse {
            session_id,
            request_id,
            input,
        } => {
            validate_field(session_id, "session_id")?;
            validate_field(request_id, "request_id")?;
            if input.len() > MAX_JCODE_TEXT_BYTES {
                return Err(JcodeProtocolError::InvalidField("input"));
            }
            Ok(())
        }
        JcodeRequest::Ping => Ok(()),
    }
}

fn decode_server_frame(bytes: &[u8]) -> Result<JcodeEvent, JcodeProtocolError> {
    let value = strict_json(bytes).map_err(|_| JcodeProtocolError::InvalidFrame)?;
    let object = value.as_object().ok_or(JcodeProtocolError::InvalidFrame)?;
    let version = object.get("v").and_then(Value::as_u64);
    if version != Some(u64::from(JCODE_API_VERSION)) {
        return Err(JcodeProtocolError::UnsupportedVersion);
    }
    let reply_to = object.get("reply_to").and_then(Value::as_u64);
    let kind = string(object, "ev")?;
    match kind {
        "hello_ok" => {
            let reply_to = reply_to.ok_or(JcodeProtocolError::InvalidField("reply_to"))?;
            let negotiated = object.get("version").and_then(Value::as_u64);
            if negotiated != Some(u64::from(JCODE_API_VERSION)) {
                return Err(JcodeProtocolError::UnsupportedVersion);
            }
            let server = bounded_string(object, "server")?.to_owned();
            let capabilities = strings(object, "capabilities")?;
            if REQUIRED_JCODE_CAPABILITIES
                .iter()
                .any(|required| !capabilities.iter().any(|found| found == required))
            {
                return Err(JcodeProtocolError::MissingCapability);
            }
            Ok(JcodeEvent::HelloOk {
                reply_to,
                server,
                capabilities,
            })
        }
        "ok" => Ok(JcodeEvent::Ok {
            reply_to: reply_to.ok_or(JcodeProtocolError::InvalidField("reply_to"))?,
        }),
        "error" => Ok(JcodeEvent::Error {
            reply_to,
            code: bounded_string(object, "code")?.to_owned(),
        }),
        "attached" => {
            let session = object
                .get("session")
                .and_then(Value::as_object)
                .ok_or(JcodeProtocolError::InvalidField("session"))?;
            Ok(JcodeEvent::Attached {
                reply_to: reply_to.ok_or(JcodeProtocolError::InvalidField("reply_to"))?,
                session_id: bounded_string(session, "session_id")?.to_owned(),
                status: bounded_string(session, "status")?.to_owned(),
            })
        }
        "message_accepted" => Ok(JcodeEvent::MessageAccepted {
            session_id: session(object)?,
        }),
        "text_delta" => Ok(JcodeEvent::TextDelta {
            session_id: session(object)?,
            text: text(object, "text")?.to_owned(),
        }),
        "reasoning_delta" => Ok(JcodeEvent::ReasoningDelta {
            session_id: session(object)?,
            text: text(object, "text")?.to_owned(),
        }),
        "reasoning_done" => Ok(JcodeEvent::ReasoningDone {
            session_id: session(object)?,
        }),
        "tool_start" => Ok(JcodeEvent::ToolStart {
            session_id: session(object)?,
            call_id: bounded_string(object, "call_id")?.to_owned(),
            name: bounded_string(object, "name")?.to_owned(),
        }),
        "tool_input_delta" => Ok(JcodeEvent::ToolInputDelta {
            session_id: session(object)?,
            call_id: bounded_string(object, "call_id")?.to_owned(),
        }),
        "tool_exec" => Ok(JcodeEvent::ToolExec {
            session_id: session(object)?,
            call_id: bounded_string(object, "call_id")?.to_owned(),
            name: bounded_string(object, "name")?.to_owned(),
        }),
        "tool_done" => Ok(JcodeEvent::ToolDone {
            session_id: session(object)?,
            call_id: bounded_string(object, "call_id")?.to_owned(),
            name: bounded_string(object, "name")?.to_owned(),
            failed: object.get("error").is_some_and(|value| !value.is_null()),
        }),
        "token_usage" => Ok(JcodeEvent::TokenUsage {
            session_id: session(object)?,
            input: unsigned(object, "input")?,
            output: unsigned(object, "output")?,
            cache_read_input: optional_unsigned(object, "cache_read_input")?,
        }),
        "permission_request" => Ok(JcodeEvent::PermissionRequest {
            session_id: session(object)?,
            request_id: bounded_string(object, "request_id")?.to_owned(),
            tool_name: bounded_string(object, "tool_name")?.to_owned(),
            description: text(object, "description")?.to_owned(),
        }),
        "stdin_request" => Ok(JcodeEvent::StdinRequest {
            session_id: session(object)?,
            request_id: bounded_string(object, "request_id")?.to_owned(),
            prompt: text(object, "prompt")?.to_owned(),
            is_password: match object.get("is_password") {
                None => false,
                Some(Value::Bool(value)) => *value,
                Some(_) => return Err(JcodeProtocolError::InvalidField("is_password")),
            },
            tool_call_id: bounded_string(object, "tool_call_id")?.to_owned(),
        }),
        "session_status" => Ok(JcodeEvent::SessionStatus {
            session_id: session(object)?,
            status: bounded_string(object, "status")?.to_owned(),
        }),
        "connection_phase" => Ok(JcodeEvent::ConnectionPhase {
            session_id: session(object)?,
            phase: bounded_string(object, "phase")?.to_owned(),
        }),
        "model_info" => Ok(JcodeEvent::ModelInfo {
            session_id: session(object)?,
            provider: optional_string(object, "provider")?,
            model: optional_string(object, "model")?,
            reasoning_effort: optional_string(object, "reasoning_effort")?,
        }),
        "turn_done" => Ok(JcodeEvent::TurnDone {
            session_id: session(object)?,
        }),
        "pong" => Ok(JcodeEvent::Pong {
            reply_to: reply_to.ok_or(JcodeProtocolError::InvalidField("reply_to"))?,
        }),
        other => {
            validate_field(other, "event_kind")?;
            Ok(JcodeEvent::Unknown {
                kind: other.to_owned(),
            })
        }
    }
}

fn event_session(event: &JcodeEvent) -> Option<&str> {
    match event {
        JcodeEvent::MessageAccepted { session_id }
        | JcodeEvent::TextDelta { session_id, .. }
        | JcodeEvent::ReasoningDelta { session_id, .. }
        | JcodeEvent::ReasoningDone { session_id }
        | JcodeEvent::ToolStart { session_id, .. }
        | JcodeEvent::ToolInputDelta { session_id, .. }
        | JcodeEvent::ToolExec { session_id, .. }
        | JcodeEvent::ToolDone { session_id, .. }
        | JcodeEvent::TokenUsage { session_id, .. }
        | JcodeEvent::PermissionRequest { session_id, .. }
        | JcodeEvent::StdinRequest { session_id, .. }
        | JcodeEvent::SessionStatus { session_id, .. }
        | JcodeEvent::ConnectionPhase { session_id, .. }
        | JcodeEvent::ModelInfo { session_id, .. }
        | JcodeEvent::TurnDone { session_id } => Some(session_id),
        _ => None,
    }
}

fn validate_field(value: &str, field: &'static str) -> Result<(), JcodeProtocolError> {
    if value.is_empty()
        || value.len() > MAX_JCODE_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        Err(JcodeProtocolError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), JcodeProtocolError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(JcodeProtocolError::InvalidField(field))
    }
}

fn string<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, JcodeProtocolError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(JcodeProtocolError::InvalidField(key))
}

fn bounded_string<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, JcodeProtocolError> {
    let value = string(object, key)?;
    validate_field(value, key)?;
    Ok(value)
}

fn text<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, JcodeProtocolError> {
    let value = string(object, key)?;
    if value.len() > MAX_JCODE_TEXT_BYTES {
        Err(JcodeProtocolError::InvalidField(key))
    } else {
        Ok(value)
    }
}

fn optional_string(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, JcodeProtocolError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            validate_field(value, key)?;
            Ok(Some(value.clone()))
        }
        Some(_) => Err(JcodeProtocolError::InvalidField(key)),
    }
}

fn strings(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Vec<String>, JcodeProtocolError> {
    let values = object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(JcodeProtocolError::InvalidField(key))?;
    if values.len() > 128 {
        return Err(JcodeProtocolError::InvalidField(key));
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or(JcodeProtocolError::InvalidField(key))?;
            validate_field(value, key)?;
            Ok(value.to_owned())
        })
        .collect()
}

fn unsigned(object: &Map<String, Value>, key: &'static str) -> Result<u64, JcodeProtocolError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(JcodeProtocolError::InvalidField(key))
}

fn optional_unsigned(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<u64>, JcodeProtocolError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(JcodeProtocolError::InvalidField(key)),
    }
}

fn session(object: &Map<String, Value>) -> Result<String, JcodeProtocolError> {
    Ok(bounded_string(object, "session_id")?.to_owned())
}
