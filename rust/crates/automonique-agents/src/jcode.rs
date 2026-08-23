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

use automonique_connector_substrate::json::strict_json;
use serde::Serialize;
use serde_json::{Map, Value};

pub const JCODE_API_VERSION: u32 = 1;
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
    "permission_requests",
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

#[derive(Clone, Debug, PartialEq)]
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
            JcodeEvent::TurnDone { .. } => {
                if !self.accepted
                    || !self.active_tools.is_empty()
                    || !self.pending_permissions.is_empty()
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
