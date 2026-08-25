// SPDX-License-Identifier: Elastic-2.0

//! Canonical transport for [`crate::platform`].
//!
//! The same request and response frames travel over the private Unix socket,
//! HTTPS, and WebSocket gateways. Authentication is deliberately outside the
//! frame: Unix peers are authenticated by the socket and remote peers by their
//! gateway, while the bytes admitted here remain identical.

use core::fmt;
use std::error::Error;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId, SupportedProtocol,
    VersionRange,
};
use crate::platform::*;
use crate::primitives::{EpochMillis, Revision};
use crate::wire::{JsonValue, Message};

/// Maximum canonical frame for the bounded platform-v1 surface.
pub const MAX_PLATFORM_CANONICAL_BYTES: usize = 512 * 1024;
/// Maximum canonical request frame. Responses are wider because a bounded
/// snapshot can carry many records; no request carries record payloads.
pub const MAX_PLATFORM_REQUEST_CANONICAL_BYTES: usize = 128 * 1024;

/// Refusal while admitting or assembling a platform frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformApiError {
    Codec(CodecError),
    Platform(PlatformError),
    UnknownKind,
    InvalidBody,
    CounterOutOfRange { field: &'static str },
}

impl PlatformApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Platform(_) => "platform_value_invalid",
            Self::UnknownKind => "platform_unknown_kind",
            Self::InvalidBody => "platform_invalid_body",
            Self::CounterOutOfRange { .. } => "platform_counter_out_of_range",
        }
    }
}

impl fmt::Display for PlatformApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "platform codec refused message: {error}"),
            Self::Platform(error) => write!(formatter, "platform value was refused: {error:?}"),
            Self::UnknownKind => formatter.write_str("platform message kind is not defined"),
            Self::InvalidBody => formatter.write_str("platform message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "platform counter {field} is outside the wire range"
                )
            }
        }
    }
}

impl Error for PlatformApiError {}

impl From<CodecError> for PlatformApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<PlatformError> for PlatformApiError {
    fn from(value: PlatformError) -> Self {
        Self::Platform(value)
    }
}

fn supported_protocol() -> Result<SupportedProtocol, PlatformApiError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(PLATFORM_PROTOCOL)?,
        VersionRange::exact(MajorVersion::FIRST),
    ))
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, PlatformApiError> {
    Ok(Envelope::new(
        ProtocolName::new(PLATFORM_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn exact_fields(value: &JsonValue, fields: &[&str]) -> Result<(), PlatformApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(PlatformApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || entries
            .iter()
            .any(|(key, _)| !fields.iter().any(|field| key == field))
    {
        return Err(PlatformApiError::InvalidBody);
    }
    Ok(())
}

fn string<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, PlatformApiError> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or(PlatformApiError::InvalidBody)
}

fn array<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a [JsonValue], PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Array(items)) => Ok(items),
        _ => Err(PlatformApiError::InvalidBody),
    }
}

fn integer(value: u64, field: &'static str) -> Result<JsonValue, PlatformApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| PlatformApiError::CounterOutOfRange { field })
}

fn unsigned(value: &JsonValue, field: &'static str) -> Result<u64, PlatformApiError> {
    let number = value
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(PlatformApiError::InvalidBody)?;
    u64::try_from(number).map_err(|_| PlatformApiError::CounterOutOfRange { field })
}

fn history_limit(value: &JsonValue, field: &'static str) -> Result<u16, PlatformApiError> {
    let value = unsigned(value, field)?;
    let limit = u16::try_from(value).map_err(|_| PlatformApiError::CounterOutOfRange { field })?;
    if limit == 0 || usize::from(limit) > MAX_SESSION_HISTORY_EVENTS {
        return Err(PlatformError::HistoryLimitOutOfRange.into());
    }
    Ok(limit)
}

fn boolean(value: &JsonValue, field: &'static str) -> Result<bool, PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        _ => Err(PlatformApiError::InvalidBody),
    }
}

fn optional_revision(
    value: &JsonValue,
    field: &'static str,
) -> Result<Option<Revision>, PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Integer(number)) => {
            let number = u64::try_from(*number)
                .map_err(|_| PlatformApiError::CounterOutOfRange { field })?;
            Revision::new(number)
                .map(Some)
                .map_err(|_| PlatformApiError::InvalidBody)
        }
        _ => Err(PlatformApiError::InvalidBody),
    }
}

fn optional_text(
    value: &JsonValue,
    field: &'static str,
) -> Result<Option<PlatformText>, PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(text)) => PlatformText::new(text.clone())
            .map(Some)
            .map_err(|error| PlatformError::Field(error).into()),
        _ => Err(PlatformApiError::InvalidBody),
    }
}

fn optional_parameter(
    value: &JsonValue,
    field: &'static str,
) -> Result<Option<PlatformParameter>, PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(text)) => PlatformParameter::new(text.clone())
            .map(Some)
            .map_err(|error| PlatformError::Field(error).into()),
        _ => Err(PlatformApiError::InvalidBody),
    }
}

fn optional_json<T>(
    value: Option<&T>,
    encode: impl FnOnce(&T) -> Result<JsonValue, PlatformApiError>,
) -> Result<JsonValue, PlatformApiError> {
    value.map_or(Ok(JsonValue::Null), encode)
}

fn coordinate_json(value: &ResourceCoordinate) -> JsonValue {
    object(vec![
        (
            "authority",
            JsonValue::String(value.authority.as_str().to_owned()),
        ),
        ("id", JsonValue::String(value.id.as_str().to_owned())),
        ("kind", JsonValue::String(value.kind.as_str().to_owned())),
    ])
}

fn coordinate(value: &JsonValue) -> Result<ResourceCoordinate, PlatformApiError> {
    exact_fields(value, &["authority", "id", "kind"])?;
    Ok(ResourceCoordinate::new(
        ResourceAuthority::parse(string(value, "authority")?)?,
        ResourceKind::parse(string(value, "kind")?)?,
        ResourceId::new(string(value, "id")?.to_owned()).map_err(PlatformError::Field)?,
    ))
}

fn cursor_json(value: &PlatformCursor) -> Result<JsonValue, PlatformApiError> {
    Ok(object(vec![
        (
            "authority",
            JsonValue::String(value.authority.as_str().to_owned()),
        ),
        ("sequence", integer(value.sequence.get(), "sequence")?),
        ("topic", JsonValue::String(value.topic.as_str().to_owned())),
    ]))
}

fn cursor(value: &JsonValue) -> Result<PlatformCursor, PlatformApiError> {
    exact_fields(value, &["authority", "sequence", "topic"])?;
    Ok(PlatformCursor {
        authority: ResourceAuthority::parse(string(value, "authority")?)?,
        topic: CursorTopic::new(string(value, "topic")?.to_owned())
            .map_err(PlatformError::Field)?,
        sequence: Revision::new(unsigned(value, "sequence")?)
            .map_err(|_| PlatformApiError::InvalidBody)?,
    })
}

fn optional_cursor(
    value: &JsonValue,
    field: &'static str,
) -> Result<Option<PlatformCursor>, PlatformApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(value) => cursor(value).map(Some),
        None => Err(PlatformApiError::InvalidBody),
    }
}

fn freshness_json(value: Freshness) -> Result<JsonValue, PlatformApiError> {
    Ok(object(vec![
        (
            "observed_at",
            JsonValue::Integer(value.observed_at.as_millis()),
        ),
        ("revision", integer(value.revision.get(), "revision")?),
        ("state", JsonValue::String(value.state.as_str().to_owned())),
    ]))
}

fn freshness(value: &JsonValue) -> Result<Freshness, PlatformApiError> {
    exact_fields(value, &["observed_at", "revision", "state"])?;
    let observed_at = value
        .get("observed_at")
        .and_then(JsonValue::as_integer)
        .ok_or(PlatformApiError::InvalidBody)?;
    Ok(Freshness {
        state: FreshnessState::parse(string(value, "state")?)?,
        observed_at: EpochMillis::from_millis(observed_at),
        revision: Revision::new(unsigned(value, "revision")?)
            .map_err(|_| PlatformApiError::InvalidBody)?,
    })
}

fn record_json(value: &ResourceRecord) -> Result<JsonValue, PlatformApiError> {
    Ok(object(vec![
        ("freshness", freshness_json(value.freshness)?),
        ("resource", coordinate_json(&value.resource)),
        (
            "summary",
            JsonValue::String(value.summary.as_str().to_owned()),
        ),
    ]))
}

fn record(value: &JsonValue) -> Result<ResourceRecord, PlatformApiError> {
    exact_fields(value, &["freshness", "resource", "summary"])?;
    Ok(ResourceRecord {
        resource: coordinate(value.get("resource").ok_or(PlatformApiError::InvalidBody)?)?,
        freshness: freshness(
            value
                .get("freshness")
                .ok_or(PlatformApiError::InvalidBody)?,
        )?,
        summary: PlatformText::new(string(value, "summary")?.to_owned())
            .map_err(PlatformError::Field)?,
    })
}

fn receipt_json(value: &ActionReceipt) -> Result<JsonValue, PlatformApiError> {
    Ok(object(vec![
        (
            "action",
            JsonValue::String(value.action.as_str().to_owned()),
        ),
        (
            "explanation",
            optional_json(value.explanation.as_ref(), |text| {
                Ok(JsonValue::String(text.as_str().to_owned()))
            })?,
        ),
        ("id", JsonValue::String(value.id.as_str().to_owned())),
        (
            "outcome",
            JsonValue::String(value.outcome.as_str().to_owned()),
        ),
        (
            "recorded_at",
            JsonValue::Integer(value.recorded_at.as_millis()),
        ),
        ("revision", integer(value.revision.get(), "revision")?),
        ("target", coordinate_json(&value.target)),
    ]))
}

fn receipt(value: &JsonValue) -> Result<ActionReceipt, PlatformApiError> {
    exact_fields(
        value,
        &[
            "action",
            "explanation",
            "id",
            "outcome",
            "recorded_at",
            "revision",
            "target",
        ],
    )?;
    Ok(ActionReceipt {
        id: ReceiptId::new(string(value, "id")?.to_owned()).map_err(PlatformError::Field)?,
        action: PlatformAction::parse(string(value, "action")?)?,
        target: coordinate(value.get("target").ok_or(PlatformApiError::InvalidBody)?)?,
        outcome: ReceiptOutcome::parse(string(value, "outcome")?)?,
        revision: Revision::new(unsigned(value, "revision")?)
            .map_err(|_| PlatformApiError::InvalidBody)?,
        recorded_at: EpochMillis::from_millis(
            value
                .get("recorded_at")
                .and_then(JsonValue::as_integer)
                .ok_or(PlatformApiError::InvalidBody)?,
        ),
        explanation: optional_text(value, "explanation")?,
    })
}

fn history_text(value: &str) -> Result<SessionHistoryText, PlatformApiError> {
    SessionHistoryText::new(value.to_owned()).map_err(|error| PlatformError::Field(error).into())
}

fn history_event_arrays(
    events: &[SessionHistoryEvent],
) -> Result<
    (
        Vec<JsonValue>,
        Vec<JsonValue>,
        Vec<JsonValue>,
        Vec<JsonValue>,
    ),
    PlatformApiError,
> {
    let mut messages = Vec::new();
    let mut tools = Vec::new();
    let mut runs = Vec::new();
    let mut unknown = Vec::new();
    for event in events {
        match event {
            SessionHistoryEvent::Message {
                cursor,
                at,
                evidence,
                role,
                text,
                truncated,
            } => messages.push(object(vec![
                ("at", JsonValue::Integer(at.as_millis())),
                ("cursor", integer(*cursor, "cursor")?),
                ("evidence", JsonValue::String(evidence.as_str().to_owned())),
                ("role", JsonValue::String(role.as_str().to_owned())),
                ("text", JsonValue::String(text.as_str().to_owned())),
                ("truncated", JsonValue::Bool(*truncated)),
            ])),
            SessionHistoryEvent::ToolState {
                cursor,
                at,
                evidence,
                state,
                label,
                truncated,
            } => tools.push(object(vec![
                ("at", JsonValue::Integer(at.as_millis())),
                ("cursor", integer(*cursor, "cursor")?),
                ("evidence", JsonValue::String(evidence.as_str().to_owned())),
                (
                    "label",
                    label.as_ref().map_or(JsonValue::Null, |label| {
                        JsonValue::String(label.as_str().to_owned())
                    }),
                ),
                ("state", JsonValue::String(state.as_str().to_owned())),
                ("truncated", JsonValue::Bool(*truncated)),
            ])),
            SessionHistoryEvent::RunState { cursor, at, state } => runs.push(object(vec![
                ("at", JsonValue::Integer(at.as_millis())),
                ("cursor", integer(*cursor, "cursor")?),
                ("state", JsonValue::String(state.as_str().to_owned())),
            ])),
            SessionHistoryEvent::Unknown { cursor, at, source } => unknown.push(object(vec![
                ("at", JsonValue::Integer(at.as_millis())),
                ("cursor", integer(*cursor, "cursor")?),
                ("source", JsonValue::String(source.as_str().to_owned())),
            ])),
        }
    }
    Ok((messages, tools, runs, unknown))
}

fn decode_history_events(value: &JsonValue) -> Result<Vec<SessionHistoryEvent>, PlatformApiError> {
    let mut events = Vec::new();
    for item in array(value, "messages")? {
        exact_fields(
            item,
            &["at", "cursor", "evidence", "role", "text", "truncated"],
        )?;
        events.push(SessionHistoryEvent::Message {
            cursor: unsigned(item, "cursor")?,
            at: EpochMillis::from_millis(
                item.get("at")
                    .and_then(JsonValue::as_integer)
                    .ok_or(PlatformApiError::InvalidBody)?,
            ),
            evidence: SessionHistoryEvidence::parse(string(item, "evidence")?)?,
            role: SessionHistoryRole::parse(string(item, "role")?)?,
            text: history_text(string(item, "text")?)?,
            truncated: boolean(item, "truncated")?,
        });
    }
    for item in array(value, "tool_states")? {
        exact_fields(
            item,
            &["at", "cursor", "evidence", "label", "state", "truncated"],
        )?;
        let label = match item.get("label") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::String(label)) => Some(history_text(label)?),
            _ => return Err(PlatformApiError::InvalidBody),
        };
        events.push(SessionHistoryEvent::ToolState {
            cursor: unsigned(item, "cursor")?,
            at: EpochMillis::from_millis(
                item.get("at")
                    .and_then(JsonValue::as_integer)
                    .ok_or(PlatformApiError::InvalidBody)?,
            ),
            evidence: SessionHistoryEvidence::parse(string(item, "evidence")?)?,
            state: SessionHistoryToolState::parse(string(item, "state")?)?,
            label,
            truncated: boolean(item, "truncated")?,
        });
    }
    for item in array(value, "run_states")? {
        exact_fields(item, &["at", "cursor", "state"])?;
        events.push(SessionHistoryEvent::RunState {
            cursor: unsigned(item, "cursor")?,
            at: EpochMillis::from_millis(
                item.get("at")
                    .and_then(JsonValue::as_integer)
                    .ok_or(PlatformApiError::InvalidBody)?,
            ),
            state: SessionHistoryRunState::parse(string(item, "state")?)?,
        });
    }
    for item in array(value, "unknown_events")? {
        exact_fields(item, &["at", "cursor", "source"])?;
        events.push(SessionHistoryEvent::Unknown {
            cursor: unsigned(item, "cursor")?,
            at: EpochMillis::from_millis(
                item.get("at")
                    .and_then(JsonValue::as_integer)
                    .ok_or(PlatformApiError::InvalidBody)?,
            ),
            source: SessionHistoryUnknownSource::parse(string(item, "source")?)?,
        });
    }
    if events.len() > MAX_SESSION_HISTORY_EVENTS {
        return Err(PlatformError::TooManyEvents.into());
    }
    events.sort_by_key(SessionHistoryEvent::cursor);
    Ok(events)
}

fn request_kind(request: &PlatformRequest) -> &'static str {
    match request {
        PlatformRequest::Capabilities => "capabilities",
        PlatformRequest::Snapshot(_) => "snapshot",
        PlatformRequest::Subscribe(_) => "subscribe",
        PlatformRequest::Execute(_) => "execute",
        PlatformRequest::GetReceipt(_) => "get_receipt",
        PlatformRequest::ListSessions(_) => "list_sessions",
        PlatformRequest::Attach(_) => "attach",
        PlatformRequest::Detach(_) => "detach",
        PlatformRequest::ClaimControl(_) => "claim_control",
        PlatformRequest::ReleaseControl(_) => "release_control",
        PlatformRequest::SessionHistorySnapshot(_) => "session_history_snapshot",
        PlatformRequest::SessionHistoryPage(_) => "session_history_page",
    }
}

fn request_body(request: &PlatformRequest) -> Result<JsonValue, PlatformApiError> {
    match request {
        PlatformRequest::Capabilities => Ok(object(Vec::new())),
        PlatformRequest::Snapshot(request) => Ok(object(vec![(
            "resources",
            JsonValue::Array(request.resources.iter().map(coordinate_json).collect()),
        )])),
        PlatformRequest::Subscribe(request) => Ok(object(vec![(
            "cursor",
            optional_json(request.cursor.as_ref(), cursor_json)?,
        )])),
        PlatformRequest::Execute(request) => Ok(object(vec![
            (
                "action",
                JsonValue::String(request.action.as_str().to_owned()),
            ),
            (
                "client",
                request.client.as_ref().map_or(JsonValue::Null, |client| {
                    JsonValue::String(client.as_str().to_owned())
                }),
            ),
            (
                "expected_revision",
                request
                    .expected_revision
                    .map_or(Ok(JsonValue::Null), |revision| {
                        integer(revision.get(), "expected_revision")
                    })?,
            ),
            (
                "idempotency_key",
                JsonValue::String(request.idempotency_key.as_str().to_owned()),
            ),
            (
                "parameter",
                optional_json(request.parameter.as_ref(), |text| {
                    Ok(JsonValue::String(text.as_str().to_owned()))
                })?,
            ),
            ("target", coordinate_json(&request.target)),
        ])),
        PlatformRequest::GetReceipt(request) => Ok(object(vec![
            (
                "client",
                request.client.as_ref().map_or(JsonValue::Null, |client| {
                    JsonValue::String(client.as_str().to_owned())
                }),
            ),
            (
                "id",
                optional_json(request.id.as_ref(), |id| {
                    Ok(JsonValue::String(id.as_str().to_owned()))
                })?,
            ),
            (
                "idempotency_key",
                optional_json(request.idempotency_key.as_ref(), |key| {
                    Ok(JsonValue::String(key.as_str().to_owned()))
                })?,
            ),
        ])),
        PlatformRequest::ListSessions(request) => Ok(object(vec![
            (
                "authority",
                JsonValue::String(request.authority.as_str().to_owned()),
            ),
            (
                "cursor",
                optional_json(request.cursor.as_ref(), cursor_json)?,
            ),
        ])),
        PlatformRequest::Attach(request) => client_session_body(&request.session, &request.client),
        PlatformRequest::Detach(request) => client_session_body(&request.session, &request.client),
        PlatformRequest::ClaimControl(request) => Ok(object(vec![
            (
                "client",
                JsonValue::String(request.client.as_str().to_owned()),
            ),
            (
                "idempotency_key",
                JsonValue::String(request.idempotency_key.as_str().to_owned()),
            ),
            ("session", coordinate_json(&request.session)),
        ])),
        PlatformRequest::ReleaseControl(request) => Ok(object(vec![
            (
                "client",
                JsonValue::String(request.client.as_str().to_owned()),
            ),
            (
                "idempotency_key",
                JsonValue::String(request.idempotency_key.as_str().to_owned()),
            ),
            (
                "lease",
                JsonValue::String(request.lease.as_str().to_owned()),
            ),
            ("session", coordinate_json(&request.session)),
        ])),
        PlatformRequest::SessionHistorySnapshot(request) => Ok(object(vec![
            ("limit", integer(u64::from(request.limit), "limit")?),
            ("session", coordinate_json(&request.session)),
        ])),
        PlatformRequest::SessionHistoryPage(request) => Ok(object(vec![
            ("after", integer(request.after, "after")?),
            ("limit", integer(u64::from(request.limit), "limit")?),
            ("session", coordinate_json(&request.session)),
        ])),
    }
}

fn client_session_body(
    session: &ResourceCoordinate,
    client: &ClientId,
) -> Result<JsonValue, PlatformApiError> {
    Ok(object(vec![
        ("client", JsonValue::String(client.as_str().to_owned())),
        ("session", coordinate_json(session)),
    ]))
}

fn request_from_message(message: &Message) -> Result<PlatformRequest, PlatformApiError> {
    let body = message.body();
    match message.envelope().kind().as_str() {
        "capabilities" => {
            exact_fields(body, &[])?;
            Ok(PlatformRequest::Capabilities)
        }
        "snapshot" => {
            exact_fields(body, &["resources"])?;
            let resources = array(body, "resources")?
                .iter()
                .map(coordinate)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PlatformRequest::Snapshot(SnapshotRequest::new(resources)?))
        }
        "subscribe" => {
            exact_fields(body, &["cursor"])?;
            Ok(PlatformRequest::Subscribe(SubscribeRequest {
                cursor: optional_cursor(body, "cursor")?,
            }))
        }
        "execute" => {
            exact_fields(
                body,
                &[
                    "action",
                    "client",
                    "expected_revision",
                    "idempotency_key",
                    "parameter",
                    "target",
                ],
            )?;
            let mut request = ExecuteRequest::new_with_parameter(
                PlatformAction::parse(string(body, "action")?)?,
                coordinate(body.get("target").ok_or(PlatformApiError::InvalidBody)?)?,
                IdempotencyKey::new(string(body, "idempotency_key")?.to_owned())
                    .map_err(PlatformError::Field)?,
                optional_revision(body, "expected_revision")?,
                optional_parameter(body, "parameter")?,
            )?;
            if let Some(JsonValue::String(client)) = body.get("client") {
                request = request
                    .with_client(ClientId::new(client.clone()).map_err(PlatformError::Field)?);
            } else if !matches!(body.get("client"), Some(JsonValue::Null)) {
                return Err(PlatformApiError::InvalidBody);
            }
            Ok(PlatformRequest::Execute(request))
        }
        "get_receipt" => {
            exact_fields(body, &["client", "id", "idempotency_key"])?;
            let client = match body.get("client") {
                Some(JsonValue::Null) => None,
                Some(JsonValue::String(value)) => {
                    Some(ClientId::new(value.clone()).map_err(PlatformError::Field)?)
                }
                _ => return Err(PlatformApiError::InvalidBody),
            };
            let id = match body.get("id") {
                Some(JsonValue::Null) => None,
                Some(JsonValue::String(value)) => {
                    Some(ReceiptId::new(value.clone()).map_err(PlatformError::Field)?)
                }
                _ => return Err(PlatformApiError::InvalidBody),
            };
            let idempotency_key = match body.get("idempotency_key") {
                Some(JsonValue::Null) => None,
                Some(JsonValue::String(value)) => {
                    Some(IdempotencyKey::new(value.clone()).map_err(PlatformError::Field)?)
                }
                _ => return Err(PlatformApiError::InvalidBody),
            };
            if id.is_some() == idempotency_key.is_some() {
                return Err(PlatformApiError::InvalidBody);
            }
            Ok(PlatformRequest::GetReceipt(GetReceiptRequest {
                client,
                id,
                idempotency_key,
            }))
        }
        "list_sessions" => {
            exact_fields(body, &["authority", "cursor"])?;
            Ok(PlatformRequest::ListSessions(ListSessionsRequest {
                authority: ResourceAuthority::parse(string(body, "authority")?)?,
                cursor: optional_cursor(body, "cursor")?,
            }))
        }
        "attach" | "detach" => {
            exact_fields(body, &["client", "session"])?;
            let session = coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?;
            let client =
                ClientId::new(string(body, "client")?.to_owned()).map_err(PlatformError::Field)?;
            if message.envelope().kind().as_str() == "attach" {
                Ok(PlatformRequest::Attach(AttachRequest { session, client }))
            } else {
                Ok(PlatformRequest::Detach(DetachRequest { session, client }))
            }
        }
        "claim_control" => {
            exact_fields(body, &["client", "idempotency_key", "session"])?;
            Ok(PlatformRequest::ClaimControl(ClaimControlRequest {
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
                idempotency_key: IdempotencyKey::new(string(body, "idempotency_key")?.to_owned())
                    .map_err(PlatformError::Field)?,
            }))
        }
        "release_control" => {
            exact_fields(body, &["client", "idempotency_key", "lease", "session"])?;
            Ok(PlatformRequest::ReleaseControl(ReleaseControlRequest {
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
                lease: ControlLeaseId::new(string(body, "lease")?.to_owned())
                    .map_err(PlatformError::Field)?,
                idempotency_key: IdempotencyKey::new(string(body, "idempotency_key")?.to_owned())
                    .map_err(PlatformError::Field)?,
            }))
        }
        "session_history_snapshot" => {
            exact_fields(body, &["limit", "session"])?;
            Ok(PlatformRequest::SessionHistorySnapshot(
                SessionHistorySnapshotRequest::new(
                    coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                    history_limit(body, "limit")?,
                )?,
            ))
        }
        "session_history_page" => {
            exact_fields(body, &["after", "limit", "session"])?;
            Ok(PlatformRequest::SessionHistoryPage(
                SessionHistoryPageRequest::new(
                    coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                    unsigned(body, "after")?,
                    history_limit(body, "limit")?,
                )?,
            ))
        }
        _ => Err(PlatformApiError::UnknownKind),
    }
}

/// Correlated platform request carried by any supported transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformRequestMessage {
    request_id: RequestId,
    request: PlatformRequest,
}

impl PlatformRequestMessage {
    #[must_use]
    pub const fn new(request_id: RequestId, request: PlatformRequest) -> Self {
        Self {
            request_id,
            request,
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn request(&self) -> &PlatformRequest {
        &self.request
    }

    pub fn to_message(&self) -> Result<Message, PlatformApiError> {
        Ok(Message::new(
            envelope(self.request_id.clone(), request_kind(&self.request))?,
            request_body(&self.request)?,
        ))
    }

    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, PlatformApiError> {
        if payload.len() > MAX_PLATFORM_REQUEST_CANONICAL_BYTES {
            return Err(CodecError::FrameTooLarge {
                max_bytes: MAX_PLATFORM_REQUEST_CANONICAL_BYTES,
                declared_bytes: payload.len(),
            }
            .into());
        }
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request = request_from_message(&message)?;
        Ok(Self::new(message.envelope().request_id().clone(), request))
    }
}

fn response_kind(response: &PlatformResponse) -> &'static str {
    match response {
        PlatformResponse::Capabilities(_) => "capabilities_result",
        PlatformResponse::Snapshot(_) => "snapshot_result",
        PlatformResponse::Subscription(_) => "subscription_result",
        PlatformResponse::Receipt(_) => "receipt_result",
        PlatformResponse::Sessions(_) => "sessions_result",
        PlatformResponse::Attached(_) => "attached",
        PlatformResponse::Detached { .. } => "detached",
        PlatformResponse::ControlClaimed(_) => "control_claimed",
        PlatformResponse::ControlReleased { .. } => "control_released",
        PlatformResponse::SessionHistory(_) => "session_history_result",
        PlatformResponse::SessionHistoryResync(_) => "session_history_resync",
        PlatformResponse::Refused { .. } => "refused",
    }
}

fn response_body(response: &PlatformResponse) -> Result<JsonValue, PlatformApiError> {
    match response {
        PlatformResponse::Capabilities(capabilities) => Ok(object(vec![
            (
                "methods",
                JsonValue::Array(
                    capabilities
                        .methods
                        .iter()
                        .map(|value| JsonValue::String(value.as_str().to_owned()))
                        .collect(),
                ),
            ),
            (
                "protocol",
                JsonValue::String(capabilities.protocol.to_owned()),
            ),
            ("schema", JsonValue::String(capabilities.schema.to_owned())),
            (
                "transports",
                JsonValue::Array(
                    capabilities
                        .transports
                        .iter()
                        .map(|value| JsonValue::String(value.as_str().to_owned()))
                        .collect(),
                ),
            ),
        ])),
        PlatformResponse::Snapshot(snapshot) => Ok(object(vec![
            ("cursor", cursor_json(&snapshot.cursor)?),
            (
                "resources",
                JsonValue::Array(
                    snapshot
                        .resources
                        .iter()
                        .map(record_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
        ])),
        PlatformResponse::Subscription(subscription) => Ok(object(vec![
            ("cursor", cursor_json(&subscription.cursor)?),
            (
                "events",
                JsonValue::Array(
                    subscription
                        .events
                        .iter()
                        .map(|event| {
                            Ok(object(vec![
                                ("cursor", cursor_json(&event.cursor)?),
                                ("resource", record_json(&event.resource)?),
                            ]))
                        })
                        .collect::<Result<Vec<_>, PlatformApiError>>()?,
                ),
            ),
        ])),
        PlatformResponse::Receipt(receipt) => receipt_json(receipt),
        PlatformResponse::Sessions(list) => Ok(object(vec![
            ("cursor", cursor_json(&list.cursor)?),
            (
                "sessions",
                JsonValue::Array(
                    list.sessions
                        .iter()
                        .map(|session| {
                            Ok(object(vec![
                                ("attachable", JsonValue::Bool(session.attachable)),
                                ("controllable", JsonValue::Bool(session.controllable)),
                                (
                                    "run",
                                    optional_json(session.run.as_ref(), |run| {
                                        Ok(coordinate_json(run))
                                    })?,
                                ),
                                ("session", record_json(&session.session)?),
                            ]))
                        })
                        .collect::<Result<Vec<_>, PlatformApiError>>()?,
                ),
            ),
        ])),
        PlatformResponse::Attached(attachment) => Ok(object(vec![
            (
                "client",
                JsonValue::String(attachment.client.as_str().to_owned()),
            ),
            ("cursor", cursor_json(&attachment.cursor)?),
            ("session", coordinate_json(&attachment.session)),
        ])),
        PlatformResponse::Detached { session, client } => client_session_body(session, client),
        PlatformResponse::ControlClaimed(lease) => Ok(object(vec![
            (
                "client",
                JsonValue::String(lease.client.as_str().to_owned()),
            ),
            (
                "expires_at",
                JsonValue::Integer(lease.expires_at.as_millis()),
            ),
            ("id", JsonValue::String(lease.id.as_str().to_owned())),
            ("revision", integer(lease.revision.get(), "revision")?),
            ("session", coordinate_json(&lease.session)),
        ])),
        PlatformResponse::ControlReleased {
            session,
            client,
            lease,
        } => Ok(object(vec![
            ("client", JsonValue::String(client.as_str().to_owned())),
            ("lease", JsonValue::String(lease.as_str().to_owned())),
            ("session", coordinate_json(session)),
        ])),
        PlatformResponse::SessionHistory(page) => {
            let (messages, tool_states, run_states, unknown_events) =
                history_event_arrays(&page.events)?;
            Ok(object(vec![
                (
                    "applied_limit",
                    integer(u64::from(page.applied_limit), "applied_limit")?,
                ),
                ("from_cursor", integer(page.from_cursor, "from_cursor")?),
                ("has_more", JsonValue::Bool(page.has_more)),
                ("messages", JsonValue::Array(messages)),
                (
                    "requested_limit",
                    integer(u64::from(page.requested_limit), "requested_limit")?,
                ),
                ("run_states", JsonValue::Array(run_states)),
                ("session", coordinate_json(&page.session)),
                (
                    "terminal_cursor",
                    integer(page.terminal_cursor, "terminal_cursor")?,
                ),
                ("tool_states", JsonValue::Array(tool_states)),
                ("unknown_events", JsonValue::Array(unknown_events)),
            ]))
        }
        PlatformResponse::SessionHistoryResync(resync) => Ok(object(vec![
            ("session", coordinate_json(&resync.session)),
            (
                "snapshot_from",
                integer(resync.snapshot_from, "snapshot_from")?,
            ),
            ("snapshot_to", integer(resync.snapshot_to, "snapshot_to")?),
        ])),
        PlatformResponse::Refused {
            outcome,
            explanation,
        } => Ok(object(vec![
            (
                "explanation",
                JsonValue::String(explanation.as_str().to_owned()),
            ),
            ("outcome", JsonValue::String(outcome.as_str().to_owned())),
        ])),
    }
}

fn response_from_message(message: &Message) -> Result<PlatformResponse, PlatformApiError> {
    let body = message.body();
    match message.envelope().kind().as_str() {
        "capabilities_result" => {
            exact_fields(body, &["methods", "protocol", "schema", "transports"])?;
            if string(body, "protocol")? != PLATFORM_PROTOCOL
                || string(body, "schema")? != PLATFORM_SCHEMA_V1
            {
                return Err(PlatformApiError::InvalidBody);
            }
            let methods = array(body, "methods")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or(PlatformApiError::InvalidBody)
                        .and_then(|value| PlatformMethod::parse(value).map_err(Into::into))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let transports = array(body, "transports")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or(PlatformApiError::InvalidBody)
                        .and_then(|value| PlatformTransport::parse(value).map_err(Into::into))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if methods.len() > MAX_CAPABILITY_METHODS
                || transports.len() > MAX_CAPABILITY_TRANSPORTS
            {
                return Err(PlatformApiError::InvalidBody);
            }
            Ok(PlatformResponse::Capabilities(Capabilities {
                protocol: PLATFORM_PROTOCOL,
                schema: PLATFORM_SCHEMA_V1,
                methods,
                transports,
            }))
        }
        "snapshot_result" => {
            exact_fields(body, &["cursor", "resources"])?;
            let resources = array(body, "resources")?
                .iter()
                .map(record)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PlatformResponse::Snapshot(Snapshot::new(
                resources,
                cursor(body.get("cursor").ok_or(PlatformApiError::InvalidBody)?)?,
            )?))
        }
        "subscription_result" => {
            exact_fields(body, &["cursor", "events"])?;
            let events = array(body, "events")?
                .iter()
                .map(|value| {
                    exact_fields(value, &["cursor", "resource"])?;
                    Ok(PlatformEvent {
                        cursor: cursor(value.get("cursor").ok_or(PlatformApiError::InvalidBody)?)?,
                        resource: record(
                            value.get("resource").ok_or(PlatformApiError::InvalidBody)?,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, PlatformApiError>>()?;
            Ok(PlatformResponse::Subscription(Subscription::new(
                events,
                cursor(body.get("cursor").ok_or(PlatformApiError::InvalidBody)?)?,
            )?))
        }
        "receipt_result" => Ok(PlatformResponse::Receipt(receipt(body)?)),
        "sessions_result" => {
            exact_fields(body, &["cursor", "sessions"])?;
            let sessions = array(body, "sessions")?
                .iter()
                .map(|value| {
                    exact_fields(value, &["attachable", "controllable", "run", "session"])?;
                    let attachable = match value.get("attachable") {
                        Some(JsonValue::Bool(value)) => *value,
                        _ => return Err(PlatformApiError::InvalidBody),
                    };
                    let controllable = match value.get("controllable") {
                        Some(JsonValue::Bool(value)) => *value,
                        _ => return Err(PlatformApiError::InvalidBody),
                    };
                    let run = match value.get("run") {
                        Some(JsonValue::Null) => None,
                        Some(value) => Some(coordinate(value)?),
                        None => return Err(PlatformApiError::InvalidBody),
                    };
                    Ok(SessionRecord {
                        session: record(
                            value.get("session").ok_or(PlatformApiError::InvalidBody)?,
                        )?,
                        run,
                        attachable,
                        controllable,
                    })
                })
                .collect::<Result<Vec<_>, PlatformApiError>>()?;
            Ok(PlatformResponse::Sessions(SessionList::new(
                sessions,
                cursor(body.get("cursor").ok_or(PlatformApiError::InvalidBody)?)?,
            )?))
        }
        "attached" => {
            exact_fields(body, &["client", "cursor", "session"])?;
            Ok(PlatformResponse::Attached(Attachment {
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
                cursor: cursor(body.get("cursor").ok_or(PlatformApiError::InvalidBody)?)?,
            }))
        }
        "detached" => {
            exact_fields(body, &["client", "session"])?;
            Ok(PlatformResponse::Detached {
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
            })
        }
        "control_claimed" => {
            exact_fields(body, &["client", "expires_at", "id", "revision", "session"])?;
            Ok(PlatformResponse::ControlClaimed(ControlLease {
                id: ControlLeaseId::new(string(body, "id")?.to_owned())
                    .map_err(PlatformError::Field)?,
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
                expires_at: EpochMillis::from_millis(
                    body.get("expires_at")
                        .and_then(JsonValue::as_integer)
                        .ok_or(PlatformApiError::InvalidBody)?,
                ),
                revision: Revision::new(unsigned(body, "revision")?)
                    .map_err(|_| PlatformApiError::InvalidBody)?,
            }))
        }
        "control_released" => {
            exact_fields(body, &["client", "lease", "session"])?;
            Ok(PlatformResponse::ControlReleased {
                session: coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                client: ClientId::new(string(body, "client")?.to_owned())
                    .map_err(PlatformError::Field)?,
                lease: ControlLeaseId::new(string(body, "lease")?.to_owned())
                    .map_err(PlatformError::Field)?,
            })
        }
        "session_history_result" => {
            exact_fields(
                body,
                &[
                    "applied_limit",
                    "from_cursor",
                    "has_more",
                    "messages",
                    "requested_limit",
                    "run_states",
                    "session",
                    "terminal_cursor",
                    "tool_states",
                    "unknown_events",
                ],
            )?;
            let events = decode_history_events(body)?;
            Ok(PlatformResponse::SessionHistory(SessionHistoryPage::new(
                coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                history_limit(body, "requested_limit")?,
                history_limit(body, "applied_limit")?,
                unsigned(body, "from_cursor")?,
                unsigned(body, "terminal_cursor")?,
                boolean(body, "has_more")?,
                events,
            )?))
        }
        "session_history_resync" => {
            exact_fields(body, &["session", "snapshot_from", "snapshot_to"])?;
            Ok(PlatformResponse::SessionHistoryResync(
                SessionHistoryResync::new(
                    coordinate(body.get("session").ok_or(PlatformApiError::InvalidBody)?)?,
                    unsigned(body, "snapshot_from")?,
                    unsigned(body, "snapshot_to")?,
                )?,
            ))
        }
        "refused" => {
            exact_fields(body, &["explanation", "outcome"])?;
            Ok(PlatformResponse::Refused {
                outcome: ReceiptOutcome::parse(string(body, "outcome")?)?,
                explanation: PlatformText::new(string(body, "explanation")?.to_owned())
                    .map_err(PlatformError::Field)?,
            })
        }
        _ => Err(PlatformApiError::UnknownKind),
    }
}

/// Correlated platform response carried by any supported transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformResponseMessage {
    request_id: RequestId,
    response: PlatformResponse,
}

impl PlatformResponseMessage {
    #[must_use]
    pub const fn new(request_id: RequestId, response: PlatformResponse) -> Self {
        Self {
            request_id,
            response,
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }
    #[must_use]
    pub const fn response(&self) -> &PlatformResponse {
        &self.response
    }

    pub fn to_message(&self) -> Result<Message, PlatformApiError> {
        Ok(Message::new(
            envelope(self.request_id.clone(), response_kind(&self.response))?,
            response_body(&self.response)?,
        ))
    }

    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, PlatformApiError> {
        if payload.len() > MAX_PLATFORM_CANONICAL_BYTES {
            return Err(CodecError::FrameTooLarge {
                max_bytes: MAX_PLATFORM_CANONICAL_BYTES,
                declared_bytes: payload.len(),
            }
            .into());
        }
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let response = response_from_message(&message)?;
        Ok(Self::new(message.envelope().request_id().clone(), response))
    }
}
