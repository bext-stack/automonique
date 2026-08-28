// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical JSON codec for authoritative Platform v2 attention reads.

use core::fmt;

use crate::codec::CodecError;
use crate::platform::{ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind};
use crate::platform_v2::{ProjectId, UserWorkspaceId};
use crate::platform_v2_attention::*;
use crate::primitives::{Revision, ValueError};
use crate::wire::{JsonValue, parse_canonical};

pub const MAX_ATTENTION_REQUEST_CANONICAL_BYTES: usize = 4 * 1024;
pub const MAX_ATTENTION_SNAPSHOT_CANONICAL_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttentionApiError {
    Codec(CodecError),
    Contract(AttentionContractError),
    InvalidBody,
    FrameTooLarge,
}

impl From<CodecError> for AttentionApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<AttentionContractError> for AttentionApiError {
    fn from(value: AttentionContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ValueError> for AttentionApiError {
    fn from(value: ValueError) -> Self {
        Self::Contract(AttentionContractError::Field(value))
    }
}
impl fmt::Display for AttentionApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "attention codec refused document: {self:?}")
    }
}
impl std::error::Error for AttentionApiError {}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: impl Into<String>) -> JsonValue {
    JsonValue::String(value.into())
}
fn integer(value: u64) -> Result<JsonValue, AttentionApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| AttentionApiError::InvalidBody)
}
fn fields(value: &JsonValue, expected: &[&str]) -> Result<(), AttentionApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(AttentionApiError::InvalidBody);
    };
    if entries.len() != expected.len()
        || entries
            .iter()
            .any(|(name, _)| !expected.contains(&name.as_str()))
    {
        return Err(AttentionApiError::InvalidBody);
    }
    Ok(())
}
fn get<'a>(value: &'a JsonValue, name: &str) -> Result<&'a JsonValue, AttentionApiError> {
    value.get(name).ok_or(AttentionApiError::InvalidBody)
}
fn string<'a>(value: &'a JsonValue, name: &str) -> Result<&'a str, AttentionApiError> {
    get(value, name)?
        .as_str()
        .ok_or(AttentionApiError::InvalidBody)
}
fn unsigned(value: &JsonValue, name: &str) -> Result<u64, AttentionApiError> {
    let raw = get(value, name)?
        .as_integer()
        .ok_or(AttentionApiError::InvalidBody)?;
    u64::try_from(raw).map_err(|_| AttentionApiError::InvalidBody)
}
fn boolean(value: &JsonValue, name: &str) -> Result<bool, AttentionApiError> {
    match get(value, name)? {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err(AttentionApiError::InvalidBody),
    }
}
fn revision(value: u64) -> Result<Revision, AttentionApiError> {
    Revision::new(value).map_err(|_| AttentionApiError::InvalidBody)
}
fn parse(payload: &[u8], maximum: usize) -> Result<JsonValue, AttentionApiError> {
    if payload.len() > maximum {
        return Err(AttentionApiError::FrameTooLarge);
    }
    Ok(parse_canonical(payload)?)
}
fn encode(value: JsonValue, maximum: usize) -> Result<Vec<u8>, AttentionApiError> {
    let bytes = value.to_canonical_bytes();
    if bytes.len() > maximum {
        return Err(AttentionApiError::FrameTooLarge);
    }
    Ok(bytes)
}

fn source_json(source: &AttentionSource) -> JsonValue {
    object(vec![
        ("id", text(source.id().as_str())),
        ("kind", text(source.kind().as_str())),
    ])
}
fn source(value: &JsonValue) -> Result<AttentionSource, AttentionApiError> {
    fields(value, &["id", "kind"])?;
    Ok(AttentionSource::new(
        AttentionSourceKind::parse(string(value, "kind")?)?,
        AttentionSourceId::new(string(value, "id")?.to_owned())?,
    ))
}
fn session_json(session: Option<&crate::platform_v2::V1SessionRef>) -> JsonValue {
    session.map_or(JsonValue::Null, |session| {
        let coordinate = session.coordinate();
        object(vec![
            ("authority", text(coordinate.authority.as_str())),
            ("id", text(coordinate.id.as_str())),
            ("kind", text(coordinate.kind.as_str())),
        ])
    })
}
fn session(
    value: &JsonValue,
) -> Result<Option<crate::platform_v2::V1SessionRef>, AttentionApiError> {
    if matches!(value, JsonValue::Null) {
        return Ok(None);
    }
    fields(value, &["authority", "id", "kind"])?;
    let authority = ResourceAuthority::parse(string(value, "authority")?)
        .map_err(|_| AttentionApiError::InvalidBody)?;
    let kind =
        ResourceKind::parse(string(value, "kind")?).map_err(|_| AttentionApiError::InvalidBody)?;
    let coordinate = ResourceCoordinate::new(
        authority,
        kind,
        ResourceId::new(string(value, "id")?.to_owned())?,
    );
    Ok(Some(platform_session(coordinate)?))
}
fn item_json(item: &AttentionItem) -> Result<JsonValue, AttentionApiError> {
    Ok(object(vec![
        ("id", text(item.id().as_str())),
        (
            "nested_agent_path",
            JsonValue::Array(
                item.nested_agent_path()
                    .iter()
                    .map(|id| text(id.as_str()))
                    .collect(),
            ),
        ),
        ("observed_at_ms", integer(item.observed_at_ms())?),
        ("platform_session", session_json(item.platform_session())),
        ("reason", text(item.reason().as_str())),
        ("revision", integer(item.revision().get())?),
        ("state", text(item.state().as_str())),
        ("unread", JsonValue::Bool(item.unread())),
    ]))
}
fn item(value: &JsonValue) -> Result<AttentionItem, AttentionApiError> {
    fields(
        value,
        &[
            "id",
            "nested_agent_path",
            "observed_at_ms",
            "platform_session",
            "reason",
            "revision",
            "state",
            "unread",
        ],
    )?;
    let path = get(value, "nested_agent_path")?
        .as_array()
        .ok_or(AttentionApiError::InvalidBody)?;
    if path.len() > MAX_NESTED_AGENT_DEPTH {
        return Err(AttentionApiError::InvalidBody);
    }
    let nested_agent_path = path
        .iter()
        .map(|entry| {
            let JsonValue::String(value) = entry else {
                return Err(AttentionApiError::InvalidBody);
            };
            AttentionAgentId::new(value.clone()).map_err(AttentionApiError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    AttentionItem::new(
        AttentionItemId::new(string(value, "id")?.to_owned())?,
        revision(unsigned(value, "revision")?)?,
        unsigned(value, "observed_at_ms")?,
        AttentionItemState::parse(string(value, "state")?)?,
        AttentionItemReason::parse(string(value, "reason")?)?,
        boolean(value, "unread")?,
        nested_agent_path,
        session(get(value, "platform_session")?)?,
    )
    .map_err(Into::into)
}

pub fn encode_attention_read_request(
    value: &AttentionReadRequest,
) -> Result<Vec<u8>, AttentionApiError> {
    encode(
        object(vec![
            ("project", text(value.project().as_str())),
            ("schema", text(PLATFORM_ATTENTION_SCHEMA_V1)),
            ("source", source_json(value.source())),
            ("user_workspace", text(value.user_workspace().as_str())),
        ]),
        MAX_ATTENTION_REQUEST_CANONICAL_BYTES,
    )
}

pub fn decode_attention_read_request(
    payload: &[u8],
) -> Result<AttentionReadRequest, AttentionApiError> {
    let value = parse(payload, MAX_ATTENTION_REQUEST_CANONICAL_BYTES)?;
    fields(&value, &["project", "schema", "source", "user_workspace"])?;
    if string(&value, "schema")? != PLATFORM_ATTENTION_SCHEMA_V1 {
        return Err(AttentionApiError::InvalidBody);
    }
    Ok(AttentionReadRequest::new(
        source(get(&value, "source")?)?,
        ProjectId::new(string(&value, "project")?.to_owned())?,
        UserWorkspaceId::new(string(&value, "user_workspace")?.to_owned())?,
    ))
}

pub fn encode_attention_source_snapshot(
    value: &AttentionSourceSnapshot,
) -> Result<Vec<u8>, AttentionApiError> {
    let previous = value
        .previous_revision()
        .map_or(Ok(JsonValue::Null), |revision| integer(revision.get()))?;
    let items = value
        .items()
        .iter()
        .map(item_json)
        .collect::<Result<Vec<_>, _>>()?;
    encode(
        object(vec![
            ("items", JsonValue::Array(items)),
            ("observed_at_ms", integer(value.observed_at_ms())?),
            ("previous_revision", previous),
            ("project", text(value.project().as_str())),
            ("revision", integer(value.revision().get())?),
            ("schema", text(PLATFORM_ATTENTION_SCHEMA_V1)),
            ("semantics", text("atomic_replace")),
            ("source", source_json(value.source())),
            ("user_workspace", text(value.user_workspace().as_str())),
        ]),
        MAX_ATTENTION_SNAPSHOT_CANONICAL_BYTES,
    )
}

pub fn decode_attention_source_snapshot(
    payload: &[u8],
) -> Result<AttentionSourceSnapshot, AttentionApiError> {
    let value = parse(payload, MAX_ATTENTION_SNAPSHOT_CANONICAL_BYTES)?;
    fields(
        &value,
        &[
            "items",
            "observed_at_ms",
            "previous_revision",
            "project",
            "revision",
            "schema",
            "semantics",
            "source",
            "user_workspace",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_ATTENTION_SCHEMA_V1
        || string(&value, "semantics")? != "atomic_replace"
    {
        return Err(AttentionApiError::InvalidBody);
    }
    let previous_revision = match get(&value, "previous_revision")? {
        JsonValue::Null => None,
        JsonValue::Integer(raw) => Some(revision(
            u64::try_from(*raw).map_err(|_| AttentionApiError::InvalidBody)?,
        )?),
        _ => return Err(AttentionApiError::InvalidBody),
    };
    let raw_items = get(&value, "items")?
        .as_array()
        .ok_or(AttentionApiError::InvalidBody)?;
    if raw_items.len() > MAX_ATTENTION_ITEMS {
        return Err(AttentionApiError::InvalidBody);
    }
    let items = raw_items.iter().map(item).collect::<Result<Vec<_>, _>>()?;
    AttentionSourceSnapshot::new(
        source(get(&value, "source")?)?,
        ProjectId::new(string(&value, "project")?.to_owned())?,
        UserWorkspaceId::new(string(&value, "user_workspace")?.to_owned())?,
        revision(unsigned(&value, "revision")?)?,
        previous_revision,
        unsigned(&value, "observed_at_ms")?,
        items,
    )
    .map_err(Into::into)
}
