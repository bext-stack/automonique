// SPDX-License-Identifier: Elastic-2.0

//! Exact canonical JSON documents for Platform v2 work-context reads.

use core::fmt;
use std::error::Error;

use crate::codec::CodecError;
use crate::platform_v2::*;
use crate::primitives::Revision;
use crate::wire::{JsonValue, parse_canonical};

pub const MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES: usize = 16 * 1024;
pub const MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkContextApiError {
    Codec(CodecError),
    Context(WorkContextError),
    InvalidBody,
    CounterOutOfRange { field: &'static str },
    FrameTooLarge,
}

impl WorkContextApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Context(_) => "work_context_value_invalid",
            Self::InvalidBody => "work_context_invalid_body",
            Self::CounterOutOfRange { .. } => "work_context_counter_out_of_range",
            Self::FrameTooLarge => "frame_too_large",
        }
    }
}

impl fmt::Display for WorkContextApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "work-context codec refused document: {error}"),
            Self::Context(error) => write!(formatter, "work-context value was refused: {error}"),
            Self::InvalidBody => formatter.write_str("work-context document body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "work-context counter {field} is outside the wire range"
                )
            }
            Self::FrameTooLarge => formatter.write_str("work-context document is too large"),
        }
    }
}

impl Error for WorkContextApiError {}

impl From<CodecError> for WorkContextApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<WorkContextError> for WorkContextApiError {
    fn from(value: WorkContextError) -> Self {
        Self::Context(value)
    }
}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn exact_fields(value: &JsonValue, fields: &[&str]) -> Result<(), WorkContextApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(WorkContextApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || entries
            .iter()
            .any(|(key, _)| !fields.iter().any(|field| key == field))
    {
        return Err(WorkContextApiError::InvalidBody);
    }
    Ok(())
}

fn string<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str, WorkContextApiError> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or(WorkContextApiError::InvalidBody)
}

fn array<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a [JsonValue], WorkContextApiError> {
    value
        .get(field)
        .and_then(JsonValue::as_array)
        .ok_or(WorkContextApiError::InvalidBody)
}

fn boolean(value: &JsonValue, field: &'static str) -> Result<bool, WorkContextApiError> {
    match value.get(field) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        _ => Err(WorkContextApiError::InvalidBody),
    }
}

fn unsigned(value: &JsonValue, field: &'static str) -> Result<u64, WorkContextApiError> {
    let value = value
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(WorkContextApiError::InvalidBody)?;
    u64::try_from(value).map_err(|_| WorkContextApiError::CounterOutOfRange { field })
}

fn integer(value: u64, field: &'static str) -> Result<JsonValue, WorkContextApiError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| WorkContextApiError::CounterOutOfRange { field })
}

fn optional_string<T>(
    value: &JsonValue,
    field: &'static str,
    build: impl FnOnce(String) -> Result<T, crate::primitives::ValueError>,
) -> Result<Option<T>, WorkContextApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => build(value.clone())
            .map(Some)
            .map_err(|error| WorkContextError::Field(error).into()),
        _ => Err(WorkContextApiError::InvalidBody),
    }
}

fn optional_json<T>(value: Option<&T>, encode: impl FnOnce(&T) -> JsonValue) -> JsonValue {
    value.map_or(JsonValue::Null, encode)
}

fn identity_json(identity: &WorkContextIdentity) -> JsonValue {
    object(vec![
        ("id", JsonValue::String(identity.id().to_owned())),
        (
            "kind",
            JsonValue::String(identity.kind().as_str().to_owned()),
        ),
    ])
}

fn identity(value: &JsonValue) -> Result<WorkContextIdentity, WorkContextApiError> {
    exact_fields(value, &["id", "kind"])?;
    WorkContextIdentity::parse(
        WorkContextTargetKind::parse(string(value, "kind")?)?,
        string(value, "id")?,
    )
    .map_err(Into::into)
}

fn attributes_json(attributes: WorkContextAttributes) -> JsonValue {
    object(vec![
        (
            "checkout",
            attributes.checkout.map_or(JsonValue::Null, |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "host_setup",
            attributes.host_setup.map_or(JsonValue::Null, |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
    ])
}

fn attributes(value: &JsonValue) -> Result<WorkContextAttributes, WorkContextApiError> {
    exact_fields(value, &["checkout", "host_setup"])?;
    let checkout = match value.get("checkout") {
        Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(CheckoutKind::parse(value)?),
        _ => return Err(WorkContextApiError::InvalidBody),
    };
    let host_setup = match value.get("host_setup") {
        Some(JsonValue::Null) => None,
        Some(JsonValue::String(value)) => Some(HostSetupKind::parse(value)?),
        _ => return Err(WorkContextApiError::InvalidBody),
    };
    Ok(WorkContextAttributes {
        host_setup,
        checkout,
    })
}

fn relation_json(relation: &WorkContextRelation) -> JsonValue {
    object(vec![
        ("kind", JsonValue::String(relation.kind.as_str().to_owned())),
        ("target", identity_json(&relation.target)),
    ])
}

fn relation(value: &JsonValue) -> Result<WorkContextRelation, WorkContextApiError> {
    exact_fields(value, &["kind", "target"])?;
    WorkContextRelation::new(
        WorkContextRelationKind::parse(string(value, "kind")?)?,
        identity(
            value
                .get("target")
                .ok_or(WorkContextApiError::InvalidBody)?,
        )?,
    )
    .map_err(Into::into)
}

fn record_json(record: &WorkContextRecord) -> Result<JsonValue, WorkContextApiError> {
    Ok(object(vec![
        ("attributes", attributes_json(record.attributes)),
        ("identity", identity_json(&record.identity)),
        ("label", JsonValue::String(record.label.as_str().to_owned())),
        (
            "lifecycle",
            JsonValue::String(record.lifecycle.as_str().to_owned()),
        ),
        (
            "relations",
            JsonValue::Array(record.relations.iter().map(relation_json).collect()),
        ),
        ("revision", integer(record.revision.get(), "revision")?),
    ]))
}

fn record(value: &JsonValue) -> Result<WorkContextRecord, WorkContextApiError> {
    exact_fields(
        value,
        &[
            "attributes",
            "identity",
            "label",
            "lifecycle",
            "relations",
            "revision",
        ],
    )?;
    let relations = array(value, "relations")?
        .iter()
        .map(relation)
        .collect::<Result<Vec<_>, _>>()?;
    WorkContextRecord::new(
        identity(
            value
                .get("identity")
                .ok_or(WorkContextApiError::InvalidBody)?,
        )?,
        Revision::new(unsigned(value, "revision")?)
            .map_err(|_| WorkContextApiError::InvalidBody)?,
        WorkContextLifecycle::parse(string(value, "lifecycle")?)?,
        WorkContextLabel::new(string(value, "label")?.to_owned())
            .map_err(WorkContextError::Field)?,
        attributes(
            value
                .get("attributes")
                .ok_or(WorkContextApiError::InvalidBody)?,
        )?,
        relations,
    )
    .map_err(Into::into)
}

fn admitted_document(bytes: &[u8], ceiling: usize) -> Result<JsonValue, WorkContextApiError> {
    if bytes.len() > ceiling {
        return Err(WorkContextApiError::FrameTooLarge);
    }
    parse_canonical(bytes).map_err(Into::into)
}

pub fn encode_work_context_query(query: &WorkContextQuery) -> Result<Vec<u8>, WorkContextApiError> {
    let value = object(vec![
        (
            "after",
            optional_json(query.after.as_ref(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "kinds",
            JsonValue::Array(
                query
                    .kinds
                    .iter()
                    .map(|value| JsonValue::String(value.as_str().to_owned()))
                    .collect(),
            ),
        ),
        (
            "lifecycles",
            JsonValue::Array(
                query
                    .lifecycles
                    .iter()
                    .map(|value| JsonValue::String(value.as_str().to_owned()))
                    .collect(),
            ),
        ),
        ("limit", integer(u64::from(query.limit), "limit")?),
        (
            "parent",
            optional_json(query.parent.as_ref(), identity_json),
        ),
        (
            "project",
            optional_json(query.project.as_ref(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]);
    let bytes = value.to_canonical_bytes();
    if bytes.len() > MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES {
        return Err(WorkContextApiError::FrameTooLarge);
    }
    Ok(bytes)
}

pub fn decode_work_context_query(bytes: &[u8]) -> Result<WorkContextQuery, WorkContextApiError> {
    let value = admitted_document(bytes, MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES)?;
    exact_fields(
        &value,
        &[
            "after",
            "kinds",
            "lifecycles",
            "limit",
            "parent",
            "project",
            "schema",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(WorkContextApiError::InvalidBody);
    }
    let kinds = array(&value, "kinds")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(WorkContextApiError::InvalidBody)
                .and_then(|value| WorkContextKind::parse(value).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let lifecycles = array(&value, "lifecycles")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(WorkContextApiError::InvalidBody)
                .and_then(|value| WorkContextLifecycle::parse(value).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parent = match value.get("parent") {
        Some(JsonValue::Null) => None,
        Some(value) => Some(identity(value)?),
        None => return Err(WorkContextApiError::InvalidBody),
    };
    let limit = u16::try_from(unsigned(&value, "limit")?)
        .map_err(|_| WorkContextApiError::CounterOutOfRange { field: "limit" })?;
    WorkContextQuery::new(
        kinds,
        lifecycles,
        optional_string(&value, "project", ProjectId::new)?,
        parent,
        optional_string(&value, "after", WorkContextCursor::new)?,
        limit,
    )
    .map_err(Into::into)
}

pub fn encode_work_context_page(page: &WorkContextPage) -> Result<Vec<u8>, WorkContextApiError> {
    let value = object(vec![
        (
            "after",
            optional_json(page.after.as_ref(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        ("has_more", JsonValue::Bool(page.has_more)),
        (
            "items",
            JsonValue::Array(
                page.items
                    .iter()
                    .map(record_json)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        (
            "next_cursor",
            optional_json(page.next_cursor.as_ref(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "requested_limit",
            integer(u64::from(page.requested_limit), "requested_limit")?,
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]);
    let bytes = value.to_canonical_bytes();
    if bytes.len() > MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES {
        return Err(WorkContextApiError::FrameTooLarge);
    }
    Ok(bytes)
}

pub fn decode_work_context_page(bytes: &[u8]) -> Result<WorkContextPage, WorkContextApiError> {
    let value = admitted_document(bytes, MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES)?;
    exact_fields(
        &value,
        &[
            "after",
            "has_more",
            "items",
            "next_cursor",
            "requested_limit",
            "schema",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(WorkContextApiError::InvalidBody);
    }
    let requested_limit = u16::try_from(unsigned(&value, "requested_limit")?).map_err(|_| {
        WorkContextApiError::CounterOutOfRange {
            field: "requested_limit",
        }
    })?;
    WorkContextPage::new(
        requested_limit,
        optional_string(&value, "after", WorkContextCursor::new)?,
        optional_string(&value, "next_cursor", WorkContextCursor::new)?,
        boolean(&value, "has_more")?,
        array(&value, "items")?
            .iter()
            .map(record)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(Into::into)
}
