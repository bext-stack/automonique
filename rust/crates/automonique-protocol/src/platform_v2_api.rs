// SPDX-License-Identifier: Elastic-2.0

//! Exact canonical JSON documents for Platform v2 work-context reads.

use core::fmt;
use std::error::Error;

use crate::codec::CodecError;
use crate::platform::{ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind};
use crate::platform_v2::*;
use crate::primitives::Revision;
use crate::wire::{JsonValue, parse_canonical};

pub const MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES: usize = 16 * 1024;
pub const MAX_WORK_CONTEXT_PAGE_CANONICAL_BYTES: usize = 512 * 1024;
pub const MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES: usize = 4 * 1024;
pub const PLATFORM_NEGOTIATION_SCHEMA_V1: &str = "automonique.platform/negotiation/v1";

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
    let kind = JsonValue::String(identity.kind().as_str().to_owned());
    identity.v1_coordinate().map_or_else(
        || {
            object(vec![
                ("id", JsonValue::String(identity.id().to_owned())),
                ("kind", kind.clone()),
            ])
        },
        |coordinate| {
            object(vec![
                ("kind", kind.clone()),
                ("resource", coordinate_json(coordinate)),
            ])
        },
    )
}

fn identity(value: &JsonValue) -> Result<WorkContextIdentity, WorkContextApiError> {
    let kind = WorkContextTargetKind::parse(string(value, "kind")?)?;
    match kind {
        WorkContextTargetKind::Repository | WorkContextTargetKind::PlatformSession => {
            exact_fields(value, &["kind", "resource"])?;
            let coordinate = coordinate(
                value
                    .get("resource")
                    .ok_or(WorkContextApiError::InvalidBody)?,
            )?;
            match kind {
                WorkContextTargetKind::Repository => Ok(WorkContextIdentity::Repository(
                    V1RepositoryRef::new(coordinate)?,
                )),
                WorkContextTargetKind::PlatformSession => Ok(WorkContextIdentity::PlatformSession(
                    V1SessionRef::new(coordinate)?,
                )),
                _ => Err(WorkContextApiError::InvalidBody),
            }
        }
        _ => {
            exact_fields(value, &["id", "kind"])?;
            WorkContextIdentity::parse_local(kind, string(value, "id")?).map_err(Into::into)
        }
    }
}

fn coordinate_json(coordinate: &ResourceCoordinate) -> JsonValue {
    object(vec![
        (
            "authority",
            JsonValue::String(coordinate.authority.as_str().to_owned()),
        ),
        ("id", JsonValue::String(coordinate.id.as_str().to_owned())),
        (
            "kind",
            JsonValue::String(coordinate.kind.as_str().to_owned()),
        ),
    ])
}

fn coordinate(value: &JsonValue) -> Result<ResourceCoordinate, WorkContextApiError> {
    exact_fields(value, &["authority", "id", "kind"])?;
    Ok(ResourceCoordinate::new(
        ResourceAuthority::parse(string(value, "authority")?)
            .map_err(|_| WorkContextError::V1CoordinateInvalid)?,
        ResourceKind::parse(string(value, "kind")?)
            .map_err(|_| WorkContextError::V1CoordinateInvalid)?,
        ResourceId::new(string(value, "id")?.to_owned()).map_err(WorkContextError::Field)?,
    ))
}

fn attributes_json(attributes: WorkContextAttributes) -> JsonValue {
    object(vec![
        (
            "checkout",
            attributes.checkout_kind().map_or(JsonValue::Null, |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "host_setup",
            attributes
                .host_setup_kind()
                .map_or(JsonValue::Null, |value| {
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
    match (host_setup, checkout) {
        (None, None) => Ok(WorkContextAttributes::EMPTY),
        (Some(kind), None) => Ok(WorkContextAttributes::host_setup(kind)),
        (None, Some(kind)) => Ok(WorkContextAttributes::checkout(kind)),
        (Some(_), Some(_)) => Err(WorkContextApiError::InvalidBody),
    }
}

fn relation_json(relation: &WorkContextRelation) -> JsonValue {
    object(vec![
        (
            "kind",
            JsonValue::String(relation.kind().as_str().to_owned()),
        ),
        ("target", identity_json(relation.target())),
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
        ("attributes", attributes_json(record.attributes())),
        ("identity", identity_json(record.identity())),
        (
            "label",
            JsonValue::String(record.label().as_str().to_owned()),
        ),
        (
            "lifecycle",
            JsonValue::String(record.lifecycle().as_str().to_owned()),
        ),
        (
            "relations",
            JsonValue::Array(record.relations().iter().map(relation_json).collect()),
        ),
        ("revision", integer(record.revision().get(), "revision")?),
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
    if !relations.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(WorkContextError::RelationOrderInvalid.into());
    }
    WorkContextRecord::new(
        identity(
            value
                .get("identity")
                .ok_or(WorkContextApiError::InvalidBody)?,
        )?,
        Revision::new(unsigned(value, "revision")?)
            .map_err(|_| WorkContextError::RevisionInvalid)?,
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

pub fn encode_platform_version_offer(
    offer: &PlatformVersionOffer,
) -> Result<Vec<u8>, WorkContextApiError> {
    let value = object(vec![
        (
            "schema",
            JsonValue::String(PLATFORM_NEGOTIATION_SCHEMA_V1.to_owned()),
        ),
        (
            "versions",
            JsonValue::Array(
                offer
                    .versions()
                    .iter()
                    .map(|version| JsonValue::Integer(i64::from(*version)))
                    .collect(),
            ),
        ),
    ]);
    Ok(value.to_canonical_bytes())
}

pub fn decode_platform_version_offer(
    bytes: &[u8],
) -> Result<PlatformVersionOffer, WorkContextApiError> {
    let value = admitted_document(bytes, MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES)?;
    exact_fields(&value, &["schema", "versions"])?;
    if string(&value, "schema")? != PLATFORM_NEGOTIATION_SCHEMA_V1 {
        return Err(WorkContextError::SchemaInvalid.into());
    }
    PlatformVersionOffer::new(
        array(&value, "versions")?
            .iter()
            .map(|value| {
                let JsonValue::Integer(value) = value else {
                    return Err(WorkContextApiError::InvalidBody);
                };
                let number = u16::try_from(*value)
                    .map_err(|_| WorkContextApiError::CounterOutOfRange { field: "versions" })?;
                Ok(number)
            })
            .collect::<Result<Vec<_>, WorkContextApiError>>()?,
    )
    .map_err(Into::into)
}

pub fn encode_negotiated_platform(
    negotiated: &NegotiatedPlatform,
) -> Result<Vec<u8>, WorkContextApiError> {
    let value = object(vec![
        ("schema", JsonValue::String(negotiated.schema().to_owned())),
        (
            "version",
            JsonValue::Integer(i64::from(negotiated.version().number())),
        ),
        (
            "work_context",
            JsonValue::String(negotiated.work_context().as_str().to_owned()),
        ),
    ]);
    Ok(value.to_canonical_bytes())
}

pub fn decode_negotiated_platform(bytes: &[u8]) -> Result<NegotiatedPlatform, WorkContextApiError> {
    let value = admitted_document(bytes, MAX_PLATFORM_NEGOTIATION_CANONICAL_BYTES)?;
    exact_fields(&value, &["schema", "version", "work_context"])?;
    let version = PlatformVersion::from_number(
        u16::try_from(unsigned(&value, "version")?)
            .map_err(|_| WorkContextApiError::CounterOutOfRange { field: "version" })?,
    )?;
    NegotiatedPlatform::new(
        version,
        match string(&value, "schema")? {
            crate::platform::PLATFORM_SCHEMA_V1 => crate::platform::PLATFORM_SCHEMA_V1,
            PLATFORM_SCHEMA_V2 => PLATFORM_SCHEMA_V2,
            _ => return Err(WorkContextError::SchemaInvalid.into()),
        },
        WorkContextAvailability::parse(string(&value, "work_context")?)?,
    )
    .map_err(Into::into)
}

pub fn encode_work_context_query(query: &WorkContextQuery) -> Result<Vec<u8>, WorkContextApiError> {
    let value = object(vec![
        (
            "after",
            optional_json(query.after(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "kinds",
            JsonValue::Array(
                query
                    .kinds()
                    .iter()
                    .map(|value| JsonValue::String(value.as_str().to_owned()))
                    .collect(),
            ),
        ),
        (
            "lifecycles",
            JsonValue::Array(
                query
                    .lifecycles()
                    .iter()
                    .map(|value| JsonValue::String(value.as_str().to_owned()))
                    .collect(),
            ),
        ),
        ("limit", integer(u64::from(query.limit()), "limit")?),
        ("parent", optional_json(query.parent(), identity_json)),
        (
            "project",
            optional_json(query.project(), |value| {
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
        return Err(WorkContextError::SchemaInvalid.into());
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
            optional_json(page.after(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        ("has_more", JsonValue::Bool(page.has_more())),
        (
            "items",
            JsonValue::Array(
                page.items()
                    .iter()
                    .map(record_json)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        (
            "next_cursor",
            optional_json(page.next_cursor(), |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        (
            "requested_limit",
            integer(u64::from(page.requested_limit()), "requested_limit")?,
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
        return Err(WorkContextError::SchemaInvalid.into());
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

pub fn encode_work_context_resync(
    resync: &WorkContextResync,
) -> Result<Vec<u8>, WorkContextApiError> {
    Ok(object(vec![
        (
            "expired_after",
            JsonValue::String(resync.expired_after().as_str().to_owned()),
        ),
        ("outcome", JsonValue::String("resync_required".to_owned())),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ])
    .to_canonical_bytes())
}

pub fn decode_work_context_resync(bytes: &[u8]) -> Result<WorkContextResync, WorkContextApiError> {
    let value = admitted_document(bytes, MAX_WORK_CONTEXT_QUERY_CANONICAL_BYTES)?;
    exact_fields(&value, &["expired_after", "outcome", "schema"])?;
    if string(&value, "outcome")? != "resync_required"
        || string(&value, "schema")? != PLATFORM_SCHEMA_V2
    {
        return Err(WorkContextError::SchemaInvalid.into());
    }
    Ok(WorkContextResync::new(
        WorkContextCursor::new(string(&value, "expired_after")?.to_owned())
            .map_err(WorkContextError::Field)?,
    ))
}
