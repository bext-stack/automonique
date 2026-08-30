// SPDX-License-Identifier: Elastic-2.0

//! Exact canonical JSON documents for the Platform v2 resource listing.
//!
//! The record body itself is not spelled here. A listed resource is the same
//! `{freshness, resource, summary}` object Platform v1 already carries, and
//! this module calls the v1 codec for it rather than writing a second one that
//! could drift from it.

use core::fmt;
use std::error::Error;

use crate::codec::CodecError;
use crate::platform::{ResourceAuthority, ResourceKind};
use crate::platform_api::PlatformApiError;
use crate::platform_v2_inventory::*;
use crate::wire::{JsonValue, parse_canonical};

/// Maximum canonical listing-query bytes.
pub const MAX_RESOURCE_LISTING_QUERY_CANONICAL_BYTES: usize = 8 * 1024;

/// Maximum canonical listing-page bytes. One page is bounded by
/// [`MAX_RESOURCE_LISTING_PAGE_ITEMS`] records, each a bounded v1 projection.
pub const MAX_RESOURCE_LISTING_PAGE_CANONICAL_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceListingApiError {
    Codec(CodecError),
    Listing(ResourceListingError),
    Record(PlatformApiError),
    InvalidBody,
    CounterOutOfRange { field: &'static str },
    FrameTooLarge,
}

impl ResourceListingApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::Listing(_) => "resource_listing_value_invalid",
            Self::Record(_) => "resource_listing_record_invalid",
            Self::InvalidBody => "resource_listing_invalid_body",
            Self::CounterOutOfRange { .. } => "resource_listing_counter_out_of_range",
            Self::FrameTooLarge => "frame_too_large",
        }
    }
}

impl fmt::Display for ResourceListingApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(
                    formatter,
                    "resource listing codec refused document: {error}"
                )
            }
            Self::Listing(error) => write!(formatter, "resource listing value refused: {error}"),
            Self::Record(error) => write!(formatter, "listed resource record refused: {error}"),
            Self::InvalidBody => formatter.write_str("resource listing document body is invalid"),
            Self::CounterOutOfRange { field } => write!(
                formatter,
                "resource listing counter {field} is outside the wire range"
            ),
            Self::FrameTooLarge => formatter.write_str("resource listing document is too large"),
        }
    }
}

impl Error for ResourceListingApiError {}

impl From<CodecError> for ResourceListingApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<ResourceListingError> for ResourceListingApiError {
    fn from(value: ResourceListingError) -> Self {
        Self::Listing(value)
    }
}

impl From<PlatformApiError> for ResourceListingApiError {
    fn from(value: PlatformApiError) -> Self {
        Self::Record(value)
    }
}

const QUERY_FIELDS: [&str; 6] = [
    "after",
    "authorities",
    "kinds",
    "requested_limit",
    "schema",
    "version",
];

const PAGE_FIELDS: [&str; 8] = [
    "after",
    "granted_limit",
    "has_more",
    "items",
    "next_cursor",
    "requested_limit",
    "schema",
    "version",
];

const RESYNC_FIELDS: [&str; 4] = ["expired_after", "outcome", "schema", "version"];

const RESYNC_OUTCOME: &str = "resync_required";

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn exact_fields(value: &JsonValue, fields: &[&str]) -> Result<(), ResourceListingApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(ResourceListingApiError::InvalidBody);
    };
    if entries.len() != fields.len()
        || entries
            .iter()
            .any(|(key, _)| !fields.iter().any(|field| key == field))
    {
        return Err(ResourceListingApiError::InvalidBody);
    }
    Ok(())
}

fn string<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a str, ResourceListingApiError> {
    value
        .get(field)
        .and_then(JsonValue::as_str)
        .ok_or(ResourceListingApiError::InvalidBody)
}

fn array<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a [JsonValue], ResourceListingApiError> {
    value
        .get(field)
        .and_then(JsonValue::as_array)
        .ok_or(ResourceListingApiError::InvalidBody)
}

fn boolean(value: &JsonValue, field: &'static str) -> Result<bool, ResourceListingApiError> {
    match value.get(field) {
        Some(JsonValue::Bool(value)) => Ok(*value),
        _ => Err(ResourceListingApiError::InvalidBody),
    }
}

fn limit(value: &JsonValue, field: &'static str) -> Result<u16, ResourceListingApiError> {
    let raw = value
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(ResourceListingApiError::InvalidBody)?;
    u16::try_from(raw).map_err(|_| ResourceListingApiError::CounterOutOfRange { field })
}

fn optional_cursor(
    value: &JsonValue,
    field: &'static str,
) -> Result<Option<ResourceListingCursor>, ResourceListingApiError> {
    match value.get(field) {
        Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => ResourceListingCursor::new(value.clone())
            .map(Some)
            .map_err(|error| ResourceListingError::Field(error).into()),
        _ => Err(ResourceListingApiError::InvalidBody),
    }
}

fn cursor_json(value: Option<&ResourceListingCursor>) -> JsonValue {
    value.map_or(JsonValue::Null, |cursor| {
        JsonValue::String(cursor.as_str().to_owned())
    })
}

fn schema_and_version(value: &JsonValue) -> Result<(), ResourceListingApiError> {
    if string(value, "schema")? != PLATFORM_INVENTORY_SCHEMA_V1
        || value.get("version").and_then(JsonValue::as_integer)
            != Some(i64::from(PLATFORM_INVENTORY_REQUIRES_PLATFORM_MAJOR))
    {
        return Err(ResourceListingApiError::InvalidBody);
    }
    Ok(())
}

fn schema_json() -> [(&'static str, JsonValue); 2] {
    [
        (
            "schema",
            JsonValue::String(PLATFORM_INVENTORY_SCHEMA_V1.to_owned()),
        ),
        (
            "version",
            JsonValue::Integer(i64::from(PLATFORM_INVENTORY_REQUIRES_PLATFORM_MAJOR)),
        ),
    ]
}

fn admitted(bytes: &[u8], ceiling: usize) -> Result<JsonValue, ResourceListingApiError> {
    if bytes.len() > ceiling {
        return Err(ResourceListingApiError::FrameTooLarge);
    }
    Ok(parse_canonical(bytes)?)
}

fn encoded(value: &JsonValue, ceiling: usize) -> Result<Vec<u8>, ResourceListingApiError> {
    let bytes = value.to_canonical_bytes();
    if bytes.len() > ceiling {
        return Err(ResourceListingApiError::FrameTooLarge);
    }
    Ok(bytes)
}

/// Render one listing query.
///
/// # Errors
///
/// Returns [`ResourceListingApiError::FrameTooLarge`] when the canonical
/// document exceeds its ceiling.
pub fn encode_resource_listing_query(
    query: &ResourceListingQuery,
) -> Result<Vec<u8>, ResourceListingApiError> {
    let [schema, version] = schema_json();
    let value = object(vec![
        ("after", cursor_json(query.after())),
        (
            "authorities",
            JsonValue::Array(
                query
                    .authorities()
                    .iter()
                    .map(|value| JsonValue::String(value.as_str().to_owned()))
                    .collect(),
            ),
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
            "requested_limit",
            JsonValue::Integer(i64::from(query.requested_limit())),
        ),
        schema,
        version,
    ]);
    encoded(&value, MAX_RESOURCE_LISTING_QUERY_CANONICAL_BYTES)
}

/// Read one listing query back.
///
/// # Errors
///
/// Returns [`ResourceListingApiError`] when the document is over its ceiling,
/// is not exactly this body, or carries a value the contract refuses.
pub fn decode_resource_listing_query(
    bytes: &[u8],
) -> Result<ResourceListingQuery, ResourceListingApiError> {
    let value = admitted(bytes, MAX_RESOURCE_LISTING_QUERY_CANONICAL_BYTES)?;
    exact_fields(&value, &QUERY_FIELDS)?;
    schema_and_version(&value)?;
    let authorities = array(&value, "authorities")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ResourceListingApiError::InvalidBody)
                .and_then(|value| {
                    ResourceAuthority::parse(value)
                        .map_err(|_| ResourceListingApiError::InvalidBody)
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let kinds = array(&value, "kinds")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ResourceListingApiError::InvalidBody)
                .and_then(|value| {
                    ResourceKind::parse(value).map_err(|_| ResourceListingApiError::InvalidBody)
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ResourceListingQuery::new(
        authorities,
        kinds,
        optional_cursor(&value, "after")?,
        limit(&value, "requested_limit")?,
    )?)
}

/// Render one listing page.
///
/// # Errors
///
/// Returns [`ResourceListingApiError`] when a record refuses to render or the
/// canonical document exceeds its ceiling.
pub fn encode_resource_listing_page(
    page: &ResourceListingPage,
) -> Result<Vec<u8>, ResourceListingApiError> {
    let [schema, version] = schema_json();
    let value = object(vec![
        ("after", cursor_json(page.after())),
        (
            "granted_limit",
            JsonValue::Integer(i64::from(page.granted_limit())),
        ),
        ("has_more", JsonValue::Bool(page.has_more())),
        (
            "items",
            JsonValue::Array(
                page.items()
                    .iter()
                    .map(|record| crate::platform_api::record_json(record).map_err(Into::into))
                    .collect::<Result<Vec<_>, ResourceListingApiError>>()?,
            ),
        ),
        ("next_cursor", cursor_json(page.next_cursor())),
        (
            "requested_limit",
            JsonValue::Integer(i64::from(page.requested_limit())),
        ),
        schema,
        version,
    ]);
    encoded(&value, MAX_RESOURCE_LISTING_PAGE_CANONICAL_BYTES)
}

/// Read one listing page back.
///
/// The two limits are both decoded and both checked: a page whose
/// `granted_limit` is not the server's own clamp of `requested_limit` is
/// refused rather than reported, so a client can prove the bound it was held to
/// instead of trusting the number.
///
/// # Errors
///
/// Returns [`ResourceListingApiError`] when the document is over its ceiling,
/// is not exactly this body, or carries a value the contract refuses.
pub fn decode_resource_listing_page(
    bytes: &[u8],
) -> Result<ResourceListingPage, ResourceListingApiError> {
    let value = admitted(bytes, MAX_RESOURCE_LISTING_PAGE_CANONICAL_BYTES)?;
    exact_fields(&value, &PAGE_FIELDS)?;
    schema_and_version(&value)?;
    let items = array(&value, "items")?;
    if items.len() > MAX_RESOURCE_LISTING_PAGE_ITEMS {
        return Err(ResourceListingApiError::InvalidBody);
    }
    let items = items
        .iter()
        .map(|record| crate::platform_api::record(record).map_err(Into::into))
        .collect::<Result<Vec<_>, ResourceListingApiError>>()?;
    Ok(ResourceListingPage::new(
        limit(&value, "requested_limit")?,
        limit(&value, "granted_limit")?,
        optional_cursor(&value, "after")?,
        optional_cursor(&value, "next_cursor")?,
        boolean(&value, "has_more")?,
        items,
    )?)
}

/// Render the answer a caller gets when its cursor no longer names a listing.
///
/// # Errors
///
/// Returns [`ResourceListingApiError::FrameTooLarge`] when the canonical
/// document exceeds its ceiling.
pub fn encode_resource_listing_resync(
    resync: &ResourceListingResync,
) -> Result<Vec<u8>, ResourceListingApiError> {
    let [schema, version] = schema_json();
    let value = object(vec![
        (
            "expired_after",
            JsonValue::String(resync.expired_after().as_str().to_owned()),
        ),
        ("outcome", JsonValue::String(RESYNC_OUTCOME.to_owned())),
        schema,
        version,
    ]);
    encoded(&value, MAX_RESOURCE_LISTING_QUERY_CANONICAL_BYTES)
}

/// Read one resync answer back.
///
/// # Errors
///
/// Returns [`ResourceListingApiError`] when the document is over its ceiling,
/// is not exactly this body, or carries a value the contract refuses.
pub fn decode_resource_listing_resync(
    bytes: &[u8],
) -> Result<ResourceListingResync, ResourceListingApiError> {
    let value = admitted(bytes, MAX_RESOURCE_LISTING_QUERY_CANONICAL_BYTES)?;
    exact_fields(&value, &RESYNC_FIELDS)?;
    schema_and_version(&value)?;
    if string(&value, "outcome")? != RESYNC_OUTCOME {
        return Err(ResourceListingApiError::InvalidBody);
    }
    Ok(ResourceListingResync::new(
        ResourceListingCursor::new(string(&value, "expired_after")?.to_owned()).map_err(
            |error| ResourceListingApiError::Listing(ResourceListingError::Field(error)),
        )?,
    ))
}
