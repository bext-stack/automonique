// SPDX-License-Identifier: Elastic-2.0

//! Frozen, dependency-free extraction of the Platform v1 response admission
//! used by the last client commit before Platform v2 existed.
//!
//! Provenance, source hashes, and the extraction boundary are recorded in
//! `../../fixtures/platform-v1-installed-client-2e428e44.PROVENANCE.md`.
//! Keep this module independent of `platform`, `platform_api`, and their typed
//! decoders: using today's v1 decoder here would not test an installed client.

use automonique_protocol::wire::{JsonValue, parse_canonical};

const AUTHORITIES: &[&str] = &[
    "ai_operations",
    "automonique",
    "github",
    "provider",
    "client",
];
const RESOURCE_KINDS: &[&str] = &[
    "job",
    "release",
    "node",
    "run",
    "session",
    "approval",
    "sandbox",
    "credential",
    "repository",
    "issue",
    "pull_request",
    "workflow",
    "provider_account",
    "model",
    "client",
    "control_lease",
    "receipt",
];
const METHODS: &[&str] = &[
    "capabilities",
    "snapshot",
    "subscribe",
    "execute",
    "get_receipt",
    "list_sessions",
    "attach",
    "detach",
    "claim_control",
    "release_control",
    "session_history_snapshot",
    "session_history_page",
    "session_command_state",
    "session_follow_up",
    "session_run_stop",
    "session_approval_decision",
];
const TRANSPORTS: &[&str] = &["local_unix", "remote_https", "remote_websocket"];
const ACTIONS: &[&str] = &[
    "start_run",
    "stop_run",
    "decide_approval",
    "submit_request",
    "follow_up",
    "steer",
    "submit_job",
    "approve_release",
    "register_node",
];
const OUTCOMES: &[&str] = &[
    "accepted",
    "completed",
    "rejected",
    "conflict",
    "unknown",
    "resync_required",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoricalResponseKind {
    Capabilities,
    Snapshot,
    Receipt,
    Sessions,
    Refused,
}

impl HistoricalResponseKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Snapshot => "snapshot",
            Self::Receipt => "receipt",
            Self::Sessions => "sessions",
            Self::Refused => "refused",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HistoricalResponse {
    pub request_id: String,
    pub kind: HistoricalResponseKind,
}

pub fn decode(payload: &[u8]) -> Result<HistoricalResponse, &'static str> {
    if payload.len() > 512 * 1024 {
        return Err("response_too_large");
    }
    let document = parse_canonical(payload).map_err(|_| "noncanonical_json")?;
    exact(
        &document,
        &["body", "kind", "protocol", "request_id", "version"],
    )?;
    if string(&document, "protocol")? != "automonique.platform"
        || integer(&document, "version")? != 1
    {
        return Err("foreign_protocol");
    }
    let request_id = string(&document, "request_id")?;
    if request_id.is_empty()
        || request_id.len() > 128
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err("request_id_invalid");
    }
    let body = value(&document, "body")?;
    let kind = match string(&document, "kind")? {
        "capabilities_result" => {
            capabilities(body)?;
            HistoricalResponseKind::Capabilities
        }
        "snapshot_result" => {
            snapshot(body)?;
            HistoricalResponseKind::Snapshot
        }
        "receipt_result" => {
            receipt(body)?;
            HistoricalResponseKind::Receipt
        }
        "sessions_result" => {
            sessions(body)?;
            HistoricalResponseKind::Sessions
        }
        "refused" => {
            refused(body)?;
            HistoricalResponseKind::Refused
        }
        _ => return Err("response_kind_unsupported_by_fixture_harness"),
    };
    Ok(HistoricalResponse {
        request_id: request_id.to_owned(),
        kind,
    })
}

fn capabilities(body: &JsonValue) -> Result<(), &'static str> {
    exact(body, &["methods", "protocol", "schema", "transports"])?;
    if string(body, "protocol")? != "automonique.platform"
        || string(body, "schema")? != "automonique.platform/v1"
    {
        return Err("capability_identity_invalid");
    }
    closed_array(body, "methods", METHODS, 32)?;
    closed_array(body, "transports", TRANSPORTS, 3)
}

fn snapshot(body: &JsonValue) -> Result<(), &'static str> {
    exact(body, &["cursor", "resources"])?;
    cursor(value(body, "cursor")?)?;
    let resources = array(body, "resources")?;
    if resources.len() > 512 {
        return Err("snapshot_too_large");
    }
    for item in resources {
        record(item)?;
    }
    Ok(())
}

fn sessions(body: &JsonValue) -> Result<(), &'static str> {
    exact(body, &["cursor", "sessions"])?;
    cursor(value(body, "cursor")?)?;
    for item in array(body, "sessions")? {
        exact(item, &["attachable", "controllable", "run", "session"])?;
        boolean(item, "attachable")?;
        boolean(item, "controllable")?;
        match value(item, "run")? {
            JsonValue::Null => {}
            coordinate => validate_coordinate(coordinate)?,
        }
        record(value(item, "session")?)?;
    }
    Ok(())
}

fn receipt(body: &JsonValue) -> Result<(), &'static str> {
    exact(
        body,
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
    closed(string(body, "action")?, ACTIONS)?;
    optional_string(body, "explanation")?;
    bounded_string(body, "id", 256)?;
    closed(string(body, "outcome")?, OUTCOMES)?;
    nonnegative(body, "recorded_at")?;
    positive(body, "revision")?;
    validate_coordinate(value(body, "target")?)
}

fn refused(body: &JsonValue) -> Result<(), &'static str> {
    exact(body, &["explanation", "outcome"])?;
    bounded_string(body, "explanation", 4096)?;
    closed(string(body, "outcome")?, OUTCOMES)
}

fn record(value_: &JsonValue) -> Result<(), &'static str> {
    exact(value_, &["freshness", "resource", "summary"])?;
    let freshness = value(value_, "freshness")?;
    exact(freshness, &["observed_at", "revision", "state"])?;
    nonnegative(freshness, "observed_at")?;
    positive(freshness, "revision")?;
    closed(string(freshness, "state")?, &["fresh", "stale", "unknown"])?;
    validate_coordinate(value(value_, "resource")?)?;
    bounded_string(value_, "summary", 4096)
}

fn validate_coordinate(value_: &JsonValue) -> Result<(), &'static str> {
    exact(value_, &["authority", "id", "kind"])?;
    closed(string(value_, "authority")?, AUTHORITIES)?;
    bounded_string(value_, "id", 256)?;
    closed(string(value_, "kind")?, RESOURCE_KINDS)
}

fn cursor(value_: &JsonValue) -> Result<(), &'static str> {
    exact(value_, &["authority", "sequence", "topic"])?;
    closed(string(value_, "authority")?, AUTHORITIES)?;
    positive(value_, "sequence")?;
    bounded_string(value_, "topic", 256)
}

fn exact(value_: &JsonValue, expected: &[&str]) -> Result<(), &'static str> {
    let JsonValue::Object(entries) = value_ else {
        return Err("object_required");
    };
    if entries.len() != expected.len()
        || !entries
            .iter()
            .zip(expected)
            .all(|((actual, _), expected)| actual == expected)
    {
        return Err("fields_invalid");
    }
    Ok(())
}

fn value<'a>(object: &'a JsonValue, field: &str) -> Result<&'a JsonValue, &'static str> {
    object.get(field).ok_or("field_missing")
}

fn string<'a>(object: &'a JsonValue, field: &str) -> Result<&'a str, &'static str> {
    value(object, field)?.as_str().ok_or("string_required")
}

fn integer(object: &JsonValue, field: &str) -> Result<i64, &'static str> {
    value(object, field)?.as_integer().ok_or("integer_required")
}

fn array<'a>(object: &'a JsonValue, field: &str) -> Result<&'a [JsonValue], &'static str> {
    value(object, field)?.as_array().ok_or("array_required")
}

fn boolean(object: &JsonValue, field: &str) -> Result<bool, &'static str> {
    match value(object, field)? {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err("boolean_required"),
    }
}

fn nonnegative(object: &JsonValue, field: &str) -> Result<(), &'static str> {
    if integer(object, field)? < 0 {
        return Err("counter_negative");
    }
    Ok(())
}

fn positive(object: &JsonValue, field: &str) -> Result<(), &'static str> {
    if integer(object, field)? <= 0 {
        return Err("counter_not_positive");
    }
    Ok(())
}

fn bounded_string(object: &JsonValue, field: &str, max: usize) -> Result<(), &'static str> {
    let value = string(object, field)?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err("string_invalid");
    }
    Ok(())
}

fn optional_string(object: &JsonValue, field: &str) -> Result<(), &'static str> {
    match value(object, field)? {
        JsonValue::Null => Ok(()),
        JsonValue::String(value) if !value.is_empty() && value.len() <= 4096 => Ok(()),
        _ => Err("optional_string_invalid"),
    }
}

fn closed(value: &str, allowed: &[&str]) -> Result<(), &'static str> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err("closed_value_invalid")
    }
}

fn closed_array(
    object: &JsonValue,
    field: &str,
    allowed: &[&str],
    maximum: usize,
) -> Result<(), &'static str> {
    let values = array(object, field)?;
    if values.len() > maximum {
        return Err("array_too_large");
    }
    for value in values {
        let JsonValue::String(value) = value else {
            return Err("array_string_required");
        };
        closed(value, allowed)?;
    }
    Ok(())
}
