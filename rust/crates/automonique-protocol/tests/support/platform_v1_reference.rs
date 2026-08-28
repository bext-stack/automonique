// SPDX-License-Identifier: Elastic-2.0

//! Independent, strict decoder for the installed Platform v1 response surface.
//!
//! This module intentionally imports no `automonique_protocol` type. Its JSON
//! parser is a public third-party implementation and every Platform v1 field,
//! closed spelling, bound, and exact object shape used below is written here as
//! a reference-client rule rather than delegated to the server codec.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

const MAX_FRAME_BYTES: usize = 512 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_RESOURCES: usize = 512;
const MAX_METHODS: usize = 32;

const TRANSCRIPT_LABELS: [&str; 5] = ["capabilities", "receipt", "refusal", "sessions", "snapshot"];

const AUTHORITIES: [&str; 5] = [
    "ai_operations",
    "automonique",
    "github",
    "provider",
    "client",
];

const RESOURCE_KINDS: [&str; 17] = [
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

const METHODS: [&str; 16] = [
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

const ACTIONS: [&str; 9] = [
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

const OUTCOMES: [&str; 6] = [
    "accepted",
    "completed",
    "rejected",
    "conflict",
    "unknown",
    "resync_required",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    Capabilities,
    Snapshot,
    Sessions,
    Receipt,
    Refusal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedResponse {
    pub request_id: String,
    pub kind: ResponseKind,
}

pub fn transcript_corpus(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "corpus JSON is invalid")?;
    let entries = value.as_object().ok_or("corpus root must be an object")?;
    exact_fields(entries, &TRANSCRIPT_LABELS)?;
    entries
        .iter()
        .map(|(label, value)| {
            let transcript = value
                .as_str()
                .ok_or("every corpus entry must be a response string")?;
            Ok((label.clone(), transcript.as_bytes().to_vec()))
        })
        .collect()
}

pub fn decode_response(bytes: &[u8]) -> Result<DecodedResponse, String> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("response frame size is outside Platform v1 bounds".to_owned());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "response JSON is invalid")?;
    if serde_json::to_vec(&value).map_err(|_| "response JSON cannot be encoded")? != bytes {
        return Err("response is not canonical JSON".to_owned());
    }
    let envelope = value
        .as_object()
        .ok_or("response envelope must be an object")?;
    exact_fields(
        envelope,
        &["body", "kind", "protocol", "request_id", "version"],
    )?;
    if text(envelope, "protocol")? != "automonique.platform" {
        return Err("response protocol is not Platform v1".to_owned());
    }
    if integer(envelope, "version")? != 1 {
        return Err("response version is not Platform v1".to_owned());
    }
    let request_id = bounded(text(envelope, "request_id")?, MAX_REQUEST_ID_BYTES)?;
    let body = object(envelope, "body")?;
    let kind = match text(envelope, "kind")? {
        "capabilities_result" => {
            capabilities(body)?;
            ResponseKind::Capabilities
        }
        "snapshot_result" => {
            snapshot(body)?;
            ResponseKind::Snapshot
        }
        "sessions_result" => {
            sessions(body)?;
            ResponseKind::Sessions
        }
        "receipt_result" => {
            receipt(body)?;
            ResponseKind::Receipt
        }
        "refused" => {
            refusal(body)?;
            ResponseKind::Refusal
        }
        _ => return Err("response kind is outside the installed v1 reference surface".to_owned()),
    };
    Ok(DecodedResponse { request_id, kind })
}

fn capabilities(body: &Map<String, Value>) -> Result<(), String> {
    exact_fields(body, &["methods", "protocol", "schema", "transports"])?;
    if text(body, "protocol")? != "automonique.platform"
        || text(body, "schema")? != "automonique.platform/v1"
    {
        return Err("capability identity is not Platform v1".to_owned());
    }
    closed_array(body, "methods", &METHODS, MAX_METHODS)?;
    closed_array(
        body,
        "transports",
        &["local_unix", "remote_https", "remote_websocket"],
        3,
    )
}

fn snapshot(body: &Map<String, Value>) -> Result<(), String> {
    exact_fields(body, &["cursor", "resources"])?;
    cursor(object(body, "cursor")?)?;
    let resources = array(body, "resources")?;
    if resources.len() > MAX_RESOURCES {
        return Err("snapshot exceeds the v1 resource ceiling".to_owned());
    }
    resources.iter().try_for_each(record)
}

fn sessions(body: &Map<String, Value>) -> Result<(), String> {
    exact_fields(body, &["cursor", "sessions"])?;
    cursor(object(body, "cursor")?)?;
    let sessions = array(body, "sessions")?;
    if sessions.len() > MAX_RESOURCES {
        return Err("session page exceeds the v1 resource ceiling".to_owned());
    }
    sessions.iter().try_for_each(|value| {
        let session = value.as_object().ok_or("session entry must be an object")?;
        exact_fields(session, &["attachable", "controllable", "run", "session"])?;
        boolean(session, "attachable")?;
        boolean(session, "controllable")?;
        match session.get("run") {
            Some(Value::Null) => {}
            Some(Value::Object(value)) => coordinate(value)?,
            _ => return Err("session run must be a coordinate or null".to_owned()),
        }
        record(session.get("session").ok_or("session record is absent")?)
    })
}

fn receipt(body: &Map<String, Value>) -> Result<(), String> {
    exact_fields(
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
    closed(text(body, "action")?, &ACTIONS, "receipt action")?;
    optional_bounded(body, "explanation", MAX_FIELD_BYTES)?;
    bounded(text(body, "id")?, MAX_FIELD_BYTES)?;
    closed(text(body, "outcome")?, &OUTCOMES, "receipt outcome")?;
    integer(body, "recorded_at")?;
    positive_integer(body, "revision")?;
    coordinate(object(body, "target")?)
}

fn refusal(body: &Map<String, Value>) -> Result<(), String> {
    exact_fields(body, &["explanation", "outcome"])?;
    bounded(text(body, "explanation")?, MAX_FIELD_BYTES)?;
    closed(text(body, "outcome")?, &OUTCOMES, "refusal outcome")
}

fn cursor(value: &Map<String, Value>) -> Result<(), String> {
    exact_fields(value, &["authority", "sequence", "topic"])?;
    closed(text(value, "authority")?, &AUTHORITIES, "cursor authority")?;
    positive_integer(value, "sequence")?;
    bounded(text(value, "topic")?, MAX_FIELD_BYTES).map(|_| ())
}

fn record(value: &Value) -> Result<(), String> {
    let value = value
        .as_object()
        .ok_or("resource record must be an object")?;
    exact_fields(value, &["freshness", "resource", "summary"])?;
    freshness(object(value, "freshness")?)?;
    coordinate(object(value, "resource")?)?;
    bounded(text(value, "summary")?, MAX_FIELD_BYTES).map(|_| ())
}

fn freshness(value: &Map<String, Value>) -> Result<(), String> {
    exact_fields(value, &["observed_at", "revision", "state"])?;
    integer(value, "observed_at")?;
    positive_integer(value, "revision")?;
    closed(
        text(value, "state")?,
        &["fresh", "stale", "unknown"],
        "freshness state",
    )
}

fn coordinate(value: &Map<String, Value>) -> Result<(), String> {
    exact_fields(value, &["authority", "id", "kind"])?;
    closed(
        text(value, "authority")?,
        &AUTHORITIES,
        "resource authority",
    )?;
    bounded(text(value, "id")?, MAX_FIELD_BYTES)?;
    closed(text(value, "kind")?, &RESOURCE_KINDS, "resource kind")
}

fn exact_fields<const N: usize>(
    value: &Map<String, Value>,
    expected: &[&str; N],
) -> Result<(), String> {
    if value.len() != expected.len()
        || value
            .keys()
            .any(|field| !expected.contains(&field.as_str()))
    {
        return Err(format!(
            "object does not have the exact v1 fields {expected:?}"
        ));
    }
    Ok(())
}

fn text<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} must be a string"))
}

fn object<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{field} must be an object"))
}

fn array<'a>(value: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{field} must be an array"))
}

fn integer(value: &Map<String, Value>, field: &str) -> Result<i64, String> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{field} must be a signed 64-bit integer"))
}

fn positive_integer(value: &Map<String, Value>, field: &str) -> Result<(), String> {
    if integer(value, field)? <= 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn boolean(value: &Map<String, Value>, field: &str) -> Result<(), String> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .map(|_| ())
        .ok_or_else(|| format!("{field} must be a boolean"))
}

fn bounded(value: &str, max_bytes: usize) -> Result<String, String> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err("bounded v1 string is empty, oversized, or control-bearing".to_owned());
    }
    Ok(value.to_owned())
}

fn optional_bounded(
    value: &Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<(), String> {
    match value.get(field) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) => bounded(value, max_bytes).map(|_| ()),
        _ => Err(format!("{field} must be a bounded string or null")),
    }
}

fn closed(value: &str, allowed: &[&str], field: &str) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} is outside the closed v1 vocabulary"))
    }
}

fn closed_array(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
    max: usize,
) -> Result<(), String> {
    let entries = array(value, field)?;
    if entries.len() > max {
        return Err(format!("{field} exceeds its v1 ceiling"));
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = entry
            .as_str()
            .ok_or_else(|| format!("{field} entries must be strings"))?;
        closed(entry, allowed, field)?;
        if !seen.insert(entry) {
            return Err(format!("{field} contains a duplicate"));
        }
    }
    Ok(())
}
