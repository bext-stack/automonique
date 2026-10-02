// SPDX-License-Identifier: Elastic-2.0

//! The conversation behind one ticket, read through its source's MCP server.
//!
//! The dashboard's ticket list comes from a server's read-only list tool; the
//! drawer for one ticket asks the same configured server for that ticket's
//! thread. Only a discovered tool that advertises `readOnlyHint=true` and is
//! named like a ticket getter is ever called, the id argument is taken from
//! that tool's own input schema, and the answer is projected into a small,
//! bounded, typed view. Nothing the caller sends selects a URL, a tool, or an
//! argument name.

use automonique_daemon::mcp_client::{McpCallResult, McpFailure, McpRegistry, McpToolDescriptor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Serialized ceiling for one detail response.
pub(crate) const TICKET_DETAIL_RESPONSE_LIMIT: usize = 24 * 1024;
/// Characters kept from one message body.
const MESSAGE_BODY_LIMIT: usize = 4_000;
/// Messages read from a thread before projection; older ones are dropped.
const MESSAGE_SCAN_LIMIT: usize = 200;
const ID_LIMIT: usize = 120;
const SERVER_LIMIT: usize = 100;

/// Argument names a ticket getter may use for the id, most specific first.
const ID_ARGUMENTS: [&str; 7] = [
    "threadId",
    "thread_id",
    "ticketId",
    "ticket_id",
    "id",
    "reference",
    "number",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TicketDetailRequest {
    integration_server: String,
    id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TicketDetailFailure {
    /// The request named something this dashboard will not read.
    InvalidRequest,
    /// The getter exists but is not advertised as read-only, or it asked for
    /// input a read must never answer.
    Refused,
    NotFound,
    Unavailable,
}

impl TicketDetailFailure {
    pub(crate) const fn status(self) -> &'static str {
        match self {
            Self::InvalidRequest => "400 Bad Request",
            Self::Refused => "403 Forbidden",
            Self::NotFound => "404 Not Found",
            Self::Unavailable => "503 Service Unavailable",
        }
    }

    pub(crate) const fn category(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::Refused => "refused",
            Self::NotFound => "not_found",
            Self::Unavailable => "ticket_detail_unavailable",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct TicketDetailView {
    schema: &'static str,
    integration_server: String,
    id: String,
    source_tool: String,
    title: Option<String>,
    status: Option<String>,
    requester: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    /// Oldest first, newest last.
    messages: Vec<TicketMessageView>,
    messages_total: usize,
    /// Older messages were left out to keep the response bounded.
    truncated: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct TicketMessageView {
    author: Option<String>,
    at: Option<String>,
    body: String,
    body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internal: Option<bool>,
}

/// Accept only a configured server and a bounded, plain ticket id.
pub(crate) fn validate<'a>(
    request: &'a TicketDetailRequest,
    configured_servers: &[String],
) -> Result<(&'a str, &'a str), TicketDetailFailure> {
    let server = request.integration_server.as_str();
    let id = request.id.as_str();
    let server_ok = !server.is_empty()
        && server.len() <= SERVER_LIMIT
        && server
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && configured_servers.iter().any(|name| name == server);
    let id_ok = !id.is_empty()
        && id.len() <= ID_LIMIT
        && id != "unreferenced"
        && id.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'#' | b'_' | b'-' | b'.' | b':')
        });
    if server_ok && id_ok {
        Ok((server, id))
    } else {
        Err(TicketDetailFailure::InvalidRequest)
    }
}

/// The argument kind the getter's schema declares for its id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdKind {
    Text,
    Integer,
}

/// Choose the server's ticket getter and the name of its id argument.
///
/// A tool named like `*get_ticket*` that is not advertised read-only is
/// refused rather than skipped, so a server that only offers a mutating getter
/// says so instead of looking merely absent.
fn select_tool(
    tools: &[McpToolDescriptor],
) -> Result<(&McpToolDescriptor, String, IdKind), TicketDetailFailure> {
    let mut getters = tools
        .iter()
        .filter(|tool| tool.name.to_ascii_lowercase().contains("get_ticket"))
        .collect::<Vec<_>>();
    if getters.is_empty() {
        return Err(TicketDetailFailure::Unavailable);
    }
    getters.retain(|tool| tool.read_only);
    if getters.is_empty() {
        return Err(TicketDetailFailure::Refused);
    }
    getters.sort_by_key(|tool| (tool.name.len(), tool.name.as_str()));
    getters
        .into_iter()
        .find_map(|tool| id_argument(&tool.input_schema).map(|(name, kind)| (tool, name, kind)))
        .ok_or(TicketDetailFailure::Unavailable)
}

fn id_argument(schema: &Value) -> Option<(String, IdKind)> {
    let properties = schema.get("properties").and_then(Value::as_object);
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let name = match required.as_slice() {
        [only] => (*only).to_owned(),
        [] => ID_ARGUMENTS
            .iter()
            .find(|name| properties.is_some_and(|properties| properties.contains_key(**name)))?
            .to_string(),
        // A getter that needs more than the id cannot be filled honestly.
        _ => return None,
    };
    let kind = match properties
        .and_then(|properties| properties.get(&name))
        .and_then(|property| property.get("type"))
        .and_then(Value::as_str)
    {
        None | Some("string") => IdKind::Text,
        Some("integer" | "number") => IdKind::Integer,
        Some(_) => return None,
    };
    Some((name, kind))
}

/// Discover the server, select its read-only getter, and read one ticket.
pub(crate) fn fetch(
    mcp: &mut McpRegistry,
    server: &str,
    id: &str,
) -> Result<TicketDetailView, TicketDetailFailure> {
    let tools = mcp
        .discover_server(server)
        .map_err(|failure| match failure {
            McpFailure::NotAllowed => TicketDetailFailure::InvalidRequest,
            _ => TicketDetailFailure::Unavailable,
        })?;
    let (tool, argument, kind) = select_tool(&tools)?;
    // Re-checked at the call site: nothing below may run a mutating tool.
    if !tool.read_only {
        return Err(TicketDetailFailure::Refused);
    }
    let value = match kind {
        IdKind::Text => Value::String(id.to_owned()),
        IdKind::Integer => id
            .trim_start_matches('#')
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| TicketDetailFailure::NotFound)?,
    };
    let mut arguments = Map::new();
    arguments.insert(argument, value);
    match mcp.call(server, &tool.name, Value::Object(arguments), None) {
        Ok(McpCallResult::Complete {
            value,
            is_error: false,
        }) => project(&value, server, id, &tool.name).ok_or(TicketDetailFailure::NotFound),
        Ok(McpCallResult::Complete {
            value,
            is_error: true,
        }) => Err(if mentions_not_found(&value) {
            TicketDetailFailure::NotFound
        } else {
            TicketDetailFailure::Unavailable
        }),
        Ok(McpCallResult::InputRequired { .. }) => Err(TicketDetailFailure::Refused),
        Err(_) => Err(TicketDetailFailure::Unavailable),
    }
}

fn mentions_not_found(value: &Value) -> bool {
    let text = serde_json::to_string(value)
        .unwrap_or_default()
        .to_ascii_lowercase();
    text.contains("not found") || text.contains("not_found") || text.contains("404")
}

/// A tool without `structuredContent` returns its JSON as text content.
fn unwrap_text_content(value: &Value) -> Option<Value> {
    value
        .get("content")
        .and_then(Value::as_array)?
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .find_map(|text| serde_json::from_str::<Value>(text).ok())
        .filter(Value::is_object)
}

const MESSAGE_KEYS: [&str; 7] = [
    "messages",
    "entries",
    "posts",
    "conversation",
    "replies",
    "comments",
    "items",
];

fn message_array(object: &Map<String, Value>) -> Option<&Vec<Value>> {
    MESSAGE_KEYS.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_array)
            .filter(|items| items.iter().all(Value::is_object))
    })
}

/// Find the object that carries the thread: the one with a message list, or
/// failing that the first one with a title.
fn thread_object(value: &Value, depth: u8) -> Option<&Map<String, Value>> {
    if depth > 4 {
        return None;
    }
    let object = value.as_object()?;
    if message_array(object).is_some() {
        return Some(object);
    }
    ["thread", "ticket", "conversation", "data", "result", "item"]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(|child| thread_object(child, depth + 1))
        .or_else(|| {
            object
                .values()
                .filter(|child| child.is_object())
                .find_map(|child| thread_object(child, depth + 1))
        })
}

fn titled_object(value: &Value, depth: u8) -> Option<&Map<String, Value>> {
    if depth > 4 {
        return None;
    }
    let object = value.as_object()?;
    if text_field(object, &["subject", "title", "name"], 300).is_some() {
        return Some(object);
    }
    object
        .values()
        .filter(|child| child.is_object())
        .find_map(|child| titled_object(child, depth + 1))
}

fn bounded_text(value: &str, limit: usize) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| {
        trimmed
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
            .take(limit)
            .collect()
    })
}

fn text_field(object: &Map<String, Value>, keys: &[&str], limit: usize) -> Option<String> {
    keys.iter().find_map(|key| match object.get(*key) {
        Some(Value::String(value)) => bounded_text(value, limit),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    })
}

fn person_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match object.get(*key) {
        Some(Value::String(value)) => bounded_text(value, 120),
        Some(Value::Object(person)) => text_field(
            person,
            &[
                "name",
                "displayName",
                "display_name",
                "fullName",
                "full_name",
                "login",
                "email",
            ],
            120,
        ),
        _ => None,
    })
}

const TIME_KEYS: [&str; 8] = [
    "createdAt",
    "created_at",
    "sentAt",
    "sent_at",
    "date",
    "timestamp",
    "at",
    "time",
];

fn time_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    text_field(object, keys, 64)
}

/// Plain text from an HTML body: tags dropped, block ends kept as newlines.
fn html_text(value: &str) -> String {
    let mut output = String::new();
    let mut tag = String::new();
    let mut in_tag = false;
    for character in value.chars() {
        match (in_tag, character) {
            (false, '<') => {
                in_tag = true;
                tag.clear();
            }
            (true, '>') => {
                in_tag = false;
                let name = tag
                    .trim_start_matches('/')
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(name.as_str(), "br" | "p" | "div" | "li" | "tr")
                    && (name == "br" || tag.starts_with('/'))
                {
                    output.push('\n');
                }
            }
            (true, other) => tag.push(other),
            (false, other) => output.push(other),
        }
    }
    output
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn message_body(object: &Map<String, Value>) -> Option<(String, bool)> {
    let plain = [
        "body",
        "text",
        "content",
        "bodyText",
        "body_text",
        "plainText",
        "plain_text",
        "message",
        "snippet",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
    })
    .or_else(|| {
        ["html", "bodyHtml", "body_html", "htmlBody"]
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str))
            .map(html_text)
    })?;
    let trimmed = plain.trim();
    if trimmed.is_empty() {
        return None;
    }
    let total = trimmed.chars().count();
    let body = bounded_text(trimmed, MESSAGE_BODY_LIMIT)?;
    Some((body, total > MESSAGE_BODY_LIMIT))
}

fn message_direction(object: &Map<String, Value>) -> Option<&'static str> {
    let value = text_field(object, &["direction", "type", "kind", "role"], 40)?
        .to_ascii_lowercase()
        .replace('-', "_");
    match value.as_str() {
        "inbound" | "incoming" | "in" | "received" | "customer" | "user" => Some("inbound"),
        "outbound" | "outgoing" | "out" | "sent" | "reply" | "agent" | "staff" | "assistant" => {
            Some("outbound")
        }
        _ => None,
    }
}

fn message_internal(object: &Map<String, Value>) -> Option<bool> {
    [
        "internal",
        "isInternal",
        "is_internal",
        "private",
        "isPrivate",
        "is_private",
    ]
    .iter()
    .find_map(|key| object.get(*key).and_then(Value::as_bool))
    .or_else(|| {
        text_field(object, &["type", "kind", "visibility"], 40).and_then(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "note" | "internal" | "internal_note" | "private"
            )
            .then_some(true)
        })
    })
}

fn message_view(object: &Map<String, Value>) -> Option<TicketMessageView> {
    let (body, body_truncated) = message_body(object)?;
    Some(TicketMessageView {
        author: person_field(
            object,
            &[
                "author",
                "from",
                "sender",
                "user",
                "createdBy",
                "created_by",
                "authorName",
                "author_name",
                "fromName",
            ],
        ),
        at: time_field(object, &TIME_KEYS),
        body,
        body_truncated,
        direction: message_direction(object),
        internal: message_internal(object),
    })
}

/// Project a getter's answer into the bounded drawer view, or `None` when it
/// names neither a ticket nor a message.
pub(crate) fn project(
    value: &Value,
    server: &str,
    id: &str,
    source_tool: &str,
) -> Option<TicketDetailView> {
    let unwrapped;
    let value = if thread_object(value, 0).is_none() && titled_object(value, 0).is_none() {
        unwrapped = unwrap_text_content(value)?;
        &unwrapped
    } else {
        value
    };
    let thread = thread_object(value, 0).or_else(|| titled_object(value, 0))?;
    let title_source = if text_field(thread, &["subject", "title", "name"], 300).is_some() {
        thread
    } else {
        titled_object(value, 0).unwrap_or(thread)
    };
    let raw_messages = message_array(thread).map_or(&[][..], Vec::as_slice);
    let messages_total = raw_messages.len();
    let skip = messages_total.saturating_sub(MESSAGE_SCAN_LIMIT);
    let mut messages = raw_messages
        .iter()
        .filter_map(Value::as_object)
        .filter_map(message_view)
        .collect::<Vec<_>>();
    // Newest last, whichever order the source used. Times written in one
    // fixed-width format (ISO 8601 UTC, or epoch digits) order as text; any
    // other mix only decides between the source order and its reverse.
    let uniform_width = messages
        .first()
        .and_then(|message| message.at.as_deref())
        .map(str::len)
        .filter(|width| {
            messages
                .iter()
                .all(|message| message.at.as_deref().map(str::len) == Some(*width))
        });
    if uniform_width.is_some() {
        messages.sort_by(|left, right| left.at.cmp(&right.at));
    } else if let (Some(first), Some(last)) = (
        messages.first().and_then(|message| message.at.as_deref()),
        messages.last().and_then(|message| message.at.as_deref()),
    ) && first > last
    {
        messages.reverse();
    }
    let mut truncated = false;
    if skip > 0 {
        // The scan limit applies to the newest end of the thread.
        let keep = messages.len().saturating_sub(MESSAGE_SCAN_LIMIT);
        messages.drain(..keep);
        truncated = true;
    }
    let title = text_field(title_source, &["subject", "title", "name"], 300);
    if title.is_none() && messages.is_empty() {
        return None;
    }
    let mut view = TicketDetailView {
        schema: "automonique.dashboard.ticket-detail/v1",
        integration_server: server.to_owned(),
        id: id.to_owned(),
        source_tool: source_tool.to_owned(),
        title,
        status: text_field(thread, &["status", "state", "lifecycle"], 60)
            .map(|status| crate::normalized_ticket_status(Some(status))),
        requester: person_field(
            thread,
            &[
                "requester",
                "customer",
                "contact",
                "requestedBy",
                "requested_by",
                "from",
                "createdBy",
                "created_by",
            ],
        ),
        created_at: time_field(
            thread,
            &["createdAt", "created_at", "openedAt", "opened_at"],
        ),
        updated_at: time_field(
            thread,
            &[
                "updatedAt",
                "updated_at",
                "lastMessageAt",
                "last_message_at",
                "modifiedAt",
                "modified_at",
            ],
        ),
        messages,
        messages_total,
        truncated,
    };
    // Keep the newest messages that fit; the oldest go first.
    while serialized_len(&view) > TICKET_DETAIL_RESPONSE_LIMIT && !view.messages.is_empty() {
        let excess = serialized_len(&view) - TICKET_DETAIL_RESPONSE_LIMIT;
        let mut freed = 0;
        let mut drop = 0;
        for message in &view.messages {
            if freed >= excess || drop + 1 >= view.messages.len() {
                break;
            }
            freed += message.body.len() + 64;
            drop += 1;
        }
        view.messages.drain(..drop.max(1));
        view.truncated = true;
    }
    Some(view)
}

fn serialized_len(view: &TicketDetailView) -> usize {
    serde_json::to_vec(view).map_or(usize::MAX, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    fn tool(name: &str, read_only: bool, schema: Value) -> McpToolDescriptor {
        McpToolDescriptor {
            server: String::from("support"),
            name: name.to_owned(),
            description: String::new(),
            input_schema: schema,
            read_only,
        }
    }

    fn request(server: &str, id: &str) -> TicketDetailRequest {
        TicketDetailRequest {
            integration_server: server.to_owned(),
            id: id.to_owned(),
        }
    }

    /// Answer one HTTP request with `response` and return what was asked.
    fn serve_once(listener: &TcpListener, response: &str) -> String {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse::<usize>().unwrap();
            }
            head.push_str(&line);
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        let wire = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.len(),
            response
        );
        stream.write_all(wire.as_bytes()).unwrap();
        format!("{head}\n{}", String::from_utf8(body).unwrap())
    }

    fn registry_for(port: u16) -> (tempfile::TempDir, McpRegistry) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("mcp")).unwrap();
        let path = root.path().join("mcp/servers.json");
        fs::write(
            &path,
            format!(
                r#"{{"schema":"automonique.mcp-servers/v1","servers":[{{"name":"support","url":"http://127.0.0.1:{port}/api/mcp","token":"0123456789abcdef"}}]}}"#
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let registry = McpRegistry::load(root.path()).unwrap();
        (root, registry)
    }

    #[test]
    fn requests_name_only_a_configured_server_and_a_plain_bounded_id() {
        let configured = vec![String::from("support"), String::from("business")];
        assert_eq!(
            Ok(("support", "thr_01J.9:x-y")),
            validate(&request("support", "thr_01J.9:x-y"), &configured)
        );
        assert!(validate(&request("business", "#42"), &configured).is_ok());
        for (server, id) in [
            ("elsewhere", "thr_1"),
            ("", "thr_1"),
            ("support/../x", "thr_1"),
            ("support", ""),
            ("support", "unreferenced"),
            ("support", "---"),
            ("support", "thr 1"),
            ("support", "thr_1/../../admin"),
            ("support", "thr_1?x=1"),
            ("support", "<script>"),
            ("support", "é"),
        ] {
            assert_eq!(
                Err(TicketDetailFailure::InvalidRequest),
                validate(&request(server, id), &configured),
                "{server:?} {id:?}"
            );
        }
        let long = "a".repeat(ID_LIMIT + 1);
        assert!(validate(&request("support", &long), &configured).is_err());
        assert!(validate(&request("support", &long[..ID_LIMIT]), &configured).is_ok());
        assert!(
            serde_json::from_str::<TicketDetailRequest>(
                r#"{"integration_server":"support","id":"1","tool":"support_reply_to_ticket"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn failures_map_to_the_three_public_categories() {
        assert_eq!("refused", TicketDetailFailure::InvalidRequest.category());
        assert_eq!("refused", TicketDetailFailure::Refused.category());
        assert_eq!("not_found", TicketDetailFailure::NotFound.category());
        assert_eq!(
            "ticket_detail_unavailable",
            TicketDetailFailure::Unavailable.category()
        );
    }

    #[test]
    fn only_a_read_only_getter_is_selected_and_its_schema_names_the_id() {
        let schema = json!({
            "type": "object",
            "properties": { "threadId": { "type": "string" } },
            "required": ["threadId"]
        });
        let mutating = tool("support_get_ticket", false, schema.clone());
        assert_eq!(
            TicketDetailFailure::Refused,
            select_tool(std::slice::from_ref(&mutating)).unwrap_err()
        );
        assert_eq!(
            TicketDetailFailure::Unavailable,
            select_tool(&[tool("support_list_tickets", true, json!({}))]).unwrap_err()
        );
        let tools = [
            mutating,
            tool("support_reply_to_ticket", false, schema.clone()),
            tool("support_get_ticket", true, schema),
        ];
        let (selected, argument, kind) = select_tool(&tools).unwrap();
        assert!(selected.read_only);
        assert_eq!("support_get_ticket", selected.name);
        assert_eq!("threadId", argument);
        assert_eq!(IdKind::Text, kind);

        let optional = json!({ "properties": { "ticket_id": { "type": "integer" }, "limit": {} } });
        assert_eq!(
            Some((String::from("ticket_id"), IdKind::Integer)),
            id_argument(&optional)
        );
        assert_eq!(
            None,
            id_argument(&json!({ "required": ["threadId", "tenant"] }))
        );
        assert_eq!(
            None,
            id_argument(&json!({ "properties": { "query": { "type": "string" } } }))
        );
    }

    #[test]
    fn a_mutating_getter_is_refused_without_ever_being_called() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_root, mut registry) = registry_for(port);
        let server = std::thread::spawn(move || {
            let discovery = serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"support_get_ticket","inputSchema":{"type":"object","properties":{"threadId":{"type":"string"}},"required":["threadId"]},"annotations":{"readOnlyHint":false}}]}}"#,
            );
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            (discovery, listener.accept().is_err())
        });
        assert_eq!(
            TicketDetailFailure::Refused,
            fetch(&mut registry, "support", "thr_1").unwrap_err()
        );
        let (discovery, no_call) = server.join().unwrap();
        assert!(discovery.contains("\"tools/list\""));
        assert!(no_call, "a non-read-only getter must never be called");
    }

    #[test]
    fn the_read_only_getter_is_called_with_its_schema_argument_and_projected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_root, mut registry) = registry_for(port);
        let server = std::thread::spawn(move || {
            let discovery = serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
                    {"name":"support_list_tickets","annotations":{"readOnlyHint":true}},
                    {"name":"support_reply_to_ticket","inputSchema":{"type":"object","required":["threadId","text"]},"annotations":{"readOnlyHint":false}},
                    {"name":"support_get_ticket","inputSchema":{"type":"object","properties":{"threadId":{"type":"string"}},"required":["threadId"]},"annotations":{"readOnlyHint":true}}]}}"#,
            );
            let call = serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"thread":{
                    "id":"thr_1","subject":"Invoice missing","status":"open",
                    "customer":{"name":"Ada","email":"ada@example.test"},
                    "createdAt":"2026-09-01T08:00:00Z","updatedAt":"2026-09-02T09:00:00Z",
                    "messages":[
                      {"direction":"outbound","author":{"name":"Support"},"createdAt":"2026-09-02T09:00:00Z","body":"Sent again."},
                      {"direction":"inbound","from":"Ada","createdAt":"2026-09-01T08:00:00Z","html":"<p>Hello,</p><p>where is my <b>invoice</b>?</p>"},
                      {"type":"note","author":"Ben","createdAt":"2026-09-01T10:00:00Z","text":"Check billing","internal":true}
                    ]}}}}"#,
            );
            (discovery, call)
        });
        let view = fetch(&mut registry, "support", "thr_1").unwrap();
        let (_, call) = server.join().unwrap();
        let lower = call.to_ascii_lowercase();
        assert!(lower.contains("mcp-name: support_get_ticket"));
        assert!(lower.contains("mcp-protocol-version: 2026-07-28"));
        assert!(call.contains("\"io.modelcontextprotocol/protocolVersion\""));
        assert!(
            call.contains(r#""arguments":{"threadId":"thr_1"}"#),
            "{call}"
        );

        assert_eq!("support_get_ticket", view.source_tool);
        assert_eq!(Some("Invoice missing"), view.title.as_deref());
        assert_eq!(Some("open"), view.status.as_deref());
        assert_eq!(Some("Ada"), view.requester.as_deref());
        assert_eq!(Some("2026-09-01T08:00:00Z"), view.created_at.as_deref());
        assert_eq!(3, view.messages_total);
        assert!(!view.truncated);
        // Source order was newest first; the projection ends on the newest.
        assert_eq!(Some("Ben"), view.messages[1].author.as_deref());
        assert_eq!(Some(true), view.messages[1].internal);
        let last = view.messages.last().unwrap();
        assert_eq!("Sent again.", last.body);
        assert_eq!(Some("outbound"), last.direction);
        let first = &view.messages[0];
        assert_eq!(Some("inbound"), first.direction);
        assert_eq!("Hello,\nwhere is my invoice?", first.body);
    }

    #[test]
    fn an_error_result_naming_a_missing_thread_is_not_found() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_root, mut registry) = registry_for(port);
        let server = std::thread::spawn(move || {
            serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"support_get_ticket","inputSchema":{"type":"object","properties":{"threadId":{"type":"string"}}},"annotations":{"readOnlyHint":true}}]}}"#,
            );
            serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"Thread not found"}]}}"#,
            );
        });
        assert_eq!(
            TicketDetailFailure::NotFound,
            fetch(&mut registry, "support", "thr_missing").unwrap_err()
        );
        server.join().unwrap();
    }

    #[test]
    fn text_content_is_parsed_and_long_threads_keep_the_newest_messages_in_bounds() {
        let messages = (0..300)
            .map(|index| {
                json!({
                    "author": format!("Person {index}"),
                    "createdAt": format!("2026-09-01T{:02}:{:02}:00Z", index / 60, index % 60),
                    "body": format!("{index} {}", "x".repeat(5_000)),
                })
            })
            .collect::<Vec<_>>();
        let text = json!({ "subject": "Long", "messages": messages }).to_string();
        let value = json!({ "content": [{ "type": "text", "text": text }] });
        let view = project(&value, "support", "thr_1", "support_get_ticket").unwrap();
        assert_eq!(300, view.messages_total);
        assert!(view.truncated);
        assert!(!view.messages.is_empty());
        assert!(serde_json::to_vec(&view).unwrap().len() <= TICKET_DETAIL_RESPONSE_LIMIT);
        let last = view.messages.last().unwrap();
        assert_eq!(Some("Person 299"), last.author.as_deref());
        assert!(last.body_truncated);
        assert_eq!(MESSAGE_BODY_LIMIT, last.body.chars().count());

        assert!(project(&json!({}), "support", "x", "t").is_none());
        assert!(project(&json!({ "content": [] }), "support", "x", "t").is_none());
        let control = project(
            &json!({ "title": "T\u{0007}x", "messages": [{ "body": "a\u{0000}b\nc" }] }),
            "support",
            "x",
            "t",
        )
        .unwrap();
        assert_eq!(Some("Tx"), control.title.as_deref());
        assert_eq!("ab\nc", control.messages[0].body);
    }
}
