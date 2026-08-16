// SPDX-License-Identifier: Elastic-2.0

//! Strict MCP 2026-07-28 client used by the conversational control surface.
//!
//! Servers are operator-configured under the private daemon state directory.
//! Model output may select only a discovered server/tool pair; it never selects
//! a URL, bearer token, or HTTP header.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const CONFIG_RELATIVE: &str = "mcp/servers.json";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpToolDescriptor {
    pub server: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum McpCallResult {
    Complete { value: Value, is_error: bool },
    InputRequired { requests: Value },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpFailure {
    Configuration,
    Unavailable,
    Protocol,
    NotAllowed,
    Oversized,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    schema: String,
    servers: Vec<ServerConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    name: String,
    url: String,
    token: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

pub struct McpRegistry {
    agent: ureq::Agent,
    servers: Vec<ServerConfig>,
    discovered: BTreeMap<String, BTreeSet<String>>,
}

impl std::fmt::Debug for McpRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpRegistry")
            .field(
                "servers",
                &self
                    .servers
                    .iter()
                    .map(|server| &server.name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Default for McpRegistry {
    fn default() -> Self {
        Self::disabled()
    }
}

impl McpRegistry {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.servers.is_empty()
    }

    #[must_use]
    pub fn has_server(&self, name: &str) -> bool {
        self.servers.iter().any(|server| server.name == name)
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            agent: agent(),
            servers: Vec::new(),
            discovered: BTreeMap::new(),
        }
    }

    /// Load an optional owner-only configuration. Absence disables MCP;
    /// malformed, insecure, or present-but-empty configuration fails closed.
    pub fn load(state_dir: &Path) -> Result<Self, McpFailure> {
        let path = state_dir.join(CONFIG_RELATIVE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::disabled());
            }
            Err(_) => return Err(McpFailure::Configuration),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(McpFailure::Configuration);
        }
        let bytes = fs::read(&path).map_err(|_| McpFailure::Configuration)?;
        let config: FileConfig =
            serde_json::from_slice(&bytes).map_err(|_| McpFailure::Configuration)?;
        if config.schema != "automonique.mcp-servers/v1"
            || config.servers.is_empty()
            || config.servers.len() > 16
        {
            return Err(McpFailure::Configuration);
        }
        let mut names = BTreeSet::new();
        for server in &config.servers {
            if !valid_label(&server.name)
                || !names.insert(server.name.clone())
                || !valid_endpoint(&server.url)
                || server.token.len() < 16
                || server.token.len() > 4096
                || server.headers.len() > 16
            {
                return Err(McpFailure::Configuration);
            }
            if server
                .headers
                .iter()
                .any(|(name, value)| !valid_header(name, value))
            {
                return Err(McpFailure::Configuration);
            }
        }
        Ok(Self {
            agent: agent(),
            servers: config.servers,
            discovered: BTreeMap::new(),
        })
    }

    pub fn discover(&mut self) -> Result<Vec<McpToolDescriptor>, McpFailure> {
        let mut output = Vec::new();
        let mut discovered = BTreeMap::new();
        for server in &self.servers {
            let value = self.request(server, "tools/list", None, json!({}))?;
            let tools = value
                .pointer("/result/tools")
                .and_then(Value::as_array)
                .ok_or(McpFailure::Protocol)?;
            let mut names = BTreeSet::new();
            for tool in tools.iter().take(256) {
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| valid_label(name))
                    .ok_or(McpFailure::Protocol)?;
                if !names.insert(name.to_owned()) {
                    return Err(McpFailure::Protocol);
                }
                output.push(McpToolDescriptor {
                    server: server.name.clone(),
                    name: name.to_owned(),
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .chars()
                        .take(500)
                        .collect(),
                });
            }
            discovered.insert(server.name.clone(), names);
        }
        self.discovered = discovered;
        Ok(output)
    }

    pub fn call(
        &self,
        server_name: &str,
        tool: &str,
        arguments: Value,
        input_responses: Option<Value>,
    ) -> Result<McpCallResult, McpFailure> {
        if !self
            .discovered
            .get(server_name)
            .is_some_and(|tools| tools.contains(tool))
        {
            return Err(McpFailure::NotAllowed);
        }
        let server = self
            .servers
            .iter()
            .find(|server| server.name == server_name)
            .ok_or(McpFailure::NotAllowed)?;
        let mut params = json!({ "name": tool, "arguments": arguments });
        if let Some(responses) = input_responses {
            params["inputResponses"] = responses;
        }
        let value = self.request(server, "tools/call", Some(tool), params)?;
        let result = value.get("result").ok_or(McpFailure::Protocol)?;
        match result.get("resultType").and_then(Value::as_str) {
            Some("input_required") => Ok(McpCallResult::InputRequired {
                requests: result
                    .get("inputRequests")
                    .cloned()
                    .ok_or(McpFailure::Protocol)?,
            }),
            Some("complete") | None => Ok(McpCallResult::Complete {
                value: result
                    .get("structuredContent")
                    .cloned()
                    .unwrap_or_else(|| result.clone()),
                is_error: result
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
            _ => Err(McpFailure::Protocol),
        }
    }

    fn request(
        &self,
        server: &ServerConfig,
        method: &str,
        tool: Option<&str>,
        mut params: Value,
    ) -> Result<Value, McpFailure> {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": { "name": "automonique", "version": env!("CARGO_PKG_VERSION") },
            "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "form": {} } }
        });
        let body = serde_json::to_vec(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
        )
        .map_err(|_| McpFailure::Protocol)?;
        let mut request = self
            .agent
            .post(&server.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("authorization", &format!("Bearer {}", server.token))
            .header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
            .header("MCP-Method", method);
        if let Some(tool) = tool {
            request = request.header("MCP-Name", tool);
        }
        for (name, value) in &server.headers {
            request = request.header(name, value);
        }
        let mut response = request
            .config()
            .timeout_global(Some(Duration::from_secs(8)))
            .build()
            .send(&body)
            .map_err(|_| McpFailure::Unavailable)?;
        if response.status().as_u16() != 200 {
            return Err(McpFailure::Unavailable);
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit((MAX_RESPONSE_BYTES + 1) as u64)
            .reader()
            .read_to_end(&mut bytes)
            .map_err(|_| McpFailure::Unavailable)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(McpFailure::Oversized);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| McpFailure::Protocol)?;
        if value.get("error").is_some() {
            return Err(McpFailure::Protocol);
        }
        Ok(value)
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(false)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent()
}
fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
fn valid_endpoint(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://[::1]:")
}
fn valid_header(name: &str, value: &str) -> bool {
    !name.eq_ignore_ascii_case("authorization")
        && name.to_ascii_lowercase().starts_with("mcp-")
        && valid_label(name)
        && !value.is_empty()
        && value.len() <= 500
        && !value.contains(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

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

    #[test]
    fn absent_configuration_disables_without_a_client_surface() {
        let root = tempfile::tempdir().unwrap();
        let registry = McpRegistry::load(root.path()).unwrap();
        assert!(registry.servers.is_empty());
    }

    #[test]
    fn configuration_rejects_model_controllable_headers_and_plain_remote_http() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("mcp")).unwrap();
        let path = root.path().join(CONFIG_RELATIVE);
        fs::write(&path, br#"{"schema":"automonique.mcp-servers/v1","servers":[{"name":"support","url":"http://example.test/api/mcp","token":"0123456789abcdef","headers":{"Authorization":"oops"}}]}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            McpRegistry::load(root.path()),
            Err(McpFailure::Configuration)
        ));
    }

    #[test]
    fn discovery_binds_calls_and_decodes_input_required() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let discovery = serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"support_reply_to_ticket","description":"Reply"}]}}"#,
            );
            let call = serve_once(
                &listener,
                r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":{"confirm":{"type":"elicitation","params":{"message":"Send it?"}}}}}"#,
            );
            (discovery, call)
        });
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("mcp")).unwrap();
        let path = root.path().join(CONFIG_RELATIVE);
        fs::write(&path, format!(r#"{{"schema":"automonique.mcp-servers/v1","servers":[{{"name":"support","url":"http://127.0.0.1:{}/api/mcp","token":"0123456789abcdef","headers":{{"MCP-Tenant-ID":"tenant-1"}}}}]}}"#, address.port())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut registry = McpRegistry::load(root.path()).unwrap();
        let tools = registry.discover().unwrap();
        assert_eq!(tools[0].name, "support_reply_to_ticket");
        let result = registry
            .call(
                "support",
                "support_reply_to_ticket",
                json!({ "threadId": "thr_1", "text": "Hello" }),
                None,
            )
            .unwrap();
        assert!(matches!(result, McpCallResult::InputRequired { .. }));
        let (discovery, call) = server.join().unwrap();
        assert!(
            discovery
                .to_ascii_lowercase()
                .contains("mcp-protocol-version: 2026-07-28")
        );
        assert!(
            call.to_ascii_lowercase()
                .contains("mcp-name: support_reply_to_ticket")
        );
        assert!(call.contains("\"io.modelcontextprotocol/clientCapabilities\""));
    }
}
