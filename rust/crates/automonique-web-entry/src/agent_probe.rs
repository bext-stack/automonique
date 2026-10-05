// SPDX-License-Identifier: Elastic-2.0
use super::*;
use serde_json::json;
#[path = "agent_probe_codex.rs"]
mod codex;

const PROMPT: &str = "This is a connection test. Reply with exactly MONIQUE_OK. Do not use any tools or read any files.";
const TIMEOUT: Duration = Duration::from_secs(45);

impl AgentAuthManager {
    pub(super) fn test_response(&self, id: &str) -> Result<(), &'static str> {
        let registry = self.read_registry()?;
        let account = registry
            .accounts
            .iter()
            .find(|a| a.id == id)
            .ok_or("agent_account_not_found")?;
        let provider = Provider::parse(&account.provider).ok_or("agent_accounts_invalid")?;
        let health = self.read_health(account).ok_or("agent_sign_in_required")?;
        if !matches!(
            health.status.as_str(),
            "authenticated" | "configured_unverified"
        ) {
            return Err("agent_sign_in_required");
        }
        let mut tests = self.response_tests.lock().map_err(|_| "agent_test_busy")?;
        if tests.values().any(|v| v["status"] == "checking") {
            return Err("agent_test_busy");
        }
        let work = self.config.root.join("response-test-workspace");
        ensure_private_directory(&work)?;
        let profile = self.profile_path(id)?;
        let binary = self.binary(provider).to_path_buf();
        tests.retain(|key, _| registry.accounts.iter().any(|account| &account.id == key));
        tests.insert(
            id.to_owned(),
            json!({"status":"checking","started_at_ms":now_ms()}),
        );
        let id = id.to_owned();
        let failure_id = id.clone();
        let cache = Arc::clone(&self.response_tests);
        let spawned = thread::Builder::new()
            .name("agent-response-test".into())
            .spawn(move || {
                let started = Instant::now();
                let mut report = if provider == Provider::Codex {
                    codex::run(&binary, &profile, &work)
                } else {
                    let mut command = claude_command(&binary, &profile, &work);
                    match bounded_provider_call(&mut command, TIMEOUT) {
                        Some(call) => decode_claude(&call),
                        None => json!({"status":"failed","reason":"timed_out"}),
                    }
                };
                report["checked_at_ms"] = json!(now_ms());
                report["duration_ms"] = json!(started.elapsed().as_millis() as u64);
                if let Ok(mut tests) = cache.lock() {
                    tests.insert(id, report);
                }
            });
        if spawned.is_err() {
            tests.remove(&failure_id);
            return Err("agent_test_unavailable");
        }
        Ok(())
    }
}
fn claude_command(binary: &Path, profile: &Path, work: &Path) -> Command {
    let mut command = provider_command(Provider::Claude, binary, profile);
    command.current_dir(work).args([
        "--print",
        "--output-format",
        "json",
        "--no-session-persistence",
        "--safe-mode",
        "--restricted",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        "{\"mcpServers\":{}}",
        "--setting-sources",
        "",
        "--system-prompt",
        "Reply to the connection test without using tools.",
        PROMPT,
    ]);
    command
}
fn safe_model(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/')))
    .then(|| value.to_owned())
}
fn decode_claude(call: &BoundedCall) -> Value {
    let stdout = String::from_utf8_lossy(&call.stdout);
    let stderr = String::from_utf8_lossy(&call.stderr);
    let value = serde_json::from_str::<Value>(&stdout).unwrap_or(Value::Null);
    let answered = value["result"]
        .as_str()
        .is_some_and(|text| text.trim() == "MONIQUE_OK");
    let completed = value["is_error"] == false && value["type"] == "result";
    let model = value["modelUsage"]
        .as_object()
        .and_then(|models| models.keys().next())
        .and_then(|name| safe_model(name));
    let ok = call.success && completed && answered;
    let text = format!("{stdout}\n{stderr}").to_lowercase();
    let reason = if ok {
        "response_verified"
    } else if text.contains("rate limit") || text.contains("usage limit") || text.contains("quota")
    {
        "quota_limited"
    } else if text.contains("unauthorized")
        || text.contains("not logged in")
        || text.contains("authentication")
        || text.contains("401")
    {
        "sign_in_required"
    } else {
        "response_failed"
    };
    json!({"status":if ok{"verified"}else{"failed"},"reason":reason,"model":model})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn success_requires_completed_turn_and_fixed_response() {
        let call=BoundedCall {success:true,stdout:br#"{"type":"result","is_error":false,"result":"MONIQUE_OK","modelUsage":{"test-model":{}}}"#.to_vec(),stderr:vec![]};
        assert_eq!(decode_claude(&call)["status"], "verified");
        assert_eq!(decode_claude(&call)["model"], "test-model");
        assert_eq!(
            decode_claude(&BoundedCall {
                success: false,
                ..call
            })["status"],
            "failed"
        );
        let result = decode_claude(&BoundedCall {
            success: false,
            stdout: vec![],
            stderr: b"401 private-credential".to_vec(),
        });
        assert_eq!(result["reason"], "sign_in_required");
        assert!(!result.to_string().contains("private-credential"));
    }
    #[test]
    fn claude_probe_disables_tools_and_isolates_working_directory() {
        let command = claude_command(
            Path::new("/bin/test"),
            Path::new("/tmp/profile"),
            Path::new("/tmp/work"),
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/tmp/work")));
        let args = command
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.contains(&PROMPT.to_owned()));
        assert!(args.windows(2).any(|pair| pair == ["--tools", ""]));
        assert!(args.contains(&"--safe-mode".to_owned()));
    }
}
