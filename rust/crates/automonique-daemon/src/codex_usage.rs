// SPDX-License-Identifier: Elastic-2.0

//! Read-only Codex account rate-limit projection.
//!
//! The configured Codex executable already owns the provider session. This
//! adapter asks its pinned app-server protocol for `account/rateLimits/read`;
//! it never opens or parses an authentication file and never returns account
//! identity or credential material to the caller.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

use crate::compose::{PROVIDER_CONFIG_NAME, ProviderConfig};

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexUsageWindow {
    pub limit_id: String,
    pub limit_name: Option<String>,
    pub used_percent: u8,
    pub window_duration_minutes: Option<u64>,
    pub resets_at_unix_seconds: Option<i64>,
}

impl CodexUsageWindow {
    #[must_use]
    pub const fn remaining_percent(&self) -> u8 {
        100_u8.saturating_sub(self.used_percent)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexUsageSnapshot {
    pub windows: Vec<CodexUsageWindow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexUsageUnavailable {
    NotConfigured,
    ConfigurationRefused,
    ProviderRefused,
    TimedOut,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexUsageRead {
    Available(CodexUsageSnapshot),
    Unavailable(CodexUsageUnavailable),
}

#[must_use]
pub fn configured_usage(state_dir: &std::path::Path) -> CodexUsageRead {
    let provider = match ProviderConfig::load(&state_dir.join(PROVIDER_CONFIG_NAME)) {
        Ok(Some(provider)) => provider,
        Ok(None) => return CodexUsageRead::Unavailable(CodexUsageUnavailable::NotConfigured),
        Err(_) => {
            return CodexUsageRead::Unavailable(CodexUsageUnavailable::ConfigurationRefused);
        }
    };
    read_usage(&provider)
}

fn read_usage(provider: &ProviderConfig) -> CodexUsageRead {
    let mut child = match Command::new(provider.binary())
        .args(["app-server", "--stdio"])
        .env("CODEX_HOME", provider.home())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused),
    };

    let request = concat!(
        "{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"automonique\",\"version\":\"0.1.0\"}}}\n",
        "{\"method\":\"initialized\"}\n",
        "{\"id\":2,\"method\":\"account/rateLimits/read\",\"params\":null}\n"
    );
    let wrote = child
        .stdin
        .take()
        .ok_or(())
        .and_then(|mut stdin| stdin.write_all(request.as_bytes()).map_err(|_| ()))
        .is_ok();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused);
    };
    if !wrote {
        let _ = child.kill();
        let _ = child.wait();
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused);
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name(String::from("automonique-codex-usage-read"))
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) if line.len() > MAX_RESPONSE_LINE_BYTES => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) => {
                        let Ok(value) = serde_json::from_str::<Value>(&line) else {
                            continue;
                        };
                        if value.get("id").and_then(Value::as_u64) == Some(2) {
                            let _ = sender.send(Some(value));
                            return;
                        }
                    }
                }
            }
        });
    let result = match receiver.recv_timeout(READ_TIMEOUT) {
        Ok(Some(value)) => decode_response(&value),
        Ok(None) => CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            CodexUsageRead::Unavailable(CodexUsageUnavailable::TimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused)
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(reader) = reader {
        let _ = reader.join();
    }
    result
}

fn decode_response(value: &Value) -> CodexUsageRead {
    let Some(result) = value.get("result").and_then(Value::as_object) else {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
    };
    let mut windows = Vec::new();
    if let Some(by_id) = result.get("rateLimitsByLimitId").and_then(Value::as_object) {
        for (id, snapshot) in by_id {
            windows.extend(decode_windows(id, snapshot));
        }
    } else if let Some(snapshot) = result.get("rateLimits") {
        windows.extend(decode_windows("codex", snapshot));
    }
    if windows.is_empty() {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
    }
    windows.sort_by(|left, right| {
        (
            left.limit_id != "codex",
            left.limit_id.as_str(),
            left.window_duration_minutes,
        )
            .cmp(&(
                right.limit_id != "codex",
                right.limit_id.as_str(),
                right.window_duration_minutes,
            ))
    });
    CodexUsageRead::Available(CodexUsageSnapshot { windows })
}

fn decode_windows(fallback_id: &str, value: &Value) -> Vec<CodexUsageWindow> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let limit_id = object
        .get("limitId")
        .and_then(Value::as_str)
        .unwrap_or(fallback_id);
    if !safe_label(limit_id) {
        return Vec::new();
    }
    let limit_name = object
        .get("limitName")
        .and_then(Value::as_str)
        .filter(|value| safe_label(value))
        .map(str::to_owned);
    ["primary", "secondary"]
        .into_iter()
        .filter_map(|field| object.get(field).and_then(Value::as_object))
        .filter_map(|window| {
            let used_percent = u8::try_from(window.get("usedPercent")?.as_u64()?).ok()?;
            (used_percent <= 100).then(|| CodexUsageWindow {
                limit_id: limit_id.to_owned(),
                limit_name: limit_name.clone(),
                used_percent,
                window_duration_minutes: window.get("windowDurationMins").and_then(Value::as_u64),
                resets_at_unix_seconds: window.get("resetsAt").and_then(Value::as_i64),
            })
        })
        .collect()
}

fn safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rate_limit_response_decodes_without_account_identity() {
        let value = serde_json::json!({
            "id": 2,
            "result": {
                "rateLimitsByLimitId": {
                    "codex": {
                        "limitId": "codex",
                        "primary": {
                            "usedPercent": 64,
                            "windowDurationMins": 10080,
                            "resetsAt": 1787211765
                        },
                        "secondary": {
                            "usedPercent": 12,
                            "windowDurationMins": 300,
                            "resetsAt": 1786752000
                        }
                    },
                    "codex_bengalfox": {
                        "limitId": "codex_bengalfox",
                        "limitName": "GPT-5.3-Codex-Spark",
                        "primary": {"usedPercent": 0}
                    }
                }
            }
        });
        let CodexUsageRead::Available(snapshot) = decode_response(&value) else {
            panic!("usage response must decode");
        };
        assert_eq!(snapshot.windows.len(), 3);
        assert_eq!(snapshot.windows[0].remaining_percent(), 88);
        assert_eq!(snapshot.windows[0].window_duration_minutes, Some(300));
        assert_eq!(snapshot.windows[1].remaining_percent(), 36);
        assert_eq!(snapshot.windows[1].window_duration_minutes, Some(10_080));
        assert_eq!(snapshot.windows[2].remaining_percent(), 100);
    }

    #[test]
    fn impossible_or_unbounded_fields_are_refused() {
        let value = serde_json::json!({
            "id": 2,
            "result": {"rateLimits": {"primary": {"usedPercent": 101}}}
        });
        assert_eq!(
            decode_response(&value),
            CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse)
        );
    }
}
