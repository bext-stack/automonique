// SPDX-License-Identifier: Elastic-2.0

//! Read-only Codex account rate-limit projection.
//!
//! The configured execution engine already owns the provider session. This
//! adapter asks either Codex App Server or JCode's read-only usage command for
//! the OpenAI subscription windows; it never opens or parses an authentication
//! file and never returns account identity or credential material to the
//! caller.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

use crate::compose::{PROVIDER_CONFIG_NAME, ProviderConfig, ProviderEngine};

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_LINE_BYTES: usize = 64 * 1024;
const MAX_JCODE_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_JCODE_PROVIDERS: usize = 32;
const MAX_JCODE_LIMITS: usize = 32;

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
    match provider.engine() {
        ProviderEngine::Codex => read_codex_usage(&provider),
        ProviderEngine::Jcode => read_jcode_usage(&provider),
    }
}

fn read_codex_usage(provider: &ProviderConfig) -> CodexUsageRead {
    let mut child = match Command::new(provider.binary())
        .args(["app-server", "--stdio"])
        .env_clear()
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

fn read_jcode_usage(provider: &ProviderConfig) -> CodexUsageRead {
    let mut child = match Command::new(provider.binary())
        .args(["--quiet", "--no-update", "--no-selfdev", "usage", "--json"])
        .env_clear()
        .env("JCODE_HOME", provider.home())
        .env("JCODE_RUNTIME_DIR", provider.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused),
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::ProviderRefused);
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name(String::from("automonique-jcode-usage-read"))
        .spawn(move || {
            let mut reader = BufReader::new(stdout).take(
                u64::try_from(MAX_JCODE_RESPONSE_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            let mut bytes = Vec::new();
            let result = reader
                .read_to_end(&mut bytes)
                .ok()
                .filter(|_| bytes.len() <= MAX_JCODE_RESPONSE_BYTES)
                .and_then(|_| serde_json::from_slice::<Value>(&bytes).ok());
            let _ = sender.send(result);
        });
    let result = match receiver.recv_timeout(READ_TIMEOUT) {
        Ok(Some(value)) => decode_jcode_response(&value),
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

fn decode_jcode_response(value: &Value) -> CodexUsageRead {
    let Some(providers) = value.get("providers").and_then(Value::as_array) else {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
    };
    if providers.len() > MAX_JCODE_PROVIDERS {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
    }
    let mut windows = Vec::new();
    let mut openai_accounts = 0_usize;
    for provider in providers {
        let Some(provider) = provider.as_object() else {
            return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
        };
        let Some(provider_name) = provider.get("provider_name").and_then(Value::as_str) else {
            return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
        };
        // JCode's display label may carry a masked account hint. It is used
        // only to select the OpenAI subscription report and never leaves this
        // function.
        if provider_name != "OpenAI (ChatGPT)" && !provider_name.starts_with("OpenAI (ChatGPT) (") {
            continue;
        }
        openai_accounts = openai_accounts.saturating_add(1);
        if !provider.get("error").is_none_or(Value::is_null) {
            continue;
        }
        let Some(limits) = provider.get("limits").and_then(Value::as_array) else {
            return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
        };
        if limits.len() > MAX_JCODE_LIMITS {
            return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
        }
        for (limit_index, limit) in limits.iter().enumerate() {
            let Some(limit) = limit.as_object() else {
                return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
            };
            let Some(name) = limit
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| safe_display_label(name))
            else {
                return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
            };
            let Some(percent) = limit.get("usage_percent").and_then(Value::as_f64) else {
                return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
            };
            if !percent.is_finite() || !(0.0..=100.0).contains(&percent) {
                return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
            }
            windows.push(CodexUsageWindow {
                limit_id: format!("openai-{openai_accounts}-{}", limit_index + 1),
                limit_name: Some(name.to_owned()),
                used_percent: percent.round() as u8,
                window_duration_minutes: jcode_window_duration(name),
                // JCode supplies an RFC 3339 display timestamp. Keeping it
                // out of this older Unix-time projection is preferable to a
                // locale-dependent or lossy conversion.
                resets_at_unix_seconds: None,
            });
        }
    }
    if openai_accounts == 0 {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::NotConfigured);
    }
    if windows.is_empty() {
        return CodexUsageRead::Unavailable(CodexUsageUnavailable::InvalidResponse);
    }
    CodexUsageRead::Available(CodexUsageSnapshot { windows })
}

fn safe_display_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 80 && !value.chars().any(char::is_control)
}

fn jcode_window_duration(name: &str) -> Option<u64> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("7-day") || lower.contains("(7d)") || lower.contains("weekly") {
        Some(10_080)
    } else if lower.contains("(5h)") || lower.contains("5-hour") {
        Some(300)
    } else {
        None
    }
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

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

    #[test]
    fn jcode_usage_selects_openai_without_projecting_account_identity() {
        let value = serde_json::json!({
            "providers": [
                {
                    "provider_name": "Anthropic (Claude) (masked-account)",
                    "limits": [{"name": "5-hour window", "usage_percent": 99.0}],
                    "extra_info": [],
                    "error": null
                },
                {
                    "provider_name": "OpenAI (ChatGPT) (masked-account)",
                    "limits": [
                        {
                            "name": "7-day window",
                            "usage_percent": 62.4,
                            "resets_at": "2026-08-27T13:30:40+00:00",
                            "reset_in": "3d 20h"
                        },
                        {
                            "name": "GPT-5.3-Codex-Spark (5h)",
                            "usage_percent": 0.0,
                            "resets_at": null,
                            "reset_in": null
                        }
                    ],
                    "extra_info": [["account", "must-not-cross"]],
                    "error": null
                }
            ]
        });
        let CodexUsageRead::Available(snapshot) = decode_jcode_response(&value) else {
            panic!("JCode usage must decode");
        };
        assert_eq!(snapshot.windows.len(), 2);
        assert_eq!(snapshot.windows[0].limit_id, "openai-1-1");
        assert_eq!(
            snapshot.windows[0].limit_name.as_deref(),
            Some("7-day window")
        );
        assert_eq!(snapshot.windows[0].used_percent, 62);
        assert_eq!(snapshot.windows[0].window_duration_minutes, Some(10_080));
        assert_eq!(snapshot.windows[1].window_duration_minutes, Some(300));
        assert!(!format!("{snapshot:?}").contains("masked-account"));
        assert!(!format!("{snapshot:?}").contains("must-not-cross"));
    }

    #[test]
    fn configured_jcode_usage_runs_the_pinned_read_only_command() {
        let root = tempfile::tempdir().expect("root");
        let home = root.path().join("jcode-home");
        fs::create_dir(&home).expect("home");
        let binary = root.path().join("fake-jcode");
        fs::write(
            &binary,
            concat!(
                "#!/bin/sh\n",
                "printf '%s' \"$*\" > \"$JCODE_HOME/invocation\"\n",
                "test \"$JCODE_RUNTIME_DIR\" = \"$JCODE_HOME\" || exit 9\n",
                "printf '%s\\n' '{\"providers\":[{\"provider_name\":\"OpenAI (ChatGPT) (private)\",\"limits\":[{\"name\":\"7-day window\",\"usage_percent\":25.0,\"resets_at\":null,\"reset_in\":null}],\"extra_info\":[],\"error\":null}]}'\n",
            ),
        )
        .expect("fixture provider");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).expect("executable");
        let config = root.path().join(PROVIDER_CONFIG_NAME);
        fs::write(
            &config,
            format!(
                "engine=jcode\nbinary={}\nhome={}\nversion=jcode-fixture\narg=api-stdio\n",
                binary.display(),
                home.display(),
            ),
        )
        .expect("provider config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("private config");

        let CodexUsageRead::Available(snapshot) = configured_usage(root.path()) else {
            panic!("configured JCode usage must be available");
        };
        assert_eq!(snapshot.windows[0].remaining_percent(), 75);
        assert_eq!(
            fs::read_to_string(home.join("invocation")).expect("invocation"),
            "--quiet --no-update --no-selfdev usage --json"
        );
    }
}
