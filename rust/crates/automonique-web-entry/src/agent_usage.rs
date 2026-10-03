// SPDX-License-Identifier: Elastic-2.0

//! Secret-free, per-profile subscription quotas. Provider IO never occupies a
//! dashboard request thread. One batch at a time, with a five-minute cooldown
//! on successes AND failures (including provider throttling).

use super::{AccountView, AgentAuthConfig, now_ms, read_private_file};
use automonique_daemon::codex_usage::{self, CodexUsageRead, CodexUsageUnavailable};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const CACHE_MS: u64 = 300_000;

#[derive(Clone, Debug, Serialize)]
pub(super) struct UsageWindow {
    name: String,
    used_percent: f64,
    duration_minutes: Option<u64>,
    resets_at_ms: Option<u64>,
    resets_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct UsageView {
    status: &'static str,
    reason: Option<&'static str>,
    checked_at_ms: Option<u64>,
    refresh_after_ms: Option<u64>,
    windows: Vec<UsageWindow>,
}

impl UsageView {
    pub(super) fn unavailable(reason: &'static str) -> Self {
        Self {
            status: "unavailable",
            reason: Some(reason),
            checked_at_ms: None,
            refresh_after_ms: None,
            windows: Vec::new(),
        }
    }
}

#[derive(Default)]
pub(super) struct UsageCache {
    entries: BTreeMap<String, UsageView>,
    running: bool,
}

pub(super) fn project(
    config: &AgentAuthConfig,
    cache: &Arc<Mutex<UsageCache>>,
    accounts: &mut [AccountView],
) -> Result<(), &'static str> {
    let now = now_ms();
    let mut state = cache.lock().map_err(|_| "agent_auth_busy")?;
    // A sign-out, removal, or new login invalidates cached usage. An in-flight
    // result is only accepted if its original loading entry still exists.
    state
        .entries
        .retain(|id, _| accounts.iter().any(|a| &a.id == id && connected(a)));
    let mut jobs = Vec::new();
    if !state.running {
        for account in accounts.iter().filter(|a| connected(a)) {
            let entry = state
                .entries
                .entry(account.id.clone())
                .or_insert_with(|| UsageView::unavailable("not_checked"));
            if entry.refresh_after_ms.is_none_or(|next| now >= next) {
                entry.status = "loading";
                entry.reason = None;
                entry.refresh_after_ms = Some(now + CACHE_MS);
                jobs.push((account.id.clone(), account.provider.clone()));
            }
        }
    }
    for account in accounts {
        account.usage = if connected(account) {
            state
                .entries
                .get(&account.id)
                .cloned()
                .unwrap_or_else(|| UsageView {
                    status: "loading",
                    ..UsageView::unavailable("not_checked")
                })
        } else {
            UsageView::unavailable("sign_in_required")
        };
    }
    if jobs.is_empty() {
        return Ok(());
    }
    state.running = true;
    drop(state);
    let config = config.clone();
    let cache = Arc::clone(cache);
    let recovery = Arc::clone(&cache);
    let spawned = std::thread::Builder::new()
        .name("account-usage".into())
        .spawn(move || {
            for (id, provider) in jobs {
                let profile = config.root.join("profiles").join(&id);
                let result = if provider == "codex" {
                    read_codex(&config.codex_binary, &profile)
                } else {
                    read_claude(&profile)
                };
                if let Ok(mut state) = cache.lock() {
                    if let Some(entry) = state.entries.get_mut(&id).filter(|entry| {
                        entry.status == "loading" && entry.refresh_after_ms == Some(now + CACHE_MS)
                    }) {
                        apply_result(entry, result, now_ms());
                    }
                }
            }
            if let Ok(mut state) = cache.lock() {
                state.running = false;
            }
        });
    if spawned.is_err() {
        if let Ok(mut state) = recovery.lock() {
            state.running = false;
            for entry in state
                .entries
                .values_mut()
                .filter(|entry| entry.status == "loading")
            {
                apply_result(entry, Err("provider_unavailable"), now_ms());
            }
        }
    }
    Ok(())
}

fn connected(account: &AccountView) -> bool {
    matches!(
        account.status.as_str(),
        "authenticated" | "configured_unverified"
    )
}

fn apply_result(entry: &mut UsageView, result: Result<Vec<UsageWindow>, &'static str>, now: u64) {
    entry.refresh_after_ms = Some(now + CACHE_MS);
    match result {
        Ok(windows) if !windows.is_empty() => {
            entry.status = "available";
            entry.reason = None;
            entry.checked_at_ms = Some(now);
            entry.windows = windows;
        }
        result => {
            entry.status = "unavailable";
            entry.reason = Some(result.err().unwrap_or("not_reported"));
            // Keep the last successful observation, visibly marked stale.
        }
    }
}

fn read_codex(binary: &Path, profile: &Path) -> Result<Vec<UsageWindow>, &'static str> {
    match codex_usage::account_usage(binary, profile) {
        CodexUsageRead::Available(snapshot) => Ok(snapshot
            .windows
            .into_iter()
            .map(|window| UsageWindow {
                name: window.limit_name.unwrap_or(window.limit_id),
                used_percent: f64::from(window.used_percent),
                duration_minutes: window.window_duration_minutes,
                resets_at_ms: window
                    .resets_at_unix_seconds
                    .and_then(|value| u64::try_from(value).ok())
                    .and_then(|value| value.checked_mul(1000)),
                resets_at: None,
            })
            .collect()),
        CodexUsageRead::Unavailable(reason) => Err(match reason {
            CodexUsageUnavailable::AuthenticationRequired => "sign_in_required",
            CodexUsageUnavailable::RateLimited => "provider_rate_limited",
            CodexUsageUnavailable::TimedOut => "provider_timeout",
            CodexUsageUnavailable::InvalidResponse => "not_reported",
            _ => "provider_unavailable",
        }),
    }
}

fn read_claude(profile: &Path) -> Result<Vec<UsageWindow>, &'static str> {
    // Native Claude credentials stay on this server. Never return raw provider
    // responses, credential contents, or provider error messages to the client.
    let bytes = Zeroizing::new(
        read_private_file(&profile.join(".credentials.json"), 64 * 1024)
            .map_err(|_| "sign_in_required")?,
    );
    let credentials: Value = serde_json::from_slice(&bytes).map_err(|_| "sign_in_required")?;
    let oauth = credentials.get("claudeAiOauth").ok_or("sign_in_required")?;
    let access = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() < 16_384 && !v.chars().any(char::is_control))
        .ok_or("sign_in_required")?;
    if oauth
        .get("expiresAt")
        .and_then(Value::as_u64)
        .is_some_and(|expiry| expiry <= now_ms())
    {
        return Err("sign_in_required");
    }
    let authorization = Zeroizing::new(format!("Bearer {access}"));
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .new_agent();
    // Fixed HTTPS origin: credentials can never follow redirects or user input.
    let mut response = agent
        .get("https://api.anthropic.com/api/oauth/usage")
        .header("authorization", authorization.as_str())
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("accept", "application/json")
        .call()
        .map_err(|_| "provider_unavailable")?;
    match response.status().as_u16() {
        200 => (),
        401 | 403 => return Err("sign_in_required"),
        429 => return Err("provider_rate_limited"),
        _ => return Err("provider_unavailable"),
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "provider_unavailable")?;
    if bytes.len() > 65_536 {
        return Err("not_reported");
    }
    decode_claude(&serde_json::from_slice(&bytes).map_err(|_| "not_reported")?)
}

fn decode_claude(value: &Value) -> Result<Vec<UsageWindow>, &'static str> {
    let windows: Vec<_> = [
        ("five_hour", "Claude", 300),
        ("seven_day", "Claude", 10_080),
        ("seven_day_sonnet", "Sonnet", 10_080),
        ("seven_day_opus", "Opus", 10_080),
    ]
    .into_iter()
    .filter_map(|(key, name, duration)| {
        let window = value.get(key)?;
        let used = window.get("utilization")?.as_f64()?;
        if !(0.0..=100.0).contains(&used) {
            return None;
        }
        Some(UsageWindow {
            name: name.into(),
            used_percent: used,
            duration_minutes: Some(duration),
            resets_at_ms: None,
            resets_at: window
                .get("resets_at")
                .and_then(Value::as_str)
                .filter(|v| {
                    v.len() <= 40
                        && v.bytes()
                            .all(|b| b.is_ascii_digit() || b"-:+.TZ".contains(&b))
                })
                .map(str::to_owned),
        })
    })
    .collect();
    if windows.is_empty() {
        Err("not_reported")
    } else {
        Ok(windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_cache_is_isolated_and_sign_out_invalidates_cached_readings() {
        let config = AgentAuthConfig {
            root: "/unused".into(),
            codex_binary: "/bin/false".into(),
            claude_binary: "/bin/false".into(),
        };
        let make_account = |id: &str, status: &str| AccountView {
            id: id.into(),
            provider: "codex".into(),
            provider_name: "Codex CLI",
            label: "Local".into(),
            selected: false,
            worker_selected: false,
            status: status.into(),
            method: "chatgpt".into(),
            evidence: "provider_unavailable".into(),
            observed_at_ms: None,
            last_verified_at_ms: None,
            usage: UsageView::unavailable("not_checked"),
        };
        let mut cached = UsageView::unavailable("not_checked");
        apply_result(
            &mut cached,
            decode_claude(&serde_json::json!({"five_hour":{"utilization":42}})),
            now_ms(),
        );
        let cache = Arc::new(Mutex::new(UsageCache {
            entries: BTreeMap::from([("one".into(), cached)]),
            running: true,
        }));
        let mut accounts = [
            make_account("one", "authenticated"),
            make_account("two", "authenticated"),
        ];
        project(&config, &cache, &mut accounts).unwrap();
        assert_eq!(accounts[0].usage.windows[0].used_percent, 42.0);
        assert!(accounts[1].usage.windows.is_empty());
        assert_eq!(accounts[1].usage.status, "loading");
        accounts[0].status = "signed_out".into();
        project(&config, &cache, &mut accounts).unwrap();
        assert!(accounts[0].usage.windows.is_empty());
        assert_eq!(accounts[0].usage.reason, Some("sign_in_required"));
        assert!(!cache.lock().unwrap().entries.contains_key("one"));
    }

    #[test]
    fn quota_projection_distinguishes_missing_from_zero_and_strips_private_fields() {
        let windows = decode_claude(&serde_json::json!({"five_hour":{"utilization":0,"resets_at":"2026-10-03T20:00:00Z"},"seven_day":{"utilization":73.5},"seven_day_sonnet":null,"email":"private","accessToken":"secret"})).unwrap();
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].used_percent, 0.0);
        assert_eq!(windows[1].used_percent, 73.5);
        let json = serde_json::to_string(&windows).unwrap();
        assert!(!json.contains("private") && !json.contains("secret"));
        assert!(
            decode_claude(
                &serde_json::json!({"five_hour":{"utilization":101},"seven_day":{"utilization":-1}})
            )
            .is_err()
        );
        assert!(decode_claude(&serde_json::json!({})).is_err());
    }
    #[test]
    fn failed_refresh_keeps_previous_observation_and_backs_off() {
        let mut usage = UsageView::unavailable("not_checked");
        apply_result(
            &mut usage,
            decode_claude(&serde_json::json!({"five_hour":{"utilization":20}})),
            1000,
        );
        apply_result(&mut usage, Err("provider_rate_limited"), 2000);
        assert_eq!(usage.status, "unavailable");
        assert_eq!(usage.checked_at_ms, Some(1000));
        assert_eq!(usage.refresh_after_ms, Some(302_000));
        assert_eq!(usage.windows[0].used_percent, 20.0);
    }
}
