// SPDX-License-Identifier: Elastic-2.0

//! Model inventory projections for operator surfaces.
//!
//! Configured routes and account-visible models are deliberately separate. The
//! route projection is credential-free and reports only models Automonique can
//! actually select. The catalog projection asks the configured, pinned
//! provider through its documented read-only surface; it never opens an auth
//! file and returns only bounded model identifiers.

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;

use crate::compose::{PROVIDER_CONFIG_NAME, ProviderConfig, ProviderEngine, QUESTION_MODEL_CONFIG};
use crate::run_lane::CONVERSATION_PROVIDER_CONFIG_NAME;

const MAX_CODEX_CONFIG_BYTES: u64 = 16 * 1024;
const CATALOG_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CATALOG_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_CATALOG_MODELS: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredModelRoutes {
    pub conversation_primary: String,
    pub conversation_fallback: String,
    pub operational_primary: String,
    pub operational_reasoning: String,
    pub operational_harness: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableModel {
    pub id: String,
    pub is_default: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderModelCatalog {
    pub models: Vec<AvailableModel>,
    pub source: ModelCatalogSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelCatalogSource {
    CodexAppServer,
    JcodeCli,
}

impl ModelCatalogSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodexAppServer => "codex_model_list",
            Self::JcodeCli => "jcode_model_list",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelCatalogUnavailable {
    NotConfigured,
    ConfigurationRefused,
    ProviderRefused,
    TimedOut,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelCatalogRead {
    Available(ProviderModelCatalog),
    Unavailable(ModelCatalogUnavailable),
}

/// One transport-neutral answer to a model-capability question.
///
/// The configured routes remain authoritative even when the bounded provider
/// catalog read is unavailable. `catalog_available` lets presentation layers
/// record which source contributed without parsing the rendered text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCapabilityAnswer {
    pub text: String,
    pub catalog_available: bool,
}

impl ConfiguredModelRoutes {
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "authority=configured Automonique routes only; not the full provider account catalog\n\
             conversation_primary={}\n\
             conversation_fallback={}\n\
             operational_primary={}\n\
             operational_reasoning={}\n\
             operational_harness={}",
            self.conversation_primary,
            self.conversation_fallback,
            self.operational_primary,
            self.operational_reasoning,
            self.operational_harness,
        )
    }
}

#[must_use]
pub fn configured_model_routes(state_dir: &Path) -> ConfiguredModelRoutes {
    let fallback = QUESTION_MODEL_CONFIG
        .strip_prefix("model=\"")
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or("unavailable")
        .to_owned();
    let conversation_primary =
        match ProviderConfig::load(&state_dir.join(CONVERSATION_PROVIDER_CONFIG_NAME)) {
            Ok(Some(provider)) if provider.version().starts_with("deepseek-v4-flash") => {
                String::from("deepseek-v4-flash")
            }
            Ok(Some(provider)) => {
                safe_token(provider.version()).unwrap_or_else(|| String::from("configured_unknown"))
            }
            Ok(None) => String::from("not_configured"),
            Err(_) => String::from("configuration_refused"),
        };

    let (operational_primary, operational_reasoning, operational_harness) =
        match ProviderConfig::load(&state_dir.join(PROVIDER_CONFIG_NAME)) {
            Ok(Some(provider)) => {
                let (model, reasoning) = match provider.engine() {
                    ProviderEngine::Codex => codex_model_config(provider.home()),
                    ProviderEngine::Jcode => jcode_runtime_config(&provider),
                };
                (
                    model.unwrap_or_else(|| String::from("configured_unknown")),
                    reasoning.unwrap_or_else(|| String::from("configured_unknown")),
                    safe_token(provider.version())
                        .unwrap_or_else(|| String::from("configured_unknown")),
                )
            }
            Ok(None) => (
                String::from("not_configured"),
                String::from("not_configured"),
                String::from("not_configured"),
            ),
            Err(_) => (
                String::from("configuration_refused"),
                String::from("configuration_refused"),
                String::from("configuration_refused"),
            ),
        };

    ConfiguredModelRoutes {
        conversation_primary,
        conversation_fallback: fallback,
        operational_primary,
        operational_reasoning,
        operational_harness,
    }
}

/// Read the picker-visible model catalog from the configured provider account.
///
/// The provider binary and home come from the same owner-controlled provider
/// configuration as execution. The child receives only a fixed read-only
/// invocation and its isolated provider home; user or model text never reaches
/// its argv or environment.
#[must_use]
pub fn configured_provider_catalog(state_dir: &Path) -> ModelCatalogRead {
    let provider = match ProviderConfig::load(&state_dir.join(PROVIDER_CONFIG_NAME)) {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::NotConfigured);
        }
        Err(_) => {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ConfigurationRefused);
        }
    };
    match provider.engine() {
        ProviderEngine::Codex => read_codex_catalog(&provider),
        ProviderEngine::Jcode => read_jcode_catalog(&provider),
    }
}

/// Render the same model inventory for every conversational surface.
#[must_use]
pub fn model_capability_answer(state_dir: &Path) -> ModelCapabilityAnswer {
    render_model_capability_answer(
        configured_model_routes(state_dir),
        configured_provider_catalog(state_dir),
    )
}

/// Combine configured routes with the bounded account-visible catalog.
#[must_use]
pub fn render_model_capability_answer(
    routes: ConfiguredModelRoutes,
    catalog: ModelCatalogRead,
) -> ModelCapabilityAnswer {
    let mut text = format!(
        "Monique’s configured model routes:\n\
         - Conversation: `{}`\n\
         - Conversation fallback: `{}`\n\
         - Operational work: `{}` (`{}` reasoning)",
        routes.conversation_primary,
        routes.conversation_fallback,
        routes.operational_primary,
        routes.operational_reasoning,
    );
    match catalog {
        ModelCatalogRead::Available(catalog) => {
            let source = match catalog.source {
                ModelCatalogSource::CodexAppServer => "Codex App Server",
                ModelCatalogSource::JcodeCli => "JCode",
            };
            let models = catalog
                .models
                .iter()
                .map(|model| {
                    if model.is_default {
                        format!("`{}` (default)", model.id)
                    } else {
                        format!("`{}`", model.id)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            text.push_str(&format!(
                "\n\nThe connected provider account currently exposes: {models}.\n\
                 Catalog source: {source}. Account-visible models are not automatically active Monique routes."
            ));
            ModelCapabilityAnswer {
                text,
                catalog_available: true,
            }
        }
        ModelCatalogRead::Unavailable(_) => {
            text.push_str(
                "\n\nThe connected provider account’s live model catalog is temporarily unavailable. The configured routes above remain authoritative for what Monique will select.",
            );
            ModelCapabilityAnswer {
                text,
                catalog_available: false,
            }
        }
    }
}

fn read_codex_catalog(provider: &ProviderConfig) -> ModelCatalogRead {
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
        Err(_) => {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused);
        }
    };

    let request = concat!(
        "{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"automonique\",\"version\":\"0.1.0\"}}}\n",
        "{\"method\":\"initialized\"}\n",
        "{\"id\":2,\"method\":\"model/list\",\"params\":{\"limit\":100,\"includeHidden\":false}}\n"
    );
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused);
    };
    if stdin.write_all(request.as_bytes()).is_err() || stdin.flush().is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused);
    }
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused);
    };

    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name(String::from("automonique-codex-model-catalog-read"))
        .spawn(move || {
            let mut reader = BufReader::new(stdout).take(
                u64::try_from(MAX_CATALOG_RESPONSE_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) if line.len() > MAX_CATALOG_RESPONSE_BYTES => {
                        let _ = sender.send(None);
                        return;
                    }
                    Ok(_) => {
                        let Ok(value) = serde_json::from_slice::<Value>(&line) else {
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
    let result = match receiver.recv_timeout(CATALOG_READ_TIMEOUT) {
        Ok(Some(value)) => decode_codex_catalog_response(&value),
        Ok(None) => ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            ModelCatalogRead::Unavailable(ModelCatalogUnavailable::TimedOut)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused)
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    drop(stdin);
    if let Ok(reader) = reader {
        let _ = reader.join();
    }
    result
}

fn decode_codex_catalog_response(value: &Value) -> ModelCatalogRead {
    let Some(result) = value.get("result").and_then(Value::as_object) else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    };
    if !result.get("nextCursor").is_some_and(Value::is_null) {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    }
    let Some(data) = result.get("data").and_then(Value::as_array) else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    };
    if data.is_empty() || data.len() > MAX_CATALOG_MODELS {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    }
    let mut models = Vec::with_capacity(data.len());
    for entry in data {
        let Some(entry) = entry.as_object() else {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        };
        let Some(id) = entry
            .get("id")
            .and_then(Value::as_str)
            .and_then(safe_model_id)
        else {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        };
        if entry.get("model").and_then(Value::as_str) != Some(id.as_str())
            || entry.get("hidden").and_then(Value::as_bool) != Some(false)
        {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        }
        let Some(is_default) = entry.get("isDefault").and_then(Value::as_bool) else {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        };
        if models.iter().any(|model: &AvailableModel| model.id == id) {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        }
        models.push(AvailableModel { id, is_default });
    }
    if models.iter().filter(|model| model.is_default).count() > 1 {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    }
    ModelCatalogRead::Available(ProviderModelCatalog {
        models,
        source: ModelCatalogSource::CodexAppServer,
    })
}

fn read_jcode_catalog(provider: &ProviderConfig) -> ModelCatalogRead {
    let Some(value) = read_jcode_json(provider, &["model", "list", "--json"]) else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::ProviderRefused);
    };
    decode_jcode_catalog_response(&value)
}

fn decode_jcode_catalog_response(value: &Value) -> ModelCatalogRead {
    let Some(object) = value.as_object() else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    };
    let Some(selected) = object
        .get("selected_model")
        .and_then(Value::as_str)
        .and_then(safe_model_id)
    else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    };
    let Some(entries) = object.get("models").and_then(Value::as_array) else {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    };
    if entries.is_empty() || entries.len() > MAX_CATALOG_MODELS {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    }
    let mut models = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(id) = entry.as_str().and_then(safe_model_id) else {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        };
        if models.iter().any(|model: &AvailableModel| model.id == id) {
            return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
        }
        models.push(AvailableModel {
            is_default: id == selected,
            id,
        });
    }
    if models.iter().filter(|model| model.is_default).count() != 1 {
        return ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse);
    }
    ModelCatalogRead::Available(ProviderModelCatalog {
        models,
        source: ModelCatalogSource::JcodeCli,
    })
}

fn read_jcode_json(provider: &ProviderConfig, command: &[&str]) -> Option<Value> {
    let mut child = Command::new(provider.binary())
        .args(["--quiet", "--no-update", "--no-selfdev"])
        .args(command)
        .env_clear()
        .env("JCODE_HOME", provider.home())
        .env("JCODE_RUNTIME_DIR", provider.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name(String::from("automonique-jcode-read"))
        .spawn(move || {
            let mut reader = BufReader::new(stdout).take(
                u64::try_from(MAX_CATALOG_RESPONSE_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
            let mut bytes = Vec::new();
            let result = reader
                .read_to_end(&mut bytes)
                .ok()
                .filter(|_| bytes.len() <= MAX_CATALOG_RESPONSE_BYTES)
                .and_then(|_| serde_json::from_slice::<Value>(&bytes).ok());
            let _ = sender.send(result);
        })
        .ok()?;
    let value = receiver.recv_timeout(CATALOG_READ_TIMEOUT).ok().flatten();
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    value
}

fn jcode_runtime_config(provider: &ProviderConfig) -> (Option<String>, Option<String>) {
    let Some(value) = read_jcode_json(provider, &["provider", "current", "--json"]) else {
        return (None, None);
    };
    let model = value
        .get("selected_model")
        .and_then(Value::as_str)
        .and_then(safe_model_id);
    // The selected effort is session-scoped in JCode. A fresh provider route
    // therefore truthfully has no single configured effort to project.
    (model, Some(String::from("session_selected")))
}

fn codex_model_config(home: &Path) -> (Option<String>, Option<String>) {
    let path = home.join("config.toml");
    let Ok(file) = fs::File::open(path) else {
        return (None, None);
    };
    let Ok(metadata) = file.metadata() else {
        return (None, None);
    };
    if !metadata.is_file() || metadata.len() > MAX_CODEX_CONFIG_BYTES {
        return (None, None);
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_CODEX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CODEX_CONFIG_BYTES
    {
        return (None, None);
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return (None, None);
    };
    let mut model = None;
    let mut reasoning = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = quoted_token(value.trim()) else {
            continue;
        };
        match key.trim() {
            "model" => model = Some(value),
            "model_reasoning_effort"
                if matches!(
                    value.as_str(),
                    "none" | "low" | "medium" | "high" | "xhigh" | "max"
                ) =>
            {
                reasoning = Some(value);
            }
            _ => {}
        }
    }
    (model, reasoning)
}

fn quoted_token(value: &str) -> Option<String> {
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    safe_token(value)
}

fn safe_token(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then(|| value.to_owned())
}

fn safe_model_id(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'[' | b']')
        }))
    .then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn configured_routes_expose_models_and_never_auth_material() {
        let root = tempfile::tempdir().expect("root");
        let home = root.path().join("codex-home");
        fs::create_dir(&home).expect("home");
        fs::write(
            home.join("config.toml"),
            "model = \"gpt-5.6-sol\"\nmodel_reasoning_effort = \"high\"\n[provider]\napi_key = \"must-not-be-read\"\n",
        )
        .expect("model config");
        let primary = format!(
            "binary=/bin/true\nhome={}\nversion=codex-0.147.0\narg={{answer}}\n",
            home.display()
        );
        fs::write(root.path().join(PROVIDER_CONFIG_NAME), primary).expect("provider");
        fs::write(
            root.path().join(CONVERSATION_PROVIDER_CONFIG_NAME),
            format!(
                "binary=/bin/true\nhome={}\nversion=deepseek-v4-flash-direct-v1\narg={{answer}}\n",
                home.display()
            ),
        )
        .expect("conversation provider");
        for path in [
            root.path().join(PROVIDER_CONFIG_NAME),
            root.path().join(CONVERSATION_PROVIDER_CONFIG_NAME),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
        }

        let routes = configured_model_routes(root.path());
        assert_eq!(routes.conversation_primary, "deepseek-v4-flash");
        assert_eq!(routes.conversation_fallback, "gpt-5.6-luna");
        assert_eq!(routes.operational_primary, "gpt-5.6-sol");
        assert_eq!(routes.operational_reasoning, "high");
        assert_eq!(routes.operational_harness, "codex-0.147.0");
        assert!(!routes.render().contains("must-not-be-read"));
        assert!(!routes.render().contains("api_key"));
    }

    #[test]
    fn exact_picker_visible_catalog_decodes_without_account_or_auth_fields() {
        let value = serde_json::json!({
            "id": 2,
            "result": {
                "data": [
                    {
                        "id": "gpt-5.6-sol",
                        "model": "gpt-5.6-sol",
                        "displayName": "GPT-5.6-Sol",
                        "hidden": false,
                        "isDefault": true,
                        "accountEmail": "must-not-cross"
                    },
                    {
                        "id": "gpt-5.6-luna",
                        "model": "gpt-5.6-luna",
                        "hidden": false,
                        "isDefault": false
                    }
                ],
                "nextCursor": null
            }
        });
        let ModelCatalogRead::Available(catalog) = decode_codex_catalog_response(&value) else {
            panic!("catalog must decode");
        };
        assert_eq!(
            catalog.models,
            vec![
                AvailableModel {
                    id: String::from("gpt-5.6-sol"),
                    is_default: true,
                },
                AvailableModel {
                    id: String::from("gpt-5.6-luna"),
                    is_default: false,
                }
            ]
        );
        assert_eq!(catalog.source, ModelCatalogSource::CodexAppServer);
    }

    #[test]
    fn hidden_unsafe_duplicate_or_paginated_catalogs_are_refused() {
        let base = serde_json::json!({
            "id": 2,
            "result": {
                "data": [{
                    "id": "gpt-5.6-sol",
                    "model": "gpt-5.6-sol",
                    "hidden": false,
                    "isDefault": true
                }],
                "nextCursor": null
            }
        });
        let mut hidden = base.clone();
        hidden["result"]["data"][0]["hidden"] = Value::Bool(true);
        let mut unsafe_id = base.clone();
        unsafe_id["result"]["data"][0]["id"] = Value::String(String::from("bad model"));
        let mut duplicate = base.clone();
        duplicate["result"]["data"] = Value::Array(vec![
            base["result"]["data"][0].clone(),
            base["result"]["data"][0].clone(),
        ]);
        let mut paginated = base;
        paginated["result"]["nextCursor"] = Value::String(String::from("more"));
        for value in [hidden, unsafe_id, duplicate, paginated] {
            assert_eq!(
                decode_codex_catalog_response(&value),
                ModelCatalogRead::Unavailable(ModelCatalogUnavailable::InvalidResponse)
            );
        }
    }

    #[test]
    fn configured_catalog_uses_the_pinned_app_server_and_provider_home() {
        let root = tempfile::tempdir().expect("root");
        let home = root.path().join("codex-home");
        fs::create_dir(&home).expect("home");
        fs::write(home.join("catalog-fixture"), "present").expect("home marker");
        let binary = root.path().join("fake-codex");
        fs::write(
            &binary,
            concat!(
                "#!/bin/sh\n",
                "printf '%s %s' \"$1\" \"$2\" > \"$CODEX_HOME/invocation\"\n",
                "IFS= read -r initialize\n",
                "IFS= read -r initialized\n",
                "IFS= read -r model_list\n",
                "printf '%s\\n' '{\"id\":2,\"result\":{\"data\":[{\"id\":\"gpt-5.6-sol\",\"model\":\"gpt-5.6-sol\",\"hidden\":false,\"isDefault\":true}],\"nextCursor\":null}}'\n",
            ),
        )
        .expect("fixture provider");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).expect("executable");
        let provider_config = root.path().join(PROVIDER_CONFIG_NAME);
        fs::write(
            &provider_config,
            format!(
                "binary={}\nhome={}\nversion=codex-fixture\narg={{answer}}\n",
                binary.display(),
                home.display(),
            ),
        )
        .expect("provider config");
        fs::set_permissions(&provider_config, fs::Permissions::from_mode(0o600))
            .expect("private provider config");

        let read = configured_provider_catalog(root.path());
        let ModelCatalogRead::Available(catalog) = &read else {
            panic!("fixture catalog must be available: {read:?}");
        };
        assert_eq!(
            &catalog.models,
            vec![AvailableModel {
                id: String::from("gpt-5.6-sol"),
                is_default: true,
            }]
            .as_slice()
        );
        assert_eq!(
            fs::read_to_string(home.join("invocation")).expect("invocation marker"),
            "app-server --stdio"
        );
    }

    #[test]
    fn jcode_catalog_uses_the_pinned_read_only_cli_and_provider_home() {
        let root = tempfile::tempdir().expect("root");
        let home = root.path().join("jcode-home");
        fs::create_dir(&home).expect("home");
        let binary = root.path().join("fake-jcode");
        fs::write(
            &binary,
            concat!(
                "#!/bin/sh\n",
                "printf '%s\\n' \"$*\" >> \"$JCODE_HOME/invocation\"\n",
                "test \"$JCODE_RUNTIME_DIR\" = \"$JCODE_HOME\" || exit 9\n",
                "if test \"$4 $5 $6\" = 'model list --json'; then\n",
                "  printf '%s\\n' '{\"provider\":\"OpenAI\",\"selected_model\":\"gpt-5.6-sol\",\"models\":[\"gpt-5.6-sol\",\"gpt-5.6-pro[web]\",\"anthropic/claude-sonnet-4\"],\"routes\":[]}'\n",
                "elif test \"$4 $5 $6\" = 'provider current --json'; then\n",
                "  printf '%s\\n' '{\"requested_provider\":\"auto\",\"requested_model\":null,\"resolved_provider\":\"openai\",\"selected_model\":\"gpt-5.6-sol\"}'\n",
                "else exit 8; fi\n",
            ),
        )
        .expect("fixture provider");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).expect("executable");
        let provider_config = root.path().join(PROVIDER_CONFIG_NAME);
        fs::write(
            &provider_config,
            format!(
                "engine=jcode\nbinary={}\nhome={}\nversion=jcode-fixture\narg=api-stdio\n",
                binary.display(),
                home.display(),
            ),
        )
        .expect("provider config");
        fs::set_permissions(&provider_config, fs::Permissions::from_mode(0o600))
            .expect("private provider config");

        let read = configured_provider_catalog(root.path());
        let ModelCatalogRead::Available(catalog) = read else {
            panic!("fixture catalog must be available");
        };
        assert_eq!(catalog.source, ModelCatalogSource::JcodeCli);
        assert_eq!(
            catalog.models,
            vec![
                AvailableModel {
                    id: String::from("gpt-5.6-sol"),
                    is_default: true,
                },
                AvailableModel {
                    id: String::from("gpt-5.6-pro[web]"),
                    is_default: false,
                },
                AvailableModel {
                    id: String::from("anthropic/claude-sonnet-4"),
                    is_default: false,
                },
            ]
        );
        let routes = configured_model_routes(root.path());
        assert_eq!(routes.operational_primary, "gpt-5.6-sol");
        assert_eq!(routes.operational_reasoning, "session_selected");
        assert_eq!(routes.operational_harness, "jcode-fixture");
        assert_eq!(
            fs::read_to_string(home.join("invocation")).expect("invocation marker"),
            "--quiet --no-update --no-selfdev model list --json\n--quiet --no-update --no-selfdev provider current --json\n"
        );
    }
}
