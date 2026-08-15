// SPDX-License-Identifier: Elastic-2.0

//! Credential-free projection of the model routes configured on this daemon.
//!
//! This is deliberately not a provider account catalog. It reports only the
//! routes Automonique can actually select: the dedicated conversation adapter,
//! its built-in Luna fallback, and the primary contained provider's configured
//! model/reasoning pair. No auth file is opened and no arbitrary config line is
//! retained.

use std::fs;
use std::io::Read as _;
use std::path::Path;

use crate::compose::{PROVIDER_CONFIG_NAME, ProviderConfig, QUESTION_MODEL_CONFIG};
use crate::run_lane::CONVERSATION_PROVIDER_CONFIG_NAME;

const MAX_CODEX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredModelRoutes {
    pub conversation_primary: String,
    pub conversation_fallback: String,
    pub operational_primary: String,
    pub operational_reasoning: String,
    pub operational_harness: String,
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
                let (model, reasoning) = codex_model_config(provider.home());
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
}
