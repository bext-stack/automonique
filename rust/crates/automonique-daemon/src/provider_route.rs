// SPDX-License-Identifier: Elastic-2.0

//! Readiness of the configured provider route against this generation's
//! admitted egress policy.
//!
//! This is deliberately evaluated from the [`ExecutionLane`](crate::execute::ExecutionLane)
//! snapshot, not by rereading `egress-destinations`: a file edit does not alter
//! what a running generation admits. JCode's route selection is read from its
//! own bounded TOML configuration, so a non-empty allowlist for the wrong
//! provider cannot be reported as provider availability.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use automonique_runner::admission::{BrokeredDestination, BrokeredScope};
use toml_edit::DocumentMut;

use crate::compose::{ProviderConfig, ProviderEngine};

const JCODE_CONFIG_NAME: &str = "config.toml";
const MAX_JCODE_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy)]
struct RequiredDestination {
    host: &'static str,
    port: u16,
}

const OPENAI: [RequiredDestination; 2] = [
    RequiredDestination {
        host: "chatgpt.com",
        port: 443,
    },
    RequiredDestination {
        host: "developers.openai.com",
        port: 443,
    },
];
const DEEPSEEK: [RequiredDestination; 1] = [RequiredDestination {
    host: "api.deepseek.com",
    port: 443,
}];
const ANTHROPIC: [RequiredDestination; 2] = [
    RequiredDestination {
        host: "api.anthropic.com",
        port: 443,
    },
    RequiredDestination {
        host: "platform.claude.com",
        port: 443,
    },
];

/// Whether this exact provider can use the route admitted by this generation.
///
/// An unknown provider, unreadable route configuration, missing destination,
/// or non-public spelling fails closed. The compatibility answer-file engine
/// has no provider-owned route selector; its historical readiness remains the
/// presence of at least one admitted destination.
pub(crate) fn is_admitted(provider: &ProviderConfig, destinations: &[BrokeredDestination]) -> bool {
    if provider.engine() != ProviderEngine::Jcode {
        return !destinations.is_empty();
    }
    let Some(route) = read_default_provider(&provider.home().join(JCODE_CONFIG_NAME)) else {
        return false;
    };
    let required = match route.as_str() {
        "openai" => OPENAI.as_slice(),
        "deepseek" => DEEPSEEK.as_slice(),
        "anthropic" => ANTHROPIC.as_slice(),
        _ => return false,
    };
    required.iter().all(|required| {
        destinations.iter().any(|destination| {
            destination.host().eq_ignore_ascii_case(required.host)
                && destination.port() == required.port
                && destination.scope() == BrokeredScope::Public
        })
    })
}

fn read_default_provider(path: &Path) -> Option<String> {
    let named = std::fs::symlink_metadata(path).ok()?;
    if !named.is_file() || named.file_type().is_symlink() || named.len() > MAX_JCODE_CONFIG_BYTES {
        return None;
    }
    let file = File::open(path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file()
        || opened.len() > MAX_JCODE_CONFIG_BYTES
        || (opened.dev(), opened.ino()) != (named.dev(), named.ino())
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_JCODE_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_JCODE_CONFIG_BYTES {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    let document = text.parse::<DocumentMut>().ok()?;
    let route = document
        .get("provider")?
        .as_table()?
        .get("default_provider")?
        .as_str()?;
    if route.is_empty()
        || route.len() > 64
        || route
            .bytes()
            .any(|byte| !byte.is_ascii_lowercase() && byte != b'-' && byte != b'_')
    {
        return None;
    }
    Some(route.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn provider(root: &Path, route: &str) -> ProviderConfig {
        let home = root.join("jcode-home");
        std::fs::create_dir(&home).expect("provider home");
        let mut route_config = File::create(home.join(JCODE_CONFIG_NAME)).expect("route config");
        writeln!(route_config, "[provider]\ndefault_provider = {route:?}").expect("route");
        let path = root.join("provider");
        std::fs::write(
            &path,
            format!(
                "engine=jcode\nbinary=/bin/false\nhome={}\nversion=jcode-fixture\narg=api-stdio\n",
                home.display()
            ),
        )
        .expect("provider config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private provider config");
        ProviderConfig::load_execution(&path)
            .expect("provider config parses")
            .expect("provider configured")
    }

    fn destination(host: &str, scope: BrokeredScope) -> BrokeredDestination {
        BrokeredDestination::new(host, 443, scope).expect("destination")
    }

    #[test]
    fn the_selected_jcode_route_requires_every_exact_admitted_destination() {
        let root = tempfile::tempdir().expect("root");
        let provider = provider(root.path(), "openai");
        let deepseek = destination("api.deepseek.com", BrokeredScope::Public);
        assert!(
            !is_admitted(&provider, &[deepseek]),
            "a non-empty policy for another provider is not readiness"
        );
        let chat = destination("chatgpt.com", BrokeredScope::Public);
        assert!(
            !is_admitted(&provider, std::slice::from_ref(&chat)),
            "a partial route is not readiness"
        );
        let auth = destination("developers.openai.com", BrokeredScope::Public);
        assert!(is_admitted(&provider, &[chat, auth]));
    }

    #[test]
    fn unknown_unreadable_and_wrong_scope_routes_fail_closed() {
        for route in ["unknown", "OpenAI"] {
            let root = tempfile::tempdir().expect("root");
            let provider = provider(root.path(), route);
            assert!(!is_admitted(
                &provider,
                &[
                    destination("chatgpt.com", BrokeredScope::Public),
                    destination("developers.openai.com", BrokeredScope::Public),
                ]
            ));
        }

        let root = tempfile::tempdir().expect("root");
        let provider = provider(root.path(), "openai");
        let route_path = provider.home().join(JCODE_CONFIG_NAME);
        std::fs::remove_file(&route_path).expect("remove config");
        std::os::unix::fs::symlink("missing", &route_path).expect("symlink");
        assert!(!is_admitted(
            &provider,
            &[
                destination("chatgpt.com", BrokeredScope::Loopback),
                destination("developers.openai.com", BrokeredScope::Public),
            ]
        ));
    }

    #[test]
    fn a_legacy_top_level_route_is_not_mistaken_for_the_jcode_schema() {
        let root = tempfile::tempdir().expect("root");
        let provider = provider(root.path(), "openai");
        std::fs::write(
            provider.home().join(JCODE_CONFIG_NAME),
            "default_provider = \"openai\"\n",
        )
        .expect("legacy-shaped config");
        assert!(!is_admitted(
            &provider,
            &[
                destination("chatgpt.com", BrokeredScope::Public),
                destination("developers.openai.com", BrokeredScope::Public),
            ]
        ));
    }

    #[test]
    fn every_supported_route_has_a_closed_destination_set() {
        let cases = [
            (
                "deepseek",
                vec![destination("api.deepseek.com", BrokeredScope::Public)],
            ),
            (
                "anthropic",
                vec![
                    destination("api.anthropic.com", BrokeredScope::Public),
                    destination("platform.claude.com", BrokeredScope::Public),
                ],
            ),
        ];
        for (route, destinations) in cases {
            let root = tempfile::tempdir().expect("root");
            let provider = provider(root.path(), route);
            assert!(is_admitted(&provider, &destinations), "route {route}");
        }
    }
}
