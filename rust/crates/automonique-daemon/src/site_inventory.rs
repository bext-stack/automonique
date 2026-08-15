// SPDX-License-Identifier: Elastic-2.0

//! Bounded read-only inventory of enabled Prism applications and hostnames.
//!
//! Prism is a framework, not a hostname convention. An enabled virtual host is
//! therefore classified from its literal Nginx `root`: the app below that root
//! must carry a bounded `bext.config.toml` whose `[framework]` section declares
//! `type = "prism"`. This keeps the answer tied to enabled deployment state and
//! includes ordinary domains such as `example.test`, not only names containing
//! `-prism`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Production source for currently enabled Nginx sites.
pub const NGINX_SITES_ENABLED: &str = "/etc/nginx/sites-enabled";
/// Directory-entry bound, including unrelated enabled sites.
const MAX_DIRECTORY_ENTRIES: usize = 512;
/// Largest enabled-site file inspected.
const MAX_VHOST_BYTES: u64 = 64 * 1024;
/// Largest framework manifest inspected.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024;
/// Most enabled Prism applications one snapshot retains.
pub const MAX_PRISM_APPS: usize = 128;
/// Most enabled Prism hostnames one snapshot retains.
pub const MAX_PRISM_SITES: usize = 256;
const MANAGE_PROFILE_ENDPOINT: &str = "http://127.0.0.1/__bext/sdk/kv/get";
const MANAGE_PROFILE_APP: &str = "inklura-manage-prism";
const MAX_MANAGE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANAGE_PROFILES: usize = 500;
const MAX_SELECTED_PROFILES: usize = 24;

/// A complete inventory derived from enabled Nginx configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrismSiteInventory {
    apps: Vec<String>,
    sites: Vec<String>,
}

impl PrismSiteInventory {
    /// Unique deployed app directory names referenced by enabled vhosts.
    #[must_use]
    pub fn apps(&self) -> &[String] {
        &self.apps
    }

    /// Unique enabled DNS hostnames backed by a Prism app.
    #[must_use]
    pub fn sites(&self) -> &[String] {
        &self.sites
    }
}

/// Closed failures; no host path or file content is ever rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteInventoryFailure {
    Unavailable,
    Insecure,
    TooManyEntries,
    TooManyApps,
    TooManySites,
    OversizedInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManageProfile {
    pub kind: String,
    pub reference: String,
    pub label: String,
    pub host: Option<String>,
    pub context: String,
    pub rules: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManageProfileInventory {
    pub total: usize,
    pub ecosystem: usize,
    pub managed: usize,
    pub company_manager: usize,
    pub selected: Vec<ManageProfile>,
}

/// Read the bounded, path-free site-profile projection from Manage's local KV.
///
/// The fixed loopback endpoint and app identity are deployment configuration,
/// not model-controlled input. Filesystem paths and design tokens are never
/// decoded into this read model.
pub fn manage_profiles(question: &str) -> Result<ManageProfileInventory, SiteInventoryFailure> {
    let config = ureq::Agent::config_builder()
        .https_only(false)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let mut response = config
        .new_agent()
        .post(MANAGE_PROFILE_ENDPOINT)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("x-bext-app-id", MANAGE_PROFILE_APP)
        .config()
        .timeout_global(Some(Duration::from_millis(1_200)))
        .build()
        .send(r#"{"key":"siteprofiles:all"}"#)
        .map_err(|_| SiteInventoryFailure::Unavailable)?;
    if response.status().as_u16() != 200 {
        return Err(SiteInventoryFailure::Unavailable);
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit((MAX_MANAGE_RESPONSE_BYTES + 1) as u64)
        .reader()
        .read_to_end(&mut bytes)
        .map_err(|_| SiteInventoryFailure::Unavailable)?;
    if bytes.len() > MAX_MANAGE_RESPONSE_BYTES {
        return Err(SiteInventoryFailure::OversizedInput);
    }
    decode_manage_profiles(&bytes, question)
}

fn decode_manage_profiles(
    bytes: &[u8],
    question: &str,
) -> Result<ManageProfileInventory, SiteInventoryFailure> {
    let outer: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| SiteInventoryFailure::Unavailable)?;
    let raw = outer
        .get("value")
        .ok_or(SiteInventoryFailure::Unavailable)?;
    let parsed;
    let rows = if let Some(text) = raw.as_str() {
        parsed = serde_json::from_str::<serde_json::Value>(text)
            .map_err(|_| SiteInventoryFailure::Unavailable)?;
        parsed.as_array()
    } else {
        raw.as_array()
    }
    .ok_or(SiteInventoryFailure::Unavailable)?;
    if rows.len() > MAX_MANAGE_PROFILES {
        return Err(SiteInventoryFailure::TooManySites);
    }
    let mut terms: BTreeSet<String> = question
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 3)
        .map(ToOwned::to_owned)
        .collect();
    // Manage's profile prose is predominantly French while an operator may
    // ask in English. Expand only narrow domain synonyms locally so retrieval
    // does not require a model call and "agency" can find "agence web".
    if terms.contains("agency") || terms.contains("agencies") {
        terms.insert(String::from("agence"));
    }
    if terms.contains("webserver") || terms.contains("webservers") {
        terms.insert(String::from("serveur"));
    }
    let mut ecosystem = 0;
    let mut managed = 0;
    let mut company_manager = 0;
    let mut profiles = Vec::with_capacity(rows.len());
    for row in rows {
        let kind = safe_value(row, "kind", 24);
        match kind.as_str() {
            "ecosystem" => ecosystem += 1,
            "managed" => managed += 1,
            "cm" => company_manager += 1,
            _ => continue,
        }
        let reference = safe_value(row, "ref", 128);
        let label = safe_value(row, "label", 160);
        if reference.is_empty() || label.is_empty() {
            continue;
        }
        let host = safe_value(row, "host", 253);
        let context = safe_value(row, "context", 1_200);
        let rules = row
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(|rule| safe_text(rule, 240))
            .filter(|rule| !rule.is_empty())
            .take(10)
            .collect();
        profiles.push(ManageProfile {
            kind,
            reference,
            label,
            host: (!host.is_empty()).then_some(host),
            context,
            rules,
        });
    }
    profiles.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.reference.cmp(&right.reference))
    });
    let selected = profiles
        .iter()
        .filter(|profile| {
            if terms.is_empty() {
                return true;
            }
            let haystack = format!(
                "{} {} {} {}",
                profile.reference,
                profile.label,
                profile.host.as_deref().unwrap_or_default(),
                profile.context
            )
            .to_lowercase();
            terms.iter().any(|term| haystack.contains(term))
        })
        .chain(profiles.iter())
        .take(MAX_SELECTED_PROFILES)
        .cloned()
        .collect::<Vec<_>>();
    let mut unique = BTreeSet::new();
    let selected = selected
        .into_iter()
        .filter(|profile| unique.insert((profile.kind.clone(), profile.reference.clone())))
        .collect();
    Ok(ManageProfileInventory {
        total: profiles.len(),
        ecosystem,
        managed,
        company_manager,
        selected,
    })
}

fn safe_value(row: &serde_json::Value, field: &str, limit: usize) -> String {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map_or_else(String::new, |value| safe_text(value, limit))
}

fn safe_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

/// Read the complete enabled Prism inventory from one trusted directory.
pub fn prism_sites(root: &Path) -> Result<PrismSiteInventory, SiteInventoryFailure> {
    let metadata = fs::metadata(root).map_err(|_| SiteInventoryFailure::Unavailable)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(SiteInventoryFailure::Insecure);
    }
    let entries = fs::read_dir(root).map_err(|_| SiteInventoryFailure::Unavailable)?;
    let mut seen = 0_usize;
    let mut apps = BTreeSet::new();
    let mut sites = BTreeSet::new();
    for entry in entries {
        seen = seen.saturating_add(1);
        if seen > MAX_DIRECTORY_ENTRIES {
            return Err(SiteInventoryFailure::TooManyEntries);
        }
        let entry = entry.map_err(|_| SiteInventoryFailure::Unavailable)?;
        let metadata = entry
            .metadata()
            .map_err(|_| SiteInventoryFailure::Unavailable)?;
        if !metadata.is_file() {
            continue;
        }
        // Enabled vhost files are deployment policy. A writable one could turn
        // this read surface into attacker-controlled operational facts.
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(SiteInventoryFailure::Insecure);
        }
        let text = read_bounded_text(&entry.path(), MAX_VHOST_BYTES)?;
        let roots = nginx_directive_values(&text, "root");
        let mut prism_apps = BTreeSet::new();
        for value in roots {
            let Some(app_root) = literal_app_root(value) else {
                continue;
            };
            if is_prism_app(&app_root)? {
                let Some(name) = app_root.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if is_safe_app_name(name) {
                    prism_apps.insert(name.to_owned());
                }
            }
        }
        if prism_apps.is_empty() {
            continue;
        }
        apps.extend(prism_apps);
        if apps.len() > MAX_PRISM_APPS {
            return Err(SiteInventoryFailure::TooManyApps);
        }
        for value in nginx_directive_values(&text, "server_name") {
            for host in value.split_ascii_whitespace() {
                if is_dns_host(host) {
                    sites.insert(host.to_owned());
                }
            }
        }
        if sites.len() > MAX_PRISM_SITES {
            return Err(SiteInventoryFailure::TooManySites);
        }
    }
    Ok(PrismSiteInventory {
        apps: apps.into_iter().collect(),
        sites: sites.into_iter().collect(),
    })
}

fn read_bounded_text(path: &Path, limit: u64) -> Result<String, SiteInventoryFailure> {
    let file = fs::File::open(path).map_err(|_| SiteInventoryFailure::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| SiteInventoryFailure::Unavailable)?;
    if !metadata.is_file() {
        return Err(SiteInventoryFailure::Unavailable);
    }
    if metadata.len() > limit {
        return Err(SiteInventoryFailure::OversizedInput);
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| SiteInventoryFailure::Unavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(SiteInventoryFailure::OversizedInput);
    }
    String::from_utf8(bytes).map_err(|_| SiteInventoryFailure::Unavailable)
}

/// Extract simple single-line Nginx directives, excluding comments.
fn nginx_directive_values<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    text.lines()
        .filter_map(|line| {
            let statement = line.split('#').next()?.trim();
            let value = statement.strip_prefix(name)?.trim_start();
            if value.is_empty() || !statement.ends_with(';') {
                return None;
            }
            Some(value.strip_suffix(';')?.trim())
        })
        .collect()
}

/// Admit only a literal app directory below a `bext/sites` path.
fn literal_app_root(value: &str) -> Option<PathBuf> {
    if value.is_empty()
        || value.split_ascii_whitespace().count() != 1
        || value.contains('$')
        || value.contains('\0')
    {
        return None;
    }
    let path = Path::new(value);
    if !path.is_absolute() || path.file_name().is_none() {
        return None;
    }
    let components: Vec<_> = path.components().collect();
    let under_sites = components
        .windows(2)
        .any(|pair| pair[0].as_os_str() == "bext" && pair[1].as_os_str() == "sites");
    under_sites.then(|| path.to_path_buf())
}

fn is_prism_app(root: &Path) -> Result<bool, SiteInventoryFailure> {
    let manifest = match read_bounded_text(&root.join("bext.config.toml"), MAX_MANIFEST_BYTES) {
        Ok(manifest) => manifest,
        Err(SiteInventoryFailure::Unavailable) => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut framework = false;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            framework = line == "[framework]";
            continue;
        }
        if framework {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == "type" {
                return Ok(value.trim().trim_matches(['\'', '"']) == "prism");
            }
        }
    }
    Ok(false)
}

fn is_safe_app_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn is_dns_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || !host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn secure_file(path: &Path, contents: &str) {
        fs::write(path, contents).expect("fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("fixture mode");
    }

    fn prism_app(root: &Path, name: &str) -> PathBuf {
        let app = root.join("bext/sites").join(name);
        fs::create_dir_all(&app).expect("app directory");
        secure_file(
            &app.join("bext.config.toml"),
            "[framework]\ntype = \"prism\"\n",
        );
        app
    }

    #[test]
    fn inventory_uses_framework_and_reports_apps_and_ordinary_hosts() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = fixture.path().join("enabled");
        fs::create_dir(&enabled).expect("enabled");
        fs::set_permissions(&enabled, fs::Permissions::from_mode(0o700)).expect("root mode");
        let alpha = prism_app(fixture.path(), "alpha-app");
        let zeta = prism_app(fixture.path(), "zeta-prism");
        secure_file(
            &enabled.join("ordinary.example.conf"),
            &format!(
                "server {{\n server_name ordinary.example www.ordinary.example;\n root {};\n}}\n",
                alpha.display()
            ),
        );
        secure_file(
            &enabled.join("zeta.example.conf"),
            &format!(
                "server {{\n server_name zeta.example;\n root {};\n}}\n",
                zeta.display()
            ),
        );
        let non_prism = fixture.path().join("bext/sites/not-prism");
        fs::create_dir_all(&non_prism).expect("non-prism app");
        secure_file(
            &non_prism.join("bext.config.toml"),
            "[framework]\ntype = \"next\"\n",
        );
        secure_file(
            &enabled.join("ignored.example.conf"),
            &format!(
                "server_name ignored.example;\nroot {};\n",
                non_prism.display()
            ),
        );

        let inventory = prism_sites(&enabled).expect("inventory");
        assert_eq!(inventory.apps(), ["alpha-app", "zeta-prism"]);
        assert_eq!(
            inventory.sites(),
            ["ordinary.example", "www.ordinary.example", "zeta.example"]
        );
    }

    #[test]
    fn comments_variables_and_unrelated_roots_do_not_create_facts() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = fixture.path().join("enabled");
        fs::create_dir(&enabled).expect("enabled");
        fs::set_permissions(&enabled, fs::Permissions::from_mode(0o700)).expect("root mode");
        secure_file(
            &enabled.join("ignored.conf"),
            "# root /tmp/bext/sites/fake;\nserver_name ignored.example;\nroot $variable;\n",
        );
        let inventory = prism_sites(&enabled).expect("inventory");
        assert!(inventory.apps().is_empty());
        assert!(inventory.sites().is_empty());
    }

    #[test]
    fn manage_profiles_are_bounded_selected_and_path_free() {
        let rows = serde_json::json!([
            {
                "kind": "ecosystem",
                "ref": "alpha-prism",
                "label": "Alpha",
                "host": "alpha.example",
                "path": "/private/alpha",
                "context": "Public catalogue",
                "rules": ["Verify live output"],
                "design_system": {"tokens": {"secret": "never expose"}}
            },
            {
                "kind": "cm",
                "ref": "uuid-beta",
                "label": "Beta",
                "host": "beta.example",
                "context": "Business site",
                "rules": []
            }
        ]);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "value": rows.to_string(),
            "version": 4
        }))
        .expect("fixture");
        let inventory = decode_manage_profiles(&bytes, "tell me about beta").expect("profiles");
        assert_eq!(inventory.total, 2);
        assert_eq!(inventory.ecosystem, 1);
        assert_eq!(inventory.company_manager, 1);
        assert_eq!(inventory.selected[0].reference, "uuid-beta");
        assert_eq!(inventory.selected[0].host.as_deref(), Some("beta.example"));
    }

    #[test]
    fn english_agency_query_finds_french_manage_profile() {
        let rows = serde_json::json!([
            {
                "kind": "ecosystem",
                "ref": "alpha-prism",
                "label": "Alpha",
                "context": "Generic application"
            },
            {
                "kind": "ecosystem",
                "ref": "webdesign29-prism",
                "label": "Webdesign29",
                "context": "Site vitrine de l'agence web Webdesign29 à Brest"
            }
        ]);
        let bytes = serde_json::to_vec(&serde_json::json!({ "value": rows })).expect("fixture");

        let inventory =
            decode_manage_profiles(&bytes, "what agency or agencies manage this webserver?")
                .expect("profiles");

        assert_eq!(inventory.selected[0].reference, "webdesign29-prism");
    }

    #[test]
    fn writable_source_or_vhost_fails_closed() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o722)).expect("root mode");
        assert_eq!(
            prism_sites(root.path()),
            Err(SiteInventoryFailure::Insecure)
        );

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let entry = root.path().join("unsafe.conf");
        secure_file(&entry, "server_name unsafe.example;");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o666)).expect("entry mode");
        assert_eq!(
            prism_sites(root.path()),
            Err(SiteInventoryFailure::Insecure)
        );
    }
}
