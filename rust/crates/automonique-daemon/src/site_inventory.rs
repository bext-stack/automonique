// SPDX-License-Identifier: Elastic-2.0

//! Bounded read-only inventory of enabled Prism applications and hostnames.
//!
//! Prism is a framework, not a hostname convention. An enabled virtual host is
//! therefore classified from its literal Nginx `root`: the app below that root
//! must carry a bounded `bext.config.toml` whose `[framework]` section declares
//! `type = "prism"`. This keeps the answer tied to enabled deployment state and
//! includes ordinary domains such as `example.test`, not only names containing
//! `-prism`.
//!
//! Every read is bounded, and a bound is a degradation rather than a failure:
//! a host serving more than the limits below still gets an inventory, cut to
//! a deterministic prefix and marked truncated. One unusable file (a vhost
//! only root can read, an oversized one) is skipped and counted instead of
//! making the whole estate unavailable. Only a policy violation — a directory
//! or vhost file that group or other can write — fails closed.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Production source for currently enabled Nginx sites.
pub const NGINX_SITES_ENABLED: &str = "/etc/nginx/sites-enabled";
/// Most directory entries one snapshot examines, including unrelated enabled
/// sites. A larger directory degrades to its first entries in file-name order.
pub const MAX_DIRECTORY_ENTRIES: usize = 2_048;
/// Largest enabled-site file inspected.
const MAX_VHOST_BYTES: u64 = 64 * 1024;
/// Largest framework manifest inspected.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024;
/// Most distinct literal `root` values classified from one enabled-site file,
/// so one file cannot buy an unbounded number of manifest reads.
const MAX_ROOTS_PER_VHOST: usize = 64;
/// Most enabled Prism applications one snapshot retains.
pub const MAX_PRISM_APPS: usize = 1_024;
/// Most enabled Prism hostnames one snapshot retains.
pub const MAX_PRISM_SITES: usize = 2_048;
/// Most enabled DNS hostnames retained across all Nginx applications.
pub const MAX_ENABLED_HOSTS: usize = 2_048;
/// Longest application root one snapshot retains for display.
const MAX_APP_ROOT_BYTES: usize = 256;
const MANAGE_PROFILE_ENDPOINT: &str = "http://127.0.0.1/__bext/sdk/kv/get";
const MAX_MANAGE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Most Manage profiles retained for ranking. The counts cover every row of
/// the size-bounded response, so a larger estate reports honest totals and
/// ranks its first rows instead of failing.
const MAX_MANAGE_PROFILES: usize = 2_000;
const MAX_SELECTED_PROFILES: usize = 24;

/// An inventory derived from enabled Nginx configuration.
///
/// The inventory is a bounded snapshot, never a failure for being large: an
/// estate beyond [`MAX_PRISM_APPS`], [`MAX_PRISM_SITES`] or
/// [`MAX_DIRECTORY_ENTRIES`] keeps the first entries in a deterministic order
/// (enabled-site files by name, then values alphabetically) and reports
/// [`Self::truncated`]. Files that could not be used are counted by
/// [`Self::skipped_files`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrismSiteInventory {
    apps: Vec<String>,
    /// Parallel to `apps`.
    app_roots: Vec<Option<String>>,
    sites: Vec<String>,
    /// Parallel to `sites`.
    site_apps: Vec<Option<String>>,
    truncated: bool,
    skipped_files: usize,
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

    /// Whether a bound was reached, so the lists and counts are a prefix of
    /// the estate rather than all of it.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Enabled-site files or manifests left out because they were unreadable
    /// by this user, oversized, not UTF-8, or reached through a link whose
    /// target is not deployment policy.
    #[must_use]
    pub const fn skipped_files(&self) -> usize {
        self.skipped_files
    }

    /// The two facts above as one fixed-shape line for a prompt or reply.
    #[must_use]
    pub fn coverage(&self) -> String {
        coverage(self.truncated, self.skipped_files)
    }

    /// The literal `root` directory of one Prism app, when it is unambiguous
    /// and safe to show.
    ///
    /// Unlike [`enabled_hosts`], the Prism inventory does retain this one
    /// filesystem path. It exists so approved work can be told where a named
    /// site's code lives; the job runs as the same user as this daemon and can
    /// read the same enabled-site files itself, so the path discloses nothing
    /// that job could not already list. It is withheld unless the root passed
    /// every check that made the app part of this inventory (a literal
    /// directive in a non-writable vhost, a Prism manifest, a safe app name),
    /// is plain printable path text, names a real directory that is neither a
    /// link nor world-writable, and is the only root seen for that app name.
    #[must_use]
    pub fn app_root(&self, app: &str) -> Option<&str> {
        let index = self
            .apps
            .binary_search_by(|candidate| candidate.as_str().cmp(app))
            .ok()?;
        self.app_roots.get(index)?.as_deref()
    }

    /// The Prism app serving one enabled hostname, when exactly one app is
    /// declared by the vhost files that name the host.
    #[must_use]
    pub fn app_for_host(&self, host: &str) -> Option<&str> {
        let index = self
            .sites
            .binary_search_by(|candidate| candidate.as_str().cmp(host))
            .ok()?;
        self.site_apps.get(index)?.as_deref()
    }
}

/// Hostnames of every enabled vhost. Bounded like [`PrismSiteInventory`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnabledHostInventory {
    sites: Vec<String>,
    truncated: bool,
    skipped_files: usize,
}

impl EnabledHostInventory {
    #[must_use]
    pub fn sites(&self) -> &[String] {
        &self.sites
    }

    /// Whether a bound was reached and the list is a prefix of the estate.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Enabled-site files left out; see [`PrismSiteInventory::skipped_files`].
    #[must_use]
    pub const fn skipped_files(&self) -> usize {
        self.skipped_files
    }

    /// See [`PrismSiteInventory::coverage`].
    #[must_use]
    pub fn coverage(&self) -> String {
        coverage(self.truncated, self.skipped_files)
    }
}

fn coverage(truncated: bool, skipped_files: usize) -> String {
    format!(
        "truncated={} skipped_vhost_files={skipped_files}",
        if truncated { "yes" } else { "no" }
    )
}

/// Closed failures; no host path or file content is ever rendered.
///
/// Size is deliberately not one of them for the vhost inventories: a large
/// estate degrades (see [`PrismSiteInventory`]) instead of failing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteInventoryFailure {
    Unavailable,
    Insecure,
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
/// The fixed loopback endpoint is a property of the deployment's own host. The
/// app identity is deployment configuration too, and is supplied by the caller
/// from [`crate::manage_config::ManageConfig`] rather than compiled in — a host
/// that configured none never reaches this function. Neither is
/// model-controlled input. Filesystem paths and design tokens are never decoded
/// into this read model.
pub fn manage_profiles(
    question: &str,
    profile_app: &crate::manage_config::ManageProfileApp,
) -> Result<ManageProfileInventory, SiteInventoryFailure> {
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
        .header("x-bext-app-id", profile_app.as_str())
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
    let mut terms: BTreeSet<String> = question
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 3)
        .filter(|term| {
            !matches!(
                *term,
                "about"
                    | "are"
                    | "can"
                    | "describe"
                    | "des"
                    | "know"
                    | "les"
                    | "moi"
                    | "parle"
                    | "propos"
                    | "que"
                    | "quoi"
                    | "sais"
                    | "savez"
                    | "tell"
                    | "the"
                    | "what"
                    | "who"
                    | "you"
            )
        })
        .map(ToOwned::to_owned)
        .collect();
    let names_company_manager = (terms.contains("company") && terms.contains("manager"))
        || terms.contains("companymanager");
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
    let mut total = 0_usize;
    let mut profiles = Vec::with_capacity(rows.len().min(MAX_MANAGE_PROFILES));
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
        total += 1;
        // Counts cover every row; only the first rows are kept for ranking.
        if profiles.len() >= MAX_MANAGE_PROFILES {
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
    let relevance = |profile: &ManageProfile| {
        if terms.is_empty() {
            return 1_usize;
        }
        let identity = format!(
            "{} {} {} {}",
            profile.kind,
            profile.reference,
            profile.label,
            profile.host.as_deref().unwrap_or_default(),
        )
        .to_lowercase();
        let context = profile.context.to_lowercase();
        let rules = profile.rules.join(" ").to_lowercase();
        let lexical = terms
            .iter()
            .map(|term| {
                if identity.contains(term) {
                    16
                } else if context.contains(term) {
                    4
                } else if rules.contains(term) {
                    1
                } else {
                    0
                }
            })
            .sum::<usize>();
        lexical.saturating_add(usize::from(names_company_manager && profile.kind == "cm") * 1_024)
    };
    let mut ranked = profiles
        .iter()
        .filter_map(|profile| {
            let score = relevance(profile);
            (score > 0).then_some((score, profile))
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_score, left), (right_score, right)| {
        right_score.cmp(left_score).then_with(|| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.reference.cmp(&right.reference))
        })
    });
    let mut unique = BTreeSet::new();
    let selected = ranked
        .into_iter()
        .map(|(_, profile)| profile)
        .chain(profiles.iter())
        .filter(|profile| unique.insert((profile.kind.clone(), profile.reference.clone())))
        .take(MAX_SELECTED_PROFILES)
        .cloned()
        .collect::<Vec<_>>();
    Ok(ManageProfileInventory {
        total,
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

/// Read the bounded enabled Prism inventory from one trusted directory.
pub fn prism_sites(root: &Path) -> Result<PrismSiteInventory, SiteInventoryFailure> {
    // App name -> the one root safe to show, or `None` once withheld.
    let mut apps: BTreeMap<String, Option<String>> = BTreeMap::new();
    // Hostname -> the one app serving it, or `None` once ambiguous.
    let mut sites: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut truncated = false;
    let mut skipped_manifests = 0_usize;
    let scan = scan_vhosts(root, |text| {
        let mut roots = BTreeSet::new();
        for value in nginx_directive_values(text, "root") {
            if let Some(app_root) = literal_app_root(value) {
                if roots.len() >= MAX_ROOTS_PER_VHOST && !roots.contains(&app_root) {
                    truncated = true;
                    continue;
                }
                roots.insert(app_root);
            }
        }
        let mut served = BTreeSet::new();
        for app_root in roots {
            match prism_manifest(&app_root) {
                Manifest::Prism => {}
                Manifest::NotPrism => continue,
                Manifest::Skipped => {
                    skipped_manifests = skipped_manifests.saturating_add(1);
                    continue;
                }
            }
            let Some(name) = app_root.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !is_safe_app_name(name) {
                continue;
            }
            let shown = displayable_root(&app_root);
            if let Some(known) = apps.get_mut(name) {
                // Two different roots under one app name: neither is "the"
                // directory, so none is shown.
                if *known != shown {
                    *known = None;
                }
            } else if apps.len() >= MAX_PRISM_APPS {
                truncated = true;
                continue;
            } else {
                apps.insert(name.to_owned(), shown);
            }
            served.insert(name.to_owned());
        }
        if served.is_empty() {
            return;
        }
        let only_app = (served.len() == 1)
            .then(|| served.first().cloned())
            .flatten();
        for value in nginx_directive_values(text, "server_name") {
            for host in value.split_ascii_whitespace() {
                if !is_dns_host(host) {
                    continue;
                }
                if let Some(known) = sites.get_mut(host) {
                    if *known != only_app {
                        *known = None;
                    }
                } else if sites.len() >= MAX_PRISM_SITES {
                    truncated = true;
                } else {
                    sites.insert(host.to_owned(), only_app.clone());
                }
            }
        }
    })?;
    let (apps, app_roots) = apps.into_iter().unzip();
    let (sites, site_apps) = sites.into_iter().unzip();
    Ok(PrismSiteInventory {
        apps,
        app_roots,
        sites,
        site_apps,
        truncated: truncated || scan.truncated,
        skipped_files: scan.skipped_files.saturating_add(skipped_manifests),
    })
}

/// Read all literal DNS hostnames from secure enabled Nginx vhosts.
///
/// This deliberately retains no filesystem paths, proxy destinations, TLS
/// material, or configuration text.
pub fn enabled_hosts(root: &Path) -> Result<EnabledHostInventory, SiteInventoryFailure> {
    let mut sites = BTreeSet::new();
    let mut truncated = false;
    let scan = scan_vhosts(root, |text| {
        for value in nginx_directive_values(text, "server_name") {
            for host in value.split_ascii_whitespace() {
                if !is_dns_host(host) || sites.contains(host) {
                    continue;
                }
                if sites.len() >= MAX_ENABLED_HOSTS {
                    truncated = true;
                } else {
                    sites.insert(host.to_owned());
                }
            }
        }
    })?;
    Ok(EnabledHostInventory {
        sites: sites.into_iter().collect(),
        truncated: truncated || scan.truncated,
        skipped_files: scan.skipped_files,
    })
}

struct VhostScan {
    truncated: bool,
    skipped_files: usize,
}

/// Visit the text of every usable enabled-site file in file-name order.
///
/// Memory is bounded by [`MAX_DIRECTORY_ENTRIES`] retained names and one
/// [`MAX_VHOST_BYTES`] file at a time. The listing is sorted before anything
/// is read because the kernel's directory order is arbitrary: a truncated
/// snapshot must be the same prefix on every call.
fn scan_vhosts(
    root: &Path,
    mut visit: impl FnMut(&str),
) -> Result<VhostScan, SiteInventoryFailure> {
    let directory = fs::metadata(root).map_err(|_| SiteInventoryFailure::Unavailable)?;
    if !directory.is_dir() || directory.mode() & 0o022 != 0 {
        return Err(SiteInventoryFailure::Insecure);
    }
    let mut names: BTreeSet<OsString> = BTreeSet::new();
    let mut truncated = false;
    for entry in fs::read_dir(root).map_err(|_| SiteInventoryFailure::Unavailable)? {
        let entry = entry.map_err(|_| SiteInventoryFailure::Unavailable)?;
        names.insert(entry.file_name());
        if names.len() > MAX_DIRECTORY_ENTRIES {
            names.pop_last();
            truncated = true;
        }
    }
    let mut skipped_files = 0_usize;
    for name in &names {
        match read_vhost(root, &directory, name)? {
            Vhost::Text(text) => visit(&text),
            Vhost::NotAFile => {}
            Vhost::Skipped => skipped_files = skipped_files.saturating_add(1),
        }
    }
    Ok(VhostScan {
        truncated,
        skipped_files,
    })
}

enum Vhost {
    Text(String),
    /// A directory or special file: never configuration, not worth counting.
    NotAFile,
    /// A file that exists but is not used; the snapshot reports the count.
    Skipped,
}

/// Read one enabled-site entry under the policy that makes it a fact source.
///
/// Enabled vhost files are deployment policy. A regular file that group or
/// other can write could turn this read surface into attacker-controlled
/// operational facts, so that fails the whole inventory closed. A file this
/// user simply cannot read (a root-only vhost) says nothing unsafe about the
/// rest: it is skipped and counted.
///
/// Symbolic links are followed, on purpose and narrowly. Linking
/// `sites-enabled/x` to `sites-available/x` is the stock Nginx layout, so
/// ignoring links hides real enabled sites. But a link can point anywhere, so
/// the resolved target is held to the same policy as a file placed in the
/// directory itself: a regular file that only its owner can write, in a
/// directory only its owner can write, both owned by root or by the owner of
/// the enabled directory. A link to anything else — a writable file, a file in
/// a writable directory, another user's file — is skipped, never followed.
fn read_vhost(
    root: &Path,
    directory: &fs::Metadata,
    name: &OsStr,
) -> Result<Vhost, SiteInventoryFailure> {
    let path = root.join(name);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(Vhost::Skipped);
    };
    let linked = metadata.file_type().is_symlink();
    let path = if linked {
        let trusted = |uid: u32| uid == 0 || uid == directory.uid();
        let Ok(target) = fs::canonicalize(&path) else {
            return Ok(Vhost::Skipped);
        };
        let parent_is_policy = target
            .parent()
            .and_then(|parent| fs::metadata(parent).ok())
            .is_some_and(|parent| {
                parent.is_dir() && parent.mode() & 0o022 == 0 && trusted(parent.uid())
            });
        if !parent_is_policy {
            return Ok(Vhost::Skipped);
        }
        target
    } else if metadata.is_file() {
        path
    } else {
        return Ok(Vhost::NotAFile);
    };
    // The final component is opened without following a link, so the object
    // checked below is the object read even if the entry is swapped meanwhile.
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(&path)
    else {
        return Ok(Vhost::Skipped);
    };
    let Ok(opened) = file.metadata() else {
        return Ok(Vhost::Skipped);
    };
    if !opened.is_file() {
        return Ok(Vhost::Skipped);
    }
    if opened.mode() & 0o022 != 0 {
        return if linked {
            Ok(Vhost::Skipped)
        } else {
            Err(SiteInventoryFailure::Insecure)
        };
    }
    if linked && opened.uid() != 0 && opened.uid() != directory.uid() {
        return Ok(Vhost::Skipped);
    }
    Ok(read_bounded_text(file, &opened, MAX_VHOST_BYTES).map_or(Vhost::Skipped, Vhost::Text))
}

/// The UTF-8 text of an opened regular file no larger than `limit`.
fn read_bounded_text(file: fs::File, metadata: &fs::Metadata, limit: u64) -> Option<String> {
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
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

enum Manifest {
    Prism,
    NotPrism,
    /// Present but oversized or not UTF-8: unclassified, and counted.
    Skipped,
}

fn prism_manifest(root: &Path) -> Manifest {
    let Ok(file) = fs::File::open(root.join("bext.config.toml")) else {
        return Manifest::NotPrism;
    };
    let Ok(metadata) = file.metadata() else {
        return Manifest::NotPrism;
    };
    if !metadata.is_file() {
        return Manifest::NotPrism;
    }
    let Some(manifest) = read_bounded_text(file, &metadata, MAX_MANIFEST_BYTES) else {
        return Manifest::Skipped;
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
                return if value.trim().trim_matches(['\'', '"']) == "prism" {
                    Manifest::Prism
                } else {
                    Manifest::NotPrism
                };
            }
        }
    }
    Manifest::NotPrism
}

/// The app root as text that may be shown, or `None` to withhold it.
///
/// See [`PrismSiteInventory::app_root`] for why a path is retained at all.
/// Only plain path characters are admitted, so a root can never spell a prompt
/// tag, a newline, or a traversal; and the directory must be a real directory
/// that is not world-writable, so what is shown is a deployment location
/// rather than something any local account could have planted.
fn displayable_root(app_root: &Path) -> Option<String> {
    let text = app_root.to_str()?.trim_end_matches('/');
    if text.is_empty()
        || text.len() > MAX_APP_ROOT_BYTES
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || text
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    let metadata = fs::symlink_metadata(text).ok()?;
    if !metadata.is_dir() || metadata.mode() & 0o002 != 0 {
        return None;
    }
    Some(text.to_owned())
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
    fn enabled_host_inventory_includes_non_prism_vhosts_without_paths() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = fixture.path().join("enabled");
        fs::create_dir(&enabled).expect("enabled");
        fs::set_permissions(&enabled, fs::Permissions::from_mode(0o700)).expect("root mode");
        secure_file(
            &enabled.join("sites.conf"),
            "server_name www.example.test example.test;\nroot /private/application;\n",
        );
        let inventory = enabled_hosts(&enabled).expect("inventory");
        assert_eq!(inventory.sites(), ["example.test", "www.example.test"]);
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
                "ref": "example-agency-prism",
                "label": "Example Agency",
                "context": "Site vitrine de l'agence web Example Agency à Brest"
            }
        ]);
        let bytes = serde_json::to_vec(&serde_json::json!({ "value": rows })).expect("fixture");

        let inventory =
            decode_manage_profiles(&bytes, "what agency or agencies manage this webserver?")
                .expect("profiles");

        assert_eq!(inventory.selected[0].reference, "example-agency-prism");
    }

    #[test]
    fn company_manager_intent_prioritizes_company_manager_profiles() {
        let rows = serde_json::json!([
            {
                "kind": "ecosystem",
                "ref": "alpha-prism",
                "label": "Alpha",
                "context": "Generic application"
            },
            {
                "kind": "cm",
                "ref": "account-console",
                "label": "Operations console",
                "context": "Create and administer customer accounts",
                "rules": ["Confirm the customer scope before creation"]
            }
        ]);
        let bytes = serde_json::to_vec(&serde_json::json!({ "value": rows })).expect("fixture");

        let inventory = decode_manage_profiles(
            &bytes,
            "do you know how to create accounts in company manager?",
        )
        .expect("profiles");

        assert_eq!(inventory.selected[0].kind, "cm");
        assert_eq!(inventory.selected[0].reference, "account-console");
        assert_eq!(
            inventory.selected[0].rules,
            ["Confirm the customer scope before creation"]
        );
    }

    #[test]
    fn named_entity_query_ignores_prompt_scaffolding_and_keeps_business_context() {
        let rows = serde_json::json!([
            {
                "kind": "ecosystem",
                "ref": "amifermestock-prism",
                "label": "amifermestock-prism",
                "host": "stock.example",
                "context": "Registre de stock AMISFERME et commandes fournisseurs"
            },
            {
                "kind": "ecosystem",
                "ref": "unrelated-prism",
                "label": "Unrelated",
                "context": "Ordinary site"
            },
            {
                "kind": "ecosystem",
                "ref": "amisdelaferme-prism",
                "label": "Amis de la ferme",
                "host": "amis.example",
                "context": "E-commerce fermier de produits locaux",
                "rules": ["Keep checkout on the principal application"]
            }
        ]);
        let bytes = serde_json::to_vec(&serde_json::json!({ "value": rows })).expect("fixture");

        let inventory = decode_manage_profiles(&bytes, "what do you know about amis de la ferme?")
            .expect("profiles");

        assert_eq!(inventory.selected[0].reference, "amisdelaferme-prism");
        assert_eq!(
            inventory.selected[0].context,
            "E-commerce fermier de produits locaux"
        );
        assert_eq!(
            inventory.selected[0].rules,
            ["Keep checkout on the principal application"]
        );
    }

    fn enabled_directory(fixture: &Path) -> PathBuf {
        let enabled = fixture.join("enabled");
        fs::create_dir(&enabled).expect("enabled");
        fs::set_permissions(&enabled, fs::Permissions::from_mode(0o755)).expect("root mode");
        enabled
    }

    fn vhost(enabled: &Path, file: &str, hosts: &str, app_root: &Path) {
        secure_file(
            &enabled.join(file),
            &format!(
                "server {{\n server_name {hosts};\n root {};\n}}\n",
                app_root.display()
            ),
        );
    }

    #[test]
    fn large_estate_of_700_vhost_files_is_read_whole_in_a_stable_order() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        // Written in reverse so creation order cannot pass for sorted order.
        for index in (0..700).rev() {
            let app = prism_app(fixture.path(), &format!("app-{index:04}"));
            vhost(
                &enabled,
                &format!("site-{index:04}.conf"),
                &format!("site-{index:04}.example.test www.site-{index:04}.example.test"),
                &app,
            );
        }
        let inventory = prism_sites(&enabled).expect("inventory");
        assert_eq!(inventory.apps().len(), 700);
        assert_eq!(inventory.sites().len(), 1_400);
        assert!(!inventory.truncated());
        assert_eq!(inventory.skipped_files(), 0);
        assert!(inventory.apps().is_sorted());
        assert!(inventory.sites().is_sorted());
        assert_eq!(
            inventory.app_for_host("www.site-0421.example.test"),
            Some("app-0421")
        );
        assert_eq!(inventory, prism_sites(&enabled).expect("second read"));

        let hosts = enabled_hosts(&enabled).expect("hosts");
        assert_eq!(hosts.sites().len(), 1_400);
        assert!(!hosts.truncated());
    }

    #[test]
    fn exceeding_a_bound_degrades_to_a_deterministic_prefix_with_the_flag() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        let app = prism_app(fixture.path(), "shared-app");
        // One app, more hostnames than a snapshot retains.
        let per_file = 100;
        let files = MAX_PRISM_SITES / per_file + 2;
        for file in (0..files).rev() {
            let hosts = (0..per_file)
                .map(|host| format!("h{file:02}-{host:03}.example.test"))
                .collect::<Vec<_>>()
                .join(" ");
            vhost(&enabled, &format!("{file:02}.conf"), &hosts, &app);
        }
        let inventory = prism_sites(&enabled).expect("degraded, not failed");
        assert!(inventory.truncated());
        assert_eq!(inventory.sites().len(), MAX_PRISM_SITES);
        assert_eq!(inventory.apps(), ["shared-app"]);
        // The retained prefix is the first files by name, whatever order the
        // directory happens to list them in.
        assert_eq!(inventory.sites()[0], "h00-000.example.test");
        assert!(
            !inventory
                .sites()
                .iter()
                .any(|host| host.starts_with(&format!("h{:02}-", files - 1)))
        );
        assert_eq!(inventory, prism_sites(&enabled).expect("second read"));

        let hosts = enabled_hosts(&enabled).expect("degraded, not failed");
        assert!(hosts.truncated());
        assert_eq!(hosts.sites().len(), MAX_ENABLED_HOSTS);
        assert_eq!(hosts.sites(), inventory.sites());
    }

    #[test]
    fn exceeding_the_app_and_directory_bounds_degrades_too() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        // One file per app, past the app bound; then filler past the
        // directory bound. Names sort apps first.
        for index in 0..MAX_PRISM_APPS + 3 {
            let app = prism_app(fixture.path(), &format!("app-{index:04}"));
            vhost(
                &enabled,
                &format!("a-{index:04}.conf"),
                &format!("a{index:04}.example.test"),
                &app,
            );
        }
        let inventory = prism_sites(&enabled).expect("degraded, not failed");
        assert!(inventory.truncated());
        assert_eq!(inventory.apps().len(), MAX_PRISM_APPS);
        assert_eq!(inventory.apps()[0], "app-0000");
        assert_eq!(
            inventory.apps().last().map(String::as_str),
            Some(format!("app-{:04}", MAX_PRISM_APPS - 1).as_str())
        );
        // A host whose app was not retained is not retained either.
        assert_eq!(inventory.sites().len(), MAX_PRISM_APPS);

        let complete = enabled_hosts(&enabled).expect("hosts");
        assert!(!complete.truncated());
        for index in 0..MAX_DIRECTORY_ENTRIES {
            secure_file(
                &enabled.join(format!("z-{index:04}.conf")),
                &format!("server_name z{index:04}.example.test;\n"),
            );
        }
        let hosts = enabled_hosts(&enabled).expect("degraded, not failed");
        assert!(hosts.truncated());
        assert_eq!(hosts.sites().len(), MAX_DIRECTORY_ENTRIES);
        assert_eq!(hosts.sites()[0], "a0000.example.test");
        assert_eq!(hosts, enabled_hosts(&enabled).expect("second read"));
    }

    #[test]
    fn unreadable_or_oversized_vhosts_are_skipped_and_counted() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        let app = prism_app(fixture.path(), "alpha-app");
        vhost(&enabled, "alpha.conf", "alpha.example.test", &app);
        secure_file(
            &enabled.join("huge.conf"),
            &format!(
                "server_name huge.example.test;\n# {}\n",
                "x".repeat(usize::try_from(MAX_VHOST_BYTES).expect("bound"))
            ),
        );
        secure_file(&enabled.join("binary.conf"), "server_name b.example.test;");
        fs::write(enabled.join("binary.conf"), [0xff, 0xfe, b'\n']).expect("binary");
        let mut expected_skips = 2;
        // A vhost only its owner may read. Root reads it regardless, so the
        // unreadable case is only observable as an ordinary user.
        let private = enabled.join("private.conf");
        secure_file(&private, "server_name private.example.test;\n");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o000)).expect("mode");
        let unreadable = fs::File::open(&private).is_err();
        if unreadable {
            expected_skips += 1;
        }

        let inventory = prism_sites(&enabled).expect("one bad file is not an outage");
        assert_eq!(inventory.apps(), ["alpha-app"]);
        assert_eq!(inventory.sites(), ["alpha.example.test"]);
        assert_eq!(inventory.skipped_files(), expected_skips);
        assert!(!inventory.truncated());
        let hosts = enabled_hosts(&enabled).expect("hosts");
        assert_eq!(hosts.skipped_files(), expected_skips);
        assert_eq!(
            hosts
                .sites()
                .contains(&String::from("private.example.test")),
            !unreadable
        );
    }

    #[test]
    fn links_are_followed_only_to_targets_that_are_deployment_policy() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        let available = fixture.path().join("available");
        fs::create_dir(&available).expect("available");
        fs::set_permissions(&available, fs::Permissions::from_mode(0o755)).expect("mode");
        secure_file(
            &available.join("linked.conf"),
            "server_name linked.example.test;\n",
        );
        std::os::unix::fs::symlink(available.join("linked.conf"), enabled.join("linked.conf"))
            .expect("link");

        // A writable target, and a sound file in a writable directory.
        let writable = available.join("writable.conf");
        secure_file(&writable, "server_name writable.example.test;\n");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o666)).expect("mode");
        std::os::unix::fs::symlink(&writable, enabled.join("writable.conf")).expect("link");
        let shared = fixture.path().join("shared");
        fs::create_dir(&shared).expect("shared");
        secure_file(&shared.join("s.conf"), "server_name shared.example.test;\n");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("mode");
        std::os::unix::fs::symlink(shared.join("s.conf"), enabled.join("shared.conf"))
            .expect("link");
        std::os::unix::fs::symlink(fixture.path().join("absent"), enabled.join("dangling.conf"))
            .expect("link");
        // A subdirectory is not configuration and is not counted.
        fs::create_dir(enabled.join("conf.d")).expect("subdirectory");

        let hosts = enabled_hosts(&enabled).expect("hosts");
        assert_eq!(hosts.sites(), ["linked.example.test"]);
        assert_eq!(hosts.skipped_files(), 3);
    }

    #[test]
    fn app_root_is_shown_for_a_named_host_and_withheld_when_unsafe() {
        let fixture = tempfile::tempdir().expect("fixture");
        let enabled = enabled_directory(fixture.path());
        let alpha = prism_app(fixture.path(), "alpha-app");
        vhost(
            &enabled,
            "alpha.conf",
            "alpha.example.test www.alpha.example.test",
            &alpha,
        );
        // World-writable root: still an enabled app, but not a path to hand out.
        let open = prism_app(fixture.path(), "open-app");
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).expect("mode");
        vhost(&enabled, "open.conf", "open.example.test", &open);
        // Root reached through a link: the literal path is not the directory.
        let real = prism_app(fixture.path(), "real-app");
        let alias = fixture.path().join("bext/sites/alias-app");
        std::os::unix::fs::symlink(&real, &alias).expect("link");
        vhost(&enabled, "alias.conf", "alias.example.test", &alias);
        // Traversal segments never reach the rendered path.
        let dotted = fixture.path().join("bext/sites/../sites/alpha-app");
        vhost(&enabled, "dotted.conf", "dotted.example.test", &dotted);
        // The same app name under two trees has no single root.
        let twin_a = prism_app(&fixture.path().join("one"), "twin-app");
        let twin_b = prism_app(&fixture.path().join("two"), "twin-app");
        vhost(&enabled, "twin-a.conf", "twin-a.example.test", &twin_a);
        vhost(&enabled, "twin-b.conf", "twin-b.example.test", &twin_b);
        // Two apps in one file: its hosts map to neither.
        secure_file(
            &enabled.join("multi.conf"),
            &format!(
                "server_name multi.example.test;\nroot {};\nroot {};\n",
                alpha.display(),
                real.display()
            ),
        );

        let inventory = prism_sites(&enabled).expect("inventory");
        assert_eq!(
            inventory.apps(),
            ["alias-app", "alpha-app", "open-app", "real-app", "twin-app"]
        );
        assert_eq!(
            inventory.app_for_host("www.alpha.example.test"),
            Some("alpha-app")
        );
        // "dotted.conf" names alpha-app by a second, unshowable spelling, so
        // even the sound spelling is withheld: one app, one root, or none.
        assert_eq!(inventory.app_root("alpha-app"), None);
        fs::remove_file(enabled.join("dotted.conf")).expect("remove");
        let inventory = prism_sites(&enabled).expect("inventory");
        assert_eq!(
            inventory.app_root("alpha-app"),
            Some(alpha.to_str().expect("utf-8 fixture path"))
        );
        assert_eq!(inventory.app_root("open-app"), None);
        assert_eq!(inventory.app_root("alias-app"), None);
        assert_eq!(inventory.app_root("twin-app"), None);
        assert_eq!(inventory.app_root("absent-app"), None);
        assert_eq!(inventory.app_for_host("multi.example.test"), None);
        assert_eq!(inventory.app_for_host("absent.example.test"), None);

        // The all-hosts inventory stays path-free by construction.
        let hosts = enabled_hosts(&enabled).expect("hosts");
        assert!(hosts.sites().iter().all(|host| !host.contains('/')));
    }

    #[test]
    fn manage_profiles_beyond_the_ranking_bound_keep_honest_counts() {
        let rows = (0..MAX_MANAGE_PROFILES + 50)
            .map(|index| {
                serde_json::json!({
                    "kind": "managed",
                    "ref": format!("site-{index:05}"),
                    "label": format!("Site {index}"),
                })
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&serde_json::json!({ "value": rows })).expect("fixture");
        let inventory = decode_manage_profiles(&bytes, "").expect("degraded, not failed");
        assert_eq!(inventory.total, MAX_MANAGE_PROFILES + 50);
        assert_eq!(inventory.managed, MAX_MANAGE_PROFILES + 50);
        assert_eq!(inventory.selected.len(), MAX_SELECTED_PROFILES);
        assert_eq!(inventory.selected[0].reference, "site-00000");
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
