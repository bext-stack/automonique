// SPDX-License-Identifier: Elastic-2.0

//! Bounded, provenance-bearing local entity knowledge.
//!
//! The catalog is an optional operator-maintained projection beneath the
//! daemon state directory. It is reloaded for each lookup, so adding or
//! correcting knowledge does not restart the daemon or interrupt an active
//! question. Catalog text is evidence, never policy, and is rendered into the
//! same untrusted-data boundary as every other operational source.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CATALOG_RELATIVE: &str = "knowledge/catalog.json";
const CATALOG_SCHEMA: &str = "automonique.local-knowledge/v1";
const MAX_CATALOG_BYTES: u64 = 128 * 1024;
const MAX_ENTITIES: usize = 128;
const MAX_MATCHES: usize = 4;
const MAX_ALIASES: usize = 16;
const MAX_FACTS: usize = 16;
const MAX_ID_BYTES: usize = 64;
const MAX_NAME_BYTES: usize = 128;
const MAX_ALIAS_BYTES: usize = 128;
const MAX_CLAIM_BYTES: usize = 512;
const MAX_SOURCE_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatalogFailure {
    Insecure,
    Unavailable,
    Malformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClaimBasis {
    OperatorAsserted,
    LocalObservation,
    PrimarySource,
}

impl ClaimBasis {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorAsserted => "operator_asserted",
            Self::LocalObservation => "local_observation",
            Self::PrimarySource => "primary_source",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct KnowledgeClaim {
    pub(crate) text: String,
    pub(crate) basis: ClaimBasis,
    pub(crate) source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct KnowledgeEntity {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) aliases: Vec<String>,
    pub(crate) description: KnowledgeClaim,
    pub(crate) facts: Vec<KnowledgeClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    schema: String,
    entities: Vec<KnowledgeEntity>,
}

pub(crate) struct KnowledgeSelection {
    pub(crate) total: usize,
    pub(crate) matched: Vec<KnowledgeEntity>,
}

pub(crate) fn catalog_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CATALOG_RELATIVE)
}

/// Load and match the optional catalog without creating it.
pub(crate) fn lookup(
    path: &Path,
    question: &str,
) -> Result<Option<KnowledgeSelection>, CatalogFailure> {
    let Some(document) = load(path)? else {
        return Ok(None);
    };
    let question_terms = significant_terms(question);
    if question_terms.is_empty() {
        return Ok(Some(KnowledgeSelection {
            total: document.entities.len(),
            matched: Vec::new(),
        }));
    }
    let mut ranked = document
        .entities
        .into_iter()
        .filter_map(|entity| {
            let score = entity_score(&entity, &question_terms);
            (score > 0).then_some((score, entity))
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.id.cmp(&right.1.id))
    });
    let total = ranked.len();
    let matched = ranked
        .into_iter()
        .take(MAX_MATCHES)
        .map(|(_, entity)| entity)
        .collect();
    Ok(Some(KnowledgeSelection { total, matched }))
}

fn load(path: &Path) -> Result<Option<CatalogDocument>, CatalogFailure> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CatalogFailure::Unavailable),
    };
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_CATALOG_BYTES
    {
        return Err(CatalogFailure::Insecure);
    }
    let bytes = fs::read(path).map_err(|_| CatalogFailure::Unavailable)?;
    let document: CatalogDocument =
        serde_json::from_slice(&bytes).map_err(|_| CatalogFailure::Malformed)?;
    validate(document)
}

fn validate(document: CatalogDocument) -> Result<Option<CatalogDocument>, CatalogFailure> {
    if document.schema != CATALOG_SCHEMA
        || document.entities.is_empty()
        || document.entities.len() > MAX_ENTITIES
    {
        return Err(CatalogFailure::Malformed);
    }
    let mut identities: HashMap<String, String> = HashMap::new();
    for entity in &document.entities {
        if !valid_id(&entity.id)
            || !valid_text(&entity.name, MAX_NAME_BYTES)
            || entity.aliases.len() > MAX_ALIASES
            || entity.facts.len() > MAX_FACTS
            || !valid_claim(&entity.description)
            || entity.facts.iter().any(|claim| !valid_claim(claim))
        {
            return Err(CatalogFailure::Malformed);
        }
        let mut names = Vec::with_capacity(entity.aliases.len() + 2);
        names.push(entity.id.as_str());
        names.push(entity.name.as_str());
        names.extend(entity.aliases.iter().map(String::as_str));
        for name in names {
            if !valid_text(name, MAX_ALIAS_BYTES) || significant_terms(name).is_empty() {
                return Err(CatalogFailure::Malformed);
            }
            let identity = normalized_identity(name);
            if let Some(owner) = identities.get(&identity) {
                if owner != &entity.id {
                    return Err(CatalogFailure::Malformed);
                }
            } else {
                identities.insert(identity, entity.id.clone());
            }
        }
    }
    Ok(Some(document))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_claim(claim: &KnowledgeClaim) -> bool {
    valid_text(&claim.text, MAX_CLAIM_BYTES) && valid_text(&claim.source, MAX_SOURCE_BYTES)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn normalized_identity(value: &str) -> String {
    significant_terms(value)
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ")
}

fn entity_score(entity: &KnowledgeEntity, question_terms: &BTreeSet<String>) -> usize {
    std::iter::once(entity.id.as_str())
        .chain(std::iter::once(entity.name.as_str()))
        .chain(entity.aliases.iter().map(String::as_str))
        .map(significant_terms)
        .filter(|alias_terms| !alias_terms.is_empty() && alias_terms.is_subset(question_terms))
        .map(|alias_terms| alias_terms.len())
        .max()
        .unwrap_or(0)
}

fn significant_terms(value: &str) -> BTreeSet<String> {
    value
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 3)
        .filter(|term| {
            !matches!(
                *term,
                "about"
                    | "app"
                    | "application"
                    | "com"
                    | "dev"
                    | "for"
                    | "know"
                    | "net"
                    | "org"
                    | "platform"
                    | "server"
                    | "service"
                    | "site"
                    | "system"
                    | "tell"
                    | "the"
                    | "this"
                    | "what"
                    | "who"
                    | "with"
                    | "www"
                    | "you"
            )
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn catalog() -> &'static str {
        r#"{
          "schema":"automonique.local-knowledge/v1",
          "entities":[{
            "id":"acme",
            "name":"Acme",
            "aliases":["acme.example","acme-stack"],
            "description":{"text":"A bounded fixture entity.","basis":"operator_asserted","source":"fixture"},
            "facts":[{"text":"It has one observed service.","basis":"local_observation","source":"fixture inventory"}]
          }]
        }"#
    }

    fn fixture(contents: &str, mode: u32) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("catalog.json");
        fs::write(&path, contents).expect("catalog");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mode");
        (root, path)
    }

    #[test]
    fn catalog_matches_named_entities_without_capturing_general_chat() {
        let (_root, path) = fixture(catalog(), 0o600);
        let selected = lookup(&path, "What do you know about Acme?")
            .expect("lookup")
            .expect("attached");
        assert_eq!(selected.total, 1);
        assert_eq!(selected.matched[0].id, "acme");

        let general = lookup(&path, "what colour is an elephant?")
            .expect("lookup")
            .expect("attached");
        assert!(general.matched.is_empty());
    }

    #[test]
    fn absent_catalog_is_optional_but_insecure_or_ambiguous_catalogs_refuse() {
        let root = tempfile::tempdir().expect("root");
        assert!(
            lookup(&root.path().join("absent"), "acme")
                .expect("optional")
                .is_none()
        );

        let (_root, insecure) = fixture(catalog(), 0o644);
        assert!(matches!(
            lookup(&insecure, "acme"),
            Err(CatalogFailure::Insecure)
        ));

        let ambiguous = catalog().replace(
            "]\n          }]",
            "]\n          },{\"id\":\"other\",\"name\":\"Other\",\"aliases\":[\"acme\"],\"description\":{\"text\":\"Other fixture.\",\"basis\":\"operator_asserted\",\"source\":\"fixture\"},\"facts\":[]}]",
        );
        let (_root, ambiguous_path) = fixture(&ambiguous, 0o600);
        assert!(matches!(
            lookup(&ambiguous_path, "acme"),
            Err(CatalogFailure::Malformed)
        ));
    }
}
