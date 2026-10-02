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
pub enum CatalogFailure {
    Insecure,
    Unavailable,
    Malformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimBasis {
    OperatorAsserted,
    LocalObservation,
    PrimarySource,
}

impl ClaimBasis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorAsserted => "operator_asserted",
            Self::LocalObservation => "local_observation",
            Self::PrimarySource => "primary_source",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeClaim {
    pub text: String,
    pub basis: ClaimBasis,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEntity {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub description: KnowledgeClaim,
    pub facts: Vec<KnowledgeClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    schema: String,
    entities: Vec<KnowledgeEntity>,
}

pub struct KnowledgeSelection {
    pub total: usize,
    pub matched: Vec<KnowledgeEntity>,
}

pub fn catalog_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CATALOG_RELATIVE)
}

/// Load and match the optional catalog without creating it.
pub fn lookup(path: &Path, question: &str) -> Result<Option<KnowledgeSelection>, CatalogFailure> {
    let Some(document) = load(path)? else {
        return Ok(None);
    };
    let question_terms = question_match_terms(question);
    if question_terms.is_empty() {
        return Ok(Some(KnowledgeSelection {
            total: document.entities.len(),
            matched: Vec::new(),
        }));
    }
    let own_terms = question_own_terms(question);
    let mut ranked = document
        .entities
        .into_iter()
        .filter_map(|entity| {
            let score = entity_score(&entity, &question_terms, &own_terms);
            (score.1 > 0).then_some((score, entity))
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

/// How well a question names one entity: whether it does so in its own words
/// (see [`question_own_terms`]), then how many words of the best-matching
/// name it spells. `(false, 0)` is no match.
fn entity_score(
    entity: &KnowledgeEntity,
    question_terms: &BTreeSet<String>,
    own_terms: &BTreeSet<String>,
) -> (bool, usize) {
    std::iter::once(entity.id.as_str())
        .chain(std::iter::once(entity.name.as_str()))
        .chain(entity.aliases.iter().map(String::as_str))
        .map(alias_match_terms)
        .filter(|alias_terms| !alias_terms.is_empty() && alias_terms.is_subset(question_terms))
        .map(|alias_terms| (!alias_terms.is_disjoint(own_terms), alias_terms.len()))
        .max()
        .unwrap_or((false, 0))
}

/// The question's terms without the parent domain of each hostname it names.
///
/// "shop.platform.example" names the shop. Its parent domain also spells the
/// platform's own name, so the platform entity still matches, but it must
/// rank below an entity the request names directly, however many words the
/// platform's domain happens to have. A host with nothing significant before
/// its last two labels ("www.shop.example") is the site itself and keeps
/// every term.
fn question_own_terms(question: &str) -> BTreeSet<String> {
    let folded = fold_diacritics(&question.to_lowercase());
    let mut own = String::with_capacity(folded.len());
    for word in folded.split_whitespace() {
        let host = word.trim_matches(|character: char| !character.is_alphanumeric());
        let labels: Vec<&str> = host.split('.').collect();
        let is_subdomain = labels.len() >= 3
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '-')
            });
        let leading = labels[..labels.len().saturating_sub(2)].join(" ");
        if is_subdomain && !significant_terms(&leading).is_empty() {
            own.push_str(&leading);
        } else {
            own.push_str(word);
        }
        own.push(' ');
    }
    let mut terms = significant_terms(&own);
    terms.extend(apostrophe_compounds(&folded));
    terms
}

/// The words a question is matched by: its significant terms with accents
/// folded, plus each name it writes with an apostrophe in the joined form a
/// deployment uses ("Regal'Terre" also offers "regalterre").
///
/// Matching is deliberately looser than [`normalized_identity`], which keeps
/// deciding whether two catalog names collide: loosening that would turn a
/// catalog that loads today into a malformed one.
fn question_match_terms(question: &str) -> BTreeSet<String> {
    let folded = fold_diacritics(&question.to_lowercase());
    let mut terms = significant_terms(&folded);
    terms.extend(apostrophe_compounds(&folded));
    terms
}

/// The words that must all occur in a question for one catalog name to match.
///
/// A deployment alias carries its framework suffix ("shop-prism"), but a
/// request names the site ("shop"), so the suffix is not required when the
/// alias has another word to be recognised by. A name written with an
/// apostrophe is also offered joined, as [`question_match_terms`] does.
fn alias_match_terms(alias: &str) -> BTreeSet<String> {
    let mut terms = significant_terms(&fold_diacritics(&alias.to_lowercase()));
    if terms.len() > 1 {
        terms.remove("prism");
    }
    terms
}

/// Replace accented Latin letters in lowercase text by their plain form, so a
/// request typed without accents (or a deployment label, which has none)
/// matches a name written with them.
pub(crate) fn fold_diacritics(lowercase: &str) -> String {
    let mut folded = String::with_capacity(lowercase.len());
    for character in lowercase.chars() {
        match character {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => folded.push('a'),
            'ç' => folded.push('c'),
            'è' | 'é' | 'ê' | 'ë' => folded.push('e'),
            'ì' | 'í' | 'î' | 'ï' => folded.push('i'),
            'ñ' => folded.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' => folded.push('o'),
            'ù' | 'ú' | 'û' | 'ü' => folded.push('u'),
            'ý' | 'ÿ' => folded.push('y'),
            'æ' => folded.push_str("ae"),
            'œ' => folded.push_str("oe"),
            other => folded.push(other),
        }
    }
    folded
}

/// Names written with an apostrophe, joined: "regal'terre" gives
/// "regalterre". An elision ("l'adresse") is grammar, not a name, so the part
/// before the apostrophe must be a word of its own.
pub(crate) fn apostrophe_compounds(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter_map(|word| {
            let (head, tail) = word.split_once(['\'', '’'])?;
            let letters = |part: &str| -> String {
                part.chars()
                    .filter(|character| character.is_alphanumeric())
                    .collect()
            };
            let (head, tail) = (letters(head), letters(tail));
            (head.len() >= 3 && !tail.is_empty()).then(|| format!("{head}{tail}"))
        })
        .collect()
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
    fn hostnames_tags_accents_and_framework_suffixes_find_their_entity() {
        let catalog = r#"{
          "schema":"automonique.local-knowledge/v1",
          "entities":[{
            "id":"hosting-stack",
            "name":"Hosting Stack",
            "aliases":["hosting-stack.test"],
            "description":{"text":"The hosting namespace.","basis":"operator_asserted","source":"fixture"},
            "facts":[]
          },{
            "id":"regal-terre",
            "name":"Régal'Terre",
            "aliases":["regalterre-prism","regalterre.hosting-stack.test"],
            "description":{"text":"A shop.","basis":"operator_asserted","source":"fixture"},
            "facts":[]
          },{
            "id":"acme-communication",
            "name":"Acme Communication",
            "aliases":["acme-communication-prism"],
            "description":{"text":"An agency site.","basis":"operator_asserted","source":"fixture"},
            "facts":[]
          }]
        }"#;
        let (_root, path) = fixture(catalog, 0o600);
        let first = |question: &str| {
            lookup(&path, question)
                .expect("lookup")
                .expect("attached")
                .matched
                .first()
                .map(|entity| entity.id.clone())
        };
        // The app alias without its framework suffix, as a ticket tag.
        assert_eq!(
            first("[REGALTERRE] page paiement").as_deref(),
            Some("regal-terre")
        );
        // Typed without the accent, joined across the apostrophe.
        assert_eq!(
            first("[Regal'Terre] page paiement").as_deref(),
            Some("regal-terre")
        );
        assert_eq!(
            first("corriger le panier de Régalterre").as_deref(),
            Some("regal-terre")
        );
        // A hostname names the app whose alias carries the framework suffix,
        // and that outranks the platform entity the host's domain also names,
        // even though the platform's domain spells more words.
        let matched = lookup(
            &path,
            "[ACME] page dépliant acme-communication.hosting-stack.test",
        )
        .expect("lookup")
        .expect("attached")
        .matched;
        assert_eq!(
            matched
                .iter()
                .map(|entity| entity.id.as_str())
                .collect::<Vec<_>>(),
            ["acme-communication", "hosting-stack"]
        );
        // With no entity of its own, a host still finds its platform; and a
        // bare domain names the platform outright.
        assert_eq!(
            first("fix unknown-shop.hosting-stack.test").as_deref(),
            Some("hosting-stack")
        );
        assert_eq!(
            first("what is hosting-stack.test?").as_deref(),
            Some("hosting-stack")
        );
        // The suffix alone names nothing.
        assert_eq!(first("update the prism framework"), None);
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
