// SPDX-License-Identifier: Elastic-2.0

//! Offline parity comparison, scoring and gate recording.
//!
//! Three verbs over the shadow-comparison database, and every one of them is
//! **local**: no socket, no daemon, no network. That is deliberate. A parity
//! verdict is derived from evidence already durable on this host, so making it
//! travel through the administration lane would add a failure mode without
//! adding a fact — and it would make the comparison unavailable exactly when the
//! daemon is the thing under investigation.
//!
//! ```text
//! automonique parity compare <database> <scope> [--registry <path>] [--category <category>]
//! automonique parity score   <database> <scope>
//! automonique parity gate    <database> <scope> <decision-key> <decider> [--registry <path>]
//! ```
//!
//! # `compare` is the only verb that writes comparisons
//!
//! It walks each source key the scope recorded, pairs the two engines' streams
//! position by position, and records one comparison row per position — including
//! the positions where one engine decided and the other did not, because
//! deliberate silence is a difference rather than an absence of evidence.
//!
//! Comparison is idempotent by construction: the store's record-once answer
//! means running `compare` twice writes nothing the second time, and a
//! comparison whose verdict has *changed* is a conflict rather than an update.
//! A verdict that could be overwritten would let a scope's evidence improve
//! without its behaviour changing.
//!
//! # `gate` writes a decision and licenses nothing
//!
//! It records the score, the band, the per-category counts and the digest of the
//! deviation registry the decision was taken against. It does not promote a
//! scope, change a mode, or enable anything: a passing band licenses
//! *progressive* cutover on an owner's acknowledgement, never a flip. The row is
//! evidence that a decision was taken, with enough pinned to it that a later
//! registry edit cannot rewrite what was known at the time.
//!
//! # Optional registries
//!
//! A caller may supply a human-readable deviation registry. This module parses
//! it with `serde_json`, builds typed entries, and hands them to
//! [`DeviationRegistry::new`], which re-canonicalizes the entries for stable
//! comparison metrics.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use automonique_protocol::digest::Sha256;
use automonique_protocol::parity::{
    Category, Classification, DeviationEntry, DeviationRegistry, IntendedActionEnvelope,
    ParityScore, ScoredComparison, compare,
};
use automonique_protocol::wire::JsonValue;
use automonique_store::shadow_comparisons::{
    ComparisonRecord, GateCounts, GateDecisionRecord, ShadowComparisonStore,
};

/// One parity operation named on the command line.
#[derive(Clone)]
pub(crate) enum Operation {
    /// Pair the recorded streams and record one comparison per position.
    Compare {
        database: OsString,
        scope: OsString,
        flags: Vec<OsString>,
    },
    /// Compute and print the weighted score over recorded comparisons.
    Score { database: OsString, scope: OsString },
    /// Record one immutable gate decision.
    Gate {
        database: OsString,
        scope: OsString,
        decision_key: OsString,
        decider: OsString,
        flags: Vec<OsString>,
    },
}

/// A refusal from a parity verb, with a stable category.
#[derive(Debug)]
enum ParityCliError {
    /// An argument was not valid filesystem data or was outside its grammar.
    Argument(&'static str),
    /// The shadow database refused an operation.
    Store(&'static str),
    /// The deviation registry could not be read or is not the shape it claims.
    Registry(&'static str),
    /// The recorded evidence could not be scored.
    Score(&'static str),
}

impl ParityCliError {
    const fn category(&self) -> &'static str {
        match self {
            Self::Argument(_) => "invalid_argument",
            Self::Store(_) => "store",
            Self::Registry(_) => "registry",
            Self::Score(_) => "score",
        }
    }

    const fn detail(&self) -> &'static str {
        match self {
            Self::Argument(detail)
            | Self::Store(detail)
            | Self::Registry(detail)
            | Self::Score(detail) => detail,
        }
    }

    const fn exit_code(&self) -> u8 {
        match self {
            Self::Argument(_) => 2,
            _ => 1,
        }
    }
}

/// Answer one parity operation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(operation: &Operation, stdout: &mut W, stderr: &mut E) -> u8 {
    let rendered = match operation {
        Operation::Compare {
            database,
            scope,
            flags,
        } => compare_verb(database, scope, flags),
        Operation::Score { database, scope } => score_verb(database, scope),
        Operation::Gate {
            database,
            scope,
            decision_key,
            decider,
            flags,
        } => gate_verb(database, scope, decision_key, decider, flags),
    };
    match rendered {
        Ok(text) => {
            if stdout.write_all(text.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "automonique parity refused: {} ({})",
                error.category(),
                error.detail()
            );
            error.exit_code()
        }
    }
}

fn compare_verb(
    database: &OsStr,
    scope: &OsStr,
    flags: &[OsString],
) -> Result<String, ParityCliError> {
    let path = database_path(database)?;
    let scope = text(scope, "scope")?;
    let (registry_path, category) = compare_flags(flags)?;
    let registry = load_registry(registry_path.as_deref())?;
    let mut store = open(&path)?;

    let source_keys = store
        .source_keys(&scope)
        .map_err(|_| ParityCliError::Store("source_keys"))?;
    let now_ms = now_ms();
    let mut recorded = 0_usize;
    let mut replayed = 0_usize;
    let mut regressions = 0_usize;
    for source_key in &source_keys {
        let shadow = envelopes(&store, &scope, source_key, "shadow-candidate")?;
        let legacy = envelopes(&store, &scope, source_key, "legacy-observed")?;
        let positions = shadow.len().max(legacy.len());
        for position in 0..positions {
            let comparison = compare(shadow.get(position), legacy.get(position));
            // The kind used for classification is the candidate's when there is
            // one, and the reference engine's otherwise. A registry entry names
            // an action kind, and a position with no candidate still has to be
            // classifiable against one.
            let kind = shadow
                .get(position)
                .or_else(|| legacy.get(position))
                .map(|envelope| envelope.action().kind());
            let (classification, ids) = match kind {
                Some(kind) => registry.classify(&scope, kind, &comparison),
                None => (Classification::Parity, Vec::new()),
            };
            if classification == Classification::Regression {
                regressions = regressions.saturating_add(1);
            }
            let diff = comparison.to_canonical_bytes();
            let diff_digest = comparison.content_digest().to_hex();
            let sequence = i64::try_from(position)
                .map_err(|_| ParityCliError::Store("sequence_unrepresentable"))?;
            let receipt = store
                .record_comparison(ComparisonRecord {
                    scope: &scope,
                    source_key,
                    sequence,
                    verdict: comparison.verdict().as_str(),
                    classification: classification.as_str(),
                    deviation_id: ids.first().map(String::as_str),
                    category: category.as_str(),
                    diff: &diff,
                    diff_digest: &diff_digest,
                    compared_at_ms: now_ms,
                })
                .map_err(|_| ParityCliError::Store("record_comparison"))?;
            if receipt.disposition.is_replay() {
                replayed = replayed.saturating_add(1);
            } else {
                recorded = recorded.saturating_add(1);
            }
        }
    }
    Ok(format!(
        "compared {} source key(s) in {scope}\nrecorded {recorded}\nreplayed {replayed}\nregressions {regressions}\n",
        source_keys.len()
    ))
}

fn score_verb(database: &OsStr, scope: &OsStr) -> Result<String, ParityCliError> {
    let path = database_path(database)?;
    let scope = text(scope, "scope")?;
    let store = open(&path)?;
    let (score, _) = scored(&store, &scope)?;
    let mut rendered = format!(
        "scope {scope}\nscore {}\nband {}\n",
        score.score(),
        score.band().as_str()
    );
    for category in Category::ALL {
        let count = score.count(category);
        rendered.push_str(&format!(
            "{} {}/{}\n",
            category.as_str(),
            count.accounted,
            count.total
        ));
    }
    Ok(rendered)
}

fn gate_verb(
    database: &OsStr,
    scope: &OsStr,
    decision_key: &OsStr,
    decider: &OsStr,
    flags: &[OsString],
) -> Result<String, ParityCliError> {
    let path = database_path(database)?;
    let scope = text(scope, "scope")?;
    let decision_key = text(decision_key, "decision_key")?;
    let decider = text(decider, "decider")?;
    let registry_path = gate_flags(flags)?;
    let registry = load_registry(registry_path.as_deref())?;
    let mut store = open(&path)?;
    let (score, evidence_digest) = scored(&store, &scope)?;
    let registry_digest = registry.digest().to_hex();
    let counts = |category: Category| {
        let count = score.count(category);
        GateCounts {
            total: i64::from(count.total),
            accounted: i64::from(count.accounted),
        }
    };
    store
        .record_gate_decision(GateDecisionRecord {
            decision_key: &decision_key,
            scope: &scope,
            score: i64::from(score.score()),
            band: score.band().as_str(),
            happy: counts(Category::Happy),
            error: counts(Category::Error),
            edge: counts(Category::Edge),
            variety: counts(Category::Variety),
            production: counts(Category::ProductionRepresentative),
            registry_digest: &registry_digest,
            evidence_digest: &evidence_digest,
            decided_at_ms: now_ms(),
            decider: &decider,
        })
        .map_err(|_| ParityCliError::Store("record_gate_decision"))?;
    Ok(format!(
        "recorded {decision_key} for {scope}\nscore {}\nband {}\nregistry {registry_digest}\nevidence {evidence_digest}\n\
         a band is evidence for a decision, never the decision: nothing was promoted.\n",
        score.score(),
        score.band().as_str()
    ))
}

/// Score one scope's recorded comparisons, and digest the evidence scored.
///
/// The evidence digest is over the canonical rendering of exactly the rows that
/// entered the score, so a decision cannot later be said to have been taken over
/// a different corpus.
fn scored(
    store: &ShadowComparisonStore,
    scope: &str,
) -> Result<(ParityScore, String), ParityCliError> {
    let rows = store
        .comparisons(scope)
        .map_err(|_| ParityCliError::Store("comparisons"))?;
    let mut corpus = Vec::with_capacity(rows.len());
    let mut evidence = Vec::with_capacity(rows.len());
    for row in rows {
        let category = wire_category(&row.category)?;
        let classification = wire_classification(&row.classification)?;
        corpus.push(ScoredComparison {
            category,
            classification,
        });
        evidence.push(JsonValue::Object(vec![
            (
                "category".to_owned(),
                JsonValue::String(category.as_str().to_owned()),
            ),
            (
                "classification".to_owned(),
                JsonValue::String(classification.as_str().to_owned()),
            ),
            ("diff_digest".to_owned(), JsonValue::String(row.diff_digest)),
            ("sequence".to_owned(), JsonValue::Integer(row.sequence)),
            ("source_key".to_owned(), JsonValue::String(row.source_key)),
        ]));
    }
    let score = ParityScore::compute(&corpus).map_err(|_| ParityCliError::Score("compute"))?;
    let document = JsonValue::Object(vec![
        ("comparisons".to_owned(), JsonValue::Array(evidence)),
        ("scope".to_owned(), JsonValue::String(scope.to_owned())),
    ]);
    let digest = Sha256::digest(&document.to_canonical_bytes()).to_hex();
    Ok((score, digest))
}

fn envelopes(
    store: &ShadowComparisonStore,
    scope: &str,
    source_key: &str,
    engine: &str,
) -> Result<Vec<IntendedActionEnvelope>, ParityCliError> {
    let rows = store
        .intended_actions(scope, source_key, engine)
        .map_err(|_| ParityCliError::Store("intended_actions"))?;
    let mut decoded = Vec::with_capacity(rows.len());
    for row in rows {
        decoded.push(
            IntendedActionEnvelope::from_canonical_bytes(&row.envelope)
                .map_err(|_| ParityCliError::Store("envelope_undecodable"))?,
        );
    }
    Ok(decoded)
}

/// Read the derived deviation ledger and build the digest-pinned registry.
///
/// An absent `--registry` is the empty registry, under which every mismatch is a
/// regression. That is the conservative default and it is the honest one: a run
/// that forgot to name the registry must not silently *excuse* differences.
fn load_registry(path: Option<&Path>) -> Result<DeviationRegistry, ParityCliError> {
    let Some(path) = path else {
        return Ok(DeviationRegistry::empty());
    };
    let raw = std::fs::read(path).map_err(|_| ParityCliError::Registry("unreadable"))?;
    let document: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| ParityCliError::Registry("not_json"))?;
    let entries = document
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or(ParityCliError::Registry("entries_absent"))?;
    let mut typed = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = |name: &str| {
            entry
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or(ParityCliError::Registry("entry_field_absent"))
        };
        typed.push(
            DeviationEntry::new(
                field("id")?,
                field("scope")?,
                wire_enum(field("action_kind")?, "action_kind")?,
                wire_enum(field("field")?, "field")?,
                wire_enum(field("relation")?, "relation")?,
                wire_enum(field("reason")?, "reason")?,
            )
            .map_err(|_| ParityCliError::Registry("entry_invalid"))?,
        );
    }
    DeviationRegistry::new(typed).map_err(|_| ParityCliError::Registry("registry_invalid"))
}

fn wire_enum<T: automonique_protocol::codec::SecuritySensitiveEnum>(
    value: &str,
    field: &'static str,
) -> Result<T, ParityCliError> {
    let _ = field;
    T::from_wire(value).ok_or(ParityCliError::Registry("unknown_spelling"))
}

fn wire_category(value: &str) -> Result<Category, ParityCliError> {
    Category::ALL
        .into_iter()
        .find(|category| category.as_str() == value)
        .ok_or(ParityCliError::Score("unknown_category"))
}

fn wire_classification(value: &str) -> Result<Classification, ParityCliError> {
    Classification::ALL
        .into_iter()
        .find(|classification| classification.as_str() == value)
        .ok_or(ParityCliError::Score("unknown_classification"))
}

/// Live rows are production traffic, so that is what an unflagged `compare`
/// records them as. A fixture replay names its category in the trace header.
fn compare_flags(flags: &[OsString]) -> Result<(Option<PathBuf>, Category), ParityCliError> {
    let mut registry = None;
    let mut category = Category::ProductionRepresentative;
    let mut words = flags.iter();
    while let Some(flag) = words.next() {
        match flag.to_str() {
            Some("--registry") => {
                let value = words.next().ok_or(ParityCliError::Argument("registry"))?;
                registry = Some(PathBuf::from(value));
            }
            Some("--category") => {
                let value = words
                    .next()
                    .and_then(|value| value.to_str())
                    .ok_or(ParityCliError::Argument("category"))?;
                category =
                    wire_category(value).map_err(|_| ParityCliError::Argument("category"))?;
            }
            _ => return Err(ParityCliError::Argument("flag")),
        }
    }
    Ok((registry, category))
}

fn gate_flags(flags: &[OsString]) -> Result<Option<PathBuf>, ParityCliError> {
    let mut registry = None;
    let mut words = flags.iter();
    while let Some(flag) = words.next() {
        match flag.to_str() {
            Some("--registry") => {
                let value = words.next().ok_or(ParityCliError::Argument("registry"))?;
                registry = Some(PathBuf::from(value));
            }
            _ => return Err(ParityCliError::Argument("flag")),
        }
    }
    Ok(registry)
}

fn open(path: &Path) -> Result<ShadowComparisonStore, ParityCliError> {
    ShadowComparisonStore::open(path).map_err(|_| ParityCliError::Store("open"))
}

fn database_path(value: &OsStr) -> Result<PathBuf, ParityCliError> {
    if value.is_empty() {
        return Err(ParityCliError::Argument("database"));
    }
    Ok(PathBuf::from(value))
}

fn text(value: &OsStr, field: &'static str) -> Result<String, ParityCliError> {
    value
        .to_str()
        .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(ParityCliError::Argument(field))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}
