// SPDX-License-Identifier: Elastic-2.0

//! Replay a live attention capture through ShellDeck's real attention board.
//!
//! This is an entry point, not an implementation. Every decision it reports is
//! made by `shelldeck_core::config::platform_attention` — the same module the
//! desktop build links — and by the protocol decoders in
//! `automonique_protocol`. Nothing here re-derives a source inventory, a
//! revision chain, or a visible item set; a second implementation that agreed
//! with itself would prove nothing.
//!
//! It reads one `automonique.attention-live-replay-input/v1` document on stdin
//! and prints one `automonique.attention-live-projection/v1` document on
//! stdout. `tools/run_attention_live_parity.py` writes the input and compares
//! the output against the other two clients'.
//!
//! It is built against whichever ShellDeck checkout the operator names, with
//! the protocol revision that checkout pins, because the claim under test is
//! about the ShellDeck a user runs and not about a version of it assembled
//! here.

use std::collections::BTreeMap;

use automonique_platform_client::platform_v2_client::AttentionReadResult;
use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId, WorkContextRecord};
use automonique_protocol::platform_v2_api::decode_work_context_page;
use automonique_protocol::platform_v2_attention_api::decode_attention_source_snapshot;
use automonique_protocol::platform_v2_transport::PlatformV2Refusal;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use shelldeck_core::config::platform_attention::{
    AttentionApplyOutcome, AttentionError, AttentionSource, AttentionSourceId,
    AttentionSourceInventory,
    AttentionSourceKind, AttentionSourceStatus, AttentionUnavailableReason,
    PlatformAttentionBoard, PlatformAttentionTarget, ReviewAttentionPresence,
};

const INPUT_SCHEMA: &str = "automonique.attention-live-replay-input/v1";
const OUTPUT_SCHEMA: &str = "automonique.attention-live-projection/v1";
const CLIENT: &str = "shelldeck";

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("input document has no `{name}`"))
}

fn string(value: &Value, name: &str) -> Result<String, String> {
    field(value, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("`{name}` is not a string"))
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value)
        .map_err(|_| "canonical payload is not base64".to_owned())
}

fn source_key(source: &AttentionSource) -> String {
    format!("{}:{}", source.kind().as_str(), source.id().as_str())
}

fn parse_source(value: &Value) -> Result<AttentionSource, String> {
    let kind = match string(value, "kind")?.as_str() {
        "review" => AttentionSourceKind::Review,
        "orchestration" => AttentionSourceKind::Orchestration,
        "provider_session" => AttentionSourceKind::ProviderSession,
        other => return Err(format!("attention source kind {other} is unknown")),
    };
    let id = AttentionSourceId::new(string(value, "id")?)
        .map_err(|_| "attention source id is not a source id".to_owned())?;
    Ok(AttentionSource::new(kind, id))
}

/// Decode every captured work-context page with the protocol's own decoder.
///
/// The pages are the exact canonical bytes the deployment served. Decoding them
/// here rather than accepting a re-serialized mirror is the difference between
/// checking ShellDeck against the deployment and checking it against the
/// harness.
fn records(pages: &Value) -> Result<Vec<WorkContextRecord>, String> {
    let pages = pages
        .as_array()
        .ok_or_else(|| "`work_context_pages_canonical_base64` is not an array".to_owned())?;
    let mut records = Vec::new();
    for page in pages {
        let payload = decode(
            page.as_str()
                .ok_or_else(|| "a captured page is not a string".to_owned())?,
        )?;
        let page = decode_work_context_page(&payload)
            .map_err(|_| "a captured work-context page did not decode".to_owned())?;
        records.extend(page.items().iter().cloned());
    }
    Ok(records)
}

fn review_presence(value: &str) -> Result<ReviewAttentionPresence, String> {
    match value {
        "present" => Ok(ReviewAttentionPresence::Present),
        "absent" => Ok(ReviewAttentionPresence::Absent),
        other => Err(format!("review presence {other} is unknown")),
    }
}

/// Name a board refusal as a bare category token.
///
/// The `Debug` spelling of a Rust enum is not a category: it varies with the
/// variant name and a reader downstream cannot match it against Mobile's, which
/// already uses tokens. This mapping is total, so a variant added upstream
/// stops this driver compiling rather than silently becoming `unknown`.
fn error_category(error: &AttentionError) -> &'static str {
    match error {
        AttentionError::MappingNotExact => "attention_mapping_not_exact",
        AttentionError::MappingInvalid => "attention_mapping_invalid",
        AttentionError::InventoryTooLarge => "attention_inventory_too_large",
        AttentionError::InventoryDuplicate => "attention_inventory_duplicate_record",
        AttentionError::WorkspaceMissingOrAmbiguous => {
            "attention_workspace_missing_or_ambiguous"
        }
        AttentionError::WorkspaceProjectMismatch => "attention_workspace_project_mismatch",
        AttentionError::SourceInvalid => "attention_source_invalid",
        AttentionError::ProviderSessionRelationInvalid => {
            "attention_provider_session_relation_invalid"
        }
        AttentionError::SourceDuplicate => "attention_source_duplicate",
        AttentionError::SourceInventoryTooLarge => "attention_source_inventory_too_large",
        AttentionError::SourceNotInventoried => "attention_source_not_inventoried",
        AttentionError::SourceMismatch => "attention_source_mismatch",
        AttentionError::TargetMismatch => "attention_target_mismatch",
        AttentionError::InitialRevisionRequired => "attention_initial_revision_required",
        AttentionError::InvalidSuccessor => "attention_successor_invalid",
        AttentionError::InvalidBaseline => "attention_baseline_invalid",
        AttentionError::ConflictingReplay => "attention_conflicting_replay",
        AttentionError::UiIdentityCollision => "attention_ui_identity_collision",
    }
}

/// The board's own outcome vocabulary, spelled the way the shared corpus and
/// Mobile spell it, so the two clients' outcomes can be compared directly.
fn outcome_token(outcome: AttentionApplyOutcome) -> &'static str {
    match outcome {
        AttentionApplyOutcome::Inserted => "inserted",
        AttentionApplyOutcome::Replaced => "replaced",
        AttentionApplyOutcome::ExactReplay => "exact_replay",
        AttentionApplyOutcome::AvailabilityRestored => "availability_restored",
        AttentionApplyOutcome::Refused => "refused",
    }
}

fn unavailable_token(reason: AttentionUnavailableReason) -> &'static str {
    match reason {
        AttentionUnavailableReason::NotObserved => "not_observed",
        AttentionUnavailableReason::Transport => "transport",
        AttentionUnavailableReason::Protocol => "protocol",
        AttentionUnavailableReason::InventoryIncomplete => "inventory_incomplete",
    }
}

fn status_json(status: Option<&AttentionSourceStatus>) -> Value {
    match status {
        Some(AttentionSourceStatus::Available) => json!({ "kind": "available" }),
        Some(AttentionSourceStatus::Refused { category }) => {
            json!({ "kind": "refused", "category": category.as_str() })
        }
        Some(AttentionSourceStatus::Unavailable(reason)) => json!({
            "kind": "unavailable",
            "reason": unavailable_token(*reason)
        }),
        // A source the board does not carry at all. Distinct from every status
        // above, and never to be smoothed into `unavailable`: the client is not
        // hiding a source it knows about, it never inventoried one.
        None => json!({ "kind": "absent" }),
    }
}

/// Apply exactly one captured read, in the client's own vocabulary.
///
/// `refusal` and `unavailable` are not interchangeable. A refusal is something
/// the server said; `transport` is the client noticing the server said nothing.
/// Collapsing them would let a replay report a server category the deployment
/// never sent.
fn apply(board: &mut PlatformAttentionBoard, source: &AttentionSource, read: &Value) -> Value {
    let outcome = match string(read, "kind") {
        Err(message) => return json!({ "state": "input_invalid", "detail": message }),
        Ok(kind) => match kind.as_str() {
            "snapshot" => {
                let payload = match string(read, "snapshot_canonical_base64").and_then(|value| decode(&value)) {
                    Ok(payload) => payload,
                    Err(message) => return json!({ "state": "input_invalid", "detail": message }),
                };
                let snapshot = match decode_attention_source_snapshot(&payload) {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        return json!({
                            "state": "decode_refused",
                            "detail": "the captured snapshot did not decode"
                        });
                    }
                };
                let result = match read.get("mode").and_then(Value::as_str).unwrap_or("continuous") {
                    "baseline" => board.apply_authenticated_baseline_read(
                        source,
                        AttentionReadResult::Snapshot(Box::new(snapshot)),
                    ),
                    _ => board.apply_read(source, AttentionReadResult::Snapshot(Box::new(snapshot))),
                };
                match result {
                    Ok(outcome) => json!({
                        "state": "applied",
                        "outcome": outcome_token(outcome)
                    }),
                    Err(error) => json!({
                        "state": "refused",
                        "error": error_category(&error)
                    }),
                }
            }
            "refusal" => {
                let category = match string(read, "category") {
                    Ok(category) => category,
                    Err(message) => return json!({ "state": "input_invalid", "detail": message }),
                };
                match PlatformV2Refusal::new(category.clone(), "live capture")
                    .map_err(|_| ())
                    .and_then(|refusal| board.mark_refused(source, &refusal).map_err(|_| ()))
                {
                    Ok(()) => json!({ "state": "refused_by_server", "category": category }),
                    Err(()) => json!({ "state": "refusal_not_representable", "category": category }),
                }
            }
            "unavailable" => {
                let reason = read
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("transport");
                let reason = match reason {
                    "transport" => AttentionUnavailableReason::Transport,
                    "inventory_incomplete" => AttentionUnavailableReason::InventoryIncomplete,
                    other => {
                        return json!({
                            "state": "input_invalid",
                            "detail": format!("unavailable reason {other} is not one a read can assert")
                        });
                    }
                };
                match board.mark_unavailable(source, reason) {
                    Ok(()) => json!({
                        "state": "unavailable",
                        "reason": unavailable_token(reason)
                    }),
                    Err(error) => json!({
                        "state": "refused",
                        "error": error_category(&error)
                    }),
                }
            }
            other => json!({
                "state": "input_invalid",
                "detail": format!("read kind {other} is unknown")
            }),
        },
    };
    outcome
}

fn project(board: &PlatformAttentionBoard, sources: &[AttentionSource]) -> Value {
    let mut per_source = serde_json::Map::new();
    for source in sources {
        let visible: Vec<String> = board
            .visible_items()
            .filter(|item| item.key().source() == source)
            .map(|item| item.value().id().as_str().to_owned())
            .collect();
        per_source.insert(
            source_key(source),
            json!({
                "status": status_json(board.status(source)),
                "generation": board
                    .retained_snapshot(source)
                    .map(|snapshot| snapshot.revision().to_string()),
                "visible_items": visible,
            }),
        );
    }
    let visible: Vec<Value> = board
        .visible_items()
        .map(|item| {
            json!({
                "source": source_key(item.key().source()),
                "item": item.value().id().as_str(),
                "state": item.value().state().as_str(),
                "reason": item.value().reason().as_str(),
            })
        })
        .collect();
    json!({
        "sources": Value::Object(per_source),
        "visible_items": visible,
        "presents_attention": !visible.is_empty(),
    })
}

fn run(input: &Value) -> Result<Value, String> {
    if string(input, "schema")? != INPUT_SCHEMA {
        return Err(format!("input document is not {INPUT_SCHEMA}"));
    }
    let target = field(input, "target")?;
    let target = PlatformAttentionTarget {
        project: ProjectId::new(string(target, "project")?)
            .map_err(|_| "target project is not a project id".to_owned())?,
        user_workspace: UserWorkspaceId::new(string(target, "user_workspace")?)
            .map_err(|_| "target user workspace is not a user workspace id".to_owned())?,
    };
    let records = records(field(input, "work_context_pages_canonical_base64")?)?;
    let presence = review_presence(&string(input, "review_presence")?)?;

    // The inventory derivation is the first parity claim, and it is allowed to
    // refuse. A refusal here is the correct answer whenever the graph does not
    // authorize a complete source set, and it is reported as such rather than
    // downgraded into an empty inventory, which would read as "this workspace
    // has no attention" instead of "this client will not say".
    let inventory =
        match AttentionSourceInventory::from_authoritative_records(target, &records, presence) {
            Ok(inventory) => inventory,
            Err(error) => {
                return Ok(json!({
                    "schema": OUTPUT_SCHEMA,
                    "client": CLIENT,
                    "inventory": { "state": "refused", "error": error_category(&error) },
                    "board": { "state": "absent" },
                    "sources": {},
                    "visible_items": [],
                    "presents_attention": false,
                    "passes": [],
                }));
            }
        };
    let sources: Vec<AttentionSource> = inventory.sources().to_vec();
    let inventory_keys: Vec<String> = sources.iter().map(source_key).collect();
    let mut board = PlatformAttentionBoard::new(inventory);

    let mut passes = Vec::new();
    let empty = Vec::new();
    for pass in field(input, "passes")?.as_array().unwrap_or(&empty) {
        let mut outcomes = BTreeMap::new();
        let reads = pass
            .get("sources")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for read in &reads {
            let source = parse_source(field(read, "source")?)?;
            if !board.inventory().contains(&source) {
                // A read for a source this client never inventoried is not
                // applied. Applying it would let the capture widen the board
                // past what the record graph authorizes.
                outcomes.insert(
                    source_key(&source),
                    json!({ "state": "not_inventoried" }),
                );
                continue;
            }
            outcomes.insert(source_key(&source), apply(&mut board, &source, field(read, "read")?));
        }
        passes.push(json!({
            "outcomes": Value::Object(outcomes.into_iter().collect()),
            "projection": project(&board, &sources),
        }));
    }

    let mut document = project(&board, &sources);
    let object = document
        .as_object_mut()
        .ok_or_else(|| "projection is not an object".to_owned())?;
    object.insert("schema".to_owned(), json!(OUTPUT_SCHEMA));
    object.insert("client".to_owned(), json!(CLIENT));
    object.insert(
        "inventory".to_owned(),
        json!({ "state": "derived", "sources": inventory_keys }),
    );
    object.insert("board".to_owned(), json!({ "state": "constructed" }));
    object.insert("passes".to_owned(), Value::Array(passes));
    Ok(document)
}

fn main() -> std::process::ExitCode {
    let mut raw = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw).is_err() {
        eprintln!("could not read the replay input from stdin");
        return std::process::ExitCode::from(2);
    }
    let input: Value = match serde_json::from_str(&raw) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("replay input is not JSON: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    match run(&input) {
        Ok(document) => {
            println!("{document}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::from(2)
        }
    }
}
