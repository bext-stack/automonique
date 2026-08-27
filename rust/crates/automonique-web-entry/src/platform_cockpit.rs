// SPDX-License-Identifier: Elastic-2.0

//! Bounded, server-owned browser projection over the authenticated Platform v2 bridge.

use std::collections::BTreeMap;
use std::time::Duration;

use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{
    PlatformVersion, UserWorkspaceId, WorkContextIdentity, WorkContextKind, WorkContextQuery,
    WorkContextRecord, WorkContextRelationKind,
};
use automonique_protocol::platform_v2_lineage_api::encode_lineage_projection;
use automonique_protocol::platform_v2_review::{ReviewAction, ReviewActionReceipt};
use automonique_protocol::platform_v2_review_api::{
    encode_review_action_receipt, encode_review_snapshot,
};
use automonique_protocol::platform_v2_transport::{
    LineageReadRequest, PlatformV2Request, PlatformV2Response, ReviewActionTransportRequest,
    ReviewReadRequest,
};
use automonique_protocol::primitives::Revision;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::platform_v2_bridge::PlatformV2Bridge;

const SCHEMA: &str = "automonique.dashboard.cockpit/v2";
const ADAPTER_PENDING: &str = "platform_v2_lifecycle_adapter_pending";
const REVIEW_ADAPTER_PENDING: &str = "platform_v2_review_adapter_pending";
const MAX_ATTENTION_WORKSPACES: usize = 16;
const ATTENTION_READ_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct AttentionInventory {
    coverage: Value,
    observations: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CockpitRequest {
    Read {
        #[serde(default)]
        workspace_id: Option<String>,
    },
    ApproveReview {
        workspace_id: String,
        expected_revision: String,
        expected_review_revision: String,
        idempotency_key: String,
    },
}

pub(crate) fn execute(
    bridge: &PlatformV2Bridge,
    request: CockpitRequest,
    retained_v1: Value,
) -> Result<Value, &'static str> {
    match request {
        CockpitRequest::Read { workspace_id } => read(bridge, workspace_id.as_deref(), retained_v1),
        CockpitRequest::ApproveReview {
            workspace_id,
            expected_revision,
            expected_review_revision,
            idempotency_key,
        } => approve_review(
            bridge,
            &workspace_id,
            &expected_revision,
            &expected_review_revision,
            &idempotency_key,
        ),
    }
}

fn read(
    bridge: &PlatformV2Bridge,
    selected_id: Option<&str>,
    retained_v1: Value,
) -> Result<Value, &'static str> {
    let selected_id = selected_id
        .map(|value| UserWorkspaceId::new(value.to_owned()))
        .transpose()
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let negotiated = match bridge.negotiate() {
        Ok(value) if value.version() == PlatformVersion::V2 => value,
        Ok(_) => return Ok(fallback(retained_v1, "platform_v2_not_negotiated")),
        Err(category) => return Ok(fallback(retained_v1, category)),
    };
    let lifecycle = match bridge.request(PlatformV2Request::GetLifecycleCapabilities) {
        Ok(PlatformV2Response::LifecycleCapabilities(value)) => {
            lifecycle_actions(value.effect_kinds())
        }
        Ok(PlatformV2Response::Refused(value)) => {
            lifecycle_actions_unavailable(value.category().as_str())
        }
        Ok(_) => return Err("platform_v2_response_invalid"),
        Err(category) => lifecycle_actions_unavailable(category),
    };
    let query = WorkContextQuery::new(
        WorkContextKind::ALL.to_vec(),
        Vec::new(),
        None,
        None,
        None,
        128,
    )
    .map_err(|_| "platform_cockpit_query_invalid")?;
    let page = match bridge.request(PlatformV2Request::QueryWorkContexts(query)) {
        Err(category) => return Ok(fallback(retained_v1, category)),
        Ok(PlatformV2Response::WorkContextPage(page)) if !page.has_more() => page,
        Ok(PlatformV2Response::WorkContextPage(_)) => {
            return Ok(fallback(retained_v1, "platform_v2_inventory_exceeds_bound"));
        }
        Ok(PlatformV2Response::Refused(value)) => {
            return Ok(fallback(retained_v1, value.category().as_str()));
        }
        Ok(_) => return Err("platform_v2_response_invalid"),
    };
    let records = page.items();
    let selected = select_workspace(records, selected_id.as_ref().map(UserWorkspaceId::as_str))?;
    let selected_identity = selected.map(|record| record.identity().clone());
    let selected_project =
        selected.and_then(|record| relation(record, WorkContextRelationKind::UserWorkspaceProject));

    let lineage = match (selected_identity.as_ref(), selected_project.as_ref()) {
        (
            Some(WorkContextIdentity::UserWorkspace(workspace)),
            Some(WorkContextIdentity::Project(project)),
        ) => {
            match bridge.request(PlatformV2Request::GetLineage(LineageReadRequest::new(
                project.clone(),
                workspace.clone(),
            ))) {
                Ok(PlatformV2Response::LineageResult(value)) => available_document(
                    encode_lineage_projection(&negotiated, &value)
                        .map_err(|_| "platform_cockpit_projection_invalid")?,
                )?,
                Ok(PlatformV2Response::Refused(value)) => {
                    refused(value.category().as_str(), value.explanation().as_str())
                }
                Ok(_) => return Err("platform_v2_response_invalid"),
                Err(category) => unavailable(category),
            }
        }
        _ => unavailable("no_selected_workspace"),
    };
    let review = match (selected_identity.as_ref(), selected_project.as_ref()) {
        (Some(workspace), Some(WorkContextIdentity::Project(project))) => {
            let request = ReviewReadRequest::new(project.clone(), workspace.clone())
                .map_err(|_| "platform_cockpit_selection_invalid")?;
            match bridge.request(PlatformV2Request::GetReview(request)) {
                Ok(PlatformV2Response::ReviewResult(value)) => available_document(
                    encode_review_snapshot(&value)
                        .map_err(|_| "platform_cockpit_projection_invalid")?,
                )?,
                Ok(PlatformV2Response::Refused(value)) => {
                    refused(value.category().as_str(), value.explanation().as_str())
                }
                Ok(_) => return Err("platform_v2_response_invalid"),
                Err(category) => unavailable(category),
            }
        }
        _ => unavailable("no_selected_workspace"),
    };
    let attention = attention_inventory(bridge, records, selected_identity.as_ref(), &review);
    Ok(json!({
        "schema": SCHEMA,
        "mode": "v2",
        "degradation": Value::Null,
        "retained_v1": retained_v1,
        "projects": named_records(records, WorkContextKind::Project),
        "hosts": host_records(records),
        "workspaces": workspace_records(records, &attention.observations),
        "selected": { "workspace": selected_identity.as_ref().map(WorkContextIdentity::id) },
        "lineage": lineage,
        "review": review,
        "attention": attention.coverage,
        "actions": {
            "lifecycle": lifecycle,
            "review": { "available": false, "category": REVIEW_ADAPTER_PENDING }
        }
    }))
}

fn lifecycle_actions(effect_kinds: &std::collections::BTreeSet<String>) -> Value {
    let operation = |kind: &str, local: bool| {
        let available = effect_kinds.contains(kind);
        json!({
            "available": available,
            "category": if available { Value::Null } else { json!(ADAPTER_PENDING) },
            "scope": if local { json!("local") } else { Value::Null },
            "preview_operation": if available { json!("prepare_mutation") } else { Value::Null },
            "receipt_operation": if available { json!("get_mutation_receipt") } else { Value::Null }
        })
    };
    json!({
        "available": !effect_kinds.is_empty(),
        "operations": {
            "create_host_setup": operation("create_host_setup", true),
            "create_checkout": operation("create_checkout", true),
            "create_attempt_workspace": operation("create_attempt_workspace", false),
            "resume_attempt_workspace": operation("resume_attempt_workspace", false),
            "resume_session": operation("resume_session", false)
        }
    })
}

fn lifecycle_actions_unavailable(category: &str) -> Value {
    let mut value = lifecycle_actions(&std::collections::BTreeSet::new());
    value["category"] = json!(category);
    if let Some(operations) = value["operations"].as_object_mut() {
        for operation in operations.values_mut() {
            operation["category"] = json!(category);
        }
    }
    value
}

fn approve_review(
    bridge: &PlatformV2Bridge,
    workspace_id: &str,
    expected_revision: &str,
    expected_review_revision: &str,
    idempotency_key: &str,
) -> Result<Value, &'static str> {
    bridge.negotiate().and_then(|value| {
        (value.version() == PlatformVersion::V2)
            .then_some(())
            .ok_or("platform_v2_not_negotiated")
    })?;
    let workspace = WorkContextIdentity::UserWorkspace(
        UserWorkspaceId::new(workspace_id.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
    );
    let expected_revision = parse_revision(expected_revision)?;
    let action = ReviewAction::ApproveReview {
        expected_review_revision: parse_revision(expected_review_revision)?,
    };
    let request = ReviewActionTransportRequest::new(
        workspace,
        expected_revision,
        action,
        IdempotencyKey::new(idempotency_key.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
    )
    .map_err(|_| "platform_cockpit_request_invalid")?;
    match bridge.request(PlatformV2Request::ExecuteReviewAction(request))? {
        PlatformV2Response::ReviewReceipt(value) => action_receipt(&value),
        PlatformV2Response::Refused(value) => Ok(json!({
            "schema": SCHEMA,
            "state": "refused",
            "category": value.category().as_str(),
            "explanation": value.explanation().as_str()
        })),
        _ => Err("platform_v2_response_invalid"),
    }
}

fn parse_revision(value: &str) -> Result<Revision, &'static str> {
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or("platform_cockpit_request_invalid")
}

fn action_receipt(value: &ReviewActionReceipt) -> Result<Value, &'static str> {
    let document = stringify_integers(
        serde_json::from_slice(
            &encode_review_action_receipt(value)
                .map_err(|_| "platform_cockpit_projection_invalid")?,
        )
        .map_err(|_| "platform_cockpit_projection_invalid")?,
    );
    Ok(json!({ "schema": SCHEMA, "state": "receipt", "receipt": document }))
}

fn select_workspace<'a>(
    records: &'a [WorkContextRecord],
    selected_id: Option<&str>,
) -> Result<Option<&'a WorkContextRecord>, &'static str> {
    let workspaces: Vec<_> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::UserWorkspace)
        .collect();
    match selected_id {
        Some(id) => workspaces
            .into_iter()
            .find(|record| record.identity().id() == id)
            .map(Some)
            .ok_or("platform_cockpit_workspace_not_found"),
        None => Ok(workspaces.into_iter().next()),
    }
}

fn named_records(records: &[WorkContextRecord], kind: WorkContextKind) -> Vec<Value> {
    records
        .iter()
        .filter(|record| record.kind() == kind)
        .map(base_record)
        .collect()
}

fn host_records(records: &[WorkContextRecord]) -> Vec<Value> {
    records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::HostSetup)
        .map(|record| {
            let mut value = base_record(record);
            value["project_id"] = relation(record, WorkContextRelationKind::HostSetupProject)
                .map_or(Value::Null, |id| json!(id.id()));
            value["kind"] = record
                .attributes()
                .host_setup_kind()
                .map_or(Value::Null, |kind| json!(kind.as_str()));
            value
        })
        .collect()
}

fn attention_inventory(
    bridge: &PlatformV2Bridge,
    records: &[WorkContextRecord],
    selected: Option<&WorkContextIdentity>,
    selected_review: &Value,
) -> AttentionInventory {
    let workspaces: Vec<_> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::UserWorkspace)
        .collect();
    let total = workspaces.len();
    if total > MAX_ATTENTION_WORKSPACES {
        return AttentionInventory {
            coverage: attention_coverage(
                "unavailable",
                Some("platform_v2_attention_inventory_exceeds_bound"),
                0,
                total,
            ),
            observations: BTreeMap::new(),
        };
    }

    let observations = workspaces
        .into_iter()
        .map(|record| {
            let review = if selected == Some(record.identity()) {
                selected_review.clone()
            } else {
                bounded_review(bridge, record)
            };
            (
                record.identity().id().to_owned(),
                attention_observation(&review),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let coverage = summarize_attention(&observations, total);
    AttentionInventory {
        coverage,
        observations,
    }
}

fn summarize_attention(observations: &BTreeMap<String, Value>, total: usize) -> Value {
    let known = observations
        .values()
        .filter(|value| value["state"] == "available")
        .count();
    let (state, category) = if known == total {
        ("available", None)
    } else if known == 0 {
        ("unavailable", Some("platform_v2_attention_unavailable"))
    } else {
        ("partial", Some("platform_v2_attention_partial"))
    };
    attention_coverage(state, category, known, total)
}

fn bounded_review(bridge: &PlatformV2Bridge, record: &WorkContextRecord) -> Value {
    let Some(WorkContextIdentity::Project(project)) =
        relation(record, WorkContextRelationKind::UserWorkspaceProject)
    else {
        return unavailable("platform_v2_workspace_project_unavailable");
    };
    let Ok(request) = ReviewReadRequest::new(project, record.identity().clone()) else {
        return unavailable("platform_cockpit_selection_invalid");
    };
    match bridge.request_with_timeout(
        PlatformV2Request::GetReview(request),
        ATTENTION_READ_TIMEOUT,
    ) {
        Ok(PlatformV2Response::ReviewResult(value)) => encode_review_snapshot(&value)
            .map_err(|_| "platform_cockpit_projection_invalid")
            .and_then(available_document)
            .unwrap_or_else(unavailable),
        Ok(PlatformV2Response::Refused(value)) => {
            refused(value.category().as_str(), value.explanation().as_str())
        }
        Ok(_) => unavailable("platform_v2_response_invalid"),
        Err(category) => unavailable(category),
    }
}

fn attention_observation(review: &Value) -> Value {
    let attention = review
        .pointer("/document/attention/state")
        .and_then(Value::as_str)
        .filter(|value| {
            matches!(
                *value,
                "idle" | "needs_you" | "working" | "blocked" | "done"
            )
        });
    if let Some(attention) = attention {
        json!({ "state": "available", "value": attention, "category": Value::Null })
    } else {
        let category = review
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("platform_v2_attention_unavailable");
        json!({ "state": "unavailable", "value": Value::Null, "category": category })
    }
}

fn attention_coverage(state: &str, category: Option<&str>, known: usize, total: usize) -> Value {
    json!({
        "state": state,
        "category": category,
        "known_workspaces": known.to_string(),
        "total_workspaces": total.to_string()
    })
}

fn workspace_records(
    records: &[WorkContextRecord],
    attention: &BTreeMap<String, Value>,
) -> Vec<Value> {
    let checkouts: BTreeMap<_, _> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::Checkout)
        .map(|record| {
            (
                record.identity().id().to_owned(),
                relation(record, WorkContextRelationKind::CheckoutHostSetup)
                    .map(|value| value.id().to_owned()),
            )
        })
        .collect();
    let attempts: BTreeMap<_, _> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::AttemptWorkspace)
        .filter_map(|record| {
            relation(record, WorkContextRelationKind::AttemptUserWorkspace)
                .map(|workspace| (record.identity().id().to_owned(), workspace.id().to_owned()))
        })
        .collect();
    let sessions: BTreeMap<_, _> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::Session)
        .filter_map(|record| {
            let attempt = relation(record, WorkContextRelationKind::SessionAttemptWorkspace)?;
            let workspace = attempts.get(attempt.id())?.clone();
            let session = relation(record, WorkContextRelationKind::SessionPlatformSession)?;
            Some((workspace, session.id().to_owned()))
        })
        .collect();
    records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::UserWorkspace)
        .map(|record| {
            let project = relation(record, WorkContextRelationKind::UserWorkspaceProject);
            let checkout = relation(record, WorkContextRelationKind::UserWorkspaceCheckout);
            let observation = attention.get(record.identity().id());
            json!({
                "id": record.identity().id(),
                "label": record.label().as_str(),
                "revision": record.revision().to_string(),
                "lifecycle": record.lifecycle().as_str(),
                "project_id": project.as_ref().map(WorkContextIdentity::id),
                "checkout_id": checkout.as_ref().map(WorkContextIdentity::id),
                "host_id": checkout.as_ref().and_then(|value| checkouts.get(value.id())).cloned().flatten(),
                "session_id": sessions.get(record.identity().id()),
                "attention": observation
                    .and_then(|value| value.get("value"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "attention_availability": observation
                    .and_then(|value| value.get("state"))
                    .cloned()
                    .unwrap_or_else(|| json!("unavailable")),
                "attention_category": observation
                    .and_then(|value| value.get("category"))
                    .cloned()
                    .unwrap_or_else(|| json!("platform_v2_attention_inventory_exceeds_bound"))
            })
        })
        .collect()
}

fn base_record(record: &WorkContextRecord) -> Value {
    json!({
        "id": record.identity().id(),
        "label": record.label().as_str(),
        "revision": record.revision().to_string(),
        "lifecycle": record.lifecycle().as_str()
    })
}

fn relation(
    record: &WorkContextRecord,
    kind: WorkContextRelationKind,
) -> Option<WorkContextIdentity> {
    record
        .relations()
        .iter()
        .find(|relation| relation.kind() == kind)
        .map(|relation| relation.target().clone())
}

fn available_document(bytes: Vec<u8>) -> Result<Value, &'static str> {
    let value = serde_json::from_slice(&bytes)
        .map(stringify_integers)
        .map_err(|_| "platform_cockpit_projection_invalid")?;
    Ok(json!({ "state": "available", "document": value }))
}

fn stringify_integers(value: Value) -> Value {
    match value {
        Value::Number(value) => Value::String(value.to_string()),
        Value::Array(values) => Value::Array(values.into_iter().map(stringify_integers).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, stringify_integers(value)))
                .collect(),
        ),
        value => value,
    }
}

fn fallback(retained_v1: Value, category: &str) -> Value {
    json!({
        "schema": SCHEMA,
        "mode": "v1",
        "degradation": { "category": category },
        "retained_v1": retained_v1,
        "projects": [], "hosts": [], "workspaces": [],
        "selected": { "workspace": Value::Null },
        "lineage": unavailable("platform_v2_unavailable"),
        "review": unavailable("platform_v2_unavailable"),
        "attention": {
            "state": "unavailable",
            "category": "platform_v2_unavailable",
            "known_workspaces": "0",
            "total_workspaces": "0"
        },
        "actions": {
            "lifecycle": { "available": false, "category": ADAPTER_PENDING },
            "review": { "available": false, "category": REVIEW_ADAPTER_PENDING }
        }
    })
}

fn unavailable(category: &str) -> Value {
    json!({ "state": "unavailable", "category": category })
}

fn refused(category: &str, explanation: &str) -> Value {
    json!({ "state": "refused", "category": category, "explanation": explanation })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_projection_is_lossless_for_javascript_clients() {
        let value =
            stringify_integers(json!({ "revision": 9_007_199_254_740_995_u64, "items": [7] }));
        assert_eq!(value["revision"], "9007199254740995");
        assert_eq!(value["items"][0], "7");
    }

    #[test]
    fn fallback_never_fabricates_v2_inventory() {
        let value = fallback(
            json!({ "sessions": [{ "summary": "working on a branch" }] }),
            "unavailable",
        );
        assert_eq!(value["mode"], "v1");
        assert_eq!(value["workspaces"], json!([]));
        assert_eq!(value["actions"]["lifecycle"]["available"], false);
    }

    #[test]
    fn lifecycle_projection_exposes_only_installed_local_effects() {
        let installed = lifecycle_actions(&std::collections::BTreeSet::from([
            String::from("create_host_setup"),
            String::from("create_checkout"),
        ]));
        assert_eq!(installed["available"], true);
        assert_eq!(
            installed["operations"]["create_host_setup"]["preview_operation"],
            "prepare_mutation"
        );
        assert_eq!(
            installed["operations"]["create_checkout"]["receipt_operation"],
            "get_mutation_receipt"
        );
        assert_eq!(
            installed["operations"]["create_attempt_workspace"]["available"],
            false
        );
        assert_eq!(
            installed["operations"]["resume_session"]["available"],
            false
        );

        let absent = lifecycle_actions_unavailable("platform_v2_selector_registry_unavailable");
        assert_eq!(absent["available"], false);
        assert_eq!(
            absent["operations"]["create_host_setup"]["category"],
            "platform_v2_selector_registry_unavailable"
        );
    }

    #[test]
    fn attention_inventory_is_complete_only_when_every_workspace_is_known() {
        let observations = BTreeMap::from([
            (
                String::from("workspace-a"),
                attention_observation(&json!({
                    "state": "available",
                    "document": { "attention": { "state": "needs_you" } }
                })),
            ),
            (
                String::from("workspace-b"),
                attention_observation(&json!({
                    "state": "available",
                    "document": { "attention": { "state": "blocked" } }
                })),
            ),
        ]);
        let complete = summarize_attention(&observations, 2);
        assert_eq!(complete["state"], "available");
        assert_eq!(complete["known_workspaces"], "2");
        assert_eq!(observations["workspace-a"]["value"], "needs_you");
        assert_eq!(observations["workspace-b"]["value"], "blocked");
        assert_eq!(
            attention_observation(&json!({
                "state": "available",
                "document": { "attention": { "state": "idle" } }
            }))["value"],
            "idle"
        );

        let mut partial = observations;
        partial.insert(
            String::from("workspace-b"),
            attention_observation(&unavailable("review_adapter_unavailable")),
        );
        let partial = summarize_attention(&partial, 2);
        assert_eq!(partial["state"], "partial");
        assert_eq!(partial["known_workspaces"], "1");
        assert_eq!(partial["total_workspaces"], "2");
    }

    #[test]
    fn bounded_attention_overflow_is_explicit_and_non_inferential() {
        let value = attention_coverage(
            "unavailable",
            Some("platform_v2_attention_inventory_exceeds_bound"),
            0,
            MAX_ATTENTION_WORKSPACES + 1,
        );
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["known_workspaces"], "0");
        assert_eq!(value["total_workspaces"], "17");
    }
}
