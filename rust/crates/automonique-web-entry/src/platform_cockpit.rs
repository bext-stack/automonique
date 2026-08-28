// SPDX-License-Identifier: Elastic-2.0

//! Bounded, server-owned browser projection over the authenticated Platform v2 bridge.

use std::collections::BTreeMap;
use std::time::Duration;

use automonique_protocol::platform::IdempotencyKey;
use automonique_protocol::platform_v2::{
    PlatformVersion, ProjectId, UserWorkspaceId, WorkContextCursor, WorkContextIdentity,
    WorkContextKind, WorkContextLifecycle, WorkContextQuery, WorkContextRecord,
    WorkContextRelationKind,
};
use automonique_protocol::platform_v2_attention::{
    AttentionItemState, AttentionReadRequest, AttentionSource, AttentionSourceId,
    AttentionSourceKind, AttentionSourceSnapshot,
};
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkAuthorityId, ExternalWorkIdentity,
    ExternalWorkKey, ExternalWorkProvider, ExternalWorkScope, ExternalWorkState,
    LineageFreshnessState, LineageProjection, LineageStatus, OrchestrationIdentity,
    OrchestrationTaskId, WorkspaceCreateIntent, WorkspaceIntent, WorkspaceIntentId,
    WorkspaceResumeIntent,
};
use automonique_protocol::platform_v2_lineage_api::encode_lineage_projection;
use automonique_protocol::platform_v2_lineage_api::encode_workspace_intent_outcome;
use automonique_protocol::platform_v2_review::{
    DiffSide, ReviewAction, ReviewActionReceipt, ReviewAnchor, ReviewCheckId, ReviewCommentId,
    ReviewDecision, ReviewFileId, ReviewFreshnessState, ReviewHunkId, ReviewSnapshot, ReviewText,
};
use automonique_protocol::platform_v2_review_api::{
    encode_review_action_receipt, encode_review_snapshot,
};
use automonique_protocol::platform_v2_transport::{
    LifecycleCapabilities, LineageReadRequest, PlatformV2Request, PlatformV2Response,
    ReviewActionTransportRequest, ReviewConfirmationDigest, ReviewReadRequest,
    ReviewReceiptCorrelationDigest, ReviewReceiptLookup, WorkspaceIntentLookup,
    WorkspaceIntentRequest,
};
use automonique_protocol::primitives::Revision;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::platform_v2_bridge::PlatformV2Bridge;

const SCHEMA: &str = "automonique.dashboard.cockpit/v2";
const ADAPTER_PENDING: &str = "platform_v2_lifecycle_adapter_pending";
const REVIEW_ADAPTER_PENDING: &str = "platform_v2_review_adapter_pending";
const MAX_ATTENTION_WORKSPACES: usize = 16;
const MAX_ATTENTION_SOURCES_PER_WORKSPACE: usize = 64;
const MAX_COCKPIT_PROJECTS: usize = 128;
const MAX_COCKPIT_WORK_CONTEXTS: usize = 1024;
const MAX_COCKPIT_ACTIVITIES: usize = 256;
const MAX_COCKPIT_INBOX_ITEMS: usize = 256;
const WORK_CONTEXT_PAGE_LIMIT: u16 = 128;
const ATTENTION_READ_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug)]
struct BoundedCockpitItems {
    items: Vec<Value>,
    total: usize,
}

#[derive(Debug)]
struct AttentionInventory {
    coverage: Value,
    observations: BTreeMap<String, Value>,
    selected_inbox: BoundedCockpitItems,
    selected_source: Value,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CockpitRequest {
    Read {
        #[serde(default)]
        workspace_id: Option<String>,
    },
    SubmitWorkspaceCreate {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        intent_id: String,
        task_id: String,
        external_work: CockpitExternalWork,
        base_selector: String,
        branch_selector: String,
    },
    SubmitWorkspaceResume {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        intent_id: String,
        task_id: String,
    },
    GetWorkspaceIntent {
        project_id: String,
        workspace_id: String,
        intent_id: String,
    },
    AddComment {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        comment_id: String,
        file_id: String,
        hunk_id: String,
        side: CockpitDiffSide,
        line: u32,
        body: String,
        idempotency_key: String,
    },
    ApproveReview {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        expected_review_revision: String,
        idempotency_key: String,
    },
    PreviewRerunCheck {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        check_id: String,
        expected_check_revision: String,
    },
    RerunCheck {
        project_id: String,
        workspace_id: String,
        expected_revision: String,
        check_id: String,
        expected_check_revision: String,
        confirmation_digest: String,
        idempotency_key: String,
    },
    GetReviewReceipt {
        project_id: String,
        workspace_id: String,
        idempotency_key: String,
        receipt_correlation_digest: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CockpitExternalWork {
    provider: String,
    authority: String,
    scope: String,
    key: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CockpitDiffSide {
    Old,
    New,
}

pub(crate) fn execute(
    bridge: &PlatformV2Bridge,
    request: CockpitRequest,
    retained_v1: Value,
) -> Result<Value, &'static str> {
    match request {
        CockpitRequest::Read { workspace_id } => read(bridge, workspace_id.as_deref(), retained_v1),
        CockpitRequest::SubmitWorkspaceCreate {
            project_id,
            workspace_id,
            expected_revision,
            intent_id,
            task_id,
            external_work,
            base_selector,
            branch_selector,
        } => submit_workspace_create(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &intent_id,
            &task_id,
            external_work,
            &base_selector,
            &branch_selector,
        ),
        CockpitRequest::SubmitWorkspaceResume {
            project_id,
            workspace_id,
            expected_revision,
            intent_id,
            task_id,
        } => submit_workspace_resume(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &intent_id,
            &task_id,
        ),
        CockpitRequest::GetWorkspaceIntent {
            project_id,
            workspace_id,
            intent_id,
        } => get_workspace_intent(bridge, &project_id, &workspace_id, &intent_id),
        CockpitRequest::AddComment {
            project_id,
            workspace_id,
            expected_revision,
            comment_id,
            file_id,
            hunk_id,
            side,
            line,
            body,
            idempotency_key,
        } => add_comment(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &comment_id,
            &file_id,
            &hunk_id,
            side,
            line,
            &body,
            &idempotency_key,
        ),
        CockpitRequest::ApproveReview {
            project_id,
            workspace_id,
            expected_revision,
            expected_review_revision,
            idempotency_key,
        } => approve_review(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &expected_review_revision,
            &idempotency_key,
        ),
        CockpitRequest::PreviewRerunCheck {
            project_id,
            workspace_id,
            expected_revision,
            check_id,
            expected_check_revision,
        } => preview_rerun_check(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &check_id,
            &expected_check_revision,
        ),
        CockpitRequest::RerunCheck {
            project_id,
            workspace_id,
            expected_revision,
            check_id,
            expected_check_revision,
            confirmation_digest,
            idempotency_key,
        } => rerun_check(
            bridge,
            &project_id,
            &workspace_id,
            &expected_revision,
            &check_id,
            &expected_check_revision,
            &confirmation_digest,
            &idempotency_key,
        ),
        CockpitRequest::GetReviewReceipt {
            project_id,
            workspace_id,
            idempotency_key,
            receipt_correlation_digest,
        } => get_review_receipt(
            bridge,
            &project_id,
            &workspace_id,
            &idempotency_key,
            receipt_correlation_digest.as_deref(),
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
        Ok(_) => return Ok(v1_fallback(retained_v1, "platform_v2_not_negotiated")),
        Err(category) => return Ok(v2_unavailable(retained_v1, category)),
    };
    let capabilities = match bridge.request(PlatformV2Request::GetLifecycleCapabilities) {
        Ok(PlatformV2Response::LifecycleCapabilities(value)) => value,
        Ok(PlatformV2Response::Refused(value)) => {
            return Ok(v2_unavailable(retained_v1, value.category().as_str()));
        }
        Ok(_) => return Err("platform_v2_response_invalid"),
        Err(category) => return Ok(v2_unavailable(retained_v1, category)),
    };
    let records = match inventory(bridge, capabilities.projects()) {
        Ok(records) => records,
        Err(category) => return Ok(v2_unavailable(retained_v1, &category)),
    };
    let selected = select_workspace(&records, selected_id.as_ref().map(UserWorkspaceId::as_str))?;
    let selected_identity = selected.map(|record| record.identity().clone());
    let selected_project =
        selected.and_then(|record| relation(record, WorkContextRelationKind::UserWorkspaceProject));
    let (lineage, lineage_projection) =
        match (selected_identity.as_ref(), selected_project.as_ref()) {
            (
                Some(WorkContextIdentity::UserWorkspace(workspace)),
                Some(WorkContextIdentity::Project(project)),
            ) => {
                match bridge.request(PlatformV2Request::GetLineage(LineageReadRequest::new(
                    project.clone(),
                    workspace.clone(),
                ))) {
                    Ok(PlatformV2Response::LineageResult(value)) => (
                        available_document(
                            encode_lineage_projection(&negotiated, &value)
                                .map_err(|_| "platform_cockpit_projection_invalid")?,
                        )?,
                        Some(value),
                    ),
                    Ok(PlatformV2Response::Refused(value)) => (
                        refused(value.category().as_str(), value.explanation().as_str()),
                        None,
                    ),
                    Ok(_) => return Err("platform_v2_response_invalid"),
                    Err(category) => (unavailable(category), None),
                }
            }
            _ => (unavailable("no_selected_workspace"), None),
        };
    let (review, review_snapshot) = match (selected_identity.as_ref(), selected_project.as_ref()) {
        (Some(workspace), Some(WorkContextIdentity::Project(project))) => {
            let request = ReviewReadRequest::new(project.clone(), workspace.clone())
                .map_err(|_| "platform_cockpit_selection_invalid")?;
            match bridge.request(PlatformV2Request::GetReview(request)) {
                Ok(PlatformV2Response::ReviewResult(value)) => (
                    available_document(
                        encode_review_snapshot(&value)
                            .map_err(|_| "platform_cockpit_projection_invalid")?,
                    )?,
                    Some(value),
                ),
                Ok(PlatformV2Response::Refused(value)) => (
                    refused(value.category().as_str(), value.explanation().as_str()),
                    None,
                ),
                Ok(_) => return Err("platform_v2_response_invalid"),
                Err(category) => (unavailable(category), None),
            }
        }
        _ => (unavailable("no_selected_workspace"), None),
    };
    let lifecycle = lifecycle_actions(
        &capabilities,
        selected_project.as_ref(),
        selected,
        lineage_projection.as_ref(),
    );
    let review_capabilities = match (
        review_snapshot.as_ref(),
        selected_identity.as_ref(),
        selected_project.as_ref(),
    ) {
        (Some(snapshot), Some(workspace), Some(WorkContextIdentity::Project(project))) => {
            let request = ReviewReadRequest::new(project.clone(), workspace.clone())
                .map_err(|_| "platform_cockpit_selection_invalid")?;
            match bridge.request(PlatformV2Request::GetReviewCapabilities(request)) {
                Ok(PlatformV2Response::ReviewCapabilities(value))
                    if value.project() == project
                        && value.workspace() == workspace
                        && value.snapshot_revision() == snapshot.revision() =>
                {
                    Some(value)
                }
                _ => None,
            }
        }
        _ => None,
    };
    let review_actions = review_actions(
        selected,
        selected_project.as_ref(),
        review_snapshot.as_ref(),
        review_capabilities.as_ref(),
    );
    let attention = attention_inventory(bridge, &records, selected_identity.as_ref());
    let activity_items = cockpit_activities(lineage_projection.as_ref(), review_snapshot.as_ref());
    let activities = collection_projection(
        activity_items,
        &[("lineage", &lineage), ("review", &review)],
    );
    let inbox = collection_projection(
        attention.selected_inbox,
        &[("attention", &attention.selected_source)],
    );
    Ok(json!({
        "schema": SCHEMA,
        "mode": "v2",
        "degradation": Value::Null,
        "retained_v1": retained_v1,
        "projects": named_records(&records, WorkContextKind::Project),
        "hosts": host_records(&records),
        "workspaces": workspace_records(&records, &attention.observations, lineage_projection.as_ref()),
        "selected": { "workspace": selected_identity.as_ref().map(WorkContextIdentity::id) },
        "lineage": lineage,
        "review": review,
        "attention": attention.coverage,
        "activities": activities,
        "inbox": inbox,
        "actions": {
            "lifecycle": lifecycle,
            "review": review_actions
        }
    }))
}

fn inventory(
    bridge: &PlatformV2Bridge,
    projects: &std::collections::BTreeSet<ProjectId>,
) -> Result<Vec<WorkContextRecord>, String> {
    if projects.is_empty() || projects.len() > MAX_COCKPIT_PROJECTS {
        return Err("platform_v2_project_inventory_invalid".to_owned());
    }
    let mut records = BTreeMap::<WorkContextIdentity, WorkContextRecord>::new();
    for project in projects {
        let mut after: Option<WorkContextCursor> = None;
        loop {
            let query = WorkContextQuery::new(
                WorkContextKind::ALL.to_vec(),
                Vec::new(),
                Some(project.clone()),
                None,
                after.clone(),
                WORK_CONTEXT_PAGE_LIMIT,
            )
            .map_err(|_| "platform_cockpit_query_invalid".to_owned())?;
            let page = match bridge.request(PlatformV2Request::QueryWorkContexts(query)) {
                Err(category) => return Err(category.to_owned()),
                Ok(PlatformV2Response::WorkContextPage(page)) => page,
                Ok(PlatformV2Response::WorkContextResync(_)) => {
                    return Err("platform_v2_inventory_resync_required".to_owned());
                }
                Ok(PlatformV2Response::Refused(value)) => {
                    return Err(value.category().as_str().to_owned());
                }
                Ok(_) => return Err("platform_v2_response_invalid".to_owned()),
            };
            verify_inventory_capacity(records.len(), page.items().len())?;
            for record in page.items() {
                if records
                    .insert(record.identity().clone(), record.clone())
                    .is_some()
                {
                    return Err("platform_v2_inventory_duplicate".to_owned());
                }
            }
            let Some(next) = page.next_cursor().cloned() else {
                break;
            };
            after = Some(next);
        }
    }
    Ok(records.into_values().collect())
}

fn verify_inventory_capacity(current: usize, incoming: usize) -> Result<(), String> {
    if current.saturating_add(incoming) > MAX_COCKPIT_WORK_CONTEXTS {
        Err("platform_v2_inventory_exceeds_bound".to_owned())
    } else {
        Ok(())
    }
}

fn lifecycle_actions(
    capabilities: &LifecycleCapabilities,
    selected_project: Option<&WorkContextIdentity>,
    selected: Option<&WorkContextRecord>,
    lineage: Option<&LineageProjection>,
) -> Value {
    let project = match selected_project {
        Some(WorkContextIdentity::Project(project)) => Some(project),
        _ => capabilities.projects().iter().next(),
    };
    let operation = |kind: &str, local: bool| {
        let capability = project.and_then(|project| {
            capabilities
                .operations()
                .iter()
                .find(|value| value.project() == project && value.effect_kind() == kind)
        });
        let available = capability.is_some_and(|value| value.available_now());
        let category = capability
            .and_then(|value| value.category())
            .map(|value| value.as_str())
            .unwrap_or("platform_v2_project_scope_unavailable");
        json!({
            "available": available,
            "category": if available { Value::Null } else { json!(category) },
            "scope": if available && local { json!("local") } else { Value::Null },
            "preview_operation": if available { json!("prepare_mutation") } else { Value::Null },
            "receipt_operation": if available { json!("get_mutation_receipt") } else { Value::Null }
        })
    };
    let any_available = project.is_some_and(|project| {
        capabilities
            .operations()
            .iter()
            .any(|value| value.project() == project && value.available_now())
    });
    let binding = selected
        .zip(lineage)
        .and_then(|(workspace, lineage)| exact_task_binding(workspace, lineage));
    let intent_operation = |kind: &str, needs_external: bool| {
        let capability = project.and_then(|project| {
            capabilities
                .operations()
                .iter()
                .find(|value| value.project() == project && value.effect_kind() == kind)
        });
        let binding_available = binding
            .as_ref()
            .is_some_and(|(_, external)| !needs_external || external.is_some());
        let available = capability.is_some_and(|value| value.available_now()) && binding_available;
        let category = capability
            .and_then(|value| value.category())
            .map(|value| value.as_str())
            .unwrap_or(if binding_available {
                "platform_v2_project_scope_unavailable"
            } else {
                "platform_v2_exact_task_binding_unavailable"
            });
        let (task_id, external_work) = binding
            .as_ref()
            .map(|(task, external)| {
                (
                    json!(task.as_str()),
                    external.clone().unwrap_or(Value::Null),
                )
            })
            .unwrap_or((Value::Null, Value::Null));
        json!({
            "available": available,
            "category": if available { Value::Null } else { json!(category) },
            "submit_operation": if available { json!("submit_workspace_intent") } else { Value::Null },
            "receipt_operation": if available { json!("get_workspace_intent") } else { Value::Null },
            "project_id": if available { project.map(|value| json!(value.as_str())).unwrap_or(Value::Null) } else { Value::Null },
            "workspace_id": if available { selected.map(|value| json!(value.identity().id())).unwrap_or(Value::Null) } else { Value::Null },
            "exact_revision": if available { selected.map(|value| json!(value.revision().to_string())).unwrap_or(Value::Null) } else { Value::Null },
            "task_id": if available { task_id } else { Value::Null },
            "external_work": if available && needs_external { external_work } else { Value::Null }
        })
    };
    json!({
        "available": any_available,
        "project": project.map(ProjectId::as_str),
        "operations": {
            "create_host_setup": operation("create_host_setup", true),
            "create_checkout": operation("create_checkout", true),
            "create_attempt_workspace": intent_operation("create_attempt_workspace", true),
            "resume_attempt_workspace": intent_operation("resume_attempt_workspace", false),
            "resume_session": operation("resume_session", false)
        }
    })
}

fn exact_task_binding(
    workspace: &WorkContextRecord,
    lineage: &LineageProjection,
) -> Option<(OrchestrationTaskId, Option<Value>)> {
    let WorkContextIdentity::UserWorkspace(workspace_id) = workspace.identity() else {
        return None;
    };
    if workspace.lifecycle() != WorkContextLifecycle::Active || lineage.workspace() != workspace_id
    {
        return None;
    }
    let mut tasks = lineage.orchestration().iter().filter(|record| {
        record.workspace() == workspace_id
            && record.freshness().state() == LineageFreshnessState::Fresh
            && matches!(record.identity(), OrchestrationIdentity::Task(_))
    });
    let task = tasks.next()?;
    if tasks.next().is_some() {
        return None;
    }
    let OrchestrationIdentity::Task(task_id) = task.identity() else {
        return None;
    };
    let external = task.external_work().and_then(|identity| {
        lineage
            .external_work_items()
            .iter()
            .find(|item| {
                item.identity() == identity
                    && item.workspace() == workspace_id
                    && item.state() == ExternalWorkState::Open
                    && item.freshness().state() == LineageFreshnessState::Fresh
            })
            .map(|item| external_work_json(item.identity()))
    });
    if task.external_work().is_some() && external.is_none() {
        return None;
    }
    Some((task_id.clone(), external))
}

fn external_work_json(value: &ExternalWorkIdentity) -> Value {
    json!({
        "provider": value.provider().as_str(),
        "authority": value.authority().as_str(),
        "scope": value.scope().as_str(),
        "key": value.key().as_str()
    })
}

fn review_actions(
    selected: Option<&WorkContextRecord>,
    selected_project: Option<&WorkContextIdentity>,
    snapshot: Option<&ReviewSnapshot>,
    capabilities: Option<&automonique_protocol::platform_v2_transport::ReviewCapabilities>,
) -> Value {
    let exact = selected.zip(snapshot).and_then(|(workspace, snapshot)| {
        let WorkContextIdentity::Project(project) = selected_project? else {
            return None;
        };
        if workspace.lifecycle() != WorkContextLifecycle::Active
            || snapshot.workspace() != workspace.identity()
            || !review_snapshot_is_fresh(snapshot)
        {
            return None;
        }
        Some((workspace, project, snapshot))
    });
    let action = |available: bool, category: &str| {
        let (workspace, project, exact_revision, exact_review_revision) = exact
            .map(|(workspace, project, snapshot)| {
                (
                    json!(workspace.identity().id()),
                    json!(project.as_str()),
                    json!(snapshot.revision().to_string()),
                    json!(
                        snapshot
                            .review()
                            .freshness()
                            .observed_revision()
                            .to_string()
                    ),
                )
            })
            .unwrap_or((Value::Null, Value::Null, Value::Null, Value::Null));
        json!({
            "available": available && exact.is_some(),
            "category": if available && exact.is_some() { Value::Null } else { json!(category) },
            "execute_operation": if available && exact.is_some() { json!("execute_review_action") } else { Value::Null },
            "receipt_operation": if available && exact.is_some() { json!("get_review_receipt") } else { Value::Null },
            "project_id": project,
            "workspace_id": workspace,
            "exact_revision": exact_revision,
            "exact_review_revision": if available { exact_review_revision } else { Value::Null }
        })
    };
    let fresh = exact.is_some();
    let approve = exact
        .is_some_and(|(_, _, snapshot)| snapshot.review().decision() == ReviewDecision::Pending);
    let rerunnable_checks = exact
        .zip(capabilities)
        .map(|((workspace, project, snapshot), capabilities)| {
            capabilities
                .rerunnable_checks()
                .iter()
                .filter_map(|capability| {
                    let check = snapshot.checks().iter().find(|check| {
                        check.id() == capability.check_id()
                            && check.authority() == capability.authority()
                            && check.freshness().state() == ReviewFreshnessState::Fresh
                            && check.freshness().observed_revision()
                                == capability.expected_check_revision()
                    })?;
                    Some(json!({
                        "project_id": project.as_str(),
                        "workspace_id": workspace.identity().id(),
                        "exact_revision": snapshot.revision().to_string(),
                        "check_id": check.id().as_str(),
                        "exact_check_revision": capability.expected_check_revision().to_string(),
                        "confirmation_digest": capability.confirmation_digest().as_str()
                        ,"receipt_correlation_digest": capability.receipt_correlation_digest().as_str()
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let rerun_available = !rerunnable_checks.is_empty();
    let rerun = json!({
        "available": rerun_available,
        "category": if rerun_available { Value::Null } else { json!("platform_cockpit_ci_family_unavailable") },
        "execute_operation": if rerun_available { json!("rerun_check") } else { Value::Null },
        "receipt_operation": if rerun_available { json!("get_review_receipt") } else { Value::Null },
        "targets": rerunnable_checks
    });
    json!({
        "available": fresh,
        "category": if fresh { Value::Null } else { json!(REVIEW_ADAPTER_PENDING) },
        "operations": {
            "add_comment": action(fresh, REVIEW_ADAPTER_PENDING),
            "approve_review": action(approve, if fresh { "platform_v2_review_not_pending" } else { REVIEW_ADAPTER_PENDING }),
            "send_comment_to_agent": action(false, "platform_cockpit_review_family_unavailable"),
            "batch_send_comments_to_agent": action(false, "platform_cockpit_review_family_unavailable"),
            "stage": action(false, "platform_cockpit_git_family_unavailable"),
            "unstage": action(false, "platform_cockpit_git_family_unavailable"),
            "commit": action(false, "platform_cockpit_git_family_unavailable"),
            "resolve_conflict": action(false, "platform_cockpit_git_family_unavailable"),
            "rerun_check": rerun,
            "open_pull_request": action(false, "platform_cockpit_pull_request_family_unavailable"),
            "update_pull_request": action(false, "platform_cockpit_pull_request_family_unavailable"),
            "merge_pull_request": action(false, "platform_cockpit_pull_request_family_unavailable")
        }
    })
}

fn review_snapshot_is_fresh(snapshot: &ReviewSnapshot) -> bool {
    snapshot.review().freshness().state() == ReviewFreshnessState::Fresh
        && snapshot.pull_request().freshness().state() == ReviewFreshnessState::Fresh
        && snapshot.delivery().freshness().state() == ReviewFreshnessState::Fresh
        && snapshot
            .checks()
            .iter()
            .all(|check| check.freshness().state() == ReviewFreshnessState::Fresh)
}

struct WorkspaceControlContext {
    project: ProjectId,
    workspace: UserWorkspaceId,
    record: WorkContextRecord,
    lineage: LineageProjection,
}

fn workspace_control_context(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    effect_kind: &str,
) -> Result<WorkspaceControlContext, &'static str> {
    require_v2(bridge)?;
    let project =
        ProjectId::new(project_id.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace = UserWorkspaceId::new(workspace_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let revision = parse_revision(expected_revision)?;
    let capabilities = lifecycle_capabilities(bridge)?;
    if !capabilities.projects().contains(&project)
        || !capabilities.operations().iter().any(|operation| {
            operation.project() == &project
                && operation.effect_kind() == effect_kind
                && operation.available_now()
        })
    {
        return Err("platform_cockpit_capability_unavailable");
    }
    let record = exact_workspace_record(bridge, &capabilities, &project, &workspace)?;
    if record.lifecycle() != WorkContextLifecycle::Active || record.revision() != revision {
        return Err("platform_cockpit_stale_revision");
    }
    let lineage = match bridge.request(PlatformV2Request::GetLineage(LineageReadRequest::new(
        project.clone(),
        workspace.clone(),
    )))? {
        PlatformV2Response::LineageResult(value) => value,
        PlatformV2Response::Refused(_) => return Err("platform_cockpit_lineage_unavailable"),
        _ => return Err("platform_v2_response_invalid"),
    };
    if lineage.workspace() != &workspace
        || lineage
            .external_work_items()
            .iter()
            .any(|value| value.freshness().state() != LineageFreshnessState::Fresh)
        || lineage
            .orchestration()
            .iter()
            .any(|value| value.freshness().state() != LineageFreshnessState::Fresh)
    {
        return Err("platform_cockpit_lineage_stale");
    }
    Ok(WorkspaceControlContext {
        project,
        workspace,
        record,
        lineage,
    })
}

fn require_v2(bridge: &PlatformV2Bridge) -> Result<(), &'static str> {
    bridge.negotiate().and_then(|value| {
        (value.version() == PlatformVersion::V2)
            .then_some(())
            .ok_or("platform_v2_not_negotiated")
    })
}

fn lifecycle_capabilities(
    bridge: &PlatformV2Bridge,
) -> Result<LifecycleCapabilities, &'static str> {
    match bridge.request(PlatformV2Request::GetLifecycleCapabilities)? {
        PlatformV2Response::LifecycleCapabilities(value) => Ok(value),
        PlatformV2Response::Refused(_) => Err("platform_cockpit_capability_unavailable"),
        _ => Err("platform_v2_response_invalid"),
    }
}

fn exact_workspace_record(
    bridge: &PlatformV2Bridge,
    capabilities: &LifecycleCapabilities,
    project: &ProjectId,
    workspace: &UserWorkspaceId,
) -> Result<WorkContextRecord, &'static str> {
    let records = inventory(bridge, capabilities.projects())
        .map_err(|_| "platform_cockpit_inventory_unavailable")?;
    let record = records
        .into_iter()
        .find(|record| record.identity() == &WorkContextIdentity::UserWorkspace(workspace.clone()))
        .ok_or("platform_cockpit_workspace_not_found")?;
    if !workspace_matches_project(&record, project) {
        return Err("platform_cockpit_project_workspace_mismatch");
    }
    Ok(record)
}

fn workspace_matches_project(record: &WorkContextRecord, project: &ProjectId) -> bool {
    relation(record, WorkContextRelationKind::UserWorkspaceProject)
        == Some(WorkContextIdentity::Project(project.clone()))
}

fn parse_external_work(value: CockpitExternalWork) -> Result<ExternalWorkIdentity, &'static str> {
    Ok(ExternalWorkIdentity::new(
        ExternalWorkProvider::parse(&value.provider)
            .map_err(|_| "platform_cockpit_request_invalid")?,
        ExternalWorkAuthorityId::new(value.authority)
            .map_err(|_| "platform_cockpit_request_invalid")?,
        ExternalWorkScope::new(value.scope).map_err(|_| "platform_cockpit_request_invalid")?,
        ExternalWorkKey::new(value.key).map_err(|_| "platform_cockpit_request_invalid")?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn submit_workspace_create(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    intent_id: &str,
    task_id: &str,
    external_work: CockpitExternalWork,
    base_selector: &str,
    branch_selector: &str,
) -> Result<Value, &'static str> {
    let context = workspace_control_context(
        bridge,
        project_id,
        workspace_id,
        expected_revision,
        "create_attempt_workspace",
    )?;
    let task = OrchestrationTaskId::new(task_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let external_work = parse_external_work(external_work)?;
    let binding = exact_task_binding(&context.record, &context.lineage)
        .ok_or("platform_cockpit_exact_task_binding_unavailable")?;
    if binding.0 != task || binding.1 != Some(external_work_json(&external_work)) {
        return Err("platform_cockpit_exact_task_binding_mismatch");
    }
    let intent_id = WorkspaceIntentId::new(intent_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    if let Some(value) =
        existing_workspace_intent(bridge, context.project.clone(), intent_id.clone())?
    {
        return workspace_intent_result(bridge, &intent_id, &context.workspace, value, false);
    }
    let intent = WorkspaceIntent::Create(WorkspaceCreateIntent::new(
        intent_id.clone(),
        task,
        external_work,
        BaseSelectorId::new(base_selector.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
        BranchSelectorId::new(branch_selector.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
    ));
    submit_workspace_intent(
        bridge,
        context.project,
        context.workspace,
        intent_id,
        intent,
    )
}

fn submit_workspace_resume(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    intent_id: &str,
    task_id: &str,
) -> Result<Value, &'static str> {
    let context = workspace_control_context(
        bridge,
        project_id,
        workspace_id,
        expected_revision,
        "resume_attempt_workspace",
    )?;
    let task = OrchestrationTaskId::new(task_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let binding = exact_task_binding(&context.record, &context.lineage)
        .ok_or("platform_cockpit_exact_task_binding_unavailable")?;
    if binding.0 != task {
        return Err("platform_cockpit_exact_task_binding_mismatch");
    }
    let intent_id = WorkspaceIntentId::new(intent_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    if let Some(value) =
        existing_workspace_intent(bridge, context.project.clone(), intent_id.clone())?
    {
        return workspace_intent_result(bridge, &intent_id, &context.workspace, value, false);
    }
    let intent = WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
        intent_id.clone(),
        task,
        context.workspace.clone(),
        context.record.revision(),
    ));
    submit_workspace_intent(
        bridge,
        context.project,
        context.workspace,
        intent_id,
        intent,
    )
}

fn existing_workspace_intent(
    bridge: &PlatformV2Bridge,
    project: ProjectId,
    intent_id: WorkspaceIntentId,
) -> Result<Option<automonique_protocol::platform_v2_lineage::WorkspaceIntentOutcome>, &'static str>
{
    match bridge.request(PlatformV2Request::GetWorkspaceIntent(
        WorkspaceIntentLookup::new(project, intent_id),
    ))? {
        PlatformV2Response::WorkspaceIntentResult(value) => Ok(Some(value)),
        PlatformV2Response::Refused(value)
            if value.category().as_str() == "platform_v2_not_found" =>
        {
            Ok(None)
        }
        PlatformV2Response::Refused(_) => Err("platform_cockpit_intent_lookup_refused"),
        _ => Err("platform_v2_response_invalid"),
    }
}

fn submit_workspace_intent(
    bridge: &PlatformV2Bridge,
    project: ProjectId,
    workspace: UserWorkspaceId,
    intent_id: WorkspaceIntentId,
    intent: WorkspaceIntent,
) -> Result<Value, &'static str> {
    match bridge.request(PlatformV2Request::SubmitWorkspaceIntent(
        WorkspaceIntentRequest::new(project, intent),
    ))? {
        PlatformV2Response::WorkspaceIntentResult(value) => {
            workspace_intent_result(bridge, &intent_id, &workspace, value, true)
        }
        PlatformV2Response::Refused(value) => Ok(json!({
            "schema": SCHEMA,
            "state": "refused",
            "intent_id": intent_id.as_str(),
            "category": value.category().as_str(),
            "explanation": value.explanation().as_str()
        })),
        _ => Err("platform_v2_response_invalid"),
    }
}

fn workspace_intent_result(
    bridge: &PlatformV2Bridge,
    intent_id: &WorkspaceIntentId,
    expected_workspace: &UserWorkspaceId,
    value: automonique_protocol::platform_v2_lineage::WorkspaceIntentOutcome,
    allow_pending: bool,
) -> Result<Value, &'static str> {
    use automonique_protocol::platform_v2_lineage::WorkspaceIntentOutcome;

    match &value {
        WorkspaceIntentOutcome::Created(workspace) | WorkspaceIntentOutcome::Resumed(workspace)
            if workspace != expected_workspace =>
        {
            return Err("platform_cockpit_intent_workspace_mismatch");
        }
        WorkspaceIntentOutcome::Accepted | WorkspaceIntentOutcome::Unknown if !allow_pending => {
            return Ok(json!({
                "schema": SCHEMA,
                "state": "pending",
                "intent_id": intent_id.as_str(),
                "category": "platform_cockpit_intent_custody_pending"
            }));
        }
        WorkspaceIntentOutcome::Cancelled(_) => {
            return Err("platform_cockpit_intent_family_unavailable");
        }
        _ => {}
    }
    let negotiated = bridge.negotiate()?;
    let document = stringify_integers(
        serde_json::from_slice(
            &encode_workspace_intent_outcome(&negotiated, &value)
                .map_err(|_| "platform_cockpit_projection_invalid")?,
        )
        .map_err(|_| "platform_cockpit_projection_invalid")?,
    );
    Ok(json!({
        "schema": SCHEMA,
        "state": "receipt",
        "intent_id": intent_id.as_str(),
        "outcome": document
    }))
}

fn get_workspace_intent(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    intent_id: &str,
) -> Result<Value, &'static str> {
    require_v2(bridge)?;
    let project =
        ProjectId::new(project_id.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace = UserWorkspaceId::new(workspace_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let intent_id = WorkspaceIntentId::new(intent_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let capabilities = lifecycle_capabilities(bridge)?;
    exact_workspace_record(bridge, &capabilities, &project, &workspace)?;
    match existing_workspace_intent(bridge, project, intent_id.clone())? {
        Some(value) => workspace_intent_result(bridge, &intent_id, &workspace, value, false),
        None => Ok(json!({
            "schema": SCHEMA,
            "state": "missing",
            "intent_id": intent_id.as_str(),
            "category": "platform_v2_not_found"
        })),
    }
}

struct ReviewControlContext {
    project: ProjectId,
    workspace: WorkContextIdentity,
    snapshot: ReviewSnapshot,
}

fn review_control_context(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
) -> Result<ReviewControlContext, &'static str> {
    require_v2(bridge)?;
    let project =
        ProjectId::new(project_id.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace_id = UserWorkspaceId::new(workspace_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace = WorkContextIdentity::UserWorkspace(workspace_id.clone());
    let capabilities = lifecycle_capabilities(bridge)?;
    let record = exact_workspace_record(bridge, &capabilities, &project, &workspace_id)?;
    if record.lifecycle() != WorkContextLifecycle::Active {
        return Err("platform_cockpit_workspace_inactive");
    }
    let request = ReviewReadRequest::new(project.clone(), workspace.clone())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let snapshot = match bridge.request(PlatformV2Request::GetReview(request))? {
        PlatformV2Response::ReviewResult(value) => value,
        PlatformV2Response::Refused(_) => return Err("platform_cockpit_review_unavailable"),
        _ => return Err("platform_v2_response_invalid"),
    };
    if snapshot.workspace() != &workspace
        || snapshot.revision() != parse_revision(expected_revision)?
        || !review_snapshot_is_fresh(&snapshot)
    {
        return Err("platform_cockpit_review_stale");
    }
    Ok(ReviewControlContext {
        project,
        workspace,
        snapshot,
    })
}

#[allow(clippy::too_many_arguments)]
fn add_comment(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    comment_id: &str,
    file_id: &str,
    hunk_id: &str,
    side: CockpitDiffSide,
    line: u32,
    body: &str,
    idempotency_key: &str,
) -> Result<Value, &'static str> {
    let context = review_control_context(bridge, project_id, workspace_id, expected_revision)?;
    let action = ReviewAction::AddComment {
        comment_id: ReviewCommentId::new(comment_id.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
        anchor: ReviewAnchor::new(
            ReviewFileId::new(file_id.to_owned())
                .map_err(|_| "platform_cockpit_request_invalid")?,
            ReviewHunkId::new(hunk_id.to_owned())
                .map_err(|_| "platform_cockpit_request_invalid")?,
            match side {
                CockpitDiffSide::Old => DiffSide::Old,
                CockpitDiffSide::New => DiffSide::New,
            },
            line,
        )
        .map_err(|_| "platform_cockpit_request_invalid")?,
        body: ReviewText::new(body.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?,
    };
    execute_review_action(
        bridge,
        context,
        action,
        IdempotencyKey::new(idempotency_key.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
        None,
    )
}

fn approve_review(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    expected_review_revision: &str,
    idempotency_key: &str,
) -> Result<Value, &'static str> {
    let context = review_control_context(bridge, project_id, workspace_id, expected_revision)?;
    let expected_review_revision = parse_revision(expected_review_revision)?;
    if context.snapshot.review().freshness().observed_revision() != expected_review_revision
        || context.snapshot.review().decision() != ReviewDecision::Pending
    {
        return Err("platform_cockpit_review_stale");
    }
    let action = ReviewAction::ApproveReview {
        expected_review_revision,
    };
    execute_review_action(
        bridge,
        context,
        action,
        IdempotencyKey::new(idempotency_key.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Mirrors the exact, separately fenced cockpit confirmation fields.
fn rerun_check(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    check_id: &str,
    expected_check_revision: &str,
    confirmation_digest: &str,
    idempotency_key: &str,
) -> Result<Value, &'static str> {
    let (
        context,
        check_id,
        expected_check_revision,
        workspace_revision,
        advertised_confirmation,
        receipt_correlation,
    ) = rerun_confirmation(
        bridge,
        project_id,
        workspace_id,
        expected_revision,
        check_id,
        expected_check_revision,
    )?;
    let supplied_confirmation = ReviewConfirmationDigest::new(confirmation_digest.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    if supplied_confirmation != advertised_confirmation {
        return Err("platform_cockpit_review_stale");
    }
    execute_review_action(
        bridge,
        context,
        ReviewAction::RerunCheck {
            check_id,
            expected_check_revision,
        },
        IdempotencyKey::new(idempotency_key.to_owned())
            .map_err(|_| "platform_cockpit_request_invalid")?,
        Some((
            supplied_confirmation,
            workspace_revision,
            receipt_correlation,
        )),
    )
}

fn preview_rerun_check(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    check_id: &str,
    expected_check_revision: &str,
) -> Result<Value, &'static str> {
    let (
        context,
        check_id,
        expected_check_revision,
        workspace_revision,
        confirmation_digest,
        receipt_correlation,
    ) = rerun_confirmation(
        bridge,
        project_id,
        workspace_id,
        expected_revision,
        check_id,
        expected_check_revision,
    )?;
    Ok(json!({
        "schema": SCHEMA,
        "state": "confirmation_preview",
        "project_id": context.project.as_str(),
        "workspace_id": context.workspace.id(),
        "exact_revision": context.snapshot.revision().to_string(),
        "check_id": check_id.as_str(),
        "exact_check_revision": expected_check_revision.to_string(),
        "confirmation_digest": confirmation_digest.as_str()
        ,"workspace_revision": workspace_revision.to_string()
        ,"receipt_correlation_digest": receipt_correlation.as_str()
    }))
}

fn rerun_confirmation(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    expected_revision: &str,
    check_id: &str,
    expected_check_revision: &str,
) -> Result<
    (
        ReviewControlContext,
        ReviewCheckId,
        Revision,
        Revision,
        ReviewConfirmationDigest,
        ReviewReceiptCorrelationDigest,
    ),
    &'static str,
> {
    let context = review_control_context(bridge, project_id, workspace_id, expected_revision)?;
    let check_id =
        ReviewCheckId::new(check_id.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?;
    let expected_check_revision = parse_revision(expected_check_revision)?;
    let capability_request =
        ReviewReadRequest::new(context.project.clone(), context.workspace.clone())
            .map_err(|_| "platform_cockpit_request_invalid")?;
    let capabilities =
        match bridge.request(PlatformV2Request::GetReviewCapabilities(capability_request))? {
            PlatformV2Response::ReviewCapabilities(value) => value,
            PlatformV2Response::Refused(_) => return Err("platform_cockpit_ci_family_unavailable"),
            _ => return Err("platform_v2_response_invalid"),
        };
    let advertised = capabilities.rerunnable_checks().iter().find(|candidate| {
        candidate.check_id() == &check_id
            && candidate.expected_check_revision() == expected_check_revision
            && context.snapshot.checks().iter().any(|check| {
                check.id() == &check_id
                    && check.authority() == candidate.authority()
                    && check.freshness().state() == ReviewFreshnessState::Fresh
                    && check.freshness().observed_revision() == expected_check_revision
            })
    });
    if capabilities.project() != &context.project
        || capabilities.workspace() != &context.workspace
        || capabilities.snapshot_revision() != context.snapshot.revision()
        || advertised.is_none()
    {
        return Err("platform_cockpit_review_stale");
    }
    Ok((
        context,
        check_id,
        expected_check_revision,
        capabilities.workspace_revision(),
        advertised
            .expect("checked above")
            .confirmation_digest()
            .clone(),
        advertised
            .expect("checked above")
            .receipt_correlation_digest()
            .clone(),
    ))
}

fn execute_review_action(
    bridge: &PlatformV2Bridge,
    context: ReviewControlContext,
    action: ReviewAction,
    idempotency_key: IdempotencyKey,
    confirmation: Option<(
        ReviewConfirmationDigest,
        Revision,
        ReviewReceiptCorrelationDigest,
    )>,
) -> Result<Value, &'static str> {
    if confirmation.is_none()
        && let Some(receipt) = existing_review_receipt(
            bridge,
            context.project.clone(),
            context.workspace.clone(),
            idempotency_key.clone(),
            None,
        )?
    {
        return action_receipt(&receipt);
    }
    let request = match confirmation {
        Some((confirmation, workspace_revision, receipt_correlation)) => {
            ReviewActionTransportRequest::new_confirmed_correlated(
                context.workspace,
                context.snapshot.revision(),
                action,
                idempotency_key,
                confirmation,
                workspace_revision,
                receipt_correlation,
            )
        }
        None => ReviewActionTransportRequest::new(
            context.workspace,
            context.snapshot.revision(),
            action,
            idempotency_key,
        ),
    }
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

fn existing_review_receipt(
    bridge: &PlatformV2Bridge,
    project: ProjectId,
    workspace: WorkContextIdentity,
    idempotency_key: IdempotencyKey,
    receipt_correlation_digest: Option<ReviewReceiptCorrelationDigest>,
) -> Result<Option<ReviewActionReceipt>, &'static str> {
    let lookup = match receipt_correlation_digest {
        Some(digest) => {
            ReviewReceiptLookup::new_correlated(project, workspace, idempotency_key, digest)
        }
        None => ReviewReceiptLookup::new(project, workspace, idempotency_key),
    }
    .map_err(|_| "platform_cockpit_request_invalid")?;
    match bridge.request(PlatformV2Request::GetReviewReceipt(lookup))? {
        PlatformV2Response::ReviewReceipt(value) => Ok(Some(value)),
        PlatformV2Response::Refused(value)
            if value.category().as_str() == "platform_v2_not_found" =>
        {
            Ok(None)
        }
        PlatformV2Response::Refused(_) => Err("platform_cockpit_review_lookup_refused"),
        _ => Err("platform_v2_response_invalid"),
    }
}

fn get_review_receipt(
    bridge: &PlatformV2Bridge,
    project_id: &str,
    workspace_id: &str,
    idempotency_key: &str,
    receipt_correlation_digest: Option<&str>,
) -> Result<Value, &'static str> {
    require_v2(bridge)?;
    let project =
        ProjectId::new(project_id.to_owned()).map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace_id = UserWorkspaceId::new(workspace_id.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let workspace = WorkContextIdentity::UserWorkspace(workspace_id.clone());
    let capabilities = lifecycle_capabilities(bridge)?;
    exact_workspace_record(bridge, &capabilities, &project, &workspace_id)?;
    let idempotency_key = IdempotencyKey::new(idempotency_key.to_owned())
        .map_err(|_| "platform_cockpit_request_invalid")?;
    let receipt_correlation_digest = receipt_correlation_digest
        .map(|value| ReviewReceiptCorrelationDigest::new(value.to_owned()))
        .transpose()
        .map_err(|_| "platform_cockpit_request_invalid")?;
    match existing_review_receipt(
        bridge,
        project,
        workspace,
        idempotency_key,
        receipt_correlation_digest,
    )? {
        Some(value) => action_receipt(&value),
        None => Ok(json!({
            "schema": SCHEMA,
            "state": "missing",
            "category": "platform_v2_not_found"
        })),
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
            selected_inbox: BoundedCockpitItems {
                items: Vec::new(),
                total: 0,
            },
            selected_source: unavailable("platform_v2_attention_inventory_exceeds_bound"),
        };
    }
    let mut selected_inbox = BoundedCockpitItems {
        items: Vec::new(),
        total: 0,
    };
    let mut selected_source = unavailable("no_selected_workspace");
    let observations = workspaces
        .into_iter()
        .map(|record| {
            let read = bounded_attention_sources(bridge, records, record);
            if selected == Some(record.identity()) {
                selected_inbox = read.inbox;
                selected_source = read.observation.clone();
            }
            (record.identity().id().to_owned(), read.observation)
        })
        .collect::<BTreeMap<_, _>>();
    let coverage = summarize_attention(&observations, total);
    AttentionInventory {
        coverage,
        observations,
        selected_inbox,
        selected_source,
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

struct WorkspaceAttentionRead {
    observation: Value,
    inbox: BoundedCockpitItems,
}

fn bounded_attention_sources(
    bridge: &PlatformV2Bridge,
    records: &[WorkContextRecord],
    workspace: &WorkContextRecord,
) -> WorkspaceAttentionRead {
    let Some(WorkContextIdentity::Project(project)) =
        relation(workspace, WorkContextRelationKind::UserWorkspaceProject)
    else {
        return unavailable_attention("platform_v2_workspace_project_unavailable");
    };
    let WorkContextIdentity::UserWorkspace(workspace_id) = workspace.identity() else {
        return unavailable_attention("platform_cockpit_selection_invalid");
    };
    let review_exists = match review_attention_source_exists(bridge, &project, workspace) {
        Ok(value) => value,
        Err(category) => return unavailable_attention(&category),
    };
    let sources = match authoritative_attention_sources(records, workspace, review_exists) {
        Ok(sources) => sources,
        Err(category) => return unavailable_attention(category),
    };

    let mut snapshots = Vec::new();
    for source in sources {
        let request = AttentionReadRequest::new(source, project.clone(), workspace_id.clone());
        match bridge.request_with_timeout(
            PlatformV2Request::GetAttentionSourceSnapshot(request),
            ATTENTION_READ_TIMEOUT,
        ) {
            Ok(PlatformV2Response::AttentionSourceSnapshot(snapshot)) => snapshots.push(snapshot),
            Ok(PlatformV2Response::Refused(value)) => {
                return unavailable_attention(value.category().as_str());
            }
            Ok(_) => return unavailable_attention("platform_v2_response_invalid"),
            Err(category) => return unavailable_attention(category),
        }
    }
    let state = snapshots
        .iter()
        .flat_map(|snapshot| snapshot.items())
        .map(|item| item.state())
        .max_by_key(|state| attention_item_precedence(*state))
        .map_or("idle", AttentionItemState::as_str);
    let inbox = attention_inbox(workspace_id, &snapshots);
    WorkspaceAttentionRead {
        observation: json!({ "state": "available", "value": state, "category": Value::Null }),
        inbox,
    }
}

fn review_attention_source_exists(
    bridge: &PlatformV2Bridge,
    project: &ProjectId,
    workspace: &WorkContextRecord,
) -> Result<bool, String> {
    let request = ReviewReadRequest::new(project.clone(), workspace.identity().clone())
        .map_err(|_| String::from("platform_v2_response_invalid"))?;
    review_attention_source_presence(
        bridge.request_with_timeout(
            PlatformV2Request::GetReview(request),
            ATTENTION_READ_TIMEOUT,
        ),
        workspace.identity(),
    )
}

fn review_attention_source_presence(
    response: Result<PlatformV2Response, &'static str>,
    workspace: &WorkContextIdentity,
) -> Result<bool, String> {
    match response {
        Ok(PlatformV2Response::ReviewResult(review)) if review.workspace() == workspace => Ok(true),
        Ok(PlatformV2Response::Refused(value))
            if value.category().as_str() == "platform_v2_not_found" =>
        {
            Ok(false)
        }
        Ok(PlatformV2Response::Refused(value)) => Err(value.category().as_str().to_owned()),
        Ok(_) => Err(String::from("platform_v2_response_invalid")),
        Err(category) => Err(category.to_owned()),
    }
}

fn authoritative_attention_sources(
    records: &[WorkContextRecord],
    workspace: &WorkContextRecord,
    review_exists: bool,
) -> Result<Vec<AttentionSource>, &'static str> {
    let WorkContextIdentity::UserWorkspace(workspace_id) = workspace.identity() else {
        return Err("platform_cockpit_selection_invalid");
    };
    let Ok(workspace_source_id) = AttentionSourceId::new(workspace_id.as_str().to_owned()) else {
        return Err("platform_v2_attention_source_exceeds_bound");
    };
    let mut sources = Vec::new();
    if review_exists {
        sources.push(AttentionSource::new(
            AttentionSourceKind::Review,
            workspace_source_id.clone(),
        ));
    }
    sources.push(AttentionSource::new(
        AttentionSourceKind::Orchestration,
        workspace_source_id,
    ));
    let attempts: std::collections::BTreeSet<_> = records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::AttemptWorkspace)
        .filter(|record| {
            relation(record, WorkContextRelationKind::AttemptUserWorkspace).as_ref()
                == Some(workspace.identity())
        })
        .map(|record| record.identity().id().to_owned())
        .collect();
    for session in records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::Session)
    {
        if relation(session, WorkContextRelationKind::SessionAttemptWorkspace)
            .is_some_and(|attempt| attempts.contains(attempt.id()))
        {
            let Ok(id) = AttentionSourceId::new(session.identity().id().to_owned()) else {
                return Err("platform_v2_attention_source_exceeds_bound");
            };
            sources.push(AttentionSource::new(
                AttentionSourceKind::ProviderSession,
                id,
            ));
        }
    }
    if sources.len() > MAX_ATTENTION_SOURCES_PER_WORKSPACE {
        return Err("platform_v2_attention_source_inventory_exceeds_bound");
    }
    if !attention_sources_unique(&sources) {
        return Err("platform_v2_attention_source_inventory_duplicate");
    }
    Ok(sources)
}

fn attention_sources_unique(sources: &[AttentionSource]) -> bool {
    sources
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == sources.len()
}

fn unavailable_attention(category: &str) -> WorkspaceAttentionRead {
    WorkspaceAttentionRead {
        observation: json!({ "state": "unavailable", "value": Value::Null, "category": category }),
        inbox: BoundedCockpitItems {
            items: Vec::new(),
            total: 0,
        },
    }
}

const fn attention_item_precedence(state: AttentionItemState) -> u8 {
    match state {
        AttentionItemState::Blocked => 4,
        AttentionItemState::NeedsYou => 3,
        AttentionItemState::Working => 2,
        AttentionItemState::Done => 1,
    }
}

fn attention_inbox(
    workspace: &UserWorkspaceId,
    snapshots: &[AttentionSourceSnapshot],
) -> BoundedCockpitItems {
    let mut items: Vec<_> = snapshots.iter().flat_map(|snapshot| snapshot.items().iter().map(|item| {
        let mut link = json!({ "workspace": workspace.as_str() });
        if let Some(session) = item.platform_session() {
            link["session"] = json!(session.coordinate().id.as_str());
        }
        json!({
            "id": format!("{}:{}:{}", snapshot.source().kind().as_str(), snapshot.source().id().as_str(), item.id().as_str()),
            "state": item.state().as_str(),
            "reason": item.reason().as_str(),
            "source_kind": snapshot.source().kind().as_str(),
            "source_id": snapshot.source().id().as_str(),
            "source_revision": snapshot.revision().to_string(),
            "item_revision": item.revision().to_string(),
            "observed_at_ms": item.observed_at_ms().to_string(),
            "unread": item.unread().to_string(),
            "link": link
        })
    })).collect();
    items.sort_by(|left, right| {
        right["observed_at_ms"]
            .as_str()
            .unwrap_or_default()
            .len()
            .cmp(&left["observed_at_ms"].as_str().unwrap_or_default().len())
            .then_with(|| {
                right["observed_at_ms"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(left["observed_at_ms"].as_str().unwrap_or_default())
            })
            .then_with(|| {
                left["id"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["id"].as_str().unwrap_or_default())
            })
    });
    let total = items.len();
    items.truncate(MAX_COCKPIT_INBOX_ITEMS);
    BoundedCockpitItems { items, total }
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
    selected_lineage: Option<&LineageProjection>,
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
    let mut panes_by_session = BTreeMap::<String, Vec<Value>>::new();
    for record in records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::Pane)
    {
        if let Some(session) = relation(record, WorkContextRelationKind::PaneSession) {
            panes_by_session
                .entry(session.id().to_owned())
                .or_default()
                .push(base_record(record));
        }
    }
    let mut sessions_by_attempt = BTreeMap::<String, Vec<Value>>::new();
    for record in records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::Session)
    {
        let Some(attempt) = relation(record, WorkContextRelationKind::SessionAttemptWorkspace)
        else {
            continue;
        };
        let platform_session = relation(record, WorkContextRelationKind::SessionPlatformSession);
        let mut value = base_record(record);
        value["platform_session_id"] = platform_session
            .as_ref()
            .map(WorkContextIdentity::id)
            .into();
        value["panes"] = panes_by_session
            .remove(record.identity().id())
            .unwrap_or_default()
            .into();
        sessions_by_attempt
            .entry(attempt.id().to_owned())
            .or_default()
            .push(value);
    }
    let mut attempts_by_workspace = BTreeMap::<String, Vec<Value>>::new();
    for record in records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::AttemptWorkspace)
    {
        let Some(workspace) = relation(record, WorkContextRelationKind::AttemptUserWorkspace)
        else {
            continue;
        };
        let mut value = base_record(record);
        value["sessions"] = sessions_by_attempt
            .remove(record.identity().id())
            .unwrap_or_default()
            .into();
        attempts_by_workspace
            .entry(workspace.id().to_owned())
            .or_default()
            .push(value);
    }
    records
        .iter()
        .filter(|record| record.kind() == WorkContextKind::UserWorkspace)
        .map(|record| {
            let project = relation(record, WorkContextRelationKind::UserWorkspaceProject);
            let checkout = relation(record, WorkContextRelationKind::UserWorkspaceCheckout);
            let observation = attention.get(record.identity().id());
            let lineage = selected_lineage
                .filter(|lineage| lineage.workspace().as_str() == record.identity().id())
                .map(lineage_read_model);
            json!({
                "id": record.identity().id(),
                "label": record.label().as_str(),
                "revision": record.revision().to_string(),
                "lifecycle": record.lifecycle().as_str(),
                "project_id": project.as_ref().map(WorkContextIdentity::id),
                "checkout_id": checkout.as_ref().map(WorkContextIdentity::id),
                "host_id": checkout.as_ref().and_then(|value| checkouts.get(value.id())).cloned().flatten(),
                "attempts": attempts_by_workspace.remove(record.identity().id()).unwrap_or_default(),
                "task": lineage.as_ref().and_then(|value| value.get("task")).cloned().unwrap_or(Value::Null),
                "external_work": lineage.as_ref().and_then(|value| value.get("external_work")).cloned().unwrap_or(Value::Null),
                "internal_agent": lineage.as_ref().and_then(|value| value.get("internal_agent")).cloned().unwrap_or(Value::Null),
                "lineage": lineage.unwrap_or(Value::Null),
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

fn lineage_read_model(lineage: &LineageProjection) -> Value {
    let external_work_items: Vec<Value> = lineage
        .external_work_items()
        .iter()
        .map(|item| {
            json!({
                "identity": external_work_json(item.identity()),
                "revision": item.revision().to_string(),
                "state": item.state().as_str(),
                "moved_to": item.moved_to().map(external_work_json),
                "origin": lineage_origin_json(item.origin()),
                "freshness": item.freshness().state().as_str(),
                "observed_at": item.freshness().observed_at_ms().to_string(),
                "latest_message": item.latest_useful_message().map(|message| message.text().as_str())
            })
        })
        .collect();
    let orchestration: Vec<Value> = lineage
        .orchestration()
        .iter()
        .map(|item| {
            json!({
                "kind": item.identity().kind().as_str(),
                "id": item.identity().id(),
                "revision": item.revision().to_string(),
                "parent": item.parent().map(|parent| json!({ "kind": parent.kind().as_str(), "id": parent.id() })),
                "external_work": item.external_work().map(external_work_json),
                "status": item.status().kind(),
                "status_message": lineage_status_message(item.status()),
                "origin": lineage_origin_json(item.origin()),
                "freshness": item.freshness().state().as_str(),
                "observed_at": item.freshness().observed_at_ms().to_string(),
                "latest_message": item.latest_useful_message().map(|message| message.text().as_str())
            })
        })
        .collect();
    let external_work = (external_work_items.len() == 1).then(|| {
        let item = &external_work_items[0];
        json!({
            "state": item["state"],
            "freshness": item["freshness"],
            "observed_at": item["observed_at"],
            "reference": item["identity"]
        })
    });
    let tasks: Vec<_> = lineage
        .orchestration()
        .iter()
        .filter(|item| matches!(item.identity(), OrchestrationIdentity::Task(_)))
        .collect();
    let task = (tasks.len() == 1).then(|| tasks[0]);
    let internal_agent = task.map(|item| {
        json!({
            "state": item.status().kind(),
            "freshness": item.freshness().state().as_str(),
            "observed_at": item.freshness().observed_at_ms().to_string(),
            "reference": { "kind": item.identity().kind().as_str(), "id": item.identity().id() }
        })
    });
    json!({
        "external_work_items": external_work_items,
        "orchestration": orchestration,
        "task": task.map(|item| item.identity().id()),
        "external_work": external_work,
        "internal_agent": internal_agent
    })
}

fn lineage_origin_json(origin: &automonique_protocol::platform_v2_lineage::LineageOrigin) -> Value {
    json!({
        "workspace": origin.workspace().as_str(),
        "attempt": origin.attempt().map(|value| value.as_str()),
        "session": origin.session().map(|value| value.as_str()),
        "pane": origin.pane().map(|value| value.as_str())
    })
}

fn lineage_status_message(status: &LineageStatus) -> Option<&str> {
    match status {
        LineageStatus::Working => None,
        LineageStatus::Blocked(message)
        | LineageStatus::Waiting(message)
        | LineageStatus::Done(message) => Some(message.as_str()),
    }
}

fn cockpit_activities(
    lineage: Option<&LineageProjection>,
    review: Option<&ReviewSnapshot>,
) -> BoundedCockpitItems {
    let mut values = Vec::<(u64, String, Value)>::new();
    if let Some(lineage) = lineage {
        for (index, item) in lineage.external_work_items().iter().enumerate() {
            let id = format!("external-work-{index}");
            let at = item.freshness().observed_at_ms();
            values.push((
                at,
                id.clone(),
                json!({
                    "id": id,
                    "at": at.to_string(),
                    "kind": "external_work",
                    "label": format!("External work {}", item.state().as_str()),
                    "source": "external_work",
                    "freshness": item.freshness().state().as_str(),
                    "source_revision": item.revision().to_string(),
                    "link": lineage_origin_json(item.origin())
                }),
            ));
        }
        for (index, item) in lineage.orchestration().iter().enumerate() {
            let id = format!("orchestration-{index}");
            let at = item.freshness().observed_at_ms();
            values.push((
                at,
                id.clone(),
                json!({
                    "id": id,
                    "at": at.to_string(),
                    "kind": item.identity().kind().as_str(),
                    "label": format!(
                        "{} {}",
                        item.identity().kind().as_str().replace('_', " "),
                        item.status().kind()
                    ),
                    "source": "orchestration",
                    "freshness": item.freshness().state().as_str(),
                    "source_revision": item.revision().to_string(),
                    "link": lineage_origin_json(item.origin())
                }),
            ));
        }
    }
    if let Some(review) = review {
        let workspace = review.workspace().id();
        let mut push_review = |id: String,
                               at: u64,
                               kind: &'static str,
                               label: String,
                               freshness: ReviewFreshnessState,
                               source_revision: Revision| {
            values.push((
                at,
                id.clone(),
                json!({
                    "id": id,
                    "at": at.to_string(),
                    "kind": kind,
                    "label": label,
                    "source": "review",
                    "freshness": freshness.as_str(),
                    "source_revision": source_revision.to_string(),
                    "link": { "workspace": workspace }
                }),
            ));
        };
        for check in review.checks() {
            push_review(
                format!("check-{}", check.id().as_str()),
                check.freshness().observed_at_ms(),
                "check",
                format!("Check {}", check.state().as_str()),
                check.freshness().state(),
                check.freshness().observed_revision(),
            );
        }
        push_review(
            "review-status".to_owned(),
            review.review().freshness().observed_at_ms(),
            "review",
            format!("Review {}", review.review().decision().as_str()),
            review.review().freshness().state(),
            review.review().freshness().observed_revision(),
        );
        push_review(
            "pull-request-status".to_owned(),
            review.pull_request().freshness().observed_at_ms(),
            "pull_request",
            format!(
                "Pull request {} · {}",
                review.pull_request().state().as_str(),
                review.pull_request().readiness().as_str()
            ),
            review.pull_request().freshness().state(),
            review.pull_request().freshness().observed_revision(),
        );
        push_review(
            "delivery-status".to_owned(),
            review.delivery().freshness().observed_at_ms(),
            "delivery",
            format!("Delivery {}", review.delivery().state().as_str()),
            review.delivery().freshness().state(),
            review.delivery().freshness().observed_revision(),
        );
    }
    values.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let total = values.len();
    values.truncate(MAX_COCKPIT_ACTIVITIES);
    BoundedCockpitItems {
        items: values.into_iter().map(|(_, _, value)| value).collect(),
        total,
    }
}

fn collection_projection(bounded: BoundedCockpitItems, sources: &[(&str, &Value)]) -> Value {
    let available_sources = sources
        .iter()
        .filter(|(_, value)| value["state"] == "available")
        .count();
    let omitted = bounded.total.saturating_sub(bounded.items.len());
    let state = if available_sources == sources.len() && omitted == 0 {
        "complete"
    } else if available_sources == 0 {
        "unavailable"
    } else {
        "partial"
    };
    let source_coverage = sources
        .iter()
        .map(|(name, value)| {
            let mut coverage = serde_json::Map::new();
            coverage.insert(
                "state".to_owned(),
                value
                    .get("state")
                    .cloned()
                    .unwrap_or_else(|| json!("unavailable")),
            );
            if let Some(category) = value.get("category") {
                coverage.insert("category".to_owned(), category.clone());
            }
            ((*name).to_owned(), Value::Object(coverage))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "state": state,
        "items": bounded.items,
        "total": bounded.total.to_string(),
        "omitted": omitted.to_string(),
        "sources": source_coverage
    })
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

fn v1_fallback(retained_v1: Value, category: &str) -> Value {
    json!({
        "schema": SCHEMA,
        "mode": "v1",
        "degradation": { "category": category },
        "retained_v1": retained_v1,
        "projects": [], "hosts": [], "workspaces": [],
        "activities": {
            "state": "unavailable", "items": [], "total": "0", "omitted": "0",
            "sources": {
                "lineage": { "state": "unavailable", "category": category },
                "review": { "state": "unavailable", "category": category }
            }
        },
        "inbox": {
            "state": "unavailable", "items": [], "total": "0", "omitted": "0",
            "sources": {
                "review": { "state": "unavailable", "category": category }
            }
        },
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

fn v2_unavailable(retained_v1: Value, category: &str) -> Value {
    let mut value = v1_fallback(retained_v1, category);
    value["mode"] = json!("partial");
    value["degradation"] = json!({
        "platform": "v2",
        "state": "unavailable",
        "category": category
    });
    value
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
    use automonique_protocol::platform_v2_transport::PlatformV2Refusal;

    fn canonical_json_bytes(value: &Value) -> Vec<u8> {
        fn write(value: &Value, output: &mut Vec<u8>) {
            match value {
                Value::Null => output.extend_from_slice(b"null"),
                Value::Bool(value) => {
                    output.extend_from_slice(if *value { b"true" } else { b"false" });
                }
                Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
                Value::String(value) => output.extend_from_slice(
                    serde_json::to_string(value)
                        .expect("a Rust string always serializes as JSON")
                        .as_bytes(),
                ),
                Value::Array(values) => {
                    output.push(b'[');
                    for (index, value) in values.iter().enumerate() {
                        if index != 0 {
                            output.push(b',');
                        }
                        write(value, output);
                    }
                    output.push(b']');
                }
                Value::Object(values) => {
                    output.push(b'{');
                    let mut fields: Vec<_> = values.iter().collect();
                    fields.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
                    for (index, (key, value)) in fields.into_iter().enumerate() {
                        if index != 0 {
                            output.push(b',');
                        }
                        output.extend_from_slice(
                            serde_json::to_string(key)
                                .expect("a Rust string always serializes as JSON")
                                .as_bytes(),
                        );
                        output.push(b':');
                        write(value, output);
                    }
                    output.push(b'}');
                }
            }
        }

        let mut output = Vec::new();
        write(value, &mut output);
        output
    }

    #[test]
    fn cockpit_control_documents_reject_unknown_or_generic_execution_fields() {
        let unknown = serde_json::from_value::<CockpitRequest>(json!({
            "action": "get_workspace_intent",
            "project_id": "project-test",
            "workspace_id": "workspace-test",
            "intent_id": "intent-test",
            "actor": "browser-asserted"
        }));
        assert!(unknown.is_err());
        let generic = serde_json::from_value::<CockpitRequest>(json!({
            "action": "execute",
            "command": "anything"
        }));
        assert!(generic.is_err());

        let preview = serde_json::from_value::<CockpitRequest>(json!({
            "action": "preview_rerun_check",
            "project_id": "project-test",
            "workspace_id": "workspace-test",
            "expected_revision": "7",
            "check_id": "check-test",
            "expected_check_revision": "5"
        }));
        assert!(matches!(
            preview,
            Ok(CockpitRequest::PreviewRerunCheck { .. })
        ));
        let unconfirmed = serde_json::from_value::<CockpitRequest>(json!({
            "action": "rerun_check",
            "project_id": "project-test",
            "workspace_id": "workspace-test",
            "expected_revision": "7",
            "check_id": "check-test",
            "expected_check_revision": "5",
            "idempotency_key": "rerun-test"
        }));
        assert!(unconfirmed.is_err());
        let confirmed = serde_json::from_value::<CockpitRequest>(json!({
            "action": "rerun_check",
            "project_id": "project-test",
            "workspace_id": "workspace-test",
            "expected_revision": "7",
            "check_id": "check-test",
            "expected_check_revision": "5",
            "confirmation_digest": "ab".repeat(32),
            "idempotency_key": "rerun-test"
        }));
        assert!(matches!(confirmed, Ok(CockpitRequest::RerunCheck { .. })));

        let correlated_lookup = serde_json::from_value::<CockpitRequest>(json!({
            "action": "get_review_receipt",
            "project_id": "project-test",
            "workspace_id": "workspace-test",
            "idempotency_key": "rerun-test",
            "receipt_correlation_digest": "cd".repeat(32)
        }))
        .unwrap();
        assert!(matches!(
            correlated_lookup,
            CockpitRequest::GetReviewReceipt {
                receipt_correlation_digest: Some(value),
                ..
            } if value == "cd".repeat(32)
        ));
    }

    #[test]
    fn workspace_project_custody_is_exact_and_cross_project_fails_closed() {
        use automonique_protocol::platform_v2::{
            WorkContextAttributes, WorkContextLabel, WorkContextRelation, WorkContextTargetKind,
        };

        let project_a = ProjectId::new("project-a").unwrap();
        let project_b = ProjectId::new("project-b").unwrap();
        let record = WorkContextRecord::new(
            WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-a").unwrap()),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Workspace A").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceProject,
                    WorkContextIdentity::Project(project_a.clone()),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceCheckout,
                    WorkContextIdentity::parse_local(WorkContextTargetKind::Checkout, "checkout-a")
                        .unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert!(workspace_matches_project(&record, &project_a));
        assert!(!workspace_matches_project(&record, &project_b));
        assert_ne!(record.revision(), Revision::new(2).unwrap());
    }

    #[test]
    fn integer_projection_is_lossless_for_javascript_clients() {
        let value =
            stringify_integers(json!({ "revision": 9_007_199_254_740_995_u64, "items": [7] }));
        assert_eq!(value["revision"], "9007199254740995");
        assert_eq!(value["items"][0], "7");
    }

    #[test]
    fn fallback_never_fabricates_v2_inventory() {
        let value = v1_fallback(
            json!({ "sessions": [{ "summary": "working on a branch" }] }),
            "unavailable",
        );
        assert_eq!(value["mode"], "v1");
        assert_eq!(value["workspaces"], json!([]));
        assert_eq!(value["activities"]["state"], "unavailable");
        assert_eq!(
            value["activities"]["sources"]["lineage"]["category"],
            "unavailable"
        );
        assert_eq!(value["inbox"]["state"], "unavailable");
        assert_eq!(value["actions"]["lifecycle"]["available"], false);
        let unavailable = v2_unavailable(json!({ "sessions": [] }), "v2_down");
        assert_eq!(unavailable["mode"], "partial");
        assert_eq!(unavailable["degradation"]["platform"], "v2");
        assert_eq!(unavailable["degradation"]["state"], "unavailable");
        assert_eq!(
            unavailable["activities"]["sources"]["review"]["category"],
            "v2_down"
        );
    }

    #[test]
    fn lifecycle_projection_exposes_only_installed_local_effects() {
        let project = ProjectId::new("project-test").unwrap();
        let capabilities = LifecycleCapabilities::new(
            std::collections::BTreeSet::from([project.clone()]),
            automonique_protocol::platform_v2_transport::LIFECYCLE_CAPABILITY_EFFECT_KINDS
                .into_iter()
                .map(|kind| {
                    if matches!(kind, "create_host_setup" | "create_checkout") {
                        automonique_protocol::platform_v2_transport::LifecycleOperationCapability::available(project.clone(), kind)
                    } else {
                        automonique_protocol::platform_v2_transport::LifecycleOperationCapability::unavailable(
                            project.clone(), kind, ADAPTER_PENDING,
                        )
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        )
        .unwrap();
        let installed = lifecycle_actions(
            &capabilities,
            Some(&WorkContextIdentity::Project(project.clone())),
            None,
            None,
        );
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

        let absent_capabilities = LifecycleCapabilities::new(
            std::collections::BTreeSet::from([project.clone()]),
            automonique_protocol::platform_v2_transport::LIFECYCLE_CAPABILITY_EFFECT_KINDS
                .into_iter()
                .map(|kind| {
                    automonique_protocol::platform_v2_transport::LifecycleOperationCapability::unavailable(
                        project.clone(), kind, "platform_v2_selector_registry_unavailable",
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        )
        .unwrap();
        let absent = lifecycle_actions(
            &absent_capabilities,
            Some(&WorkContextIdentity::Project(project)),
            None,
            None,
        );
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
                json!({ "state": "available", "value": "needs_you", "category": Value::Null }),
            ),
            (
                String::from("workspace-b"),
                json!({ "state": "available", "value": "blocked", "category": Value::Null }),
            ),
        ]);
        let complete = summarize_attention(&observations, 2);
        assert_eq!(complete["state"], "available");
        assert_eq!(complete["known_workspaces"], "2");
        assert_eq!(observations["workspace-a"]["value"], "needs_you");
        assert_eq!(observations["workspace-b"]["value"], "blocked");
        let mut partial = observations;
        partial.insert(
            String::from("workspace-b"),
            json!({ "state": "unavailable", "value": Value::Null, "category": "attention_source_unavailable" }),
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

    #[test]
    fn retention_gap_or_source_refusal_discards_partial_attention_aggregation() {
        let unavailable = unavailable_attention("platform_v2_attention_resync_required");
        assert_eq!(unavailable.observation["state"], "unavailable");
        assert_eq!(
            unavailable.observation["category"],
            "platform_v2_attention_resync_required"
        );
        assert_eq!(unavailable.inbox.total, 0);
        assert!(unavailable.inbox.items.is_empty());
        let projection = collection_projection(
            unavailable.inbox,
            &[("attention", &unavailable.observation)],
        );
        assert_eq!(projection["state"], "unavailable");
        assert_eq!(projection["items"], json!([]));
    }

    #[test]
    fn bounded_source_discovery_rejects_duplicates_but_keeps_kinds_distinct() {
        let review = AttentionSource::new(
            AttentionSourceKind::Review,
            AttentionSourceId::new("workspace-1").unwrap(),
        );
        let orchestration = AttentionSource::new(
            AttentionSourceKind::Orchestration,
            AttentionSourceId::new("workspace-1").unwrap(),
        );
        assert!(attention_sources_unique(&[review.clone(), orchestration]));
        assert!(!attention_sources_unique(&[review.clone(), review]));
    }

    #[test]
    fn workspace_without_review_discovers_existing_orchestration_without_review_inference() {
        use automonique_protocol::platform_v2::{
            WorkContextAttributes, WorkContextLabel, WorkContextRelation, WorkContextTargetKind,
        };

        let workspace = WorkContextRecord::new(
            WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap()),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Workspace").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceProject,
                    WorkContextIdentity::Project(ProjectId::new("project-1").unwrap()),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceCheckout,
                    WorkContextIdentity::parse_local(WorkContextTargetKind::Checkout, "checkout-1")
                        .unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();

        let absent_review =
            authoritative_attention_sources(std::slice::from_ref(&workspace), &workspace, false)
                .unwrap();
        assert_eq!(absent_review.len(), 1);
        assert_eq!(absent_review[0].kind(), AttentionSourceKind::Orchestration);
        let present_review =
            authoritative_attention_sources(std::slice::from_ref(&workspace), &workspace, true)
                .unwrap();
        assert_eq!(
            present_review
                .iter()
                .map(AttentionSource::kind)
                .collect::<Vec<_>>(),
            vec![
                AttentionSourceKind::Review,
                AttentionSourceKind::Orchestration
            ]
        );
        assert_eq!(
            review_attention_source_presence(
                Ok(PlatformV2Response::Refused(
                    PlatformV2Refusal::new("platform_v2_not_found", "absent").unwrap(),
                )),
                workspace.identity(),
            ),
            Ok(false),
            "typed producer absence is source discovery, not workspace failure"
        );
        assert_eq!(
            review_attention_source_presence(
                Ok(PlatformV2Response::Refused(
                    PlatformV2Refusal::new("platform_v2_scope_denied", "denied").unwrap(),
                )),
                workspace.identity(),
            ),
            Err(String::from("platform_v2_scope_denied")),
            "authorization failures must not be reclassified as absence"
        );
    }

    #[test]
    fn work_context_inventory_accepts_the_bound_and_refuses_overflow() {
        assert_eq!(
            verify_inventory_capacity(WORK_CONTEXT_PAGE_LIMIT as usize * 4, 1),
            Ok(()),
            "a fifth page must remain accepted beyond 512 records"
        );
        assert_eq!(
            verify_inventory_capacity(MAX_COCKPIT_WORK_CONTEXTS - 128, 128),
            Ok(())
        );
        assert_eq!(
            verify_inventory_capacity(MAX_COCKPIT_WORK_CONTEXTS, 1),
            Err(String::from("platform_v2_inventory_exceeds_bound"))
        );
        assert_eq!(
            verify_inventory_capacity(usize::MAX, usize::MAX),
            Err(String::from("platform_v2_inventory_exceeds_bound"))
        );
    }

    #[test]
    fn hierarchy_preserves_attempt_session_and_pane_siblings_beyond_512_records() {
        use automonique_protocol::platform::{
            ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
        };
        use automonique_protocol::platform_v2::{
            V1SessionRef, WorkContextAttributes, WorkContextLabel, WorkContextRelation,
            WorkContextTargetKind,
        };

        let project = WorkContextIdentity::Project(ProjectId::new("project-hierarchy").unwrap());
        let checkout =
            WorkContextIdentity::parse_local(WorkContextTargetKind::Checkout, "checkout-hierarchy")
                .unwrap();
        let workspace = WorkContextIdentity::UserWorkspace(
            UserWorkspaceId::new("workspace-hierarchy").unwrap(),
        );
        let mut records = vec![
            WorkContextRecord::new(
                workspace.clone(),
                Revision::FIRST,
                WorkContextLifecycle::Active,
                WorkContextLabel::new("Workspace hierarchy").unwrap(),
                WorkContextAttributes::EMPTY,
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::UserWorkspaceProject,
                        project,
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::UserWorkspaceCheckout,
                        checkout,
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ];
        for index in 0..128 {
            let attempt = WorkContextIdentity::parse_local(
                WorkContextTargetKind::AttemptWorkspace,
                &format!("attempt-{index:03}"),
            )
            .unwrap();
            let session = WorkContextIdentity::parse_local(
                WorkContextTargetKind::Session,
                &format!("runtime-session-{index:03}"),
            )
            .unwrap();
            records.push(
                WorkContextRecord::new(
                    attempt.clone(),
                    Revision::FIRST,
                    WorkContextLifecycle::Running,
                    WorkContextLabel::new(format!("Attempt {index:03}")).unwrap(),
                    WorkContextAttributes::EMPTY,
                    vec![
                        WorkContextRelation::new(
                            WorkContextRelationKind::AttemptUserWorkspace,
                            workspace.clone(),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap(),
            );
            records.push(
                WorkContextRecord::new(
                    session.clone(),
                    Revision::FIRST,
                    WorkContextLifecycle::Active,
                    WorkContextLabel::new(format!("Session {index:03}")).unwrap(),
                    WorkContextAttributes::EMPTY,
                    vec![
                        WorkContextRelation::new(
                            WorkContextRelationKind::SessionAttemptWorkspace,
                            attempt,
                        )
                        .unwrap(),
                        WorkContextRelation::new(
                            WorkContextRelationKind::SessionPlatformSession,
                            WorkContextIdentity::PlatformSession(
                                V1SessionRef::new(ResourceCoordinate::new(
                                    ResourceAuthority::Automonique,
                                    ResourceKind::Session,
                                    ResourceId::new(format!("platform-session-{index:03}"))
                                        .unwrap(),
                                ))
                                .unwrap(),
                            ),
                        )
                        .unwrap(),
                    ],
                )
                .unwrap(),
            );
            for pane_index in 0..2 {
                records.push(
                    WorkContextRecord::new(
                        WorkContextIdentity::parse_local(
                            WorkContextTargetKind::Pane,
                            &format!("pane-{index:03}-{pane_index}"),
                        )
                        .unwrap(),
                        Revision::FIRST,
                        WorkContextLifecycle::Active,
                        WorkContextLabel::new(format!("Pane {index:03}-{pane_index}")).unwrap(),
                        WorkContextAttributes::EMPTY,
                        vec![
                            WorkContextRelation::new(
                                WorkContextRelationKind::PaneSession,
                                session.clone(),
                            )
                            .unwrap(),
                        ],
                    )
                    .unwrap(),
                );
            }
        }
        assert_eq!(records.len(), 513);
        let projection = workspace_records(&records, &BTreeMap::new(), None);
        let attempts = projection[0]["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 128);
        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt["sessions"].as_array().unwrap().len())
                .sum::<usize>(),
            128
        );
        assert_eq!(
            attempts
                .iter()
                .flat_map(|attempt| attempt["sessions"].as_array().unwrap())
                .map(|session| session["panes"].as_array().unwrap().len())
                .sum::<usize>(),
            256
        );
    }

    #[test]
    fn lineage_read_model_preserves_external_and_orchestration_meaning() {
        use automonique_protocol::platform_v2_lineage::{
            ExternalWorkItem, LineageFreshness, LineageMessage, LineageStatus, OrchestrationRecord,
            OrchestrationRunId,
        };

        let workspace = UserWorkspaceId::new("workspace-lineage").unwrap();
        let identity = ExternalWorkIdentity::new(
            ExternalWorkProvider::GitHub,
            ExternalWorkAuthorityId::new("github.com").unwrap(),
            ExternalWorkScope::new("owner/repository").unwrap(),
            ExternalWorkKey::new("42").unwrap(),
        );
        let freshness = LineageFreshness::new(123, 60_000, LineageFreshnessState::Fresh).unwrap();
        let external = ExternalWorkItem::new(
            identity.clone(),
            workspace.clone(),
            Revision::FIRST,
            ExternalWorkState::Open,
            None,
            freshness,
            None,
        )
        .unwrap();
        let run_identity = OrchestrationIdentity::Run(OrchestrationRunId::new("run-42").unwrap());
        let run = OrchestrationRecord::new(
            run_identity.clone(),
            workspace.clone(),
            Some(identity.clone()),
            None,
            LineageStatus::Working,
            freshness,
            None,
        )
        .unwrap();
        let task = OrchestrationRecord::new(
            OrchestrationIdentity::Task(OrchestrationTaskId::new("task-42").unwrap()),
            workspace.clone(),
            Some(identity),
            Some(run_identity),
            LineageStatus::Blocked(LineageMessage::new("awaiting review").unwrap()),
            freshness,
            None,
        )
        .unwrap();
        let projection =
            LineageProjection::new(workspace, vec![external], vec![run, task]).unwrap();
        let value = lineage_read_model(&projection);
        assert_eq!(value["task"], "task-42");
        assert_eq!(value["external_work"]["state"], "open");
        assert_eq!(value["external_work"]["freshness"], "fresh");
        assert_eq!(
            value["external_work_items"][0]["origin"]["workspace"],
            "workspace-lineage"
        );
        assert_eq!(value["external_work_items"][0]["moved_to"], Value::Null);
        assert_eq!(
            value["external_work"]["reference"],
            json!({
                "provider": "github",
                "authority": "github.com",
                "scope": "owner/repository",
                "key": "42"
            })
        );
        assert_eq!(value["internal_agent"]["state"], "blocked");
        assert_eq!(value["internal_agent"]["reference"]["kind"], "task");
        let orchestration = value["orchestration"].as_array().unwrap();
        let task = orchestration
            .iter()
            .find(|record| record["kind"] == "task")
            .unwrap();
        assert_eq!(task["status"], "blocked");
        assert_eq!(task["status_message"], "awaiting review");
        assert_eq!(task["origin"]["workspace"], "workspace-lineage");
        assert_eq!(task["parent"]["kind"], "run");
        assert_eq!(task["parent"]["id"], "run-42");
    }

    #[test]
    fn authoritative_activity_and_attention_inbox_keep_chronology_without_local_coordinates() {
        use automonique_protocol::platform_v2_attention_api::decode_attention_source_snapshot;
        use automonique_protocol::platform_v2_lineage::{
            ExternalWorkItem, LineageFreshness, LineageMessage, LineageOrigin, OrchestrationRecord,
            OrchestrationRunId,
        };
        use automonique_protocol::platform_v2_review_api::decode_review_snapshot;

        let workspace = UserWorkspaceId::new("wc_user_1").unwrap();
        let freshness = LineageFreshness::new(100, 60_000, LineageFreshnessState::Fresh).unwrap();
        let external_identity = ExternalWorkIdentity::new(
            ExternalWorkProvider::GitHub,
            ExternalWorkAuthorityId::new("github.com").unwrap(),
            ExternalWorkScope::new("owner/repository").unwrap(),
            ExternalWorkKey::new("42").unwrap(),
        );
        let external = ExternalWorkItem::new_with_origin(
            external_identity.clone(),
            LineageOrigin::workspace_only(workspace.clone()),
            Revision::FIRST,
            ExternalWorkState::Open,
            None,
            freshness,
            None,
        )
        .unwrap();
        let orchestration = OrchestrationRecord::new_with_origin(
            OrchestrationIdentity::Run(OrchestrationRunId::new("run-42").unwrap()),
            LineageOrigin::workspace_only(workspace.clone()),
            Some(external_identity),
            None,
            LineageStatus::Blocked(LineageMessage::new("awaiting review").unwrap()),
            LineageFreshness::new(200, 60_000, LineageFreshnessState::Fresh).unwrap(),
            None,
            Revision::FIRST,
        )
        .unwrap();
        let lineage =
            LineageProjection::new(workspace, vec![external], vec![orchestration]).unwrap();

        let mut review_value: Value = serde_json::from_slice(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-review-v2.json"
        ))
        .unwrap();
        review_value["attention_events"][0] = json!({
            "id": "attention-comment",
            "origin": {
                "authority": { "id": "authority-1", "kind": "review" },
                "id": "comment-1",
                "kind": "comment",
                "revision": 2
            },
            "reason": "comment_reply",
            "unread": 1
        });
        review_value["attention"] = json!({
            "reason": "comment_reply",
            "source_revision": 2,
            "state": "needs_you",
            "unread": 1
        });
        let review = decode_review_snapshot(&canonical_json_bytes(&review_value)).unwrap();

        let activity = cockpit_activities(Some(&lineage), Some(&review));
        assert_eq!(activity.total, 6);
        assert_eq!(activity.items[0]["at"], "1800000000000");
        assert_eq!(activity.items.last().unwrap()["at"], "100");
        assert!(
            activity
                .items
                .iter()
                .all(|value| value["link"]["workspace"] == "wc_user_1")
        );

        let mut attention_value: Value = serde_json::from_slice(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap();
        attention_value["source"] = json!({ "kind": "review", "id": "wc_user_1" });
        attention_value["project"] = json!("project-1");
        attention_value["user_workspace"] = json!("wc_user_1");
        attention_value["items"][0]["platform_session"] = Value::Null;
        let attention =
            decode_attention_source_snapshot(&canonical_json_bytes(&attention_value)).unwrap();
        let inbox = attention_inbox(&UserWorkspaceId::new("wc_user_1").unwrap(), &[attention]);
        assert_eq!(inbox.total, 1);
        assert_eq!(inbox.items[0]["state"], "needs_you");
        assert_eq!(inbox.items[0]["source_kind"], "review");
        assert_eq!(inbox.items[0]["source_id"], "wc_user_1");
        assert_eq!(inbox.items[0]["source_revision"], "7");
        assert_eq!(inbox.items[0]["link"]["workspace"], "wc_user_1");
        assert!(inbox.items[0]["link"].get("file").is_none());
        assert!(inbox.items[0]["link"].get("pane").is_none());

        let available = json!({ "state": "available" });
        let refused = json!({ "state": "refused", "category": "review_refused" });
        let projection = collection_projection(
            BoundedCockpitItems {
                items: vec![json!({ "id": "newest" }); MAX_COCKPIT_ACTIVITIES],
                total: MAX_COCKPIT_ACTIVITIES + 3,
            },
            &[("lineage", &available), ("review", &refused)],
        );
        assert_eq!(projection["state"], "partial");
        assert_eq!(projection["total"], "259");
        assert_eq!(projection["omitted"], "3");
        assert_eq!(
            projection["sources"]["review"]["category"],
            "review_refused"
        );
    }
}
