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
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkAuthorityId, ExternalWorkIdentity,
    ExternalWorkKey, ExternalWorkProvider, ExternalWorkScope, ExternalWorkState,
    LineageFreshnessState, LineageProjection, OrchestrationIdentity, OrchestrationTaskId,
    WorkspaceCreateIntent, WorkspaceIntent, WorkspaceIntentId, WorkspaceResumeIntent,
};
use automonique_protocol::platform_v2_lineage_api::encode_lineage_projection;
use automonique_protocol::platform_v2_lineage_api::encode_workspace_intent_outcome;
use automonique_protocol::platform_v2_review::{
    DiffSide, ReviewAction, ReviewActionReceipt, ReviewAnchor, ReviewCommentId, ReviewDecision,
    ReviewFileId, ReviewFreshnessState, ReviewHunkId, ReviewSnapshot, ReviewText,
};
use automonique_protocol::platform_v2_review_api::{
    encode_review_action_receipt, encode_review_snapshot,
};
use automonique_protocol::platform_v2_transport::{
    LifecycleCapabilities, LineageReadRequest, PlatformV2Request, PlatformV2Response,
    ReviewActionTransportRequest, ReviewReadRequest, ReviewReceiptLookup, WorkspaceIntentLookup,
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
const MAX_COCKPIT_PROJECTS: usize = 128;
const MAX_COCKPIT_WORK_CONTEXTS: usize = 1024;
const WORK_CONTEXT_PAGE_LIMIT: u16 = 128;
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
    GetReviewReceipt {
        project_id: String,
        workspace_id: String,
        idempotency_key: String,
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
    Base,
    Head,
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
        CockpitRequest::GetReviewReceipt {
            project_id,
            workspace_id,
            idempotency_key,
        } => get_review_receipt(bridge, &project_id, &workspace_id, &idempotency_key),
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
    let capabilities = match bridge.request(PlatformV2Request::GetLifecycleCapabilities) {
        Ok(PlatformV2Response::LifecycleCapabilities(value)) => value,
        Ok(PlatformV2Response::Refused(value)) => {
            return Ok(fallback(retained_v1, value.category().as_str()));
        }
        Ok(_) => return Err("platform_v2_response_invalid"),
        Err(category) => return Ok(fallback(retained_v1, category)),
    };
    let records = match inventory(bridge, capabilities.projects()) {
        Ok(records) => records,
        Err(category) => return Ok(fallback(retained_v1, &category)),
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
    let review_actions = review_actions(
        selected,
        selected_project.as_ref(),
        review_snapshot.as_ref(),
    );
    let attention = attention_inventory(bridge, &records, selected_identity.as_ref(), &review);
    Ok(json!({
        "schema": SCHEMA,
        "mode": "v2",
        "degradation": Value::Null,
        "retained_v1": retained_v1,
        "projects": named_records(&records, WorkContextKind::Project),
        "hosts": host_records(&records),
        "workspaces": workspace_records(&records, &attention.observations),
        "selected": { "workspace": selected_identity.as_ref().map(WorkContextIdentity::id) },
        "lineage": lineage,
        "review": review,
        "attention": attention.coverage,
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
            "rerun_check": action(false, "platform_cockpit_ci_family_unavailable"),
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
                CockpitDiffSide::Base => DiffSide::Old,
                CockpitDiffSide::Head => DiffSide::New,
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
    )
}

fn execute_review_action(
    bridge: &PlatformV2Bridge,
    context: ReviewControlContext,
    action: ReviewAction,
    idempotency_key: IdempotencyKey,
) -> Result<Value, &'static str> {
    if let Some(receipt) = existing_review_receipt(
        bridge,
        context.project.clone(),
        context.workspace.clone(),
        idempotency_key.clone(),
    )? {
        return action_receipt(&receipt);
    }
    let request = ReviewActionTransportRequest::new(
        context.workspace,
        context.snapshot.revision(),
        action,
        idempotency_key,
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

fn existing_review_receipt(
    bridge: &PlatformV2Bridge,
    project: ProjectId,
    workspace: WorkContextIdentity,
    idempotency_key: IdempotencyKey,
) -> Result<Option<ReviewActionReceipt>, &'static str> {
    let lookup = ReviewReceiptLookup::new(project, workspace, idempotency_key)
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
    match existing_review_receipt(bridge, project, workspace, idempotency_key)? {
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

    #[test]
    fn work_context_inventory_accepts_the_bound_and_refuses_overflow() {
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
}
