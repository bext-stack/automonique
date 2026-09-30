// SPDX-License-Identifier: Elastic-2.0

//! Credential-scoped task creation; never exposes generic Platform execution.
use crate::WebIntegration;
use crate::mobile_auth::{MobileAction, MobileAuthorization};
use crate::platform_task::{self, TaskRequest};
use automonique_protocol::platform::{PlatformParameter, ResourceId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const INVALID: &str = "mobile_task_request_invalid";

fn scoped_key(authorization: &MobileAuthorization, key: &str) -> Result<String, &'static str> {
    if key.is_empty()
        || key.len() > 128
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(INVALID);
    }
    let mut digest = Sha256::new();
    digest.update(b"automonique.mobile-task/v1\0");
    digest.update(authorization.credential_id.as_bytes());
    digest.update([0]);
    digest.update(key.as_bytes());
    Ok(format!("dashboard-task-{:x}", digest.finalize()))
}

pub(crate) fn execute(
    integration: &WebIntegration,
    authorization: &MobileAuthorization,
    request: TaskRequest,
) -> Result<Value, &'static str> {
    if !authorization.allows(MobileAction::StartTask) {
        return Err("mobile_task_unauthorized");
    }
    let now = crate::now_ms_i64();
    let mut custody_key = None;
    let request = match request {
        TaskRequest::Prepare {} => TaskRequest::Prepare {},
        TaskRequest::Submit {
            node_id,
            expected_revision,
            idempotency_key,
            text,
        } => {
            ResourceId::new(node_id.clone()).map_err(|_| INVALID)?;
            if node_id == automonique_daemon::CURRENT_NODE_ALIAS
                || text.trim().is_empty()
                || text.len() > authorization.limits.max_follow_up_bytes as usize
            {
                return Err(INVALID);
            }
            crate::parse_platform_decimal(&expected_revision, false).map_err(|_| INVALID)?;
            PlatformParameter::new(text.clone()).map_err(|_| INVALID)?;
            let key = scoped_key(authorization, &idempotency_key)?;
            let digest = format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&json!([&node_id, &expected_revision, &text]))
                        .map_err(|_| INVALID)?
                )
            );
            let dispatch = integration
                .mobile_auth
                .lock()
                .map_err(|_| "mobile_credential_authority_busy")?
                .bind_task(authorization, &key, &node_id, &digest, now)
                .map_err(|_| INVALID)?;
            custody_key = Some(key.clone());
            if dispatch {
                TaskRequest::Submit {
                    node_id,
                    expected_revision,
                    idempotency_key: key,
                    text,
                }
            } else {
                TaskRequest::Reconcile {
                    node_id,
                    idempotency_key: key,
                }
            }
        }
        TaskRequest::Reconcile {
            node_id,
            idempotency_key,
        } => {
            let key = scoped_key(authorization, &idempotency_key)?;
            let stored = integration
                .mobile_auth
                .lock()
                .map_err(|_| "mobile_credential_authority_busy")?
                .task_node(authorization, &key, now)
                .map_err(|_| INVALID)?;
            if stored != node_id {
                return Err(INVALID);
            }
            custody_key = Some(key.clone());
            TaskRequest::Reconcile {
                node_id,
                idempotency_key: key,
            }
        }
    };
    let mut view = {
        let mut client = integration
            .platform
            .lock()
            .map_err(|_| "platform_client_unavailable")?;
        platform_task::execute(&mut client, request)?
    };
    if let (Some(key), Some(session)) =
        (custody_key, view.get("session_id").and_then(Value::as_str))
    {
        integration
            .mobile_auth
            .lock()
            .map_err(|_| "mobile_credential_authority_busy")?
            .grant_task_session(authorization, &key, session, crate::now_ms_i64())
            .map_err(|_| "mobile_task_session_unavailable")?;
    }
    view["schema"] = json!("automonique.mobile-task/v1");
    Ok(view)
}
