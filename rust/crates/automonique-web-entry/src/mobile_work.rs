// SPDX-License-Identifier: Elastic-2.0

//! Explicitly delegated Slack reads and instance-scoped ticket decisions.
use crate::{
    WebIntegration,
    mobile_auth::{MobileAction, MobileAuthorization},
};
use automonique_daemon::ticket_intake::FleetConfig;
use automonique_support_connector::{
    FleetOutcome, TicketDecision, TicketDecisionRequest, TicketDispatchRequest,
};
use automonique_transport_runtime::ChannelName;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;

const INVALID: &str = "mobile_work_request_invalid";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelBinding {
    channel: String,
    display_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkRequest {
    Snapshot {},
    Channel {},
    Dispatch {
        issue_url: String,
        idempotency_key: String,
    },
    Decide {
        job_id: String,
        source_key: String,
        idempotency_key: String,
        decision: String,
        reason: String,
    },
}

fn key(auth: &MobileAuthorization, supplied: &str) -> Result<String, &'static str> {
    if supplied.is_empty()
        || supplied.len() > 128
        || !supplied
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(INVALID);
    }
    let mut hash = Sha256::new();
    hash.update(b"automonique.mobile-work/v1\0");
    hash.update(auth.credential_id.as_bytes());
    hash.update([0]);
    hash.update(supplied.as_bytes());
    Ok(format!("mobile:{:x}", hash.finalize()))
}

fn accepted<T>(
    value: Result<FleetOutcome<T>, automonique_support_connector::FleetFailure>,
) -> Result<T, &'static str> {
    match value {
        Ok(FleetOutcome::Accepted(value)) => Ok(value),
        Ok(FleetOutcome::Rejected(_)) => Err("mobile_work_refused"),
        Err(_) => Err("mobile_work_outcome_unknown"),
    }
}

pub(crate) fn execute(
    integration: &WebIntegration,
    auth: &MobileAuthorization,
    request: WorkRequest,
) -> Result<Value, &'static str> {
    if !auth.allows(MobileAction::ManageWork) {
        return Err("mobile_work_unauthorized");
    }
    let schema = "automonique.mobile-work/v1";
    if matches!(request, WorkRequest::Channel {}) {
        let path = integration.state_dir.join("mobile-work.json");
        let meta =
            std::fs::symlink_metadata(&path).map_err(|_| "mobile_work_channel_unconfigured")?;
        if !meta.is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
            || meta.len() > 4096
        {
            return Err("mobile_work_channel_unconfigured");
        }
        let binding: ChannelBinding = serde_json::from_slice(
            &std::fs::read(path).map_err(|_| "mobile_work_channel_unconfigured")?,
        )
        .map_err(|_| "mobile_work_channel_unconfigured")?;
        let channel = ChannelName::new(&binding.channel).map_err(|_| INVALID)?;
        if binding.display_name.is_empty()
            || binding.display_name.len() > 80
            || binding.display_name.chars().any(char::is_control)
        {
            return Err(INVALID);
        }
        let mut slack = integration
            .slack
            .lock()
            .map_err(|_| "mobile_work_unavailable")?;
        let slack = slack
            .as_deref_mut()
            .ok_or("mobile_work_channel_unconfigured")?;
        if !slack.channel_labels().contains(&binding.channel) {
            return Err("mobile_work_channel_unconfigured");
        }
        let text = slack
            .recent_messages(&channel)
            .map_err(|_| "mobile_work_channel_unavailable")?;
        return Ok(json!({"schema":schema,"channel":binding.display_name,"text":text}));
    }
    let client = FleetConfig::load(&integration.state_dir)
        .map_err(|_| "mobile_work_unavailable")?
        .ok_or("mobile_work_unavailable")?
        .into_action_client();
    match request {
        WorkRequest::Snapshot {} => {
            let queue = accepted(client.ticket_queue())?;
            let items: Vec<Value> = queue.items.iter().map(|row| json!({
                "job_id":row.job_id,"source_key":row.source_key,"issue_url":row.issue_url,
                "issue_title":row.issue_title,"job_status":row.job_status.as_str(),"updated_at":row.updated_at
            })).collect();
            Ok(json!({"schema":schema,"items":items,"has_more":queue.has_more}))
        }
        WorkRequest::Dispatch {
            ref issue_url,
            ref idempotency_key,
        } => {
            let scoped = key(auth, idempotency_key)?;
            let dispatch = TicketDispatchRequest::new(issue_url, &scoped).map_err(|_| INVALID)?;
            bind(integration, auth, &scoped, &request)?;
            // The unconfirmed constructor always creates/reuses a pending gate.
            let row = accepted(client.dispatch_ticket(&dispatch))?;
            Ok(
                json!({"schema":schema,"job_id":row.job_id,"job_status":row.job_status.as_str(),"duplicate":row.duplicate}),
            )
        }
        WorkRequest::Decide {
            ref job_id,
            ref source_key,
            ref idempotency_key,
            ref decision,
            ref reason,
        } => {
            let scoped = key(auth, idempotency_key)?;
            let typed = match decision.as_str() {
                "approve" if reason.is_empty() => TicketDecision::Approve,
                "reject" => TicketDecision::reject(reason).map_err(|_| INVALID)?,
                _ => return Err(INVALID),
            };
            let actor = format!("mobile:{}", auth.credential_id);
            let decision = TicketDecisionRequest::new(job_id, source_key, &scoped, &actor, typed)
                .map_err(|_| INVALID)?;
            bind(integration, auth, &scoped, &request)?;
            let row = accepted(client.decide_ticket(&decision))?;
            if row.job_id != *job_id {
                return Err("mobile_work_outcome_unknown");
            }
            Ok(
                json!({"schema":schema,"job_id":row.job_id,"job_status":row.job_status.as_str(),"duplicate":row.duplicate}),
            )
        }
        WorkRequest::Channel {} => unreachable!(),
    }
}

fn bind(
    integration: &WebIntegration,
    auth: &MobileAuthorization,
    key: &str,
    request: &WorkRequest,
) -> Result<(), &'static str> {
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(request).map_err(|_| INVALID)?)
    );
    integration
        .mobile_auth
        .lock()
        .map_err(|_| "mobile_work_unavailable")?
        .bind_work_request(auth, key, &fingerprint, crate::now_ms_i64())
        .map_err(|_| INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn work_request_cannot_supply_actor_instance_or_channel_overrides() {
        for body in [
            r#"{"action":"channel","channel":"private"}"#,
            r#"{"action":"snapshot","instance":"foreign"}"#,
            r#"{"action":"decide","job_id":"job-a","source_key":"slack:fixture","idempotency_key":"k","decision":"approve","reason":"","actor":"admin"}"#,
        ] {
            assert!(serde_json::from_str::<WorkRequest>(body).is_err());
        }
    }
}
