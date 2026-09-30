// SPDX-License-Identifier: Elastic-2.0

//! Operator task submission over the existing durable, contained execution lane.
//! Preparation discovers only the active node. Reconciliation never submits work.

use automonique_daemon::CURRENT_NODE_ALIAS;
use automonique_platform_client::{ActionResult, PlatformClient, UnixTransport};
use automonique_protocol::platform::{
    ActionReceipt, ExecuteRequest, FreshnessState, GetReceiptRequest, IdempotencyKey,
    PlatformAction, PlatformParameter, ReceiptOutcome, ResourceAuthority, ResourceCoordinate,
    ResourceId, ResourceKind,
};
use automonique_protocol::primitives::Revision;
use serde::Deserialize;
use serde_json::{Value, json};

const INVALID: &str = "platform_task_request_invalid";

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TaskRequest {
    Prepare {},
    Submit {
        node_id: String,
        expected_revision: String,
        idempotency_key: String,
        text: String,
    },
    Reconcile {
        node_id: String,
        idempotency_key: String,
    },
}

fn node(id: String) -> Result<ResourceCoordinate, &'static str> {
    if id == CURRENT_NODE_ALIAS {
        return Err(INVALID);
    }
    Ok(ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Node,
        ResourceId::new(id).map_err(|_| INVALID)?,
    ))
}

fn key(value: String) -> Result<IdempotencyKey, &'static str> {
    // Keep this surface's receipt lookups distinct from other operator work.
    if !value.starts_with("dashboard-task-") {
        return Err(INVALID);
    }
    IdempotencyKey::new(value).map_err(|_| INVALID)
}

fn ambiguous() -> Value {
    json!({"state":"ambiguous", "explanation":"Task outcome is uncertain. Check its receipt; do not resubmit."})
}

fn receipt_view(receipt: ActionReceipt, target: &ResourceCoordinate) -> Value {
    if receipt.action != PlatformAction::SubmitRequest || &receipt.target != target {
        return ambiguous();
    }
    let session = if receipt.outcome == ReceiptOutcome::Completed {
        receipt.explanation.as_ref().and_then(|text| {
            let (run, session) = text.as_str().split_once(";session=")?;
            ResourceId::new(run.strip_prefix("run=")?).ok()?;
            ResourceId::new(session).ok().map(|id| id.into_inner())
        })
    } else {
        None
    };
    json!({"state":"receipt", "receipt": super::platform_receipt_view(receipt), "session_id":session})
}

pub(crate) fn execute(
    client: &mut PlatformClient<UnixTransport>,
    request: TaskRequest,
) -> Result<Value, &'static str> {
    match request {
        TaskRequest::Prepare {} => {
            let current = ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Node,
                ResourceId::new(CURRENT_NODE_ALIAS).map_err(|_| INVALID)?,
            );
            let snapshot = client
                .snapshot(vec![current])
                .map_err(|_| "platform_unavailable")?;
            let mut nodes = snapshot.resources.into_iter().filter(|record| {
                record.resource.authority == ResourceAuthority::Automonique
                    && record.resource.kind == ResourceKind::Node
                    && record.resource.id.as_str() != CURRENT_NODE_ALIAS
                    && record.freshness.state == FreshnessState::Fresh
                    && record.summary.as_str() == "daemon ready"
            });
            let active = nodes.next().ok_or("platform_task_node_unavailable")?;
            if nodes.next().is_some() {
                return Err("platform_task_node_ambiguous");
            }
            Ok(
                json!({"state":"ready", "node_id":active.resource.id.as_str(), "expected_revision":active.freshness.revision.to_string()}),
            )
        }
        TaskRequest::Submit {
            node_id,
            expected_revision,
            idempotency_key,
            text,
        } => {
            let target = node(node_id)?;
            let revision = Revision::new(
                super::parse_platform_decimal(&expected_revision, false).map_err(|_| INVALID)?,
            )
            .map_err(|_| INVALID)?;
            if text.trim().is_empty() {
                return Err(INVALID);
            }
            let request = ExecuteRequest::new_with_parameter(
                PlatformAction::SubmitRequest,
                target.clone(),
                key(idempotency_key)?,
                Some(revision),
                Some(PlatformParameter::new(text).map_err(|_| INVALID)?),
            )
            .map_err(|_| INVALID)?;
            Ok(match client.execute_outcome(request) {
                Ok(ActionResult::Receipt(receipt)) => receipt_view(receipt, &target),
                Ok(ActionResult::Refused {
                    outcome,
                    explanation,
                }) => {
                    json!({"state":"refused", "outcome":outcome.as_str(), "explanation":explanation.as_str()})
                }
                Err(_) => ambiguous(),
            })
        }
        TaskRequest::Reconcile {
            node_id,
            idempotency_key,
        } => {
            let target = node(node_id)?;
            Ok(
                match client
                    .get_receipt(GetReceiptRequest::by_idempotency_key(key(idempotency_key)?))
                {
                    Ok(receipt) => receipt_view(receipt, &target),
                    Err(_) => ambiguous(),
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::platform::{
        CursorTopic, Freshness, PlatformCursor, PlatformRequest, PlatformResponse, PlatformText,
        ReceiptId, ResourceRecord, Snapshot,
    };
    use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
    use automonique_protocol::primitives::EpochMillis;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    fn receipt(target: ResourceCoordinate) -> ActionReceipt {
        ActionReceipt {
            id: ReceiptId::new("task-receipt").unwrap(),
            action: PlatformAction::SubmitRequest,
            target,
            outcome: ReceiptOutcome::Completed,
            revision: Revision::FIRST,
            recorded_at: EpochMillis::from_millis(1),
            explanation: Some(PlatformText::new("run=run-1;session=session-1").unwrap()),
        }
    }

    #[test]
    fn task_reconciles_lost_submission_without_another_execute() {
        const REVISION: u64 = 9_007_199_254_740_995;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let target = node("daemon-1".into()).unwrap();
            for index in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut length = [0; 4];
                stream.read_exact(&mut length).unwrap();
                let mut payload = vec![0; u32::from_be_bytes(length) as usize];
                stream.read_exact(&mut payload).unwrap();
                let message = PlatformRequestMessage::from_canonical_bytes(&payload).unwrap();
                let response = match (index, message.request()) {
                    (0, PlatformRequest::Snapshot(request)) => {
                        assert_eq!(request.resources.len(), 1);
                        assert_eq!(request.resources[0].id.as_str(), CURRENT_NODE_ALIAS);
                        PlatformResponse::Snapshot(
                            Snapshot::new(
                                vec![ResourceRecord {
                                    resource: target.clone(),
                                    freshness: Freshness {
                                        state: FreshnessState::Fresh,
                                        observed_at: EpochMillis::from_millis(1),
                                        revision: Revision::new(REVISION).unwrap(),
                                    },
                                    summary: PlatformText::new("daemon ready").unwrap(),
                                }],
                                PlatformCursor {
                                    authority: ResourceAuthority::Automonique,
                                    topic: CursorTopic::new("resources").unwrap(),
                                    sequence: Revision::FIRST,
                                },
                            )
                            .unwrap(),
                        )
                    }
                    (1, PlatformRequest::Execute(request)) => {
                        assert_eq!(request.action, PlatformAction::SubmitRequest);
                        assert_eq!(request.target, target);
                        assert_eq!(request.expected_revision.unwrap().get(), REVISION);
                        assert_eq!(request.idempotency_key.as_str(), "dashboard-task-test");
                        assert_eq!(
                            request.parameter.as_ref().unwrap().as_str(),
                            "write a script"
                        );
                        // The daemon took custody but the reply was lost.
                        continue;
                    }
                    (2, PlatformRequest::GetReceipt(request)) => {
                        assert_eq!(
                            request.idempotency_key.as_ref().unwrap().as_str(),
                            "dashboard-task-test"
                        );
                        PlatformResponse::Receipt(receipt(target.clone()))
                    }
                    _ => panic!("unexpected task operation"),
                };
                let bytes = PlatformResponseMessage::new(message.request_id().clone(), response)
                    .to_message()
                    .unwrap()
                    .to_canonical_bytes();
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let mut client = PlatformClient::new(UnixTransport::new(&socket));
        let ready = execute(&mut client, TaskRequest::Prepare {}).unwrap();
        assert_eq!(ready["expected_revision"], REVISION.to_string());
        let submitted = execute(
            &mut client,
            TaskRequest::Submit {
                node_id: "daemon-1".into(),
                expected_revision: REVISION.to_string(),
                idempotency_key: "dashboard-task-test".into(),
                text: "write a script".into(),
            },
        )
        .unwrap();
        assert_eq!(submitted["state"], "ambiguous");
        let settled = execute(
            &mut client,
            TaskRequest::Reconcile {
                node_id: "daemon-1".into(),
                idempotency_key: "dashboard-task-test".into(),
            },
        )
        .unwrap();
        assert_eq!(settled["receipt"]["outcome"], "completed");
        assert_eq!(settled["session_id"], "session-1");
        server.join().unwrap();
    }

    #[test]
    fn task_receipts_require_exact_action_and_original_node() {
        let target = node("daemon-1".into()).unwrap();
        let mut value = receipt(target.clone());
        value.action = PlatformAction::FollowUp;
        assert_eq!(receipt_view(value, &target)["state"], "ambiguous");
        assert_eq!(
            receipt_view(receipt(node("daemon-2".into()).unwrap()), &target)["state"],
            "ambiguous"
        );
        let mut value = receipt(target.clone());
        value.explanation = Some(PlatformText::new("unrelated;session=session-1").unwrap());
        assert!(receipt_view(value, &target)["session_id"].is_null());
    }

    #[test]
    fn task_rejects_invalid_fences_before_transport() {
        let mut client = PlatformClient::new(UnixTransport::new("/no-such-task-socket"));
        for (node_id, revision, key, text) in [
            (CURRENT_NODE_ALIAS, "1", "dashboard-task-test", "work"),
            ("daemon-1", "01", "dashboard-task-test", "work"),
            ("daemon-1", "0", "dashboard-task-test", "work"),
            ("daemon-1", "1", "another-surface", "work"),
            ("daemon-1", "1", "dashboard-task-test", "  "),
        ] {
            assert_eq!(
                execute(
                    &mut client,
                    TaskRequest::Submit {
                        node_id: node_id.into(),
                        expected_revision: revision.into(),
                        idempotency_key: key.into(),
                        text: text.into()
                    }
                )
                .unwrap_err(),
                INVALID
            );
        }
        assert!(
            serde_json::from_value::<TaskRequest>(json!({"action":"prepare", "path":"/tmp"}))
                .is_err()
        );
    }
}
