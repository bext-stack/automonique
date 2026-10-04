// SPDX-License-Identifier: Elastic-2.0

use super::*;
use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::*;
use automonique_store::agent_memory::redact_content;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::json;

#[derive(Default)]
pub(super) struct Controls {
    backup_checks: Arc<Mutex<BTreeMap<String, Value>>>,
    discovery: Mutex<()>,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    VerifyBackup {
        id: String,
    },
    ListAutomations {
        cursor: u64,
    },
    PreviewAutomation {
        id: String,
    },
    SetAutomation {
        id: String,
        revision: u64,
        paused: bool,
    },
    DiscoverMcp {
        server: String,
    },
    CheckRun {
        id: String,
    },
    RetrieveMemory {
        query: String,
    },
    FindDuplicates,
    ArchiveMemories {
        entries: Vec<MemorySelection>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemorySelection {
    reference: String,
    revision: u32,
}

impl WebIntegration {
    pub(super) fn controls_view(&self) -> Value {
        let mcp =
            McpRegistry::load(&self.state_dir).map(|registry| registry.configured_server_names());
        json!({"checked_at_ms":now_ms(), "backups": self.controls.backups(&self.state_dir),
            "automations":self.automation_list(0).unwrap_or_else(|reason| json!({"status":"unavailable","reason":reason,"items":[]})),
            "mcp":match mcp { Ok(names)=>json!({"status":"ready","servers":names}),Err(_)=>json!({"status":"unavailable","servers":[]}) }})
    }
    pub(super) fn control_action(&self, action: Action) -> Result<Value, &'static str> {
        match action {
            Action::VerifyBackup { id } => self.controls.verify_backup(&self.state_dir, &id),
            Action::ListAutomations { cursor } => self.automation_list(cursor),
            Action::PreviewAutomation { id } => {
                let response = self.automation_request(AutomationRequest::AutomationDetail {
                    request_id: self.control_request_id()?,
                    automation_id: AutomationId::new(id).map_err(|_| "invalid_request")?,
                })?;
                let AutomationResponse::AutomationDetail { record, prompt, .. } = response else {
                    return Err("automation_unavailable");
                };
                Ok(
                    json!({"id":record.automation_id().as_str(),"state":automation_state(record.enablement()),"schedule":record.schedule().map(|s|s.render()),"scope":record.scope().map(|s|s.as_str()),"prompt":prompt.map(|p|redact_content(p.as_str())),"next_run_at_ms":record.next_fire_at().map(|t|t.as_millis()),"checked_at_ms":now_ms(),"preview_only":true}),
                )
            }
            Action::SetAutomation {
                id,
                revision,
                paused,
            } => {
                let transition = SetEnablement::new(
                    AutomationId::new(id).map_err(|_| "invalid_request")?,
                    revision,
                    if paused {
                        EnablementState::Paused
                    } else {
                        EnablementState::Enabled
                    },
                    AutomationActor::new(&self.config.actor).map_err(|_| "invalid_request")?,
                    if paused {
                        Some(PauseReason::new("dashboard_pause").map_err(|_| "invalid_request")?)
                    } else {
                        None
                    },
                )
                .map_err(|_| "invalid_request")?;
                match self.automation_request(AutomationRequest::SetEnablement {
                    request_id: self.control_request_id()?,
                    transition,
                })? {
                    AutomationResponse::Accepted { .. } => {
                        Ok(json!({"ok":true,"checked_at_ms":now_ms()}))
                    }
                    AutomationResponse::Conflict { .. } => Err("automation_revision_stale"),
                    _ => Err("automation_unavailable"),
                }
            }
            Action::DiscoverMcp { server } => {
                let _guard = self
                    .controls
                    .discovery
                    .try_lock()
                    .map_err(|_| "connection_test_busy")?;
                let mut registry =
                    McpRegistry::load(&self.state_dir).map_err(|_| "invalid_configuration")?;
                if !registry.has_server(&server) {
                    return Err("invalid_request");
                }
                let started = Instant::now();
                match registry.discover_server(&server) {
                    Ok(tools) => {
                        let mut connection = Value::Null;
                        let mut status = "verified";
                        let mut probe = "catalog";
                        if tools
                            .iter()
                            .any(|tool| tool.name == "app_connection_info" && tool.read_only)
                        {
                            probe = "app";
                            match registry.call(&server, "app_connection_info", json!({}), None) {
                                Ok(McpCallResult::Complete {
                                    value,
                                    is_error: false,
                                }) => {
                                    connection = app_connection_view(&value);
                                    if connection.is_null() {
                                        status = "failed";
                                    }
                                }
                                _ => status = "failed",
                            }
                        }
                        Ok(
                            json!({"server":server,"status":status,"probe":probe,"connection":connection,"checked_at_ms":now_ms(),"duration_ms":started.elapsed().as_millis() as u64,"reason":if status == "failed" {Some("service_unavailable")} else {None},"tools":tools.iter().map(|tool|json!({"name":tool.name,"description":redact_content(&tool.description),"read_only":tool.read_only})).collect::<Vec<_>>()}),
                        )
                    }
                    Err(error) => Ok(
                        json!({"server":server,"status":"failed","checked_at_ms":now_ms(),"reason":match error {automonique_daemon::mcp_client::McpFailure::NotAllowed=>"access_refused",automonique_daemon::mcp_client::McpFailure::Protocol=>"invalid_response",_=>"service_unavailable"},"tools":[]}),
                    ),
                }
            }
            Action::CheckRun { id } => self.check_run(&id),
            Action::RetrieveMemory { query } => {
                if query.trim().is_empty() || query.len() > 512 {
                    return Err("invalid_request");
                }
                let store =
                    AgentMemoryStore::open(&self.memory_path).map_err(memory_error_category)?;
                // Identical tenant, actor, search and limit to dashboard chat.
                let entries = store
                    .search(
                        &self.config.tenant,
                        &self.config.actor,
                        &query,
                        now_ms_i64(),
                        6,
                    )
                    .map_err(memory_error_category)?;
                Ok(
                    json!({"checked_at_ms":now_ms(),"entries":entries.into_iter().map(memory_entry).collect::<Vec<_>>(),"limit":6}),
                )
            }
            Action::FindDuplicates => {
                let store =
                    AgentMemoryStore::open(&self.memory_path).map_err(memory_error_category)?;
                let records = store
                    .active_for_actor(&self.config.tenant, &self.config.actor, now_ms_i64())
                    .map_err(memory_error_category)?;
                let truncated = records.len() >= 4096;
                let mut groups: BTreeMap<String, Vec<MemoryRecord>> = BTreeMap::new();
                for record in records {
                    let key = record
                        .content
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase();
                    groups.entry(key).or_default().push(record);
                }
                let truncated =
                    truncated || groups.values().filter(|items| items.len() > 1).count() > 100;
                let groups = groups
                    .into_values()
                    .filter(|items| items.len() > 1)
                    .take(100)
                    .map(|items| {
                        items
                            .into_iter()
                            .map(|record| {
                                let editable = record.actor == self.config.actor;
                                let mut entry = memory_entry(record);
                                entry.editable = editable;
                                entry
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                Ok(
                    json!({"groups":groups,"truncated":truncated,"checked_at_ms":now_ms(),"method":"same_text_ignoring_case_and_spacing"}),
                )
            }
            Action::ArchiveMemories { entries } => {
                let selected = entries
                    .into_iter()
                    .map(|e| {
                        Ok((
                            e.reference
                                .strip_prefix("M-")
                                .and_then(|id| id.parse::<i64>().ok())
                                .filter(|id| *id > 0)
                                .ok_or("invalid_request")?,
                            e.revision,
                        ))
                    })
                    .collect::<Result<Vec<_>, &str>>()?;
                let mut store =
                    AgentMemoryStore::open(&self.memory_path).map_err(memory_error_category)?;
                let archived = store
                    .archive_many(
                        &self.config.tenant,
                        &self.config.actor,
                        &selected,
                        now_ms_i64(),
                    )
                    .map_err(memory_error_category)?;
                Ok(json!({"archived":archived,"checked_at_ms":now_ms()}))
            }
        }
    }
    fn control_request_id(&self) -> Result<RequestId, &'static str> {
        RequestId::new(format!("dashboard-controls-{}", self.next_sequence()?))
            .map_err(|_| "invalid_request")
    }
    fn automation_request(
        &self,
        request: AutomationRequest,
    ) -> Result<AutomationResponse, &'static str> {
        automonique_cli::dashboard_automation_request(
            self.runtime_dir.parent().ok_or("automation_unavailable")?,
            &request,
        )
    }
    fn automation_list(&self, cursor: u64) -> Result<Value, &'static str> {
        let response = self.automation_request(AutomationRequest::ListAutomations {
            request_id: self.control_request_id()?,
            query: ListAutomations::new(
                AutomationStateFilter::any(),
                AutomationCursor::new(cursor),
                AutomationPageSize::MAX,
            ),
        })?;
        let AutomationResponse::AutomationList { page, .. } = response else {
            return Err("automation_unavailable");
        };
        let items=page.entries().iter().map(|r|json!({"id":r.automation_id().as_str(),"revision":r.revision(),"state":automation_state(r.enablement()),"schedule":r.schedule().map(|s|s.render()),"scope":r.scope().map(|s|s.as_str()),"next_run_at_ms":if r.enablement()==EnablementState::Enabled {r.next_fire_at().map(|t|t.as_millis())}else{None},"last_run_at_ms":r.last_fired_at().map(|t|t.as_millis()),"last_result":automation_last_result(&self.state_dir,r.automation_id().as_str())})).collect::<Vec<_>>();
        Ok(
            json!({"status":"ready","items":items,"next_cursor":page.continuation().cursor().map(|c|c.position()),"checked_at_ms":now_ms()}),
        )
    }
    fn check_run(&self, id: &str) -> Result<Value, &'static str> {
        let snapshot = self.processes();
        let job = snapshot
            .jobs
            .iter()
            .find(|j| j.id == id)
            .ok_or("run_not_found")?;
        let mut github = json!({"status":"unavailable"});
        if let Some(url) = &job.issue_url {
            if let Some(locator) = automonique_github_connector::IssueLocator::parse(url) {
                if let Ok(mut guard) = self.github.try_lock() {
                    if let Some(client) = guard.as_mut() {
                        if let Ok(issue) = client.issue_brief(&locator, 0) {
                            github = json!({"status":"verified","state":issue.state,"updated_at":issue.updated_at,"closed_at":issue.closed_at});
                        }
                    }
                }
            }
        }
        let fresh = matches!(snapshot.health.as_str(), "ready" | "degraded")
            && snapshot.observed_at_ms <= now_ms() + 5000;
        let issue_conflict = github.get("state").and_then(Value::as_str) == Some("closed")
            && matches!(
                job.status.as_str(),
                "pending" | "running" | "pending_approval"
            );
        let worker_conflict = fresh
            && job.assigned_to_worker
            && job.status == "running"
            && snapshot.worker.as_ref().is_some_and(|w| w.active_jobs == 0);
        Ok(
            json!({"checked_at_ms":now_ms(),"manage":{"status":job.status,"observed_at_ms":snapshot.observed_at_ms,"fresh":fresh,"last_activity":job.updated_at},"github":github,"disagreement":issue_conflict || worker_conflict,"issue_conflict":issue_conflict,"worker_conflict":worker_conflict,"worker":{"assigned":job.assigned_to_worker,"status":snapshot.worker.as_ref().map(|w|w.status.as_str()),"active_jobs":snapshot.worker.as_ref().map(|w|w.active_jobs),"snapshot_health":snapshot.health}}),
        )
    }
}

fn automation_state(state: EnablementState) -> &'static str {
    match state {
        EnablementState::Enabled => "enabled",
        EnablementState::Paused => "paused",
        EnablementState::Archived => "archived",
    }
}
fn automation_last_result(state: &Path, id: &str) -> String {
    let read = || -> Result<Option<String>, rusqlite::Error> {
        let db = Connection::open_with_flags(
            state.join(automonique_daemon::DATABASE_NAME),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(Duration::from_secs(1))?;
        let prefix = format!("automation:{id}:");
        db.query_row("SELECT state FROM inbox WHERE transport='local.synthetic' AND substr(transport_key,1,length(?1))=?1 ORDER BY received_ms DESC,inbox_id DESC LIMIT 1",params![prefix],|row|row.get(0)).optional()
    };
    match read() {
        Ok(Some(state))
            if ["pending", "claimed", "completed", "failed"].contains(&state.as_str()) =>
        {
            state
        }
        Ok(None) => "never_run".into(),
        _ => "unavailable".into(),
    }
}

fn safe_backup_id(id: &str) -> bool {
    id.starts_with("recovery-")
        && id.len() <= 120
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn backup_rows(state: &Path) -> Vec<Value> {
    let root = state.join("backups");
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut candidates = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| e.file_name().to_str().is_some_and(safe_backup_id))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|entry| {
        std::cmp::Reverse(
            entry
                .file_name()
                .to_str()
                .and_then(|id| id.split('-').nth(1))
                .and_then(|time| time.parse::<u64>().ok())
                .unwrap_or(0),
        )
    });
    let mut rows=candidates.into_iter().filter_map(|entry|{
        let id=entry.file_name().to_str()?.to_owned();
        let path=entry.path().join(automonique_backup::MANIFEST_NAME);
        let metadata=fs::symlink_metadata(&path).ok()?;
        if !metadata.file_type().is_file() || metadata.len()>4*1024*1024{return None;}
        let manifest:automonique_backup::RecoveryManifest=serde_json::from_slice(&fs::read(path).ok()?).ok()?;
        if manifest.schema!=automonique_backup::MANIFEST_SCHEMA{return None;}
        Some(json!({"id":id,"created_at_ms":manifest.snapshot_completed_unix_ms,"databases":manifest.database_count,"bytes":manifest.components.iter().fold(0u64,|total,c|total.saturating_add(c.size_bytes))}))
    }).take(20).collect::<Vec<_>>();
    rows.sort_by_key(|row| std::cmp::Reverse(row["created_at_ms"].as_u64().unwrap_or(0)));
    rows.truncate(20);
    rows
}
impl Controls {
    fn backups(&self, state: &Path) -> Value {
        let mut rows = backup_rows(state);
        if let Ok(checks) = self.backup_checks.lock() {
            for row in &mut rows {
                row["verification"] = checks
                    .get(row["id"].as_str().unwrap_or(""))
                    .cloned()
                    .unwrap_or(json!({"status":"not_checked"}));
            }
        }
        let timer = backup_timer();
        json!({"items":rows,"timer":timer,"checked_at_ms":now_ms()})
    }
    fn verify_backup(&self, state: &Path, id: &str) -> Result<Value, &'static str> {
        if !safe_backup_id(id) || !backup_rows(state).iter().any(|r| r["id"] == id) {
            return Err("backup_not_found");
        }
        let mut checks = self.backup_checks.lock().map_err(|_| "backup_busy")?;
        if checks.values().any(|v| v["status"] == "checking") {
            return Err("backup_busy");
        }
        checks.insert(
            id.to_owned(),
            json!({"status":"checking","started_at_ms":now_ms()}),
        );
        let path = state.join("backups").join(id);
        let id = id.to_owned();
        let cache = Arc::clone(&self.backup_checks);
        let failure_id = id.clone();
        let spawned=thread::Builder::new().name("backup-verification".into()).spawn(move||{
            let result=automonique_backup::verify(&path);
            let value=match result {Ok(_)=>json!({"status":"verified","checked_at_ms":now_ms()}),Err(error)=>json!({"status":"failed","reason":error.category(),"checked_at_ms":now_ms()})};
            if let Ok(mut checks)=cache.lock(){checks.insert(id,value);}
        });
        if spawned.is_err() {
            checks.remove(&failure_id);
            return Err("backup_unavailable");
        }
        Ok(json!({"status":"checking"}))
    }
}
fn backup_timer() -> Value {
    let mut cmd = std::process::Command::new("/usr/bin/systemctl");
    cmd.args([
        "--user",
        "show",
        "automonique-backup.timer",
        "--property=LoadState,ActiveState,NextElapseUSecRealtime,NextElapseUSecMonotonic",
    ]);
    let Some(call) = crate::agent_auth::bounded_provider_call(&mut cmd, Duration::from_secs(2))
    else {
        return json!({"status":"unavailable"});
    };
    if !call.success {
        return json!({"status":"unavailable"});
    }
    let text = String::from_utf8_lossy(&call.stdout);
    let fields = text
        .lines()
        .filter_map(|s| s.split_once('='))
        .collect::<BTreeMap<_, _>>();
    let active = fields.get("ActiveState") == Some(&"active");
    let next_run_at_ms = if active {
        let mut list = std::process::Command::new("/usr/bin/systemctl");
        list.args([
            "--user",
            "list-timers",
            "automonique-backup.timer",
            "--all",
            "--output=json",
        ]);
        crate::agent_auth::bounded_provider_call(&mut list, Duration::from_secs(2))
            .filter(|call| call.success)
            .and_then(|call| serde_json::from_slice::<Value>(&call.stdout).ok())
            .and_then(|value| {
                value
                    .as_array()
                    .and_then(|rows| rows.first())
                    .and_then(|row| row.get("next"))
                    .and_then(Value::as_u64)
            })
            .filter(|value| *value > 0 && *value < u64::MAX)
            .map(|value| value / 1000)
    } else {
        None
    };
    json!({"status":if fields.get("LoadState")==Some(&"not-found"){"not_configured"}else if active{"active"}else{"inactive"},"next_run_at_ms":next_run_at_ms,"next_run":fields.get("NextElapseUSecRealtime").filter(|s|!s.is_empty()).copied()})
}

// Project only the public connection contract, never a remote server's raw config.
fn app_connection_view(value: &Value) -> Value {
    let Some(tenant) = value
        .get("tenant_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 160)
    else {
        return Value::Null;
    };
    let labels = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .take(100)
                    .map(|s| redact_content(&s.chars().take(160).collect::<String>()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let usage = value.get("usage").unwrap_or(&Value::Null);
    json!({"tenant_id":redact_content(tenant),"tenants":labels("authorized_tenants"),"resources":labels("resources"),"scopes":labels("scopes"),"expires_at":value.get("expires_at").and_then(Value::as_str).filter(|s|s.len()<=40),"calls":usage.get("calls").and_then(Value::as_u64),"errors":usage.get("errors").and_then(Value::as_u64)})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn app_probe_projects_only_safe_contract_fields() {
        let output = app_connection_view(
            &json!({"tenant_id":"sample","authorized_tenants":["sample"],"scopes":["read"],"resources":["project"],"token":"never expose","usage":{"calls":12,"errors":1,"recent":[{"token":"hidden"}]}}),
        );
        assert_eq!(output["calls"], 12);
        assert!(output.get("token").is_none());
        assert!(output.get("recent").is_none());
        assert!(app_connection_view(&json!({"status":"ok"})).is_null());
    }

    #[test]
    fn control_requests_do_not_accept_paths_tools_or_extra_authority() {
        for body in [
            r#"{"action":"verify_backup","id":"ok","path":"/etc"}"#,
            r#"{"action":"discover_mcp","server":"test","tool":"send_message"}"#,
            r#"{"action":"set_automation","id":"a","revision":1,"paused":true,"actor":"other"}"#,
        ] {
            assert!(serde_json::from_str::<Action>(body).is_err());
        }
        for id in [
            "../recovery-test",
            "recovery-../file",
            "/recovery-x",
            "recovery-x/path",
        ] {
            assert!(!safe_backup_id(id));
        }
    }
    #[test]
    fn backup_verification_detects_tampering_and_refuses_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let db = Connection::open(state.path().join("fixture.sqlite3")).unwrap();
        db.execute_batch(
            "CREATE TABLE evidence(value TEXT); INSERT INTO evidence VALUES ('kept');",
        )
        .unwrap();
        drop(db);
        let set = automonique_backup::create(state.path(), &state.path().join("backups")).unwrap();
        assert!(automonique_backup::verify(&set).is_ok());
        let rows = backup_rows(state.path());
        assert_eq!(rows.len(), 1);
        symlink(&set, state.path().join("backups/recovery-link")).unwrap();
        assert_eq!(backup_rows(state.path()).len(), 1);
        let manifest: automonique_backup::RecoveryManifest =
            serde_json::from_slice(&fs::read(set.join("manifest.json")).unwrap()).unwrap();
        fs::write(set.join(&manifest.components[0].path), b"corrupt").unwrap();
        assert!(automonique_backup::verify(&set).is_err());
        let controls = Controls::default();
        assert!(
            controls
                .verify_backup(state.path(), "../fixture.sqlite3")
                .is_err()
        );
    }
    #[test]
    fn automation_last_result_is_not_inferred_from_schedule() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(
            automation_last_result(state.path(), "sample"),
            "unavailable"
        );
        let db = Connection::open(state.path().join(automonique_daemon::DATABASE_NAME)).unwrap();
        db.execute_batch("CREATE TABLE inbox(inbox_id INTEGER, transport TEXT, transport_key TEXT, received_ms INTEGER, state TEXT); INSERT INTO inbox VALUES(1,'local.synthetic','automation:sample:1000',1000,'failed'); INSERT INTO inbox VALUES(2,'local.synthetic','automation:sample-other:2000',2000,'completed');").unwrap();
        assert_eq!(automation_last_result(state.path(), "sample"), "failed");
        assert_eq!(automation_last_result(state.path(), "missing"), "never_run");
    }
}
