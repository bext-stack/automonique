// SPDX-License-Identifier: Elastic-2.0
use super::*;
use serde_json::json;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ConversationAction {
    Select {
        id: String,
        expected_conversation: String,
    },
    Older {
        id: String,
        before: i64,
    },
}
impl WebIntegration {
    pub(super) fn dashboard_conversation_id(&self) -> Result<Option<String>, &'static str> {
        AgentMemoryStore::open(&self.memory_path)
            .map_err(|_| "memory_unavailable")?
            .current_conversation(&self.config.tenant, &self.config.actor, "web", "dashboard")
            .map_err(|_| "memory_unavailable")
    }
    pub(super) fn check_chat_selection(&self, expected: &str) -> Result<(), &'static str> {
        if self.dashboard_conversation_id()?.as_deref().unwrap_or("") != expected {
            return Err("chat_conversation_changed");
        }
        Ok(())
    }
    pub(super) fn chat_conversations(&self) -> Result<Value, &'static str> {
        let store = AgentMemoryStore::open(&self.memory_path).map_err(|_| "memory_unavailable")?;
        let items = store
            .scoped_conversations(
                &self.config.tenant,
                &self.config.actor,
                "web",
                "dashboard",
                now_ms_i64(),
            )
            .map_err(|_| "memory_unavailable")?;
        Ok(
            json!({"current_id":self.dashboard_conversation_id()?,"limit":100,"items":items.into_iter().map(|(id,title,updated_at_ms)|json!({"id":id,"title":automonique_store::agent_memory::redact_content(&title),"updated_at_ms":updated_at_ms})).collect::<Vec<_>>()}),
        )
    }
    pub(super) fn chat_conversation_action(
        &self,
        action: ConversationAction,
    ) -> Result<Value, &'static str> {
        match action {
            ConversationAction::Select {
                id,
                expected_conversation,
            } => {
                let _guard = self
                    .dashboard_chat
                    .try_lock()
                    .map_err(|_| "chat_lane_busy")?;
                self.check_chat_selection(&expected_conversation)?;
                let mut store =
                    AgentMemoryStore::open(&self.memory_path).map_err(|_| "memory_unavailable")?;
                store
                    .resume_conversation(
                        &self.config.tenant,
                        &self.config.actor,
                        "web",
                        "dashboard",
                        &id,
                    )
                    .map_err(|_| "chat_conversation_unavailable")?;
                serde_json::to_value(self.chat_history()?).map_err(|_| "memory_unavailable")
            }
            ConversationAction::Older { id, before } => {
                let store =
                    AgentMemoryStore::open(&self.memory_path).map_err(|_| "memory_unavailable")?;
                let messages = store
                    .scoped_messages_before(
                        &self.config.tenant,
                        &self.config.actor,
                        "web",
                        "dashboard",
                        &id,
                        before,
                        now_ms_i64(),
                    )
                    .map_err(|_| "chat_conversation_unavailable")?;
                Ok(
                    json!({"conversation_id":id,"has_more":messages.len()==32,"messages":messages.into_iter().map(|m|json!({"id":m.id,"role":m.role,"content":m.content,"created_at_ms":m.created_at_ms})).collect::<Vec<_>>()}),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn conversation_selection_refuses_stale_clients_and_busy_turns() {
        let state = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let integration = WebIntegration::open(
            IntegrationConfig {
                tenant: "test".into(),
                actor: "reader".into(),
                hosts: DashboardHosts::new("chat.example.invalid", "legacy.example.invalid")
                    .unwrap(),
            },
            state.path(),
            runtime.path(),
        )
        .unwrap();
        let mut store = AgentMemoryStore::open(&integration.memory_path).unwrap();
        store
            .start_conversation("test", "reader", "web", "dashboard", "first", 1)
            .unwrap();
        store
            .start_conversation("test", "reader", "web", "dashboard", "second", 2)
            .unwrap();
        let action = || ConversationAction::Select {
            id: "first".into(),
            expected_conversation: "second".into(),
        };
        assert_eq!(
            integration.chat_conversation_action(ConversationAction::Select {
                id: "first".into(),
                expected_conversation: "stale".into()
            }),
            Err("chat_conversation_changed")
        );
        {
            let _busy = integration.dashboard_chat.lock().unwrap();
            assert_eq!(
                integration.chat_conversation_action(action()),
                Err("chat_lane_busy")
            );
        }
        assert_eq!(
            integration.dashboard_conversation_id().unwrap().as_deref(),
            Some("second")
        );
        let history = integration.chat_conversation_action(action()).unwrap();
        assert_eq!(history["conversation_id"], "first");
        assert_eq!(
            integration.check_chat_selection("second"),
            Err("chat_conversation_changed")
        );
        assert_eq!(
            integration.chat_conversation_action(ConversationAction::Select {
                id: "foreign".into(),
                expected_conversation: "first".into()
            }),
            Err("chat_conversation_unavailable")
        );
        assert_eq!(
            integration.dashboard_conversation_id().unwrap().as_deref(),
            Some("first")
        );
    }
    #[test]
    fn conversation_actions_do_not_accept_other_scopes_or_arbitrary_fields() {
        assert!(serde_json::from_str::<ConversationAction>(r#"{"action":"select","id":"first","expected_conversation":"second","actor":"someone_else"}"#).is_err());
        assert!(
            serde_json::from_str::<ConversationAction>(
                r#"{"action":"older","id":"first","before":1,"transport":"slack"}"#
            )
            .is_err()
        );
    }
}
