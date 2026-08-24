// SPDX-License-Identifier: Elastic-2.0

//! Stable Agent Client Protocol v1 termination for Automonique.
//!
//! This crate owns only the ACP wire projection. Implementations of
//! [`Authority`] remain responsible for resolving sessions, turns, approvals,
//! cancellation, and workspace scope through Automonique's canonical domain.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    AgentCapabilities, CancelNotification, ContentBlock, ContentChunk, Implementation,
    InitializeRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse,
    LoadSessionRequest, LoadSessionResponse, NewSessionRequest, NewSessionResponse,
    PermissionOption, PermissionOptionKind, PromptRequest, PromptResponse,
    RequestPermissionOutcome, RequestPermissionRequest, SelectedPermissionOutcome,
    SessionCapabilities, SessionId, SessionInfo, SessionListCapabilities, SessionNotification,
    SessionUpdate, StopReason, TextContent, ToolCall, ToolCallContent, ToolCallStatus,
    ToolCallUpdate, ToolCallUpdateFields,
};
use agent_client_protocol::{Agent, ConnectionTo, Stdio};

mod platform;
mod session_store;

pub use platform::{PlatformAuthority, PlatformAuthorityConfig};

/// Stable protocol revision implemented by this adapter.
pub const ACP_SDK_VERSION: &str = "2.0.0";
/// Adapter implementation name reported during initialization.
pub const IMPLEMENTATION_NAME: &str = "automonique";
/// Maximum text admitted from one ACP prompt after baseline resource links are rendered.
pub const MAX_PROMPT_BYTES: usize = automonique_protocol::platform::MAX_PLATFORM_PARAMETER_BYTES;

/// One durable Automonique session projected into ACP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: String,
    pub cwd: PathBuf,
    pub additional_directories: Vec<PathBuf>,
    pub title: Option<String>,
    pub updated_at: Option<String>,
}

/// One authoritative or bounded progress update emitted while a prompt runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptEvent {
    Message {
        text: String,
        message_id: Option<String>,
    },
    Thought {
        text: String,
        message_id: Option<String>,
    },
    ToolStarted {
        id: String,
        title: String,
    },
    ToolProgress {
        id: String,
        text: Option<String>,
    },
    ToolFinished {
        id: String,
        text: Option<String>,
        failed: bool,
    },
    ApprovalRequested {
        id: String,
        title: String,
        description: String,
    },
}

/// Terminal result of one canonical turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptOutcome {
    Completed,
    Cancelled,
    Refused,
    MaxTokens,
    MaxTurnRequests,
}

impl PromptOutcome {
    const fn stop_reason(self) -> StopReason {
        match self {
            Self::Completed => StopReason::EndTurn,
            Self::Cancelled => StopReason::Cancelled,
            Self::Refused => StopReason::Refusal,
            Self::MaxTokens => StopReason::MaxTokens,
            Self::MaxTurnRequests => StopReason::MaxTurnRequests,
        }
    }
}

/// Typed refusal from the canonical authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityError {
    category: &'static str,
}

impl AuthorityError {
    #[must_use]
    pub const fn new(category: &'static str) -> Self {
        Self { category }
    }

    #[must_use]
    pub const fn category(&self) -> &'static str {
        self.category
    }

    fn rpc(&self) -> agent_client_protocol::Error {
        agent_client_protocol::Error::internal_error().data(self.category)
    }
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.category)
    }
}

impl std::error::Error for AuthorityError {}

/// Canonical operations required by the stable ACP surface.
pub trait Authority: Send + Sync + 'static {
    fn new_session(
        &self,
        cwd: &Path,
        additional_directories: &[PathBuf],
    ) -> Result<Session, AuthorityError>;

    fn load_session(
        &self,
        id: &str,
        cwd: &Path,
        additional_directories: &[PathBuf],
    ) -> Result<Session, AuthorityError>;

    fn list_sessions(
        &self,
        cwd: Option<&Path>,
        cursor: Option<&str>,
    ) -> Result<(Vec<Session>, Option<String>), AuthorityError>;

    fn prompt(
        &self,
        session_id: &str,
        prompt: &str,
        emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
    ) -> Result<PromptOutcome, AuthorityError>;

    fn cancel(&self, session_id: &str) -> Result<(), AuthorityError>;

    fn decide_approval(&self, approval_id: &str, allowed: bool) -> Result<(), AuthorityError>;
}

/// Serve stable ACP v1 over newline-framed JSON-RPC stdio.
pub fn serve_stdio(authority: Arc<dyn Authority>) -> Result<(), agent_client_protocol::Error> {
    futures::executor::block_on(serve(authority, Stdio::new()))
}

/// Serve stable ACP v1 over an injected transport.
pub async fn serve(
    authority: Arc<dyn Authority>,
    transport: impl agent_client_protocol::ConnectTo<Agent>,
) -> Result<(), agent_client_protocol::Error> {
    let new_authority = Arc::clone(&authority);
    let load_authority = Arc::clone(&authority);
    let list_authority = Arc::clone(&authority);
    let prompt_authority = Arc::clone(&authority);
    let cancel_authority = authority;

    Agent
        .builder()
        .name(IMPLEMENTATION_NAME)
        .on_receive_request(
            async move |request: InitializeRequest, responder, _connection| {
                let capabilities = AgentCapabilities::new()
                    .load_session(true)
                    .session_capabilities(
                        SessionCapabilities::new().list(SessionListCapabilities::new()),
                    );
                responder.respond(
                    InitializeResponse::new(negotiated_version(request.protocol_version))
                        .agent_capabilities(capabilities)
                        .agent_info(Implementation::new(
                            IMPLEMENTATION_NAME,
                            env!("CARGO_PKG_VERSION"),
                        )),
                )
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: NewSessionRequest, responder, _connection| {
                if !request.mcp_servers.is_empty() {
                    return Err(invalid_params("mcp_servers_not_supported"));
                }
                validate_session_paths(&request.cwd, &request.additional_directories)?;
                let authority = Arc::clone(&new_authority);
                let cwd = request.cwd;
                let additional = request.additional_directories;
                let session = blocking::unblock(move || authority.new_session(&cwd, &additional))
                    .await
                    .map_err(|error| error.rpc())?;
                responder.respond(NewSessionResponse::new(session.id))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: LoadSessionRequest, responder, _connection| {
                if !request.mcp_servers.is_empty() {
                    return Err(invalid_params("mcp_servers_not_supported"));
                }
                validate_session_paths(&request.cwd, &request.additional_directories)?;
                let authority = Arc::clone(&load_authority);
                let id = request.session_id.to_string();
                let cwd = request.cwd;
                let additional = request.additional_directories;
                blocking::unblock(move || authority.load_session(&id, &cwd, &additional))
                    .await
                    .map_err(|error| error.rpc())?;
                responder.respond(LoadSessionResponse::new())
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: ListSessionsRequest, responder, _connection| {
                if request.cwd.as_ref().is_some_and(|path| !path.is_absolute()) {
                    return Err(invalid_params("cwd_must_be_absolute"));
                }
                let authority = Arc::clone(&list_authority);
                let cwd = request.cwd;
                let cursor = request.cursor;
                let (sessions, next) = blocking::unblock(move || {
                    authority.list_sessions(cwd.as_deref(), cursor.as_deref())
                })
                .await
                .map_err(|error| error.rpc())?;
                let sessions = sessions.into_iter().map(session_info).collect::<Vec<_>>();
                responder.respond(ListSessionsResponse::new(sessions).next_cursor(next))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |request: PromptRequest, responder, connection| {
                let prompt = prompt_text(&request.prompt)?;
                let session_id = request.session_id.to_string();
                let notification_id = request.session_id;
                let authority = Arc::clone(&prompt_authority);
                let outcome = blocking::unblock(move || {
                    let mut emit = |event| {
                        emit_event(&connection, &notification_id, authority.as_ref(), event)
                    };
                    authority.prompt(&session_id, &prompt, &mut emit)
                })
                .await
                .map_err(|error| error.rpc())?;
                responder.respond(PromptResponse::new(outcome.stop_reason()))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_notification(
            async move |notification: CancelNotification, _connection| {
                let authority = Arc::clone(&cancel_authority);
                let id = notification.session_id.to_string();
                blocking::unblock(move || authority.cancel(&id))
                    .await
                    .map_err(|error| error.rpc())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .connect_to(transport)
        .await
}

fn negotiated_version(client: ProtocolVersion) -> ProtocolVersion {
    if client == ProtocolVersion::V1 {
        client
    } else {
        ProtocolVersion::V1
    }
}

fn validate_session_paths(cwd: &Path, additional: &[PathBuf]) -> agent_client_protocol::Result<()> {
    if !cwd.is_absolute() {
        return Err(invalid_params("cwd_must_be_absolute"));
    }
    if !additional.is_empty() {
        return Err(invalid_params("additional_directories_not_supported"));
    }
    Ok(())
}

fn invalid_params(category: &'static str) -> agent_client_protocol::Error {
    agent_client_protocol::Error::invalid_params().data(category)
}

fn prompt_text(blocks: &[ContentBlock]) -> agent_client_protocol::Result<String> {
    let mut output = String::new();
    for block in blocks {
        let part = match block {
            ContentBlock::Text(text) => text.text.as_str(),
            ContentBlock::ResourceLink(link) => link.uri.as_str(),
            ContentBlock::Image(_) | ContentBlock::Audio(_) | ContentBlock::Resource(_) => {
                return Err(invalid_params("prompt_content_not_advertised"));
            }
            _ => return Err(invalid_params("prompt_content_unknown")),
        };
        if !output.is_empty() {
            output.push('\n');
        }
        if output.len().saturating_add(part.len()) > MAX_PROMPT_BYTES {
            return Err(invalid_params("prompt_too_large"));
        }
        output.push_str(part);
    }
    if output.trim().is_empty() {
        return Err(invalid_params("prompt_empty"));
    }
    Ok(output)
}

fn emit_event(
    connection: &ConnectionTo<agent_client_protocol::Client>,
    session_id: &SessionId,
    authority: &dyn Authority,
    event: PromptEvent,
) -> Result<(), AuthorityError> {
    if let PromptEvent::ApprovalRequested {
        id,
        title,
        description,
    } = event
    {
        let request = RequestPermissionRequest::new(
            session_id.clone(),
            ToolCallUpdate::new(
                id.clone(),
                ToolCallUpdateFields::new()
                    .title(title)
                    .status(ToolCallStatus::Pending)
                    .content(vec![ToolCallContent::from(ContentBlock::Text(
                        TextContent::new(description),
                    ))]),
            ),
            vec![
                PermissionOption::new("allow_once", "Allow once", PermissionOptionKind::AllowOnce),
                PermissionOption::new("reject_once", "Reject", PermissionOptionKind::RejectOnce),
            ],
        );
        let response = futures::executor::block_on(connection.send_request(request).block_task())
            .map_err(|_| AuthorityError::new("acp_permission_disconnected"))?;
        let allowed = matches!(
            response.outcome,
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome { option_id, .. })
                if option_id.0.as_ref() == "allow_once"
        );
        return authority.decide_approval(&id, allowed);
    }
    let update = match event {
        PromptEvent::Message { text, message_id } => {
            SessionUpdate::AgentMessageChunk(content_chunk(text, message_id))
        }
        PromptEvent::Thought { text, message_id } => {
            SessionUpdate::AgentThoughtChunk(content_chunk(text, message_id))
        }
        PromptEvent::ToolStarted { id, title } => {
            SessionUpdate::ToolCall(ToolCall::new(id, title).status(ToolCallStatus::InProgress))
        }
        PromptEvent::ToolProgress { id, text } => {
            SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                id,
                ToolCallUpdateFields::new()
                    .status(ToolCallStatus::InProgress)
                    .content(text.map(|text| {
                        vec![ToolCallContent::from(ContentBlock::Text(TextContent::new(
                            text,
                        )))]
                    })),
            ))
        }
        PromptEvent::ToolFinished { id, text, failed } => {
            SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(
                id,
                ToolCallUpdateFields::new()
                    .status(if failed {
                        ToolCallStatus::Failed
                    } else {
                        ToolCallStatus::Completed
                    })
                    .content(text.map(|text| {
                        vec![ToolCallContent::from(ContentBlock::Text(TextContent::new(
                            text,
                        )))]
                    })),
            ))
        }
        PromptEvent::ApprovalRequested { .. } => unreachable!("handled above"),
    };
    connection
        .send_notification(SessionNotification::new(session_id.clone(), update))
        .map_err(|_| AuthorityError::new("acp_client_disconnected"))
}

fn content_chunk(text: String, message_id: Option<String>) -> ContentChunk {
    ContentChunk::new(ContentBlock::Text(TextContent::new(text)))
        .message_id(message_id.map(Into::into))
}

fn session_info(session: Session) -> SessionInfo {
    SessionInfo::new(session.id, session.cwd)
        .additional_directories(session.additional_directories)
        .title(session.title)
        .updated_at(session.updated_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use agent_client_protocol::schema::v1::{
        CancelNotification, InitializeRequest, ListSessionsRequest, NewSessionRequest,
        PromptRequest,
    };
    use agent_client_protocol::{Client, ConnectTo};

    #[derive(Default)]
    struct FakeAuthority {
        prompts: Mutex<Vec<String>>,
        cancellations: Mutex<Vec<String>>,
    }

    impl Authority for FakeAuthority {
        fn new_session(
            &self,
            cwd: &Path,
            _additional_directories: &[PathBuf],
        ) -> Result<Session, AuthorityError> {
            Ok(Session {
                id: "acp-00000000000000000000000000000000".into(),
                cwd: cwd.into(),
                additional_directories: Vec::new(),
                title: None,
                updated_at: None,
            })
        }

        fn load_session(
            &self,
            id: &str,
            cwd: &Path,
            additional_directories: &[PathBuf],
        ) -> Result<Session, AuthorityError> {
            let mut session = self.new_session(cwd, additional_directories)?;
            session.id = id.into();
            Ok(session)
        }

        fn list_sessions(
            &self,
            _cwd: Option<&Path>,
            _cursor: Option<&str>,
        ) -> Result<(Vec<Session>, Option<String>), AuthorityError> {
            Ok((Vec::new(), None))
        }

        fn prompt(
            &self,
            session_id: &str,
            prompt: &str,
            emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
        ) -> Result<PromptOutcome, AuthorityError> {
            self.prompts
                .lock()
                .expect("prompt lock")
                .push(format!("{session_id}:{prompt}"));
            emit(PromptEvent::Message {
                text: "done".into(),
                message_id: Some("message-1".into()),
            })?;
            Ok(PromptOutcome::Completed)
        }

        fn cancel(&self, session_id: &str) -> Result<(), AuthorityError> {
            self.cancellations
                .lock()
                .expect("cancel lock")
                .push(session_id.into());
            Ok(())
        }

        fn decide_approval(
            &self,
            _approval_id: &str,
            _allowed: bool,
        ) -> Result<(), AuthorityError> {
            Ok(())
        }
    }

    struct ConformanceClient {
        cwd: PathBuf,
        updates: Arc<Mutex<Vec<SessionUpdate>>>,
    }

    impl ConnectTo<Agent> for ConformanceClient {
        async fn connect_to(
            self,
            agent: impl ConnectTo<Client>,
        ) -> Result<(), agent_client_protocol::Error> {
            let updates = self.updates;
            let cwd = self.cwd;
            Client
                .builder()
                .on_receive_notification(
                    async move |notification: SessionNotification, _connection| {
                        updates
                            .lock()
                            .expect("updates lock")
                            .push(notification.update);
                        Ok(())
                    },
                    agent_client_protocol::on_receive_notification!(),
                )
                .connect_with(agent, async move |connection| {
                    let initialized = connection
                        .send_request(InitializeRequest::new(ProtocolVersion::V1))
                        .block_task()
                        .await?;
                    assert_eq!(initialized.protocol_version, ProtocolVersion::V1);
                    assert!(initialized.agent_capabilities.load_session);
                    let session_capabilities = initialized.agent_capabilities.session_capabilities;
                    assert!(session_capabilities.list.is_some());
                    assert!(session_capabilities.additional_directories.is_none());

                    let session = connection
                        .send_request(NewSessionRequest::new(cwd))
                        .block_task()
                        .await?;
                    let response = connection
                        .send_request(PromptRequest::new(
                            session.session_id.clone(),
                            vec![ContentBlock::Text(TextContent::new("hello"))],
                        ))
                        .block_task()
                        .await?;
                    assert_eq!(response.stop_reason, StopReason::EndTurn);
                    connection.send_notification(CancelNotification::new(session.session_id))?;
                    connection
                        .send_request(ListSessionsRequest::new())
                        .block_task()
                        .await?;
                    Ok(())
                })
                .await
        }
    }

    #[test]
    fn stable_v1_round_trip_negotiates_and_streams() {
        let workspace = tempfile::tempdir().expect("workspace");
        let authority = Arc::new(FakeAuthority::default());
        let updates = Arc::new(Mutex::new(Vec::new()));
        futures::executor::block_on(serve(
            authority.clone(),
            ConformanceClient {
                cwd: workspace.path().into(),
                updates: Arc::clone(&updates),
            },
        ))
        .expect("ACP round trip");

        assert_eq!(
            authority.prompts.lock().expect("prompt lock").as_slice(),
            ["acp-00000000000000000000000000000000:hello"]
        );
        assert_eq!(updates.lock().expect("updates lock").len(), 1);
        assert_eq!(
            authority
                .cancellations
                .lock()
                .expect("cancel lock")
                .as_slice(),
            ["acp-00000000000000000000000000000000"]
        );
    }

    #[test]
    fn baseline_prompt_accepts_text_and_resource_links_only() {
        let blocks = vec![
            ContentBlock::Text(TextContent::new("Inspect this")),
            ContentBlock::ResourceLink(agent_client_protocol::schema::v1::ResourceLink::new(
                "source",
                "file:///workspace/src/lib.rs",
            )),
        ];
        assert_eq!(
            prompt_text(&blocks).expect("baseline prompt"),
            "Inspect this\nfile:///workspace/src/lib.rs"
        );
    }

    #[test]
    fn unsupported_prompt_content_fails_closed() {
        let blocks = vec![ContentBlock::Image(
            agent_client_protocol::schema::v1::ImageContent::new("AA==", "image/png"),
        )];
        let error = prompt_text(&blocks).expect_err("image was not advertised");
        assert_eq!(error.data, Some("prompt_content_not_advertised".into()));
    }

    #[test]
    fn session_paths_must_be_absolute() {
        assert!(validate_session_paths(Path::new("relative"), &[]).is_err());
        assert!(validate_session_paths(Path::new("/workspace"), &[]).is_ok());
        assert!(
            validate_session_paths(Path::new("/workspace"), &[PathBuf::from("/other")]).is_err()
        );
    }
}
