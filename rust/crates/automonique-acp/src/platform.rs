// SPDX-License-Identifier: Elastic-2.0

//! Production ACP authority over the canonical local Platform v1 socket.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use automonique_platform_client::{ActionResult, PlatformClient, UnixTransport};
use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, encode_frame};
use automonique_protocol::event::EventKind;
use automonique_protocol::platform::{
    ExecuteRequest, FreshnessState, GetReceiptRequest, IdempotencyKey, PlatformAction,
    PlatformParameter, PlatformText, ReceiptOutcome, ResourceAuthority, ResourceCoordinate,
    ResourceId, ResourceKind,
};
use automonique_protocol::progress_api::{
    MAX_PROGRESS_STREAM_CANONICAL_BYTES, StreamMessage, SubscribeRequest,
};
use automonique_protocol::tools::RunId;
use sha2::{Digest as _, Sha256};

use crate::session_store::{SessionStore, StoredSession};
use crate::{Authority, AuthorityError, PromptEvent, PromptOutcome, Session};

const IO_TIMEOUT: Duration = Duration::from_millis(250);
const TURN_DEADLINE: Duration = Duration::from_secs(21_600);

/// Paths required by the separately invokable ACP stdio adapter.
#[derive(Clone, Debug)]
pub struct PlatformAuthorityConfig {
    pub state_dir: PathBuf,
    pub platform_socket: PathBuf,
    pub progress_socket: PathBuf,
}

/// Canonical Platform v1 implementation of the ACP authority seam.
pub struct PlatformAuthority {
    config: PlatformAuthorityConfig,
    sessions: Mutex<SessionStore>,
    active: Mutex<BTreeMap<String, String>>,
}

impl PlatformAuthority {
    pub fn open(config: PlatformAuthorityConfig) -> Result<Self, AuthorityError> {
        if !config.state_dir.is_absolute()
            || !config.platform_socket.is_absolute()
            || !config.progress_socket.is_absolute()
        {
            return Err(AuthorityError::new("acp_path_not_absolute"));
        }
        let sessions = SessionStore::open(&config.state_dir)?;
        Ok(Self {
            config,
            sessions: Mutex::new(sessions),
            active: Mutex::new(BTreeMap::new()),
        })
    }

    fn platform(&self) -> PlatformClient<UnixTransport> {
        PlatformClient::new(UnixTransport::new(&self.config.platform_socket))
    }

    fn prompt_inner(
        &self,
        stored: &StoredSession,
        prompt: &str,
        emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
    ) -> Result<PromptOutcome, AuthorityError> {
        let key = turn_key(&stored.session.id, stored.turn_sequence);
        let run_id = deterministic_run_id(&key);
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| AuthorityError::new("acp_mapping_lock"))?;
            sessions.bind_turn(&stored.session.id, &run_id, None)?;
        }
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| AuthorityError::new("acp_active_lock"))?;
            if active.contains_key(&stored.session.id) {
                return Err(AuthorityError::new("acp_session_busy"));
            }
            active.insert(stored.session.id.clone(), run_id.clone());
        }

        let result = self.execute_turn(stored, prompt, &key, &run_id, emit);
        if let Ok(mut active) = self.active.lock() {
            active.remove(&stored.session.id);
        }
        result
    }

    fn execute_turn(
        &self,
        stored: &StoredSession,
        prompt: &str,
        key: &str,
        run_id: &str,
        emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
    ) -> Result<PromptOutcome, AuthorityError> {
        let mut progress = ProgressSubscription::open(&self.config.progress_socket, run_id)?;
        let mut platform = self.platform();
        let (action, target, revision) = match stored.provider_session_id.as_deref() {
            Some(provider_session) => {
                let sessions = platform
                    .list_sessions(ResourceAuthority::Automonique, None)
                    .map_err(|_| AuthorityError::new("acp_platform_sessions"))?;
                let record = sessions
                    .sessions
                    .into_iter()
                    .find(|record| {
                        record.session.resource.id.as_str() == provider_session && record.attachable
                    })
                    .ok_or(AuthorityError::new("acp_session_not_resumable"))?;
                (
                    PlatformAction::FollowUp,
                    record.session.resource,
                    Some(record.session.freshness.revision),
                )
            }
            None => {
                let snapshot = platform
                    .snapshot(Vec::new())
                    .map_err(|_| AuthorityError::new("acp_platform_snapshot"))?;
                let record = snapshot
                    .resources
                    .into_iter()
                    .find(|record| {
                        record.resource.authority == ResourceAuthority::Automonique
                            && record.resource.kind == ResourceKind::Node
                            && record.freshness.state == FreshnessState::Fresh
                    })
                    .ok_or(AuthorityError::new("acp_platform_node"))?;
                (
                    PlatformAction::SubmitRequest,
                    record.resource,
                    Some(record.freshness.revision),
                )
            }
        };
        let request = ExecuteRequest::new_with_parameter(
            action,
            target,
            IdempotencyKey::new(key).map_err(|_| AuthorityError::new("acp_idempotency_key"))?,
            revision,
            Some(
                PlatformParameter::new(prompt)
                    .map_err(|_| AuthorityError::new("acp_prompt_refused"))?,
            ),
        )
        .map_err(|_| AuthorityError::new("acp_execute_request"))?;
        let receipt = match platform
            .execute_outcome(request)
            .map_err(|_| AuthorityError::new("acp_platform_execute"))?
        {
            ActionResult::Receipt(receipt) => receipt,
            ActionResult::Refused { .. } => return Ok(PromptOutcome::Refused),
        };

        let mut projection = Projection::new(run_id);
        let deadline = Instant::now() + TURN_DEADLINE;
        let mut receipt = receipt;
        loop {
            if Instant::now() >= deadline {
                return Err(AuthorityError::new("acp_turn_deadline"));
            }
            match progress.next()? {
                Some(StreamMessage::Frame(frame)) => projection.frame(&frame, emit)?,
                Some(StreamMessage::Lagged { .. } | StreamMessage::ResyncRequired { .. }) => {
                    return Err(AuthorityError::new("acp_progress_resync_required"));
                }
                Some(StreamMessage::Refused { .. }) => {
                    return Err(AuthorityError::new("acp_progress_refused"));
                }
                Some(StreamMessage::Retired { .. }) | None => {}
                Some(StreamMessage::Greeting { .. } | StreamMessage::Live { .. }) => {
                    return Err(AuthorityError::new("acp_progress_protocol"));
                }
            }
            if receipt.outcome != ReceiptOutcome::Accepted {
                break;
            }
            receipt = platform
                .get_receipt(GetReceiptRequest::by_idempotency_key(
                    IdempotencyKey::new(key)
                        .map_err(|_| AuthorityError::new("acp_idempotency_key"))?,
                ))
                .map_err(|_| AuthorityError::new("acp_platform_receipt"))?;
        }

        let provider_session = receipt
            .explanation
            .as_ref()
            .and_then(|explanation| receipt_session(explanation.as_str()));
        self.sessions
            .lock()
            .map_err(|_| AuthorityError::new("acp_mapping_lock"))?
            .bind_turn(&stored.session.id, run_id, provider_session.as_deref())?;
        Ok(match receipt.outcome {
            ReceiptOutcome::Completed => PromptOutcome::Completed,
            ReceiptOutcome::Rejected => {
                if receipt
                    .explanation
                    .as_ref()
                    .is_some_and(|value| value.as_str().contains("cancel"))
                {
                    PromptOutcome::Cancelled
                } else {
                    PromptOutcome::Refused
                }
            }
            ReceiptOutcome::Conflict | ReceiptOutcome::Unknown | ReceiptOutcome::ResyncRequired => {
                PromptOutcome::Refused
            }
            ReceiptOutcome::Accepted => return Err(AuthorityError::new("acp_receipt_nonterminal")),
        })
    }
}

impl Authority for PlatformAuthority {
    fn new_session(
        &self,
        cwd: &Path,
        additional_directories: &[PathBuf],
    ) -> Result<Session, AuthorityError> {
        self.sessions
            .lock()
            .map_err(|_| AuthorityError::new("acp_mapping_lock"))?
            .create(cwd, additional_directories)
            .map(|stored| stored.session)
    }

    fn load_session(
        &self,
        id: &str,
        cwd: &Path,
        additional_directories: &[PathBuf],
    ) -> Result<Session, AuthorityError> {
        self.sessions
            .lock()
            .map_err(|_| AuthorityError::new("acp_mapping_lock"))?
            .load(id, cwd, additional_directories)
            .map(|stored| stored.session)
    }

    fn list_sessions(
        &self,
        cwd: Option<&Path>,
        cursor: Option<&str>,
    ) -> Result<(Vec<Session>, Option<String>), AuthorityError> {
        self.sessions
            .lock()
            .map_err(|_| AuthorityError::new("acp_mapping_lock"))?
            .list(cwd, cursor)
    }

    fn prompt(
        &self,
        session_id: &str,
        prompt: &str,
        emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
    ) -> Result<PromptOutcome, AuthorityError> {
        let stored = self
            .sessions
            .lock()
            .map_err(|_| AuthorityError::new("acp_mapping_lock"))?
            .reserve_turn(session_id)?;
        self.prompt_inner(&stored, prompt, emit)
    }

    fn cancel(&self, session_id: &str) -> Result<(), AuthorityError> {
        let run_id = self
            .active
            .lock()
            .map_err(|_| AuthorityError::new("acp_active_lock"))?
            .get(session_id)
            .cloned()
            .or_else(|| {
                self.sessions
                    .lock()
                    .ok()
                    .and_then(|store| store.get(session_id).ok().flatten())
                    .and_then(|stored| stored.current_run_id)
            })
            .ok_or(AuthorityError::new("acp_session_not_running"))?;
        let mut platform = self.platform();
        let target = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Run,
            automonique_protocol::platform::ResourceId::new(&run_id)
                .map_err(|_| AuthorityError::new("acp_run_id"))?,
        );
        let snapshot = platform
            .snapshot(vec![target.clone()])
            .map_err(|_| AuthorityError::new("acp_platform_snapshot"))?;
        let revision = snapshot
            .resources
            .into_iter()
            .find(|record| record.resource == target)
            .map(|record| record.freshness.revision)
            .ok_or(AuthorityError::new("acp_run_not_found"))?;
        let key = cancel_key(session_id, &run_id);
        let request = ExecuteRequest::new(
            PlatformAction::StopRun,
            target,
            IdempotencyKey::new(key).map_err(|_| AuthorityError::new("acp_cancel_key"))?,
            Some(revision),
            None,
        )
        .map_err(|_| AuthorityError::new("acp_cancel_request"))?;
        match platform
            .execute_outcome(request)
            .map_err(|_| AuthorityError::new("acp_platform_cancel"))?
        {
            ActionResult::Receipt(_) => Ok(()),
            ActionResult::Refused { .. } => Err(AuthorityError::new("acp_cancel_refused")),
        }
    }

    fn decide_approval(&self, approval_id: &str, allowed: bool) -> Result<(), AuthorityError> {
        let target = ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Approval,
            ResourceId::new(approval_id).map_err(|_| AuthorityError::new("acp_approval_id"))?,
        );
        let mut platform = self.platform();
        let snapshot = platform
            .snapshot(vec![target.clone()])
            .map_err(|_| AuthorityError::new("acp_platform_snapshot"))?;
        let revision = snapshot
            .resources
            .into_iter()
            .find(|record| record.resource == target)
            .map(|record| record.freshness.revision)
            .ok_or(AuthorityError::new("acp_approval_not_found"))?;
        let request = ExecuteRequest::new(
            PlatformAction::DecideApproval,
            target,
            IdempotencyKey::new(approval_key(approval_id, allowed))
                .map_err(|_| AuthorityError::new("acp_approval_key"))?,
            Some(revision),
            Some(
                PlatformText::new(if allowed { "grant" } else { "deny" })
                    .map_err(|_| AuthorityError::new("acp_approval_decision"))?,
            ),
        )
        .map_err(|_| AuthorityError::new("acp_approval_request"))?;
        match platform
            .execute_outcome(request)
            .map_err(|_| AuthorityError::new("acp_platform_approval"))?
        {
            ActionResult::Receipt(_) => Ok(()),
            ActionResult::Refused { .. } => Err(AuthorityError::new("acp_approval_refused")),
        }
    }
}

struct ProgressSubscription {
    stream: UnixStream,
}

impl ProgressSubscription {
    fn open(socket: &Path, run_id: &str) -> Result<Self, AuthorityError> {
        let mut stream =
            UnixStream::connect(socket).map_err(|_| AuthorityError::new("acp_progress_connect"))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| AuthorityError::new("acp_progress_timeout"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| AuthorityError::new("acp_progress_timeout"))?;
        match read_message(&mut stream)? {
            Some(StreamMessage::Greeting { .. }) => {}
            _ => return Err(AuthorityError::new("acp_progress_greeting")),
        }
        let request = SubscribeRequest::new(
            RunId::new(run_id).map_err(|_| AuthorityError::new("acp_run_id"))?,
            0,
        )
        .to_canonical_bytes()
        .map_err(|_| AuthorityError::new("acp_progress_subscribe"))?;
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + request.len());
        encode_frame(&request, &mut frame)
            .map_err(|_| AuthorityError::new("acp_progress_subscribe"))?;
        stream
            .write_all(&frame)
            .and_then(|()| stream.flush())
            .map_err(|_| AuthorityError::new("acp_progress_write"))?;
        match read_message(&mut stream)? {
            Some(StreamMessage::Live { from: 1 }) => Ok(Self { stream }),
            Some(StreamMessage::ResyncRequired { .. }) => {
                Err(AuthorityError::new("acp_progress_resync_required"))
            }
            _ => Err(AuthorityError::new("acp_progress_start")),
        }
    }

    fn next(&mut self) -> Result<Option<StreamMessage>, AuthorityError> {
        read_message(&mut self.stream)
    }
}

fn read_message(stream: &mut UnixStream) -> Result<Option<StreamMessage>, AuthorityError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    match stream.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            return Ok(None);
        }
        Err(_) => return Err(AuthorityError::new("acp_progress_read")),
    }
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| AuthorityError::new("acp_progress_frame"))?;
    if length == 0 || length > MAX_PROGRESS_STREAM_CANONICAL_BYTES {
        return Err(AuthorityError::new("acp_progress_frame"));
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| AuthorityError::new("acp_progress_read"))?;
    StreamMessage::from_canonical_bytes(&payload)
        .map(Some)
        .map_err(|_| AuthorityError::new("acp_progress_decode"))
}

struct Projection {
    message_id: String,
    delivered: String,
    tool_sequence: u64,
    current_tool: Option<String>,
}

impl Projection {
    fn new(run_id: &str) -> Self {
        Self {
            message_id: format!("message-{run_id}"),
            delivered: String::new(),
            tool_sequence: 0,
            current_tool: None,
        }
    }

    fn frame(
        &mut self,
        frame: &automonique_protocol::progress_api::ProgressFrame,
        emit: &mut dyn FnMut(PromptEvent) -> Result<(), AuthorityError>,
    ) -> Result<(), AuthorityError> {
        let text = frame.body().text().map(|text| text.as_str());
        match frame.kind() {
            EventKind::AssistantMessageDelta => {
                if let Some(snapshot) = text
                    && let Some(delta) = snapshot.strip_prefix(&self.delivered)
                    && !delta.is_empty()
                {
                    emit(PromptEvent::Message {
                        text: delta.to_owned(),
                        message_id: Some(self.message_id.clone()),
                    })?;
                    self.delivered = snapshot.to_owned();
                }
            }
            EventKind::AssistantMessageCompleted => {
                if let Some(answer) = text {
                    if let Some(delta) = answer.strip_prefix(&self.delivered) {
                        if !delta.is_empty() {
                            emit(PromptEvent::Message {
                                text: delta.to_owned(),
                                message_id: Some(self.message_id.clone()),
                            })?;
                        }
                    } else {
                        emit(PromptEvent::Message {
                            text: answer.to_owned(),
                            message_id: Some(format!("{}-final", self.message_id)),
                        })?;
                    }
                    self.delivered = answer.to_owned();
                }
            }
            EventKind::ToolCallStarted => {
                self.tool_sequence = self.tool_sequence.saturating_add(1);
                let id = format!("tool-{}-{}", self.message_id, self.tool_sequence);
                emit(PromptEvent::ToolStarted {
                    id: id.clone(),
                    title: text.unwrap_or("tool").to_owned(),
                })?;
                self.current_tool = Some(id);
            }
            EventKind::ToolCallUpdated => {
                if let Some(id) = self.current_tool.clone() {
                    emit(PromptEvent::ToolProgress {
                        id,
                        text: text.map(str::to_owned),
                    })?;
                }
            }
            EventKind::ToolCallCompleted => {
                if let Some(id) = self.current_tool.take() {
                    emit(PromptEvent::ToolFinished {
                        id,
                        text: text.map(str::to_owned),
                        failed: matches!(
                            frame.body().step(),
                            Some(automonique_protocol::event::StepStatus::Error)
                        ),
                    })?;
                }
            }
            EventKind::ApprovalRequested => {
                if let Some((id, title, description)) = text.and_then(parse_approval) {
                    emit(PromptEvent::ApprovalRequested {
                        id,
                        title,
                        description,
                    })?;
                }
            }
            EventKind::ProviderWarning | EventKind::ProviderFault => {
                if let Some(text) = text {
                    emit(PromptEvent::Thought {
                        text: text.to_owned(),
                        message_id: Some(format!("{}-diagnostic", self.message_id)),
                    })?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn turn_key(session_id: &str, sequence: u64) -> String {
    let digest = Sha256::digest(format!("{session_id}\0{sequence}").as_bytes());
    format!("acp-turn-{:x}", digest)
}

fn cancel_key(session_id: &str, run_id: &str) -> String {
    let digest = Sha256::digest(format!("{session_id}\0{run_id}\0cancel").as_bytes());
    format!("acp-cancel-{:x}", digest)
}

fn approval_key(approval_id: &str, allowed: bool) -> String {
    let digest = Sha256::digest(
        format!("{approval_id}\0{}", if allowed { "grant" } else { "deny" }).as_bytes(),
    );
    format!("acp-approval-{:x}", digest)
}

fn parse_approval(text: &str) -> Option<(String, String, String)> {
    let (id, detail) = text.strip_prefix("approval ")?.split_once(':')?;
    if id.is_empty() {
        return None;
    }
    let detail = detail.trim();
    let (title, description) = detail
        .split_once(" — ")
        .map_or((detail, detail), |(title, description)| {
            (title, description)
        });
    Some((id.to_owned(), title.to_owned(), description.to_owned()))
}

fn deterministic_run_id(key: &str) -> String {
    let digest = Sha256::digest(format!("automonique.managed-tui.run.v1\0{key}").as_bytes());
    format!("tui-{}", &format!("{:x}", digest)[..24])
}

fn receipt_session(explanation: &str) -> Option<String> {
    explanation
        .split(';')
        .find_map(|part| part.strip_prefix("session="))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_run_identity_matches_the_canonical_worker_algorithm() {
        assert_eq!(
            deterministic_run_id("fixture"),
            "tui-a0c4d41b5ebc9ea52dff9eba"
        );
    }

    #[test]
    fn completed_receipt_exposes_only_the_provider_session_coordinate() {
        assert_eq!(
            receipt_session("run=tui-1;session=provider-1").as_deref(),
            Some("provider-1")
        );
        assert_eq!(receipt_session("run=tui-1"), None);
    }

    #[test]
    fn approval_progress_preserves_the_exact_canonical_coordinate() {
        assert_eq!(
            parse_approval("approval approval-42: shell — run tests"),
            Some((
                "approval-42".to_owned(),
                "shell".to_owned(),
                "run tests".to_owned(),
            ))
        );
        assert_eq!(parse_approval("provider waiting"), None);
    }
}
