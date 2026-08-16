// SPDX-License-Identifier: Elastic-2.0

//! Bounded session-scoped provider process ownership.
//!
//! One host owns one sandboxed process and serializes turns over NDJSON. It
//! keeps no more than one reader thread worth of work (the caller's thread),
//! records every process/session/turn/request edge in the provider journal,
//! and requires an explicit close or idle-TTL reap. A daemon restart cannot
//! adopt an unverified descriptor: an open journal attempt is marked lost
//! before a replacement is spawned.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use automonique_agents::{
    ExecutionMode, NormalizedEvent, NormalizedTranscript, ProviderDisposition, ProviderEventStream,
    RecordedKind, ResumeBinding, RunCoordinates, SessionScope, StreamPolicy,
};
use automonique_protocol::provenance::{CausationId, CorrelationId, Provenance, TraceId};
use automonique_runner::{LaunchPlan, RunContainment, SandboxedSession, spawn_sandboxed_session};
use automonique_store::provider_journal::{
    CursorAdvance, FinishReason, ProcessExit, ProcessSpawn, ProcessState, ProcessTermination,
    ProviderJournal, ProviderJournalError, RequestDirection, RequestRecord, RequestSettlement,
    SessionClosing, SessionClosure, SessionOpening, SettledOutcome, TurnCompletion, TurnOpening,
    TurnOutcome, TurnUsage,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const MAX_LIVE_PROVIDER_SESSIONS: usize = 16;
pub const DEFAULT_SESSION_IDLE_TTL_MS: i64 = 15 * 60 * 1_000;
pub const MAX_PROVIDER_TURN_LINE_BYTES: usize = 64 * 1024;
const CLOSE_DRAIN: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum SessionHostError {
    InvalidField(&'static str),
    AtCapacity,
    IdleExpired,
    Launch(automonique_runner::LaunchError),
    Journal(ProviderJournalError),
    Io(std::io::Error),
    Adapter(automonique_agents::AdapterError),
    Containment(automonique_runner::ContainmentError),
}

impl fmt::Display for SessionHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid session host field: {field}"),
            Self::AtCapacity => formatter.write_str("provider session host capacity reached"),
            Self::IdleExpired => formatter.write_str("provider session host idle TTL expired"),
            Self::Launch(error) => write!(formatter, "provider session launch: {error}"),
            Self::Journal(error) => write!(formatter, "provider session journal: {error}"),
            Self::Io(error) => write!(formatter, "provider session I/O: {error}"),
            Self::Adapter(error) => write!(formatter, "provider session stream: {error}"),
            Self::Containment(error) => write!(formatter, "provider session containment: {error}"),
        }
    }
}

impl std::error::Error for SessionHostError {}

impl From<ProviderJournalError> for SessionHostError {
    fn from(value: ProviderJournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<std::io::Error> for SessionHostError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<automonique_agents::AdapterError> for SessionHostError {
    fn from(value: automonique_agents::AdapterError) -> Self {
        Self::Adapter(value)
    }
}

#[derive(Serialize)]
struct UserTurn<'a> {
    r#type: &'static str,
    turn_id: &'a str,
    message: &'a str,
}

/// One live, session-scoped provider process.
pub struct ProviderSessionHost {
    session_key: String,
    provider_kind: String,
    request_model: Option<String>,
    scope: SessionScope,
    process: SandboxedSession,
    reader: BufReader<std::os::unix::net::UnixStream>,
    containment: Option<RunContainment>,
    journal: ProviderJournal,
    process_id: i64,
    process_revision: u64,
    session_id: i64,
    session_revision: u64,
    next_ordinal: u64,
    last_active_ms: i64,
    idle_ttl_ms: i64,
    closed: bool,
}

/// The daemon's bounded set of live session hosts.
#[derive(Default)]
pub struct ProviderSessionPool {
    hosts: BTreeMap<String, ProviderSessionHost>,
}

impl ProviderSessionPool {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, host: ProviderSessionHost) -> Result<(), SessionHostError> {
        if self.hosts.len() >= MAX_LIVE_PROVIDER_SESSIONS {
            return Err(SessionHostError::AtCapacity);
        }
        let key = host.session_key().to_owned();
        if self.hosts.contains_key(&key) {
            return Err(SessionHostError::InvalidField("duplicate_session"));
        }
        self.hosts.insert(key, host);
        Ok(())
    }

    pub fn get_mut(&mut self, session_key: &str) -> Option<&mut ProviderSessionHost> {
        self.hosts.get_mut(session_key)
    }

    /// Close and remove every host whose idle TTL has elapsed.
    pub fn reap_idle(&mut self, now_ms: i64) -> Result<usize, SessionHostError> {
        let expired: Vec<String> = self
            .hosts
            .iter()
            .filter(|(_, host)| host.is_idle_expired(now_ms))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            if let Some(host) = self.hosts.remove(key) {
                host.close(now_ms)?;
            }
        }
        Ok(expired.len())
    }

    pub fn close(&mut self, session_key: &str, now_ms: i64) -> Result<bool, SessionHostError> {
        let Some(host) = self.hosts.remove(session_key) else {
            return Ok(false);
        };
        host.close(now_ms)?;
        Ok(true)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

impl ProviderSessionHost {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        helper: &Path,
        plan: &LaunchPlan,
        containment: RunContainment,
        journal_path: &Path,
        session_key: &str,
        scope: SessionScope,
        provider_kind: &str,
        request_model: Option<&str>,
        now_ms: i64,
        idle_ttl_ms: i64,
    ) -> Result<Self, SessionHostError> {
        validate_key(session_key, "session_key")?;
        validate_key(provider_kind, "provider_kind")?;
        if let Some(model) = request_model {
            validate_key(model, "request_model")?;
        }
        if now_ms < 0 || idle_ttl_ms <= 0 {
            return Err(SessionHostError::InvalidField("time"));
        }
        let mut journal = ProviderJournal::open(journal_path)?;
        retire_orphaned_attempt(&mut journal, session_key, now_ms)?;

        let mut process = spawn_sandboxed_session(helper, plan, &containment)
            .map_err(SessionHostError::Launch)?;
        let reader = match process.try_clone_stream() {
            Ok(stream) => BufReader::new(stream),
            Err(error) => {
                let _ = process.kill();
                return Err(SessionHostError::Io(error));
            }
        };
        let spawn_key = format!("{session_key}:{now_ms}");
        let process_receipt = match journal.record_process(ProcessSpawn {
            spawn_key: &spawn_key,
            attempt_id: session_key,
            provider_kind,
            executable_digest: plan.program_sha256(),
            spawned_ms: now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = process.kill();
                return Err(SessionHostError::Journal(error));
            }
        };
        let session = journal.open_session(SessionOpening {
            process_id: process_receipt.process_id,
            provider_session_key: session_key,
            opened_ms: now_ms,
        })?;
        Ok(Self {
            session_key: session_key.to_owned(),
            provider_kind: provider_kind.to_owned(),
            request_model: request_model.map(str::to_owned),
            scope,
            process,
            reader,
            containment: Some(containment),
            journal,
            process_id: process_receipt.process_id,
            process_revision: process_receipt.revision,
            session_id: session.session_id,
            session_revision: session.revision,
            next_ordinal: 1,
            last_active_ms: now_ms,
            idle_ttl_ms,
            closed: false,
        })
    }

    #[must_use]
    pub fn operating_system_process_id(&self) -> u32 {
        self.process.id()
    }

    #[must_use]
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    #[must_use]
    pub fn is_idle_expired(&self, now_ms: i64) -> bool {
        now_ms.saturating_sub(self.last_active_ms) >= self.idle_ttl_ms
    }

    /// Execute one serialized turn on the already-live process.
    pub fn turn(
        &mut self,
        turn_key: &str,
        prompt: &str,
        now_ms: i64,
        read_timeout: Duration,
    ) -> Result<NormalizedTranscript, SessionHostError> {
        validate_key(turn_key, "turn_key")?;
        if self.closed || now_ms < 0 || prompt.is_empty() {
            return Err(SessionHostError::InvalidField("turn"));
        }
        if self.is_idle_expired(now_ms) {
            return Err(SessionHostError::IdleExpired);
        }
        let trace_id = TraceId::for_ingress("provider_session", &self.session_key);
        let provenance = Provenance::new(
            trace_id,
            CorrelationId::new(format!(
                "provider-turn:{}:{}",
                self.session_id, self.next_ordinal
            ))
            .map_err(|_| SessionHostError::InvalidField("turn_key"))?,
            CausationId::new(format!("provider-session:{}", self.session_id))
                .map_err(|_| SessionHostError::InvalidField("session_key"))?,
        );
        let opening = self.journal.open_turn(TurnOpening {
            session_id: self.session_id,
            ordinal: self.next_ordinal,
            turn_key,
            opened_ms: now_ms,
            provenance: Some(&provenance),
        })?;
        let input = serde_json::to_vec(&UserTurn {
            r#type: "user",
            turn_id: turn_key,
            message: prompt,
        })
        .map_err(|_| SessionHostError::InvalidField("prompt"))?;
        if input.len() + 1 > MAX_PROVIDER_TURN_LINE_BYTES {
            self.abort_turn(opening.turn_id, opening.revision, now_ms)?;
            return Err(SessionHostError::InvalidField("prompt"));
        }
        let digest = sha256(&input);
        let request_key = format!("{turn_key}:user");
        self.journal.record_request(RequestRecord {
            turn_id: opening.turn_id,
            request_key: &request_key,
            direction: RequestDirection::ToProvider,
            payload_digest: &digest,
            created_ms: now_ms,
        })?;

        if let Err(error) = self
            .process
            .write_all(&input)
            .and_then(|()| self.process.write_all(b"\n"))
        {
            self.abort_recorded_turn(
                opening.turn_id,
                opening.revision,
                &request_key,
                now_ms,
                "write_failed",
            )?;
            return Err(SessionHostError::Io(error));
        }
        self.reader.get_ref().set_read_timeout(Some(read_timeout))?;
        let coordinates =
            RunCoordinates::new(self.session_key.clone(), turn_key, self.scope.clone())
                .map_err(|_| SessionHostError::InvalidField("coordinates"))?;
        let mode = if self.next_ordinal == 1 {
            ExecutionMode::NewSession
        } else {
            ExecutionMode::Resume(
                ResumeBinding::new(self.scope.clone(), self.session_key.clone())
                    .map_err(|_| SessionHostError::InvalidField("session_key"))?,
            )
        };
        let mut stream =
            ProviderEventStream::with_policy(&coordinates, &mode, StreamPolicy::Session);
        let mut response = Vec::new();
        let exit_success;
        loop {
            let mut line = Vec::new();
            match self.reader.read_until(b'\n', &mut line) {
                Ok(0) => {
                    exit_success = self
                        .process
                        .try_wait()?
                        .is_some_and(|status| status.success());
                    break;
                }
                Ok(_) => {
                    response.extend_from_slice(&line);
                    if let Err(error) = stream.push_bytes(&line) {
                        self.abort_recorded_turn(
                            opening.turn_id,
                            opening.revision,
                            &request_key,
                            now_ms,
                            "stream_refused",
                        )?;
                        return Err(SessionHostError::Adapter(error));
                    }
                    if stream.events().iter().any(|event| {
                        matches!(
                            event,
                            NormalizedEvent::Recorded(recorded)
                                if recorded.kind() == RecordedKind::TurnCompleted
                        )
                    }) {
                        exit_success = true;
                        break;
                    }
                }
                Err(error) => {
                    self.abort_recorded_turn(
                        opening.turn_id,
                        opening.revision,
                        &request_key,
                        now_ms,
                        "read_failed",
                    )?;
                    return Err(SessionHostError::Io(error));
                }
            }
        }
        let transcript = match stream.finish_session(exit_success) {
            Ok(transcript) => transcript,
            Err(error) => {
                self.abort_recorded_turn(
                    opening.turn_id,
                    opening.revision,
                    &request_key,
                    now_ms,
                    "stream_incomplete",
                )?;
                return Err(SessionHostError::Adapter(error));
            }
        };
        let response_digest = sha256(&response);
        let settlement = [RequestSettlement {
            request_key: &request_key,
            expected_revision: 1,
            outcome: SettledOutcome::Answered {
                response_digest: &response_digest,
            },
        }];
        let sequence = u64::try_from(transcript.events().len())
            .map_err(|_| SessionHostError::InvalidField("event_count"))?;
        let usage = transcript.usage().map(|usage| TurnUsage {
            gen_ai_system: &self.provider_kind,
            request_model: self.request_model.as_deref(),
            response_model: None,
            input_tokens: usage.input_tokens(),
            cached_input_tokens: usage.cached_input_tokens(),
            output_tokens: usage.output_tokens(),
            finish_reason: match transcript.disposition() {
                ProviderDisposition::Succeeded => FinishReason::Stop,
                ProviderDisposition::Failed => FinishReason::Error,
            },
        });
        let completed = self.journal.complete_turn(TurnCompletion {
            turn_id: opening.turn_id,
            expected_revision: opening.revision,
            now_ms,
            outcome: TurnOutcome::Completed,
            settlements: &settlement,
            cursor: Some(CursorAdvance {
                session_id: self.session_id,
                stream: "events",
                sequence,
                now_ms,
            }),
            usage,
        })?;
        self.next_ordinal = completed.ordinal.saturating_add(1);
        self.last_active_ms = now_ms;
        if !exit_success {
            let process = self.journal.finish_process(ProcessExit {
                process_id: self.process_id,
                expected_revision: self.process_revision,
                now_ms,
                termination: ProcessTermination::Failed,
            })?;
            self.process_revision = process.revision;
            let _ = self.process.kill();
            let _ = self.process.wait();
            if let Some(containment) = self.containment.take() {
                containment
                    .dispose(CLOSE_DRAIN)
                    .map_err(SessionHostError::Containment)?;
            }
            self.closed = true;
        }
        Ok(transcript)
    }

    fn abort_turn(
        &mut self,
        turn_id: i64,
        revision: u64,
        now_ms: i64,
    ) -> Result<(), SessionHostError> {
        self.journal.complete_turn(TurnCompletion {
            turn_id,
            expected_revision: revision,
            now_ms,
            outcome: TurnOutcome::Aborted,
            settlements: &[],
            cursor: None,
            usage: None,
        })?;
        Ok(())
    }

    fn abort_recorded_turn(
        &mut self,
        turn_id: i64,
        revision: u64,
        request_key: &str,
        now_ms: i64,
        reason: &'static str,
    ) -> Result<(), SessionHostError> {
        let settlement = [RequestSettlement {
            request_key,
            expected_revision: 1,
            outcome: SettledOutcome::Failed { reason },
        }];
        self.journal.complete_turn(TurnCompletion {
            turn_id,
            expected_revision: revision,
            now_ms,
            outcome: TurnOutcome::Aborted,
            settlements: &settlement,
            cursor: None,
            usage: None,
        })?;
        Ok(())
    }

    /// Close the session, reap its process and destroy its containment domain.
    pub fn close(mut self, now_ms: i64) -> Result<(), SessionHostError> {
        if self.closed {
            return Ok(());
        }
        let session = self.journal.close_session(SessionClosing {
            session_id: self.session_id,
            expected_revision: self.session_revision,
            now_ms,
            closure: SessionClosure::Closed,
        })?;
        self.session_revision = session.revision;
        let _ = self.process.kill();
        let _ = self.process.wait();
        let process = self.journal.finish_process(ProcessExit {
            process_id: self.process_id,
            expected_revision: self.process_revision,
            now_ms,
            termination: ProcessTermination::Exited,
        })?;
        self.process_revision = process.revision;
        if let Some(containment) = self.containment.take() {
            containment
                .dispose(CLOSE_DRAIN)
                .map_err(SessionHostError::Containment)?;
        }
        self.closed = true;
        Ok(())
    }
}

/// Mark a process descriptor left by a previous daemon generation as lost.
/// The provider journal atomically cascades its open session and turn.
pub fn retire_orphaned_attempt(
    journal: &mut ProviderJournal,
    attempt_id: &str,
    now_ms: i64,
) -> Result<bool, SessionHostError> {
    let recovery = journal.recover_attempt(attempt_id)?;
    let Some(process) = recovery
        .process
        .filter(|process| process.state == ProcessState::Live)
    else {
        return Ok(false);
    };
    journal.finish_process(ProcessExit {
        process_id: process.process_id,
        expected_revision: process.revision,
        now_ms,
        termination: ProcessTermination::Lost,
    })?;
    Ok(true)
}

impl Drop for ProviderSessionHost {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

fn validate_key(value: &str, field: &'static str) -> Result<(), SessionHostError> {
    if value.is_empty()
        || value.len() > 256
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        Err(SessionHostError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
