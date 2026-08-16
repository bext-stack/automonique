// SPDX-License-Identifier: Elastic-2.0

use crate::types::{
    AdapterError, ExecutionMode, MAX_EVENT_TEXT_BYTES, NormalizedEvent, ProviderDisposition,
    ProviderItemKind, RecordedEvent, RecordedKind, ResumeBinding, RunCoordinates, UnknownEventKind,
    validate_coordinate, validate_provider_session,
};
use automonique_connector_substrate::json::strict_json;
use serde_json::{Map, Value};

pub(crate) struct NormalizedRun {
    pub binding: ResumeBinding,
    pub events: Vec<NormalizedEvent>,
    pub disposition: ProviderDisposition,
}

/// The state machine, which owns the coordinates it normalizes against.
///
/// Owned rather than borrowed, and the clone is the point: a normalizer that
/// borrowed its coordinates could not be moved onto a reader thread, and the
/// live progress stream is exactly a normalizer on a reader thread. The cost is
/// five short strings per run, paid once.
pub(crate) struct Normalizer {
    coordinates: RunCoordinates,
    mode: ExecutionMode,
    session: Option<String>,
    turn_started: bool,
    active_item: Option<String>,
    final_seen: bool,
    disposition: Option<ProviderDisposition>,
    events: Vec<NormalizedEvent>,
}

impl Normalizer {
    pub fn new(coordinates: &RunCoordinates, mode: &ExecutionMode) -> Self {
        Self {
            coordinates: coordinates.clone(),
            mode: mode.clone(),
            session: None,
            turn_started: false,
            active_item: None,
            final_seen: false,
            disposition: None,
            events: Vec::new(),
        }
    }

    pub fn push(&mut self, line: &str) -> Result<(), AdapterError> {
        if self.disposition.is_some() {
            return Err(AdapterError::EventOrder);
        }
        let value = strict_json(line.as_bytes())?;
        let object = value.as_object().ok_or(AdapterError::UnknownSchema)?;
        let event_type = string(object, "type")?;
        match event_type {
            "thread.started" => self.thread_started(object),
            "turn.started" => self.turn_started(object),
            "item.started" => self.item_started(object),
            "item.updated" => self.item_updated(object),
            "item.completed" => self.item_completed(object),
            "turn.completed" => self.turn_completed(object),
            "turn.failed" => self.turn_failed(object),
            other => Err(AdapterError::UnknownEvent(UnknownEventKind::event(other))),
        }
    }

    /// Events accepted so far, in acceptance order.
    pub fn events(&self) -> &[NormalizedEvent] {
        &self.events
    }

    pub fn is_terminal(&self) -> bool {
        self.disposition.is_some()
    }

    pub fn finish(&self) -> Result<NormalizedRun, AdapterError> {
        let session = self.session.clone().ok_or(AdapterError::EventOrder)?;
        let disposition = self.disposition.ok_or(AdapterError::EventOrder)?;
        let binding = ResumeBinding::new(self.coordinates.scope().clone(), session)?;
        Ok(NormalizedRun {
            binding,
            events: self.events.clone(),
            disposition,
        })
    }

    /// Complete an interrupted active turn as a provider failure.
    pub fn finish_failed(mut self) -> Result<NormalizedRun, AdapterError> {
        if self.disposition.is_none() {
            self.active_item = None;
            self.record(RecordedKind::ProviderFault, None)?;
            self.record(RecordedKind::TurnCompleted, None)?;
            self.disposition = Some(ProviderDisposition::Failed);
        }
        self.finish()
    }

    fn thread_started(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["thread_id", "type"])?;
        if self.session.is_some() || self.turn_started {
            return Err(AdapterError::EventOrder);
        }
        let session = string(object, "thread_id")?.to_owned();
        validate_provider_session(&session)?;
        let kind = match &self.mode {
            ExecutionMode::NewSession => RecordedKind::SessionCreated,
            ExecutionMode::Resume(binding) => {
                if binding.provider_session_id() != session {
                    return Err(AdapterError::SessionMismatch);
                }
                RecordedKind::SessionLoaded
            }
        };
        self.session = Some(session);
        self.record(kind, None)
    }

    fn turn_started(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["type"])?;
        if self.session.is_none() || self.turn_started {
            return Err(AdapterError::EventOrder);
        }
        self.turn_started = true;
        self.record(RecordedKind::TurnStarted, None)
    }

    fn item_started(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["item", "type"])?;
        self.require_active()?;
        if self.active_item.is_some() || self.final_seen {
            return Err(AdapterError::EventOrder);
        }
        let item = item(object)?;
        exact(item, &["id", "type"])?;
        let item_id = string(item, "id")?;
        validate_coordinate(item_id, "provider_item_id")?;
        require_agent_message(item)?;
        self.active_item = Some(item_id.to_owned());
        Ok(())
    }

    fn item_updated(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["item", "type"])?;
        self.require_active()?;
        let item = item(object)?;
        exact(item, &["id", "text", "type"])?;
        let item_id = string(item, "id")?;
        validate_coordinate(item_id, "provider_item_id")?;
        if self.active_item.as_deref() != Some(item_id) || self.final_seen {
            return Err(AdapterError::EventOrder);
        }
        require_agent_message(item)?;
        let text = bounded_text(item, "text")?.to_owned();
        let session = self.session.clone().ok_or(AdapterError::EventOrder)?;
        let sequence = self.next_sequence()?;
        self.events.push(NormalizedEvent::Preview {
            sequence,
            run_id: self.coordinates.run_id().to_owned(),
            turn_id: self.coordinates.turn_id().to_owned(),
            provider_session_id: session,
            text,
        });
        Ok(())
    }

    fn item_completed(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["item", "type"])?;
        self.require_active()?;
        if self.final_seen {
            return Err(AdapterError::EventOrder);
        }
        let item = item(object)?;
        exact(item, &["id", "text", "type"])?;
        let item_id = string(item, "id")?;
        validate_coordinate(item_id, "provider_item_id")?;
        if self.active_item.as_deref() != Some(item_id) {
            return Err(AdapterError::EventOrder);
        }
        require_agent_message(item)?;
        let text = bounded_text(item, "text")?.to_owned();
        self.active_item = None;
        self.final_seen = true;
        self.record(RecordedKind::AssistantMessageCompleted, Some(text))
    }

    fn turn_completed(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["type", "usage"])?;
        self.require_active()?;
        if !self.final_seen || self.active_item.is_some() {
            return Err(AdapterError::EventOrder);
        }
        let usage = object
            .get("usage")
            .and_then(Value::as_object)
            .ok_or(AdapterError::UnknownSchema)?;
        exact(
            usage,
            &["cached_input_tokens", "input_tokens", "output_tokens"],
        )?;
        for field in ["cached_input_tokens", "input_tokens", "output_tokens"] {
            if usage.get(field).and_then(Value::as_u64).is_none() {
                return Err(AdapterError::UnknownSchema);
            }
        }
        self.record(RecordedKind::UsageUpdated, None)?;
        self.record(RecordedKind::TurnCompleted, None)?;
        self.disposition = Some(ProviderDisposition::Succeeded);
        Ok(())
    }

    fn turn_failed(&mut self, object: &Map<String, Value>) -> Result<(), AdapterError> {
        exact(object, &["error", "type"])?;
        self.require_active()?;
        let error = object
            .get("error")
            .and_then(Value::as_object)
            .ok_or(AdapterError::UnknownSchema)?;
        exact(error, &["message"])?;
        let message = bounded_text(error, "message")?.to_owned();
        self.active_item = None;
        self.record(RecordedKind::ProviderFault, Some(message))?;
        self.record(RecordedKind::TurnCompleted, None)?;
        self.disposition = Some(ProviderDisposition::Failed);
        Ok(())
    }

    fn require_active(&self) -> Result<(), AdapterError> {
        if self.session.is_none() || !self.turn_started {
            Err(AdapterError::EventOrder)
        } else {
            Ok(())
        }
    }

    fn record(&mut self, kind: RecordedKind, text: Option<String>) -> Result<(), AdapterError> {
        let provider_session_id = self.session.clone().ok_or(AdapterError::EventOrder)?;
        let sequence = self.next_sequence()?;
        self.events.push(NormalizedEvent::Recorded(RecordedEvent {
            sequence,
            run_id: self.coordinates.run_id().to_owned(),
            turn_id: self.coordinates.turn_id().to_owned(),
            provider_session_id,
            kind,
            text,
        }));
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64, AdapterError> {
        u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(AdapterError::OutputTooLarge)
    }
}

/// The only item type this vocabulary accepts.
///
/// Every other item type — a tool call, a reasoning summary, a patch — is a
/// refusal naming that type, not a silently dropped item. Accepting a
/// transcript while discarding the items it does not model would produce a
/// normalized event list that is a strict, unannounced subset of what the
/// provider actually did.
///
/// The admitted set is [`ProviderItemKind`] rather than a literal, so the
/// vocabulary a consumer maps over and the vocabulary this grammar enforces are
/// one declaration.
fn require_agent_message(item: &Map<String, Value>) -> Result<(), AdapterError> {
    let item_type = string(item, "type")?;
    match ProviderItemKind::from_spelling(item_type) {
        Some(ProviderItemKind::AgentMessage) => Ok(()),
        None => Err(AdapterError::UnknownEvent(UnknownEventKind::item(
            item_type,
        ))),
    }
}

fn item(object: &Map<String, Value>) -> Result<&Map<String, Value>, AdapterError> {
    object
        .get("item")
        .and_then(Value::as_object)
        .ok_or(AdapterError::UnknownSchema)
}

fn bounded_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, AdapterError> {
    let value = string(object, field)?;
    if value.len() > MAX_EVENT_TEXT_BYTES || value.contains('\0') {
        Err(AdapterError::UnknownSchema)
    } else {
        Ok(value)
    }
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, AdapterError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AdapterError::UnknownSchema)
}

fn exact(object: &Map<String, Value>, fields: &[&str]) -> Result<(), AdapterError> {
    if object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)) {
        Ok(())
    } else {
        Err(AdapterError::UnknownSchema)
    }
}
