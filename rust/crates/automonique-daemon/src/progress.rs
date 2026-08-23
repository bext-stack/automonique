// SPDX-License-Identifier: Elastic-2.0

//! Provider stdout, turned into the frames every surface renders.
//!
//! This is the seam between two crates that deliberately do not know each
//! other. `automonique-agents` owns the provider grammar and depends on
//! `automonique-runner`, so the runner cannot own a normalizer; the runner owns
//! the pipe, the reader thread and the spool, so `automonique-agents` cannot own
//! a writer. This module is the daemon standing between them, and it is the only
//! place where a provider's vocabulary meets the shared one.
//!
//! # The mapping is a projection, not a translation
//!
//! [`RecordedKind`] has ten members and the shared
//! [`EventKind`](automonique_protocol::event::EventKind) has twenty-four, so
//! [`frame_kind`] is total in one direction and deliberately partial in the
//! other: Codex command-execution items become tool-call frames, while shared
//! kinds with no admitted provider schema remain impossible here. The mapping
//! is written as a closed `match` over both
//! published sets ([`RecordedKind::ALL`], [`ProviderItemKind::ALL`]) so that
//! admitting another item type is a compile error here rather than a kind that
//! silently never reaches a renderer.
//!
//! # Coalescing, and why previews replace rather than accumulate
//!
//! The provider's `item.updated` carries the item's text *so far*, not the
//! bytes added since the last one — see the fixtures in
//! `automonique-agents/tests/provider_stream.rs`, where a preview and its
//! completion are two whole strings rather than two halves of one. So the
//! coalescer keeps the latest snapshot and drops the ones it superseded, which
//! is both the correct reading and the one that cannot grow without bound.
//!
//! A snapshot is emitted when it reaches [`PREVIEW_FLUSH_BYTES`] or when
//! [`PREVIEW_FLUSH_MS`] have passed since the last one — evaluated when bytes
//! arrive, because that is the only moment anything has changed. There is no
//! timer thread: a stream that has gone quiet has nothing new to show, and
//! whatever is held is flushed at end of file.
//!
//! # A poisoned stream ends the rendering, not the run
//!
//! [`ProviderEventStream`] is refusal-first: one line outside the grammar
//! refuses the stream permanently. That is the right trade here and the reason
//! it is safe — progress is an optional projection, and the run's answer comes
//! back through the file the document names. A refused stream emits one final
//! warning frame carrying the refusal's *category* (never the line, which is
//! provider output) and then nothing.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use automonique_agents::{
    AdapterError, ExecutionMode, NormalizedEvent, ProviderEventStream, ProviderItemKind,
    RecordedEvent, RecordedKind, RunCoordinates, StreamPolicy,
};
use automonique_protocol::event::{
    Authority, EventKind, MemberRule, RetryCategory, RetryContext, StepStatus,
};
use automonique_protocol::progress_api::{ProgressBody, ProgressBodyParts, ProgressText};
use automonique_runner::backend::{CapturedFrame, ProgressMapper};

/// Coalesced preview bytes that force a frame.
pub const PREVIEW_FLUSH_BYTES: usize = 1024;

/// Time since the last preview frame that forces the next one.
pub const PREVIEW_FLUSH_MS: u64 = 750;

/// The interval spelled as a duration.
pub const PREVIEW_FLUSH_INTERVAL: Duration = Duration::from_millis(PREVIEW_FLUSH_MS);

/// The text of the one warning a refused provider stream emits.
pub const STREAM_REFUSED_PREFIX: &str = "progress stream refused: ";
pub const STREAM_WARNING_TEXT: &str = "progress stream warning: malformed provider line skipped";

/// The shared kind one adapter record projects onto.
///
/// Total over [`RecordedKind`] by a closed `match`, so a kind added to the
/// adapter's vocabulary fails to compile here rather than arriving at a
/// renderer as nothing.
#[must_use]
pub const fn frame_kind(kind: RecordedKind) -> EventKind {
    match kind {
        RecordedKind::SessionCreated => EventKind::SessionCreated,
        RecordedKind::SessionLoaded => EventKind::SessionLoaded,
        RecordedKind::ProviderWarning => EventKind::ProviderWarning,
        RecordedKind::TurnStarted => EventKind::TurnStarted,
        RecordedKind::AssistantMessageCompleted => EventKind::AssistantMessageCompleted,
        RecordedKind::ToolCallStarted => EventKind::ToolCallStarted,
        RecordedKind::ToolCallCompleted | RecordedKind::ToolCallFailed => {
            EventKind::ToolCallCompleted
        }
        RecordedKind::UsageUpdated => EventKind::UsageUpdated,
        RecordedKind::ProviderFault => EventKind::ProviderFault,
        RecordedKind::TurnCompleted => EventKind::TurnCompleted,
    }
}

/// The shared kind one *in-progress* item projects onto.
///
/// The other half of the matrix. An item's completion is a [`RecordedKind`] and
/// goes through [`frame_kind`]; an item still being written is a preview, and
/// this is what a preview of each admitted item type is called.
#[must_use]
pub const fn item_frame_kind(item: ProviderItemKind) -> EventKind {
    match item {
        ProviderItemKind::AgentMessage => EventKind::AssistantMessageDelta,
        ProviderItemKind::CommandExecution => EventKind::ToolCallUpdated,
    }
}

/// The authority a preview of one item type may claim.
///
/// Always synthetic, and the type system agrees: `AssistantMessageDelta` is the
/// one preview-only kind, and the frame constructor refuses an authoritative
/// record of it. This function exists so the rule is stated once rather than
/// spelled at each call site.
#[must_use]
pub const fn item_frame_authority(item: ProviderItemKind) -> Authority {
    match item {
        ProviderItemKind::AgentMessage => Authority::Synthetic,
        ProviderItemKind::CommandExecution => Authority::Synthetic,
    }
}

/// Normalizes one attempt's stdout into frames, coalescing its previews.
pub struct ProviderProgressMapper {
    stream: ProviderEventStream,
    /// How many normalized events have already been turned into frames.
    projected: usize,
    /// The latest preview snapshot, not yet shown.
    pending_preview: Option<String>,
    /// When the last preview frame was produced.
    last_preview: Instant,
    /// Set once the stream refused, after the one warning that says so.
    finished: bool,
    /// Session-policy malformed lines already surfaced as warning frames.
    projected_warnings: u64,
    /// Optional durable-owner handoff for the provider session observed by
    /// this exact run. The mapper writes only the normalized identifier; the
    /// execution worker decides whether a terminal run may persist it.
    session_capture: Option<Arc<Mutex<Option<String>>>>,
}

impl ProviderProgressMapper {
    /// Start a mapper for one attempt.
    #[must_use]
    pub fn new(coordinates: &RunCoordinates, mode: &ExecutionMode) -> Self {
        Self {
            stream: ProviderEventStream::new(coordinates, mode),
            projected: 0,
            pending_preview: None,
            last_preview: Instant::now(),
            finished: false,
            projected_warnings: 0,
            session_capture: None,
        }
    }

    /// Start the explicitly lenient mapper used by a persistent session host.
    #[must_use]
    pub fn for_session(coordinates: &RunCoordinates, mode: &ExecutionMode) -> Self {
        Self {
            stream: ProviderEventStream::with_policy(coordinates, mode, StreamPolicy::Session),
            projected: 0,
            pending_preview: None,
            last_preview: Instant::now(),
            finished: false,
            projected_warnings: 0,
            session_capture: None,
        }
    }

    /// Capture the exact provider session observed by this normalized stream.
    #[must_use]
    pub fn with_session_capture(mut self, capture: Arc<Mutex<Option<String>>>) -> Self {
        self.session_capture = Some(capture);
        self
    }

    /// Project every event the stream has accepted since the last call.
    fn project(&mut self, frames: &mut Vec<CapturedFrame>) {
        let events: Vec<NormalizedEvent> = self
            .stream
            .events()
            .get(self.projected..)
            .unwrap_or_default()
            .to_vec();
        self.projected += events.len();
        for event in events {
            match event {
                NormalizedEvent::Preview { text, .. } => {
                    // Latest wins: the provider's update carries the item's
                    // whole text, so an earlier snapshot is not a fragment to
                    // keep but a strictly worse version of this one.
                    self.pending_preview = Some(text);
                    if self.preview_is_due() {
                        self.flush_preview(frames);
                    }
                }
                NormalizedEvent::Recorded(recorded) => {
                    if matches!(
                        recorded.kind(),
                        RecordedKind::SessionCreated | RecordedKind::SessionLoaded
                    ) && let Some(capture) = self.session_capture.as_ref()
                        && let Ok(mut captured) = capture.lock()
                        && captured
                            .as_deref()
                            .is_none_or(|value| value == recorded.provider_session_id())
                    {
                        *captured = Some(recorded.provider_session_id().to_owned());
                    }
                    // Ordering matters more than the byte bound here: a preview
                    // shown *after* the message it previewed would redraw a
                    // finished answer as an unfinished one.
                    self.flush_preview(frames);
                    if let Some(frame) = recorded_frame(&recorded) {
                        frames.push(frame);
                    }
                }
            }
        }
    }

    fn preview_is_due(&self) -> bool {
        self.pending_preview
            .as_ref()
            .is_some_and(|text| text.len() >= PREVIEW_FLUSH_BYTES)
            || self.last_preview.elapsed() >= PREVIEW_FLUSH_INTERVAL
    }

    fn flush_preview(&mut self, frames: &mut Vec<CapturedFrame>) {
        let Some(text) = self.pending_preview.take() else {
            return;
        };
        self.last_preview = Instant::now();
        let kind = item_frame_kind(ProviderItemKind::AgentMessage);
        // Sanitized rather than validated: a preview that cannot be shown is
        // dropped, and a run is never failed for the shape of its own output.
        let Some(text) = ProgressText::sanitized(&text) else {
            return;
        };
        let Ok(body) = ProgressBody::new(
            kind,
            ProgressBodyParts {
                text: Some(text),
                step: None,
                retry: None,
            },
        ) else {
            return;
        };
        frames.push(CapturedFrame {
            authority: item_frame_authority(ProviderItemKind::AgentMessage),
            kind,
            body,
        });
    }

    /// The one warning a refused stream leaves behind.
    ///
    /// It carries the refusal's stable category and, when the refusal named an
    /// offending token, that token — which `automonique_agents` has already
    /// reduced to a schema-keyword character set or to a placeholder. The line
    /// that carried it is never named, because the line is provider output.
    fn refusal_frame(error: &AdapterError) -> Option<CapturedFrame> {
        let detail = error.unknown_kind().map_or_else(
            || format!("{STREAM_REFUSED_PREFIX}{}", error.category()),
            |kind| format!("{STREAM_REFUSED_PREFIX}{} ({kind})", error.category()),
        );
        ProgressBody::new(
            EventKind::ProviderWarning,
            ProgressBodyParts {
                text: ProgressText::sanitized(&detail),
                step: None,
                // Nothing about a poisoned parse is retryable: the parser's view
                // and the provider's have diverged and no later byte reconciles
                // them.
                retry: RetryContext::new(RetryCategory::Internal, false, None, 1).ok(),
            },
        )
        .ok()
        .map(|body| CapturedFrame {
            authority: Authority::Synthetic,
            kind: EventKind::ProviderWarning,
            body,
        })
    }

    fn project_warnings(&mut self, frames: &mut Vec<CapturedFrame>) {
        while self.projected_warnings < self.stream.warning_count() {
            self.projected_warnings = self.projected_warnings.saturating_add(1);
            let Ok(body) = ProgressBody::new(
                EventKind::ProviderWarning,
                ProgressBodyParts {
                    text: ProgressText::new(STREAM_WARNING_TEXT).ok(),
                    step: None,
                    retry: RetryContext::new(RetryCategory::Internal, true, None, 1).ok(),
                },
            ) else {
                continue;
            };
            frames.push(CapturedFrame {
                authority: Authority::Synthetic,
                kind: EventKind::ProviderWarning,
                body,
            });
        }
    }
}

impl ProgressMapper for ProviderProgressMapper {
    fn push(&mut self, chunk: &[u8]) -> Vec<CapturedFrame> {
        if self.finished {
            return Vec::new();
        }
        let mut frames = Vec::new();
        match self.stream.push_bytes(chunk) {
            Ok(_) => {
                self.project(&mut frames);
                self.project_warnings(&mut frames);
            }
            Err(error) => {
                // Whatever the stream accepted before the bad line is still
                // true, so it is projected before the warning that ends the
                // stream — a consumer sees what happened and then why it
                // stopped, in that order.
                self.project(&mut frames);
                self.flush_preview(&mut frames);
                self.finished = true;
                frames.extend(Self::refusal_frame(&error));
            }
        }
        frames
    }

    fn finish(&mut self) -> Vec<CapturedFrame> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut frames = Vec::new();
        self.project(&mut frames);
        self.flush_preview(&mut frames);
        frames
    }
}

/// One adapter record, as the frame a renderer draws.
///
/// `None` for a record whose required body cannot be built — an assistant
/// message whose text sanitized away to nothing, a retry context this build
/// would refuse. Dropping such a frame is the correct answer: the durable
/// record of the run is the spool and the answer file, and neither depends on
/// this projection.
fn recorded_frame(event: &RecordedEvent) -> Option<CapturedFrame> {
    let kind = frame_kind(event.kind());
    let text = match kind.text_rule() {
        MemberRule::Forbidden => None,
        MemberRule::Required | MemberRule::Optional => {
            event.text().and_then(ProgressText::sanitized)
        }
    };
    let retry = match kind.retry_rule() {
        MemberRule::Forbidden => None,
        // The provider said the turn failed and said nothing about trying
        // again, so this claims nothing about trying again either.
        MemberRule::Required | MemberRule::Optional => {
            Some(RetryContext::new(RetryCategory::Rejected, false, None, 1).ok()?)
        }
    };
    let step = match event.kind() {
        RecordedKind::ToolCallStarted => Some(StepStatus::InProgress),
        RecordedKind::ToolCallCompleted => Some(StepStatus::Completed),
        RecordedKind::ToolCallFailed => Some(StepStatus::Error),
        _ => None,
    };
    let body = ProgressBody::new(kind, ProgressBodyParts { text, step, retry }).ok()?;
    Some(CapturedFrame {
        authority: Authority::Authoritative,
        kind,
        body,
    })
}
