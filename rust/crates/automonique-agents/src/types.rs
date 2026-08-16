// SPDX-License-Identifier: Elastic-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_COORDINATE_BYTES: usize = 160;
/// Longest offending event kind an error may name back to the caller.
pub const MAX_EVENT_KIND_BYTES: usize = 64;
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
pub const MAX_ENV_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_EVENT_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_JSONL_LINE_BYTES: usize = 64 * 1024;
pub const MAX_JSONL_TOTAL_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinateError {
    InvalidField(&'static str),
    CrossScopeResume,
    SessionMismatch,
    InvalidEnvironment,
}

impl fmt::Display for CoordinateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid coordinate: {field}"),
            Self::CrossScopeResume => formatter.write_str("resume crosses a session scope"),
            Self::SessionMismatch => formatter.write_str("provider session does not match resume"),
            Self::InvalidEnvironment => formatter.write_str("environment is not allowlisted"),
        }
    }
}

impl std::error::Error for CoordinateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionScope {
    tenant_id: String,
    provider_account: String,
    provider_namespace: String,
}

impl SessionScope {
    pub fn new(
        tenant_id: impl Into<String>,
        provider_account: impl Into<String>,
        provider_namespace: impl Into<String>,
    ) -> Result<Self, CoordinateError> {
        let tenant_id = tenant_id.into();
        let provider_account = provider_account.into();
        let provider_namespace = provider_namespace.into();
        validate_coordinate(&tenant_id, "tenant_id")?;
        validate_coordinate(&provider_account, "provider_account")?;
        validate_coordinate(&provider_namespace, "provider_namespace")?;
        Ok(Self {
            tenant_id,
            provider_account,
            provider_namespace,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeBinding {
    scope: SessionScope,
    provider_session_id: String,
}

impl ResumeBinding {
    pub fn new(
        scope: SessionScope,
        provider_session_id: impl Into<String>,
    ) -> Result<Self, CoordinateError> {
        let provider_session_id = provider_session_id.into();
        validate_provider_session(&provider_session_id)?;
        Ok(Self {
            scope,
            provider_session_id,
        })
    }

    pub fn provider_session_id(&self) -> &str {
        &self.provider_session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCoordinates {
    run_id: String,
    turn_id: String,
    scope: SessionScope,
}

impl RunCoordinates {
    pub fn new(
        run_id: impl Into<String>,
        turn_id: impl Into<String>,
        scope: SessionScope,
    ) -> Result<Self, CoordinateError> {
        let run_id = run_id.into();
        let turn_id = turn_id.into();
        validate_coordinate(&run_id, "run_id")?;
        validate_coordinate(&turn_id, "turn_id")?;
        Ok(Self {
            run_id,
            turn_id,
            scope,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    NewSession,
    Resume(ResumeBinding),
}

#[derive(Clone, Eq, PartialEq)]
pub struct AdapterEnvironment(BTreeMap<String, String>);

impl AdapterEnvironment {
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    pub fn new(
        entries: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, CoordinateError> {
        let mut values = BTreeMap::new();
        for (key, value) in entries {
            if !matches!(
                key.as_str(),
                "CODEX_HOME" | "SSL_CERT_FILE" | "SSL_CERT_DIR"
            ) || value.is_empty()
                || value.len() > MAX_ENV_VALUE_BYTES
                || value.contains('\0')
                || values.insert(key, value).is_some()
            {
                return Err(CoordinateError::InvalidEnvironment);
            }
        }
        Ok(Self(values))
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

impl fmt::Debug for AdapterEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterEnvironment")
            .field("keys", &self.0.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct RunRequest {
    pub(crate) coordinates: RunCoordinates,
    pub(crate) mode: ExecutionMode,
    pub(crate) prompt: Vec<u8>,
    pub(crate) environment: AdapterEnvironment,
}

impl RunRequest {
    pub fn new(
        coordinates: RunCoordinates,
        mode: ExecutionMode,
        prompt: impl Into<Vec<u8>>,
        environment: AdapterEnvironment,
    ) -> Result<Self, CoordinateError> {
        let prompt = prompt.into();
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains(&0) {
            return Err(CoordinateError::InvalidField("prompt"));
        }
        if let ExecutionMode::Resume(binding) = &mode
            && binding.scope != coordinates.scope
        {
            return Err(CoordinateError::CrossScopeResume);
        }
        Ok(Self {
            coordinates,
            mode,
            prompt,
            environment,
        })
    }
}

impl fmt::Debug for RunRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunRequest")
            .field("coordinates", &self.coordinates)
            .field("mode", &self.mode)
            .field(
                "prompt",
                &format_args!("<redacted:{} bytes>", self.prompt.len()),
            )
            .field("environment", &self.environment)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamAuthority {
    Preview,
    Authoritative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedKind {
    SessionCreated,
    SessionLoaded,
    TurnStarted,
    AssistantMessageCompleted,
    UsageUpdated,
    ProviderFault,
    TurnCompleted,
}

impl RecordedKind {
    /// Every kind this normalizer can produce, in the order a transcript
    /// produces them.
    ///
    /// Published because it is the domain of a mapping somebody else owns: a
    /// consumer that projects these onto a rendering vocabulary needs a closed
    /// set to be exhaustive over, and a set it restated by hand would be a set
    /// that silently stopped covering a kind added here.
    pub const ALL: [Self; 7] = [
        Self::SessionCreated,
        Self::SessionLoaded,
        Self::TurnStarted,
        Self::AssistantMessageCompleted,
        Self::UsageUpdated,
        Self::ProviderFault,
        Self::TurnCompleted,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionCreated => "session_created",
            Self::SessionLoaded => "session_loaded",
            Self::TurnStarted => "turn_started",
            Self::AssistantMessageCompleted => "assistant_message_completed",
            Self::UsageUpdated => "usage_updated",
            Self::ProviderFault => "provider_fault",
            Self::TurnCompleted => "turn_completed",
        }
    }
}

/// The provider item types this normalizer admits.
///
/// One member, and that is the fact rather than an oversight: the grammar
/// accepts `agent_message` and refuses every other item type by name — a tool
/// call, a reasoning summary, a patch — because a transcript that dropped the
/// items it does not model would be a strict, unannounced subset of what the
/// provider did. The enum exists so a consumer mapping items onto a rendering
/// vocabulary is exhaustive over a *declared* set, and gains a compile error
/// rather than a silent gap when a second item type is admitted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderItemKind {
    /// An assistant message.
    AgentMessage,
}

impl ProviderItemKind {
    /// Every admitted item type.
    pub const ALL: [Self; 1] = [Self::AgentMessage];

    /// The provider's own spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentMessage => "agent_message",
        }
    }

    /// Parse the provider's spelling, or nothing.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedEvent {
    pub(crate) sequence: u64,
    pub(crate) run_id: String,
    pub(crate) turn_id: String,
    pub(crate) provider_session_id: String,
    pub(crate) kind: RecordedKind,
    pub(crate) text: Option<String>,
}

impl RecordedEvent {
    pub const fn authority(&self) -> StreamAuthority {
        StreamAuthority::Authoritative
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn kind(&self) -> RecordedKind {
        self.kind
    }
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }
    pub fn provider_session_id(&self) -> &str {
        &self.provider_session_id
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedEvent {
    Preview {
        sequence: u64,
        run_id: String,
        turn_id: String,
        provider_session_id: String,
        text: String,
    },
    Recorded(RecordedEvent),
}

impl NormalizedEvent {
    pub const fn authority(&self) -> StreamAuthority {
        match self {
            Self::Preview { .. } => StreamAuthority::Preview,
            Self::Recorded(_) => StreamAuthority::Authoritative,
        }
    }
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::Preview { sequence, .. } | Self::Recorded(RecordedEvent { sequence, .. }) => {
                *sequence
            }
        }
    }
}

/// Provider-reported disposition from a fully normalized fixture transcript.
///
/// This is not an authoritative run terminal because no trusted process exit
/// or sandbox-enforcement evidence exists in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDisposition {
    Succeeded,
    Failed,
}

/// Complete, strictly normalized provider fixture transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedTranscript {
    pub(crate) binding: ResumeBinding,
    pub(crate) events: Vec<NormalizedEvent>,
    pub(crate) disposition: ProviderDisposition,
}

impl NormalizedTranscript {
    #[must_use]
    pub const fn binding(&self) -> &ResumeBinding {
        &self.binding
    }

    #[must_use]
    pub fn events(&self) -> &[NormalizedEvent] {
        &self.events
    }

    #[must_use]
    pub const fn disposition(&self) -> ProviderDisposition {
        self.disposition
    }
}

/// The offending vocabulary token of a refused event, safe to log.
///
/// A refusal must be actionable — "some event was unknown" tells an operator
/// nothing — but the line that carried it is provider output, and provider
/// output may contain prompt or workspace content. This type therefore carries
/// **only** the event's kind token, and only when that token is short and
/// drawn from the harmless character set a schema keyword uses. Anything else
/// collapses to a fixed placeholder, so no payload byte can ever reach a log
/// through an error message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownEventKind(String);

impl UnknownEventKind {
    /// Name a refused top-level event kind, e.g. `turn.interrupted`.
    pub(crate) fn event(raw: &str) -> Self {
        Self(sanitize_kind(raw))
    }

    /// Name a refused item kind, kept distinct from the top-level vocabulary
    /// because `item.started` itself is known while its item type is not.
    pub(crate) fn item(raw: &str) -> Self {
        Self(format!("item:{}", sanitize_kind(raw)))
    }

    /// Exact token, already sanitized.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownEventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Reduce an untrusted token to something safe to name, or to a placeholder.
fn sanitize_kind(raw: &str) -> String {
    if raw.is_empty() {
        return "<empty>".to_owned();
    }
    if raw.len() > MAX_EVENT_KIND_BYTES {
        // Truncating would still emit payload bytes chosen by the provider.
        return "<oversized>".to_owned();
    }
    if raw
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        raw.to_owned()
    } else {
        "<unprintable>".to_owned()
    }
}

#[derive(Clone, Debug)]
pub enum AdapterError {
    Coordinate(CoordinateError),
    ExecutionUnavailable,
    UnsafeExecutable,
    OutputTooLarge,
    InvalidUtf8,
    InvalidJson,
    /// An event kind outside the accepted vocabulary. Never a skip: a stream
    /// containing one is refused, because an adapter that ignored the events
    /// it does not understand would report a transcript it cannot vouch for.
    UnknownEvent(UnknownEventKind),
    UnknownSchema,
    EventOrder,
    SessionMismatch,
    /// The stream carried more accepted events than
    /// [`crate::MAX_STREAM_EVENTS`].
    TooManyEvents,
    /// The stream ended mid-line, so the last event cannot be proven complete.
    IncompleteFinalLine,
}

impl AdapterError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Coordinate(_) => "coordinate",
            Self::ExecutionUnavailable => "execution_unavailable",
            Self::UnsafeExecutable => "unsafe_executable",
            Self::OutputTooLarge => "output_too_large",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InvalidJson => "invalid_json",
            Self::UnknownEvent(_) => "unknown_event",
            Self::UnknownSchema => "unknown_schema",
            Self::EventOrder => "event_order",
            Self::SessionMismatch => "session_mismatch",
            Self::TooManyEvents => "too_many_events",
            Self::IncompleteFinalLine => "incomplete_final_line",
        }
    }

    /// The offending kind, when the refusal names one.
    #[must_use]
    pub const fn unknown_kind(&self) -> Option<&UnknownEventKind> {
        match self {
            Self::UnknownEvent(kind) => Some(kind),
            _ => None,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The kind token is named; the line that carried it never is.
            Self::UnknownEvent(kind) => {
                write!(formatter, "Codex adapter refused: unknown_event: {kind}")
            }
            _ => write!(formatter, "Codex adapter refused: {}", self.category()),
        }
    }
}

impl std::error::Error for AdapterError {}

/// A stream line that is not strictly valid JSON is one refusal.
///
/// The provider's transcript is untrusted input; which byte offended is a
/// detail that would only reach a log line as a fragment of a model's output.
impl From<automonique_connector_substrate::json::StrictJsonError> for AdapterError {
    fn from(_: automonique_connector_substrate::json::StrictJsonError) -> Self {
        Self::InvalidJson
    }
}

impl From<CoordinateError> for AdapterError {
    fn from(value: CoordinateError) -> Self {
        Self::Coordinate(value)
    }
}

pub(crate) fn validate_coordinate(value: &str, field: &'static str) -> Result<(), CoordinateError> {
    if value.is_empty() || value.len() > MAX_COORDINATE_BYTES || value.chars().any(char::is_control)
    {
        Err(CoordinateError::InvalidField(field))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_provider_session(value: &str) -> Result<(), CoordinateError> {
    validate_coordinate(value, "provider_session_id")?;
    if value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(CoordinateError::InvalidField("provider_session_id"))
    } else {
        Ok(())
    }
}
