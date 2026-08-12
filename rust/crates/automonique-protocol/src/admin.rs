// SPDX-License-Identifier: Elastic-2.0

//! Bounded local administration protocol for the Automonique daemon.
//!
//! Authentication is intentionally not represented in these messages. A local
//! server authenticates the Unix peer before it decodes a frame; putting a
//! bearer secret in the payload would make that boundary weaker and easier to
//! leak. Version one exposes only a read-only status query and an orderly
//! shutdown request, a local no-effect synthetic intake, and an explicit
//! fail-only reconciliation path for an ambiguously claimed synthetic run.

use std::error::Error;
use std::fmt;

use crate::codec::{
    CodecError, Envelope, MajorVersion, MessageKind, ProtocolName, RequestId, SupportedProtocol,
    VersionRange,
};
use crate::wire::{JsonValue, Message};

/// Stable protocol name for local daemon administration.
pub const ADMIN_PROTOCOL: &str = "automonique.admin";

/// Maximum canonical message bytes accepted by the local admin transport.
pub const MAX_ADMIN_CANONICAL_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of a daemon instance identifier.
pub const MAX_INSTANCE_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a local synthetic-work scope.
pub const MAX_SYNTHETIC_SCOPE_BYTES: usize = 256;

/// Maximum UTF-8 byte length of its caller-supplied idempotency key.
///
/// The scheduler derives bounded receipt keys from this coordinate, so this
/// limit intentionally leaves room for their fixed namespace prefixes.
pub const MAX_SYNTHETIC_KEY_BYTES: usize = 128;

/// Maximum task bytes accepted by the local synthetic intake.
pub const MAX_SYNTHETIC_TASK_BYTES: usize = 8 * 1024;

/// Maximum byte length of reconciliation coordinates and reasons.
pub const MAX_RECONCILIATION_FIELD_BYTES: usize = 256;

/// Maximum stable refusal-category bytes returned to an authenticated client.
pub const MAX_ADMIN_REFUSAL_CATEGORY_BYTES: usize = 64;

/// A refusal while constructing or decoding an administration message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminError {
    /// The shared envelope or canonical JSON codec refused the message.
    Codec(CodecError),
    /// The message kind is not part of this closed protocol version.
    UnknownKind,
    /// A command body was not the exact shape defined for its kind.
    InvalidBody,
    /// A response counter cannot be represented by the integer-only wire codec.
    CounterOutOfRange {
        /// Field that was outside the wire range.
        field: &'static str,
    },
    /// The instance identifier was empty, too long, or contained a control.
    InvalidInstanceId,
    /// A security-relevant daemon state spelling was not defined by this build.
    UnknownState,
}

impl AdminError {
    /// Stable category suitable for logs and refusal metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.category(),
            Self::UnknownKind => "admin_unknown_kind",
            Self::InvalidBody => "admin_invalid_body",
            Self::CounterOutOfRange { .. } => "admin_counter_out_of_range",
            Self::InvalidInstanceId => "admin_invalid_instance_id",
            Self::UnknownState => "admin_unknown_state",
        }
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => {
                write!(formatter, "administration codec refused message: {error}")
            }
            Self::UnknownKind => formatter.write_str("administration message kind is not defined"),
            Self::InvalidBody => formatter.write_str("administration message body is invalid"),
            Self::CounterOutOfRange { field } => {
                write!(
                    formatter,
                    "administration counter {field} is outside the wire range"
                )
            }
            Self::InvalidInstanceId => formatter.write_str("daemon instance identifier is invalid"),
            Self::UnknownState => formatter.write_str("daemon state is not defined"),
        }
    }
}

impl Error for AdminError {}

impl From<CodecError> for AdminError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

/// Opaque identifier for one daemon process generation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdminInstanceId(String);

impl AdminInstanceId {
    /// Validate and construct an instance identifier.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidInstanceId`] for empty, overlong, or
    /// control-character-bearing values.
    pub fn new(value: impl Into<String>) -> Result<Self, AdminError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_INSTANCE_ID_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(AdminError::InvalidInstanceId);
        }
        Ok(Self(value))
    }

    /// Borrow the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle state reported by the foreground daemon.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DaemonState {
    /// Durable state is being opened and checked.
    Starting,
    /// The daemon is ready and may accept intake.
    Ready,
    /// Intake is closed while existing work drains.
    Draining,
    /// The daemon completed its orderly shutdown.
    Stopped,
    /// A required subsystem failed and operation is refused.
    Failed,
}

impl DaemonState {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, AdminError> {
        match value {
            "starting" => Ok(Self::Starting),
            "ready" => Ok(Self::Ready),
            "draining" => Ok(Self::Draining),
            "stopped" => Ok(Self::Stopped),
            "failed" => Ok(Self::Failed),
            _ => Err(AdminError::UnknownState),
        }
    }
}

/// Commands admitted by the first local administration protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminCommand {
    /// Read a consistent daemon status snapshot.
    Status,
    /// Durably enqueue a no-effect synthetic work item.
    SubmitSynthetic,
    /// Inspect the durable evidence for one ambiguously claimed run.
    InspectReconciliation,
    /// Explicitly fail one exact old run observation under the daemon's fence.
    FailReconciliation,
    /// Stop intake and request an orderly shutdown.
    Shutdown,
}

impl AdminCommand {
    const fn kind(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::SubmitSynthetic => "submit_synthetic",
            Self::InspectReconciliation => "inspect_reconciliation",
            Self::FailReconciliation => "fail_reconciliation",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Exact old-run coordinates carried into a fail-only reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationFailure {
    run_id: u64,
    expected_generation_id: String,
    expected_lease_epoch: u64,
    expected_revision: u64,
    decision_key: String,
    reason: String,
}

impl ReconciliationFailure {
    /// Construct a bounded compare-and-set decision.
    pub fn new(
        run_id: u64,
        expected_generation_id: impl Into<String>,
        expected_lease_epoch: u64,
        expected_revision: u64,
        decision_key: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let expected_generation_id = expected_generation_id.into();
        let decision_key = decision_key.into();
        let reason = reason.into();
        if run_id == 0
            || expected_lease_epoch == 0
            || expected_revision == 0
            || !valid_coordinate(&expected_generation_id, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&decision_key, MAX_RECONCILIATION_FIELD_BYTES)
            || !valid_coordinate(&reason, MAX_RECONCILIATION_FIELD_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            run_id,
            expected_generation_id,
            expected_lease_epoch,
            expected_revision,
            decision_key,
            reason,
        })
    }

    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }
    #[must_use]
    pub fn expected_generation_id(&self) -> &str {
        &self.expected_generation_id
    }
    #[must_use]
    pub const fn expected_lease_epoch(&self) -> u64 {
        self.expected_lease_epoch
    }
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    #[must_use]
    pub fn decision_key(&self) -> &str {
        &self.decision_key
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "decision_key".to_owned(),
                JsonValue::String(self.decision_key.clone()),
            ),
            (
                "expected_generation_id".to_owned(),
                JsonValue::String(self.expected_generation_id.clone()),
            ),
            (
                "expected_lease_epoch".to_owned(),
                integer("expected_lease_epoch", self.expected_lease_epoch)?,
            ),
            (
                "expected_revision".to_owned(),
                integer("expected_revision", self.expected_revision)?,
            ),
            ("reason".to_owned(), JsonValue::String(self.reason.clone())),
            ("run_id".to_owned(), integer("run_id", self.run_id)?),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "decision_key",
                "expected_generation_id",
                "expected_lease_epoch",
                "expected_revision",
                "reason",
                "run_id",
            ],
        )?;
        Self::new(
            unsigned(body, "run_id")?,
            required_body_string(body, "expected_generation_id")?,
            unsigned(body, "expected_lease_epoch")?,
            unsigned(body, "expected_revision")?,
            required_body_string(body, "decision_key")?,
            required_body_string(body, "reason")?,
        )
    }
}

/// Bounded local work used to exercise the durable scheduler without a provider
/// or transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticSubmission {
    scope: String,
    idempotency_key: String,
    task: String,
}

impl SyntheticSubmission {
    /// Validate a synthetic intake request.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::InvalidBody`] for empty, overlong, or
    /// control-character-bearing coordinates, or for an empty/overlong task.
    pub fn new(
        scope: impl Into<String>,
        idempotency_key: impl Into<String>,
        task: impl Into<String>,
    ) -> Result<Self, AdminError> {
        let scope = scope.into();
        let idempotency_key = idempotency_key.into();
        let task = task.into();
        if !valid_coordinate(&scope, MAX_SYNTHETIC_SCOPE_BYTES)
            || !valid_coordinate(&idempotency_key, MAX_SYNTHETIC_KEY_BYTES)
            || task.is_empty()
            || task.len() > MAX_SYNTHETIC_TASK_BYTES
            || task.contains('\0')
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            scope,
            idempotency_key,
            task,
        })
    }

    /// Serialization scope used by the scheduler.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Stable caller-controlled retry key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Synthetic task text. It grants no provider or external-effect authority.
    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }

    fn to_body(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "idempotency_key".to_owned(),
                JsonValue::String(self.idempotency_key.clone()),
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
            ("task".to_owned(), JsonValue::String(self.task.clone())),
        ])
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(body, &["idempotency_key", "scope", "task"])?;
        Self::new(
            required_body_string(body, "scope")?,
            required_body_string(body, "idempotency_key")?,
            required_body_string(body, "task")?,
        )
    }
}

/// A correlated local administration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRequest {
    request_id: RequestId,
    command: AdminCommand,
    submission: Option<SyntheticSubmission>,
    reconciliation_run_id: Option<u64>,
    reconciliation_failure: Option<ReconciliationFailure>,
}

impl AdminRequest {
    /// Construct a request from a validated correlation identifier.
    #[must_use]
    pub const fn new(request_id: RequestId, command: AdminCommand) -> Self {
        Self {
            request_id,
            command,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: None,
        }
    }

    /// Construct a durable synthetic-intake request.
    #[must_use]
    pub const fn submit(request_id: RequestId, submission: SyntheticSubmission) -> Self {
        Self {
            request_id,
            command: AdminCommand::SubmitSynthetic,
            submission: Some(submission),
            reconciliation_run_id: None,
            reconciliation_failure: None,
        }
    }

    /// Construct a read-only reconciliation inspection.
    pub fn inspect_reconciliation(request_id: RequestId, run_id: u64) -> Result<Self, AdminError> {
        if run_id == 0 {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self {
            request_id,
            command: AdminCommand::InspectReconciliation,
            submission: None,
            reconciliation_run_id: Some(run_id),
            reconciliation_failure: None,
        })
    }

    /// Construct an exact fail-only reconciliation decision.
    #[must_use]
    pub const fn fail_reconciliation(
        request_id: RequestId,
        failure: ReconciliationFailure,
    ) -> Self {
        Self {
            request_id,
            command: AdminCommand::FailReconciliation,
            submission: None,
            reconciliation_run_id: None,
            reconciliation_failure: Some(failure),
        }
    }

    /// Correlation identifier copied into the response.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Requested command.
    #[must_use]
    pub const fn command(&self) -> AdminCommand {
        self.command
    }

    /// Synthetic work body, present only for [`AdminCommand::SubmitSynthetic`].
    #[must_use]
    pub const fn submission(&self) -> Option<&SyntheticSubmission> {
        self.submission.as_ref()
    }

    #[must_use]
    pub const fn reconciliation_run_id(&self) -> Option<u64> {
        self.reconciliation_run_id
    }

    #[must_use]
    pub const fn reconciliation_failure(&self) -> Option<&ReconciliationFailure> {
        self.reconciliation_failure.as_ref()
    }

    /// Encode this request as a canonical local-protocol message.
    ///
    /// # Errors
    ///
    /// Returns a shared codec error only if a compile-time protocol literal no
    /// longer satisfies the shared envelope grammar.
    pub fn to_message(&self) -> Result<Message, AdminError> {
        let body = match (
            self.command,
            &self.submission,
            self.reconciliation_run_id,
            &self.reconciliation_failure,
        ) {
            (AdminCommand::SubmitSynthetic, Some(submission), None, None) => submission.to_body(),
            (AdminCommand::InspectReconciliation, None, Some(run_id), None) => {
                JsonValue::Object(vec![("run_id".to_owned(), integer("run_id", run_id)?)])
            }
            (AdminCommand::FailReconciliation, None, None, Some(failure)) => failure.to_body()?,
            (AdminCommand::Status | AdminCommand::Shutdown, None, None, None) => {
                JsonValue::Object(Vec::new())
            }
            _ => return Err(AdminError::InvalidBody),
        };
        Ok(Message::new(
            envelope(self.request_id.clone(), self.command.kind())?,
            body,
        ))
    }

    /// Decode and admit a request against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown versions, unknown command kinds, and every nonempty or
    /// non-object command body.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AdminError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        match message.envelope().kind().as_str() {
            "submit_synthetic" => Ok(Self::submit(
                message.envelope().request_id().clone(),
                SyntheticSubmission::from_body(message.body())?,
            )),
            "inspect_reconciliation" => {
                exact_fields(message.body(), &["run_id"])?;
                Self::inspect_reconciliation(
                    message.envelope().request_id().clone(),
                    unsigned(message.body(), "run_id")?,
                )
            }
            "fail_reconciliation" => Ok(Self::fail_reconciliation(
                message.envelope().request_id().clone(),
                ReconciliationFailure::from_body(message.body())?,
            )),
            "status" | "shutdown" => {
                if !matches!(message.body(), JsonValue::Object(entries) if entries.is_empty()) {
                    return Err(AdminError::InvalidBody);
                }
                let command = if message.envelope().kind().as_str() == "status" {
                    AdminCommand::Status
                } else {
                    AdminCommand::Shutdown
                };
                Ok(Self::new(message.envelope().request_id().clone(), command))
            }
            _ => Err(AdminError::UnknownKind),
        }
    }
}

/// One consistent daemon status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonStatus {
    instance_id: AdminInstanceId,
    state: DaemonState,
    generation: u64,
    event_cursor: u64,
    inbox_pending: u64,
    outbox_pending: u64,
    running: u64,
    accepting_intake: bool,
}

impl DaemonStatus {
    /// Construct a snapshot, refusing counters the integer-only wire cannot carry.
    ///
    /// # Errors
    ///
    /// Returns [`AdminError::CounterOutOfRange`] for the first value above
    /// `i64::MAX`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: AdminInstanceId,
        state: DaemonState,
        generation: u64,
        event_cursor: u64,
        inbox_pending: u64,
        outbox_pending: u64,
        running: u64,
        accepting_intake: bool,
    ) -> Result<Self, AdminError> {
        for (field, value) in [
            ("generation", generation),
            ("event_cursor", event_cursor),
            ("inbox_pending", inbox_pending),
            ("outbox_pending", outbox_pending),
            ("running", running),
        ] {
            i64::try_from(value).map_err(|_| AdminError::CounterOutOfRange { field })?;
        }
        Ok(Self {
            instance_id,
            state,
            generation,
            event_cursor,
            inbox_pending,
            outbox_pending,
            running,
            accepting_intake,
        })
    }

    /// Daemon instance identifier.
    #[must_use]
    pub const fn instance_id(&self) -> &AdminInstanceId {
        &self.instance_id
    }

    /// Lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DaemonState {
        self.state
    }

    /// Monotonic persisted daemon generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Latest durable global event position.
    #[must_use]
    pub const fn event_cursor(&self) -> u64 {
        self.event_cursor
    }

    /// Durable inbox entries awaiting admission.
    #[must_use]
    pub const fn inbox_pending(&self) -> u64 {
        self.inbox_pending
    }

    /// Durable effects awaiting delivery or reconciliation.
    #[must_use]
    pub const fn outbox_pending(&self) -> u64 {
        self.outbox_pending
    }

    /// Runs with nonterminal durable state.
    #[must_use]
    pub const fn running(&self) -> u64 {
        self.running
    }

    /// Whether new intake is currently admitted.
    #[must_use]
    pub const fn accepting_intake(&self) -> bool {
        self.accepting_intake
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "accepting_intake".to_owned(),
                JsonValue::Bool(self.accepting_intake),
            ),
            (
                "event_cursor".to_owned(),
                integer("event_cursor", self.event_cursor)?,
            ),
            (
                "generation".to_owned(),
                integer("generation", self.generation)?,
            ),
            (
                "inbox_pending".to_owned(),
                integer("inbox_pending", self.inbox_pending)?,
            ),
            (
                "instance_id".to_owned(),
                JsonValue::String(self.instance_id.as_str().to_owned()),
            ),
            (
                "outbox_pending".to_owned(),
                integer("outbox_pending", self.outbox_pending)?,
            ),
            ("running".to_owned(), integer("running", self.running)?),
            (
                "state".to_owned(),
                JsonValue::String(self.state.as_str().to_owned()),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        const FIELDS: [&str; 8] = [
            "accepting_intake",
            "event_cursor",
            "generation",
            "inbox_pending",
            "instance_id",
            "outbox_pending",
            "running",
            "state",
        ];
        let JsonValue::Object(entries) = body else {
            return Err(AdminError::InvalidBody);
        };
        if entries.len() != FIELDS.len()
            || !FIELDS
                .iter()
                .all(|field| entries.iter().any(|(name, _)| name == field))
        {
            return Err(AdminError::InvalidBody);
        }
        let accepting_intake = match body.get("accepting_intake") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AdminError::InvalidBody),
        };
        let instance_id = body
            .get("instance_id")
            .and_then(JsonValue::as_str)
            .ok_or(AdminError::InvalidBody)?;
        let state = body
            .get("state")
            .and_then(JsonValue::as_str)
            .ok_or(AdminError::InvalidBody)?;
        Self::new(
            AdminInstanceId::new(instance_id)?,
            DaemonState::parse(state)?,
            unsigned(body, "generation")?,
            unsigned(body, "event_cursor")?,
            unsigned(body, "inbox_pending")?,
            unsigned(body, "outbox_pending")?,
            unsigned(body, "running")?,
            accepting_intake,
        )
    }
}

/// Bounded durable summary used to authorize a later exact reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminReconciliationEvidence {
    run_id: u64,
    scope: String,
    generation_id: String,
    lease_epoch: u64,
    run_revision: u64,
    terminal_payload_present: bool,
    outbox_count: u64,
}

/// Redacted stable refusal category for a correlated admin operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRefusalCategory(String);

impl AdminRefusalCategory {
    pub fn new(value: impl Into<String>) -> Result<Self, AdminError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ADMIN_REFUSAL_CATEGORY_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AdminError::InvalidBody);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AdminReconciliationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: u64,
        scope: impl Into<String>,
        generation_id: impl Into<String>,
        lease_epoch: u64,
        run_revision: u64,
        terminal_payload_present: bool,
        outbox_count: u64,
    ) -> Result<Self, AdminError> {
        let scope = scope.into();
        let generation_id = generation_id.into();
        if run_id == 0
            || lease_epoch == 0
            || run_revision == 0
            || !valid_coordinate(&scope, MAX_SYNTHETIC_SCOPE_BYTES)
            || !valid_coordinate(&generation_id, MAX_RECONCILIATION_FIELD_BYTES)
        {
            return Err(AdminError::InvalidBody);
        }
        i64::try_from(outbox_count).map_err(|_| AdminError::CounterOutOfRange {
            field: "outbox_count",
        })?;
        Ok(Self {
            run_id,
            scope,
            generation_id,
            lease_epoch,
            run_revision,
            terminal_payload_present,
            outbox_count,
        })
    }

    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
    #[must_use]
    pub const fn run_revision(&self) -> u64 {
        self.run_revision
    }
    #[must_use]
    pub const fn terminal_payload_present(&self) -> bool {
        self.terminal_payload_present
    }
    #[must_use]
    pub const fn outbox_count(&self) -> u64 {
        self.outbox_count
    }

    fn to_body(&self) -> Result<JsonValue, AdminError> {
        Ok(JsonValue::Object(vec![
            (
                "generation_id".to_owned(),
                JsonValue::String(self.generation_id.clone()),
            ),
            (
                "lease_epoch".to_owned(),
                integer("lease_epoch", self.lease_epoch)?,
            ),
            (
                "outbox_count".to_owned(),
                integer("outbox_count", self.outbox_count)?,
            ),
            ("run_id".to_owned(), integer("run_id", self.run_id)?),
            (
                "run_revision".to_owned(),
                integer("run_revision", self.run_revision)?,
            ),
            ("scope".to_owned(), JsonValue::String(self.scope.clone())),
            (
                "terminal_payload_present".to_owned(),
                JsonValue::Bool(self.terminal_payload_present),
            ),
        ]))
    }

    fn from_body(body: &JsonValue) -> Result<Self, AdminError> {
        exact_fields(
            body,
            &[
                "generation_id",
                "lease_epoch",
                "outbox_count",
                "run_id",
                "run_revision",
                "scope",
                "terminal_payload_present",
            ],
        )?;
        let terminal_payload_present = match body.get("terminal_payload_present") {
            Some(JsonValue::Bool(value)) => *value,
            _ => return Err(AdminError::InvalidBody),
        };
        Self::new(
            unsigned(body, "run_id")?,
            required_body_string(body, "scope")?,
            required_body_string(body, "generation_id")?,
            unsigned(body, "lease_epoch")?,
            unsigned(body, "run_revision")?,
            terminal_payload_present,
            unsigned(body, "outbox_count")?,
        )
    }
}

/// A correlated response from the local daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminResponse {
    /// Current durable status.
    Status {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Consistent status snapshot.
        status: DaemonStatus,
    },
    /// A synthetic work item is durable, or the exact retry was replayed.
    SyntheticAccepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
        /// Durable inbox identity.
        inbox_id: u64,
        /// Whether an identical stable-key submission already existed.
        duplicate: bool,
    },
    /// Durable reconciliation evidence for one run.
    ReconciliationInspected {
        request_id: RequestId,
        evidence: AdminReconciliationEvidence,
    },
    /// One explicit failure decision was committed or exactly replayed.
    ReconciliationFailed {
        request_id: RequestId,
        run_event_id: u64,
        inbox_event_id: u64,
        outbox_id: u64,
        duplicate: bool,
    },
    /// The request was definitely refused before a successful mutation.
    Refused {
        request_id: RequestId,
        category: AdminRefusalCategory,
    },
    /// The daemon accepted an orderly-shutdown request and closed intake.
    ShutdownAccepted {
        /// Correlation identifier from the request.
        request_id: RequestId,
    },
}

impl AdminResponse {
    /// Correlation identifier from the request.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        match self {
            Self::Status { request_id, .. }
            | Self::SyntheticAccepted { request_id, .. }
            | Self::ReconciliationInspected { request_id, .. }
            | Self::ReconciliationFailed { request_id, .. }
            | Self::Refused { request_id, .. }
            | Self::ShutdownAccepted { request_id } => request_id,
        }
    }

    /// Encode the response as a canonical message.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal if a counter or compile-time envelope literal is
    /// outside the protocol bounds.
    pub fn to_message(&self) -> Result<Message, AdminError> {
        match self {
            Self::Status { request_id, status } => Ok(Message::new(
                envelope(request_id.clone(), "status_result")?,
                status.to_body()?,
            )),
            Self::SyntheticAccepted {
                request_id,
                inbox_id,
                duplicate,
            } => Ok(Message::new(
                envelope(request_id.clone(), "synthetic_accepted")?,
                JsonValue::Object(vec![
                    ("duplicate".to_owned(), JsonValue::Bool(*duplicate)),
                    ("inbox_id".to_owned(), integer("inbox_id", *inbox_id)?),
                ]),
            )),
            Self::ReconciliationInspected {
                request_id,
                evidence,
            } => Ok(Message::new(
                envelope(request_id.clone(), "reconciliation_inspected")?,
                evidence.to_body()?,
            )),
            Self::ReconciliationFailed {
                request_id,
                run_event_id,
                inbox_event_id,
                outbox_id,
                duplicate,
            } => Ok(Message::new(
                envelope(request_id.clone(), "reconciliation_failed")?,
                JsonValue::Object(vec![
                    ("duplicate".to_owned(), JsonValue::Bool(*duplicate)),
                    (
                        "inbox_event_id".to_owned(),
                        integer("inbox_event_id", *inbox_event_id)?,
                    ),
                    ("outbox_id".to_owned(), integer("outbox_id", *outbox_id)?),
                    (
                        "run_event_id".to_owned(),
                        integer("run_event_id", *run_event_id)?,
                    ),
                ]),
            )),
            Self::Refused {
                request_id,
                category,
            } => Ok(Message::new(
                envelope(request_id.clone(), "refused")?,
                JsonValue::Object(vec![(
                    "category".to_owned(),
                    JsonValue::String(category.as_str().to_owned()),
                )]),
            )),
            Self::ShutdownAccepted { request_id } => Ok(Message::new(
                envelope(request_id.clone(), "shutdown_accepted")?,
                JsonValue::Object(Vec::new()),
            )),
        }
    }

    /// Decode and admit a response against the exact first protocol version.
    ///
    /// # Errors
    ///
    /// Refuses unknown response kinds and bodies that are not exact.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, AdminError> {
        let message = Message::from_canonical_bytes_admitted(payload, &[supported_protocol()?])?;
        let request_id = message.envelope().request_id().clone();
        match message.envelope().kind().as_str() {
            "status_result" => Ok(Self::Status {
                request_id,
                status: DaemonStatus::from_body(message.body())?,
            }),
            "synthetic_accepted" => {
                exact_fields(message.body(), &["duplicate", "inbox_id"])?;
                let duplicate = match message.body().get("duplicate") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                Ok(Self::SyntheticAccepted {
                    request_id,
                    inbox_id: unsigned(message.body(), "inbox_id")?,
                    duplicate,
                })
            }
            "reconciliation_inspected" => Ok(Self::ReconciliationInspected {
                request_id,
                evidence: AdminReconciliationEvidence::from_body(message.body())?,
            }),
            "reconciliation_failed" => {
                exact_fields(
                    message.body(),
                    &["duplicate", "inbox_event_id", "outbox_id", "run_event_id"],
                )?;
                let duplicate = match message.body().get("duplicate") {
                    Some(JsonValue::Bool(value)) => *value,
                    _ => return Err(AdminError::InvalidBody),
                };
                Ok(Self::ReconciliationFailed {
                    request_id,
                    run_event_id: unsigned(message.body(), "run_event_id")?,
                    inbox_event_id: unsigned(message.body(), "inbox_event_id")?,
                    outbox_id: unsigned(message.body(), "outbox_id")?,
                    duplicate,
                })
            }
            "refused" => {
                exact_fields(message.body(), &["category"])?;
                Ok(Self::Refused {
                    request_id,
                    category: AdminRefusalCategory::new(required_body_string(
                        message.body(),
                        "category",
                    )?)?,
                })
            }
            "shutdown_accepted" => {
                if !matches!(message.body(), JsonValue::Object(entries) if entries.is_empty()) {
                    return Err(AdminError::InvalidBody);
                }
                Ok(Self::ShutdownAccepted { request_id })
            }
            _ => Err(AdminError::UnknownKind),
        }
    }
}

fn envelope(request_id: RequestId, kind: &str) -> Result<Envelope, AdminError> {
    Ok(Envelope::new(
        ProtocolName::new(ADMIN_PROTOCOL)?,
        MajorVersion::FIRST,
        request_id,
        MessageKind::new(kind)?,
    ))
}

fn supported_protocol() -> Result<SupportedProtocol, AdminError> {
    Ok(SupportedProtocol::new(
        ProtocolName::new(ADMIN_PROTOCOL)?,
        VersionRange::new(MajorVersion::FIRST, MajorVersion::FIRST)?,
    ))
}

fn integer(field: &'static str, value: u64) -> Result<JsonValue, AdminError> {
    i64::try_from(value)
        .map(JsonValue::Integer)
        .map_err(|_| AdminError::CounterOutOfRange { field })
}

fn unsigned(body: &JsonValue, field: &'static str) -> Result<u64, AdminError> {
    let value = body
        .get(field)
        .and_then(JsonValue::as_integer)
        .ok_or(AdminError::InvalidBody)?;
    u64::try_from(value).map_err(|_| AdminError::InvalidBody)
}

fn valid_coordinate(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn exact_fields(body: &JsonValue, fields: &[&str]) -> Result<(), AdminError> {
    let JsonValue::Object(entries) = body else {
        return Err(AdminError::InvalidBody);
    };
    if entries.len() != fields.len()
        || !fields
            .iter()
            .all(|field| entries.iter().any(|(name, _)| name == field))
    {
        return Err(AdminError::InvalidBody);
    }
    Ok(())
}

fn required_body_string(body: &JsonValue, field: &'static str) -> Result<String, AdminError> {
    body.get(field)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or(AdminError::InvalidBody)
}
