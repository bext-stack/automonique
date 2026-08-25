// SPDX-License-Identifier: Elastic-2.0

//! Federated operator platform contract shared by every Automonique client.
//!
//! The contract names the authority that owns a resource separately from its
//! kind and identifier. A projection therefore cannot accidentally present a
//! provider observation as Automonique state, or a queued global job as local
//! execution. Transport is deliberately absent from request and response
//! values: local Unix sockets and remote HTTPS/WebSocket endpoints carry the
//! same values and differ only in framing and authentication.

use core::fmt;

use crate::primitives::{BoundedString, EpochMillis, IdDomain, OpaqueId, Revision, ValueError};

/// Stable protocol name.
pub const PLATFORM_PROTOCOL: &str = "automonique.platform";
/// Stable version-one schema identifier.
pub const PLATFORM_SCHEMA_V1: &str = "automonique.platform/v1";
/// Largest identifier, cursor topic, action parameter, or explanation.
pub const MAX_PLATFORM_FIELD_BYTES: usize = 256;
/// Largest free-form parameter accepted by one typed platform action.
pub const MAX_PLATFORM_PARAMETER_BYTES: usize = 64 * 1024;
/// Largest number of resources in a snapshot request or response.
pub const MAX_SNAPSHOT_RESOURCES: usize = 512;
/// Largest number of ordered events returned in one subscription page.
pub const MAX_SUBSCRIPTION_EVENTS: usize = 512;
/// Largest number of sanitized session-history events returned in one page.
pub const MAX_SESSION_HISTORY_EVENTS: usize = 512;
/// Largest display text retained in one mobile-safe history event.
pub const MAX_SESSION_HISTORY_TEXT_BYTES: usize = 512;
/// Largest number of service methods advertised by one endpoint.
pub const MAX_CAPABILITY_METHODS: usize = 32;
/// Maximum transport projections advertised by one endpoint.
pub const MAX_CAPABILITY_TRANSPORTS: usize = PlatformTransport::ALL.len();
/// Default and maximum lifetime of one interactive controller lease.
pub const CONTROL_LEASE_TTL_MILLIS: i64 = 30_000;

/// One temporary projection retained while existing clients move to platform
/// v1. The removal test is a stable executable-test name, not a calendar date.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityAdapter {
    pub name: &'static str,
    pub consumers: &'static [&'static str],
    pub removal_test: &'static str,
}

/// Complete Automonique-local compatibility inventory at the v1 boundary.
/// Cross-repository adapters are inventoried by their owning repositories.
pub const COMPATIBILITY_ADAPTERS: [CompatibilityAdapter; 3] = [
    CompatibilityAdapter {
        name: "admin_to_platform_v1",
        consumers: &["daemon_cli", "web_entry"],
        removal_test: "platform_v1_clients_cover_admin_status_and_control",
    },
    CompatibilityAdapter {
        name: "runs_to_platform_v1",
        consumers: &["typescript_sdk", "web_entry"],
        removal_test: "platform_v1_clients_cover_run_reads_and_actions",
    },
    CompatibilityAdapter {
        name: "progress_to_platform_v1",
        consumers: &["chat_bridges", "typescript_sdk", "web_entry"],
        removal_test: "platform_v1_clients_resume_ordered_events",
    },
];

/// Opaque resource identity domain.
#[derive(Clone, Copy, Debug)]
pub struct ResourceIdDomain;
impl IdDomain for ResourceIdDomain {}
/// Opaque idempotency-key domain.
#[derive(Clone, Copy, Debug)]
pub struct IdempotencyKeyDomain;
impl IdDomain for IdempotencyKeyDomain {}
/// Opaque receipt identity domain.
#[derive(Clone, Copy, Debug)]
pub struct ReceiptIdDomain;
impl IdDomain for ReceiptIdDomain {}
/// Opaque client identity domain.
#[derive(Clone, Copy, Debug)]
pub struct ClientIdDomain;
impl IdDomain for ClientIdDomain {}
/// Opaque control-lease identity domain.
#[derive(Clone, Copy, Debug)]
pub struct ControlLeaseIdDomain;
impl IdDomain for ControlLeaseIdDomain {}

/// A resource identifier meaningful only with its authority and kind.
pub type ResourceId = OpaqueId<ResourceIdDomain, MAX_PLATFORM_FIELD_BYTES>;
/// A retry key whose repeated execution must resolve to one receipt.
pub type IdempotencyKey = OpaqueId<IdempotencyKeyDomain, MAX_PLATFORM_FIELD_BYTES>;
/// Durable action receipt identifier.
pub type ReceiptId = OpaqueId<ReceiptIdDomain, MAX_PLATFORM_FIELD_BYTES>;
/// Client instance participating in attach and control operations.
pub type ClientId = OpaqueId<ClientIdDomain, MAX_PLATFORM_FIELD_BYTES>;
/// Exclusive interactive-control lease identifier.
pub type ControlLeaseId = OpaqueId<ControlLeaseIdDomain, MAX_PLATFORM_FIELD_BYTES>;
/// Bounded cursor topic.
pub type CursorTopic = BoundedString<MAX_PLATFORM_FIELD_BYTES>;
/// Bounded action parameter or human-readable refusal explanation.
pub type PlatformText = BoundedString<MAX_PLATFORM_FIELD_BYTES>;
/// Sanitized display text carried by session history. Raw provider payloads,
/// prompts, tool inputs, and credentials have no representation in this type.
pub type SessionHistoryText = BoundedString<MAX_SESSION_HISTORY_TEXT_BYTES>;
/// Bounded free-form action input. Identifiers and display text retain the
/// much smaller [`MAX_PLATFORM_FIELD_BYTES`] limit.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlatformParameter(String);

impl PlatformParameter {
    pub const MAX_BYTES: usize = MAX_PLATFORM_PARAMETER_BYTES;

    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ValueError::TooLong {
                max_bytes: Self::MAX_BYTES,
                actual_bytes: value.len(),
            });
        }
        if value.contains('\0') {
            return Err(ValueError::ControlCharacter);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for PlatformParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// System whose evidence is authoritative for a resource.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceAuthority {
    /// Global jobs, release approvals, and registered nodes.
    AiOperations,
    /// Local execution, sessions, sandboxes, credentials, and control leases.
    Automonique,
    /// Repository, issue, pull-request, and workflow state.
    GitHub,
    /// Provider account, model catalogue, and measured availability.
    Provider,
    /// Client-local presentation or connection state.
    Client,
}

impl ResourceAuthority {
    /// Every version-one spelling in declaration order.
    pub const ALL: [Self; 5] = [
        Self::AiOperations,
        Self::Automonique,
        Self::GitHub,
        Self::Provider,
        Self::Client,
    ];

    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AiOperations => "ai_operations",
            Self::Automonique => "automonique",
            Self::GitHub => "github",
            Self::Provider => "provider",
            Self::Client => "client",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "resource_authority")
    }
}

/// Closed resource vocabulary projected by the platform.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    Job,
    Release,
    Node,
    Run,
    Session,
    Approval,
    Sandbox,
    Credential,
    Repository,
    Issue,
    PullRequest,
    Workflow,
    ProviderAccount,
    Model,
    Client,
    ControlLease,
    Receipt,
}

impl ResourceKind {
    /// Every version-one spelling in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Job,
        Self::Release,
        Self::Node,
        Self::Run,
        Self::Session,
        Self::Approval,
        Self::Sandbox,
        Self::Credential,
        Self::Repository,
        Self::Issue,
        Self::PullRequest,
        Self::Workflow,
        Self::ProviderAccount,
        Self::Model,
        Self::Client,
        Self::ControlLease,
        Self::Receipt,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Job => "job",
            Self::Release => "release",
            Self::Node => "node",
            Self::Run => "run",
            Self::Session => "session",
            Self::Approval => "approval",
            Self::Sandbox => "sandbox",
            Self::Credential => "credential",
            Self::Repository => "repository",
            Self::Issue => "issue",
            Self::PullRequest => "pull_request",
            Self::Workflow => "workflow",
            Self::ProviderAccount => "provider_account",
            Self::Model => "model",
            Self::Client => "client",
            Self::ControlLease => "control_lease",
            Self::Receipt => "receipt",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "resource_kind")
    }
}

/// Authority-qualified resource coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceCoordinate {
    pub authority: ResourceAuthority,
    pub kind: ResourceKind,
    pub id: ResourceId,
}

impl ResourceCoordinate {
    #[must_use]
    pub const fn new(authority: ResourceAuthority, kind: ResourceKind, id: ResourceId) -> Self {
        Self {
            authority,
            kind,
            id,
        }
    }
}

/// Confidence a client may place in an observation at its displayed time.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
}

impl FreshnessState {
    pub const ALL: [Self; 3] = [Self::Fresh, Self::Stale, Self::Unknown];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "freshness_state")
    }
}

/// Revision and observation time attached to every projected resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Freshness {
    pub state: FreshnessState,
    pub observed_at: EpochMillis,
    pub revision: Revision,
}

/// Resume coordinate for one authority-owned event topic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformCursor {
    pub authority: ResourceAuthority,
    pub topic: CursorTopic,
    pub sequence: Revision,
}

/// Version-one operation names. Only `execute` and control methods mutate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlatformMethod {
    Capabilities,
    Snapshot,
    Subscribe,
    Execute,
    GetReceipt,
    ListSessions,
    Attach,
    Detach,
    ClaimControl,
    ReleaseControl,
    SessionHistorySnapshot,
    SessionHistoryPage,
}

impl PlatformMethod {
    pub const ALL: [Self; 12] = [
        Self::Capabilities,
        Self::Snapshot,
        Self::Subscribe,
        Self::Execute,
        Self::GetReceipt,
        Self::ListSessions,
        Self::Attach,
        Self::Detach,
        Self::ClaimControl,
        Self::ReleaseControl,
        Self::SessionHistorySnapshot,
        Self::SessionHistoryPage,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Snapshot => "snapshot",
            Self::Subscribe => "subscribe",
            Self::Execute => "execute",
            Self::GetReceipt => "get_receipt",
            Self::ListSessions => "list_sessions",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::ClaimControl => "claim_control",
            Self::ReleaseControl => "release_control",
            Self::SessionHistorySnapshot => "session_history_snapshot",
            Self::SessionHistoryPage => "session_history_page",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "platform_method")
    }
}

/// Evidence class retained by the normalized history projection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionHistoryEvidence {
    Authoritative,
    Synthetic,
}

impl SessionHistoryEvidence {
    pub const ALL: [Self; 2] = [Self::Authoritative, Self::Synthetic];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Synthetic => "synthetic",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "session_history_evidence")
    }
}

/// Speaker of one sanitized retained message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionHistoryRole {
    Assistant,
    User,
}

impl SessionHistoryRole {
    pub const ALL: [Self; 2] = [Self::Assistant, Self::User];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assistant => "assistant",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "session_history_role")
    }
}

/// Public lifecycle of one tool step. Tool input and output are absent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionHistoryToolState {
    Pending,
    InProgress,
    Completed,
    Error,
}

impl SessionHistoryToolState {
    pub const ALL: [Self; 4] = [
        Self::Pending,
        Self::InProgress,
        Self::Completed,
        Self::Error,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(
            &Self::ALL,
            value,
            Self::as_str,
            "session_history_tool_state",
        )
    }
}

/// Public run state derived only from the runner's closed terminal vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionHistoryRunState {
    Started,
    CancelRequested,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl SessionHistoryRunState {
    pub const ALL: [Self; 6] = [
        Self::Started,
        Self::CancelRequested,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::CancelRequested => "cancel_requested",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "session_history_run_state")
    }
}

/// Closed source class for an event this schema intentionally does not expose.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionHistoryUnknownSource {
    AdapterEvent,
    SimulationEvent,
}

impl SessionHistoryUnknownSource {
    pub const ALL: [Self; 2] = [Self::AdapterEvent, Self::SimulationEvent];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterEvent => "adapter_event",
            Self::SimulationEvent => "simulation_event",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(
            &Self::ALL,
            value,
            Self::as_str,
            "session_history_unknown_source",
        )
    }
}

/// Mobile-safe projection of one hash-chained runner event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionHistoryEvent {
    Message {
        cursor: u64,
        at: EpochMillis,
        evidence: SessionHistoryEvidence,
        role: SessionHistoryRole,
        text: SessionHistoryText,
        truncated: bool,
    },
    ToolState {
        cursor: u64,
        at: EpochMillis,
        evidence: SessionHistoryEvidence,
        state: SessionHistoryToolState,
        label: Option<SessionHistoryText>,
        truncated: bool,
    },
    RunState {
        cursor: u64,
        at: EpochMillis,
        state: SessionHistoryRunState,
    },
    Unknown {
        cursor: u64,
        at: EpochMillis,
        source: SessionHistoryUnknownSource,
    },
}

impl SessionHistoryEvent {
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        match self {
            Self::Message { cursor, .. }
            | Self::ToolState { cursor, .. }
            | Self::RunState { cursor, .. }
            | Self::Unknown { cursor, .. } => *cursor,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHistorySnapshotRequest {
    pub session: ResourceCoordinate,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHistoryPageRequest {
    pub session: ResourceCoordinate,
    pub after: u64,
    pub limit: u16,
}

fn validate_history_request(session: &ResourceCoordinate, limit: u16) -> Result<(), PlatformError> {
    if session.authority != ResourceAuthority::Automonique || session.kind != ResourceKind::Session
    {
        return Err(PlatformError::AuthorityMismatch);
    }
    if limit == 0 || usize::from(limit) > MAX_SESSION_HISTORY_EVENTS {
        return Err(PlatformError::HistoryLimitOutOfRange);
    }
    Ok(())
}

impl SessionHistorySnapshotRequest {
    pub fn new(session: ResourceCoordinate, limit: u16) -> Result<Self, PlatformError> {
        validate_history_request(&session, limit)?;
        Ok(Self { session, limit })
    }
}

impl SessionHistoryPageRequest {
    pub fn new(session: ResourceCoordinate, after: u64, limit: u16) -> Result<Self, PlatformError> {
        validate_history_request(&session, limit)?;
        Ok(Self {
            session,
            after,
            limit,
        })
    }
}

/// One exclusive-cursor, gap-free page. Every retained source event has one
/// projection, including `Unknown`, so cursor advancement cannot hide a gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHistoryPage {
    pub session: ResourceCoordinate,
    pub requested_limit: u16,
    pub applied_limit: u16,
    pub from_cursor: u64,
    pub terminal_cursor: u64,
    pub has_more: bool,
    pub events: Vec<SessionHistoryEvent>,
}

impl SessionHistoryPage {
    pub fn new(
        session: ResourceCoordinate,
        requested_limit: u16,
        applied_limit: u16,
        from_cursor: u64,
        terminal_cursor: u64,
        has_more: bool,
        events: Vec<SessionHistoryEvent>,
    ) -> Result<Self, PlatformError> {
        validate_history_request(&session, requested_limit)?;
        validate_history_request(&session, applied_limit)?;
        if applied_limit > requested_limit
            || events.len() > usize::from(applied_limit)
            || terminal_cursor < from_cursor
        {
            return Err(PlatformError::HistoryPageInvalid);
        }
        let mut previous = from_cursor;
        for event in &events {
            let cursor = event.cursor();
            if cursor <= previous || cursor > terminal_cursor {
                return Err(PlatformError::HistoryPageInvalid);
            }
            previous = cursor;
        }
        if events
            .last()
            .map_or(from_cursor, SessionHistoryEvent::cursor)
            != terminal_cursor
        {
            return Err(PlatformError::HistoryPageInvalid);
        }
        Ok(Self {
            session,
            requested_limit,
            applied_limit,
            from_cursor,
            terminal_cursor,
            has_more,
            events,
        })
    }
}

/// Explicit retention refusal. It never carries a partial event page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionHistoryResync {
    pub session: ResourceCoordinate,
    pub snapshot_from: u64,
    pub snapshot_to: u64,
}

impl SessionHistoryResync {
    pub fn new(
        session: ResourceCoordinate,
        snapshot_from: u64,
        snapshot_to: u64,
    ) -> Result<Self, PlatformError> {
        validate_history_request(&session, 1)?;
        if snapshot_from > snapshot_to {
            return Err(PlatformError::HistoryPageInvalid);
        }
        Ok(Self {
            session,
            snapshot_from,
            snapshot_to,
        })
    }
}

/// Transport projections required to preserve platform semantics.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlatformTransport {
    LocalUnix,
    RemoteHttps,
    RemoteWebSocket,
}

impl PlatformTransport {
    pub const ALL: [Self; 3] = [Self::LocalUnix, Self::RemoteHttps, Self::RemoteWebSocket];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalUnix => "local_unix",
            Self::RemoteHttps => "remote_https",
            Self::RemoteWebSocket => "remote_websocket",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "platform_transport")
    }
}

/// Stable actions admitted through the single public mutation method.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PlatformAction {
    StartRun,
    StopRun,
    DecideApproval,
    /// Submit a new free-form request into the node's durable intake.
    SubmitRequest,
    /// Submit a new turn explicitly bound to one retained provider session.
    FollowUp,
    /// Inject input into the active turn named by an exclusive control lease.
    Steer,
    SubmitJob,
    ApproveRelease,
    RegisterNode,
}

impl PlatformAction {
    pub const ALL: [Self; 9] = [
        Self::StartRun,
        Self::StopRun,
        Self::DecideApproval,
        Self::SubmitRequest,
        Self::FollowUp,
        Self::Steer,
        Self::SubmitJob,
        Self::ApproveRelease,
        Self::RegisterNode,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartRun => "start_run",
            Self::StopRun => "stop_run",
            Self::DecideApproval => "decide_approval",
            Self::SubmitRequest => "submit_request",
            Self::FollowUp => "follow_up",
            Self::Steer => "steer",
            Self::SubmitJob => "submit_job",
            Self::ApproveRelease => "approve_release",
            Self::RegisterNode => "register_node",
        }
    }

    /// Authority that alone may accept this action.
    #[must_use]
    pub const fn authority(self) -> ResourceAuthority {
        match self {
            Self::SubmitJob | Self::ApproveRelease | Self::RegisterNode => {
                ResourceAuthority::AiOperations
            }
            Self::StartRun
            | Self::StopRun
            | Self::DecideApproval
            | Self::SubmitRequest
            | Self::FollowUp
            | Self::Steer => ResourceAuthority::Automonique,
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "platform_action")
    }
}

/// Durable outcome. `Unknown` is never equivalent to rejection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReceiptOutcome {
    Accepted,
    Completed,
    Rejected,
    Conflict,
    Unknown,
    ResyncRequired,
}

impl ReceiptOutcome {
    pub const ALL: [Self; 6] = [
        Self::Accepted,
        Self::Completed,
        Self::Rejected,
        Self::Conflict,
        Self::Unknown,
        Self::ResyncRequired,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
            Self::ResyncRequired => "resync_required",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "receipt_outcome")
    }
}

/// Endpoint capability declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub protocol: &'static str,
    pub schema: &'static str,
    pub methods: Vec<PlatformMethod>,
    pub transports: Vec<PlatformTransport>,
}

impl Capabilities {
    /// Complete version-one capability set.
    #[must_use]
    pub fn platform_v1() -> Self {
        Self {
            protocol: PLATFORM_PROTOCOL,
            schema: PLATFORM_SCHEMA_V1,
            methods: PlatformMethod::ALL.to_vec(),
            transports: PlatformTransport::ALL.to_vec(),
        }
    }
}

/// Resource projection. Payload is bounded display state, never credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub resource: ResourceCoordinate,
    pub freshness: Freshness,
    pub summary: PlatformText,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRequest {
    pub resources: Vec<ResourceCoordinate>,
}

impl SnapshotRequest {
    pub fn new(resources: Vec<ResourceCoordinate>) -> Result<Self, PlatformError> {
        if resources.len() > MAX_SNAPSHOT_RESOURCES {
            return Err(PlatformError::TooManyResources);
        }
        Ok(Self { resources })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub resources: Vec<ResourceRecord>,
    pub cursor: PlatformCursor,
}

/// One ordered change after a snapshot cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformEvent {
    pub cursor: PlatformCursor,
    pub resource: ResourceRecord,
}

/// A bounded, gap-free event page. A caller whose cursor is no longer
/// retained receives `resync_required` rather than a partial page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subscription {
    pub events: Vec<PlatformEvent>,
    pub cursor: PlatformCursor,
}

impl Subscription {
    pub fn new(events: Vec<PlatformEvent>, cursor: PlatformCursor) -> Result<Self, PlatformError> {
        if events.len() > MAX_SUBSCRIPTION_EVENTS {
            return Err(PlatformError::TooManyEvents);
        }
        Ok(Self { events, cursor })
    }
}

impl Snapshot {
    pub fn new(
        resources: Vec<ResourceRecord>,
        cursor: PlatformCursor,
    ) -> Result<Self, PlatformError> {
        if resources.len() > MAX_SNAPSHOT_RESOURCES {
            return Err(PlatformError::TooManyResources);
        }
        Ok(Self { resources, cursor })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeRequest {
    pub cursor: Option<PlatformCursor>,
}

/// All mutations pass through this request; no transport-specific mutation
/// or provider-direct escape hatch exists in the public contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteRequest {
    /// Authenticated remote principal. Gateways verify this value against the
    /// presented credential; local operator requests carry `None`.
    pub client: Option<ClientId>,
    pub action: PlatformAction,
    pub target: ResourceCoordinate,
    pub idempotency_key: IdempotencyKey,
    pub expected_revision: Option<Revision>,
    pub parameter: Option<PlatformParameter>,
}

impl ExecuteRequest {
    pub fn new(
        action: PlatformAction,
        target: ResourceCoordinate,
        idempotency_key: IdempotencyKey,
        expected_revision: Option<Revision>,
        parameter: Option<PlatformText>,
    ) -> Result<Self, PlatformError> {
        Self::new_with_parameter(
            action,
            target,
            idempotency_key,
            expected_revision,
            parameter.map(|text| PlatformParameter(text.into_inner())),
        )
    }

    pub fn new_with_parameter(
        action: PlatformAction,
        target: ResourceCoordinate,
        idempotency_key: IdempotencyKey,
        expected_revision: Option<Revision>,
        parameter: Option<PlatformParameter>,
    ) -> Result<Self, PlatformError> {
        if action.authority() != target.authority {
            return Err(PlatformError::AuthorityMismatch);
        }
        Ok(Self {
            client: None,
            action,
            target,
            idempotency_key,
            expected_revision,
            parameter,
        })
    }

    #[must_use]
    pub fn with_client(mut self, client: ClientId) -> Self {
        self.client = Some(client);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReceipt {
    pub id: ReceiptId,
    pub action: PlatformAction,
    pub target: ResourceCoordinate,
    pub outcome: ReceiptOutcome,
    pub revision: Revision,
    pub recorded_at: EpochMillis,
    pub explanation: Option<PlatformText>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetReceiptRequest {
    /// Authenticated owner required for credential-scoped lookup.
    pub client: Option<ClientId>,
    pub id: Option<ReceiptId>,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl GetReceiptRequest {
    #[must_use]
    pub const fn by_id(id: ReceiptId) -> Self {
        Self {
            client: None,
            id: Some(id),
            idempotency_key: None,
        }
    }

    #[must_use]
    pub const fn by_idempotency_key(idempotency_key: IdempotencyKey) -> Self {
        Self {
            client: None,
            id: None,
            idempotency_key: Some(idempotency_key),
        }
    }

    #[must_use]
    pub fn with_client(mut self, client: ClientId) -> Self {
        self.client = Some(client);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListSessionsRequest {
    pub authority: ResourceAuthority,
    pub cursor: Option<PlatformCursor>,
}

/// One attachable provider session projected without provider credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub session: ResourceRecord,
    pub run: Option<ResourceCoordinate>,
    pub attachable: bool,
    pub controllable: bool,
}

/// A bounded page of sessions and its resume cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionList {
    pub sessions: Vec<SessionRecord>,
    pub cursor: PlatformCursor,
}

impl SessionList {
    pub fn new(
        sessions: Vec<SessionRecord>,
        cursor: PlatformCursor,
    ) -> Result<Self, PlatformError> {
        if sessions.len() > MAX_SNAPSHOT_RESOURCES {
            return Err(PlatformError::TooManyResources);
        }
        Ok(Self { sessions, cursor })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachRequest {
    pub session: ResourceCoordinate,
    pub client: ClientId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachRequest {
    pub session: ResourceCoordinate,
    pub client: ClientId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimControlRequest {
    pub session: ResourceCoordinate,
    pub client: ClientId,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseControlRequest {
    pub session: ResourceCoordinate,
    pub client: ClientId,
    pub lease: ControlLeaseId,
    pub idempotency_key: IdempotencyKey,
}

/// Observation attachment. It carries an independent resume cursor and no
/// provider/control authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub session: ResourceCoordinate,
    pub client: ClientId,
    pub cursor: PlatformCursor,
}

/// Short exclusive authority to steer one session. Observation never creates
/// one of these; only `claim_control` does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlLease {
    pub id: ControlLeaseId,
    pub session: ResourceCoordinate,
    pub client: ClientId,
    pub expires_at: EpochMillis,
    pub revision: Revision,
}

/// Complete request vocabulary. Adding a mutation requires adding an explicit
/// arm here and updating conformance fixtures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformRequest {
    Capabilities,
    Snapshot(SnapshotRequest),
    Subscribe(SubscribeRequest),
    Execute(ExecuteRequest),
    GetReceipt(GetReceiptRequest),
    ListSessions(ListSessionsRequest),
    Attach(AttachRequest),
    Detach(DetachRequest),
    ClaimControl(ClaimControlRequest),
    ReleaseControl(ReleaseControlRequest),
    SessionHistorySnapshot(SessionHistorySnapshotRequest),
    SessionHistoryPage(SessionHistoryPageRequest),
}

/// Complete response vocabulary shared by local and remote transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformResponse {
    Capabilities(Capabilities),
    Snapshot(Snapshot),
    Subscription(Subscription),
    Receipt(ActionReceipt),
    Sessions(SessionList),
    Attached(Attachment),
    Detached {
        session: ResourceCoordinate,
        client: ClientId,
    },
    ControlClaimed(ControlLease),
    ControlReleased {
        session: ResourceCoordinate,
        client: ClientId,
        lease: ControlLeaseId,
    },
    SessionHistory(SessionHistoryPage),
    SessionHistoryResync(SessionHistoryResync),
    Refused {
        outcome: ReceiptOutcome,
        explanation: PlatformText,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Field(ValueError),
    TooManyResources,
    TooManyEvents,
    AuthorityMismatch,
    HistoryLimitOutOfRange,
    HistoryPageInvalid,
    UnknownEnum { field: &'static str },
}

impl From<ValueError> for PlatformError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}

fn parse_closed<T: Copy, const N: usize>(
    values: &[T; N],
    value: &str,
    spelling: impl Fn(T) -> &'static str,
    field: &'static str,
) -> Result<T, PlatformError> {
    values
        .iter()
        .copied()
        .find(|candidate| spelling(*candidate) == value)
        .ok_or(PlatformError::UnknownEnum { field })
}
