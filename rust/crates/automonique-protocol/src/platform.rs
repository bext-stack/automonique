// SPDX-License-Identifier: Elastic-2.0

//! Federated operator platform contract shared by every Automonique client.
//!
//! The contract names the authority that owns a resource separately from its
//! kind and identifier. A projection therefore cannot accidentally present a
//! provider observation as Automonique state, or a queued global job as local
//! execution. Transport is deliberately absent from request and response
//! values: local Unix sockets and remote HTTPS/WebSocket endpoints carry the
//! same values and differ only in framing and authentication.

use crate::primitives::{BoundedString, EpochMillis, IdDomain, OpaqueId, Revision, ValueError};

/// Stable protocol name.
pub const PLATFORM_PROTOCOL: &str = "automonique.platform";
/// Stable version-one schema identifier.
pub const PLATFORM_SCHEMA_V1: &str = "automonique.platform/v1";
/// Largest identifier, cursor topic, action parameter, or explanation.
pub const MAX_PLATFORM_FIELD_BYTES: usize = 256;
/// Largest number of resources in a snapshot request or response.
pub const MAX_SNAPSHOT_RESOURCES: usize = 512;
/// Largest number of ordered events returned in one subscription page.
pub const MAX_SUBSCRIPTION_EVENTS: usize = 512;
/// Largest number of service methods advertised by one endpoint.
pub const MAX_CAPABILITY_METHODS: usize = 32;
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
    pub const ALL: [Self; 16] = [
        Self::Job,
        Self::Release,
        Self::Node,
        Self::Run,
        Self::Session,
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
}

impl PlatformMethod {
    pub const ALL: [Self; 10] = [
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
        }
    }

    pub fn parse(value: &str) -> Result<Self, PlatformError> {
        parse_closed(&Self::ALL, value, Self::as_str, "platform_method")
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
    SubmitJob,
    ApproveRelease,
    RegisterNode,
}

impl PlatformAction {
    pub const ALL: [Self; 6] = [
        Self::StartRun,
        Self::StopRun,
        Self::DecideApproval,
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
            Self::StartRun | Self::StopRun | Self::DecideApproval => ResourceAuthority::Automonique,
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
    pub action: PlatformAction,
    pub target: ResourceCoordinate,
    pub idempotency_key: IdempotencyKey,
    pub expected_revision: Option<Revision>,
    pub parameter: Option<PlatformText>,
}

impl ExecuteRequest {
    pub fn new(
        action: PlatformAction,
        target: ResourceCoordinate,
        idempotency_key: IdempotencyKey,
        expected_revision: Option<Revision>,
        parameter: Option<PlatformText>,
    ) -> Result<Self, PlatformError> {
        if action.authority() != target.authority {
            return Err(PlatformError::AuthorityMismatch);
        }
        Ok(Self {
            action,
            target,
            idempotency_key,
            expected_revision,
            parameter,
        })
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
    pub id: Option<ReceiptId>,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl GetReceiptRequest {
    #[must_use]
    pub const fn by_id(id: ReceiptId) -> Self {
        Self {
            id: Some(id),
            idempotency_key: None,
        }
    }

    #[must_use]
    pub const fn by_idempotency_key(idempotency_key: IdempotencyKey) -> Self {
        Self {
            id: None,
            idempotency_key: Some(idempotency_key),
        }
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
