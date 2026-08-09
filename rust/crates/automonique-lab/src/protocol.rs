// SPDX-License-Identifier: Elastic-2.0

//! Typed, dependency-free foundations for `automonique.lab-scenario/v1`.
//!
//! This module owns domain validation, not serialization. A later canonical
//! JSON codec can translate these closed types without changing their
//! invariants or the byte framing in [`crate::framing`].

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

pub const LAB_PROTOCOL: &str = "automonique.lab-scenario/v1";
pub const TRANSPORT_ERROR_PROTOCOL: &str = "automonique.lab-transport-error/v1";
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_EVENTS: usize = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationKind {
    Empty,
    TooLong,
    InvalidCharacter,
    InvalidDigest,
    OutOfRange,
    Duplicate,
    EmptyCollection,
    CoordinateMismatch,
    Incoherent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub field: &'static str,
    pub kind: ValidationKind,
}

impl ValidationError {
    const fn new(field: &'static str, kind: ValidationKind) -> Self {
        Self { field, kind }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} is {:?}", self.field, self.kind)
    }
}

impl Error for ValidationError {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OpaqueId(String);

impl OpaqueId {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidationError::new("identifier", ValidationKind::Empty));
        }
        if value.len() > 128 {
            return Err(ValidationError::new("identifier", ValidationKind::TooLong));
        }
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err(ValidationError::new("identifier", ValidationKind::Empty));
        };
        if !first.is_ascii_alphanumeric()
            || !bytes.all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(ValidationError::new(
                "identifier",
                ValidationKind::InvalidCharacter,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedText(String);

impl BoundedText {
    pub fn new(
        value: impl Into<String>,
        maximum: usize,
        field: &'static str,
    ) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidationError::new(field, ValidationKind::Empty));
        }
        if value.encode_utf16().count() > maximum {
            return Err(ValidationError::new(field, ValidationKind::TooLong));
        }
        if value
            .chars()
            .any(|character| ('\u{0000}'..='\u{001f}').contains(&character))
        {
            return Err(ValidationError::new(
                field,
                ValidationKind::InvalidCharacter,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JsUInt(u64);

impl JsUInt {
    pub fn new(value: u64, field: &'static str) -> Result<Self, ValidationError> {
        if value > MAX_JS_SAFE_INTEGER {
            return Err(ValidationError::new(field, ValidationKind::OutOfRange));
        }
        Ok(Self(value))
    }

    pub fn positive(value: u64, field: &'static str) -> Result<Self, ValidationError> {
        if value == 0 {
            return Err(ValidationError::new(field, ValidationKind::OutOfRange));
        }
        Self::new(value, field)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GitSha1(String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Sha256Digest(String);

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl GitSha1 {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if !lowercase_hex(&value, 40) {
            return Err(ValidationError::new(
                "git_sha1",
                ValidationKind::InvalidDigest,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if !lowercase_hex(&value, 64) {
            return Err(ValidationError::new(
                "sha256",
                ValidationKind::InvalidDigest,
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Select,
    Observe,
    Resume,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    Selected,
    Observed,
    Action,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitState {
    Queued,
    Selected,
    Running,
    Paused,
    CancelRequested,
    Cancelled,
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionOperation {
    Resume,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionStatus {
    Accepted,
    AlreadyApplied,
    Conflict,
    Denied,
}

impl ActionStatus {
    const fn applied(self) -> bool {
        matches!(self, Self::Accepted | Self::AlreadyApplied)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KnownEventType {
    UnitSelected,
    UnitResumed,
    UnitCancelRequested,
    UnitCancelled,
    UnitTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventType {
    Known(KnownEventType),
    Unknown(BoundedText),
}

impl EventType {
    pub fn from_wire(value: &str) -> Result<Self, ValidationError> {
        let known = match value {
            "unit.selected" => Some(KnownEventType::UnitSelected),
            "unit.resumed" => Some(KnownEventType::UnitResumed),
            "unit.cancel_requested" => Some(KnownEventType::UnitCancelRequested),
            "unit.cancelled" => Some(KnownEventType::UnitCancelled),
            "unit.terminal" => Some(KnownEventType::UnitTerminal),
            _ => None,
        };
        Ok(match known {
            Some(event) => Self::Known(event),
            None => Self::Unknown(BoundedText::new(value, 128, "event_type")?),
        })
    }

    pub fn as_wire(&self) -> &str {
        match self {
            Self::Known(KnownEventType::UnitSelected) => "unit.selected",
            Self::Known(KnownEventType::UnitResumed) => "unit.resumed",
            Self::Known(KnownEventType::UnitCancelRequested) => "unit.cancel_requested",
            Self::Known(KnownEventType::UnitCancelled) => "unit.cancelled",
            Self::Known(KnownEventType::UnitTerminal) => "unit.terminal",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    OperatorRequest,
    BudgetExhausted,
    PolicyDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Execution {
    Synthetic,
    Inventory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetEnforcement {
    SyntheticInProcess,
    HostBrokerRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabBudget {
    max_wall_ms: JsUInt,
    max_cpu_ms: JsUInt,
    max_disk_bytes: JsUInt,
    max_output_bytes: JsUInt,
    max_pids: JsUInt,
    max_model_calls: JsUInt,
    max_cost_microunits: JsUInt,
    enforcement: BudgetEnforcement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabBudgetValues {
    pub max_wall_ms: u64,
    pub max_cpu_ms: u64,
    pub max_disk_bytes: u64,
    pub max_output_bytes: u64,
    pub max_pids: u64,
    pub max_model_calls: u64,
    pub max_cost_microunits: u64,
    pub enforcement: BudgetEnforcement,
}

impl LabBudget {
    pub fn new(values: LabBudgetValues) -> Result<Self, ValidationError> {
        Ok(Self {
            max_wall_ms: JsUInt::positive(values.max_wall_ms, "budget.max_wall_ms")?,
            max_cpu_ms: JsUInt::positive(values.max_cpu_ms, "budget.max_cpu_ms")?,
            max_disk_bytes: JsUInt::positive(values.max_disk_bytes, "budget.max_disk_bytes")?,
            max_output_bytes: JsUInt::positive(values.max_output_bytes, "budget.max_output_bytes")?,
            max_pids: JsUInt::positive(values.max_pids, "budget.max_pids")?,
            max_model_calls: JsUInt::new(values.max_model_calls, "budget.max_model_calls")?,
            max_cost_microunits: JsUInt::new(
                values.max_cost_microunits,
                "budget.max_cost_microunits",
            )?,
            enforcement: values.enforcement,
        })
    }

    pub const fn max_wall_ms(&self) -> JsUInt {
        self.max_wall_ms
    }
    pub const fn max_cpu_ms(&self) -> JsUInt {
        self.max_cpu_ms
    }
    pub const fn max_disk_bytes(&self) -> JsUInt {
        self.max_disk_bytes
    }
    pub const fn max_output_bytes(&self) -> JsUInt {
        self.max_output_bytes
    }
    pub const fn max_pids(&self) -> JsUInt {
        self.max_pids
    }
    pub const fn max_model_calls(&self) -> JsUInt {
        self.max_model_calls
    }
    pub const fn max_cost_microunits(&self) -> JsUInt {
        self.max_cost_microunits
    }
    pub const fn enforcement(&self) -> BudgetEnforcement {
        self.enforcement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticProviderPolicy;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Capability {
    Approval,
    Cancel,
    Create,
    Model,
    Observe,
    Reconnect,
    Resume,
    Steer,
    Usage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceLevel {
    Advertised,
    Observed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryTrust {
    UntrustedWireCoordinates,
    VerifiedByTrustedLoader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitFallback {
    mode: OpaqueId,
    accepted_lost_guarantees: Vec<BoundedText>,
}

impl ExplicitFallback {
    pub fn new(
        mode: OpaqueId,
        losses: impl IntoIterator<Item = String>,
    ) -> Result<Self, ValidationError> {
        let losses = losses
            .into_iter()
            .map(|loss| BoundedText::new(loss, 512, "fallback.loss"))
            .collect::<Result<Vec<_>, _>>()?;
        if losses.len() > 32 {
            return Err(ValidationError::new(
                "fallback.losses",
                ValidationKind::TooLong,
            ));
        }
        Ok(Self {
            mode,
            accepted_lost_guarantees: losses,
        })
    }

    pub fn mode(&self) -> &OpaqueId {
        &self.mode
    }
    pub fn accepted_lost_guarantees(&self) -> &[BoundedText] {
        &self.accepted_lost_guarantees
    }
}

/// Provider inventory coordinates decoded from the wire.
///
/// Digests are claims until a trusted inventory loader checks them. This type
/// deliberately cannot be used as [`ProviderPolicy`] authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedInventoryPolicy {
    provider: OpaqueId,
    mode: OpaqueId,
    inventory_digest: Sha256Digest,
    surface_digest: Sha256Digest,
    required_capabilities: Vec<Capability>,
    minimum_evidence: EvidenceLevel,
    explicit_fallbacks: Vec<ExplicitFallback>,
}

impl UntrustedInventoryPolicy {
    pub fn new(
        provider: OpaqueId,
        mode: OpaqueId,
        inventory_digest: Sha256Digest,
        surface_digest: Sha256Digest,
        required_capabilities: Vec<Capability>,
        minimum_evidence: EvidenceLevel,
        explicit_fallbacks: Vec<ExplicitFallback>,
    ) -> Result<Self, ValidationError> {
        if required_capabilities.is_empty() {
            return Err(ValidationError::new(
                "required_capabilities",
                ValidationKind::EmptyCollection,
            ));
        }
        if required_capabilities.len() > 9 {
            return Err(ValidationError::new(
                "required_capabilities",
                ValidationKind::TooLong,
            ));
        }
        if required_capabilities
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != required_capabilities.len()
        {
            return Err(ValidationError::new(
                "required_capabilities",
                ValidationKind::Duplicate,
            ));
        }
        if explicit_fallbacks.len() > 16 {
            return Err(ValidationError::new(
                "explicit_fallbacks",
                ValidationKind::TooLong,
            ));
        }
        let mut modes = HashSet::new();
        if explicit_fallbacks
            .iter()
            .any(|fallback| !modes.insert(fallback.mode.clone()))
        {
            return Err(ValidationError::new(
                "explicit_fallbacks",
                ValidationKind::Duplicate,
            ));
        }
        Ok(Self {
            provider,
            mode,
            inventory_digest,
            surface_digest,
            required_capabilities,
            minimum_evidence,
            explicit_fallbacks,
        })
    }

    pub fn provider(&self) -> &OpaqueId {
        &self.provider
    }
    pub fn mode(&self) -> &OpaqueId {
        &self.mode
    }
    pub fn inventory_digest(&self) -> &Sha256Digest {
        &self.inventory_digest
    }
    pub fn surface_digest(&self) -> &Sha256Digest {
        &self.surface_digest
    }
    pub fn required_capabilities(&self) -> &[Capability] {
        &self.required_capabilities
    }
    pub const fn minimum_evidence(&self) -> EvidenceLevel {
        self.minimum_evidence
    }
    pub fn explicit_fallbacks(&self) -> &[ExplicitFallback] {
        &self.explicit_fallbacks
    }
    pub const fn trust(&self) -> InventoryTrust {
        InventoryTrust::UntrustedWireCoordinates
    }
}

/// A provider policy minted only by a future trusted inventory verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInventoryPolicy(UntrustedInventoryPolicy);

impl VerifiedInventoryPolicy {
    pub fn coordinates(&self) -> &UntrustedInventoryPolicy {
        &self.0
    }
    pub const fn trust(&self) -> InventoryTrust {
        InventoryTrust::VerifiedByTrustedLoader
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderPolicy {
    Synthetic(SyntheticProviderPolicy),
    VerifiedInventory(VerifiedInventoryPolicy),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectRequest {
    request_id: OpaqueId,
    objective_id: OpaqueId,
    expected_base: GitSha1,
    execution: Execution,
    provider_policy: ProviderPolicy,
    budget: LabBudget,
}

impl SelectRequest {
    pub fn new(
        request_id: OpaqueId,
        objective_id: OpaqueId,
        expected_base: GitSha1,
        execution: Execution,
        provider_policy: ProviderPolicy,
        budget: LabBudget,
    ) -> Result<Self, ValidationError> {
        let coherent = matches!(
            (execution, &provider_policy),
            (Execution::Synthetic, ProviderPolicy::Synthetic(_))
                | (Execution::Inventory, ProviderPolicy::VerifiedInventory(_))
        );
        if !coherent {
            return Err(ValidationError::new(
                "provider_policy",
                ValidationKind::Incoherent,
            ));
        }
        match execution {
            Execution::Synthetic => {
                if budget.enforcement != BudgetEnforcement::SyntheticInProcess
                    || budget.max_model_calls.get() != 0
                    || budget.max_cost_microunits.get() != 0
                {
                    return Err(ValidationError::new(
                        "synthetic_budget",
                        ValidationKind::Incoherent,
                    ));
                }
            }
            Execution::Inventory => {
                if budget.enforcement != BudgetEnforcement::HostBrokerRequired {
                    return Err(ValidationError::new(
                        "inventory_budget",
                        ValidationKind::Incoherent,
                    ));
                }
            }
        }
        Ok(Self {
            request_id,
            objective_id,
            expected_base,
            execution,
            provider_policy,
            budget,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn expected_base(&self) -> &GitSha1 {
        &self.expected_base
    }
    pub const fn execution(&self) -> Execution {
        self.execution
    }
    pub fn provider_policy(&self) -> &ProviderPolicy {
        &self.provider_policy
    }
    pub fn budget(&self) -> &LabBudget {
        &self.budget
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveRequest {
    request_id: OpaqueId,
    objective_id: OpaqueId,
    unit_id: OpaqueId,
    after_sequence: JsUInt,
    limit: JsUInt,
}

impl ObserveRequest {
    pub fn new(
        request_id: OpaqueId,
        objective_id: OpaqueId,
        unit_id: OpaqueId,
        after_sequence: u64,
        limit: u64,
    ) -> Result<Self, ValidationError> {
        if !(1..=MAX_EVENTS as u64).contains(&limit) {
            return Err(ValidationError::new("limit", ValidationKind::OutOfRange));
        }
        Ok(Self {
            request_id,
            objective_id,
            unit_id,
            after_sequence: JsUInt::new(after_sequence, "after_sequence")?,
            limit: JsUInt::new(limit, "limit")?,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub const fn after_sequence(&self) -> JsUInt {
        self.after_sequence
    }
    pub const fn limit(&self) -> JsUInt {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeRequest {
    request_id: OpaqueId,
    objective_id: OpaqueId,
    unit_id: OpaqueId,
    checkpoint_id: OpaqueId,
    expected_revision: JsUInt,
    idempotency_key: OpaqueId,
}

impl ResumeRequest {
    pub fn new(
        request_id: OpaqueId,
        objective_id: OpaqueId,
        unit_id: OpaqueId,
        checkpoint_id: OpaqueId,
        expected_revision: u64,
        idempotency_key: OpaqueId,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            request_id,
            objective_id,
            unit_id,
            checkpoint_id,
            expected_revision: JsUInt::new(expected_revision, "expected_revision")?,
            idempotency_key,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub fn checkpoint_id(&self) -> &OpaqueId {
        &self.checkpoint_id
    }
    pub const fn expected_revision(&self) -> JsUInt {
        self.expected_revision
    }
    pub fn idempotency_key(&self) -> &OpaqueId {
        &self.idempotency_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelRequest {
    request_id: OpaqueId,
    objective_id: OpaqueId,
    unit_id: OpaqueId,
    expected_revision: JsUInt,
    idempotency_key: OpaqueId,
    reason: CancelReason,
}

impl CancelRequest {
    pub fn new(
        request_id: OpaqueId,
        objective_id: OpaqueId,
        unit_id: OpaqueId,
        expected_revision: u64,
        idempotency_key: OpaqueId,
        reason: CancelReason,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            request_id,
            objective_id,
            unit_id,
            expected_revision: JsUInt::new(expected_revision, "expected_revision")?,
            idempotency_key,
            reason,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub const fn expected_revision(&self) -> JsUInt {
        self.expected_revision
    }
    pub fn idempotency_key(&self) -> &OpaqueId {
        &self.idempotency_key
    }
    pub const fn reason(&self) -> CancelReason {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabRequest {
    Select(SelectRequest),
    Observe(ObserveRequest),
    Resume(ResumeRequest),
    Cancel(CancelRequest),
}

impl LabRequest {
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Select(_) => Operation::Select,
            Self::Observe(_) => Operation::Observe,
            Self::Resume(_) => Operation::Resume,
            Self::Cancel(_) => Operation::Cancel,
        }
    }

    pub fn request_id(&self) -> &OpaqueId {
        match self {
            Self::Select(request) => &request.request_id,
            Self::Observe(request) => &request.request_id,
            Self::Resume(request) => &request.request_id,
            Self::Cancel(request) => &request.request_id,
        }
    }

    pub fn objective_id(&self) -> &OpaqueId {
        match self {
            Self::Select(request) => &request.objective_id,
            Self::Observe(request) => &request.objective_id,
            Self::Resume(request) => &request.objective_id,
            Self::Cancel(request) => &request.objective_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitSnapshot {
    unit_id: OpaqueId,
    objective_id: OpaqueId,
    state: UnitState,
    revision: JsUInt,
    checkpoint_id: Option<OpaqueId>,
    last_sequence: JsUInt,
}

impl UnitSnapshot {
    pub fn new(
        unit_id: OpaqueId,
        objective_id: OpaqueId,
        state: UnitState,
        revision: u64,
        checkpoint_id: Option<OpaqueId>,
        last_sequence: u64,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            unit_id,
            objective_id,
            state,
            revision: JsUInt::new(revision, "unit.revision")?,
            checkpoint_id,
            last_sequence: JsUInt::new(last_sequence, "unit.last_sequence")?,
        })
    }

    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub const fn state(&self) -> UnitState {
        self.state
    }
    pub const fn revision(&self) -> JsUInt {
        self.revision
    }
    pub fn checkpoint_id(&self) -> Option<&OpaqueId> {
        self.checkpoint_id.as_ref()
    }
    pub const fn last_sequence(&self) -> JsUInt {
        self.last_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabEvent {
    event_type: EventType,
    objective_id: OpaqueId,
    unit_id: OpaqueId,
    sequence: JsUInt,
    revision: JsUInt,
}

impl LabEvent {
    pub fn new(
        event_type: EventType,
        objective_id: OpaqueId,
        unit_id: OpaqueId,
        sequence: u64,
        revision: u64,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            event_type,
            objective_id,
            unit_id,
            sequence: JsUInt::new(sequence, "event.sequence")?,
            revision: JsUInt::new(revision, "event.revision")?,
        })
    }

    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub const fn sequence(&self) -> JsUInt {
        self.sequence
    }
    pub const fn revision(&self) -> JsUInt {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedResponse {
    request_id: OpaqueId,
    unit: UnitSnapshot,
}

impl SelectedResponse {
    pub fn new(request_id: OpaqueId, unit: UnitSnapshot) -> Self {
        Self { request_id, unit }
    }
    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn unit(&self) -> &UnitSnapshot {
        &self.unit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedResponse {
    request_id: OpaqueId,
    unit: UnitSnapshot,
    events: Vec<LabEvent>,
    next_sequence: JsUInt,
}

impl ObservedResponse {
    pub fn new(
        request_id: OpaqueId,
        unit: UnitSnapshot,
        events: Vec<LabEvent>,
        next_sequence: u64,
    ) -> Result<Self, ValidationError> {
        if events.len() > MAX_EVENTS {
            return Err(ValidationError::new("events", ValidationKind::TooLong));
        }
        Ok(Self {
            request_id,
            unit,
            events,
            next_sequence: JsUInt::new(next_sequence, "next_sequence")?,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn unit(&self) -> &UnitSnapshot {
        &self.unit
    }
    pub fn events(&self) -> &[LabEvent] {
        &self.events
    }
    pub const fn next_sequence(&self) -> JsUInt {
        self.next_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReceipt {
    action_id: OpaqueId,
    operation: ActionOperation,
    objective_id: OpaqueId,
    unit_id: OpaqueId,
    checkpoint_id: Option<OpaqueId>,
    expected_revision: JsUInt,
    idempotency_key: OpaqueId,
    status: ActionStatus,
    effect_count: JsUInt,
    reason: Option<BoundedText>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionCoordinates {
    pub action_id: OpaqueId,
    pub operation: ActionOperation,
    pub objective_id: OpaqueId,
    pub unit_id: OpaqueId,
    pub checkpoint_id: Option<OpaqueId>,
    pub expected_revision: u64,
    pub idempotency_key: OpaqueId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOutcome {
    pub status: ActionStatus,
    pub effect_count: u64,
    pub reason: Option<String>,
}

impl ActionReceipt {
    pub fn new(
        coordinates: ActionCoordinates,
        outcome: ActionOutcome,
    ) -> Result<Self, ValidationError> {
        let reason = outcome
            .reason
            .map(|value| BoundedText::new(value, 1_024, "action.reason"))
            .transpose()?;
        if outcome.status.applied() != (outcome.effect_count == 1 && reason.is_none())
            || (!outcome.status.applied() && (outcome.effect_count != 0 || reason.is_none()))
        {
            return Err(ValidationError::new(
                "action_receipt",
                ValidationKind::Incoherent,
            ));
        }
        Ok(Self {
            action_id: coordinates.action_id,
            operation: coordinates.operation,
            objective_id: coordinates.objective_id,
            unit_id: coordinates.unit_id,
            checkpoint_id: coordinates.checkpoint_id,
            expected_revision: JsUInt::new(coordinates.expected_revision, "expected_revision")?,
            idempotency_key: coordinates.idempotency_key,
            status: outcome.status,
            effect_count: JsUInt::new(outcome.effect_count, "effect_count")?,
            reason,
        })
    }

    pub fn action_id(&self) -> &OpaqueId {
        &self.action_id
    }
    pub const fn operation(&self) -> ActionOperation {
        self.operation
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn unit_id(&self) -> &OpaqueId {
        &self.unit_id
    }
    pub fn checkpoint_id(&self) -> Option<&OpaqueId> {
        self.checkpoint_id.as_ref()
    }
    pub const fn expected_revision(&self) -> JsUInt {
        self.expected_revision
    }
    pub fn idempotency_key(&self) -> &OpaqueId {
        &self.idempotency_key
    }
    pub const fn status(&self) -> ActionStatus {
        self.status
    }
    pub const fn effect_count(&self) -> JsUInt {
        self.effect_count
    }
    pub fn reason(&self) -> Option<&BoundedText> {
        self.reason.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResponse {
    request_id: OpaqueId,
    receipt: ActionReceipt,
    unit: UnitSnapshot,
}

impl ActionResponse {
    pub fn new(request_id: OpaqueId, receipt: ActionReceipt, unit: UnitSnapshot) -> Self {
        Self {
            request_id,
            receipt,
            unit,
        }
    }
    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn receipt(&self) -> &ActionReceipt {
        &self.receipt
    }
    pub fn unit(&self) -> &UnitSnapshot {
        &self.unit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeniedResponse {
    request_id: OpaqueId,
    code: OpaqueId,
    reason: BoundedText,
}

impl DeniedResponse {
    pub fn new(
        request_id: OpaqueId,
        code: OpaqueId,
        reason: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            request_id,
            code,
            reason: BoundedText::new(reason, 1_024, "denied.reason")?,
        })
    }

    pub fn request_id(&self) -> &OpaqueId {
        &self.request_id
    }
    pub fn code(&self) -> &OpaqueId {
        &self.code
    }
    pub fn reason(&self) -> &BoundedText {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabResponse {
    Selected(SelectedResponse),
    Observed(ObservedResponse),
    Action(ActionResponse),
    Denied(DeniedResponse),
}

impl LabResponse {
    pub const fn kind(&self) -> ResponseKind {
        match self {
            Self::Selected(_) => ResponseKind::Selected,
            Self::Observed(_) => ResponseKind::Observed,
            Self::Action(_) => ResponseKind::Action,
            Self::Denied(_) => ResponseKind::Denied,
        }
    }

    pub fn validate_for(&self, request: &LabRequest) -> Result<(), ValidationError> {
        if let Self::Denied(response) = self {
            return coordinate(
                &response.request_id,
                request.request_id(),
                "response.request_id",
            );
        }
        match (request, self) {
            (LabRequest::Select(request), Self::Selected(response)) => {
                coordinate(
                    &response.request_id,
                    &request.request_id,
                    "response.request_id",
                )?;
                coordinate(
                    &response.unit.objective_id,
                    &request.objective_id,
                    "unit.objective_id",
                )
            }
            (LabRequest::Observe(request), Self::Observed(response)) => {
                coordinate(
                    &response.request_id,
                    &request.request_id,
                    "response.request_id",
                )?;
                validate_unit_coordinates(&response.unit, &request.objective_id, &request.unit_id)?;
                if response.events.len() > request.limit.get() as usize
                    || response.unit.last_sequence < request.after_sequence
                {
                    return Err(ValidationError::new("events", ValidationKind::Incoherent));
                }
                let mut sequence = request.after_sequence.get();
                let mut revision = 0;
                for event in &response.events {
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        ValidationError::new("event.sequence", ValidationKind::OutOfRange)
                    })?;
                    if event.sequence.get() != sequence
                        || event.revision.get() < revision
                        || event.revision > response.unit.revision
                    {
                        return Err(ValidationError::new("events", ValidationKind::Incoherent));
                    }
                    coordinate(
                        &event.objective_id,
                        &request.objective_id,
                        "event.objective_id",
                    )?;
                    coordinate(&event.unit_id, &request.unit_id, "event.unit_id")?;
                    revision = event.revision.get();
                }
                if response.next_sequence.get() != sequence
                    || response.next_sequence > response.unit.last_sequence
                {
                    return Err(ValidationError::new(
                        "next_sequence",
                        ValidationKind::Incoherent,
                    ));
                }
                Ok(())
            }
            (LabRequest::Resume(request), Self::Action(response)) => validate_action(
                &response.request_id,
                &response.receipt,
                &response.unit,
                ExpectedActionCoordinates {
                    operation: ActionOperation::Resume,
                    request_id: &request.request_id,
                    objective_id: &request.objective_id,
                    unit_id: &request.unit_id,
                    checkpoint_id: Some(&request.checkpoint_id),
                    expected_revision: request.expected_revision,
                    idempotency_key: &request.idempotency_key,
                },
            ),
            (LabRequest::Cancel(request), Self::Action(response)) => validate_action(
                &response.request_id,
                &response.receipt,
                &response.unit,
                ExpectedActionCoordinates {
                    operation: ActionOperation::Cancel,
                    request_id: &request.request_id,
                    objective_id: &request.objective_id,
                    unit_id: &request.unit_id,
                    checkpoint_id: None,
                    expected_revision: request.expected_revision,
                    idempotency_key: &request.idempotency_key,
                },
            ),
            _ => Err(ValidationError::new(
                "response.kind",
                ValidationKind::Incoherent,
            )),
        }
    }
}

fn coordinate(
    actual: &OpaqueId,
    expected: &OpaqueId,
    field: &'static str,
) -> Result<(), ValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ValidationError::new(
            field,
            ValidationKind::CoordinateMismatch,
        ))
    }
}

fn validate_unit_coordinates(
    unit: &UnitSnapshot,
    objective_id: &OpaqueId,
    unit_id: &OpaqueId,
) -> Result<(), ValidationError> {
    coordinate(&unit.objective_id, objective_id, "unit.objective_id")?;
    coordinate(&unit.unit_id, unit_id, "unit.unit_id")
}

struct ExpectedActionCoordinates<'a> {
    operation: ActionOperation,
    request_id: &'a OpaqueId,
    objective_id: &'a OpaqueId,
    unit_id: &'a OpaqueId,
    checkpoint_id: Option<&'a OpaqueId>,
    expected_revision: JsUInt,
    idempotency_key: &'a OpaqueId,
}

fn validate_action(
    response_request_id: &OpaqueId,
    receipt: &ActionReceipt,
    unit: &UnitSnapshot,
    expected: ExpectedActionCoordinates<'_>,
) -> Result<(), ValidationError> {
    coordinate(
        response_request_id,
        expected.request_id,
        "response.request_id",
    )?;
    validate_unit_coordinates(unit, expected.objective_id, expected.unit_id)?;
    if receipt.operation != expected.operation
        || receipt.checkpoint_id.as_ref() != expected.checkpoint_id
        || receipt.expected_revision != expected.expected_revision
    {
        return Err(ValidationError::new(
            "action_receipt",
            ValidationKind::CoordinateMismatch,
        ));
    }
    coordinate(
        &receipt.objective_id,
        expected.objective_id,
        "receipt.objective_id",
    )?;
    coordinate(&receipt.unit_id, expected.unit_id, "receipt.unit_id")?;
    coordinate(
        &receipt.idempotency_key,
        expected.idempotency_key,
        "receipt.idempotency_key",
    )?;
    if receipt.status.applied()
        && unit.revision.get() < expected.expected_revision.get().saturating_add(1)
    {
        return Err(ValidationError::new(
            "unit.revision",
            ValidationKind::Incoherent,
        ));
    }
    if receipt.status == ActionStatus::Accepted {
        match receipt.operation {
            ActionOperation::Resume
                if unit.state != UnitState::Running || unit.checkpoint_id.is_some() =>
            {
                return Err(ValidationError::new(
                    "unit.state",
                    ValidationKind::Incoherent,
                ));
            }
            ActionOperation::Cancel
                if !matches!(
                    unit.state,
                    UnitState::CancelRequested | UnitState::Cancelled
                ) =>
            {
                return Err(ValidationError::new(
                    "unit.state",
                    ValidationKind::Incoherent,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}
