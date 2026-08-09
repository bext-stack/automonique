// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical JSON at the typed lab-protocol boundary.

use crate::framing::PayloadCodec;
use crate::protocol::{
    ActionCoordinates, ActionOperation, ActionOutcome, ActionReceipt, ActionResponse, ActionStatus,
    BudgetEnforcement, CancelReason, CancelRequest, Capability, DeniedResponse, EventType,
    EvidenceLevel, Execution, ExplicitFallback, GitSha1, LAB_PROTOCOL, LabBudget, LabBudgetValues,
    LabEvent, LabRequest, LabResponse, ObserveRequest, ObservedResponse, OpaqueId, ProviderPolicy,
    ResumeRequest, SelectRequest, SelectedResponse, Sha256Digest, SyntheticProviderPolicy,
    TRANSPORT_ERROR_PROTOCOL, UnitSnapshot, UnitState, UntrustedInventoryPolicy, ValidationError,
};
use serde_json::{Map, Number, Value};
use std::error::Error;
use std::fmt;

const MAX_JSON_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorCode {
    PeerDenied,
    FrameTooLarge,
    MalformedJson,
    InvalidJsonValue,
    NoncanonicalJson,
    InvalidRequest,
    ExtraData,
    HandlerError,
    InvalidHandlerResult,
}

impl TransportErrorCode {
    const fn as_wire(self) -> &'static str {
        match self {
            Self::PeerDenied => "peer_denied",
            Self::FrameTooLarge => "frame_too_large",
            Self::MalformedJson => "malformed_json",
            Self::InvalidJsonValue => "invalid_json_value",
            Self::NoncanonicalJson => "noncanonical_json",
            Self::InvalidRequest => "invalid_request",
            Self::ExtraData => "extra_data",
            Self::HandlerError => "handler_error",
            Self::InvalidHandlerResult => "invalid_handler_result",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        Some(match value {
            "peer_denied" => Self::PeerDenied,
            "frame_too_large" => Self::FrameTooLarge,
            "malformed_json" => Self::MalformedJson,
            "invalid_json_value" => Self::InvalidJsonValue,
            "noncanonical_json" => Self::NoncanonicalJson,
            "invalid_request" => Self::InvalidRequest,
            "extra_data" => Self::ExtraData,
            "handler_error" => Self::HandlerError,
            "invalid_handler_result" => Self::InvalidHandlerResult,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportErrorDocument {
    code: TransportErrorCode,
    reason: crate::protocol::BoundedText,
}

impl TransportErrorDocument {
    pub fn new(
        code: TransportErrorCode,
        reason: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            code,
            reason: crate::protocol::BoundedText::new(reason, 1_024, "transport_error.reason")?,
        })
    }

    pub const fn code(&self) -> TransportErrorCode {
        self.code
    }

    pub fn reason(&self) -> &str {
        self.reason.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalJsonError {
    InvalidUtf8,
    MalformedJson,
    Noncanonical,
    DepthExceeded,
    FloatingPoint,
    RootNotObject,
    MissingField(&'static str),
    UnknownField(String),
    WrongType(&'static str),
    UnsupportedVersion,
    UnknownEnum(&'static str),
    UntrustedInventoryPolicy,
    Domain(ValidationError),
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "canonical JSON error: {self:?}")
    }
}

impl Error for CanonicalJsonError {}

impl From<ValidationError> for CanonicalJsonError {
    fn from(value: ValidationError) -> Self {
        Self::Domain(value)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalRequestCodec;

impl PayloadCodec for CanonicalRequestCodec {
    type Value = LabRequest;
    type Error = CanonicalJsonError;

    fn encode_payload(&self, value: &Self::Value) -> Result<Vec<u8>, Self::Error> {
        encode_request(value)
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<Self::Value, Self::Error> {
        decode_request(payload)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CanonicalResponseCodec<'a> {
    request: &'a LabRequest,
}

impl<'a> CanonicalResponseCodec<'a> {
    pub const fn new(request: &'a LabRequest) -> Self {
        Self { request }
    }
}

impl PayloadCodec for CanonicalResponseCodec<'_> {
    type Value = LabResponse;
    type Error = CanonicalJsonError;

    fn encode_payload(&self, value: &Self::Value) -> Result<Vec<u8>, Self::Error> {
        value.validate_for(self.request)?;
        encode_response(value)
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<Self::Value, Self::Error> {
        decode_response_for(payload, self.request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalTransportErrorCodec;

impl PayloadCodec for CanonicalTransportErrorCodec {
    type Value = TransportErrorDocument;
    type Error = CanonicalJsonError;

    fn encode_payload(&self, value: &Self::Value) -> Result<Vec<u8>, Self::Error> {
        encode_transport_error(value)
    }

    fn decode_payload(&self, payload: &[u8]) -> Result<Self::Value, Self::Error> {
        decode_transport_error(payload)
    }
}

pub fn encode_request(request: &LabRequest) -> Result<Vec<u8>, CanonicalJsonError> {
    serialize(&request_value(request))
}

pub fn decode_request(payload: &[u8]) -> Result<LabRequest, CanonicalJsonError> {
    let value = parse_canonical(payload)?;
    let object = exact_object(&value, request_fields(&value)?)?;
    version(object, LAB_PROTOCOL)?;
    match string(object, "op")? {
        "select" => decode_select(object),
        "observe" => Ok(LabRequest::Observe(ObserveRequest::new(
            identifier(object, "requestId")?,
            identifier(object, "objectiveId")?,
            identifier(object, "unitId")?,
            uint(object, "afterSequence")?,
            uint(object, "limit")?,
        )?)),
        "resume" => Ok(LabRequest::Resume(ResumeRequest::new(
            identifier(object, "requestId")?,
            identifier(object, "objectiveId")?,
            identifier(object, "unitId")?,
            identifier(object, "checkpointId")?,
            uint(object, "expectedRevision")?,
            identifier(object, "idempotencyKey")?,
        )?)),
        "cancel" => Ok(LabRequest::Cancel(CancelRequest::new(
            identifier(object, "requestId")?,
            identifier(object, "objectiveId")?,
            identifier(object, "unitId")?,
            uint(object, "expectedRevision")?,
            identifier(object, "idempotencyKey")?,
            cancel_reason(string(object, "reason")?)?,
        )?)),
        _ => Err(CanonicalJsonError::UnknownEnum("op")),
    }
}

pub fn encode_response(response: &LabResponse) -> Result<Vec<u8>, CanonicalJsonError> {
    serialize(&response_value(response))
}

pub fn decode_response_for(
    payload: &[u8],
    request: &LabRequest,
) -> Result<LabResponse, CanonicalJsonError> {
    let value = parse_canonical(payload)?;
    let object = exact_object(&value, response_fields(&value)?)?;
    version(object, LAB_PROTOCOL)?;
    let response = match string(object, "kind")? {
        "selected" => LabResponse::Selected(SelectedResponse::new(
            identifier(object, "requestId")?,
            decode_unit(required(object, "unit")?)?,
        )),
        "observed" => {
            let events = array(object, "events")?
                .iter()
                .map(decode_event)
                .collect::<Result<Vec<_>, _>>()?;
            LabResponse::Observed(ObservedResponse::new(
                identifier(object, "requestId")?,
                decode_unit(required(object, "unit")?)?,
                events,
                uint(object, "nextSequence")?,
            )?)
        }
        "action" => LabResponse::Action(ActionResponse::new(
            identifier(object, "requestId")?,
            decode_receipt(required(object, "receipt")?)?,
            decode_unit(required(object, "unit")?)?,
        )),
        "denied" => LabResponse::Denied(DeniedResponse::new(
            identifier(object, "requestId")?,
            identifier(object, "code")?,
            string(object, "reason")?,
        )?),
        _ => return Err(CanonicalJsonError::UnknownEnum("kind")),
    };
    response.validate_for(request)?;
    Ok(response)
}

pub fn encode_transport_error(
    error: &TransportErrorDocument,
) -> Result<Vec<u8>, CanonicalJsonError> {
    serialize(&object([
        ("code", text(error.code.as_wire())),
        ("protocol", text(TRANSPORT_ERROR_PROTOCOL)),
        ("reason", text(error.reason())),
    ]))
}

pub fn decode_transport_error(
    payload: &[u8],
) -> Result<TransportErrorDocument, CanonicalJsonError> {
    let value = parse_canonical(payload)?;
    let object = exact_object(&value, &["code", "protocol", "reason"])?;
    version(object, TRANSPORT_ERROR_PROTOCOL)?;
    let code = TransportErrorCode::from_wire(string(object, "code")?)
        .ok_or(CanonicalJsonError::UnknownEnum("code"))?;
    Ok(TransportErrorDocument::new(
        code,
        string(object, "reason")?,
    )?)
}

fn parse_canonical(payload: &[u8]) -> Result<Value, CanonicalJsonError> {
    std::str::from_utf8(payload).map_err(|_| CanonicalJsonError::InvalidUtf8)?;
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| CanonicalJsonError::MalformedJson)?;
    validate_json_value(&value, 0)?;
    if serialize(&value)? != payload {
        return Err(CanonicalJsonError::Noncanonical);
    }
    if !value.is_object() {
        return Err(CanonicalJsonError::RootNotObject);
    }
    Ok(value)
}

fn validate_json_value(value: &Value, depth: usize) -> Result<(), CanonicalJsonError> {
    if depth > MAX_JSON_DEPTH {
        return Err(CanonicalJsonError::DepthExceeded);
    }
    match value {
        Value::Number(number) if number.as_u64().is_none() && number.as_i64().is_none() => {
            Err(CanonicalJsonError::FloatingPoint)
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_json_value(value, depth + 1)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_json_value(value, depth + 1)),
        _ => Ok(()),
    }
}

fn serialize(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    serde_json::to_vec(value).map_err(|_| CanonicalJsonError::MalformedJson)
}

fn request_fields(value: &Value) -> Result<&'static [&'static str], CanonicalJsonError> {
    let object = value.as_object().ok_or(CanonicalJsonError::RootNotObject)?;
    Ok(match string(object, "op")? {
        "select" => &[
            "budget",
            "execution",
            "expectedBase",
            "objectiveId",
            "op",
            "protocol",
            "providerPolicy",
            "requestId",
        ],
        "observe" => &[
            "afterSequence",
            "limit",
            "objectiveId",
            "op",
            "protocol",
            "requestId",
            "unitId",
        ],
        "resume" => &[
            "checkpointId",
            "expectedRevision",
            "idempotencyKey",
            "objectiveId",
            "op",
            "protocol",
            "requestId",
            "unitId",
        ],
        "cancel" => &[
            "expectedRevision",
            "idempotencyKey",
            "objectiveId",
            "op",
            "protocol",
            "reason",
            "requestId",
            "unitId",
        ],
        _ => return Err(CanonicalJsonError::UnknownEnum("op")),
    })
}

fn response_fields(value: &Value) -> Result<&'static [&'static str], CanonicalJsonError> {
    let object = value.as_object().ok_or(CanonicalJsonError::RootNotObject)?;
    Ok(match string(object, "kind")? {
        "selected" => &["kind", "protocol", "requestId", "unit"],
        "observed" => &[
            "events",
            "kind",
            "nextSequence",
            "protocol",
            "requestId",
            "unit",
        ],
        "action" => &["kind", "protocol", "receipt", "requestId", "unit"],
        "denied" => &["code", "kind", "protocol", "reason", "requestId"],
        _ => return Err(CanonicalJsonError::UnknownEnum("kind")),
    })
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, CanonicalJsonError> {
    let object = value.as_object().ok_or(CanonicalJsonError::RootNotObject)?;
    for field in fields {
        if !object.contains_key(*field) {
            return Err(CanonicalJsonError::MissingField(field_name(field)?));
        }
    }
    if let Some(field) = object
        .keys()
        .find(|field| !fields.contains(&field.as_str()))
    {
        return Err(CanonicalJsonError::UnknownField(field.clone()));
    }
    Ok(object)
}

fn field_name(field: &str) -> Result<&'static str, CanonicalJsonError> {
    match field {
        "protocol" => Ok("protocol"),
        "requestId" => Ok("requestId"),
        "op" => Ok("op"),
        "objectiveId" => Ok("objectiveId"),
        "expectedBase" => Ok("expectedBase"),
        "execution" => Ok("execution"),
        "providerPolicy" => Ok("providerPolicy"),
        "budget" => Ok("budget"),
        "unitId" => Ok("unitId"),
        "afterSequence" => Ok("afterSequence"),
        "limit" => Ok("limit"),
        "checkpointId" => Ok("checkpointId"),
        "expectedRevision" => Ok("expectedRevision"),
        "idempotencyKey" => Ok("idempotencyKey"),
        "reason" => Ok("reason"),
        "kind" => Ok("kind"),
        "unit" => Ok("unit"),
        "events" => Ok("events"),
        "nextSequence" => Ok("nextSequence"),
        "receipt" => Ok("receipt"),
        "code" => Ok("code"),
        _ => Err(CanonicalJsonError::MalformedJson),
    }
}

fn required<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, CanonicalJsonError> {
    object
        .get(field)
        .ok_or(CanonicalJsonError::MissingField(field))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, CanonicalJsonError> {
    required(object, field)?
        .as_str()
        .ok_or(CanonicalJsonError::WrongType(field))
}

fn uint(object: &Map<String, Value>, field: &'static str) -> Result<u64, CanonicalJsonError> {
    required(object, field)?
        .as_u64()
        .ok_or(CanonicalJsonError::WrongType(field))
}

fn array<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a [Value], CanonicalJsonError> {
    required(object, field)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(CanonicalJsonError::WrongType(field))
}

fn identifier(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<OpaqueId, CanonicalJsonError> {
    Ok(OpaqueId::new(string(object, field)?)?)
}

fn version(object: &Map<String, Value>, expected: &str) -> Result<(), CanonicalJsonError> {
    if string(object, "protocol")? == expected {
        Ok(())
    } else {
        Err(CanonicalJsonError::UnsupportedVersion)
    }
}

fn decode_select(object: &Map<String, Value>) -> Result<LabRequest, CanonicalJsonError> {
    let execution = match string(object, "execution")? {
        "synthetic" => Execution::Synthetic,
        "inventory" => Execution::Inventory,
        _ => return Err(CanonicalJsonError::UnknownEnum("execution")),
    };
    let policy = decode_policy(required(object, "providerPolicy")?)?;
    if execution == Execution::Inventory {
        return Err(CanonicalJsonError::UntrustedInventoryPolicy);
    }
    Ok(LabRequest::Select(SelectRequest::new(
        identifier(object, "requestId")?,
        identifier(object, "objectiveId")?,
        GitSha1::new(string(object, "expectedBase")?)?,
        execution,
        policy,
        decode_budget(required(object, "budget")?)?,
    )?))
}

fn decode_policy(value: &Value) -> Result<ProviderPolicy, CanonicalJsonError> {
    let object = value
        .as_object()
        .ok_or(CanonicalJsonError::WrongType("providerPolicy"))?;
    match string(object, "kind")? {
        "synthetic" => {
            exact_object(
                value,
                &[
                    "authentication",
                    "driver",
                    "kind",
                    "maxCostMicrounits",
                    "maxModelCalls",
                    "network",
                ],
            )?;
            if string(object, "driver")? != "in_process_fixture"
                || string(object, "network")? != "deny"
                || string(object, "authentication")? != "none"
                || uint(object, "maxModelCalls")? != 0
                || uint(object, "maxCostMicrounits")? != 0
            {
                return Err(CanonicalJsonError::UnknownEnum("providerPolicy"));
            }
            Ok(ProviderPolicy::Synthetic(SyntheticProviderPolicy))
        }
        "inventory" => {
            exact_object(
                value,
                &[
                    "explicitFallbacks",
                    "inventoryDigest",
                    "kind",
                    "minimumEvidence",
                    "mode",
                    "provider",
                    "requiredCapabilities",
                    "surfaceDigest",
                ],
            )?;
            let capabilities = array(object, "requiredCapabilities")?
                .iter()
                .map(|value| {
                    capability(
                        value
                            .as_str()
                            .ok_or(CanonicalJsonError::WrongType("requiredCapabilities"))?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let fallbacks = array(object, "explicitFallbacks")?
                .iter()
                .map(decode_fallback)
                .collect::<Result<Vec<_>, _>>()?;
            let evidence = match string(object, "minimumEvidence")? {
                "advertised" => EvidenceLevel::Advertised,
                "observed" => EvidenceLevel::Observed,
                _ => return Err(CanonicalJsonError::UnknownEnum("minimumEvidence")),
            };
            let _untrusted = UntrustedInventoryPolicy::new(
                identifier(object, "provider")?,
                identifier(object, "mode")?,
                Sha256Digest::new(string(object, "inventoryDigest")?)?,
                Sha256Digest::new(string(object, "surfaceDigest")?)?,
                capabilities,
                evidence,
                fallbacks,
            )?;
            Err(CanonicalJsonError::UntrustedInventoryPolicy)
        }
        _ => Err(CanonicalJsonError::UnknownEnum("providerPolicy.kind")),
    }
}

fn decode_fallback(value: &Value) -> Result<ExplicitFallback, CanonicalJsonError> {
    let object = exact_object(value, &["acceptedLostGuarantees", "mode"])?;
    let losses = array(object, "acceptedLostGuarantees")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(CanonicalJsonError::WrongType("acceptedLostGuarantees"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExplicitFallback::new(identifier(object, "mode")?, losses)?)
}

fn capability(value: &str) -> Result<Capability, CanonicalJsonError> {
    match value {
        "approval" => Ok(Capability::Approval),
        "cancel" => Ok(Capability::Cancel),
        "create" => Ok(Capability::Create),
        "model" => Ok(Capability::Model),
        "observe" => Ok(Capability::Observe),
        "reconnect" => Ok(Capability::Reconnect),
        "resume" => Ok(Capability::Resume),
        "steer" => Ok(Capability::Steer),
        "usage" => Ok(Capability::Usage),
        _ => Err(CanonicalJsonError::UnknownEnum("capability")),
    }
}

fn decode_budget(value: &Value) -> Result<LabBudget, CanonicalJsonError> {
    let object = exact_object(
        value,
        &[
            "enforcement",
            "maxCostMicrounits",
            "maxCpuMs",
            "maxDiskBytes",
            "maxModelCalls",
            "maxOutputBytes",
            "maxPids",
            "maxWallMs",
        ],
    )?;
    let enforcement = match string(object, "enforcement")? {
        "synthetic_in_process" => BudgetEnforcement::SyntheticInProcess,
        "host_broker_required" => BudgetEnforcement::HostBrokerRequired,
        _ => return Err(CanonicalJsonError::UnknownEnum("budget.enforcement")),
    };
    Ok(LabBudget::new(LabBudgetValues {
        max_wall_ms: uint(object, "maxWallMs")?,
        max_cpu_ms: uint(object, "maxCpuMs")?,
        max_disk_bytes: uint(object, "maxDiskBytes")?,
        max_output_bytes: uint(object, "maxOutputBytes")?,
        max_pids: uint(object, "maxPids")?,
        max_model_calls: uint(object, "maxModelCalls")?,
        max_cost_microunits: uint(object, "maxCostMicrounits")?,
        enforcement,
    })?)
}

fn decode_unit(value: &Value) -> Result<UnitSnapshot, CanonicalJsonError> {
    let object = exact_object(
        value,
        &[
            "checkpointId",
            "lastSequence",
            "objectiveId",
            "revision",
            "state",
            "unitId",
        ],
    )?;
    UnitSnapshot::new(
        identifier(object, "unitId")?,
        identifier(object, "objectiveId")?,
        unit_state(string(object, "state")?)?,
        uint(object, "revision")?,
        optional_identifier(object, "checkpointId")?,
        uint(object, "lastSequence")?,
    )
    .map_err(Into::into)
}

fn decode_event(value: &Value) -> Result<LabEvent, CanonicalJsonError> {
    let object = exact_object(
        value,
        &["objectiveId", "revision", "sequence", "type", "unitId"],
    )?;
    LabEvent::new(
        EventType::from_wire(string(object, "type")?)?,
        identifier(object, "objectiveId")?,
        identifier(object, "unitId")?,
        uint(object, "sequence")?,
        uint(object, "revision")?,
    )
    .map_err(Into::into)
}

fn decode_receipt(value: &Value) -> Result<ActionReceipt, CanonicalJsonError> {
    let object = exact_object(
        value,
        &[
            "actionId",
            "checkpointId",
            "effectCount",
            "expectedRevision",
            "idempotencyKey",
            "objectiveId",
            "operation",
            "reason",
            "status",
            "unitId",
        ],
    )?;
    ActionReceipt::new(
        ActionCoordinates {
            action_id: identifier(object, "actionId")?,
            operation: action_operation(string(object, "operation")?)?,
            objective_id: identifier(object, "objectiveId")?,
            unit_id: identifier(object, "unitId")?,
            checkpoint_id: optional_identifier(object, "checkpointId")?,
            expected_revision: uint(object, "expectedRevision")?,
            idempotency_key: identifier(object, "idempotencyKey")?,
        },
        ActionOutcome {
            status: action_status(string(object, "status")?)?,
            effect_count: uint(object, "effectCount")?,
            reason: optional_string(object, "reason")?,
        },
    )
    .map_err(Into::into)
}

fn optional_identifier(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<OpaqueId>, CanonicalJsonError> {
    match required(object, field)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(OpaqueId::new(value)?)),
        _ => Err(CanonicalJsonError::WrongType(field)),
    }
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, CanonicalJsonError> {
    match required(object, field)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(CanonicalJsonError::WrongType(field)),
    }
}

fn cancel_reason(value: &str) -> Result<CancelReason, CanonicalJsonError> {
    match value {
        "operator_request" => Ok(CancelReason::OperatorRequest),
        "budget_exhausted" => Ok(CancelReason::BudgetExhausted),
        "policy_denied" => Ok(CancelReason::PolicyDenied),
        _ => Err(CanonicalJsonError::UnknownEnum("reason")),
    }
}
fn action_operation(value: &str) -> Result<ActionOperation, CanonicalJsonError> {
    match value {
        "resume" => Ok(ActionOperation::Resume),
        "cancel" => Ok(ActionOperation::Cancel),
        _ => Err(CanonicalJsonError::UnknownEnum("operation")),
    }
}
fn action_status(value: &str) -> Result<ActionStatus, CanonicalJsonError> {
    match value {
        "accepted" => Ok(ActionStatus::Accepted),
        "already_applied" => Ok(ActionStatus::AlreadyApplied),
        "conflict" => Ok(ActionStatus::Conflict),
        "denied" => Ok(ActionStatus::Denied),
        _ => Err(CanonicalJsonError::UnknownEnum("status")),
    }
}
fn unit_state(value: &str) -> Result<UnitState, CanonicalJsonError> {
    match value {
        "queued" => Ok(UnitState::Queued),
        "selected" => Ok(UnitState::Selected),
        "running" => Ok(UnitState::Running),
        "paused" => Ok(UnitState::Paused),
        "cancel_requested" => Ok(UnitState::CancelRequested),
        "cancelled" => Ok(UnitState::Cancelled),
        "succeeded" => Ok(UnitState::Succeeded),
        "failed" => Ok(UnitState::Failed),
        "blocked" => Ok(UnitState::Blocked),
        _ => Err(CanonicalJsonError::UnknownEnum("state")),
    }
}

fn request_value(request: &LabRequest) -> Value {
    match request {
        LabRequest::Select(request) => object([
            ("budget", budget_value(request.budget())),
            ("execution", text(execution_wire(request.execution()))),
            ("expectedBase", text(request.expected_base().as_str())),
            ("objectiveId", text(request.objective_id().as_str())),
            ("op", text("select")),
            ("protocol", text(LAB_PROTOCOL)),
            ("providerPolicy", policy_value(request.provider_policy())),
            ("requestId", text(request.request_id().as_str())),
        ]),
        LabRequest::Observe(request) => object([
            ("afterSequence", number(request.after_sequence().get())),
            ("limit", number(request.limit().get())),
            ("objectiveId", text(request.objective_id().as_str())),
            ("op", text("observe")),
            ("protocol", text(LAB_PROTOCOL)),
            ("requestId", text(request.request_id().as_str())),
            ("unitId", text(request.unit_id().as_str())),
        ]),
        LabRequest::Resume(request) => object([
            ("checkpointId", text(request.checkpoint_id().as_str())),
            (
                "expectedRevision",
                number(request.expected_revision().get()),
            ),
            ("idempotencyKey", text(request.idempotency_key().as_str())),
            ("objectiveId", text(request.objective_id().as_str())),
            ("op", text("resume")),
            ("protocol", text(LAB_PROTOCOL)),
            ("requestId", text(request.request_id().as_str())),
            ("unitId", text(request.unit_id().as_str())),
        ]),
        LabRequest::Cancel(request) => object([
            (
                "expectedRevision",
                number(request.expected_revision().get()),
            ),
            ("idempotencyKey", text(request.idempotency_key().as_str())),
            ("objectiveId", text(request.objective_id().as_str())),
            ("op", text("cancel")),
            ("protocol", text(LAB_PROTOCOL)),
            ("reason", text(cancel_reason_wire(request.reason()))),
            ("requestId", text(request.request_id().as_str())),
            ("unitId", text(request.unit_id().as_str())),
        ]),
    }
}

fn response_value(response: &LabResponse) -> Value {
    match response {
        LabResponse::Selected(response) => object([
            ("kind", text("selected")),
            ("protocol", text(LAB_PROTOCOL)),
            ("requestId", text(response.request_id().as_str())),
            ("unit", unit_value(response.unit())),
        ]),
        LabResponse::Observed(response) => object([
            (
                "events",
                Value::Array(response.events().iter().map(event_value).collect()),
            ),
            ("kind", text("observed")),
            ("nextSequence", number(response.next_sequence().get())),
            ("protocol", text(LAB_PROTOCOL)),
            ("requestId", text(response.request_id().as_str())),
            ("unit", unit_value(response.unit())),
        ]),
        LabResponse::Action(response) => object([
            ("kind", text("action")),
            ("protocol", text(LAB_PROTOCOL)),
            ("receipt", receipt_value(response.receipt())),
            ("requestId", text(response.request_id().as_str())),
            ("unit", unit_value(response.unit())),
        ]),
        LabResponse::Denied(response) => object([
            ("code", text(response.code().as_str())),
            ("kind", text("denied")),
            ("protocol", text(LAB_PROTOCOL)),
            ("reason", text(response.reason().as_str())),
            ("requestId", text(response.request_id().as_str())),
        ]),
    }
}

fn budget_value(value: &LabBudget) -> Value {
    object([
        (
            "enforcement",
            text(match value.enforcement() {
                BudgetEnforcement::SyntheticInProcess => "synthetic_in_process",
                BudgetEnforcement::HostBrokerRequired => "host_broker_required",
            }),
        ),
        (
            "maxCostMicrounits",
            number(value.max_cost_microunits().get()),
        ),
        ("maxCpuMs", number(value.max_cpu_ms().get())),
        ("maxDiskBytes", number(value.max_disk_bytes().get())),
        ("maxModelCalls", number(value.max_model_calls().get())),
        ("maxOutputBytes", number(value.max_output_bytes().get())),
        ("maxPids", number(value.max_pids().get())),
        ("maxWallMs", number(value.max_wall_ms().get())),
    ])
}

fn policy_value(value: &ProviderPolicy) -> Value {
    match value {
        ProviderPolicy::Synthetic(_) => object([
            ("authentication", text("none")),
            ("driver", text("in_process_fixture")),
            ("kind", text("synthetic")),
            ("maxCostMicrounits", number(0)),
            ("maxModelCalls", number(0)),
            ("network", text("deny")),
        ]),
        ProviderPolicy::VerifiedInventory(policy) => {
            let policy = policy.coordinates();
            object([
                (
                    "explicitFallbacks",
                    Value::Array(
                        policy
                            .explicit_fallbacks()
                            .iter()
                            .map(|fallback| {
                                object([
                                    (
                                        "acceptedLostGuarantees",
                                        Value::Array(
                                            fallback
                                                .accepted_lost_guarantees()
                                                .iter()
                                                .map(|loss| text(loss.as_str()))
                                                .collect(),
                                        ),
                                    ),
                                    ("mode", text(fallback.mode().as_str())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("inventoryDigest", text(policy.inventory_digest().as_str())),
                ("kind", text("inventory")),
                (
                    "minimumEvidence",
                    text(match policy.minimum_evidence() {
                        crate::protocol::EvidenceLevel::Advertised => "advertised",
                        crate::protocol::EvidenceLevel::Observed => "observed",
                    }),
                ),
                ("mode", text(policy.mode().as_str())),
                ("provider", text(policy.provider().as_str())),
                (
                    "requiredCapabilities",
                    Value::Array(
                        policy
                            .required_capabilities()
                            .iter()
                            .map(|capability| text(capability_wire(*capability)))
                            .collect(),
                    ),
                ),
                ("surfaceDigest", text(policy.surface_digest().as_str())),
            ])
        }
    }
}

fn unit_value(value: &UnitSnapshot) -> Value {
    object([
        (
            "checkpointId",
            value
                .checkpoint_id()
                .map_or(Value::Null, |id| text(id.as_str())),
        ),
        ("lastSequence", number(value.last_sequence().get())),
        ("objectiveId", text(value.objective_id().as_str())),
        ("revision", number(value.revision().get())),
        ("state", text(unit_state_wire(value.state()))),
        ("unitId", text(value.unit_id().as_str())),
    ])
}
fn event_value(value: &LabEvent) -> Value {
    object([
        ("objectiveId", text(value.objective_id().as_str())),
        ("revision", number(value.revision().get())),
        ("sequence", number(value.sequence().get())),
        ("type", text(value.event_type().as_wire())),
        ("unitId", text(value.unit_id().as_str())),
    ])
}
fn receipt_value(value: &ActionReceipt) -> Value {
    object([
        ("actionId", text(value.action_id().as_str())),
        (
            "checkpointId",
            value
                .checkpoint_id()
                .map_or(Value::Null, |id| text(id.as_str())),
        ),
        ("effectCount", number(value.effect_count().get())),
        ("expectedRevision", number(value.expected_revision().get())),
        ("idempotencyKey", text(value.idempotency_key().as_str())),
        ("objectiveId", text(value.objective_id().as_str())),
        ("operation", text(action_operation_wire(value.operation()))),
        (
            "reason",
            value
                .reason()
                .map_or(Value::Null, |reason| text(reason.as_str())),
        ),
        ("status", text(action_status_wire(value.status()))),
        ("unitId", text(value.unit_id().as_str())),
    ])
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}
fn number(value: u64) -> Value {
    Value::Number(Number::from(value))
}
fn execution_wire(value: Execution) -> &'static str {
    match value {
        Execution::Synthetic => "synthetic",
        Execution::Inventory => "inventory",
    }
}
fn cancel_reason_wire(value: CancelReason) -> &'static str {
    match value {
        CancelReason::OperatorRequest => "operator_request",
        CancelReason::BudgetExhausted => "budget_exhausted",
        CancelReason::PolicyDenied => "policy_denied",
    }
}
fn action_operation_wire(value: ActionOperation) -> &'static str {
    match value {
        ActionOperation::Resume => "resume",
        ActionOperation::Cancel => "cancel",
    }
}
fn action_status_wire(value: ActionStatus) -> &'static str {
    match value {
        ActionStatus::Accepted => "accepted",
        ActionStatus::AlreadyApplied => "already_applied",
        ActionStatus::Conflict => "conflict",
        ActionStatus::Denied => "denied",
    }
}
fn unit_state_wire(value: UnitState) -> &'static str {
    match value {
        UnitState::Queued => "queued",
        UnitState::Selected => "selected",
        UnitState::Running => "running",
        UnitState::Paused => "paused",
        UnitState::CancelRequested => "cancel_requested",
        UnitState::Cancelled => "cancelled",
        UnitState::Succeeded => "succeeded",
        UnitState::Failed => "failed",
        UnitState::Blocked => "blocked",
    }
}
fn capability_wire(value: Capability) -> &'static str {
    match value {
        Capability::Approval => "approval",
        Capability::Cancel => "cancel",
        Capability::Create => "create",
        Capability::Model => "model",
        Capability::Observe => "observe",
        Capability::Reconnect => "reconnect",
        Capability::Resume => "resume",
        Capability::Steer => "steer",
        Capability::Usage => "usage",
    }
}
