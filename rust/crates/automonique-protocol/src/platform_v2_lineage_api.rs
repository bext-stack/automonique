// SPDX-License-Identifier: Elastic-2.0

//! Strict canonical Platform v2 lineage documents.

use core::fmt;

use crate::codec::CodecError;
use crate::platform_v2::{
    AttemptWorkspaceId, NegotiatedPlatform, PLATFORM_SCHEMA_V2, PaneId, PlatformVersion,
    UserWorkspaceId, WorkSessionId,
};
use crate::platform_v2_lineage::*;
use crate::primitives::{Revision, RevisionError, ValueError};
use crate::wire::{JsonValue, parse_canonical};

pub const MAX_LINEAGE_CANONICAL_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageApiError {
    Codec(CodecError),
    Value(LineageError),
    Field(ValueError),
    Revision(RevisionError),
    InvalidBody,
    CounterOutOfRange,
    FrameTooLarge,
    VersionUnavailable,
}

impl LineageApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Codec(value) => value.category(),
            Self::Value(_) | Self::Field(_) | Self::Revision(_) | Self::VersionUnavailable => {
                "work_context_value_invalid"
            }
            Self::InvalidBody => "work_context_invalid_body",
            Self::CounterOutOfRange => "work_context_counter_out_of_range",
            Self::FrameTooLarge => "frame_too_large",
        }
    }
}

impl fmt::Display for LineageApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.category())
    }
}
impl std::error::Error for LineageApiError {}
impl From<CodecError> for LineageApiError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<LineageError> for LineageApiError {
    fn from(value: LineageError) -> Self {
        Self::Value(value)
    }
}
impl From<ValueError> for LineageApiError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
impl From<RevisionError> for LineageApiError {
    fn from(value: RevisionError) -> Self {
        Self::Revision(value)
    }
}

pub fn require_lineage_v2(negotiated: &NegotiatedPlatform) -> Result<(), LineageApiError> {
    if negotiated.version() == PlatformVersion::V2 && negotiated.schema() == PLATFORM_SCHEMA_V2 {
        Ok(())
    } else {
        Err(LineageApiError::VersionUnavailable)
    }
}

fn obj(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}
fn fields(value: &JsonValue, expected: &[&str]) -> Result<(), LineageApiError> {
    let JsonValue::Object(entries) = value else {
        return Err(LineageApiError::InvalidBody);
    };
    if entries.len() != expected.len()
        || entries
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err(LineageApiError::InvalidBody);
    }
    Ok(())
}
fn get<'a>(value: &'a JsonValue, name: &str) -> Result<&'a JsonValue, LineageApiError> {
    value.get(name).ok_or(LineageApiError::InvalidBody)
}
fn string<'a>(value: &'a JsonValue, name: &str) -> Result<&'a str, LineageApiError> {
    get(value, name)?
        .as_str()
        .ok_or(LineageApiError::InvalidBody)
}
fn uint(value: &JsonValue, name: &str) -> Result<u64, LineageApiError> {
    u64::try_from(
        get(value, name)?
            .as_integer()
            .ok_or(LineageApiError::InvalidBody)?,
    )
    .map_err(|_| LineageApiError::CounterOutOfRange)
}
fn integer(value: u64) -> Result<JsonValue, LineageApiError> {
    Ok(JsonValue::Integer(
        i64::try_from(value).map_err(|_| LineageApiError::CounterOutOfRange)?,
    ))
}
fn nullable<T>(
    value: &JsonValue,
    decode: impl FnOnce(&JsonValue) -> Result<T, LineageApiError>,
) -> Result<Option<T>, LineageApiError> {
    if matches!(value, JsonValue::Null) {
        Ok(None)
    } else {
        decode(value).map(Some)
    }
}
fn optional<T>(value: Option<&T>, encode: impl FnOnce(&T) -> JsonValue) -> JsonValue {
    value.map_or(JsonValue::Null, encode)
}

fn identity_json(value: &ExternalWorkIdentity) -> JsonValue {
    obj(vec![
        (
            "authority",
            JsonValue::String(value.authority().as_str().to_owned()),
        ),
        ("key", JsonValue::String(value.key().as_str().to_owned())),
        (
            "provider",
            JsonValue::String(value.provider().as_str().to_owned()),
        ),
        (
            "scope",
            JsonValue::String(value.scope().as_str().to_owned()),
        ),
    ])
}
fn identity(value: &JsonValue) -> Result<ExternalWorkIdentity, LineageApiError> {
    fields(value, &["authority", "key", "provider", "scope"])?;
    Ok(ExternalWorkIdentity::new(
        ExternalWorkProvider::parse(string(value, "provider")?)?,
        ExternalWorkAuthorityId::new(string(value, "authority")?.to_owned())?,
        ExternalWorkScope::new(string(value, "scope")?.to_owned())?,
        ExternalWorkKey::new(string(value, "key")?.to_owned())?,
    ))
}

fn origin_json(value: &LineageOrigin) -> JsonValue {
    obj(vec![
        (
            "attempt",
            optional(value.attempt(), |v| {
                JsonValue::String(v.as_str().to_owned())
            }),
        ),
        (
            "pane",
            optional(value.pane(), |v| JsonValue::String(v.as_str().to_owned())),
        ),
        (
            "session",
            optional(value.session(), |v| {
                JsonValue::String(v.as_str().to_owned())
            }),
        ),
        (
            "workspace",
            JsonValue::String(value.workspace().as_str().to_owned()),
        ),
    ])
}
fn optional_id<T>(
    value: &JsonValue,
    build: impl FnOnce(String) -> Result<T, ValueError>,
) -> Result<Option<T>, LineageApiError> {
    nullable(value, |v| {
        build(v.as_str().ok_or(LineageApiError::InvalidBody)?.to_owned()).map_err(Into::into)
    })
}
fn origin(value: &JsonValue) -> Result<LineageOrigin, LineageApiError> {
    fields(value, &["attempt", "pane", "session", "workspace"])?;
    Ok(LineageOrigin::new(
        UserWorkspaceId::new(string(value, "workspace")?.to_owned())?,
        optional_id(get(value, "attempt")?, AttemptWorkspaceId::new)?,
        optional_id(get(value, "session")?, WorkSessionId::new)?,
        optional_id(get(value, "pane")?, PaneId::new)?,
    )?)
}

fn freshness_json(value: LineageFreshness) -> Result<JsonValue, LineageApiError> {
    Ok(obj(vec![
        ("observed_at_ms", integer(value.observed_at_ms())?),
        ("stale_after_ms", integer(value.stale_after_ms())?),
        (
            "state",
            JsonValue::String(value.state().as_str().to_owned()),
        ),
    ]))
}
fn freshness(value: &JsonValue) -> Result<LineageFreshness, LineageApiError> {
    fields(value, &["observed_at_ms", "stale_after_ms", "state"])?;
    let state_name = string(value, "state")?;
    let state = LineageFreshnessState::ALL
        .into_iter()
        .find(|v| v.as_str() == state_name)
        .ok_or(LineageApiError::InvalidBody)?;
    Ok(LineageFreshness::new(
        uint(value, "observed_at_ms")?,
        uint(value, "stale_after_ms")?,
        state,
    )?)
}
fn message_json(value: &LatestUsefulMessage) -> Result<JsonValue, LineageApiError> {
    Ok(obj(vec![
        ("observed_at_ms", integer(value.observed_at_ms())?),
        ("text", JsonValue::String(value.text().as_str().to_owned())),
    ]))
}
fn message(value: &JsonValue) -> Result<LatestUsefulMessage, LineageApiError> {
    fields(value, &["observed_at_ms", "text"])?;
    Ok(LatestUsefulMessage::new(
        LineageMessage::new(string(value, "text")?.to_owned())?,
        uint(value, "observed_at_ms")?,
    )?)
}

fn orchestration_identity_json(value: &OrchestrationIdentity) -> JsonValue {
    obj(vec![
        ("id", JsonValue::String(value.id().to_owned())),
        ("kind", JsonValue::String(value.kind().as_str().to_owned())),
    ])
}
fn orchestration_identity(value: &JsonValue) -> Result<OrchestrationIdentity, LineageApiError> {
    fields(value, &["id", "kind"])?;
    let id = string(value, "id")?.to_owned();
    Ok(match string(value, "kind")? {
        "run" => OrchestrationIdentity::Run(OrchestrationRunId::new(id)?),
        "task" => OrchestrationIdentity::Task(OrchestrationTaskId::new(id)?),
        "dispatch" => OrchestrationIdentity::Dispatch(OrchestrationDispatchId::new(id)?),
        "worker" => OrchestrationIdentity::Worker(OrchestrationWorkerId::new(id)?),
        "heartbeat" => OrchestrationIdentity::Heartbeat(OrchestrationHeartbeatId::new(id)?),
        "question" => OrchestrationIdentity::Question(OrchestrationQuestionId::new(id)?),
        "decision_gate" => {
            OrchestrationIdentity::DecisionGate(OrchestrationDecisionGateId::new(id)?)
        }
        _ => return Err(LineageApiError::InvalidBody),
    })
}

fn status_json(value: &LineageStatus) -> JsonValue {
    match value {
        LineageStatus::Working => obj(vec![("kind", JsonValue::String("working".to_owned()))]),
        LineageStatus::Blocked(v) => obj(vec![
            ("kind", JsonValue::String("blocked".to_owned())),
            ("reason", JsonValue::String(v.as_str().to_owned())),
        ]),
        LineageStatus::Waiting(v) => obj(vec![
            ("kind", JsonValue::String("waiting".to_owned())),
            ("reason", JsonValue::String(v.as_str().to_owned())),
        ]),
        LineageStatus::Done(v) => obj(vec![
            ("kind", JsonValue::String("done".to_owned())),
            ("outcome", JsonValue::String(v.as_str().to_owned())),
        ]),
    }
}
fn status(value: &JsonValue) -> Result<LineageStatus, LineageApiError> {
    Ok(match string(value, "kind")? {
        "working" => {
            fields(value, &["kind"])?;
            LineageStatus::Working
        }
        "blocked" => {
            fields(value, &["kind", "reason"])?;
            LineageStatus::Blocked(LineageMessage::new(string(value, "reason")?.to_owned())?)
        }
        "waiting" => {
            fields(value, &["kind", "reason"])?;
            LineageStatus::Waiting(LineageMessage::new(string(value, "reason")?.to_owned())?)
        }
        "done" => {
            fields(value, &["kind", "outcome"])?;
            LineageStatus::Done(LineageMessage::new(string(value, "outcome")?.to_owned())?)
        }
        _ => return Err(LineageApiError::InvalidBody),
    })
}

fn external_json(value: &ExternalWorkItem) -> Result<JsonValue, LineageApiError> {
    Ok(obj(vec![
        ("freshness", freshness_json(value.freshness())?),
        ("identity", identity_json(value.identity())),
        (
            "latest_useful_message",
            match value.latest_useful_message() {
                Some(v) => message_json(v)?,
                None => JsonValue::Null,
            },
        ),
        ("moved_to", optional(value.moved_to(), identity_json)),
        ("origin", origin_json(value.origin())),
        ("revision", integer(value.revision().get())?),
        (
            "state",
            JsonValue::String(value.state().as_str().to_owned()),
        ),
        (
            "workspace",
            JsonValue::String(value.workspace().as_str().to_owned()),
        ),
    ]))
}
fn external(value: &JsonValue) -> Result<ExternalWorkItem, LineageApiError> {
    fields(
        value,
        &[
            "freshness",
            "identity",
            "latest_useful_message",
            "moved_to",
            "origin",
            "revision",
            "state",
            "workspace",
        ],
    )?;
    let state_name = string(value, "state")?;
    let state = ExternalWorkState::ALL
        .into_iter()
        .find(|v| v.as_str() == state_name)
        .ok_or(LineageApiError::InvalidBody)?;
    let result = ExternalWorkItem::new_with_origin(
        identity(get(value, "identity")?)?,
        origin(get(value, "origin")?)?,
        Revision::new(uint(value, "revision")?)?,
        state,
        nullable(get(value, "moved_to")?, identity)?,
        freshness(get(value, "freshness")?)?,
        nullable(get(value, "latest_useful_message")?, message)?,
    )?;
    if result.workspace().as_str() != string(value, "workspace")? {
        return Err(LineageApiError::InvalidBody);
    }
    Ok(result)
}

fn record_json(value: &OrchestrationRecord) -> Result<JsonValue, LineageApiError> {
    Ok(obj(vec![
        (
            "external_work",
            optional(value.external_work(), identity_json),
        ),
        ("freshness", freshness_json(value.freshness())?),
        ("identity", orchestration_identity_json(value.identity())),
        (
            "latest_useful_message",
            match value.latest_useful_message() {
                Some(v) => message_json(v)?,
                None => JsonValue::Null,
            },
        ),
        ("origin", origin_json(value.origin())),
        (
            "parent",
            optional(value.parent(), orchestration_identity_json),
        ),
        ("revision", integer(value.revision().get())?),
        ("status", status_json(value.status())),
        (
            "workspace",
            JsonValue::String(value.workspace().as_str().to_owned()),
        ),
    ]))
}
fn record(value: &JsonValue) -> Result<OrchestrationRecord, LineageApiError> {
    fields(
        value,
        &[
            "external_work",
            "freshness",
            "identity",
            "latest_useful_message",
            "origin",
            "parent",
            "revision",
            "status",
            "workspace",
        ],
    )?;
    let result = OrchestrationRecord::new_with_origin(
        orchestration_identity(get(value, "identity")?)?,
        origin(get(value, "origin")?)?,
        nullable(get(value, "external_work")?, identity)?,
        nullable(get(value, "parent")?, orchestration_identity)?,
        status(get(value, "status")?)?,
        freshness(get(value, "freshness")?)?,
        nullable(get(value, "latest_useful_message")?, message)?,
        Revision::new(uint(value, "revision")?)?,
    )?;
    if result.workspace().as_str() != string(value, "workspace")? {
        return Err(LineageApiError::InvalidBody);
    }
    Ok(result)
}

fn envelope(value: JsonValue) -> JsonValue {
    obj(vec![
        ("platform_version", JsonValue::Integer(2)),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        ("value", value),
    ])
}
fn decoded_value(payload: &[u8]) -> Result<JsonValue, LineageApiError> {
    if payload.len() > MAX_LINEAGE_CANONICAL_BYTES {
        return Err(LineageApiError::FrameTooLarge);
    }
    let envelope = parse_canonical(payload)?;
    fields(&envelope, &["platform_version", "schema", "value"])?;
    if uint(&envelope, "platform_version")? != 2
        || string(&envelope, "schema")? != PLATFORM_SCHEMA_V2
    {
        return Err(LineageApiError::VersionUnavailable);
    }
    Ok(get(&envelope, "value")?.clone())
}
fn encoded(value: JsonValue) -> Result<Vec<u8>, LineageApiError> {
    let bytes = envelope(value).to_canonical_bytes();
    if bytes.len() > MAX_LINEAGE_CANONICAL_BYTES {
        Err(LineageApiError::FrameTooLarge)
    } else {
        Ok(bytes)
    }
}

pub fn encode_lineage_projection(
    negotiated: &NegotiatedPlatform,
    value: &LineageProjection,
) -> Result<Vec<u8>, LineageApiError> {
    require_lineage_v2(negotiated)?;
    encoded(obj(vec![
        (
            "external_work_items",
            JsonValue::Array(
                value
                    .external_work_items()
                    .iter()
                    .map(external_json)
                    .collect::<Result<_, _>>()?,
            ),
        ),
        (
            "orchestration",
            JsonValue::Array(
                value
                    .orchestration()
                    .iter()
                    .map(record_json)
                    .collect::<Result<_, _>>()?,
            ),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        (
            "workspace",
            JsonValue::String(value.workspace().as_str().to_owned()),
        ),
    ]))
}
pub fn decode_lineage_projection(
    negotiated: &NegotiatedPlatform,
    payload: &[u8],
) -> Result<LineageProjection, LineageApiError> {
    require_lineage_v2(negotiated)?;
    let value = decoded_value(payload)?;
    fields(
        &value,
        &[
            "external_work_items",
            "orchestration",
            "schema",
            "workspace",
        ],
    )?;
    if string(&value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(LineageApiError::VersionUnavailable);
    }
    let array = |name| {
        get(&value, name)?
            .as_array()
            .ok_or(LineageApiError::InvalidBody)
    };
    Ok(LineageProjection::new(
        UserWorkspaceId::new(string(&value, "workspace")?.to_owned())?,
        array("external_work_items")?
            .iter()
            .map(external)
            .collect::<Result<_, _>>()?,
        array("orchestration")?
            .iter()
            .map(record)
            .collect::<Result<_, _>>()?,
    )?)
}

fn intent_json(value: &WorkspaceIntent) -> Result<JsonValue, LineageApiError> {
    Ok(match value {
        WorkspaceIntent::Create(v) => obj(vec![
            ("kind", JsonValue::String("create".to_owned())),
            (
                "request",
                obj(vec![
                    (
                        "base_selector",
                        JsonValue::String(v.base_selector().as_str().to_owned()),
                    ),
                    (
                        "branch_selector",
                        JsonValue::String(v.branch_selector().as_str().to_owned()),
                    ),
                    ("external_work", identity_json(v.external_work())),
                    (
                        "intent_id",
                        JsonValue::String(v.intent_id().as_str().to_owned()),
                    ),
                    ("task", JsonValue::String(v.task().as_str().to_owned())),
                ]),
            ),
        ]),
        WorkspaceIntent::Resume(v) => obj(vec![
            ("kind", JsonValue::String("resume".to_owned())),
            (
                "request",
                obj(vec![
                    ("expected_revision", integer(v.expected_revision().get())?),
                    (
                        "intent_id",
                        JsonValue::String(v.intent_id().as_str().to_owned()),
                    ),
                    ("task", JsonValue::String(v.task().as_str().to_owned())),
                    (
                        "workspace",
                        JsonValue::String(v.workspace().as_str().to_owned()),
                    ),
                ]),
            ),
        ]),
    })
}
fn intent(value: &JsonValue) -> Result<WorkspaceIntent, LineageApiError> {
    fields(value, &["kind", "request"])?;
    let request = get(value, "request")?;
    Ok(match string(value, "kind")? {
        "create" => {
            fields(
                request,
                &[
                    "base_selector",
                    "branch_selector",
                    "external_work",
                    "intent_id",
                    "task",
                ],
            )?;
            WorkspaceIntent::Create(WorkspaceCreateIntent::new(
                WorkspaceIntentId::new(string(request, "intent_id")?.to_owned())?,
                OrchestrationTaskId::new(string(request, "task")?.to_owned())?,
                identity(get(request, "external_work")?)?,
                BaseSelectorId::new(string(request, "base_selector")?.to_owned())?,
                BranchSelectorId::new(string(request, "branch_selector")?.to_owned())?,
            ))
        }
        "resume" => {
            fields(
                request,
                &["expected_revision", "intent_id", "task", "workspace"],
            )?;
            WorkspaceIntent::Resume(WorkspaceResumeIntent::new(
                WorkspaceIntentId::new(string(request, "intent_id")?.to_owned())?,
                OrchestrationTaskId::new(string(request, "task")?.to_owned())?,
                UserWorkspaceId::new(string(request, "workspace")?.to_owned())?,
                Revision::new(uint(request, "expected_revision")?)?,
            ))
        }
        _ => return Err(LineageApiError::InvalidBody),
    })
}
pub fn encode_workspace_intent(
    negotiated: &NegotiatedPlatform,
    value: &WorkspaceIntent,
) -> Result<Vec<u8>, LineageApiError> {
    require_lineage_v2(negotiated)?;
    encoded(intent_json(value)?)
}
pub fn decode_workspace_intent(
    negotiated: &NegotiatedPlatform,
    payload: &[u8],
) -> Result<WorkspaceIntent, LineageApiError> {
    require_lineage_v2(negotiated)?;
    intent(&decoded_value(payload)?)
}

fn outcome_json(value: &WorkspaceIntentOutcome) -> JsonValue {
    match value {
        WorkspaceIntentOutcome::Accepted => {
            obj(vec![("kind", JsonValue::String("accepted".to_owned()))])
        }
        WorkspaceIntentOutcome::Unknown => {
            obj(vec![("kind", JsonValue::String("unknown".to_owned()))])
        }
        WorkspaceIntentOutcome::Created(v) => obj(vec![
            ("kind", JsonValue::String("created".to_owned())),
            ("workspace", JsonValue::String(v.as_str().to_owned())),
        ]),
        WorkspaceIntentOutcome::Resumed(v) => obj(vec![
            ("kind", JsonValue::String("resumed".to_owned())),
            ("workspace", JsonValue::String(v.as_str().to_owned())),
        ]),
        WorkspaceIntentOutcome::Conflict(v) => obj(vec![
            ("conflict", JsonValue::String(v.as_str().to_owned())),
            ("kind", JsonValue::String("conflict".to_owned())),
        ]),
    }
}
fn outcome(value: &JsonValue) -> Result<WorkspaceIntentOutcome, LineageApiError> {
    Ok(match string(value, "kind")? {
        "accepted" => {
            fields(value, &["kind"])?;
            WorkspaceIntentOutcome::Accepted
        }
        "unknown" => {
            fields(value, &["kind"])?;
            WorkspaceIntentOutcome::Unknown
        }
        "created" => {
            fields(value, &["kind", "workspace"])?;
            WorkspaceIntentOutcome::Created(UserWorkspaceId::new(
                string(value, "workspace")?.to_owned(),
            )?)
        }
        "resumed" => {
            fields(value, &["kind", "workspace"])?;
            WorkspaceIntentOutcome::Resumed(UserWorkspaceId::new(
                string(value, "workspace")?.to_owned(),
            )?)
        }
        "conflict" => {
            fields(value, &["conflict", "kind"])?;
            let conflict = WorkspaceIntentConflict::ALL
                .into_iter()
                .find(|v| v.as_str() == string(value, "conflict").unwrap_or(""))
                .ok_or(LineageApiError::InvalidBody)?;
            WorkspaceIntentOutcome::Conflict(conflict)
        }
        _ => return Err(LineageApiError::InvalidBody),
    })
}
pub fn encode_workspace_intent_outcome(
    negotiated: &NegotiatedPlatform,
    value: &WorkspaceIntentOutcome,
) -> Result<Vec<u8>, LineageApiError> {
    require_lineage_v2(negotiated)?;
    encoded(outcome_json(value))
}
pub fn decode_workspace_intent_outcome(
    negotiated: &NegotiatedPlatform,
    payload: &[u8],
) -> Result<WorkspaceIntentOutcome, LineageApiError> {
    require_lineage_v2(negotiated)?;
    outcome(&decoded_value(payload)?)
}
