// SPDX-License-Identifier: Elastic-2.0

//! Exact canonical JSON documents for Platform v2 work-context lifecycle.

use core::fmt;
use core::str::FromStr;

use crate::identity::Actor;
use crate::platform::{IdempotencyKey, ReceiptId, ReceiptOutcome, ResourceAuthority};
use crate::platform_v2::{PLATFORM_SCHEMA_V2, WorkContextLabel};
use crate::platform_v2_api::{
    WorkContextApiError, admitted_document, array, exact_fields, identity, identity_json, integer,
    object, record, record_json, string, unsigned,
};
use crate::platform_v2_lifecycle::*;
use crate::primitives::{EpochMillis, Revision};
use crate::wire::JsonValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleApiError {
    WorkContext(WorkContextApiError),
    Lifecycle(LifecycleError),
    InvalidBody,
    CounterOutOfRange { field: &'static str },
    FrameTooLarge,
}

impl LifecycleApiError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::WorkContext(error) => error.category(),
            Self::Lifecycle(_) => "work_context_value_invalid",
            Self::InvalidBody => "work_context_lifecycle_invalid_body",
            Self::CounterOutOfRange { .. } => "work_context_lifecycle_counter_out_of_range",
            Self::FrameTooLarge => "frame_too_large",
        }
    }
}
impl fmt::Display for LifecycleApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}
impl std::error::Error for LifecycleApiError {}
impl From<WorkContextApiError> for LifecycleApiError {
    fn from(value: WorkContextApiError) -> Self {
        Self::WorkContext(value)
    }
}
impl From<LifecycleError> for LifecycleApiError {
    fn from(value: LifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}
impl From<crate::platform_v2::WorkContextError> for LifecycleApiError {
    fn from(value: crate::platform_v2::WorkContextError) -> Self {
        Self::Lifecycle(value.into())
    }
}

fn field<'a>(value: &'a JsonValue, name: &'static str) -> Result<&'a JsonValue, LifecycleApiError> {
    value.get(name).ok_or(LifecycleApiError::InvalidBody)
}
fn signed(value: &JsonValue, name: &'static str) -> Result<i64, LifecycleApiError> {
    value
        .get(name)
        .and_then(JsonValue::as_integer)
        .ok_or(LifecycleApiError::InvalidBody)
}
fn admitted(bytes: &[u8]) -> Result<JsonValue, LifecycleApiError> {
    if bytes.len() > MAX_MUTATION_CANONICAL_BYTES {
        return Err(LifecycleApiError::FrameTooLarge);
    }
    admitted_document(bytes, MAX_MUTATION_CANONICAL_BYTES).map_err(Into::into)
}
fn canonical_document(value: JsonValue) -> Result<Vec<u8>, LifecycleApiError> {
    let bytes = value.to_canonical_bytes();
    if bytes.len() > MAX_MUTATION_CANONICAL_BYTES {
        return Err(LifecycleApiError::FrameTooLarge);
    }
    Ok(bytes)
}
fn check_schema(value: &JsonValue) -> Result<(), LifecycleApiError> {
    if string(value, "schema")? != PLATFORM_SCHEMA_V2 {
        return Err(LifecycleError::Field { field: "schema" }.into());
    }
    Ok(())
}

fn actor_json(actor: &Actor) -> JsonValue {
    object(vec![
        ("id", JsonValue::String(actor.id().to_owned())),
        ("tenant", JsonValue::String(actor.tenant().to_owned())),
    ])
}
fn actor(value: &JsonValue) -> Result<Actor, LifecycleApiError> {
    exact_fields(value, &["id", "tenant"])?;
    Actor::new(string(value, "tenant")?, string(value, "id")?)
        .map_err(|_| LifecycleError::Field { field: "actor" }.into())
}

fn grants_json(grants: &[AuthorityGrantId]) -> JsonValue {
    JsonValue::Array(
        grants
            .iter()
            .map(|grant| JsonValue::String(grant.as_str().to_owned()))
            .collect(),
    )
}
fn authority_json(authority: &WorkContextAuthority) -> JsonValue {
    object(vec![
        ("credentials", grants_json(authority.credentials())),
        ("filesystem", grants_json(authority.filesystem())),
        ("models", grants_json(authority.models())),
        ("network", grants_json(authority.network())),
        ("providers", grants_json(authority.providers())),
        ("tools", grants_json(authority.tools())),
    ])
}
fn grants(
    value: &JsonValue,
    name: &'static str,
) -> Result<Vec<AuthorityGrantId>, LifecycleApiError> {
    array(value, name)?
        .iter()
        .map(|item| {
            let JsonValue::String(item) = item else {
                return Err(LifecycleApiError::InvalidBody);
            };
            AuthorityGrantId::new(item.clone()).map_err(Into::into)
        })
        .collect()
}
fn authority(value: &JsonValue) -> Result<WorkContextAuthority, LifecycleApiError> {
    exact_fields(
        value,
        &[
            "credentials",
            "filesystem",
            "models",
            "network",
            "providers",
            "tools",
        ],
    )?;
    WorkContextAuthority::new(
        grants(value, "filesystem")?,
        grants(value, "credentials")?,
        grants(value, "network")?,
        grants(value, "tools")?,
        grants(value, "providers")?,
        grants(value, "models")?,
    )
    .map_err(Into::into)
}

fn expected_json(expected: &ExpectedWorkContext) -> Result<JsonValue, LifecycleApiError> {
    Ok(object(vec![
        ("identity", identity_json(expected.identity())),
        ("revision", integer(expected.revision().get(), "revision")?),
    ]))
}
fn expected(value: &JsonValue) -> Result<ExpectedWorkContext, LifecycleApiError> {
    exact_fields(value, &["identity", "revision"])?;
    Ok(ExpectedWorkContext::new(
        identity(field(value, "identity")?)?,
        Revision::new(unsigned(value, "revision")?)
            .map_err(|_| LifecycleError::Field { field: "revision" })?,
    ))
}
fn label(value: &JsonValue) -> Result<WorkContextLabel, LifecycleApiError> {
    WorkContextLabel::new(string(value, "label")?.to_owned())
        .map_err(|_| LifecycleError::Field { field: "label" }.into())
}
fn registry(value: &JsonValue) -> Result<WorkContextRegistrySelector, LifecycleApiError> {
    WorkContextRegistrySelector::new(string(value, "registry")?.to_owned()).map_err(Into::into)
}

fn intent_json(intent: &WorkContextMutationIntent) -> Result<JsonValue, LifecycleApiError> {
    let kind = ("kind", JsonValue::String(intent.kind().to_owned()));
    Ok(match intent {
        WorkContextMutationIntent::CreateProject(value) => object(vec![
            kind,
            (
                "label",
                JsonValue::String(value.label().as_str().to_owned()),
            ),
            (
                "repositories",
                JsonValue::Array(
                    value
                        .repositories()
                        .iter()
                        .map(expected_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
        ]),
        WorkContextMutationIntent::CreateHostSetup(value) => object(vec![
            kind,
            (
                "label",
                JsonValue::String(value.label().as_str().to_owned()),
            ),
            ("project", expected_json(value.project())?),
            (
                "registry",
                JsonValue::String(value.registry().as_str().to_owned()),
            ),
            (
                "setup_kind",
                JsonValue::String(value.setup_kind().as_str().to_owned()),
            ),
        ]),
        WorkContextMutationIntent::CreateCheckout(value) => object(vec![
            (
                "checkout_kind",
                JsonValue::String(value.checkout_kind().as_str().to_owned()),
            ),
            ("host_setup", expected_json(value.host_setup())?),
            kind,
            (
                "label",
                JsonValue::String(value.label().as_str().to_owned()),
            ),
            ("project", expected_json(value.project())?),
            (
                "registry",
                JsonValue::String(value.registry().as_str().to_owned()),
            ),
            ("repository", expected_json(value.repository())?),
        ]),
        WorkContextMutationIntent::CreateUserWorkspace(value) => object(vec![
            ("checkout", expected_json(value.checkout())?),
            kind,
            (
                "label",
                JsonValue::String(value.label().as_str().to_owned()),
            ),
            ("project", expected_json(value.project())?),
        ]),
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => object(vec![
            kind,
            (
                "label",
                JsonValue::String(value.label().as_str().to_owned()),
            ),
            (
                "requested_authority",
                authority_json(value.requested_authority()),
            ),
            ("user_workspace", expected_json(value.user_workspace())?),
        ]),
        WorkContextMutationIntent::ResumeAttemptWorkspace(value) => object(vec![
            kind,
            (
                "requested_authority",
                authority_json(value.requested_authority()),
            ),
            ("target", expected_json(value.target())?),
        ]),
        WorkContextMutationIntent::ResumeSession(value) => object(vec![
            kind,
            (
                "requested_authority",
                authority_json(value.requested_authority()),
            ),
            ("target", expected_json(value.target())?),
        ]),
        WorkContextMutationIntent::ArchiveProject(value)
        | WorkContextMutationIntent::ArchiveHostSetup(value)
        | WorkContextMutationIntent::ArchiveCheckout(value)
        | WorkContextMutationIntent::ArchiveUserWorkspace(value) => {
            object(vec![kind, ("target", expected_json(value.target())?)])
        }
    })
}

fn intent(value: &JsonValue) -> Result<WorkContextMutationIntent, LifecycleApiError> {
    Ok(match string(value, "kind")? {
        "create_project" => {
            exact_fields(value, &["kind", "label", "repositories"])?;
            WorkContextMutationIntent::CreateProject(CreateProjectIntent::new(
                label(value)?,
                array(value, "repositories")?
                    .iter()
                    .map(expected)
                    .collect::<Result<Vec<_>, _>>()?,
            )?)
        }
        "create_host_setup" => {
            exact_fields(
                value,
                &["kind", "label", "project", "registry", "setup_kind"],
            )?;
            WorkContextMutationIntent::CreateHostSetup(CreateHostSetupIntent::new(
                label(value)?,
                expected(field(value, "project")?)?,
                crate::platform_v2::HostSetupKind::parse(string(value, "setup_kind")?)?,
                registry(value)?,
            )?)
        }
        "create_checkout" => {
            exact_fields(
                value,
                &[
                    "checkout_kind",
                    "host_setup",
                    "kind",
                    "label",
                    "project",
                    "registry",
                    "repository",
                ],
            )?;
            WorkContextMutationIntent::CreateCheckout(CreateCheckoutIntent::new(
                label(value)?,
                expected(field(value, "project")?)?,
                expected(field(value, "host_setup")?)?,
                expected(field(value, "repository")?)?,
                crate::platform_v2::CheckoutKind::parse(string(value, "checkout_kind")?)?,
                registry(value)?,
            )?)
        }
        "create_user_workspace" => {
            exact_fields(value, &["checkout", "kind", "label", "project"])?;
            WorkContextMutationIntent::CreateUserWorkspace(CreateUserWorkspaceIntent::new(
                label(value)?,
                expected(field(value, "project")?)?,
                expected(field(value, "checkout")?)?,
            )?)
        }
        "create_attempt_workspace" => {
            exact_fields(
                value,
                &["kind", "label", "requested_authority", "user_workspace"],
            )?;
            WorkContextMutationIntent::CreateAttemptWorkspace(CreateAttemptWorkspaceIntent::new(
                label(value)?,
                expected(field(value, "user_workspace")?)?,
                authority(field(value, "requested_authority")?)?,
            )?)
        }
        "resume_attempt_workspace" => {
            exact_fields(value, &["kind", "requested_authority", "target"])?;
            WorkContextMutationIntent::ResumeAttemptWorkspace(ResumeAttemptWorkspaceIntent::new(
                expected(field(value, "target")?)?,
                authority(field(value, "requested_authority")?)?,
            )?)
        }
        "resume_session" => {
            exact_fields(value, &["kind", "requested_authority", "target"])?;
            WorkContextMutationIntent::ResumeSession(ResumeSessionIntent::new(
                expected(field(value, "target")?)?,
                authority(field(value, "requested_authority")?)?,
            )?)
        }
        "archive_project" => {
            exact_fields(value, &["kind", "target"])?;
            WorkContextMutationIntent::ArchiveProject(ArchiveIntent::new(expected(field(
                value, "target",
            )?)?)?)
        }
        "archive_host_setup" => {
            exact_fields(value, &["kind", "target"])?;
            WorkContextMutationIntent::ArchiveHostSetup(ArchiveIntent::new(expected(field(
                value, "target",
            )?)?)?)
        }
        "archive_checkout" => {
            exact_fields(value, &["kind", "target"])?;
            WorkContextMutationIntent::ArchiveCheckout(ArchiveIntent::new(expected(field(
                value, "target",
            )?)?)?)
        }
        "archive_user_workspace" => {
            exact_fields(value, &["kind", "target"])?;
            WorkContextMutationIntent::ArchiveUserWorkspace(ArchiveIntent::new(expected(field(
                value, "target",
            )?)?)?)
        }
        _ => return Err(LifecycleError::Field { field: "kind" }.into()),
    })
}

fn proposal_json(proposal: &WorkContextMutationProposal) -> Result<JsonValue, LifecycleApiError> {
    Ok(object(vec![
        ("actor", actor_json(proposal.actor())),
        (
            "actor_authority",
            authority_json(proposal.actor_authority()),
        ),
        (
            "authority",
            JsonValue::String(proposal.authority().as_str().to_owned()),
        ),
        (
            "idempotency_key",
            JsonValue::String(proposal.idempotency_key().as_str().to_owned()),
        ),
        ("intent", intent_json(proposal.intent())?),
        (
            "request_digest",
            JsonValue::String(proposal.request_digest().to_string()),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]))
}
fn proposal(value: &JsonValue) -> Result<WorkContextMutationProposal, LifecycleApiError> {
    exact_fields(
        value,
        &[
            "actor",
            "actor_authority",
            "authority",
            "idempotency_key",
            "intent",
            "request_digest",
            "schema",
        ],
    )?;
    check_schema(value)?;
    let claimed =
        WorkContextRequestDigest::from_str(string(value, "request_digest")?).map_err(|_| {
            LifecycleError::Field {
                field: "request_digest",
            }
        })?;
    let result = WorkContextMutationProposal::new(
        actor(field(value, "actor")?)?,
        ResourceAuthority::parse(string(value, "authority")?)
            .map_err(|_| LifecycleError::Field { field: "authority" })?,
        authority(field(value, "actor_authority")?)?,
        IdempotencyKey::new(string(value, "idempotency_key")?.to_owned()).map_err(|_| {
            LifecycleError::Field {
                field: "idempotency_key",
            }
        })?,
        intent(field(value, "intent")?)?,
    )?;
    if result.request_digest() != claimed {
        return Err(LifecycleError::RequestDigestMismatch.into());
    }
    Ok(result)
}

pub fn encode_work_context_mutation_proposal(
    proposal: &WorkContextMutationProposal,
) -> Result<Vec<u8>, LifecycleApiError> {
    canonical_document(proposal_json(proposal)?)
}
pub fn decode_work_context_mutation_proposal(
    bytes: &[u8],
) -> Result<WorkContextMutationProposal, LifecycleApiError> {
    proposal(&admitted(bytes)?)
}

fn preview_ref_json(value: &MutationPreviewRef) -> Result<JsonValue, LifecycleApiError> {
    Ok(object(vec![
        ("id", JsonValue::String(value.id().as_str().to_owned())),
        ("revision", integer(value.revision().get(), "revision")?),
    ]))
}
fn preview_ref(value: &JsonValue) -> Result<MutationPreviewRef, LifecycleApiError> {
    exact_fields(value, &["id", "revision"])?;
    Ok(MutationPreviewRef::new(
        MutationPreviewId::new(string(value, "id")?.to_owned()).map_err(|_| {
            LifecycleError::Field {
                field: "preview_id",
            }
        })?,
        Revision::new(unsigned(value, "revision")?)
            .map_err(|_| LifecycleError::Field { field: "revision" })?,
    ))
}

fn preview_json(preview: &MutationPreview) -> Result<JsonValue, LifecycleApiError> {
    Ok(object(vec![
        (
            "approval",
            JsonValue::String(preview.approval().as_str().to_owned()),
        ),
        (
            "current",
            match preview.current() {
                Some(value) => record_json(value)?,
                None => JsonValue::Null,
            },
        ),
        (
            "effective_authority",
            authority_json(preview.effective_authority()),
        ),
        (
            "expires_at_ms",
            JsonValue::Integer(preview.expires_at().as_millis()),
        ),
        (
            "inherited_authority",
            authority_json(preview.inherited_authority()),
        ),
        (
            "issued_at_ms",
            JsonValue::Integer(preview.issued_at().as_millis()),
        ),
        ("preview", preview_ref_json(preview.preview())?),
        ("proposal", proposal_json(preview.proposal())?),
        ("resulting", record_json(preview.resulting())?),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]))
}
fn preview(value: &JsonValue) -> Result<MutationPreview, LifecycleApiError> {
    exact_fields(
        value,
        &[
            "approval",
            "current",
            "effective_authority",
            "expires_at_ms",
            "inherited_authority",
            "issued_at_ms",
            "preview",
            "proposal",
            "resulting",
            "schema",
        ],
    )?;
    check_schema(value)?;
    let proposal = proposal(field(value, "proposal")?)?;
    let current = match field(value, "current")? {
        JsonValue::Null => None,
        value => Some(record(value)?),
    };
    let wire_result = record(field(value, "resulting")?)?;
    let issued = proposal
        .intent()
        .is_create()
        .then(|| wire_result.identity().clone());
    let result = MutationPreview::new(
        preview_ref(field(value, "preview")?)?,
        proposal,
        current,
        issued,
        authority(field(value, "inherited_authority")?)?,
        authority(field(value, "effective_authority")?)?,
        MutationApprovalRequirement::parse(string(value, "approval")?)?,
        EpochMillis::from_millis(signed(value, "issued_at_ms")?),
        EpochMillis::from_millis(signed(value, "expires_at_ms")?),
    )?;
    if result.resulting() != &wire_result {
        return Err(LifecycleError::CurrentRecordMismatch.into());
    }
    Ok(result)
}
pub fn encode_work_context_mutation_preview(
    preview: &MutationPreview,
) -> Result<Vec<u8>, LifecycleApiError> {
    canonical_document(preview_json(preview)?)
}
pub fn decode_work_context_mutation_preview(
    bytes: &[u8],
) -> Result<MutationPreview, LifecycleApiError> {
    preview(&admitted(bytes)?)
}

fn approval_json(approval: &MutationApproval) -> Result<JsonValue, LifecycleApiError> {
    Ok(object(vec![
        (
            "decided_at_ms",
            JsonValue::Integer(approval.decided_at().as_millis()),
        ),
        ("decided_by", actor_json(approval.decided_by())),
        (
            "decision",
            JsonValue::String(approval.decision().as_str().to_owned()),
        ),
        (
            "expires_at_ms",
            JsonValue::Integer(approval.expires_at().as_millis()),
        ),
        ("id", JsonValue::String(approval.id().as_str().to_owned())),
        (
            "idempotency_key",
            JsonValue::String(approval.idempotency_key().as_str().to_owned()),
        ),
        ("preview", preview_ref_json(approval.preview())?),
        (
            "request_digest",
            JsonValue::String(approval.request_digest().to_string()),
        ),
    ]))
}
fn approval(
    value: &JsonValue,
    preview: &MutationPreview,
) -> Result<MutationApproval, LifecycleApiError> {
    exact_fields(
        value,
        &[
            "decided_at_ms",
            "decided_by",
            "decision",
            "expires_at_ms",
            "id",
            "idempotency_key",
            "preview",
            "request_digest",
        ],
    )?;
    let result = MutationApproval::new(
        MutationApprovalId::new(string(value, "id")?.to_owned()).map_err(|_| {
            LifecycleError::Field {
                field: "approval_id",
            }
        })?,
        preview,
        MutationApprovalDecision::parse(string(value, "decision")?)?,
        actor(field(value, "decided_by")?)?,
        EpochMillis::from_millis(signed(value, "decided_at_ms")?),
        EpochMillis::from_millis(signed(value, "expires_at_ms")?),
    )?;
    if result.preview() != &preview_ref(field(value, "preview")?)?
        || result.request_digest().to_string() != string(value, "request_digest")?
        || result.idempotency_key().as_str() != string(value, "idempotency_key")?
    {
        return Err(LifecycleError::ApprovalMismatch.into());
    }
    Ok(result)
}
pub fn encode_work_context_mutation_approval(
    approval: &MutationApproval,
) -> Result<Vec<u8>, LifecycleApiError> {
    canonical_document(object(vec![
        ("approval", approval_json(approval)?),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]))
}
pub fn decode_work_context_mutation_approval(
    bytes: &[u8],
    preview_value: &MutationPreview,
) -> Result<MutationApproval, LifecycleApiError> {
    let value = admitted(bytes)?;
    exact_fields(&value, &["approval", "schema"])?;
    check_schema(&value)?;
    approval(field(&value, "approval")?, preview_value)
}

pub fn encode_work_context_mutation_submission(
    preview: &MutationPreview,
    approval: Option<&MutationApproval>,
    submitted_at: EpochMillis,
) -> Result<Vec<u8>, LifecycleApiError> {
    let submission = MutationSubmission::new(preview, approval, submitted_at)?;
    canonical_document(object(vec![
        (
            "approval",
            match approval {
                Some(value) => approval_json(value)?,
                None => JsonValue::Null,
            },
        ),
        (
            "idempotency_key",
            JsonValue::String(submission.idempotency_key().as_str().to_owned()),
        ),
        ("preview", preview_ref_json(submission.preview())?),
        (
            "request_digest",
            JsonValue::String(submission.request_digest().to_string()),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
        (
            "submitted_at_ms",
            JsonValue::Integer(submission.submitted_at().as_millis()),
        ),
    ]))
}
pub fn decode_work_context_mutation_submission(
    bytes: &[u8],
    preview_value: &MutationPreview,
) -> Result<MutationSubmission, LifecycleApiError> {
    let value = admitted(bytes)?;
    exact_fields(
        &value,
        &[
            "approval",
            "idempotency_key",
            "preview",
            "request_digest",
            "schema",
            "submitted_at_ms",
        ],
    )?;
    check_schema(&value)?;
    let approval = match field(&value, "approval")? {
        JsonValue::Null => None,
        value => Some(approval(value, preview_value)?),
    };
    let result = MutationSubmission::new(
        preview_value,
        approval.as_ref(),
        EpochMillis::from_millis(signed(&value, "submitted_at_ms")?),
    )?;
    if result.preview() != &preview_ref(field(&value, "preview")?)?
        || result.request_digest().to_string() != string(&value, "request_digest")?
        || result.idempotency_key().as_str() != string(&value, "idempotency_key")?
    {
        return Err(LifecycleError::SubmissionMismatch.into());
    }
    Ok(result)
}

pub fn encode_work_context_mutation_receipt(
    receipt: &MutationReceipt,
) -> Result<Vec<u8>, LifecycleApiError> {
    canonical_document(object(vec![
        (
            "approval_id",
            receipt.approval_id().map_or(JsonValue::Null, |value| {
                JsonValue::String(value.as_str().to_owned())
            }),
        ),
        ("id", JsonValue::String(receipt.id().as_str().to_owned())),
        (
            "idempotency_key",
            JsonValue::String(receipt.idempotency_key().as_str().to_owned()),
        ),
        (
            "outcome",
            JsonValue::String(receipt.outcome().as_str().to_owned()),
        ),
        ("preview", preview_ref_json(receipt.preview())?),
        (
            "recorded_at_ms",
            JsonValue::Integer(receipt.recorded_at().as_millis()),
        ),
        (
            "request_digest",
            JsonValue::String(receipt.request_digest().to_string()),
        ),
        (
            "resulting_revision",
            match receipt.resulting_revision() {
                Some(value) => integer(value.get(), "resulting_revision")?,
                None => JsonValue::Null,
            },
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]))
}
pub fn decode_work_context_mutation_receipt(
    bytes: &[u8],
    submission: &MutationSubmission,
    preview_value: &MutationPreview,
) -> Result<MutationReceipt, LifecycleApiError> {
    let value = admitted(bytes)?;
    exact_fields(
        &value,
        &[
            "approval_id",
            "id",
            "idempotency_key",
            "outcome",
            "preview",
            "recorded_at_ms",
            "request_digest",
            "resulting_revision",
            "schema",
        ],
    )?;
    check_schema(&value)?;
    let outcome = ReceiptOutcome::parse(string(&value, "outcome")?)
        .map_err(|_| LifecycleError::Field { field: "outcome" })?;
    let result = MutationReceipt::new(
        ReceiptId::new(string(&value, "id")?.to_owned()).map_err(|_| LifecycleError::Field {
            field: "receipt_id",
        })?,
        submission,
        preview_value,
        outcome,
        EpochMillis::from_millis(signed(&value, "recorded_at_ms")?),
    )?;
    let wire_approval = match field(&value, "approval_id")? {
        JsonValue::Null => None,
        JsonValue::String(value) => Some(value.as_str()),
        _ => return Err(LifecycleApiError::InvalidBody),
    };
    let wire_revision = match field(&value, "resulting_revision")? {
        JsonValue::Null => None,
        JsonValue::Integer(value) => {
            Some(
                u64::try_from(*value).map_err(|_| LifecycleApiError::CounterOutOfRange {
                    field: "resulting_revision",
                })?,
            )
        }
        _ => return Err(LifecycleApiError::InvalidBody),
    };
    if result.preview() != &preview_ref(field(&value, "preview")?)?
        || result.request_digest().to_string() != string(&value, "request_digest")?
        || result.idempotency_key().as_str() != string(&value, "idempotency_key")?
        || result.approval_id().map(|id| id.as_str()) != wire_approval
        || result.resulting_revision().map(Revision::get) != wire_revision
    {
        return Err(LifecycleError::SubmissionMismatch.into());
    }
    Ok(result)
}

pub fn encode_work_context_mutation_refusal(
    refusal: &MutationRefusal,
) -> Result<Vec<u8>, LifecycleApiError> {
    canonical_document(object(vec![
        (
            "category",
            JsonValue::String(refusal.category().as_str().to_owned()),
        ),
        (
            "explanation",
            JsonValue::String(refusal.explanation().as_str().to_owned()),
        ),
        (
            "request_digest",
            refusal.request_digest().map_or(JsonValue::Null, |value| {
                JsonValue::String(value.to_string())
            }),
        ),
        ("schema", JsonValue::String(PLATFORM_SCHEMA_V2.to_owned())),
    ]))
}
pub fn decode_work_context_mutation_refusal(
    bytes: &[u8],
) -> Result<MutationRefusal, LifecycleApiError> {
    let value = admitted(bytes)?;
    exact_fields(
        &value,
        &["category", "explanation", "request_digest", "schema"],
    )?;
    check_schema(&value)?;
    let digest = match field(&value, "request_digest")? {
        JsonValue::Null => None,
        JsonValue::String(value) => Some(value.parse().map_err(|_| LifecycleError::Field {
            field: "request_digest",
        })?),
        _ => return Err(LifecycleApiError::InvalidBody),
    };
    Ok(MutationRefusal::new(
        MutationRefusalCategory::parse(string(&value, "category")?)?,
        digest,
        MutationExplanation::new(string(&value, "explanation")?.to_owned()).map_err(|_| {
            LifecycleError::Field {
                field: "explanation",
            }
        })?,
    ))
}
