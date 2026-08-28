// SPDX-License-Identifier: Elastic-2.0

//! Authoritative SQLite custody for Platform v2 review state.
//!
//! This store persists only strict, canonical protocol documents. It owns the
//! transaction that binds a mutation preview to its actor, workspace, exact
//! revision, authority, request digest, idempotency key, approval and receipt.
//! It deliberately has no git, shell, CI, provider or pull-request adapter.
//! Provider observations use a separate table and can never create a local
//! authority grant.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform::{IdempotencyKey, ReceiptId};
use automonique_protocol::platform_v2::WorkContextIdentity;
use automonique_protocol::platform_v2_review::{
    AttentionEvent, AttentionOrigin, AttentionOriginKind, AttentionReason, CheckProjection,
    CheckState, CommentAgentState, ConflictState, DeliveryState, PullRequestState, ReviewAction,
    ReviewActionId, ReviewActionReceipt, ReviewActionRequest, ReviewActorId,
    ReviewAttentionEventId, ReviewAuthentication, ReviewAuthority, ReviewAuthorityId,
    ReviewAuthorityKind, ReviewCheckId, ReviewComment, ReviewCommentId, ReviewDecision,
    ReviewField, ReviewFreshness, ReviewFreshnessState, ReviewReceiptOutcome, ReviewReconciliation,
    ReviewSchemaVersion, ReviewSnapshot, ReviewStatusProjection, ReviewText,
};
use automonique_protocol::platform_v2_review_api::{
    decode_review_action_receipt, decode_review_action_request, decode_review_snapshot,
    encode_review_action_receipt, encode_review_action_request, encode_review_snapshot,
};
use automonique_protocol::primitives::Revision;
use automonique_protocol::wire::JsonValue;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{StoreError, validate_database_path};

pub const REVIEW_STORE_SCHEMA_VERSION: u32 = 4;
const MAX_PROVIDER_OBSERVATION_BYTES: usize = 4096;
const MAX_REVIEW_EFFECT_PAYLOAD_BYTES: usize = 1_048_576;

const SCHEMA_V1: &str = r#"
CREATE TABLE review_current (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (workspace_kind, workspace_id)
) STRICT;

CREATE TABLE review_store_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_namespace TEXT NOT NULL
) STRICT;

CREATE TABLE review_snapshots (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    document BLOB NOT NULL,
    document_digest BLOB NOT NULL CHECK (length(document_digest) = 32),
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    PRIMARY KEY (workspace_kind, workspace_id, revision)
) STRICT;

CREATE TABLE review_comments (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    snapshot_revision INTEGER NOT NULL CHECK (snapshot_revision >= 1),
    comment_id TEXT NOT NULL,
    comment_revision INTEGER NOT NULL CHECK (comment_revision >= 1),
    actor_id TEXT NOT NULL,
    body TEXT NOT NULL,
    file_id TEXT NOT NULL,
    hunk_id TEXT NOT NULL,
    side TEXT NOT NULL CHECK (side IN ('old', 'new')),
    line INTEGER NOT NULL CHECK (line >= 1),
    agent_state TEXT NOT NULL CHECK (agent_state IN ('not_sent', 'pending', 'sent', 'refused')),
    unread INTEGER NOT NULL CHECK (unread IN (0, 1)),
    PRIMARY KEY (workspace_kind, workspace_id, snapshot_revision, comment_id),
    FOREIGN KEY (workspace_kind, workspace_id, snapshot_revision)
        REFERENCES review_snapshots(workspace_kind, workspace_id, revision)
) STRICT;

CREATE TABLE review_authority_grants (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication IN ('user_session', 'service_identity')),
    authority_kind TEXT NOT NULL CHECK (authority_kind IN ('filesystem', 'git', 'ci', 'pull_request', 'review', 'delivery')),
    authority_id TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    grant_revision INTEGER NOT NULL CHECK (grant_revision >= 1),
    granted_at_ms INTEGER NOT NULL CHECK (granted_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > granted_at_ms),
    revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= granted_at_ms),
    PRIMARY KEY (workspace_kind, workspace_id, actor_id, authentication, authority_kind, authority_id)
) STRICT;

CREATE TABLE review_authority_grant_events (
    authorization_id TEXT PRIMARY KEY,
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication IN ('user_session', 'service_identity')),
    authority_kind TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    grant_revision INTEGER NOT NULL CHECK (grant_revision >= 1),
    granted_at_ms INTEGER NOT NULL CHECK (granted_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > granted_at_ms),
    UNIQUE (workspace_kind, workspace_id, actor_id, authentication, authority_kind, authority_id, grant_revision)
) STRICT;

CREATE TABLE review_action_previews (
    preview_id TEXT PRIMARY KEY,
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 1),
    actor_id TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication IN ('user_session', 'service_identity')),
    authority_kind TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    action_id TEXT NOT NULL UNIQUE,
    request_document BLOB NOT NULL,
    protocol_request_digest BLOB NOT NULL CHECK (length(protocol_request_digest) = 32),
    preview_document BLOB NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    approval_policy TEXT NOT NULL CHECK (approval_policy IN ('not_required', 'required')),
    approval_required INTEGER NOT NULL CHECK (approval_required IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    write_admission_id TEXT,
    write_admitted_at_ms INTEGER CHECK (write_admitted_at_ms IS NULL OR write_admitted_at_ms >= created_at_ms),
    write_admission_document BLOB,
    write_admission_digest BLOB CHECK (write_admission_digest IS NULL OR length(write_admission_digest) = 32),
    UNIQUE (workspace_kind, workspace_id, actor_id, idempotency_key)
) STRICT;

CREATE TABLE review_completion_evidence (
    preview_id TEXT PRIMARY KEY REFERENCES review_action_previews(preview_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    result_revision INTEGER NOT NULL CHECK (result_revision >= 1),
    evidence_id TEXT NOT NULL,
    verifying_actor_id TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication = 'service_identity'),
    authority_kind TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    evidence_document BLOB NOT NULL CHECK (length(evidence_document) <= 4096),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT;

CREATE TABLE review_action_approvals (
    preview_id TEXT PRIMARY KEY REFERENCES review_action_previews(preview_id),
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 1),
    approving_actor_id TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication IN ('user_session', 'service_identity')),
    authority_kind TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'refused')),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    decided_at_ms INTEGER NOT NULL CHECK (decided_at_ms >= 0),
    approval_document BLOB NOT NULL,
    approval_digest BLOB NOT NULL CHECK (length(approval_digest) = 32)
) STRICT;

CREATE TABLE review_action_receipts (
    receipt_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE REFERENCES review_action_previews(preview_id),
    receipt_document BLOB NOT NULL,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    approval_digest BLOB CHECK (approval_digest IS NULL OR length(approval_digest) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'completed', 'refused', 'conflict', 'unknown')),
    result_revision INTEGER CHECK (result_revision IS NULL OR result_revision >= 1),
    current_revision INTEGER CHECK (current_revision IS NULL OR current_revision >= 1),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE TABLE review_provider_observations (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    provider_session_id TEXT NOT NULL,
    observed_revision INTEGER NOT NULL CHECK (observed_revision >= 1),
    sanitized_document BLOB NOT NULL CHECK (length(sanitized_document) <= 4096),
    document_digest BLOB NOT NULL CHECK (length(document_digest) = 32),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    PRIMARY KEY (workspace_kind, workspace_id, provider_session_id, observed_revision)
) STRICT;
"#;

const ADD_SNAPSHOT_PROTOCOL_SCHEMA_V2: &str = r#"
ALTER TABLE review_snapshots ADD COLUMN protocol_schema TEXT NOT NULL
    DEFAULT 'automonique.platform/review/v1'
    CHECK (protocol_schema IN ('automonique.platform/review/v1', 'automonique.platform/review/v2'));
"#;

const ADD_EXTERNAL_EFFECT_PLANS_V3: &str = r#"
CREATE TABLE review_external_effect_plans (
    preview_id TEXT PRIMARY KEY REFERENCES review_action_previews(preview_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    effect_kind TEXT NOT NULL CHECK (effect_kind = 'retained_session'),
    registry_generation_digest BLOB NOT NULL CHECK (length(registry_generation_digest) = 32),
    provider TEXT NOT NULL,
    work_session_id TEXT NOT NULL,
    provider_session_id TEXT NOT NULL,
    work_session_revision INTEGER NOT NULL CHECK (work_session_revision >= 1),
    provider_session_revision INTEGER NOT NULL CHECK (provider_session_revision >= 1),
    transport_key TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 1048576),
    payload_digest BLOB NOT NULL CHECK (length(payload_digest) = 32),
    plan_document BLOB NOT NULL,
    plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE review_external_effect_targets (
    preview_id TEXT NOT NULL REFERENCES review_external_effect_plans(preview_id),
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    comment_id TEXT NOT NULL,
    comment_revision INTEGER NOT NULL CHECK (comment_revision >= 1),
    disposition TEXT NOT NULL CHECK (disposition IN ('reserved', 'delivered', 'refused', 'delivered_conflict')),
    PRIMARY KEY (preview_id, comment_id),
    UNIQUE (workspace_kind, workspace_id, comment_id, comment_revision)
) STRICT;

-- Evidence written only while upgrading a pre-plan schema. It is the exact
-- reason one legacy retained action may truthfully have a terminal receipt
-- without a v3 external-effect plan; native v3 rows never receive one.
CREATE TABLE review_external_effect_migration_tombstones (
    preview_id TEXT PRIMARY KEY REFERENCES review_action_previews(preview_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('completed', 'refused', 'conflict')),
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32)
) STRICT;
"#;

const ADD_GITHUB_CHECK_EFFECT_PLANS_V4: &str = r#"
CREATE TABLE review_github_check_effect_plans (
    preview_id TEXT PRIMARY KEY REFERENCES review_action_previews(preview_id),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    registry_generation_digest BLOB NOT NULL CHECK (length(registry_generation_digest) = 32),
    credential_generation_digest BLOB NOT NULL CHECK (length(credential_generation_digest) = 32),
    credential_reference TEXT NOT NULL,
    repository_owner TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    run_id TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    observed_attempt INTEGER NOT NULL CHECK (observed_attempt >= 1),
    check_id TEXT NOT NULL,
    expected_check_revision INTEGER NOT NULL CHECK (expected_check_revision >= 1),
    custody TEXT NOT NULL CHECK (custody IN ('not_started','custody_started','accepted','ambiguous','refused','completed')),
    plan_document BLOB NOT NULL,
    plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms)
) STRICT;
"#;

#[derive(Debug)]
pub enum ReviewStoreError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    Conflict(&'static str),
    StaleRevision { current: Revision },
    Unauthorized,
    ApprovalRequired,
    NotFound,
    Corrupt(&'static str),
    Protocol(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl ReviewStoreError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict(_) => "conflict",
            Self::StaleRevision { .. } => "stale_revision",
            Self::Unauthorized => "unauthorized",
            Self::ApprovalRequired => "approval_required",
            Self::NotFound => "not_found",
            Self::Corrupt(_) => "corrupt",
            Self::Protocol(_) => "protocol",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}
impl fmt::Display for ReviewStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "review store refused: {}", self.category())
    }
}
impl Error for ReviewStoreError {}
impl From<std::io::Error> for ReviewStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for ReviewStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}
type Stored<T> = Result<T, ReviewStoreError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPolicy {
    NotRequired,
    Required,
}
impl ApprovalPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Required => "required",
        }
    }
    fn parse(value: &str) -> Stored<Self> {
        match value {
            "not_required" => Ok(Self::NotRequired),
            "required" => Ok(Self::Required),
            _ => Err(ReviewStoreError::Corrupt("approval_policy")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewApprovalDecision {
    Approved,
    Refused,
}
impl ReviewApprovalDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Refused => "refused",
        }
    }
    fn parse(value: &str) -> Stored<Self> {
        match value {
            "approved" => Ok(Self::Approved),
            "refused" => Ok(Self::Refused),
            _ => Err(ReviewStoreError::Corrupt("approval_decision")),
        }
    }
}

/// Authenticated, exact-authority approval of one persisted preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewApprovalDocument {
    preview_id: String,
    workspace: WorkContextIdentity,
    approving_actor: ReviewActorId,
    authentication: ReviewAuthentication,
    authority: ReviewAuthority,
    request_digest: [u8; 32],
    expected_revision: Revision,
    decision: ReviewApprovalDecision,
    expires_at_ms: i64,
}
impl ReviewApprovalDocument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        preview_id: impl Into<String>,
        workspace: WorkContextIdentity,
        approving_actor: ReviewActorId,
        authentication: ReviewAuthentication,
        authority: ReviewAuthority,
        request_digest: [u8; 32],
        expected_revision: Revision,
        decision: ReviewApprovalDecision,
        expires_at_ms: i64,
    ) -> Stored<Self> {
        let preview_id = preview_id.into();
        if ReviewField::new(&preview_id).is_err()
            || authentication == ReviewAuthentication::ProviderSession
            || expires_at_ms < 0
        {
            return Err(ReviewStoreError::InvalidField("approval"));
        }
        Ok(Self {
            preview_id,
            workspace,
            approving_actor,
            authentication,
            authority,
            request_digest,
            expected_revision,
            decision,
            expires_at_ms,
        })
    }
    #[must_use]
    pub fn preview_id(&self) -> &str {
        &self.preview_id
    }
    #[must_use]
    pub fn workspace(&self) -> &WorkContextIdentity {
        &self.workspace
    }
    #[must_use]
    pub fn approving_actor(&self) -> &ReviewActorId {
        &self.approving_actor
    }
    #[must_use]
    pub const fn authentication(&self) -> ReviewAuthentication {
        self.authentication
    }
    #[must_use]
    pub fn authority(&self) -> &ReviewAuthority {
        &self.authority
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
    #[must_use]
    pub const fn decision(&self) -> ReviewApprovalDecision {
        self.decision
    }
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReviewApproval {
    pub document: ReviewApprovalDocument,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewActionAdmission {
    New(StoredReviewAction),
    Replay(StoredReviewAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewWriteAdmission {
    New(StoredReviewAction),
    Replay(StoredReviewAction),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReviewAction {
    pub preview_id: String,
    pub request_digest: [u8; 32],
    pub request: ReviewActionRequest,
    pub receipt: ReviewActionReceipt,
    pub approval_required: bool,
    pub approval_policy: ApprovalPolicy,
    pub approved: bool,
    pub approval: Option<StoredReviewApproval>,
    pub external_effect_plan_digest: Option<[u8; 32]>,
    pub write_admission_id: Option<String>,
    pub write_admitted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReviewComment {
    pub workspace: WorkContextIdentity,
    pub snapshot_revision: Revision,
    pub comment: ReviewComment,
}

/// Exact, durable target and bytes for one retained-session review effect.
/// The scheduler may recover this plan after a crash; mutable registry state
/// is never consulted to reconstruct an already-admitted write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewExternalEffectPlan {
    request_digest: [u8; 32],
    registry_generation_digest: [u8; 32],
    provider: String,
    work_session_id: String,
    provider_session_id: String,
    work_session_revision: Revision,
    provider_session_revision: Revision,
    transport_key: String,
    payload: Vec<u8>,
    payload_digest: [u8; 32],
    document: Vec<u8>,
    digest: [u8; 32],
    github_check: Option<GitHubCheckEffectPlan>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewExternalEffectCustody {
    NotStarted,
    CustodyStarted,
    Accepted,
    Ambiguous,
    Refused,
    Completed,
}

impl ReviewExternalEffectCustody {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::CustodyStarted => "custody_started",
            Self::Accepted => "accepted",
            Self::Ambiguous => "ambiguous",
            Self::Refused => "refused",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Stored<Self> {
        match value {
            "not_started" => Ok(Self::NotStarted),
            "custody_started" => Ok(Self::CustodyStarted),
            "accepted" => Ok(Self::Accepted),
            "ambiguous" => Ok(Self::Ambiguous),
            "refused" => Ok(Self::Refused),
            "completed" => Ok(Self::Completed),
            _ => Err(ReviewStoreError::Corrupt("github_check_custody")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitHubCheckEffectPlan {
    credential_generation_digest: [u8; 32],
    credential_reference: String,
    repository_owner: String,
    repository_name: String,
    run_id: u64,
    head_sha: String,
    observed_attempt: u32,
    check_id: ReviewCheckId,
    expected_check_revision: Revision,
    custody: ReviewExternalEffectCustody,
}

impl ReviewExternalEffectPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn retained_session(
        request_digest: [u8; 32],
        registry_generation_digest: [u8; 32],
        provider: &str,
        work_session_id: &str,
        provider_session_id: &str,
        work_session_revision: Revision,
        provider_session_revision: Revision,
        transport_key: &str,
        payload: Vec<u8>,
    ) -> Stored<Self> {
        if ReviewField::new(provider).is_err()
            || ReviewField::new(work_session_id).is_err()
            || ReviewField::new(provider_session_id).is_err()
            || ReviewField::new(transport_key).is_err()
            || payload.is_empty()
            || payload.len() > MAX_REVIEW_EFFECT_PAYLOAD_BYTES
            || std::str::from_utf8(&payload).is_err()
        {
            return Err(ReviewStoreError::InvalidField("external_effect_plan"));
        }
        let payload_digest = digest(&payload);
        let document = JsonValue::Object(vec![
            (
                "effect_kind".to_owned(),
                JsonValue::String("retained_session".to_owned()),
            ),
            (
                "payload_digest".to_owned(),
                JsonValue::String(digest_token(&payload_digest)),
            ),
            (
                "provider".to_owned(),
                JsonValue::String(provider.to_owned()),
            ),
            (
                "provider_session_id".to_owned(),
                JsonValue::String(provider_session_id.to_owned()),
            ),
            (
                "registry_generation_digest".to_owned(),
                JsonValue::String(digest_token(&registry_generation_digest)),
            ),
            (
                "request_digest".to_owned(),
                JsonValue::String(digest_token(&request_digest)),
            ),
            (
                "schema".to_owned(),
                JsonValue::String("automonique.store/review-external-effect/v1".to_owned()),
            ),
            (
                "provider_session_revision".to_owned(),
                JsonValue::Integer(db_revision(provider_session_revision)?),
            ),
            (
                "work_session_revision".to_owned(),
                JsonValue::Integer(db_revision(work_session_revision)?),
            ),
            (
                "transport_key".to_owned(),
                JsonValue::String(transport_key.to_owned()),
            ),
            (
                "work_session_id".to_owned(),
                JsonValue::String(work_session_id.to_owned()),
            ),
        ])
        .to_canonical_bytes();
        let plan_digest = digest(&document);
        Ok(Self {
            request_digest,
            registry_generation_digest,
            provider: provider.to_owned(),
            work_session_id: work_session_id.to_owned(),
            provider_session_id: provider_session_id.to_owned(),
            work_session_revision,
            provider_session_revision,
            transport_key: transport_key.to_owned(),
            payload,
            payload_digest,
            document,
            digest: plan_digest,
            github_check: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn github_check_rerun(
        request_digest: [u8; 32],
        registry_generation_digest: [u8; 32],
        credential_generation_digest: [u8; 32],
        credential_reference: &str,
        repository_owner: &str,
        repository_name: &str,
        run_id: u64,
        head_sha: &str,
        observed_attempt: u32,
        check_id: ReviewCheckId,
        expected_check_revision: Revision,
    ) -> Stored<Self> {
        if !safe_effect_coordinate(credential_reference)
            || !safe_effect_coordinate(repository_owner)
            || !safe_effect_coordinate(repository_name)
            || run_id == 0
            || observed_attempt == 0
            || !valid_effect_head_sha(head_sha)
        {
            return Err(ReviewStoreError::InvalidField("external_effect_plan"));
        }
        let document = JsonValue::Object(vec![
            (
                "check_id".to_owned(),
                JsonValue::String(check_id.as_str().to_owned()),
            ),
            (
                "credential_generation_digest".to_owned(),
                JsonValue::String(digest_token(&credential_generation_digest)),
            ),
            (
                "credential_reference".to_owned(),
                JsonValue::String(credential_reference.to_owned()),
            ),
            (
                "effect_kind".to_owned(),
                JsonValue::String("github_check_rerun".to_owned()),
            ),
            (
                "expected_check_revision".to_owned(),
                JsonValue::Integer(db_revision(expected_check_revision)?),
            ),
            (
                "head_sha".to_owned(),
                JsonValue::String(head_sha.to_owned()),
            ),
            (
                "observed_attempt".to_owned(),
                JsonValue::Integer(i64::from(observed_attempt)),
            ),
            (
                "registry_generation_digest".to_owned(),
                JsonValue::String(digest_token(&registry_generation_digest)),
            ),
            (
                "repository_name".to_owned(),
                JsonValue::String(repository_name.to_owned()),
            ),
            (
                "repository_owner".to_owned(),
                JsonValue::String(repository_owner.to_owned()),
            ),
            (
                "request_digest".to_owned(),
                JsonValue::String(digest_token(&request_digest)),
            ),
            ("run_id".to_owned(), JsonValue::String(run_id.to_string())),
            (
                "schema".to_owned(),
                JsonValue::String("automonique.store/review-external-effect/v1".to_owned()),
            ),
        ])
        .to_canonical_bytes();
        let plan_digest = digest(&document);
        Ok(Self {
            request_digest,
            registry_generation_digest,
            provider: "github".to_owned(),
            work_session_id: String::new(),
            provider_session_id: String::new(),
            work_session_revision: Revision::FIRST,
            provider_session_revision: Revision::FIRST,
            transport_key: String::new(),
            payload: Vec::new(),
            payload_digest: digest(&[]),
            document,
            digest: plan_digest,
            github_check: Some(GitHubCheckEffectPlan {
                credential_generation_digest,
                credential_reference: credential_reference.to_owned(),
                repository_owner: repository_owner.to_owned(),
                repository_name: repository_name.to_owned(),
                run_id,
                head_sha: head_sha.to_owned(),
                observed_attempt,
                check_id,
                expected_check_revision,
                custody: ReviewExternalEffectCustody::NotStarted,
            }),
        })
    }

    #[must_use]
    pub const fn is_github_check_rerun(&self) -> bool {
        self.github_check.is_some()
    }

    #[must_use]
    pub const fn github_custody(&self) -> Option<ReviewExternalEffectCustody> {
        match &self.github_check {
            Some(plan) => Some(plan.custody),
            None => None,
        }
    }

    #[must_use]
    pub fn github_credential_reference(&self) -> Option<&str> {
        self.github_check
            .as_ref()
            .map(|p| p.credential_reference.as_str())
    }
    #[must_use]
    pub fn github_repository_owner(&self) -> Option<&str> {
        self.github_check
            .as_ref()
            .map(|p| p.repository_owner.as_str())
    }
    #[must_use]
    pub fn github_repository_name(&self) -> Option<&str> {
        self.github_check
            .as_ref()
            .map(|p| p.repository_name.as_str())
    }
    #[must_use]
    pub fn github_run_id(&self) -> Option<u64> {
        self.github_check.as_ref().map(|p| p.run_id)
    }
    #[must_use]
    pub fn github_head_sha(&self) -> Option<&str> {
        self.github_check.as_ref().map(|p| p.head_sha.as_str())
    }
    #[must_use]
    pub fn github_observed_attempt(&self) -> Option<u32> {
        self.github_check.as_ref().map(|p| p.observed_attempt)
    }
    #[must_use]
    pub fn github_check_id(&self) -> Option<&ReviewCheckId> {
        self.github_check.as_ref().map(|p| &p.check_id)
    }
    #[must_use]
    pub fn github_expected_check_revision(&self) -> Option<Revision> {
        self.github_check
            .as_ref()
            .map(|p| p.expected_check_revision)
    }
    #[must_use]
    pub fn github_credential_generation_digest(&self) -> Option<[u8; 32]> {
        self.github_check
            .as_ref()
            .map(|p| p.credential_generation_digest)
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
    #[must_use]
    pub const fn registry_generation_digest(&self) -> [u8; 32] {
        self.registry_generation_digest
    }
    #[must_use]
    pub fn work_session_id(&self) -> &str {
        &self.work_session_id
    }
    #[must_use]
    pub fn provider_session_id(&self) -> &str {
        &self.provider_session_id
    }
    #[must_use]
    pub const fn work_session_revision(&self) -> Revision {
        self.work_session_revision
    }
    #[must_use]
    pub const fn provider_session_revision(&self) -> Revision {
        self.provider_session_revision
    }
    #[must_use]
    pub fn transport_key(&self) -> &str {
        &self.transport_key
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Debug)]
pub struct ReviewStore {
    connection: Connection,
    path: PathBuf,
    authority_namespace: String,
}

impl ReviewStore {
    pub fn open(path: impl AsRef<Path>) -> Stored<Self> {
        Self::open_scoped(path, "local")
    }

    /// Open one authority namespace. A database is intentionally bound to one
    /// namespace; callers must use a separate database for another tenant or
    /// authority domain.
    pub fn open_scoped(path: impl AsRef<Path>, authority_namespace: &str) -> Stored<Self> {
        if ReviewField::new(authority_namespace).is_err() {
            return Err(ReviewStoreError::InvalidField("authority_namespace"));
        }
        let path = path.as_ref();
        secure_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        secure_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        crate::sqlite_policy::configure_authoritative(&connection)?;
        let schema_fresh = initialize(&mut connection)?;
        bind_authority_namespace(&connection, authority_namespace, schema_fresh)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            authority_namespace: authority_namespace.to_owned(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn authority_namespace(&self) -> &str {
        &self.authority_namespace
    }

    /// Persist a revalidated sanitized snapshot and its normalized comments.
    pub fn put_snapshot(&mut self, snapshot: &ReviewSnapshot, recorded_at_ms: i64) -> Stored<()> {
        validate_time(recorded_at_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        persist_snapshot(&transaction, snapshot, recorded_at_ms)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn snapshot(&self, workspace: &WorkContextIdentity) -> Stored<Option<ReviewSnapshot>> {
        let (kind, id) = workspace_parts(workspace);
        read_current_snapshot(&self.connection, kind, id)
    }

    /// Install a grant supplied by the future local policy registry.
    /// Provider sessions are observations and are categorically refused here.
    pub fn grant_authority(
        &mut self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        granted_at_ms: i64,
    ) -> Stored<()> {
        self.grant_authority_until(
            workspace,
            actor,
            authentication,
            authority,
            granted_at_ms,
            i64::MAX,
        )
    }

    pub fn grant_authority_until(
        &mut self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        granted_at_ms: i64,
        expires_at_ms: i64,
    ) -> Stored<()> {
        validate_time(granted_at_ms)?;
        if authentication == ReviewAuthentication::ProviderSession || expires_at_ms <= granted_at_ms
        {
            return Err(ReviewStoreError::Unauthorized);
        }
        let (kind, id) = workspace_parts(workspace);
        let authorization_id =
            initial_authorization_id(workspace, actor, authentication, authority);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        type RawGrant = (String, i64, i64, i64, Option<i64>);
        let existing: Option<RawGrant> = transaction.query_row(
            "SELECT authorization_id,grant_revision,granted_at_ms,expires_at_ms,revoked_at_ms FROM review_authority_grants WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND authentication=?4 AND authority_kind=?5 AND authority_id=?6",
            params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        if let Some((stored_id, revision, stored_granted, stored_expires, revoked)) = existing {
            if stored_id == authorization_id
                && revision == 1
                && stored_granted == granted_at_ms
                && stored_expires == expires_at_ms
                && revoked.is_none()
            {
                transaction.commit()?;
                return Ok(());
            }
            return Err(ReviewStoreError::Conflict("authority_grant"));
        }
        transaction.execute(
            "INSERT INTO review_authority_grants(workspace_kind,workspace_id,actor_id,authentication,authority_kind,authority_id,authorization_id,grant_revision,granted_at_ms,expires_at_ms,revoked_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?9,NULL)",
            params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), authorization_id, granted_at_ms, expires_at_ms])?;
        transaction.execute(
            "INSERT INTO review_authority_grant_events(authorization_id,workspace_kind,workspace_id,actor_id,authentication,authority_kind,authority_id,grant_revision,granted_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?9)",
            params![authorization_id, kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), granted_at_ms, expires_at_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reauthorize_authority_until(
        &mut self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        authorization_id: &str,
        expected_grant_revision: Revision,
        granted_at_ms: i64,
        expires_at_ms: i64,
    ) -> Stored<()> {
        validate_time(granted_at_ms)?;
        if authentication == ReviewAuthentication::ProviderSession
            || ReviewField::new(authorization_id).is_err()
            || expires_at_ms <= granted_at_ms
        {
            return Err(ReviewStoreError::Unauthorized);
        }
        let (kind, id) = workspace_parts(workspace);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        type RawGrant = (String, i64, i64, i64, Option<i64>);
        let (stored_id, stored_revision, stored_granted, stored_expires, revoked): RawGrant = transaction.query_row(
            "SELECT authorization_id,grant_revision,granted_at_ms,expires_at_ms,revoked_at_ms FROM review_authority_grants WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND authentication=?4 AND authority_kind=?5 AND authority_id=?6",
            params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?.ok_or(ReviewStoreError::NotFound)?;
        if stored_id == authorization_id
            && stored_granted == granted_at_ms
            && stored_expires == expires_at_ms
            && revoked.is_none()
        {
            transaction.commit()?;
            return Ok(());
        }
        if stored_revision != db_revision(expected_grant_revision)?
            || authorization_id == stored_id
            || granted_at_ms <= revoked.unwrap_or(stored_granted).max(stored_granted)
        {
            return Err(ReviewStoreError::Conflict("authority_grant"));
        }
        let reused: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_authority_grant_events WHERE authorization_id=?1)",
            [authorization_id],
            |row| row.get(0),
        )?;
        if reused {
            return Err(ReviewStoreError::Conflict("authority_grant"));
        }
        let next_revision = stored_revision
            .checked_add(1)
            .ok_or(ReviewStoreError::Conflict("authority_grant"))?;
        transaction.execute(
            "UPDATE review_authority_grants SET authorization_id=?1,grant_revision=?2,granted_at_ms=?3,expires_at_ms=?4,revoked_at_ms=NULL WHERE workspace_kind=?5 AND workspace_id=?6 AND actor_id=?7 AND authentication=?8 AND authority_kind=?9 AND authority_id=?10 AND grant_revision=?11",
            params![authorization_id, next_revision, granted_at_ms, expires_at_ms, kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), stored_revision],
        )?;
        transaction.execute(
            "INSERT INTO review_authority_grant_events(authorization_id,workspace_kind,workspace_id,actor_id,authentication,authority_kind,authority_id,grant_revision,granted_at_ms,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![authorization_id, kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), next_revision, granted_at_ms, expires_at_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn revoke_authority(
        &mut self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        revoked_at_ms: i64,
    ) -> Stored<()> {
        validate_time(revoked_at_ms)?;
        let (kind, id) = workspace_parts(workspace);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (granted_at, current): (i64, Option<i64>) = transaction.query_row(
            "SELECT granted_at_ms,revoked_at_ms FROM review_authority_grants WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND authentication=?4 AND authority_kind=?5 AND authority_id=?6",
            params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?.ok_or(ReviewStoreError::NotFound)?;
        if let Some(current) = current {
            if current == revoked_at_ms {
                transaction.commit()?;
                return Ok(());
            }
            return Err(ReviewStoreError::Conflict("authority_revocation"));
        }
        if revoked_at_ms < granted_at {
            return Err(ReviewStoreError::Conflict("authority_revocation"));
        }
        transaction.execute(
            "UPDATE review_authority_grants SET revoked_at_ms=?1 WHERE workspace_kind=?2 AND workspace_id=?3 AND actor_id=?4 AND authentication=?5 AND authority_kind=?6 AND authority_id=?7 AND revoked_at_ms IS NULL",
            params![revoked_at_ms, kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn prepare_action(
        &mut self,
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
        created_at_ms: i64,
    ) -> Stored<ReviewActionAdmission> {
        self.prepare_action_with_external_plan(request, approval, None, created_at_ms)
    }

    /// Atomically bind the complete external plan to the accepted receipt.
    /// There is no crash window in which custody exists but the scheduler
    /// target or bytes must be reconstructed from mutable registry state.
    pub fn prepare_external_action(
        &mut self,
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
        plan: &ReviewExternalEffectPlan,
        created_at_ms: i64,
    ) -> Stored<ReviewActionAdmission> {
        self.prepare_action_with_external_plan(request, approval, Some(plan), created_at_ms)
    }

    fn prepare_action_with_external_plan(
        &mut self,
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
        external_plan: Option<&ReviewExternalEffectPlan>,
        created_at_ms: i64,
    ) -> Stored<ReviewActionAdmission> {
        validate_time(created_at_ms)?;
        let document = encode_review_action_request(request).map_err(protocol)?;
        decode_review_action_request(&document).map_err(protocol)?;
        let protocol_request_digest = digest(&document);
        let preview_document = encode_preview_document(&protocol_request_digest, approval);
        let request_digest = digest(&preview_document);
        let retained_session_action = matches!(
            request.action(),
            ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. }
        );
        if external_plan.is_some()
            && !retained_session_action
            && (!matches!(request.action(), ReviewAction::RerunCheck { .. })
                || !external_plan.is_some_and(ReviewExternalEffectPlan::is_github_check_rerun))
        {
            return Err(ReviewStoreError::InvalidField("external_effect_action"));
        }
        if retained_session_action && external_plan.is_none() {
            return Err(ReviewStoreError::InvalidField("external_effect_plan"));
        }
        if external_plan.is_some_and(|plan| plan.request_digest != request_digest) {
            return Err(ReviewStoreError::Conflict("external_effect_request"));
        }
        if let (
            ReviewAction::RerunCheck {
                check_id,
                expected_check_revision,
            },
            Some(plan),
        ) = (request.action(), external_plan)
            && (plan.github_check_id() != Some(check_id)
                || plan.github_expected_check_revision() != Some(*expected_check_revision))
        {
            return Err(ReviewStoreError::Conflict("external_effect_request"));
        }
        let (kind, id) = workspace_parts(request.workspace());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_action_by_key(
            &transaction,
            kind,
            id,
            request.actor().as_str(),
            request.idempotency_key().as_str(),
        )? {
            if existing.request_digest != request_digest || existing.approval_policy != approval {
                return Err(ReviewStoreError::Conflict("idempotency_key"));
            }
            if existing.receipt.outcome() == ReviewReceiptOutcome::Refused
                && existing.write_admitted_at_ms.is_none()
                && existing.external_effect_plan_digest.is_some()
                && matches!(
                    existing.request.action(),
                    ReviewAction::SendCommentToAgent { .. }
                        | ReviewAction::BatchSendCommentsToAgent { .. }
                )
            {
                require_exact_external_plan(&transaction, &existing.preview_id, external_plan)?;
                transaction.commit()?;
                return Ok(ReviewActionAdmission::Replay(existing));
            }
            require_active_authority(&transaction, request, created_at_ms)?;
            if is_terminal(existing.receipt.outcome()) {
                require_exact_external_plan(&transaction, &existing.preview_id, external_plan)?;
                transaction.commit()?;
                return Ok(ReviewActionAdmission::Replay(existing));
            }
            validate_current_action(&transaction, &existing.request)?;
            require_exact_external_plan(&transaction, &existing.preview_id, external_plan)?;
            transaction.commit()?;
            return Ok(ReviewActionAdmission::Replay(existing));
        }
        require_active_authority(&transaction, request, created_at_ms)?;
        // Authorization is decided before revealing whether the workspace or
        // revision exists, so an ungranted actor cannot use stale refusals as
        // a revision oracle.
        validate_current_action(&transaction, request)?;
        let token = digest_token(&request_digest);
        let preview_id = format!("preview_{token}");
        let action_id = ReviewActionId::new(format!("action_{token}"))
            .map_err(|_| ReviewStoreError::Corrupt("action_id"))?;
        let receipt_id = ReceiptId::new(format!("receipt_{token}"))
            .map_err(|_| ReviewStoreError::Corrupt("receipt_id"))?;
        let receipt = ReviewActionReceipt::new(
            receipt_id,
            request.idempotency_key().clone(),
            action_id.clone(),
            request.actor().clone(),
            ReviewReceiptOutcome::Accepted,
            None,
            None,
            ReviewReconciliation::PollReceipt,
        )
        .map_err(protocol)?;
        let receipt_document = encode_review_action_receipt(&receipt).map_err(protocol)?;
        let receipt_digest = digest(&receipt_document);
        transaction.execute(
            "INSERT INTO review_action_previews(preview_id,workspace_kind,workspace_id,expected_revision,actor_id,authentication,authority_kind,authority_id,idempotency_key,action_kind,action_id,request_document,protocol_request_digest,preview_document,request_digest,approval_policy,approval_required,created_at_ms,write_admission_id,write_admitted_at_ms,write_admission_document,write_admission_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,NULL,NULL,NULL,NULL)",
            params![preview_id, kind, id, db_revision(request.expected_revision())?, request.actor().as_str(), request.authentication().as_str(), request.authority().kind().as_str(), request.authority().id().as_str(), request.idempotency_key().as_str(), request.action().kind().as_str(), action_id.as_str(), document, protocol_request_digest.as_slice(), preview_document, request_digest.as_slice(), approval.as_str(), i64::from(approval == ApprovalPolicy::Required), created_at_ms])?;
        if let Some(plan) = external_plan {
            insert_external_plan(&transaction, &preview_id, plan, created_at_ms)?;
            if retained_session_action {
                reserve_external_targets(&transaction, &preview_id, request)?;
            }
        }
        transaction.execute(
            "INSERT INTO review_action_receipts(receipt_id,preview_id,receipt_document,receipt_digest,request_digest,approval_digest,outcome,result_revision,current_revision,updated_at_ms) VALUES(?1,?2,?3,?4,?5,NULL,?6,NULL,NULL,?7)",
            params![receipt.receipt_id().as_str(), preview_id, receipt_document, receipt_digest.as_slice(), request_digest.as_slice(), receipt.outcome().as_str(), created_at_ms])?;
        let stored = read_action_by_preview(&transaction, &preview_id)?
            .ok_or(ReviewStoreError::Corrupt("preview"))?;
        transaction.commit()?;
        Ok(ReviewActionAdmission::New(stored))
    }

    /// Canonical request-plus-approval digest used to construct an exact plan
    /// before the atomic admission transaction.
    pub fn action_request_digest(
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
    ) -> Stored<[u8; 32]> {
        let document = encode_review_action_request(request).map_err(protocol)?;
        decode_review_action_request(&document).map_err(protocol)?;
        Ok(digest(&encode_preview_document(
            &digest(&document),
            approval,
        )))
    }

    /// Inspect an exact action without creating custody. This is the adapter
    /// preflight seam: a missing external target can still refuse without an
    /// accepted receipt, while an existing idempotency key is checked against
    /// the complete canonical request before any target availability is
    /// disclosed.
    pub fn inspect_action(
        &self,
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
        now_ms: i64,
    ) -> Stored<Option<StoredReviewAction>> {
        validate_time(now_ms)?;
        let document = encode_review_action_request(request).map_err(protocol)?;
        decode_review_action_request(&document).map_err(protocol)?;
        let protocol_request_digest = digest(&document);
        let preview_document = encode_preview_document(&protocol_request_digest, approval);
        let request_digest = digest(&preview_document);
        let (kind, id) = workspace_parts(request.workspace());
        require_active_authority(&self.connection, request, now_ms)?;
        let existing = read_action_by_key(
            &self.connection,
            kind,
            id,
            request.actor().as_str(),
            request.idempotency_key().as_str(),
        )?;
        if let Some(existing) = existing {
            if existing.request_digest != request_digest || existing.approval_policy != approval {
                return Err(ReviewStoreError::Conflict("idempotency_key"));
            }
            if !is_terminal(existing.receipt.outcome()) {
                validate_current_action(&self.connection, &existing.request)?;
            }
            return Ok(Some(existing));
        }
        validate_current_action(&self.connection, request)?;
        Ok(None)
    }

    /// Validate the exact actor grant, workspace revision, and action against
    /// current durable state without admitting custody or creating a receipt.
    pub fn validate_action(&self, request: &ReviewActionRequest, now_ms: i64) -> Stored<()> {
        validate_time(now_ms)?;
        require_active_authority(&self.connection, request, now_ms)?;
        validate_current_action(&self.connection, request)
    }

    /// Apply a store-owned review mutation in the same transaction that
    /// records its write admission and terminal receipt. No accepted receipt
    /// or externally replayable write can be stranded by a process crash.
    pub fn execute_local_action(
        &mut self,
        request: &ReviewActionRequest,
        recorded_at_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(recorded_at_ms)?;
        if !matches!(
            request.action(),
            ReviewAction::AddComment { .. } | ReviewAction::ApproveReview { .. }
        ) {
            return Err(ReviewStoreError::InvalidField("local_action"));
        }
        let request_document = encode_review_action_request(request).map_err(protocol)?;
        decode_review_action_request(&request_document).map_err(protocol)?;
        let protocol_request_digest = digest(&request_document);
        let approval_policy = ApprovalPolicy::NotRequired;
        let preview_document = encode_preview_document(&protocol_request_digest, approval_policy);
        let request_digest = digest(&preview_document);
        let (workspace_kind, workspace_id) = workspace_parts(request.workspace());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_active_authority(&transaction, request, recorded_at_ms)?;

        if let Some(existing) = read_action_by_key(
            &transaction,
            workspace_kind,
            workspace_id,
            request.actor().as_str(),
            request.idempotency_key().as_str(),
        )? {
            if existing.request_digest != request_digest
                || existing.approval_policy != approval_policy
            {
                return Err(ReviewStoreError::Conflict("idempotency_key"));
            }
            if is_terminal(existing.receipt.outcome()) {
                transaction.commit()?;
                return Ok(existing.receipt);
            }
            // An admission created by another execution path may already have
            // crossed an effect boundary. Never reinterpret or replay it as a
            // local write.
            if existing.write_admitted_at_ms.is_some() {
                let unknown = ReviewActionReceipt::new(
                    existing.receipt.receipt_id().clone(),
                    existing.receipt.idempotency_key().clone(),
                    existing.receipt.action_id().clone(),
                    existing.receipt.actor().clone(),
                    ReviewReceiptOutcome::Unknown,
                    None,
                    None,
                    ReviewReconciliation::PollReceipt,
                )
                .map_err(protocol)?;
                update_receipt(&transaction, &existing.preview_id, &unknown, recorded_at_ms)?;
                transaction.commit()?;
                return Ok(unknown);
            }
        } else {
            validate_current_action(&transaction, request)?;
            let token = digest_token(&request_digest);
            let preview_id = format!("preview_{token}");
            let action_id = ReviewActionId::new(format!("action_{token}"))
                .map_err(|_| ReviewStoreError::Corrupt("action_id"))?;
            let receipt_id = ReceiptId::new(format!("receipt_{token}"))
                .map_err(|_| ReviewStoreError::Corrupt("receipt_id"))?;
            let accepted = ReviewActionReceipt::new(
                receipt_id,
                request.idempotency_key().clone(),
                action_id,
                request.actor().clone(),
                ReviewReceiptOutcome::Accepted,
                None,
                None,
                ReviewReconciliation::PollReceipt,
            )
            .map_err(protocol)?;
            let receipt_document = encode_review_action_receipt(&accepted).map_err(protocol)?;
            let receipt_digest = digest(&receipt_document);
            transaction.execute(
                "INSERT INTO review_action_previews(preview_id,workspace_kind,workspace_id,expected_revision,actor_id,authentication,authority_kind,authority_id,idempotency_key,action_kind,action_id,request_document,protocol_request_digest,preview_document,request_digest,approval_policy,approval_required,created_at_ms,write_admission_id,write_admitted_at_ms,write_admission_document,write_admission_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,0,?17,NULL,NULL,NULL,NULL)",
                params![preview_id, workspace_kind, workspace_id, db_revision(request.expected_revision())?, request.actor().as_str(), request.authentication().as_str(), request.authority().kind().as_str(), request.authority().id().as_str(), request.idempotency_key().as_str(), request.action().kind().as_str(), accepted.action_id().as_str(), request_document, protocol_request_digest.as_slice(), preview_document, request_digest.as_slice(), approval_policy.as_str(), recorded_at_ms],
            )?;
            transaction.execute(
                "INSERT INTO review_action_receipts(receipt_id,preview_id,receipt_document,receipt_digest,request_digest,approval_digest,outcome,result_revision,current_revision,updated_at_ms) VALUES(?1,?2,?3,?4,?5,NULL,?6,NULL,NULL,?7)",
                params![accepted.receipt_id().as_str(), preview_id, receipt_document, receipt_digest.as_slice(), request_digest.as_slice(), accepted.outcome().as_str(), recorded_at_ms],
            )?;
        }

        let action = read_action_by_key(
            &transaction,
            workspace_kind,
            workspace_id,
            request.actor().as_str(),
            request.idempotency_key().as_str(),
        )?
        .ok_or(ReviewStoreError::Corrupt("preview"))?;
        if let Err(error) = validate_current_action(&transaction, &action.request) {
            if let ReviewStoreError::StaleRevision { current } = error {
                let conflict = ReviewActionReceipt::new(
                    action.receipt.receipt_id().clone(),
                    action.receipt.idempotency_key().clone(),
                    action.receipt.action_id().clone(),
                    action.receipt.actor().clone(),
                    ReviewReceiptOutcome::Conflict,
                    None,
                    Some(current),
                    ReviewReconciliation::Final,
                )
                .map_err(protocol)?;
                update_receipt(&transaction, &action.preview_id, &conflict, recorded_at_ms)?;
                transaction.commit()?;
                return Ok(conflict);
            }
            return Err(error);
        }
        let admission_id = write_admission_id(&action, None, recorded_at_ms)?;
        let admission_document =
            encode_write_admission(&action, None, recorded_at_ms, &admission_id)?;
        let admission_digest = digest(&admission_document);
        let changed = transaction.execute(
            "UPDATE review_action_previews SET write_admission_id=?1,write_admitted_at_ms=?2,write_admission_document=?3,write_admission_digest=?4 WHERE preview_id=?5 AND write_admitted_at_ms IS NULL",
            params![admission_id, recorded_at_ms, admission_document, admission_digest.as_slice(), action.preview_id],
        )?;
        if changed != 1 {
            return Err(ReviewStoreError::Conflict("write_admission"));
        }
        let current = read_current_snapshot(&transaction, workspace_kind, workspace_id)?
            .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
        let next = local_action_snapshot(&current, request, &action.receipt, recorded_at_ms)?;
        persist_snapshot(&transaction, &next, recorded_at_ms)?;
        let completed = ReviewActionReceipt::new(
            action.receipt.receipt_id().clone(),
            action.receipt.idempotency_key().clone(),
            action.receipt.action_id().clone(),
            action.receipt.actor().clone(),
            ReviewReceiptOutcome::Completed,
            Some(next.revision()),
            None,
            ReviewReconciliation::Final,
        )
        .map_err(protocol)?;
        update_receipt(&transaction, &action.preview_id, &completed, recorded_at_ms)?;
        transaction.commit()?;
        Ok(completed)
    }

    pub fn decide_action(
        &mut self,
        approval: &ReviewApprovalDocument,
        decided_at_ms: i64,
    ) -> Stored<StoredReviewAction> {
        validate_time(decided_at_ms)?;
        if approval.expires_at_ms() <= decided_at_ms {
            return Err(ReviewStoreError::InvalidField("approval_expired"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Authorize the claimed approver scope before resolving an opaque
        // preview identifier or exposing any of its persisted bindings.
        require_active_grant(
            &transaction,
            approval.workspace(),
            approval.approving_actor(),
            approval.authentication(),
            approval.authority(),
            decided_at_ms,
        )?;
        let action = read_action_by_preview_in_scope(
            &transaction,
            approval.preview_id(),
            approval.workspace(),
            approval.authority(),
        )?
        .ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != approval.request_digest()
            || action.request.expected_revision() != approval.expected_revision()
            || action.request.workspace() != approval.workspace()
            || action.request.authority() != approval.authority()
        {
            return Err(ReviewStoreError::Conflict("approval_binding"));
        }
        if !action.approval_required {
            return Err(ReviewStoreError::InvalidField("approval_not_required"));
        }
        let (kind, id) = workspace_parts(approval.workspace());
        let current: i64 = transaction
            .query_row(
                "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
                params![kind, id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ReviewStoreError::Corrupt("current_revision"))?;
        if parse_revision(current)? != approval.expected_revision() {
            return Err(ReviewStoreError::StaleRevision {
                current: parse_revision(current)?,
            });
        }
        let snapshot = read_current_snapshot(&transaction, kind, id)?
            .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
        snapshot.resolve_action(&action.request).map_err(protocol)?;
        let approval_document = encode_approval(approval)?;
        let approval_digest = digest(&approval_document);
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO review_action_approvals(preview_id,workspace_kind,workspace_id,request_digest,expected_revision,approving_actor_id,authentication,authority_kind,authority_id,decision,expires_at_ms,decided_at_ms,approval_document,approval_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![approval.preview_id(), kind, id, approval.request_digest().as_slice(), db_revision(approval.expected_revision())?, approval.approving_actor().as_str(), approval.authentication().as_str(), approval.authority().kind().as_str(), approval.authority().id().as_str(), approval.decision().as_str(), approval.expires_at_ms(), decided_at_ms, approval_document, approval_digest.as_slice()])?;
        if changed == 0 {
            let existing = read_approval(&transaction, approval.preview_id())?
                .ok_or(ReviewStoreError::Corrupt("approval"))?;
            if existing.document != *approval || existing.digest != approval_digest {
                return Err(ReviewStoreError::Conflict("approval"));
            }
        }
        transaction.execute(
            "UPDATE review_action_receipts SET approval_digest=?1 WHERE preview_id=?2",
            params![approval_digest.as_slice(), approval.preview_id()],
        )?;
        if approval.decision() == ReviewApprovalDecision::Refused {
            let refused = ReviewActionReceipt::new(
                action.receipt.receipt_id().clone(),
                action.receipt.idempotency_key().clone(),
                action.receipt.action_id().clone(),
                action.receipt.actor().clone(),
                ReviewReceiptOutcome::Refused,
                None,
                None,
                ReviewReconciliation::Final,
            )
            .map_err(protocol)?;
            if action.external_effect_plan_digest.is_some() {
                release_external_plan_before_write(&transaction, approval.preview_id())?;
            }
            update_receipt(&transaction, approval.preview_id(), &refused, decided_at_ms)?;
        }
        let result = read_action_by_preview(&transaction, approval.preview_id())?
            .ok_or(ReviewStoreError::Corrupt("preview"))?;
        transaction.commit()?;
        Ok(result)
    }

    /// Durably admit exactly one external write while authorization, revision
    /// and approval are live. Repeating an already-recorded admission is a
    /// read; it never authorizes a second write.
    pub fn start_write(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        now_ms: i64,
    ) -> Stored<ReviewWriteAdmission> {
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest {
            return Err(ReviewStoreError::Conflict("request_digest"));
        }
        if matches!(
            action.request.action(),
            ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. }
        ) && action.external_effect_plan_digest.is_none()
        {
            return Err(ReviewStoreError::Conflict("external_effect_plan"));
        }
        if is_terminal(action.receipt.outcome()) {
            return Err(ReviewStoreError::Conflict("terminal_receipt"));
        }
        require_active_authority(&transaction, &action.request, now_ms)?;
        if action.write_admitted_at_ms.is_some() {
            if let Some(plan) = read_external_plan(&transaction, preview_id)?
                && plan.is_github_check_rerun()
                && plan.github_custody() == Some(ReviewExternalEffectCustody::NotStarted)
            {
                return Err(ReviewStoreError::Corrupt("github_check_custody"));
            }
            transaction.commit()?;
            return Ok(ReviewWriteAdmission::Replay(action));
        }
        if action.approval_required && !action.approved {
            return Err(ReviewStoreError::ApprovalRequired);
        }
        validate_live_approval(&action, now_ms)?;
        validate_current_action(&transaction, &action.request)?;
        let approval_digest = action.approval.as_ref().map(|value| value.digest);
        let admission_id = write_admission_id(&action, approval_digest.as_ref(), now_ms)?;
        let admission_document =
            encode_write_admission(&action, approval_digest.as_ref(), now_ms, &admission_id)?;
        let admission_digest = digest(&admission_document);
        let changed = transaction.execute(
            "UPDATE review_action_previews SET write_admission_id=?1,write_admitted_at_ms=?2,write_admission_document=?3,write_admission_digest=?4 WHERE preview_id=?5 AND write_admitted_at_ms IS NULL",
            params![admission_id, now_ms, admission_document, admission_digest.as_slice(), preview_id],
        )?;
        if changed != 1 {
            return Err(ReviewStoreError::Conflict("write_admission"));
        }
        let github_plan: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_github_check_effect_plans WHERE preview_id=?1)",
            [preview_id],
            |row| row.get(0),
        )?;
        if github_plan {
            let changed = transaction.execute(
                "UPDATE review_github_check_effect_plans SET custody='custody_started',updated_at_ms=?1 WHERE preview_id=?2 AND custody='not_started'",
                params![now_ms, preview_id],
            )?;
            if changed != 1 {
                return Err(ReviewStoreError::Conflict("github_check_custody"));
            }
        }
        let result = read_action_by_preview(&transaction, preview_id)?
            .ok_or(ReviewStoreError::Corrupt("preview"))?;
        transaction.commit()?;
        Ok(ReviewWriteAdmission::New(result))
    }

    /// Settle retained-session custody when a target fence changes after
    /// preparation but before any external write is admitted.
    pub fn refuse_external_action_not_started(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        now_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest {
            return Err(ReviewStoreError::Conflict("request_digest"));
        }
        if is_terminal(action.receipt.outcome()) {
            if action.receipt.outcome() == ReviewReceiptOutcome::Refused {
                transaction.commit()?;
                return Ok(action.receipt);
            }
            return Err(ReviewStoreError::Conflict("terminal_receipt"));
        }
        if action.external_effect_plan_digest.is_none() {
            return Err(ReviewStoreError::InvalidField("external_effect_action"));
        }
        if action.write_admitted_at_ms.is_some() {
            return Err(ReviewStoreError::Conflict("write_already_started"));
        }
        let plan = read_external_plan(&transaction, preview_id)?
            .ok_or(ReviewStoreError::Corrupt("external_effect_plan"))?;
        if plan.is_github_check_rerun() {
            let changed = transaction.execute(
                "UPDATE review_github_check_effect_plans SET custody='refused',updated_at_ms=?1 WHERE preview_id=?2 AND custody='not_started'",
                params![now_ms, preview_id],
            )?;
            if changed != 1 {
                return Err(ReviewStoreError::Conflict("github_check_custody"));
            }
        } else {
            release_external_plan_before_write(&transaction, preview_id)?;
        }
        let refused = ReviewActionReceipt::new(
            action.receipt.receipt_id().clone(),
            action.receipt.idempotency_key().clone(),
            action.receipt.action_id().clone(),
            action.receipt.actor().clone(),
            ReviewReceiptOutcome::Refused,
            None,
            None,
            ReviewReconciliation::Final,
        )
        .map_err(protocol)?;
        update_receipt(&transaction, preview_id, &refused, now_ms)?;
        transaction.commit()?;
        Ok(refused)
    }

    /// Close the crash-ambiguous window without replaying the mutation.
    pub fn mark_ambiguous(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        now_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest {
            return Err(ReviewStoreError::Conflict("request_digest"));
        }
        require_active_authority(&transaction, &action.request, now_ms)?;
        if action.approval_required && !action.approved {
            return Err(ReviewStoreError::ApprovalRequired);
        }
        if action.write_admitted_at_ms.is_none() {
            return Err(ReviewStoreError::Conflict("write_not_started"));
        }
        if action.receipt.outcome() != ReviewReceiptOutcome::Accepted {
            transaction.commit()?;
            return Ok(action.receipt);
        }
        if read_external_plan(&transaction, preview_id)?
            .is_some_and(|plan| plan.is_github_check_rerun())
        {
            transaction.execute(
                "UPDATE review_github_check_effect_plans SET custody='ambiguous',updated_at_ms=?1 WHERE preview_id=?2 AND custody IN ('custody_started','accepted','ambiguous')",
                params![now_ms, preview_id],
            )?;
        }
        let receipt = ReviewActionReceipt::new(
            action.receipt.receipt_id().clone(),
            action.receipt.idempotency_key().clone(),
            action.receipt.action_id().clone(),
            action.receipt.actor().clone(),
            ReviewReceiptOutcome::Unknown,
            None,
            None,
            ReviewReconciliation::PollReceipt,
        )
        .map_err(protocol)?;
        update_receipt(&transaction, preview_id, &receipt, now_ms)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Persist the observed GitHub custody transition and its receipt in one
    /// transaction. `Completed` means the exact next workflow attempt exists;
    /// it advances the local check projection to `running` without claiming
    /// that the new attempt itself has finished.
    pub fn settle_github_check_rerun(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        custody: ReviewExternalEffectCustody,
        now_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(now_ms)?;
        if matches!(
            custody,
            ReviewExternalEffectCustody::NotStarted | ReviewExternalEffectCustody::CustodyStarted
        ) {
            return Err(ReviewStoreError::InvalidField("github_check_custody"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest
            || action.write_admitted_at_ms.is_none()
            || !matches!(action.request.action(), ReviewAction::RerunCheck { .. })
        {
            return Err(ReviewStoreError::Conflict("external_effect_completion"));
        }
        let plan = read_external_plan(&transaction, preview_id)?
            .ok_or(ReviewStoreError::Corrupt("external_effect_plan"))?;
        if !plan.is_github_check_rerun() {
            return Err(ReviewStoreError::Conflict("external_effect_completion"));
        }
        let current_custody = plan
            .github_custody()
            .ok_or(ReviewStoreError::Corrupt("github_check_custody"))?;
        if matches!(
            current_custody,
            ReviewExternalEffectCustody::Refused | ReviewExternalEffectCustody::Completed
        ) {
            if current_custody == custody {
                transaction.commit()?;
                return Ok(action.receipt);
            }
            return Err(ReviewStoreError::Conflict("github_check_custody"));
        }
        let allowed = match custody {
            ReviewExternalEffectCustody::Accepted => {
                current_custody == ReviewExternalEffectCustody::CustodyStarted
            }
            ReviewExternalEffectCustody::Ambiguous => matches!(
                current_custody,
                ReviewExternalEffectCustody::CustodyStarted
                    | ReviewExternalEffectCustody::Accepted
                    | ReviewExternalEffectCustody::Ambiguous
            ),
            ReviewExternalEffectCustody::Refused => {
                current_custody == ReviewExternalEffectCustody::CustodyStarted
            }
            ReviewExternalEffectCustody::Completed => matches!(
                current_custody,
                ReviewExternalEffectCustody::CustodyStarted
                    | ReviewExternalEffectCustody::Accepted
                    | ReviewExternalEffectCustody::Ambiguous
            ),
            ReviewExternalEffectCustody::NotStarted
            | ReviewExternalEffectCustody::CustodyStarted => false,
        };
        if !allowed {
            return Err(ReviewStoreError::Conflict("github_check_custody"));
        }
        let changed = transaction.execute(
            "UPDATE review_github_check_effect_plans SET custody=?1,updated_at_ms=?2 WHERE preview_id=?3 AND custody=?4",
            params![custody.as_str(), now_ms, preview_id, current_custody.as_str()],
        )?;
        if changed != 1 {
            return Err(ReviewStoreError::Conflict("github_check_custody"));
        }

        let receipt = match custody {
            ReviewExternalEffectCustody::Accepted => action.receipt.clone(),
            ReviewExternalEffectCustody::Ambiguous => ReviewActionReceipt::new(
                action.receipt.receipt_id().clone(),
                action.receipt.idempotency_key().clone(),
                action.receipt.action_id().clone(),
                action.receipt.actor().clone(),
                ReviewReceiptOutcome::Unknown,
                None,
                None,
                ReviewReconciliation::PollReceipt,
            )
            .map_err(protocol)?,
            ReviewExternalEffectCustody::Refused => ReviewActionReceipt::new(
                action.receipt.receipt_id().clone(),
                action.receipt.idempotency_key().clone(),
                action.receipt.action_id().clone(),
                action.receipt.actor().clone(),
                ReviewReceiptOutcome::Refused,
                None,
                None,
                ReviewReconciliation::Final,
            )
            .map_err(protocol)?,
            ReviewExternalEffectCustody::Completed => {
                let (kind, id) = workspace_parts(action.request.workspace());
                let current = read_current_snapshot(&transaction, kind, id)?
                    .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
                if current.revision() != action.request.expected_revision() {
                    ReviewActionReceipt::new(
                        action.receipt.receipt_id().clone(),
                        action.receipt.idempotency_key().clone(),
                        action.receipt.action_id().clone(),
                        action.receipt.actor().clone(),
                        ReviewReceiptOutcome::Conflict,
                        None,
                        Some(current.revision()),
                        ReviewReconciliation::Final,
                    )
                    .map_err(protocol)?
                } else {
                    let next = github_check_rerun_snapshot(&current, &action.request, now_ms)?;
                    persist_snapshot(&transaction, &next, now_ms)?;
                    ReviewActionReceipt::new(
                        action.receipt.receipt_id().clone(),
                        action.receipt.idempotency_key().clone(),
                        action.receipt.action_id().clone(),
                        action.receipt.actor().clone(),
                        ReviewReceiptOutcome::Completed,
                        Some(next.revision()),
                        None,
                        ReviewReconciliation::Final,
                    )
                    .map_err(protocol)?
                }
            }
            ReviewExternalEffectCustody::NotStarted
            | ReviewExternalEffectCustody::CustodyStarted => unreachable!(),
        };
        if receipt != action.receipt {
            update_receipt(&transaction, preview_id, &receipt, now_ms)?;
        }
        transaction.commit()?;
        Ok(receipt)
    }

    /// Persist an adapter-reconciled outcome without granting the adapter any
    /// new authority. The receipt must preserve the preview's exact identities.
    /// A terminal receipt is immutable; an identical retry is a read, while a
    /// different retry is a conflict.
    pub fn reconcile_receipt(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        receipt: &ReviewActionReceipt,
        now_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(now_ms)?;
        let canonical = encode_review_action_receipt(receipt).map_err(protocol)?;
        decode_review_action_receipt(&canonical).map_err(protocol)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest {
            return Err(ReviewStoreError::Conflict("request_digest"));
        }
        require_active_authority(&transaction, &action.request, now_ms)?;
        if receipt.receipt_id() != action.receipt.receipt_id()
            || receipt.idempotency_key() != action.request.idempotency_key()
            || receipt.action_id() != action.receipt.action_id()
            || receipt.actor() != action.request.actor()
        {
            return Err(ReviewStoreError::Conflict("receipt_binding"));
        }
        if receipt.outcome() == ReviewReceiptOutcome::Accepted {
            return Err(ReviewStoreError::InvalidField("receipt_outcome"));
        }
        if action.external_effect_plan_digest.is_some() {
            return Err(ReviewStoreError::InvalidField("external_effect_completion"));
        }
        if is_terminal(action.receipt.outcome()) {
            if action.receipt == *receipt {
                transaction.commit()?;
                return Ok(action.receipt);
            }
            return Err(ReviewStoreError::Conflict("terminal_receipt"));
        }
        if action.write_admitted_at_ms.is_none() {
            return Err(ReviewStoreError::Conflict("write_not_started"));
        }
        if action.approval_required && !action.approved {
            return Err(ReviewStoreError::ApprovalRequired);
        }
        let (workspace_kind, workspace_id) = workspace_parts(action.request.workspace());
        let current = read_current_snapshot(&transaction, workspace_kind, workspace_id)?
            .ok_or(ReviewStoreError::Corrupt("current_revision"))?
            .revision();
        if receipt.outcome() == ReviewReceiptOutcome::Completed {
            let expected_result = action
                .request
                .expected_revision()
                .get()
                .checked_add(1)
                .and_then(|value| Revision::new(value).ok())
                .ok_or(ReviewStoreError::Conflict("result_revision"))?;
            let evidence =
                has_completion_evidence(&transaction, preview_id, request_digest, expected_result)?;
            let exact_snapshot = read_snapshot_revision(
                &transaction,
                workspace_kind,
                workspace_id,
                expected_result,
            )?
            .is_some();
            if receipt.revision() != Some(expected_result) || (!exact_snapshot && !evidence) {
                return Err(ReviewStoreError::Conflict("result_revision"));
            }
        }
        if receipt.outcome() == ReviewReceiptOutcome::Conflict
            && receipt.current_revision() != Some(current)
        {
            return Err(ReviewStoreError::Conflict("current_revision"));
        }
        update_receipt(&transaction, preview_id, receipt, now_ms)?;
        transaction.commit()?;
        Ok(receipt.clone())
    }

    /// Record bounded evidence observed by an authenticated service adapter.
    /// This does not grant mutation authority; it only permits a later
    /// `Completed` receipt when the local snapshot has not caught up yet.
    #[allow(clippy::too_many_arguments)]
    pub fn record_completion_evidence(
        &mut self,
        workspace: &WorkContextIdentity,
        preview_id: &str,
        request_digest: [u8; 32],
        verifying_actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        result_revision: Revision,
        evidence_id: &str,
        sanitized_document: &[u8],
        observed_at_ms: i64,
    ) -> Stored<()> {
        validate_time(observed_at_ms)?;
        if authentication != ReviewAuthentication::ServiceIdentity
            || ReviewField::new(evidence_id).is_err()
            || sanitized_document.len() > MAX_PROVIDER_OBSERVATION_BYTES
            || std::str::from_utf8(sanitized_document)
                .ok()
                .and_then(|value| ReviewText::new(value).ok())
                .is_none()
        {
            return Err(ReviewStoreError::InvalidField("completion_evidence"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The verifier's supplied scope is authenticated before the opaque
        // preview identifier is resolved, preventing an existence oracle.
        require_active_grant(
            &transaction,
            workspace,
            verifying_actor,
            authentication,
            authority,
            observed_at_ms,
        )?;
        let action =
            read_action_by_preview_in_scope(&transaction, preview_id, workspace, authority)?
                .ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest
            || action.request.workspace() != workspace
            || action.request.authority() != authority
            || action.write_admitted_at_ms.is_none()
        {
            return Err(ReviewStoreError::Conflict("completion_evidence_binding"));
        }
        let expected = action
            .request
            .expected_revision()
            .get()
            .checked_add(1)
            .and_then(|value| Revision::new(value).ok())
            .ok_or(ReviewStoreError::Conflict("result_revision"))?;
        if result_revision != expected {
            return Err(ReviewStoreError::Conflict("result_revision"));
        }
        let evidence_document = encode_completion_evidence(
            preview_id,
            &request_digest,
            result_revision,
            evidence_id,
            verifying_actor,
            authentication,
            authority,
            sanitized_document,
            observed_at_ms,
        )?;
        if evidence_document.len() > MAX_PROVIDER_OBSERVATION_BYTES {
            return Err(ReviewStoreError::InvalidField("completion_evidence"));
        }
        let evidence_digest = digest(&evidence_document);
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO review_completion_evidence(preview_id,request_digest,result_revision,evidence_id,verifying_actor_id,authentication,authority_kind,authority_id,evidence_document,evidence_digest,observed_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![preview_id, request_digest.as_slice(), db_revision(result_revision)?, evidence_id, verifying_actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), evidence_document, evidence_digest.as_slice(), observed_at_ms],
        )?;
        if changed == 0 {
            let existing: Vec<u8> = transaction.query_row(
                "SELECT evidence_digest FROM review_completion_evidence WHERE preview_id=?1",
                [preview_id],
                |row| row.get(0),
            )?;
            if existing.as_slice() != evidence_digest {
                return Err(ReviewStoreError::Conflict("completion_evidence"));
            }
            has_completion_evidence(&transaction, preview_id, request_digest, result_revision)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn receipt(
        &self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        key: &IdempotencyKey,
        now_ms: i64,
    ) -> Stored<Option<ReviewActionReceipt>> {
        validate_time(now_ms)?;
        require_active_grant(
            &self.connection,
            workspace,
            actor,
            authentication,
            authority,
            now_ms,
        )?;
        let (kind, id) = workspace_parts(workspace);
        let action = read_action_by_key(&self.connection, kind, id, actor.as_str(), key.as_str())?;
        if let Some(action) = &action
            && (action.request.authentication() != authentication
                || action.request.authority() != authority)
        {
            return Err(ReviewStoreError::Unauthorized);
        }
        Ok(action.map(|action| action.receipt))
    }

    /// Resolve one already-admitted retained-session action and its immutable
    /// plan under the caller's exact grant. This is the recovery path used by
    /// receipt polling after a daemon restart.
    pub fn external_action(
        &self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        authentication: ReviewAuthentication,
        authority: &ReviewAuthority,
        key: &IdempotencyKey,
        now_ms: i64,
    ) -> Stored<Option<(StoredReviewAction, ReviewExternalEffectPlan)>> {
        validate_time(now_ms)?;
        require_active_grant(
            &self.connection,
            workspace,
            actor,
            authentication,
            authority,
            now_ms,
        )?;
        let (kind, id) = workspace_parts(workspace);
        let Some(action) =
            read_action_by_key(&self.connection, kind, id, actor.as_str(), key.as_str())?
        else {
            return Ok(None);
        };
        if action.request.authentication() != authentication
            || action.request.authority() != authority
        {
            return Err(ReviewStoreError::Unauthorized);
        }
        let Some(plan) = read_external_plan(&self.connection, &action.preview_id)? else {
            return Ok(None);
        };
        Ok(Some((action, plan)))
    }

    /// Materialize the exact next snapshot and final receipt after the durable
    /// scheduler lane proves a retained-session delivery terminal. This is one
    /// transaction, so receipt and comment delivery state cannot diverge.
    pub fn complete_retained_session_delivery(
        &mut self,
        preview_id: &str,
        request_digest: [u8; 32],
        transport_key: &str,
        delivered: bool,
        recorded_at_ms: i64,
    ) -> Stored<ReviewActionReceipt> {
        validate_time(recorded_at_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let action =
            read_action_by_preview(&transaction, preview_id)?.ok_or(ReviewStoreError::NotFound)?;
        if action.request_digest != request_digest
            || action.write_admitted_at_ms.is_none()
            || !matches!(
                action.request.action(),
                ReviewAction::SendCommentToAgent { .. }
                    | ReviewAction::BatchSendCommentsToAgent { .. }
            )
        {
            return Err(ReviewStoreError::Conflict("external_effect_completion"));
        }
        let plan = read_external_plan(&transaction, preview_id)?
            .ok_or(ReviewStoreError::Corrupt("external_effect_plan"))?;
        if plan.request_digest != request_digest || plan.transport_key != transport_key {
            return Err(ReviewStoreError::Conflict("external_effect_completion"));
        }
        if is_terminal(action.receipt.outcome()) {
            transaction.commit()?;
            return Ok(action.receipt);
        }
        let (kind, id) = workspace_parts(action.request.workspace());
        let current = read_current_snapshot(&transaction, kind, id)?
            .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
        let original =
            read_snapshot_revision(&transaction, kind, id, action.request.expected_revision())?
                .ok_or(ReviewStoreError::Corrupt("external_effect_snapshot"))?;
        let targets_exact = external_targets_are_exact(&original, &current, &action.request)?;
        if !targets_exact {
            let (outcome, disposition) = if delivered {
                (ReviewReceiptOutcome::Conflict, "delivered_conflict")
            } else {
                (ReviewReceiptOutcome::Refused, "refused")
            };
            settle_external_targets(&transaction, preview_id, disposition)?;
            let terminal = ReviewActionReceipt::new(
                action.receipt.receipt_id().clone(),
                action.receipt.idempotency_key().clone(),
                action.receipt.action_id().clone(),
                action.receipt.actor().clone(),
                outcome,
                None,
                delivered.then_some(current.revision()),
                ReviewReconciliation::Final,
            )
            .map_err(protocol)?;
            update_receipt(&transaction, preview_id, &terminal, recorded_at_ms)?;
            transaction.commit()?;
            return Ok(terminal);
        }
        let next =
            retained_session_delivery_snapshot(&original, &current, &action.request, delivered)?;
        persist_snapshot(&transaction, &next, recorded_at_ms)?;
        settle_external_targets(
            &transaction,
            preview_id,
            if delivered { "delivered" } else { "refused" },
        )?;
        let receipt = ReviewActionReceipt::new(
            action.receipt.receipt_id().clone(),
            action.receipt.idempotency_key().clone(),
            action.receipt.action_id().clone(),
            action.receipt.actor().clone(),
            if delivered {
                ReviewReceiptOutcome::Completed
            } else {
                ReviewReceiptOutcome::Refused
            },
            delivered.then_some(next.revision()),
            None,
            ReviewReconciliation::Final,
        )
        .map_err(protocol)?;
        update_receipt(&transaction, preview_id, &receipt, recorded_at_ms)?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn comment(
        &self,
        workspace: &WorkContextIdentity,
        snapshot_revision: Revision,
        comment_id: &ReviewCommentId,
    ) -> Stored<Option<StoredReviewComment>> {
        let (kind, id) = workspace_parts(workspace);
        type RawComment = (
            Vec<u8>,
            Vec<u8>,
            i64,
            String,
            String,
            String,
            String,
            String,
            i64,
            String,
            i64,
        );
        let raw: Option<RawComment> = self.connection.query_row(
            "SELECT s.document,s.document_digest,c.comment_revision,c.actor_id,c.body,c.file_id,c.hunk_id,c.side,c.line,c.agent_state,c.unread FROM review_snapshots s JOIN review_comments c ON c.workspace_kind=s.workspace_kind AND c.workspace_id=s.workspace_id AND c.snapshot_revision=s.revision WHERE c.workspace_kind=?1 AND c.workspace_id=?2 AND c.snapshot_revision=?3 AND c.comment_id=?4",
            params![kind, id, db_revision(snapshot_revision)?, comment_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?))).optional()?;
        let Some((
            document,
            raw_digest,
            comment_revision,
            actor,
            body,
            file,
            hunk,
            side,
            line,
            agent_state,
            unread,
        )) = raw
        else {
            return Ok(None);
        };
        let document_digest: [u8; 32] = raw_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("snapshot_digest"))?;
        if digest(&document) != document_digest {
            return Err(ReviewStoreError::Corrupt("snapshot_digest"));
        }
        let snapshot =
            decode_review_snapshot(&document).map_err(|_| ReviewStoreError::Corrupt("snapshot"))?;
        let (decoded_kind, decoded_id) = workspace_parts(snapshot.workspace());
        if decoded_kind != kind || decoded_id != id || snapshot.revision() != snapshot_revision {
            return Err(ReviewStoreError::Corrupt("snapshot_projection"));
        }
        let comment = snapshot
            .comments()
            .iter()
            .find(|value| value.id() == comment_id)
            .cloned()
            .ok_or(ReviewStoreError::Corrupt("comment"))?;
        if db_revision(comment.revision())? != comment_revision
            || comment.actor().as_str() != actor
            || comment.body().as_str() != body
            || comment.anchor().file_id().as_str() != file
            || comment.anchor().hunk_id().as_str() != hunk
            || comment.anchor().side().as_str() != side
            || i64::from(comment.anchor().line()) != line
            || comment.agent_state().as_str() != agent_state
            || i64::from(comment.unread()) != unread
        {
            return Err(ReviewStoreError::Corrupt("comment_projection"));
        }
        Ok(Some(StoredReviewComment {
            workspace: workspace.clone(),
            snapshot_revision,
            comment,
        }))
    }

    pub fn record_provider_observation(
        &mut self,
        workspace: &WorkContextIdentity,
        provider_session_id: &str,
        observed_revision: Revision,
        sanitized_document: &[u8],
        observed_at_ms: i64,
    ) -> Stored<()> {
        validate_time(observed_at_ms)?;
        let sanitized_text = std::str::from_utf8(sanitized_document)
            .ok()
            .and_then(|value| ReviewText::new(value).ok());
        if ReviewField::new(provider_session_id).is_err()
            || sanitized_document.len() > MAX_PROVIDER_OBSERVATION_BYTES
            || sanitized_text.is_none()
        {
            return Err(ReviewStoreError::InvalidField("provider_observation"));
        }
        let (kind, id) = workspace_parts(workspace);
        let document_digest = digest(sanitized_document);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = transaction.query_row(
            "SELECT document_digest FROM review_provider_observations WHERE workspace_kind=?1 AND workspace_id=?2 AND provider_session_id=?3 AND observed_revision=?4",
            params![kind, id, provider_session_id, db_revision(observed_revision)?], |row| row.get(0)).optional()?;
        if let Some(existing) = existing {
            if existing.as_slice() != document_digest {
                return Err(ReviewStoreError::Conflict("provider_observation_revision"));
            }
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO review_provider_observations(workspace_kind,workspace_id,provider_session_id,observed_revision,sanitized_document,document_digest,observed_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![kind, id, provider_session_id, db_revision(observed_revision)?, sanitized_document, document_digest.as_slice(), observed_at_ms])?;
        transaction.commit()?;
        Ok(())
    }
}

fn initialize(connection: &mut Connection) -> Stored<bool> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == REVIEW_STORE_SCHEMA_VERSION {
        return Ok(false);
    }
    if version > REVIEW_STORE_SCHEMA_VERSION {
        return Err(ReviewStoreError::SchemaVersion {
            found: version,
            supported: REVIEW_STORE_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let fresh = version == 0;
    if fresh {
        transaction.execute_batch(SCHEMA_V1)?;
        transaction.execute_batch(ADD_SNAPSHOT_PROTOCOL_SCHEMA_V2)?;
        transaction.execute_batch(ADD_EXTERNAL_EFFECT_PLANS_V3)?;
        transaction.execute_batch(ADD_GITHUB_CHECK_EFFECT_PLANS_V4)?;
    } else if version == 1 {
        transaction.execute_batch(ADD_SNAPSHOT_PROTOCOL_SCHEMA_V2)?;
        migrate_review_v1_snapshots(&transaction)?;
        transaction.execute_batch(ADD_EXTERNAL_EFFECT_PLANS_V3)?;
        transaction.execute_batch(ADD_GITHUB_CHECK_EFFECT_PLANS_V4)?;
        terminalize_legacy_external_actions(&transaction)?;
    } else if version == 2 {
        transaction.execute_batch(ADD_EXTERNAL_EFFECT_PLANS_V3)?;
        transaction.execute_batch(ADD_GITHUB_CHECK_EFFECT_PLANS_V4)?;
        terminalize_legacy_external_actions(&transaction)?;
    } else if version == 3 {
        transaction.execute_batch(ADD_GITHUB_CHECK_EFFECT_PLANS_V4)?;
    } else {
        return Err(ReviewStoreError::SchemaVersion {
            found: version,
            supported: REVIEW_STORE_SCHEMA_VERSION,
        });
    }
    transaction.pragma_update(None, "user_version", REVIEW_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(fresh)
}

fn terminalize_legacy_external_actions(connection: &Connection) -> Stored<()> {
    type LegacyAction = (
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        Option<i64>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        i64,
    );
    let actions: Vec<LegacyAction> = {
        let mut statement = connection.prepare(
            "SELECT p.preview_id,p.request_document,p.request_digest,p.action_id,p.write_admitted_at_ms,r.receipt_document,r.receipt_digest,r.request_digest,r.outcome,r.updated_at_ms FROM review_action_previews p JOIN review_action_receipts r ON r.preview_id=p.preview_id ORDER BY p.preview_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })?
            .collect::<Result<_, _>>()?
    };
    for (
        preview_id,
        request_document,
        preview_request_digest,
        action_id,
        write_admitted_at_ms,
        receipt_document,
        receipt_digest,
        receipt_request_digest,
        projected_outcome,
        updated_at_ms,
    ) in actions
    {
        let request = decode_review_action_request(&request_document)
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_action"))?;
        if !matches!(
            request.action(),
            ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. }
        ) {
            continue;
        }
        let receipt = decode_review_action_receipt(&receipt_document)
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?;
        let stored_receipt_digest: [u8; 32] = receipt_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?;
        let preview_request_digest: [u8; 32] = preview_request_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_action"))?;
        let receipt_request_digest: [u8; 32] = receipt_request_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?;
        if digest(&receipt_document) != stored_receipt_digest
            || receipt_request_digest != preview_request_digest
            || receipt.outcome().as_str() != projected_outcome
            || receipt.idempotency_key() != request.idempotency_key()
            || receipt.actor() != request.actor()
            || receipt.action_id().as_str() != action_id
        {
            return Err(ReviewStoreError::Corrupt("legacy_external_receipt"));
        }
        let terminal = match receipt.outcome() {
            ReviewReceiptOutcome::Completed
            | ReviewReceiptOutcome::Conflict
            | ReviewReceiptOutcome::Refused => receipt.clone(),
            ReviewReceiptOutcome::Accepted if write_admitted_at_ms.is_none() => {
                ReviewActionReceipt::new(
                    receipt.receipt_id().clone(),
                    receipt.idempotency_key().clone(),
                    receipt.action_id().clone(),
                    receipt.actor().clone(),
                    ReviewReceiptOutcome::Refused,
                    None,
                    None,
                    ReviewReconciliation::Final,
                )
                .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?
            }
            ReviewReceiptOutcome::Accepted | ReviewReceiptOutcome::Unknown => {
                if receipt.outcome() == ReviewReceiptOutcome::Unknown
                    && write_admitted_at_ms.is_none()
                {
                    return Err(ReviewStoreError::Corrupt("legacy_external_receipt"));
                }
                let (kind, id) = workspace_parts(request.workspace());
                let current: i64 = connection
                    .query_row(
                        "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
                        params![kind, id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(ReviewStoreError::Corrupt("legacy_external_action"))?;
                ReviewActionReceipt::new(
                    receipt.receipt_id().clone(),
                    receipt.idempotency_key().clone(),
                    receipt.action_id().clone(),
                    receipt.actor().clone(),
                    ReviewReceiptOutcome::Conflict,
                    None,
                    Some(parse_revision(current)?),
                    ReviewReconciliation::Final,
                )
                .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?
            }
        };
        if terminal.outcome() == ReviewReceiptOutcome::Completed {
            validate_legacy_external_completed_basis(connection, &request, &terminal)?;
        }
        if terminal != receipt {
            update_receipt(connection, &preview_id, &terminal, updated_at_ms)?;
        }
        let terminal_document = encode_review_action_receipt(&terminal)
            .map_err(|_| ReviewStoreError::Corrupt("legacy_external_receipt"))?;
        let terminal_digest = digest(&terminal_document);
        connection.execute(
            "INSERT INTO review_external_effect_migration_tombstones(preview_id,outcome,receipt_digest) VALUES(?1,?2,?3)",
            params![preview_id, terminal.outcome().as_str(), terminal_digest.as_slice()],
        )?;
        read_action_by_preview(connection, &preview_id)?
            .ok_or(ReviewStoreError::Corrupt("legacy_external_action"))?;
    }
    Ok(())
}

fn migrate_review_v1_snapshots(connection: &Connection) -> Stored<()> {
    type LegacySnapshot = (String, String, i64, Vec<u8>, Vec<u8>);
    let snapshots: Vec<LegacySnapshot> = {
        let mut statement = connection.prepare(
            "SELECT workspace_kind,workspace_id,revision,document,document_digest FROM review_snapshots ORDER BY workspace_kind,workspace_id,revision",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?
    };
    for (kind, id, revision, document, raw_digest) in snapshots {
        let stored_digest: [u8; 32] = raw_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("snapshot_digest"))?;
        if digest(&document) != stored_digest {
            return Err(ReviewStoreError::Corrupt("snapshot_digest"));
        }
        let (snapshot, canonical, protocol_schema) = match decode_review_snapshot(&document) {
            Ok(snapshot) if snapshot.schema() == ReviewSchemaVersion::V1 => {
                let canonical = encode_review_snapshot(&snapshot)
                    .map_err(|_| ReviewStoreError::Corrupt("legacy_snapshot"))?;
                (snapshot, canonical, ReviewSchemaVersion::V1)
            }
            _ => migrate_mislabeled_authority_snapshot(&document)?,
        };
        let (decoded_kind, decoded_id) = workspace_parts(snapshot.workspace());
        if decoded_kind != kind
            || decoded_id != id
            || db_revision(snapshot.revision())? != revision
            || (protocol_schema == ReviewSchemaVersion::V1 && canonical != document)
        {
            return Err(ReviewStoreError::Corrupt("legacy_snapshot_projection"));
        }
        validate_snapshot_comments(connection, &kind, &id, revision, &snapshot)?;
        let canonical_digest = digest(&canonical);
        connection.execute(
            "UPDATE review_snapshots SET document=?1,document_digest=?2,protocol_schema=?3 WHERE workspace_kind=?4 AND workspace_id=?5 AND revision=?6",
            params![canonical, canonical_digest.as_slice(), protocol_schema.as_str(), kind, id, revision],
        )?;
    }
    Ok(())
}

fn migrate_mislabeled_authority_snapshot(
    document: &[u8],
) -> Stored<(ReviewSnapshot, Vec<u8>, ReviewSchemaVersion)> {
    // The first implementation of authority-bearing proposals was briefly
    // persisted with the historical v1 schema tag. This rewrite is deliberately
    // private to the v1 -> v2 store transaction: ordinary v1 decoding stays
    // exact and never accepts or invents proposal authority.
    automonique_protocol::wire::parse_canonical(document)
        .map_err(|_| ReviewStoreError::Corrupt("legacy_snapshot"))?;
    let text =
        std::str::from_utf8(document).map_err(|_| ReviewStoreError::Corrupt("legacy_snapshot"))?;
    const V1_FIELD: &str = "\"schema\":\"automonique.platform/review/v1\"";
    const V2_FIELD: &str = "\"schema\":\"automonique.platform/review/v2\"";
    if text.matches(V1_FIELD).count() != 1 {
        return Err(ReviewStoreError::Corrupt("legacy_snapshot"));
    }
    let canonical = text.replacen(V1_FIELD, V2_FIELD, 1).into_bytes();
    let snapshot = decode_review_snapshot(&canonical)
        .map_err(|_| ReviewStoreError::Corrupt("legacy_snapshot"))?;
    if snapshot.schema() != ReviewSchemaVersion::V2
        || encode_review_snapshot(&snapshot)
            .map_err(|_| ReviewStoreError::Corrupt("legacy_snapshot"))?
            != canonical
    {
        return Err(ReviewStoreError::Corrupt("legacy_snapshot"));
    }
    Ok((snapshot, canonical, ReviewSchemaVersion::V2))
}
fn bind_authority_namespace(
    connection: &Connection,
    namespace: &str,
    schema_fresh: bool,
) -> Stored<()> {
    let current: Option<String> = connection
        .query_row(
            "SELECT authority_namespace FROM review_store_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match current {
        Some(current) if current != namespace => {
            Err(ReviewStoreError::Conflict("authority_namespace"))
        }
        Some(_) => Ok(()),
        None => {
            let populated: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM review_current UNION ALL SELECT 1 FROM review_snapshots UNION ALL SELECT 1 FROM review_comments UNION ALL SELECT 1 FROM review_authority_grants UNION ALL SELECT 1 FROM review_authority_grant_events UNION ALL SELECT 1 FROM review_action_previews UNION ALL SELECT 1 FROM review_action_approvals UNION ALL SELECT 1 FROM review_action_receipts UNION ALL SELECT 1 FROM review_completion_evidence UNION ALL SELECT 1 FROM review_provider_observations UNION ALL SELECT 1 FROM review_external_effect_plans UNION ALL SELECT 1 FROM review_github_check_effect_plans)",
                [],
                |row| row.get(0),
            )?;
            if populated || !schema_fresh {
                return Err(ReviewStoreError::Corrupt("authority_namespace"));
            }
            connection.execute(
                "INSERT OR IGNORE INTO review_store_metadata(singleton,authority_namespace) VALUES(1,?1)",
                [namespace],
            )?;
            let recorded: String = connection.query_row(
                "SELECT authority_namespace FROM review_store_metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if recorded == namespace {
                Ok(())
            } else {
                Err(ReviewStoreError::Conflict("authority_namespace"))
            }
        }
    }
}
fn secure_path(path: &Path) -> Stored<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ReviewStoreError::Io(io),
        other => ReviewStoreError::InsecurePath(other.to_string()),
    })
}
fn workspace_parts(workspace: &WorkContextIdentity) -> (&str, &str) {
    (workspace.kind().as_str(), workspace.id())
}
fn validate_time(value: i64) -> Stored<()> {
    if value < 0 {
        Err(ReviewStoreError::InvalidField("time"))
    } else {
        Ok(())
    }
}
fn db_revision(value: Revision) -> Stored<i64> {
    i64::try_from(value.get()).map_err(|_| ReviewStoreError::InvalidField("revision"))
}
fn parse_revision(value: i64) -> Stored<Revision> {
    u64::try_from(value)
        .ok()
        .and_then(|v| Revision::new(v).ok())
        .ok_or(ReviewStoreError::Corrupt("revision"))
}
fn digest(document: &[u8]) -> [u8; 32] {
    Sha256::digest(document).into()
}
fn digest_token(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn protocol(error: impl fmt::Display) -> ReviewStoreError {
    ReviewStoreError::Protocol(error.to_string())
}

fn encode_preview_document(protocol_request_digest: &[u8; 32], policy: ApprovalPolicy) -> Vec<u8> {
    JsonValue::Object(vec![
        (
            "approval_policy".to_owned(),
            JsonValue::String(policy.as_str().to_owned()),
        ),
        (
            "approval_required".to_owned(),
            JsonValue::Bool(policy == ApprovalPolicy::Required),
        ),
        (
            "protocol_request_digest".to_owned(),
            JsonValue::String(digest_token(protocol_request_digest)),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("automonique.store/review-preview/v1".to_owned()),
        ),
    ])
    .to_canonical_bytes()
}

fn initial_authorization_id(
    workspace: &WorkContextIdentity,
    actor: &ReviewActorId,
    authentication: ReviewAuthentication,
    authority: &ReviewAuthority,
) -> String {
    let (workspace_kind, workspace_id) = workspace_parts(workspace);
    let material = JsonValue::Object(vec![
        (
            "actor".to_owned(),
            JsonValue::String(actor.as_str().to_owned()),
        ),
        (
            "authentication".to_owned(),
            JsonValue::String(authentication.as_str().to_owned()),
        ),
        (
            "authority_id".to_owned(),
            JsonValue::String(authority.id().as_str().to_owned()),
        ),
        (
            "authority_kind".to_owned(),
            JsonValue::String(authority.kind().as_str().to_owned()),
        ),
        (
            "workspace_id".to_owned(),
            JsonValue::String(workspace_id.to_owned()),
        ),
        (
            "workspace_kind".to_owned(),
            JsonValue::String(workspace_kind.to_owned()),
        ),
    ])
    .to_canonical_bytes();
    format!("grant_{}", digest_token(&digest(&material)))
}

fn write_admission_id(
    action: &StoredReviewAction,
    approval_digest: Option<&[u8; 32]>,
    admitted_at_ms: i64,
) -> Stored<String> {
    let material = encode_write_admission(action, approval_digest, admitted_at_ms, "pending")?;
    Ok(format!("write_{}", digest_token(&digest(&material))))
}

fn encode_write_admission(
    action: &StoredReviewAction,
    approval_digest: Option<&[u8; 32]>,
    admitted_at_ms: i64,
    admission_id: &str,
) -> Stored<Vec<u8>> {
    let (workspace_kind, workspace_id) = workspace_parts(action.request.workspace());
    Ok(JsonValue::Object(vec![
        (
            "action_id".to_owned(),
            JsonValue::String(action.receipt.action_id().as_str().to_owned()),
        ),
        (
            "action_kind".to_owned(),
            JsonValue::String(action.request.action().kind().as_str().to_owned()),
        ),
        (
            "actor".to_owned(),
            JsonValue::String(action.request.actor().as_str().to_owned()),
        ),
        (
            "admission_id".to_owned(),
            JsonValue::String(admission_id.to_owned()),
        ),
        (
            "admitted_at_ms".to_owned(),
            JsonValue::Integer(admitted_at_ms),
        ),
        (
            "approval_digest".to_owned(),
            approval_digest.map_or(JsonValue::Null, |value| {
                JsonValue::String(digest_token(value))
            }),
        ),
        (
            "approval_policy".to_owned(),
            JsonValue::String(action.approval_policy.as_str().to_owned()),
        ),
        (
            "authentication".to_owned(),
            JsonValue::String(action.request.authentication().as_str().to_owned()),
        ),
        (
            "authority_id".to_owned(),
            JsonValue::String(action.request.authority().id().as_str().to_owned()),
        ),
        (
            "authority_kind".to_owned(),
            JsonValue::String(action.request.authority().kind().as_str().to_owned()),
        ),
        (
            "expected_revision".to_owned(),
            JsonValue::Integer(db_revision(action.request.expected_revision())?),
        ),
        (
            "external_effect_plan_digest".to_owned(),
            action
                .external_effect_plan_digest
                .map_or(JsonValue::Null, |value| {
                    JsonValue::String(digest_token(&value))
                }),
        ),
        (
            "request_digest".to_owned(),
            JsonValue::String(digest_token(&action.request_digest)),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("automonique.store/review-write-admission/v1".to_owned()),
        ),
        (
            "workspace_id".to_owned(),
            JsonValue::String(workspace_id.to_owned()),
        ),
        (
            "workspace_kind".to_owned(),
            JsonValue::String(workspace_kind.to_owned()),
        ),
    ])
    .to_canonical_bytes())
}

fn is_terminal(outcome: ReviewReceiptOutcome) -> bool {
    !matches!(
        outcome,
        ReviewReceiptOutcome::Accepted | ReviewReceiptOutcome::Unknown
    )
}

fn require_active_authority(
    connection: &Connection,
    request: &ReviewActionRequest,
    now_ms: i64,
) -> Stored<()> {
    require_active_grant(
        connection,
        request.workspace(),
        request.actor(),
        request.authentication(),
        request.authority(),
        now_ms,
    )
}

fn require_active_grant(
    connection: &Connection,
    workspace: &WorkContextIdentity,
    actor: &ReviewActorId,
    authentication: ReviewAuthentication,
    authority: &ReviewAuthority,
    now_ms: i64,
) -> Stored<()> {
    if authentication == ReviewAuthentication::ProviderSession {
        return Err(ReviewStoreError::Unauthorized);
    }
    let (kind, id) = workspace_parts(workspace);
    let authorized: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM review_authority_grants g JOIN review_authority_grant_events e ON e.authorization_id=g.authorization_id AND e.workspace_kind=g.workspace_kind AND e.workspace_id=g.workspace_id AND e.actor_id=g.actor_id AND e.authentication=g.authentication AND e.authority_kind=g.authority_kind AND e.authority_id=g.authority_id AND e.grant_revision=g.grant_revision AND e.granted_at_ms=g.granted_at_ms AND e.expires_at_ms=g.expires_at_ms WHERE g.workspace_kind=?1 AND g.workspace_id=?2 AND g.actor_id=?3 AND g.authentication=?4 AND g.authority_kind=?5 AND g.authority_id=?6 AND g.granted_at_ms<=?7 AND g.expires_at_ms>?7 AND g.revoked_at_ms IS NULL)",
        params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), now_ms],
        |row| row.get(0),
    )?;
    if authorized {
        Ok(())
    } else {
        Err(ReviewStoreError::Unauthorized)
    }
}

fn validate_current_action(connection: &Connection, request: &ReviewActionRequest) -> Stored<()> {
    let (kind, id) = workspace_parts(request.workspace());
    let current: i64 = connection
        .query_row(
            "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
            params![kind, id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ReviewStoreError::NotFound)?;
    if current != db_revision(request.expected_revision())? {
        return Err(ReviewStoreError::StaleRevision {
            current: parse_revision(current)?,
        });
    }
    let snapshot = read_current_snapshot(connection, kind, id)?
        .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
    snapshot.resolve_action(request).map_err(protocol)
}

fn validate_comment_history(previous: &ReviewSnapshot, next: &ReviewSnapshot) -> Stored<()> {
    for old in previous.comments() {
        let new = next
            .comments()
            .iter()
            .find(|value| value.id() == old.id())
            .ok_or(ReviewStoreError::Conflict("comment_removed"))?;
        if new.revision() == old.revision() {
            if new != old {
                return Err(ReviewStoreError::Conflict("comment_same_revision"));
            }
            continue;
        }
        let expected = old
            .revision()
            .get()
            .checked_add(1)
            .and_then(|value| Revision::new(value).ok())
            .ok_or(ReviewStoreError::Conflict("comment_revision"))?;
        if new.revision() != expected
            || new.actor() != old.actor()
            || new.anchor() != old.anchor()
            || comment_state_rank(new.agent_state().as_str())
                < comment_state_rank(old.agent_state().as_str())
        {
            return Err(ReviewStoreError::Conflict("comment_history"));
        }
    }
    if next.comments().iter().any(|comment| {
        !previous
            .comments()
            .iter()
            .any(|old| old.id() == comment.id())
            && comment.revision().get() != 1
    }) {
        return Err(ReviewStoreError::Conflict("comment_revision"));
    }
    Ok(())
}

fn comment_state_rank(value: &str) -> u8 {
    match value {
        "not_sent" => 0,
        "pending" => 1,
        "refused" => 2,
        "sent" => 3,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_completion_evidence(
    preview_id: &str,
    request_digest: &[u8; 32],
    result_revision: Revision,
    evidence_id: &str,
    actor: &ReviewActorId,
    authentication: ReviewAuthentication,
    authority: &ReviewAuthority,
    sanitized_document: &[u8],
    observed_at_ms: i64,
) -> Stored<Vec<u8>> {
    let document = std::str::from_utf8(sanitized_document)
        .map_err(|_| ReviewStoreError::InvalidField("completion_evidence"))?;
    Ok(JsonValue::Object(vec![
        (
            "authority_id".to_owned(),
            JsonValue::String(authority.id().as_str().to_owned()),
        ),
        (
            "authority_kind".to_owned(),
            JsonValue::String(authority.kind().as_str().to_owned()),
        ),
        (
            "authentication".to_owned(),
            JsonValue::String(authentication.as_str().to_owned()),
        ),
        (
            "evidence_id".to_owned(),
            JsonValue::String(evidence_id.to_owned()),
        ),
        (
            "observed_at_ms".to_owned(),
            JsonValue::Integer(observed_at_ms),
        ),
        (
            "preview_id".to_owned(),
            JsonValue::String(preview_id.to_owned()),
        ),
        (
            "request_digest".to_owned(),
            JsonValue::String(digest_token(request_digest)),
        ),
        (
            "result_revision".to_owned(),
            JsonValue::Integer(db_revision(result_revision)?),
        ),
        (
            "sanitized_document".to_owned(),
            JsonValue::String(document.to_owned()),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("automonique.store/review-completion-evidence/v1".to_owned()),
        ),
        (
            "verifying_actor".to_owned(),
            JsonValue::String(actor.as_str().to_owned()),
        ),
    ])
    .to_canonical_bytes())
}

fn has_completion_evidence(
    connection: &Connection,
    preview_id: &str,
    request_digest: [u8; 32],
    result_revision: Revision,
) -> Stored<bool> {
    type RawEvidence = (
        Vec<u8>,
        i64,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let raw: Option<RawEvidence> = connection.query_row(
        "SELECT request_digest,result_revision,evidence_id,verifying_actor_id,authentication,authority_kind,authority_id,evidence_document,evidence_digest,observed_at_ms FROM review_completion_evidence WHERE preview_id=?1",
        [preview_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
    ).optional()?;
    let Some((
        raw_request_digest,
        raw_revision,
        evidence_id,
        actor,
        authentication,
        authority_kind,
        authority_id,
        document,
        raw_digest,
        observed_at_ms,
    )) = raw
    else {
        return Ok(false);
    };
    let stored_request_digest: [u8; 32] = raw_request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let stored_digest: [u8; 32] = raw_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let authentication = ReviewAuthentication::parse(&authentication)
        .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let authority = ReviewAuthority::new(
        ReviewAuthorityKind::parse(&authority_kind)
            .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?,
        ReviewAuthorityId::new(authority_id)
            .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?,
    );
    let actor =
        ReviewActorId::new(actor).map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let parsed_revision = parse_revision(raw_revision)?;
    if observed_at_ms < 0 {
        return Err(ReviewStoreError::Corrupt("completion_evidence"));
    }
    let decoded = std::str::from_utf8(&document)
        .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let parsed = automonique_protocol::wire::parse_canonical(decoded.as_bytes())
        .map_err(|_| ReviewStoreError::Corrupt("completion_evidence"))?;
    let sanitized = parsed
        .get("sanitized_document")
        .and_then(JsonValue::as_str)
        .ok_or(ReviewStoreError::Corrupt("completion_evidence"))?;
    let expected = encode_completion_evidence(
        preview_id,
        &stored_request_digest,
        parsed_revision,
        &evidence_id,
        &actor,
        authentication,
        &authority,
        sanitized.as_bytes(),
        observed_at_ms,
    )?;
    if stored_request_digest != request_digest
        || parsed_revision != result_revision
        || digest(&document) != stored_digest
        || document != expected
    {
        return Err(ReviewStoreError::Corrupt("completion_evidence"));
    }
    Ok(true)
}

fn read_current_snapshot(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Stored<Option<ReviewSnapshot>> {
    let current_revision: Option<i64> = connection
        .query_row(
            "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
            params![kind, id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(current_revision) = current_revision else {
        return Ok(None);
    };
    read_snapshot_revision(connection, kind, id, parse_revision(current_revision)?)?
        .ok_or(ReviewStoreError::Corrupt("current_snapshot"))
        .map(Some)
}

fn persist_snapshot(
    connection: &Connection,
    snapshot: &ReviewSnapshot,
    recorded_at_ms: i64,
) -> Stored<()> {
    let document = encode_review_snapshot(snapshot).map_err(protocol)?;
    // Storage accepts only a value that its canonical decoder accepts again.
    decode_review_snapshot(&document).map_err(protocol)?;
    let document_digest = digest(&document);
    let (kind, workspace_id) = workspace_parts(snapshot.workspace());
    let revision = db_revision(snapshot.revision())?;
    let current: Option<i64> = connection
        .query_row(
            "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
            params![kind, workspace_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(current) = current {
        if current == revision {
            let existing: (Vec<u8>, Vec<u8>, String) = connection.query_row(
                "SELECT document,document_digest,protocol_schema FROM review_snapshots WHERE workspace_kind=?1 AND workspace_id=?2 AND revision=?3",
                params![kind, workspace_id, revision],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if digest(&existing.0).as_slice() != existing.1
                || existing.1.as_slice() != document_digest
                || existing.2 != snapshot.schema().as_str()
            {
                return Err(ReviewStoreError::Conflict("snapshot_revision"));
            }
            return Ok(());
        }
        if revision
            != current
                .checked_add(1)
                .ok_or(ReviewStoreError::InvalidField("revision"))?
        {
            return Err(ReviewStoreError::StaleRevision {
                current: parse_revision(current)?,
            });
        }
        let previous = read_current_snapshot(connection, kind, workspace_id)?
            .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
        if previous.schema() == ReviewSchemaVersion::V2
            && snapshot.schema() == ReviewSchemaVersion::V1
        {
            return Err(ReviewStoreError::Conflict("snapshot_schema_downgrade"));
        }
        validate_comment_history(&previous, snapshot)?;
    }
    connection.execute(
        "INSERT INTO review_snapshots(workspace_kind,workspace_id,revision,document,document_digest,recorded_at_ms,protocol_schema) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![kind, workspace_id, revision, document, document_digest.as_slice(), recorded_at_ms, snapshot.schema().as_str()],
    )?;
    for comment in snapshot.comments() {
        connection.execute(
            "INSERT INTO review_comments(workspace_kind,workspace_id,snapshot_revision,comment_id,comment_revision,actor_id,body,file_id,hunk_id,side,line,agent_state,unread) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![kind, workspace_id, revision, comment.id().as_str(), db_revision(comment.revision())?, comment.actor().as_str(), comment.body().as_str(), comment.anchor().file_id().as_str(), comment.anchor().hunk_id().as_str(), comment.anchor().side().as_str(), i64::from(comment.anchor().line()), comment.agent_state().as_str(), i64::from(comment.unread())],
        )?;
    }
    connection.execute(
        "INSERT INTO review_current(workspace_kind,workspace_id,revision) VALUES(?1,?2,?3) ON CONFLICT(workspace_kind,workspace_id) DO UPDATE SET revision=excluded.revision",
        params![kind, workspace_id, revision],
    )?;
    Ok(())
}

fn local_action_snapshot(
    current: &ReviewSnapshot,
    request: &ReviewActionRequest,
    receipt: &ReviewActionReceipt,
    recorded_at_ms: i64,
) -> Stored<ReviewSnapshot> {
    if current.schema() != ReviewSchemaVersion::V2
        || current.workspace() != request.workspace()
        || current.revision() != request.expected_revision()
    {
        return Err(ReviewStoreError::Conflict("local_action_snapshot"));
    }
    let next_revision = current
        .revision()
        .get()
        .checked_add(1)
        .and_then(|value| Revision::new(value).ok())
        .ok_or(ReviewStoreError::InvalidField("revision"))?;
    let mut comments = current.comments().to_vec();
    let mut review = current.review().clone();
    let approving = match request.action() {
        ReviewAction::AddComment {
            comment_id,
            anchor,
            body,
        } => {
            comments.push(ReviewComment::new(
                comment_id.clone(),
                Revision::FIRST,
                request.actor().clone(),
                body.clone(),
                anchor.clone(),
                CommentAgentState::NotSent,
                false,
            ));
            comments.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
            false
        }
        ReviewAction::ApproveReview { .. } => {
            let observed_at_ms = u64::try_from(recorded_at_ms)
                .map_err(|_| ReviewStoreError::InvalidField("time"))?;
            review = ReviewStatusProjection::new(
                ReviewDecision::Approved,
                current.review().authority().clone(),
                ReviewFreshness::new(ReviewFreshnessState::Fresh, next_revision, observed_at_ms)
                    .map_err(protocol)?,
            )
            .map_err(protocol)?;
            true
        }
        _ => return Err(ReviewStoreError::InvalidField("local_action")),
    };

    let mut attention_events = Vec::with_capacity(current.attention_events().len() + 1);
    for event in current.attention_events() {
        if approving
            && matches!(
                event.reason(),
                AttentionReason::ReviewRequested | AttentionReason::ApprovalRequired
            )
        {
            continue;
        }
        if matches!(
            event.reason(),
            AttentionReason::Conflict | AttentionReason::Complete
        ) {
            let origin = AttentionOrigin::new(
                event.origin().kind(),
                event.origin().id().cloned(),
                event.origin().authority().clone(),
                next_revision,
            )
            .map_err(protocol)?;
            attention_events.push(
                AttentionEvent::new(event.id().clone(), origin, event.reason(), event.unread())
                    .map_err(protocol)?,
            );
        } else {
            attention_events.push(event.clone());
        }
    }
    let complete = approving
        && current
            .files()
            .iter()
            .all(|file| file.conflict() != ConflictState::Unresolved)
        && current
            .checks()
            .iter()
            .filter(|check| check.required())
            .all(|check| {
                check.freshness().state() == ReviewFreshnessState::Fresh
                    && check.state() == CheckState::Passed
            })
        && current.pull_request().freshness().state() == ReviewFreshnessState::Fresh
        && matches!(
            current.pull_request().state(),
            PullRequestState::Absent | PullRequestState::Merged
        )
        && current.delivery().freshness().state() == ReviewFreshnessState::Fresh
        && matches!(
            current.delivery().state(),
            DeliveryState::NotDelivered | DeliveryState::Delivered
        );
    if complete
        && !attention_events
            .iter()
            .any(|event| event.reason() == AttentionReason::Complete)
    {
        let event_id =
            ReviewAttentionEventId::new(format!("complete_{}", receipt.action_id().as_str()))
                .map_err(protocol)?;
        let origin = AttentionOrigin::new(
            AttentionOriginKind::Snapshot,
            None,
            review.authority().clone(),
            next_revision,
        )
        .map_err(protocol)?;
        attention_events.push(
            AttentionEvent::new(event_id, origin, AttentionReason::Complete, 0)
                .map_err(protocol)?,
        );
    }
    attention_events.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    ReviewSnapshot::new(
        current.workspace().clone(),
        next_revision,
        current.files().to_vec(),
        comments,
        current.proposals().to_vec(),
        current.checks().to_vec(),
        review,
        current.pull_request().clone(),
        current.delivery().clone(),
        attention_events,
    )
    .map_err(protocol)
}

fn external_targets_are_exact(
    original: &ReviewSnapshot,
    current: &ReviewSnapshot,
    request: &ReviewActionRequest,
) -> Stored<bool> {
    for (comment_id, expected_revision) in external_action_targets(request)? {
        let original_comment = original.comments().iter().find(|comment| {
            comment.id().as_str() == comment_id && comment.revision() == expected_revision
        });
        let current_comment = current
            .comments()
            .iter()
            .find(|comment| comment.id().as_str() == comment_id);
        if original_comment.is_none() || current_comment != original_comment {
            return Ok(false);
        }
    }
    Ok(true)
}

fn settle_external_targets(
    connection: &Connection,
    preview_id: &str,
    disposition: &str,
) -> Stored<()> {
    let (expected, already_settled, total): (i64, i64, i64) = connection.query_row(
        "SELECT coalesce(sum(disposition='reserved'),0),coalesce(sum(disposition=?2),0),count(*) FROM review_external_effect_targets WHERE preview_id=?1",
        params![preview_id, disposition],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if expected == 0 {
        return if total > 0 && already_settled == total {
            Ok(())
        } else {
            Err(ReviewStoreError::Corrupt("external_effect_targets"))
        };
    }
    let changed = connection.execute(
        "UPDATE review_external_effect_targets SET disposition=?1 WHERE preview_id=?2 AND disposition='reserved'",
        params![disposition, preview_id],
    )?;
    if changed
        != usize::try_from(expected)
            .map_err(|_| ReviewStoreError::Corrupt("external_effect_targets"))?
    {
        return Err(ReviewStoreError::Conflict("external_effect_completion"));
    }
    Ok(())
}

fn release_external_plan_before_write(connection: &Connection, preview_id: &str) -> Stored<()> {
    let targets = connection.execute(
        "DELETE FROM review_external_effect_targets WHERE preview_id=?1 AND disposition='reserved'",
        [preview_id],
    )?;
    if targets == 0 {
        return Err(ReviewStoreError::Corrupt("external_effect_targets"));
    }
    let plans: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM review_external_effect_plans WHERE preview_id=?1)",
        [preview_id],
        |row| row.get(0),
    )?;
    if !plans {
        return Err(ReviewStoreError::Corrupt("external_effect_plan"));
    }
    Ok(())
}

fn safe_effect_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_effect_head_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn github_check_rerun_snapshot(
    current: &ReviewSnapshot,
    request: &ReviewActionRequest,
    recorded_at_ms: i64,
) -> Stored<ReviewSnapshot> {
    let ReviewAction::RerunCheck {
        check_id,
        expected_check_revision,
    } = request.action()
    else {
        return Err(ReviewStoreError::InvalidField("external_effect_action"));
    };
    if current.schema() != ReviewSchemaVersion::V2
        || current.workspace() != request.workspace()
        || current.revision() != request.expected_revision()
    {
        return Err(ReviewStoreError::Conflict("external_effect_completion"));
    }
    let next_revision = Revision::new(
        current
            .revision()
            .get()
            .checked_add(1)
            .ok_or(ReviewStoreError::InvalidField("revision"))?,
    )
    .map_err(|_| ReviewStoreError::InvalidField("revision"))?;
    let next_check_revision = Revision::new(
        expected_check_revision
            .get()
            .checked_add(1)
            .ok_or(ReviewStoreError::InvalidField("revision"))?,
    )
    .map_err(|_| ReviewStoreError::InvalidField("revision"))?;
    let observed_at_ms =
        u64::try_from(recorded_at_ms).map_err(|_| ReviewStoreError::InvalidField("time"))?;
    let mut checks = Vec::with_capacity(current.checks().len());
    let mut found = false;
    for check in current.checks() {
        if check.id() == check_id {
            if check.freshness().observed_revision() != *expected_check_revision {
                return Err(ReviewStoreError::Conflict("external_effect_completion"));
            }
            checks.push(
                CheckProjection::new(
                    check.id().clone(),
                    CheckState::Running,
                    check.authority().clone(),
                    ReviewFreshness::new(
                        ReviewFreshnessState::Fresh,
                        next_check_revision,
                        observed_at_ms,
                    )
                    .map_err(protocol)?,
                    check.required(),
                )
                .map_err(protocol)?,
            );
            found = true;
        } else {
            checks.push(check.clone());
        }
    }
    if !found {
        return Err(ReviewStoreError::Corrupt("external_effect_check"));
    }
    ReviewSnapshot::new(
        current.workspace().clone(),
        next_revision,
        current.files().to_vec(),
        current.comments().to_vec(),
        current.proposals().to_vec(),
        checks,
        current.review().clone(),
        current.pull_request().clone(),
        current.delivery().clone(),
        current.attention_events().to_vec(),
    )
    .map_err(protocol)
}

fn retained_session_delivery_snapshot(
    original: &ReviewSnapshot,
    current: &ReviewSnapshot,
    request: &ReviewActionRequest,
    delivered: bool,
) -> Stored<ReviewSnapshot> {
    if current.schema() != ReviewSchemaVersion::V2
        || original.schema() != ReviewSchemaVersion::V2
        || current.workspace() != request.workspace()
        || original.workspace() != request.workspace()
        || original.revision() != request.expected_revision()
        || !external_targets_are_exact(original, current, request)?
    {
        return Err(ReviewStoreError::Conflict("retained_session_snapshot"));
    }
    let next_revision = current
        .revision()
        .get()
        .checked_add(1)
        .and_then(|value| Revision::new(value).ok())
        .ok_or(ReviewStoreError::InvalidField("revision"))?;
    let targets: BTreeSet<&str> = match request.action() {
        ReviewAction::SendCommentToAgent { comment_id, .. } => {
            std::iter::once(comment_id.as_str()).collect()
        }
        ReviewAction::BatchSendCommentsToAgent { comments } => comments
            .iter()
            .map(|target| target.comment_id().as_str())
            .collect(),
        _ => return Err(ReviewStoreError::InvalidField("retained_session_action")),
    };
    let next_state = if delivered {
        CommentAgentState::Sent
    } else {
        CommentAgentState::Refused
    };
    let mut comments = Vec::with_capacity(current.comments().len());
    for comment in current.comments() {
        if targets.contains(comment.id().as_str()) {
            let revision = comment
                .revision()
                .get()
                .checked_add(1)
                .and_then(|value| Revision::new(value).ok())
                .ok_or(ReviewStoreError::InvalidField("comment_revision"))?;
            comments.push(ReviewComment::new(
                comment.id().clone(),
                revision,
                comment.actor().clone(),
                comment.body().clone(),
                comment.anchor().clone(),
                next_state,
                comment.unread(),
            ));
        } else {
            comments.push(comment.clone());
        }
    }
    let mut attention_events = Vec::with_capacity(current.attention_events().len());
    for event in current.attention_events() {
        let target_comment_revision = event
            .origin()
            .id()
            .filter(|id| {
                event.origin().kind() == AttentionOriginKind::Comment
                    && targets.contains(id.as_str())
            })
            .and_then(|id| {
                comments
                    .iter()
                    .find(|comment| comment.id().as_str() == id.as_str())
            })
            .map(ReviewComment::revision);
        let origin_revision = target_comment_revision.unwrap_or_else(|| {
            if matches!(
                event.reason(),
                AttentionReason::Conflict | AttentionReason::Complete
            ) {
                next_revision
            } else {
                event.origin().revision()
            }
        });
        let origin = AttentionOrigin::new(
            event.origin().kind(),
            event.origin().id().cloned(),
            event.origin().authority().clone(),
            origin_revision,
        )
        .map_err(protocol)?;
        attention_events.push(
            AttentionEvent::new(event.id().clone(), origin, event.reason(), event.unread())
                .map_err(protocol)?,
        );
    }
    ReviewSnapshot::new(
        current.workspace().clone(),
        next_revision,
        current.files().to_vec(),
        comments,
        current.proposals().to_vec(),
        current.checks().to_vec(),
        current.review().clone(),
        current.pull_request().clone(),
        current.delivery().clone(),
        attention_events,
    )
    .map_err(protocol)
}

fn read_snapshot_revision(
    connection: &Connection,
    kind: &str,
    id: &str,
    revision: Revision,
) -> Stored<Option<ReviewSnapshot>> {
    type RawSnapshot = (Vec<u8>, Vec<u8>, String, String, i64, String);
    let stored_revision = db_revision(revision)?;
    let raw: Option<RawSnapshot> = connection
        .query_row(
            "SELECT document,document_digest,workspace_kind,workspace_id,revision,protocol_schema FROM review_snapshots WHERE workspace_kind=?1 AND workspace_id=?2 AND revision=?3",
            params![kind, id, stored_revision],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()?;
    let Some((document, raw_digest, stored_kind, stored_id, raw_revision, protocol_schema)) = raw
    else {
        return Ok(None);
    };
    let document_digest: [u8; 32] = raw_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("snapshot_digest"))?;
    if digest(&document) != document_digest || raw_revision != stored_revision {
        return Err(ReviewStoreError::Corrupt("snapshot_digest"));
    }
    let snapshot =
        decode_review_snapshot(&document).map_err(|_| ReviewStoreError::Corrupt("snapshot"))?;
    let (decoded_kind, decoded_id) = workspace_parts(snapshot.workspace());
    if stored_kind != kind
        || stored_id != id
        || decoded_kind != stored_kind
        || decoded_id != stored_id
        || snapshot.revision() != revision
        || snapshot.schema().as_str() != protocol_schema
    {
        return Err(ReviewStoreError::Corrupt("snapshot_projection"));
    }
    validate_snapshot_comments(connection, kind, id, stored_revision, &snapshot)?;
    Ok(Some(snapshot))
}

fn validate_snapshot_comments(
    connection: &Connection,
    kind: &str,
    id: &str,
    revision: i64,
    snapshot: &ReviewSnapshot,
) -> Stored<()> {
    type RawComment = (
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
    );
    let rows: Vec<RawComment> = {
        let mut statement = connection.prepare(
            "SELECT comment_id,comment_revision,actor_id,body,file_id,hunk_id,side,line,agent_state,unread FROM review_comments WHERE workspace_kind=?1 AND workspace_id=?2 AND snapshot_revision=?3 ORDER BY comment_id",
        )?;
        statement
            .query_map(params![kind, id, revision], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })?
            .collect::<Result<_, _>>()?
    };
    if rows.len() != snapshot.comments().len() {
        return Err(ReviewStoreError::Corrupt("snapshot_comments"));
    }
    for (raw, comment) in rows.iter().zip(snapshot.comments()) {
        if raw.0 != comment.id().as_str()
            || raw.1 != db_revision(comment.revision())?
            || raw.2 != comment.actor().as_str()
            || raw.3 != comment.body().as_str()
            || raw.4 != comment.anchor().file_id().as_str()
            || raw.5 != comment.anchor().hunk_id().as_str()
            || raw.6 != comment.anchor().side().as_str()
            || raw.7 != i64::from(comment.anchor().line())
            || raw.8 != comment.agent_state().as_str()
            || raw.9 != i64::from(comment.unread())
        {
            return Err(ReviewStoreError::Corrupt("snapshot_comments"));
        }
    }
    Ok(())
}

fn validate_external_effect_custody(
    connection: &Connection,
    action: &StoredReviewAction,
    plan: Option<&ReviewExternalEffectPlan>,
) -> Stored<()> {
    let retained_action = matches!(
        action.request.action(),
        ReviewAction::SendCommentToAgent { .. } | ReviewAction::BatchSendCommentsToAgent { .. }
    );
    let github_action = plan.is_some_and(ReviewExternalEffectPlan::is_github_check_rerun);
    let rows: Vec<(String, i64, String, String, String)> = {
        let mut statement = connection.prepare(
            "SELECT comment_id,comment_revision,workspace_kind,workspace_id,disposition FROM review_external_effect_targets WHERE preview_id=?1 ORDER BY comment_id",
        )?;
        statement
            .query_map([&action.preview_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<Result<_, _>>()?
    };
    if github_action {
        let Some(plan) = plan else {
            return Err(ReviewStoreError::Corrupt("external_effect_custody"));
        };
        let Some(custody) = plan.github_custody() else {
            return Err(ReviewStoreError::Corrupt("external_effect_custody"));
        };
        if !rows.is_empty() {
            return Err(ReviewStoreError::Corrupt("external_effect_custody"));
        }
        let exact = match action.receipt.outcome() {
            ReviewReceiptOutcome::Accepted => {
                if action.write_admitted_at_ms.is_some() {
                    matches!(
                        custody,
                        ReviewExternalEffectCustody::CustodyStarted
                            | ReviewExternalEffectCustody::Accepted
                    )
                } else {
                    custody == ReviewExternalEffectCustody::NotStarted
                }
            }
            ReviewReceiptOutcome::Unknown => {
                action.write_admitted_at_ms.is_some()
                    && custody == ReviewExternalEffectCustody::Ambiguous
            }
            ReviewReceiptOutcome::Refused => custody == ReviewExternalEffectCustody::Refused,
            ReviewReceiptOutcome::Completed | ReviewReceiptOutcome::Conflict => {
                action.write_admitted_at_ms.is_some()
                    && custody == ReviewExternalEffectCustody::Completed
            }
        };
        return if exact {
            Ok(())
        } else {
            Err(ReviewStoreError::Corrupt("external_effect_custody"))
        };
    }
    if !retained_action {
        return if plan.is_none() && rows.is_empty() {
            Ok(())
        } else {
            Err(ReviewStoreError::Corrupt("external_effect_custody"))
        };
    }
    if plan.is_none() {
        return if rows.is_empty() && migration_tombstone_matches(connection, action)? {
            Ok(())
        } else {
            Err(ReviewStoreError::Corrupt("external_effect_custody"))
        };
    }
    if action.receipt.outcome() == ReviewReceiptOutcome::Refused
        && action.write_admitted_at_ms.is_none()
        && rows.is_empty()
    {
        return Ok(());
    }
    let (workspace_kind, workspace_id) = workspace_parts(action.request.workspace());
    let expected: BTreeSet<(String, i64)> = external_action_targets(&action.request)?
        .into_iter()
        .map(|(comment_id, revision)| Ok((comment_id.to_owned(), db_revision(revision)?)))
        .collect::<Stored<_>>()?;
    let actual: BTreeSet<(String, i64)> = rows
        .iter()
        .map(|(comment_id, revision, _, _, _)| (comment_id.clone(), *revision))
        .collect();
    let expected_disposition = match action.receipt.outcome() {
        ReviewReceiptOutcome::Accepted | ReviewReceiptOutcome::Unknown => "reserved",
        ReviewReceiptOutcome::Completed => "delivered",
        ReviewReceiptOutcome::Refused => "refused",
        ReviewReceiptOutcome::Conflict => "delivered_conflict",
    };
    if expected != actual
        || rows.iter().any(|(_, _, kind, id, disposition)| {
            kind != workspace_kind || id != workspace_id || disposition != expected_disposition
        })
    {
        return Err(ReviewStoreError::Corrupt("external_effect_custody"));
    }
    Ok(())
}

fn migration_tombstone_matches(
    connection: &Connection,
    action: &StoredReviewAction,
) -> Stored<bool> {
    let raw: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT outcome,receipt_digest FROM review_external_effect_migration_tombstones WHERE preview_id=?1",
            [&action.preview_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((outcome, stored_digest)) = raw else {
        return Ok(false);
    };
    let stored_digest: [u8; 32] = stored_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_migration_tombstone"))?;
    let receipt_document = encode_review_action_receipt(&action.receipt).map_err(protocol)?;
    if !is_terminal(action.receipt.outcome())
        || outcome != action.receipt.outcome().as_str()
        || stored_digest != digest(&receipt_document)
    {
        return Err(ReviewStoreError::Corrupt(
            "external_effect_migration_tombstone",
        ));
    }
    Ok(true)
}

fn validate_completed_basis(connection: &Connection, action: &StoredReviewAction) -> Stored<()> {
    if action.receipt.outcome() != ReviewReceiptOutcome::Completed {
        return Ok(());
    }
    if action.external_effect_plan_digest.is_none()
        && migration_tombstone_matches(connection, action)?
    {
        return validate_legacy_external_completed_basis(
            connection,
            &action.request,
            &action.receipt,
        );
    }
    if action.external_effect_plan_digest.is_some() {
        if matches!(action.request.action(), ReviewAction::RerunCheck { .. }) {
            let result = action
                .receipt
                .revision()
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            let (kind, id) = workspace_parts(action.request.workspace());
            let completed = read_snapshot_revision(connection, kind, id, result)?
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            let ReviewAction::RerunCheck {
                check_id,
                expected_check_revision,
            } = action.request.action()
            else {
                unreachable!()
            };
            let check = completed
                .checks()
                .iter()
                .find(|check| check.id() == check_id)
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            let expected = Revision::new(
                expected_check_revision
                    .get()
                    .checked_add(1)
                    .ok_or(ReviewStoreError::Corrupt("completion_basis"))?,
            )
            .map_err(|_| ReviewStoreError::Corrupt("completion_basis"))?;
            return if check.state() == CheckState::Running
                && check.freshness().state() == ReviewFreshnessState::Fresh
                && check.freshness().observed_revision() == expected
            {
                Ok(())
            } else {
                Err(ReviewStoreError::Corrupt("completion_basis"))
            };
        }
        let result = action
            .receipt
            .revision()
            .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        if result <= action.request.expected_revision() {
            return Err(ReviewStoreError::Corrupt("completion_basis"));
        }
        let (kind, id) = workspace_parts(action.request.workspace());
        let original =
            read_snapshot_revision(connection, kind, id, action.request.expected_revision())?
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        let completed = read_snapshot_revision(connection, kind, id, result)?
            .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        for (comment_id, expected_revision) in external_action_targets(&action.request)? {
            let original_comment = original
                .comments()
                .iter()
                .find(|comment| {
                    comment.id().as_str() == comment_id && comment.revision() == expected_revision
                })
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            let completed_comment = completed
                .comments()
                .iter()
                .find(|comment| comment.id().as_str() == comment_id)
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            let next_comment_revision = expected_revision
                .get()
                .checked_add(1)
                .and_then(|value| Revision::new(value).ok())
                .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
            if completed_comment.revision() != next_comment_revision
                || completed_comment.actor() != original_comment.actor()
                || completed_comment.body() != original_comment.body()
                || completed_comment.anchor() != original_comment.anchor()
                || completed_comment.unread() != original_comment.unread()
                || completed_comment.agent_state() != CommentAgentState::Sent
            {
                return Err(ReviewStoreError::Corrupt("completion_basis"));
            }
        }
        return Ok(());
    }
    let expected_result = action
        .request
        .expected_revision()
        .get()
        .checked_add(1)
        .and_then(|value| Revision::new(value).ok())
        .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
    if action.receipt.revision() != Some(expected_result) {
        return Err(ReviewStoreError::Corrupt("completion_basis"));
    }
    // Validate an evidence row whenever one exists; malformed evidence may
    // not be hidden by a separately valid snapshot. Missing evidence is safe
    // only when the exact historical authoritative snapshot is retained.
    let evidence = has_completion_evidence(
        connection,
        &action.preview_id,
        action.request_digest,
        expected_result,
    )?;
    let (kind, id) = workspace_parts(action.request.workspace());
    let snapshot = read_snapshot_revision(connection, kind, id, expected_result)?.is_some();
    if snapshot || evidence {
        Ok(())
    } else {
        Err(ReviewStoreError::Corrupt("completion_basis"))
    }
}

fn validate_legacy_external_completed_basis(
    connection: &Connection,
    request: &ReviewActionRequest,
    receipt: &ReviewActionReceipt,
) -> Stored<()> {
    let expected_result = request
        .expected_revision()
        .get()
        .checked_add(1)
        .and_then(|value| Revision::new(value).ok())
        .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
    if receipt.outcome() != ReviewReceiptOutcome::Completed
        || receipt.revision() != Some(expected_result)
    {
        return Err(ReviewStoreError::Corrupt("completion_basis"));
    }
    let (kind, id) = workspace_parts(request.workspace());
    let original = read_snapshot_revision(connection, kind, id, request.expected_revision())?
        .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
    let completed = read_snapshot_revision(connection, kind, id, expected_result)?
        .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
    for (comment_id, expected_revision) in external_action_targets(request)? {
        let original_comment = original
            .comments()
            .iter()
            .find(|comment| {
                comment.id().as_str() == comment_id && comment.revision() == expected_revision
            })
            .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        let completed_comment = completed
            .comments()
            .iter()
            .find(|comment| comment.id().as_str() == comment_id)
            .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        let next_comment_revision = expected_revision
            .get()
            .checked_add(1)
            .and_then(|value| Revision::new(value).ok())
            .ok_or(ReviewStoreError::Corrupt("completion_basis"))?;
        if completed_comment.revision() != next_comment_revision
            || completed_comment.actor() != original_comment.actor()
            || completed_comment.body() != original_comment.body()
            || completed_comment.anchor() != original_comment.anchor()
            || completed_comment.unread() != original_comment.unread()
            || completed_comment.agent_state() != CommentAgentState::Sent
        {
            return Err(ReviewStoreError::Corrupt("completion_basis"));
        }
    }
    Ok(())
}

fn encode_approval(value: &ReviewApprovalDocument) -> Stored<Vec<u8>> {
    let (workspace_kind, workspace_id) = workspace_parts(value.workspace());
    Ok(JsonValue::Object(vec![
        (
            "approving_actor".to_owned(),
            JsonValue::String(value.approving_actor().as_str().to_owned()),
        ),
        (
            "authentication".to_owned(),
            JsonValue::String(value.authentication().as_str().to_owned()),
        ),
        (
            "authority".to_owned(),
            JsonValue::Object(vec![
                (
                    "id".to_owned(),
                    JsonValue::String(value.authority().id().as_str().to_owned()),
                ),
                (
                    "kind".to_owned(),
                    JsonValue::String(value.authority().kind().as_str().to_owned()),
                ),
            ]),
        ),
        (
            "decision".to_owned(),
            JsonValue::String(value.decision().as_str().to_owned()),
        ),
        (
            "expected_revision".to_owned(),
            JsonValue::Integer(db_revision(value.expected_revision())?),
        ),
        (
            "expires_at_ms".to_owned(),
            JsonValue::Integer(value.expires_at_ms()),
        ),
        (
            "preview_id".to_owned(),
            JsonValue::String(value.preview_id().to_owned()),
        ),
        (
            "request_digest".to_owned(),
            JsonValue::String(digest_token(&value.request_digest())),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("automonique.store/review-approval/v1".to_owned()),
        ),
        (
            "workspace".to_owned(),
            JsonValue::Object(vec![
                ("id".to_owned(), JsonValue::String(workspace_id.to_owned())),
                (
                    "kind".to_owned(),
                    JsonValue::String(workspace_kind.to_owned()),
                ),
            ]),
        ),
    ])
    .to_canonical_bytes())
}

fn read_approval(
    connection: &Connection,
    preview_id: &str,
) -> Stored<Option<StoredReviewApproval>> {
    type RawApproval = (
        String,
        String,
        Vec<u8>,
        i64,
        String,
        String,
        String,
        String,
        String,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<RawApproval> = connection
        .query_row(
            "SELECT a.workspace_kind,a.workspace_id,a.request_digest,a.expected_revision,a.approving_actor_id,a.authentication,a.authority_kind,a.authority_id,a.decision,a.expires_at_ms,a.approval_document,a.approval_digest,p.request_document,p.preview_document FROM review_action_approvals a JOIN review_action_previews p USING(preview_id) WHERE a.preview_id=?1",
            [preview_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?)),
        )
        .optional()?;
    let Some((
        workspace_kind,
        workspace_id,
        request_digest,
        expected_revision,
        actor,
        authentication,
        authority_kind,
        authority_id,
        decision,
        expires_at_ms,
        approval_document,
        approval_digest,
        request_document,
        preview_document,
    )) = raw
    else {
        return Ok(None);
    };
    let request = decode_review_action_request(&request_document)
        .map_err(|_| ReviewStoreError::Corrupt("approval_request"))?;
    let stored_request_digest: [u8; 32] = request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("approval_request_digest"))?;
    let stored_approval_digest: [u8; 32] = approval_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("approval_digest"))?;
    if digest(&preview_document) != stored_request_digest {
        return Err(ReviewStoreError::Corrupt("approval_request_digest"));
    }
    let document = ReviewApprovalDocument::new(
        preview_id,
        request.workspace().clone(),
        ReviewActorId::new(actor).map_err(|_| ReviewStoreError::Corrupt("approval_actor"))?,
        ReviewAuthentication::parse(&authentication)
            .map_err(|_| ReviewStoreError::Corrupt("approval_authentication"))?,
        ReviewAuthority::new(
            ReviewAuthorityKind::parse(&authority_kind)
                .map_err(|_| ReviewStoreError::Corrupt("approval_authority"))?,
            ReviewAuthorityId::new(authority_id)
                .map_err(|_| ReviewStoreError::Corrupt("approval_authority"))?,
        ),
        stored_request_digest,
        parse_revision(expected_revision)?,
        ReviewApprovalDecision::parse(&decision)?,
        expires_at_ms,
    )
    .map_err(|_| ReviewStoreError::Corrupt("approval_document"))?;
    let (decoded_kind, decoded_id) = workspace_parts(document.workspace());
    if decoded_kind != workspace_kind
        || decoded_id != workspace_id
        || digest(&approval_document) != stored_approval_digest
        || encode_approval(&document)? != approval_document
    {
        return Err(ReviewStoreError::Corrupt("approval_projection"));
    }
    Ok(Some(StoredReviewApproval {
        document,
        digest: stored_approval_digest,
    }))
}

fn validate_live_approval(action: &StoredReviewAction, now_ms: i64) -> Stored<()> {
    if !action.approval_required {
        return Ok(());
    }
    let approval = action
        .approval
        .as_ref()
        .ok_or(ReviewStoreError::ApprovalRequired)?;
    if approval.document.decision() != ReviewApprovalDecision::Approved
        || approval.document.expires_at_ms() <= now_ms
    {
        return Err(ReviewStoreError::ApprovalRequired);
    }
    Ok(())
}

fn read_action_by_key(
    connection: &Connection,
    kind: &str,
    id: &str,
    actor: &str,
    key: &str,
) -> Stored<Option<StoredReviewAction>> {
    let preview: Option<String> = connection.query_row(
        "SELECT preview_id FROM review_action_previews WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND idempotency_key=?4",
        params![kind, id, actor, key], |row| row.get(0)).optional()?;
    preview
        .map(|value| {
            read_action_by_preview(connection, &value)
                .and_then(|v| v.ok_or(ReviewStoreError::Corrupt("preview")))
        })
        .transpose()
}

fn insert_external_plan(
    transaction: &rusqlite::Transaction<'_>,
    preview_id: &str,
    plan: &ReviewExternalEffectPlan,
    created_at_ms: i64,
) -> Stored<()> {
    if let Some(github) = &plan.github_check {
        transaction.execute(
            "INSERT INTO review_github_check_effect_plans(preview_id,request_digest,registry_generation_digest,credential_generation_digest,credential_reference,repository_owner,repository_name,run_id,head_sha,observed_attempt,check_id,expected_check_revision,custody,plan_document,plan_digest,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'not_started',?13,?14,?15,?15)",
            params![
                preview_id,
                plan.request_digest.as_slice(),
                plan.registry_generation_digest.as_slice(),
                github.credential_generation_digest.as_slice(),
                github.credential_reference,
                github.repository_owner,
                github.repository_name,
                github.run_id.to_string(),
                github.head_sha,
                i64::from(github.observed_attempt),
                github.check_id.as_str(),
                db_revision(github.expected_check_revision)?,
                plan.document,
                plan.digest.as_slice(),
                created_at_ms,
            ],
        )?;
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO review_external_effect_plans(preview_id,request_digest,effect_kind,registry_generation_digest,provider,work_session_id,provider_session_id,work_session_revision,provider_session_revision,transport_key,payload,payload_digest,plan_document,plan_digest,created_at_ms) VALUES(?1,?2,'retained_session',?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            preview_id,
            plan.request_digest.as_slice(),
            plan.registry_generation_digest.as_slice(),
            plan.provider,
            plan.work_session_id,
            plan.provider_session_id,
            db_revision(plan.work_session_revision)?,
            db_revision(plan.provider_session_revision)?,
            plan.transport_key,
            plan.payload,
            plan.payload_digest.as_slice(),
            plan.document,
            plan.digest.as_slice(),
            created_at_ms,
        ],
    )?;
    Ok(())
}

fn external_action_targets(request: &ReviewActionRequest) -> Stored<Vec<(&str, Revision)>> {
    match request.action() {
        ReviewAction::SendCommentToAgent {
            comment_id,
            expected_comment_revision,
        } => Ok(vec![(comment_id.as_str(), *expected_comment_revision)]),
        ReviewAction::BatchSendCommentsToAgent { comments } => Ok(comments
            .iter()
            .map(|target| (target.comment_id().as_str(), target.expected_revision()))
            .collect()),
        _ => Err(ReviewStoreError::InvalidField("external_effect_action")),
    }
}

fn reserve_external_targets(
    transaction: &rusqlite::Transaction<'_>,
    preview_id: &str,
    request: &ReviewActionRequest,
) -> Stored<()> {
    let (kind, id) = workspace_parts(request.workspace());
    for (comment_id, comment_revision) in external_action_targets(request)? {
        let existing: Option<String> = transaction
            .query_row(
                "SELECT preview_id FROM review_external_effect_targets WHERE workspace_kind=?1 AND workspace_id=?2 AND comment_id=?3 AND comment_revision=?4",
                params![kind, id, comment_id, db_revision(comment_revision)?],
                |row| row.get(0),
            )
            .optional()?;
        if existing.as_deref().is_some_and(|value| value != preview_id) {
            return Err(ReviewStoreError::Conflict("external_effect_target"));
        }
        transaction.execute(
            "INSERT OR IGNORE INTO review_external_effect_targets(preview_id,workspace_kind,workspace_id,comment_id,comment_revision,disposition) VALUES(?1,?2,?3,?4,?5,'reserved')",
            params![preview_id, kind, id, comment_id, db_revision(comment_revision)?],
        )?;
    }
    Ok(())
}

fn require_exact_external_plan(
    connection: &Connection,
    preview_id: &str,
    expected: Option<&ReviewExternalEffectPlan>,
) -> Stored<()> {
    let stored = read_external_plan(connection, preview_id)?;
    match (stored.as_ref(), expected) {
        (None, None) => Ok(()),
        (Some(stored), Some(expected)) if stored == expected => Ok(()),
        (Some(stored), Some(expected))
            if stored.is_github_check_rerun()
                && expected.is_github_check_rerun()
                && stored.digest() == expected.digest() =>
        {
            Ok(())
        }
        _ => Err(ReviewStoreError::Conflict("external_effect_plan")),
    }
}

fn read_external_plan(
    connection: &Connection,
    preview_id: &str,
) -> Stored<Option<ReviewExternalEffectPlan>> {
    let (retained_exists, github_exists): (bool, bool) = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM review_external_effect_plans WHERE preview_id=?1),EXISTS(SELECT 1 FROM review_github_check_effect_plans WHERE preview_id=?1)",
        [preview_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if retained_exists && github_exists {
        return Err(ReviewStoreError::Corrupt("external_effect_plan"));
    }
    if github_exists {
        return read_github_check_plan(connection, preview_id);
    }
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        String,
        i64,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<Raw> = connection
        .query_row(
            "SELECT request_digest,registry_generation_digest,provider,work_session_id,provider_session_id,work_session_revision,provider_session_revision,transport_key,payload,payload_digest,plan_document,plan_digest FROM review_external_effect_plans WHERE preview_id=?1",
            [preview_id],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        request_digest,
        registry_generation_digest,
        provider,
        work_session_id,
        provider_session_id,
        work_session_revision,
        provider_session_revision,
        transport_key,
        payload,
        payload_digest,
        document,
        plan_digest,
    )) = raw
    else {
        return Ok(None);
    };
    let request_digest: [u8; 32] = request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_request_digest"))?;
    let registry_generation_digest: [u8; 32] = registry_generation_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_registry_digest"))?;
    let stored_payload_digest: [u8; 32] = payload_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_payload_digest"))?;
    let stored_plan_digest: [u8; 32] = plan_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_plan_digest"))?;
    let plan = ReviewExternalEffectPlan::retained_session(
        request_digest,
        registry_generation_digest,
        &provider,
        &work_session_id,
        &provider_session_id,
        parse_revision(work_session_revision)?,
        parse_revision(provider_session_revision)?,
        &transport_key,
        payload,
    )?;
    if plan.payload_digest != stored_payload_digest
        || plan.document != document
        || plan.digest != stored_plan_digest
    {
        return Err(ReviewStoreError::Corrupt("external_effect_plan"));
    }
    Ok(Some(plan))
}

fn read_github_check_plan(
    connection: &Connection,
    preview_id: &str,
) -> Stored<Option<ReviewExternalEffectPlan>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
    );
    let raw: Option<Raw> = connection.query_row(
        "SELECT request_digest,registry_generation_digest,credential_generation_digest,credential_reference,repository_owner,repository_name,run_id,head_sha,observed_attempt,check_id,expected_check_revision,custody,plan_document,plan_digest FROM review_github_check_effect_plans WHERE preview_id=?1",
        [preview_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?)),
    ).optional()?;
    let Some((
        request_digest,
        registry_digest,
        credential_digest,
        credential_reference,
        owner,
        repository,
        run_id,
        head_sha,
        observed_attempt,
        check_id,
        expected_revision,
        custody,
        document,
        stored_digest,
    )) = raw
    else {
        return Ok(None);
    };
    let request_digest: [u8; 32] = request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_request_digest"))?;
    let registry_digest: [u8; 32] = registry_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_registry_digest"))?;
    let credential_digest: [u8; 32] = credential_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_credential_digest"))?;
    let stored_digest: [u8; 32] = stored_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_plan_digest"))?;
    let run_id = run_id
        .parse::<u64>()
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_plan"))?;
    let observed_attempt = u32::try_from(observed_attempt)
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_plan"))?;
    let check_id = ReviewCheckId::new(check_id)
        .map_err(|_| ReviewStoreError::Corrupt("external_effect_plan"))?;
    let mut plan = ReviewExternalEffectPlan::github_check_rerun(
        request_digest,
        registry_digest,
        credential_digest,
        &credential_reference,
        &owner,
        &repository,
        run_id,
        &head_sha,
        observed_attempt,
        check_id,
        parse_revision(expected_revision)?,
    )?;
    if plan.document != document || plan.digest != stored_digest {
        return Err(ReviewStoreError::Corrupt("external_effect_plan"));
    }
    plan.github_check
        .as_mut()
        .ok_or(ReviewStoreError::Corrupt("external_effect_plan"))?
        .custody = ReviewExternalEffectCustody::parse(&custody)?;
    Ok(Some(plan))
}

fn read_action_by_preview_in_scope(
    connection: &Connection,
    preview_id: &str,
    workspace: &WorkContextIdentity,
    authority: &ReviewAuthority,
) -> Stored<Option<StoredReviewAction>> {
    let (kind, id) = workspace_parts(workspace);
    let in_scope: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM review_action_previews WHERE preview_id=?1 AND workspace_kind=?2 AND workspace_id=?3 AND authority_kind=?4 AND authority_id=?5)",
        params![
            preview_id,
            kind,
            id,
            authority.kind().as_str(),
            authority.id().as_str()
        ],
        |row| row.get(0),
    )?;
    if !in_scope {
        return Ok(None);
    }
    read_action_by_preview(connection, preview_id)
}

fn read_action_by_preview(
    connection: &Connection,
    preview_id: &str,
) -> Stored<Option<StoredReviewAction>> {
    struct RawAction {
        workspace_kind: String,
        workspace_id: String,
        expected_revision: i64,
        actor_id: String,
        authentication: String,
        authority_kind: String,
        authority_id: String,
        idempotency_key: String,
        action_kind: String,
        action_id: String,
        request_document: Vec<u8>,
        protocol_request_digest: Vec<u8>,
        preview_document: Vec<u8>,
        request_digest: Vec<u8>,
        approval_policy: String,
        approval_required: i64,
        write_admission_id: Option<String>,
        write_admitted_at_ms: Option<i64>,
        write_admission_document: Option<Vec<u8>>,
        write_admission_digest: Option<Vec<u8>>,
        receipt_id: String,
        receipt_document: Vec<u8>,
        receipt_digest: Vec<u8>,
        receipt_request_digest: Vec<u8>,
        receipt_approval_digest: Option<Vec<u8>>,
        receipt_outcome: String,
        receipt_result_revision: Option<i64>,
        receipt_current_revision: Option<i64>,
    }
    let raw: Option<RawAction> = connection
        .query_row(
            "SELECT p.workspace_kind,p.workspace_id,p.expected_revision,p.actor_id,p.authentication,p.authority_kind,p.authority_id,p.idempotency_key,p.action_kind,p.action_id,p.request_document,p.protocol_request_digest,p.preview_document,p.request_digest,p.approval_policy,p.approval_required,p.write_admission_id,p.write_admitted_at_ms,p.write_admission_document,p.write_admission_digest,r.receipt_id,r.receipt_document,r.receipt_digest,r.request_digest,r.approval_digest,r.outcome,r.result_revision,r.current_revision FROM review_action_previews p JOIN review_action_receipts r USING(preview_id) WHERE p.preview_id=?1",
            [preview_id],
            |row| {
                Ok(RawAction {
                    workspace_kind: row.get(0)?,
                    workspace_id: row.get(1)?,
                    expected_revision: row.get(2)?,
                    actor_id: row.get(3)?,
                    authentication: row.get(4)?,
                    authority_kind: row.get(5)?,
                    authority_id: row.get(6)?,
                    idempotency_key: row.get(7)?,
                    action_kind: row.get(8)?,
                    action_id: row.get(9)?,
                    request_document: row.get(10)?,
                    protocol_request_digest: row.get(11)?,
                    preview_document: row.get(12)?,
                    request_digest: row.get(13)?,
                    approval_policy: row.get(14)?,
                    approval_required: row.get(15)?,
                    write_admission_id: row.get(16)?,
                    write_admitted_at_ms: row.get(17)?,
                    write_admission_document: row.get(18)?,
                    write_admission_digest: row.get(19)?,
                    receipt_id: row.get(20)?,
                    receipt_document: row.get(21)?,
                    receipt_digest: row.get(22)?,
                    receipt_request_digest: row.get(23)?,
                    receipt_approval_digest: row.get(24)?,
                    receipt_outcome: row.get(25)?,
                    receipt_result_revision: row.get(26)?,
                    receipt_current_revision: row.get(27)?,
                })
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let request_digest: [u8; 32] = raw
        .request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("request_digest"))?;
    let protocol_request_digest: [u8; 32] = raw
        .protocol_request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("protocol_request_digest"))?;
    let receipt_request_digest: [u8; 32] = raw
        .receipt_request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("receipt_request_digest"))?;
    let request = decode_review_action_request(&raw.request_document)
        .map_err(|_| ReviewStoreError::Corrupt("request"))?;
    let (request_kind, request_workspace_id) = workspace_parts(request.workspace());
    let approval_policy = ApprovalPolicy::parse(&raw.approval_policy)?;
    if digest(&raw.request_document) != protocol_request_digest
        || encode_preview_document(&protocol_request_digest, approval_policy)
            != raw.preview_document
        || digest(&raw.preview_document) != request_digest
        || receipt_request_digest != request_digest
        || request_kind != raw.workspace_kind
        || request_workspace_id != raw.workspace_id
        || db_revision(request.expected_revision())? != raw.expected_revision
        || request.actor().as_str() != raw.actor_id
        || request.authentication().as_str() != raw.authentication
        || request.authority().kind().as_str() != raw.authority_kind
        || request.authority().id().as_str() != raw.authority_id
        || request.idempotency_key().as_str() != raw.idempotency_key
        || request.action().kind().as_str() != raw.action_kind
    {
        return Err(ReviewStoreError::Corrupt("request_digest"));
    }
    if (approval_policy == ApprovalPolicy::Required) != (raw.approval_required != 0) {
        return Err(ReviewStoreError::Corrupt("approval_requirement"));
    }
    let receipt_digest: [u8; 32] = raw
        .receipt_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("receipt_digest"))?;
    let receipt = decode_review_action_receipt(&raw.receipt_document)
        .map_err(|_| ReviewStoreError::Corrupt("receipt"))?;
    if digest(&raw.receipt_document) != receipt_digest {
        return Err(ReviewStoreError::Corrupt("receipt_digest"));
    }
    if receipt.receipt_id().as_str() != raw.receipt_id
        || receipt.action_id().as_str() != raw.action_id
        || receipt.idempotency_key() != request.idempotency_key()
        || receipt.actor() != request.actor()
        || receipt.outcome().as_str() != raw.receipt_outcome
        || receipt.revision().map(db_revision).transpose()? != raw.receipt_result_revision
        || receipt.current_revision().map(db_revision).transpose()? != raw.receipt_current_revision
    {
        return Err(ReviewStoreError::Corrupt("receipt_projection"));
    }
    let approval = read_approval(connection, preview_id)?;
    let receipt_approval_digest = raw
        .receipt_approval_digest
        .map(|value| {
            value
                .try_into()
                .map_err(|_| ReviewStoreError::Corrupt("receipt_approval_digest"))
        })
        .transpose()?;
    if approval.as_ref().map(|value| value.digest) != receipt_approval_digest {
        return Err(ReviewStoreError::Corrupt("receipt_approval_binding"));
    }
    if let Some(value) = &approval {
        if value.document.preview_id() != preview_id
            || value.document.workspace() != request.workspace()
            || value.document.request_digest() != request_digest
            || value.document.expected_revision() != request.expected_revision()
            || value.document.authority() != request.authority()
        {
            return Err(ReviewStoreError::Corrupt("approval_binding"));
        }
        if value.document.decision() == ReviewApprovalDecision::Refused
            && receipt.outcome() != ReviewReceiptOutcome::Refused
        {
            return Err(ReviewStoreError::Corrupt("approval_receipt"));
        }
    }
    if raw.approval_required == 0 && approval.is_some() {
        return Err(ReviewStoreError::Corrupt("approval_requirement"));
    }
    let approved = approval
        .as_ref()
        .is_some_and(|value| value.document.decision() == ReviewApprovalDecision::Approved);
    let external_plan = read_external_plan(connection, preview_id)?;
    let external_effect_plan_digest = external_plan.as_ref().map(ReviewExternalEffectPlan::digest);
    let migration_tombstone: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM review_external_effect_migration_tombstones WHERE preview_id=?1)",
        [preview_id],
        |row| row.get(0),
    )?;
    let admission_fields = [
        raw.write_admission_id.is_some(),
        raw.write_admitted_at_ms.is_some(),
        raw.write_admission_document.is_some(),
        raw.write_admission_digest.is_some(),
    ];
    if admission_fields.iter().any(|value| *value) && !admission_fields.iter().all(|value| *value) {
        return Err(ReviewStoreError::Corrupt("write_admission"));
    }
    if matches!(
        receipt.outcome(),
        ReviewReceiptOutcome::Completed | ReviewReceiptOutcome::Unknown
    ) && !admission_fields.iter().all(|value| *value)
    {
        return Err(ReviewStoreError::Corrupt("write_admission"));
    }
    if let (Some(admission_id), Some(admitted_at), Some(document), Some(raw_digest)) = (
        raw.write_admission_id.as_deref(),
        raw.write_admitted_at_ms,
        raw.write_admission_document.as_deref(),
        raw.write_admission_digest.as_deref(),
    ) {
        let stored_digest: [u8; 32] = raw_digest
            .try_into()
            .map_err(|_| ReviewStoreError::Corrupt("write_admission"))?;
        let partial = StoredReviewAction {
            preview_id: preview_id.to_owned(),
            request_digest,
            request: request.clone(),
            receipt: receipt.clone(),
            approval_required: raw.approval_required != 0,
            approval_policy,
            approved,
            approval: approval.clone(),
            external_effect_plan_digest,
            write_admission_id: None,
            write_admitted_at_ms: None,
        };
        let expected = encode_write_admission(
            &partial,
            approval.as_ref().map(|value| &value.digest),
            admitted_at,
            admission_id,
        )?;
        if digest(document) != stored_digest
            || (migration_tombstone
                && automonique_protocol::wire::parse_canonical(document).is_err())
            || (!migration_tombstone && document != expected)
        {
            return Err(ReviewStoreError::Corrupt("write_admission"));
        }
    }
    let action = StoredReviewAction {
        preview_id: preview_id.to_owned(),
        request_digest,
        request,
        receipt,
        approval_required: raw.approval_required != 0,
        approval_policy,
        approved,
        approval,
        external_effect_plan_digest,
        write_admission_id: raw.write_admission_id,
        write_admitted_at_ms: raw.write_admitted_at_ms,
    };
    validate_external_effect_custody(connection, &action, external_plan.as_ref())?;
    validate_completed_basis(connection, &action)?;
    Ok(Some(action))
}
fn update_receipt(
    connection: &Connection,
    preview_id: &str,
    receipt: &ReviewActionReceipt,
    now_ms: i64,
) -> Stored<()> {
    let document = encode_review_action_receipt(receipt).map_err(protocol)?;
    let receipt_digest = digest(&document);
    connection.execute("UPDATE review_action_receipts SET receipt_document=?1,receipt_digest=?2,outcome=?3,result_revision=?4,current_revision=?5,updated_at_ms=?6 WHERE preview_id=?7", params![document, receipt_digest.as_slice(), receipt.outcome().as_str(), receipt.revision().map(db_revision).transpose()?, receipt.current_revision().map(db_revision).transpose()?, now_ms, preview_id])?;
    Ok(())
}
