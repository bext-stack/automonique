// SPDX-License-Identifier: Elastic-2.0

//! Authoritative SQLite custody for Platform v2 review state.
//!
//! This store persists only strict, canonical protocol documents. It owns the
//! transaction that binds a mutation preview to its actor, workspace, exact
//! revision, authority, request digest, idempotency key, approval and receipt.
//! It deliberately has no git, shell, CI, provider or pull-request adapter.
//! Provider observations use a separate table and can never create a local
//! authority grant.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform::{IdempotencyKey, ReceiptId};
use automonique_protocol::platform_v2::WorkContextIdentity;
use automonique_protocol::platform_v2_review::{
    ReviewActionId, ReviewActionReceipt, ReviewActionRequest, ReviewActorId, ReviewAuthentication,
    ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind, ReviewComment, ReviewCommentId,
    ReviewField, ReviewReceiptOutcome, ReviewReconciliation, ReviewSnapshot, ReviewText,
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

pub const REVIEW_STORE_SCHEMA_VERSION: u32 = 1;
const MAX_PROVIDER_OBSERVATION_BYTES: usize = 4096;

const SCHEMA_V1: &str = r#"
CREATE TABLE review_current (
    workspace_kind TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (workspace_kind, workspace_id)
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
    granted_at_ms INTEGER NOT NULL CHECK (granted_at_ms >= 0),
    PRIMARY KEY (workspace_kind, workspace_id, actor_id, authentication, authority_kind, authority_id)
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
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    approval_required INTEGER NOT NULL CHECK (approval_required IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE (workspace_kind, workspace_id, actor_id, idempotency_key)
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
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    approval_digest BLOB CHECK (approval_digest IS NULL OR length(approval_digest) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'completed', 'refused', 'conflict', 'unknown')),
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
pub struct StoredReviewAction {
    pub preview_id: String,
    pub request_digest: [u8; 32],
    pub request: ReviewActionRequest,
    pub receipt: ReviewActionReceipt,
    pub approval_required: bool,
    pub approved: bool,
    pub approval: Option<StoredReviewApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReviewComment {
    pub workspace: WorkContextIdentity,
    pub snapshot_revision: Revision,
    pub comment: ReviewComment,
}

#[derive(Debug)]
pub struct ReviewStore {
    connection: Connection,
    path: PathBuf,
}

impl ReviewStore {
    pub fn open(path: impl AsRef<Path>) -> Stored<Self> {
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
        initialize(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a revalidated sanitized snapshot and its normalized comments.
    pub fn put_snapshot(&mut self, snapshot: &ReviewSnapshot, recorded_at_ms: i64) -> Stored<()> {
        validate_time(recorded_at_ms)?;
        let document = encode_review_snapshot(snapshot).map_err(protocol)?;
        // This second pass pins the invariant that storage never accepts a value
        // its wire decoder would later refuse.
        decode_review_snapshot(&document).map_err(protocol)?;
        let document_digest = digest(&document);
        let (kind, workspace_id) = workspace_parts(snapshot.workspace());
        let revision = db_revision(snapshot.revision())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM review_current WHERE workspace_kind=?1 AND workspace_id=?2",
                params![kind, workspace_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(current) = current {
            if current == revision {
                let existing: (Vec<u8>, Vec<u8>) = transaction.query_row(
                    "SELECT document,document_digest FROM review_snapshots WHERE workspace_kind=?1 AND workspace_id=?2 AND revision=?3",
                    params![kind, workspace_id, revision], |row| Ok((row.get(0)?, row.get(1)?)))?;
                if digest(&existing.0).as_slice() != existing.1
                    || existing.1.as_slice() != document_digest
                {
                    return Err(ReviewStoreError::Conflict("snapshot_revision"));
                }
                transaction.commit()?;
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
        }
        transaction.execute(
            "INSERT INTO review_snapshots(workspace_kind,workspace_id,revision,document,document_digest,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
            params![kind, workspace_id, revision, document, document_digest.as_slice(), recorded_at_ms])?;
        for comment in snapshot.comments() {
            transaction.execute(
                "INSERT INTO review_comments(workspace_kind,workspace_id,snapshot_revision,comment_id,comment_revision,actor_id,body,file_id,hunk_id,side,line,agent_state,unread) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![kind, workspace_id, revision, comment.id().as_str(), db_revision(comment.revision())?, comment.actor().as_str(), comment.body().as_str(), comment.anchor().file_id().as_str(), comment.anchor().hunk_id().as_str(), comment.anchor().side().as_str(), i64::from(comment.anchor().line()), comment.agent_state().as_str(), i64::from(comment.unread())])?;
        }
        transaction.execute(
            "INSERT INTO review_current(workspace_kind,workspace_id,revision) VALUES(?1,?2,?3) ON CONFLICT(workspace_kind,workspace_id) DO UPDATE SET revision=excluded.revision",
            params![kind, workspace_id, revision])?;
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
        validate_time(granted_at_ms)?;
        if authentication == ReviewAuthentication::ProviderSession {
            return Err(ReviewStoreError::Unauthorized);
        }
        let (kind, id) = workspace_parts(workspace);
        self.connection.execute(
            "INSERT OR IGNORE INTO review_authority_grants(workspace_kind,workspace_id,actor_id,authentication,authority_kind,authority_id,granted_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![kind, id, actor.as_str(), authentication.as_str(), authority.kind().as_str(), authority.id().as_str(), granted_at_ms])?;
        Ok(())
    }

    pub fn prepare_action(
        &mut self,
        request: &ReviewActionRequest,
        approval: ApprovalPolicy,
        created_at_ms: i64,
    ) -> Stored<ReviewActionAdmission> {
        validate_time(created_at_ms)?;
        let document = encode_review_action_request(request).map_err(protocol)?;
        decode_review_action_request(&document).map_err(protocol)?;
        let request_digest = digest(&document);
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
            if existing.request_digest != request_digest {
                return Err(ReviewStoreError::Conflict("idempotency_key"));
            }
            transaction.commit()?;
            return Ok(ReviewActionAdmission::Replay(existing));
        }
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_authority_grants WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND authentication=?4 AND authority_kind=?5 AND authority_id=?6)",
            params![kind, id, request.actor().as_str(), request.authentication().as_str(), request.authority().kind().as_str(), request.authority().id().as_str()], |row| row.get(0))?;
        if !authorized {
            return Err(ReviewStoreError::Unauthorized);
        }
        // Authorization is decided before revealing whether the workspace or
        // revision exists, so an ungranted actor cannot use stale refusals as
        // a revision oracle.
        let current: i64 = transaction
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
        let snapshot = read_current_snapshot(&transaction, kind, id)?
            .ok_or(ReviewStoreError::Corrupt("current_snapshot"))?;
        snapshot.resolve_action(request).map_err(protocol)?;
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
        transaction.execute(
            "INSERT INTO review_action_previews(preview_id,workspace_kind,workspace_id,expected_revision,actor_id,authentication,authority_kind,authority_id,idempotency_key,action_kind,action_id,request_document,request_digest,approval_required,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![preview_id, kind, id, db_revision(request.expected_revision())?, request.actor().as_str(), request.authentication().as_str(), request.authority().kind().as_str(), request.authority().id().as_str(), request.idempotency_key().as_str(), request.action().kind().as_str(), action_id.as_str(), document, request_digest.as_slice(), i64::from(approval == ApprovalPolicy::Required), created_at_ms])?;
        transaction.execute(
            "INSERT INTO review_action_receipts(receipt_id,preview_id,receipt_document,request_digest,approval_digest,outcome,updated_at_ms) VALUES(?1,?2,?3,?4,NULL,?5,?6)",
            params![receipt.receipt_id().as_str(), preview_id, receipt_document, request_digest.as_slice(), receipt.outcome().as_str(), created_at_ms])?;
        let stored = read_action_by_preview(&transaction, &preview_id)?
            .ok_or(ReviewStoreError::Corrupt("preview"))?;
        transaction.commit()?;
        Ok(ReviewActionAdmission::New(stored))
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
        let action = read_action_by_preview(&transaction, approval.preview_id())?
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
        let authorized: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM review_authority_grants WHERE workspace_kind=?1 AND workspace_id=?2 AND actor_id=?3 AND authentication=?4 AND authority_kind=?5 AND authority_id=?6)",
            params![kind, id, approval.approving_actor().as_str(), approval.authentication().as_str(), approval.authority().kind().as_str(), approval.authority().id().as_str()],
            |row| row.get(0),
        )?;
        if !authorized {
            return Err(ReviewStoreError::Unauthorized);
        }
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
            update_receipt(&transaction, approval.preview_id(), &refused, decided_at_ms)?;
        }
        let result = read_action_by_preview(&transaction, approval.preview_id())?
            .ok_or(ReviewStoreError::Corrupt("preview"))?;
        transaction.commit()?;
        Ok(result)
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
        if action.approval_required && !action.approved {
            return Err(ReviewStoreError::ApprovalRequired);
        }
        validate_live_approval(&action, now_ms)?;
        if action.receipt.outcome() != ReviewReceiptOutcome::Accepted {
            transaction.commit()?;
            return Ok(action.receipt);
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
        if action.approval_required && !action.approved {
            return Err(ReviewStoreError::ApprovalRequired);
        }
        validate_live_approval(&action, now_ms)?;
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
            if receipt.revision() != Some(expected_result)
                || current < action.request.expected_revision()
                || current > expected_result
            {
                return Err(ReviewStoreError::Conflict("result_revision"));
            }
        }
        if receipt.outcome() == ReviewReceiptOutcome::Conflict
            && receipt.current_revision() != Some(current)
        {
            return Err(ReviewStoreError::Conflict("current_revision"));
        }
        if action.receipt.outcome() != ReviewReceiptOutcome::Accepted
            && action.receipt.outcome() != ReviewReceiptOutcome::Unknown
        {
            if action.receipt == *receipt {
                transaction.commit()?;
                return Ok(action.receipt);
            }
            return Err(ReviewStoreError::Conflict("terminal_receipt"));
        }
        update_receipt(&transaction, preview_id, receipt, now_ms)?;
        transaction.commit()?;
        Ok(receipt.clone())
    }

    pub fn receipt(
        &self,
        workspace: &WorkContextIdentity,
        actor: &ReviewActorId,
        key: &IdempotencyKey,
    ) -> Stored<Option<ReviewActionReceipt>> {
        let (kind, id) = workspace_parts(workspace);
        read_action_by_key(&self.connection, kind, id, actor.as_str(), key.as_str())
            .map(|value| value.map(|action| action.receipt))
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

fn initialize(connection: &mut Connection) -> Stored<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == REVIEW_STORE_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(ReviewStoreError::SchemaVersion {
            found: version,
            supported: REVIEW_STORE_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", REVIEW_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
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
    type RawSnapshot = (Vec<u8>, Vec<u8>, String, String, i64);
    let raw: Option<RawSnapshot> = connection
        .query_row(
            "SELECT document,document_digest,workspace_kind,workspace_id,revision FROM review_snapshots WHERE workspace_kind=?1 AND workspace_id=?2 AND revision=?3",
            params![kind, id, current_revision],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((document, raw_digest, stored_kind, stored_id, stored_revision)) = raw else {
        return Err(ReviewStoreError::Corrupt("current_snapshot"));
    };
    let document_digest: [u8; 32] = raw_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("snapshot_digest"))?;
    if digest(&document) != document_digest || stored_revision != current_revision {
        return Err(ReviewStoreError::Corrupt("snapshot_digest"));
    }
    let snapshot =
        decode_review_snapshot(&document).map_err(|_| ReviewStoreError::Corrupt("snapshot"))?;
    let (decoded_kind, decoded_id) = workspace_parts(snapshot.workspace());
    if stored_kind != kind
        || stored_id != id
        || decoded_kind != stored_kind
        || decoded_id != stored_id
        || db_revision(snapshot.revision())? != stored_revision
    {
        return Err(ReviewStoreError::Corrupt("snapshot_projection"));
    }
    Ok(Some(snapshot))
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
    );
    let raw: Option<RawApproval> = connection
        .query_row(
            "SELECT a.workspace_kind,a.workspace_id,a.request_digest,a.expected_revision,a.approving_actor_id,a.authentication,a.authority_kind,a.authority_id,a.decision,a.expires_at_ms,a.approval_document,a.approval_digest,p.request_document FROM review_action_approvals a JOIN review_action_previews p USING(preview_id) WHERE a.preview_id=?1",
            [preview_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?)),
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
    if digest(&request_document) != stored_request_digest {
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
        request_digest: Vec<u8>,
        approval_required: i64,
        receipt_id: String,
        receipt_document: Vec<u8>,
        receipt_request_digest: Vec<u8>,
        receipt_approval_digest: Option<Vec<u8>>,
        receipt_outcome: String,
    }
    let raw: Option<RawAction> = connection
        .query_row(
            "SELECT p.workspace_kind,p.workspace_id,p.expected_revision,p.actor_id,p.authentication,p.authority_kind,p.authority_id,p.idempotency_key,p.action_kind,p.action_id,p.request_document,p.request_digest,p.approval_required,r.receipt_id,r.receipt_document,r.request_digest,r.approval_digest,r.outcome FROM review_action_previews p JOIN review_action_receipts r USING(preview_id) WHERE p.preview_id=?1",
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
                    request_digest: row.get(11)?,
                    approval_required: row.get(12)?,
                    receipt_id: row.get(13)?,
                    receipt_document: row.get(14)?,
                    receipt_request_digest: row.get(15)?,
                    receipt_approval_digest: row.get(16)?,
                    receipt_outcome: row.get(17)?,
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
    let receipt_request_digest: [u8; 32] = raw
        .receipt_request_digest
        .try_into()
        .map_err(|_| ReviewStoreError::Corrupt("receipt_request_digest"))?;
    let request = decode_review_action_request(&raw.request_document)
        .map_err(|_| ReviewStoreError::Corrupt("request"))?;
    let (request_kind, request_workspace_id) = workspace_parts(request.workspace());
    if digest(&raw.request_document) != request_digest
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
    let receipt = decode_review_action_receipt(&raw.receipt_document)
        .map_err(|_| ReviewStoreError::Corrupt("receipt"))?;
    if receipt.receipt_id().as_str() != raw.receipt_id
        || receipt.action_id().as_str() != raw.action_id
        || receipt.idempotency_key() != request.idempotency_key()
        || receipt.actor() != request.actor()
        || receipt.outcome().as_str() != raw.receipt_outcome
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
    Ok(Some(StoredReviewAction {
        preview_id: preview_id.to_owned(),
        request_digest,
        request,
        receipt,
        approval_required: raw.approval_required != 0,
        approved,
        approval,
    }))
}
fn update_receipt(
    connection: &Connection,
    preview_id: &str,
    receipt: &ReviewActionReceipt,
    now_ms: i64,
) -> Stored<()> {
    let document = encode_review_action_receipt(receipt).map_err(protocol)?;
    connection.execute("UPDATE review_action_receipts SET receipt_document=?1,outcome=?2,updated_at_ms=?3 WHERE preview_id=?4", params![document, receipt.outcome().as_str(), now_ms, preview_id])?;
    Ok(())
}
