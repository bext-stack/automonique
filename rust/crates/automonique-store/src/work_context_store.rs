// SPDX-License-Identifier: Elastic-2.0

//! Authoritative SQLite state for Platform v2 work-context lifecycle.
//!
//! The store accepts only checked protocol values. Authentication and policy
//! evaluation happen outside this crate, but their exact actor, serving
//! authority, inherited ceiling, and approval decision are rechecked inside
//! the same immediate transaction that reserves or mutates durable state.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{ReceiptId, ReceiptOutcome, ResourceAuthority};
use automonique_protocol::platform_v2::{
    AuthorizedWorkContextRecord, ProjectId, WorkContextIdentity, WorkContextKind,
    WorkContextLifecycle, WorkContextPage, WorkContextQuery, WorkContextQueryResult,
    WorkContextRecord, WorkContextTargetKind, page_authorized_work_context,
};
use automonique_protocol::platform_v2_api::{decode_work_context_page, encode_work_context_page};
use automonique_protocol::platform_v2_lifecycle::{
    ExpectedWorkContext, ExternalParentResolution, MutationApproval, MutationApprovalDecision,
    MutationApprovalId, MutationApprovalRequirement, MutationPreview, MutationPreviewId,
    MutationPreviewRef, MutationReceipt, MutationSubmission, ResolvedParentSnapshot,
    WorkContextAuthority, WorkContextMutationIntent, WorkContextMutationProposal,
    WorkContextRegistrySelector,
};
use automonique_protocol::platform_v2_lifecycle_api::{
    decode_work_context_mutation_approval, decode_work_context_mutation_preview,
    decode_work_context_mutation_receipt, decode_work_context_mutation_submission,
    encode_work_context_mutation_approval, encode_work_context_mutation_preview,
    encode_work_context_mutation_proposal, encode_work_context_mutation_receipt,
    encode_work_context_mutation_submission, work_context_mutation_preview_digest,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest as _, Sha256};

use crate::{StoreError, validate_database_path};

pub const WORK_CONTEXT_STORE_SCHEMA_VERSION: u32 = 2;

const SCHEMA_V2: &str = r#"
CREATE TABLE work_context_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    inventory_generation INTEGER NOT NULL CHECK(inventory_generation>=1)
) STRICT;
INSERT INTO work_context_meta(singleton,inventory_generation) VALUES(1,1);

CREATE TABLE work_context_records (
    tenant TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    identity_kind TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    resource_authority TEXT,
    resource_kind TEXT,
    revision INTEGER NOT NULL CHECK(revision>=1),
    lifecycle TEXT NOT NULL,
    record_document BLOB NOT NULL,
    PRIMARY KEY(tenant,identity_key)
) STRICT;
CREATE TABLE work_context_relations (
    tenant TEXT NOT NULL,
    source_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    relation_kind TEXT NOT NULL,
    target_key TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_authority TEXT,
    target_resource_kind TEXT,
    PRIMARY KEY(tenant,source_key,ordinal),
    UNIQUE(tenant,source_key,relation_kind,target_key),
    FOREIGN KEY(tenant,source_key) REFERENCES work_context_records(tenant,identity_key) ON DELETE CASCADE
) STRICT;
CREATE INDEX work_context_relations_target ON work_context_relations(tenant,target_key,source_key);

CREATE TABLE work_context_expected_revisions (
    tenant TEXT NOT NULL,
    identity_key TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=1),
    owning_project_id TEXT,
    external_resolution TEXT CHECK(external_resolution IS NULL OR external_resolution IN ('available','unavailable')),
    PRIMARY KEY(tenant,identity_key)
) STRICT;

CREATE TABLE work_context_selector_bindings (
    tenant TEXT NOT NULL,
    selector TEXT NOT NULL,
    private_binding BLOB NOT NULL,
    PRIMARY KEY(tenant,selector)
) STRICT;

CREATE TABLE work_context_previews (
    preview_id TEXT PRIMARY KEY,
    preview_revision INTEGER NOT NULL CHECK(preview_revision>=1),
    tenant TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    serving_authority TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    proposal_document BLOB NOT NULL,
    preview_document BLOB NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    submitted_at_ms INTEGER,
    UNIQUE(tenant,actor_id,serving_authority,idempotency_key)
) STRICT;

CREATE TABLE work_context_approvals (
    approval_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL REFERENCES work_context_previews(preview_id),
    approval_document BLOB NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    consumed_at_ms INTEGER
) STRICT;

CREATE TABLE work_context_receipts (
    receipt_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE REFERENCES work_context_previews(preview_id),
    submission_document BLOB NOT NULL,
    receipt_document BLOB NOT NULL,
    outcome TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE work_context_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    preview_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    event_document BLOB NOT NULL,
    recorded_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE work_context_outbox (
    outbox_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE REFERENCES work_context_previews(preview_id),
    effect_kind TEXT NOT NULL,
    effect_document BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('ready','completed')),
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER
) STRICT;

CREATE TABLE work_context_effect_reservations (
    tenant TEXT NOT NULL,
    target_key TEXT NOT NULL,
    target_revision INTEGER NOT NULL CHECK(target_revision>=1),
    effect_kind TEXT NOT NULL,
    preview_id TEXT NOT NULL UNIQUE REFERENCES work_context_previews(preview_id),
    PRIMARY KEY(tenant,target_key,target_revision,effect_kind)
) STRICT;

CREATE TABLE work_context_effect_leases (
    lease_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL UNIQUE REFERENCES work_context_previews(preview_id),
    tenant TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    serving_authority TEXT NOT NULL,
    target_key TEXT NOT NULL,
    target_revision INTEGER NOT NULL CHECK(target_revision>=1),
    effect_kind TEXT NOT NULL,
    effect_digest TEXT NOT NULL CHECK(length(effect_digest)=64 AND effect_digest NOT GLOB '*[^0-9a-f]*'),
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('claimed','completed'))
) STRICT;

CREATE TABLE work_context_cursor_state (
    tenant TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    cursor TEXT NOT NULL,
    inventory_generation INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY(tenant,actor_id,cursor)
) STRICT;
"#;

#[derive(Debug)]
pub enum WorkContextStoreError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    Unauthorized,
    AuthorityWidening,
    StaleRevision,
    GraphConflict,
    BodyConflict,
    ApprovalRequired,
    ApprovalMismatch,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalConsumed,
    PreviewExpired,
    Unavailable,
    NotFound,
    Corrupt(&'static str),
    Protocol(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl WorkContextStoreError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::AuthorityWidening => "authority_widening",
            Self::StaleRevision => "stale_revision",
            Self::GraphConflict | Self::BodyConflict => "conflict",
            Self::ApprovalRequired => "approval_required",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalConsumed => "approval_consumed",
            Self::PreviewExpired => "preview_expired",
            Self::Unavailable => "unavailable",
            Self::NotFound => "not_found",
            Self::Corrupt(_) => "corrupt",
            Self::Protocol(_) => "protocol",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}
impl fmt::Display for WorkContextStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "work-context store refused: {}", self.category())
    }
}
impl Error for WorkContextStoreError {}
impl From<std::io::Error> for WorkContextStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for WorkContextStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

type Stored<T> = Result<T, WorkContextStoreError>;

pub trait WorkContextNonceSource {
    fn nonce(&mut self) -> [u8; 16];
}

#[derive(Clone, Debug)]
pub struct MutationPolicyDecision {
    authenticated_actor: Actor,
    serving_authority: ResourceAuthority,
    actor_authority: WorkContextAuthority,
    inherited_authority: WorkContextAuthority,
    authorized_project: Option<ProjectId>,
    authorized_targets: BTreeSet<WorkContextIdentity>,
    approval: MutationApprovalRequirement,
}
impl MutationPolicyDecision {
    #[must_use]
    pub fn new(
        authenticated_actor: Actor,
        serving_authority: ResourceAuthority,
        actor_authority: WorkContextAuthority,
        inherited_authority: WorkContextAuthority,
        authorized_project: Option<ProjectId>,
        authorized_targets: BTreeSet<WorkContextIdentity>,
        approval: MutationApprovalRequirement,
    ) -> Self {
        Self {
            authenticated_actor,
            serving_authority,
            actor_authority,
            inherited_authority,
            authorized_project,
            authorized_targets,
            approval,
        }
    }
}

/// A transaction-rechecked authorization result for a human approval.
#[derive(Clone, Debug)]
pub struct ApprovalPolicyDecision {
    authenticated_approver: Actor,
    serving_authority: ResourceAuthority,
    approval_authority: WorkContextApprovalAuthority,
    preview: MutationPreviewRef,
    preview_digest: automonique_protocol::platform_v2_lifecycle::MutationPreviewDigest,
    expires_at: EpochMillis,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkContextApprovalAuthority {
    LifecycleMutation,
}
impl ApprovalPolicyDecision {
    #[must_use]
    pub const fn new(
        authenticated_approver: Actor,
        serving_authority: ResourceAuthority,
        approval_authority: WorkContextApprovalAuthority,
        preview: MutationPreviewRef,
        preview_digest: automonique_protocol::platform_v2_lifecycle::MutationPreviewDigest,
        expires_at: EpochMillis,
    ) -> Self {
        Self {
            authenticated_approver,
            serving_authority,
            approval_authority,
            preview,
            preview_digest,
            expires_at,
        }
    }
}

/// A checked executor authorization used to atomically claim an effect.
#[derive(Clone, Debug)]
pub struct ExternalEffectExecutorPolicy {
    executor: Actor,
    serving_authority: ResourceAuthority,
    allowed_effect_kinds: BTreeSet<String>,
}
impl ExternalEffectExecutorPolicy {
    #[must_use]
    pub fn new(
        executor: Actor,
        serving_authority: ResourceAuthority,
        allowed_effect_kinds: BTreeSet<String>,
    ) -> Self {
        Self {
            executor,
            serving_authority,
            allowed_effect_kinds,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalEffectLeaseId(String);
impl ExternalEffectLeaseId {
    fn issue(nonce: [u8; 16]) -> Self {
        Self(format!("effect_lease_{}", hex(&nonce)))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A durable worker lease bound to one exact external effect.
#[derive(Clone, Debug)]
pub struct ExternalEffectCompletionPolicy {
    lease_id: ExternalEffectLeaseId,
    executor: Actor,
    serving_authority: ResourceAuthority,
    preview: MutationPreviewRef,
    target: ExpectedWorkContext,
    effect_kind: String,
    effect_document: Vec<u8>,
    expires_at: EpochMillis,
}
impl ExternalEffectCompletionPolicy {
    #[must_use]
    pub const fn lease_id(&self) -> &ExternalEffectLeaseId {
        &self.lease_id
    }
    #[must_use]
    pub const fn preview(&self) -> &MutationPreviewRef {
        &self.preview
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviewAdmission {
    New(MutationPreview),
    Replay(MutationPreview),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptAdmission {
    New(MutationReceipt),
    Replay(MutationReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptLookup {
    Found(MutationReceipt),
    Unknown,
}

#[derive(Debug)]
pub struct WorkContextStore {
    connection: Connection,
    path: PathBuf,
}

impl WorkContextStore {
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

    pub fn bind_private_selector(
        &mut self,
        tenant: &str,
        selector: &WorkContextRegistrySelector,
        private_binding: &[u8],
    ) -> Stored<()> {
        if tenant.is_empty() || private_binding.is_empty() || private_binding.len() > 16 * 1024 {
            return Err(WorkContextStoreError::InvalidField("selector_binding"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO work_context_selector_bindings(tenant,selector,private_binding) VALUES(?1,?2,?3) ON CONFLICT(tenant,selector) DO UPDATE SET private_binding=excluded.private_binding", params![tenant,selector.as_str(),private_binding])?;
        tx.commit()?;
        Ok(())
    }

    pub fn put_authoritative_record(
        &mut self,
        tenant: &str,
        record: &WorkContextRecord,
    ) -> Stored<()> {
        validate_tenant(tenant)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        store_record(&tx, tenant, record)?;
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn put_external_snapshot(
        &mut self,
        tenant: &str,
        expected: &ExpectedWorkContext,
        resolution: ExternalParentResolution,
        owning_project: Option<&ProjectId>,
    ) -> Stored<()> {
        validate_tenant(tenant)?;
        if expected.identity().kind() != WorkContextTargetKind::Repository {
            return Err(WorkContextStoreError::InvalidField("external_identity"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let key = identity_key(expected.identity());
        let prior: Option<(i64, Option<String>, Option<String>)> = tx.query_row(
            "SELECT revision,owning_project_id,external_resolution FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
            params![tenant, key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let next_revision = to_i64(expected.revision())?;
        let next_owner = owning_project.map(ProjectId::as_str);
        if let Some((revision, owner, prior_resolution)) = prior {
            if revision == next_revision
                && owner.as_deref() == next_owner
                && prior_resolution.as_deref() == Some(resolution.as_str())
            {
                tx.commit()?;
                return Ok(());
            }
            if revision.checked_add(1) != Some(next_revision) || owner.as_deref() != next_owner {
                return Err(WorkContextStoreError::StaleRevision);
            }
        }
        tx.execute("INSERT INTO work_context_expected_revisions(tenant,identity_key,revision,owning_project_id,external_resolution) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(tenant,identity_key) DO UPDATE SET revision=excluded.revision,owning_project_id=excluded.owning_project_id,external_resolution=excluded.external_resolution", params![tenant,key,next_revision,next_owner,resolution.as_str()])?;
        tx.commit()?;
        Ok(())
    }

    pub fn record(
        &self,
        policy: &MutationPolicyDecision,
        identity: &WorkContextIdentity,
    ) -> Stored<Option<WorkContextRecord>> {
        authorize_identity(policy, identity)?;
        load_record(
            &self.connection,
            policy.authenticated_actor.tenant(),
            identity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_mutation(
        &mut self,
        proposal: &WorkContextMutationProposal,
        policy: &MutationPolicyDecision,
        trusted_now_ms: i64,
        expires_at_ms: i64,
        nonces: &mut impl WorkContextNonceSource,
    ) -> Stored<PreviewAdmission> {
        if trusted_now_ms < 0 || expires_at_ms <= trusted_now_ms {
            return Err(WorkContextStoreError::InvalidField("preview_expiry"));
        }
        authorize_proposal(proposal, policy)?;
        let proposal_document =
            encode_work_context_mutation_proposal(proposal).map_err(protocol)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize_transaction_scope(&tx, proposal.intent(), policy)?;
        let scope = (
            proposal.actor().tenant(),
            proposal.actor().id(),
            proposal.authority().as_str(),
            proposal.idempotency_key().as_str(),
        );
        let replay: Option<(String,i64,Vec<u8>)> = tx.query_row("SELECT preview_id,preview_revision,proposal_document FROM work_context_previews WHERE tenant=?1 AND actor_id=?2 AND serving_authority=?3 AND idempotency_key=?4", params![scope.0,scope.1,scope.2,scope.3], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        if let Some((stored_preview_id, stored_revision, stored_proposal)) = replay {
            if stored_proposal != proposal_document {
                return Err(WorkContextStoreError::BodyConflict);
            }
            let stored_preview_id = MutationPreviewId::new(stored_preview_id)
                .map_err(|_| WorkContextStoreError::Corrupt("preview_id"))?;
            let stored_revision = u64::try_from(stored_revision)
                .ok()
                .and_then(|value| Revision::new(value).ok())
                .ok_or(WorkContextStoreError::Corrupt("preview_revision"))?;
            let stored_ref = MutationPreviewRef::new(stored_preview_id, stored_revision);
            let decoded = load_preview_for_scope(
                &tx,
                &stored_ref,
                proposal.actor().tenant(),
                proposal.authority(),
            )?;
            recheck_policy(&decoded, policy)?;
            return Ok(PreviewAdmission::Replay(decoded));
        }
        let parent_snapshots =
            resolve_parent_snapshots(&tx, proposal.intent(), proposal.actor().tenant())?;
        verify_expected_and_graph(&tx, proposal.intent(), proposal.actor().tenant())?;
        let current = proposal
            .intent()
            .expected_target()
            .map(|target| load_required_record(&tx, proposal.actor().tenant(), target.identity()))
            .transpose()?;
        let issued_identity = if proposal.intent().is_create() {
            Some(
                automonique_protocol::platform_v2::issue_work_context_identity_from_random_nonce(
                    intent_record_kind(proposal.intent())?,
                    nonces.nonce(),
                ),
            )
        } else {
            None
        };
        let preview_id = MutationPreviewId::new(format!("preview_{}", hex(&nonces.nonce())))
            .map_err(|_| WorkContextStoreError::InvalidField("preview_id"))?;
        let preview = MutationPreview::new(
            MutationPreviewRef::new(preview_id, Revision::FIRST),
            proposal.clone(),
            current,
            issued_identity,
            parent_snapshots,
            policy.inherited_authority.clone(),
            proposal
                .intent()
                .requested_authority()
                .cloned()
                .unwrap_or(WorkContextAuthority::EMPTY),
            policy.approval,
            EpochMillis::from_millis(trusted_now_ms),
            EpochMillis::from_millis(expires_at_ms),
        )
        .map_err(protocol)?;
        let preview_document = encode_work_context_mutation_preview(&preview).map_err(protocol)?;
        tx.execute("INSERT INTO work_context_previews(preview_id,preview_revision,tenant,actor_id,serving_authority,idempotency_key,request_digest,proposal_document,preview_document,expires_at_ms) VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9)", params![preview.preview().id().as_str(),scope.0,scope.1,scope.2,scope.3,proposal.request_digest().to_string(),proposal_document,preview_document,expires_at_ms])?;
        tx.commit()?;
        Ok(PreviewAdmission::New(preview))
    }

    pub fn record_approval(
        &mut self,
        preview_ref: &MutationPreviewRef,
        id: MutationApprovalId,
        decision: MutationApprovalDecision,
        policy: &ApprovalPolicyDecision,
        trusted_now_ms: i64,
    ) -> Stored<MutationApproval> {
        if trusted_now_ms < 0
            || policy.preview != *preview_ref
            || policy.expires_at.as_millis() <= trusted_now_ms
            || policy.approval_authority != WorkContextApprovalAuthority::LifecycleMutation
        {
            return Err(WorkContextStoreError::Unauthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview_for_scope(
            &tx,
            preview_ref,
            policy.authenticated_approver.tenant(),
            policy.serving_authority,
        )?;
        if preview.approval() != MutationApprovalRequirement::Required {
            return Err(WorkContextStoreError::ApprovalMismatch);
        }
        let digest = work_context_mutation_preview_digest(&preview).map_err(protocol)?;
        if digest != policy.preview_digest
            || policy.authenticated_approver.tenant() != preview.proposal().actor().tenant()
            || policy.expires_at.as_millis() > preview.expires_at().as_millis()
            || trusted_now_ms >= preview.expires_at().as_millis()
        {
            return Err(WorkContextStoreError::Unauthorized);
        }
        let approval = MutationApproval::new(
            id,
            &preview,
            digest,
            decision,
            policy.authenticated_approver.clone(),
            EpochMillis::from_millis(trusted_now_ms),
            policy.expires_at,
        )
        .map_err(protocol)?;
        let document = encode_work_context_mutation_approval(&approval).map_err(protocol)?;
        tx.execute("INSERT INTO work_context_approvals(approval_id,preview_id,approval_document,expires_at_ms) VALUES(?1,?2,?3,?4)",params![approval.id().as_str(),preview.preview().id().as_str(),document,policy.expires_at.as_millis()])?;
        tx.commit()?;
        Ok(approval)
    }

    pub fn submit_mutation(
        &mut self,
        preview_ref: &MutationPreviewRef,
        submission_document: &[u8],
        policy: &MutationPolicyDecision,
        receipt_id: ReceiptId,
        trusted_now_ms: i64,
    ) -> Stored<ReceiptAdmission> {
        if trusted_now_ms < 0 {
            return Err(WorkContextStoreError::InvalidField("trusted_now"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview_for_scope(
            &tx,
            preview_ref,
            policy.authenticated_actor.tenant(),
            policy.serving_authority,
        )?;
        recheck_policy(&preview, policy)?;
        authorize_transaction_scope(&tx, preview.proposal().intent(), policy)?;
        let submission = decode_work_context_mutation_submission(submission_document, &preview)
            .map_err(protocol)?;
        let existing: Option<(String,Vec<u8>)> = tx.query_row("SELECT receipt_id,submission_document FROM work_context_receipts WHERE preview_id=?1",[preview_ref.id().as_str()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((stored_receipt_id, stored_submission)) = existing {
            if stored_submission != submission_document {
                return Err(WorkContextStoreError::BodyConflict);
            }
            let ReceiptLookup::Found(receipt) =
                load_receipt_lookup(&tx, policy, "r.receipt_id=?4", &stored_receipt_id)?
            else {
                return Err(WorkContextStoreError::Corrupt("receipt_lookup"));
            };
            return Ok(ReceiptAdmission::Replay(receipt));
        }
        if trusted_now_ms < submission.submitted_at().as_millis() {
            return Err(WorkContextStoreError::InvalidField("recorded_at"));
        }
        if trusted_now_ms >= preview.expires_at().as_millis() {
            return Err(WorkContextStoreError::PreviewExpired);
        }
        consume_approval(
            &tx,
            &preview,
            &submission,
            submission_document,
            trusted_now_ms,
        )?;
        recheck_preview_state(&tx, &preview)?;
        let external = external_effect(preview.proposal().intent());
        let outcome = if external.is_some() {
            ReceiptOutcome::Accepted
        } else {
            ReceiptOutcome::Completed
        };
        if external.is_none() {
            store_record(
                &tx,
                preview.proposal().actor().tenant(),
                preview.resulting(),
            )?;
            bump_generation(&tx)?;
        }
        let receipt = MutationReceipt::new(
            receipt_id,
            &submission,
            &preview,
            work_context_mutation_preview_digest(&preview).map_err(protocol)?,
            outcome,
            EpochMillis::from_millis(trusted_now_ms),
        )
        .map_err(protocol)?;
        let receipt_document = encode_work_context_mutation_receipt(&receipt).map_err(protocol)?;
        tx.execute("INSERT INTO work_context_receipts(receipt_id,preview_id,submission_document,receipt_document,outcome,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![receipt.id().as_str(),preview_ref.id().as_str(),submission_document,receipt_document,outcome.as_str(),trusted_now_ms])?;
        tx.execute("UPDATE work_context_previews SET submitted_at_ms=?1 WHERE preview_id=?2 AND submitted_at_ms IS NULL",params![submission.submitted_at().as_millis(),preview_ref.id().as_str()])?;
        tx.execute("INSERT INTO work_context_events(preview_id,event_kind,event_document,recorded_at_ms) VALUES(?1,?2,?3,?4)",params![preview_ref.id().as_str(),outcome.as_str(),receipt_document,trusted_now_ms])?;
        if let Some(kind) = external {
            let target = effect_target(preview.proposal().intent())?;
            let reserved = tx.execute("INSERT OR IGNORE INTO work_context_effect_reservations(tenant,target_key,target_revision,effect_kind,preview_id) VALUES(?1,?2,?3,?4,?5)", params![preview.proposal().actor().tenant(), identity_key(target.identity()), to_i64(target.revision())?, kind, preview_ref.id().as_str()])?;
            if reserved != 1 {
                return Err(WorkContextStoreError::GraphConflict);
            }
            tx.execute("INSERT INTO work_context_outbox(outbox_id,preview_id,effect_kind,effect_document,state,created_at_ms) VALUES(?1,?2,?3,?4,'ready',?5)",params![format!("outbox_{}",preview_ref.id().as_str()),preview_ref.id().as_str(),kind,submission_document,trusted_now_ms])?;
        }
        tx.commit()?;
        Ok(ReceiptAdmission::New(receipt))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_external_effect(
        &mut self,
        preview_ref: &MutationPreviewRef,
        policy: &ExternalEffectExecutorPolicy,
        trusted_now_ms: i64,
        expires_at_ms: i64,
        nonces: &mut impl WorkContextNonceSource,
    ) -> Stored<ExternalEffectCompletionPolicy> {
        if trusted_now_ms < 0 || expires_at_ms <= trusted_now_ms {
            return Err(WorkContextStoreError::InvalidField("effect_lease_expiry"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview_for_scope(
            &tx,
            preview_ref,
            policy.executor.tenant(),
            policy.serving_authority,
        )?;
        let effect_kind =
            external_effect(preview.proposal().intent()).ok_or(WorkContextStoreError::NotFound)?;
        if !policy.allowed_effect_kinds.contains(effect_kind) {
            return Err(WorkContextStoreError::Unauthorized);
        }
        let target = effect_target(preview.proposal().intent())?.clone();
        recheck_preview_state(&tx, &preview)?;
        type OutboxRow = (Vec<u8>, String, String, i64, String, String, i64, String);
        let row: Option<OutboxRow> = tx
            .query_row(
                "SELECT o.effect_document,o.state,o.effect_kind,o.created_at_ms,e.tenant,e.target_key,e.target_revision,e.effect_kind FROM work_context_outbox o JOIN work_context_effect_reservations e ON e.preview_id=o.preview_id WHERE o.preview_id=?1",
                [preview_ref.id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            )
            .optional()?;
        let Some((
            effect_document,
            outbox_state,
            outbox_kind,
            created_at,
            reservation_tenant,
            reservation_target,
            reservation_revision,
            reservation_kind,
        )) = row
        else {
            return Err(WorkContextStoreError::NotFound);
        };
        if outbox_state != "ready" {
            return Err(WorkContextStoreError::NotFound);
        }
        if trusted_now_ms < created_at
            || outbox_kind != effect_kind
            || reservation_tenant != policy.executor.tenant()
            || reservation_target != identity_key(target.identity())
            || reservation_revision != to_i64(target.revision())?
            || reservation_kind != effect_kind
        {
            return Err(WorkContextStoreError::Corrupt("effect_reservation"));
        }
        let digest = document_digest(&effect_document);
        type LeaseRow = (
            String,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            i64,
            String,
        );
        let existing: Option<LeaseRow> = tx
            .query_row(
                "SELECT lease_id,tenant,executor_id,serving_authority,target_key,target_revision,effect_kind,effect_digest,expires_at_ms,state FROM work_context_effect_leases WHERE preview_id=?1",
                [preview_ref.id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
            )
            .optional()?;
        let mut claim_expiry = expires_at_ms;
        let lease_id = if let Some((
            lease_id,
            tenant,
            executor_id,
            authority,
            target_key,
            revision,
            stored_kind,
            stored_digest,
            stored_expiry,
            state,
        )) = existing
        {
            if state != "claimed"
                || tenant != policy.executor.tenant()
                || authority != policy.serving_authority.as_str()
                || target_key != identity_key(target.identity())
                || revision != to_i64(target.revision())?
                || stored_kind != effect_kind
                || stored_digest != digest
            {
                return Err(WorkContextStoreError::Corrupt("effect_lease"));
            }
            if stored_expiry > trusted_now_ms {
                if executor_id != policy.executor.id() {
                    return Err(WorkContextStoreError::Unavailable);
                }
                claim_expiry = stored_expiry;
                ExternalEffectLeaseId(lease_id)
            } else {
                let replacement = ExternalEffectLeaseId::issue(nonces.nonce());
                tx.execute(
                    "UPDATE work_context_effect_leases SET lease_id=?1,executor_id=?2,expires_at_ms=?3 WHERE preview_id=?4 AND state='claimed' AND expires_at_ms<=?5",
                    params![replacement.as_str(), policy.executor.id(), expires_at_ms, preview_ref.id().as_str(), trusted_now_ms],
                )?;
                replacement
            }
        } else {
            let issued = ExternalEffectLeaseId::issue(nonces.nonce());
            tx.execute(
                "INSERT INTO work_context_effect_leases(lease_id,preview_id,tenant,executor_id,serving_authority,target_key,target_revision,effect_kind,effect_digest,expires_at_ms,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'claimed')",
                params![issued.as_str(), preview_ref.id().as_str(), policy.executor.tenant(), policy.executor.id(), policy.serving_authority.as_str(), identity_key(target.identity()), to_i64(target.revision())?, effect_kind, digest, expires_at_ms],
            )?;
            issued
        };
        let claim = ExternalEffectCompletionPolicy {
            lease_id,
            executor: policy.executor.clone(),
            serving_authority: policy.serving_authority,
            preview: preview_ref.clone(),
            target,
            effect_kind: effect_kind.to_owned(),
            effect_document,
            expires_at: EpochMillis::from_millis(claim_expiry),
        };
        tx.commit()?;
        Ok(claim)
    }

    pub fn complete_external_effect(
        &mut self,
        policy: &ExternalEffectCompletionPolicy,
        trusted_now_ms: i64,
    ) -> Stored<MutationReceipt> {
        if trusted_now_ms < 0 || policy.executor.tenant() == "" {
            return Err(WorkContextStoreError::Unauthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview_for_scope(
            &tx,
            &policy.preview,
            policy.executor.tenant(),
            policy.serving_authority,
        )?;
        let target = effect_target(preview.proposal().intent())?;
        if target != &policy.target
            || external_effect(preview.proposal().intent()) != Some(policy.effect_kind.as_str())
        {
            return Err(WorkContextStoreError::Unauthorized);
        }
        type CompletionRow = (
            String,
            Vec<u8>,
            Vec<u8>,
            String,
            i64,
            Option<i64>,
            String,
            i64,
            Vec<u8>,
            String,
            String,
            String,
            String,
            i64,
            String,
        );
        let row: Option<CompletionRow>=tx.query_row(
            "SELECT r.receipt_id,r.submission_document,o.effect_document,o.state,o.created_at_ms,o.completed_at_ms,r.outcome,r.recorded_at_ms,r.receipt_document,l.lease_id,l.executor_id,l.serving_authority,l.effect_digest,l.expires_at_ms,l.state FROM work_context_receipts r JOIN work_context_outbox o ON o.preview_id=r.preview_id JOIN work_context_effect_reservations e ON e.preview_id=r.preview_id JOIN work_context_effect_leases l ON l.preview_id=r.preview_id WHERE r.preview_id=?1 AND e.tenant=?2 AND e.target_key=?3 AND e.target_revision=?4 AND e.effect_kind=?5",
            params![policy.preview.id().as_str(), policy.executor.tenant(), identity_key(target.identity()), to_i64(target.revision())?, policy.effect_kind],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?)),
        ).optional()?;
        let Some((
            receipt_id,
            submission_document,
            effect_document,
            state,
            created_at,
            completed_at,
            prior_outcome,
            prior_recorded_at,
            prior_receipt,
            lease_id,
            executor_id,
            lease_authority,
            lease_digest,
            lease_expiry,
            lease_state,
        )) = row
        else {
            return Err(WorkContextStoreError::NotFound);
        };
        if effect_document != policy.effect_document
            || effect_document != submission_document
            || lease_id != policy.lease_id.as_str()
            || executor_id != policy.executor.id()
            || lease_authority != policy.serving_authority.as_str()
            || lease_digest != document_digest(&effect_document)
            || lease_expiry != policy.expires_at.as_millis()
        {
            return Err(WorkContextStoreError::Unauthorized);
        }
        let submission = decode_work_context_mutation_submission(&submission_document, &preview)
            .map_err(protocol)?;
        let decoded_prior =
            decode_work_context_mutation_receipt(&prior_receipt, &submission, &preview)
                .map_err(protocol)?;
        if decoded_prior.id().as_str() != receipt_id
            || decoded_prior.outcome().as_str() != prior_outcome
            || decoded_prior.recorded_at().as_millis() != prior_recorded_at
            || encode_work_context_mutation_receipt(&decoded_prior).map_err(protocol)?
                != prior_receipt
        {
            return Err(WorkContextStoreError::Corrupt("effect_receipt"));
        }
        if state == "completed" {
            if prior_outcome != ReceiptOutcome::Completed.as_str()
                || completed_at.is_none()
                || lease_state != "completed"
            {
                return Err(WorkContextStoreError::Corrupt("completed_effect"));
            }
            return decode_work_context_mutation_receipt(&prior_receipt, &submission, &preview)
                .map_err(protocol);
        }
        if state != "ready"
            || prior_outcome != ReceiptOutcome::Accepted.as_str()
            || lease_state != "claimed"
        {
            return Err(WorkContextStoreError::Corrupt("effect_state"));
        }
        if trusted_now_ms < created_at
            || trusted_now_ms < submission.submitted_at().as_millis()
            || trusted_now_ms >= lease_expiry
        {
            return Err(WorkContextStoreError::InvalidField("completed_at"));
        }
        recheck_preview_state(&tx, &preview)?;
        store_record(
            &tx,
            preview.proposal().actor().tenant(),
            preview.resulting(),
        )?;
        bump_generation(&tx)?;
        let receipt = MutationReceipt::new(
            ReceiptId::new(receipt_id).map_err(|_| WorkContextStoreError::Corrupt("receipt_id"))?,
            &submission,
            &preview,
            work_context_mutation_preview_digest(&preview).map_err(protocol)?,
            ReceiptOutcome::Completed,
            EpochMillis::from_millis(trusted_now_ms),
        )
        .map_err(protocol)?;
        let document = encode_work_context_mutation_receipt(&receipt).map_err(protocol)?;
        tx.execute("UPDATE work_context_receipts SET receipt_document=?1,outcome='completed',recorded_at_ms=?2 WHERE preview_id=?3",params![document,trusted_now_ms,policy.preview.id().as_str()])?;
        tx.execute("UPDATE work_context_outbox SET state='completed',completed_at_ms=?1 WHERE preview_id=?2 AND state='ready'",params![trusted_now_ms,policy.preview.id().as_str()])?;
        tx.execute("UPDATE work_context_effect_leases SET state='completed' WHERE lease_id=?1 AND state='claimed'", [policy.lease_id.as_str()])?;
        tx.execute("INSERT INTO work_context_events(preview_id,event_kind,event_document,recorded_at_ms) VALUES(?1,'completed',?2,?3)",params![policy.preview.id().as_str(),document,trusted_now_ms])?;
        tx.commit()?;
        Ok(receipt)
    }

    pub fn receipt_by_id(
        &self,
        policy: &MutationPolicyDecision,
        receipt_id: &ReceiptId,
    ) -> Stored<ReceiptLookup> {
        load_receipt_lookup(
            &self.connection,
            policy,
            "r.receipt_id=?4",
            receipt_id.as_str(),
        )
    }

    pub fn receipt_by_idempotency_key(
        &self,
        policy: &MutationPolicyDecision,
        key: &automonique_protocol::platform::IdempotencyKey,
    ) -> Stored<ReceiptLookup> {
        load_receipt_lookup(
            &self.connection,
            policy,
            "p.idempotency_key=?4",
            key.as_str(),
        )
    }

    pub fn inventory(
        &mut self,
        actor: &Actor,
        query: &WorkContextQuery,
        allowed: &BTreeSet<WorkContextIdentity>,
        now_ms: i64,
    ) -> Stored<WorkContextQueryResult> {
        if let Some(after) = query.after() {
            let owner: Option<(String, String)> = self
                .connection
                .query_row(
                    "SELECT tenant,actor_id FROM work_context_cursor_state WHERE tenant=?1 AND actor_id=?2 AND cursor=?3",
                    params![actor.tenant(), actor.id(), after.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if owner
                .as_ref()
                .is_none_or(|(tenant, id)| tenant != actor.tenant() || id != actor.id())
            {
                return Ok(WorkContextQueryResult::Resync(
                    automonique_protocol::platform_v2::WorkContextResync::new(after.clone()),
                ));
            }
        }
        let all = load_all_records(&self.connection, actor.tenant())?;
        let map: BTreeMap<WorkContextIdentity, WorkContextRecord> = all
            .into_iter()
            .map(|record| (record.identity().clone(), record))
            .collect();
        let mut authorized = Vec::new();
        for identity in allowed {
            if let Some(record) = map.get(identity) {
                let (project, parents) = resolve_inventory_context(identity, &map)?;
                authorized.push(
                    AuthorizedWorkContextRecord::new(record.clone(), project, parents)
                        .map_err(protocol)?,
                );
            }
        }
        let result = page_authorized_work_context(query, &authorized).map_err(protocol)?;
        if let WorkContextQueryResult::Page(page) = &result
            && let Some(cursor) = page.next_cursor()
        {
            let generation: i64 = self.connection.query_row(
                "SELECT inventory_generation FROM work_context_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            self.connection.execute("INSERT INTO work_context_cursor_state(tenant,actor_id,cursor,inventory_generation,created_at_ms) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(tenant,actor_id,cursor) DO UPDATE SET inventory_generation=excluded.inventory_generation,created_at_ms=excluded.created_at_ms",params![actor.tenant(),actor.id(),cursor.as_str(),generation,now_ms])?;
        }
        Ok(result)
    }

    pub fn ready_outbox_count(&self) -> Stored<u64> {
        self.connection
            .query_row(
                "SELECT count(*) FROM work_context_outbox WHERE state='ready'",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }
}

fn initialize(connection: &mut Connection) -> Stored<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == WORK_CONTEXT_STORE_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        return migrate_v1_to_v2(connection);
    }
    if version != 0 {
        return Err(WorkContextStoreError::SchemaVersion {
            found: version,
            supported: WORK_CONTEXT_STORE_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(WorkContextStoreError::SchemaVersion {
            found: 0,
            supported: WORK_CONTEXT_STORE_SCHEMA_VERSION,
        });
    }
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(SCHEMA_V2)?;
    tx.pragma_update(None, "user_version", WORK_CONTEXT_STORE_SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}
fn migrate_v1_to_v2(connection: &mut Connection) -> Stored<()> {
    let populated: i64 = connection.query_row(
        "SELECT (SELECT count(*) FROM work_context_records)+(SELECT count(*) FROM work_context_expected_revisions)+(SELECT count(*) FROM work_context_previews)+(SELECT count(*) FROM work_context_selector_bindings)",
        [],
        |row| row.get(0),
    )?;
    if populated != 0 {
        // Version 1 did not record record/revision ownership. Guessing a tenant here
        // would turn an upgrade into a cross-tenant data exposure.
        return Err(WorkContextStoreError::SchemaVersion {
            found: 1,
            supported: WORK_CONTEXT_STORE_SCHEMA_VERSION,
        });
    }
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "DROP TABLE work_context_cursor_state;
         DROP TABLE IF EXISTS work_context_effect_leases;
         DROP TABLE IF EXISTS work_context_effect_reservations;
         DROP TABLE work_context_outbox;
         DROP TABLE work_context_events;
         DROP TABLE work_context_receipts;
         DROP TABLE work_context_approvals;
         DROP TABLE work_context_previews;
         DROP TABLE work_context_selector_bindings;
         DROP TABLE work_context_expected_revisions;
         DROP TABLE work_context_relations;
         DROP TABLE work_context_records;
         DROP TABLE work_context_meta;",
    )?;
    tx.execute_batch(SCHEMA_V2)?;
    tx.pragma_update(None, "user_version", WORK_CONTEXT_STORE_SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(())
}
fn secure_path(path: &Path) -> Stored<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => WorkContextStoreError::Io(io),
        other => WorkContextStoreError::InsecurePath(other.to_string()),
    })
}
fn protocol(error: impl fmt::Display) -> WorkContextStoreError {
    WorkContextStoreError::Protocol(error.to_string())
}
fn to_i64(value: Revision) -> Stored<i64> {
    i64::try_from(value.get()).map_err(|_| WorkContextStoreError::InvalidField("revision"))
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        s.push(char::from(H[usize::from(byte >> 4)]));
        s.push(char::from(H[usize::from(byte & 15)]));
    }
    s
}
fn document_digest(document: &[u8]) -> String {
    hex(&Sha256::digest(document))
}
fn identity_key(identity: &WorkContextIdentity) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(identity.kind().as_str().as_bytes());
    material.push(0xff);
    if let Some(c) = identity.v1_coordinate() {
        material.extend_from_slice(c.authority.as_str().as_bytes());
        material.push(0xfe);
        material.extend_from_slice(c.kind.as_str().as_bytes());
        material.push(0xfd);
    }
    material.extend_from_slice(identity.id().as_bytes());
    hex(&material)
}
fn record_document(record: &WorkContextRecord) -> Stored<Vec<u8>> {
    let page =
        WorkContextPage::new(1, None, None, false, vec![record.clone()]).map_err(protocol)?;
    encode_work_context_page(&page).map_err(protocol)
}
fn decode_record_document(bytes: &[u8]) -> Stored<WorkContextRecord> {
    let page = decode_work_context_page(bytes).map_err(protocol)?;
    let mut items = page.into_items();
    if items.len() != 1 {
        return Err(WorkContextStoreError::Corrupt("record_document"));
    }
    Ok(items.remove(0))
}
fn store_record(tx: &Transaction<'_>, tenant: &str, record: &WorkContextRecord) -> Stored<()> {
    validate_tenant(tenant)?;
    let key = identity_key(record.identity());
    let coordinate = record.identity().v1_coordinate();
    let document = record_document(record)?;
    let existing: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT revision,record_document FROM work_context_records WHERE tenant=?1 AND identity_key=?2",
            params![tenant, &key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((revision, stored)) = existing {
        if revision == to_i64(record.revision())? && stored == document {
            return Ok(());
        }
        let prior = decode_record_document(&stored)?;
        if revision.checked_add(1) != Some(to_i64(record.revision())?) {
            return Err(WorkContextStoreError::StaleRevision);
        }
        if prior.identity() != record.identity()
            || prior.label() != record.label()
            || prior.attributes() != record.attributes()
            || prior.relations() != record.relations()
            || !valid_lifecycle_transition(prior.lifecycle(), record.lifecycle())
        {
            return Err(WorkContextStoreError::GraphConflict);
        }
    }
    validate_record_graph(tx, tenant, record)?;
    let owner = record_project_id(tx, tenant, record)?;
    tx.execute("INSERT INTO work_context_records(tenant,identity_key,identity_kind,identity_id,resource_authority,resource_kind,revision,lifecycle,record_document) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(tenant,identity_key) DO UPDATE SET revision=excluded.revision,lifecycle=excluded.lifecycle,record_document=excluded.record_document",params![tenant,key,record.identity().kind().as_str(),record.identity().id(),coordinate.map(|v|v.authority.as_str()),coordinate.map(|v|v.kind.as_str()),to_i64(record.revision())?,record.lifecycle().as_str(),document])?;
    tx.execute(
        "DELETE FROM work_context_relations WHERE tenant=?1 AND source_key=?2",
        params![tenant, &key],
    )?;
    for (ordinal, relation) in record.relations().iter().enumerate() {
        let c = relation.target().v1_coordinate();
        tx.execute("INSERT INTO work_context_relations(tenant,source_key,ordinal,relation_kind,target_key,target_kind,target_id,target_authority,target_resource_kind) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![tenant,key,i64::try_from(ordinal).unwrap_or(i64::MAX),relation.kind().as_str(),identity_key(relation.target()),relation.target().kind().as_str(),relation.target().id(),c.map(|v|v.authority.as_str()),c.map(|v|v.kind.as_str())])?;
    }
    tx.execute("INSERT INTO work_context_expected_revisions(tenant,identity_key,revision,owning_project_id,external_resolution) VALUES(?1,?2,?3,?4,NULL) ON CONFLICT(tenant,identity_key) DO UPDATE SET revision=excluded.revision,owning_project_id=excluded.owning_project_id,external_resolution=NULL",params![tenant,key,to_i64(record.revision())?,owner])?;
    Ok(())
}
fn direct_project_id(record: &WorkContextRecord) -> Option<&str> {
    if let WorkContextIdentity::Project(project) = record.identity() {
        return Some(project.as_str());
    }
    record
        .relations()
        .iter()
        .find(|r| r.target().kind() == WorkContextTargetKind::Project)
        .map(|r| r.target().id())
}
fn valid_lifecycle_transition(from: WorkContextLifecycle, to: WorkContextLifecycle) -> bool {
    use WorkContextLifecycle::{
        Active, Archived, Cancelled, Closed, Completed, Failed, Hibernated, Preparing, Running,
    };
    matches!(
        (from, to),
        (
            Active,
            Archived | Hibernated | Completed | Failed | Cancelled | Closed
        ) | (Preparing, Running | Failed | Cancelled)
            | (Running, Hibernated | Completed | Failed | Cancelled)
            | (
                Hibernated,
                Active | Running | Completed | Failed | Cancelled
            )
    )
}
fn record_project_id(
    tx: &Connection,
    tenant: &str,
    record: &WorkContextRecord,
) -> Stored<Option<String>> {
    if let Some(project) = direct_project_id(record) {
        return Ok(Some(project.to_owned()));
    }
    for relation in record.relations() {
        if matches!(
            relation.target().kind(),
            WorkContextTargetKind::UserWorkspace
                | WorkContextTargetKind::AttemptWorkspace
                | WorkContextTargetKind::Session
        ) {
            return tx
                .query_row(
                    "SELECT owning_project_id FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2 AND external_resolution IS NULL",
                    params![tenant, identity_key(relation.target())],
                    |row| row.get(0),
                )
                .optional()?
                .flatten()
                .map(Some)
                .ok_or(WorkContextStoreError::GraphConflict);
        }
    }
    Ok(None)
}
fn validate_record_graph(
    tx: &Transaction<'_>,
    tenant: &str,
    record: &WorkContextRecord,
) -> Stored<()> {
    let selected_project = direct_project_id(record).map(str::to_owned);
    for relation in record.relations() {
        if relation.target().kind() == WorkContextTargetKind::PlatformSession {
            continue;
        }
        let row: Option<(Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT owning_project_id,external_resolution FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
                params![tenant, identity_key(relation.target())],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((owner, _resolution)) = row else {
            return Err(WorkContextStoreError::GraphConflict);
        };
        if relation.target().kind() != WorkContextTargetKind::Repository
            && load_record(tx, tenant, relation.target())?.is_none()
        {
            return Err(WorkContextStoreError::GraphConflict);
        }
        if record.kind() != WorkContextKind::Project
            && let Some(project) = &selected_project
            && relation.target().kind() != WorkContextTargetKind::Project
            && owner.as_deref().is_some_and(|value| value != project)
        {
            return Err(WorkContextStoreError::GraphConflict);
        }
    }
    Ok(())
}
fn load_record(
    connection: &Connection,
    tenant: &str,
    identity: &WorkContextIdentity,
) -> Stored<Option<WorkContextRecord>> {
    type RecordRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Vec<u8>,
        i64,
        String,
    );
    let row:Option<RecordRow>=connection.query_row("SELECT tenant,identity_key,identity_kind,identity_id,resource_authority,resource_kind,record_document,revision,lifecycle FROM work_context_records WHERE tenant=?1 AND identity_key=?2",params![tenant,identity_key(identity)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?))).optional()?;
    row.map(
        |(stored_tenant, key, kind, id, authority, resource_kind, bytes, revision, lifecycle)| {
            let record = decode_record_document(&bytes)?;
            let coordinate = record.identity().v1_coordinate();
            if record.identity() != identity
                || stored_tenant != tenant
                || key != identity_key(identity)
                || kind != identity.kind().as_str()
                || id != identity.id()
                || authority.as_deref() != coordinate.map(|value| value.authority.as_str())
                || resource_kind.as_deref() != coordinate.map(|value| value.kind.as_str())
                || to_i64(record.revision())? != revision
                || record.lifecycle().as_str() != lifecycle
                || record_document(&record)? != bytes
            {
                return Err(WorkContextStoreError::Corrupt("record_projection"));
            }
            verify_record_projections(connection, tenant, &key, &record)?;
            Ok(record)
        },
    )
    .transpose()
}
fn verify_record_projections(
    connection: &Connection,
    tenant: &str,
    key: &str,
    record: &WorkContextRecord,
) -> Stored<()> {
    type RelationRow = (
        i64,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
    );
    let mut statement = connection.prepare(
        "SELECT ordinal,relation_kind,target_key,target_kind,target_id,target_authority,target_resource_kind FROM work_context_relations WHERE tenant=?1 AND source_key=?2 ORDER BY ordinal",
    )?;
    let rows: Vec<RelationRow> = statement
        .query_map(params![tenant, key], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    if rows.len() != record.relations().len() {
        return Err(WorkContextStoreError::Corrupt("relation_projection"));
    }
    for (ordinal, (row, relation)) in rows.iter().zip(record.relations()).enumerate() {
        let coordinate = relation.target().v1_coordinate();
        if row.0 != i64::try_from(ordinal).unwrap_or(i64::MAX)
            || row.1 != relation.kind().as_str()
            || row.2 != identity_key(relation.target())
            || row.3 != relation.target().kind().as_str()
            || row.4 != relation.target().id()
            || row.5.as_deref() != coordinate.map(|value| value.authority.as_str())
            || row.6.as_deref() != coordinate.map(|value| value.kind.as_str())
        {
            return Err(WorkContextStoreError::Corrupt("relation_projection"));
        }
    }
    let expected: Option<(i64, Option<String>, Option<String>)> = connection
        .query_row(
            "SELECT revision,owning_project_id,external_resolution FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
            params![tenant, key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let owner = record_project_id(connection, tenant, record)?;
    if expected != Some((to_i64(record.revision())?, owner, None)) {
        return Err(WorkContextStoreError::Corrupt("revision_projection"));
    }
    Ok(())
}
fn load_required_record(
    connection: &Connection,
    tenant: &str,
    identity: &WorkContextIdentity,
) -> Stored<WorkContextRecord> {
    load_record(connection, tenant, identity)?.ok_or(WorkContextStoreError::NotFound)
}
fn load_all_records(connection: &Connection, tenant: &str) -> Stored<Vec<WorkContextRecord>> {
    let mut statement = connection
        .prepare("SELECT identity_key,record_document FROM work_context_records WHERE tenant=?1 ORDER BY identity_key")?;
    let rows = statement.query_map([tenant], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let identities: Vec<WorkContextIdentity> = rows
        .map(|row| {
            let (key, bytes) = row?;
            let record = decode_record_document(&bytes)?;
            if identity_key(record.identity()) != key || record_document(&record)? != bytes {
                return Err(WorkContextStoreError::Corrupt("record_projection"));
            }
            Ok(record.identity().clone())
        })
        .collect::<Stored<_>>()?;
    drop(statement);
    identities
        .iter()
        .map(|identity| load_required_record(connection, tenant, identity))
        .collect()
}
fn bump_generation(tx: &Transaction<'_>) -> Stored<()> {
    tx.execute("UPDATE work_context_meta SET inventory_generation=inventory_generation+1 WHERE singleton=1",[])?;
    Ok(())
}
fn load_preview_for_scope(
    connection: &Connection,
    preview_ref: &MutationPreviewRef,
    tenant: &str,
    authority: ResourceAuthority,
) -> Stored<MutationPreview> {
    type PreviewRow = (
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<i64>,
    );
    let row:Option<PreviewRow>=connection.query_row("SELECT preview_id,preview_revision,tenant,actor_id,serving_authority,idempotency_key,request_digest,proposal_document,preview_document,expires_at_ms,submitted_at_ms FROM work_context_previews WHERE preview_id=?1 AND tenant=?2 AND serving_authority=?3",params![preview_ref.id().as_str(),tenant,authority.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?))).optional()?;
    let Some((
        id,
        revision,
        stored_tenant,
        actor_id,
        stored_authority,
        idempotency_key,
        request_digest,
        proposal_document,
        bytes,
        expires_at,
        submitted_at,
    )) = row
    else {
        return Err(WorkContextStoreError::NotFound);
    };
    if revision != to_i64(preview_ref.revision())? {
        return Err(WorkContextStoreError::StaleRevision);
    };
    let preview = decode_work_context_mutation_preview(&bytes).map_err(protocol)?;
    let canonical_preview = encode_work_context_mutation_preview(&preview).map_err(protocol)?;
    let canonical_proposal =
        encode_work_context_mutation_proposal(preview.proposal()).map_err(protocol)?;
    if id != preview_ref.id().as_str()
        || preview.preview() != preview_ref
        || stored_tenant != tenant
        || preview.proposal().actor().tenant() != stored_tenant
        || preview.proposal().actor().id() != actor_id
        || preview.proposal().authority().as_str() != stored_authority
        || stored_authority != authority.as_str()
        || preview.proposal().idempotency_key().as_str() != idempotency_key
        || preview.proposal().request_digest().to_string() != request_digest
        || preview.expires_at().as_millis() != expires_at
        || canonical_proposal != proposal_document
        || canonical_preview != bytes
    {
        return Err(WorkContextStoreError::Corrupt("preview_projection"));
    }
    let stored_submission: Option<Vec<u8>> = connection
        .query_row(
            "SELECT submission_document FROM work_context_receipts WHERE preview_id=?1",
            [preview_ref.id().as_str()],
            |row| row.get(0),
        )
        .optional()?;
    match (submitted_at, stored_submission) {
        (None, None) => {}
        (Some(stored), Some(document)) => {
            let submission =
                decode_work_context_mutation_submission(&document, &preview).map_err(protocol)?;
            if submission.submitted_at().as_millis() != stored {
                return Err(WorkContextStoreError::Corrupt("preview_submission"));
            }
        }
        _ => return Err(WorkContextStoreError::Corrupt("preview_submission")),
    }
    Ok(preview)
}
fn expected_values(intent: &WorkContextMutationIntent) -> Vec<&ExpectedWorkContext> {
    match intent {
        WorkContextMutationIntent::CreateProject(v) => v.repositories().iter().collect(),
        WorkContextMutationIntent::CreateHostSetup(v) => vec![v.project()],
        WorkContextMutationIntent::CreateCheckout(v) => {
            vec![v.project(), v.host_setup(), v.repository()]
        }
        WorkContextMutationIntent::CreateUserWorkspace(v) => vec![v.project(), v.checkout()],
        WorkContextMutationIntent::CreateAttemptWorkspace(v) => vec![v.user_workspace()],
        WorkContextMutationIntent::ResumeAttemptWorkspace(v) => vec![v.target()],
        WorkContextMutationIntent::ResumeSession(v) => vec![v.target()],
        WorkContextMutationIntent::ArchiveProject(v)
        | WorkContextMutationIntent::ArchiveHostSetup(v)
        | WorkContextMutationIntent::ArchiveCheckout(v)
        | WorkContextMutationIntent::ArchiveUserWorkspace(v) => vec![v.target()],
    }
}
fn parent_expected_values(intent: &WorkContextMutationIntent) -> Vec<&ExpectedWorkContext> {
    match intent {
        WorkContextMutationIntent::CreateProject(v) => v.repositories().iter().collect(),
        WorkContextMutationIntent::CreateHostSetup(v) => vec![v.project()],
        WorkContextMutationIntent::CreateCheckout(v) => {
            vec![v.project(), v.host_setup(), v.repository()]
        }
        WorkContextMutationIntent::CreateUserWorkspace(v) => vec![v.project(), v.checkout()],
        WorkContextMutationIntent::CreateAttemptWorkspace(v) => vec![v.user_workspace()],
        WorkContextMutationIntent::ResumeAttemptWorkspace(_)
        | WorkContextMutationIntent::ResumeSession(_)
        | WorkContextMutationIntent::ArchiveProject(_)
        | WorkContextMutationIntent::ArchiveHostSetup(_)
        | WorkContextMutationIntent::ArchiveCheckout(_)
        | WorkContextMutationIntent::ArchiveUserWorkspace(_) => Vec::new(),
    }
}
fn resolve_parent_snapshots(
    tx: &Transaction<'_>,
    intent: &WorkContextMutationIntent,
    tenant: &str,
) -> Stored<Vec<ResolvedParentSnapshot>> {
    parent_expected_values(intent)
        .into_iter()
        .map(|expected| {
            if expected.identity().kind() == WorkContextTargetKind::Repository {
                let row: Option<(i64, Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT revision,owning_project_id,external_resolution FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
                        params![tenant, identity_key(expected.identity())],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((revision, owner, resolution)) = row else {
                    return Err(WorkContextStoreError::StaleRevision);
                };
                if revision != to_i64(expected.revision())? {
                    return Err(WorkContextStoreError::StaleRevision);
                }
                let resolution = resolution
                    .as_deref()
                    .ok_or(WorkContextStoreError::Corrupt("external_resolution"))
                    .and_then(|value| {
                        ExternalParentResolution::parse(value)
                            .map_err(|_| WorkContextStoreError::Corrupt("external_resolution"))
                    })?;
                if resolution == ExternalParentResolution::Unavailable {
                    return Err(WorkContextStoreError::Unavailable);
                }
                let owning_project = owner
                    .map(ProjectId::new)
                    .transpose()
                    .map_err(|_| WorkContextStoreError::Corrupt("owning_project"))?;
                Ok(ResolvedParentSnapshot::External {
                    identity: expected.identity().clone(),
                    revision: expected.revision(),
                    resolution,
                    owning_project,
                })
            } else {
                let record = load_required_record(tx, tenant, expected.identity())?;
                if record.revision() != expected.revision() {
                    return Err(WorkContextStoreError::StaleRevision);
                }
                Ok(ResolvedParentSnapshot::WorkContext { record })
            }
        })
        .collect()
}
fn verify_expected_and_graph(
    tx: &Transaction<'_>,
    intent: &WorkContextMutationIntent,
    tenant: &str,
) -> Stored<()> {
    for expected in expected_values(intent) {
        let stored: Option<i64> = tx
            .query_row(
                "SELECT revision FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
                params![tenant, identity_key(expected.identity())],
                |row| row.get(0),
            )
            .optional()?;
        if stored != Some(to_i64(expected.revision())?) {
            return Err(WorkContextStoreError::StaleRevision);
        }
    }
    match intent {
        WorkContextMutationIntent::CreateHostSetup(v) => selector_exists(tx, tenant, v.registry())?,
        WorkContextMutationIntent::CreateCheckout(v) => {
            selector_exists(tx, tenant, v.registry())?;
            same_project(
                tx,
                tenant,
                v.host_setup().identity(),
                v.project().identity(),
            )?;
            reject_mismatched_optional_project(
                tx,
                tenant,
                v.repository().identity(),
                v.project().identity(),
            )?
        }
        WorkContextMutationIntent::CreateUserWorkspace(v) => {
            same_project(tx, tenant, v.checkout().identity(), v.project().identity())?
        }
        WorkContextMutationIntent::CreateAttemptWorkspace(v) => {
            ensure_active(tx, tenant, v.user_workspace().identity())?
        }
        _ => {}
    };
    for expected in expected_values(intent) {
        if !matches!(
            expected.identity().kind(),
            WorkContextTargetKind::Repository | WorkContextTargetKind::PlatformSession
        ) && intent.is_create()
        {
            ensure_active(tx, tenant, expected.identity())?
        }
    }
    Ok(())
}
fn selector_exists(
    tx: &Transaction<'_>,
    tenant: &str,
    selector: &WorkContextRegistrySelector,
) -> Stored<()> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM work_context_selector_bindings WHERE tenant=?1 AND selector=?2)",params![tenant,selector.as_str()],|row|row.get(0))?;
    if !exists {
        return Err(WorkContextStoreError::Unauthorized);
    }
    Ok(())
}
fn ensure_active(
    connection: &Connection,
    tenant: &str,
    identity: &WorkContextIdentity,
) -> Stored<()> {
    if load_required_record(connection, tenant, identity)?.lifecycle()
        != WorkContextLifecycle::Active
    {
        return Err(WorkContextStoreError::GraphConflict);
    }
    Ok(())
}
fn same_project(
    connection: &Connection,
    tenant: &str,
    child: &WorkContextIdentity,
    project: &WorkContextIdentity,
) -> Stored<()> {
    let owner: Option<String> = connection
        .query_row(
            "SELECT owning_project_id FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
            params![tenant, identity_key(child)],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if owner.as_deref() != Some(project.id()) {
        return Err(WorkContextStoreError::GraphConflict);
    }
    Ok(())
}
fn reject_mismatched_optional_project(
    connection: &Connection,
    tenant: &str,
    child: &WorkContextIdentity,
    project: &WorkContextIdentity,
) -> Stored<()> {
    let owner: Option<String> = connection
        .query_row(
            "SELECT owning_project_id FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
            params![tenant, identity_key(child)],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    if owner.as_deref().is_some_and(|owner| owner != project.id()) {
        return Err(WorkContextStoreError::GraphConflict);
    }
    Ok(())
}
fn intent_record_kind(intent: &WorkContextMutationIntent) -> Stored<WorkContextKind> {
    Ok(match intent {
        WorkContextMutationIntent::CreateProject(_) => WorkContextKind::Project,
        WorkContextMutationIntent::CreateHostSetup(_) => WorkContextKind::HostSetup,
        WorkContextMutationIntent::CreateCheckout(_) => WorkContextKind::Checkout,
        WorkContextMutationIntent::CreateUserWorkspace(_) => WorkContextKind::UserWorkspace,
        WorkContextMutationIntent::CreateAttemptWorkspace(_) => WorkContextKind::AttemptWorkspace,
        _ => return Err(WorkContextStoreError::InvalidField("create_intent")),
    })
}
fn recheck_preview_state(tx: &Transaction<'_>, preview: &MutationPreview) -> Stored<()> {
    let snapshots = resolve_parent_snapshots(
        tx,
        preview.proposal().intent(),
        preview.proposal().actor().tenant(),
    )?;
    if snapshots != preview.parent_snapshots() {
        return Err(WorkContextStoreError::StaleRevision);
    }
    verify_expected_and_graph(
        tx,
        preview.proposal().intent(),
        preview.proposal().actor().tenant(),
    )?;
    if let Some(current) = preview.current() {
        let loaded =
            load_required_record(tx, preview.proposal().actor().tenant(), current.identity())?;
        if &loaded != current {
            return Err(WorkContextStoreError::StaleRevision);
        }
    }
    Ok(())
}
fn recheck_policy(preview: &MutationPreview, policy: &MutationPolicyDecision) -> Stored<()> {
    let proposal = preview.proposal();
    if proposal.actor() != &policy.authenticated_actor
        || proposal.authority() != policy.serving_authority
    {
        return Err(WorkContextStoreError::Unauthorized);
    }
    if proposal.actor_authority() != &policy.actor_authority
        || preview.approval() != policy.approval
        || !preview
            .effective_authority()
            .is_subset_of(&policy.actor_authority)
        || !preview
            .effective_authority()
            .is_subset_of(&policy.inherited_authority)
    {
        return Err(WorkContextStoreError::AuthorityWidening);
    }
    for expected in expected_values(proposal.intent()) {
        authorize_identity(policy, expected.identity())?;
    }
    Ok(())
}

fn validate_tenant(tenant: &str) -> Stored<()> {
    if tenant.is_empty() || tenant.len() > 128 {
        return Err(WorkContextStoreError::InvalidField("tenant"));
    }
    Ok(())
}
fn authorize_identity(
    policy: &MutationPolicyDecision,
    identity: &WorkContextIdentity,
) -> Stored<()> {
    if policy.authorized_targets.contains(identity)
        || matches!(
            (identity, policy.authorized_project.as_ref()),
            (WorkContextIdentity::Project(identity), Some(project)) if identity == project
        )
    {
        Ok(())
    } else {
        Err(WorkContextStoreError::Unauthorized)
    }
}
fn authorize_proposal(
    proposal: &WorkContextMutationProposal,
    policy: &MutationPolicyDecision,
) -> Stored<()> {
    if proposal.actor() != &policy.authenticated_actor
        || proposal.authority() != policy.serving_authority
    {
        return Err(WorkContextStoreError::Unauthorized);
    }
    if proposal.actor_authority() != &policy.actor_authority {
        return Err(WorkContextStoreError::AuthorityWidening);
    }
    let requested = proposal
        .intent()
        .requested_authority()
        .cloned()
        .unwrap_or(WorkContextAuthority::EMPTY);
    if !requested.is_subset_of(&policy.actor_authority)
        || !requested.is_subset_of(&policy.inherited_authority)
    {
        return Err(WorkContextStoreError::AuthorityWidening);
    }
    for expected in expected_values(proposal.intent()) {
        authorize_identity(policy, expected.identity())?;
    }
    Ok(())
}
fn authorize_transaction_scope(
    tx: &Connection,
    intent: &WorkContextMutationIntent,
    policy: &MutationPolicyDecision,
) -> Stored<()> {
    if matches!(intent, WorkContextMutationIntent::CreateProject(_)) {
        return Ok(());
    }
    let Some(project) = policy.authorized_project.as_ref() else {
        return Err(WorkContextStoreError::Unauthorized);
    };
    for expected in expected_values(intent) {
        let owner: Option<String> = tx
            .query_row(
                "SELECT owning_project_id FROM work_context_expected_revisions WHERE tenant=?1 AND identity_key=?2",
                params![policy.authenticated_actor.tenant(), identity_key(expected.identity())],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let authorized = match expected.identity() {
            WorkContextIdentity::Project(identity) => identity == project,
            WorkContextIdentity::Repository(_) => true,
            _ => owner.as_deref() == Some(project.as_str()),
        };
        if !authorized {
            return Err(WorkContextStoreError::Unauthorized);
        }
    }
    Ok(())
}
fn load_receipt_lookup(
    connection: &Connection,
    policy: &MutationPolicyDecision,
    predicate: &'static str,
    value: &str,
) -> Stored<ReceiptLookup> {
    let sql = match predicate {
        "r.receipt_id=?4" => {
            "SELECT r.receipt_id,r.preview_id,p.preview_revision,r.submission_document,r.receipt_document,r.outcome,r.recorded_at_ms FROM work_context_receipts r JOIN work_context_previews p ON p.preview_id=r.preview_id WHERE p.tenant=?1 AND p.actor_id=?2 AND p.serving_authority=?3 AND r.receipt_id=?4"
        }
        "p.idempotency_key=?4" => {
            "SELECT r.receipt_id,r.preview_id,p.preview_revision,r.submission_document,r.receipt_document,r.outcome,r.recorded_at_ms FROM work_context_receipts r JOIN work_context_previews p ON p.preview_id=r.preview_id WHERE p.tenant=?1 AND p.actor_id=?2 AND p.serving_authority=?3 AND p.idempotency_key=?4"
        }
        _ => return Err(WorkContextStoreError::InvalidField("receipt_lookup")),
    };
    type ReceiptRow = (String, String, i64, Vec<u8>, Vec<u8>, String, i64);
    let row: Option<ReceiptRow> = connection
        .query_row(
            sql,
            params![
                policy.authenticated_actor.tenant(),
                policy.authenticated_actor.id(),
                policy.serving_authority.as_str(),
                value
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        receipt_id,
        preview_id,
        preview_revision,
        submission_document,
        receipt_document,
        outcome,
        recorded_at,
    )) = row
    else {
        return Ok(ReceiptLookup::Unknown);
    };
    let preview_id = MutationPreviewId::new(preview_id)
        .map_err(|_| WorkContextStoreError::Corrupt("preview_id"))?;
    let preview_revision = u64::try_from(preview_revision)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(WorkContextStoreError::Corrupt("preview_revision"))?;
    let preview_ref = MutationPreviewRef::new(preview_id, preview_revision);
    let preview = load_preview_for_scope(
        connection,
        &preview_ref,
        policy.authenticated_actor.tenant(),
        policy.serving_authority,
    )?;
    recheck_policy(&preview, policy)?;
    authorize_transaction_scope(connection, preview.proposal().intent(), policy)?;
    let submission = decode_work_context_mutation_submission(&submission_document, &preview)
        .map_err(protocol)?;
    let approval = submission.approval_id().map(|id| {
        let document: Vec<u8> = connection.query_row(
            "SELECT approval_document FROM work_context_approvals WHERE approval_id=?1 AND preview_id=?2",
            params![id.as_str(), preview_ref.id().as_str()],
            |row| row.get(0),
        ).map_err(WorkContextStoreError::from)?;
        decode_work_context_mutation_approval(&document, &preview).map_err(protocol)
    }).transpose()?;
    if encode_work_context_mutation_submission(
        &preview,
        approval.as_ref(),
        submission.submitted_at(),
    )
    .map_err(protocol)?
        != submission_document
    {
        return Err(WorkContextStoreError::Corrupt("submission_document"));
    }
    let receipt = decode_work_context_mutation_receipt(&receipt_document, &submission, &preview)
        .map_err(protocol)?;
    if receipt.id().as_str() != receipt_id
        || receipt.preview() != &preview_ref
        || receipt.outcome().as_str() != outcome
        || receipt.recorded_at().as_millis() != recorded_at
        || encode_work_context_mutation_receipt(&receipt).map_err(protocol)? != receipt_document
    {
        return Err(WorkContextStoreError::Corrupt("receipt_projection"));
    }
    Ok(ReceiptLookup::Found(receipt))
}
fn consume_approval(
    tx: &Transaction<'_>,
    preview: &MutationPreview,
    submission: &MutationSubmission,
    submission_document: &[u8],
    recorded_at_ms: i64,
) -> Stored<()> {
    match (preview.approval(), submission.approval_id()) {
        (MutationApprovalRequirement::NotRequired, None) => {
            let expected =
                encode_work_context_mutation_submission(preview, None, submission.submitted_at())
                    .map_err(protocol)?;
            if expected != submission_document {
                return Err(WorkContextStoreError::ApprovalMismatch);
            }
            Ok(())
        }
        (MutationApprovalRequirement::NotRequired, Some(_)) => {
            Err(WorkContextStoreError::ApprovalMismatch)
        }
        (MutationApprovalRequirement::Required, None) => {
            Err(WorkContextStoreError::ApprovalRequired)
        }
        (MutationApprovalRequirement::Required, Some(id)) => {
            let row:Option<(Vec<u8>,i64,Option<i64>)>=tx.query_row("SELECT approval_document,expires_at_ms,consumed_at_ms FROM work_context_approvals WHERE approval_id=?1 AND preview_id=?2",params![id.as_str(),preview.preview().id().as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let Some((document, expires, consumed)) = row else {
                return Err(WorkContextStoreError::ApprovalMismatch);
            };
            if consumed.is_some() {
                return Err(WorkContextStoreError::ApprovalConsumed);
            }
            let approval =
                decode_work_context_mutation_approval(&document, preview).map_err(protocol)?;
            if approval.expires_at().as_millis() != expires
                || approval.id() != id
                || encode_work_context_mutation_approval(&approval).map_err(protocol)? != document
            {
                return Err(WorkContextStoreError::Corrupt("approval_projection"));
            }
            if approval.decision() != MutationApprovalDecision::Granted {
                return Err(WorkContextStoreError::ApprovalDenied);
            }
            if recorded_at_ms >= expires {
                return Err(WorkContextStoreError::ApprovalExpired);
            }
            let expected = encode_work_context_mutation_submission(
                preview,
                Some(&approval),
                submission.submitted_at(),
            )
            .map_err(protocol)?;
            if expected != submission_document {
                return Err(WorkContextStoreError::ApprovalMismatch);
            }
            let changed=tx.execute("UPDATE work_context_approvals SET consumed_at_ms=?1 WHERE approval_id=?2 AND consumed_at_ms IS NULL",params![recorded_at_ms,id.as_str()])?;
            if changed != 1 {
                return Err(WorkContextStoreError::ApprovalConsumed);
            }
            Ok(())
        }
    }
}
fn external_effect(intent: &WorkContextMutationIntent) -> Option<&'static str> {
    match intent {
        WorkContextMutationIntent::CreateAttemptWorkspace(_) => Some("create_attempt_workspace"),
        WorkContextMutationIntent::ResumeAttemptWorkspace(_) => Some("resume_attempt_workspace"),
        WorkContextMutationIntent::ResumeSession(_) => Some("resume_session"),
        _ => None,
    }
}
fn effect_target(intent: &WorkContextMutationIntent) -> Stored<&ExpectedWorkContext> {
    match intent {
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => Ok(value.user_workspace()),
        WorkContextMutationIntent::ResumeAttemptWorkspace(value) => Ok(value.target()),
        WorkContextMutationIntent::ResumeSession(value) => Ok(value.target()),
        _ => Err(WorkContextStoreError::InvalidField("external_effect")),
    }
}
fn resolve_inventory_context(
    identity: &WorkContextIdentity,
    map: &BTreeMap<WorkContextIdentity, WorkContextRecord>,
) -> Stored<(ProjectId, Vec<WorkContextIdentity>)> {
    let mut parents = Vec::new();
    let mut cursor = identity.clone();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor.clone()) {
            return Err(WorkContextStoreError::Corrupt("relation_cycle"));
        }
        let record = map
            .get(&cursor)
            .ok_or(WorkContextStoreError::Corrupt("inventory_record"))?;
        if let WorkContextIdentity::Project(project) = record.identity() {
            return Ok((project.clone(), parents));
        }
        let mut next = None;
        for relation in record.relations() {
            parents.push(relation.target().clone());
            if relation.target().kind() == WorkContextTargetKind::Project
                && let WorkContextIdentity::Project(project) = relation.target()
            {
                return Ok((project.clone(), parents));
            }
            if matches!(
                relation.target().kind(),
                WorkContextTargetKind::Checkout
                    | WorkContextTargetKind::UserWorkspace
                    | WorkContextTargetKind::AttemptWorkspace
                    | WorkContextTargetKind::Session
            ) {
                next = Some(relation.target().clone());
            }
        }
        cursor = next.ok_or(WorkContextStoreError::Corrupt("project_ancestry"))?;
    }
}
