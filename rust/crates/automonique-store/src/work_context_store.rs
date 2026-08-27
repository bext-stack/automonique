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

use crate::{StoreError, validate_database_path};

pub const WORK_CONTEXT_STORE_SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE work_context_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    inventory_generation INTEGER NOT NULL CHECK(inventory_generation>=1)
) STRICT;
INSERT INTO work_context_meta(singleton,inventory_generation) VALUES(1,1);

CREATE TABLE work_context_records (
    identity_key TEXT PRIMARY KEY,
    identity_kind TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    resource_authority TEXT,
    resource_kind TEXT,
    revision INTEGER NOT NULL CHECK(revision>=1),
    lifecycle TEXT NOT NULL,
    record_document BLOB NOT NULL
) STRICT;
CREATE TABLE work_context_relations (
    source_key TEXT NOT NULL REFERENCES work_context_records(identity_key) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    relation_kind TEXT NOT NULL,
    target_key TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_authority TEXT,
    target_resource_kind TEXT,
    PRIMARY KEY(source_key,ordinal),
    UNIQUE(source_key,relation_kind,target_key)
) STRICT;
CREATE INDEX work_context_relations_target ON work_context_relations(target_key,source_key);

CREATE TABLE work_context_expected_revisions (
    identity_key TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK(revision>=1),
    owning_project_id TEXT,
    external_resolution TEXT CHECK(external_resolution IS NULL OR external_resolution IN ('available','unavailable'))
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

CREATE TABLE work_context_cursor_state (
    cursor TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    inventory_generation INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
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
    approval: MutationApprovalRequirement,
}
impl MutationPolicyDecision {
    #[must_use]
    pub const fn new(
        authenticated_actor: Actor,
        serving_authority: ResourceAuthority,
        actor_authority: WorkContextAuthority,
        inherited_authority: WorkContextAuthority,
        approval: MutationApprovalRequirement,
    ) -> Self {
        Self {
            authenticated_actor,
            serving_authority,
            actor_authority,
            inherited_authority,
            approval,
        }
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

    pub fn put_authoritative_record(&mut self, record: &WorkContextRecord) -> Stored<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        store_record(&tx, record)?;
        bump_generation(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn put_external_snapshot(
        &mut self,
        expected: &ExpectedWorkContext,
        resolution: ExternalParentResolution,
        owning_project: Option<&ProjectId>,
    ) -> Stored<()> {
        if expected.identity().kind() != WorkContextTargetKind::Repository {
            return Err(WorkContextStoreError::InvalidField("external_identity"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO work_context_expected_revisions(identity_key,revision,owning_project_id,external_resolution) VALUES(?1,?2,?3,?4) ON CONFLICT(identity_key) DO UPDATE SET revision=excluded.revision,owning_project_id=excluded.owning_project_id,external_resolution=excluded.external_resolution", params![identity_key(expected.identity()),to_i64(expected.revision())?,owning_project.map(ProjectId::as_str),resolution.as_str()])?;
        tx.commit()?;
        Ok(())
    }

    pub fn record(&self, identity: &WorkContextIdentity) -> Stored<Option<WorkContextRecord>> {
        load_record(&self.connection, identity)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_mutation(
        &mut self,
        proposal: &WorkContextMutationProposal,
        policy: &MutationPolicyDecision,
        issued_at_ms: i64,
        expires_at_ms: i64,
        nonces: &mut impl WorkContextNonceSource,
    ) -> Stored<PreviewAdmission> {
        if issued_at_ms < 0 || expires_at_ms <= issued_at_ms {
            return Err(WorkContextStoreError::InvalidField("preview_expiry"));
        }
        let proposal_document =
            encode_work_context_mutation_proposal(proposal).map_err(protocol)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scope = (
            proposal.actor().tenant(),
            proposal.actor().id(),
            proposal.authority().as_str(),
            proposal.idempotency_key().as_str(),
        );
        let replay: Option<(Vec<u8>, Vec<u8>)> = tx.query_row("SELECT proposal_document,preview_document FROM work_context_previews WHERE tenant=?1 AND actor_id=?2 AND serving_authority=?3 AND idempotency_key=?4", params![scope.0,scope.1,scope.2,scope.3], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((stored_proposal, stored_preview)) = replay {
            if stored_proposal != proposal_document {
                return Err(WorkContextStoreError::BodyConflict);
            }
            return Ok(PreviewAdmission::Replay(
                decode_work_context_mutation_preview(&stored_preview).map_err(protocol)?,
            ));
        }
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
        let parent_snapshots =
            resolve_parent_snapshots(&tx, proposal.intent(), proposal.actor().tenant())?;
        verify_expected_and_graph(&tx, proposal.intent(), proposal.actor().tenant())?;
        let current = proposal
            .intent()
            .expected_target()
            .map(|target| load_required_record(&tx, target.identity()))
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
            requested,
            policy.approval,
            EpochMillis::from_millis(issued_at_ms),
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
        decided_by: Actor,
        decided_at_ms: i64,
        expires_at_ms: i64,
    ) -> Stored<MutationApproval> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview(&tx, preview_ref)?;
        if preview.approval() != MutationApprovalRequirement::Required {
            return Err(WorkContextStoreError::ApprovalMismatch);
        }
        let approval = MutationApproval::new(
            id,
            &preview,
            work_context_mutation_preview_digest(&preview).map_err(protocol)?,
            decision,
            decided_by,
            EpochMillis::from_millis(decided_at_ms),
            EpochMillis::from_millis(expires_at_ms),
        )
        .map_err(protocol)?;
        let document = encode_work_context_mutation_approval(&approval).map_err(protocol)?;
        tx.execute("INSERT INTO work_context_approvals(approval_id,preview_id,approval_document,expires_at_ms) VALUES(?1,?2,?3,?4)",params![approval.id().as_str(),preview.preview().id().as_str(),document,expires_at_ms])?;
        tx.commit()?;
        Ok(approval)
    }

    pub fn submit_mutation(
        &mut self,
        preview_ref: &MutationPreviewRef,
        submission_document: &[u8],
        policy: &MutationPolicyDecision,
        receipt_id: ReceiptId,
        recorded_at_ms: i64,
    ) -> Stored<ReceiptAdmission> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview(&tx, preview_ref)?;
        let submission = decode_work_context_mutation_submission(submission_document, &preview)
            .map_err(protocol)?;
        let existing: Option<(Vec<u8>,Vec<u8>)> = tx.query_row("SELECT submission_document,receipt_document FROM work_context_receipts WHERE preview_id=?1",[preview_ref.id().as_str()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((stored_submission, stored_receipt)) = existing {
            if stored_submission != submission_document {
                return Err(WorkContextStoreError::BodyConflict);
            }
            return Ok(ReceiptAdmission::Replay(
                decode_work_context_mutation_receipt(&stored_receipt, &submission, &preview)
                    .map_err(protocol)?,
            ));
        }
        recheck_policy(&preview, policy)?;
        if recorded_at_ms < submission.submitted_at().as_millis() {
            return Err(WorkContextStoreError::InvalidField("recorded_at"));
        }
        if submission.submitted_at().as_millis() >= preview.expires_at().as_millis() {
            return Err(WorkContextStoreError::PreviewExpired);
        }
        consume_approval(
            &tx,
            &preview,
            &submission,
            submission_document,
            recorded_at_ms,
        )?;
        recheck_preview_state(&tx, &preview)?;
        let external = external_effect(preview.proposal().intent());
        let outcome = if external.is_some() {
            ReceiptOutcome::Accepted
        } else {
            ReceiptOutcome::Completed
        };
        if external.is_none() {
            store_record(&tx, preview.resulting())?;
            bump_generation(&tx)?;
        }
        let receipt = MutationReceipt::new(
            receipt_id,
            &submission,
            &preview,
            work_context_mutation_preview_digest(&preview).map_err(protocol)?,
            outcome,
            EpochMillis::from_millis(recorded_at_ms),
        )
        .map_err(protocol)?;
        let receipt_document = encode_work_context_mutation_receipt(&receipt).map_err(protocol)?;
        tx.execute("INSERT INTO work_context_receipts(receipt_id,preview_id,submission_document,receipt_document,outcome,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![receipt.id().as_str(),preview_ref.id().as_str(),submission_document,receipt_document,outcome.as_str(),recorded_at_ms])?;
        tx.execute("UPDATE work_context_previews SET submitted_at_ms=?1 WHERE preview_id=?2 AND submitted_at_ms IS NULL",params![submission.submitted_at().as_millis(),preview_ref.id().as_str()])?;
        tx.execute("INSERT INTO work_context_events(preview_id,event_kind,event_document,recorded_at_ms) VALUES(?1,?2,?3,?4)",params![preview_ref.id().as_str(),outcome.as_str(),receipt_document,recorded_at_ms])?;
        if let Some(kind) = external {
            tx.execute("INSERT INTO work_context_outbox(outbox_id,preview_id,effect_kind,effect_document,state,created_at_ms) VALUES(?1,?2,?3,?4,'ready',?5)",params![format!("outbox_{}",preview_ref.id().as_str()),preview_ref.id().as_str(),kind,submission_document,recorded_at_ms])?;
        }
        tx.commit()?;
        Ok(ReceiptAdmission::New(receipt))
    }

    pub fn complete_external_effect(
        &mut self,
        preview_ref: &MutationPreviewRef,
        completed_at_ms: i64,
    ) -> Stored<MutationReceipt> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let preview = load_preview(&tx, preview_ref)?;
        let row: Option<(String,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT r.receipt_id,r.submission_document,o.effect_document FROM work_context_receipts r JOIN work_context_outbox o ON o.preview_id=r.preview_id WHERE r.preview_id=?1 AND o.state='ready'",[preview_ref.id().as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let Some((receipt_id, submission_document, _)) = row else {
            return Err(WorkContextStoreError::NotFound);
        };
        let submission = decode_work_context_mutation_submission(&submission_document, &preview)
            .map_err(protocol)?;
        store_record(&tx, preview.resulting())?;
        bump_generation(&tx)?;
        let receipt = MutationReceipt::new(
            ReceiptId::new(receipt_id).map_err(|_| WorkContextStoreError::Corrupt("receipt_id"))?,
            &submission,
            &preview,
            work_context_mutation_preview_digest(&preview).map_err(protocol)?,
            ReceiptOutcome::Completed,
            EpochMillis::from_millis(completed_at_ms),
        )
        .map_err(protocol)?;
        let document = encode_work_context_mutation_receipt(&receipt).map_err(protocol)?;
        tx.execute("UPDATE work_context_receipts SET receipt_document=?1,outcome='completed',recorded_at_ms=?2 WHERE preview_id=?3",params![document,completed_at_ms,preview_ref.id().as_str()])?;
        tx.execute("UPDATE work_context_outbox SET state='completed',completed_at_ms=?1 WHERE preview_id=?2 AND state='ready'",params![completed_at_ms,preview_ref.id().as_str()])?;
        tx.execute("INSERT INTO work_context_events(preview_id,event_kind,event_document,recorded_at_ms) VALUES(?1,'completed',?2,?3)",params![preview_ref.id().as_str(),document,completed_at_ms])?;
        tx.commit()?;
        Ok(receipt)
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
                    "SELECT tenant,actor_id FROM work_context_cursor_state WHERE cursor=?1",
                    [after.as_str()],
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
        let all = load_all_records(&self.connection)?;
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
            self.connection.execute("INSERT OR REPLACE INTO work_context_cursor_state(cursor,tenant,actor_id,inventory_generation,created_at_ms) VALUES(?1,?2,?3,?4,?5)",params![cursor.as_str(),actor.tenant(),actor.id(),generation,now_ms])?;
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
    tx.execute_batch(SCHEMA_V1)?;
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
fn store_record(tx: &Transaction<'_>, record: &WorkContextRecord) -> Stored<()> {
    let key = identity_key(record.identity());
    let coordinate = record.identity().v1_coordinate();
    let document = record_document(record)?;
    let existing: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT revision,record_document FROM work_context_records WHERE identity_key=?1",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((revision, stored)) = existing {
        if revision == to_i64(record.revision())? && stored == document {
            return Ok(());
        }
        if revision.checked_add(1) != Some(to_i64(record.revision())?) {
            return Err(WorkContextStoreError::StaleRevision);
        }
    }
    tx.execute("INSERT INTO work_context_records(identity_key,identity_kind,identity_id,resource_authority,resource_kind,revision,lifecycle,record_document) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(identity_key) DO UPDATE SET revision=excluded.revision,lifecycle=excluded.lifecycle,record_document=excluded.record_document",params![key,record.identity().kind().as_str(),record.identity().id(),coordinate.map(|v|v.authority.as_str()),coordinate.map(|v|v.kind.as_str()),to_i64(record.revision())?,record.lifecycle().as_str(),document])?;
    tx.execute(
        "DELETE FROM work_context_relations WHERE source_key=?1",
        [&key],
    )?;
    for (ordinal, relation) in record.relations().iter().enumerate() {
        let c = relation.target().v1_coordinate();
        tx.execute("INSERT INTO work_context_relations(source_key,ordinal,relation_kind,target_key,target_kind,target_id,target_authority,target_resource_kind) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![key,i64::try_from(ordinal).unwrap_or(i64::MAX),relation.kind().as_str(),identity_key(relation.target()),relation.target().kind().as_str(),relation.target().id(),c.map(|v|v.authority.as_str()),c.map(|v|v.kind.as_str())])?;
    }
    tx.execute("INSERT INTO work_context_expected_revisions(identity_key,revision,owning_project_id,external_resolution) VALUES(?1,?2,?3,NULL) ON CONFLICT(identity_key) DO UPDATE SET revision=excluded.revision,owning_project_id=excluded.owning_project_id,external_resolution=NULL",params![key,to_i64(record.revision())?,direct_project_id(record)])?;
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
fn load_record(
    connection: &Connection,
    identity: &WorkContextIdentity,
) -> Stored<Option<WorkContextRecord>> {
    let row:Option<(Vec<u8>,i64,String)>=connection.query_row("SELECT record_document,revision,lifecycle FROM work_context_records WHERE identity_key=?1",[identity_key(identity)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    row.map(|(bytes, revision, lifecycle)| {
        let record = decode_record_document(&bytes)?;
        if record.identity() != identity
            || to_i64(record.revision())? != revision
            || record.lifecycle().as_str() != lifecycle
        {
            return Err(WorkContextStoreError::Corrupt("record_projection"));
        }
        Ok(record)
    })
    .transpose()
}
fn load_required_record(
    connection: &Connection,
    identity: &WorkContextIdentity,
) -> Stored<WorkContextRecord> {
    load_record(connection, identity)?.ok_or(WorkContextStoreError::NotFound)
}
fn load_all_records(connection: &Connection) -> Stored<Vec<WorkContextRecord>> {
    let mut statement = connection
        .prepare("SELECT record_document FROM work_context_records ORDER BY identity_key")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    rows.map(|row| decode_record_document(&row?)).collect()
}
fn bump_generation(tx: &Transaction<'_>) -> Stored<()> {
    tx.execute("UPDATE work_context_meta SET inventory_generation=inventory_generation+1 WHERE singleton=1",[])?;
    Ok(())
}
fn load_preview(
    connection: &Connection,
    preview_ref: &MutationPreviewRef,
) -> Stored<MutationPreview> {
    let row:Option<(i64,Vec<u8>)>=connection.query_row("SELECT preview_revision,preview_document FROM work_context_previews WHERE preview_id=?1",[preview_ref.id().as_str()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
    let Some((revision, bytes)) = row else {
        return Err(WorkContextStoreError::NotFound);
    };
    if revision != to_i64(preview_ref.revision())? {
        return Err(WorkContextStoreError::StaleRevision);
    };
    decode_work_context_mutation_preview(&bytes).map_err(protocol)
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
    _tenant: &str,
) -> Stored<Vec<ResolvedParentSnapshot>> {
    parent_expected_values(intent)
        .into_iter()
        .map(|expected| {
            if expected.identity().kind() == WorkContextTargetKind::Repository {
                let row: Option<(i64, Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT revision,owning_project_id,external_resolution FROM work_context_expected_revisions WHERE identity_key=?1",
                        [identity_key(expected.identity())],
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
                let record = load_required_record(tx, expected.identity())?;
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
                "SELECT revision FROM work_context_expected_revisions WHERE identity_key=?1",
                [identity_key(expected.identity())],
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
            same_project(tx, v.host_setup().identity(), v.project().identity())?;
            reject_mismatched_optional_project(
                tx,
                v.repository().identity(),
                v.project().identity(),
            )?
        }
        WorkContextMutationIntent::CreateUserWorkspace(v) => {
            same_project(tx, v.checkout().identity(), v.project().identity())?
        }
        WorkContextMutationIntent::CreateAttemptWorkspace(v) => {
            ensure_active(tx, v.user_workspace().identity())?
        }
        _ => {}
    };
    for expected in expected_values(intent) {
        if !matches!(
            expected.identity().kind(),
            WorkContextTargetKind::Repository | WorkContextTargetKind::PlatformSession
        ) && intent.is_create()
        {
            ensure_active(tx, expected.identity())?
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
fn ensure_active(connection: &Connection, identity: &WorkContextIdentity) -> Stored<()> {
    if load_required_record(connection, identity)?.lifecycle() != WorkContextLifecycle::Active {
        return Err(WorkContextStoreError::GraphConflict);
    }
    Ok(())
}
fn same_project(
    connection: &Connection,
    child: &WorkContextIdentity,
    project: &WorkContextIdentity,
) -> Stored<()> {
    let owner: Option<String> = connection
        .query_row(
            "SELECT owning_project_id FROM work_context_expected_revisions WHERE identity_key=?1",
            [identity_key(child)],
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
    child: &WorkContextIdentity,
    project: &WorkContextIdentity,
) -> Stored<()> {
    let owner: Option<String> = connection
        .query_row(
            "SELECT owning_project_id FROM work_context_expected_revisions WHERE identity_key=?1",
            [identity_key(child)],
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
        let loaded = load_required_record(tx, current.identity())?;
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
    Ok(())
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
            if approval.decision() != MutationApprovalDecision::Granted {
                return Err(WorkContextStoreError::ApprovalDenied);
            }
            if submission.submitted_at().as_millis() >= expires {
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
