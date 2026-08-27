// SPDX-License-Identifier: Elastic-2.0

//! Authoritative durable index for Platform v2 external work and orchestration lineage.
//!
//! External provider records and internal orchestration records occupy separate
//! tables and identity domains. Every durable identity is namespaced by tenant
//! and bound to an exact user workspace, but neither table uses that workspace
//! identity alone as its primary key. Mutations use immediate transactions,
//! exact idempotent replay, and revision fencing. Projection and receipt reads
//! require one caller-authorized tenant/project/workspace scope.
//!
//! This index stores normalized contract fields only. It stores no provider
//! payload, provider URL, repository ref, command fragment, or host path. It
//! does not execute workspace intents or claim that a stored observation is
//! fresh; those remain responsibilities of the caller and lifecycle runtime.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform_v2::{
    AttemptWorkspaceId, NegotiatedPlatform, PaneId, ProjectId, UserWorkspaceId, WorkSessionId,
};
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkAuthorityId, ExternalWorkIdentity,
    ExternalWorkItem, ExternalWorkKey, ExternalWorkProvider, ExternalWorkScope, ExternalWorkState,
    LatestUsefulMessage, LineageFreshness, LineageFreshnessState, LineageMessage, LineageOrigin,
    LineageProjection, LineageStatus, MAX_LINEAGE_RECORDS, OrchestrationDecisionGateId,
    OrchestrationDispatchId, OrchestrationHeartbeatId, OrchestrationIdentity, OrchestrationKind,
    OrchestrationQuestionId, OrchestrationRecord, OrchestrationRunId, OrchestrationTaskId,
    OrchestrationWorkerId, WorkspaceCancelIntent, WorkspaceIntent, WorkspaceIntentConflict,
    WorkspaceIntentId, WorkspaceIntentOutcome, WorkspaceIntentReconciliation,
};
use automonique_protocol::platform_v2_lineage_api::require_lineage_v2;
use automonique_protocol::primitives::Revision;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{StoreError, validate_database_path};

/// The only lineage-index schema this build reads or writes.
pub const LINEAGE_INDEX_SCHEMA_VERSION: u32 = 4;
const LEGACY_TENANT: &str = "legacy-unqualified";

const SCHEMA_V4: &str = r#"
CREATE TABLE lineage_external_work (
    tenant TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('github','gitlab','linear','jira_compatible')),
    authority_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    work_key TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    external_state TEXT NOT NULL CHECK (external_state IN ('open','moved','closed')),
    moved_provider TEXT,
    moved_authority_id TEXT,
    moved_scope TEXT,
    moved_key TEXT,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 1),
    stale_after_ms INTEGER NOT NULL CHECK (stale_after_ms >= 1),
    freshness_state TEXT NOT NULL CHECK (freshness_state IN ('fresh','stale')),
    latest_message TEXT,
    latest_observed_at_ms INTEGER CHECK (latest_observed_at_ms >= 1),
    origin_attempt_id TEXT,
    origin_session_id TEXT,
    origin_pane_id TEXT,
    PRIMARY KEY (tenant, provider, authority_id, scope, work_key),
    UNIQUE (tenant, provider, authority_id, scope, work_key, workspace_id),
    CHECK ((external_state = 'moved') = (moved_provider IS NOT NULL)),
    CHECK ((moved_provider IS NULL) = (moved_scope IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_authority_id IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_key IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
    CHECK (origin_session_id IS NULL OR origin_attempt_id IS NOT NULL),
    CHECK (origin_pane_id IS NULL OR origin_session_id IS NOT NULL)
) STRICT;

CREATE INDEX lineage_external_by_workspace
    ON lineage_external_work(tenant, workspace_id, provider, authority_id, scope, work_key);

CREATE TABLE lineage_orchestration (
    tenant TEXT NOT NULL,
    orchestration_kind TEXT NOT NULL CHECK (orchestration_kind IN
        ('run','task','dispatch','worker','heartbeat','question','decision_gate')),
    orchestration_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
    external_authority_id TEXT,
    external_scope TEXT,
    external_key TEXT,
    parent_kind TEXT,
    parent_id TEXT,
    status_kind TEXT NOT NULL CHECK (status_kind IN ('working','blocked','waiting','done')),
    status_message TEXT,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 1),
    stale_after_ms INTEGER NOT NULL CHECK (stale_after_ms >= 1),
    freshness_state TEXT NOT NULL CHECK (freshness_state IN ('fresh','stale')),
    latest_message TEXT,
    latest_observed_at_ms INTEGER CHECK (latest_observed_at_ms >= 1),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    origin_attempt_id TEXT,
    origin_session_id TEXT,
    origin_pane_id TEXT,
    PRIMARY KEY (tenant, orchestration_kind, orchestration_id),
    UNIQUE (tenant, orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (tenant, external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(tenant, provider, authority_id, scope, work_key, workspace_id),
    FOREIGN KEY (tenant, parent_kind, parent_id, workspace_id)
        REFERENCES lineage_orchestration(tenant, orchestration_kind, orchestration_id, workspace_id),
    CHECK ((external_provider IS NULL) = (external_scope IS NULL)),
    CHECK ((external_provider IS NULL) = (external_authority_id IS NULL)),
    CHECK ((external_provider IS NULL) = (external_key IS NULL)),
    CHECK ((parent_kind IS NULL) = (parent_id IS NULL)),
    CHECK (parent_kind IS NULL OR orchestration_kind != parent_kind OR orchestration_id != parent_id),
    CHECK ((status_kind = 'working') = (status_message IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
    CHECK (origin_session_id IS NULL OR origin_attempt_id IS NOT NULL),
    CHECK (origin_pane_id IS NULL OR origin_session_id IS NOT NULL),
    CHECK (
        (orchestration_kind = 'run' AND parent_kind IS NULL) OR
        (orchestration_kind = 'task' AND parent_kind IN ('run','task')) OR
        (orchestration_kind = 'dispatch' AND parent_kind = 'task') OR
        (orchestration_kind = 'worker' AND parent_kind = 'dispatch') OR
        (orchestration_kind = 'heartbeat' AND parent_kind = 'worker') OR
        (orchestration_kind = 'question' AND parent_kind = 'task') OR
        (orchestration_kind = 'decision_gate' AND parent_kind IN ('question','task'))
    )
) STRICT;

CREATE INDEX lineage_orchestration_by_workspace
    ON lineage_orchestration(tenant, workspace_id, orchestration_kind, orchestration_id);

CREATE TABLE lineage_workspace_intents (
    tenant TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('create','resume','cancel')),
    task_kind TEXT NOT NULL CHECK (task_kind = 'task'),
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
    external_authority_id TEXT,
    external_scope TEXT,
    external_key TEXT,
    base_selector TEXT,
    branch_selector TEXT,
    expected_revision INTEGER CHECK (expected_revision >= 1),
    target_intent_id TEXT,
    revision INTEGER NOT NULL CHECK (revision >= 1 AND revision <= 2),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('accepted','unknown','created','resumed','cancelled','conflict')),
    outcome_conflict TEXT CHECK (outcome_conflict IN
        ('duplicate_intake','task_already_bound','workspace_not_found','revision_mismatch',
         'external_work_moved','external_work_closed','orphan_dispatch','stale_heartbeat',
         'question_pending','creation_cancelled')),
    outcome_workspace_id TEXT,
    reconciliation TEXT NOT NULL CHECK (reconciliation IN ('final','poll_receipt')),
    PRIMARY KEY (tenant, intent_id),
    FOREIGN KEY (tenant, task_kind, task_id, workspace_id)
        REFERENCES lineage_orchestration(tenant, orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (tenant, external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(tenant, provider, authority_id, scope, work_key, workspace_id),
    FOREIGN KEY (tenant, target_intent_id)
        REFERENCES lineage_workspace_intents(tenant, intent_id),
    CHECK (
        (intent_kind = 'create' AND external_provider IS NOT NULL AND external_authority_id IS NOT NULL AND external_scope IS NOT NULL
            AND external_key IS NOT NULL AND base_selector IS NOT NULL
            AND branch_selector IS NOT NULL AND expected_revision IS NULL AND target_intent_id IS NULL) OR
        (intent_kind = 'resume' AND external_provider IS NULL AND external_authority_id IS NULL AND external_scope IS NULL
            AND external_key IS NULL AND base_selector IS NULL
            AND branch_selector IS NULL AND expected_revision IS NOT NULL AND target_intent_id IS NULL) OR
        (intent_kind = 'cancel' AND external_provider IS NULL AND external_authority_id IS NULL AND external_scope IS NULL
            AND external_key IS NULL AND base_selector IS NULL
            AND branch_selector IS NULL AND expected_revision IS NOT NULL AND target_intent_id IS NOT NULL)
    ),
    CHECK (
        (outcome_kind IN ('accepted','unknown') AND outcome_conflict IS NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'poll_receipt') OR
        (outcome_kind = 'conflict' AND outcome_conflict IS NOT NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'final') OR
        (outcome_kind IN ('created','resumed') AND outcome_conflict IS NULL
            AND outcome_workspace_id = workspace_id AND reconciliation = 'final') OR
        (outcome_kind = 'cancelled' AND outcome_conflict IS NULL
            AND outcome_workspace_id IS NULL AND target_intent_id IS NOT NULL AND reconciliation = 'final')
    ),
    CHECK (
        (intent_kind = 'create' AND outcome_kind IN ('accepted','unknown','created','conflict')) OR
        (intent_kind = 'resume' AND outcome_kind IN ('accepted','unknown','resumed','conflict')) OR
        (intent_kind = 'cancel' AND outcome_kind IN ('accepted','unknown','cancelled','conflict'))
    ),
    CHECK (
        (reconciliation = 'poll_receipt' AND revision = 1) OR
        (reconciliation = 'final' AND revision IN (1,2))
    )
) STRICT;

CREATE UNIQUE INDEX lineage_cancel_by_target
    ON lineage_workspace_intents(tenant,target_intent_id) WHERE intent_kind = 'cancel';
"#;

// Exact short-lived unscoped schema accepted only as a v2 migration source.
const SCHEMA_V2: &str = include_str!("lineage_index_v2.sql");
// Exact tenant-scoped schema accepted only as a v3 migration source.
const SCHEMA_V3: &str = include_str!("lineage_index_v3.sql");

/// Stable lineage-index refusal.
#[derive(Debug)]
pub enum LineageIndexError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    DuplicateIntake,
    IdentityConflict,
    RevisionMismatch { expected: u64, durable: u64 },
    NotFound(&'static str),
    OrphanDispatch,
    Unauthorized,
    ProjectionTooLarge,
    Corrupt(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl LineageIndexError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::DuplicateIntake => "duplicate_intake",
            Self::IdentityConflict => "identity_conflict",
            Self::RevisionMismatch { .. } => "revision_mismatch",
            Self::NotFound(_) => "not_found",
            Self::OrphanDispatch => "orphan_dispatch",
            Self::Unauthorized => "unauthorized",
            Self::ProjectionTooLarge => "projection_too_large",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }

    #[must_use]
    pub const fn conflict(&self) -> Option<WorkspaceIntentConflict> {
        match self {
            Self::DuplicateIntake => Some(WorkspaceIntentConflict::DuplicateIntake),
            Self::RevisionMismatch { .. } => Some(WorkspaceIntentConflict::RevisionMismatch),
            Self::OrphanDispatch => Some(WorkspaceIntentConflict::OrphanDispatch),
            _ => None,
        }
    }
}

impl fmt::Display for LineageIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaVersion { found, supported } => {
                write!(
                    formatter,
                    "lineage index schema {found} is unsupported; expected {supported}"
                )
            }
            Self::RevisionMismatch { expected, durable } => {
                write!(
                    formatter,
                    "expected revision {expected}, durable revision is {durable}"
                )
            }
            Self::InsecurePath(reason) => {
                write!(formatter, "insecure lineage index path: {reason}")
            }
            Self::NotFound(entity) => write!(formatter, "no such {entity}"),
            Self::Io(error) => write!(formatter, "lineage index filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "lineage index sqlite error: {error}"),
            other => formatter.write_str(other.category()),
        }
    }
}

impl Error for LineageIndexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LineageIndexError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for LineageIndexError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub type Indexed<T> = Result<T, LineageIndexError>;

/// Result of an idempotent authoritative write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteAdmission {
    Inserted { revision: u64 },
    Updated { revision: u64 },
    Replayed { revision: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredWorkspaceIntent {
    pub request_digest: [u8; 32],
    pub revision: Revision,
    pub intent: WorkspaceIntent,
    pub outcome: WorkspaceIntentOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIntentExecutionReceipt {
    pub intent_id: WorkspaceIntentId,
    pub request_digest: [u8; 32],
    pub outcome: WorkspaceIntentOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentAuthorizationScope {
    tenant: String,
    project: ProjectId,
    workspace: UserWorkspaceId,
}

impl IntentAuthorizationScope {
    pub fn new(tenant: String, project: ProjectId, workspace: UserWorkspaceId) -> Indexed<Self> {
        validate_tenant(&tenant)?;
        Ok(Self {
            tenant,
            project,
            workspace,
        })
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }
    pub const fn workspace(&self) -> &UserWorkspaceId {
        &self.workspace
    }
}

impl WriteAdmission {
    #[must_use]
    pub const fn revision(self) -> u64 {
        match self {
            Self::Inserted { revision }
            | Self::Updated { revision }
            | Self::Replayed { revision } => revision,
        }
    }
}

/// Authoritative normalized lineage index.
#[derive(Debug)]
pub struct LineageIndex {
    connection: Connection,
    path: PathBuf,
}

impl LineageIndex {
    pub fn open(path: impl AsRef<Path>) -> Indexed<Self> {
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

    /// Insert one tenant-scoped external item or replay the exact durable intake.
    pub fn intake_external(
        &mut self,
        tenant: &str,
        item: &ExternalWorkItem,
    ) -> Indexed<WriteAdmission> {
        validate_tenant(tenant)?;
        if item.revision() != Revision::FIRST {
            return Err(LineageIndexError::InvalidField("revision"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_external(&transaction, tenant, item.identity())? {
            return if &existing == item {
                Ok(WriteAdmission::Replayed {
                    revision: existing.revision().get(),
                })
            } else {
                Err(LineageIndexError::DuplicateIntake)
            };
        }
        validate_moved_target(&transaction, tenant, item)?;
        insert_external(&transaction, tenant, item)?;
        transaction.commit()?;
        Ok(WriteAdmission::Inserted { revision: 1 })
    }

    /// Revision-fenced update of external source state and observation fields.
    pub fn update_external(
        &mut self,
        tenant: &str,
        item: &ExternalWorkItem,
        expected_revision: Revision,
    ) -> Indexed<WriteAdmission> {
        validate_tenant(tenant)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read_external(&transaction, tenant, item.identity())?
            .ok_or(LineageIndexError::NotFound("external work item"))?;
        if &existing == item {
            if expected_revision.get().checked_add(1) == Some(existing.revision().get()) {
                return Ok(WriteAdmission::Replayed {
                    revision: existing.revision().get(),
                });
            }
            return Err(LineageIndexError::RevisionMismatch {
                expected: expected_revision.get(),
                durable: existing.revision().get(),
            });
        }
        if existing.revision() != expected_revision {
            return Err(LineageIndexError::RevisionMismatch {
                expected: expected_revision.get(),
                durable: existing.revision().get(),
            });
        }
        let next = expected_revision
            .get()
            .checked_add(1)
            .ok_or(LineageIndexError::InvalidField("revision"))?;
        if item.revision().get() != next
            || item.workspace() != existing.workspace()
            || item.origin() != existing.origin()
            || !external_transition_allowed(&existing, item)
        {
            return Err(LineageIndexError::IdentityConflict);
        }
        validate_moved_target(&transaction, tenant, item)?;
        update_external_row(&transaction, tenant, item, expected_revision)?;
        transaction.commit()?;
        Ok(WriteAdmission::Updated { revision: next })
    }

    /// Insert, update, or replay one internal orchestration record.
    pub fn record_orchestration(
        &mut self,
        tenant: &str,
        record: &OrchestrationRecord,
        expected_revision: Option<Revision>,
    ) -> Indexed<WriteAdmission> {
        validate_tenant(tenant)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_record_links(&transaction, tenant, record)?;
        let existing = read_orchestration(&transaction, tenant, record.identity())?;
        match (existing, expected_revision) {
            (None, None) => {
                if record.revision() != Revision::FIRST {
                    return Err(LineageIndexError::InvalidField("revision"));
                }
                insert_orchestration(&transaction, tenant, record)?;
                transaction.commit()?;
                Ok(WriteAdmission::Inserted { revision: 1 })
            }
            (Some((stored, revision)), expected) if &stored == record => match expected {
                None if revision == 1 => Ok(WriteAdmission::Replayed { revision }),
                Some(value)
                    if value.get() == revision || value.get().checked_add(1) == Some(revision) =>
                {
                    Ok(WriteAdmission::Replayed { revision })
                }
                Some(value) => Err(LineageIndexError::RevisionMismatch {
                    expected: value.get(),
                    durable: revision,
                }),
                None => Err(LineageIndexError::IdentityConflict),
            },
            (Some(_), None) => Err(LineageIndexError::IdentityConflict),
            (None, Some(_)) => Err(LineageIndexError::NotFound("orchestration record")),
            (Some((stored, durable)), Some(expected)) => {
                if durable != expected.get() {
                    return Err(LineageIndexError::RevisionMismatch {
                        expected: expected.get(),
                        durable,
                    });
                }
                if stored.workspace() != record.workspace()
                    || stored.origin() != record.origin()
                    || stored.parent() != record.parent()
                    || stored.external_work() != record.external_work()
                    || record.revision().get() != durable.saturating_add(1)
                    || !observation_monotonic(
                        stored.freshness().observed_at_ms(),
                        stored.latest_useful_message(),
                        record.freshness().observed_at_ms(),
                        record.latest_useful_message(),
                    )
                    || (matches!(stored.status(), LineageStatus::Done(_))
                        && stored.status() != record.status())
                {
                    return Err(LineageIndexError::IdentityConflict);
                }
                let next = durable
                    .checked_add(1)
                    .ok_or(LineageIndexError::InvalidField("revision"))?;
                update_orchestration_row(&transaction, tenant, record, expected, next)?;
                transaction.commit()?;
                Ok(WriteAdmission::Updated { revision: next })
            }
        }
    }

    /// Persist a create, resume, or cancellation decision under its exact
    /// tenant-scoped idempotent intent ID.
    pub fn record_intent(
        &mut self,
        tenant: &str,
        intent: &WorkspaceIntent,
        outcome: &WorkspaceIntentOutcome,
    ) -> Indexed<WriteAdmission> {
        validate_tenant(tenant)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_digest = intent_digest(intent);
        if let Some(existing) = read_intent(&transaction, tenant, intent.intent_id().as_str())? {
            return if existing.request_digest == request_digest {
                Ok(WriteAdmission::Replayed {
                    revision: from_db(existing.revision, "intent_revision")?,
                })
            } else {
                Err(LineageIndexError::IdentityConflict)
            };
        }
        let fingerprint =
            intent_fingerprint(&transaction, tenant, intent, outcome, request_digest)?;
        if matches!(outcome, WorkspaceIntentOutcome::Cancelled(_)) {
            apply_cancellation(&transaction, tenant, &fingerprint)?;
        }
        insert_intent(&transaction, tenant, &fingerprint)?;
        transaction.commit()?;
        Ok(WriteAdmission::Inserted { revision: 1 })
    }

    /// Transactionally advance a durable accepted/unknown receipt to one exact
    /// final decision. This records reconciliation only; it never executes the
    /// underlying workspace operation.
    pub fn reconcile_intent(
        &mut self,
        tenant: &str,
        receipt: &WorkspaceIntentExecutionReceipt,
    ) -> Indexed<WriteAdmission> {
        validate_tenant(tenant)?;
        if receipt.outcome.reconciliation() != WorkspaceIntentReconciliation::Final {
            return Err(LineageIndexError::InvalidField("final_outcome"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read_intent(&transaction, tenant, receipt.intent_id.as_str())?
            .ok_or(LineageIndexError::NotFound("workspace intent"))?;
        if existing.request_digest != receipt.request_digest {
            return Err(LineageIndexError::IdentityConflict);
        }
        if existing.reconciliation == "final" {
            let revision = from_db(existing.revision, "intent_revision")?;
            let stored = existing.into_stored()?;
            return if stored.outcome == receipt.outcome {
                Ok(WriteAdmission::Replayed { revision })
            } else {
                Err(LineageIndexError::IdentityConflict)
            };
        }
        let (outcome_kind, outcome_conflict, outcome_workspace, valid_final) =
            match &receipt.outcome {
                WorkspaceIntentOutcome::Created(workspace) => (
                    "created",
                    None,
                    Some(workspace.as_str()),
                    existing.intent_kind == "create" && workspace.as_str() == existing.workspace,
                ),
                WorkspaceIntentOutcome::Resumed(workspace) => (
                    "resumed",
                    None,
                    Some(workspace.as_str()),
                    existing.intent_kind == "resume" && workspace.as_str() == existing.workspace,
                ),
                WorkspaceIntentOutcome::Cancelled(target) => (
                    "cancelled",
                    None,
                    None,
                    existing.intent_kind == "cancel"
                        && existing.target_intent_id.as_deref() == Some(target.as_str()),
                ),
                WorkspaceIntentOutcome::Conflict(value) => {
                    ("conflict", Some(value.as_str()), None, true)
                }
                WorkspaceIntentOutcome::Accepted | WorkspaceIntentOutcome::Unknown => {
                    ("", None, None, false)
                }
            };
        if !valid_final {
            return Err(LineageIndexError::IdentityConflict);
        }
        if matches!(receipt.outcome, WorkspaceIntentOutcome::Cancelled(_)) {
            apply_cancellation(&transaction, tenant, &existing)?;
        }
        let changed = transaction.execute(
            "UPDATE lineage_workspace_intents SET outcome_kind=?3,outcome_conflict=?4,outcome_workspace_id=?5,reconciliation='final',revision=2 WHERE tenant=?1 AND intent_id=?2 AND request_digest=?6 AND reconciliation='poll_receipt' AND revision=1",
            params![tenant, receipt.intent_id.as_str(), outcome_kind, outcome_conflict, outcome_workspace, receipt.request_digest.as_slice()],
        )?;
        if changed != 1 {
            return Err(LineageIndexError::IdentityConflict);
        }
        transaction.commit()?;
        Ok(WriteAdmission::Updated { revision: 2 })
    }

    /// Look up an intent only through an exact negotiated tenant/project/workspace scope.
    pub fn intent_authorized(
        &self,
        negotiated: &NegotiatedPlatform,
        scope: &IntentAuthorizationScope,
        id: &WorkspaceIntentId,
        authorize: impl FnOnce(&IntentAuthorizationScope) -> bool,
    ) -> Indexed<Option<StoredWorkspaceIntent>> {
        require_lineage_v2(negotiated)
            .map_err(|_| LineageIndexError::InvalidField("negotiated_platform"))?;
        if !authorize(scope) {
            return Err(LineageIndexError::Unauthorized);
        }
        let Some(value) = read_intent(&self.connection, scope.tenant(), id.as_str())? else {
            return Ok(None);
        };
        if value.workspace != scope.workspace.as_str() {
            return Ok(None);
        }
        value.into_stored().map(Some)
    }

    /// Resolve an opaque intent id with one indexed lookup, then authorize its
    /// stored workspace against the server-owned bounded visibility set.
    pub fn intent_authorized_in_workspaces(
        &self,
        negotiated: &NegotiatedPlatform,
        tenant: &str,
        id: &WorkspaceIntentId,
        allowed: &BTreeSet<UserWorkspaceId>,
    ) -> Indexed<Option<StoredWorkspaceIntent>> {
        require_lineage_v2(negotiated)
            .map_err(|_| LineageIndexError::InvalidField("negotiated_platform"))?;
        validate_tenant(tenant)?;
        let Some(value) = read_intent(&self.connection, tenant, id.as_str())? else {
            return Ok(None);
        };
        let workspace = UserWorkspaceId::new(value.workspace.clone())
            .map_err(|_| LineageIndexError::Corrupt("intent_workspace"))?;
        if !allowed.contains(&workspace) {
            return Ok(None);
        }
        value.into_stored().map(Some)
    }

    /// Resolve a task only through a server-owned bounded workspace set.
    /// Possession of an orchestration task ID is not workspace authority.
    pub fn task_workspace_authorized(
        &self,
        tenant: &str,
        task: &automonique_protocol::platform_v2_lineage::OrchestrationTaskId,
        allowed: &BTreeSet<UserWorkspaceId>,
    ) -> Indexed<Option<UserWorkspaceId>> {
        validate_tenant(tenant)?;
        let identity = OrchestrationIdentity::Task(task.clone());
        let Some((record, _)) = read_orchestration(&self.connection, tenant, &identity)? else {
            return Ok(None);
        };
        if !allowed.contains(record.workspace()) {
            return Ok(None);
        }
        Ok(Some(record.workspace().clone()))
    }

    /// Rebuild the bounded projection for one exact authorized tenant/workspace.
    fn projection_unchecked(
        &self,
        tenant: &str,
        workspace: &UserWorkspaceId,
    ) -> Indexed<LineageProjection> {
        let external = read_external_workspace(&self.connection, tenant, workspace)?;
        let orchestration = read_orchestration_workspace(&self.connection, tenant, workspace)?;
        if external.len().saturating_add(orchestration.len()) > MAX_LINEAGE_RECORDS {
            return Err(LineageIndexError::ProjectionTooLarge);
        }
        LineageProjection::new(workspace.clone(), external, orchestration)
            .map_err(|_| LineageIndexError::Corrupt("projection"))
    }

    /// Rebuild a projection only after the embedding authority accepts the
    /// exact tenant/project/workspace scope. This is the daemon-facing seam;
    /// the index does not infer authorization from possession of identifiers.
    pub fn projection_authorized(
        &self,
        negotiated: &NegotiatedPlatform,
        scope: &IntentAuthorizationScope,
        authorize: impl FnOnce(&IntentAuthorizationScope) -> bool,
    ) -> Indexed<LineageProjection> {
        require_lineage_v2(negotiated)
            .map_err(|_| LineageIndexError::InvalidField("negotiated_platform"))?;
        if !authorize(scope) {
            return Err(LineageIndexError::Unauthorized);
        }
        self.projection_unchecked(scope.tenant(), scope.workspace())
    }
}

fn external_transition_allowed(previous: &ExternalWorkItem, next: &ExternalWorkItem) -> bool {
    observation_monotonic(
        previous.freshness().observed_at_ms(),
        previous.latest_useful_message(),
        next.freshness().observed_at_ms(),
        next.latest_useful_message(),
    ) && match previous.state() {
        ExternalWorkState::Open => matches!(
            next.state(),
            ExternalWorkState::Open | ExternalWorkState::Moved | ExternalWorkState::Closed
        ),
        ExternalWorkState::Moved => {
            next.state() == ExternalWorkState::Moved && previous.moved_to() == next.moved_to()
        }
        ExternalWorkState::Closed => next.state() == ExternalWorkState::Closed,
    }
}

fn validate_moved_target(
    connection: &Connection,
    tenant: &str,
    item: &ExternalWorkItem,
) -> Indexed<()> {
    let Some(target_id) = item.moved_to() else {
        return Ok(());
    };
    let target = read_external(connection, tenant, target_id)?
        .ok_or(LineageIndexError::NotFound("moved external work target"))?;
    if target.workspace() != item.workspace() || !target.origin().refines(item.origin()) {
        return Err(LineageIndexError::IdentityConflict);
    }
    let mut cursor = Some(target);
    let mut steps = 0usize;
    while let Some(current) = cursor {
        if current.identity() == item.identity() || steps >= MAX_LINEAGE_RECORDS {
            return Err(LineageIndexError::IdentityConflict);
        }
        cursor = current
            .moved_to()
            .map(|identity| {
                read_external(connection, tenant, identity)?.ok_or(LineageIndexError::NotFound(
                    "moved external work descendant",
                ))
            })
            .transpose()?;
        steps += 1;
    }
    Ok(())
}

fn observation_monotonic(
    previous_observed: u64,
    previous_message: Option<&LatestUsefulMessage>,
    next_observed: u64,
    next_message: Option<&LatestUsefulMessage>,
) -> bool {
    if next_observed < previous_observed {
        return false;
    }
    match (previous_message, next_message) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(previous), Some(next)) => {
            next.observed_at_ms() > previous.observed_at_ms()
                || (next.observed_at_ms() == previous.observed_at_ms() && next == previous)
        }
    }
}

fn validate_record_links(
    connection: &Connection,
    tenant: &str,
    record: &OrchestrationRecord,
) -> Indexed<()> {
    if let Some(external) = record.external_work() {
        let item = read_external(connection, tenant, external)?
            .ok_or(LineageIndexError::NotFound("external work item"))?;
        if item.workspace() != record.workspace() {
            return Err(LineageIndexError::IdentityConflict);
        }
        if !record.origin().refines(item.origin()) {
            return Err(LineageIndexError::IdentityConflict);
        }
    }
    if let Some(parent) = record.parent() {
        let parent = read_orchestration(connection, tenant, parent)?
            .ok_or(LineageIndexError::OrphanDispatch)?;
        if parent.0.workspace() != record.workspace() {
            return Err(LineageIndexError::IdentityConflict);
        }
        if !record.origin().refines(parent.0.origin()) {
            return Err(LineageIndexError::IdentityConflict);
        }
    }
    Ok(())
}

fn insert_external(connection: &Connection, tenant: &str, item: &ExternalWorkItem) -> Indexed<()> {
    let moved = item.moved_to();
    let latest = item.latest_useful_message();
    connection.execute(
        "INSERT INTO lineage_external_work VALUES
         (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![
            tenant,
            item.identity().provider().as_str(),
            item.identity().authority().as_str(),
            item.identity().scope().as_str(),
            item.identity().key().as_str(),
            item.workspace().as_str(),
            to_db(item.revision().get(), "revision")?,
            item.state().as_str(),
            moved.map(|value| value.provider().as_str()),
            moved.map(|value| value.authority().as_str()),
            moved.map(|value| value.scope().as_str()),
            moved.map(|value| value.key().as_str()),
            to_db(item.freshness().observed_at_ms(), "observed_at_ms")?,
            to_db(item.freshness().stale_after_ms(), "stale_after_ms")?,
            item.freshness().state().as_str(),
            latest.map(|value| value.text().as_str()),
            latest
                .map(|value| to_db(value.observed_at_ms(), "latest_observed_at_ms"))
                .transpose()?,
            item.origin().attempt().map(|value| value.as_str()),
            item.origin().session().map(|value| value.as_str()),
            item.origin().pane().map(|value| value.as_str()),
        ],
    )?;
    Ok(())
}

fn update_external_row(
    connection: &Connection,
    tenant: &str,
    item: &ExternalWorkItem,
    expected: Revision,
) -> Indexed<()> {
    let moved = item.moved_to();
    let latest = item.latest_useful_message();
    let changed = connection.execute(
        "UPDATE lineage_external_work SET revision=?7,external_state=?8,moved_provider=?9,
         moved_authority_id=?10,moved_scope=?11,moved_key=?12,observed_at_ms=?13,stale_after_ms=?14,freshness_state=?15,
         latest_message=?16,latest_observed_at_ms=?17
         WHERE tenant=?1 AND provider=?2 AND authority_id=?3 AND scope=?4 AND work_key=?5 AND revision=?6",
        params![
            tenant,
            item.identity().provider().as_str(),
            item.identity().authority().as_str(),
            item.identity().scope().as_str(),
            item.identity().key().as_str(),
            to_db(expected.get(), "revision")?,
            to_db(item.revision().get(), "revision")?,
            item.state().as_str(),
            moved.map(|value| value.provider().as_str()),
            moved.map(|value| value.authority().as_str()),
            moved.map(|value| value.scope().as_str()),
            moved.map(|value| value.key().as_str()),
            to_db(item.freshness().observed_at_ms(), "observed_at_ms")?,
            to_db(item.freshness().stale_after_ms(), "stale_after_ms")?,
            item.freshness().state().as_str(),
            latest.map(|value| value.text().as_str()),
            latest
                .map(|value| to_db(value.observed_at_ms(), "latest_observed_at_ms"))
                .transpose()?,
        ],
    )?;
    if changed != 1 {
        return Err(LineageIndexError::Corrupt("external_update"));
    }
    Ok(())
}

fn status_parts(status: &LineageStatus) -> (&'static str, Option<&str>) {
    match status {
        LineageStatus::Working => ("working", None),
        LineageStatus::Blocked(value) => ("blocked", Some(value.as_str())),
        LineageStatus::Waiting(value) => ("waiting", Some(value.as_str())),
        LineageStatus::Done(value) => ("done", Some(value.as_str())),
    }
}

fn insert_orchestration(
    connection: &Connection,
    tenant: &str,
    record: &OrchestrationRecord,
) -> Indexed<()> {
    write_orchestration(connection, tenant, record, None, 1, true)
}

fn update_orchestration_row(
    connection: &Connection,
    tenant: &str,
    record: &OrchestrationRecord,
    expected: Revision,
    next: u64,
) -> Indexed<()> {
    write_orchestration(connection, tenant, record, Some(expected), next, false)
}

fn write_orchestration(
    connection: &Connection,
    tenant: &str,
    record: &OrchestrationRecord,
    expected: Option<Revision>,
    revision: u64,
    insert: bool,
) -> Indexed<()> {
    let external = record.external_work();
    let parent = record.parent();
    let latest = record.latest_useful_message();
    let (status_kind, status_message) = status_parts(record.status());
    let values = params![
        tenant,
        record.identity().kind().as_str(),
        record.identity().id(),
        record.workspace().as_str(),
        external.map(|value| value.provider().as_str()),
        external.map(|value| value.authority().as_str()),
        external.map(|value| value.scope().as_str()),
        external.map(|value| value.key().as_str()),
        parent.map(|value| value.kind().as_str()),
        parent.map(OrchestrationIdentity::id),
        status_kind,
        status_message,
        to_db(record.freshness().observed_at_ms(), "observed_at_ms")?,
        to_db(record.freshness().stale_after_ms(), "stale_after_ms")?,
        record.freshness().state().as_str(),
        latest.map(|value| value.text().as_str()),
        latest
            .map(|value| to_db(value.observed_at_ms(), "latest_observed_at_ms"))
            .transpose()?,
        to_db(revision, "revision")?,
        record.origin().attempt().map(|value| value.as_str()),
        record.origin().session().map(|value| value.as_str()),
        record.origin().pane().map(|value| value.as_str()),
        expected
            .map(|value| to_db(value.get(), "revision"))
            .transpose()?,
    ];
    let changed = if insert {
        connection.execute(
            "INSERT INTO lineage_orchestration
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21
             WHERE ?22 IS NULL",
            values,
        )?
    } else {
        connection.execute(
            "UPDATE lineage_orchestration SET status_kind=?11,status_message=?12,observed_at_ms=?13,
             stale_after_ms=?14,freshness_state=?15,latest_message=?16,latest_observed_at_ms=?17,revision=?18
             WHERE tenant=?1 AND orchestration_kind=?2 AND orchestration_id=?3 AND revision=?22", values)?
    };
    if changed != 1 {
        return Err(LineageIndexError::Corrupt("orchestration_write"));
    }
    Ok(())
}

#[derive(Debug)]
struct RawExternal {
    provider: String,
    authority: String,
    scope: String,
    key: String,
    workspace: String,
    revision: i64,
    state: String,
    moved_provider: Option<String>,
    moved_authority: Option<String>,
    moved_scope: Option<String>,
    moved_key: Option<String>,
    observed_at_ms: i64,
    stale_after_ms: i64,
    freshness_state: String,
    latest_message: Option<String>,
    latest_observed_at_ms: Option<i64>,
    origin_attempt: Option<String>,
    origin_session: Option<String>,
    origin_pane: Option<String>,
}

const EXTERNAL_COLUMNS: &str = "provider,authority_id,scope,work_key,workspace_id,revision,external_state,
    moved_provider,moved_authority_id,moved_scope,moved_key,observed_at_ms,stale_after_ms,freshness_state,
    latest_message,latest_observed_at_ms,origin_attempt_id,origin_session_id,origin_pane_id";

fn raw_external(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawExternal> {
    Ok(RawExternal {
        provider: row.get(0)?,
        authority: row.get(1)?,
        scope: row.get(2)?,
        key: row.get(3)?,
        workspace: row.get(4)?,
        revision: row.get(5)?,
        state: row.get(6)?,
        moved_provider: row.get(7)?,
        moved_authority: row.get(8)?,
        moved_scope: row.get(9)?,
        moved_key: row.get(10)?,
        observed_at_ms: row.get(11)?,
        stale_after_ms: row.get(12)?,
        freshness_state: row.get(13)?,
        latest_message: row.get(14)?,
        latest_observed_at_ms: row.get(15)?,
        origin_attempt: row.get(16)?,
        origin_session: row.get(17)?,
        origin_pane: row.get(18)?,
    })
}

fn read_external(
    connection: &Connection,
    tenant: &str,
    identity: &ExternalWorkIdentity,
) -> Indexed<Option<ExternalWorkItem>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {EXTERNAL_COLUMNS} FROM lineage_external_work
                  WHERE tenant=?1 AND provider=?2 AND authority_id=?3 AND scope=?4 AND work_key=?5"
            ),
            params![
                tenant,
                identity.provider().as_str(),
                identity.authority().as_str(),
                identity.scope().as_str(),
                identity.key().as_str()
            ],
            raw_external,
        )
        .optional()?;
    raw.map(decode_external).transpose()
}

fn read_external_workspace(
    connection: &Connection,
    tenant: &str,
    workspace: &UserWorkspaceId,
) -> Indexed<Vec<ExternalWorkItem>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {EXTERNAL_COLUMNS} FROM lineage_external_work WHERE tenant=?1 AND workspace_id=?2
         ORDER BY provider,authority_id,scope,work_key LIMIT ?3"
    ))?;
    let limit = i64::try_from(MAX_LINEAGE_RECORDS + 1)
        .map_err(|_| LineageIndexError::InvalidField("limit"))?;
    let rows = statement.query_map(params![tenant, workspace.as_str(), limit], raw_external)?;
    rows.map(|row| {
        row.map_err(LineageIndexError::from)
            .and_then(decode_external)
    })
    .collect()
}

fn decode_external(raw: RawExternal) -> Indexed<ExternalWorkItem> {
    let identity = decode_external_identity(&raw.provider, &raw.authority, &raw.scope, &raw.key)?;
    let moved_to = match (
        raw.moved_provider,
        raw.moved_authority,
        raw.moved_scope,
        raw.moved_key,
    ) {
        (None, None, None, None) => None,
        (Some(provider), Some(authority), Some(scope), Some(key)) => Some(
            decode_external_identity(&provider, &authority, &scope, &key)?,
        ),
        _ => return Err(LineageIndexError::Corrupt("moved_identity")),
    };
    let freshness = LineageFreshness::new(
        from_db(raw.observed_at_ms, "observed_at_ms")?,
        from_db(raw.stale_after_ms, "stale_after_ms")?,
        parse_freshness(&raw.freshness_state)?,
    )
    .map_err(|_| LineageIndexError::Corrupt("freshness"))?;
    let latest = match (raw.latest_message, raw.latest_observed_at_ms) {
        (None, None) => None,
        (Some(message), Some(observed)) => Some(
            LatestUsefulMessage::new(
                LineageMessage::new(message)
                    .map_err(|_| LineageIndexError::Corrupt("latest_message"))?,
                from_db(observed, "latest_observed_at_ms")?,
            )
            .map_err(|_| LineageIndexError::Corrupt("latest_message"))?,
        ),
        _ => return Err(LineageIndexError::Corrupt("latest_message")),
    };
    ExternalWorkItem::new_with_origin(
        identity,
        decode_origin(
            raw.workspace,
            raw.origin_attempt,
            raw.origin_session,
            raw.origin_pane,
        )?,
        Revision::new(from_db(raw.revision, "revision")?)
            .map_err(|_| LineageIndexError::Corrupt("revision"))?,
        parse_external_state(&raw.state)?,
        moved_to,
        freshness,
        latest,
    )
    .map_err(|_| LineageIndexError::Corrupt("external_work_item"))
}

fn decode_origin(
    workspace: String,
    attempt: Option<String>,
    session: Option<String>,
    pane: Option<String>,
) -> Indexed<LineageOrigin> {
    LineageOrigin::new(
        UserWorkspaceId::new(workspace).map_err(|_| LineageIndexError::Corrupt("workspace_id"))?,
        attempt
            .map(AttemptWorkspaceId::new)
            .transpose()
            .map_err(|_| LineageIndexError::Corrupt("origin_attempt_id"))?,
        session
            .map(WorkSessionId::new)
            .transpose()
            .map_err(|_| LineageIndexError::Corrupt("origin_session_id"))?,
        pane.map(PaneId::new)
            .transpose()
            .map_err(|_| LineageIndexError::Corrupt("origin_pane_id"))?,
    )
    .map_err(|_| LineageIndexError::Corrupt("origin"))
}

fn decode_external_identity(
    provider: &str,
    authority: &str,
    scope: &str,
    key: &str,
) -> Indexed<ExternalWorkIdentity> {
    Ok(ExternalWorkIdentity::new(
        ExternalWorkProvider::parse(provider)
            .map_err(|_| LineageIndexError::Corrupt("provider"))?,
        ExternalWorkAuthorityId::new(authority)
            .map_err(|_| LineageIndexError::Corrupt("external_authority"))?,
        ExternalWorkScope::new(scope).map_err(|_| LineageIndexError::Corrupt("scope"))?,
        ExternalWorkKey::new(key).map_err(|_| LineageIndexError::Corrupt("work_key"))?,
    ))
}

fn parse_external_state(value: &str) -> Indexed<ExternalWorkState> {
    ExternalWorkState::ALL
        .into_iter()
        .find(|state| state.as_str() == value)
        .ok_or(LineageIndexError::Corrupt("external_state"))
}

fn parse_freshness(value: &str) -> Indexed<LineageFreshnessState> {
    LineageFreshnessState::ALL
        .into_iter()
        .find(|state| state.as_str() == value)
        .ok_or(LineageIndexError::Corrupt("freshness_state"))
}

#[derive(Debug)]
struct RawOrchestration {
    kind: String,
    id: String,
    workspace: String,
    external_provider: Option<String>,
    external_authority: Option<String>,
    external_scope: Option<String>,
    external_key: Option<String>,
    parent_kind: Option<String>,
    parent_id: Option<String>,
    status_kind: String,
    status_message: Option<String>,
    observed_at_ms: i64,
    stale_after_ms: i64,
    freshness_state: String,
    latest_message: Option<String>,
    latest_observed_at_ms: Option<i64>,
    revision: i64,
    origin_attempt: Option<String>,
    origin_session: Option<String>,
    origin_pane: Option<String>,
}

const ORCHESTRATION_COLUMNS: &str = "orchestration_kind,orchestration_id,workspace_id,
    external_provider,external_authority_id,external_scope,external_key,parent_kind,parent_id,status_kind,status_message,
    observed_at_ms,stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision,
    origin_attempt_id,origin_session_id,origin_pane_id";

fn raw_orchestration(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawOrchestration> {
    Ok(RawOrchestration {
        kind: row.get(0)?,
        id: row.get(1)?,
        workspace: row.get(2)?,
        external_provider: row.get(3)?,
        external_authority: row.get(4)?,
        external_scope: row.get(5)?,
        external_key: row.get(6)?,
        parent_kind: row.get(7)?,
        parent_id: row.get(8)?,
        status_kind: row.get(9)?,
        status_message: row.get(10)?,
        observed_at_ms: row.get(11)?,
        stale_after_ms: row.get(12)?,
        freshness_state: row.get(13)?,
        latest_message: row.get(14)?,
        latest_observed_at_ms: row.get(15)?,
        revision: row.get(16)?,
        origin_attempt: row.get(17)?,
        origin_session: row.get(18)?,
        origin_pane: row.get(19)?,
    })
}

fn read_orchestration(
    connection: &Connection,
    tenant: &str,
    identity: &OrchestrationIdentity,
) -> Indexed<Option<(OrchestrationRecord, u64)>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {ORCHESTRATION_COLUMNS} FROM lineage_orchestration
                  WHERE tenant=?1 AND orchestration_kind=?2 AND orchestration_id=?3"
            ),
            params![tenant, identity.kind().as_str(), identity.id()],
            raw_orchestration,
        )
        .optional()?;
    raw.map(decode_orchestration).transpose()
}

fn read_orchestration_workspace(
    connection: &Connection,
    tenant: &str,
    workspace: &UserWorkspaceId,
) -> Indexed<Vec<OrchestrationRecord>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ORCHESTRATION_COLUMNS} FROM lineage_orchestration WHERE tenant=?1 AND workspace_id=?2
         ORDER BY orchestration_kind,orchestration_id LIMIT ?3"
    ))?;
    let limit = i64::try_from(MAX_LINEAGE_RECORDS + 1)
        .map_err(|_| LineageIndexError::InvalidField("limit"))?;
    let rows = statement.query_map(
        params![tenant, workspace.as_str(), limit],
        raw_orchestration,
    )?;
    rows.map(|row| {
        row.map_err(LineageIndexError::from)
            .and_then(decode_orchestration)
            .map(|(record, _)| record)
    })
    .collect()
}

fn decode_orchestration(raw: RawOrchestration) -> Indexed<(OrchestrationRecord, u64)> {
    let identity = decode_orchestration_identity(&raw.kind, &raw.id)?;
    let external = match (
        raw.external_provider,
        raw.external_authority,
        raw.external_scope,
        raw.external_key,
    ) {
        (None, None, None, None) => None,
        (Some(provider), Some(authority), Some(scope), Some(key)) => Some(
            decode_external_identity(&provider, &authority, &scope, &key)?,
        ),
        _ => return Err(LineageIndexError::Corrupt("external_identity")),
    };
    let parent = match (raw.parent_kind, raw.parent_id) {
        (None, None) => None,
        (Some(kind), Some(id)) => Some(decode_orchestration_identity(&kind, &id)?),
        _ => return Err(LineageIndexError::Corrupt("parent_identity")),
    };
    let status = decode_status(&raw.status_kind, raw.status_message)?;
    let freshness = LineageFreshness::new(
        from_db(raw.observed_at_ms, "observed_at_ms")?,
        from_db(raw.stale_after_ms, "stale_after_ms")?,
        parse_freshness(&raw.freshness_state)?,
    )
    .map_err(|_| LineageIndexError::Corrupt("freshness"))?;
    let latest = match (raw.latest_message, raw.latest_observed_at_ms) {
        (None, None) => None,
        (Some(message), Some(observed)) => Some(
            LatestUsefulMessage::new(
                LineageMessage::new(message)
                    .map_err(|_| LineageIndexError::Corrupt("latest_message"))?,
                from_db(observed, "latest_observed_at_ms")?,
            )
            .map_err(|_| LineageIndexError::Corrupt("latest_message"))?,
        ),
        _ => return Err(LineageIndexError::Corrupt("latest_message")),
    };
    let durable_revision = from_db(raw.revision, "revision")?;
    let origin = decode_origin(
        raw.workspace,
        raw.origin_attempt,
        raw.origin_session,
        raw.origin_pane,
    )?;
    let record = OrchestrationRecord::new_with_origin(
        identity,
        origin,
        external,
        parent,
        status,
        freshness,
        latest,
        Revision::new(durable_revision).map_err(|_| LineageIndexError::Corrupt("revision"))?,
    )
    .map_err(|_| LineageIndexError::Corrupt("orchestration_record"))?;
    Ok((record, durable_revision))
}

fn parse_orchestration_kind(value: &str) -> Indexed<OrchestrationKind> {
    OrchestrationKind::ALL
        .into_iter()
        .find(|kind| kind.as_str() == value)
        .ok_or(LineageIndexError::Corrupt("orchestration_kind"))
}

fn decode_orchestration_identity(kind: &str, id: &str) -> Indexed<OrchestrationIdentity> {
    let invalid = |_| LineageIndexError::Corrupt("orchestration_id");
    Ok(match parse_orchestration_kind(kind)? {
        OrchestrationKind::Run => {
            OrchestrationIdentity::Run(OrchestrationRunId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::Task => {
            OrchestrationIdentity::Task(OrchestrationTaskId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::Dispatch => {
            OrchestrationIdentity::Dispatch(OrchestrationDispatchId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::Worker => {
            OrchestrationIdentity::Worker(OrchestrationWorkerId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::Heartbeat => {
            OrchestrationIdentity::Heartbeat(OrchestrationHeartbeatId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::Question => {
            OrchestrationIdentity::Question(OrchestrationQuestionId::new(id).map_err(invalid)?)
        }
        OrchestrationKind::DecisionGate => OrchestrationIdentity::DecisionGate(
            OrchestrationDecisionGateId::new(id).map_err(invalid)?,
        ),
    })
}

fn decode_status(kind: &str, message: Option<String>) -> Indexed<LineageStatus> {
    let checked = |value| {
        LineageMessage::new(value).map_err(|_| LineageIndexError::Corrupt("status_message"))
    };
    match (kind, message) {
        ("working", None) => Ok(LineageStatus::Working),
        ("blocked", Some(value)) => Ok(LineageStatus::Blocked(checked(value)?)),
        ("waiting", Some(value)) => Ok(LineageStatus::Waiting(checked(value)?)),
        ("done", Some(value)) => Ok(LineageStatus::Done(checked(value)?)),
        _ => Err(LineageIndexError::Corrupt("status_kind")),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntentFingerprint {
    intent_id: String,
    request_digest: [u8; 32],
    intent_kind: &'static str,
    task_id: String,
    workspace: String,
    external_provider: Option<String>,
    external_authority: Option<String>,
    external_scope: Option<String>,
    external_key: Option<String>,
    base_selector: Option<String>,
    branch_selector: Option<String>,
    expected_revision: Option<i64>,
    target_intent_id: Option<String>,
    revision: i64,
    outcome_kind: &'static str,
    outcome_conflict: Option<&'static str>,
    outcome_workspace: Option<String>,
    reconciliation: &'static str,
}

impl IntentFingerprint {
    fn into_stored(self) -> Indexed<StoredWorkspaceIntent> {
        let intent_id = WorkspaceIntentId::new(self.intent_id)
            .map_err(|_| LineageIndexError::Corrupt("intent_id"))?;
        let task = OrchestrationTaskId::new(self.task_id)
            .map_err(|_| LineageIndexError::Corrupt("task_id"))?;
        let intent = match self.intent_kind {
            "create" => WorkspaceIntent::Create(
                automonique_protocol::platform_v2_lineage::WorkspaceCreateIntent::new(
                    intent_id,
                    task,
                    decode_external_identity(
                        self.external_provider
                            .as_deref()
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                        self.external_authority
                            .as_deref()
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                        self.external_scope
                            .as_deref()
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                        self.external_key
                            .as_deref()
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                    )?,
                    BaseSelectorId::new(
                        self.base_selector
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                    )
                    .map_err(|_| LineageIndexError::Corrupt("base_selector"))?,
                    BranchSelectorId::new(
                        self.branch_selector
                            .ok_or(LineageIndexError::Corrupt("create_intent"))?,
                    )
                    .map_err(|_| LineageIndexError::Corrupt("branch_selector"))?,
                ),
            ),
            "resume" => WorkspaceIntent::Resume(
                automonique_protocol::platform_v2_lineage::WorkspaceResumeIntent::new(
                    intent_id,
                    task,
                    UserWorkspaceId::new(self.workspace.clone())
                        .map_err(|_| LineageIndexError::Corrupt("workspace_id"))?,
                    Revision::new(from_db(
                        self.expected_revision
                            .ok_or(LineageIndexError::Corrupt("resume_intent"))?,
                        "expected_revision",
                    )?)
                    .map_err(|_| LineageIndexError::Corrupt("expected_revision"))?,
                ),
            ),
            "cancel" => WorkspaceIntent::Cancel(
                WorkspaceCancelIntent::new(
                    intent_id,
                    WorkspaceIntentId::new(
                        self.target_intent_id
                            .clone()
                            .ok_or(LineageIndexError::Corrupt("cancel_intent"))?,
                    )
                    .map_err(|_| LineageIndexError::Corrupt("target_intent_id"))?,
                    UserWorkspaceId::new(self.workspace.clone())
                        .map_err(|_| LineageIndexError::Corrupt("workspace_id"))?,
                    Revision::new(from_db(
                        self.expected_revision
                            .ok_or(LineageIndexError::Corrupt("cancel_intent"))?,
                        "expected_revision",
                    )?)
                    .map_err(|_| LineageIndexError::Corrupt("expected_revision"))?,
                )
                .map_err(|_| LineageIndexError::Corrupt("cancel_intent"))?,
            ),
            _ => return Err(LineageIndexError::Corrupt("intent_kind")),
        };
        let outcome = match self.outcome_kind {
            "accepted" => WorkspaceIntentOutcome::Accepted,
            "unknown" => WorkspaceIntentOutcome::Unknown,
            "created" => WorkspaceIntentOutcome::Created(
                UserWorkspaceId::new(
                    self.outcome_workspace
                        .ok_or(LineageIndexError::Corrupt("intent_outcome"))?,
                )
                .map_err(|_| LineageIndexError::Corrupt("intent_outcome"))?,
            ),
            "resumed" => WorkspaceIntentOutcome::Resumed(
                UserWorkspaceId::new(
                    self.outcome_workspace
                        .ok_or(LineageIndexError::Corrupt("intent_outcome"))?,
                )
                .map_err(|_| LineageIndexError::Corrupt("intent_outcome"))?,
            ),
            "cancelled" => WorkspaceIntentOutcome::Cancelled(
                WorkspaceIntentId::new(
                    self.target_intent_id
                        .ok_or(LineageIndexError::Corrupt("intent_outcome"))?,
                )
                .map_err(|_| LineageIndexError::Corrupt("intent_outcome"))?,
            ),
            "conflict" => WorkspaceIntentOutcome::Conflict(parse_conflict(
                self.outcome_conflict
                    .ok_or(LineageIndexError::Corrupt("intent_outcome"))?,
            )?),
            _ => return Err(LineageIndexError::Corrupt("intent_outcome")),
        };
        Ok(StoredWorkspaceIntent {
            request_digest: self.request_digest,
            revision: Revision::new(from_db(self.revision, "intent_revision")?)
                .map_err(|_| LineageIndexError::Corrupt("intent_revision"))?,
            intent,
            outcome,
        })
    }
}

fn intent_digest(intent: &WorkspaceIntent) -> [u8; 32] {
    fn field(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let mut hasher = Sha256::new();
    field(&mut hasher, "automonique.platform/v2/workspace-intent/v1");
    match intent {
        WorkspaceIntent::Create(value) => {
            field(&mut hasher, "create");
            field(&mut hasher, value.intent_id().as_str());
            field(&mut hasher, value.task().as_str());
            field(&mut hasher, value.external_work().provider().as_str());
            field(&mut hasher, value.external_work().authority().as_str());
            field(&mut hasher, value.external_work().scope().as_str());
            field(&mut hasher, value.external_work().key().as_str());
            field(&mut hasher, value.base_selector().as_str());
            field(&mut hasher, value.branch_selector().as_str());
        }
        WorkspaceIntent::Resume(value) => {
            field(&mut hasher, "resume");
            field(&mut hasher, value.intent_id().as_str());
            field(&mut hasher, value.task().as_str());
            field(&mut hasher, value.workspace().as_str());
            hasher.update(value.expected_revision().get().to_be_bytes());
        }
        WorkspaceIntent::Cancel(value) => {
            field(&mut hasher, "cancel");
            field(&mut hasher, value.intent_id().as_str());
            field(&mut hasher, value.target_intent_id().as_str());
            field(&mut hasher, value.workspace().as_str());
            hasher.update(value.expected_revision().get().to_be_bytes());
        }
    }
    hasher.finalize().into()
}

fn intent_fingerprint(
    connection: &Connection,
    tenant: &str,
    intent: &WorkspaceIntent,
    outcome: &WorkspaceIntentOutcome,
    request_digest: [u8; 32],
) -> Indexed<IntentFingerprint> {
    let (
        intent_id,
        intent_kind,
        requested_task_id,
        requested_workspace,
        external,
        base,
        branch,
        expected,
        target_intent_id,
    ) = match intent {
        WorkspaceIntent::Create(request) => (
            request.intent_id().as_str().to_owned(),
            "create",
            Some(request.task().as_str()),
            None,
            Some(request.external_work()),
            Some(request.base_selector().as_str()),
            Some(request.branch_selector().as_str()),
            None,
            None,
        ),
        WorkspaceIntent::Resume(request) => (
            request.intent_id().as_str().to_owned(),
            "resume",
            Some(request.task().as_str()),
            Some(request.workspace()),
            None,
            None,
            None,
            Some(to_db(
                request.expected_revision().get(),
                "expected_revision",
            )?),
            None,
        ),
        WorkspaceIntent::Cancel(request) => (
            request.intent_id().as_str().to_owned(),
            "cancel",
            None,
            Some(request.workspace()),
            None,
            None,
            None,
            Some(to_db(
                request.expected_revision().get(),
                "expected_revision",
            )?),
            Some(request.target_intent_id().as_str().to_owned()),
        ),
    };
    let target = target_intent_id
        .as_deref()
        .map(|target_id| {
            read_intent(connection, tenant, target_id)?
                .ok_or(LineageIndexError::NotFound("target intent"))
        })
        .transpose()?;
    if let Some(target) = &target
        && (target.revision != expected.ok_or(LineageIndexError::IdentityConflict)?
            || requested_workspace.is_none_or(|workspace| workspace.as_str() != target.workspace)
            || target.intent_kind == "cancel"
            || !matches!(target.outcome_kind, "accepted" | "unknown")
            || target.reconciliation != "poll_receipt")
    {
        return Err(LineageIndexError::IdentityConflict);
    }
    let task_id = requested_task_id
        .map(str::to_owned)
        .or_else(|| target.as_ref().map(|value| value.task_id.clone()))
        .ok_or(LineageIndexError::IdentityConflict)?;
    let task_identity = OrchestrationIdentity::Task(
        OrchestrationTaskId::new(&task_id).map_err(|_| LineageIndexError::InvalidField("task"))?,
    );
    let (task, _) = read_orchestration(connection, tenant, &task_identity)?
        .ok_or(LineageIndexError::OrphanDispatch)?;
    if requested_workspace.is_some_and(|workspace| workspace != task.workspace()) {
        return Err(LineageIndexError::IdentityConflict);
    }
    let mut external_state = None;
    if let Some(external) = external {
        let item = read_external(connection, tenant, external)?
            .ok_or(LineageIndexError::NotFound("external work item"))?;
        if item.workspace() != task.workspace() || task.external_work() != Some(external) {
            return Err(LineageIndexError::IdentityConflict);
        }
        external_state = Some(item.state());
    }
    let (outcome_kind, outcome_conflict, outcome_workspace) = match outcome {
        WorkspaceIntentOutcome::Accepted => ("accepted", None, None),
        WorkspaceIntentOutcome::Unknown => ("unknown", None, None),
        WorkspaceIntentOutcome::Created(workspace) if intent_kind == "create" => {
            ("created", None, Some(workspace.as_str().to_owned()))
        }
        WorkspaceIntentOutcome::Resumed(workspace) if intent_kind == "resume" => {
            ("resumed", None, Some(workspace.as_str().to_owned()))
        }
        WorkspaceIntentOutcome::Cancelled(target)
            if intent_kind == "cancel" && target_intent_id.as_deref() == Some(target.as_str()) =>
        {
            ("cancelled", None, None)
        }
        WorkspaceIntentOutcome::Conflict(conflict) => ("conflict", Some(conflict.as_str()), None),
        _ => return Err(LineageIndexError::IdentityConflict),
    };
    if outcome_workspace
        .as_deref()
        .is_some_and(|workspace| workspace != task.workspace().as_str())
    {
        return Err(LineageIndexError::IdentityConflict);
    }
    match external_state {
        Some(ExternalWorkState::Moved)
            if outcome_conflict != Some(WorkspaceIntentConflict::ExternalWorkMoved.as_str()) =>
        {
            return Err(LineageIndexError::IdentityConflict);
        }
        Some(ExternalWorkState::Closed)
            if outcome_conflict != Some(WorkspaceIntentConflict::ExternalWorkClosed.as_str()) =>
        {
            return Err(LineageIndexError::IdentityConflict);
        }
        _ => {}
    }
    Ok(IntentFingerprint {
        intent_id,
        request_digest,
        intent_kind,
        task_id,
        workspace: task.workspace().as_str().to_owned(),
        external_provider: external.map(|value| value.provider().as_str().to_owned()),
        external_authority: external.map(|value| value.authority().as_str().to_owned()),
        external_scope: external.map(|value| value.scope().as_str().to_owned()),
        external_key: external.map(|value| value.key().as_str().to_owned()),
        base_selector: base.map(str::to_owned),
        branch_selector: branch.map(str::to_owned),
        expected_revision: expected,
        target_intent_id,
        revision: 1,
        outcome_kind,
        outcome_conflict,
        outcome_workspace,
        reconciliation: outcome.reconciliation().as_str(),
    })
}

fn insert_intent(connection: &Connection, tenant: &str, value: &IntentFingerprint) -> Indexed<()> {
    connection.execute(
        "INSERT INTO lineage_workspace_intents VALUES
         (?1,?2,?3,?4,'task',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            tenant,
            value.intent_id,
            value.request_digest.as_slice(),
            value.intent_kind,
            value.task_id,
            value.workspace,
            value.external_provider,
            value.external_authority,
            value.external_scope,
            value.external_key,
            value.base_selector,
            value.branch_selector,
            value.expected_revision,
            value.target_intent_id,
            value.revision,
            value.outcome_kind,
            value.outcome_conflict,
            value.outcome_workspace,
            value.reconciliation,
        ],
    )?;
    Ok(())
}

fn apply_cancellation(
    connection: &Connection,
    tenant: &str,
    cancellation: &IntentFingerprint,
) -> Indexed<()> {
    let target = cancellation
        .target_intent_id
        .as_deref()
        .ok_or(LineageIndexError::IdentityConflict)?;
    let expected = cancellation
        .expected_revision
        .ok_or(LineageIndexError::IdentityConflict)?;
    let changed = connection.execute(
        "UPDATE lineage_workspace_intents
         SET outcome_kind='conflict',outcome_conflict='creation_cancelled',outcome_workspace_id=NULL,
             reconciliation='final',revision=2
         WHERE tenant=?1 AND intent_id=?2 AND workspace_id=?3 AND task_id=?4 AND revision=?5
           AND intent_kind IN ('create','resume') AND outcome_kind IN ('accepted','unknown')
           AND reconciliation='poll_receipt'",
        params![
            tenant,
            target,
            cancellation.workspace,
            cancellation.task_id,
            expected
        ],
    )?;
    if changed != 1 {
        return Err(LineageIndexError::IdentityConflict);
    }
    Ok(())
}

fn read_intent(
    connection: &Connection,
    tenant: &str,
    intent_id: &str,
) -> Indexed<Option<IntentFingerprint>> {
    type Raw = (
        String,
        Vec<u8>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
    );
    connection.query_row(
        "SELECT intent_id,request_digest,intent_kind,task_id,workspace_id,external_provider,external_authority_id,external_scope,external_key,base_selector,branch_selector,expected_revision,target_intent_id,revision,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation FROM lineage_workspace_intents WHERE tenant=?1 AND intent_id=?2",
        params![tenant, intent_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?,row.get(16)?,row.get(17)?)))
    .optional()?.map(|raw: Raw| {
            WorkspaceIntentId::new(&raw.0).map_err(|_| LineageIndexError::Corrupt("intent_id"))?;
            let request_digest: [u8;32] = raw.1.clone().try_into().map_err(|_| LineageIndexError::Corrupt("request_digest"))?;
            OrchestrationTaskId::new(&raw.3).map_err(|_| LineageIndexError::Corrupt("task_id"))?;
            UserWorkspaceId::new(&raw.4).map_err(|_| LineageIndexError::Corrupt("workspace_id"))?;
            let intent_kind = match raw.2.as_str() {
                "create" => "create",
                "resume" => "resume",
                "cancel" => "cancel",
                _ => return Err(LineageIndexError::Corrupt("intent_kind")),
            };
            let outcome_kind = match raw.14.as_str() {
                "accepted" => "accepted",
                "unknown" => "unknown",
                "created" => "created",
                "resumed" => "resumed",
                "cancelled" => "cancelled",
                "conflict" => "conflict",
                _ => return Err(LineageIndexError::Corrupt("outcome_kind")),
            };
            let outcome_conflict = raw.15.as_deref().map(parse_conflict).transpose()?;
            if !matches!(
                (intent_kind, outcome_kind),
                ("create", "accepted" | "unknown" | "created" | "conflict")
                    | ("resume", "accepted" | "unknown" | "resumed" | "conflict")
                    | ("cancel", "accepted" | "unknown" | "cancelled" | "conflict")
            ) {
                return Err(LineageIndexError::Corrupt("intent_outcome"));
            }
            match intent_kind {
                "create" => {
                    let (Some(provider), Some(authority), Some(scope), Some(key), Some(base), Some(branch), None, None) =
                        (&raw.5, &raw.6, &raw.7, &raw.8, &raw.9, &raw.10, raw.11, &raw.12)
                    else {
                        return Err(LineageIndexError::Corrupt("create_intent"));
                    };
                    decode_external_identity(provider, authority, scope, key)?;
                    BaseSelectorId::new(base)
                        .map_err(|_| LineageIndexError::Corrupt("base_selector"))?;
                    BranchSelectorId::new(branch)
                        .map_err(|_| LineageIndexError::Corrupt("branch_selector"))?;
                }
                "resume" => {
                    if raw.5.is_some() || raw.6.is_some() || raw.7.is_some() || raw.8.is_some()
                        || raw.9.is_some() || raw.10.is_some() || raw.11.is_none_or(|value| value < 1)
                        || raw.12.is_some()
                    {
                        return Err(LineageIndexError::Corrupt("resume_intent"));
                    }
                }
                "cancel" => {
                    if raw.5.is_some() || raw.6.is_some() || raw.7.is_some() || raw.8.is_some()
                        || raw.9.is_some() || raw.10.is_some()
                        || raw.11.is_none_or(|value| value < 1)
                        || raw.12.as_deref().is_none_or(|target| {
                            WorkspaceIntentId::new(target).is_err() || target == raw.0
                        })
                    {
                        return Err(LineageIndexError::Corrupt("cancel_intent"));
                    }
                }
                _ => unreachable!(),
            }
            match (outcome_kind, outcome_conflict, raw.16.as_deref(), raw.17.as_str(), raw.13) {
                ("accepted" | "unknown", None, None, "poll_receipt", 1) => {}
                ("conflict", Some(_), None, "final", 1 | 2) => {}
                ("cancelled", None, None, "final", 1 | 2) if intent_kind == "cancel" => {}
                ("created", None, Some(workspace), "final", 1 | 2)
                | ("resumed", None, Some(workspace), "final", 1 | 2)
                    if workspace == raw.4 =>
                {
                    UserWorkspaceId::new(workspace)
                        .map_err(|_| LineageIndexError::Corrupt("outcome_workspace_id"))?;
                }
                _ => return Err(LineageIndexError::Corrupt("intent_outcome")),
            }
            Ok(IntentFingerprint {
                intent_id: raw.0,
                request_digest,
                intent_kind,
                task_id: raw.3, workspace: raw.4, external_provider: raw.5, external_authority: raw.6,
                external_scope: raw.7, external_key: raw.8, base_selector: raw.9, branch_selector: raw.10,
                expected_revision: raw.11,
                target_intent_id: raw.12,
                revision: raw.13,
                outcome_kind,
                outcome_conflict: outcome_conflict.map(WorkspaceIntentConflict::as_str),
                outcome_workspace: raw.16,
                reconciliation: if raw.17 == "final" { "final" } else { "poll_receipt" },
            })
        })
        .transpose()
}

fn parse_conflict(value: &str) -> Indexed<WorkspaceIntentConflict> {
    WorkspaceIntentConflict::ALL
        .into_iter()
        .find(|conflict| conflict.as_str() == value)
        .ok_or(LineageIndexError::Corrupt("outcome_conflict"))
}

fn secure_path(path: &Path) -> Indexed<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => LineageIndexError::Io(io),
        other => LineageIndexError::InsecurePath(other.to_string()),
    })
}

fn initialize(connection: &mut Connection) -> Indexed<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 1 {
        return migrate_v1(connection);
    }
    if version == 2 {
        return migrate_v2(connection);
    }
    if version == 3 {
        return migrate_v3(connection);
    }
    if version == LINEAGE_INDEX_SCHEMA_VERSION {
        validate_current_schema(connection)?;
        return validate_durable_graphs(connection);
    }
    if version != 0 {
        return Err(LineageIndexError::SchemaVersion {
            found: version,
            supported: LINEAGE_INDEX_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(LineageIndexError::SchemaVersion {
            found: 0,
            supported: LINEAGE_INDEX_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V4)?;
    transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_current_schema(connection: &Connection) -> Indexed<()> {
    validate_schema(connection, SCHEMA_V4)
}

fn validate_schema(connection: &Connection, schema: &str) -> Indexed<()> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(LineageIndexError::Corrupt("integrity_check"));
    }
    let foreign_key_failures: u32 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_failures != 0 {
        return Err(LineageIndexError::Corrupt("foreign_keys"));
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(schema)?;
    if schema_snapshot(connection)? != schema_snapshot(&expected)? {
        return Err(LineageIndexError::Corrupt("schema_shape"));
    }
    Ok(())
}

type SchemaObject = (String, String, String, Option<String>);

fn schema_snapshot(connection: &Connection) -> Indexed<Vec<SchemaObject>> {
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn validate_durable_graphs(connection: &Connection) -> Indexed<()> {
    let mut statement = connection.prepare(
        "SELECT tenant,workspace_id FROM lineage_external_work UNION SELECT tenant,workspace_id FROM lineage_orchestration",
    )?;
    let workspaces = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for (tenant, raw) in workspaces {
        validate_tenant(&tenant).map_err(|_| LineageIndexError::Corrupt("tenant"))?;
        let workspace =
            UserWorkspaceId::new(raw).map_err(|_| LineageIndexError::Corrupt("workspace_id"))?;
        let external = read_external_workspace(connection, &tenant, &workspace)?;
        let orchestration = read_orchestration_workspace(connection, &tenant, &workspace)?;
        for item in &external {
            if item.origin().workspace() != &workspace {
                return Err(LineageIndexError::Corrupt("lineage_origin"));
            }
            let mut cursor = item.moved_to();
            let mut steps = 0usize;
            while let Some(identity) = cursor {
                let target = external
                    .iter()
                    .find(|candidate| candidate.identity() == identity)
                    .ok_or(LineageIndexError::Corrupt("moved_target"))?;
                if target.identity() == item.identity()
                    || steps >= external.len()
                    || !target.origin().refines(item.origin())
                {
                    return Err(LineageIndexError::Corrupt("moved_cycle"));
                }
                cursor = target.moved_to();
                steps += 1;
            }
        }
        for record in &orchestration {
            if record.origin().workspace() != &workspace {
                return Err(LineageIndexError::Corrupt("lineage_origin"));
            }
            if let Some(identity) = record.external_work() {
                let target = external
                    .iter()
                    .find(|candidate| candidate.identity() == identity)
                    .ok_or(LineageIndexError::Corrupt("orchestration_external"))?;
                if !record.origin().refines(target.origin()) {
                    return Err(LineageIndexError::Corrupt("lineage_origin"));
                }
            }
            let mut cursor = record.parent();
            let mut steps = 0usize;
            while let Some(identity) = cursor {
                let parent = orchestration
                    .iter()
                    .find(|candidate| candidate.identity() == identity)
                    .ok_or(LineageIndexError::Corrupt("orchestration_parent"))?;
                if parent.identity() == record.identity()
                    || steps >= orchestration.len()
                    || !record.origin().refines(parent.origin())
                {
                    return Err(LineageIndexError::Corrupt("orchestration_cycle"));
                }
                cursor = parent.parent();
                steps += 1;
            }
        }
    }
    let mut statement =
        connection.prepare("SELECT tenant,intent_id FROM lineage_workspace_intents")?;
    let intent_ids = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for (tenant, id) in intent_ids {
        validate_tenant(&tenant).map_err(|_| LineageIndexError::Corrupt("tenant"))?;
        let fingerprint =
            read_intent(connection, &tenant, &id)?.ok_or(LineageIndexError::Corrupt("intent"))?;
        let task = read_orchestration(
            connection,
            &tenant,
            &OrchestrationIdentity::Task(
                OrchestrationTaskId::new(fingerprint.task_id.clone())
                    .map_err(|_| LineageIndexError::Corrupt("intent_task"))?,
            ),
        )?
        .ok_or(LineageIndexError::Corrupt("intent_task"))?
        .0;
        if task.workspace().as_str() != fingerprint.workspace {
            return Err(LineageIndexError::Corrupt("intent_workspace"));
        }
        if fingerprint.intent_kind == "create" {
            let external = decode_external_identity(
                fingerprint
                    .external_provider
                    .as_deref()
                    .ok_or(LineageIndexError::Corrupt("intent_external"))?,
                fingerprint
                    .external_authority
                    .as_deref()
                    .ok_or(LineageIndexError::Corrupt("intent_external"))?,
                fingerprint
                    .external_scope
                    .as_deref()
                    .ok_or(LineageIndexError::Corrupt("intent_external"))?,
                fingerprint
                    .external_key
                    .as_deref()
                    .ok_or(LineageIndexError::Corrupt("intent_external"))?,
            )?;
            let item = read_external(connection, &tenant, &external)?
                .ok_or(LineageIndexError::Corrupt("intent_external"))?;
            if item.workspace() != task.workspace() || task.external_work() != Some(&external) {
                return Err(LineageIndexError::Corrupt("intent_external"));
            }
        }
        if fingerprint.intent_kind == "cancel" {
            let target_id = fingerprint
                .target_intent_id
                .as_deref()
                .ok_or(LineageIndexError::Corrupt("cancel_target"))?;
            let target = read_intent(connection, &tenant, target_id)?
                .ok_or(LineageIndexError::Corrupt("cancel_target"))?;
            if target.intent_kind == "cancel"
                || target.workspace != fingerprint.workspace
                || target.task_id != fingerprint.task_id
            {
                return Err(LineageIndexError::Corrupt("cancel_target"));
            }
            if fingerprint.outcome_kind == "cancelled" {
                let expected = fingerprint
                    .expected_revision
                    .and_then(|value| value.checked_add(1))
                    .ok_or(LineageIndexError::Corrupt("cancel_revision"))?;
                if target.revision != expected
                    || target.outcome_kind != "conflict"
                    || target.outcome_conflict
                        != Some(WorkspaceIntentConflict::CreationCancelled.as_str())
                {
                    return Err(LineageIndexError::Corrupt("cancel_target"));
                }
            } else if matches!(fingerprint.outcome_kind, "accepted" | "unknown")
                && (target.revision != fingerprint.expected_revision.unwrap_or_default()
                    || !matches!(target.outcome_kind, "accepted" | "unknown"))
            {
                return Err(LineageIndexError::Corrupt("cancel_target"));
            }
        }
        let stored = fingerprint.clone().into_stored()?;
        if intent_digest(&stored.intent) != fingerprint.request_digest {
            return Err(LineageIndexError::Corrupt("intent_digest"));
        }
    }
    Ok(())
}

/// Add tenant-composite cancellable intent fields to the exact v3 schema while
/// preserving every tenant, digest, outcome, and reconciliation state.
fn migrate_v3(connection: &mut Connection) -> Indexed<()> {
    with_foreign_keys_disabled(connection, |connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&transaction, SCHEMA_V3)?;
        transaction.execute_batch(
            "ALTER TABLE lineage_workspace_intents RENAME TO lineage_workspace_intents_v3;",
        )?;
        let start = SCHEMA_V4
            .find("CREATE TABLE lineage_workspace_intents")
            .ok_or(LineageIndexError::Corrupt("schema_shape"))?;
        transaction.execute_batch(&SCHEMA_V4[start..])?;
        transaction.execute_batch(
            r#"
INSERT INTO lineage_workspace_intents (
 tenant,intent_id,request_digest,intent_kind,task_kind,task_id,workspace_id,external_provider,
 external_authority_id,external_scope,external_key,base_selector,branch_selector,expected_revision,
 target_intent_id,revision,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation
)
SELECT tenant,intent_id,request_digest,intent_kind,task_kind,task_id,workspace_id,external_provider,
 external_authority_id,external_scope,external_key,base_selector,branch_selector,expected_revision,
 NULL,1,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation
FROM lineage_workspace_intents_v3;
DROP TABLE lineage_workspace_intents_v3;
"#,
        )?;
        validate_durable_graphs(&transaction)?;
        validate_current_schema(&transaction)?;
        transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    })
}

/// Quarantine the short-lived unscoped v2 rows under one explicit tenant while
/// preserving every already-normalized value exactly.
fn migrate_v2(connection: &mut Connection) -> Indexed<()> {
    with_foreign_keys_disabled(connection, |connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&transaction, SCHEMA_V2)?;
        transaction.execute_batch(
            r#"
ALTER TABLE lineage_workspace_intents RENAME TO lineage_workspace_intents_v2;
ALTER TABLE lineage_orchestration RENAME TO lineage_orchestration_v2;
ALTER TABLE lineage_external_work RENAME TO lineage_external_work_v2;
DROP INDEX lineage_external_by_workspace;
DROP INDEX lineage_orchestration_by_workspace;
"#,
        )?;
        transaction.execute_batch(SCHEMA_V4)?;
        transaction.execute_batch(
            r#"
INSERT INTO lineage_external_work (
 tenant,provider,authority_id,scope,work_key,workspace_id,revision,external_state,
 moved_provider,moved_authority_id,moved_scope,moved_key,observed_at_ms,stale_after_ms,
 freshness_state,latest_message,latest_observed_at_ms,origin_attempt_id,origin_session_id,origin_pane_id
)
SELECT 'legacy-unqualified',provider,authority_id,scope,work_key,workspace_id,revision,external_state,
 moved_provider,moved_authority_id,moved_scope,moved_key,observed_at_ms,stale_after_ms,
 freshness_state,latest_message,latest_observed_at_ms,origin_attempt_id,origin_session_id,origin_pane_id
FROM lineage_external_work_v2;

INSERT INTO lineage_orchestration (
 tenant,orchestration_kind,orchestration_id,workspace_id,external_provider,external_authority_id,
 external_scope,external_key,parent_kind,parent_id,status_kind,status_message,observed_at_ms,
 stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision,
 origin_attempt_id,origin_session_id,origin_pane_id
)
SELECT 'legacy-unqualified',orchestration_kind,orchestration_id,workspace_id,external_provider,
 external_authority_id,external_scope,external_key,parent_kind,parent_id,status_kind,status_message,
 observed_at_ms,stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision,
 origin_attempt_id,origin_session_id,origin_pane_id
FROM lineage_orchestration_v2;

INSERT INTO lineage_workspace_intents (
 tenant,intent_id,request_digest,intent_kind,task_kind,task_id,workspace_id,external_provider,
 external_authority_id,external_scope,external_key,base_selector,branch_selector,expected_revision,
 target_intent_id,revision,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation
)
SELECT 'legacy-unqualified',intent_id,request_digest,intent_kind,task_kind,task_id,workspace_id,
 external_provider,external_authority_id,external_scope,external_key,base_selector,branch_selector,
 expected_revision,NULL,1,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation
FROM lineage_workspace_intents_v2;
"#,
        )?;
        validate_durable_graphs(&transaction)?;
        transaction.execute_batch(
            "DROP TABLE lineage_workspace_intents_v2; DROP TABLE lineage_orchestration_v2; DROP TABLE lineage_external_work_v2;",
        )?;
        validate_current_schema(&transaction)?;
        transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    })
}

/// Upgrade the short-lived pre-authority branch schema without losing durable
/// rows. Its provider-only custody is retained under an explicit opaque legacy
/// authority; no hostname or provider payload is invented during migration.
fn migrate_v1(connection: &mut Connection) -> Indexed<()> {
    with_foreign_keys_disabled(connection, |connection| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            r#"
ALTER TABLE lineage_workspace_intents RENAME TO lineage_workspace_intents_v1;
ALTER TABLE lineage_orchestration RENAME TO lineage_orchestration_v1;
ALTER TABLE lineage_external_work RENAME TO lineage_external_work_v1;
DROP INDEX lineage_external_by_workspace;
DROP INDEX lineage_orchestration_by_workspace;
"#,
        )?;
        transaction.execute_batch(SCHEMA_V4)?;
        transaction.execute_batch(
        r#"
INSERT INTO lineage_external_work
SELECT 'legacy-unqualified',provider,'legacy-unqualified-'||provider,scope,work_key,workspace_id,revision,
 external_state,moved_provider,
 CASE WHEN moved_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||moved_provider END,
 moved_scope,moved_key,observed_at_ms,stale_after_ms,freshness_state,latest_message,
 latest_observed_at_ms,NULL,NULL,NULL
FROM lineage_external_work_v1;

INSERT INTO lineage_orchestration
SELECT 'legacy-unqualified',orchestration_kind,orchestration_id,workspace_id,external_provider,
 CASE WHEN external_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||external_provider END,
 external_scope,external_key,parent_kind,parent_id,status_kind,status_message,observed_at_ms,
 stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision,NULL,NULL,NULL
FROM lineage_orchestration_v1;

INSERT INTO lineage_workspace_intents
SELECT 'legacy-unqualified',intent_id,zeroblob(32),intent_kind,task_kind,task_id,workspace_id,external_provider,
 CASE WHEN external_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||external_provider END,
 external_scope,external_key,base_selector,branch_selector,expected_revision,NULL,1,outcome_kind,
 outcome_conflict,outcome_workspace_id,
 CASE WHEN outcome_kind IN ('accepted','unknown') THEN 'poll_receipt' ELSE 'final' END
FROM lineage_workspace_intents_v1;
"#,
    )?;
        let ids = {
            let mut statement = transaction
                .prepare("SELECT intent_id FROM lineage_workspace_intents WHERE tenant=?1")?;
            statement
                .query_map([LEGACY_TENANT], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for id in ids {
            let stored = read_intent(&transaction, LEGACY_TENANT, &id)?
                .ok_or(LineageIndexError::Corrupt("migrated_intent"))?
                .into_stored()?;
            let digest = intent_digest(&stored.intent);
            transaction.execute(
            "UPDATE lineage_workspace_intents SET request_digest=?3 WHERE tenant=?1 AND intent_id=?2",
            params![LEGACY_TENANT, id, digest.as_slice()],
        )?;
        }
        validate_durable_graphs(&transaction)?;
        transaction.execute_batch(
        "DROP TABLE lineage_workspace_intents_v1; DROP TABLE lineage_orchestration_v1; DROP TABLE lineage_external_work_v1;",
    )?;
        validate_current_schema(&transaction)?;
        transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    })
}

fn with_foreign_keys_disabled(
    connection: &mut Connection,
    migration: impl FnOnce(&mut Connection) -> Indexed<()>,
) -> Indexed<()> {
    connection.pragma_update(None, "foreign_keys", false)?;
    let result = migration(connection);
    let restore = connection.pragma_update(None, "foreign_keys", true);
    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(LineageIndexError::Sqlite(error)),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn validate_tenant(tenant: &str) -> Indexed<()> {
    if tenant.is_empty() || tenant.len() > 255 || tenant.chars().any(char::is_control) {
        return Err(LineageIndexError::InvalidField("tenant"));
    }
    Ok(())
}

fn to_db(value: u64, field: &'static str) -> Indexed<i64> {
    i64::try_from(value).map_err(|_| LineageIndexError::InvalidField(field))
}

fn from_db(value: i64, field: &'static str) -> Indexed<u64> {
    u64::try_from(value).map_err(|_| LineageIndexError::Corrupt(field))
}
