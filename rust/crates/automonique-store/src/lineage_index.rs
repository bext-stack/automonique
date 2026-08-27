// SPDX-License-Identifier: Elastic-2.0

//! Authoritative durable index for Platform v2 external work and orchestration lineage.
//!
//! External provider records and internal orchestration records occupy separate
//! tables and identity domains. Both are bound to an exact user workspace, but
//! neither table uses that workspace identity as its primary key. Mutations use
//! immediate transactions, exact idempotent replay, and revision fencing. The
//! only projection read is scoped by one caller-supplied workspace identity.
//!
//! This index stores normalized contract fields only. It stores no provider
//! payload, provider URL, repository ref, command fragment, or host path. It
//! does not execute workspace intents or claim that a stored observation is
//! fresh; those remain responsibilities of the caller and lifecycle runtime.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform_v2::{
    AttemptWorkspaceId, PaneId, UserWorkspaceId, WorkSessionId,
};
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkAuthorityId, ExternalWorkIdentity,
    ExternalWorkItem, ExternalWorkKey, ExternalWorkProvider, ExternalWorkScope, ExternalWorkState,
    LatestUsefulMessage, LineageFreshness, LineageFreshnessState, LineageMessage, LineageOrigin,
    LineageProjection, LineageStatus, MAX_LINEAGE_RECORDS, OrchestrationDecisionGateId,
    OrchestrationDispatchId, OrchestrationHeartbeatId, OrchestrationIdentity, OrchestrationKind,
    OrchestrationQuestionId, OrchestrationRecord, OrchestrationRunId, OrchestrationTaskId,
    OrchestrationWorkerId, WorkspaceIntent, WorkspaceIntentConflict, WorkspaceIntentId,
    WorkspaceIntentOutcome, WorkspaceIntentReconciliation,
};
use automonique_protocol::primitives::Revision;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{StoreError, validate_database_path};

/// The only lineage-index schema this build reads or writes.
pub const LINEAGE_INDEX_SCHEMA_VERSION: u32 = 2;

const SCHEMA_V2: &str = r#"
CREATE TABLE lineage_external_work (
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
    PRIMARY KEY (provider, authority_id, scope, work_key),
    UNIQUE (provider, authority_id, scope, work_key, workspace_id),
    CHECK ((external_state = 'moved') = (moved_provider IS NOT NULL)),
    CHECK ((moved_provider IS NULL) = (moved_scope IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_authority_id IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_key IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
    CHECK (origin_session_id IS NULL OR origin_attempt_id IS NOT NULL),
    CHECK (origin_pane_id IS NULL OR origin_session_id IS NOT NULL)
) STRICT;

CREATE INDEX lineage_external_by_workspace
    ON lineage_external_work(workspace_id, provider, authority_id, scope, work_key);

CREATE TABLE lineage_orchestration (
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
    PRIMARY KEY (orchestration_kind, orchestration_id),
    UNIQUE (orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(provider, authority_id, scope, work_key, workspace_id),
    FOREIGN KEY (parent_kind, parent_id, workspace_id)
        REFERENCES lineage_orchestration(orchestration_kind, orchestration_id, workspace_id),
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
    ON lineage_orchestration(workspace_id, orchestration_kind, orchestration_id);

CREATE TABLE lineage_workspace_intents (
    intent_id TEXT PRIMARY KEY,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('create','resume')),
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
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('accepted','unknown','created','resumed','conflict')),
    outcome_conflict TEXT CHECK (outcome_conflict IN
        ('duplicate_intake','task_already_bound','workspace_not_found','revision_mismatch',
         'external_work_moved','external_work_closed','orphan_dispatch','stale_heartbeat',
         'question_pending','creation_cancelled')),
    outcome_workspace_id TEXT,
    reconciliation TEXT NOT NULL CHECK (reconciliation IN ('final','poll_receipt')),
    FOREIGN KEY (task_kind, task_id, workspace_id)
        REFERENCES lineage_orchestration(orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(provider, authority_id, scope, work_key, workspace_id),
    CHECK (
        (intent_kind = 'create' AND external_provider IS NOT NULL AND external_authority_id IS NOT NULL AND external_scope IS NOT NULL
            AND external_key IS NOT NULL AND base_selector IS NOT NULL
            AND branch_selector IS NOT NULL AND expected_revision IS NULL) OR
        (intent_kind = 'resume' AND external_provider IS NULL AND external_authority_id IS NULL AND external_scope IS NULL
            AND external_key IS NULL AND base_selector IS NULL
            AND branch_selector IS NULL AND expected_revision IS NOT NULL)
    ),
    CHECK (
        (outcome_kind IN ('accepted','unknown') AND outcome_conflict IS NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'poll_receipt') OR
        (outcome_kind = 'conflict' AND outcome_conflict IS NOT NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'final') OR
        (outcome_kind IN ('created','resumed') AND outcome_conflict IS NULL
            AND outcome_workspace_id = workspace_id AND reconciliation = 'final')
    ),
    CHECK (
        (intent_kind = 'create' AND outcome_kind IN ('accepted','unknown','created','conflict')) OR
        (intent_kind = 'resume' AND outcome_kind IN ('accepted','unknown','resumed','conflict'))
    )
) STRICT;
"#;

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
    pub intent: WorkspaceIntent,
    pub outcome: WorkspaceIntentOutcome,
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

    /// Insert one external item or replay the exact already-durable intake.
    pub fn intake_external(&mut self, item: &ExternalWorkItem) -> Indexed<WriteAdmission> {
        if item.revision() != Revision::FIRST {
            return Err(LineageIndexError::InvalidField("revision"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_external(&transaction, item.identity())? {
            return if &existing == item {
                Ok(WriteAdmission::Replayed {
                    revision: existing.revision().get(),
                })
            } else {
                Err(LineageIndexError::DuplicateIntake)
            };
        }
        insert_external(&transaction, item)?;
        transaction.commit()?;
        Ok(WriteAdmission::Inserted { revision: 1 })
    }

    /// Revision-fenced update of external source state and observation fields.
    pub fn update_external(
        &mut self,
        item: &ExternalWorkItem,
        expected_revision: Revision,
    ) -> Indexed<WriteAdmission> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read_external(&transaction, item.identity())?
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
        if let Some(target_id) = item.moved_to() {
            let target = read_external(&transaction, target_id)?
                .ok_or(LineageIndexError::NotFound("moved external work target"))?;
            if target.workspace() != item.workspace()
                || target.identity().provider() != item.identity().provider()
                || target.identity().authority() != item.identity().authority()
                || !target.origin().refines(item.origin())
            {
                return Err(LineageIndexError::IdentityConflict);
            }
        }
        update_external_row(&transaction, item, expected_revision)?;
        transaction.commit()?;
        Ok(WriteAdmission::Updated { revision: next })
    }

    /// Insert, update, or replay one internal orchestration record.
    pub fn record_orchestration(
        &mut self,
        record: &OrchestrationRecord,
        expected_revision: Option<Revision>,
    ) -> Indexed<WriteAdmission> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_record_links(&transaction, record)?;
        let existing = read_orchestration(&transaction, record.identity())?;
        match (existing, expected_revision) {
            (None, None) => {
                if record.revision() != Revision::FIRST {
                    return Err(LineageIndexError::InvalidField("revision"));
                }
                insert_orchestration(&transaction, record)?;
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
                    || matches!(stored.status(), LineageStatus::Done(_))
                {
                    return Err(LineageIndexError::IdentityConflict);
                }
                let next = durable
                    .checked_add(1)
                    .ok_or(LineageIndexError::InvalidField("revision"))?;
                update_orchestration_row(&transaction, record, expected, next)?;
                transaction.commit()?;
                Ok(WriteAdmission::Updated { revision: next })
            }
        }
    }

    /// Persist a create/resume decision under its exact idempotent intent ID.
    pub fn record_intent(
        &mut self,
        intent: &WorkspaceIntent,
        outcome: &WorkspaceIntentOutcome,
    ) -> Indexed<WriteAdmission> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_digest = intent_digest(intent);
        if let Some(existing) = read_intent(&transaction, intent.intent_id().as_str())? {
            return if existing.request_digest == request_digest {
                Ok(WriteAdmission::Replayed { revision: 1 })
            } else {
                Err(LineageIndexError::IdentityConflict)
            };
        }
        let fingerprint = intent_fingerprint(&transaction, intent, outcome, request_digest)?;
        insert_intent(&transaction, &fingerprint)?;
        transaction.commit()?;
        Ok(WriteAdmission::Inserted { revision: 1 })
    }

    /// Transactionally advance a durable accepted/unknown receipt to one exact
    /// final decision. This records reconciliation only; it never executes the
    /// underlying create/resume operation.
    pub fn reconcile_intent(
        &mut self,
        intent: &WorkspaceIntent,
        final_outcome: &WorkspaceIntentOutcome,
    ) -> Indexed<WriteAdmission> {
        if final_outcome.reconciliation() != WorkspaceIntentReconciliation::Final {
            return Err(LineageIndexError::InvalidField("final_outcome"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let digest = intent_digest(intent);
        let existing = read_intent(&transaction, intent.intent_id().as_str())?
            .ok_or(LineageIndexError::NotFound("workspace intent"))?;
        if existing.request_digest != digest {
            return Err(LineageIndexError::IdentityConflict);
        }
        if existing.reconciliation == "final" {
            let stored = existing.into_stored()?;
            return if &stored.outcome == final_outcome {
                Ok(WriteAdmission::Replayed { revision: 2 })
            } else {
                Err(LineageIndexError::IdentityConflict)
            };
        }
        let final_value = intent_fingerprint(&transaction, intent, final_outcome, digest)?;
        let changed = transaction.execute(
            "UPDATE lineage_workspace_intents SET outcome_kind=?2,outcome_conflict=?3,outcome_workspace_id=?4,reconciliation='final' WHERE intent_id=?1 AND request_digest=?5 AND reconciliation='poll_receipt'",
            params![final_value.intent_id, final_value.outcome_kind, final_value.outcome_conflict, final_value.outcome_workspace, digest.as_slice()],
        )?;
        if changed != 1 {
            return Err(LineageIndexError::IdentityConflict);
        }
        transaction.commit()?;
        Ok(WriteAdmission::Updated { revision: 2 })
    }

    /// Look up the immutable request and its accepted/unknown/final decision.
    pub fn intent(&self, id: &WorkspaceIntentId) -> Indexed<Option<StoredWorkspaceIntent>> {
        read_intent(&self.connection, id.as_str())?
            .map(IntentFingerprint::into_stored)
            .transpose()
    }

    /// Rebuild the bounded projection for one exact authorized workspace.
    fn projection_unchecked(&self, workspace: &UserWorkspaceId) -> Indexed<LineageProjection> {
        let external = read_external_workspace(&self.connection, workspace)?;
        let orchestration = read_orchestration_workspace(&self.connection, workspace)?;
        if external.len().saturating_add(orchestration.len()) > MAX_LINEAGE_RECORDS {
            return Err(LineageIndexError::ProjectionTooLarge);
        }
        LineageProjection::new(workspace.clone(), external, orchestration)
            .map_err(|_| LineageIndexError::Corrupt("projection"))
    }

    /// Rebuild a projection only after the embedding authority accepts the
    /// exact workspace scope. This is the daemon-facing seam; the index does
    /// not infer authorization from possession of a workspace identifier.
    pub fn projection_authorized(
        &self,
        workspace: &UserWorkspaceId,
        authorize: impl FnOnce(&UserWorkspaceId) -> bool,
    ) -> Indexed<LineageProjection> {
        if !authorize(workspace) {
            return Err(LineageIndexError::Unauthorized);
        }
        self.projection_unchecked(workspace)
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

fn validate_record_links(connection: &Connection, record: &OrchestrationRecord) -> Indexed<()> {
    if let Some(external) = record.external_work() {
        let item = read_external(connection, external)?
            .ok_or(LineageIndexError::NotFound("external work item"))?;
        if item.workspace() != record.workspace() {
            return Err(LineageIndexError::IdentityConflict);
        }
        if !record.origin().refines(item.origin()) {
            return Err(LineageIndexError::IdentityConflict);
        }
    }
    if let Some(parent) = record.parent() {
        let parent =
            read_orchestration(connection, parent)?.ok_or(LineageIndexError::OrphanDispatch)?;
        if parent.0.workspace() != record.workspace() {
            return Err(LineageIndexError::IdentityConflict);
        }
        if !record.origin().refines(parent.0.origin()) {
            return Err(LineageIndexError::IdentityConflict);
        }
    }
    Ok(())
}

fn insert_external(connection: &Connection, item: &ExternalWorkItem) -> Indexed<()> {
    let moved = item.moved_to();
    let latest = item.latest_useful_message();
    connection.execute(
        "INSERT INTO lineage_external_work VALUES
         (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
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
    item: &ExternalWorkItem,
    expected: Revision,
) -> Indexed<()> {
    let moved = item.moved_to();
    let latest = item.latest_useful_message();
    let changed = connection.execute(
        "UPDATE lineage_external_work SET revision=?6,external_state=?7,moved_provider=?8,
         moved_authority_id=?9,moved_scope=?10,moved_key=?11,observed_at_ms=?12,stale_after_ms=?13,freshness_state=?14,
         latest_message=?15,latest_observed_at_ms=?16
         WHERE provider=?1 AND authority_id=?2 AND scope=?3 AND work_key=?4 AND revision=?5",
        params![
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

fn insert_orchestration(connection: &Connection, record: &OrchestrationRecord) -> Indexed<()> {
    write_orchestration(connection, record, None, 1, true)
}

fn update_orchestration_row(
    connection: &Connection,
    record: &OrchestrationRecord,
    expected: Revision,
    next: u64,
) -> Indexed<()> {
    write_orchestration(connection, record, Some(expected), next, false)
}

fn write_orchestration(
    connection: &Connection,
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
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20
             WHERE ?21 IS NULL",
            values,
        )?
    } else {
        connection.execute(
            "UPDATE lineage_orchestration SET status_kind=?10,status_message=?11,observed_at_ms=?12,
             stale_after_ms=?13,freshness_state=?14,latest_message=?15,latest_observed_at_ms=?16,revision=?17
             WHERE orchestration_kind=?1 AND orchestration_id=?2 AND revision=?21", values)?
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
    identity: &ExternalWorkIdentity,
) -> Indexed<Option<ExternalWorkItem>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {EXTERNAL_COLUMNS} FROM lineage_external_work
                  WHERE provider=?1 AND authority_id=?2 AND scope=?3 AND work_key=?4"
            ),
            params![
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
    workspace: &UserWorkspaceId,
) -> Indexed<Vec<ExternalWorkItem>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {EXTERNAL_COLUMNS} FROM lineage_external_work WHERE workspace_id=?1
         ORDER BY provider,authority_id,scope,work_key LIMIT ?2"
    ))?;
    let limit = i64::try_from(MAX_LINEAGE_RECORDS + 1)
        .map_err(|_| LineageIndexError::InvalidField("limit"))?;
    let rows = statement.query_map(params![workspace.as_str(), limit], raw_external)?;
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
    identity: &OrchestrationIdentity,
) -> Indexed<Option<(OrchestrationRecord, u64)>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {ORCHESTRATION_COLUMNS} FROM lineage_orchestration
                  WHERE orchestration_kind=?1 AND orchestration_id=?2"
            ),
            params![identity.kind().as_str(), identity.id()],
            raw_orchestration,
        )
        .optional()?;
    raw.map(decode_orchestration).transpose()
}

fn read_orchestration_workspace(
    connection: &Connection,
    workspace: &UserWorkspaceId,
) -> Indexed<Vec<OrchestrationRecord>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ORCHESTRATION_COLUMNS} FROM lineage_orchestration WHERE workspace_id=?1
         ORDER BY orchestration_kind,orchestration_id LIMIT ?2"
    ))?;
    let limit = i64::try_from(MAX_LINEAGE_RECORDS + 1)
        .map_err(|_| LineageIndexError::InvalidField("limit"))?;
    let rows = statement.query_map(params![workspace.as_str(), limit], raw_orchestration)?;
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
            "conflict" => WorkspaceIntentOutcome::Conflict(parse_conflict(
                self.outcome_conflict
                    .ok_or(LineageIndexError::Corrupt("intent_outcome"))?,
            )?),
            _ => return Err(LineageIndexError::Corrupt("intent_outcome")),
        };
        Ok(StoredWorkspaceIntent {
            request_digest: self.request_digest,
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
    }
    hasher.finalize().into()
}

fn intent_fingerprint(
    connection: &Connection,
    intent: &WorkspaceIntent,
    outcome: &WorkspaceIntentOutcome,
    request_digest: [u8; 32],
) -> Indexed<IntentFingerprint> {
    let (intent_id, intent_kind, task_id, requested_workspace, external, base, branch, expected) =
        match intent {
            WorkspaceIntent::Create(request) => (
                request.intent_id().as_str().to_owned(),
                "create",
                request.task().as_str(),
                None,
                Some(request.external_work()),
                Some(request.base_selector().as_str()),
                Some(request.branch_selector().as_str()),
                None,
            ),
            WorkspaceIntent::Resume(request) => (
                request.intent_id().as_str().to_owned(),
                "resume",
                request.task().as_str(),
                Some(request.workspace()),
                None,
                None,
                None,
                Some(to_db(
                    request.expected_revision().get(),
                    "expected_revision",
                )?),
            ),
        };
    let task_identity = OrchestrationIdentity::Task(
        OrchestrationTaskId::new(task_id).map_err(|_| LineageIndexError::InvalidField("task"))?,
    );
    let (task, _) =
        read_orchestration(connection, &task_identity)?.ok_or(LineageIndexError::OrphanDispatch)?;
    if requested_workspace.is_some_and(|workspace| workspace != task.workspace()) {
        return Err(LineageIndexError::IdentityConflict);
    }
    let mut external_state = None;
    if let Some(external) = external {
        let item = read_external(connection, external)?
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
        task_id: task_id.to_owned(),
        workspace: task.workspace().as_str().to_owned(),
        external_provider: external.map(|value| value.provider().as_str().to_owned()),
        external_authority: external.map(|value| value.authority().as_str().to_owned()),
        external_scope: external.map(|value| value.scope().as_str().to_owned()),
        external_key: external.map(|value| value.key().as_str().to_owned()),
        base_selector: base.map(str::to_owned),
        branch_selector: branch.map(str::to_owned),
        expected_revision: expected,
        outcome_kind,
        outcome_conflict,
        outcome_workspace,
        reconciliation: outcome.reconciliation().as_str(),
    })
}

fn insert_intent(connection: &Connection, value: &IntentFingerprint) -> Indexed<()> {
    connection.execute(
        "INSERT INTO lineage_workspace_intents VALUES
         (?1,?2,?3,'task',?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
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
            value.outcome_kind,
            value.outcome_conflict,
            value.outcome_workspace,
            value.reconciliation,
        ],
    )?;
    Ok(())
}

fn read_intent(connection: &Connection, intent_id: &str) -> Indexed<Option<IntentFingerprint>> {
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
        String,
        Option<String>,
        Option<String>,
        String,
    );
    connection.query_row(
        "SELECT intent_id,request_digest,intent_kind,task_id,workspace_id,external_provider,external_authority_id,external_scope,external_key,base_selector,branch_selector,expected_revision,outcome_kind,outcome_conflict,outcome_workspace_id,reconciliation FROM lineage_workspace_intents WHERE intent_id=?1",
        [intent_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?)))
    .optional()?.map(|raw: Raw| {
            WorkspaceIntentId::new(&raw.0).map_err(|_| LineageIndexError::Corrupt("intent_id"))?;
            let request_digest: [u8;32] = raw.1.clone().try_into().map_err(|_| LineageIndexError::Corrupt("request_digest"))?;
            OrchestrationTaskId::new(&raw.3).map_err(|_| LineageIndexError::Corrupt("task_id"))?;
            UserWorkspaceId::new(&raw.4).map_err(|_| LineageIndexError::Corrupt("workspace_id"))?;
            let intent_kind = match raw.2.as_str() {
                "create" => "create",
                "resume" => "resume",
                _ => return Err(LineageIndexError::Corrupt("intent_kind")),
            };
            let outcome_kind = match raw.12.as_str() {
                "accepted" => "accepted",
                "unknown" => "unknown",
                "created" => "created",
                "resumed" => "resumed",
                "conflict" => "conflict",
                _ => return Err(LineageIndexError::Corrupt("outcome_kind")),
            };
            let outcome_conflict = raw.13.as_deref().map(parse_conflict).transpose()?;
            if !matches!(
                (intent_kind, outcome_kind),
                ("create", "accepted" | "unknown" | "created" | "conflict") | ("resume", "accepted" | "unknown" | "resumed" | "conflict")
            ) {
                return Err(LineageIndexError::Corrupt("intent_outcome"));
            }
            match intent_kind {
                "create" => {
                    let (Some(provider), Some(authority), Some(scope), Some(key), Some(base), Some(branch), None) =
                        (&raw.5, &raw.6, &raw.7, &raw.8, &raw.9, &raw.10, raw.11)
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
                    {
                        return Err(LineageIndexError::Corrupt("resume_intent"));
                    }
                }
                _ => unreachable!(),
            }
            match (outcome_kind, outcome_conflict, raw.14.as_deref(), raw.15.as_str()) {
                ("accepted" | "unknown", None, None, "poll_receipt") => {}
                ("conflict", Some(_), None, "final") => {}
                ("created", None, Some(workspace), "final") | ("resumed", None, Some(workspace), "final")
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
                outcome_kind,
                outcome_conflict: outcome_conflict.map(WorkspaceIntentConflict::as_str),
                outcome_workspace: raw.14,
                reconciliation: if raw.15 == "final" { "final" } else { "poll_receipt" },
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
    if version == LINEAGE_INDEX_SCHEMA_VERSION {
        return Ok(());
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
    transaction.execute_batch(SCHEMA_V2)?;
    transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

/// Upgrade the short-lived pre-authority branch schema without losing durable
/// rows. Its provider-only custody is retained under an explicit opaque legacy
/// authority; no hostname or provider payload is invented during migration.
fn migrate_v1(connection: &mut Connection) -> Indexed<()> {
    connection.pragma_update(None, "foreign_keys", false)?;
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
    transaction.execute_batch(SCHEMA_V2)?;
    transaction.execute_batch(
        r#"
INSERT INTO lineage_external_work
SELECT provider,'legacy-unqualified-'||provider,scope,work_key,workspace_id,revision,
 external_state,moved_provider,
 CASE WHEN moved_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||moved_provider END,
 moved_scope,moved_key,observed_at_ms,stale_after_ms,freshness_state,latest_message,
 latest_observed_at_ms,NULL,NULL,NULL
FROM lineage_external_work_v1;

INSERT INTO lineage_orchestration
SELECT orchestration_kind,orchestration_id,workspace_id,external_provider,
 CASE WHEN external_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||external_provider END,
 external_scope,external_key,parent_kind,parent_id,status_kind,status_message,observed_at_ms,
 stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision,NULL,NULL,NULL
FROM lineage_orchestration_v1;

INSERT INTO lineage_workspace_intents
SELECT intent_id,zeroblob(32),intent_kind,task_kind,task_id,workspace_id,external_provider,
 CASE WHEN external_provider IS NULL THEN NULL ELSE 'legacy-unqualified-'||external_provider END,
 external_scope,external_key,base_selector,branch_selector,expected_revision,outcome_kind,
 outcome_conflict,outcome_workspace_id,'final'
FROM lineage_workspace_intents_v1;
"#,
    )?;
    let ids = {
        let mut statement =
            transaction.prepare("SELECT intent_id FROM lineage_workspace_intents")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for id in ids {
        let stored = read_intent(&transaction, &id)?
            .ok_or(LineageIndexError::Corrupt("migrated_intent"))?
            .into_stored()?;
        let digest = intent_digest(&stored.intent);
        transaction.execute(
            "UPDATE lineage_workspace_intents SET request_digest=?2 WHERE intent_id=?1",
            params![id, digest.as_slice()],
        )?;
    }
    transaction.execute_batch(
        "DROP TABLE lineage_workspace_intents_v1; DROP TABLE lineage_orchestration_v1; DROP TABLE lineage_external_work_v1;",
    )?;
    transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
    transaction.commit()?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn to_db(value: u64, field: &'static str) -> Indexed<i64> {
    i64::try_from(value).map_err(|_| LineageIndexError::InvalidField(field))
}

fn from_db(value: i64, field: &'static str) -> Indexed<u64> {
    u64::try_from(value).map_err(|_| LineageIndexError::Corrupt(field))
}
