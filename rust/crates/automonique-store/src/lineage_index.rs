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

use automonique_protocol::platform_v2::UserWorkspaceId;
use automonique_protocol::platform_v2_lineage::{
    BaseSelectorId, BranchSelectorId, ExternalWorkIdentity, ExternalWorkItem, ExternalWorkKey,
    ExternalWorkProvider, ExternalWorkScope, ExternalWorkState, LatestUsefulMessage,
    LineageFreshness, LineageFreshnessState, LineageMessage, LineageProjection, LineageStatus,
    MAX_LINEAGE_RECORDS, OrchestrationDecisionGateId, OrchestrationDispatchId,
    OrchestrationHeartbeatId, OrchestrationIdentity, OrchestrationKind, OrchestrationQuestionId,
    OrchestrationRecord, OrchestrationRunId, OrchestrationTaskId, OrchestrationWorkerId,
    WorkspaceIntent, WorkspaceIntentConflict, WorkspaceIntentId, WorkspaceIntentOutcome,
};
use automonique_protocol::primitives::Revision;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, validate_database_path};

/// The only lineage-index schema this build reads or writes.
pub const LINEAGE_INDEX_SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE lineage_external_work (
    provider TEXT NOT NULL CHECK (provider IN ('github','gitlab','linear','jira_compatible')),
    scope TEXT NOT NULL,
    work_key TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    external_state TEXT NOT NULL CHECK (external_state IN ('open','moved','closed')),
    moved_provider TEXT,
    moved_scope TEXT,
    moved_key TEXT,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 1),
    stale_after_ms INTEGER NOT NULL CHECK (stale_after_ms >= 1),
    freshness_state TEXT NOT NULL CHECK (freshness_state IN ('fresh','stale')),
    latest_message TEXT,
    latest_observed_at_ms INTEGER CHECK (latest_observed_at_ms >= 1),
    PRIMARY KEY (provider, scope, work_key),
    UNIQUE (provider, scope, work_key, workspace_id),
    CHECK ((external_state = 'moved') = (moved_provider IS NOT NULL)),
    CHECK ((moved_provider IS NULL) = (moved_scope IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_key IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL))
) STRICT;

CREATE INDEX lineage_external_by_workspace
    ON lineage_external_work(workspace_id, provider, scope, work_key);

CREATE TABLE lineage_orchestration (
    orchestration_kind TEXT NOT NULL CHECK (orchestration_kind IN
        ('run','task','dispatch','worker','heartbeat','question','decision_gate')),
    orchestration_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
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
    PRIMARY KEY (orchestration_kind, orchestration_id),
    UNIQUE (orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (external_provider, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(provider, scope, work_key, workspace_id),
    FOREIGN KEY (parent_kind, parent_id, workspace_id)
        REFERENCES lineage_orchestration(orchestration_kind, orchestration_id, workspace_id),
    CHECK ((external_provider IS NULL) = (external_scope IS NULL)),
    CHECK ((external_provider IS NULL) = (external_key IS NULL)),
    CHECK ((parent_kind IS NULL) = (parent_id IS NULL)),
    CHECK (parent_kind IS NULL OR orchestration_kind != parent_kind OR orchestration_id != parent_id),
    CHECK ((status_kind = 'working') = (status_message IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
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
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('create','resume')),
    task_kind TEXT NOT NULL CHECK (task_kind = 'task'),
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
    external_scope TEXT,
    external_key TEXT,
    base_selector TEXT,
    branch_selector TEXT,
    expected_revision INTEGER CHECK (expected_revision >= 1),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('created','resumed','conflict')),
    outcome_conflict TEXT CHECK (outcome_conflict IN
        ('duplicate_intake','task_already_bound','workspace_not_found','revision_mismatch',
         'external_work_moved','external_work_closed','orphan_dispatch','stale_heartbeat',
         'question_pending','creation_cancelled')),
    outcome_workspace_id TEXT,
    FOREIGN KEY (task_kind, task_id, workspace_id)
        REFERENCES lineage_orchestration(orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (external_provider, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(provider, scope, work_key, workspace_id),
    CHECK (
        (intent_kind = 'create' AND external_provider IS NOT NULL AND external_scope IS NOT NULL
            AND external_key IS NOT NULL AND base_selector IS NOT NULL
            AND branch_selector IS NOT NULL AND expected_revision IS NULL) OR
        (intent_kind = 'resume' AND external_provider IS NULL AND external_scope IS NULL
            AND external_key IS NULL AND base_selector IS NULL
            AND branch_selector IS NULL AND expected_revision IS NOT NULL)
    ),
    CHECK (
        (outcome_kind = 'conflict' AND outcome_conflict IS NOT NULL
            AND outcome_workspace_id IS NULL) OR
        (outcome_kind IN ('created','resumed') AND outcome_conflict IS NULL
            AND outcome_workspace_id = workspace_id)
    ),
    CHECK (
        (intent_kind = 'create' AND outcome_kind IN ('created','conflict')) OR
        (intent_kind = 'resume' AND outcome_kind IN ('resumed','conflict'))
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
            || !external_transition_allowed(&existing, item)
        {
            return Err(LineageIndexError::IdentityConflict);
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
                    || stored.parent() != record.parent()
                    || stored.external_work() != record.external_work()
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
        let fingerprint = intent_fingerprint(&transaction, intent, outcome)?;
        if let Some(existing) = read_intent(&transaction, &fingerprint.intent_id)? {
            return if existing == fingerprint {
                Ok(WriteAdmission::Replayed { revision: 1 })
            } else {
                Err(LineageIndexError::IdentityConflict)
            };
        }
        insert_intent(&transaction, &fingerprint)?;
        transaction.commit()?;
        Ok(WriteAdmission::Inserted { revision: 1 })
    }

    /// Rebuild the bounded projection for one exact authorized workspace.
    pub fn projection(&self, workspace: &UserWorkspaceId) -> Indexed<LineageProjection> {
        let external = read_external_workspace(&self.connection, workspace)?;
        let orchestration = read_orchestration_workspace(&self.connection, workspace)?;
        if external.len().saturating_add(orchestration.len()) > MAX_LINEAGE_RECORDS {
            return Err(LineageIndexError::ProjectionTooLarge);
        }
        LineageProjection::new(workspace.clone(), external, orchestration)
            .map_err(|_| LineageIndexError::Corrupt("projection"))
    }
}

fn external_transition_allowed(previous: &ExternalWorkItem, next: &ExternalWorkItem) -> bool {
    match previous.state() {
        ExternalWorkState::Open => true,
        ExternalWorkState::Moved => {
            next.state() == ExternalWorkState::Moved && previous.moved_to() == next.moved_to()
        }
        ExternalWorkState::Closed => next.state() == ExternalWorkState::Closed,
    }
}

fn validate_record_links(connection: &Connection, record: &OrchestrationRecord) -> Indexed<()> {
    if let Some(external) = record.external_work() {
        let item = read_external(connection, external)?
            .ok_or(LineageIndexError::NotFound("external work item"))?;
        if item.workspace() != record.workspace() {
            return Err(LineageIndexError::IdentityConflict);
        }
    }
    if let Some(parent) = record.parent() {
        let parent =
            read_orchestration(connection, parent)?.ok_or(LineageIndexError::OrphanDispatch)?;
        if parent.0.workspace() != record.workspace() {
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
         (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            item.identity().provider().as_str(),
            item.identity().scope().as_str(),
            item.identity().key().as_str(),
            item.workspace().as_str(),
            to_db(item.revision().get(), "revision")?,
            item.state().as_str(),
            moved.map(|value| value.provider().as_str()),
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
        "UPDATE lineage_external_work SET revision=?5,external_state=?6,moved_provider=?7,
         moved_scope=?8,moved_key=?9,observed_at_ms=?10,stale_after_ms=?11,freshness_state=?12,
         latest_message=?13,latest_observed_at_ms=?14
         WHERE provider=?1 AND scope=?2 AND work_key=?3 AND revision=?4",
        params![
            item.identity().provider().as_str(),
            item.identity().scope().as_str(),
            item.identity().key().as_str(),
            to_db(expected.get(), "revision")?,
            to_db(item.revision().get(), "revision")?,
            item.state().as_str(),
            moved.map(|value| value.provider().as_str()),
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
        expected
            .map(|value| to_db(value.get(), "revision"))
            .transpose()?,
    ];
    let changed = if insert {
        connection.execute(
            "INSERT INTO lineage_orchestration
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16
             WHERE ?17 IS NULL",
            values,
        )?
    } else {
        connection.execute(
            "UPDATE lineage_orchestration SET status_kind=?9,status_message=?10,observed_at_ms=?11,
             stale_after_ms=?12,freshness_state=?13,latest_message=?14,latest_observed_at_ms=?15,revision=?16
             WHERE orchestration_kind=?1 AND orchestration_id=?2 AND revision=?17", values)?
    };
    if changed != 1 {
        return Err(LineageIndexError::Corrupt("orchestration_write"));
    }
    Ok(())
}

#[derive(Debug)]
struct RawExternal {
    provider: String,
    scope: String,
    key: String,
    workspace: String,
    revision: i64,
    state: String,
    moved_provider: Option<String>,
    moved_scope: Option<String>,
    moved_key: Option<String>,
    observed_at_ms: i64,
    stale_after_ms: i64,
    freshness_state: String,
    latest_message: Option<String>,
    latest_observed_at_ms: Option<i64>,
}

const EXTERNAL_COLUMNS: &str = "provider,scope,work_key,workspace_id,revision,external_state,
    moved_provider,moved_scope,moved_key,observed_at_ms,stale_after_ms,freshness_state,
    latest_message,latest_observed_at_ms";

fn raw_external(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawExternal> {
    Ok(RawExternal {
        provider: row.get(0)?,
        scope: row.get(1)?,
        key: row.get(2)?,
        workspace: row.get(3)?,
        revision: row.get(4)?,
        state: row.get(5)?,
        moved_provider: row.get(6)?,
        moved_scope: row.get(7)?,
        moved_key: row.get(8)?,
        observed_at_ms: row.get(9)?,
        stale_after_ms: row.get(10)?,
        freshness_state: row.get(11)?,
        latest_message: row.get(12)?,
        latest_observed_at_ms: row.get(13)?,
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
                  WHERE provider=?1 AND scope=?2 AND work_key=?3"
            ),
            params![
                identity.provider().as_str(),
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
         ORDER BY provider,scope,work_key LIMIT ?2"
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
    let identity = decode_external_identity(&raw.provider, &raw.scope, &raw.key)?;
    let moved_to = match (raw.moved_provider, raw.moved_scope, raw.moved_key) {
        (None, None, None) => None,
        (Some(provider), Some(scope), Some(key)) => {
            Some(decode_external_identity(&provider, &scope, &key)?)
        }
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
    ExternalWorkItem::new(
        identity,
        UserWorkspaceId::new(raw.workspace)
            .map_err(|_| LineageIndexError::Corrupt("workspace_id"))?,
        Revision::new(from_db(raw.revision, "revision")?)
            .map_err(|_| LineageIndexError::Corrupt("revision"))?,
        parse_external_state(&raw.state)?,
        moved_to,
        freshness,
        latest,
    )
    .map_err(|_| LineageIndexError::Corrupt("external_work_item"))
}

fn decode_external_identity(
    provider: &str,
    scope: &str,
    key: &str,
) -> Indexed<ExternalWorkIdentity> {
    Ok(ExternalWorkIdentity::new(
        ExternalWorkProvider::parse(provider)
            .map_err(|_| LineageIndexError::Corrupt("provider"))?,
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
}

const ORCHESTRATION_COLUMNS: &str = "orchestration_kind,orchestration_id,workspace_id,
    external_provider,external_scope,external_key,parent_kind,parent_id,status_kind,status_message,
    observed_at_ms,stale_after_ms,freshness_state,latest_message,latest_observed_at_ms,revision";

fn raw_orchestration(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawOrchestration> {
    Ok(RawOrchestration {
        kind: row.get(0)?,
        id: row.get(1)?,
        workspace: row.get(2)?,
        external_provider: row.get(3)?,
        external_scope: row.get(4)?,
        external_key: row.get(5)?,
        parent_kind: row.get(6)?,
        parent_id: row.get(7)?,
        status_kind: row.get(8)?,
        status_message: row.get(9)?,
        observed_at_ms: row.get(10)?,
        stale_after_ms: row.get(11)?,
        freshness_state: row.get(12)?,
        latest_message: row.get(13)?,
        latest_observed_at_ms: row.get(14)?,
        revision: row.get(15)?,
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
    let external = match (raw.external_provider, raw.external_scope, raw.external_key) {
        (None, None, None) => None,
        (Some(provider), Some(scope), Some(key)) => {
            Some(decode_external_identity(&provider, &scope, &key)?)
        }
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
    let record = OrchestrationRecord::new(
        identity,
        UserWorkspaceId::new(raw.workspace)
            .map_err(|_| LineageIndexError::Corrupt("workspace_id"))?,
        external,
        parent,
        status,
        freshness,
        latest,
    )
    .map_err(|_| LineageIndexError::Corrupt("orchestration_record"))?;
    Ok((record, from_db(raw.revision, "revision")?))
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
    intent_kind: &'static str,
    task_id: String,
    workspace: String,
    external_provider: Option<String>,
    external_scope: Option<String>,
    external_key: Option<String>,
    base_selector: Option<String>,
    branch_selector: Option<String>,
    expected_revision: Option<i64>,
    outcome_kind: &'static str,
    outcome_conflict: Option<&'static str>,
    outcome_workspace: Option<String>,
}

fn intent_fingerprint(
    connection: &Connection,
    intent: &WorkspaceIntent,
    outcome: &WorkspaceIntentOutcome,
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
        intent_kind,
        task_id: task_id.to_owned(),
        workspace: task.workspace().as_str().to_owned(),
        external_provider: external.map(|value| value.provider().as_str().to_owned()),
        external_scope: external.map(|value| value.scope().as_str().to_owned()),
        external_key: external.map(|value| value.key().as_str().to_owned()),
        base_selector: base.map(str::to_owned),
        branch_selector: branch.map(str::to_owned),
        expected_revision: expected,
        outcome_kind,
        outcome_conflict,
        outcome_workspace,
    })
}

fn insert_intent(connection: &Connection, value: &IntentFingerprint) -> Indexed<()> {
    connection.execute(
        "INSERT INTO lineage_workspace_intents VALUES
         (?1,?2,'task',?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            value.intent_id,
            value.intent_kind,
            value.task_id,
            value.workspace,
            value.external_provider,
            value.external_scope,
            value.external_key,
            value.base_selector,
            value.branch_selector,
            value.expected_revision,
            value.outcome_kind,
            value.outcome_conflict,
            value.outcome_workspace,
        ],
    )?;
    Ok(())
}

fn read_intent(connection: &Connection, intent_id: &str) -> Indexed<Option<IntentFingerprint>> {
    connection
        .query_row(
            "SELECT intent_id,intent_kind,task_id,workspace_id,external_provider,external_scope,
         external_key,base_selector,branch_selector,expected_revision,outcome_kind,
         outcome_conflict,outcome_workspace_id FROM lineage_workspace_intents WHERE intent_id=?1",
            [intent_id],
            |row| {
                let intent_kind: String = row.get(1)?;
                let outcome_kind: String = row.get(10)?;
                let conflict: Option<String> = row.get(11)?;
                Ok((
                    row.get::<_, String>(0)?,
                    intent_kind,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    outcome_kind,
                    conflict,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        )
        .optional()?
        .map(|raw| {
            WorkspaceIntentId::new(&raw.0).map_err(|_| LineageIndexError::Corrupt("intent_id"))?;
            OrchestrationTaskId::new(&raw.2).map_err(|_| LineageIndexError::Corrupt("task_id"))?;
            UserWorkspaceId::new(&raw.3).map_err(|_| LineageIndexError::Corrupt("workspace_id"))?;
            let intent_kind = match raw.1.as_str() {
                "create" => "create",
                "resume" => "resume",
                _ => return Err(LineageIndexError::Corrupt("intent_kind")),
            };
            let outcome_kind = match raw.10.as_str() {
                "created" => "created",
                "resumed" => "resumed",
                "conflict" => "conflict",
                _ => return Err(LineageIndexError::Corrupt("outcome_kind")),
            };
            let outcome_conflict = raw.11.as_deref().map(parse_conflict).transpose()?;
            if !matches!(
                (intent_kind, outcome_kind),
                ("create", "created" | "conflict") | ("resume", "resumed" | "conflict")
            ) {
                return Err(LineageIndexError::Corrupt("intent_outcome"));
            }
            match intent_kind {
                "create" => {
                    let (Some(provider), Some(scope), Some(key), Some(base), Some(branch), None) =
                        (&raw.4, &raw.5, &raw.6, &raw.7, &raw.8, raw.9)
                    else {
                        return Err(LineageIndexError::Corrupt("create_intent"));
                    };
                    decode_external_identity(provider, scope, key)?;
                    BaseSelectorId::new(base)
                        .map_err(|_| LineageIndexError::Corrupt("base_selector"))?;
                    BranchSelectorId::new(branch)
                        .map_err(|_| LineageIndexError::Corrupt("branch_selector"))?;
                }
                "resume" => {
                    if raw.4.is_some()
                        || raw.5.is_some()
                        || raw.6.is_some()
                        || raw.7.is_some()
                        || raw.8.is_some()
                        || raw.9.is_none_or(|value| value < 1)
                    {
                        return Err(LineageIndexError::Corrupt("resume_intent"));
                    }
                }
                _ => unreachable!(),
            }
            match (outcome_kind, outcome_conflict, raw.12.as_deref()) {
                ("conflict", Some(_), None) => {}
                ("created", None, Some(workspace)) | ("resumed", None, Some(workspace))
                    if workspace == raw.3 =>
                {
                    UserWorkspaceId::new(workspace)
                        .map_err(|_| LineageIndexError::Corrupt("outcome_workspace_id"))?;
                }
                _ => return Err(LineageIndexError::Corrupt("intent_outcome")),
            }
            Ok(IntentFingerprint {
                intent_id: raw.0,
                intent_kind,
                task_id: raw.2,
                workspace: raw.3,
                external_provider: raw.4,
                external_scope: raw.5,
                external_key: raw.6,
                base_selector: raw.7,
                branch_selector: raw.8,
                expected_revision: raw.9,
                outcome_kind,
                outcome_conflict: outcome_conflict.map(WorkspaceIntentConflict::as_str),
                outcome_workspace: raw.12,
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
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", LINEAGE_INDEX_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn to_db(value: u64, field: &'static str) -> Indexed<i64> {
    i64::try_from(value).map_err(|_| LineageIndexError::InvalidField(field))
}

fn from_db(value: i64, field: &'static str) -> Indexed<u64> {
    u64::try_from(value).map_err(|_| LineageIndexError::Corrupt(field))
}
