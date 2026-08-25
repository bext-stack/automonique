// SPDX-License-Identifier: Elastic-2.0

//! Durable implementation of the scheduler-core state machine.
//!
//! This store owns admission order, scope pauses, running slots, cancellation,
//! and the exact [`SchedulerFence`] under which mutations are allowed. It does
//! not invent schedules or execute work. A caller must submit a stable work ID
//! and scope, consume the IDs returned by [`DurableSchedulerStore::tick`], and
//! commit their terminal outcome.
//!
//! A crash after `tick` commits but before execution begins deliberately leaves
//! the item `running`. Reopening never changes that row to `queued`, so work is
//! not started twice; the caller must reconcile the ambiguous start and then
//! call `complete` or `cancel`/`complete`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_core::SchedulerFence;
use automonique_core::scheduler_conformance::{
    CancelDisposition, MAX_PARALLELISM_LIMIT, QueuedWork, SchedulerRefusal, ScopeId, WorkId,
    WorkState,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{StoreError, validate_database_path};

/// Schema implemented by this build.
pub const DURABLE_SCHEDULER_SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE scheduler_authority (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation_id TEXT NOT NULL,
    holder_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    parallelism_limit INTEGER NOT NULL CHECK (
        parallelism_limit BETWEEN 1 AND 1024
    )
) STRICT;

CREATE TABLE scheduler_scopes (
    scope_id TEXT PRIMARY KEY,
    paused INTEGER NOT NULL CHECK (paused IN (0, 1))
) STRICT;

CREATE TABLE scheduler_work (
    sequence INTEGER PRIMARY KEY,
    work_id TEXT NOT NULL UNIQUE,
    scope_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'stop_requested', 'completed', 'cancelled')
    )
) STRICT;

CREATE INDEX scheduler_work_by_state_sequence
    ON scheduler_work(state, sequence);
CREATE INDEX scheduler_work_by_scope_state
    ON scheduler_work(scope_id, state, sequence);
"#;

/// Failure from the durable scheduler boundary.
#[derive(Debug)]
pub enum DurableSchedulerError {
    /// The database path is not a private, owned regular file location.
    InsecurePath(String),
    /// The database has a schema this build cannot use.
    SchemaVersion { found: u32, supported: u32 },
    /// A configured value is outside its declared bounds.
    InvalidField(&'static str),
    /// Another generation has taken scheduler authority.
    StaleFence,
    /// The work identity was already admitted.
    DuplicateWork,
    /// No admitted work has that identity.
    UnknownWork,
    /// The work is already terminal.
    AlreadyTerminal,
    /// The work does not currently hold a slot.
    NotRunning,
    /// Stored state violates this module's closed vocabulary or invariants.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the database.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl DurableSchedulerError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::StaleFence => "stale_fence",
            Self::DuplicateWork => "duplicate_work",
            Self::UnknownWork => "unknown_work",
            Self::AlreadyTerminal => "already_terminal",
            Self::NotRunning => "not_running",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }

    /// Map a state-machine refusal without hiding storage failures.
    #[must_use]
    pub const fn refusal(&self) -> Option<SchedulerRefusal> {
        match self {
            Self::StaleFence => Some(SchedulerRefusal::StaleFence),
            Self::DuplicateWork => Some(SchedulerRefusal::DuplicateWork),
            Self::UnknownWork => Some(SchedulerRefusal::UnknownWork),
            Self::AlreadyTerminal => Some(SchedulerRefusal::AlreadyTerminal),
            Self::NotRunning => Some(SchedulerRefusal::NotRunning),
            _ => None,
        }
    }
}

impl fmt::Display for DurableSchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => write!(formatter, "insecure scheduler path: {reason}"),
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "scheduler schema version {found} is unsupported (supported {supported})"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid scheduler field: {field}"),
            Self::StaleFence => formatter.write_str("stale scheduler fence"),
            Self::DuplicateWork => formatter.write_str("work is already admitted"),
            Self::UnknownWork => formatter.write_str("work is unknown"),
            Self::AlreadyTerminal => formatter.write_str("work is already terminal"),
            Self::NotRunning => formatter.write_str("work is not running"),
            Self::Corrupt(field) => write!(formatter, "corrupt scheduler field: {field}"),
            Self::Io(error) => write!(formatter, "scheduler I/O failed: {error}"),
            Self::Sqlite(error) => write!(formatter, "scheduler SQLite failed: {error}"),
        }
    }
}

impl Error for DurableSchedulerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DurableSchedulerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for DurableSchedulerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

type Scheduled<T> = Result<T, DurableSchedulerError>;

/// A SQLite-backed scheduler-core state machine.
#[derive(Debug)]
pub struct DurableSchedulerStore {
    connection: Connection,
    path: PathBuf,
    limit: u32,
    fence: SchedulerFence,
}

impl DurableSchedulerStore {
    /// Open the scheduler and atomically install this process's fence.
    ///
    /// The product control lock must already prove this caller is the sole live
    /// generation. Installing a new fence does not reset queued, paused,
    /// running, stop-requested, or terminal state.
    pub fn open(path: impl AsRef<Path>, limit: u32, fence: SchedulerFence) -> Scheduled<Self> {
        if limit == 0 || limit > MAX_PARALLELISM_LIMIT {
            return Err(DurableSchedulerError::InvalidField("parallelism_limit"));
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
        initialize_or_validate_schema(&mut connection)?;
        install_authority(&mut connection, limit, &fence)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            limit,
            fence,
        })
    }

    /// Exact database path this handle opened.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configured global slot bound.
    #[must_use]
    pub const fn parallelism_limit(&self) -> u32 {
        self.limit
    }

    /// Fence this handle presents on every mutation and read.
    #[must_use]
    pub const fn fence(&self) -> &SchedulerFence {
        &self.fence
    }

    /// Durably admit one item without starting it.
    pub fn submit(&mut self, work: &QueuedWork) -> Scheduled<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_fence(&transaction, &self.fence)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM scheduler_work WHERE work_id = ?1)",
            [work.work_id().as_str()],
            |row| row.get(0),
        )?;
        if exists {
            return Err(DurableSchedulerError::DuplicateWork);
        }
        transaction.execute(
            "INSERT INTO scheduler_work(work_id, scope_id, state) VALUES(?1, ?2, 'queued')",
            params![work.work_id().as_str(), work.scope().as_str()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically start every currently eligible item that fits the bound.
    pub fn tick(&mut self, fence: &SchedulerFence) -> Scheduled<Vec<WorkId>> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_fence(&transaction, fence)?;
        if fence != &self.fence {
            return Err(DurableSchedulerError::StaleFence);
        }
        let occupied: i64 = transaction.query_row(
            "SELECT count(*) FROM scheduler_work WHERE state IN ('running', 'stop_requested')",
            [],
            |row| row.get(0),
        )?;
        let occupied = u32::try_from(occupied)
            .map_err(|_| DurableSchedulerError::Corrupt("occupied_slots"))?;
        let available = self.limit.saturating_sub(occupied);
        if available == 0 {
            transaction.commit()?;
            return Ok(Vec::new());
        }

        let mut busy = BTreeSet::new();
        {
            let mut statement = transaction.prepare(
                "SELECT DISTINCT scope_id FROM scheduler_work
                 WHERE state IN ('running', 'stop_requested')",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                busy.insert(row?);
            }
        }
        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT w.work_id, w.scope_id
                 FROM scheduler_work w
                 LEFT JOIN scheduler_scopes s ON s.scope_id = w.scope_id
                 WHERE w.state = 'queued' AND COALESCE(s.paused, 0) = 0
                 ORDER BY w.sequence",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut started = Vec::new();
        for (work_id, scope_id) in candidates {
            if started.len() >= available as usize {
                break;
            }
            if !busy.insert(scope_id) {
                continue;
            }
            let changed = transaction.execute(
                "UPDATE scheduler_work SET state = 'running'
                 WHERE work_id = ?1 AND state = 'queued'",
                [&work_id],
            )?;
            if changed != 1 {
                return Err(DurableSchedulerError::Corrupt("tick_transition"));
            }
            started
                .push(WorkId::new(work_id).map_err(|_| DurableSchedulerError::Corrupt("work_id"))?);
        }
        transaction.commit()?;
        Ok(started)
    }

    /// Commit a terminal transition for an item that still holds its slot.
    pub fn complete(&mut self, work_id: &WorkId) -> Scheduled<WorkState> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_fence(&transaction, &self.fence)?;
        let state = read_state(&transaction, work_id)?.ok_or(DurableSchedulerError::UnknownWork)?;
        let terminal = match state {
            WorkState::Running => WorkState::Completed,
            WorkState::StopRequested => WorkState::Cancelled,
            _ => return Err(DurableSchedulerError::NotRunning),
        };
        set_state(&transaction, work_id, terminal)?;
        transaction.commit()?;
        Ok(terminal)
    }

    /// Idempotently set whether one scope admits new starts.
    pub fn set_paused(&mut self, scope: &ScopeId, paused: bool) -> Scheduled<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_fence(&transaction, &self.fence)?;
        transaction.execute(
            "INSERT INTO scheduler_scopes(scope_id, paused) VALUES(?1, ?2)
             ON CONFLICT(scope_id) DO UPDATE SET paused = excluded.paused",
            params![scope.as_str(), paused],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Durably cancel queued work or request a stop for running work.
    pub fn cancel(&mut self, work_id: &WorkId) -> Scheduled<CancelDisposition> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_fence(&transaction, &self.fence)?;
        let state = read_state(&transaction, work_id)?.ok_or(DurableSchedulerError::UnknownWork)?;
        let disposition = match state {
            WorkState::Queued => {
                set_state(&transaction, work_id, WorkState::Cancelled)?;
                CancelDisposition::NeverStarted
            }
            WorkState::Running => {
                set_state(&transaction, work_id, WorkState::StopRequested)?;
                CancelDisposition::StopRequested
            }
            WorkState::StopRequested => CancelDisposition::StopRequested,
            WorkState::Completed | WorkState::Cancelled => {
                return Err(DurableSchedulerError::AlreadyTerminal);
            }
        };
        transaction.commit()?;
        Ok(disposition)
    }

    /// Work currently holding slots, in submission order.
    pub fn running(&self) -> Scheduled<Vec<WorkId>> {
        require_fence(&self.connection, &self.fence)?;
        let mut statement = self.connection.prepare(
            "SELECT work_id FROM scheduler_work
             WHERE state IN ('running', 'stop_requested') ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| WorkId::new(row?).map_err(|_| DurableSchedulerError::Corrupt("work_id")))
            .collect()
    }

    /// Current state of one admitted work identity.
    pub fn state(&self, work_id: &WorkId) -> Scheduled<Option<WorkState>> {
        require_fence(&self.connection, &self.fence)?;
        read_state(&self.connection, work_id)
    }
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Scheduled<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == DURABLE_SCHEDULER_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(DurableSchedulerError::SchemaVersion {
            found: version,
            supported: DURABLE_SCHEDULER_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(DurableSchedulerError::SchemaVersion {
            found: 0,
            supported: DURABLE_SCHEDULER_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", DURABLE_SCHEDULER_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn install_authority(
    connection: &mut Connection,
    limit: u32,
    fence: &SchedulerFence,
) -> Scheduled<()> {
    let epoch =
        i64::try_from(fence.epoch()).map_err(|_| DurableSchedulerError::InvalidField("epoch"))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO scheduler_authority(singleton, generation_id, holder_id, epoch, parallelism_limit)
         VALUES(1, ?1, ?2, ?3, ?4)
         ON CONFLICT(singleton) DO UPDATE SET
             generation_id = excluded.generation_id,
             holder_id = excluded.holder_id,
             epoch = excluded.epoch,
             parallelism_limit = excluded.parallelism_limit",
        params![fence.generation_id(), fence.holder_id(), epoch, limit],
    )?;
    transaction.commit()?;
    Ok(())
}

fn require_fence(connection: &Connection, fence: &SchedulerFence) -> Scheduled<()> {
    let epoch =
        i64::try_from(fence.epoch()).map_err(|_| DurableSchedulerError::InvalidField("epoch"))?;
    let matches: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM scheduler_authority
             WHERE singleton = 1 AND generation_id = ?1 AND holder_id = ?2 AND epoch = ?3
         )",
        params![fence.generation_id(), fence.holder_id(), epoch],
        |row| row.get(0),
    )?;
    if matches {
        Ok(())
    } else {
        Err(DurableSchedulerError::StaleFence)
    }
}

fn read_state(connection: &Connection, work_id: &WorkId) -> Scheduled<Option<WorkState>> {
    let spelling = connection
        .query_row(
            "SELECT state FROM scheduler_work WHERE work_id = ?1",
            [work_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    spelling.map(|value| parse_state(&value)).transpose()
}

fn parse_state(value: &str) -> Scheduled<WorkState> {
    match value {
        "queued" => Ok(WorkState::Queued),
        "running" => Ok(WorkState::Running),
        "stop_requested" => Ok(WorkState::StopRequested),
        "completed" => Ok(WorkState::Completed),
        "cancelled" => Ok(WorkState::Cancelled),
        _ => Err(DurableSchedulerError::Corrupt("state")),
    }
}

fn set_state(transaction: &Transaction<'_>, work_id: &WorkId, state: WorkState) -> Scheduled<()> {
    let changed = transaction.execute(
        "UPDATE scheduler_work SET state = ?1 WHERE work_id = ?2",
        params![state.as_str(), work_id.as_str()],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(DurableSchedulerError::Corrupt("state_transition"))
    }
}

fn secure_path(path: &Path) -> Scheduled<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => DurableSchedulerError::Io(io),
        other => DurableSchedulerError::InsecurePath(other.to_string()),
    })
}
