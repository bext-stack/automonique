// SPDX-License-Identifier: Elastic-2.0

//! Durable reload epochs and their append-only phase history.
//!
//! A generation tenure records who held the main store lease. A reload epoch
//! records the attempted relationship between two generations and one verified
//! immutable release. Keeping those questions in separate databases preserves
//! rollback compatibility with releases that know only generation-audit v1.
//! Nothing in this module grants authority: the generation lease remains the
//! sole write fence. This ledger records only transitions a lifecycle owner
//! already performed and refuses any transition outside the closed protocol.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::validate_database_path;

pub const RELOAD_AUDIT_SCHEMA_VERSION: u32 = 1;
pub const MAX_RELOAD_RECORDS: usize = 65_536;
pub const MAX_RELOAD_ID_BYTES: usize = 128;
pub const MAX_GENERATION_ID_BYTES: usize = 256;
pub const MAX_FAILURE_CATEGORY_BYTES: usize = 128;
pub const MAX_HISTORY_PAGE: usize = 512;

const SCHEMA_V1: &str = r#"
CREATE TABLE reloads (
    reload_row_id INTEGER PRIMARY KEY,
    reload_id TEXT NOT NULL UNIQUE,
    source_generation_id TEXT NOT NULL,
    source_lease_epoch INTEGER NOT NULL CHECK (source_lease_epoch >= 1),
    target_generation_id TEXT NOT NULL,
    target_release_digest TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN (
        'created', 'candidate_started', 'warm', 'quiescing', 'transferred',
        'active_proven', 'draining', 'succeeded', 'failed', 'rolled_back'
    )),
    failure_category TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    terminal_at_ms INTEGER CHECK (terminal_at_ms IS NULL OR terminal_at_ms >= created_at_ms),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    CHECK (source_generation_id <> target_generation_id),
    CHECK ((phase IN ('succeeded', 'failed', 'rolled_back')) = (terminal_at_ms IS NOT NULL)),
    CHECK ((phase IN ('failed', 'rolled_back')) = (failure_category IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX reloads_one_active
    ON reloads((1)) WHERE terminal_at_ms IS NULL;

CREATE TABLE reload_transitions (
    transition_id INTEGER PRIMARY KEY,
    reload_row_id INTEGER NOT NULL REFERENCES reloads(reload_row_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    phase TEXT NOT NULL CHECK (phase IN (
        'created', 'candidate_started', 'warm', 'quiescing', 'transferred',
        'active_proven', 'draining', 'succeeded', 'failed', 'rolled_back'
    )),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    failure_category TEXT,
    UNIQUE (reload_row_id, revision),
    CHECK ((phase IN ('failed', 'rolled_back')) = (failure_category IS NOT NULL))
) STRICT;

CREATE INDEX reload_transitions_by_reload
    ON reload_transitions(reload_row_id, revision);
"#;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReloadPhase {
    Created,
    CandidateStarted,
    Warm,
    Quiescing,
    Transferred,
    ActiveProven,
    Draining,
    Succeeded,
    Failed,
    RolledBack,
}

impl ReloadPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::CandidateStarted => "candidate_started",
            Self::Warm => "warm",
            Self::Quiescing => "quiescing",
            Self::Transferred => "transferred",
            Self::ActiveProven => "active_proven",
            Self::Draining => "draining",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::RolledBack)
    }

    const fn admits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::CandidateStarted | Self::Failed)
                | (Self::CandidateStarted, Self::Warm | Self::Failed)
                | (Self::Warm, Self::Quiescing | Self::Failed)
                | (Self::Quiescing, Self::Transferred | Self::Failed)
                | (
                    Self::Transferred,
                    Self::ActiveProven | Self::Failed | Self::RolledBack
                )
                | (
                    Self::ActiveProven,
                    Self::Draining | Self::Failed | Self::RolledBack
                )
                | (
                    Self::Draining,
                    Self::Succeeded | Self::Failed | Self::RolledBack
                )
        )
    }

    fn parse(value: &str) -> Audited<Self> {
        match value {
            "created" => Ok(Self::Created),
            "candidate_started" => Ok(Self::CandidateStarted),
            "warm" => Ok(Self::Warm),
            "quiescing" => Ok(Self::Quiescing),
            "transferred" => Ok(Self::Transferred),
            "active_proven" => Ok(Self::ActiveProven),
            "draining" => Ok(Self::Draining),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "rolled_back" => Ok(Self::RolledBack),
            _ => Err(corrupt("phase")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadRecord {
    pub reload_id: String,
    pub source_generation_id: String,
    pub source_lease_epoch: u64,
    pub target_generation_id: String,
    pub target_release_digest: String,
    pub phase: ReloadPhase,
    pub failure_category: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub terminal_at_ms: Option<i64>,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadTransition {
    pub revision: u64,
    pub phase: ReloadPhase,
    pub observed_at_ms: i64,
    pub failure_category: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadHistory {
    pub record: ReloadRecord,
    pub transitions: Vec<ReloadTransition>,
}

pub struct BeginReload<'a> {
    pub reload_id: &'a str,
    pub source_generation_id: &'a str,
    pub source_lease_epoch: u64,
    pub target_generation_id: &'a str,
    pub target_release_digest: &'a str,
    pub created_at_ms: i64,
}

pub struct AdvanceReload<'a> {
    pub reload_id: &'a str,
    pub expected_revision: u64,
    pub phase: ReloadPhase,
    pub failure_category: Option<&'a str>,
    pub observed_at_ms: i64,
}

#[derive(Debug)]
pub struct ReloadAudit {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl ReloadAudit {
    pub fn open(path: impl AsRef<Path>) -> Audited<Self> {
        Self::open_with_capacity(path, MAX_RELOAD_RECORDS)
    }

    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Audited<Self> {
        if capacity == 0 || capacity > MAX_RELOAD_RECORDS {
            return Err(ReloadAuditError::InvalidField("capacity"));
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
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn begin(&mut self, request: BeginReload<'_>) -> Audited<ReloadRecord> {
        validate_begin(&request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_record(&transaction, request.reload_id)? {
            let same = existing.source_generation_id == request.source_generation_id
                && existing.source_lease_epoch == request.source_lease_epoch
                && existing.target_generation_id == request.target_generation_id
                && existing.target_release_digest == request.target_release_digest;
            return if same {
                Ok(existing)
            } else {
                Err(ReloadAuditError::Conflict)
            };
        }
        if let Some(active) = read_active(&transaction)? {
            return Err(ReloadAuditError::AlreadyActive(active.reload_id));
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM reloads", [], |row| row.get(0))?;
        if usize::try_from(count).map_err(|_| corrupt("reload_count"))? >= self.capacity {
            return Err(ReloadAuditError::AuditFull);
        }
        transaction.execute(
            "INSERT INTO reloads (
                reload_id, source_generation_id, source_lease_epoch,
                target_generation_id, target_release_digest, phase,
                failure_category, created_at_ms, updated_at_ms, terminal_at_ms, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'created', NULL, ?6, ?6, NULL, 1)",
            params![
                request.reload_id,
                request.source_generation_id,
                to_i64(request.source_lease_epoch, "source_lease_epoch")?,
                request.target_generation_id,
                request.target_release_digest,
                request.created_at_ms,
            ],
        )?;
        let row_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO reload_transitions (
                reload_row_id, revision, phase, observed_at_ms, failure_category
             ) VALUES (?1, 1, 'created', ?2, NULL)",
            params![row_id, request.created_at_ms],
        )?;
        transaction.commit()?;
        self.get(request.reload_id)?
            .ok_or(ReloadAuditError::Corrupt("reload"))
    }

    pub fn advance(&mut self, request: AdvanceReload<'_>) -> Audited<ReloadRecord> {
        validate_reload_id(request.reload_id)?;
        validate_time(request.observed_at_ms, "observed_at_ms")?;
        validate_failure(request.phase, request.failure_category)?;
        if request.expected_revision == 0 {
            return Err(ReloadAuditError::InvalidField("expected_revision"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            read_record(&transaction, request.reload_id)?.ok_or(ReloadAuditError::NotFound)?;
        if current.revision != request.expected_revision {
            return Err(ReloadAuditError::RevisionMismatch {
                expected: request.expected_revision,
                durable: current.revision,
            });
        }
        if request.observed_at_ms < current.updated_at_ms {
            return Err(ReloadAuditError::InvalidField("observed_at_ms"));
        }
        if !current.phase.admits(request.phase) {
            return Err(ReloadAuditError::InvalidTransition {
                from: current.phase,
                to: request.phase,
            });
        }
        let revision = current
            .revision
            .checked_add(1)
            .ok_or(ReloadAuditError::InvalidField("revision"))?;
        let terminal_at_ms = request
            .phase
            .is_terminal()
            .then_some(request.observed_at_ms);
        let changed = transaction.execute(
            "UPDATE reloads SET phase = ?1, failure_category = ?2,
                updated_at_ms = ?3, terminal_at_ms = ?4, revision = ?5
             WHERE reload_id = ?6 AND revision = ?7 AND terminal_at_ms IS NULL",
            params![
                request.phase.as_str(),
                request.failure_category,
                request.observed_at_ms,
                terminal_at_ms,
                to_i64(revision, "revision")?,
                request.reload_id,
                to_i64(request.expected_revision, "expected_revision")?,
            ],
        )?;
        if changed != 1 {
            return Err(ReloadAuditError::Conflict);
        }
        let row_id: i64 = transaction.query_row(
            "SELECT reload_row_id FROM reloads WHERE reload_id = ?1",
            [request.reload_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO reload_transitions (
                reload_row_id, revision, phase, observed_at_ms, failure_category
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row_id,
                to_i64(revision, "revision")?,
                request.phase.as_str(),
                request.observed_at_ms,
                request.failure_category,
            ],
        )?;
        transaction.commit()?;
        self.get(request.reload_id)?
            .ok_or(ReloadAuditError::Corrupt("reload"))
    }

    pub fn get(&self, reload_id: &str) -> Audited<Option<ReloadRecord>> {
        validate_reload_id(reload_id)?;
        read_record(&self.connection, reload_id)
    }

    pub fn active(&self) -> Audited<Option<ReloadRecord>> {
        read_active(&self.connection)
    }

    pub fn history(
        &self,
        reload_id: &str,
        since_revision: u64,
        limit: usize,
    ) -> Audited<ReloadHistory> {
        validate_reload_id(reload_id)?;
        if limit == 0 || limit > MAX_HISTORY_PAGE {
            return Err(ReloadAuditError::InvalidField("limit"));
        }
        let record = read_record(&self.connection, reload_id)?.ok_or(ReloadAuditError::NotFound)?;
        let row_id: i64 = self.connection.query_row(
            "SELECT reload_row_id FROM reloads WHERE reload_id = ?1",
            [reload_id],
            |row| row.get(0),
        )?;
        let mut statement = self.connection.prepare(
            "SELECT revision, phase, observed_at_ms, failure_category
             FROM reload_transitions
             WHERE reload_row_id = ?1 AND revision > ?2
             ORDER BY revision ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                row_id,
                to_i64(since_revision, "since_revision")?,
                i64::try_from(limit).map_err(|_| ReloadAuditError::InvalidField("limit"))?,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )?;
        let mut transitions = Vec::new();
        for row in rows {
            let (revision, phase, observed_at_ms, failure_category) = row?;
            let phase = ReloadPhase::parse(&phase)?;
            validate_failure(phase, failure_category.as_deref())
                .map_err(|_| corrupt("failure_category"))?;
            transitions.push(ReloadTransition {
                revision: to_u64(revision, "revision")?,
                phase,
                observed_at_ms,
                failure_category,
            });
        }
        Ok(ReloadHistory {
            record,
            transitions,
        })
    }
}

#[derive(Debug)]
pub enum ReloadAuditError {
    InvalidField(&'static str),
    AlreadyActive(String),
    NotFound,
    Conflict,
    RevisionMismatch { expected: u64, durable: u64 },
    InvalidTransition { from: ReloadPhase, to: ReloadPhase },
    AuditFull,
    InsecurePath,
    ForeignSchema(u32),
    Corrupt(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl ReloadAuditError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "reload_audit_invalid_field",
            Self::AlreadyActive(_) => "reload_already_active",
            Self::NotFound => "reload_not_found",
            Self::Conflict => "reload_conflict",
            Self::RevisionMismatch { .. } => "reload_revision_mismatch",
            Self::InvalidTransition { .. } => "reload_invalid_transition",
            Self::AuditFull => "reload_audit_full",
            Self::InsecurePath => "reload_audit_insecure_path",
            Self::ForeignSchema(_) => "reload_audit_foreign_schema",
            Self::Corrupt(_) => "reload_audit_corrupt",
            Self::Io(_) => "reload_audit_io",
            Self::Sqlite(_) => "reload_audit_sqlite",
        }
    }
}

impl fmt::Display for ReloadAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for ReloadAuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ReloadAuditError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for ReloadAuditError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub type Audited<T> = Result<T, ReloadAuditError>;

fn validate_begin(request: &BeginReload<'_>) -> Audited<()> {
    validate_reload_id(request.reload_id)?;
    validate_identifier(request.source_generation_id, "source_generation_id")?;
    validate_identifier(request.target_generation_id, "target_generation_id")?;
    if request.source_generation_id == request.target_generation_id {
        return Err(ReloadAuditError::InvalidField("target_generation_id"));
    }
    if request.source_lease_epoch == 0 {
        return Err(ReloadAuditError::InvalidField("source_lease_epoch"));
    }
    validate_digest(request.target_release_digest)?;
    validate_time(request.created_at_ms, "created_at_ms")
}

fn validate_reload_id(value: &str) -> Audited<()> {
    validate_text(value, MAX_RELOAD_ID_BYTES, "reload_id")
}

fn validate_identifier(value: &str, field: &'static str) -> Audited<()> {
    validate_text(value, MAX_GENERATION_ID_BYTES, field)
}

fn validate_failure(phase: ReloadPhase, category: Option<&str>) -> Audited<()> {
    if matches!(phase, ReloadPhase::Failed | ReloadPhase::RolledBack) {
        let category = category.ok_or(ReloadAuditError::InvalidField("failure_category"))?;
        validate_text(category, MAX_FAILURE_CATEGORY_BYTES, "failure_category")
    } else if category.is_some() {
        Err(ReloadAuditError::InvalidField("failure_category"))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Audited<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ReloadAuditError::InvalidField("target_release_digest"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReloadAuditError::InvalidField("target_release_digest"));
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, field: &'static str) -> Audited<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ReloadAuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Audited<()> {
    if value < 0 {
        Err(ReloadAuditError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Audited<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA_V1)?;
        transaction.pragma_update(None, "user_version", RELOAD_AUDIT_SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version != RELOAD_AUDIT_SCHEMA_VERSION {
        return Err(ReloadAuditError::ForeignSchema(version));
    }
    Ok(())
}

fn secure_path(path: &Path) -> Audited<()> {
    validate_database_path(path).map_err(|_| ReloadAuditError::InsecurePath)?;
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ReloadAuditError::InsecurePath);
        }
    }
    Ok(())
}

fn read_active(connection: &Connection) -> Audited<Option<ReloadRecord>> {
    let id = connection
        .query_row(
            "SELECT reload_id FROM reloads WHERE terminal_at_ms IS NULL",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    id.map_or(Ok(None), |id| read_record(connection, &id))
}

fn read_record(connection: &Connection, reload_id: &str) -> Audited<Option<ReloadRecord>> {
    let raw = connection
        .query_row(
            "SELECT source_generation_id, source_lease_epoch, target_generation_id,
                    target_release_digest, phase, failure_category, created_at_ms,
                    updated_at_ms, terminal_at_ms, revision
             FROM reloads WHERE reload_id = ?1",
            [reload_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        source_generation_id,
        source_lease_epoch,
        target_generation_id,
        target_release_digest,
        phase,
        failure_category,
        created_at_ms,
        updated_at_ms,
        terminal_at_ms,
        revision,
    )) = raw
    else {
        return Ok(None);
    };
    validate_reload_id(reload_id).map_err(|_| corrupt("reload_id"))?;
    validate_identifier(&source_generation_id, "source_generation_id")
        .map_err(|_| corrupt("source_generation_id"))?;
    validate_identifier(&target_generation_id, "target_generation_id")
        .map_err(|_| corrupt("target_generation_id"))?;
    if source_generation_id == target_generation_id {
        return Err(corrupt("target_generation_id"));
    }
    validate_digest(&target_release_digest).map_err(|_| corrupt("target_release_digest"))?;
    let phase = ReloadPhase::parse(&phase)?;
    validate_failure(phase, failure_category.as_deref())
        .map_err(|_| corrupt("failure_category"))?;
    if created_at_ms < 0
        || updated_at_ms < created_at_ms
        || terminal_at_ms.is_some_and(|value| value < created_at_ms)
    {
        return Err(corrupt("time"));
    }
    if phase.is_terminal() != terminal_at_ms.is_some() {
        return Err(corrupt("terminal_at_ms"));
    }
    Ok(Some(ReloadRecord {
        reload_id: reload_id.to_owned(),
        source_generation_id,
        source_lease_epoch: to_u64(source_lease_epoch, "source_lease_epoch")?,
        target_generation_id,
        target_release_digest,
        phase,
        failure_category,
        created_at_ms,
        updated_at_ms,
        terminal_at_ms,
        revision: to_u64(revision, "revision")?,
    }))
}

fn to_i64(value: u64, field: &'static str) -> Audited<i64> {
    i64::try_from(value).map_err(|_| ReloadAuditError::InvalidField(field))
}

fn to_u64(value: i64, field: &'static str) -> Audited<u64> {
    u64::try_from(value).map_err(|_| corrupt(field))
}

const fn corrupt(field: &'static str) -> ReloadAuditError {
    ReloadAuditError::Corrupt(field)
}
