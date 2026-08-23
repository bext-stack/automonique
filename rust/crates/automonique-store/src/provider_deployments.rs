// SPDX-License-Identifier: Elastic-2.0

//! Durable provider deployment routing and per-deployment cooldowns.

use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

pub const PROVIDER_DEPLOYMENTS_SCHEMA_VERSION: u32 = 1;
pub const FAILURE_THRESHOLD: u32 = 3;
pub const FAILURE_WINDOW_MS: i64 = 60_000;
pub const COOLDOWN_MS: i64 = 30_000;
const MAX_ID_BYTES: usize = 256;

const SCHEMA_V1: &str = r#"
CREATE TABLE provider_deployments (
    deployment_id TEXT PRIMARY KEY,
    provider_kind TEXT NOT NULL,
    primary_rank INTEGER CHECK (primary_rank IS NULL OR primary_rank >= 0),
    context_window_rank INTEGER CHECK (context_window_rank IS NULL OR context_window_rank >= 0),
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 4294967295),
    failure_window_started_ms INTEGER,
    cooldown_until_ms INTEGER NOT NULL DEFAULT 0 CHECK (cooldown_until_ms >= 0),
    last_probe_ms INTEGER,
    last_probe_healthy INTEGER CHECK (last_probe_healthy IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    CHECK (primary_rank IS NOT NULL OR context_window_rank IS NOT NULL),
    CHECK (failure_window_started_ms IS NULL OR failure_window_started_ms >= 0),
    CHECK (last_probe_ms IS NULL OR last_probe_ms >= 0)
) STRICT;
CREATE UNIQUE INDEX provider_deployments_primary_rank
    ON provider_deployments(primary_rank) WHERE primary_rank IS NOT NULL;
CREATE UNIQUE INDEX provider_deployments_context_rank
    ON provider_deployments(context_window_rank) WHERE context_window_rank IS NOT NULL;
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteClass {
    Primary,
    ContextWindow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentRegistration<'a> {
    pub deployment_id: &'a str,
    pub provider_kind: &'a str,
    pub primary_rank: Option<u32>,
    pub context_window_rank: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub provider_kind: String,
    pub primary_rank: Option<u32>,
    pub context_window_rank: Option<u32>,
    pub failure_count: u32,
    pub failure_window_started_ms: Option<i64>,
    pub cooldown_until_ms: i64,
    pub last_probe_ms: Option<i64>,
    pub last_probe_healthy: Option<bool>,
    pub revision: u64,
}

#[derive(Debug)]
pub enum DeploymentError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    NotFound,
    Conflict,
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for DeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => write!(formatter, "deployment store path: {reason}"),
            Self::SchemaVersion { found, supported } => {
                write!(formatter, "deployment schema {found}, expected {supported}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::NotFound => formatter.write_str("provider deployment not found"),
            Self::Conflict => formatter.write_str("provider deployment conflicts"),
            Self::Io(error) => write!(formatter, "deployment store I/O: {error}"),
            Self::Sqlite(error) => write!(formatter, "deployment store SQLite: {error}"),
        }
    }
}

impl std::error::Error for DeploymentError {}

impl From<std::io::Error> for DeploymentError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for DeploymentError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

#[derive(Debug)]
pub struct ProviderDeployments {
    connection: Connection,
    path: PathBuf,
}

impl ProviderDeployments {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DeploymentError> {
        let path = path.as_ref();
        validate_database_path(path).map_err(map_store_error)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        validate_database_path(path).map_err(map_store_error)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(DeploymentError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn register(
        &mut self,
        registration: DeploymentRegistration<'_>,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_text(registration.deployment_id, "deployment_id")?;
        validate_text(registration.provider_kind, "provider_kind")?;
        if registration.primary_rank.is_none() && registration.context_window_rank.is_none() {
            return Err(DeploymentError::InvalidField("route_rank"));
        }
        let primary = registration.primary_rank.map(i64::from);
        let context = registration.context_window_rank.map(i64::from);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read(&transaction, registration.deployment_id)?;
        if let Some(existing) = existing {
            if existing.primary_rank != registration.primary_rank
                || existing.context_window_rank != registration.context_window_rank
            {
                return Err(DeploymentError::Conflict);
            }
            if existing.provider_kind != registration.provider_kind {
                // A deployment id names one stable routing slot, not one
                // provider implementation forever. Production cutovers replace
                // the implementation behind that slot while preserving its
                // rank topology. Carrying the old provider's failures,
                // cooldown, or probe result into the replacement would make a
                // healthy cutover unavailable; refusing the new kind would
                // make the entire router fail closed at startup. Reset health
                // atomically with the kind change so the replacement begins
                // unevaluated and immediately eligible.
                transaction.execute(
                    "UPDATE provider_deployments
                     SET provider_kind=?2,
                         failure_count=0,
                         failure_window_started_ms=NULL,
                         cooldown_until_ms=0,
                         last_probe_ms=NULL,
                         last_probe_healthy=NULL,
                         revision=revision+1
                     WHERE deployment_id=?1",
                    params![registration.deployment_id, registration.provider_kind],
                )?;
                let replaced = read(&transaction, registration.deployment_id)?
                    .ok_or(DeploymentError::NotFound)?;
                transaction.commit()?;
                return Ok(replaced);
            }
            transaction.commit()?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO provider_deployments
             (deployment_id, provider_kind, primary_rank, context_window_rank)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                registration.deployment_id,
                registration.provider_kind,
                primary,
                context
            ],
        )?;
        let record =
            read(&transaction, registration.deployment_id)?.ok_or(DeploymentError::NotFound)?;
        transaction.commit()?;
        Ok(record)
    }

    /// Pick the first deployment in the class-specific ordered chain that is
    /// not cooling down. The context-window chain is independent.
    pub fn select(
        &self,
        class: RouteClass,
        now_ms: i64,
    ) -> Result<Option<DeploymentRecord>, DeploymentError> {
        validate_time(now_ms)?;
        let rank = match class {
            RouteClass::Primary => "primary_rank",
            RouteClass::ContextWindow => "context_window_rank",
        };
        let sql = format!(
            "SELECT deployment_id, provider_kind, primary_rank, context_window_rank,
                    failure_count, failure_window_started_ms, cooldown_until_ms,
                    last_probe_ms, last_probe_healthy, revision
             FROM provider_deployments
             WHERE {rank} IS NOT NULL AND cooldown_until_ms <= ?1
             ORDER BY {rank} LIMIT 1"
        );
        self.connection
            .query_row(&sql, [now_ms], decode)
            .optional()?
            .map(validate_record)
            .transpose()
    }

    /// Record one user-path failure. Three failures inside one minute trip only
    /// this deployment for thirty seconds.
    pub fn record_failure(
        &mut self,
        deployment_id: &str,
        now_ms: i64,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_text(deployment_id, "deployment_id")?;
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read(&transaction, deployment_id)?.ok_or(DeploymentError::NotFound)?;
        let in_window = current
            .failure_window_started_ms
            .is_some_and(|start| now_ms.saturating_sub(start) < FAILURE_WINDOW_MS);
        let count = if in_window {
            current.failure_count.saturating_add(1)
        } else {
            1
        };
        let window = if in_window {
            current.failure_window_started_ms.unwrap_or(now_ms)
        } else {
            now_ms
        };
        let cooldown = if count >= FAILURE_THRESHOLD {
            now_ms.saturating_add(COOLDOWN_MS)
        } else {
            current.cooldown_until_ms
        };
        transaction.execute(
            "UPDATE provider_deployments
             SET failure_count=?2, failure_window_started_ms=?3,
                 cooldown_until_ms=?4, revision=revision+1
             WHERE deployment_id=?1",
            params![deployment_id, i64::from(count), window, cooldown],
        )?;
        let record = read(&transaction, deployment_id)?.ok_or(DeploymentError::NotFound)?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn record_success(
        &mut self,
        deployment_id: &str,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_text(deployment_id, "deployment_id")?;
        self.connection.execute(
            "UPDATE provider_deployments
             SET failure_count=0, failure_window_started_ms=NULL,
                 cooldown_until_ms=0, revision=revision+1
             WHERE deployment_id=?1",
            [deployment_id],
        )?;
        self.get(deployment_id)
    }

    /// Record a cheap background probe. A failed probe evicts this deployment
    /// immediately; it does not spend a user request to reach the threshold.
    pub fn record_probe(
        &mut self,
        deployment_id: &str,
        healthy: bool,
        now_ms: i64,
    ) -> Result<DeploymentRecord, DeploymentError> {
        validate_text(deployment_id, "deployment_id")?;
        validate_time(now_ms)?;
        let cooldown = if healthy {
            0
        } else {
            now_ms.saturating_add(COOLDOWN_MS)
        };
        let changed = self.connection.execute(
            "UPDATE provider_deployments
             SET last_probe_ms=?2, last_probe_healthy=?3,
                 cooldown_until_ms=?4,
                 failure_count=CASE WHEN ?3=1 THEN 0 ELSE failure_count END,
                 failure_window_started_ms=CASE WHEN ?3=1 THEN NULL ELSE failure_window_started_ms END,
                 revision=revision+1
             WHERE deployment_id=?1",
            params![deployment_id, now_ms, i64::from(healthy), cooldown],
        )?;
        if changed == 0 {
            return Err(DeploymentError::NotFound);
        }
        self.get(deployment_id)
    }

    pub fn get(&self, deployment_id: &str) -> Result<DeploymentRecord, DeploymentError> {
        validate_text(deployment_id, "deployment_id")?;
        read(&self.connection, deployment_id)?.ok_or(DeploymentError::NotFound)
    }

    pub fn all(&self) -> Result<Vec<DeploymentRecord>, DeploymentError> {
        let mut statement = self.connection.prepare(
            "SELECT deployment_id, provider_kind, primary_rank, context_window_rank,
                    failure_count, failure_window_started_ms, cooldown_until_ms,
                    last_probe_ms, last_probe_healthy, revision
             FROM provider_deployments ORDER BY deployment_id",
        )?;
        let rows = statement.query_map([], decode)?;
        rows.map(|row| row.map_err(DeploymentError::from).and_then(validate_record))
            .collect()
    }
}

fn read(
    connection: &Connection,
    deployment_id: &str,
) -> Result<Option<DeploymentRecord>, DeploymentError> {
    connection
        .query_row(
            "SELECT deployment_id, provider_kind, primary_rank, context_window_rank,
                    failure_count, failure_window_started_ms, cooldown_until_ms,
                    last_probe_ms, last_probe_healthy, revision
             FROM provider_deployments WHERE deployment_id=?1",
            [deployment_id],
            decode,
        )
        .optional()?
        .map(validate_record)
        .transpose()
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeploymentRecord> {
    let healthy: Option<i64> = row.get(8)?;
    Ok(DeploymentRecord {
        deployment_id: row.get(0)?,
        provider_kind: row.get(1)?,
        primary_rank: row.get(2)?,
        context_window_rank: row.get(3)?,
        failure_count: row.get(4)?,
        failure_window_started_ms: row.get(5)?,
        cooldown_until_ms: row.get(6)?,
        last_probe_ms: row.get(7)?,
        last_probe_healthy: healthy.map(|value| value == 1),
        revision: row.get(9)?,
    })
}

fn validate_record(record: DeploymentRecord) -> Result<DeploymentRecord, DeploymentError> {
    validate_text(&record.deployment_id, "deployment_id")?;
    validate_text(&record.provider_kind, "provider_kind")?;
    if record.primary_rank.is_none() && record.context_window_rank.is_none()
        || record.cooldown_until_ms < 0
        || record.revision == 0
    {
        return Err(DeploymentError::Conflict);
    }
    Ok(record)
}

fn initialize(connection: &mut Connection) -> Result<(), DeploymentError> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == PROVIDER_DEPLOYMENTS_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(DeploymentError::SchemaVersion {
            found: version,
            supported: PROVIDER_DEPLOYMENTS_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(DeploymentError::SchemaVersion {
            found: 0,
            supported: PROVIDER_DEPLOYMENTS_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", PROVIDER_DEPLOYMENTS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), DeploymentError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(DeploymentError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64) -> Result<(), DeploymentError> {
    if value < 0 {
        Err(DeploymentError::InvalidField("now_ms"))
    } else {
        Ok(())
    }
}

fn map_store_error(error: StoreError) -> DeploymentError {
    match error {
        StoreError::Io(error) => DeploymentError::Io(error),
        other => DeploymentError::InsecurePath(other.to_string()),
    }
}
