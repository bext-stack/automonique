// SPDX-License-Identifier: Elastic-2.0

//! Durable bindings between normalized provider sessions and Automonique runs.
//!
//! The provider's session identifier is observed from its normalized stdout,
//! never inferred from filenames or "most recent" state.  One row names the
//! latest Automonique run for that resumable provider session.  A follow-up
//! therefore has an exact provider binding and an exact run to observe after a
//! daemon restart.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use automonique_protocol::platform::{IdempotencyKey, PlatformText, ReceiptOutcome, ResourceId};
use automonique_protocol::tools::RunId;
use nix::unistd::geteuid;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};

const SCHEMA_VERSION: u32 = 1;
const MAX_SESSIONS: usize = automonique_protocol::platform::MAX_SNAPSHOT_RESOURCES;

const SCHEMA: &str = r#"
CREATE TABLE managed_sessions (
    provider_session_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'lost')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= created_ms)
) STRICT;
CREATE UNIQUE INDEX managed_sessions_by_run ON managed_sessions(run_id);
CREATE TABLE managed_receipt_intents (
    outbox_key TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    outcome TEXT NOT NULL CHECK (outcome IN ('completed', 'rejected')),
    explanation TEXT,
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0)
) STRICT;
"#;

#[derive(Debug)]
pub enum ManagedSessionError {
    InvalidField(&'static str),
    InsecurePath,
    SchemaVersion,
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
}

impl ManagedSessionError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "managed_session_invalid",
            Self::InsecurePath => "managed_session_insecure",
            Self::SchemaVersion => "managed_session_schema",
            Self::Sqlite(_) => "managed_session_sqlite",
            Self::Io(_) => "managed_session_io",
        }
    }
}

impl From<rusqlite::Error> for ManagedSessionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for ManagedSessionError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Managed<T> = Result<T, ManagedSessionError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedSession {
    pub provider_session_id: String,
    pub run_id: String,
    pub open: bool,
    pub revision: u64,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedReceiptIntent {
    pub outbox_key: String,
    pub idempotency_key: String,
    pub outcome: ReceiptOutcome,
    pub explanation: Option<String>,
    pub created_ms: i64,
}

pub struct ManagedSessionStore {
    connection: Connection,
    path: PathBuf,
}

impl ManagedSessionStore {
    pub fn open(path: impl AsRef<Path>) -> Managed<Self> {
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
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(ManagedSessionError::SchemaVersion);
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
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

    pub fn observe(
        &mut self,
        provider_session_id: &str,
        run_id: &str,
        now_ms: i64,
    ) -> Managed<ManagedSession> {
        validate(provider_session_id, run_id, now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read(&transaction, provider_session_id)?;
        match existing {
            Some(existing) if existing.run_id == run_id && existing.open => {
                transaction.commit()?;
                return Ok(existing);
            }
            Some(existing) => {
                let revision = existing
                    .revision
                    .checked_add(1)
                    .ok_or(ManagedSessionError::InvalidField("revision"))?;
                transaction.execute(
                    "UPDATE managed_sessions SET run_id=?2,state='open',revision=?3,updated_ms=?4
                     WHERE provider_session_id=?1 AND revision=?5",
                    params![
                        provider_session_id,
                        run_id,
                        to_i64(revision)?,
                        now_ms,
                        to_i64(existing.revision)?
                    ],
                )?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO managed_sessions(provider_session_id,run_id,state,revision,created_ms,updated_ms)
                     VALUES(?1,?2,'open',1,?3,?3)",
                    params![provider_session_id, run_id, now_ms],
                )?;
            }
        }
        let row = read(&transaction, provider_session_id)?
            .ok_or(ManagedSessionError::InvalidField("missing_session"))?;
        transaction.commit()?;
        Ok(row)
    }

    pub fn by_id(&self, provider_session_id: &str) -> Managed<Option<ManagedSession>> {
        ResourceId::new(provider_session_id)
            .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
        read(&self.connection, provider_session_id)
    }

    pub fn by_run(&self, run_id: &str) -> Managed<Option<ManagedSession>> {
        RunId::new(run_id).map_err(|_| ManagedSessionError::InvalidField("run_id"))?;
        self.connection
            .query_row(
                "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
                 FROM managed_sessions WHERE run_id=?1",
                [run_id],
                decode,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list(&self) -> Managed<Vec<ManagedSession>> {
        let mut statement = self.connection.prepare(
            "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
             FROM managed_sessions ORDER BY updated_ms DESC,provider_session_id LIMIT ?1",
        )?;
        let limit =
            i64::try_from(MAX_SESSIONS).map_err(|_| ManagedSessionError::InvalidField("limit"))?;
        let rows = statement.query_map([limit], decode)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Mirror a platform receipt effect before the scheduler transaction that
    /// makes it eligible for delivery.  This tiny typed record is sufficient
    /// to prove the exact idempotent platform effect after an outbox lease is
    /// abandoned by a crashed generation.
    pub fn record_receipt_intent(
        &mut self,
        outbox_key: &str,
        idempotency_key: &str,
        outcome: ReceiptOutcome,
        explanation: Option<&str>,
        now_ms: i64,
    ) -> Managed<ManagedReceiptIntent> {
        validate_receipt_intent(outbox_key, idempotency_key, outcome, explanation, now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO managed_receipt_intents(outbox_key,idempotency_key,outcome,explanation,created_ms)
             VALUES(?1,?2,?3,?4,?5) ON CONFLICT(outbox_key) DO NOTHING",
            params![
                outbox_key,
                idempotency_key,
                outcome.as_str(),
                explanation,
                now_ms
            ],
        )?;
        let intent = read_receipt_intent(&transaction, outbox_key)?
            .ok_or(ManagedSessionError::InvalidField("missing_receipt_intent"))?;
        if intent.idempotency_key != idempotency_key
            || intent.outcome != outcome
            || intent.explanation.as_deref() != explanation
        {
            return Err(ManagedSessionError::InvalidField("receipt_intent_conflict"));
        }
        transaction.commit()?;
        Ok(intent)
    }

    pub fn receipt_intent(&self, outbox_key: &str) -> Managed<Option<ManagedReceiptIntent>> {
        IdempotencyKey::new(outbox_key)
            .map_err(|_| ManagedSessionError::InvalidField("outbox_key"))?;
        read_receipt_intent(&self.connection, outbox_key)
    }
}

fn validate(provider_session_id: &str, run_id: &str, now_ms: i64) -> Managed<()> {
    ResourceId::new(provider_session_id)
        .map_err(|_| ManagedSessionError::InvalidField("provider_session_id"))?;
    RunId::new(run_id).map_err(|_| ManagedSessionError::InvalidField("run_id"))?;
    if now_ms < 0 {
        return Err(ManagedSessionError::InvalidField("now_ms"));
    }
    Ok(())
}

fn read(connection: &Connection, id: &str) -> Managed<Option<ManagedSession>> {
    connection
        .query_row(
            "SELECT provider_session_id,run_id,state,revision,created_ms,updated_ms
             FROM managed_sessions WHERE provider_session_id=?1",
            [id],
            decode,
        )
        .optional()
        .map_err(Into::into)
}

fn validate_receipt_intent(
    outbox_key: &str,
    idempotency_key: &str,
    outcome: ReceiptOutcome,
    explanation: Option<&str>,
    now_ms: i64,
) -> Managed<()> {
    IdempotencyKey::new(outbox_key).map_err(|_| ManagedSessionError::InvalidField("outbox_key"))?;
    IdempotencyKey::new(idempotency_key)
        .map_err(|_| ManagedSessionError::InvalidField("idempotency_key"))?;
    if !matches!(
        outcome,
        ReceiptOutcome::Completed | ReceiptOutcome::Rejected
    ) {
        return Err(ManagedSessionError::InvalidField("receipt_outcome"));
    }
    if let Some(explanation) = explanation {
        PlatformText::new(explanation)
            .map_err(|_| ManagedSessionError::InvalidField("explanation"))?;
    }
    if now_ms < 0 {
        return Err(ManagedSessionError::InvalidField("now_ms"));
    }
    Ok(())
}

fn read_receipt_intent(
    connection: &Connection,
    outbox_key: &str,
) -> Managed<Option<ManagedReceiptIntent>> {
    connection
        .query_row(
            "SELECT outbox_key,idempotency_key,outcome,explanation,created_ms
             FROM managed_receipt_intents WHERE outbox_key=?1",
            [outbox_key],
            |row| {
                let outcome = match row.get::<_, String>(2)?.as_str() {
                    "completed" => ReceiptOutcome::Completed,
                    "rejected" => ReceiptOutcome::Rejected,
                    _ => {
                        return Err(rusqlite::Error::InvalidColumnType(
                            2,
                            "outcome".to_owned(),
                            rusqlite::types::Type::Text,
                        ));
                    }
                };
                Ok(ManagedReceiptIntent {
                    outbox_key: row.get(0)?,
                    idempotency_key: row.get(1)?,
                    outcome,
                    explanation: row.get(3)?,
                    created_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedSession> {
    let revision = row.get::<_, i64>(3)?;
    Ok(ManagedSession {
        provider_session_id: row.get(0)?,
        run_id: row.get(1)?,
        open: row.get::<_, String>(2)? == "open",
        revision: u64::try_from(revision).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        created_ms: row.get(4)?,
        updated_ms: row.get(5)?,
    })
}

fn to_i64(value: u64) -> Managed<i64> {
    i64::try_from(value).map_err(|_| ManagedSessionError::InvalidField("revision"))
}

fn initialize(connection: &mut Connection) -> Managed<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    } else if version != SCHEMA_VERSION {
        return Err(ManagedSessionError::SchemaVersion);
    }
    Ok(())
}

fn secure_path(path: &Path) -> Managed<()> {
    if !path.is_absolute() {
        return Err(ManagedSessionError::InsecurePath);
    }
    let Some(parent) = path.parent() else {
        return Err(ManagedSessionError::InsecurePath);
    };
    validate_owned_private(&fs::symlink_metadata(parent)?, true)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        validate_owned_private(&metadata, false)?;
    }
    Ok(())
}

fn validate_owned_private(metadata: &fs::Metadata, directory: bool) -> Managed<()> {
    let expected_kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !expected_kind
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ManagedSessionError::InsecurePath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn observation_is_idempotent_and_follow_up_advances_the_binding() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        let first = store.observe("session-1", "run-1", 10).unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(store.observe("session-1", "run-1", 11).unwrap(), first);
        let second = store.observe("session-1", "run-2", 12).unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(second.run_id, "run-2");
        assert_eq!(store.by_run("run-2").unwrap(), Some(second.clone()));
        assert_eq!(store.list().unwrap(), vec![second]);
    }

    #[test]
    fn receipt_intent_is_typed_idempotent_and_conflict_detecting() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = ManagedSessionStore::open(root.path().join("managed.sqlite3")).unwrap();
        let first = store
            .record_receipt_intent(
                "outbox-1",
                "request-1",
                ReceiptOutcome::Completed,
                Some("run=run-1;session=session-1"),
                10,
            )
            .unwrap();
        assert_eq!(
            store
                .record_receipt_intent(
                    "outbox-1",
                    "request-1",
                    ReceiptOutcome::Completed,
                    Some("run=run-1;session=session-1"),
                    11,
                )
                .unwrap(),
            first
        );
        assert_eq!(store.receipt_intent("outbox-1").unwrap(), Some(first));
        assert!(
            store
                .record_receipt_intent(
                    "outbox-1",
                    "request-1",
                    ReceiptOutcome::Rejected,
                    Some("different"),
                    12,
                )
                .is_err()
        );
    }
}
