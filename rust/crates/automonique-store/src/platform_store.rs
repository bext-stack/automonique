// SPDX-License-Identifier: Elastic-2.0

//! Durable state behind `automonique.platform/v1`.
//!
//! Accepted actions and their first event commit in one immediate transaction.
//! A retry returns the original receipt and never asks the caller to perform
//! the action again. Attachments are observation-only rows; controller leases
//! are short, exclusive, and independently durable.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform::{
    ActionReceipt, Attachment, CONTROL_LEASE_TTL_MILLIS, ClientId, ControlLease, ControlLeaseId,
    CursorTopic, ExecuteRequest, Freshness, FreshnessState, IdempotencyKey,
    MAX_SUBSCRIPTION_EVENTS, PlatformAction, PlatformCursor, PlatformEvent, PlatformText,
    ReceiptId, ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    ResourceRecord, Subscription,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

pub const PLATFORM_STORE_SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE platform_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 1)
) STRICT;
INSERT INTO platform_meta(singleton, revision) VALUES (1, 1);

CREATE TABLE platform_resources (
    authority TEXT NOT NULL,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    freshness_state TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    summary TEXT NOT NULL,
    PRIMARY KEY(authority, kind, resource_id)
) STRICT;

CREATE TABLE platform_events (
    sequence INTEGER PRIMARY KEY,
    topic_sequence INTEGER NOT NULL CHECK (topic_sequence >= 1),
    topic TEXT NOT NULL,
    authority TEXT NOT NULL,
    kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    freshness_state TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    summary TEXT NOT NULL,
    UNIQUE(topic, topic_sequence)
) STRICT;
INSERT INTO platform_events(
    sequence, topic_sequence, topic, authority, kind, resource_id, freshness_state,
    observed_at_ms, revision, summary
) VALUES (
    1, 1, 'platform', 'client', 'client', 'platform-store', 'fresh',
    0, 1, 'platform store initialized'
);

CREATE TABLE platform_receipts (
    receipt_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    target_authority TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    expected_revision INTEGER,
    parameter TEXT,
    outcome TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    recorded_at_ms INTEGER NOT NULL,
    explanation TEXT
) STRICT;

CREATE TABLE platform_attachments (
    session_authority TEXT NOT NULL,
    session_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    cursor_sequence INTEGER NOT NULL CHECK (cursor_sequence >= 1),
    attached_at_ms INTEGER NOT NULL,
    PRIMARY KEY(session_authority, session_kind, session_id, client_id)
) STRICT;

CREATE TABLE platform_control_leases (
    session_authority TEXT NOT NULL,
    session_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    lease_id TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY(session_authority, session_kind, session_id)
) STRICT;

CREATE TABLE platform_control_receipts (
    idempotency_key TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    session_authority TEXT NOT NULL,
    session_kind TEXT NOT NULL,
    session_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    expires_at_ms INTEGER,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    recorded_at_ms INTEGER NOT NULL
) STRICT;
"#;

#[derive(Debug)]
pub enum PlatformStoreError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    Conflict(&'static str),
    StaleRevision,
    NotFound,
    ResyncRequired,
    Corrupt(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl PlatformStoreError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict(_) => "conflict",
            Self::StaleRevision => "stale_revision",
            Self::NotFound => "not_found",
            Self::ResyncRequired => "resync_required",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for PlatformStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "platform store refused: {}", self.category())
    }
}

impl Error for PlatformStoreError {}
impl From<std::io::Error> for PlatformStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for PlatformStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

type Stored<T> = Result<T, PlatformStoreError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionAdmission {
    New(ActionReceipt),
    Replay(ActionReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlAdmission {
    New(ControlLease),
    Replay(ControlLease),
}

#[derive(Debug)]
pub struct PlatformStore {
    connection: Connection,
    path: PathBuf,
}

impl PlatformStore {
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
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(PlatformStoreError::Sqlite(rusqlite::Error::InvalidQuery));
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

    pub fn revision(&self) -> Stored<Revision> {
        let value: i64 = self.connection.query_row(
            "SELECT revision FROM platform_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        revision(value)
    }

    pub fn upsert_resource(
        &mut self,
        topic: &str,
        record: &ResourceRecord,
    ) -> Stored<PlatformCursor> {
        validate_topic(topic)?;
        validate_record(record)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, i64, i64, String)> = transaction
            .query_row(
                "SELECT freshness_state, observed_at_ms, revision, summary FROM platform_resources
             WHERE authority=?1 AND kind=?2 AND resource_id=?3",
                params![
                    record.resource.authority.as_str(),
                    record.resource.kind.as_str(),
                    record.resource.id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let wanted = (
            record.freshness.state.as_str().to_owned(),
            to_db_revision(record.freshness.revision)?,
            record.summary.as_str().to_owned(),
        );
        let semantic_existing = existing
            .as_ref()
            .map(|(state, _, revision, summary)| (state.clone(), *revision, summary.clone()));
        if semantic_existing.as_ref() != Some(&wanted) {
            let topic_sequence = next_topic_sequence(&transaction, topic)?;
            transaction.execute(
                "INSERT INTO platform_resources(authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(authority,kind,resource_id) DO UPDATE SET
                   freshness_state=excluded.freshness_state, observed_at_ms=excluded.observed_at_ms,
                   revision=excluded.revision, summary=excluded.summary",
                params![record.resource.authority.as_str(), record.resource.kind.as_str(), record.resource.id.as_str(),
                    record.freshness.state.as_str(), record.freshness.observed_at.as_millis(),
                    to_db_revision(record.freshness.revision)?, record.summary.as_str()],
            )?;
            transaction.execute(
                "INSERT INTO platform_events(topic_sequence,topic,authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![to_db_u64(topic_sequence,"sequence")?, topic, record.resource.authority.as_str(), record.resource.kind.as_str(), record.resource.id.as_str(),
                    record.freshness.state.as_str(), record.freshness.observed_at.as_millis(),
                    to_db_revision(record.freshness.revision)?, record.summary.as_str()],
            )?;
        } else if existing.as_ref().is_some_and(|(_, observed_at, _, _)| {
            *observed_at != record.freshness.observed_at.as_millis()
        }) {
            transaction.execute(
                "UPDATE platform_resources SET observed_at_ms=?1
                 WHERE authority=?2 AND kind=?3 AND resource_id=?4",
                params![
                    record.freshness.observed_at.as_millis(),
                    record.resource.authority.as_str(),
                    record.resource.kind.as_str(),
                    record.resource.id.as_str()
                ],
            )?;
        }
        let sequence = last_topic_sequence(&transaction, topic)?;
        transaction.commit()?;
        platform_cursor(record.resource.authority, topic, sequence)
    }

    pub fn snapshot(
        &self,
        requested: &[ResourceCoordinate],
        topic: &str,
    ) -> Stored<(Vec<ResourceRecord>, PlatformCursor)> {
        validate_topic(topic)?;
        let mut records = Vec::new();
        if requested.is_empty() {
            let mut statement = self.connection.prepare(
                "SELECT authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary
                 FROM platform_resources ORDER BY authority,kind,resource_id",
            )?;
            let rows = statement.query_map([], raw_record)?;
            for row in rows {
                records.push(record_from_row(row?)?);
            }
        } else {
            for coordinate in requested {
                let raw = self.connection.query_row(
                    "SELECT authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary
                     FROM platform_resources WHERE authority=?1 AND kind=?2 AND resource_id=?3",
                    params![coordinate.authority.as_str(), coordinate.kind.as_str(), coordinate.id.as_str()], raw_record,
                ).optional()?;
                if let Some(raw) = raw {
                    records.push(record_from_row(raw)?);
                }
            }
        }
        let sequence = last_topic_sequence(&self.connection, topic)?;
        Ok((
            records,
            platform_cursor(ResourceAuthority::Automonique, topic, sequence)?,
        ))
    }

    pub fn subscribe(
        &self,
        requested: Option<&PlatformCursor>,
        topic: &str,
    ) -> Stored<Subscription> {
        validate_topic(topic)?;
        let current = last_topic_sequence(&self.connection, topic)?;
        let after = requested.map_or(0, |cursor| cursor.sequence.get());
        if let Some(cursor) = requested
            && (cursor.authority != ResourceAuthority::Automonique
                || cursor.topic.as_str() != topic
                || after > current)
        {
            return Err(PlatformStoreError::ResyncRequired);
        }
        let mut statement = self.connection.prepare(
            "SELECT topic_sequence,authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary
             FROM platform_events WHERE topic_sequence > ?1 AND topic = ?2 ORDER BY topic_sequence LIMIT ?3")?;
        let rows = statement.query_map(
            params![
                to_db_u64(after, "sequence")?,
                topic,
                i64::try_from(MAX_SUBSCRIPTION_EVENTS).unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    RawRecord {
                        authority: row.get(1)?,
                        kind: row.get(2)?,
                        resource_id: row.get(3)?,
                        freshness_state: row.get(4)?,
                        observed_at_ms: row.get(5)?,
                        revision: row.get(6)?,
                        summary: row.get(7)?,
                    },
                ))
            },
        )?;
        let mut events = Vec::new();
        let mut last = after.max(1);
        for row in rows {
            let (sequence, raw) = row?;
            let sequence = from_db_u64(sequence, "sequence")?;
            last = sequence;
            events.push(PlatformEvent {
                cursor: platform_cursor(ResourceAuthority::Automonique, topic, sequence)?,
                resource: record_from_row(raw)?,
            });
        }
        Subscription::new(
            events,
            platform_cursor(ResourceAuthority::Automonique, topic, last.max(1))?,
        )
        .map_err(|_| PlatformStoreError::Corrupt("subscription"))
    }

    pub fn prepare_execute(
        &mut self,
        request: &ExecuteRequest,
        authoritative_revision: Revision,
        now_ms: i64,
    ) -> Stored<ActionAdmission> {
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt_by_key(&transaction, request.idempotency_key.as_str())?
        {
            if !receipt_matches_request(&existing, request) {
                return Err(PlatformStoreError::Conflict("idempotency_key"));
            }
            transaction.commit()?;
            return Ok(ActionAdmission::Replay(existing.receipt));
        }
        if request
            .expected_revision
            .is_some_and(|expected| expected != authoritative_revision)
        {
            return Err(PlatformStoreError::StaleRevision);
        }
        let revision = next_revision(&transaction)?;
        let receipt_id = deterministic_id("receipt", request.idempotency_key.as_str());
        transaction.execute(
            "INSERT INTO platform_receipts(receipt_id,idempotency_key,action,target_authority,target_kind,target_id,
             expected_revision,parameter,outcome,revision,recorded_at_ms,explanation)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'accepted',?9,?10,NULL)",
            params![receipt_id, request.idempotency_key.as_str(), request.action.as_str(), request.target.authority.as_str(),
                request.target.kind.as_str(), request.target.id.as_str(), request.expected_revision.map(to_db_revision).transpose()?,
                request.parameter.as_ref().map(PlatformText::as_str), to_db_revision(revision)?, now_ms],
        )?;
        let receipt = ActionReceipt {
            id: ReceiptId::new(receipt_id)
                .map_err(|_| PlatformStoreError::Corrupt("receipt_id"))?,
            action: request.action,
            target: request.target.clone(),
            outcome: ReceiptOutcome::Accepted,
            revision,
            recorded_at: EpochMillis::from_millis(now_ms),
            explanation: None,
        };
        append_receipt_event(&transaction, &receipt)?;
        transaction.commit()?;
        Ok(ActionAdmission::New(receipt))
    }

    pub fn finalize_execute(
        &mut self,
        key: &IdempotencyKey,
        outcome: ReceiptOutcome,
        explanation: Option<&str>,
        now_ms: i64,
    ) -> Stored<ActionReceipt> {
        validate_time(now_ms)?;
        if matches!(
            outcome,
            ReceiptOutcome::Unknown | ReceiptOutcome::ResyncRequired
        ) {
            return Err(PlatformStoreError::InvalidField("outcome"));
        }
        if let Some(explanation) = explanation {
            PlatformText::new(explanation)
                .map_err(|_| PlatformStoreError::InvalidField("explanation"))?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing =
            read_receipt_by_key(&transaction, key.as_str())?.ok_or(PlatformStoreError::NotFound)?;
        if existing.receipt.outcome != ReceiptOutcome::Accepted {
            transaction.commit()?;
            return Ok(existing.receipt);
        }
        let revision = next_revision(&transaction)?;
        transaction.execute(
            "UPDATE platform_receipts SET outcome=?1, revision=?2, recorded_at_ms=?3, explanation=?4 WHERE idempotency_key=?5 AND outcome='accepted'",
            params![outcome.as_str(), to_db_revision(revision)?, now_ms, explanation, key.as_str()],
        )?;
        let receipt = read_receipt_by_key(&transaction, key.as_str())?
            .ok_or(PlatformStoreError::Corrupt("receipt_missing"))?
            .receipt;
        append_receipt_event(&transaction, &receipt)?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn receipt(
        &self,
        id: Option<&ReceiptId>,
        key: Option<&IdempotencyKey>,
    ) -> Stored<ActionReceipt> {
        let stored = match (id, key) {
            (Some(id), None) => read_receipt_by_id(&self.connection, id.as_str())?,
            (None, Some(key)) => read_receipt_by_key(&self.connection, key.as_str())?,
            _ => return Err(PlatformStoreError::InvalidField("receipt_lookup")),
        };
        stored
            .map(|value| value.receipt)
            .ok_or(PlatformStoreError::NotFound)
    }

    pub fn attach(
        &mut self,
        session: &ResourceCoordinate,
        client: &ClientId,
        now_ms: i64,
        topic: &str,
    ) -> Stored<Attachment> {
        validate_session(session)?;
        validate_time(now_ms)?;
        validate_topic(topic)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sequence = last_topic_sequence(&transaction, topic)?;
        transaction.execute(
            "INSERT INTO platform_attachments(session_authority,session_kind,session_id,client_id,cursor_sequence,attached_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(session_authority,session_kind,session_id,client_id)
             DO UPDATE SET cursor_sequence=excluded.cursor_sequence,attached_at_ms=excluded.attached_at_ms",
            params![session.authority.as_str(),session.kind.as_str(),session.id.as_str(),client.as_str(),to_db_u64(sequence,"sequence")?,now_ms],
        )?;
        transaction.commit()?;
        Ok(Attachment {
            session: session.clone(),
            client: client.clone(),
            cursor: platform_cursor(ResourceAuthority::Automonique, topic, sequence)?,
        })
    }

    pub fn detach(&mut self, session: &ResourceCoordinate, client: &ClientId) -> Stored<()> {
        validate_session(session)?;
        self.connection.execute(
            "DELETE FROM platform_attachments WHERE session_authority=?1 AND session_kind=?2 AND session_id=?3 AND client_id=?4",
            params![session.authority.as_str(),session.kind.as_str(),session.id.as_str(),client.as_str()],
        )?;
        Ok(())
    }

    pub fn claim_control(
        &mut self,
        session: &ResourceCoordinate,
        client: &ClientId,
        key: &IdempotencyKey,
        now_ms: i64,
    ) -> Stored<ControlAdmission> {
        validate_session(session)?;
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(lease) =
            read_control_receipt(&transaction, key.as_str(), "claim", session, client)?
        {
            transaction.commit()?;
            return Ok(ControlAdmission::Replay(lease));
        }
        let active: Option<(String, String, i64, i64)> = transaction
            .query_row(
                "SELECT lease_id,client_id,expires_at_ms,revision FROM platform_control_leases
             WHERE session_authority=?1 AND session_kind=?2 AND session_id=?3",
                params![
                    session.authority.as_str(),
                    session.kind.as_str(),
                    session.id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if active
            .as_ref()
            .is_some_and(|(_, owner, expires, _)| *expires > now_ms && owner != client.as_str())
        {
            return Err(PlatformStoreError::Conflict("controller"));
        }
        let revision = next_revision(&transaction)?;
        let expires_at = now_ms
            .checked_add(CONTROL_LEASE_TTL_MILLIS)
            .ok_or(PlatformStoreError::InvalidField("expires_at"))?;
        let lease_id = deterministic_id("lease", key.as_str());
        transaction.execute(
            "INSERT INTO platform_control_leases(session_authority,session_kind,session_id,lease_id,client_id,expires_at_ms,revision)
             VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(session_authority,session_kind,session_id) DO UPDATE SET
             lease_id=excluded.lease_id,client_id=excluded.client_id,expires_at_ms=excluded.expires_at_ms,revision=excluded.revision",
            params![session.authority.as_str(),session.kind.as_str(),session.id.as_str(),lease_id,client.as_str(),expires_at,to_db_revision(revision)?],
        )?;
        transaction.execute(
            "INSERT INTO platform_control_receipts(idempotency_key,operation,session_authority,session_kind,session_id,client_id,lease_id,expires_at_ms,revision,recorded_at_ms)
             VALUES(?1,'claim',?2,?3,?4,?5,?6,?7,?8,?9)",
            params![key.as_str(),session.authority.as_str(),session.kind.as_str(),session.id.as_str(),client.as_str(),lease_id,expires_at,to_db_revision(revision)?,now_ms],
        )?;
        let lease = ControlLease {
            id: ControlLeaseId::new(lease_id)
                .map_err(|_| PlatformStoreError::Corrupt("lease_id"))?,
            session: session.clone(),
            client: client.clone(),
            expires_at: EpochMillis::from_millis(expires_at),
            revision,
        };
        transaction.commit()?;
        Ok(ControlAdmission::New(lease))
    }

    pub fn release_control(
        &mut self,
        session: &ResourceCoordinate,
        client: &ClientId,
        lease: &ControlLeaseId,
        key: &IdempotencyKey,
        now_ms: i64,
    ) -> Stored<()> {
        validate_session(session)?;
        validate_time(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if control_receipt_exists(
            &transaction,
            key.as_str(),
            "release",
            session,
            client,
            lease.as_str(),
        )? {
            transaction.commit()?;
            return Ok(());
        }
        let active: Option<(String, String, i64)> = transaction
            .query_row(
                "SELECT lease_id,client_id,expires_at_ms FROM platform_control_leases
             WHERE session_authority=?1 AND session_kind=?2 AND session_id=?3",
                params![
                    session.authority.as_str(),
                    session.kind.as_str(),
                    session.id.as_str()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((active_lease, active_client, _)) = active else {
            return Err(PlatformStoreError::NotFound);
        };
        if active_lease != lease.as_str() || active_client != client.as_str() {
            return Err(PlatformStoreError::Conflict("lease"));
        }
        let revision = next_revision(&transaction)?;
        transaction.execute(
            "DELETE FROM platform_control_leases WHERE session_authority=?1 AND session_kind=?2 AND session_id=?3 AND lease_id=?4 AND client_id=?5",
            params![session.authority.as_str(),session.kind.as_str(),session.id.as_str(),lease.as_str(),client.as_str()],
        )?;
        transaction.execute(
            "INSERT INTO platform_control_receipts(idempotency_key,operation,session_authority,session_kind,session_id,client_id,lease_id,expires_at_ms,revision,recorded_at_ms)
             VALUES(?1,'release',?2,?3,?4,?5,?6,NULL,?7,?8)",
            params![key.as_str(),session.authority.as_str(),session.kind.as_str(),session.id.as_str(),client.as_str(),lease.as_str(),to_db_revision(revision)?,now_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Debug)]
struct RawRecord {
    authority: String,
    kind: String,
    resource_id: String,
    freshness_state: String,
    observed_at_ms: i64,
    revision: i64,
    summary: String,
}
fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok(RawRecord {
        authority: row.get(0)?,
        kind: row.get(1)?,
        resource_id: row.get(2)?,
        freshness_state: row.get(3)?,
        observed_at_ms: row.get(4)?,
        revision: row.get(5)?,
        summary: row.get(6)?,
    })
}
fn record_from_row(raw: RawRecord) -> Stored<ResourceRecord> {
    Ok(ResourceRecord {
        resource: ResourceCoordinate::new(
            authority(&raw.authority)?,
            kind(&raw.kind)?,
            ResourceId::new(raw.resource_id)
                .map_err(|_| PlatformStoreError::Corrupt("resource_id"))?,
        ),
        freshness: Freshness {
            state: freshness_state(&raw.freshness_state)?,
            observed_at: EpochMillis::from_millis(raw.observed_at_ms),
            revision: revision(raw.revision)?,
        },
        summary: PlatformText::new(raw.summary)
            .map_err(|_| PlatformStoreError::Corrupt("summary"))?,
    })
}

struct StoredReceipt {
    receipt: ActionReceipt,
    idempotency_key: String,
    expected_revision: Option<Revision>,
    parameter: Option<String>,
}

type RawReceiptRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    Option<String>,
    String,
    i64,
    i64,
    Option<String>,
);

type RawControlReceiptRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    i64,
);

fn read_receipt_by_key(connection: &Connection, key: &str) -> Stored<Option<StoredReceipt>> {
    read_receipt(connection, "idempotency_key", key)
}
fn read_receipt_by_id(connection: &Connection, id: &str) -> Stored<Option<StoredReceipt>> {
    read_receipt(connection, "receipt_id", id)
}
fn read_receipt(
    connection: &Connection,
    column: &str,
    value: &str,
) -> Stored<Option<StoredReceipt>> {
    let sql = format!(
        "SELECT receipt_id,idempotency_key,action,target_authority,target_kind,target_id,expected_revision,parameter,outcome,revision,recorded_at_ms,explanation FROM platform_receipts WHERE {column}=?1"
    );
    let raw: Option<RawReceiptRow> = connection
        .query_row(&sql, [value], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
            ))
        })
        .optional()?;
    raw.map(
        |(
            id,
            key,
            action_name,
            target_authority,
            target_kind,
            target_id,
            expected,
            parameter,
            outcome_name,
            rev,
            recorded,
            explanation,
        )| {
            Ok(StoredReceipt {
                receipt: ActionReceipt {
                    id: ReceiptId::new(id)
                        .map_err(|_| PlatformStoreError::Corrupt("receipt_id"))?,
                    action: action(&action_name)?,
                    target: ResourceCoordinate::new(
                        authority(&target_authority)?,
                        kind(&target_kind)?,
                        ResourceId::new(target_id)
                            .map_err(|_| PlatformStoreError::Corrupt("target_id"))?,
                    ),
                    outcome: outcome(&outcome_name)?,
                    revision: revision(rev)?,
                    recorded_at: EpochMillis::from_millis(recorded),
                    explanation: explanation
                        .map(PlatformText::new)
                        .transpose()
                        .map_err(|_| PlatformStoreError::Corrupt("explanation"))?,
                },
                idempotency_key: key,
                expected_revision: expected.map(revision).transpose()?,
                parameter,
            })
        },
    )
    .transpose()
}

fn receipt_matches_request(stored: &StoredReceipt, request: &ExecuteRequest) -> bool {
    stored.idempotency_key == request.idempotency_key.as_str()
        && stored.receipt.action == request.action
        && stored.receipt.target == request.target
        && stored.expected_revision == request.expected_revision
        && stored.parameter.as_deref() == request.parameter.as_ref().map(PlatformText::as_str)
}

fn append_receipt_event(connection: &Connection, receipt: &ActionReceipt) -> Stored<()> {
    let resource = ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Receipt,
        ResourceId::new(receipt.id.as_str())
            .map_err(|_| PlatformStoreError::Corrupt("receipt_id"))?,
    );
    let summary = match &receipt.explanation {
        Some(explanation) => format!(
            "{} {}: {}",
            receipt.action.as_str(),
            receipt.outcome.as_str(),
            explanation.as_str()
        ),
        None => format!("{} {}", receipt.action.as_str(), receipt.outcome.as_str()),
    };
    let summary =
        PlatformText::new(summary).map_err(|_| PlatformStoreError::Corrupt("receipt_summary"))?;
    connection.execute(
        "INSERT INTO platform_resources(authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary)
         VALUES(?1,?2,?3,'fresh',?4,?5,?6)
         ON CONFLICT(authority,kind,resource_id) DO UPDATE SET freshness_state='fresh',
           observed_at_ms=excluded.observed_at_ms,revision=excluded.revision,summary=excluded.summary",
        params![resource.authority.as_str(), resource.kind.as_str(), resource.id.as_str(),
            receipt.recorded_at.as_millis(), to_db_revision(receipt.revision)?, summary.as_str()],
    )?;
    let topic_sequence = next_topic_sequence(connection, "receipts")?;
    connection.execute(
        "INSERT INTO platform_events(topic_sequence,topic,authority,kind,resource_id,freshness_state,observed_at_ms,revision,summary)
         VALUES(?1,'receipts',?2,?3,?4,'fresh',?5,?6,?7)",
        params![to_db_u64(topic_sequence,"sequence")?, resource.authority.as_str(), resource.kind.as_str(), resource.id.as_str(),
            receipt.recorded_at.as_millis(), to_db_revision(receipt.revision)?, summary.as_str()],
    )?;
    Ok(())
}
fn read_control_receipt(
    connection: &Connection,
    key: &str,
    operation: &str,
    session: &ResourceCoordinate,
    client: &ClientId,
) -> Stored<Option<ControlLease>> {
    let raw: Option<RawControlReceiptRow> = connection
        .query_row(
            "SELECT operation,session_authority,session_kind,session_id,client_id,lease_id,expires_at_ms,revision
             FROM platform_control_receipts WHERE idempotency_key=?1",
            [key],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((op, a, k, id, c, lease, expires, rev)) = raw else {
        return Ok(None);
    };
    if op != operation
        || a != session.authority.as_str()
        || k != session.kind.as_str()
        || id != session.id.as_str()
        || c != client.as_str()
    {
        return Err(PlatformStoreError::Conflict("idempotency_key"));
    }
    let expires = expires.ok_or(PlatformStoreError::Corrupt("expires_at"))?;
    Ok(Some(ControlLease {
        id: ControlLeaseId::new(lease).map_err(|_| PlatformStoreError::Corrupt("lease_id"))?,
        session: session.clone(),
        client: client.clone(),
        expires_at: EpochMillis::from_millis(expires),
        revision: revision(rev)?,
    }))
}
fn control_receipt_exists(
    connection: &Connection,
    key: &str,
    operation: &str,
    session: &ResourceCoordinate,
    client: &ClientId,
    lease: &str,
) -> Stored<bool> {
    let raw:Option<(String,String,String,String,String,String)>=connection.query_row("SELECT operation,session_authority,session_kind,session_id,client_id,lease_id FROM platform_control_receipts WHERE idempotency_key=?1",[key],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).optional()?;
    match raw {
        None => Ok(false),
        Some((op, a, k, id, c, l))
            if op == operation
                && a == session.authority.as_str()
                && k == session.kind.as_str()
                && id == session.id.as_str()
                && c == client.as_str()
                && l == lease =>
        {
            Ok(true)
        }
        Some(_) => Err(PlatformStoreError::Conflict("idempotency_key")),
    }
}

fn initialize(connection: &mut Connection) -> Stored<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == PLATFORM_STORE_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(PlatformStoreError::SchemaVersion {
            found: version,
            supported: PLATFORM_STORE_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(PlatformStoreError::SchemaVersion {
            found: 0,
            supported: PLATFORM_STORE_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", PLATFORM_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}
fn secure_path(path: &Path) -> Stored<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => PlatformStoreError::Io(io),
        other => PlatformStoreError::InsecurePath(other.to_string()),
    })
}
fn next_revision(connection: &Connection) -> Stored<Revision> {
    connection.execute(
        "UPDATE platform_meta SET revision=revision+1 WHERE singleton=1",
        [],
    )?;
    let value: i64 = connection.query_row(
        "SELECT revision FROM platform_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    revision(value)
}
fn last_topic_sequence(connection: &Connection, topic: &str) -> Stored<u64> {
    let value: i64 = connection.query_row(
        "SELECT COALESCE(max(topic_sequence),1) FROM platform_events WHERE topic=?1",
        [topic],
        |row| row.get(0),
    )?;
    from_db_u64(value, "sequence")
}

fn next_topic_sequence(connection: &Connection, topic: &str) -> Stored<u64> {
    last_topic_sequence(connection, topic)?
        .checked_add(1)
        .ok_or(PlatformStoreError::InvalidField("sequence"))
}
fn deterministic_id(prefix: &str, key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!(
        "{prefix}_{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn validate_time(value: i64) -> Stored<()> {
    if value < 0 {
        Err(PlatformStoreError::InvalidField("time"))
    } else {
        Ok(())
    }
}
fn validate_topic(value: &str) -> Stored<()> {
    CursorTopic::new(value)
        .map(|_| ())
        .map_err(|_| PlatformStoreError::InvalidField("topic"))
}
fn validate_session(value: &ResourceCoordinate) -> Stored<()> {
    if value.authority == ResourceAuthority::Automonique && value.kind == ResourceKind::Session {
        Ok(())
    } else {
        Err(PlatformStoreError::InvalidField("session"))
    }
}
fn validate_record(value: &ResourceRecord) -> Stored<()> {
    validate_time(value.freshness.observed_at.as_millis())
}
fn to_db_u64(value: u64, field: &'static str) -> Stored<i64> {
    i64::try_from(value).map_err(|_| PlatformStoreError::InvalidField(field))
}
fn from_db_u64(value: i64, field: &'static str) -> Stored<u64> {
    u64::try_from(value).map_err(|_| PlatformStoreError::Corrupt(field))
}
fn to_db_revision(value: Revision) -> Stored<i64> {
    to_db_u64(value.get(), "revision")
}
fn revision(value: i64) -> Stored<Revision> {
    Revision::new(from_db_u64(value, "revision")?)
        .map_err(|_| PlatformStoreError::Corrupt("revision"))
}
fn platform_cursor(
    authority: ResourceAuthority,
    topic: &str,
    sequence: u64,
) -> Stored<PlatformCursor> {
    Ok(PlatformCursor {
        authority,
        topic: CursorTopic::new(topic).map_err(|_| PlatformStoreError::InvalidField("topic"))?,
        sequence: Revision::new(sequence.max(1))
            .map_err(|_| PlatformStoreError::Corrupt("sequence"))?,
    })
}
fn authority(value: &str) -> Stored<ResourceAuthority> {
    ResourceAuthority::parse(value).map_err(|_| PlatformStoreError::Corrupt("authority"))
}
fn kind(value: &str) -> Stored<ResourceKind> {
    ResourceKind::parse(value).map_err(|_| PlatformStoreError::Corrupt("kind"))
}
fn action(value: &str) -> Stored<PlatformAction> {
    PlatformAction::parse(value).map_err(|_| PlatformStoreError::Corrupt("action"))
}
fn outcome(value: &str) -> Stored<ReceiptOutcome> {
    ReceiptOutcome::parse(value).map_err(|_| PlatformStoreError::Corrupt("outcome"))
}
fn freshness_state(value: &str) -> Stored<FreshnessState> {
    FreshnessState::parse(value).map_err(|_| PlatformStoreError::Corrupt("freshness"))
}
