// SPDX-License-Identifier: Elastic-2.0

//! Canonical, tenant-scoped conversational and operational memory.
//!
//! This is deliberately separate from [`crate::context_memory`]. That store is
//! an immutable digest ledger proving that context was captured; this store
//! owns the actual bounded content, its provenance, lifecycle and retrieval.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

pub const AGENT_MEMORY_SCHEMA_VERSION: u32 = 1;
pub const MAX_MEMORY_CONTENT_BYTES: usize = 8 * 1024;
pub const MAX_MESSAGE_CONTENT_BYTES: usize = 32 * 1024;
pub const MAX_MEMORY_FIELD_BYTES: usize = 512;
pub const MAX_SEARCH_RESULTS: usize = 32;
pub const DEFAULT_RAW_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1_000;

#[must_use]
pub fn redact_content(text: &str) -> String {
    let normalized = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut redacted = Vec::new();
    let mut redact_next = false;
    for token in normalized.split_whitespace() {
        let lowered = token.to_ascii_lowercase();
        let telegram_token = token.split_once(':').is_some_and(|(prefix, suffix)| {
            prefix.len() >= 5
                && prefix.bytes().all(|byte| byte.is_ascii_digit())
                && suffix.starts_with("AA")
                && suffix.len() >= 20
        });
        let secret = redact_next
            || (token.len() >= 16
                && (lowered.contains("sk-")
                    || lowered.starts_with("xoxb-")
                    || lowered.starts_with("xapp-")
                    || lowered.contains("api_key=")
                    || lowered.contains("apikey=")
                    || lowered.contains("password=")
                    || lowered.contains("token=")))
            || telegram_token;
        redacted.push(if secret { "[REDACTED]" } else { token });
        redact_next = matches!(
            lowered.trim_end_matches([':', '=']),
            "password" | "passwd" | "api_key" | "apikey" | "bearer" | "token"
        );
    }
    redacted.join(" ")
}

const SCHEMA_V1: &str = r#"
CREATE TABLE identity_bindings (
    binding_id INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    platform TEXT NOT NULL,
    application TEXT NOT NULL,
    external_tenant TEXT NOT NULL,
    external_user TEXT NOT NULL,
    linked_at_ms INTEGER NOT NULL CHECK (linked_at_ms >= 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision = 1),
    UNIQUE (platform, application, external_tenant, external_user)
) STRICT;

CREATE INDEX identity_bindings_by_actor
ON identity_bindings(tenant, actor, binding_id);

CREATE TABLE conversations (
    conversation_id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    transport TEXT NOT NULL,
    external_scope TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    last_message_at_ms INTEGER NOT NULL CHECK (last_message_at_ms >= created_at_ms),
    archived_at_ms INTEGER,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)
) STRICT;

CREATE TABLE conversation_heads (
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    transport TEXT NOT NULL,
    external_scope TEXT NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    PRIMARY KEY (tenant, actor, transport, external_scope)
) STRICT;

CREATE TABLE messages (
    message_id INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    transport TEXT NOT NULL,
    transport_key TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system', 'tool')),
    content TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= created_at_ms),
    UNIQUE (transport, transport_key)
) STRICT;

CREATE INDEX messages_by_conversation
ON messages(tenant, conversation_id, created_at_ms, message_id);
CREATE INDEX messages_by_expiry ON messages(expires_at_ms, message_id);

CREATE VIRTUAL TABLE message_fts USING fts5(
    content,
    message_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO message_fts(rowid, content, message_id)
    VALUES (new.message_id, new.content, new.message_id);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    DELETE FROM message_fts WHERE rowid = old.message_id;
END;

CREATE TABLE memories (
    memory_id INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (
        kind IN ('user_profile', 'workspace', 'team', 'task', 'episodic', 'procedure')
    ),
    content TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('candidate', 'active', 'superseded', 'deleted')
    ),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 1000),
    sensitivity TEXT NOT NULL CHECK (
        sensitivity IN ('public', 'internal', 'personal', 'restricted')
    ),
    visibility TEXT NOT NULL CHECK (
        visibility IN ('private', 'team', 'tenant')
    ),
    source_transport TEXT NOT NULL,
    source_key TEXT NOT NULL,
    valid_from_ms INTEGER NOT NULL CHECK (valid_from_ms >= 0),
    expires_at_ms INTEGER,
    review_at_ms INTEGER,
    superseded_by INTEGER REFERENCES memories(memory_id),
    deleted_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    UNIQUE (tenant, source_transport, source_key, kind, scope),
    CHECK (expires_at_ms IS NULL OR expires_at_ms >= valid_from_ms),
    CHECK (review_at_ms IS NULL OR review_at_ms >= created_at_ms),
    CHECK (
        (status = 'superseded' AND superseded_by IS NOT NULL)
        OR (status != 'superseded' AND superseded_by IS NULL)
    ),
    CHECK (
        (status = 'deleted' AND deleted_at_ms IS NOT NULL)
        OR (status != 'deleted' AND deleted_at_ms IS NULL)
    )
) STRICT;

CREATE INDEX memories_by_scope
ON memories(tenant, actor, scope, status, kind, updated_at_ms DESC);
CREATE INDEX memories_by_review
ON memories(tenant, status, review_at_ms, memory_id);

CREATE VIRTUAL TABLE memory_fts USING fts5(
    content,
    memory_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER memories_fts_insert AFTER INSERT ON memories BEGIN
    INSERT INTO memory_fts(rowid, content, memory_id)
    VALUES (new.memory_id, new.content, new.memory_id);
END;

CREATE TABLE memory_audit (
    audit_id INTEGER PRIMARY KEY,
    memory_id INTEGER NOT NULL REFERENCES memories(memory_id),
    tenant TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('proposed', 'activated', 'superseded', 'deleted', 'denied')
    ),
    cause TEXT NOT NULL,
    at_ms INTEGER NOT NULL CHECK (at_ms >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 1)
) STRICT;

CREATE INDEX memory_audit_by_memory ON memory_audit(memory_id, audit_id);
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    UserProfile,
    Workspace,
    Team,
    Task,
    Episodic,
    Procedure,
}

impl MemoryKind {
    pub const ALL: [Self; 6] = [
        Self::UserProfile,
        Self::Workspace,
        Self::Team,
        Self::Task,
        Self::Episodic,
        Self::Procedure,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserProfile => "user_profile",
            Self::Workspace => "workspace",
            Self::Team => "team",
            Self::Task => "task",
            Self::Episodic => "episodic",
            Self::Procedure => "procedure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryStatus {
    Candidate,
    Active,
    Superseded,
    Deleted,
}

impl MemoryStatus {
    const ALL: [Self; 4] = [
        Self::Candidate,
        Self::Active,
        Self::Superseded,
        Self::Deleted,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Deleted => "deleted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemorySensitivity {
    Public,
    Internal,
    Personal,
    Restricted,
}

impl MemorySensitivity {
    const ALL: [Self; 4] = [
        Self::Public,
        Self::Internal,
        Self::Personal,
        Self::Restricted,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Personal => "personal",
            Self::Restricted => "restricted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|sensitivity| sensitivity.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryVisibility {
    Private,
    Team,
    Tenant,
}

impl MemoryVisibility {
    const ALL: [Self; 3] = [Self::Private, Self::Team, Self::Tenant];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Team => "team",
            Self::Tenant => "tenant",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|visibility| visibility.as_str() == value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageInput<'a> {
    pub tenant: &'a str,
    pub actor: &'a str,
    pub conversation_id: &'a str,
    pub transport: &'a str,
    pub external_scope: &'a str,
    pub transport_key: &'a str,
    pub role: &'a str,
    pub content: &'a str,
    pub created_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalIdentity<'a> {
    pub platform: &'a str,
    pub application: &'a str,
    pub external_tenant: &'a str,
    pub external_user: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemorySupersession<'a> {
    pub old_id: i64,
    pub old_revision: u32,
    pub replacement_id: i64,
    pub cause: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryInput<'a> {
    pub tenant: &'a str,
    pub actor: &'a str,
    pub scope: &'a str,
    pub kind: MemoryKind,
    pub content: &'a str,
    pub status: MemoryStatus,
    pub confidence: u16,
    pub sensitivity: MemorySensitivity,
    pub visibility: MemoryVisibility,
    pub source_transport: &'a str,
    pub source_key: &'a str,
    pub valid_from_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub review_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRecord {
    pub id: i64,
    pub tenant: String,
    pub actor: String,
    pub scope: String,
    pub kind: MemoryKind,
    pub content: String,
    pub status: MemoryStatus,
    pub confidence: u16,
    pub sensitivity: MemorySensitivity,
    pub visibility: MemoryVisibility,
    pub source_transport: String,
    pub source_key: String,
    pub valid_from_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub review_at_ms: Option<i64>,
    pub superseded_by: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationMessage {
    pub id: i64,
    pub role: String,
    pub content: String,
    pub created_at_ms: i64,
}

impl MemoryRecord {
    #[must_use]
    pub fn reference(&self) -> String {
        format!("M-{}", self.id)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryCounts {
    pub active: usize,
    pub candidates: usize,
    pub superseded: usize,
    pub deleted: usize,
    pub messages: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDisposition {
    Recorded,
    Duplicate,
}

#[derive(Debug)]
pub enum AgentMemoryError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    Conflict,
    NotFound,
    StaleRevision,
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Corrupt(&'static str),
}

impl fmt::Display for AgentMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => write!(formatter, "memory path is insecure: {reason}"),
            Self::SchemaVersion { found, supported } => {
                write!(
                    formatter,
                    "memory schema {found} is unsupported; expected {supported}"
                )
            }
            Self::InvalidField(field) => write!(formatter, "memory field is invalid: {field}"),
            Self::Conflict => formatter.write_str("memory binding conflicts with a durable row"),
            Self::NotFound => formatter.write_str("memory was not found"),
            Self::StaleRevision => formatter.write_str("memory revision is stale"),
            Self::Sqlite(error) => write!(formatter, "memory sqlite failure: {error}"),
            Self::Io(error) => write!(formatter, "memory filesystem failure: {error}"),
            Self::Corrupt(field) => write!(formatter, "memory row is corrupt: {field}"),
        }
    }
}

impl Error for AgentMemoryError {}

impl From<rusqlite::Error> for AgentMemoryError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for AgentMemoryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

type Kept<T> = Result<T, AgentMemoryError>;

#[derive(Debug)]
pub struct AgentMemoryStore {
    connection: Connection,
    path: PathBuf,
}

impl AgentMemoryStore {
    pub fn open(path: impl AsRef<Path>) -> Kept<Self> {
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
            return Err(AgentMemoryError::Corrupt("journal_mode"));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bind_identity(
        &mut self,
        tenant: &str,
        actor: &str,
        identity: ExternalIdentity<'_>,
        linked_at_ms: i64,
    ) -> Kept<WriteDisposition> {
        let ExternalIdentity {
            platform,
            application,
            external_tenant,
            external_user,
        } = identity;
        for (value, field) in [
            (tenant, "tenant"),
            (actor, "actor"),
            (platform, "platform"),
            (application, "application"),
            (external_tenant, "external_tenant"),
            (external_user, "external_user"),
        ] {
            validate_field(value, field)?;
        }
        validate_time(linked_at_ms, "linked_at_ms")?;
        let existing: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT tenant, actor FROM identity_bindings
                 WHERE platform=?1 AND application=?2 AND external_tenant=?3 AND external_user=?4",
                params![platform, application, external_tenant, external_user],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((recorded_tenant, recorded_actor)) = existing {
            return if recorded_tenant == tenant && recorded_actor == actor {
                Ok(WriteDisposition::Duplicate)
            } else {
                Err(AgentMemoryError::Conflict)
            };
        }
        self.connection.execute(
            "INSERT INTO identity_bindings
             (tenant, actor, platform, application, external_tenant, external_user, linked_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                tenant,
                actor,
                platform,
                application,
                external_tenant,
                external_user,
                linked_at_ms
            ],
        )?;
        Ok(WriteDisposition::Recorded)
    }

    pub fn resolve_identity(
        &self,
        platform: &str,
        application: &str,
        external_tenant: &str,
        external_user: &str,
    ) -> Kept<Option<(String, String)>> {
        self.connection
            .query_row(
                "SELECT tenant, actor FROM identity_bindings
                 WHERE platform=?1 AND application=?2 AND external_tenant=?3 AND external_user=?4",
                params![platform, application, external_tenant, external_user],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn record_message(&mut self, input: &MessageInput<'_>) -> Kept<WriteDisposition> {
        validate_message_input(input)?;
        let expires_at_ms = input
            .created_at_ms
            .checked_add(DEFAULT_RAW_RETENTION_MS)
            .ok_or(AgentMemoryError::InvalidField("expires_at_ms"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT role, content FROM messages WHERE transport=?1 AND transport_key=?2",
                params![input.transport, input.transport_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((role, content)) = existing {
            return if role == input.role && content == input.content {
                Ok(WriteDisposition::Duplicate)
            } else {
                Err(AgentMemoryError::Conflict)
            };
        }
        transaction.execute(
            "INSERT INTO conversations
             (conversation_id, tenant, actor, transport, external_scope, created_at_ms, last_message_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?6)
             ON CONFLICT(conversation_id) DO UPDATE SET
                 last_message_at_ms=MAX(last_message_at_ms, excluded.last_message_at_ms),
                 revision=revision+1",
            params![
                input.conversation_id,
                input.tenant,
                input.actor,
                input.transport,
                input.external_scope,
                input.created_at_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO conversation_heads
             (tenant,actor,transport,external_scope,conversation_id)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(tenant,actor,transport,external_scope) DO NOTHING",
            params![
                input.tenant,
                input.actor,
                input.transport,
                input.external_scope,
                input.conversation_id
            ],
        )?;
        transaction.execute(
            "INSERT INTO messages
             (tenant, actor, conversation_id, transport, transport_key, role, content,
              created_at_ms, expires_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                input.tenant,
                input.actor,
                input.conversation_id,
                input.transport,
                input.transport_key,
                input.role,
                input.content,
                input.created_at_ms,
                expires_at_ms
            ],
        )?;
        transaction.commit()?;
        Ok(WriteDisposition::Recorded)
    }

    /// Resolve one unexpired message by its exact external transport identity.
    pub fn message_by_transport_key(
        &self,
        tenant: &str,
        actor: &str,
        transport: &str,
        transport_key: &str,
        at_ms: i64,
    ) -> Kept<Option<ConversationMessage>> {
        for (value, field) in [
            (tenant, "tenant"),
            (actor, "actor"),
            (transport, "transport"),
            (transport_key, "transport_key"),
        ] {
            validate_field(value, field)?;
        }
        validate_time(at_ms, "at_ms")?;
        self.connection
            .query_row(
                "SELECT message_id,role,content,created_at_ms FROM messages
                 WHERE tenant=?1 AND actor=?2 AND transport=?3 AND transport_key=?4
                   AND expires_at_ms>?5",
                params![tenant, actor, transport, transport_key, at_ms],
                |row| {
                    Ok(ConversationMessage {
                        id: row.get(0)?,
                        role: row.get(1)?,
                        content: row.get(2)?,
                        created_at_ms: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn current_conversation(
        &self,
        tenant: &str,
        actor: &str,
        transport: &str,
        external_scope: &str,
    ) -> Kept<Option<String>> {
        self.connection
            .query_row(
                "SELECT conversation_id FROM conversation_heads
                 WHERE tenant=?1 AND actor=?2 AND transport=?3 AND external_scope=?4",
                params![tenant, actor, transport, external_scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn start_conversation(
        &mut self,
        tenant: &str,
        actor: &str,
        transport: &str,
        external_scope: &str,
        conversation_id: &str,
        at_ms: i64,
    ) -> Kept<u32> {
        for (value, field) in [
            (tenant, "tenant"),
            (actor, "actor"),
            (transport, "transport"),
            (external_scope, "external_scope"),
            (conversation_id, "conversation_id"),
        ] {
            validate_field(value, field)?;
        }
        validate_time(at_ms, "at_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO conversations
             (conversation_id,tenant,actor,transport,external_scope,created_at_ms,last_message_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![conversation_id, tenant, actor, transport, external_scope, at_ms],
        )?;
        transaction.execute(
            "INSERT INTO conversation_heads
             (tenant,actor,transport,external_scope,conversation_id)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(tenant,actor,transport,external_scope) DO UPDATE SET
                 conversation_id=excluded.conversation_id,
                 revision=conversation_heads.revision+1",
            params![tenant, actor, transport, external_scope, conversation_id],
        )?;
        let revision: u32 = transaction.query_row(
            "SELECT revision FROM conversation_heads
             WHERE tenant=?1 AND actor=?2 AND transport=?3 AND external_scope=?4",
            params![tenant, actor, transport, external_scope],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(revision)
    }

    pub fn recent_messages(
        &self,
        tenant: &str,
        actor: &str,
        conversation_id: &str,
        at_ms: i64,
        limit: usize,
    ) -> Kept<Vec<ConversationMessage>> {
        validate_field(tenant, "tenant")?;
        validate_field(actor, "actor")?;
        validate_field(conversation_id, "conversation_id")?;
        validate_time(at_ms, "at_ms")?;
        let limit = limit.clamp(1, MAX_SEARCH_RESULTS);
        let mut statement = self.connection.prepare(
            "SELECT message_id,role,content,created_at_ms FROM (
                 SELECT message_id,role,content,created_at_ms
                 FROM messages
                 WHERE tenant=?1 AND actor=?2 AND conversation_id=?3 AND expires_at_ms>?4
                 ORDER BY created_at_ms DESC,message_id DESC LIMIT ?5
             ) ORDER BY created_at_ms ASC,message_id ASC",
        )?;
        let rows = statement.query_map(
            params![tenant, actor, conversation_id, at_ms, limit],
            |row| {
                Ok(ConversationMessage {
                    id: row.get(0)?,
                    role: row.get(1)?,
                    content: row.get(2)?,
                    created_at_ms: row.get(3)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn record_memory(&mut self, input: &MemoryInput<'_>) -> Kept<MemoryRecord> {
        validate_memory_input(input)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read_memory_by_source(
            &transaction,
            input.tenant,
            input.source_transport,
            input.source_key,
            input.kind,
            input.scope,
        )?;
        if let Some(record) = existing {
            return if same_memory(&record, input) {
                Ok(record)
            } else {
                Err(AgentMemoryError::Conflict)
            };
        }
        transaction.execute(
            "INSERT INTO memories
             (tenant,actor,scope,kind,content,status,confidence,sensitivity,visibility,
              source_transport,source_key,valid_from_ms,expires_at_ms,review_at_ms,
              created_at_ms,updated_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
            params![
                input.tenant,
                input.actor,
                input.scope,
                input.kind.as_str(),
                input.content,
                input.status.as_str(),
                input.confidence,
                input.sensitivity.as_str(),
                input.visibility.as_str(),
                input.source_transport,
                input.source_key,
                input.valid_from_ms,
                input.expires_at_ms,
                input.review_at_ms,
                input.created_at_ms
            ],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO memory_audit
             (memory_id,tenant,actor,action,cause,at_ms,revision)
             VALUES (?1,?2,?3,?4,'capture',?5,1)",
            params![
                id,
                input.tenant,
                input.actor,
                if input.status == MemoryStatus::Active {
                    "activated"
                } else {
                    "proposed"
                },
                input.created_at_ms
            ],
        )?;
        let record = read_memory(&transaction, input.tenant, id)?
            .ok_or(AgentMemoryError::Corrupt("inserted_memory"))?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn activate(
        &mut self,
        tenant: &str,
        actor: &str,
        id: i64,
        expected_revision: u32,
        cause: &str,
        at_ms: i64,
    ) -> Kept<MemoryRecord> {
        self.transition(
            tenant,
            actor,
            id,
            expected_revision,
            MemoryStatus::Candidate,
            MemoryStatus::Active,
            "activated",
            cause,
            at_ms,
        )
    }

    pub fn deny(
        &mut self,
        tenant: &str,
        actor: &str,
        id: i64,
        expected_revision: u32,
        cause: &str,
        at_ms: i64,
    ) -> Kept<MemoryRecord> {
        self.transition(
            tenant,
            actor,
            id,
            expected_revision,
            MemoryStatus::Candidate,
            MemoryStatus::Deleted,
            "denied",
            cause,
            at_ms,
        )
    }

    pub fn forget(
        &mut self,
        tenant: &str,
        actor: &str,
        id: i64,
        expected_revision: u32,
        cause: &str,
        at_ms: i64,
    ) -> Kept<MemoryRecord> {
        self.transition(
            tenant,
            actor,
            id,
            expected_revision,
            MemoryStatus::Active,
            MemoryStatus::Deleted,
            "deleted",
            cause,
            at_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition(
        &mut self,
        tenant: &str,
        actor: &str,
        id: i64,
        expected_revision: u32,
        from: MemoryStatus,
        to: MemoryStatus,
        action: &str,
        cause: &str,
        at_ms: i64,
    ) -> Kept<MemoryRecord> {
        validate_field(tenant, "tenant")?;
        validate_field(actor, "actor")?;
        validate_field(cause, "cause")?;
        validate_time(at_ms, "at_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_memory(&transaction, tenant, id)?.ok_or(AgentMemoryError::NotFound)?;
        if current.actor != actor {
            return Err(AgentMemoryError::NotFound);
        }
        if current.revision != expected_revision {
            return Err(AgentMemoryError::StaleRevision);
        }
        if current.status != from {
            return Err(AgentMemoryError::Conflict);
        }
        let deleted_at = (to == MemoryStatus::Deleted).then_some(at_ms);
        transaction.execute(
            "UPDATE memories SET status=?1, deleted_at_ms=?2, updated_at_ms=?3,
             revision=revision+1 WHERE memory_id=?4 AND tenant=?5 AND revision=?6",
            params![
                to.as_str(),
                deleted_at,
                at_ms,
                id,
                tenant,
                expected_revision
            ],
        )?;
        let revision = expected_revision + 1;
        transaction.execute(
            "INSERT INTO memory_audit
             (memory_id,tenant,actor,action,cause,at_ms,revision)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![id, tenant, actor, action, cause, at_ms, revision],
        )?;
        let record = read_memory(&transaction, tenant, id)?
            .ok_or(AgentMemoryError::Corrupt("transitioned_memory"))?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn supersede(
        &mut self,
        tenant: &str,
        actor: &str,
        supersession: MemorySupersession<'_>,
        at_ms: i64,
    ) -> Kept<MemoryRecord> {
        let MemorySupersession {
            old_id,
            old_revision,
            replacement_id,
            cause,
        } = supersession;
        validate_field(cause, "cause")?;
        validate_time(at_ms, "at_ms")?;
        if old_id == replacement_id {
            return Err(AgentMemoryError::InvalidField("replacement_id"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_memory(&transaction, tenant, old_id)?.ok_or(AgentMemoryError::NotFound)?;
        let replacement =
            read_memory(&transaction, tenant, replacement_id)?.ok_or(AgentMemoryError::NotFound)?;
        if old.actor != actor || replacement.actor != actor {
            return Err(AgentMemoryError::NotFound);
        }
        if old.revision != old_revision {
            return Err(AgentMemoryError::StaleRevision);
        }
        if old.status != MemoryStatus::Active || replacement.status != MemoryStatus::Active {
            return Err(AgentMemoryError::Conflict);
        }
        transaction.execute(
            "UPDATE memories SET status='superseded', superseded_by=?1,
             updated_at_ms=?2, revision=revision+1
             WHERE tenant=?3 AND memory_id=?4 AND revision=?5",
            params![replacement_id, at_ms, tenant, old_id, old_revision],
        )?;
        transaction.execute(
            "INSERT INTO memory_audit
             (memory_id,tenant,actor,action,cause,at_ms,revision)
             VALUES (?1,?2,?3,'superseded',?4,?5,?6)",
            params![old_id, tenant, actor, cause, at_ms, old_revision + 1],
        )?;
        let record = read_memory(&transaction, tenant, old_id)?
            .ok_or(AgentMemoryError::Corrupt("superseded_memory"))?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn item(&self, tenant: &str, actor: &str, id: i64) -> Kept<Option<MemoryRecord>> {
        let item = read_memory(&self.connection, tenant, id)?;
        Ok(item.filter(|item| item.actor == actor || item.visibility != MemoryVisibility::Private))
    }

    pub fn search(
        &self,
        tenant: &str,
        actor: &str,
        query: &str,
        now_ms: i64,
        limit: usize,
    ) -> Kept<Vec<MemoryRecord>> {
        validate_field(tenant, "tenant")?;
        validate_field(actor, "actor")?;
        validate_time(now_ms, "now_ms")?;
        if limit == 0 || limit > MAX_SEARCH_RESULTS {
            return Err(AgentMemoryError::InvalidField("limit"));
        }
        let fts = fts_query(query)?;
        let mut statement = self.connection.prepare(
            "SELECT m.memory_id,m.tenant,m.actor,m.scope,m.kind,m.content,m.status,
                    m.confidence,m.sensitivity,m.visibility,m.source_transport,m.source_key,
                    m.valid_from_ms,m.expires_at_ms,m.review_at_ms,m.superseded_by,
                    m.created_at_ms,m.updated_at_ms,m.revision
             FROM memory_fts f JOIN memories m ON m.memory_id=f.memory_id
             WHERE memory_fts MATCH ?1 AND m.tenant=?2 AND m.status='active'
               AND (m.expires_at_ms IS NULL OR m.expires_at_ms>?3)
               AND (m.visibility!='private' OR m.actor=?4)
             ORDER BY bm25(memory_fts), m.updated_at_ms DESC, m.memory_id DESC
             LIMIT ?5",
        )?;
        let rows =
            statement.query_map(params![fts, tenant, now_ms, actor, limit], read_memory_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub fn recent(
        &self,
        tenant: &str,
        actor: &str,
        now_ms: i64,
        limit: usize,
    ) -> Kept<Vec<MemoryRecord>> {
        if limit == 0 || limit > MAX_SEARCH_RESULTS {
            return Err(AgentMemoryError::InvalidField("limit"));
        }
        let mut statement = self.connection.prepare(
            "SELECT memory_id,tenant,actor,scope,kind,content,status,confidence,
                    sensitivity,visibility,source_transport,source_key,valid_from_ms,
                    expires_at_ms,review_at_ms,superseded_by,created_at_ms,updated_at_ms,revision
             FROM memories WHERE tenant=?1 AND status='active'
               AND (expires_at_ms IS NULL OR expires_at_ms>?2)
               AND (visibility!='private' OR actor=?3)
             ORDER BY updated_at_ms DESC, memory_id DESC LIMIT ?4",
        )?;
        let rows = statement.query_map(params![tenant, now_ms, actor, limit], read_memory_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub fn active_for_actor(
        &self,
        tenant: &str,
        actor: &str,
        now_ms: i64,
    ) -> Kept<Vec<MemoryRecord>> {
        validate_field(tenant, "tenant")?;
        validate_field(actor, "actor")?;
        validate_time(now_ms, "now_ms")?;
        let mut statement = self.connection.prepare(
            "SELECT memory_id,tenant,actor,scope,kind,content,status,confidence,
                    sensitivity,visibility,source_transport,source_key,valid_from_ms,
                    expires_at_ms,review_at_ms,superseded_by,created_at_ms,updated_at_ms,revision
             FROM memories WHERE tenant=?1 AND status='active'
               AND (expires_at_ms IS NULL OR expires_at_ms>?2)
               AND (visibility!='private' OR actor=?3)
             ORDER BY kind,updated_at_ms DESC,memory_id DESC LIMIT 4096",
        )?;
        let rows = statement.query_map(params![tenant, now_ms, actor], read_memory_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub fn proposals(&self, tenant: &str, actor: &str, limit: usize) -> Kept<Vec<MemoryRecord>> {
        if limit == 0 || limit > MAX_SEARCH_RESULTS {
            return Err(AgentMemoryError::InvalidField("limit"));
        }
        let mut statement = self.connection.prepare(
            "SELECT memory_id,tenant,actor,scope,kind,content,status,confidence,
                    sensitivity,visibility,source_transport,source_key,valid_from_ms,
                    expires_at_ms,review_at_ms,superseded_by,created_at_ms,updated_at_ms,revision
             FROM memories WHERE tenant=?1 AND actor=?2 AND status='candidate'
             ORDER BY created_at_ms, memory_id LIMIT ?3",
        )?;
        let rows = statement.query_map(params![tenant, actor, limit], read_memory_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub fn counts(&self, tenant: &str, actor: &str) -> Kept<MemoryCounts> {
        let count = |status: MemoryStatus| -> Kept<usize> {
            let value: i64 = self.connection.query_row(
                "SELECT count(*) FROM memories WHERE tenant=?1 AND status=?2
                 AND (visibility!='private' OR actor=?3)",
                params![tenant, status.as_str(), actor],
                |row| row.get(0),
            )?;
            usize::try_from(value).map_err(|_| AgentMemoryError::Corrupt("count"))
        };
        let messages: i64 = self.connection.query_row(
            "SELECT count(*) FROM messages WHERE tenant=?1 AND actor=?2",
            params![tenant, actor],
            |row| row.get(0),
        )?;
        Ok(MemoryCounts {
            active: count(MemoryStatus::Active)?,
            candidates: count(MemoryStatus::Candidate)?,
            superseded: count(MemoryStatus::Superseded)?,
            deleted: count(MemoryStatus::Deleted)?,
            messages: usize::try_from(messages)
                .map_err(|_| AgentMemoryError::Corrupt("message_count"))?,
        })
    }

    pub fn prune_messages(&mut self, now_ms: i64) -> Kept<usize> {
        validate_time(now_ms, "now_ms")?;
        self.connection
            .execute("DELETE FROM messages WHERE expires_at_ms<=?1", [now_ms])
            .map_err(Into::into)
    }

    /// Remove transport control commands from conversational history.
    ///
    /// The durable transport inbox remains the source of truth for commands;
    /// retaining a second copy here only pollutes natural-language recall.
    pub fn prune_control_messages(&mut self, tenant: &str, actor: &str) -> Kept<usize> {
        validate_field(tenant, "tenant")?;
        validate_field(actor, "actor")?;
        self.connection
            .execute(
                "DELETE FROM messages
                 WHERE tenant=?1 AND actor=?2 AND role='user'
                   AND ltrim(content) LIKE '/%'",
                params![tenant, actor],
            )
            .map_err(Into::into)
    }
}

fn validate_message_input(input: &MessageInput<'_>) -> Kept<()> {
    for (value, field) in [
        (input.tenant, "tenant"),
        (input.actor, "actor"),
        (input.conversation_id, "conversation_id"),
        (input.transport, "transport"),
        (input.external_scope, "external_scope"),
        (input.transport_key, "transport_key"),
    ] {
        validate_field(value, field)?;
    }
    if !matches!(input.role, "user" | "assistant" | "system" | "tool") {
        return Err(AgentMemoryError::InvalidField("role"));
    }
    validate_content(input.content, MAX_MESSAGE_CONTENT_BYTES, "content")?;
    validate_time(input.created_at_ms, "created_at_ms")
}

fn validate_memory_input(input: &MemoryInput<'_>) -> Kept<()> {
    for (value, field) in [
        (input.tenant, "tenant"),
        (input.actor, "actor"),
        (input.scope, "scope"),
        (input.source_transport, "source_transport"),
        (input.source_key, "source_key"),
    ] {
        validate_field(value, field)?;
    }
    validate_content(input.content, MAX_MEMORY_CONTENT_BYTES, "content")?;
    if input.confidence > 1000 {
        return Err(AgentMemoryError::InvalidField("confidence"));
    }
    validate_time(input.valid_from_ms, "valid_from_ms")?;
    validate_time(input.created_at_ms, "created_at_ms")?;
    if input
        .expires_at_ms
        .is_some_and(|value| value < input.valid_from_ms)
    {
        return Err(AgentMemoryError::InvalidField("expires_at_ms"));
    }
    if input
        .review_at_ms
        .is_some_and(|value| value < input.created_at_ms)
    {
        return Err(AgentMemoryError::InvalidField("review_at_ms"));
    }
    Ok(())
}

fn same_memory(record: &MemoryRecord, input: &MemoryInput<'_>) -> bool {
    record.actor == input.actor
        && record.content == input.content
        && record.status == input.status
        && record.confidence == input.confidence
        && record.sensitivity == input.sensitivity
        && record.visibility == input.visibility
        && record.valid_from_ms == input.valid_from_ms
        && record.expires_at_ms == input.expires_at_ms
        && record.review_at_ms == input.review_at_ms
}

fn validate_field(value: &str, field: &'static str) -> Kept<()> {
    if value.is_empty()
        || value.len() > MAX_MEMORY_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(AgentMemoryError::InvalidField(field));
    }
    Ok(())
}

fn validate_content(value: &str, max: usize, field: &'static str) -> Kept<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(AgentMemoryError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Kept<()> {
    if value < 0 {
        return Err(AgentMemoryError::InvalidField(field));
    }
    Ok(())
}

fn fts_query(query: &str) -> Kept<String> {
    let terms = query
        .split(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '-'
        })
        .filter(|term| !term.is_empty())
        .take(12)
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err(AgentMemoryError::InvalidField("query"));
    }
    Ok(terms.join(" OR "))
}

fn secure_path(path: &Path) -> Kept<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => AgentMemoryError::Io(io),
        other => AgentMemoryError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Kept<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == AGENT_MEMORY_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(AgentMemoryError::SchemaVersion {
            found: version,
            supported: AGENT_MEMORY_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(AgentMemoryError::SchemaVersion {
            found: 0,
            supported: AGENT_MEMORY_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", AGENT_MEMORY_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn read_memory_by_source(
    connection: &Connection,
    tenant: &str,
    source_transport: &str,
    source_key: &str,
    kind: MemoryKind,
    scope: &str,
) -> Kept<Option<MemoryRecord>> {
    connection
        .query_row(
            "SELECT memory_id,tenant,actor,scope,kind,content,status,confidence,
                    sensitivity,visibility,source_transport,source_key,valid_from_ms,
                    expires_at_ms,review_at_ms,superseded_by,created_at_ms,updated_at_ms,revision
             FROM memories WHERE tenant=?1 AND source_transport=?2 AND source_key=?3
             AND kind=?4 AND scope=?5",
            params![tenant, source_transport, source_key, kind.as_str(), scope],
            read_memory_row,
        )
        .optional()
        .map_err(Into::into)
}

fn read_memory(connection: &Connection, tenant: &str, id: i64) -> Kept<Option<MemoryRecord>> {
    connection
        .query_row(
            "SELECT memory_id,tenant,actor,scope,kind,content,status,confidence,
                    sensitivity,visibility,source_transport,source_key,valid_from_ms,
                    expires_at_ms,review_at_ms,superseded_by,created_at_ms,updated_at_ms,revision
             FROM memories WHERE tenant=?1 AND memory_id=?2",
            params![tenant, id],
            read_memory_row,
        )
        .optional()
        .map_err(Into::into)
}

fn read_memory_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryRecord> {
    let kind: String = row.get(4)?;
    let status: String = row.get(6)?;
    let sensitivity: String = row.get(8)?;
    let visibility: String = row.get(9)?;
    let confidence: i64 = row.get(7)?;
    let revision: i64 = row.get(18)?;
    Ok(MemoryRecord {
        id: row.get(0)?,
        tenant: row.get(1)?,
        actor: row.get(2)?,
        scope: row.get(3)?,
        kind: MemoryKind::parse(&kind).ok_or(rusqlite::Error::InvalidQuery)?,
        content: row.get(5)?,
        status: MemoryStatus::parse(&status).ok_or(rusqlite::Error::InvalidQuery)?,
        confidence: u16::try_from(confidence).map_err(|_| rusqlite::Error::InvalidQuery)?,
        sensitivity: MemorySensitivity::parse(&sensitivity).ok_or(rusqlite::Error::InvalidQuery)?,
        visibility: MemoryVisibility::parse(&visibility).ok_or(rusqlite::Error::InvalidQuery)?,
        source_transport: row.get(10)?,
        source_key: row.get(11)?,
        valid_from_ms: row.get(12)?,
        expires_at_ms: row.get(13)?,
        review_at_ms: row.get(14)?,
        superseded_by: row.get(15)?,
        created_at_ms: row.get(16)?,
        updated_at_ms: row.get(17)?,
        revision: u32::try_from(revision).map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn store() -> (TempDir, AgentMemoryStore) {
        let root = TempDir::new().expect("temp root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let store = AgentMemoryStore::open(root.path().join("memory.sqlite3")).expect("store");
        (root, store)
    }

    fn memory<'a>(source_key: &'a str, content: &'a str, status: MemoryStatus) -> MemoryInput<'a> {
        MemoryInput {
            tenant: "inklura",
            actor: "ben",
            scope: "user:ben",
            kind: MemoryKind::UserProfile,
            content,
            status,
            confidence: 950,
            sensitivity: MemorySensitivity::Personal,
            visibility: MemoryVisibility::Private,
            source_transport: "telegram",
            source_key,
            valid_from_ms: 1_000,
            expires_at_ms: None,
            review_at_ms: Some(2_000),
            created_at_ms: 1_000,
        }
    }

    #[test]
    fn records_searches_and_replays_one_tenant_scoped_memory() {
        let (_root, mut store) = store();
        let input = memory(
            "telegram:1",
            "Ben préfère les réponses concises.",
            MemoryStatus::Active,
        );
        let first = store.record_memory(&input).expect("recorded");
        let replay = store.record_memory(&input).expect("replayed");
        assert_eq!(first, replay);
        let found = store
            .search("inklura", "ben", "réponses concises", 1_500, 5)
            .expect("search");
        assert_eq!(found, vec![first]);
        assert!(
            store
                .search("another", "ben", "concises", 1_500, 5)
                .expect("isolated")
                .is_empty()
        );
    }

    #[test]
    fn messages_are_deduplicated_and_pruned_after_ninety_days() {
        let (_root, mut store) = store();
        let message = MessageInput {
            tenant: "inklura",
            actor: "ben",
            conversation_id: "telegram:chat:7",
            transport: "telegram",
            external_scope: "chat:7",
            transport_key: "telegram:update:1",
            role: "user",
            content: "Souviens-toi que je préfère le français.",
            created_at_ms: 10,
        };
        assert_eq!(
            store.record_message(&message).expect("record"),
            WriteDisposition::Recorded
        );
        assert_eq!(
            store.record_message(&message).expect("replay"),
            WriteDisposition::Duplicate
        );
        assert_eq!(store.counts("inklura", "ben").expect("counts").messages, 1);
        assert_eq!(
            store
                .prune_messages(10 + DEFAULT_RAW_RETENTION_MS)
                .expect("prune"),
            1
        );
    }

    #[test]
    fn control_commands_are_removed_without_touching_conversation_text() {
        let (_root, mut store) = store();
        for (key, content) in [
            ("telegram:update:1", " /status"),
            ("telegram:update:2", "what is the status?"),
        ] {
            store
                .record_message(&MessageInput {
                    tenant: "inklura",
                    actor: "ben",
                    conversation_id: "telegram:chat:7",
                    transport: "telegram",
                    external_scope: "chat:7",
                    transport_key: key,
                    role: "user",
                    content,
                    created_at_ms: 10,
                })
                .expect("record");
        }
        assert_eq!(
            store
                .prune_control_messages("inklura", "ben")
                .expect("prune commands"),
            1
        );
        assert_eq!(store.counts("inklura", "ben").expect("counts").messages, 1);
    }

    #[test]
    fn an_exact_transport_reply_is_actor_scoped_and_expires_with_raw_history() {
        let (_root, mut store) = store();
        store
            .record_message(&MessageInput {
                tenant: "inklura",
                actor: "telegram:42",
                conversation_id: "telegram:chat:7",
                transport: "telegram",
                external_scope: "chat:7",
                transport_key: "telegram:9:message:7:55",
                role: "assistant",
                content: "the exact answer",
                created_at_ms: 10,
            })
            .expect("message");
        let exact = store
            .message_by_transport_key(
                "inklura",
                "telegram:42",
                "telegram",
                "telegram:9:message:7:55",
                11,
            )
            .expect("exact lookup")
            .expect("present");
        assert_eq!(exact.content, "the exact answer");
        assert!(
            store
                .message_by_transport_key(
                    "inklura",
                    "telegram:99",
                    "telegram",
                    "telegram:9:message:7:55",
                    11,
                )
                .expect("other actor")
                .is_none()
        );
        assert!(
            store
                .message_by_transport_key(
                    "inklura",
                    "telegram:42",
                    "telegram",
                    "telegram:9:message:7:55",
                    10 + DEFAULT_RAW_RETENTION_MS,
                )
                .expect("expired")
                .is_none()
        );
    }

    #[test]
    fn a_new_conversation_moves_only_the_head_and_keeps_prior_history() {
        let (_root, mut store) = store();
        store
            .start_conversation("inklura", "ben", "telegram", "chat:7", "first", 10)
            .expect("first conversation");
        store
            .record_message(&MessageInput {
                tenant: "inklura",
                actor: "ben",
                conversation_id: "first",
                transport: "telegram",
                external_scope: "chat:7",
                transport_key: "telegram:update:1",
                role: "user",
                content: "first turn",
                created_at_ms: 11,
            })
            .expect("first message");
        assert_eq!(
            store
                .start_conversation("inklura", "ben", "telegram", "chat:7", "second", 20)
                .expect("second conversation"),
            2
        );
        assert_eq!(
            store
                .current_conversation("inklura", "ben", "telegram", "chat:7")
                .expect("head"),
            Some(String::from("second"))
        );
        assert_eq!(
            store
                .recent_messages("inklura", "ben", "first", 21, 10)
                .expect("prior history")
                .len(),
            1
        );
        assert!(
            store
                .recent_messages("inklura", "ben", "second", 21, 10)
                .expect("new history")
                .is_empty()
        );
    }

    #[test]
    fn proposals_require_exact_revision_and_leave_an_audit_safe_lifecycle() {
        let (_root, mut store) = store();
        let candidate = store
            .record_memory(&memory(
                "telegram:2",
                "Ben travaille habituellement en français.",
                MemoryStatus::Candidate,
            ))
            .expect("candidate");
        assert_eq!(candidate.revision, 1);
        let active = store
            .activate("inklura", "ben", candidate.id, 1, "owner approval", 2_100)
            .expect("active");
        assert_eq!(active.status, MemoryStatus::Active);
        assert_eq!(active.revision, 2);
        assert!(matches!(
            store.activate("inklura", "ben", candidate.id, 1, "stale", 2_200),
            Err(AgentMemoryError::StaleRevision)
        ));
    }

    #[test]
    fn immutable_external_identities_never_merge_on_display_names() {
        let (_root, mut store) = store();
        assert_eq!(
            store
                .bind_identity(
                    "inklura",
                    "ben",
                    ExternalIdentity {
                        platform: "telegram",
                        application: "monique",
                        external_tenant: "telegram",
                        external_user: "765",
                    },
                    10,
                )
                .expect("binding"),
            WriteDisposition::Recorded
        );
        assert_eq!(
            store
                .resolve_identity("telegram", "monique", "telegram", "765")
                .expect("resolve"),
            Some((String::from("inklura"), String::from("ben")))
        );
        assert!(matches!(
            store.bind_identity(
                "inklura",
                "someone-else",
                ExternalIdentity {
                    platform: "telegram",
                    application: "monique",
                    external_tenant: "telegram",
                    external_user: "765",
                },
                11
            ),
            Err(AgentMemoryError::Conflict)
        ));
    }
}
