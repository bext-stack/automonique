// SPDX-License-Identifier: Elastic-2.0

//! Durable custody for authoritative Platform v2 attention source snapshots.
//!
//! One row is the complete current value for an exact source/project/user
//! workspace tuple. Writes accept only an idempotent replay or a successor
//! validated by the protocol contract; reads revalidate canonical bytes,
//! digest, and duplicated lookup fields before returning anything.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::platform_v2::{ProjectId, UserWorkspaceId};
use automonique_protocol::platform_v2_attention::{
    AttentionField, AttentionSource, AttentionSourceSnapshot,
};
use automonique_protocol::platform_v2_attention_api::{
    decode_attention_source_snapshot, encode_attention_source_snapshot,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::{StoreError, validate_database_path};

pub const ATTENTION_STORE_SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE attention_store_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_namespace TEXT NOT NULL
) STRICT;

CREATE TABLE attention_source_current (
    source_kind TEXT NOT NULL,
    source_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    user_workspace_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    snapshot_document BLOB NOT NULL,
    snapshot_digest BLOB NOT NULL CHECK (length(snapshot_digest) = 32),
    PRIMARY KEY (source_kind, source_id, project_id, user_workspace_id)
) STRICT;
"#;

#[derive(Debug)]
pub enum AttentionStoreError {
    InsecurePath(String),
    SchemaVersion { found: u32, supported: u32 },
    InvalidField(&'static str),
    Conflict(&'static str),
    NotFound,
    Corrupt(&'static str),
    Protocol(String),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl AttentionStoreError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict(_) => "conflict",
            Self::NotFound => "not_found",
            Self::Corrupt(_) => "corrupt",
            Self::Protocol(_) => "protocol",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}
impl fmt::Display for AttentionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "attention store refused: {}", self.category())
    }
}
impl Error for AttentionStoreError {}
impl From<std::io::Error> for AttentionStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<rusqlite::Error> for AttentionStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}
type Stored<T> = Result<T, AttentionStoreError>;

#[derive(Debug)]
pub struct AttentionStore {
    connection: Connection,
    path: PathBuf,
    authority_namespace: String,
}

impl AttentionStore {
    pub fn open_scoped(path: impl AsRef<Path>, authority_namespace: &str) -> Stored<Self> {
        if AttentionField::new(authority_namespace).is_err() {
            return Err(AttentionStoreError::InvalidField("authority_namespace"));
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
        let fresh = initialize(&mut connection)?;
        bind_namespace(&connection, authority_namespace, fresh)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            authority_namespace: authority_namespace.to_owned(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    #[must_use]
    pub fn authority_namespace(&self) -> &str {
        &self.authority_namespace
    }

    /// Persist one complete source-owned snapshot.
    pub fn put_snapshot(&mut self, snapshot: &AttentionSourceSnapshot) -> Stored<()> {
        let document = encode_attention_source_snapshot(snapshot).map_err(protocol)?;
        let document_digest: [u8; 32] = Sha256::digest(&document).into();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = transaction.query_row(
            "SELECT snapshot_document FROM attention_source_current WHERE source_kind=?1 AND source_id=?2 AND project_id=?3 AND user_workspace_id=?4",
            params![snapshot.source().kind().as_str(), snapshot.source().id().as_str(), snapshot.project().as_str(), snapshot.user_workspace().as_str()],
            |row| row.get(0),
        ).optional()?;
        if let Some(existing) = existing {
            if existing == document {
                transaction.commit()?;
                return Ok(());
            }
            let current = decode_attention_source_snapshot(&existing).map_err(protocol)?;
            current
                .validate_successor(snapshot)
                .map_err(|_| AttentionStoreError::Conflict("source_revision"))?;
            let changed = transaction.execute(
                "UPDATE attention_source_current SET source_revision=?1,observed_at_ms=?2,snapshot_document=?3,snapshot_digest=?4 WHERE source_kind=?5 AND source_id=?6 AND project_id=?7 AND user_workspace_id=?8 AND source_revision=?9",
                params![to_db(snapshot.revision().get())?, to_db(snapshot.observed_at_ms())?, document, document_digest.as_slice(), snapshot.source().kind().as_str(), snapshot.source().id().as_str(), snapshot.project().as_str(), snapshot.user_workspace().as_str(), to_db(current.revision().get())?],
            )?;
            if changed != 1 {
                return Err(AttentionStoreError::Conflict("source_revision"));
            }
        } else {
            transaction.execute(
                "INSERT INTO attention_source_current(source_kind,source_id,project_id,user_workspace_id,source_revision,observed_at_ms,snapshot_document,snapshot_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![snapshot.source().kind().as_str(), snapshot.source().id().as_str(), snapshot.project().as_str(), snapshot.user_workspace().as_str(), to_db(snapshot.revision().get())?, to_db(snapshot.observed_at_ms())?, document, document_digest.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn snapshot(
        &self,
        source: &AttentionSource,
        project: &ProjectId,
        user_workspace: &UserWorkspaceId,
    ) -> Stored<Option<AttentionSourceSnapshot>> {
        type Raw = (i64, i64, Vec<u8>, Vec<u8>);
        let raw: Option<Raw> = self.connection.query_row(
            "SELECT source_revision,observed_at_ms,snapshot_document,snapshot_digest FROM attention_source_current WHERE source_kind=?1 AND source_id=?2 AND project_id=?3 AND user_workspace_id=?4",
            params![source.kind().as_str(), source.id().as_str(), project.as_str(), user_workspace.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        let Some((revision, observed_at_ms, document, stored_digest)) = raw else {
            return Ok(None);
        };
        let digest: [u8; 32] = Sha256::digest(&document).into();
        if stored_digest.as_slice() != digest || revision < 1 || observed_at_ms < 0 {
            return Err(AttentionStoreError::Corrupt("snapshot_integrity"));
        }
        let snapshot = decode_attention_source_snapshot(&document).map_err(protocol)?;
        let canonical = encode_attention_source_snapshot(&snapshot).map_err(protocol)?;
        if canonical != document
            || snapshot.source() != source
            || snapshot.project() != project
            || snapshot.user_workspace() != user_workspace
            || snapshot.revision().get() != u64::try_from(revision).unwrap_or(0)
            || snapshot.observed_at_ms() != u64::try_from(observed_at_ms).unwrap_or(u64::MAX)
        {
            return Err(AttentionStoreError::Corrupt("snapshot_binding"));
        }
        Ok(Some(snapshot))
    }
}

fn initialize(connection: &mut Connection) -> Stored<bool> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == ATTENTION_STORE_SCHEMA_VERSION {
        return Ok(false);
    }
    if version != 0 {
        return Err(AttentionStoreError::SchemaVersion {
            found: version,
            supported: ATTENTION_STORE_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", ATTENTION_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(true)
}

fn bind_namespace(connection: &Connection, namespace: &str, fresh: bool) -> Stored<()> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT authority_namespace FROM attention_store_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(existing) if existing == namespace => Ok(()),
        Some(_) => Err(AttentionStoreError::Conflict("authority_namespace")),
        None if fresh => {
            connection.execute(
                "INSERT INTO attention_store_metadata(singleton,authority_namespace) VALUES(1,?1)",
                [namespace],
            )?;
            Ok(())
        }
        None => Err(AttentionStoreError::Corrupt("authority_namespace")),
    }
}

fn secure_path(path: &Path) -> Stored<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => AttentionStoreError::Io(io),
        other => AttentionStoreError::InsecurePath(other.to_string()),
    })
}
fn to_db(value: u64) -> Stored<i64> {
    i64::try_from(value).map_err(|_| AttentionStoreError::InvalidField("counter"))
}
fn protocol(error: impl fmt::Display) -> AttentionStoreError {
    AttentionStoreError::Protocol(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_protocol::platform_v2_attention::{
        AttentionItem, AttentionItemId, AttentionItemReason, AttentionItemState, AttentionSourceId,
        AttentionSourceKind,
    };
    use automonique_protocol::primitives::Revision;
    use rusqlite::params;
    use tempfile::tempdir;

    fn snapshot(
        revision_value: u64,
        previous: Option<u64>,
        state: AttentionItemState,
    ) -> AttentionSourceSnapshot {
        let reason = match state {
            AttentionItemState::NeedsYou => AttentionItemReason::ApprovalRequired,
            AttentionItemState::Working => AttentionItemReason::AgentWorking,
            AttentionItemState::Done => AttentionItemReason::Complete,
            AttentionItemState::Blocked => AttentionItemReason::ExternalBlocker,
        };
        AttentionSourceSnapshot::new(
            AttentionSource::new(
                AttentionSourceKind::Review,
                AttentionSourceId::new("review-source").unwrap(),
            ),
            ProjectId::new("project").unwrap(),
            UserWorkspaceId::new("workspace").unwrap(),
            Revision::new(revision_value).unwrap(),
            previous.map(|value| Revision::new(value).unwrap()),
            1_000 + revision_value,
            vec![
                AttentionItem::new(
                    AttentionItemId::new("item").unwrap(),
                    Revision::new(revision_value).unwrap(),
                    1_000,
                    state,
                    reason,
                    true,
                    Vec::new(),
                    None,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn store() -> (tempfile::TempDir, AttentionStore) {
        let directory = tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let store =
            AttentionStore::open_scoped(directory.path().join("attention.sqlite3"), "tenant")
                .unwrap();
        (directory, store)
    }

    #[test]
    fn exact_replay_and_monotone_successor_are_the_only_writes() {
        let (_directory, mut store) = store();
        let first = snapshot(1, None, AttentionItemState::Working);
        store.put_snapshot(&first).unwrap();
        store.put_snapshot(&first).unwrap();
        let next = snapshot(3, Some(1), AttentionItemState::Done);
        store.put_snapshot(&next).unwrap();
        assert_eq!(
            store
                .snapshot(next.source(), next.project(), next.user_workspace())
                .unwrap(),
            Some(next)
        );
        assert!(matches!(
            store.put_snapshot(&snapshot(2, Some(1), AttentionItemState::Blocked)),
            Err(AttentionStoreError::Conflict("source_revision"))
        ));
    }

    #[test]
    fn tuple_scope_and_namespace_are_exact_and_corruption_fails_closed() {
        let (directory, mut store) = store();
        let current = snapshot(1, None, AttentionItemState::NeedsYou);
        store.put_snapshot(&current).unwrap();
        assert!(
            store
                .snapshot(
                    current.source(),
                    &ProjectId::new("other").unwrap(),
                    current.user_workspace()
                )
                .unwrap()
                .is_none()
        );
        store
            .connection
            .execute(
                "UPDATE attention_source_current SET observed_at_ms=observed_at_ms+1",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.snapshot(
                current.source(),
                current.project(),
                current.user_workspace()
            ),
            Err(AttentionStoreError::Corrupt("snapshot_binding"))
        ));
        drop(store);
        assert!(matches!(
            AttentionStore::open_scoped(directory.path().join("attention.sqlite3"), "other-tenant"),
            Err(AttentionStoreError::Conflict("authority_namespace"))
        ));
    }

    #[test]
    fn digest_corruption_fails_closed_after_restart() {
        let (directory, mut store) = store();
        let current = snapshot(1, None, AttentionItemState::Working);
        store.put_snapshot(&current).unwrap();
        store
            .connection
            .execute(
                "UPDATE attention_source_current SET snapshot_digest=?1",
                params![vec![0_u8; 32]],
            )
            .unwrap();
        drop(store);
        let reopened =
            AttentionStore::open_scoped(directory.path().join("attention.sqlite3"), "tenant")
                .unwrap();
        assert!(matches!(
            reopened.snapshot(
                current.source(),
                current.project(),
                current.user_workspace()
            ),
            Err(AttentionStoreError::Corrupt("snapshot_integrity"))
        ));
    }
}
