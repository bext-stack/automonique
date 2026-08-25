// SPDX-License-Identifier: Elastic-2.0

//! Durable ACP-to-canonical coordinate mapping.
//!
//! This is compatibility metadata, not an alternate session record. Provider
//! session state and run outcomes remain authoritative in Platform v1; this
//! store only remembers which opaque ACP ID and workspace a client used to
//! address those records across adapter and daemon restarts.

use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};

use crate::{AuthorityError, Session};

pub const DATABASE_NAME: &str = "acp-sessions.sqlite3";
const PAGE_SIZE: usize = 100;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS acp_sessions (
    session_id TEXT PRIMARY KEY,
    cwd BLOB NOT NULL,
    additional_directories BLOB NOT NULL,
    provider_session_id TEXT,
    current_run_id TEXT,
    turn_sequence INTEGER NOT NULL CHECK (turn_sequence >= 0),
    created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= created_ms)
) STRICT;
"#;

static NONCE: AtomicU64 = AtomicU64::new(1);

pub struct SessionStore {
    connection: Connection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSession {
    pub session: Session,
    pub provider_session_id: Option<String>,
    pub current_run_id: Option<String>,
    pub turn_sequence: u64,
}

impl SessionStore {
    pub fn open(state_dir: &Path) -> Result<Self, AuthorityError> {
        let path = state_dir.join(DATABASE_NAME);
        secure_parent(state_dir)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| AuthorityError::new("acp_mapping_create"))?;
        }
        let metadata = path
            .symlink_metadata()
            .map_err(|_| AuthorityError::new("acp_mapping_metadata"))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(AuthorityError::new("acp_mapping_insecure"));
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|_| AuthorityError::new("acp_mapping_open"))?;
        automonique_store::sqlite_policy::configure_authoritative(&connection)
            .map_err(|_| AuthorityError::new("acp_mapping_sqlite_policy"))?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| AuthorityError::new("acp_mapping_schema"))?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        cwd: &Path,
        additional: &[PathBuf],
    ) -> Result<StoredSession, AuthorityError> {
        let (cwd, additional) = canonical_paths(cwd, additional)?;
        let now = now_ms()?;
        for _ in 0..4 {
            let id = new_session_id(&cwd, now);
            let encoded = encode_paths(&additional)?;
            let inserted = self
                .connection
                .execute(
                    "INSERT OR IGNORE INTO acp_sessions(session_id,cwd,additional_directories,turn_sequence,created_ms,updated_ms) VALUES(?1,?2,?3,0,?4,?4)",
                    params![id, path_bytes(&cwd), encoded, now],
                )
                .map_err(|_| AuthorityError::new("acp_mapping_insert"))?;
            if inserted == 1 {
                return self
                    .get(&id)?
                    .ok_or(AuthorityError::new("acp_mapping_missing"));
            }
        }
        Err(AuthorityError::new("acp_session_id_collision"))
    }

    pub fn load(
        &self,
        id: &str,
        cwd: &Path,
        additional: &[PathBuf],
    ) -> Result<StoredSession, AuthorityError> {
        validate_session_id(id)?;
        let (cwd, additional) = canonical_paths(cwd, additional)?;
        let session = self
            .get(id)?
            .ok_or(AuthorityError::new("acp_session_unknown"))?;
        if session.session.cwd != cwd || session.session.additional_directories != additional {
            return Err(AuthorityError::new("acp_workspace_mismatch"));
        }
        Ok(session)
    }

    pub fn get(&self, id: &str) -> Result<Option<StoredSession>, AuthorityError> {
        validate_session_id(id)?;
        self.connection
            .query_row(
                "SELECT session_id,cwd,additional_directories,provider_session_id,current_run_id,turn_sequence,updated_ms FROM acp_sessions WHERE session_id=?1",
                [id],
                decode,
            )
            .optional()
            .map_err(|_| AuthorityError::new("acp_mapping_read"))
    }

    pub fn list(
        &self,
        cwd: Option<&Path>,
        cursor: Option<&str>,
    ) -> Result<(Vec<Session>, Option<String>), AuthorityError> {
        let cwd = cwd.map(canonical_directory).transpose()?;
        if let Some(cursor) = cursor {
            validate_session_id(cursor)?;
        }
        let after = cursor.unwrap_or("");
        let limit =
            i64::try_from(PAGE_SIZE + 1).map_err(|_| AuthorityError::new("acp_mapping_limit"))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT session_id,cwd,additional_directories,provider_session_id,current_run_id,turn_sequence,updated_ms FROM acp_sessions WHERE session_id>?1 AND (?2 IS NULL OR cwd=?2) ORDER BY session_id LIMIT ?3",
            )
            .map_err(|_| AuthorityError::new("acp_mapping_query"))?;
        let cwd_bytes = cwd.as_deref().map(path_bytes);
        let rows = statement
            .query_map(params![after, cwd_bytes, limit], decode)
            .map_err(|_| AuthorityError::new("acp_mapping_query"))?;
        let mut sessions = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuthorityError::new("acp_mapping_decode"))?;
        let next = (sessions.len() > PAGE_SIZE).then(|| sessions[PAGE_SIZE - 1].session.id.clone());
        sessions.truncate(PAGE_SIZE);
        Ok((
            sessions.into_iter().map(|stored| stored.session).collect(),
            next,
        ))
    }

    pub fn reserve_turn(&mut self, id: &str) -> Result<StoredSession, AuthorityError> {
        validate_session_id(id)?;
        let now = now_ms()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::new("acp_mapping_transaction"))?;
        let current = transaction
            .query_row(
                "SELECT session_id,cwd,additional_directories,provider_session_id,current_run_id,turn_sequence,updated_ms FROM acp_sessions WHERE session_id=?1",
                [id],
                decode,
            )
            .optional()
            .map_err(|_| AuthorityError::new("acp_mapping_read"))?
            .ok_or(AuthorityError::new("acp_session_unknown"))?;
        let next = current
            .turn_sequence
            .checked_add(1)
            .ok_or(AuthorityError::new("acp_turn_overflow"))?;
        transaction
            .execute(
                "UPDATE acp_sessions SET turn_sequence=?2,updated_ms=?3 WHERE session_id=?1 AND turn_sequence=?4",
                params![id, to_i64(next)?, now, to_i64(current.turn_sequence)?],
            )
            .map_err(|_| AuthorityError::new("acp_mapping_update"))?;
        transaction
            .commit()
            .map_err(|_| AuthorityError::new("acp_mapping_commit"))?;
        let mut reserved = current;
        reserved.turn_sequence = next;
        Ok(reserved)
    }

    pub fn bind_turn(
        &mut self,
        id: &str,
        run_id: &str,
        provider_session_id: Option<&str>,
    ) -> Result<(), AuthorityError> {
        validate_session_id(id)?;
        let changed = self
            .connection
            .execute(
                "UPDATE acp_sessions SET current_run_id=?2,provider_session_id=COALESCE(?3,provider_session_id),updated_ms=?4 WHERE session_id=?1",
                params![id, run_id, provider_session_id, now_ms()?],
            )
            .map_err(|_| AuthorityError::new("acp_mapping_bind"))?;
        if changed != 1 {
            return Err(AuthorityError::new("acp_session_unknown"));
        }
        Ok(())
    }
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSession> {
    let cwd: Vec<u8> = row.get(1)?;
    let additional: Vec<u8> = row.get(2)?;
    let _: i64 = row.get(6)?;
    Ok(StoredSession {
        session: Session {
            id: row.get(0)?,
            cwd: path_from_bytes(cwd)?,
            additional_directories: decode_paths(&additional)?,
            title: None,
            updated_at: None,
        },
        provider_session_id: row.get(3)?,
        current_run_id: row.get(4)?,
        turn_sequence: u64::try_from(row.get::<_, i64>(5)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
    })
}

fn canonical_paths(
    cwd: &Path,
    additional: &[PathBuf],
) -> Result<(PathBuf, Vec<PathBuf>), AuthorityError> {
    let cwd = canonical_directory(cwd)?;
    let mut resolved = Vec::with_capacity(additional.len());
    for path in additional {
        let path = canonical_directory(path)?;
        if path == cwd || resolved.contains(&path) {
            return Err(AuthorityError::new("acp_workspace_root_duplicate"));
        }
        resolved.push(path);
    }
    Ok((cwd, resolved))
}

fn canonical_directory(path: &Path) -> Result<PathBuf, AuthorityError> {
    if !path.is_absolute() {
        return Err(AuthorityError::new("acp_workspace_not_absolute"));
    }
    let resolved = path
        .canonicalize()
        .map_err(|_| AuthorityError::new("acp_workspace_unavailable"))?;
    if !resolved.is_dir() {
        return Err(AuthorityError::new("acp_workspace_not_directory"));
    }
    Ok(resolved)
}

fn secure_parent(path: &Path) -> Result<(), AuthorityError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| AuthorityError::new("acp_state_dir_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuthorityError::new("acp_state_dir_insecure"));
    }
    Ok(())
}

fn validate_session_id(id: &str) -> Result<(), AuthorityError> {
    let digest = id
        .strip_prefix("acp-")
        .ok_or(AuthorityError::new("acp_session_id_invalid"))?;
    if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthorityError::new("acp_session_id_invalid"));
    }
    Ok(())
}

fn encode_paths(paths: &[PathBuf]) -> Result<Vec<u8>, AuthorityError> {
    let mut encoded = Vec::new();
    for path in paths {
        let bytes = path_bytes(path);
        let length = u32::try_from(bytes.len())
            .map_err(|_| AuthorityError::new("acp_workspace_path_too_long"))?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&bytes);
    }
    Ok(encoded)
}

fn decode_paths(mut bytes: &[u8]) -> rusqlite::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let length = usize::try_from(u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ))
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        bytes = &bytes[4..];
        if length > bytes.len() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        paths.push(path_from_bytes(bytes[..length].to_vec())?);
        bytes = &bytes[length..];
    }
    Ok(paths)
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(unix)]
fn path_from_bytes(bytes: Vec<u8>) -> rusqlite::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn new_session_id(cwd: &Path, now: i64) -> String {
    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    let mut digest = Sha256::new();
    digest.update(b"automonique.acp.session/v1\0");
    digest.update(path_bytes(cwd));
    digest.update(now.to_be_bytes());
    digest.update(std::process::id().to_be_bytes());
    digest.update(nonce.to_be_bytes());
    let hex = format!("{:x}", digest.finalize());
    format!("acp-{}", &hex[..32])
}

fn now_ms() -> Result<i64, AuthorityError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityError::new("acp_clock"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| AuthorityError::new("acp_clock"))
}

fn to_i64(value: u64) -> Result<i64, AuthorityError> {
    i64::try_from(value).map_err(|_| AuthorityError::new("acp_counter_out_of_range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_survives_reopen_and_fences_workspace_changes() {
        let state = tempfile::tempdir().expect("state");
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private state permissions");
        let workspace = tempfile::tempdir().expect("workspace");
        let other = tempfile::tempdir().expect("other");
        let id = {
            let mut store = SessionStore::open(state.path()).expect("store");
            let created = store.create(workspace.path(), &[]).expect("create");
            store
                .bind_turn(&created.session.id, "run-1", Some("provider-1"))
                .expect("bind");
            created.session.id
        };
        let store = SessionStore::open(state.path()).expect("reopen");
        let loaded = store.load(&id, workspace.path(), &[]).expect("load");
        assert_eq!(loaded.provider_session_id.as_deref(), Some("provider-1"));
        assert!(store.load(&id, other.path(), &[]).is_err());
    }
}
