// SPDX-License-Identifier: Elastic-2.0

//! Online SQLite recovery sets and clean-target restore.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component as PathComponent, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "manifest.json";
pub const MANIFEST_SCHEMA: &str = "automonique.recovery-set/v1";
pub const RPO_MILLIS: u64 = 5 * 60 * 1_000;
pub const RTO_MILLIS: u64 = 30 * 60 * 1_000;
const MAX_DATABASES: usize = 64;
const MAX_DERIVED_FILES: usize = 16_384;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const ORDERING: [&str; 3] = [
    "database_snapshot_before_derived_files",
    "blob_bytes_before_referencing_row",
    "config_revision_before_current_setting",
];

#[derive(Debug)]
pub enum RecoveryError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Refused(&'static str),
}

impl RecoveryError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Io(_) => "recovery_io_failed",
            Self::Sqlite(_) => "recovery_sqlite_failed",
            Self::Json(_) => "recovery_manifest_invalid",
            Self::Refused(category) => category,
        }
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for RecoveryError {}

impl From<std::io::Error> for RecoveryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for RecoveryError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for RecoveryError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryManifest {
    pub schema: String,
    pub snapshot_started_unix_ms: u64,
    pub snapshot_completed_unix_ms: u64,
    pub database_count: usize,
    pub ordering_invariants: Vec<String>,
    pub components: Vec<RecoveryComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryComponent {
    pub path: String,
    pub kind: ComponentKind,
    pub sha256: String,
    pub size_bytes: u64,
    pub integrity_check: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Database,
    Blob,
    Configuration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DerivedFile {
    path: String,
    kind: ComponentKind,
    sha256: String,
    size_bytes: u64,
}

/// Create one timestamped recovery set below `backup_root`.
///
/// Databases are snapshotted first with SQLite's online backup API. Optional
/// blob and non-secret configuration members are then derived only from
/// `recovery_blobs` and `recovery_configs` rows in those snapshots.
pub fn create(state_dir: &Path, backup_root: &Path) -> Result<PathBuf, RecoveryError> {
    require_real_directory(state_dir, "state_directory_invalid")?;
    ensure_private_directory(backup_root)?;
    let lock_path = backup_root.join(".backup.lock");
    let _lock = LockFile::acquire(&lock_path)?;
    let started = unix_millis()?;
    let identity = format!("recovery-{started}-{}", std::process::id());
    let staging = backup_root.join(format!(".{identity}.staging"));
    let final_path = backup_root.join(identity);
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;

    let result = create_in(state_dir, &staging, started).and_then(|manifest| {
        write_manifest(&staging, &manifest)?;
        fs::rename(&staging, &final_path)?;
        Ok(final_path.clone())
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn create_in(
    state_dir: &Path,
    staging: &Path,
    started: u64,
) -> Result<RecoveryManifest, RecoveryError> {
    let databases = database_paths(state_dir)?;
    let database_dir = staging.join("databases");
    fs::create_dir(&database_dir)?;
    fs::set_permissions(&database_dir, fs::Permissions::from_mode(0o700))?;
    let mut components = Vec::new();

    for source in &databases {
        let leaf = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RecoveryError::Refused("database_name_invalid"))?;
        let target = database_dir.join(leaf);
        snapshot_database(source, &target)
            .map_err(|_| RecoveryError::Refused("database_snapshot_failed"))?;
        let integrity = integrity_check(&target)
            .map_err(|_| RecoveryError::Refused("database_integrity_query_failed"))?;
        if integrity != "ok" {
            return Err(RecoveryError::Refused("database_integrity_failed"));
        }
        let relative = format!("databases/{leaf}");
        components.push(component_for(
            staging,
            &relative,
            ComponentKind::Database,
            Some(integrity),
        )?);
    }

    let derived = derived_files(&database_dir)
        .map_err(|_| RecoveryError::Refused("derived_index_invalid"))?;
    for file in derived.values() {
        let source = state_dir.join(&file.path);
        let metadata = fs::symlink_metadata(&source)
            .map_err(|_| RecoveryError::Refused("derived_file_missing"))?;
        if !metadata.file_type().is_file() {
            return Err(RecoveryError::Refused("derived_file_not_regular"));
        }
        if metadata.len() != file.size_bytes || sha256_file(&source)? != file.sha256 {
            return Err(RecoveryError::Refused("derived_file_digest_mismatch"));
        }
        let target = staging.join(&file.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        fs::copy(&source, &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        components.push(component_for(staging, &file.path, file.kind, None)?);
    }
    components.sort_by(|left, right| left.path.cmp(&right.path));
    let completed = unix_millis()?;
    Ok(RecoveryManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        snapshot_started_unix_ms: started,
        snapshot_completed_unix_ms: completed,
        database_count: databases.len(),
        ordering_invariants: ORDERING.iter().map(ToString::to_string).collect(),
        components,
    })
}

/// Verify every digest, SQLite integrity result, ordering assertion and member.
pub fn verify(recovery_set: &Path) -> Result<RecoveryManifest, RecoveryError> {
    require_real_directory(recovery_set, "recovery_set_invalid")?;
    let manifest_path = recovery_set.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(RecoveryError::Refused("recovery_manifest_invalid"));
    }
    let bytes = fs::read(&manifest_path)?;
    let manifest: RecoveryManifest = serde_json::from_slice(&bytes)?;
    validate_manifest(&manifest)?;
    let mut declared = BTreeSet::new();
    declared.insert(MANIFEST_NAME.to_owned());
    for component in &manifest.components {
        safe_relative_path(&component.path)?;
        if !declared.insert(component.path.clone()) {
            return Err(RecoveryError::Refused("recovery_component_duplicate"));
        }
        let path = recovery_set.join(&component.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| RecoveryError::Refused("recovery_component_missing"))?;
        if !metadata.file_type().is_file()
            || metadata.len() != component.size_bytes
            || sha256_file(&path)? != component.sha256
        {
            return Err(RecoveryError::Refused("recovery_component_digest_mismatch"));
        }
        if component.kind == ComponentKind::Database
            && (component.integrity_check.as_deref() != Some("ok")
                || integrity_check(&path)? != "ok")
        {
            return Err(RecoveryError::Refused("database_integrity_failed"));
        }
    }
    let expected_derived = derived_files(&recovery_set.join("databases"))?;
    let declared_derived = manifest
        .components
        .iter()
        .filter(|component| component.kind != ComponentKind::Database)
        .map(|component| {
            (
                component.path.clone(),
                DerivedFile {
                    path: component.path.clone(),
                    kind: component.kind,
                    sha256: component.sha256.clone(),
                    size_bytes: component.size_bytes,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if expected_derived != declared_derived {
        return Err(RecoveryError::Refused("derived_file_set_mismatch"));
    }
    let actual = regular_files(recovery_set)?;
    if actual != declared {
        return Err(RecoveryError::Refused("recovery_set_members_mismatch"));
    }
    Ok(manifest)
}

/// Restore a verified set into a target that is absent or empty.
pub fn restore(recovery_set: &Path, target: &Path) -> Result<RecoveryManifest, RecoveryError> {
    let manifest = verify(recovery_set)?;
    if target.exists() {
        require_real_directory(target, "restore_target_invalid")?;
        if fs::read_dir(target)?.next().is_some() {
            return Err(RecoveryError::Refused("restore_target_not_empty"));
        }
    } else {
        fs::create_dir(target)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    }
    for component in &manifest.components {
        let relative = match component.kind {
            ComponentKind::Database => component
                .path
                .strip_prefix("databases/")
                .ok_or(RecoveryError::Refused("recovery_component_path_invalid"))?,
            ComponentKind::Blob | ComponentKind::Configuration => &component.path,
        };
        safe_relative_path(relative)?;
        let destination = target.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        fs::copy(recovery_set.join(&component.path), &destination)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
    }
    Ok(manifest)
}

fn database_paths(state_dir: &Path) -> Result<Vec<PathBuf>, RecoveryError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(state_dir)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("sqlite3") {
            if !metadata.file_type().is_file() {
                return Err(RecoveryError::Refused("database_not_regular"));
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.is_empty() || paths.len() > MAX_DATABASES {
        return Err(RecoveryError::Refused("database_count_invalid"));
    }
    Ok(paths)
}

fn snapshot_database(source_path: &Path, target_path: &Path) -> Result<(), RecoveryError> {
    let source = Connection::open_with_flags(
        source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut target = Connection::open(target_path)?;
    {
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(128, Duration::from_millis(2), None)?;
    }
    let _: String = target.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    target.close().map_err(|(_, error)| error)?;
    fs::set_permissions(target_path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn integrity_check(path: &Path) -> Result<String, RecoveryError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?)
}

fn derived_files(database_dir: &Path) -> Result<BTreeMap<String, DerivedFile>, RecoveryError> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(database_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("sqlite3") {
            continue;
        }
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        read_derived_table(
            &connection,
            "recovery_blobs",
            ComponentKind::Blob,
            &mut files,
        )?;
        read_derived_table(
            &connection,
            "recovery_configs",
            ComponentKind::Configuration,
            &mut files,
        )?;
    }
    if files.len() > MAX_DERIVED_FILES {
        return Err(RecoveryError::Refused("derived_file_count_invalid"));
    }
    Ok(files)
}

fn read_derived_table(
    connection: &Connection,
    table: &str,
    kind: ComponentKind,
    files: &mut BTreeMap<String, DerivedFile>,
) -> Result<(), RecoveryError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(());
    }
    let sql =
        format!("SELECT relative_path, sha256, size_bytes FROM {table} ORDER BY relative_path");
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map([], |row| {
        Ok(DerivedFile {
            path: row.get(0)?,
            kind,
            sha256: row.get(1)?,
            size_bytes: row.get(2)?,
        })
    })?;
    for row in rows {
        let file = row?;
        safe_relative_path(&file.path)?;
        let required_prefix = match kind {
            ComponentKind::Blob => "blobs/",
            ComponentKind::Configuration => "config/",
            ComponentKind::Database => unreachable!(),
        };
        if !file.path.starts_with(required_prefix) || !is_sha256(&file.sha256) {
            return Err(RecoveryError::Refused("derived_file_record_invalid"));
        }
        if let Some(existing) = files.insert(file.path.clone(), file.clone())
            && existing != file
        {
            return Err(RecoveryError::Refused("derived_file_record_conflict"));
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &RecoveryManifest) -> Result<(), RecoveryError> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.snapshot_completed_unix_ms < manifest.snapshot_started_unix_ms
        || manifest.database_count == 0
        || manifest.database_count > MAX_DATABASES
        || manifest.ordering_invariants != ORDERING
        || manifest.components.len() > MAX_DATABASES + MAX_DERIVED_FILES
        || manifest
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::Database)
            .count()
            != manifest.database_count
    {
        return Err(RecoveryError::Refused("recovery_manifest_invalid"));
    }
    for component in &manifest.components {
        if !is_sha256(&component.sha256)
            || (component.kind == ComponentKind::Database
                && !component.path.starts_with("databases/"))
            || (component.kind != ComponentKind::Database && component.integrity_check.is_some())
        {
            return Err(RecoveryError::Refused("recovery_manifest_invalid"));
        }
    }
    Ok(())
}

fn component_for(
    root: &Path,
    relative: &str,
    kind: ComponentKind,
    integrity_check: Option<String>,
) -> Result<RecoveryComponent, RecoveryError> {
    safe_relative_path(relative)?;
    let path = root.join(relative);
    Ok(RecoveryComponent {
        path: relative.to_owned(),
        kind,
        sha256: sha256_file(&path)?,
        size_bytes: fs::metadata(path)?.len(),
        integrity_check,
    })
}

fn write_manifest(root: &Path, manifest: &RecoveryManifest) -> Result<(), RecoveryError> {
    let path = root.join(MANIFEST_NAME);
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn regular_files(root: &Path) -> Result<BTreeSet<String>, RecoveryError> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
    ) -> Result<(), RecoveryError> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(RecoveryError::Refused("recovery_set_symlink_refused"));
            }
            if metadata.is_dir() {
                visit(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| RecoveryError::Refused("recovery_component_path_invalid"))?
                    .to_str()
                    .ok_or(RecoveryError::Refused("recovery_component_path_invalid"))?
                    .to_owned();
                files.insert(relative);
            } else {
                return Err(RecoveryError::Refused("recovery_component_not_regular"));
            }
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

fn safe_relative_path(value: &str) -> Result<(), RecoveryError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, PathComponent::Normal(_)))
    {
        return Err(RecoveryError::Refused("recovery_component_path_invalid"));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, RecoveryError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unix_millis() -> Result<u64, RecoveryError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RecoveryError::Refused("system_clock_invalid"))?;
    u64::try_from(duration.as_millis()).map_err(|_| RecoveryError::Refused("system_clock_invalid"))
}

fn require_real_directory(path: &Path, category: &'static str) -> Result<(), RecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::Refused(category))?;
    if !metadata.file_type().is_dir() {
        return Err(RecoveryError::Refused(category));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), RecoveryError> {
    if path.exists() {
        require_real_directory(path, "backup_root_invalid")?;
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

struct LockFile(PathBuf);

impl LockFile {
    fn acquire(path: &Path) -> Result<Self, RecoveryError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    RecoveryError::Refused("backup_already_running")
                } else {
                    RecoveryError::Io(error)
                }
            })?;
        Ok(Self(path.to_owned()))
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixteen_databases_and_snapshot_derived_files_round_trip() {
        let source = tempfile::tempdir().expect("source");
        let backups = tempfile::tempdir().expect("backups");
        let restore_root = tempfile::tempdir().expect("restore root");
        let target = restore_root.path().join("restored");
        for index in 0..16 {
            let connection = Connection::open(source.path().join(format!("state-{index}.sqlite3")))
                .expect("database");
            connection
                .execute("CREATE TABLE values_table (value INTEGER NOT NULL)", [])
                .expect("schema");
            connection
                .execute("INSERT INTO values_table VALUES (?1)", [index])
                .expect("row");
        }
        let primary = Connection::open(source.path().join("state-0.sqlite3")).expect("primary");
        primary
            .execute(
                "CREATE TABLE recovery_blobs (relative_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL)",
                [],
            )
            .expect("blob schema");
        primary
            .execute(
                "CREATE TABLE recovery_configs (relative_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL)",
                [],
            )
            .expect("config schema");
        let blob = b"artifact bytes";
        let blob_digest = hex::encode(Sha256::digest(blob));
        let blob_relative = format!("blobs/{}/{blob_digest}", &blob_digest[..2]);
        write_source_file(source.path(), &blob_relative, blob);
        primary
            .execute(
                "INSERT INTO recovery_blobs VALUES (?1, ?2, ?3)",
                rusqlite::params![blob_relative, blob_digest, blob.len()],
            )
            .expect("blob row");
        let config = b"{\"revision\":1}\n";
        let config_digest = hex::encode(Sha256::digest(config));
        write_source_file(source.path(), "config/runtime.json", config);
        primary
            .execute(
                "INSERT INTO recovery_configs VALUES ('config/runtime.json', ?1, ?2)",
                rusqlite::params![config_digest, config.len()],
            )
            .expect("config row");
        drop(primary);

        let recovery_set = create(source.path(), backups.path()).expect("backup");
        let manifest = verify(&recovery_set).expect("verified backup");
        assert_eq!(manifest.database_count, 16);
        assert_eq!(manifest.components.len(), 18);
        let restored = restore(&recovery_set, &target).expect("restore");
        assert_eq!(restored, manifest);
        assert_eq!(fs::read(target.join(&blob_relative)).expect("blob"), blob);
        assert_eq!(
            fs::read(target.join("config/runtime.json")).expect("config"),
            config
        );
        for index in 0..16 {
            assert_eq!(
                integrity_check(&target.join(format!("state-{index}.sqlite3"))).expect("integrity"),
                "ok"
            );
        }
    }

    #[test]
    fn online_backup_restarts_to_include_a_concurrent_commit() {
        let directory = tempfile::tempdir().expect("directory");
        let source_path = directory.path().join("source.sqlite3");
        let target_path = directory.path().join("target.sqlite3");
        let source = Connection::open(&source_path).expect("source");
        let journal_mode: String = source
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("wal mode");
        assert_eq!(journal_mode, "wal");
        source
            .execute(
                "CREATE TABLE events (event_id INTEGER PRIMARY KEY, payload BLOB NOT NULL)",
                [],
            )
            .expect("schema");
        let payload = vec![7_u8; 8 * 1024];
        for index in 0..64 {
            source
                .execute(
                    "INSERT INTO events VALUES (?1, ?2)",
                    rusqlite::params![index, payload],
                )
                .expect("seed");
        }
        let concurrent = Connection::open(&source_path).expect("concurrent");
        let mut target = Connection::open(&target_path).expect("target");
        {
            let backup = Backup::new(&source, &mut target).expect("backup");
            assert_ne!(
                backup.step(1).expect("first page"),
                rusqlite::backup::StepResult::Done
            );
            concurrent
                .execute("INSERT INTO events VALUES (1000, X'01')", [])
                .expect("concurrent commit");
            backup
                .run_to_completion(1, Duration::ZERO, None)
                .expect("completion");
        }
        let included: bool = target
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE event_id=1000)",
                [],
                |row| row.get(0),
            )
            .expect("watermark row");
        assert!(included);
    }

    #[test]
    fn a_naive_database_after_blobs_set_fails_while_sqlite_is_healthy() {
        let source = tempfile::tempdir().expect("source");
        let set = tempfile::tempdir().expect("set");
        fs::create_dir(set.path().join("databases")).expect("database directory");
        let database = source.path().join("control.sqlite3");
        let connection = Connection::open(&database).expect("database");
        connection
            .execute(
                "CREATE TABLE recovery_blobs (relative_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL)",
                [],
            )
            .expect("schema");
        let payload = b"committed after blobs were copied";
        let digest = hex::encode(Sha256::digest(payload));
        let relative = format!("blobs/{}/{digest}", &digest[..2]);
        connection
            .execute(
                "INSERT INTO recovery_blobs VALUES (?1, ?2, ?3)",
                rusqlite::params![relative, digest, payload.len()],
            )
            .expect("row");
        drop(connection);
        snapshot_database(&database, &set.path().join("databases/control.sqlite3"))
            .expect("snapshot");
        assert_eq!(
            integrity_check(&set.path().join("databases/control.sqlite3")).expect("integrity"),
            "ok"
        );
        let database_component = component_for(
            set.path(),
            "databases/control.sqlite3",
            ComponentKind::Database,
            Some("ok".to_owned()),
        )
        .expect("component");
        let now = unix_millis().expect("time");
        write_manifest(
            set.path(),
            &RecoveryManifest {
                schema: MANIFEST_SCHEMA.to_owned(),
                snapshot_started_unix_ms: now,
                snapshot_completed_unix_ms: now,
                database_count: 1,
                ordering_invariants: ORDERING.iter().map(ToString::to_string).collect(),
                components: vec![database_component],
            },
        )
        .expect("manifest");
        assert_eq!(
            verify(set.path()).expect_err("torn set refused").category(),
            "derived_file_set_mismatch"
        );
    }

    #[test]
    fn restore_refuses_a_non_empty_target() {
        let source = tempfile::tempdir().expect("source");
        let backups = tempfile::tempdir().expect("backups");
        Connection::open(source.path().join("state.sqlite3")).expect("database");
        let recovery_set = create(source.path(), backups.path()).expect("backup");
        let target = tempfile::tempdir().expect("target");
        fs::write(target.path().join("owned.txt"), b"keep").expect("existing file");
        assert_eq!(
            restore(&recovery_set, target.path())
                .expect_err("non-empty target refused")
                .category(),
            "restore_target_not_empty"
        );
        assert_eq!(
            fs::read(target.path().join("owned.txt")).expect("preserved"),
            b"keep"
        );
    }

    fn write_source_file(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, bytes).expect("source file");
    }
}
