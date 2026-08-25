// SPDX-License-Identifier: Elastic-2.0

//! Non-owning candidate process and its one-time warm-up channel.
//!
//! The source generation launches the exact binary selected by
//! [`VerifiedCodeRelease`](crate::release_activation::VerifiedCodeRelease).
//! The child inherits one private socket as stdin/stdout, proves that its own
//! executable still has the verified digest, and reads the durable stores in
//! SQLite read-only mode. It never acquires the control lock, opens a transport,
//! migrates a database, or claims a lease. A warm child therefore remains a
//! candidate: later handoff code must explicitly transfer authority before it
//! can serve.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use automonique_store::SCHEMA_VERSION;
use automonique_store::generation_audit::GENERATION_AUDIT_SCHEMA_VERSION;
use automonique_store::reload_audit::RELOAD_AUDIT_SCHEMA_VERSION;
use nix::unistd::{geteuid, getppid};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DaemonConfig;
use crate::attempt_adoption::{AttemptAdoptionClient, socket_path as attempt_adoption_socket_path};
use crate::attempt_host::MAX_ATTEMPT_REGISTRATIONS;
use crate::control_lock::{ControlLock, ControlLockError};
use crate::lease_identity::{ProcessIdentity, ProcessIdentityError};
use crate::release_activation::VerifiedCodeRelease;

const CHANNEL_SCHEMA: &str = "automonique.reload-candidate/v2";
const MAX_CHANNEL_LINE_BYTES: u64 = 4 * 1024;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateSpec {
    pub reload_id: String,
    pub source_holder_id: String,
    pub source_lease_epoch: u64,
    pub target_generation_id: String,
    pub warm_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateInput {
    pub manifest_digest: String,
    pub binary_sha256: String,
    pub reload_id: String,
    pub source_holder_id: String,
    pub source_lease_epoch: u64,
    pub target_generation_id: String,
    pub expected_parent_pid: u32,
}

#[derive(Debug)]
pub struct WarmCandidate {
    child: Child,
    channel: UnixStream,
    identity: CandidateIdentity,
    stopped: bool,
}

/// Bounded proof of the source attempt inventory observed during warm-up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptInventoryProof {
    pub count: u32,
    pub sha256: String,
}

/// Exact candidate identity the source binds into a transferred lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLeaseTarget {
    pub holder_id: String,
    pub boot_id: String,
    pub pid: u32,
    pub starttime: u64,
}

/// Duplicated kernel capabilities the source may send only to its warmed child.
pub struct CandidateTransferDescriptors {
    admin_listener: UnixListener,
    control_lock: File,
}

impl CandidateTransferDescriptors {
    pub(crate) const fn new(admin_listener: UnixListener, control_lock: File) -> Self {
        Self {
            admin_listener,
            control_lock,
        }
    }
}

/// Validated listener and continuously-held generation lock for activation.
pub struct AdoptedCandidateResources {
    admin_listener: UnixListener,
    _control_lock: ControlLock,
}

impl AdoptedCandidateResources {
    /// Validate descriptors duplicated by the source against the configured
    /// named inodes. No bind or unlocked interval occurs here.
    pub fn adopt(
        config: &DaemonConfig,
        descriptors: CandidateTransferDescriptors,
    ) -> Result<Self, CandidateError> {
        let local = descriptors.admin_listener.local_addr()?;
        if local.as_pathname() != Some(config.admin_socket().as_path()) {
            return Err(CandidateError::UnsafePath("admin_listener"));
        }
        let metadata = fs::symlink_metadata(config.admin_socket())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(CandidateError::UnsafePath("admin_listener"));
        }
        let control_lock = ControlLock::adopt(descriptors.control_lock, config.control_lock_path())
            .map_err(map_control_lock)?;
        Ok(Self {
            admin_listener: descriptors.admin_listener,
            _control_lock: control_lock,
        })
    }

    #[must_use]
    pub fn admin_socket(&self) -> Option<std::path::PathBuf> {
        self.admin_listener
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(Path::to_path_buf))
    }
}

fn map_control_lock(error: ControlLockError) -> CandidateError {
    match error {
        ControlLockError::Io(error) => CandidateError::Io(error),
        ControlLockError::Held => CandidateError::Protocol,
        ControlLockError::InsecurePath => CandidateError::UnsafePath("control_lock"),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateIdentity {
    schema: String,
    event: String,
    reload_id: String,
    target_generation_id: String,
    manifest_digest: String,
    binary_sha256: String,
    attempt_count: u32,
    attempt_inventory_sha256: String,
    target_holder_id: String,
    boot_id: String,
    starttime: u64,
    pid: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateControl {
    schema: String,
    command: String,
    reload_id: String,
    target_generation_id: String,
}

#[derive(Debug)]
pub enum CandidateError {
    InvalidField(&'static str),
    UnsafePath(&'static str),
    DigestMismatch,
    SchemaMismatch(&'static str),
    Integrity(&'static str),
    SourceLeaseChanged,
    ParentChanged,
    Protocol,
    CandidateExited,
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl CandidateError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "candidate_invalid_field",
            Self::UnsafePath(_) => "candidate_unsafe_path",
            Self::DigestMismatch => "candidate_digest_mismatch",
            Self::SchemaMismatch(_) => "candidate_schema_mismatch",
            Self::Integrity(_) => "candidate_integrity",
            Self::SourceLeaseChanged => "candidate_source_lease_changed",
            Self::ParentChanged => "candidate_parent_changed",
            Self::Protocol => "candidate_protocol",
            Self::CandidateExited => "candidate_exited",
            Self::Io(_) => "candidate_io",
            Self::Sqlite(_) => "candidate_sqlite",
        }
    }
}

impl fmt::Display for CandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for CandidateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CandidateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for CandidateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Launch the exact verified release and wait for its non-owning warm proof.
pub fn spawn_warm_candidate(
    config: &DaemonConfig,
    release: &VerifiedCodeRelease,
    spec: &CandidateSpec,
) -> Result<WarmCandidate, CandidateError> {
    validate_identifier(&spec.reload_id, "reload_id")?;
    validate_identifier(&spec.source_holder_id, "source_holder_id")?;
    validate_identifier(&spec.target_generation_id, "target_generation_id")?;
    if spec.source_lease_epoch == 0 || spec.warm_timeout.is_zero() {
        return Err(CandidateError::InvalidField("candidate_spec"));
    }
    validate_digest(&release.manifest_digest, true, "manifest_digest")?;
    validate_digest(&release.binary_sha256, false, "binary_sha256")?;

    let (parent, child_channel) = UnixStream::pair()?;
    parent.set_read_timeout(Some(spec.warm_timeout))?;
    parent.set_write_timeout(Some(spec.warm_timeout))?;
    let child_stdin: OwnedFd = child_channel.try_clone()?.into();
    let child_stdout: OwnedFd = child_channel.into();
    let parent_pid = std::process::id();
    let arguments = candidate_arguments(release, spec, parent_pid);
    let mut child = Command::new(release.binary_path())
        .args(arguments)
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()?;
    let observed: CandidateIdentity = match read_message(&parent) {
        Ok(observed) => observed,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if validate_digest(
        &observed.attempt_inventory_sha256,
        false,
        "attempt_inventory_sha256",
    )
    .is_err()
        || usize::try_from(observed.attempt_count)
            .map_or(true, |count| count > MAX_ATTEMPT_REGISTRATIONS)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CandidateError::Protocol);
    }
    let measured = match process_identity(child.id()) {
        Ok(measured) => measured,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let expected = CandidateIdentity {
        schema: CHANNEL_SCHEMA.to_owned(),
        event: "warm".to_owned(),
        reload_id: spec.reload_id.clone(),
        target_generation_id: spec.target_generation_id.clone(),
        manifest_digest: release.manifest_digest.clone(),
        binary_sha256: release.binary_sha256.clone(),
        attempt_count: observed.attempt_count,
        attempt_inventory_sha256: observed.attempt_inventory_sha256.clone(),
        target_holder_id: candidate_holder_id(child.id(), &spec.reload_id),
        boot_id: measured.boot_id,
        starttime: measured.starttime,
        pid: child.id(),
    };
    if observed != expected {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CandidateError::Protocol);
    }
    Ok(WarmCandidate {
        child,
        channel: parent,
        identity: observed,
        stopped: false,
    })
}

fn candidate_arguments(
    release: &VerifiedCodeRelease,
    spec: &CandidateSpec,
    parent_pid: u32,
) -> Vec<OsString> {
    [
        "__reload-candidate".into(),
        "--manifest-digest".into(),
        release.manifest_digest.clone().into(),
        "--binary-sha256".into(),
        release.binary_sha256.clone().into(),
        "--reload-id".into(),
        spec.reload_id.clone().into(),
        "--source-holder".into(),
        spec.source_holder_id.clone().into(),
        "--source-epoch".into(),
        spec.source_lease_epoch.to_string().into(),
        "--generation-id".into(),
        spec.target_generation_id.clone().into(),
        "--parent-pid".into(),
        parent_pid.to_string().into(),
    ]
    .into()
}

impl WarmCandidate {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.identity.pid
    }

    /// Source-host inventory the candidate reached through the pinned route.
    #[must_use]
    pub fn attempt_inventory_proof(&self) -> AttemptInventoryProof {
        AttemptInventoryProof {
            count: self.identity.attempt_count,
            sha256: self.identity.attempt_inventory_sha256.clone(),
        }
    }

    /// Kernel-bound coordinates the source writes into the successor lease.
    #[must_use]
    pub fn lease_target(&self) -> CandidateLeaseTarget {
        CandidateLeaseTarget {
            holder_id: self.identity.target_holder_id.clone(),
            boot_id: self.identity.boot_id.clone(),
            pid: self.identity.pid,
            starttime: self.identity.starttime,
        }
    }

    /// End a still-non-owning candidate and require a matching acknowledgement.
    pub fn stop(mut self) -> Result<(), CandidateError> {
        let control = CandidateControl {
            schema: CHANNEL_SCHEMA.to_owned(),
            command: "stop".to_owned(),
            reload_id: self.identity.reload_id.clone(),
            target_generation_id: self.identity.target_generation_id.clone(),
        };
        write_message(&mut self.channel, &control)?;
        let mut expected = self.identity.clone();
        expected.event = "stopped".to_owned();
        let observed: CandidateIdentity = read_message(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        if !self.child.wait()?.success() {
            return Err(CandidateError::CandidateExited);
        }
        self.stopped = true;
        Ok(())
    }
}

impl Drop for WarmCandidate {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Candidate entry point used only by the private inherited channel.
pub fn run_candidate(
    config: &DaemonConfig,
    input: CandidateInput,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(), CandidateError> {
    validate_input(&input)?;
    if getppid().as_raw() as u32 != input.expected_parent_pid {
        return Err(CandidateError::ParentChanged);
    }
    verify_own_binary(&input.binary_sha256)?;
    warm_state(config, &input.source_holder_id, input.source_lease_epoch)?;
    let (attempt_count, attempt_inventory_sha256) =
        warm_attempt_host(config, &input.source_holder_id, input.source_lease_epoch)?;
    let process_identity = process_identity(std::process::id())?;
    let target_holder_id = candidate_holder_id(process_identity.pid, &input.reload_id);
    if getppid().as_raw() as u32 != input.expected_parent_pid {
        return Err(CandidateError::ParentChanged);
    }
    let identity = CandidateIdentity {
        schema: CHANNEL_SCHEMA.to_owned(),
        event: "warm".to_owned(),
        reload_id: input.reload_id,
        target_generation_id: input.target_generation_id,
        manifest_digest: input.manifest_digest,
        binary_sha256: input.binary_sha256,
        attempt_count,
        attempt_inventory_sha256,
        target_holder_id,
        boot_id: process_identity.boot_id,
        starttime: process_identity.starttime,
        pid: process_identity.pid,
    };
    write_message(&mut writer, &identity)?;
    let control: CandidateControl = read_message_from(&mut reader)?;
    if control.schema != CHANNEL_SCHEMA
        || control.command != "stop"
        || control.reload_id != identity.reload_id
        || control.target_generation_id != identity.target_generation_id
    {
        return Err(CandidateError::Protocol);
    }
    let mut stopped = identity;
    stopped.event = "stopped".to_owned();
    write_message(&mut writer, &stopped)
}

fn process_identity(pid: u32) -> Result<ProcessIdentity, CandidateError> {
    ProcessIdentity::for_pid(pid)
        .map_err(|error| match error {
            ProcessIdentityError::Io(error) => CandidateError::Io(error),
            ProcessIdentityError::Malformed(category) => CandidateError::UnsafePath(category),
        })?
        .ok_or(CandidateError::CandidateExited)
}

fn candidate_holder_id(pid: u32, reload_id: &str) -> String {
    let digest = encode_hex(&Sha256::digest(reload_id.as_bytes()));
    format!("daemon-{pid}-reload-{}", &digest[..16])
}

fn warm_attempt_host(
    config: &DaemonConfig,
    source_holder_id: &str,
    source_lease_epoch: u64,
) -> Result<(u32, String), CandidateError> {
    let socket_path = attempt_adoption_socket_path(&config.runtime_dir(), source_holder_id)
        .map_err(|_| CandidateError::UnsafePath("attempt_adoption"))?;
    let inventory = AttemptAdoptionClient::new(socket_path, source_holder_id, source_lease_epoch)
        .map_err(|_| CandidateError::Protocol)?
        .inventory()
        .map_err(|_| CandidateError::Protocol)?;
    let attempt_count = u32::try_from(inventory.attempt_ids.len())
        .map_err(|_| CandidateError::InvalidField("attempt_count"))?;
    let mut digest = Sha256::new();
    for attempt_id in inventory.attempt_ids {
        let length = u32::try_from(attempt_id.len())
            .map_err(|_| CandidateError::InvalidField("attempt_id"))?;
        digest.update(length.to_be_bytes());
        digest.update(attempt_id.as_bytes());
    }
    Ok((attempt_count, encode_hex(&digest.finalize())))
}

fn validate_input(input: &CandidateInput) -> Result<(), CandidateError> {
    validate_digest(&input.manifest_digest, true, "manifest_digest")?;
    validate_digest(&input.binary_sha256, false, "binary_sha256")?;
    validate_identifier(&input.reload_id, "reload_id")?;
    validate_identifier(&input.source_holder_id, "source_holder_id")?;
    validate_identifier(&input.target_generation_id, "target_generation_id")?;
    if input.source_lease_epoch == 0 || input.expected_parent_pid == 0 {
        return Err(CandidateError::InvalidField("candidate_input"));
    }
    Ok(())
}

fn verify_own_binary(expected: &str) -> Result<(), CandidateError> {
    let path = std::env::current_exe()?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_BINARY_BYTES
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(CandidateError::UnsafePath("candidate_binary"));
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if encode_hex(&digest.finalize()) == expected {
        Ok(())
    } else {
        Err(CandidateError::DigestMismatch)
    }
}

fn warm_state(
    config: &DaemonConfig,
    source_holder_id: &str,
    source_lease_epoch: u64,
) -> Result<(), CandidateError> {
    super::validate_root(&config.runtime_root, "runtime root")
        .map_err(|_| CandidateError::UnsafePath("runtime_root"))?;
    super::validate_root(&config.state_root, "state root")
        .map_err(|_| CandidateError::UnsafePath("state_root"))?;
    super::validate_root(&config.runtime_dir(), "runtime directory")
        .map_err(|_| CandidateError::UnsafePath("runtime_directory"))?;
    super::validate_root(&config.state_dir(), "state directory")
        .map_err(|_| CandidateError::UnsafePath("state_directory"))?;

    let main = read_only_database(&config.database_path(), SCHEMA_VERSION, "main")?;
    let lease = main
        .query_row(
            "SELECT lease_holder, lease_epoch FROM generations
             WHERE generation_id = 'foreground'",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if lease
        != Some((
            source_holder_id.to_owned(),
            i64::try_from(source_lease_epoch)
                .map_err(|_| CandidateError::InvalidField("source_lease_epoch"))?,
        ))
    {
        return Err(CandidateError::SourceLeaseChanged);
    }
    drop(main);
    drop(read_only_database(
        &config.generation_audit_path(),
        GENERATION_AUDIT_SCHEMA_VERSION,
        "generation_audit",
    )?);
    drop(read_only_database(
        &config.reload_audit_path(),
        RELOAD_AUDIT_SCHEMA_VERSION,
        "reload_audit",
    )?);
    Ok(())
}

fn read_only_database(
    path: &Path,
    expected_version: u32,
    label: &'static str,
) -> Result<Connection, CandidateError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(CandidateError::UnsafePath(label));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.pragma_update(None, "query_only", true)?;
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != expected_version {
        return Err(CandidateError::SchemaMismatch(label));
    }
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(CandidateError::Integrity(label));
    }
    Ok(connection)
}

fn write_message(writer: &mut impl Write, value: &impl Serialize) -> Result<(), CandidateError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CandidateError::Protocol)?;
    if bytes.is_empty() || bytes.len() as u64 >= MAX_CHANNEL_LINE_BYTES {
        return Err(CandidateError::Protocol);
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_message<T: for<'de> Deserialize<'de>>(channel: &UnixStream) -> Result<T, CandidateError> {
    read_message_from(&mut BufReader::new(channel))
}

fn read_message_from<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, CandidateError> {
    let mut line = Vec::new();
    let read = BufReader::new(reader)
        .take(MAX_CHANNEL_LINE_BYTES)
        .read_until(b'\n', &mut line)?;
    if read == 0 || read as u64 == MAX_CHANNEL_LINE_BYTES || line.last() != Some(&b'\n') {
        return Err(CandidateError::Protocol);
    }
    line.pop();
    serde_json::from_slice(&line).map_err(|_| CandidateError::Protocol)
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CandidateError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(CandidateError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(value: &str, prefixed: bool, field: &'static str) -> Result<(), CandidateError> {
    let value = if prefixed {
        value
            .strip_prefix("sha256:")
            .ok_or(CandidateError::InvalidField(field))?
    } else {
        value
    };
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(CandidateError::InvalidField(field));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_is_closed_bounded_and_identity_bound() {
        let identity = CandidateIdentity {
            schema: CHANNEL_SCHEMA.to_owned(),
            event: "warm".to_owned(),
            reload_id: "reload-1".to_owned(),
            target_generation_id: "generation-2".to_owned(),
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
            binary_sha256: "b".repeat(64),
            attempt_count: 2,
            attempt_inventory_sha256: "c".repeat(64),
            target_holder_id: "daemon-42-reload-0123456789abcdef".to_owned(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            starttime: 100,
            pid: 42,
        };
        let mut bytes = Vec::new();
        write_message(&mut bytes, &identity).expect("encode");
        assert_eq!(
            read_message_from::<CandidateIdentity>(&mut bytes.as_slice()).expect("decode"),
            identity
        );

        let unknown = br#"{"schema":"automonique.reload-candidate/v2","event":"warm","reload_id":"reload-1","target_generation_id":"generation-2","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","binary_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt_count":2,"attempt_inventory_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","target_holder_id":"daemon-42-reload-0123456789abcdef","boot_id":"01234567-89ab-cdef-0123-456789abcdef","starttime":100,"pid":42,"extra":true}\n"#;
        assert!(matches!(
            read_message_from::<CandidateIdentity>(&mut unknown.as_slice()),
            Err(CandidateError::Protocol)
        ));
        let oversized = vec![b'x'; MAX_CHANNEL_LINE_BYTES as usize];
        assert!(matches!(
            read_message_from::<CandidateIdentity>(&mut oversized.as_slice()),
            Err(CandidateError::Protocol)
        ));
    }

    #[test]
    fn warm_state_is_read_only_and_bound_to_the_source_lease() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
        let runtime_root = root.path().join("runtime");
        let state_root = root.path().join("state");
        for path in [&runtime_root, &state_root] {
            fs::create_dir(path).expect("root child");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private");
        }
        let config = DaemonConfig {
            runtime_root,
            state_root,
        };
        for path in [config.runtime_dir(), config.state_dir()] {
            fs::create_dir(&path).expect("product dir");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private");
        }
        create_database(&config.database_path(), SCHEMA_VERSION, true);
        create_database(
            &config.generation_audit_path(),
            GENERATION_AUDIT_SCHEMA_VERSION,
            false,
        );
        create_database(
            &config.reload_audit_path(),
            RELOAD_AUDIT_SCHEMA_VERSION,
            false,
        );

        warm_state(&config, "holder-1", 7).expect("warm");
        assert!(matches!(
            warm_state(&config, "holder-1", 8),
            Err(CandidateError::SourceLeaseChanged)
        ));
        let version: u32 = Connection::open(config.database_path())
            .expect("open")
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version");
        assert_eq!(version, SCHEMA_VERSION, "warm-up migrated no state");
    }

    #[test]
    fn listener_and_lock_capabilities_transfer_without_rebinding_or_unlocking() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
        let runtime_root = root.path().join("runtime");
        let state_root = root.path().join("state");
        for path in [&runtime_root, &state_root] {
            fs::create_dir(path).expect("root child");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private");
        }
        let config = DaemonConfig {
            runtime_root,
            state_root,
        };
        let daemon = crate::Daemon::open(&config).expect("source daemon");
        let adopted = AdoptedCandidateResources::adopt(
            &config,
            daemon
                .candidate_transfer_descriptors()
                .expect("duplicate capabilities"),
        )
        .expect("candidate adopts capabilities");
        assert_eq!(
            adopted.admin_socket().as_deref(),
            Some(config.admin_socket().as_path())
        );
        assert!(matches!(
            ControlLock::acquire(config.control_lock_path()),
            Err(ControlLockError::Held)
        ));

        drop(daemon);
        assert!(matches!(
            ControlLock::acquire(config.control_lock_path()),
            Err(ControlLockError::Held)
        ));
        drop(adopted);
        ControlLock::acquire(config.control_lock_path()).expect("final duplicate releases lock");
    }

    fn create_database(path: &Path, version: u32, main: bool) {
        let connection = Connection::open(path).expect("database");
        connection
            .pragma_update(None, "user_version", version)
            .expect("version");
        if main {
            connection
                .execute_batch(
                    "CREATE TABLE generations (
                        generation_id TEXT PRIMARY KEY,
                        lease_holder TEXT NOT NULL,
                        lease_epoch INTEGER NOT NULL
                    ) STRICT;
                    INSERT INTO generations VALUES ('foreground', 'holder-1', 7);",
                )
                .expect("lease");
        }
        drop(connection);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private database");
    }
}
