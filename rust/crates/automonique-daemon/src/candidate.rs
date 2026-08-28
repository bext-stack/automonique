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
use std::io::{BufRead, BufReader, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use automonique_store::generation_audit::GENERATION_AUDIT_SCHEMA_VERSION;
use automonique_store::reload_audit::{
    AdvanceReload, RELOAD_AUDIT_SCHEMA_VERSION, ReloadAudit, ReloadPhase,
};
use automonique_store::{
    GenerationLease, LeaseRenewal, LeaseTimeSource, SCHEMA_VERSION, Store, StoreError,
};
use nix::unistd::{geteuid, getppid};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DaemonConfig;
use crate::attempt_adoption::{
    AdoptedSourceAttempts, AttemptAdoptionClient, AttemptHostRoute, inventory_digest,
    socket_path as attempt_adoption_socket_path,
};
use crate::attempt_host::MAX_ATTEMPT_REGISTRATIONS;
use crate::control_lock::{ControlLock, ControlLockError};
use crate::lease_identity::{ProcessIdentity, ProcessIdentityError};
use crate::release_activation::VerifiedCodeRelease;

const CHANNEL_SCHEMA: &str = "automonique.reload-candidate/v8";
/// Failure category a successor records when the private channel to its
/// source closes after it proved active but before the source committed it.
pub const SOURCE_GENERATION_LOST: &str = "source_generation_lost";
const MAX_CHANNEL_LINE_BYTES: u64 = 4 * 1024;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const CONTROL_STOP: u8 = b'S';
const CONTROL_PREPARE_TRANSFER: u8 = b'T';
const CONTROL_CONFIRM_AUTHORITY: u8 = b'A';
const CONTROL_CONFIRM_RELINQUISHED: u8 = b'R';
/// Activate, with the admin pathname owned by the daemon process tree: the
/// candidate inherits the duty to unlink it when it stops.
const CONTROL_ACTIVATE_SERVING_OWNED: u8 = b'V';
/// Activate, with the admin pathname owned by the service manager's socket
/// unit: the candidate holds that unit's inode and must never unlink it.
const CONTROL_ACTIVATE_SERVING_ACTIVATED: u8 = b'W';
const CONTROL_QUIESCE: u8 = b'Q';
const CONTROL_COMMIT: u8 = b'C';

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
    source_holder_id: String,
    source_lease_epoch: u64,
    transfer_ready: bool,
    authority_ready: bool,
    serving: bool,
    quiesced: bool,
    relinquished: bool,
    stopped: bool,
    /// The child was observed to have exited on its own; see
    /// [`WarmCandidate::has_exited`].
    exited: bool,
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
    progress_listener: UnixListener,
    control_lock: File,
}

/// One-use proof that the source disarmed cleanup of the transferred sockets,
/// carrying whether the admin pathname was the source's to unlink at all.
pub struct EndpointCleanupTransfer {
    admin_socket_path_owned: bool,
}

impl EndpointCleanupTransfer {
    pub(crate) const fn new(admin_socket_path_owned: bool) -> Self {
        Self {
            admin_socket_path_owned,
        }
    }

    /// Whether the source owned the admin pathname, and so whether the
    /// candidate may arm an unlink of it.
    ///
    /// False for a socket-activated source: the pathname belongs to the
    /// socket unit, outlives every generation that answers on it, and is
    /// recreated by nobody in this process tree once it is gone.
    pub(crate) const fn admin_socket_path_owned(&self) -> bool {
        self.admin_socket_path_owned
    }
}

impl CandidateTransferDescriptors {
    pub(crate) const fn new(
        admin_listener: UnixListener,
        progress_listener: UnixListener,
        control_lock: File,
    ) -> Self {
        Self {
            admin_listener,
            progress_listener,
            control_lock,
        }
    }
}

/// Validated listener and continuously-held generation lock for activation.
pub struct AdoptedCandidateResources {
    admin_listener: UnixListener,
    progress_listener: UnixListener,
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
        let progress_local = descriptors.progress_listener.local_addr()?;
        if progress_local.as_pathname() != Some(config.progress_socket().as_path()) {
            return Err(CandidateError::UnsafePath("progress_listener"));
        }
        let progress_metadata = fs::symlink_metadata(config.progress_socket())?;
        if !progress_metadata.file_type().is_socket()
            || progress_metadata.uid() != geteuid().as_raw()
            || progress_metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(CandidateError::UnsafePath("progress_listener"));
        }
        let control_lock = ControlLock::adopt(descriptors.control_lock, config.control_lock_path())
            .map_err(map_control_lock)?;
        Ok(Self {
            admin_listener: descriptors.admin_listener,
            progress_listener: descriptors.progress_listener,
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

    #[must_use]
    pub fn progress_socket(&self) -> Option<std::path::PathBuf> {
        self.progress_listener
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(Path::to_path_buf))
    }

    pub(crate) fn into_parts(self) -> (UnixListener, UnixListener, ControlLock) {
        (
            self.admin_listener,
            self.progress_listener,
            self._control_lock,
        )
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

/// Authority the source hands its warmed child, or the return of it.
///
/// `adopted_runs` is what the durable lease transfer moved: scheduler runs of
/// the generation now fenced at the child's epoch, which the child re-counts
/// from the store before it trusts the number. `source_attempts` is the other
/// population the handoff carries — attempts whose worker threads stay in the
/// source until they finish — measured from the source's own attempt host at
/// transfer time, so the child can check the inventory it took during warm-up
/// against what the source actually still hosts. The two are deliberately not
/// compared with each other: they count different things.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateAuthority {
    schema: String,
    event: String,
    generation_id: String,
    holder_id: String,
    lease_epoch: u64,
    boot_id: String,
    pid: u32,
    starttime: u64,
    adopted_runs: u64,
    source_attempts: u32,
    source_attempts_sha256: String,
}

/// The one line a candidate writes before exiting on a refusal, so the source
/// records why its child stopped rather than only that the channel closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateRefusal {
    schema: String,
    event: String,
    reload_id: String,
    category: String,
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
    /// The other side of the private channel speaks a different
    /// `automonique.reload-candidate` schema.
    ///
    /// Its own category, distinct from [`CandidateError::SchemaMismatch`]
    /// (the *durable* schema the candidate's read-only warm-up could not
    /// read) and from [`CandidateError::Protocol`] (a line that is malformed
    /// or names the wrong identity), because the repair is different: this
    /// release cannot hand off to, or back to, a release whose channel is
    /// older or newer than [`CHANNEL_SCHEMA`], and the crossing has to be a
    /// restart rather than a reload.
    ChannelSchemaMismatch,
    /// The child reported its own refusal over the channel before exiting.
    CandidateRefused(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Store(StoreError),
    Daemon(&'static str),
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
            Self::ChannelSchemaMismatch => "candidate_channel_schema_mismatch",
            Self::CandidateRefused(category) | Self::Daemon(category) => category,
            Self::Io(_) => "candidate_io",
            Self::Sqlite(_) => "candidate_sqlite",
            Self::Store(_) => "candidate_store",
        }
    }

    /// The closed set of categories a child may report, as static strings.
    ///
    /// A category outside this set is reported as the generic refusal: the
    /// channel is a private, bounded line and never a free-text conduit. The
    /// set is this module's own categories plus those a candidate legitimately
    /// carries out of the daemon it opened or served
    /// ([`CandidateError::Daemon`]), so a transferred daemon that could not
    /// open its store, bind its route, or record its tenure is reported under
    /// that word rather than collapsed to `candidate_refused`.
    fn reported_category(reported: &str) -> &'static str {
        const KNOWN: [&str; 13] = [
            "candidate_invalid_field",
            "candidate_unsafe_path",
            "candidate_digest_mismatch",
            "candidate_schema_mismatch",
            "candidate_integrity",
            "candidate_source_lease_changed",
            "candidate_parent_changed",
            "candidate_protocol",
            "candidate_exited",
            "candidate_channel_schema_mismatch",
            "candidate_io",
            "candidate_sqlite",
            "candidate_store",
        ];
        KNOWN
            .into_iter()
            .chain(super::DAEMON_ERROR_CATEGORIES)
            .chain(crate::attempt_adoption::AttemptAdoptionError::CATEGORIES)
            .chain(["candidate_serve_panicked"])
            .find(|known| *known == reported)
            .unwrap_or("candidate_refused")
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
            Self::Store(error) => Some(error),
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

impl From<StoreError> for CandidateError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
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
        // The service manager set WATCHDOG_PID to the source's pid; the
        // candidate exists to become the main process, so it must keep the
        // watchdog cadence from WATCHDOG_USEC rather than disable itself on
        // a pid that is not its own. Its pings are ignored until the source
        // announces it as main, then they are the ones that count.
        .env_remove("WATCHDOG_PID")
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()?;
    let observed = match read_identity(&parent) {
        Ok(observed) => observed,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    // A child that speaks another channel schema is a release this one
    // cannot hand off to; that is judged before anything else about its
    // identity, so the operator sees the schema and not a protocol mismatch
    // that the schema difference merely caused.
    if observed.schema != CHANNEL_SCHEMA {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CandidateError::ChannelSchemaMismatch);
    }
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
        source_holder_id: spec.source_holder_id.clone(),
        source_lease_epoch: spec.source_lease_epoch,
        transfer_ready: false,
        authority_ready: false,
        serving: false,
        quiesced: false,
        relinquished: false,
        stopped: false,
        exited: false,
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

    /// Send the duplicated listener and continuously-held lock over the private
    /// parent/child channel and require the child to validate both.
    pub fn prepare_transfer(
        &mut self,
        descriptors: CandidateTransferDescriptors,
    ) -> Result<(), CandidateError> {
        if self.transfer_ready {
            return Err(CandidateError::Protocol);
        }
        send_control(&self.channel, CONTROL_PREPARE_TRANSFER, Some(descriptors))?;
        let mut expected = self.identity.clone();
        expected.event = "transfer_ready".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.transfer_ready = true;
        Ok(())
    }

    #[must_use]
    pub const fn is_transfer_ready(&self) -> bool {
        self.transfer_ready
    }

    /// Whether the child process has already exited, reaping it if so.
    ///
    /// A candidate that died is not a candidate that must acknowledge
    /// anything: the durable lease is what says who holds authority, and a
    /// dead process holds nothing. Callers use this to decide whether a channel
    /// exchange can still be expected before they attempt one.
    pub fn has_exited(&mut self) -> bool {
        if self.exited {
            return true;
        }
        match self.child.try_wait() {
            Ok(Some(_)) => {
                self.exited = true;
                // Nothing is left for the drop guard to kill.
                self.stopped = true;
                true
            }
            Ok(None) => false,
            // A wait that cannot be performed says nothing about liveness; the
            // next channel exchange will settle it.
            Err(_) => false,
        }
    }

    /// Require the transferred candidate lease to match the child's measured
    /// kernel identity, then require the child to renew that exact epoch.
    ///
    /// `source_attempts` is the source's own live attempt registry at this
    /// instant. It must be covered by the inventory the child took during
    /// warm-up — the same count and digest when nothing finished in between,
    /// fewer when something did — because an attempt the child never
    /// inventoried would be one it could neither refuse to duplicate nor route
    /// a cancellation to.
    pub fn confirm_authority(
        &mut self,
        lease: &GenerationLease,
        adopted_runs: u64,
        source_attempts: &[String],
    ) -> Result<(), CandidateError> {
        if !self.transfer_ready || self.authority_ready || self.relinquished {
            return Err(CandidateError::Protocol);
        }
        let expected_epoch = self
            .source_lease_epoch
            .checked_add(1)
            .ok_or(CandidateError::Protocol)?;
        let target = self.lease_target();
        if lease.generation_id != super::GENERATION_ID
            || lease.holder_id != target.holder_id
            || lease.epoch != expected_epoch
            || lease.boot_id != target.boot_id
            || lease.holder_pid != target.pid
            || lease.holder_starttime != target.starttime
        {
            return Err(CandidateError::Protocol);
        }
        let source_attempt_count =
            u32::try_from(source_attempts.len()).map_err(|_| CandidateError::Protocol)?;
        let source_attempts_sha256 = inventory_digest(source_attempts);
        if source_attempt_count > self.identity.attempt_count
            || (source_attempt_count == self.identity.attempt_count
                && source_attempts_sha256 != self.identity.attempt_inventory_sha256)
        {
            return Err(CandidateError::Protocol);
        }
        let authority = CandidateAuthority::from_lease(
            "authority",
            lease,
            adopted_runs,
            source_attempt_count,
            source_attempts_sha256,
        );
        send_control(&self.channel, CONTROL_CONFIRM_AUTHORITY, None)?;
        write_message(&mut self.channel, &authority)?;
        let mut expected = self.identity.clone();
        expected.event = "authority_ready".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.authority_ready = true;
        Ok(())
    }

    /// Prove rollback committed at the next epoch before a formerly
    /// authoritative candidate is allowed to stop.
    pub fn confirm_relinquished(
        &mut self,
        returned_lease: &GenerationLease,
    ) -> Result<(), CandidateError> {
        let expected_epoch = self
            .source_lease_epoch
            .checked_add(2)
            .ok_or(CandidateError::Protocol)?;
        if !self.authority_ready
            || self.serving
            || self.relinquished
            || returned_lease.generation_id != super::GENERATION_ID
            || returned_lease.holder_id != self.source_holder_id
            || returned_lease.epoch != expected_epoch
        {
            return Err(CandidateError::Protocol);
        }
        let authority = CandidateAuthority::from_lease(
            "relinquished",
            returned_lease,
            0,
            0,
            inventory_digest(&[]),
        );
        send_control(&self.channel, CONTROL_CONFIRM_RELINQUISHED, None)?;
        write_message(&mut self.channel, &authority)?;
        let mut expected = self.identity.clone();
        expected.event = "relinquished".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.relinquished = true;
        Ok(())
    }

    /// Start the fully composed candidate and require readiness after every
    /// worker and inherited accept loop has started.
    pub fn activate_serving(
        &mut self,
        cleanup: EndpointCleanupTransfer,
    ) -> Result<(), CandidateError> {
        if !self.authority_ready || self.serving || self.quiesced || self.relinquished {
            return Err(CandidateError::Protocol);
        }
        let marker = if cleanup.admin_socket_path_owned() {
            CONTROL_ACTIVATE_SERVING_OWNED
        } else {
            CONTROL_ACTIVATE_SERVING_ACTIVATED
        };
        send_control(&self.channel, marker, None)?;
        let mut expected = self.identity.clone();
        expected.event = "active".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.serving = true;
        Ok(())
    }

    /// Stop candidate intake and workers while retaining its generation lease
    /// and inherited kernel capabilities for an explicit return transaction.
    pub fn quiesce(&mut self) -> Result<(), CandidateError> {
        if !self.serving || self.quiesced || self.relinquished {
            return Err(CandidateError::Protocol);
        }
        send_control(&self.channel, CONTROL_QUIESCE, None)?;
        let mut expected = self.identity.clone();
        expected.event = "quiesced".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.serving = false;
        self.quiesced = true;
        Ok(())
    }

    /// Commit this active candidate as the independent generation.
    ///
    /// After the matching acknowledgement the child no longer depends on the
    /// private handoff channel. Its normal admin shutdown path owns tenure and
    /// lease release, while dropping this source-side handle no longer kills
    /// the promoted daemon.
    pub fn commit(&mut self) -> Result<(), CandidateError> {
        if !self.serving || self.quiesced || self.relinquished || self.stopped {
            return Err(CandidateError::Protocol);
        }
        send_control(&self.channel, CONTROL_COMMIT, None)?;
        let mut expected = self.identity.clone();
        expected.event = "committed".to_owned();
        let observed = read_identity(&self.channel)?;
        if observed != expected {
            return Err(CandidateError::Protocol);
        }
        self.identity = observed;
        self.serving = false;
        // `Child`'s Drop does not terminate a process. This flag suppresses the
        // explicit candidate-only kill in our Drop implementation now that the
        // process is the committed generation rather than a disposable child.
        self.stopped = true;
        Ok(())
    }

    /// End a non-owning candidate and require a matching acknowledgement.
    /// A candidate that proved authority must first prove a fresh-epoch return.
    ///
    /// A child that has already exited is already stopped: there is no
    /// process left to acknowledge, and the durable lease — never this
    /// handle — is what records who holds authority.
    pub fn stop(&mut self) -> Result<(), CandidateError> {
        if self.has_exited() {
            return Ok(());
        }
        if self.stopped || (self.authority_ready && !self.relinquished) {
            return Err(CandidateError::Protocol);
        }
        send_control(&self.channel, CONTROL_STOP, None)?;
        let mut expected = self.identity.clone();
        expected.event = "stopped".to_owned();
        let observed = read_identity(&self.channel)?;
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

impl CandidateAuthority {
    fn from_lease(
        event: &str,
        lease: &GenerationLease,
        adopted_runs: u64,
        source_attempts: u32,
        source_attempts_sha256: String,
    ) -> Self {
        Self {
            schema: CHANNEL_SCHEMA.to_owned(),
            event: event.to_owned(),
            generation_id: lease.generation_id.clone(),
            holder_id: lease.holder_id.clone(),
            lease_epoch: lease.epoch,
            boot_id: lease.boot_id.clone(),
            pid: lease.holder_pid,
            starttime: lease.holder_starttime,
            adopted_runs,
            source_attempts,
            source_attempts_sha256,
        }
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
///
/// A refusal is reported on the channel before the process exits, so the
/// source records the child's own category rather than a closed pipe. The
/// write is best-effort: a channel that is already gone has nobody to tell.
pub fn run_candidate(
    config: &DaemonConfig,
    input: CandidateInput,
    mut reader: impl Read + AsFd,
    mut writer: impl Write,
) -> Result<(), CandidateError> {
    let reload_id = input.reload_id.clone();
    let outcome = run_candidate_channel(config, input, &mut reader, &mut writer);
    if let Err(error) = &outcome {
        let _ = write_message(
            &mut writer,
            &CandidateRefusal {
                schema: CHANNEL_SCHEMA.to_owned(),
                event: "refused".to_owned(),
                reload_id,
                category: error.category().to_owned(),
            },
        );
    }
    outcome
}

fn run_candidate_channel<R: Read + AsFd, W: Write>(
    config: &DaemonConfig,
    input: CandidateInput,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), CandidateError> {
    validate_input(&input)?;
    let source_pid = input.expected_parent_pid;
    if getppid().as_raw() as u32 != source_pid {
        return Err(CandidateError::ParentChanged);
    }
    verify_own_binary(&input.binary_sha256)?;
    warm_state(config, &input.source_holder_id, input.source_lease_epoch)?;
    let warm_inventory =
        warm_attempt_host(config, &input.source_holder_id, input.source_lease_epoch)?;
    let attempt_count = u32::try_from(warm_inventory.len())
        .map_err(|_| CandidateError::InvalidField("attempt_count"))?;
    let attempt_inventory_sha256 = inventory_digest(&warm_inventory);
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
    write_message(writer, &identity)?;
    let mut identity = identity;
    let adopted = match receive_control(reader.as_fd())? {
        CandidateControl::Stop => None,
        CandidateControl::PrepareTransfer(descriptors) => {
            let adopted = AdoptedCandidateResources::adopt(config, descriptors)?;
            identity.event = "transfer_ready".to_owned();
            write_message(writer, &identity)?;
            match receive_control(reader.as_fd())? {
                CandidateControl::Stop => {}
                CandidateControl::ConfirmAuthority => {
                    let authority: CandidateAuthority = read_message_from(reader)?;
                    let (renewed, adopted_attempts) = confirm_candidate_authority(
                        config,
                        &authority,
                        &identity,
                        &input.source_holder_id,
                        input.source_lease_epoch,
                        &warm_inventory,
                    )?;
                    let daemon =
                        crate::Daemon::open_transferred(config, adopted, renewed, adopted_attempts)
                            .map_err(|error| CandidateError::Daemon(error.category()))?;
                    identity.event = "authority_ready".to_owned();
                    write_message(writer, &identity)?;
                    let mut daemon = match receive_control(reader.as_fd())? {
                        CandidateControl::ConfirmRelinquished => daemon,
                        CandidateControl::ActivateServing {
                            admin_socket_path_owned,
                        } => {
                            let stop = Arc::new(AtomicBool::new(false));
                            let thread_stop = Arc::clone(&stop);
                            let release_on_stop = Arc::new(AtomicBool::new(false));
                            let thread_release_on_stop = Arc::clone(&release_on_stop);
                            let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
                            let serving = std::thread::spawn(move || {
                                daemon.serve_candidate(
                                    &thread_stop,
                                    ready_sender,
                                    thread_release_on_stop,
                                    source_pid,
                                    admin_socket_path_owned,
                                )
                            });
                            if ready_receiver
                                .recv_timeout(Duration::from_secs(20))
                                .is_err()
                            {
                                stop.store(true, Ordering::Release);
                                let (_, outcome) = serving.join().map_err(|_| {
                                    CandidateError::Daemon("candidate_serve_panicked")
                                })?;
                                return match outcome {
                                    Ok(()) => Err(CandidateError::Protocol),
                                    Err(error) => Err(CandidateError::Daemon(error.category())),
                                };
                            }
                            identity.event = "active".to_owned();
                            write_message(writer, &identity)?;
                            // THE CHANNEL MAY DIE HERE, AND THE GENERATION MUST NOT.
                            //
                            // From this point the durable lease names this
                            // process and its inherited endpoints answer
                            // operators. A source that crashes, hangs and is
                            // terminated, or otherwise loses the channel
                            // before it commits has left exactly one live
                            // authority, and that authority keeps serving as
                            // the generation it already is. The reload epoch
                            // is closed as failed under its own category
                            // because nobody drained the source; the operator
                            // sees that and the release links stay wherever
                            // the source left them.
                            let control = match receive_control(reader.as_fd()) {
                                Ok(control) => control,
                                Err(_) => {
                                    return serve_orphaned_after_active(
                                        config,
                                        &identity.reload_id,
                                        &release_on_stop,
                                        serving,
                                    );
                                }
                            };
                            if matches!(control, CandidateControl::Commit) {
                                release_on_stop.store(true, Ordering::Release);
                                identity.event = "committed".to_owned();
                                write_message(writer, &identity)?;
                                let (_, outcome) = serving.join().map_err(|_| {
                                    CandidateError::Daemon("candidate_serve_panicked")
                                })?;
                                return outcome
                                    .map_err(|error| CandidateError::Daemon(error.category()));
                            }
                            if !matches!(control, CandidateControl::Quiesce) {
                                stop.store(true, Ordering::Release);
                                let _ = serving.join();
                                return Err(CandidateError::Protocol);
                            }
                            stop.store(true, Ordering::Release);
                            let (daemon, outcome) = serving
                                .join()
                                .map_err(|_| CandidateError::Daemon("candidate_serve_panicked"))?;
                            outcome.map_err(|error| CandidateError::Daemon(error.category()))?;
                            identity.event = "quiesced".to_owned();
                            write_message(writer, &identity)?;
                            if !matches!(
                                receive_control(reader.as_fd())?,
                                CandidateControl::ConfirmRelinquished
                            ) {
                                return Err(CandidateError::Protocol);
                            }
                            daemon
                        }
                        CandidateControl::Stop
                        | CandidateControl::PrepareTransfer(_)
                        | CandidateControl::ConfirmAuthority
                        | CandidateControl::Quiesce
                        | CandidateControl::Commit => {
                            return Err(CandidateError::Protocol);
                        }
                    };
                    let returned: CandidateAuthority = read_message_from(reader)?;
                    confirm_candidate_relinquished(
                        config,
                        &returned,
                        &input.source_holder_id,
                        input.source_lease_epoch,
                    )?;
                    let _ = daemon
                        .relinquish_endpoint_cleanup()
                        .map_err(|error| CandidateError::Daemon(error.category()))?;
                    drop(daemon);
                    identity.event = "relinquished".to_owned();
                    write_message(writer, &identity)?;
                    if !matches!(receive_control(reader.as_fd())?, CandidateControl::Stop) {
                        return Err(CandidateError::Protocol);
                    }
                    return write_stopped(writer, identity);
                }
                CandidateControl::ConfirmRelinquished
                | CandidateControl::ActivateServing { .. }
                | CandidateControl::Quiesce
                | CandidateControl::Commit
                | CandidateControl::PrepareTransfer(_) => {
                    return Err(CandidateError::Protocol);
                }
            }
            Some(adopted)
        }
        CandidateControl::ConfirmAuthority
        | CandidateControl::ConfirmRelinquished
        | CandidateControl::ActivateServing { .. }
        | CandidateControl::Quiesce
        | CandidateControl::Commit => {
            return Err(CandidateError::Protocol);
        }
    };
    drop(adopted);
    write_stopped(writer, identity)
}

fn write_stopped(
    writer: &mut impl Write,
    mut identity: CandidateIdentity,
) -> Result<(), CandidateError> {
    identity.event = "stopped".to_owned();
    write_message(writer, &identity)
}

/// Keep serving as the generation this process already is after the source
/// vanished between active proof and commit.
///
/// The reload epoch is closed as failed under [`SOURCE_GENERATION_LOST`]
/// when it is still the active epoch for this reload: leaving it open would
/// refuse every later reload as "already in progress" for a handoff nobody
/// can finish. Closing it as succeeded would claim a drain that never
/// happened. The lease is released on this generation's own shutdown, exactly
/// as a committed candidate releases it.
fn serve_orphaned_after_active(
    config: &DaemonConfig,
    reload_id: &str,
    release_on_stop: &AtomicBool,
    serving: std::thread::JoinHandle<(crate::Daemon, Result<(), crate::DaemonError>)>,
) -> Result<(), CandidateError> {
    release_on_stop.store(true, Ordering::Release);
    if let Ok(mut audit) = ReloadAudit::open(config.reload_audit_path())
        && let Ok(Some(active)) = audit.active()
        && active.reload_id == reload_id
        && let Ok(observed_at_ms) = super::unix_millis()
    {
        let _ = audit.advance(AdvanceReload {
            reload_id,
            expected_revision: active.revision,
            phase: ReloadPhase::Failed,
            failure_category: Some(SOURCE_GENERATION_LOST),
            observed_at_ms,
        });
    }
    let (_, outcome) = serving
        .join()
        .map_err(|_| CandidateError::Daemon("candidate_serve_panicked"))?;
    outcome.map_err(|error| CandidateError::Daemon(error.category()))
}

enum CandidateControl {
    Stop,
    PrepareTransfer(CandidateTransferDescriptors),
    ConfirmAuthority,
    ConfirmRelinquished,
    /// Serve as the adopted generation. `admin_socket_path_owned` is the
    /// source's ownership of the admin pathname, which the candidate inherits
    /// along with the descriptor.
    ActivateServing {
        admin_socket_path_owned: bool,
    },
    Quiesce,
    Commit,
}

fn send_control(
    channel: &UnixStream,
    marker: u8,
    descriptors: Option<CandidateTransferDescriptors>,
) -> Result<(), CandidateError> {
    let marker = [marker];
    let vectors = [IoSlice::new(&marker)];
    let sent = if let Some(descriptors) = descriptors {
        let rights = [
            descriptors.admin_listener.as_fd(),
            descriptors.progress_listener.as_fd(),
            descriptors.control_lock.as_fd(),
        ];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&rights)) {
            return Err(CandidateError::Protocol);
        }
        sendmsg(channel, &vectors, &mut control, SendFlags::NOSIGNAL)
    } else {
        sendmsg(
            channel,
            &vectors,
            &mut SendAncillaryBuffer::default(),
            SendFlags::NOSIGNAL,
        )
    }
    .map_err(|error| CandidateError::Io(error.into()))?;
    if sent != marker.len() {
        return Err(CandidateError::Protocol);
    }
    Ok(())
}

fn receive_control(fd: impl AsFd) -> Result<CandidateControl, CandidateError> {
    let mut marker = [0_u8; 1];
    let mut received = Vec::new();
    let (bytes, flags) = {
        let mut vectors = [IoSliceMut::new(&mut marker)];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let message = recvmsg(fd, &mut vectors, &mut control, RecvFlags::CMSG_CLOEXEC)
            .map_err(|error| CandidateError::Io(error.into()))?;
        for message in control.drain() {
            let RecvAncillaryMessage::ScmRights(rights) = message else {
                return Err(CandidateError::Protocol);
            };
            received.extend(rights);
        }
        (message.bytes, message.flags)
    };
    if bytes != 1 || flags.contains(ReturnFlags::CTRUNC) || flags.contains(ReturnFlags::TRUNC) {
        return Err(CandidateError::Protocol);
    }
    match marker[0] {
        CONTROL_STOP if received.is_empty() => Ok(CandidateControl::Stop),
        CONTROL_CONFIRM_AUTHORITY if received.is_empty() => Ok(CandidateControl::ConfirmAuthority),
        CONTROL_CONFIRM_RELINQUISHED if received.is_empty() => {
            Ok(CandidateControl::ConfirmRelinquished)
        }
        CONTROL_ACTIVATE_SERVING_OWNED if received.is_empty() => {
            Ok(CandidateControl::ActivateServing {
                admin_socket_path_owned: true,
            })
        }
        CONTROL_ACTIVATE_SERVING_ACTIVATED if received.is_empty() => {
            Ok(CandidateControl::ActivateServing {
                admin_socket_path_owned: false,
            })
        }
        CONTROL_QUIESCE if received.is_empty() => Ok(CandidateControl::Quiesce),
        CONTROL_COMMIT if received.is_empty() => Ok(CandidateControl::Commit),
        CONTROL_PREPARE_TRANSFER if received.len() == 3 => {
            let control_lock = received.pop().expect("length checked");
            let progress_listener = received.pop().expect("length checked");
            let admin_listener = received.pop().expect("length checked");
            Ok(CandidateControl::PrepareTransfer(
                CandidateTransferDescriptors::new(
                    UnixListener::from(admin_listener),
                    UnixListener::from(progress_listener),
                    File::from(control_lock),
                ),
            ))
        }
        _ => Err(CandidateError::Protocol),
    }
}

/// Accept transferred authority only when every durable population it names
/// is what this process can see for itself.
///
/// Three checks, three populations:
///
/// - the lease: renewed at the exact epoch, holder and kernel identity the
///   source claims, which is what makes this process the fence;
/// - scheduler runs: the transfer's `adopted_runs` must equal the rows now
///   fenced at this epoch in the main store, so the number the source reports
///   is the number the database holds rather than the number it remembers;
/// - source-hosted attempts: the source's registry at transfer time must be
///   covered by the warm-up inventory, and the route is read again here so
///   the set this process adopts is the set still live at the source — never
///   larger than what the source reported, and identical when nothing
///   finished in between.
fn confirm_candidate_authority(
    config: &DaemonConfig,
    authority: &CandidateAuthority,
    identity: &CandidateIdentity,
    source_holder_id: &str,
    source_lease_epoch: u64,
    warm_inventory: &[String],
) -> Result<(GenerationLease, AdoptedSourceAttempts), CandidateError> {
    let expected_epoch = source_lease_epoch
        .checked_add(1)
        .ok_or(CandidateError::Protocol)?;
    if authority.schema != CHANNEL_SCHEMA {
        return Err(CandidateError::ChannelSchemaMismatch);
    }
    if authority.event != "authority"
        || authority.generation_id != super::GENERATION_ID
        || authority.holder_id != identity.target_holder_id
        || authority.lease_epoch != expected_epoch
        || authority.boot_id != identity.boot_id
        || authority.pid != identity.pid
        || authority.starttime != identity.starttime
        || authority.source_attempts > identity.attempt_count
        || (authority.source_attempts == identity.attempt_count
            && authority.source_attempts_sha256 != identity.attempt_inventory_sha256)
    {
        return Err(CandidateError::Protocol);
    }
    validate_digest(
        &authority.source_attempts_sha256,
        false,
        "source_attempts_sha256",
    )?;
    let mut store = Store::open_with_lease_time_source(
        config.database_path(),
        Arc::new(crate::lease_time::BootTimeSource),
    )?;
    let renewed = store.renew_generation_lease(LeaseRenewal {
        generation_id: &authority.generation_id,
        holder_id: &authority.holder_id,
        epoch: authority.lease_epoch,
        now_ms: super::unix_millis().map_err(|_| CandidateError::Integrity("clock"))?,
        ttl_ms: super::LEASE_TTL_MS,
    })?;
    if renewed.holder_id != authority.holder_id
        || renewed.epoch != authority.lease_epoch
        || renewed.boot_id != authority.boot_id
        || renewed.holder_pid != authority.pid
        || renewed.holder_starttime != authority.starttime
    {
        return Err(CandidateError::Protocol);
    }
    drop(store);

    let fenced_runs = read_only_database(&config.database_path(), SCHEMA_VERSION, "main")?
        .query_row(
            "SELECT count(*) FROM runs
             WHERE generation_id = ?1 AND lease_epoch = ?2 AND state = 'running'",
            rusqlite::params![
                authority.generation_id,
                i64::try_from(authority.lease_epoch).map_err(|_| CandidateError::Protocol)?
            ],
            |row| row.get::<_, i64>(0),
        )?;
    if u64::try_from(fenced_runs).map_err(|_| CandidateError::Protocol)? != authority.adopted_runs {
        return Err(CandidateError::Protocol);
    }

    let route = AttemptHostRoute {
        socket_path: attempt_adoption_socket_path(&config.runtime_dir(), source_holder_id)
            .map_err(|_| CandidateError::UnsafePath("attempt_adoption"))?,
        holder_id: source_holder_id.to_owned(),
        lease_epoch: source_lease_epoch,
    };
    let live = AttemptAdoptionClient::new(&route.socket_path, &route.holder_id, route.lease_epoch)
        .map_err(|_| CandidateError::Protocol)?
        .inventory()
        .map_err(|_| CandidateError::Protocol)?
        .attempt_ids;
    let live_count = u32::try_from(live.len()).map_err(|_| CandidateError::Protocol)?;
    if live_count > authority.source_attempts
        || (live_count == authority.source_attempts
            && inventory_digest(&live) != authority.source_attempts_sha256)
        || live
            .iter()
            .any(|attempt_id| !warm_inventory.contains(attempt_id))
    {
        return Err(CandidateError::Protocol);
    }
    Ok((
        renewed,
        AdoptedSourceAttempts {
            route,
            attempt_ids: live,
        },
    ))
}

fn confirm_candidate_relinquished(
    config: &DaemonConfig,
    returned: &CandidateAuthority,
    source_holder_id: &str,
    source_lease_epoch: u64,
) -> Result<(), CandidateError> {
    let expected_epoch = source_lease_epoch
        .checked_add(2)
        .ok_or(CandidateError::Protocol)?;
    if returned.schema != CHANNEL_SCHEMA {
        return Err(CandidateError::ChannelSchemaMismatch);
    }
    if returned.event != "relinquished"
        || returned.generation_id != super::GENERATION_ID
        || returned.holder_id != source_holder_id
        || returned.lease_epoch != expected_epoch
        || returned.pid == 0
        || returned.starttime == 0
        || returned.adopted_runs != 0
        || returned.source_attempts != 0
        || returned.source_attempts_sha256 != inventory_digest(&[])
    {
        return Err(CandidateError::Protocol);
    }
    let connection = read_only_database(&config.database_path(), SCHEMA_VERSION, "main")?;
    let durable = connection
        .query_row(
            "SELECT lease_holder, lease_epoch, boot_id, holder_pid, holder_starttime,
                    lease_expires_ms
             FROM generations WHERE generation_id = ?1",
            [&returned.generation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((holder_id, epoch, boot_id, pid, starttime, expires_ms)) = durable else {
        return Err(CandidateError::Protocol);
    };
    let lease_now_ms = crate::lease_time::BootTimeSource
        .now_boottime_ms()
        .map_err(|_| CandidateError::Integrity("clock"))?;
    if holder_id != returned.holder_id
        || epoch != returned.lease_epoch
        || boot_id != returned.boot_id
        || pid != returned.pid
        || starttime != returned.starttime
        || expires_ms <= lease_now_ms
    {
        return Err(CandidateError::Protocol);
    }
    Ok(())
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

/// The exact attempts the source hosts right now, read through its pinned
/// route.
///
/// The identifiers are kept, not only counted: authority confirmation later
/// checks that nothing the source still hosts is outside this inventory, and
/// the adopted set handed to the transferred daemon is drawn from it.
fn warm_attempt_host(
    config: &DaemonConfig,
    source_holder_id: &str,
    source_lease_epoch: u64,
) -> Result<Vec<String>, CandidateError> {
    let socket_path = attempt_adoption_socket_path(&config.runtime_dir(), source_holder_id)
        .map_err(|_| CandidateError::UnsafePath("attempt_adoption"))?;
    let inventory = AttemptAdoptionClient::new(socket_path, source_holder_id, source_lease_epoch)
        .map_err(|_| CandidateError::Protocol)?
        .inventory()
        .map_err(|_| CandidateError::Protocol)?;
    if inventory.attempt_ids.len() > MAX_ATTEMPT_REGISTRATIONS
        || inventory
            .attempt_ids
            .iter()
            .any(|attempt_id| u32::try_from(attempt_id.len()).is_err())
    {
        return Err(CandidateError::InvalidField("attempt_count"));
    }
    Ok(inventory.attempt_ids)
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

/// Read one identity line from the child, surfacing a reported refusal.
///
/// A line that is not an identity but is a well-formed refusal for this
/// channel becomes the child's own category; a refusal shaped like this
/// channel's but stamped with another schema is the schema mismatch it is;
/// anything else is a protocol violation, exactly as before.
fn read_identity(channel: &UnixStream) -> Result<CandidateIdentity, CandidateError> {
    let line = read_line(&mut BufReader::new(channel))?;
    if let Ok(identity) = serde_json::from_slice::<CandidateIdentity>(&line) {
        return Ok(identity);
    }
    match serde_json::from_slice::<CandidateRefusal>(&line) {
        Ok(refusal) if refusal.event == "refused" && refusal.schema == CHANNEL_SCHEMA => Err(
            CandidateError::CandidateRefused(CandidateError::reported_category(&refusal.category)),
        ),
        Ok(refusal) if refusal.event == "refused" => Err(CandidateError::ChannelSchemaMismatch),
        _ => Err(CandidateError::Protocol),
    }
}

fn read_line(reader: &mut impl Read) -> Result<Vec<u8>, CandidateError> {
    let mut line = Vec::new();
    let read = BufReader::new(reader)
        .take(MAX_CHANNEL_LINE_BYTES)
        .read_until(b'\n', &mut line)?;
    if read == 0 || read as u64 == MAX_CHANNEL_LINE_BYTES || line.last() != Some(&b'\n') {
        return Err(CandidateError::Protocol);
    }
    line.pop();
    Ok(line)
}

fn read_message_from<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, CandidateError> {
    let line = read_line(reader)?;
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

    /// A refusal line stamped with another channel schema is the schema
    /// mismatch it is, and a well-formed refusal in this schema carries the
    /// child's own category — from the closed set, which now includes what a
    /// transferred daemon can legitimately fail with.
    #[test]
    fn a_refusal_in_another_channel_schema_is_a_schema_mismatch_not_a_protocol_error() {
        fn read(line: &str) -> Result<CandidateIdentity, CandidateError> {
            let (parent, mut child) = UnixStream::pair().expect("channel pair");
            parent
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            child.write_all(line.as_bytes()).expect("child line");
            drop(child);
            read_identity(&parent)
        }

        let foreign = read(
            "{\"schema\":\"automonique.reload-candidate/v6\",\"event\":\"refused\",\
             \"reload_id\":\"reload-1\",\"category\":\"candidate_protocol\"}\n",
        );
        assert!(
            matches!(foreign, Err(CandidateError::ChannelSchemaMismatch)),
            "{foreign:?}"
        );
        assert_eq!(
            CandidateError::ChannelSchemaMismatch.category(),
            "candidate_channel_schema_mismatch"
        );

        let own = read(&format!(
            "{{\"schema\":\"{CHANNEL_SCHEMA}\",\"event\":\"refused\",\
             \"reload_id\":\"reload-1\",\"category\":\"candidate_channel_schema_mismatch\"}}\n"
        ));
        assert!(
            matches!(
                own,
                Err(CandidateError::CandidateRefused(
                    "candidate_channel_schema_mismatch"
                ))
            ),
            "{own:?}"
        );

        // Not a refusal at all: a protocol violation, exactly as before.
        let garbage = read("{\"schema\":\"automonique.reload-candidate/v6\",\"event\":\"warm\"}\n");
        assert!(
            matches!(garbage, Err(CandidateError::Protocol)),
            "{garbage:?}"
        );

        // The daemon's own categories are reported as themselves; free text
        // is not.
        assert_eq!(CandidateError::reported_category("io"), "io");
        assert_eq!(
            CandidateError::reported_category("attempt_adoption_socket_in_use"),
            "attempt_adoption_socket_in_use"
        );
        assert_eq!(
            CandidateError::reported_category("candidate_serve_panicked"),
            "candidate_serve_panicked"
        );
        assert_eq!(
            CandidateError::reported_category("anything else"),
            "candidate_refused"
        );
    }

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

        let unknown = br#"{"schema":"automonique.reload-candidate/v8","event":"warm","reload_id":"reload-1","target_generation_id":"generation-2","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","binary_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","attempt_count":2,"attempt_inventory_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","target_holder_id":"daemon-42-reload-0123456789abcdef","boot_id":"01234567-89ab-cdef-0123-456789abcdef","starttime":100,"pid":42,"extra":true}\n"#;
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
        assert_eq!(
            adopted.progress_socket().as_deref(),
            Some(config.progress_socket().as_path())
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

        // The library suite runs concurrently with tests that spawn real
        // binaries. A child between fork and exec can briefly inherit this
        // open-file description; CLOEXEC releases that unrelated duplicate at
        // exec, but an instantaneous reacquire races that hand-off on loaded
        // CI runners. Keep this process-wide assertion bounded: a real leaked
        // descriptor still fails, while a transient pre-exec duplicate does
        // not make an otherwise exact capability-transfer test flaky. The
        // control_lock unit test separately proves immediate last-drop release
        // without concurrent process creation.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match ControlLock::acquire(config.control_lock_path()) {
                Ok(lock) => {
                    drop(lock);
                    break;
                }
                Err(ControlLockError::Held) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("final duplicate releases lock: {error:?}"),
            }
        }
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
