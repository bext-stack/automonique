// SPDX-License-Identifier: Elastic-2.0

//! Mount ownership for the temporary-storage budget: fail-closed
//! prerequisites, the `fusermount3` handshake, kernel readback, checkpointing,
//! a bounded reconcile, and a stale-mount reaper.
//!
//! An unprivileged process cannot call `mount(2)`. What it can do on the
//! runner host is ask the setuid-root `fusermount3` to mount a FUSE
//! filesystem on a directory it owns and hand back the `/dev/fuse` descriptor
//! over a socket. This module does exactly that — by explicit absolute path
//! and explicit argument vector, no `PATH` search, no shell — and then
//! refuses to report success until `/proc/self/mountinfo` shows a FUSE mount
//! of this crate's subtype owned by this uid at the mountpoint, and
//! `statvfs(2)` on it returns the budget that was asked for.

use crate::backend::TemporaryStorageWatch;
use crate::tempfs_checkpoint::{Checkpoint, FinalRecord, Phase, now_millis};
use crate::tempfs_fs::{ExceedanceChannel, QuotaFs, SharedState, snapshot};
use crate::tempfs_ledger::{LedgerSnapshot, TemporaryStorageBudget};
use crate::tempfs_readback::{
    MountEvidence, MountStatus, ReadbackError, StatfsReadback, abort_connection, classify, inspect,
    mount_evidence, mount_table, statfs_bounded,
};
use fuser::{BackgroundSession, Config, Session, SessionACL};
use nix::unistd::{AccessFlags, access};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The kernel's FUSE control device.
pub const DEFAULT_DEV_FUSE: &str = "/dev/fuse";
/// libfuse's setuid mount helper, at the path the runner host installs it.
pub const DEFAULT_FUSERMOUNT3: &str = "/usr/bin/fusermount3";
/// `fsname=`: the source column in the mount table.
pub const FS_NAME: &str = "automonique-tempfs";
/// `subtype=`: the mount table shows `fuse.<subtype>`, which is how a stale
/// mount is told apart from anything else at the same path.
pub const FS_SUBTYPE: &str = "automonique-tempfs";
/// The leaf a run's mountpoint is created at under its private directory.
pub const MOUNT_LEAF: &str = "tmp";
/// The leaf a run's ledger checkpoint is written at, a sibling of the mount.
pub const CHECKPOINT_LEAF: &str = "tempfs-ledger";
/// The environment variable `fusermount3` reads the descriptor-passing
/// socket's number from.
const COMM_FD_ENV: &str = "_FUSE_COMMFD";
/// Mount options beyond the name and subtype. `default_permissions` makes the
/// kernel check mode bits; the three flags keep the scratch tree from ever
/// executing anything or carrying a device node.
const MOUNT_OPTIONS: &str = "default_permissions,nosuid,nodev,noexec";
/// The setuid bit, as `st_mode` carries it.
const S_ISUID: u32 = 0o4000;
/// Bound on the helper's diagnostic kept in an error.
const MAX_STDERR_BYTES: usize = 4096;
/// Default deadline for a `statvfs` against the supervisor's own mount.
pub const DEFAULT_READBACK_DEADLINE: Duration = Duration::from_secs(5);
/// How long a bounded session join waits before detaching the worker thread.
const SESSION_JOIN_DEADLINE: Duration = Duration::from_secs(5);

/// Why the host cannot mount at all, decided before anything is tried.
#[derive(Debug)]
pub enum PrerequisiteError {
    DevFuseMissing(PathBuf),
    DevFuseNotCharacterDevice(PathBuf),
    /// Present, but this uid cannot open it read-write.
    DevFuseNotOpenable(PathBuf, io::Error),
    FusermountMissing(PathBuf),
    FusermountNotRegularFile(PathBuf),
    /// Without setuid root the helper cannot mount for an unprivileged uid.
    FusermountNotSetuidRoot(PathBuf),
    FusermountNotExecutable(PathBuf),
    Io(PathBuf, io::Error),
}

impl fmt::Display for PrerequisiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DevFuseMissing(path) => write!(formatter, "{} is missing", path.display()),
            Self::DevFuseNotCharacterDevice(path) => {
                write!(formatter, "{} is not a character device", path.display())
            }
            Self::DevFuseNotOpenable(path, error) => {
                write!(formatter, "{} cannot be opened: {error}", path.display())
            }
            Self::FusermountMissing(path) => write!(formatter, "{} is missing", path.display()),
            Self::FusermountNotRegularFile(path) => {
                write!(formatter, "{} is not a regular file", path.display())
            }
            Self::FusermountNotSetuidRoot(path) => {
                write!(formatter, "{} is not setuid root", path.display())
            }
            Self::FusermountNotExecutable(path) => {
                write!(
                    formatter,
                    "{} is not executable by this uid",
                    path.display()
                )
            }
            Self::Io(path, error) => write!(formatter, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for PrerequisiteError {}

/// The two host facts a FUSE mount depends on.
#[derive(Clone, Debug)]
pub struct FusePrerequisites {
    dev_fuse: PathBuf,
    fusermount: PathBuf,
}

impl FusePrerequisites {
    /// This host's conventional locations.
    #[must_use]
    pub fn host_default() -> Self {
        Self::at(DEFAULT_DEV_FUSE, DEFAULT_FUSERMOUNT3)
    }

    /// Explicit locations, for tests and for hosts that differ.
    pub fn at(dev_fuse: impl Into<PathBuf>, fusermount: impl Into<PathBuf>) -> Self {
        Self {
            dev_fuse: dev_fuse.into(),
            fusermount: fusermount.into(),
        }
    }

    /// Refuse unless both prerequisites are present and usable by this uid.
    ///
    /// The device is actually opened, because "exists" and "this uid can open
    /// it" are different facts and only the second one mounts anything. This
    /// is the admission gate: a run declaring a temporary-storage budget on a
    /// host that fails this check is refused, not admitted acknowledging it.
    pub fn verify(&self) -> Result<VerifiedFuse, PrerequisiteError> {
        let device = match fs::symlink_metadata(&self.dev_fuse) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PrerequisiteError::DevFuseMissing(self.dev_fuse.clone()));
            }
            Err(error) => return Err(PrerequisiteError::Io(self.dev_fuse.clone(), error)),
        };
        if !device.file_type().is_char_device() {
            return Err(PrerequisiteError::DevFuseNotCharacterDevice(
                self.dev_fuse.clone(),
            ));
        }
        File::options()
            .read(true)
            .write(true)
            .open(&self.dev_fuse)
            .map_err(|error| PrerequisiteError::DevFuseNotOpenable(self.dev_fuse.clone(), error))?;

        let helper = match fs::metadata(&self.fusermount) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(PrerequisiteError::FusermountMissing(
                    self.fusermount.clone(),
                ));
            }
            Err(error) => return Err(PrerequisiteError::Io(self.fusermount.clone(), error)),
        };
        if !helper.is_file() {
            return Err(PrerequisiteError::FusermountNotRegularFile(
                self.fusermount.clone(),
            ));
        }
        if helper.uid() != 0 || helper.permissions().mode() & S_ISUID == 0 {
            return Err(PrerequisiteError::FusermountNotSetuidRoot(
                self.fusermount.clone(),
            ));
        }
        if access(&self.fusermount, AccessFlags::X_OK).is_err() {
            return Err(PrerequisiteError::FusermountNotExecutable(
                self.fusermount.clone(),
            ));
        }
        Ok(VerifiedFuse {
            dev_fuse: self.dev_fuse.clone(),
            fusermount: self.fusermount.clone(),
        })
    }
}

/// Proof that [`FusePrerequisites::verify`] passed; the only way to mount.
#[derive(Clone, Debug)]
pub struct VerifiedFuse {
    dev_fuse: PathBuf,
    fusermount: PathBuf,
}

impl VerifiedFuse {
    #[must_use]
    pub fn dev_fuse(&self) -> &Path {
        &self.dev_fuse
    }

    #[must_use]
    pub fn fusermount(&self) -> &Path {
        &self.fusermount
    }
}

/// Why a mount did not happen, or could not be confirmed.
#[derive(Debug)]
pub enum MountError {
    /// The mountpoint is not an empty directory this uid owns, or is already
    /// a mountpoint.
    MountpointRejected(PathBuf, &'static str),
    /// `fusermount3` could not be started.
    Spawn(io::Error),
    /// `fusermount3` exited without handing over a descriptor. Its diagnostic
    /// is the reason.
    Refused { status: Option<i32>, stderr: String },
    /// Receiving the descriptor failed.
    Handshake(io::Error),
    /// The FUSE protocol handshake or the server thread failed.
    Session(io::Error),
    /// The mount table could not be read.
    MountTable(io::Error),
    /// `fusermount3` reported success but the mount table shows no FUSE mount
    /// of this subtype at the mountpoint.
    EvidenceMissing(PathBuf),
    /// The mount table shows a mount that is not this crate's, or is owned by
    /// another uid.
    EvidenceMismatch(Box<MountEvidence>),
    /// `statvfs` on the new mount did not answer with the requested budget.
    StatfsMismatch {
        budget: TemporaryStorageBudget,
        observed: Box<Result<StatfsReadback, ReadbackError>>,
    },
}

impl fmt::Display for MountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MountpointRejected(path, reason) => {
                write!(
                    formatter,
                    "mountpoint {} rejected: {reason}",
                    path.display()
                )
            }
            Self::Spawn(error) => write!(formatter, "fusermount3 could not be started: {error}"),
            Self::Refused { status, stderr } => write!(
                formatter,
                "fusermount3 exited with {status:?} without a descriptor: {}",
                stderr.trim()
            ),
            Self::Handshake(error) => write!(formatter, "descriptor handshake failed: {error}"),
            Self::Session(error) => write!(formatter, "FUSE session failed: {error}"),
            Self::MountTable(error) => write!(formatter, "mount table unreadable: {error}"),
            Self::EvidenceMissing(path) => write!(
                formatter,
                "no {FS_SUBTYPE} mount is visible at {} after fusermount3 returned",
                path.display()
            ),
            Self::EvidenceMismatch(evidence) => {
                write!(formatter, "unexpected mount at the mountpoint: {evidence}")
            }
            Self::StatfsMismatch { budget, observed } => write!(
                formatter,
                "statvfs did not read back the budget {budget}: {observed:?}"
            ),
        }
    }
}

impl std::error::Error for MountError {}

/// Why an unmount did not happen, or could not be confirmed.
#[derive(Debug)]
pub enum UnmountError {
    Spawn(io::Error),
    /// `fusermount3 -u` refused; `EBUSY` from a still-open descriptor is the
    /// usual reason.
    Refused {
        status: Option<i32>,
        stderr: String,
    },
    MountTable(io::Error),
    /// The mount table still shows the mount after the helper reported
    /// success.
    StillMounted(Box<MountEvidence>),
}

impl fmt::Display for UnmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "fusermount3 could not be started: {error}"),
            Self::Refused { status, stderr } => write!(
                formatter,
                "fusermount3 -u exited with {status:?}: {}",
                stderr.trim()
            ),
            Self::MountTable(error) => write!(formatter, "mount table unreadable: {error}"),
            Self::StillMounted(evidence) => {
                write!(formatter, "still mounted after unmount: {evidence}")
            }
        }
    }
}

impl std::error::Error for UnmountError {}

/// The typed result of one mounted lifetime, assembled at reconcile.
///
/// Everything here is either the filesystem's own ledger or a kernel
/// readback; nothing is copied from the request that created the mount.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub budget: TemporaryStorageBudget,
    pub ledger: LedgerSnapshot,
    /// The mount table entry observed right after mounting.
    pub evidence: MountEvidence,
    /// `statvfs` right after mounting: the budget, empty.
    pub statfs_at_mount: StatfsReadback,
    /// `statvfs` right before unmounting: the final usage the kernel saw.
    /// Absent when the server had already gone, or the readback was aborted.
    pub statfs_before_unmount: Option<StatfsReadback>,
    /// The connection had to be aborted because the readback did not answer.
    pub aborted: bool,
    /// The mount table showed no entry after unmounting.
    pub unmount_confirmed: bool,
}

impl Outcome {
    /// Whether any ceiling refused anything during the mount's life.
    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.ledger.exceeded()
    }

    fn final_record(&self) -> FinalRecord {
        FinalRecord {
            statfs_before_unmount: self.statfs_before_unmount,
            unmount_confirmed: self.unmount_confirmed,
            aborted: self.aborted,
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.ledger)?;
        writeln!(formatter, "mount.evidence={}", self.evidence)?;
        writeln!(formatter, "statfs.at_mount={}", self.statfs_at_mount)?;
        match &self.statfs_before_unmount {
            Some(statfs) => writeln!(formatter, "statfs.before_unmount={statfs}")?,
            None => writeln!(formatter, "statfs.before_unmount=absent")?,
        }
        writeln!(formatter, "readback.aborted={}", self.aborted)?;
        writeln!(formatter, "unmount.confirmed={}", self.unmount_confirmed)
    }
}

/// A mounted, serving temporary-storage filesystem. Dropping it detaches the
/// mount.
pub struct MountedTempfs {
    mountpoint: PathBuf,
    fusermount: PathBuf,
    budget: TemporaryStorageBudget,
    state: SharedState,
    channel: Arc<ExceedanceChannel>,
    session: Option<BackgroundSession>,
    evidence: MountEvidence,
    statfs_at_mount: StatfsReadback,
    checkpoint_path: Option<PathBuf>,
    checkpoint_sequence: u64,
    detached: bool,
}

impl fmt::Debug for MountedTempfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MountedTempfs")
            .field("mountpoint", &self.mountpoint)
            .field("budget", &self.budget)
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl MountedTempfs {
    /// Mount an empty quota filesystem on `mountpoint` and confirm it from the
    /// kernel.
    ///
    /// On any failure after the helper ran, the mount is detached again before
    /// the error is returned: a mount this function cannot vouch for is not
    /// left behind.
    pub fn mount(
        verified: &VerifiedFuse,
        mountpoint: &Path,
        budget: TemporaryStorageBudget,
    ) -> Result<Self, MountError> {
        let mountpoint = validate_mountpoint(mountpoint)?;
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        let descriptor = fusermount_handshake(&verified.fusermount, &mountpoint)?;
        let channel = Arc::new(ExceedanceChannel::default());
        let filesystem = QuotaFs::new(budget, uid, gid, Arc::clone(&channel));
        let state = filesystem.state();
        // The descriptor is the mount: from here on, an early return must
        // detach it, which `Drop` does once `mounted` exists.
        let session =
            match Session::from_fd(filesystem, descriptor, SessionACL::Owner, Config::default())
                .and_then(Session::spawn)
            {
                Ok(session) => session,
                Err(error) => {
                    let _ = run_unmount(&verified.fusermount, &mountpoint, true);
                    return Err(MountError::Session(error));
                }
            };
        let mut mounted = Self {
            mountpoint,
            fusermount: verified.fusermount.clone(),
            budget,
            state,
            channel,
            session: Some(session),
            evidence: placeholder_evidence(),
            statfs_at_mount: zero_statfs(),
            checkpoint_path: None,
            checkpoint_sequence: 0,
            detached: false,
        };

        // Readback, or refuse. `mounted` is dropped on the error path, which
        // detaches the mount.
        let evidence = mount_evidence(&mounted.mountpoint)
            .map_err(MountError::MountTable)?
            .ok_or_else(|| MountError::EvidenceMissing(mounted.mountpoint.clone()))?;
        if !evidence.is_fuse_subtype(FS_SUBTYPE)
            || evidence.source != FS_NAME
            || evidence.user_id() != Some(uid)
        {
            return Err(MountError::EvidenceMismatch(Box::new(evidence)));
        }
        let observed = statfs_bounded(&mounted.mountpoint, DEFAULT_READBACK_DEADLINE);
        match observed {
            Ok(statfs)
                if statfs.ceiling_bytes() == budget.bytes()
                    && statfs.files == budget.objects()
                    && statfs.used_bytes() == 0
                    && statfs.used_objects() == 0 =>
            {
                mounted.statfs_at_mount = statfs;
            }
            other => {
                return Err(MountError::StatfsMismatch {
                    budget,
                    observed: Box::new(other),
                });
            }
        }
        mounted.evidence = evidence;
        Ok(mounted)
    }

    /// Bind a checkpoint file to this mount, and write the first `Live`
    /// checkpoint.
    ///
    /// The path is a sibling of the mountpoint, outside the mount and outside
    /// every grant the workload holds. A supervisor that dies keeps the last
    /// checkpoint; the reaper reads it back.
    pub fn with_checkpoint(mut self, path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        self.checkpoint_path = Some(path);
        self.checkpoint(Phase::Live)?;
        Ok(self)
    }

    /// Write one checkpoint of the current ledger, if a checkpoint path is
    /// bound. A `Final` checkpoint additionally records the reconcile's own
    /// readbacks through [`Self::checkpoint_final`].
    pub fn checkpoint(&mut self, phase: Phase) -> io::Result<()> {
        let Some(path) = self.checkpoint_path.clone() else {
            return Ok(());
        };
        self.checkpoint_sequence += 1;
        let checkpoint = Checkpoint {
            sequence: self.checkpoint_sequence,
            at_millis: now_millis(),
            phase,
            snapshot: self.snapshot(),
            mount_evidence: self.evidence.to_string(),
            statfs_at_mount: self.statfs_at_mount,
            final_record: None,
        };
        checkpoint.write(&path)
    }

    fn checkpoint_final(&mut self, outcome: &Outcome) -> io::Result<()> {
        let Some(path) = self.checkpoint_path.clone() else {
            return Ok(());
        };
        self.checkpoint_sequence += 1;
        let checkpoint = Checkpoint {
            sequence: self.checkpoint_sequence,
            at_millis: now_millis(),
            phase: Phase::Final,
            snapshot: outcome.ledger.clone(),
            mount_evidence: outcome.evidence.to_string(),
            statfs_at_mount: outcome.statfs_at_mount,
            final_record: Some(outcome.final_record()),
        };
        checkpoint.write(&path)
    }

    /// Exact mountpoint, canonical.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// The budget in force.
    #[must_use]
    pub const fn budget(&self) -> TemporaryStorageBudget {
        self.budget
    }

    /// The mount table entry observed at mount time.
    #[must_use]
    pub const fn evidence(&self) -> &MountEvidence {
        &self.evidence
    }

    /// `statvfs` observed at mount time.
    #[must_use]
    pub const fn statfs_at_mount(&self) -> StatfsReadback {
        self.statfs_at_mount
    }

    /// The channel a supervisor polls to learn of the first refusal without a
    /// `statfs` round trip.
    #[must_use]
    pub fn exceedance_channel(&self) -> Arc<ExceedanceChannel> {
        Arc::clone(&self.channel)
    }

    /// What a supervisor polls to contain a run on its first refusal and reads
    /// back from once the run is dead: the channel and the mountpoint, without
    /// the mount itself, which stays here to be reconciled after the run.
    #[must_use]
    pub fn watch(&self) -> TemporaryStorageWatch {
        TemporaryStorageWatch::new(Arc::clone(&self.channel), &self.mountpoint)
    }

    /// The ledger as it stands right now.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        snapshot(&self.state)
    }

    /// Whether the server thread is still serving. It ends when the kernel
    /// closes the connection — after an unmount, whoever performed it, or an
    /// abort.
    #[must_use]
    pub fn serving(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| !session.guard.is_finished())
    }

    /// Reconcile the mount under a deadline, then unmount, then assemble the
    /// [`Outcome`] and write the final checkpoint.
    ///
    /// The `statvfs` taken before unmount is bounded by `deadline`. If the
    /// server does not answer within it, the connection is aborted through
    /// `fusectl` so a stuck server cannot hang this call, `statfs_before` is
    /// absent, and the outcome records `aborted`. The ledger snapshot is the
    /// supervisor's in-memory copy either way, so the consumed-budget record
    /// survives an unresponsive server.
    pub fn reconcile(mut self, deadline: Duration) -> Result<Outcome, UnmountError> {
        let already_gone = mount_evidence(&self.mountpoint)
            .map_err(UnmountError::MountTable)?
            .is_none();
        let (statfs_before_unmount, aborted) = if already_gone {
            (None, false)
        } else {
            match statfs_bounded(&self.mountpoint, deadline) {
                Ok(statfs) => (Some(statfs), false),
                Err(ReadbackError::Errno(_) | ReadbackError::ThreadUnavailable) => (None, false),
                Err(ReadbackError::TimedOut) => {
                    // A stuck server: abort the connection so unmount and the
                    // session join both complete rather than block.
                    let _ = abort_connection(&self.evidence);
                    (None, true)
                }
            }
        };
        if !already_gone {
            run_unmount(&self.fusermount, &self.mountpoint, false).or_else(|error| {
                // A non-lazy unmount can refuse EBUSY if a descriptor is still
                // open; on the abort path the connection is already dead, so a
                // lazy detach is correct and cannot leave a writable mount.
                if aborted {
                    run_unmount(&self.fusermount, &self.mountpoint, true)
                } else {
                    Err(error)
                }
            })?;
        }
        self.detached = true;
        finish_session(self.session.take(), SESSION_JOIN_DEADLINE);
        let unmount_confirmed =
            match mount_evidence(&self.mountpoint).map_err(UnmountError::MountTable)? {
                None => true,
                Some(evidence) => return Err(UnmountError::StillMounted(Box::new(evidence))),
            };
        let outcome = Outcome {
            budget: self.budget,
            ledger: self.snapshot(),
            evidence: self.evidence.clone(),
            statfs_at_mount: self.statfs_at_mount,
            statfs_before_unmount,
            aborted,
            unmount_confirmed,
        };
        // Best effort: the outcome is the supervisor's to report regardless,
        // and a checkpoint that cannot be written is not a reason to fail a
        // reconcile that already produced the record.
        let _ = self.checkpoint_final(&outcome);
        Ok(outcome)
    }
}

impl Drop for MountedTempfs {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        // Best effort, and lazy: on this path the owner is going away, so the
        // mount must not outlive it even if a descriptor is still open. The
        // server thread ends once the kernel closes the connection.
        let _ = run_unmount(&self.fusermount, &self.mountpoint, true);
        finish_session(self.session.take(), SESSION_JOIN_DEADLINE);
    }
}

/// The stale-mount reaper's finding for one owned, disconnected mount.
#[derive(Clone, Debug)]
pub struct ReapedMount {
    /// The run whose mount this was, from the mountpoint's parent directory.
    pub run_id: String,
    pub mountpoint: PathBuf,
    /// The last checkpoint the dead supervisor wrote, if it wrote one.
    pub checkpoint: Option<Checkpoint>,
    /// Whether the detach left the mount table clear.
    pub detached: bool,
}

/// Detach every stale (`Disconnected`) mount this uid owns under `runs_root`,
/// and attach each one's last checkpoint.
///
/// Called once, when the daemon opens its execution lane at start; a run's own
/// mount is reconciled by its owner and never reaches this. A `Live` entry is
/// left alone: it belongs to a still-running supervisor (a previous generation
/// during handoff), and detaching it would pull a writable scratch space out
/// from under an accounted run. Only this uid's `fuse.<FS_SUBTYPE>` mounts
/// whose mountpoint is `<runs_root>/<run_id>/<MOUNT_LEAF>` are considered, so
/// nothing outside the runner's own tree is touched.
pub fn reap_stale_mounts(
    verified: &VerifiedFuse,
    runs_root: &Path,
    deadline: Duration,
) -> io::Result<Vec<ReapedMount>> {
    let uid = nix::unistd::getuid().as_raw();
    let runs_root = fs::canonicalize(runs_root).unwrap_or_else(|_| runs_root.to_path_buf());
    let mut reaped = Vec::new();
    for evidence in mount_table()? {
        if !evidence.is_fuse_subtype(FS_SUBTYPE) || evidence.user_id() != Some(uid) {
            continue;
        }
        let Some(run_id) = run_id_of(&evidence.mountpoint, &runs_root) else {
            continue;
        };
        let status = classify(evidence.clone(), FS_SUBTYPE, deadline);
        let disconnected = matches!(status, MountStatus::Disconnected { .. });
        if !disconnected {
            // Live and owned by a running supervisor, or foreign; leave it.
            continue;
        }
        let checkpoint = evidence
            .mountpoint
            .parent()
            .map(|parent| parent.join(CHECKPOINT_LEAF))
            .and_then(|path| Checkpoint::read(&path).ok());
        let detached =
            matches!(
                run_unmount(&verified.fusermount, &evidence.mountpoint, true)
                    .and_then(|()| inspect(&evidence.mountpoint, FS_SUBTYPE, deadline)
                        .map_err(UnmountError::MountTable)),
                Ok(MountStatus::NotMounted)
            );
        reaped.push(ReapedMount {
            run_id,
            mountpoint: evidence.mountpoint.clone(),
            checkpoint,
            detached,
        });
    }
    Ok(reaped)
}

/// The run identifier a mountpoint `<runs_root>/<run_id>/<MOUNT_LEAF>` names.
fn run_id_of(mountpoint: &Path, runs_root: &Path) -> Option<String> {
    if mountpoint.file_name()? != std::ffi::OsStr::new(MOUNT_LEAF) {
        return None;
    }
    let run_dir = mountpoint.parent()?;
    if run_dir.parent()? != runs_root {
        return None;
    }
    run_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
}

/// Detach whatever this crate left at `mountpoint`, live or stale.
///
/// Lazy on purpose: a disconnected mount cannot be busy in any way that
/// matters, and a live one whose owner is gone is exactly what this exists to
/// remove. Returns the status observed after the detach.
pub fn detach_stale(
    verified: &VerifiedFuse,
    mountpoint: &Path,
    deadline: Duration,
) -> Result<MountStatus, UnmountError> {
    match inspect(mountpoint, FS_SUBTYPE, deadline).map_err(UnmountError::MountTable)? {
        MountStatus::NotMounted => return Ok(MountStatus::NotMounted),
        MountStatus::Foreign { evidence } => {
            // Not ours to touch.
            return Ok(MountStatus::Foreign { evidence });
        }
        MountStatus::Live { .. } | MountStatus::Disconnected { .. } => {}
    }
    run_unmount(&verified.fusermount, mountpoint, true)?;
    inspect(mountpoint, FS_SUBTYPE, deadline).map_err(UnmountError::MountTable)
}

/// Join the session if it finishes within `deadline`, else detach the worker.
///
/// There is no way to interrupt a thread blocked reading `/dev/fuse`, so a
/// worker that has not noticed the connection close is dropped rather than
/// joined: a leaked thread on an already-torn-down mount is the smaller harm,
/// and it ends on its own the moment the kernel returns from its read.
fn finish_session(session: Option<BackgroundSession>, deadline: Duration) {
    let Some(session) = session else {
        return;
    };
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if session.guard.is_finished() {
            let _ = session.join();
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Detach: dropping a `BackgroundSession` whose `mount` is `None` — which
    // is the case here, since the mount was performed by `fusermount3` and not
    // by fuser — drops its `JoinHandle` without joining.
    drop(session);
}

fn placeholder_evidence() -> MountEvidence {
    MountEvidence {
        mountpoint: PathBuf::new(),
        device_minor: 0,
        fstype: String::new(),
        source: String::new(),
        mount_options: String::new(),
        super_options: String::new(),
    }
}

fn zero_statfs() -> StatfsReadback {
    StatfsReadback {
        block_size: 0,
        fragment_size: 0,
        blocks: 0,
        blocks_free: 0,
        blocks_available: 0,
        files: 0,
        files_free: 0,
        name_max: 0,
    }
}

/// Canonical, existing, empty, owned by this uid, and not already a mount.
fn validate_mountpoint(mountpoint: &Path) -> Result<PathBuf, MountError> {
    let rejected = |reason| MountError::MountpointRejected(mountpoint.to_path_buf(), reason);
    if !mountpoint.is_absolute() {
        return Err(rejected("not absolute"));
    }
    let canonical = fs::canonicalize(mountpoint).map_err(|_| rejected("does not resolve"))?;
    let metadata = fs::metadata(&canonical).map_err(|_| rejected("unreadable"))?;
    if !metadata.is_dir() {
        return Err(rejected("not a directory"));
    }
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err(rejected("not owned by this uid"));
    }
    let mut entries = fs::read_dir(&canonical).map_err(|_| rejected("unlistable"))?;
    if entries.next().is_some() {
        return Err(rejected("not empty"));
    }
    if mount_evidence(&canonical)
        .map_err(MountError::MountTable)?
        .is_some()
    {
        return Err(rejected("already a mountpoint"));
    }
    Ok(canonical)
}

/// Run `fusermount3 -o <options> -- <mountpoint>` with a socket on its stdin
/// and receive the `/dev/fuse` descriptor it sends back over that socket.
///
/// The socket rides on fd 0 so no descriptor has to be un-`CLOEXEC`ed in this
/// process: `fusermount3` reads the socket's number from `_FUSE_COMMFD` and
/// never reads its stdin for anything else.
fn fusermount_handshake(fusermount: &Path, mountpoint: &Path) -> Result<OwnedFd, MountError> {
    let options = format!("fsname={FS_NAME},subtype={FS_SUBTYPE},{MOUNT_OPTIONS}");
    let handshake = spawn_fusermount(fusermount, mountpoint, &options)?;
    // Without `auto_unmount` the helper exits as soon as the descriptor is
    // sent; reap it so the mount owns no stray child.
    drop(handshake.socket);
    let _ = handshake.child.wait_with_output();
    Ok(handshake.descriptor)
}

/// A mount the helper has performed: the kernel connection it handed over, the
/// socket it was handed over on, and the helper process itself.
struct Handshake {
    descriptor: OwnedFd,
    socket: UnixStream,
    child: Child,
}

fn spawn_fusermount(
    fusermount: &Path,
    mountpoint: &Path,
    options: &str,
) -> Result<Handshake, MountError> {
    let (ours, theirs) = UnixStream::pair().map_err(MountError::Spawn)?;
    let theirs: OwnedFd = theirs.into();
    let mut child = Command::new(fusermount)
        .arg("-o")
        .arg(options)
        .arg("--")
        .arg(mountpoint)
        .env_clear()
        .env(COMM_FD_ENV, "0")
        .stdin(Stdio::from(theirs))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(MountError::Spawn)?;
    match receive_descriptor(&ours) {
        Ok(Some(descriptor)) => Ok(Handshake {
            descriptor,
            socket: ours,
            child,
        }),
        Ok(None) => {
            drop(ours);
            let output = child.wait_with_output().map_err(MountError::Spawn)?;
            Err(MountError::Refused {
                status: output.status.code(),
                stderr: bounded_stderr(&output.stderr),
            })
        }
        Err(error) => {
            drop(ours);
            let _ = child.kill();
            let output = child.wait_with_output().map_err(MountError::Spawn)?;
            if output.status.success() {
                Err(MountError::Handshake(error))
            } else {
                Err(MountError::Refused {
                    status: output.status.code(),
                    stderr: bounded_stderr(&output.stderr),
                })
            }
        }
    }
}

fn receive_descriptor(socket: &UnixStream) -> io::Result<Option<OwnedFd>> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut byte = [0_u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let received = loop {
        match recvmsg(socket, &mut iov, &mut control, RecvFlags::empty()) {
            Ok(received) => break received,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    };
    if received.bytes == 0 {
        return Ok(None);
    }
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmRights(descriptors) = message
            && let Some(descriptor) = descriptors.into_iter().next()
        {
            return Ok(Some(descriptor));
        }
    }
    Ok(None)
}

fn run_unmount(fusermount: &Path, mountpoint: &Path, lazy: bool) -> Result<(), UnmountError> {
    let mut command = Command::new(fusermount);
    command.arg("-u").arg("-q");
    if lazy {
        command.arg("-z");
    }
    let output = command
        .arg("--")
        .arg(mountpoint)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(UnmountError::Spawn)?;
    if output.status.success() {
        return Ok(());
    }
    Err(UnmountError::Refused {
        status: status_code(output.status),
        stderr: bounded_stderr(&output.stderr),
    })
}

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

fn bounded_stderr(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_STDERR_BYTES);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_dev_fuse_is_refused_before_anything_is_mounted() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent-dev-fuse");
        let error = FusePrerequisites::at(&missing, DEFAULT_FUSERMOUNT3)
            .verify()
            .unwrap_err();
        assert!(
            matches!(error, PrerequisiteError::DevFuseMissing(path) if path == missing),
            "a missing /dev/fuse must fail closed"
        );
    }

    #[test]
    fn a_regular_file_dev_fuse_is_refused_as_not_a_character_device() {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = directory.path().join("not-a-device");
        std::fs::write(&ordinary, b"x").unwrap();
        let error = FusePrerequisites::at(&ordinary, DEFAULT_FUSERMOUNT3)
            .verify()
            .unwrap_err();
        assert!(matches!(
            error,
            PrerequisiteError::DevFuseNotCharacterDevice(_)
        ));
    }

    #[test]
    fn a_non_setuid_fusermount_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("fusermount3");
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        // /dev/fuse is real on this host; when it is not, the device check
        // fails first and this still exercises fail-closed admission.
        let error = FusePrerequisites::at(DEFAULT_DEV_FUSE, &helper)
            .verify()
            .unwrap_err();
        assert!(
            matches!(
                error,
                PrerequisiteError::FusermountNotSetuidRoot(_)
                    | PrerequisiteError::DevFuseMissing(_)
                    | PrerequisiteError::DevFuseNotCharacterDevice(_)
                    | PrerequisiteError::DevFuseNotOpenable(..)
            ),
            "got {error}"
        );
    }

    #[test]
    fn a_missing_fusermount_is_refused_when_the_device_is_usable() {
        // Only meaningful where /dev/fuse opens; elsewhere the device check
        // fails first, which is also a closed refusal.
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("no-fusermount");
        let error = FusePrerequisites::at(DEFAULT_DEV_FUSE, &missing)
            .verify()
            .unwrap_err();
        assert!(
            matches!(
                error,
                PrerequisiteError::FusermountMissing(_)
                    | PrerequisiteError::DevFuseMissing(_)
                    | PrerequisiteError::DevFuseNotCharacterDevice(_)
                    | PrerequisiteError::DevFuseNotOpenable(..)
            ),
            "got {error}"
        );
    }

    #[test]
    fn a_run_id_is_recovered_only_from_a_well_formed_mountpoint() {
        let runs = Path::new("/state/runs");
        assert_eq!(
            run_id_of(Path::new("/state/runs/run-1/tmp"), runs),
            Some("run-1".to_owned())
        );
        // Wrong leaf, wrong depth, and the runs root itself are all refused.
        assert_eq!(run_id_of(Path::new("/state/runs/run-1/other"), runs), None);
        assert_eq!(run_id_of(Path::new("/state/runs/run-1/a/tmp"), runs), None);
        assert_eq!(run_id_of(Path::new("/elsewhere/run-1/tmp"), runs), None);
    }
}
