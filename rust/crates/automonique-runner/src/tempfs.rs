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
//!
//! That is one of two mount sites. A plan whose workload identity is separated
//! cannot use it at all — FUSE refuses a process in a child user namespace —
//! so its filesystem is mounted by the launch, inside the namespaces the
//! launch creates, and handed back here over a socket
//! ([`crate::tempfs_namespace`]). The site follows from the plan
//! ([`RunTempfs::provide`]), not from a caller's choice, so the wrong one
//! cannot be attached to a run. Everything after the `mount(2)` is shared: the
//! same [`crate::tempfs_fs::QuotaFs`] served in this process, the same ledger,
//! the same checkpoint, the same exceedance channel, the same reconcile. What
//! differs is what a reconcile can read — a mount in the workload's own mount
//! namespace is in no table this process can see, so its readback is the
//! filesystem's own `statfs` rather than a `statvfs` round trip, and its
//! unmount is the namespace's death rather than a `fusermount3 -u`.

use crate::backend::TemporaryStorageWatch;
use crate::launch::LaunchPlan;
use crate::tempfs_checkpoint::{Checkpoint, FinalRecord, Phase, now_millis};
use crate::tempfs_fs::{ExceedanceChannel, QuotaFs, SharedState, snapshot, statfs_view};
use crate::tempfs_ledger::{LedgerSnapshot, TemporaryStorageBudget};
use crate::tempfs_namespace::{TemporaryStorageMount, receive_mount, release};
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
use std::sync::{Arc, Mutex};
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
    /// The launch was to mount the filesystem inside the workload's own
    /// namespaces and the handover did not complete. The string is what the
    /// rendezvous refused with; nothing was left mounted, because the mount
    /// only ever existed in a namespace that dies with the refused launch.
    Rendezvous(String),
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
            Self::Rendezvous(reason) => {
                write!(formatter, "the launch did not hand back a mount: {reason}")
            }
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
    /// The launch was to mount the filesystem and never did, so there is no
    /// mount to reconcile and no ledger the kernel ever touched. The run was
    /// refused before the workload existed.
    NeverMounted,
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
            Self::NeverMounted => {
                formatter.write_str("the launch never mounted the temporary filesystem")
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

/// Which side of the launch performed the mount, and therefore what a
/// reconcile can read and who takes it down.
///
/// One filesystem, one ledger, one checkpoint and one supervisor-side server
/// either way; the difference is entirely the `mount(2)`.
#[derive(Clone, Debug)]
enum MountSite {
    /// The supervisor mounted it through the setuid `fusermount3`, in its own
    /// mount namespace. It can see the mount in its own table, `statvfs` the
    /// mountpoint, and unmount it by name.
    Supervisor { fusermount: PathBuf },
    /// The launch helper mounted it inside the workload's user and mount
    /// namespaces and handed the connection back
    /// ([`crate::tempfs_namespace`]). The mount is private to that namespace:
    /// it is in no table the supervisor can read, there is no path here to
    /// `statvfs`, and there is nothing to unmount — the namespace dies with
    /// the run tree and takes the mount with it, and the kernel closing this
    /// connection is the evidence that it did. The ledger, which only
    /// kernel-delivered FUSE requests move, is the readback.
    Workload,
}

/// A mounted, serving temporary-storage filesystem. Dropping it detaches the
/// mount.
pub struct MountedTempfs {
    mountpoint: PathBuf,
    site: MountSite,
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
            site: MountSite::Supervisor {
                fusermount: verified.fusermount.clone(),
            },
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
    ///
    /// A mount the supervisor performed is read back through `statvfs` on its
    /// own mountpoint. A mount the launch performed is private to the
    /// workload's mount namespace, so its readback is the filesystem's own
    /// `statfs` answer, computed from the ledger by the same call the kernel
    /// would have reached.
    #[must_use]
    pub fn watch(&self) -> TemporaryStorageWatch {
        match self.site {
            MountSite::Supervisor { .. } => {
                TemporaryStorageWatch::new(Arc::clone(&self.channel), &self.mountpoint)
            }
            MountSite::Workload => TemporaryStorageWatch::served(
                Arc::clone(&self.channel),
                &self.mountpoint,
                Arc::clone(&self.state),
            ),
        }
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
        let (statfs_before_unmount, aborted, unmount_confirmed) = match self.site.clone() {
            MountSite::Supervisor { fusermount } => self.detach_own_mount(&fusermount, deadline)?,
            MountSite::Workload => self.release_workload_mount(deadline),
        };
        self.detached = true;
        finish_session(self.session.take(), SESSION_JOIN_DEADLINE);
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

impl MountedTempfs {
    /// Read back and detach a mount this supervisor performed: the behaviour
    /// the enforced budget has always had.
    fn detach_own_mount(
        &mut self,
        fusermount: &Path,
        deadline: Duration,
    ) -> Result<(Option<StatfsReadback>, bool, bool), UnmountError> {
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
            run_unmount(fusermount, &self.mountpoint, false).or_else(|error| {
                // A non-lazy unmount can refuse EBUSY if a descriptor is still
                // open; on the abort path the connection is already dead, so a
                // lazy detach is correct and cannot leave a writable mount.
                if aborted {
                    run_unmount(fusermount, &self.mountpoint, true)
                } else {
                    Err(error)
                }
            })?;
        }
        match mount_evidence(&self.mountpoint).map_err(UnmountError::MountTable)? {
            None => Ok((statfs_before_unmount, aborted, true)),
            Some(evidence) => Err(UnmountError::StillMounted(Box::new(evidence))),
        }
    }

    /// Let go of a mount the launch performed inside the workload's own
    /// namespaces.
    ///
    /// There is nothing here to unmount: the mount lives in a mount namespace
    /// this process is not in, and that namespace dies with the run tree the
    /// caller has already disposed. What the supervisor owns is the
    /// connection, and the kernel closing it — which is what the last mount
    /// going away does — is the evidence the mount is gone. A connection still
    /// alive after `deadline` means something in that namespace outlived the
    /// disposal, so it is aborted through `fusectl`: after that write every
    /// request on it fails with `ENOTCONN` and no writable scratch space
    /// remains, whoever is still holding it.
    ///
    /// The readback is the filesystem's own `statfs`, taken from the ledger by
    /// the same call the kernel's `statvfs` would have reached. It is always
    /// available, which is why this path records one where the supervisor's
    /// own mount can record `statfs unavailable`.
    fn release_workload_mount(
        &mut self,
        deadline: Duration,
    ) -> (Option<StatfsReadback>, bool, bool) {
        let statfs = Some(ledger_statfs(&self.state));
        if wait_for_session(self.session.as_ref(), deadline) {
            return (statfs, false, true);
        }
        let _ = abort_connection(&self.evidence);
        let confirmed = wait_for_session(self.session.as_ref(), SESSION_JOIN_DEADLINE);
        (statfs, true, confirmed)
    }
}

impl Drop for MountedTempfs {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        match &self.site {
            MountSite::Supervisor { fusermount } => {
                // Best effort, and lazy: on this path the owner is going away,
                // so the mount must not outlive it even if a descriptor is
                // still open. The server thread ends once the kernel closes
                // the connection.
                let _ = run_unmount(fusermount, &self.mountpoint, true);
            }
            MountSite::Workload => {
                // Nothing to detach and nothing that could outlive this: the
                // mount is in the workload's own mount namespace, and aborting
                // the connection makes it answer `ENOTCONN` to whatever is
                // left there. The abort is also what unblocks the server
                // thread below.
                let _ = abort_connection(&self.evidence);
            }
        }
        finish_session(self.session.take(), SESSION_JOIN_DEADLINE);
    }
}

/// Whether the FUSE session ended within `deadline`.
fn wait_for_session(session: Option<&BackgroundSession>, deadline: Duration) -> bool {
    let Some(session) = session else {
        return true;
    };
    let until = Instant::now() + deadline;
    loop {
        if session.guard.is_finished() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The `statfs` this filesystem would answer the kernel with, right now.
///
/// Crate-visible because a watch on a mount the supervisor cannot see reads
/// back through the same call.
pub(crate) fn ledger_statfs(state: &SharedState) -> StatfsReadback {
    let view = statfs_view(state);
    StatfsReadback {
        block_size: u64::from(view.block_bytes),
        fragment_size: u64::from(view.block_bytes),
        blocks: view.blocks,
        blocks_free: view.blocks_free,
        blocks_available: view.blocks_free,
        files: view.files,
        files_free: view.files_free,
        name_max: u64::from(view.name_max),
    }
}

/// A run's temporary filesystem when the *launch* is what mounts it.
///
/// Created before the launch, so the supervisor can watch and reconcile the
/// run whatever the launch does, and completed by the launch's own rendezvous
/// ([`crate::tempfs_namespace`]). Everything a supervisor needs before the
/// mount exists — the exceedance channel it polls, the ledger it reads back,
/// the mountpoint the plan grants — exists from construction; only the
/// `mount(2)` and the kernel evidence wait.
pub struct WorkloadTempfs {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
    checkpoint_path: Option<PathBuf>,
    state: SharedState,
    channel: Arc<ExceedanceChannel>,
    /// The uid the filesystem's nodes are owned by, which must be the uid the
    /// workload sees itself as inside its namespace.
    node_uid: u32,
    /// Taken by [`Self::rendezvous`], once.
    filesystem: Option<QuotaFs>,
    mounted: Arc<Mutex<Option<MountedTempfs>>>,
}

impl fmt::Debug for WorkloadTempfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadTempfs")
            .field("mountpoint", &self.mountpoint)
            .field("budget", &self.budget)
            .field("mounted", &self.is_mounted())
            .finish_non_exhaustive()
    }
}

impl WorkloadTempfs {
    /// Prepare `budget` at `mountpoint` for a launch to mount.
    ///
    /// The mountpoint is checked here, by the supervisor that owns it, for
    /// exactly what [`MountedTempfs::mount`] checks: an empty directory this
    /// uid owns that is not already a mountpoint. The launch checks it again
    /// inside its own namespace, because between the two checks the only
    /// process that could change it is the supervisor itself.
    ///
    /// # Errors
    ///
    /// [`MountError::MountpointRejected`] for anything else, and
    /// [`MountError::MountTable`] when the mount table cannot be read.
    pub fn prepare(mountpoint: &Path, budget: TemporaryStorageBudget) -> Result<Self, MountError> {
        let mountpoint = validate_mountpoint(mountpoint)?;
        // Finding 3 of the in-namespace mount: the nodes must be owned by the
        // uid the workload sees itself as. The identity map re-uses the
        // supervisor's uid number as the workload's namespace uid, so this is
        // that number — and the launch reports what it actually got, which the
        // rendezvous refuses unless it is this.
        let node_uid = nix::unistd::getuid().as_raw();
        let channel = Arc::new(ExceedanceChannel::default());
        let filesystem = QuotaFs::new(
            budget,
            node_uid,
            crate::identity::SUPERVISOR_NAMESPACE_ID,
            Arc::clone(&channel),
        );
        Ok(Self {
            mountpoint,
            budget,
            checkpoint_path: None,
            state: filesystem.state(),
            channel,
            node_uid,
            filesystem: Some(filesystem),
            mounted: Arc::new(Mutex::new(None)),
        })
    }

    /// Bind a checkpoint file to this filesystem.
    ///
    /// The first checkpoint is written when the launch's mount arrives, not
    /// here: before that there is no mount, no evidence and no ledger the
    /// kernel has touched, and a checkpoint of those would be a claim rather
    /// than a record.
    #[must_use]
    pub fn with_checkpoint(mut self, path: impl Into<PathBuf>) -> Self {
        self.checkpoint_path = Some(path.into());
        self
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

    /// The mount request the plan carries to the launch helper.
    #[must_use]
    pub fn request(&self) -> TemporaryStorageMount {
        TemporaryStorageMount::new(self.mountpoint.clone(), self.budget)
    }

    /// What the supervision loop polls, and reads back from.
    #[must_use]
    pub fn watch(&self) -> TemporaryStorageWatch {
        TemporaryStorageWatch::served(
            Arc::clone(&self.channel),
            &self.mountpoint,
            Arc::clone(&self.state),
        )
    }

    /// Whether the launch's mount has arrived.
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        self.mounted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Take the half of this that a launch consumes, once.
    ///
    /// The launch owns the rendezvous for exactly as long as the spawn takes:
    /// it serves the descriptor the helper hands back and leaves the mount
    /// here, where the supervisor reconciles it.
    #[must_use]
    pub fn rendezvous(&mut self) -> Option<TempfsRendezvous> {
        let filesystem = self.filesystem.take()?;
        Some(TempfsRendezvous {
            mountpoint: self.mountpoint.clone(),
            budget: self.budget,
            checkpoint_path: self.checkpoint_path.clone(),
            node_uid: self.node_uid,
            filesystem,
            channel: Arc::clone(&self.channel),
            mounted: Arc::clone(&self.mounted),
        })
    }

    /// Reconcile the launch's mount, exactly as a supervisor-mounted one is
    /// reconciled.
    ///
    /// # Errors
    ///
    /// [`UnmountError::NeverMounted`] when the launch was refused before it
    /// mounted anything; otherwise whatever the mount's own reconcile says.
    pub fn reconcile(self, deadline: Duration) -> Result<Outcome, UnmountError> {
        let mounted = self
            .mounted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        mounted
            .ok_or(UnmountError::NeverMounted)?
            .reconcile(deadline)
    }
}

/// The half of a [`WorkloadTempfs`] one launch consumes.
///
/// Moved into the spawn, which is the only place that holds the launch's own
/// end of the rendezvous socket.
pub struct TempfsRendezvous {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
    checkpoint_path: Option<PathBuf>,
    node_uid: u32,
    filesystem: QuotaFs,
    channel: Arc<ExceedanceChannel>,
    mounted: Arc<Mutex<Option<MountedTempfs>>>,
}

impl fmt::Debug for TempfsRendezvous {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TempfsRendezvous")
            .field("mountpoint", &self.mountpoint)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl TempfsRendezvous {
    /// Take the launch's mount over `socket`, serve it, and keep it.
    ///
    /// Receives the `/dev/fuse` descriptor the launch mounted with, refuses
    /// anything but a `fuse.<subtype>` mount at this mountpoint owned by
    /// namespace-root and serving the identity the filesystem's nodes were
    /// built for, starts the FUSE session, and only then releases the launch —
    /// which answers with the `statvfs` it read in its own namespace, checked
    /// here against the admitted budget before the launch is allowed to go on.
    ///
    /// # Errors
    ///
    /// [`MountError::Rendezvous`] for a socket that fails, a launch that
    /// refuses, or a report that does not match; [`MountError::Session`] when
    /// the FUSE session cannot be started. Every one of them refuses the
    /// launch, and nothing is left mounted: the mount exists only in the
    /// launch's own mount namespace, which dies with it.
    pub fn complete(self, socket: &UnixStream) -> Result<(), MountError> {
        let Self {
            mountpoint,
            budget,
            checkpoint_path,
            node_uid,
            filesystem,
            channel,
            mounted,
        } = self;
        let state = filesystem.state();
        let (descriptor, evidence) = receive_mount(socket, &mountpoint, FS_SUBTYPE, node_uid)
            .map_err(MountError::Rendezvous)?;
        let session =
            Session::from_fd(filesystem, descriptor, SessionACL::Owner, Config::default())
                .and_then(Session::spawn)
                .map_err(MountError::Session)?;
        let mut attached = MountedTempfs {
            mountpoint,
            site: MountSite::Workload,
            budget,
            state,
            channel,
            session: Some(session),
            evidence,
            statfs_at_mount: zero_statfs(),
            checkpoint_path: None,
            checkpoint_sequence: 0,
            detached: false,
        };
        // From here a failure drops `attached`, which aborts the connection:
        // the launch's mount answers `ENOTCONN` and the launch, still waiting
        // on a socket that just closed, refuses itself.
        attached.statfs_at_mount = release(socket, budget).map_err(MountError::Rendezvous)?;
        if let Some(path) = checkpoint_path {
            attached = attached
                .with_checkpoint(path)
                .map_err(|error| MountError::Rendezvous(error.to_string()))?;
        }
        *mounted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(attached);
        Ok(())
    }
}

/// A run's temporary filesystem, mounted where the plan's identity requires.
///
/// The site is chosen once, from the plan, by [`Self::provide`], and there is
/// no other way to obtain a supervisor-mounted one. That is what makes the
/// pairing this type replaced — a workload in a child user namespace holding a
/// grant on a filesystem the supervisor mounted, which it would read `EACCES`
/// from — unrepresentable rather than merely refused.
pub struct RunTempfs {
    site: RunTempfsSite,
}

enum RunTempfsSite {
    /// The plan keeps the supervisor's identity, so the supervisor mounts.
    Supervisor(Box<MountedTempfs>),
    /// The plan separates the workload's identity, so the launch mounts inside
    /// the namespaces it creates.
    Workload(Box<WorkloadTempfs>),
}

impl fmt::Debug for RunTempfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.site {
            RunTempfsSite::Supervisor(mounted) => {
                formatter.debug_tuple("Supervisor").field(mounted).finish()
            }
            RunTempfsSite::Workload(pending) => {
                formatter.debug_tuple("Workload").field(pending).finish()
            }
        }
    }
}

impl RunTempfs {
    /// Provide `budget` at `mountpoint` for `plan`.
    ///
    /// # Errors
    ///
    /// Whatever the chosen site refuses with, before any workload exists.
    pub fn provide(
        plan: &LaunchPlan,
        verified: &VerifiedFuse,
        mountpoint: &Path,
        budget: TemporaryStorageBudget,
    ) -> Result<Self, MountError> {
        if plan.separates_workload_identity() {
            Self::for_workload(mountpoint, budget)
        } else {
            MountedTempfs::mount(verified, mountpoint, budget).map(|mounted| Self {
                site: RunTempfsSite::Supervisor(Box::new(mounted)),
            })
        }
    }

    /// Prepare a filesystem for the launch to mount, without a plan to derive
    /// it from.
    ///
    /// Safe to reach directly, unlike the supervisor-mounted site: attaching
    /// this to a plan that does not separate its workload's identity adds a
    /// `tempfs=` line that plan cannot carry, and the plan refuses to encode.
    ///
    /// # Errors
    ///
    /// [`MountError::MountpointRejected`] for a mountpoint that is not an
    /// empty directory this uid owns.
    pub fn for_workload(
        mountpoint: &Path,
        budget: TemporaryStorageBudget,
    ) -> Result<Self, MountError> {
        WorkloadTempfs::prepare(mountpoint, budget).map(|pending| Self {
            site: RunTempfsSite::Workload(Box::new(pending)),
        })
    }

    /// Bind a checkpoint file to whichever site holds the filesystem.
    ///
    /// # Errors
    ///
    /// The supervisor-mounted site writes its first checkpoint here and
    /// reports a write that fails.
    pub fn with_checkpoint(self, path: impl Into<PathBuf>) -> io::Result<Self> {
        let site = match self.site {
            RunTempfsSite::Supervisor(mounted) => {
                RunTempfsSite::Supervisor(Box::new(mounted.with_checkpoint(path)?))
            }
            RunTempfsSite::Workload(pending) => {
                RunTempfsSite::Workload(Box::new(pending.with_checkpoint(path)))
            }
        };
        Ok(Self { site })
    }

    /// Exact mountpoint, canonical.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        match &self.site {
            RunTempfsSite::Supervisor(mounted) => mounted.mountpoint(),
            RunTempfsSite::Workload(pending) => pending.mountpoint(),
        }
    }

    /// The budget in force.
    #[must_use]
    pub const fn budget(&self) -> TemporaryStorageBudget {
        match &self.site {
            RunTempfsSite::Supervisor(mounted) => mounted.budget(),
            RunTempfsSite::Workload(pending) => pending.budget(),
        }
    }

    /// What the supervision loop polls, and reads back from.
    #[must_use]
    pub fn watch(&self) -> TemporaryStorageWatch {
        match &self.site {
            RunTempfsSite::Supervisor(mounted) => mounted.watch(),
            RunTempfsSite::Workload(pending) => pending.watch(),
        }
    }

    /// The mount request this run's plan must carry, when the launch is what
    /// mounts it.
    #[must_use]
    pub fn request(&self) -> Option<TemporaryStorageMount> {
        match &self.site {
            RunTempfsSite::Supervisor(_) => None,
            RunTempfsSite::Workload(pending) => Some(pending.request()),
        }
    }

    /// Take the half of this that a launch consumes, once.
    #[must_use]
    pub fn rendezvous(&mut self) -> Option<TempfsRendezvous> {
        match &mut self.site {
            RunTempfsSite::Supervisor(_) => None,
            RunTempfsSite::Workload(pending) => pending.rendezvous(),
        }
    }

    /// Reconcile the run's mount and assemble its outcome.
    ///
    /// # Errors
    ///
    /// Whatever the site's own reconcile says.
    pub fn reconcile(self, deadline: Duration) -> Result<Outcome, UnmountError> {
        match self.site {
            RunTempfsSite::Supervisor(mounted) => mounted.reconcile(deadline),
            RunTempfsSite::Workload(pending) => pending.reconcile(deadline),
        }
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
