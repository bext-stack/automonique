// SPDX-License-Identifier: Elastic-2.0

//! Mount ownership: fail-closed prerequisites, the `fusermount3` handshake,
//! kernel readback, and unmount.
//!
//! An unprivileged process cannot call `mount(2)`. What it can do on this
//! host is ask the setuid-root `fusermount3` to mount a FUSE filesystem on a
//! directory it owns and hand back the `/dev/fuse` descriptor over a socket.
//! This module does exactly that, by explicit absolute path and explicit
//! argument vector — no `PATH` search, no shell — and then refuses to report
//! success until `/proc/self/mountinfo` shows a FUSE mount of this crate's
//! subtype owned by this uid at the mountpoint, and `statvfs(2)` on it
//! returns the ceilings that were asked for.

use crate::filesystem::{QuotaFs, SharedState, snapshot};
use crate::ledger::{Ceilings, LedgerSnapshot};
use crate::readback::{
    MountEvidence, MountStatus, StatfsReadback, inspect, mount_evidence, statfs_readback,
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
use std::thread;
use std::time::{Duration, Instant};

/// The kernel's FUSE control device.
pub const DEFAULT_DEV_FUSE: &str = "/dev/fuse";
/// libfuse's setuid mount helper, at the path this host installs it.
pub const DEFAULT_FUSERMOUNT3: &str = "/usr/bin/fusermount3";
/// `fsname=`: the source column in the mount table.
pub const FS_NAME: &str = "automonique-tempfs";
/// `subtype=`: the mount table shows `fuse.<subtype>`, which is how a stale
/// mount is told apart from anything else at the same path.
pub const FS_SUBTYPE: &str = "tempfs-quota";
/// The environment variable `fusermount3` reads the descriptor-passing
/// socket's number from.
const COMM_FD_ENV: &str = "_FUSE_COMMFD";
/// Mount options beyond the name and subtype. `default_permissions` makes
/// the kernel check mode bits; the three flags keep the scratch tree from
/// ever executing anything or carrying a device node.
const MOUNT_OPTIONS: &str = "default_permissions,nosuid,nodev,noexec";
/// The setuid bit, as `st_mode` carries it.
const S_ISUID: u32 = 0o4000;
/// Bound on the helper's diagnostic kept in an error.
const MAX_STDERR_BYTES: usize = 4096;

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
    /// The device is actually opened, because "exists" and "this uid can
    /// open it" are different facts and only the second one mounts anything.
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
    /// `fusermount3` exited without handing over a descriptor. Its
    /// diagnostic is the reason.
    Refused { status: Option<i32>, stderr: String },
    /// Receiving the descriptor failed.
    Handshake(io::Error),
    /// The FUSE protocol handshake or the server thread failed.
    Session(io::Error),
    /// The mount table could not be read.
    MountTable(io::Error),
    /// `fusermount3` reported success but the mount table shows no FUSE
    /// mount of this subtype at the mountpoint.
    EvidenceMissing(PathBuf),
    /// The mount table shows a mount that is not this crate's, or is owned by
    /// another uid.
    EvidenceMismatch(MountEvidence),
    /// `statvfs` on the new mount did not answer with the requested ceilings.
    StatfsMismatch {
        ceilings: Ceilings,
        observed: Result<StatfsReadback, nix::errno::Errno>,
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
            Self::StatfsMismatch { ceilings, observed } => write!(
                formatter,
                "statvfs did not read back the ceilings {ceilings:?}: {observed:?}"
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
    StillMounted(MountEvidence),
    /// The server thread ended with an error.
    Session(io::Error),
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
            Self::Session(error) => write!(formatter, "server thread failed: {error}"),
        }
    }
}

impl std::error::Error for UnmountError {}

/// The typed result of one mounted lifetime, assembled at unmount.
///
/// Everything here is either the filesystem's own ledger or a kernel readback;
/// nothing is copied from the request that created the mount.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub ceilings: Ceilings,
    pub ledger: LedgerSnapshot,
    /// The mount table entry observed right after mounting.
    pub evidence: MountEvidence,
    /// `statvfs` right after mounting: the ceilings, empty.
    pub statfs_at_mount: StatfsReadback,
    /// `statvfs` right before unmounting: the final usage the kernel saw.
    /// Absent when the server had already gone (an external unmount).
    pub statfs_before_unmount: Option<StatfsReadback>,
    /// The mount table showed no entry after unmounting.
    pub unmount_confirmed: bool,
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
        writeln!(formatter, "unmount.confirmed={}", self.unmount_confirmed)
    }
}

/// A mounted, serving quota filesystem. Dropping it detaches the mount.
pub struct MountedTempfs {
    mountpoint: PathBuf,
    fusermount: PathBuf,
    ceilings: Ceilings,
    state: SharedState,
    session: Option<BackgroundSession>,
    evidence: MountEvidence,
    statfs_at_mount: StatfsReadback,
    detached: bool,
}

impl fmt::Debug for MountedTempfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MountedTempfs")
            .field("mountpoint", &self.mountpoint)
            .field("ceilings", &self.ceilings)
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl MountedTempfs {
    /// Mount an empty quota filesystem on `mountpoint` and confirm it from
    /// the kernel.
    ///
    /// On any failure after the helper ran, the mount is detached again
    /// before the error is returned: a mount this function cannot vouch for
    /// is not left behind.
    pub fn mount(
        verified: &VerifiedFuse,
        mountpoint: &Path,
        ceilings: Ceilings,
    ) -> Result<Self, MountError> {
        let mountpoint = validate_mountpoint(mountpoint)?;
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        let descriptor = fusermount_handshake(&verified.fusermount, &mountpoint)?;
        let filesystem = QuotaFs::new(ceilings, uid, gid);
        let state = filesystem.state();
        // The descriptor is the mount: from here on, an early return must
        // detach it, which `Drop` does once `mounted` exists. Until then the
        // helper's own drop of `descriptor` aborts the connection and the
        // explicit detach below removes the table entry.
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
        let placeholder = MountEvidence {
            mountpoint: mountpoint.clone(),
            fstype: String::new(),
            source: String::new(),
            mount_options: String::new(),
            super_options: String::new(),
        };
        let mut mounted = Self {
            mountpoint,
            fusermount: verified.fusermount.clone(),
            ceilings,
            state,
            session: Some(session),
            evidence: placeholder,
            statfs_at_mount: StatfsReadback {
                block_size: 0,
                fragment_size: 0,
                blocks: 0,
                blocks_free: 0,
                blocks_available: 0,
                files: 0,
                files_free: 0,
                name_max: 0,
            },
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
            return Err(MountError::EvidenceMismatch(evidence));
        }
        let observed = statfs_readback(&mounted.mountpoint);
        match observed {
            Ok(statfs)
                if statfs.ceiling_bytes() == ceilings.bytes()
                    && statfs.files == ceilings.objects()
                    && statfs.used_bytes() == 0
                    && statfs.used_objects() == 0 =>
            {
                mounted.statfs_at_mount = statfs;
            }
            other => {
                return Err(MountError::StatfsMismatch {
                    ceilings,
                    observed: other,
                });
            }
        }
        mounted.evidence = evidence;
        Ok(mounted)
    }

    /// Exact mountpoint, canonical.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// The ceilings in force.
    #[must_use]
    pub const fn ceilings(&self) -> Ceilings {
        self.ceilings
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

    /// The ledger as it stands right now.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        snapshot(&self.state)
    }

    /// Ask the kernel for the current statistics.
    pub fn statfs(&self) -> Result<StatfsReadback, nix::errno::Errno> {
        statfs_readback(&self.mountpoint)
    }

    /// Whether the server thread is still serving. It ends when the kernel
    /// closes the connection — after an unmount, whoever performed it.
    #[must_use]
    pub fn serving(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| !session.guard.is_finished())
    }

    /// Unmount, join the server, and assemble the [`Outcome`].
    ///
    /// A non-lazy unmount: if something still holds the mount open this
    /// refuses with [`UnmountError::Refused`] rather than detaching a mount
    /// someone is using. The caller then decides — for a run whose cgroup has
    /// been killed, nothing can be holding it.
    pub fn unmount(mut self) -> Result<Outcome, UnmountError> {
        let already_gone = mount_evidence(&self.mountpoint)
            .map_err(UnmountError::MountTable)?
            .is_none();
        let statfs_before_unmount = if already_gone {
            None
        } else {
            let statfs = self.statfs().ok();
            run_unmount(&self.fusermount, &self.mountpoint, false)?;
            statfs
        };
        self.detached = true;
        if let Some(session) = self.session.take() {
            session.join().map_err(UnmountError::Session)?;
        }
        let unmount_confirmed =
            match mount_evidence(&self.mountpoint).map_err(UnmountError::MountTable)? {
                None => true,
                Some(evidence) => return Err(UnmountError::StillMounted(evidence)),
            };
        Ok(Outcome {
            ceilings: self.ceilings,
            ledger: snapshot(&self.state),
            evidence: self.evidence.clone(),
            statfs_at_mount: self.statfs_at_mount,
            statfs_before_unmount,
            unmount_confirmed,
        })
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
        if let Some(session) = self.session.take() {
            let _ = session.join();
        }
    }
}

/// Detach whatever this crate left at `mountpoint`, live or stale.
///
/// Lazy on purpose: a disconnected mount cannot be busy in any way that
/// matters, and a live one whose owner is gone is exactly what this exists to
/// remove. Returns the status observed after the detach.
pub fn detach_stale(
    verified: &VerifiedFuse,
    mountpoint: &Path,
) -> Result<MountStatus, UnmountError> {
    match inspect(mountpoint, FS_SUBTYPE).map_err(UnmountError::MountTable)? {
        MountStatus::NotMounted => return Ok(MountStatus::NotMounted),
        MountStatus::Foreign { evidence } => {
            // Not ours to touch.
            return Ok(MountStatus::Foreign { evidence });
        }
        MountStatus::Live { .. } | MountStatus::Disconnected { .. } => {}
    }
    run_unmount(&verified.fusermount, mountpoint, true)?;
    inspect(mountpoint, FS_SUBTYPE).map_err(UnmountError::MountTable)
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

/// A mount the helper has performed: the kernel connection it handed over,
/// the socket it was handed over on, and the helper process itself.
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

/// What `auto_unmount` does for a same-uid mount on this host, measured.
///
/// libfuse documents `auto_unmount` as the mount helper staying alive and
/// unmounting when the owning process's socket closes — which would make a
/// crashed supervisor's mount disappear on its own. Whether that holds for a
/// mount without `allow_other` is a property of the installed helper and the
/// host's `/etc/fuse.conf`, so it is probed rather than assumed.
#[derive(Clone, Debug)]
pub struct AutoUnmountProbe {
    /// The helper accepted the option and the mount appeared in the table.
    pub mounted: bool,
    /// The helper's exit status once the owning socket closed, or `None` if
    /// it was still running at the deadline and had to be killed.
    pub helper_exit: Option<i32>,
    /// The table after the socket closed. `NotMounted` means the host cleans
    /// up by itself; `Disconnected` means a stale mount was left behind and
    /// the owner must detach it.
    pub after_close: MountStatus,
}

impl AutoUnmountProbe {
    /// Whether closing the owning socket removed the mount.
    #[must_use]
    pub fn self_cleaning(&self) -> bool {
        matches!(self.after_close, MountStatus::NotMounted)
    }
}

impl fmt::Display for AutoUnmountProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "auto_unmount.mounted={} auto_unmount.helper_exit={:?} auto_unmount.after_close={} \
             auto_unmount.self_cleaning={}",
            self.mounted,
            self.helper_exit,
            self.after_close,
            self.self_cleaning()
        )
    }
}

/// Mount with `auto_unmount`, close everything the way a dying supervisor
/// would, and report what the kernel's table shows afterwards. Whatever is
/// left is detached before returning, so the probe leaves nothing behind.
pub fn probe_auto_unmount(
    verified: &VerifiedFuse,
    mountpoint: &Path,
) -> Result<AutoUnmountProbe, MountError> {
    const HELPER_EXIT_DEADLINE: Duration = Duration::from_secs(5);
    const KERNEL_SETTLE: Duration = Duration::from_millis(200);

    let mountpoint = validate_mountpoint(mountpoint)?;
    let options = format!("auto_unmount,fsname={FS_NAME},subtype={FS_SUBTYPE},{MOUNT_OPTIONS}");
    let Handshake {
        descriptor,
        socket,
        mut child,
    } = spawn_fusermount(&verified.fusermount, &mountpoint, &options)?;
    let mounted = mount_evidence(&mountpoint)
        .map_err(MountError::MountTable)?
        .is_some_and(|evidence| evidence.is_fuse_subtype(FS_SUBTYPE));

    // The supervisor dies: its kernel connection and its end of the helper's
    // socket close together.
    drop(descriptor);
    drop(socket);
    let deadline = Instant::now() + HELPER_EXIT_DEADLINE;
    let helper_exit = loop {
        match child.try_wait().map_err(MountError::Spawn)? {
            Some(status) => break status.code(),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    thread::sleep(KERNEL_SETTLE);
    let after_close = inspect(&mountpoint, FS_SUBTYPE).map_err(MountError::MountTable)?;
    if !matches!(after_close, MountStatus::NotMounted) {
        let _ = run_unmount(&verified.fusermount, &mountpoint, true);
    }
    Ok(AutoUnmountProbe {
        mounted,
        helper_exit,
        after_close,
    })
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
