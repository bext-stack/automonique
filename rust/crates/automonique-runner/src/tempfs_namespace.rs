// SPDX-License-Identifier: Elastic-2.0

//! Mounting the per-run temporary filesystem *inside* the workload's own user
//! and mount namespaces, and handing the connection back to the supervisor
//! that serves it.
//!
//! # Why the mount moved
//!
//! A FUSE connection remembers the user namespace of the process that opened
//! `/dev/fuse`, and `fuse_permission` refuses a process in a **child** user
//! namespace of the mount's own. So a supervisor-mounted scratch filesystem —
//! [`crate::tempfs::MountedTempfs::mount`], through the setuid `fusermount3` —
//! is reachable by every workload except the one whose identity has been
//! separated: for that one `stat` succeeds while `open` and `write` answer
//! `EACCES`, whatever the uid and whatever the mode. The two features could
//! not compose, and admission refused the combination.
//!
//! They compose when the mount is performed by the process that owns the
//! namespace. The launch helper is exactly that process: between
//! [`crate::identity::enter_workload_namespace`] and
//! [`crate::identity::assume_workload_identity`] it is namespace-root, holding
//! a full capability set inside a user namespace it created and none outside
//! it, which is what an unprivileged FUSE mount needs. Three facts make the
//! mount succeed, and each was a distinct `EINVAL` or `EACCES` before it was
//! understood:
//!
//! 1. **The `/dev/fuse` descriptor is opened here, in the namespace.** The
//!    kernel refuses the mount unless the opener's user namespace is the
//!    mounter's (`file->f_cred->user_ns == sb->s_user_ns`), so a descriptor
//!    the supervisor opened is `EINVAL` however it travels.
//! 2. **`user_id`/`group_id` name the *mounter*, not the workload.** They are
//!    read in the mount's own user namespace and must be the mounting
//!    process's own ids there, which are namespace-root's: `0`/`0`.
//! 3. **The server's node uid and gid are read in the mount's user
//!    namespace.** The filesystem's root node must therefore be owned by the
//!    workload's *namespace* uid — the supervisor's uid number, which the
//!    identity map re-uses inside the namespace — and not by the workload's
//!    host uid. This was the last `EACCES`.
//!
//! `allow_other` is still necessary, because the workload is not the mounter:
//! with it, `fuse_allow_current_process` admits any process inside the mount's
//! user namespace, and the kernel's own `default_permissions` mode check
//! against the node ownership above is what actually bounds access.
//!
//! # Who serves it
//!
//! The supervisor does, over a descriptor this module passes back with
//! `SCM_RIGHTS`. The helper cannot: `execve` destroys every thread but the
//! calling one, so a server thread started here would die at the exact moment
//! the workload begins, and the helper must in any case still be
//! single-threaded when it installs Landlock and seccomp
//! ([`crate::filesystem::require_single_threaded`]). Forking a server process
//! instead would put the filesystem that accounts for the run inside the run's
//! own cgroup and give the supervisor a second child to reap. Passing the
//! descriptor keeps the ledger, the checkpoint, the exceedance channel and the
//! reconcile exactly where [`crate::tempfs`] already has them — in the
//! supervisor — and changes only where the `mount(2)` happens.
//!
//! # The rendezvous
//!
//! Four steps on the launch's own plan channel, which is a socket rather than
//! a pipe when a mount is expected. Every step can refuse, and a refusal on
//! either side closes the socket, which refuses the launch on the other:
//!
//! | Direction | Line |
//! | --- | --- |
//! | helper → supervisor | `mounted=<mountinfo>:<namespace uid>:<namespace gid>` plus the `/dev/fuse` descriptor as ancillary data |
//! | supervisor → helper | `serving` once the FUSE session is answering |
//! | helper → supervisor | `statfs=<statvfs readback>`, taken **after** the helper has become the workload |
//! | supervisor → helper | `go` once the readback is exactly the admitted budget |
//!
//! The third step is where the identity switch lands, and it is the proof
//! rather than a formality: the readback is taken by the process that is about
//! to `execve` the workload, under the credentials it will run with, so it is
//! the exact operation a supervisor-mounted filesystem answers `EACCES` to.
//!
//! The helper closes its own copy of the descriptor before it goes on, so the
//! connection has exactly one server, and closes the socket before the launch
//! verifies its descriptor table.

use crate::identity::SUPERVISOR_NAMESPACE_ID;
use crate::tempfs_ledger::TemporaryStorageBudget;
use crate::tempfs_readback::{
    MountEvidence, StatfsReadback, parse_mountinfo_line, statfs_readback,
};
use nix::sched::{CloneFlags, unshare};
use rustix::mount::{MountFlags, MountPropagationFlags, mount, mount_change};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The kernel's FUSE control device, opened inside the workload's namespace.
pub const DEV_FUSE: &str = "/dev/fuse";
/// `rootmode=`, as the kernel's octal `S_IFDIR`.
const ROOT_MODE: u32 = 0o040_000;
/// Superblock options beyond the descriptor, the root mode and the ids.
///
/// `nosuid`, `nodev` and `noexec` are mount *flags* here rather than options,
/// because `mount(2)` takes them as flags and FUSE's own option parser would
/// refuse them as unknown; the setuid helper the supervisor-mounted path uses
/// makes the same split, one layer further out. `default_permissions` puts the
/// mode check in the kernel, and `allow_other` is what admits a process that
/// is inside the mount's user namespace without being its mounter — which is
/// exactly the workload, after it drops namespace-root.
const MOUNT_OPTIONS: &str = "default_permissions,allow_other";
/// Longest rendezvous line either side will read, before decoding.
const MAX_RENDEZVOUS_LINE: usize = 8192;
/// What the supervisor answers once its FUSE session is serving.
const SERVING: &str = "serving";
/// What the supervisor answers once the readback matched the budget.
const GO: &str = "go";

/// A temporary-storage mount one launch is asked to perform, as the plan
/// frame carries it.
///
/// Data: holding one mounts nothing. The mountpoint is the directory the
/// supervisor created under the run's private tree, and the budget is the one
/// admission proved the host can enforce; the helper refuses the launch unless
/// the kernel reads back exactly that budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporaryStorageMount {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
}

impl TemporaryStorageMount {
    /// Ask the launch to mount `budget` at `mountpoint`.
    #[must_use]
    pub fn new(mountpoint: impl Into<PathBuf>, budget: TemporaryStorageBudget) -> Self {
        Self {
            mountpoint: mountpoint.into(),
            budget,
        }
    }

    /// Exact directory the filesystem is mounted on.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// The ceilings the kernel must read back.
    #[must_use]
    pub const fn budget(&self) -> TemporaryStorageBudget {
        self.budget
    }
}

impl fmt::Display for TemporaryStorageMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}",
            self.budget,
            self.mountpoint.display()
        )
    }
}

/// What the helper reported about the mount it performed.
#[derive(Clone, Debug)]
pub struct WorkloadMountReport {
    /// The mount table entry, read from the workload's own mount namespace.
    pub evidence: MountEvidence,
    /// `statvfs(2)` on the new mount, taken in the namespace.
    pub statfs: StatfsReadback,
    /// The uid the workload sees itself as, which is what the filesystem's
    /// nodes must be owned by.
    pub namespace_uid: u32,
    /// The gid the workload sees itself as.
    pub namespace_gid: u32,
}

/// Why a launch could not mount its temporary storage, or could not hand it
/// over.
#[derive(Debug)]
pub enum WorkloadMountError {
    /// The mountpoint is not an empty directory this namespace owns.
    MountpointRejected(PathBuf, &'static str),
    /// `unshare(CLONE_NEWNS)` or the propagation change was refused.
    MountNamespaceRefused(io::Error),
    /// `/dev/fuse` could not be opened inside the namespace.
    DeviceUnopenable(io::Error),
    /// `mount(2)` refused the FUSE filesystem.
    MountRefused(io::Error),
    /// The mount table shows no `fuse.<subtype>` mount at the mountpoint.
    EvidenceMissing(PathBuf),
    /// The rendezvous socket failed, or the supervisor refused.
    Rendezvous(String),
    /// `statvfs` on the new mount did not answer with the requested budget.
    StatfsMismatch {
        budget: TemporaryStorageBudget,
        observed: Box<StatfsReadback>,
    },
    /// `statvfs` on the new mount failed outright.
    StatfsUnreadable(nix::errno::Errno),
}

impl fmt::Display for WorkloadMountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MountpointRejected(path, reason) => {
                write!(
                    formatter,
                    "mountpoint {} rejected: {reason}",
                    path.display()
                )
            }
            Self::MountNamespaceRefused(error) => {
                write!(formatter, "no private mount namespace: {error}")
            }
            Self::DeviceUnopenable(error) => {
                write!(
                    formatter,
                    "{DEV_FUSE} cannot be opened in-namespace: {error}"
                )
            }
            Self::MountRefused(error) => write!(formatter, "mount refused: {error}"),
            Self::EvidenceMissing(path) => write!(
                formatter,
                "no mount is visible at {} after mount returned",
                path.display()
            ),
            Self::Rendezvous(reason) => write!(formatter, "mount handover failed: {reason}"),
            Self::StatfsMismatch { budget, observed } => write!(
                formatter,
                "statvfs did not read back the budget {budget}: {observed}"
            ),
            Self::StatfsUnreadable(errno) => write!(formatter, "statvfs failed: {errno}"),
        }
    }
}

impl std::error::Error for WorkloadMountError {}

/// A mount this launch performed and the supervisor is now serving, waiting to
/// be confirmed under the workload's own credentials.
#[derive(Clone, Debug)]
pub struct MountedByLaunch {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
}

/// Mount `request` inside the calling process's namespaces and hand the
/// connection to the supervisor over `socket`.
///
/// The caller must be namespace-root in a user namespace of its own and
/// single-threaded — that is, it must have returned from
/// [`crate::identity::enter_workload_namespace`] and not yet called
/// [`crate::identity::assume_workload_identity`]. On return the mount is
/// private to this process's mount namespace and the supervisor is serving it;
/// this process holds no descriptor into it. The caller must then take the
/// workload identity and call [`confirm_for_workload`], which is what releases
/// the launch.
///
/// # Errors
///
/// Every failure is a refusal before the workload exists. Nothing is left
/// mounted that this function could not vouch for: the mount lives in a mount
/// namespace that dies with this process, and the helper exits on any error.
pub fn mount_for_workload(
    request: &TemporaryStorageMount,
    namespace_uid: u32,
    socket: &UnixStream,
) -> Result<MountedByLaunch, WorkloadMountError> {
    let mountpoint = validate_mountpoint(request.mountpoint())?;

    // A mount namespace of this process's own, with propagation cut, so the
    // scratch filesystem is visible to the workload and to nothing else.
    // Without the propagation change a mount under a shared parent would
    // travel straight back to the supervisor's namespace, which is the one
    // place this mount must never appear.
    unshare(CloneFlags::CLONE_NEWNS).map_err(|errno: nix::errno::Errno| {
        WorkloadMountError::MountNamespaceRefused(errno.into())
    })?;
    mount_change(
        "/",
        MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
    )
    .map_err(|errno: rustix::io::Errno| WorkloadMountError::MountNamespaceRefused(errno.into()))?;

    // Finding 1: the connection remembers this namespace because this open
    // happens in it.
    let device = File::options()
        .read(true)
        .write(true)
        .open(DEV_FUSE)
        .map_err(WorkloadMountError::DeviceUnopenable)?;
    let device: OwnedFd = device.into();

    // Finding 2: `user_id`/`group_id` are the mounter's ids in this
    // namespace, which are namespace-root's.
    let options = format!(
        "fd={},rootmode={ROOT_MODE:o},user_id={SUPERVISOR_NAMESPACE_ID},\
         group_id={SUPERVISOR_NAMESPACE_ID},{MOUNT_OPTIONS}",
        rustix::fd::AsRawFd::as_raw_fd(&device),
    );
    let fstype = format!("fuse.{}", crate::tempfs::FS_SUBTYPE);
    let options = CString::new(options).expect("mount options carry no NUL");
    mount(
        crate::tempfs::FS_NAME,
        &mountpoint,
        fstype.as_str(),
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        options.as_c_str(),
    )
    .map_err(|errno: rustix::io::Errno| WorkloadMountError::MountRefused(errno.into()))?;

    let evidence = crate::tempfs_readback::mount_evidence(&mountpoint)
        .map_err(|error| {
            WorkloadMountError::Rendezvous(format!("mount table unreadable: {error}"))
        })?
        .ok_or_else(|| WorkloadMountError::EvidenceMissing(mountpoint.clone()))?;

    // Hand the connection over and let go of it: from here the supervisor is
    // the only server, and this process must own no descriptor into a
    // filesystem it is about to be sandboxed inside.
    send_descriptor(
        socket,
        &format!(
            "mounted={}:{namespace_uid}:{SUPERVISOR_NAMESPACE_ID}\n",
            hex(evidence_line(&evidence).as_bytes())
        ),
        &device,
    )
    .map_err(|error| WorkloadMountError::Rendezvous(error.to_string()))?;
    drop(device);

    expect_line(socket, SERVING).map_err(WorkloadMountError::Rendezvous)?;
    Ok(MountedByLaunch {
        mountpoint,
        budget: request.budget(),
    })
}

/// Read the mount back under the workload's own credentials, report it, and
/// wait to be released.
///
/// Called after [`crate::identity::assume_workload_identity`], deliberately:
/// this is the exact readback a supervisor-mounted filesystem answers `EACCES`
/// to. Taking it here — by the process that is about to `execve` the workload,
/// under the credentials it will run with — is the kernel and the filesystem
/// both saying the composition works. It also matters mechanically: the FUSE
/// session admits its owner's uid, which inside the mount's user namespace is
/// the workload's number and not namespace-root's.
///
/// # Errors
///
/// A readback that fails or does not equal the admitted budget, or a
/// supervisor that refuses. Each refuses the launch before the workload runs.
pub fn confirm_for_workload(
    mounted: &MountedByLaunch,
    socket: &UnixStream,
) -> Result<StatfsReadback, WorkloadMountError> {
    let statfs =
        statfs_readback(&mounted.mountpoint).map_err(WorkloadMountError::StatfsUnreadable)?;
    let budget = mounted.budget;
    if statfs.ceiling_bytes() != budget.bytes()
        || statfs.files != budget.objects()
        || statfs.used_bytes() != 0
        || statfs.used_objects() != 0
    {
        return Err(WorkloadMountError::StatfsMismatch {
            budget,
            observed: Box::new(statfs),
        });
    }
    write_line(
        socket,
        &format!("statfs={}", hex(statfs.to_string().as_bytes())),
    )
    .map_err(|error| WorkloadMountError::Rendezvous(error.to_string()))?;
    expect_line(socket, GO).map_err(WorkloadMountError::Rendezvous)?;
    Ok(statfs)
}

/// Receive one launch's mount over `socket`: the `/dev/fuse` descriptor and
/// the helper's report, checked against `budget` before the launch is released.
///
/// The caller starts the FUSE session on the returned descriptor and then
/// calls [`release`], which is what lets the helper go on to become the
/// workload. Splitting the two is what makes the helper's own `statvfs` proof
/// possible: it can only be answered once a server is answering.
///
/// # Errors
///
/// A socket that fails, a helper that refuses, a report that does not parse,
/// or a report that does not match `budget` or the identity the filesystem's
/// nodes were built for.
pub fn receive_mount(
    socket: &UnixStream,
    mountpoint: &Path,
    subtype: &str,
    node_uid: u32,
) -> Result<(OwnedFd, MountEvidence), String> {
    let (line, descriptor) = receive_descriptor(socket)?;
    let descriptor = descriptor.ok_or_else(|| "the launch sent no descriptor".to_owned())?;
    let value = line
        .strip_prefix("mounted=")
        .ok_or_else(|| format!("unexpected rendezvous line {line:?}"))?;
    let mut fields = value.split(':');
    let evidence = fields
        .next()
        .and_then(unhex)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|line| parse_mountinfo_line(&line))
        .ok_or_else(|| "the launch reported no mount table entry".to_owned())?;
    let namespace_uid: u32 = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "the launch reported no namespace uid".to_owned())?;
    let namespace_gid: u32 = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "the launch reported no namespace gid".to_owned())?;
    if fields.next().is_some() {
        return Err("the mount report has trailing fields".to_owned());
    }
    if evidence.mountpoint != mountpoint {
        return Err(format!(
            "the launch mounted {} rather than {}",
            evidence.mountpoint.display(),
            mountpoint.display()
        ));
    }
    if !evidence.is_fuse_subtype(subtype) || evidence.source != crate::tempfs::FS_NAME {
        return Err(format!("the launch mounted something else: {evidence}"));
    }
    if evidence.user_id() != Some(SUPERVISOR_NAMESPACE_ID) {
        return Err(format!("the mount is not namespace-root's: {evidence}"));
    }
    // Finding 3: the filesystem's nodes were built for these ids, and a
    // mismatch would be an `EACCES` the workload discovers on its own scratch
    // directory rather than a refusal here.
    if namespace_uid != node_uid || namespace_gid != SUPERVISOR_NAMESPACE_ID {
        return Err(format!(
            "the workload's namespace identity is {namespace_uid}:{namespace_gid}, not \
             {node_uid}:{SUPERVISOR_NAMESPACE_ID}"
        ));
    }
    Ok((descriptor, evidence))
}

/// Tell the launch its filesystem is being served, and take the readback it
/// answers with.
///
/// # Errors
///
/// A socket that fails, or a readback that is not exactly `budget`.
pub fn release(
    socket: &UnixStream,
    budget: TemporaryStorageBudget,
) -> Result<StatfsReadback, String> {
    write_line(socket, SERVING).map_err(|error| error.to_string())?;
    let line = read_line(socket).map_err(|error| error.to_string())?;
    let statfs = line
        .strip_prefix("statfs=")
        .and_then(unhex)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|value| StatfsReadback::from_spelling(&value))
        .ok_or_else(|| format!("unexpected rendezvous line {line:?}"))?;
    if statfs.ceiling_bytes() != budget.bytes()
        || statfs.files != budget.objects()
        || statfs.used_bytes() != 0
        || statfs.used_objects() != 0
    {
        return Err(format!(
            "the launch read back {statfs} rather than the admitted budget {budget}"
        ));
    }
    write_line(socket, GO).map_err(|error| error.to_string())?;
    Ok(statfs)
}

/// Bound every read either side of the rendezvous makes.
///
/// A launch that stops answering must not hold the supervisor's worker, and a
/// supervisor that stops answering must not hold a launch that is already
/// inside its namespaces; the deadline is what turns either into a refusal.
pub fn bound_reads(socket: &UnixStream, deadline: Duration) -> io::Result<()> {
    socket.set_read_timeout(Some(deadline))?;
    socket.set_write_timeout(Some(deadline))
}

/// Canonical, existing, empty, owned by this namespace's root, and not
/// already a mountpoint.
fn validate_mountpoint(mountpoint: &Path) -> Result<PathBuf, WorkloadMountError> {
    use std::os::unix::fs::MetadataExt as _;

    let rejected =
        |reason| WorkloadMountError::MountpointRejected(mountpoint.to_path_buf(), reason);
    if !mountpoint.is_absolute() {
        return Err(rejected("not absolute"));
    }
    let canonical = std::fs::canonicalize(mountpoint).map_err(|_| rejected("does not resolve"))?;
    let metadata = std::fs::metadata(&canonical).map_err(|_| rejected("unreadable"))?;
    if !metadata.is_dir() {
        return Err(rejected("not a directory"));
    }
    // Read inside the namespace, so the supervisor's uid is namespace-root.
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err(rejected("not owned by this uid"));
    }
    let mut entries = std::fs::read_dir(&canonical).map_err(|_| rejected("unlistable"))?;
    if entries.next().is_some() {
        return Err(rejected("not empty"));
    }
    if crate::tempfs_readback::mount_evidence(&canonical)
        .map_err(|_| rejected("mount table unreadable"))?
        .is_some()
    {
        return Err(rejected("already a mountpoint"));
    }
    Ok(canonical)
}

/// The mount table line this evidence stands for, in the exact grammar
/// [`parse_mountinfo_line`] reads.
fn evidence_line(evidence: &MountEvidence) -> String {
    // Rebuilt rather than carried verbatim so the report is bounded and holds
    // exactly the fields the supervisor checks.
    format!(
        "0 0 0:{} / {} {} - {} {} {}",
        evidence.device_minor,
        escape(&evidence.mountpoint.to_string_lossy()),
        evidence.mount_options,
        evidence.fstype,
        escape(&evidence.source),
        evidence.super_options
    )
}

/// `mountinfo`'s octal escaping of space, tab, newline and backslash.
fn escape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for byte in field.bytes() {
        match byte {
            b' ' | b'\t' | b'\n' | b'\\' => out.push_str(&format!("\\{byte:03o}")),
            _ => out.push(char::from(byte)),
        }
    }
    out
}

fn send_descriptor(socket: &UnixStream, line: &str, descriptor: &OwnedFd) -> io::Result<()> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let borrowed = [descriptor.as_fd()];
    if !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
        return Err(io::Error::other(
            "the ancillary buffer refused the descriptor",
        ));
    }
    let bytes = line.as_bytes();
    let mut sent = 0;
    while sent < bytes.len() {
        let iov = [IoSlice::new(&bytes[sent..])];
        match sendmsg(socket, &iov, &mut control, SendFlags::empty()) {
            Ok(0) => return Err(io::Error::other("the rendezvous socket accepted nothing")),
            Ok(count) => sent += count,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        // The descriptor rides on the first byte only; a partial write must
        // not send it twice.
        control.clear();
    }
    Ok(())
}

/// One line and, if the sender attached one, one descriptor.
fn receive_descriptor(socket: &UnixStream) -> Result<(String, Option<OwnedFd>), String> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut line = Vec::new();
    let mut descriptor = None;
    loop {
        let mut byte = [0_u8; 1];
        let mut iov = [IoSliceMut::new(&mut byte)];
        let received = loop {
            match recvmsg(socket, &mut iov, &mut control, RecvFlags::empty()) {
                Ok(received) => break received,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(format!("rendezvous read failed: {error}")),
            }
        };
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(descriptors) = message {
                for received in descriptors {
                    if descriptor.is_some() {
                        return Err("the launch sent more than one descriptor".to_owned());
                    }
                    descriptor = Some(received);
                }
            }
        }
        if received.bytes == 0 {
            return Err("the launch closed the rendezvous".to_owned());
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_RENDEZVOUS_LINE {
            return Err("the rendezvous line is oversized".to_owned());
        }
    }
    let line =
        String::from_utf8(line).map_err(|_| "the rendezvous line is not UTF-8".to_owned())?;
    Ok((line, descriptor))
}

fn write_line(socket: &UnixStream, line: &str) -> io::Result<()> {
    let mut socket = socket;
    socket.write_all(line.as_bytes())?;
    socket.write_all(b"\n")
}

fn read_line(socket: &UnixStream) -> io::Result<String> {
    let mut socket = socket;
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        match socket.read(&mut byte) {
            Ok(0) => return Err(io::Error::other("the rendezvous was closed")),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_RENDEZVOUS_LINE {
            return Err(io::Error::other("the rendezvous line is oversized"));
        }
    }
    String::from_utf8(line).map_err(|_| io::Error::other("the rendezvous line is not UTF-8"))
}

fn expect_line(socket: &UnixStream, expected: &str) -> Result<(), String> {
    match read_line(socket) {
        Ok(line) if line == expected => Ok(()),
        Ok(line) => Err(format!("the supervisor answered {line:?}")),
        Err(error) => Err(error.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_report_round_trips_through_the_rendezvous_grammar() {
        let line = "42 30 0:161 / /run/scratch\\040space rw,nosuid,nodev,noexec,relatime - \
                    fuse.automonique-tempfs automonique-tempfs rw,user_id=0,group_id=0,\
                    default_permissions,allow_other";
        let evidence = parse_mountinfo_line(line).expect("the fixture is a mountinfo line");
        let rebuilt = parse_mountinfo_line(&evidence_line(&evidence))
            .expect("the report is a mountinfo line");
        assert_eq!(rebuilt.mountpoint, evidence.mountpoint);
        assert_eq!(rebuilt.device_minor, evidence.device_minor);
        assert_eq!(rebuilt.fstype, evidence.fstype);
        assert_eq!(rebuilt.source, evidence.source);
        assert_eq!(rebuilt.super_options, evidence.super_options);
        assert_eq!(rebuilt.user_id(), Some(0));
    }

    #[test]
    fn hex_round_trips_every_byte() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&bytes)), Some(bytes));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }
}
