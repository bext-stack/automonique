// SPDX-License-Identifier: Elastic-2.0

//! Durable owner for private temporary-storage FUSE connections.
//!
//! This process is packaged as a sibling systemd service, outside the daemon
//! service's kill domain. The daemon transfers the in-namespace `/dev/fuse`
//! descriptor and the helper handshake socket exactly once. Afterwards this
//! owner checkpoints the exact ledger independently and fences every request
//! by run id, an unguessable adoption token, and the cgroup directory's
//! device/inode identity.

use crate::tempfs::{NamespacedMountedTempfs, start_namespaced_tempfs};
use crate::{Checkpoint, CheckpointPhase, NamespacedOutcome, TemporaryStorageBudget};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{getsockopt, sockopt};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, IoSlice, IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{
    FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const OWNER_MODE_FLAG: &str = "--temporary-storage-owner";
pub const OWNER_SOCKET_ENV: &str = "AUTOMONIQUE_TEMPFS_OWNER_SOCKET";
pub const OWNER_TOKEN_LEAF: &str = "tempfs-owner-token";
pub const OWNER_CUSTODY_LEAF: &str = "tempfs-owner-custody";
const OWNER_LOCK_LEAF: &str = "tempfs-owner.lock";
const VERSION: &str = "automonique.tempfs-owner/v1";
const MAX_REQUEST_BYTES: usize = 4096;
const MAX_RUNS: usize = 8;
const MAX_RECOVERY_ENTRIES: usize = 4096;
const CHECKPOINT_INTERVAL: Duration = Duration::from_millis(200);
const IDLE_TICK: Duration = Duration::from_millis(10);

/// Verify the packaged owner endpoint before production admission advertises
/// temporary-storage enforcement.
pub fn verify_available() -> Result<(), OwnerError> {
    let socket = std::env::var_os(OWNER_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or(OwnerError::Refused("owner unavailable"))?;
    secure_socket(&socket)
}

#[derive(Debug)]
pub enum OwnerError {
    Io(io::Error),
    Protocol(&'static str),
    Refused(&'static str),
}

impl From<io::Error> for OwnerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl std::fmt::Display for OwnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "temporary-storage owner I/O failed: {error}"),
            Self::Protocol(reason) => write!(
                formatter,
                "temporary-storage owner protocol failed: {reason}"
            ),
            Self::Refused(reason) => write!(formatter, "temporary-storage owner refused: {reason}"),
        }
    }
}

impl std::error::Error for OwnerError {}

struct Custody {
    token: String,
    cgroup: PathBuf,
    cgroup_dev: u64,
    cgroup_ino: u64,
    budget: TemporaryStorageBudget,
    checkpoint: PathBuf,
    storage: Arc<Mutex<Option<NamespacedMountedTempfs>>>,
}

pub(crate) struct RemoteCustody {
    socket: PathBuf,
    run_id: String,
    token: String,
    cgroup: PathBuf,
    cgroup_dev: u64,
    cgroup_ino: u64,
    budget: TemporaryStorageBudget,
    checkpoint: PathBuf,
    checkpoint_sequence: u64,
}

struct CustodyRecord {
    run_id: String,
    socket: PathBuf,
    cgroup: PathBuf,
    cgroup_dev: u64,
    cgroup_ino: u64,
    budget: TemporaryStorageBudget,
    checkpoint: PathBuf,
}

impl std::fmt::Debug for RemoteCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteCustody")
            .field("checkpoint_sequence", &self.checkpoint_sequence)
            .finish_non_exhaustive()
    }
}

impl RemoteCustody {
    pub(crate) fn open(
        fuse: OwnedFd,
        helper: &UnixStream,
        run_id: &str,
        cgroup: &Path,
        budget: TemporaryStorageBudget,
        namespace_uid: u32,
        checkpoint: &Path,
    ) -> Result<Self, OwnerError> {
        let socket = std::env::var_os(OWNER_SOCKET_ENV)
            .map(PathBuf::from)
            .ok_or(OwnerError::Refused("owner unavailable"))?;
        secure_socket(&socket)?;
        let cgroup_metadata = fs::symlink_metadata(cgroup)?;
        if !cgroup_metadata.is_dir() || cgroup_metadata.file_type().is_symlink() {
            return Err(OwnerError::Refused("cgroup identity"));
        }
        verify_checkpoint_parent(checkpoint)?;
        let token_path = checkpoint
            .parent()
            .ok_or(OwnerError::Refused("checkpoint parent"))?
            .join(OWNER_TOKEN_LEAF);
        let token = create_token(&token_path)?;
        let custody_path = checkpoint
            .parent()
            .ok_or(OwnerError::Refused("checkpoint parent"))?
            .join(OWNER_CUSTODY_LEAF);
        let record = CustodyRecord {
            run_id: run_id.to_owned(),
            socket: socket.clone(),
            cgroup: cgroup.to_path_buf(),
            cgroup_dev: cgroup_metadata.dev(),
            cgroup_ino: cgroup_metadata.ino(),
            budget,
            checkpoint: checkpoint.to_path_buf(),
        };
        if let Err(error) = write_custody(&custody_path, &record) {
            let _ = fs::remove_file(&token_path);
            return Err(error);
        }
        let helper = rustix::io::dup(helper).map_err(|error| OwnerError::Io(error.into()))?;
        let request = format!(
            "{VERSION} open 1 {} {token} {} {} {} {} {} {} {namespace_uid}\n",
            encode_hex(run_id.as_bytes()),
            encode_hex(cgroup.as_os_str().as_encoded_bytes()),
            cgroup_metadata.dev(),
            cgroup_metadata.ino(),
            budget.bytes(),
            budget.objects(),
            encode_hex(checkpoint.as_os_str().as_encoded_bytes()),
        );
        let mut stream = match UnixStream::connect(&socket) {
            Ok(stream) => stream,
            Err(error) => {
                cleanup_unaccepted(&token_path, &custody_path);
                return Err(error.into());
            }
        };
        let descriptors = [fuse.as_fd(), helper.as_fd()];
        if let Err(error) = send_request(&stream, request.as_bytes(), &descriptors) {
            cleanup_unaccepted(&token_path, &custody_path);
            return Err(error);
        }
        let checkpoint_sequence = match read_response(&mut stream, "ok", 1) {
            Ok(sequence) => sequence,
            Err(error) => {
                // The owner may have accepted custody before its reply was
                // lost. Preserve both private recovery files in that case;
                // startup adoption resolves the ambiguity fail closed.
                if Checkpoint::read(checkpoint).is_err_and(|_| !checkpoint.exists()) {
                    cleanup_unaccepted(&token_path, &custody_path);
                }
                return Err(error);
            }
        };
        let durable = Checkpoint::read(checkpoint)
            .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
        if durable.phase != CheckpointPhase::Live || durable.sequence != checkpoint_sequence {
            return Err(OwnerError::Refused("checkpoint fence"));
        }
        Ok(Self {
            socket,
            run_id: run_id.to_owned(),
            token,
            cgroup: cgroup.to_path_buf(),
            cgroup_dev: cgroup_metadata.dev(),
            cgroup_ino: cgroup_metadata.ino(),
            budget,
            checkpoint: checkpoint.to_path_buf(),
            checkpoint_sequence,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<crate::LedgerSnapshot, OwnerError> {
        let checkpoint = Checkpoint::read(&self.checkpoint)
            .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
        if checkpoint.sequence < self.checkpoint_sequence
            || checkpoint.snapshot.budget != self.budget
            || !checkpoint
                .mount_evidence
                .starts_with("automonique.namespaced-tempfs/v1 ")
        {
            return Err(OwnerError::Refused("checkpoint regression"));
        }
        Ok(checkpoint.snapshot)
    }

    pub(crate) fn checkpoint(&mut self) -> Result<(), OwnerError> {
        self.rpc("checkpoint", "ok")
    }

    pub(crate) fn adopt(&mut self) -> Result<(), OwnerError> {
        self.rpc("adopt", "adopted")
    }

    fn rpc(&mut self, verb: &str, response: &str) -> Result<(), OwnerError> {
        secure_socket(&self.socket)?;
        verify_cgroup(&self.cgroup, self.cgroup_dev, self.cgroup_ino)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let durable = Checkpoint::read(&self.checkpoint)
                .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
            if durable.phase != CheckpointPhase::Live || durable.sequence < self.checkpoint_sequence
            {
                return Err(OwnerError::Refused("checkpoint fence"));
            }
            self.checkpoint_sequence = durable.sequence;
            let request_sequence = durable
                .sequence
                .checked_add(1)
                .ok_or(OwnerError::Refused("sequence exhausted"))?;
            let request = format!(
                "{VERSION} {verb} {} {} {} {} {} {} {} {}\n",
                request_sequence,
                encode_hex(self.run_id.as_bytes()),
                self.token,
                self.cgroup_dev,
                self.cgroup_ino,
                self.budget.bytes(),
                self.budget.objects(),
                self.checkpoint_sequence,
            );
            if let Ok(mut stream) = UnixStream::connect(&self.socket)
                && send_request(&stream, request.as_bytes(), &[]).is_ok()
                && let Ok(sequence) = read_response(&mut stream, response, request_sequence)
            {
                self.checkpoint_sequence = sequence;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(OwnerError::Refused("request timeout"));
            }
            std::thread::sleep(IDLE_TICK);
        }
    }

    pub(crate) fn reconcile(mut self) -> Result<NamespacedOutcome, OwnerError> {
        if let Ok(final_checkpoint) = Checkpoint::read(&self.checkpoint)
            && final_checkpoint.phase == CheckpointPhase::Final
        {
            return outcome_from_final(&final_checkpoint);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let durable = Checkpoint::read(&self.checkpoint)
                .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
            if durable.phase == CheckpointPhase::Final {
                return outcome_from_final(&durable);
            }
            if durable.sequence < self.checkpoint_sequence {
                return Err(OwnerError::Refused("checkpoint regression"));
            }
            self.checkpoint_sequence = durable.sequence;
            let request_sequence = durable
                .sequence
                .checked_add(1)
                .ok_or(OwnerError::Refused("sequence exhausted"))?;
            let request = format!(
                "{VERSION} reconcile {} {} {} {} {} {} {} {}\n",
                request_sequence,
                encode_hex(self.run_id.as_bytes()),
                self.token,
                self.cgroup_dev,
                self.cgroup_ino,
                self.budget.bytes(),
                self.budget.objects(),
                self.checkpoint_sequence,
            );
            if let Ok(mut stream) = UnixStream::connect(&self.socket)
                && send_request(&stream, request.as_bytes(), &[]).is_ok()
                && let Ok(sequence) = read_response(&mut stream, "final", request_sequence)
            {
                self.checkpoint_sequence = sequence;
                let final_checkpoint = Checkpoint::read(&self.checkpoint)
                    .map_err(|_| OwnerError::Refused("final checkpoint unreadable"))?;
                return outcome_from_final(&final_checkpoint);
            }
            if Instant::now() >= deadline {
                return Err(OwnerError::Refused("reconciliation timeout"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Reattach a restarted daemon to custody that the sibling owner still holds.
///
/// The returned checkpoint is read only after the owner has authenticated the
/// private token, cgroup inode and next durable sequence. A restarted owner
/// cannot satisfy this request: its startup pass first turns every recoverable
/// live checkpoint into an aborted final record.
pub fn adopt_run(run_directory: &Path) -> Result<Checkpoint, OwnerError> {
    private_directory(run_directory)?;
    let record = read_custody(&run_directory.join(OWNER_CUSTODY_LEAF))?;
    let expected_run = run_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(OwnerError::Refused("run directory"))?;
    if record.run_id != expected_run
        || record.checkpoint.parent() != Some(run_directory)
        || record.checkpoint.file_name().and_then(|name| name.to_str())
            != Some(crate::CHECKPOINT_LEAF)
    {
        return Err(OwnerError::Refused("custody binding"));
    }
    secure_socket(&record.socket)?;
    verify_cgroup(&record.cgroup, record.cgroup_dev, record.cgroup_ino)?;
    let token_bytes = read_private_file(&run_directory.join(OWNER_TOKEN_LEAF), 64)?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| OwnerError::Protocol("token utf8"))
        .and_then(parse_token)?;
    let checkpoint = Checkpoint::read(&record.checkpoint)
        .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
    if checkpoint.phase != CheckpointPhase::Live {
        return Err(OwnerError::Refused("checkpoint not live"));
    }
    if checkpoint.snapshot.budget != record.budget {
        return Err(OwnerError::Refused("custody budget"));
    }
    let mut remote = RemoteCustody {
        socket: record.socket,
        run_id: record.run_id,
        token,
        cgroup: record.cgroup,
        cgroup_dev: record.cgroup_dev,
        cgroup_ino: record.cgroup_ino,
        budget: record.budget,
        checkpoint: record.checkpoint,
        checkpoint_sequence: checkpoint.sequence,
    };
    remote.adopt()?;
    Checkpoint::read(&remote.checkpoint)
        .map_err(|_| OwnerError::Refused("adopted checkpoint unreadable"))
}

impl std::fmt::Debug for Custody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Custody")
            .field(
                "has_storage",
                &self.storage.lock().is_ok_and(|value| value.is_some()),
            )
            .finish_non_exhaustive()
    }
}

/// Run the separately supervised owner service at the configured socket.
pub fn owner_main() -> i32 {
    let Some(path) = std::env::var_os(OWNER_SOCKET_ENV).map(PathBuf::from) else {
        eprintln!("automonique temporary-storage owner refused: socket unavailable");
        return 1;
    };
    match run_owner(&path) {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("automonique temporary-storage owner refused: {error}");
            1
        }
    }
}

fn run_owner(path: &Path) -> Result<Never, OwnerError> {
    let parent = path
        .parent()
        .ok_or(OwnerError::Refused("socket parent missing"))?;
    private_directory(parent)?;
    // The lock is the authority to declare prior custody orphaned. Acquiring it
    // after recovery would let a second invocation mutate the live owner's
    // checkpoint and adoption material before learning that it is not owner.
    let owner_lock = owner_lock(parent)?;
    abort_orphaned_live_checkpoints()?;
    serve(path, owner_lock)
}

fn abort_orphaned_live_checkpoints() -> Result<(), OwnerError> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .ok_or(OwnerError::Refused("state unavailable"))?;
    abort_orphaned_live_checkpoints_at(&state_home.join("automonique/runs"))
}

fn abort_orphaned_live_checkpoints_at(runs: &Path) -> Result<(), OwnerError> {
    let entries = match fs::read_dir(runs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // Collect before mutating so an overfull or unreadable inventory refuses
    // startup without partially terminalizing an arbitrary prefix. Historical
    // directories can therefore make startup fail closed, never crowd a live
    // custody record out of reconciliation.
    let mut bounded = Vec::new();
    for entry in entries {
        if bounded.len() == MAX_RECOVERY_ENTRIES {
            return Err(OwnerError::Refused("recovery inventory exceeded"));
        }
        bounded.push(entry?);
    }
    for entry in bounded {
        let run = entry.path();
        if !entry
            .file_type()
            .is_ok_and(|file_type| file_type.is_dir() && !file_type.is_symlink())
            || private_directory(&run).is_err()
        {
            continue;
        }
        let Ok(record) = read_custody(&run.join(OWNER_CUSTODY_LEAF)) else {
            continue;
        };
        let Ok(token) = read_private_file(&run.join(OWNER_TOKEN_LEAF), 64) else {
            continue;
        };
        if parse_token(std::str::from_utf8(&token).unwrap_or_default()).is_err()
            || record.run_id != entry.file_name().to_string_lossy()
            || record.checkpoint != run.join(crate::CHECKPOINT_LEAF)
        {
            continue;
        }
        let path = run.join(crate::CHECKPOINT_LEAF);
        let Ok(checkpoint) = Checkpoint::read(&path) else {
            continue;
        };
        if checkpoint.phase != CheckpointPhase::Live {
            continue;
        }
        if checkpoint.snapshot.budget != record.budget {
            continue;
        }
        if write_aborted_final(&path, checkpoint).is_ok() {
            cleanup_custody_state(&path);
        }
    }
    Ok(())
}

enum Never {}

fn serve(path: &Path, _owner_lock: Flock<fs::File>) -> Result<Never, OwnerError> {
    if fs::symlink_metadata(path).is_ok() {
        secure_socket(path)?;
        if UnixStream::connect(path).is_ok() {
            return Err(OwnerError::Refused("owner already running"));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(OwnerError::Refused("socket ownership is unsafe"));
    }
    listener.set_nonblocking(true)?;
    let mut runs = BTreeMap::new();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let response = handle(stream, &mut runs);
                if let Err(error) = response {
                    // Stable category only: requests contain private paths and
                    // adoption tokens that must never enter service logs.
                    eprintln!(
                        "automonique temporary-storage owner request refused: {}",
                        category(&error)
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        tick(&mut runs);
        await_request(&listener, IDLE_TICK);
    }
}

/// Wait up to `timeout` for a request, instead of napping for it.
///
/// # Why this loop of all of them
///
/// This one is on the run's own critical path twice over. Opening a private
/// temporary-storage mount is a three-round-trip handshake through this socket,
/// and every checkpoint afterwards is another request; the client's own retry
/// (`OWNER_RETRY`) waits on this endpoint too. A blind nap therefore added most
/// of [`IDLE_TICK`] to each leg of setting a run up, and again to each
/// checkpoint, for a connection that was usually already there.
///
/// `crate::control::ControlServer::serve_once` has waited on its listener this
/// way from the start. This endpoint is the outlier, not the pattern.
///
/// # The bound is the tick, and it stays
///
/// [`tick`] runs once per iteration and is what advances every live run's
/// checkpoint cadence, so this bound is that cadence's ceiling. It is unchanged
/// deliberately: waiting on the socket must make requests arrive sooner without
/// making checkpoints arrive later, and a caller that ends the wait early only
/// ever ticks *more* often.
///
/// A failed wait degrades to the sleep it replaced rather than spinning, and an
/// interrupted one simply returns to the accept above.
fn await_request(listener: &UnixListener, timeout: Duration) {
    let milliseconds =
        u16::try_from(timeout.as_millis().clamp(1, u16::MAX.into())).unwrap_or(u16::MAX);
    let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::from(milliseconds)) {
        Ok(_) | Err(Errno::EINTR) => {}
        Err(_) => std::thread::sleep(timeout),
    }
}

fn owner_lock(parent: &Path) -> Result<Flock<fs::File>, OwnerError> {
    let path = parent.join(OWNER_LOCK_LEAF);
    let mut options = OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(OwnerError::Refused("owner lock"));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|_| OwnerError::Refused("owner already running"))
}

fn category(error: &OwnerError) -> &'static str {
    match error {
        OwnerError::Io(_) => "io",
        OwnerError::Protocol(_) => "protocol",
        OwnerError::Refused(_) => "refused",
    }
}

fn tick(runs: &mut BTreeMap<String, Custody>) {
    let mut finished = Vec::new();
    for (run_id, custody) in runs.iter_mut() {
        if custody.storage.lock().is_ok_and(|storage| {
            storage
                .as_ref()
                .is_none_or(NamespacedMountedTempfs::session_finished)
        }) {
            finished.push(run_id.clone());
        }
    }
    for run_id in finished {
        if let Some(custody) = runs.remove(&run_id) {
            let checkpoint = custody.checkpoint.clone();
            let storage = custody
                .storage
                .lock()
                .ok()
                .and_then(|mut storage| storage.take());
            if storage.is_some_and(|storage| storage.reconcile().is_ok()) {
                cleanup_custody_state(&checkpoint);
            } else if let Ok(durable) = Checkpoint::read(&checkpoint)
                && (durable.phase == CheckpointPhase::Final
                    || write_aborted_final(&checkpoint, durable).is_ok())
            {
                cleanup_custody_state(&checkpoint);
            }
        }
    }
}

fn start_checkpoint_ticker(
    storage: Arc<Mutex<Option<NamespacedMountedTempfs>>>,
    checkpoint: PathBuf,
) {
    let weak = Arc::downgrade(&storage);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(CHECKPOINT_INTERVAL);
            let Some(storage) = weak.upgrade() else {
                return;
            };
            let Ok(mut guard) = storage.lock() else {
                return;
            };
            let Some(mounted) = guard.as_mut() else {
                return;
            };
            if mounted.session_finished() {
                return;
            }
            if mounted
                .write_checkpoint(CheckpointPhase::Live, None)
                .is_err()
            {
                let failed = guard.take();
                drop(guard);
                if let Some(failed) = failed {
                    let _ = failed.reconcile();
                }
                if let Ok(durable) = Checkpoint::read(&checkpoint) {
                    let _ = write_aborted_final(&checkpoint, durable);
                }
                return;
            }
        }
    });
}

fn handle(mut stream: UnixStream, runs: &mut BTreeMap<String, Custody>) -> Result<(), OwnerError> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let peer = getsockopt(&stream, sockopt::PeerCredentials)
        .map_err(|error| OwnerError::Io(io::Error::from_raw_os_error(error as i32)))?;
    if peer.uid() != nix::unistd::geteuid().as_raw() {
        return Err(OwnerError::Refused("foreign peer"));
    }
    let (request, descriptors) = receive_request(&stream)?;
    let fields: Vec<&str> = request.split(' ').collect();
    if fields.first().copied() != Some(VERSION) {
        return Err(OwnerError::Protocol("version"));
    }
    match fields.get(1).copied() {
        Some("open") => open(&mut stream, &fields, descriptors, runs),
        Some("checkpoint") => checkpoint(&mut stream, &fields, descriptors, runs),
        Some("adopt") => adopt(&mut stream, &fields, descriptors, runs),
        Some("reconcile") => reconcile(&mut stream, &fields, descriptors, runs),
        _ => Err(OwnerError::Protocol("verb")),
    }
}

fn open(
    stream: &mut UnixStream,
    fields: &[&str],
    mut descriptors: Vec<OwnedFd>,
    runs: &mut BTreeMap<String, Custody>,
) -> Result<(), OwnerError> {
    if fields.len() != 12 || descriptors.len() != 2 {
        return Err(OwnerError::Protocol("open shape"));
    }
    if runs.len() >= MAX_RUNS {
        return Err(OwnerError::Refused("capacity"));
    }
    let sequence = parse_sequence(fields[2])?;
    if sequence != 1 {
        return Err(OwnerError::Protocol("open sequence"));
    }
    let run_id = decode_safe(fields[3], 64)?;
    let token = parse_token(fields[4])?;
    let cgroup = PathBuf::from(decode_path(fields[5])?);
    let cgroup_dev = parse_u64(fields[6])?;
    let cgroup_ino = parse_u64(fields[7])?;
    let bytes = parse_u64(fields[8])?;
    let objects = parse_u64(fields[9])?;
    let checkpoint = PathBuf::from(decode_path(fields[10])?);
    let namespace_uid = fields[11]
        .parse::<u32>()
        .map_err(|_| OwnerError::Protocol("uid"))?;
    if runs.contains_key(&run_id) {
        return Err(OwnerError::Refused("run already owned"));
    }
    verify_cgroup(&cgroup, cgroup_dev, cgroup_ino)?;
    verify_checkpoint_parent(&checkpoint)?;
    let budget =
        TemporaryStorageBudget::new(bytes, objects).map_err(|_| OwnerError::Protocol("budget"))?;
    let helper = UnixStream::from(descriptors.pop().expect("length checked"));
    let fuse = descriptors.pop().expect("length checked");
    let mut helper = helper;
    let storage = start_namespaced_tempfs(fuse, &mut helper, budget, namespace_uid, &checkpoint)
        .map_err(|_| OwnerError::Refused("mount setup"))?;
    let storage = Arc::new(Mutex::new(Some(storage)));
    start_checkpoint_ticker(Arc::clone(&storage), checkpoint.clone());
    runs.insert(
        run_id,
        Custody {
            token,
            cgroup,
            cgroup_dev,
            cgroup_ino,
            budget,
            checkpoint,
            storage,
        },
    );
    writeln!(stream, "{VERSION} ok {sequence} 1")?;
    Ok(())
}

fn checkpoint(
    stream: &mut UnixStream,
    fields: &[&str],
    descriptors: Vec<OwnedFd>,
    runs: &mut BTreeMap<String, Custody>,
) -> Result<(), OwnerError> {
    let (sequence, custody) = authenticated(fields, descriptors, runs)?;
    custody
        .storage
        .lock()
        .map_err(|_| OwnerError::Refused("storage poisoned"))?
        .as_mut()
        .ok_or(OwnerError::Refused("storage absent"))?
        .write_checkpoint(CheckpointPhase::Live, None)?;
    let checkpoint = Checkpoint::read(&custody.checkpoint)
        .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
    if checkpoint.sequence != sequence {
        return Err(OwnerError::Refused("checkpoint sequence"));
    }
    writeln!(stream, "{VERSION} ok {sequence} {}", checkpoint.sequence)?;
    Ok(())
}

fn adopt(
    stream: &mut UnixStream,
    fields: &[&str],
    descriptors: Vec<OwnedFd>,
    runs: &mut BTreeMap<String, Custody>,
) -> Result<(), OwnerError> {
    let (sequence, custody) = authenticated(fields, descriptors, runs)?;
    custody
        .storage
        .lock()
        .map_err(|_| OwnerError::Refused("storage poisoned"))?
        .as_mut()
        .ok_or(OwnerError::Refused("storage absent"))?
        .write_checkpoint(CheckpointPhase::Live, None)?;
    let checkpoint = Checkpoint::read(&custody.checkpoint)
        .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
    if checkpoint.sequence != sequence {
        return Err(OwnerError::Refused("checkpoint sequence"));
    }
    writeln!(
        stream,
        "{VERSION} adopted {sequence} {}",
        checkpoint.sequence
    )?;
    Ok(())
}

fn reconcile(
    stream: &mut UnixStream,
    fields: &[&str],
    descriptors: Vec<OwnedFd>,
    runs: &mut BTreeMap<String, Custody>,
) -> Result<(), OwnerError> {
    let (sequence, run_id) = authentication_identity(fields, descriptors)?;
    {
        let custody = runs.get(&run_id).ok_or(OwnerError::Refused("run absent"))?;
        authenticate(fields, custody)?;
        if !custody.storage.lock().is_ok_and(|storage| {
            storage
                .as_ref()
                .is_some_and(NamespacedMountedTempfs::session_finished)
        }) {
            return Err(OwnerError::Refused("run still mounted"));
        }
    }
    let custody = runs.remove(&run_id).expect("checked");
    let storage = custody
        .storage
        .lock()
        .map_err(|_| OwnerError::Refused("storage poisoned"))?
        .take()
        .ok_or(OwnerError::Refused("storage absent"))?;
    storage
        .reconcile()
        .map_err(|_| OwnerError::Refused("reconciliation"))?;
    let checkpoint = Checkpoint::read(&custody.checkpoint)
        .map_err(|_| OwnerError::Refused("final checkpoint unreadable"))?;
    if checkpoint.sequence != sequence {
        return Err(OwnerError::Refused("checkpoint sequence"));
    }
    writeln!(stream, "{VERSION} final {sequence} {}", checkpoint.sequence)?;
    cleanup_custody_state(&custody.checkpoint);
    Ok(())
}

fn authenticated<'a>(
    fields: &[&str],
    descriptors: Vec<OwnedFd>,
    runs: &'a mut BTreeMap<String, Custody>,
) -> Result<(u64, &'a mut Custody), OwnerError> {
    let (sequence, run_id) = authentication_identity(fields, descriptors)?;
    let custody = runs
        .get_mut(&run_id)
        .ok_or(OwnerError::Refused("run absent"))?;
    authenticate(fields, custody)?;
    Ok((sequence, custody))
}

fn authentication_identity(
    fields: &[&str],
    descriptors: Vec<OwnedFd>,
) -> Result<(u64, String), OwnerError> {
    if fields.len() != 10 || !descriptors.is_empty() {
        return Err(OwnerError::Protocol("request shape"));
    }
    Ok((parse_sequence(fields[2])?, decode_safe(fields[3], 64)?))
}

fn authenticate(fields: &[&str], custody: &Custody) -> Result<(), OwnerError> {
    let request_sequence = parse_sequence(fields[2])?;
    let token = parse_token(fields[4])?;
    let dev = parse_u64(fields[5])?;
    let ino = parse_u64(fields[6])?;
    let budget = TemporaryStorageBudget::new(parse_u64(fields[7])?, parse_u64(fields[8])?)
        .map_err(|_| OwnerError::Protocol("budget"))?;
    let checkpoint_sequence = parse_u64(fields[9])?;
    if token != custody.token || dev != custody.cgroup_dev || ino != custody.cgroup_ino {
        return Err(OwnerError::Refused("identity mismatch"));
    }
    if budget != custody.budget {
        return Err(OwnerError::Refused("budget mismatch"));
    }
    verify_cgroup(&custody.cgroup, dev, ino)?;
    let checkpoint = Checkpoint::read(&custody.checkpoint)
        .map_err(|_| OwnerError::Refused("checkpoint unreadable"))?;
    if checkpoint.snapshot.budget != custody.budget
        || !sequence_is_next(request_sequence, checkpoint_sequence, checkpoint.sequence)
        || checkpoint.phase != CheckpointPhase::Live
    {
        return Err(OwnerError::Refused("checkpoint fence"));
    }
    Ok(())
}

fn sequence_is_next(request: u64, fence: u64, durable: u64) -> bool {
    durable == fence && fence.checked_add(1) == Some(request)
}

fn verify_cgroup(path: &Path, dev: u64, ino: u64) -> Result<(), OwnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.dev() != dev
        || metadata.ino() != ino
    {
        return Err(OwnerError::Refused("cgroup identity"));
    }
    Ok(())
}

fn verify_checkpoint_parent(path: &Path) -> Result<(), OwnerError> {
    if !path.is_absolute() {
        return Err(OwnerError::Refused("checkpoint path"));
    }
    let parent = path
        .parent()
        .ok_or(OwnerError::Refused("checkpoint parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(OwnerError::Refused("checkpoint parent"));
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<(), OwnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(OwnerError::Refused("socket parent"));
    }
    Ok(())
}

fn secure_socket(path: &Path) -> Result<(), OwnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(OwnerError::Refused("owner socket"));
    }
    Ok(())
}

fn create_token(path: &Path) -> Result<String, OwnerError> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let token = encode_hex(&bytes);
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(token)
}

fn cleanup_unaccepted(token: &Path, custody: &Path) {
    let _ = fs::remove_file(custody);
    let _ = fs::remove_file(token);
}

fn cleanup_custody_state(checkpoint: &Path) {
    if let Some(parent) = checkpoint.parent() {
        let _ = fs::remove_file(parent.join(OWNER_CUSTODY_LEAF));
        let _ = fs::remove_file(parent.join(OWNER_TOKEN_LEAF));
    }
}

fn write_aborted_final(path: &Path, checkpoint: Checkpoint) -> Result<(), OwnerError> {
    let statfs = crate::StatfsReadback::from_ledger(&checkpoint.snapshot)
        .map_err(|_| OwnerError::Refused("checkpoint ledger"))?;
    let sequence = checkpoint
        .sequence
        .checked_add(1)
        .ok_or(OwnerError::Refused("sequence exhausted"))?;
    Checkpoint {
        sequence,
        at_millis: crate::tempfs_checkpoint::now_millis(),
        phase: CheckpointPhase::Final,
        snapshot: checkpoint.snapshot,
        mount_evidence: checkpoint.mount_evidence,
        statfs_at_mount: checkpoint.statfs_at_mount,
        final_record: Some(crate::FinalRecord {
            statfs_before_unmount: Some(statfs),
            unmount_confirmed: false,
            aborted: true,
        }),
    }
    .write(path)
    .map_err(OwnerError::Io)
}

fn write_custody(path: &Path, record: &CustodyRecord) -> Result<(), OwnerError> {
    let request = format!(
        "{VERSION} custody {} {} {} {} {} {} {} {}\n",
        encode_hex(record.run_id.as_bytes()),
        encode_hex(record.socket.as_os_str().as_encoded_bytes()),
        encode_hex(record.cgroup.as_os_str().as_encoded_bytes()),
        record.cgroup_dev,
        record.cgroup_ino,
        record.budget.bytes(),
        record.budget.objects(),
        encode_hex(record.checkpoint.as_os_str().as_encoded_bytes()),
    );
    if request.len() > MAX_REQUEST_BYTES {
        return Err(OwnerError::Protocol("custody bound"));
    }
    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(request.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn read_custody(path: &Path) -> Result<CustodyRecord, OwnerError> {
    let bytes = read_private_file(path, MAX_REQUEST_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| OwnerError::Protocol("custody utf8"))?;
    let fields: Vec<&str> = text
        .strip_suffix('\n')
        .ok_or(OwnerError::Protocol("custody frame"))?
        .split(' ')
        .collect();
    if fields.len() != 10 || fields[0] != VERSION || fields[1] != "custody" {
        return Err(OwnerError::Protocol("custody shape"));
    }
    Ok(CustodyRecord {
        run_id: decode_safe(fields[2], 64)?,
        socket: PathBuf::from(decode_path(fields[3])?),
        cgroup: PathBuf::from(decode_path(fields[4])?),
        cgroup_dev: parse_u64(fields[5])?,
        cgroup_ino: parse_u64(fields[6])?,
        budget: TemporaryStorageBudget::new(parse_u64(fields[7])?, parse_u64(fields[8])?)
            .map_err(|_| OwnerError::Protocol("budget"))?,
        checkpoint: PathBuf::from(decode_path(fields[9])?),
    })
}

fn read_private_file(path: &Path, limit: usize) -> Result<Vec<u8>, OwnerError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > limit as u64
    {
        return Err(OwnerError::Refused("private state"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(OwnerError::Refused("private state bound"));
    }
    Ok(bytes)
}

fn read_response(
    stream: &mut UnixStream,
    disposition: &str,
    sequence: u64,
) -> Result<u64, OwnerError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() == 255 {
            return Err(OwnerError::Protocol("response bound"));
        }
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| OwnerError::Protocol("response utf8"))?;
    let fields: Vec<&str> = text.split(' ').collect();
    if fields.len() != 4
        || fields[0] != VERSION
        || fields[1] != disposition
        || parse_sequence(fields[2])? != sequence
    {
        return Err(OwnerError::Protocol("response shape"));
    }
    parse_sequence(fields[3])
}

fn receive_request(stream: &UnixStream) -> Result<(String, Vec<OwnedFd>), OwnerError> {
    let mut bytes = [0_u8; MAX_REQUEST_BYTES + 1];
    let mut descriptors = Vec::new();
    let mut total = 0;
    loop {
        let (read, flags) = {
            let mut vectors = [IoSliceMut::new(&mut bytes[total..])];
            let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let received = recvmsg(
                stream,
                &mut vectors,
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            )
            .map_err(|error| OwnerError::Io(error.into()))?;
            for message in ancillary.drain() {
                let RecvAncillaryMessage::ScmRights(rights) = message else {
                    return Err(OwnerError::Protocol("ancillary"));
                };
                descriptors.extend(rights);
            }
            (received.bytes, received.flags)
        };
        if read == 0
            || flags.contains(ReturnFlags::CTRUNC)
            || flags.contains(ReturnFlags::TRUNC)
            || descriptors.len() > 2
        {
            return Err(OwnerError::Protocol("frame"));
        }
        total += read;
        if total > MAX_REQUEST_BYTES {
            return Err(OwnerError::Protocol("frame"));
        }
        if let Some(newline) = bytes[..total].iter().position(|byte| *byte == b'\n') {
            if newline + 1 != total {
                return Err(OwnerError::Protocol("frame"));
            }
            break;
        }
    }
    let request = std::str::from_utf8(&bytes[..total - 1])
        .map_err(|_| OwnerError::Protocol("utf8"))?
        .to_owned();
    Ok((request, descriptors))
}

pub(crate) fn send_request(
    stream: &UnixStream,
    request: &[u8],
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), OwnerError> {
    if request.is_empty() || request.len() > MAX_REQUEST_BYTES || request.last() != Some(&b'\n') {
        return Err(OwnerError::Protocol("outbound frame"));
    }
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(OwnerError::Protocol("outbound descriptors"));
    }
    let vectors = [IoSlice::new(request)];
    let sent = sendmsg(stream, &vectors, &mut ancillary, SendFlags::NOSIGNAL)
        .map_err(|error| OwnerError::Io(error.into()))?;
    if sent != request.len() {
        return Err(OwnerError::Protocol("partial send"));
    }
    Ok(())
}

fn parse_sequence(value: &str) -> Result<u64, OwnerError> {
    let sequence = parse_u64(value)?;
    if sequence == 0 {
        return Err(OwnerError::Protocol("sequence"));
    }
    Ok(sequence)
}

fn parse_u64(value: &str) -> Result<u64, OwnerError> {
    value.parse().map_err(|_| OwnerError::Protocol("integer"))
}

fn parse_token(value: &str) -> Result<String, OwnerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OwnerError::Protocol("token"));
    }
    Ok(value.to_owned())
}

fn decode_safe(value: &str, limit: usize) -> Result<String, OwnerError> {
    let decoded = decode_hex(value, limit)?;
    if decoded.is_empty()
        || !decoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(OwnerError::Protocol("identifier"));
    }
    Ok(decoded)
}

fn decode_path(value: &str) -> Result<String, OwnerError> {
    let decoded = decode_hex(value, 1024)?;
    if decoded.as_bytes().contains(&0) {
        return Err(OwnerError::Protocol("path"));
    }
    Ok(decoded)
}

fn decode_hex(value: &str, limit: usize) -> Result<String, OwnerError> {
    if !value.len().is_multiple_of(2) || value.len() > limit.saturating_mul(2) {
        return Err(OwnerError::Protocol("hex"));
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| OwnerError::Protocol("hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| OwnerError::Protocol("hex"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| OwnerError::Protocol("utf8"))
}

pub(crate) fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn outcome_from_final(checkpoint: &Checkpoint) -> Result<NamespacedOutcome, OwnerError> {
    if checkpoint.phase != CheckpointPhase::Final {
        return Err(OwnerError::Refused("not final"));
    }
    let final_record = checkpoint
        .final_record
        .as_ref()
        .ok_or(OwnerError::Refused("final record"))?;
    let statfs = final_record
        .statfs_before_unmount
        .ok_or(OwnerError::Refused("final statfs"))?;
    Ok(NamespacedOutcome {
        ledger: checkpoint.snapshot.clone(),
        statfs_at_mount: checkpoint.statfs_at_mount,
        statfs_from_ledger: statfs,
        unmount_confirmed: final_record.unmount_confirmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempfs_ledger::Ledger;

    fn private_directory_at(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn live_checkpoint(path: &Path, sequence: u64) {
        let ledger = Ledger::new(TemporaryStorageBudget::new(8192, 8).unwrap()).snapshot();
        let statfs = crate::StatfsReadback::from_ledger(&ledger).unwrap();
        Checkpoint {
            sequence,
            at_millis: 1,
            phase: CheckpointPhase::Live,
            snapshot: ledger,
            mount_evidence: "automonique.namespaced-tempfs/v1 fstype=fuse.automonique-tempfs"
                .to_owned(),
            statfs_at_mount: statfs,
            final_record: None,
        }
        .write(path)
        .unwrap();
    }

    #[test]
    fn tokens_and_identifiers_are_closed_and_debug_is_redacted() {
        assert!(parse_token(&"a".repeat(64)).is_ok());
        assert!(parse_token(&"A".repeat(64)).is_err());
        assert!(decode_safe(&encode_hex(b"run-1"), 64).is_ok());
        assert!(decode_safe(&encode_hex(b"../run"), 64).is_err());
        let error = OwnerError::Refused("identity mismatch");
        assert!(!format!("{error:?}").contains(&"a".repeat(64)));
        let remote = RemoteCustody {
            socket: PathBuf::from("/secret/socket"),
            run_id: "secret-run".to_owned(),
            token: "a".repeat(64),
            cgroup: PathBuf::from("/secret/cgroup"),
            cgroup_dev: 1,
            cgroup_ino: 2,
            budget: TemporaryStorageBudget::new(8192, 8).unwrap(),
            checkpoint: PathBuf::from("/secret/checkpoint"),
            checkpoint_sequence: 3,
        };
        let debug = format!("{remote:?}");
        let token = "a".repeat(64);
        for secret in ["secret", token.as_str()] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn protocol_frames_are_bounded_and_versioned() {
        let (left, right) = UnixStream::pair().unwrap();
        let request = format!(
            "{VERSION} adopt 1 {} {} 1 2 8192 8 3\n",
            encode_hex(b"run"),
            "a".repeat(64)
        );
        send_request(&left, request.as_bytes(), &[]).unwrap();
        let (decoded, descriptors) = receive_request(&right).unwrap();
        assert_eq!(decoded, request.trim_end());
        assert!(descriptors.is_empty());
    }

    #[test]
    fn request_sequence_is_exactly_the_next_durable_checkpoint() {
        assert!(sequence_is_next(8, 7, 7));
        assert!(!sequence_is_next(7, 7, 7));
        assert!(!sequence_is_next(9, 7, 7));
        assert!(!sequence_is_next(8, 6, 7));
        assert!(!sequence_is_next(u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn exhausted_live_checkpoint_is_never_rewritten_as_a_non_monotonic_final() {
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = directory.path().join("checkpoint");
        live_checkpoint(&checkpoint, u64::MAX);

        let durable = Checkpoint::read(&checkpoint).unwrap();
        assert!(matches!(
            write_aborted_final(&checkpoint, durable),
            Err(OwnerError::Refused("sequence exhausted"))
        ));
        let unchanged = Checkpoint::read(&checkpoint).unwrap();
        assert_eq!(unchanged.phase, CheckpointPhase::Live);
        assert_eq!(unchanged.sequence, u64::MAX);
    }

    #[test]
    fn owner_restart_finds_live_custody_after_more_than_sixty_four_historical_runs() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        private_directory_at(&runs);
        for index in 0..80 {
            private_directory_at(&runs.join(format!("historical-{index:03}")));
        }
        let run = runs.join("run-1");
        private_directory_at(&run);
        let cgroup = temporary.path().join("cgroup");
        private_directory_at(&cgroup);
        let checkpoint = run.join(crate::CHECKPOINT_LEAF);
        live_checkpoint(&checkpoint, 7);
        create_token(&run.join(OWNER_TOKEN_LEAF)).unwrap();
        write_custody(
            &run.join(OWNER_CUSTODY_LEAF),
            &CustodyRecord {
                run_id: "run-1".to_owned(),
                socket: temporary.path().join("owner.sock"),
                cgroup,
                cgroup_dev: 1,
                cgroup_ino: 2,
                budget: TemporaryStorageBudget::new(8192, 8).unwrap(),
                checkpoint: checkpoint.clone(),
            },
        )
        .unwrap();

        abort_orphaned_live_checkpoints_at(&runs).unwrap();

        let final_checkpoint = Checkpoint::read(&checkpoint).unwrap();
        assert_eq!(final_checkpoint.phase, CheckpointPhase::Final);
        assert_eq!(final_checkpoint.sequence, 8);
        let final_record = final_checkpoint.final_record.unwrap();
        assert!(final_record.aborted);
        assert!(!final_record.unmount_confirmed);
        assert!(!run.join(OWNER_TOKEN_LEAF).exists());
        assert!(!run.join(OWNER_CUSTODY_LEAF).exists());
    }

    #[test]
    fn overfull_recovery_inventory_refuses_before_mutating_live_custody() {
        let temporary = tempfile::tempdir().unwrap();
        let runs = temporary.path().join("runs");
        private_directory_at(&runs);
        let run = runs.join("run-1");
        private_directory_at(&run);
        let cgroup = temporary.path().join("cgroup");
        private_directory_at(&cgroup);
        let checkpoint = run.join(crate::CHECKPOINT_LEAF);
        live_checkpoint(&checkpoint, 7);
        create_token(&run.join(OWNER_TOKEN_LEAF)).unwrap();
        write_custody(
            &run.join(OWNER_CUSTODY_LEAF),
            &CustodyRecord {
                run_id: "run-1".to_owned(),
                socket: temporary.path().join("owner.sock"),
                cgroup,
                cgroup_dev: 1,
                cgroup_ino: 2,
                budget: TemporaryStorageBudget::new(8192, 8).unwrap(),
                checkpoint: checkpoint.clone(),
            },
        )
        .unwrap();
        for index in 0..MAX_RECOVERY_ENTRIES {
            private_directory_at(&runs.join(format!("historical-{index:04}")));
        }

        assert!(matches!(
            abort_orphaned_live_checkpoints_at(&runs),
            Err(OwnerError::Refused("recovery inventory exceeded"))
        ));
        let unchanged = Checkpoint::read(&checkpoint).unwrap();
        assert_eq!(unchanged.phase, CheckpointPhase::Live);
        assert_eq!(unchanged.sequence, 7);
        assert!(run.join(OWNER_TOKEN_LEAF).exists());
        assert!(run.join(OWNER_CUSTODY_LEAF).exists());
    }

    #[test]
    fn restarted_client_adopts_the_live_owner_with_the_next_durable_sequence() {
        let temporary = tempfile::tempdir().unwrap();
        let run = temporary.path().join("run-1");
        private_directory_at(&run);
        let cgroup = temporary.path().join("cgroup");
        private_directory_at(&cgroup);
        let cgroup_metadata = fs::symlink_metadata(&cgroup).unwrap();
        let checkpoint = run.join(crate::CHECKPOINT_LEAF);
        let budget = TemporaryStorageBudget::new(8192, 8).unwrap();
        let storage = crate::tempfs::namespaced_owner_fixture(&checkpoint, budget);
        let storage = Arc::new(Mutex::new(Some(storage)));
        let storage_witness = Arc::clone(&storage);
        let token = create_token(&run.join(OWNER_TOKEN_LEAF)).unwrap();
        let socket = temporary.path().join("owner.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        write_custody(
            &run.join(OWNER_CUSTODY_LEAF),
            &CustodyRecord {
                run_id: "run-1".to_owned(),
                socket: socket.clone(),
                cgroup: cgroup.clone(),
                cgroup_dev: cgroup_metadata.dev(),
                cgroup_ino: cgroup_metadata.ino(),
                budget,
                checkpoint: checkpoint.clone(),
            },
        )
        .unwrap();
        let mut runs = BTreeMap::from([(
            "run-1".to_owned(),
            Custody {
                token: token.clone(),
                cgroup: cgroup.clone(),
                cgroup_dev: cgroup_metadata.dev(),
                cgroup_ino: cgroup_metadata.ino(),
                budget,
                checkpoint: checkpoint.clone(),
                storage,
            },
        )]);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, &mut runs).unwrap();
            runs
        });
        let adopted = adopt_run(&run).unwrap();

        assert_eq!(adopted.sequence, 2);
        assert_eq!(adopted.snapshot.budget, budget);
        let retained = server.join().unwrap();
        assert_eq!(retained.len(), 1);
        assert!(Arc::ptr_eq(
            &retained.get("run-1").unwrap().storage,
            &storage_witness
        ));
    }

    #[test]
    fn owner_socket_requires_the_exact_private_mode_and_no_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("owner.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(secure_socket(&socket).is_ok());
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(secure_socket(&socket).is_err());
        let link = temporary.path().join("owner-link.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        assert!(secure_socket(&link).is_err());
    }

    #[test]
    fn owner_process_lock_refuses_a_second_live_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = temporary.path().join("runtime");
        private_directory_at(&runtime);
        let first = owner_lock(&runtime).unwrap();
        assert!(owner_lock(&runtime).is_err());
        drop(first);
        assert!(owner_lock(&runtime).is_ok());
    }
}
