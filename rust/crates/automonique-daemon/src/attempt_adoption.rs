// SPDX-License-Identifier: Elastic-2.0

//! Private cross-generation route to attempts still hosted by a source daemon.
//!
//! A reload does not move a worker thread or its process-owned cancellation
//! token into the candidate. Instead, the source publishes this bounded local
//! endpoint for as long as those workers remain live. A successor inventories
//! exact attempt identifiers and forwards cancellation to the same
//! [`DaemonAttemptHost`](crate::attempt_host::DaemonAttemptHost) that already
//! owns their sinks. The endpoint is routing, not ownership: its identity is
//! bound to the source holder and lease epoch, and every delivery still passes
//! through durable cancellation custody.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_runner::dispatch::DispatchOutcome;
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};

use crate::attempt_host::DaemonAttemptHost;

const SCHEMA: &str = "automonique.attempt-adoption/v1";
const MAX_LINE_BYTES: u64 = 16 * 1024;
const MAX_SOCKET_PATH_BYTES: usize = 107;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const SOCKET_PREFIX: &str = "attempt-host-";
const SOCKET_SUFFIX: &str = ".sock";

/// Holder-specific endpoint path beneath the already-private runtime directory.
pub fn socket_path(runtime_dir: &Path, holder_id: &str) -> Result<PathBuf, AttemptAdoptionError> {
    validate_identifier(holder_id, "holder_id")?;
    let path = runtime_dir.join(format!("{SOCKET_PREFIX}{holder_id}{SOCKET_SUFFIX}"));
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES
    {
        return Err(AttemptAdoptionError::InvalidField("socket_path"));
    }
    Ok(path)
}

#[derive(Debug)]
pub enum AttemptAdoptionError {
    InvalidField(&'static str),
    UnsafeSocket,
    SocketInUse,
    PeerDenied,
    Protocol,
    HostUnavailable,
    AlreadyStarted,
    WorkerPanicked,
    Io(std::io::Error),
}

impl AttemptAdoptionError {
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidField(_) => "attempt_adoption_invalid_field",
            Self::UnsafeSocket => "attempt_adoption_unsafe_socket",
            Self::SocketInUse => "attempt_adoption_socket_in_use",
            Self::PeerDenied => "attempt_adoption_peer_denied",
            Self::Protocol => "attempt_adoption_protocol",
            Self::HostUnavailable => "attempt_adoption_host_unavailable",
            Self::AlreadyStarted => "attempt_adoption_already_started",
            Self::WorkerPanicked => "attempt_adoption_worker_panicked",
            Self::Io(_) => "attempt_adoption_io",
        }
    }
}

impl fmt::Display for AttemptAdoptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl Error for AttemptAdoptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AttemptAdoptionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptHostInventory {
    pub holder_id: String,
    pub lease_epoch: u64,
    pub attempt_ids: Vec<String>,
}

/// Exact private route a warmed successor must bind before trusting replies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptHostRoute {
    pub socket_path: PathBuf,
    pub holder_id: String,
    pub lease_epoch: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    operation: Operation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Inventory,
    Cancel {
        attempt_id: String,
        request_ref: String,
        observed_sequence: u64,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: String,
    holder_id: String,
    lease_epoch: u64,
    answer: Answer,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
enum Answer {
    Inventory { attempt_ids: Vec<String> },
    Cancel { outcome: String },
    Refused { category: String },
}

/// Source-generation endpoint backed by its one live attempt host.
pub struct AttemptAdoptionEndpoint {
    listener: Option<UnixListener>,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    holder_id: String,
    lease_epoch: u64,
    host: Arc<DaemonAttemptHost>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl AttemptAdoptionEndpoint {
    pub fn bind(
        socket_path: impl Into<PathBuf>,
        holder_id: &str,
        lease_epoch: u64,
        host: Arc<DaemonAttemptHost>,
    ) -> Result<Self, AttemptAdoptionError> {
        validate_identifier(holder_id, "holder_id")?;
        if lease_epoch == 0 {
            return Err(AttemptAdoptionError::InvalidField("lease_epoch"));
        }
        let socket_path = socket_path.into();
        if !socket_path.is_absolute()
            || socket_path.file_name().is_none()
            || socket_path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES
        {
            return Err(AttemptAdoptionError::InvalidField("socket_path"));
        }
        let uid = geteuid().as_raw();
        if uid == 0 {
            return Err(AttemptAdoptionError::UnsafeSocket);
        }
        prepare_socket_path(&socket_path, uid)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(AttemptAdoptionError::UnsafeSocket);
        }
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener: Some(listener),
            socket_path,
            socket_identity: (metadata.dev(), metadata.ino()),
            holder_id: holder_id.to_owned(),
            lease_epoch,
            host,
            stop: Arc::new(AtomicBool::new(false)),
            accept: None,
        })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn route(&self) -> AttemptHostRoute {
        AttemptHostRoute {
            socket_path: self.socket_path.clone(),
            holder_id: self.holder_id.clone(),
            lease_epoch: self.lease_epoch,
        }
    }

    pub fn start(&mut self) -> Result<(), AttemptAdoptionError> {
        if self.accept.is_some() {
            return Err(AttemptAdoptionError::AlreadyStarted);
        }
        let listener = self
            .listener
            .take()
            .ok_or(AttemptAdoptionError::AlreadyStarted)?;
        let holder_id = self.holder_id.clone();
        let lease_epoch = self.lease_epoch;
        let host = Arc::clone(&self.host);
        let stop = Arc::clone(&self.stop);
        self.accept = Some(std::thread::spawn(move || {
            accept_loop(&listener, &holder_id, lease_epoch, &host, &stop);
        }));
        Ok(())
    }

    /// Rebind this source-owned route at a newly returned lease epoch.
    ///
    /// The old accept loop is joined before its exact inode is removed. The
    /// replacement retains the same holder and attempt host, but answers only
    /// at the new fence, so no cancellation client can mistake an E route for
    /// the source's returned E+2 authority.
    pub(crate) fn retarget(&mut self, lease_epoch: u64) -> Result<(), AttemptAdoptionError> {
        if lease_epoch == 0 || lease_epoch == self.lease_epoch {
            return Err(AttemptAdoptionError::InvalidField("lease_epoch"));
        }
        let was_started = self.accept.is_some();
        self.stop.store(true, Ordering::Release);
        if let Some(accept) = self.accept.take() {
            accept
                .join()
                .map_err(|_| AttemptAdoptionError::WorkerPanicked)?;
        }
        drop(self.listener.take());
        remove_socket_if_identity(&self.socket_path, self.socket_identity);
        // The filesystem may immediately reuse the removed inode for the
        // replacement below. Disarm the old Drop guard before rebinding so it
        // cannot mistake that reuse for the endpoint it used to own.
        self.socket_identity = (0, 0);

        let mut replacement = Self::bind(
            self.socket_path.clone(),
            &self.holder_id,
            lease_epoch,
            Arc::clone(&self.host),
        )?;
        if was_started {
            replacement.start()?;
        }
        *self = replacement;
        Ok(())
    }

    pub(crate) fn begin_shutdown(mut self) -> Option<JoinHandle<()>> {
        self.stop.store(true, Ordering::Release);
        self.accept.take()
    }
}

impl Drop for AttemptAdoptionEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        remove_socket_if_identity(&self.socket_path, self.socket_identity);
    }
}

/// Authenticated client pinned to one source holder and epoch.
pub struct AttemptAdoptionClient {
    socket_path: PathBuf,
    holder_id: String,
    lease_epoch: u64,
}

impl AttemptAdoptionClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        holder_id: &str,
        lease_epoch: u64,
    ) -> Result<Self, AttemptAdoptionError> {
        validate_identifier(holder_id, "holder_id")?;
        if lease_epoch == 0 {
            return Err(AttemptAdoptionError::InvalidField("lease_epoch"));
        }
        let socket_path = socket_path.into();
        if !socket_path.is_absolute()
            || socket_path.file_name().is_none()
            || socket_path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES
        {
            return Err(AttemptAdoptionError::InvalidField("socket_path"));
        }
        Ok(Self {
            socket_path,
            holder_id: holder_id.to_owned(),
            lease_epoch,
        })
    }

    pub fn inventory(&self) -> Result<AttemptHostInventory, AttemptAdoptionError> {
        let response = self.exchange(&Request {
            schema: SCHEMA.to_owned(),
            operation: Operation::Inventory,
        })?;
        match response.answer {
            Answer::Inventory { attempt_ids } => Ok(AttemptHostInventory {
                holder_id: response.holder_id,
                lease_epoch: response.lease_epoch,
                attempt_ids,
            }),
            Answer::Refused { .. } => Err(AttemptAdoptionError::HostUnavailable),
            Answer::Cancel { .. } => Err(AttemptAdoptionError::Protocol),
        }
    }

    pub fn cancel(
        &self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: u64,
    ) -> Result<DispatchOutcome, AttemptAdoptionError> {
        validate_identifier(attempt_id, "attempt_id")?;
        validate_identifier(request_ref, "request_ref")?;
        let response = self.exchange(&Request {
            schema: SCHEMA.to_owned(),
            operation: Operation::Cancel {
                attempt_id: attempt_id.to_owned(),
                request_ref: request_ref.to_owned(),
                observed_sequence,
            },
        })?;
        match response.answer {
            Answer::Cancel { outcome } => parse_outcome(&outcome),
            Answer::Refused { .. } => Err(AttemptAdoptionError::HostUnavailable),
            Answer::Inventory { .. } => Err(AttemptAdoptionError::Protocol),
        }
    }

    fn exchange(&self, request: &Request) -> Result<Response, AttemptAdoptionError> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        write_message(&mut stream, request)?;
        let response: Response = read_message(&mut stream)?;
        if response.schema != SCHEMA
            || response.holder_id != self.holder_id
            || response.lease_epoch != self.lease_epoch
        {
            return Err(AttemptAdoptionError::Protocol);
        }
        Ok(response)
    }
}

fn accept_loop(
    listener: &UnixListener,
    holder_id: &str,
    lease_epoch: u64,
    host: &Arc<DaemonAttemptHost>,
    stop: &AtomicBool,
) {
    let uid = geteuid().as_raw();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                if !admit_peer(&stream, uid) {
                    continue;
                }
                let answer = read_message::<Request>(&mut stream)
                    .and_then(|request| answer(request, holder_id, lease_epoch, host));
                let response = answer.unwrap_or_else(|error| Response {
                    schema: SCHEMA.to_owned(),
                    holder_id: holder_id.to_owned(),
                    lease_epoch,
                    answer: Answer::Refused {
                        category: error.category().to_owned(),
                    },
                });
                let _ = write_message(&mut stream, &response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

fn answer(
    request: Request,
    holder_id: &str,
    lease_epoch: u64,
    host: &DaemonAttemptHost,
) -> Result<Response, AttemptAdoptionError> {
    if request.schema != SCHEMA {
        return Err(AttemptAdoptionError::Protocol);
    }
    let answer = match request.operation {
        Operation::Inventory => Answer::Inventory {
            attempt_ids: host
                .registered_attempts()
                .map_err(|_| AttemptAdoptionError::HostUnavailable)?,
        },
        Operation::Cancel {
            attempt_id,
            request_ref,
            observed_sequence,
        } => {
            validate_identifier(&attempt_id, "attempt_id")?;
            validate_identifier(&request_ref, "request_ref")?;
            Answer::Cancel {
                outcome: host
                    .cancel(&attempt_id, &request_ref, observed_sequence)
                    .as_str()
                    .to_owned(),
            }
        }
    };
    Ok(Response {
        schema: SCHEMA.to_owned(),
        holder_id: holder_id.to_owned(),
        lease_epoch,
        answer,
    })
}

fn parse_outcome(value: &str) -> Result<DispatchOutcome, AttemptAdoptionError> {
    match value {
        "delivered" => Ok(DispatchOutcome::Delivered),
        "already_delivered" => Ok(DispatchOutcome::AlreadyDelivered),
        "conflict" => Ok(DispatchOutcome::Conflict),
        "unknown_attempt" => Ok(DispatchOutcome::UnknownAttempt),
        "sink_unavailable" => Ok(DispatchOutcome::SinkUnavailable),
        "custody_full" => Ok(DispatchOutcome::CustodyFull),
        "custody_unavailable" => Ok(DispatchOutcome::CustodyUnavailable),
        "field_invalid" => Ok(DispatchOutcome::FieldInvalid),
        _ => Err(AttemptAdoptionError::Protocol),
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), AttemptAdoptionError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(AttemptAdoptionError::InvalidField(field));
    }
    Ok(())
}

fn write_message(
    writer: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), AttemptAdoptionError> {
    let encoded = serde_json::to_vec(value).map_err(|_| AttemptAdoptionError::Protocol)?;
    if encoded.is_empty() || encoded.len() as u64 >= MAX_LINE_BYTES {
        return Err(AttemptAdoptionError::Protocol);
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_message<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, AttemptAdoptionError> {
    let mut line = Vec::new();
    let read = BufReader::new(reader)
        .take(MAX_LINE_BYTES)
        .read_until(b'\n', &mut line)?;
    if read == 0 || read as u64 == MAX_LINE_BYTES || line.last() != Some(&b'\n') {
        return Err(AttemptAdoptionError::Protocol);
    }
    line.pop();
    serde_json::from_slice(&line).map_err(|_| AttemptAdoptionError::Protocol)
}

fn admit_peer(stream: &UnixStream, uid: u32) -> bool {
    getsockopt(stream, sockopt::PeerCredentials).is_ok_and(|credentials| {
        credentials.pid() > 0 && credentials.uid() != 0 && credentials.uid() == uid
    })
}

fn prepare_socket_path(path: &Path, uid: u32) -> Result<(), AttemptAdoptionError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(AttemptAdoptionError::UnsafeSocket);
    }
    let identity = (metadata.dev(), metadata.ino());
    match UnixStream::connect(path) {
        Ok(_) => Err(AttemptAdoptionError::SocketInUse),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.uid() != uid
                || current.mode() & 0o7777 != 0o600
                || current.nlink() != 1
                || (current.dev(), current.ino()) != identity
            {
                return Err(AttemptAdoptionError::UnsafeSocket);
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) => Err(AttemptAdoptionError::Io(error)),
    }
}

fn remove_socket_if_identity(path: &Path, identity: (u64, u64)) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket()
        && metadata.uid() == geteuid().as_raw()
        && metadata.mode() & 0o7777 == 0o600
        && (metadata.dev(), metadata.ino()) == identity
    {
        let _ = fs::remove_file(path);
    }
}
