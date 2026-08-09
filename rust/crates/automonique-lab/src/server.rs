// SPDX-License-Identifier: Elastic-2.0

//! Local, same-UID, exactly-one-frame Unix protocol server.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::Uid;

use crate::canonical_json::{
    CanonicalJsonError, TransportErrorCode, TransportErrorDocument, decode_request,
    encode_response, encode_transport_error,
};
use crate::controller::{ControllerError, LabController, SyntheticBuildBroker};
use crate::framing::{FRAME_PREFIX_BYTES, FrameLimits, decode_frame, encode_frame};
use crate::protocol::{LabRequest, LabResponse};

const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub trait LabHandler {
    fn handle_request(&mut self, request: LabRequest) -> Result<LabResponse, ControllerError>;
}

impl<B: SyntheticBuildBroker> LabHandler for LabController<B> {
    fn handle_request(&mut self, request: LabRequest) -> Result<LabResponse, ControllerError> {
        self.handle(request)
    }
}

#[derive(Clone, Debug)]
pub struct UnixServerConfig {
    pub socket_path: PathBuf,
    pub frame_limits: FrameLimits,
    pub io_timeout: Duration,
}

#[derive(Debug)]
pub enum ServerError {
    UnsafePath(&'static str),
    InvalidTimeout,
    Io(io::Error),
    PeerDenied,
    Protocol,
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath(_) => "unsafe Unix socket path",
            Self::InvalidTimeout => "invalid server I/O timeout",
            Self::Io(_) => "Unix server I/O failed",
            Self::PeerDenied => "Unix peer was denied",
            Self::Protocol => "Unix protocol request failed",
        })
    }
}

impl Error for ServerError {}

impl From<io::Error> for ServerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct UnixLabServer<H> {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    config: UnixServerConfig,
    handler: H,
}

impl<H: LabHandler> UnixLabServer<H> {
    pub fn bind(config: UnixServerConfig, handler: H) -> Result<Self, ServerError> {
        if config.io_timeout.is_zero() || config.io_timeout > Duration::from_secs(60) {
            return Err(ServerError::InvalidTimeout);
        }
        let socket_path = secure_socket_path(&config.socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(&socket_path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ServerError::UnsafePath(
                "socket ownership or mode is unsafe",
            ));
        }
        let socket_identity = (metadata.dev(), metadata.ino());
        Ok(Self {
            listener,
            socket_path,
            socket_identity,
            config,
            handler,
        })
    }

    pub fn serve_once(&mut self) -> Result<(), ServerError> {
        let (stream, _) = self.listener.accept()?;
        self.handle_stream(stream)
    }

    pub fn serve_until(&mut self, stop: &AtomicBool) -> Result<(), ServerError> {
        self.listener.set_nonblocking(true)?;
        while !stop.load(Ordering::Acquire) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // A malformed or denied client is local request failure,
                    // not authority to stop the listener for other clients.
                    let _ = self.handle_stream(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn handle_stream(&mut self, mut stream: UnixStream) -> Result<(), ServerError> {
        stream.set_read_timeout(Some(self.config.io_timeout))?;
        stream.set_write_timeout(Some(self.config.io_timeout))?;
        let credentials =
            getsockopt(&stream, sockopt::PeerCredentials).map_err(|_| ServerError::PeerDenied)?;
        if credentials.uid() != Uid::effective().as_raw() {
            let _ = write_transport_error(
                &mut stream,
                self.config.frame_limits,
                TransportErrorCode::PeerDenied,
                "peer UID denied",
            );
            return Ok(());
        }

        let frame = match read_one_frame(&mut stream, self.config.frame_limits) {
            Ok(value) => value,
            Err(ReadFrameError::TooLarge) => {
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    TransportErrorCode::FrameTooLarge,
                    "frame exceeds configured bound",
                )?;
                return Ok(());
            }
            Err(ReadFrameError::ExtraData) => {
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    TransportErrorCode::ExtraData,
                    "exactly one frame is required",
                )?;
                return Ok(());
            }
            Err(ReadFrameError::Truncated) => {
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    TransportErrorCode::InvalidRequest,
                    "frame is truncated",
                )?;
                return Ok(());
            }
            Err(ReadFrameError::Timeout) => {
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    TransportErrorCode::InvalidRequest,
                    "request write was not closed",
                )?;
                return Ok(());
            }
            Err(ReadFrameError::Io(error)) => return Err(ServerError::Io(error)),
        };
        let payload =
            decode_frame(&frame, self.config.frame_limits).map_err(|_| ServerError::Protocol)?;
        let request = match decode_request(payload) {
            Ok(value) => value,
            Err(error) => {
                let code = canonical_error_code(&error);
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    code,
                    "request payload denied",
                )?;
                return Ok(());
            }
        };
        let response = match self.handler.handle_request(request.clone()) {
            Ok(value) => value,
            Err(_) => {
                write_transport_error(
                    &mut stream,
                    self.config.frame_limits,
                    TransportErrorCode::HandlerError,
                    "handler denied request",
                )?;
                return Ok(());
            }
        };
        if response.validate_for(&request).is_err() {
            write_transport_error(
                &mut stream,
                self.config.frame_limits,
                TransportErrorCode::InvalidHandlerResult,
                "handler returned invalid coordinates",
            )?;
            return Ok(());
        }
        let payload = encode_response(&response).map_err(|_| ServerError::Protocol)?;
        let frame =
            encode_frame(&payload, self.config.frame_limits).map_err(|_| ServerError::Protocol)?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }
}

impl<H> Drop for UnixLabServer<H> {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && (metadata.dev(), metadata.ino()) == self.socket_identity
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

enum ReadFrameError {
    TooLarge,
    ExtraData,
    Truncated,
    Timeout,
    Io(io::Error),
}

fn read_one_frame(stream: &mut UnixStream, limits: FrameLimits) -> Result<Vec<u8>, ReadFrameError> {
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    stream
        .read_exact(&mut prefix)
        .map_err(classify_read_error)?;
    let length = u32::from_be_bytes(prefix);
    if length == 0 || length > limits.maximum_payload_bytes() {
        return Err(ReadFrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(FRAME_PREFIX_BYTES + length as usize);
    frame.extend_from_slice(&prefix);
    let mut payload = vec![0_u8; length as usize];
    stream
        .read_exact(&mut payload)
        .map_err(classify_read_error)?;
    frame.extend_from_slice(&payload);
    let mut extra = [0_u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(ReadFrameError::ExtraData),
        Err(error) => return Err(classify_read_error(error)),
    }
    Ok(frame)
}

fn classify_read_error(error: io::Error) -> ReadFrameError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => ReadFrameError::Truncated,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ReadFrameError::Timeout,
        _ => ReadFrameError::Io(error),
    }
}

fn write_transport_error(
    stream: &mut UnixStream,
    limits: FrameLimits,
    code: TransportErrorCode,
    reason: &str,
) -> Result<(), ServerError> {
    let document = TransportErrorDocument::new(code, reason).map_err(|_| ServerError::Protocol)?;
    let payload = encode_transport_error(&document).map_err(|_| ServerError::Protocol)?;
    let frame = encode_frame(&payload, limits).map_err(|_| ServerError::Protocol)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn canonical_error_code(error: &CanonicalJsonError) -> TransportErrorCode {
    match error {
        CanonicalJsonError::InvalidUtf8 | CanonicalJsonError::MalformedJson => {
            TransportErrorCode::MalformedJson
        }
        CanonicalJsonError::Noncanonical => TransportErrorCode::NoncanonicalJson,
        CanonicalJsonError::DepthExceeded | CanonicalJsonError::FloatingPoint => {
            TransportErrorCode::InvalidJsonValue
        }
        _ => TransportErrorCode::InvalidRequest,
    }
}

fn secure_socket_path(path: &Path) -> Result<PathBuf, ServerError> {
    if !path.is_absolute() {
        return Err(ServerError::UnsafePath("socket path must be absolute"));
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(ServerError::UnsafePath("NUL in path"));
    }
    let parent = path
        .parent()
        .ok_or(ServerError::UnsafePath("socket has no parent"))?;
    reject_symlink_components(parent)?;
    if !parent.exists() {
        let private_parent = parent.parent().ok_or(ServerError::UnsafePath(
            "socket directory has no private parent",
        ))?;
        require_private_directory(private_parent)?;
        fs::DirBuilder::new().mode(0o700).create(parent)?;
    }
    reject_symlink_components(parent)?;
    require_private_directory(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(ServerError::UnsafePath("socket path already exists"));
    }
    Ok(path.to_path_buf())
}

fn require_private_directory(path: &Path) -> Result<(), ServerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(ServerError::UnsafePath(
            "socket directory must already be owner-only",
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), ServerError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ServerError::UnsafePath("noncanonical path"));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ServerError::UnsafePath("symlink component"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
