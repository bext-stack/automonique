// SPDX-License-Identifier: Elastic-2.0

//! Bounded client for the peer-authenticated local daemon endpoint.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

const MAX_ADMIN_PAYLOAD_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Status,
    Shutdown,
}

#[derive(Debug)]
pub(crate) enum ClientError {
    RuntimeUnavailable,
    InsecureSocket,
    Io,
    Protocol(&'static str),
}

impl ClientError {
    pub(crate) const fn category(&self) -> &'static str {
        match self {
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::InsecureSocket => "insecure_socket",
            Self::Io => "io",
            Self::Protocol(category) => category,
        }
    }
}

pub(crate) fn request(
    runtime: Option<&OsStr>,
    operation: Operation,
) -> Result<AdminResponse, ClientError> {
    let runtime = runtime.ok_or(ClientError::RuntimeUnavailable)?;
    let runtime = Path::new(runtime);
    let socket = runtime.join("automonique/admin.sock");
    validate_socket_components(&socket)?;
    validate_private_directory(runtime)?;
    validate_private_directory(&runtime.join("automonique"))?;
    let metadata = std::fs::symlink_metadata(&socket).map_err(|_| ClientError::Io)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ClientError::InsecureSocket);
    }
    let mut stream = UnixStream::connect(&socket).map_err(|_| ClientError::Io)?;
    let credentials =
        getsockopt(&stream, sockopt::PeerCredentials).map_err(|_| ClientError::InsecureSocket)?;
    if credentials.uid() != geteuid().as_raw() || credentials.pid() <= 0 {
        return Err(ClientError::InsecureSocket);
    }
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| ClientError::Io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| ClientError::Io)?;
    let (operation_name, command) = match operation {
        Operation::Status => ("status", AdminCommand::Status),
        Operation::Shutdown => ("shutdown", AdminCommand::Shutdown),
    };
    let request_id = format!(
        "cli-{operation_name}-{}-{}",
        std::process::id(),
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let request = AdminRequest::new(
        RequestId::new(&request_id).map_err(|error| ClientError::Protocol(error.category()))?,
        command,
    );
    let payload = request
        .to_message()
        .map_err(|error| ClientError::Protocol(error.category()))?
        .to_canonical_bytes();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    encode_frame(&payload, &mut frame).map_err(|error| ClientError::Protocol(error.category()))?;
    stream.write_all(&frame).map_err(|_| ClientError::Io)?;

    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| ClientError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| ClientError::Io)?;
    if length == 0 || length > MAX_ADMIN_PAYLOAD_BYTES {
        return Err(ClientError::Protocol("frame_size"));
    }
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .map_err(|_| ClientError::Io)?;
    let payload =
        match decode_frame(&response).map_err(|error| ClientError::Protocol(error.category()))? {
            FrameDecode::Frame { payload, consumed } if consumed == response.len() => payload,
            _ => return Err(ClientError::Protocol("incomplete_frame")),
        };
    let response = AdminResponse::from_canonical_bytes(payload)
        .map_err(|error| ClientError::Protocol(error.category()))?;
    if response.request_id().as_str() != request_id {
        return Err(ClientError::Protocol("request_id_mismatch"));
    }
    Ok(response)
}

fn validate_private_directory(path: &Path) -> Result<(), ClientError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ClientError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(ClientError::InsecureSocket);
    }
    Ok(())
}

fn validate_socket_components(socket: &Path) -> Result<(), ClientError> {
    if !socket.is_absolute() {
        return Err(ClientError::InsecureSocket);
    }
    let mut current = PathBuf::new();
    for component in socket.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = std::fs::symlink_metadata(&current).map_err(|_| ClientError::Io)?;
                if metadata.file_type().is_symlink() || (current != socket && !metadata.is_dir()) {
                    return Err(ClientError::InsecureSocket);
                }
            }
            _ => return Err(ClientError::InsecureSocket),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use automonique_protocol::admin::{AdminInstanceId, AdminResponse, DaemonState, DaemonStatus};

    #[test]
    fn a_response_with_another_request_id_is_refused() {
        let runtime = tempfile::tempdir().expect("runtime");
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let product = runtime.path().join("automonique");
        std::fs::create_dir(&product).expect("product runtime");
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
            .expect("product mode");
        let socket = product.join("admin.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let status = DaemonStatus::new(
                AdminInstanceId::new("test-daemon").expect("instance"),
                DaemonState::Ready,
                1,
                1,
                0,
                0,
                0,
                false,
            )
            .expect("status");
            let response = AdminResponse::Status {
                request_id: RequestId::new("wrong-request").expect("request ID"),
                status,
            }
            .to_message()
            .expect("response")
            .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            stream.write_all(&frame).expect("write");
        });

        let error = request(Some(runtime.path().as_os_str()), Operation::Status)
            .expect_err("correlation mismatch");
        assert_eq!(error.category(), "request_id_mismatch");
        server.join().expect("server");
    }
}
