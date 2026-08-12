// SPDX-License-Identifier: Elastic-2.0

//! Bounded client for the peer-authenticated local daemon endpoint.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, MAX_ADMIN_CANONICAL_BYTES, OutboxReconciliation,
    ReconciliationFailure, SyntheticSubmission,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

const MAX_ADMIN_PAYLOAD_BYTES: usize = MAX_ADMIN_CANONICAL_BYTES;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) enum Operation {
    Status,
    Submit(SyntheticSubmission),
    InspectReconciliation(u64),
    FailReconciliation(ReconciliationFailure),
    InspectOutbox(u64),
    ReconcileOutbox(OutboxReconciliation),
    Shutdown,
}

#[derive(Debug)]
pub(crate) enum ClientError {
    RuntimeUnavailable,
    InsecureSocket,
    Io,
    Protocol(&'static str),
    Refused(String),
}

impl ClientError {
    pub(crate) fn category(&self) -> &str {
        match self {
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::InsecureSocket => "insecure_socket",
            Self::Io => "io",
            Self::Protocol(category) => category,
            Self::Refused(category) => category,
        }
    }
}

pub(crate) fn request(
    runtime: Option<&OsStr>,
    operation: Operation,
) -> Result<AdminResponse, ClientError> {
    let operation_name = match &operation {
        Operation::Status => "status",
        Operation::Submit(_) => "submit",
        Operation::InspectReconciliation(_) => "reconcile-inspect",
        Operation::FailReconciliation(_) => "reconcile-fail",
        Operation::InspectOutbox(_) => "outbox-inspect",
        Operation::ReconcileOutbox(_) => "outbox-reconcile",
        Operation::Shutdown => "shutdown",
    };
    let request_id = format!(
        "cli-{operation_name}-{}-{}",
        std::process::id(),
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let request_id =
        RequestId::new(&request_id).map_err(|error| ClientError::Protocol(error.category()))?;
    let request = match operation {
        Operation::Submit(submission) => AdminRequest::submit(request_id, submission),
        Operation::InspectReconciliation(run_id) => {
            AdminRequest::inspect_reconciliation(request_id, run_id)
                .map_err(|error| ClientError::Protocol(error.category()))?
        }
        Operation::FailReconciliation(failure) => {
            AdminRequest::fail_reconciliation(request_id, failure)
        }
        Operation::InspectOutbox(outbox_id) => AdminRequest::inspect_outbox(request_id, outbox_id)
            .map_err(|error| ClientError::Protocol(error.category()))?,
        Operation::ReconcileOutbox(reconciliation) => {
            AdminRequest::reconcile_outbox(request_id, reconciliation)
        }
        Operation::Status => AdminRequest::new(request_id, AdminCommand::Status),
        Operation::Shutdown => AdminRequest::new(request_id, AdminCommand::Shutdown),
    };
    let request_id = request.request_id().as_str().to_owned();
    let payload = request
        .to_message()
        .map_err(|error| ClientError::Protocol(error.category()))?
        .to_canonical_bytes();
    if payload.is_empty() || payload.len() > MAX_ADMIN_PAYLOAD_BYTES {
        return Err(ClientError::Protocol("frame_size"));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    encode_frame(&payload, &mut frame).map_err(|error| ClientError::Protocol(error.category()))?;

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
    if let AdminResponse::Refused { category, .. } = response {
        return Err(ClientError::Refused(category.as_str().to_owned()));
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

    use automonique_protocol::admin::{
        AdminInstanceId, AdminResponse, DaemonState, DaemonStatus, OperationalMetric,
        OperationalStatus, OperationalStatusParts, SyntheticSubmission,
    };

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
            .and_then(|status| {
                status.with_operational(
                    OperationalStatus::new(OperationalStatusParts {
                        observed_ms: 1,
                        reconciliation_pending: 0,
                        outbox_pending_ready: 0,
                        outbox_pending_delayed: 0,
                        outbox_in_flight_live: 0,
                        outbox_in_flight_ambiguous: 0,
                        outbox_delivered: 0,
                        outbox_dead_lettered: 0,
                        outbox_oldest_ready_age_ms: 0,
                        telegram_pollers_live: 0,
                        telegram_pollers_expired: 0,
                        telegram_offset_lag: OperationalMetric::Unavailable,
                        provider_available: OperationalMetric::Unavailable,
                        sandbox_launch_refusals: OperationalMetric::Unavailable,
                    })
                    .expect("operational"),
                )
            })
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

    #[test]
    fn synthetic_submission_uses_the_typed_request_and_correlated_response() {
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
            let request = AdminRequest::from_canonical_bytes(&body).expect("typed request");
            let submission = request.submission().expect("synthetic submission");
            assert_eq!(submission.scope(), "scope:test");
            assert_eq!(submission.idempotency_key(), "cli:test:1");
            assert_eq!(submission.task(), "synthetic task from stdin");
            let response = AdminResponse::SyntheticAccepted {
                request_id: request.request_id().clone(),
                inbox_id: 41,
                duplicate: false,
            }
            .to_message()
            .expect("response")
            .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            stream.write_all(&frame).expect("write");
        });

        let submission =
            SyntheticSubmission::new("scope:test", "cli:test:1", "synthetic task from stdin")
                .expect("submission");
        let response = request(
            Some(runtime.path().as_os_str()),
            Operation::Submit(submission),
        )
        .expect("accepted response");
        assert!(matches!(
            response,
            AdminResponse::SyntheticAccepted {
                inbox_id: 41,
                duplicate: false,
                ..
            }
        ));
        server.join().expect("server");
    }
}
