// SPDX-License-Identifier: Elastic-2.0

//! Bounded client for the peer-authenticated local daemon endpoint.
//!
//! The endpoint serves four protocols over one socket — local administration,
//! the native Runs API read surface, the native Automation control surface and
//! the native Approval decision surface — so this module has one transport and
//! four typed exchanges over it. [`exchange`] owns everything that is a property
//! of the socket rather than of a protocol: the path judgement, the peer check,
//! the deadlines, and the frame bound. No lane repeats any of it, so no lane can
//! weaken it.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, MAX_ADMIN_CANONICAL_BYTES, OutboxReconciliation,
    ReconciliationFailure, SubmittedRunSpec, SyntheticSubmission,
};
use automonique_protocol::approval_api::{ApprovalRequest, ApprovalResponse};
use automonique_protocol::automation_api::{AutomationRequest, AutomationResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::runs_api::{RunsRequest, RunsResponse};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

const MAX_ADMIN_PAYLOAD_BYTES: usize = MAX_ADMIN_CANONICAL_BYTES;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) enum Operation {
    Status,
    Submit(SyntheticSubmission),
    SubmitRun(SubmittedRunSpec),
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
        Operation::SubmitRun(_) => "run-submit",
        Operation::InspectReconciliation(_) => "reconcile-inspect",
        Operation::FailReconciliation(_) => "reconcile-fail",
        Operation::InspectOutbox(_) => "outbox-inspect",
        Operation::ReconcileOutbox(_) => "outbox-reconcile",
        Operation::Shutdown => "shutdown",
    };
    let request_id = correlation(operation_name)?;
    let request = match operation {
        Operation::Submit(submission) => AdminRequest::submit(request_id, submission),
        Operation::SubmitRun(run_submission) => {
            AdminRequest::submit_run(request_id, run_submission)
        }
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
    let payload = exchange(runtime, &payload)?;
    let response = AdminResponse::from_canonical_bytes(&payload)
        .map_err(|error| ClientError::Protocol(error.category()))?;
    if response.request_id().as_str() != request_id {
        return Err(ClientError::Protocol("request_id_mismatch"));
    }
    if let AdminResponse::Refused { category, .. } = response {
        return Err(ClientError::Refused(category.as_str().to_owned()));
    }
    Ok(response)
}

/// Ask the daemon one bounded question on the native Runs API.
///
/// The request travels under its own protocol name on the same socket, so the
/// daemon places it by envelope rather than by which client sent it. A typed
/// refusal is mapped onto [`ClientError::Refused`] exactly as the
/// administration lane's is, so both render identically; a `resync_required`
/// answer is *not* a refusal and is returned for the caller to report with the
/// window it carries.
pub(crate) fn runs_request(
    runtime: Option<&OsStr>,
    request: &RunsRequest,
) -> Result<RunsResponse, ClientError> {
    let request_id = request.request_id().as_str().to_owned();
    let payload = request
        .to_message()
        .map_err(|error| ClientError::Protocol(error.category()))?
        .to_canonical_bytes();
    let payload = exchange(runtime, &payload)?;
    let response = RunsResponse::from_canonical_bytes(&payload)
        .map_err(|error| ClientError::Protocol(error.category()))?;
    if response.request_id().as_str() != request_id {
        return Err(ClientError::Protocol("request_id_mismatch"));
    }
    if let RunsResponse::Refused { refusal, .. } = response {
        return Err(ClientError::Refused(refusal.as_str().to_owned()));
    }
    Ok(response)
}

/// Ask the daemon one bounded question on the native Automation control API.
///
/// The request travels under its own protocol name on the same socket, so the
/// daemon places it by envelope rather than by which client sent it. A typed
/// refusal is mapped onto [`ClientError::Refused`] exactly as the other two
/// lanes' are; a `revision_conflict` answer is *not* a refusal — the request
/// was well-formed and the row simply moved — and is returned for the caller to
/// report with the durable revision it carries.
pub(crate) fn automation_request(
    runtime: Option<&OsStr>,
    request: &AutomationRequest,
) -> Result<AutomationResponse, ClientError> {
    let request_id = request.request_id().as_str().to_owned();
    let payload = request
        .to_message()
        .map_err(|error| ClientError::Protocol(error.category()))?
        .to_canonical_bytes();
    let payload = exchange(runtime, &payload)?;
    let response = AutomationResponse::from_canonical_bytes(&payload)
        .map_err(|error| ClientError::Protocol(error.category()))?;
    if response.request_id().as_str() != request_id {
        return Err(ClientError::Protocol("request_id_mismatch"));
    }
    if let AutomationResponse::Refused { refusal, .. } = response {
        return Err(ClientError::Refused(refusal.as_str().to_owned()));
    }
    Ok(response)
}

/// Ask the daemon one bounded question on the native Approval decision API.
///
/// The request travels under its own protocol name on the same socket, so the
/// daemon places it by envelope rather than by which client sent it. A typed
/// refusal is mapped onto [`ClientError::Refused`] exactly as the other three
/// lanes' are; an `approval_conflict` answer is *not* a refusal — the request
/// was well-formed and the key was simply already spoken for — and is returned
/// for the caller to report with the recorded coordinates it carries.
pub(crate) fn approval_request(
    runtime: Option<&OsStr>,
    request: &ApprovalRequest,
) -> Result<ApprovalResponse, ClientError> {
    let request_id = request.request_id().as_str().to_owned();
    let payload = request
        .to_message()
        .map_err(|error| ClientError::Protocol(error.category()))?
        .to_canonical_bytes();
    let payload = exchange(runtime, &payload)?;
    let response = ApprovalResponse::from_canonical_bytes(&payload)
        .map_err(|error| ClientError::Protocol(error.category()))?;
    if response.request_id().as_str() != request_id {
        return Err(ClientError::Protocol("request_id_mismatch"));
    }
    if let ApprovalResponse::Refused { refusal, .. } = response {
        return Err(ClientError::Refused(refusal.as_str().to_owned()));
    }
    Ok(response)
}

/// Correlation identifier for one client request, unique within this process.
pub(crate) fn correlation(operation: &str) -> Result<RequestId, ClientError> {
    let request_id = format!(
        "cli-{operation}-{}-{}",
        std::process::id(),
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    RequestId::new(&request_id).map_err(|error| ClientError::Protocol(error.category()))
}

/// Send one canonical payload to the local endpoint and read one back.
///
/// Everything here is a property of the socket rather than of a protocol: the
/// path is judged before a `connect`, the peer is checked after it, both
/// directions carry a deadline, and both frames are bounded by the transport's
/// own ceiling. The Runs protocol's canonical ceiling is asserted at compile
/// time in `automonique_protocol::admin` to be no larger than this one, so a
/// legal message of either lane fits a frame this function will carry.
fn exchange(runtime: Option<&OsStr>, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
    if payload.is_empty() || payload.len() > MAX_ADMIN_PAYLOAD_BYTES {
        return Err(ClientError::Protocol("frame_size"));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    encode_frame(payload, &mut frame).map_err(|error| ClientError::Protocol(error.category()))?;

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
    match decode_frame(&response).map_err(|error| ClientError::Protocol(error.category()))? {
        FrameDecode::Frame { payload, consumed } if consumed == response.len() => {
            Ok(payload.to_vec())
        }
        _ => Err(ClientError::Protocol("incomplete_frame")),
    }
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
        AdminInstanceId, AdminResponse, DaemonState, DaemonStatus, DurableStateCounts,
        DurableStateCountsParts, OperationalMetric, OperationalStatus, OperationalStatusParts,
        SyntheticSubmission,
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
            .and_then(|status| {
                status.with_durable_state(
                    DurableStateCounts::new(DurableStateCountsParts {
                        approvals_recorded: OperationalMetric::Measured(0),
                        automations_registered: OperationalMetric::Measured(0),
                        // The generation above is one, and the tenure open over
                        // it has to say the same.
                        open_tenure_epoch: OperationalMetric::Measured(1),
                        open_tenures: OperationalMetric::Measured(1),
                        runs_registered: OperationalMetric::Measured(0),
                        tenures_recorded: OperationalMetric::Measured(1),
                    })
                    .expect("durable counts"),
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
