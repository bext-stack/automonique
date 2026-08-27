// SPDX-License-Identifier: Elastic-2.0

//! Authenticated HTTP-to-local Platform v2 bridge.
//!
//! HTTP credentials never cross the local socket. The caller first proves the
//! request came from the web entry's one configured Basic principal; this
//! module then rechecks that the server-owned tenant and actor are the sole
//! Platform v2 principal mapped to the web process uid. The public request
//! carries no actor, tenant, grant, or review-authority assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, encode_frame_with_limit};
use automonique_protocol::platform_v2::ProjectId;
use automonique_protocol::platform_v2_transport::{
    MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES, MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES, PlatformNegotiationRequest,
    PlatformNegotiationRequestMessage, PlatformNegotiationResponse,
    PlatformNegotiationResponseMessage, PlatformV2Refusal, PlatformV2Request,
    PlatformV2RequestMessage, PlatformV2Response, PlatformV2ResponseMessage, ReceiptLookupKey,
};

use crate::mobile_auth::{
    MobileCredentialAuthority, MobilePlatformV2Action, MobilePlatformV2Authorization,
    MobilePlatformV2ReceiptCustody,
};
use automonique_protocol::{
    codec::RequestId,
    platform_v2::{NegotiatedPlatform, PlatformVersionOffer},
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt::SocketError,
};

pub(crate) const PLATFORM_NEGOTIATION_CONTENT_TYPE: &str =
    "application/vnd.automonique.platform.negotiation.v1+json";
pub(crate) const PLATFORM_V2_CONTENT_TYPE: &str = "application/vnd.automonique.platform.v2+json";
const MAX_MOBILE_PREVIEW_SCOPES: usize = 128;
const MAX_MOBILE_DISPATCH_IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
struct MobilePreviewScope {
    project: ProjectId,
    idempotency_key: String,
    expires_at_ms: i64,
    credential_id: String,
    principal_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformV2Lane {
    Negotiation,
    V2,
}

impl PlatformV2Lane {
    pub(crate) const fn content_type(self) -> &'static str {
        match self {
            Self::Negotiation => PLATFORM_NEGOTIATION_CONTENT_TYPE,
            Self::V2 => PLATFORM_V2_CONTENT_TYPE,
        }
    }

    pub(crate) const fn request_limit(self) -> usize {
        match self {
            Self::Negotiation => MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
            Self::V2 => MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
        }
    }

    const fn response_limit(self) -> usize {
        match self {
            Self::Negotiation => MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES,
            Self::V2 => MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES,
        }
    }

    pub(crate) fn from_media_type(value: &str) -> Option<Self> {
        match value {
            PLATFORM_NEGOTIATION_CONTENT_TYPE => Some(Self::Negotiation),
            PLATFORM_V2_CONTENT_TYPE => Some(Self::V2),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PlatformV2Bridge {
    socket: PathBuf,
    policy: PathBuf,
    uid: u32,
    tenant: String,
    actor: String,
    timeout: Duration,
    sequence: AtomicU64,
    preview_scopes: Mutex<BTreeMap<String, MobilePreviewScope>>,
}

impl PlatformV2Bridge {
    pub(crate) fn new(
        state_dir: &Path,
        socket: PathBuf,
        uid: u32,
        tenant: String,
        actor: String,
        timeout: Duration,
    ) -> Self {
        Self {
            socket,
            policy: state_dir.join(automonique_daemon::PLATFORM_V2_POLICY_FILE_NAME),
            uid,
            tenant,
            actor,
            timeout,
            sequence: AtomicU64::new(1),
            preview_scopes: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn verify_project_roots(&self, roots: &[String]) -> Result<(), &'static str> {
        let roots = roots
            .iter()
            .cloned()
            .map(ProjectId::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| "platform_v2_mobile_project_denied")?;
        automonique_daemon::verify_web_project_roots(
            &self.policy,
            self.uid,
            &self.tenant,
            &self.actor,
            &roots,
        )
    }

    pub(crate) fn exchange_mobile(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
        authorization: &MobilePlatformV2Authorization,
        authority: &mut MobileCredentialAuthority,
        now_ms: i64,
    ) -> Result<Vec<u8>, &'static str> {
        if request.is_empty() || request.len() > lane.request_limit() {
            return Err("platform_v2_request_invalid");
        }
        let canonical_request = request;
        match lane {
            PlatformV2Lane::Negotiation => {
                let request = PlatformNegotiationRequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                if authorization.tenant_id != self.tenant
                    || authorization.actor_id != self.actor
                    || authorization.expires_at_ms <= now_ms
                {
                    return typed_negotiation_refusal(
                        &request,
                        "platform_v2_mobile_authorization_invalid",
                    );
                }
                if let Err(category) = self.verify_binding() {
                    return typed_negotiation_refusal(&request, category);
                }
                let lease = match authority.acquire_platform_v2_dispatch(
                    authorization,
                    MobilePlatformV2ReceiptCustody::None,
                    canonical_request,
                    now_ms,
                ) {
                    Ok(lease) => lease,
                    Err(_) => {
                        return typed_negotiation_refusal(
                            &request,
                            "platform_v2_mobile_generation_changed",
                        );
                    }
                };
                let result = (|| {
                    let response = self.exchange_mobile_local(
                        lane,
                        &request
                            .to_canonical_bytes()
                            .map_err(|_| "platform_v2_request_invalid")?,
                    )?;
                    PlatformNegotiationResponseMessage::from_canonical_bytes(&response, &request)
                        .and_then(|message| message.to_canonical_bytes())
                        .map_err(|_| "platform_v2_response_invalid")
                })();
                let _ = authority.release_platform_v2_dispatch(&lease);
                result
            }
            PlatformV2Lane::V2 => {
                let request = PlatformV2RequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                if authorization.tenant_id != self.tenant
                    || authorization.actor_id != self.actor
                    || authorization.expires_at_ms <= now_ms
                {
                    return typed_v2_refusal(&request, "platform_v2_mobile_authorization_invalid");
                }
                let (project, submit_idempotency_key) =
                    match self.authorize_mobile_request(authorization, request.request(), now_ms) {
                        Ok(project) => project,
                        Err(category) => return typed_v2_refusal(&request, category),
                    };
                let custody = if let automonique_protocol::platform_v2_transport::PlatformV2Request::GetMutationReceipt(lookup) = request.request() {
                    let ReceiptLookupKey::IdempotencyKey(idempotency_key) = lookup.key() else {
                        return typed_v2_refusal(
                            &request,
                            "platform_v2_mobile_receipt_custody_required",
                        );
                    };
                    MobilePlatformV2ReceiptCustody::Read {
                        project: &project,
                        idempotency_key: idempotency_key.as_str(),
                    }
                } else if let Some(idempotency_key) = submit_idempotency_key.as_deref() {
                    MobilePlatformV2ReceiptCustody::Bind {
                        project: &project,
                        idempotency_key,
                    }
                } else {
                    MobilePlatformV2ReceiptCustody::None
                };
                let custody_required = !matches!(&custody, MobilePlatformV2ReceiptCustody::None);
                let lease = match authority.acquire_platform_v2_dispatch(
                    authorization,
                    custody,
                    canonical_request,
                    now_ms,
                ) {
                    Ok(lease) => lease,
                    Err(_) => {
                        return typed_v2_refusal(
                            &request,
                            if custody_required {
                                "platform_v2_mobile_receipt_custody_denied"
                            } else {
                                "platform_v2_mobile_generation_changed"
                            },
                        );
                    }
                };
                let result = (|| {
                    let response = self.exchange_mobile_local(
                        lane,
                        &request
                            .to_canonical_bytes()
                            .map_err(|_| "platform_v2_request_invalid")?,
                    )?;
                    let response =
                        PlatformV2ResponseMessage::from_canonical_bytes(&response, &request)
                            .map_err(|_| "platform_v2_response_invalid")?;
                    if let PlatformV2Response::MutationPreview(preview) = response.response() {
                        let mut scopes = self
                            .preview_scopes
                            .lock()
                            .map_err(|_| "platform_v2_bridge_unavailable")?;
                        scopes.retain(|_, scope| scope.expires_at_ms > now_ms);
                        if scopes.len() >= MAX_MOBILE_PREVIEW_SCOPES
                            && !scopes.contains_key(preview.preview().id().as_str())
                        {
                            return typed_v2_refusal(&request, "platform_v2_mobile_preview_limit");
                        }
                        scopes.insert(
                            preview.preview().id().as_str().to_owned(),
                            MobilePreviewScope {
                                project,
                                idempotency_key: preview
                                    .proposal()
                                    .idempotency_key()
                                    .as_str()
                                    .to_owned(),
                                expires_at_ms: preview.expires_at().as_millis(),
                                credential_id: authorization.credential_id.clone(),
                                principal_generation: authorization.principal_generation,
                            },
                        );
                    }
                    response
                        .to_canonical_bytes()
                        .map_err(|_| "platform_v2_response_invalid")
                })();
                let _ = authority.release_platform_v2_dispatch(&lease);
                result
            }
        }
    }

    fn authorize_mobile_request(
        &self,
        authorization: &MobilePlatformV2Authorization,
        request: &automonique_protocol::platform_v2_transport::PlatformV2Request,
        now_ms: i64,
    ) -> Result<(ProjectId, Option<String>), &'static str> {
        use automonique_protocol::platform_v2_transport::PlatformV2Request;

        let action = match request {
            PlatformV2Request::QueryWorkContexts(_) => MobilePlatformV2Action::QueryWorkContexts,
            PlatformV2Request::GetLineage(_) => MobilePlatformV2Action::GetLineage,
            PlatformV2Request::PrepareMutation(_) => MobilePlatformV2Action::PrepareMutation,
            PlatformV2Request::DecideMutation(_) => MobilePlatformV2Action::DecideMutation,
            PlatformV2Request::SubmitMutation(_) => MobilePlatformV2Action::SubmitMutation,
            PlatformV2Request::GetMutationReceipt(_) => MobilePlatformV2Action::GetMutationReceipt,
            PlatformV2Request::SubmitWorkspaceIntent(_) => {
                MobilePlatformV2Action::SubmitWorkspaceIntent
            }
            PlatformV2Request::GetWorkspaceIntent(_) => MobilePlatformV2Action::GetWorkspaceIntent,
            PlatformV2Request::GetReview(_) => MobilePlatformV2Action::GetReview,
            PlatformV2Request::GetWorkContext(_)
            | PlatformV2Request::ExecuteReviewAction(_)
            | PlatformV2Request::GetReviewReceipt(_) => {
                return Err("platform_v2_mobile_action_denied");
            }
        };
        if !authorization.allows(action) {
            return Err("platform_v2_mobile_action_denied");
        }
        let roots = authorization
            .project_roots
            .iter()
            .cloned()
            .map(ProjectId::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| "platform_v2_mobile_project_denied")?;
        let (project, submit_idempotency_key) = match request {
            PlatformV2Request::DecideMutation(value) => {
                let (project, _) =
                    self.preview_scope(value.preview().id().as_str(), authorization, now_ms)?;
                (project, None)
            }
            PlatformV2Request::SubmitMutation(value) => {
                let (project, idempotency_key) =
                    self.preview_scope(value.preview().id().as_str(), authorization, now_ms)?;
                (project, Some(idempotency_key))
            }
            _ => (
                automonique_daemon::resolve_web_mobile_request_project(
                    &self.policy,
                    self.uid,
                    &self.tenant,
                    &self.actor,
                    &roots,
                    request,
                )?,
                None,
            ),
        };
        if !authorization.allows_project(&project) {
            return Err("platform_v2_mobile_project_denied");
        }
        Ok((project, submit_idempotency_key))
    }

    fn preview_scope(
        &self,
        preview_id: &str,
        authorization: &MobilePlatformV2Authorization,
        now_ms: i64,
    ) -> Result<(ProjectId, String), &'static str> {
        let mut scopes = self
            .preview_scopes
            .lock()
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        scopes.retain(|_, scope| scope.expires_at_ms > now_ms);
        scopes
            .get(preview_id)
            .filter(|scope| {
                scope.credential_id == authorization.credential_id
                    && scope.principal_generation == authorization.principal_generation
            })
            .map(|scope| (scope.project.clone(), scope.idempotency_key.clone()))
            .ok_or("platform_v2_mobile_preview_scope_required")
    }

    pub(crate) fn negotiate(&self) -> Result<NegotiatedPlatform, &'static str> {
        let request = PlatformNegotiationRequestMessage::new(
            self.request_id("negotiation")?,
            PlatformNegotiationRequest::Negotiate(
                PlatformVersionOffer::new(vec![1, 2]).map_err(|_| "platform_v2_request_invalid")?,
            ),
        );
        let bytes = request
            .to_canonical_bytes()
            .map_err(|_| "platform_v2_request_invalid")?;
        let response = self.exchange(PlatformV2Lane::Negotiation, &bytes)?;
        match PlatformNegotiationResponseMessage::from_canonical_bytes(&response, &request)
            .map_err(|_| "platform_v2_response_invalid")?
            .response()
        {
            PlatformNegotiationResponse::Negotiated(value) => Ok(*value),
            PlatformNegotiationResponse::Refused(value) => Err(category(value.category().as_str())),
        }
    }

    pub(crate) fn request(
        &self,
        request: PlatformV2Request,
    ) -> Result<PlatformV2Response, &'static str> {
        let request = PlatformV2RequestMessage::new(self.request_id("cockpit")?, request);
        let bytes = request
            .to_canonical_bytes()
            .map_err(|_| "platform_v2_request_invalid")?;
        let response = self.exchange(PlatformV2Lane::V2, &bytes)?;
        PlatformV2ResponseMessage::from_canonical_bytes(&response, &request)
            .map(|message| message.response().clone())
            .map_err(|_| "platform_v2_response_invalid")
    }

    /// Issue one internal Platform v2 read with a caller-owned wall-clock
    /// bound. The ordinary bridge path retains its configured timeout; this
    /// narrower path is used only for best-effort inventory enrichment where
    /// one slow workspace must not stall the entire hosted cockpit.
    pub(crate) fn request_with_timeout(
        &self,
        request: PlatformV2Request,
        timeout: Duration,
    ) -> Result<PlatformV2Response, &'static str> {
        let request = PlatformV2RequestMessage::new(self.request_id("cockpit-bounded")?, request);
        let bytes = request
            .to_canonical_bytes()
            .map_err(|_| "platform_v2_request_invalid")?;
        self.verify_binding()?;
        let response = self.exchange_local_with_timeout(PlatformV2Lane::V2, &bytes, timeout)?;
        PlatformV2ResponseMessage::from_canonical_bytes(&response, &request)
            .map(|message| message.response().clone())
            .map_err(|_| "platform_v2_response_invalid")
    }

    fn request_id(&self, lane: &str) -> Result<RequestId, &'static str> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!("web-{lane}-{sequence}")).map_err(|_| "platform_v2_request_invalid")
    }

    pub(crate) fn exchange(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if request.is_empty() || request.len() > lane.request_limit() {
            return Err("platform_v2_request_invalid");
        }
        match lane {
            PlatformV2Lane::Negotiation => {
                let request = PlatformNegotiationRequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                if let Err(category) = self.verify_binding() {
                    return typed_negotiation_refusal(&request, category);
                }
                let response = self.exchange_local(
                    lane,
                    &request
                        .to_canonical_bytes()
                        .map_err(|_| "platform_v2_request_invalid")?,
                )?;
                PlatformNegotiationResponseMessage::from_canonical_bytes(&response, &request)
                    .and_then(|message| message.to_canonical_bytes())
                    .map_err(|_| "platform_v2_response_invalid")
            }
            PlatformV2Lane::V2 => {
                let request = PlatformV2RequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                if let Err(category) = self.verify_binding() {
                    return typed_v2_refusal(&request, category);
                }
                let response = self.exchange_local(
                    lane,
                    &request
                        .to_canonical_bytes()
                        .map_err(|_| "platform_v2_request_invalid")?,
                )?;
                PlatformV2ResponseMessage::from_canonical_bytes(&response, &request)
                    .and_then(|message| message.to_canonical_bytes())
                    .map_err(|_| "platform_v2_response_invalid")
            }
        }
    }

    fn verify_binding(&self) -> Result<(), &'static str> {
        automonique_daemon::verify_web_principal_binding(
            &self.policy,
            self.uid,
            &self.tenant,
            &self.actor,
        )
    }

    fn exchange_local(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.exchange_local_with_timeout(lane, request, self.timeout)
    }

    fn exchange_mobile_local(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.exchange_local_with_timeout(
            lane,
            request,
            self.timeout.min(MAX_MOBILE_DISPATCH_IO_TIMEOUT),
        )
    }

    fn exchange_local_with_timeout(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, &'static str> {
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + request.len());
        encode_frame_with_limit(request, &mut frame, lane.request_limit())
            .map_err(|_| "platform_v2_request_invalid")?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("platform_v2_bridge_unavailable")?;
        let mut stream =
            connect_until(&self.socket, deadline).map_err(|_| "platform_v2_bridge_unavailable")?;
        write_all_until(&mut stream, &frame, deadline)
            .map_err(|_| "platform_v2_bridge_unavailable")?;

        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        read_exact_until(&mut stream, &mut prefix, deadline)
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| "platform_v2_response_invalid")?;
        if length == 0 || length > lane.response_limit() {
            return Err("platform_v2_response_too_large");
        }
        let mut response = vec![0_u8; length];
        read_exact_until(&mut stream, &mut response, deadline)
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        Ok(response)
    }
}

fn connect_until(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let fd: OwnedFd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(errno_io)?;
    let address = UnixAddr::new(path).map_err(errno_io)?;
    match connect(fd.as_raw_fd(), &address) {
        Ok(()) => {}
        Err(Errno::EINPROGRESS | Errno::EALREADY | Errno::EAGAIN) => {
            wait_until(&fd, PollFlags::POLLOUT, deadline)?;
            let error = getsockopt(&fd, SocketError).map_err(errno_io)?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
        }
        Err(error) => return Err(errno_io(error)),
    }
    Ok(UnixStream::from(fd))
}

fn write_all_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        ensure_before(deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_until(stream, PollFlags::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        ensure_before(deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_until(stream, PollFlags::POLLIN, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_until(fd: &impl AsFd, events: PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        let milliseconds =
            u16::try_from(remaining.as_millis().clamp(1, u16::MAX.into())).unwrap_or(u16::MAX);
        let mut poll_fd = [PollFd::new(fd.as_fd(), events)];
        let result = match poll(&mut poll_fd, PollTimeout::from(milliseconds)) {
            Ok(result) => result,
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(errno_io(error)),
        };
        if result > 0 {
            if poll_fd[0]
                .revents()
                .is_some_and(|flags| flags.contains(PollFlags::POLLNVAL))
            {
                return Err(io::Error::from_raw_os_error(nix::libc::EBADF));
            }
            return Ok(());
        }
        if result == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
    }
}

fn ensure_before(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(io::ErrorKind::TimedOut.into())
    }
}

fn errno_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn category(value: &str) -> &'static str {
    match value {
        "platform_v2_web_binding_unavailable" => "platform_v2_web_binding_unavailable",
        "platform_v2_web_binding_mismatch" => "platform_v2_web_binding_mismatch",
        _ => "platform_v2_refused",
    }
}

fn refusal(category: &'static str) -> Result<PlatformV2Refusal, &'static str> {
    PlatformV2Refusal::new(
        category,
        "Platform v2 is unavailable for this authenticated web principal",
    )
    .map_err(|_| "platform_v2_response_invalid")
}

fn typed_negotiation_refusal(
    request: &PlatformNegotiationRequestMessage,
    category: &'static str,
) -> Result<Vec<u8>, &'static str> {
    PlatformNegotiationResponseMessage::for_request(
        request,
        PlatformNegotiationResponse::Refused(refusal(category)?),
    )
    .and_then(|message| message.to_canonical_bytes())
    .map_err(|_| "platform_v2_response_invalid")
}

fn typed_v2_refusal(
    request: &PlatformV2RequestMessage,
    category: &'static str,
) -> Result<Vec<u8>, &'static str> {
    PlatformV2ResponseMessage::for_request(request, PlatformV2Response::Refused(refusal(category)?))
        .and_then(|message| message.to_canonical_bytes())
        .map_err(|_| "platform_v2_response_invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crate::mobile_auth::{
        MobileAction, MobileCredentialAuthority, MobileCredentialRevokeRequest, MobileLimits,
        MobileOperatorProvisionRequest, MobilePlatformV2GrantRequest,
    };
    use automonique_protocol::codec::RequestId;
    use automonique_protocol::digest::Sha256;
    use automonique_protocol::platform::{IdempotencyKey, ReceiptId};
    use automonique_protocol::platform_v2::{PlatformVersionOffer, ProjectId, WorkContextIdentity};
    use automonique_protocol::platform_v2_lifecycle::{
        MutationPreviewDigest, MutationPreviewId, MutationPreviewRef,
    };
    use automonique_protocol::platform_v2_transport::{
        MutationReceiptLookup, MutationSubmitRequest, PlatformNegotiationRequest, PlatformV2Request,
    };
    use automonique_protocol::primitives::Revision;

    fn write_policy(root: &Path, uid: u32, tenant: &str, actor: &str) {
        let policy = serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": tenant,
                "actor": actor,
                "serving_authority": "automonique",
                "projects": ["project-test"],
                "workspaces": [{
                    "project": "project-test", "kind": "project", "id": "project-test",
                    "inherited_authority": {
                        "filesystem": [], "credentials": [], "network": [],
                        "tools": [], "providers": [], "models": []
                    }
                }],
                "authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": [], "providers": [], "models": []
                },
                "review_authorities": {}
            }]
        });
        let path = root.join(automonique_daemon::PLATFORM_V2_POLICY_FILE_NAME);
        fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn negotiation_request() -> PlatformNegotiationRequestMessage {
        PlatformNegotiationRequestMessage::new(
            RequestId::new("web-negotiation").unwrap(),
            PlatformNegotiationRequest::Negotiate(PlatformVersionOffer::new(vec![1, 2]).unwrap()),
        )
    }

    fn v2_request() -> PlatformV2RequestMessage {
        PlatformV2RequestMessage::new(
            RequestId::new("web-v2-request").unwrap(),
            PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                ProjectId::new("project-test").unwrap(),
            )),
        )
    }

    fn bridge(root: &Path, socket: PathBuf, tenant: &str, actor: &str) -> PlatformV2Bridge {
        PlatformV2Bridge::new(
            root,
            socket,
            nix::unistd::geteuid().as_raw(),
            tenant.to_owned(),
            actor.to_owned(),
            Duration::from_secs(1),
        )
    }

    fn grant_mobile(
        authority: &mut MobileCredentialAuthority,
        actions: Vec<MobilePlatformV2Action>,
        roots: Vec<&str>,
    ) -> MobilePlatformV2Authorization {
        let issued = authority
            .operator_provision(
                MobileOperatorProvisionRequest {
                    actions: vec![MobileAction::Attach],
                    session_scope: vec!["session-test".to_owned()],
                    limits: MobileLimits {
                        max_page_events: 16,
                        max_follow_up_bytes: 1_024,
                    },
                },
                1_000,
            )
            .unwrap();
        authority
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: roots.into_iter().map(str::to_owned).collect(),
                    actions,
                },
                1_001,
            )
            .unwrap()
    }

    #[test]
    fn mobile_action_and_project_scope_refuse_before_opening_the_socket() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        write_policy(root.path(), uid, "tenant-test", "actor-test");
        let bridge = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-test",
            "actor-test",
        );
        let mut authority = MobileCredentialAuthority::open_scoped(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "tenant-test",
            "actor-test",
        )
        .unwrap();
        let request = v2_request();
        let authorization = grant_mobile(
            &mut authority,
            vec![MobilePlatformV2Action::GetLineage],
            vec!["project-test"],
        );
        let wrong_action = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &request.to_canonical_bytes().unwrap(),
                &authorization,
                &mut authority,
                1_002,
            )
            .unwrap();
        let response =
            PlatformV2ResponseMessage::from_canonical_bytes(&wrong_action, &request).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value)
                if value.category().as_str() == "platform_v2_mobile_action_denied"
        ));

        let query = PlatformV2RequestMessage::new(
            RequestId::new("mobile-wrong-root").unwrap(),
            PlatformV2Request::QueryWorkContexts(
                automonique_protocol::platform_v2::WorkContextQuery::new(
                    vec![automonique_protocol::platform_v2::WorkContextKind::Project],
                    vec![],
                    Some(ProjectId::new("project-test").unwrap()),
                    None,
                    None,
                    1,
                )
                .unwrap(),
            ),
        );
        let authorization = grant_mobile(
            &mut authority,
            vec![MobilePlatformV2Action::QueryWorkContexts],
            vec!["project-other"],
        );
        let wrong_root = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &query.to_canonical_bytes().unwrap(),
                &authorization,
                &mut authority,
                1_002,
            )
            .unwrap();
        let response =
            PlatformV2ResponseMessage::from_canonical_bytes(&wrong_root, &query).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value)
                if value.category().as_str() == "platform_v2_mobile_project_denied"
        ));
    }

    #[test]
    fn mobile_receipt_lookup_requires_durable_exact_custody_before_the_socket() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        write_policy(root.path(), uid, "tenant-test", "actor-test");
        let bridge = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-test",
            "actor-test",
        );
        let mut authority = MobileCredentialAuthority::open_scoped(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "tenant-test",
            "actor-test",
        )
        .unwrap();
        let issued = authority
            .operator_provision(
                MobileOperatorProvisionRequest {
                    actions: vec![MobileAction::Attach],
                    session_scope: vec!["session-test".to_owned()],
                    limits: MobileLimits {
                        max_page_events: 16,
                        max_follow_up_bytes: 1_024,
                    },
                },
                1_000,
            )
            .unwrap();
        let authorization = authority
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: vec!["project-test".to_owned()],
                    actions: vec![MobilePlatformV2Action::GetMutationReceipt],
                },
                1_001,
            )
            .unwrap();

        let absent = PlatformV2RequestMessage::new(
            RequestId::new("mobile-receipt-no-custody").unwrap(),
            PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
                ProjectId::new("project-test").unwrap(),
                ReceiptLookupKey::IdempotencyKey(
                    IdempotencyKey::new("mobile:mutation:absent").unwrap(),
                ),
            )),
        );
        let response = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &absent.to_canonical_bytes().unwrap(),
                &authorization,
                &mut authority,
                1_002,
            )
            .unwrap();
        let response = PlatformV2ResponseMessage::from_canonical_bytes(&response, &absent).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value)
                if value.category().as_str() == "platform_v2_mobile_receipt_custody_denied"
        ));

        let by_receipt_id = PlatformV2RequestMessage::new(
            RequestId::new("mobile-receipt-id-no-custody").unwrap(),
            PlatformV2Request::GetMutationReceipt(MutationReceiptLookup::new(
                ProjectId::new("project-test").unwrap(),
                ReceiptLookupKey::ReceiptId(ReceiptId::new("receipt-absent").unwrap()),
            )),
        );
        let response = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &by_receipt_id.to_canonical_bytes().unwrap(),
                &authorization,
                &mut authority,
                1_002,
            )
            .unwrap();
        let response =
            PlatformV2ResponseMessage::from_canonical_bytes(&response, &by_receipt_id).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value)
                if value.category().as_str() == "platform_v2_mobile_receipt_custody_required"
        ));
    }

    #[test]
    fn mobile_submit_durably_binds_receipt_custody_before_socket_exchange() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        write_policy(root.path(), uid, "tenant-test", "actor-test");
        let bridge = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-test",
            "actor-test",
        );
        let mut authority = MobileCredentialAuthority::open_scoped(
            root.path().join("mobile.sqlite3"),
            "ops.example.test",
            "tenant-test",
            "actor-test",
        )
        .unwrap();
        let issued = authority
            .operator_provision(
                MobileOperatorProvisionRequest {
                    actions: vec![MobileAction::Attach],
                    session_scope: vec!["session-test".to_owned()],
                    limits: MobileLimits {
                        max_page_events: 16,
                        max_follow_up_bytes: 1_024,
                    },
                },
                1_000,
            )
            .unwrap();
        let authorization = authority
            .grant_platform_v2(
                MobilePlatformV2GrantRequest {
                    credential_id: issued.authorization.credential_id.clone(),
                    project_roots: vec!["project-test".to_owned()],
                    actions: vec![MobilePlatformV2Action::SubmitMutation],
                },
                1_001,
            )
            .unwrap();
        let preview_id = MutationPreviewId::new("preview-mobile-submit").unwrap();
        let idempotency_key = "mobile:mutation:bound";
        bridge.preview_scopes.lock().unwrap().insert(
            preview_id.as_str().to_owned(),
            MobilePreviewScope {
                project: ProjectId::new("project-test").unwrap(),
                idempotency_key: idempotency_key.to_owned(),
                expires_at_ms: 2_000,
                credential_id: authorization.credential_id.clone(),
                principal_generation: authorization.principal_generation,
            },
        );
        let submit = PlatformV2RequestMessage::new(
            RequestId::new("mobile-submit-bind-custody").unwrap(),
            PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
                MutationPreviewRef::new(preview_id, Revision::FIRST),
                MutationPreviewDigest::from_digest(Sha256::digest(b"preview")),
                None,
            )),
        );
        assert_eq!(
            bridge.exchange_mobile(
                PlatformV2Lane::V2,
                &submit.to_canonical_bytes().unwrap(),
                &authorization,
                &mut authority,
                1_002,
            ),
            Err("platform_v2_bridge_unavailable")
        );
        authority
            .authorize_platform_v2_receipt_custody(
                &authorization,
                &ProjectId::new("project-test").unwrap(),
                idempotency_key,
                1_002,
            )
            .expect("custody precedes socket exchange");
    }

    #[derive(Clone, Copy, Debug)]
    enum ConcurrentCredentialMutation {
        Refresh,
        Regrant,
        Revoke,
    }

    #[test]
    fn mobile_dispatch_fence_blocks_cross_connection_credential_mutations_until_dispatch() {
        for mutation in [
            ConcurrentCredentialMutation::Refresh,
            ConcurrentCredentialMutation::Regrant,
            ConcurrentCredentialMutation::Revoke,
        ] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let uid = nix::unistd::geteuid().as_raw();
            write_policy(root.path(), uid, "tenant-test", "actor-test");
            let database = root.path().join("mobile.sqlite3");
            let mut dispatch_authority = MobileCredentialAuthority::open_scoped(
                &database,
                "ops.example.test",
                "tenant-test",
                "actor-test",
            )
            .unwrap();
            let issued = dispatch_authority
                .operator_provision(
                    MobileOperatorProvisionRequest {
                        actions: vec![MobileAction::Attach],
                        session_scope: vec!["session-test".to_owned()],
                        limits: MobileLimits {
                            max_page_events: 16,
                            max_follow_up_bytes: 1_024,
                        },
                    },
                    1_000,
                )
                .unwrap();
            let authorization = dispatch_authority
                .grant_platform_v2(
                    MobilePlatformV2GrantRequest {
                        credential_id: issued.authorization.credential_id.clone(),
                        project_roots: vec!["project-test".to_owned()],
                        actions: vec![MobilePlatformV2Action::QueryWorkContexts],
                    },
                    1_001,
                )
                .unwrap();
            let mut mutation_authority = MobileCredentialAuthority::open_scoped(
                &database,
                "ops.example.test",
                "tenant-test",
                "actor-test",
            )
            .unwrap();
            let socket = root.path().join("admin.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
                stream.read_exact(&mut prefix).unwrap();
                let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
                stream.read_exact(&mut payload).unwrap();
                let request =
                    PlatformNegotiationRequestMessage::from_canonical_bytes(&payload).unwrap();
                let response = PlatformNegotiationResponseMessage::for_request(
                    &request,
                    PlatformNegotiationResponse::Refused(
                        PlatformV2Refusal::new("fixture_refused", "fixture refusal").unwrap(),
                    ),
                )
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
                stream
                    .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            });

            let request = negotiation_request();
            let request_bytes = request.to_canonical_bytes().unwrap();
            let lease = dispatch_authority
                .acquire_platform_v2_dispatch(
                    &authorization,
                    MobilePlatformV2ReceiptCustody::None,
                    &request_bytes,
                    1_002,
                )
                .unwrap();
            let credential_id = issued.authorization.credential_id.clone();
            let mut refresh_token = issued.refresh_token.clone();
            let server_identity = issued.authorization.server_identity.clone();
            let writer = thread::spawn(move || {
                let result = match mutation {
                    ConcurrentCredentialMutation::Refresh => mutation_authority
                        .refresh(&mut refresh_token, &server_identity, 1_003)
                        .map(|_| ()),
                    ConcurrentCredentialMutation::Regrant => mutation_authority
                        .grant_platform_v2(
                            MobilePlatformV2GrantRequest {
                                credential_id,
                                project_roots: vec!["project-test".to_owned()],
                                actions: vec![MobilePlatformV2Action::GetLineage],
                            },
                            1_003,
                        )
                        .map(|_| ()),
                    ConcurrentCredentialMutation::Revoke => mutation_authority
                        .revoke_credential_id(
                            MobileCredentialRevokeRequest { credential_id },
                            1_003,
                        )
                        .map(|_| ()),
                };
                (mutation_authority, result.map_err(|error| error.category()))
            });
            let (mut mutation_authority, mutation_result) = writer.join().unwrap();
            assert_eq!(
                mutation_result,
                Err("mobile_platform_v2_dispatch_busy"),
                "{mutation:?}"
            );
            let response = bridge(root.path(), socket, "tenant-test", "actor-test")
                .exchange_mobile_local(PlatformV2Lane::Negotiation, &request_bytes)
                .unwrap();
            let response =
                PlatformNegotiationResponseMessage::from_canonical_bytes(&response, &request)
                    .unwrap();
            assert!(matches!(
                response.response(),
                PlatformNegotiationResponse::Refused(value)
                    if value.category().as_str() == "fixture_refused"
            ));
            dispatch_authority
                .release_platform_v2_dispatch(&lease)
                .unwrap();
            server.join().unwrap();
            let mut retry_refresh_token = issued.refresh_token.clone();
            let retry_result = match mutation {
                ConcurrentCredentialMutation::Refresh => mutation_authority
                    .refresh(
                        &mut retry_refresh_token,
                        &issued.authorization.server_identity,
                        1_004,
                    )
                    .map(|_| ()),
                ConcurrentCredentialMutation::Regrant => mutation_authority
                    .grant_platform_v2(
                        MobilePlatformV2GrantRequest {
                            credential_id: issued.authorization.credential_id.clone(),
                            project_roots: vec!["project-test".to_owned()],
                            actions: vec![MobilePlatformV2Action::GetLineage],
                        },
                        1_004,
                    )
                    .map(|_| ()),
                ConcurrentCredentialMutation::Revoke => mutation_authority
                    .revoke_credential_id(
                        MobileCredentialRevokeRequest {
                            credential_id: issued.authorization.credential_id.clone(),
                        },
                        1_004,
                    )
                    .map(|_| ()),
            };
            assert!(retry_result.is_ok(), "{mutation:?}");
            assert!(
                dispatch_authority
                    .reauthorize_platform_v2(&authorization, 1_005)
                    .is_err(),
                "{mutation:?}"
            );
        }
    }

    #[test]
    fn crash_after_submit_dispatch_keeps_durable_receipt_custody_recoverable() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        write_policy(root.path(), uid, "tenant-test", "actor-test");
        let database = root.path().join("mobile.sqlite3");
        let mut authority = MobileCredentialAuthority::open_scoped(
            &database,
            "ops.example.test",
            "tenant-test",
            "actor-test",
        )
        .unwrap();
        let authorization = grant_mobile(
            &mut authority,
            vec![MobilePlatformV2Action::SubmitMutation],
            vec!["project-test"],
        );
        let project = ProjectId::new("project-test").unwrap();
        let idempotency_key = "mobile:mutation:crash-recovery";
        let submit = PlatformV2RequestMessage::new(
            RequestId::new("mobile-submit-crash-recovery").unwrap(),
            PlatformV2Request::SubmitMutation(MutationSubmitRequest::new(
                MutationPreviewRef::new(
                    MutationPreviewId::new("preview-mobile-crash").unwrap(),
                    Revision::FIRST,
                ),
                MutationPreviewDigest::from_digest(Sha256::digest(b"preview-crash")),
                None,
            )),
        );
        let submit_bytes = submit.to_canonical_bytes().unwrap();
        let lease = authority
            .acquire_platform_v2_dispatch(
                &authorization,
                MobilePlatformV2ReceiptCustody::Bind {
                    project: &project,
                    idempotency_key,
                },
                &submit_bytes,
                1_002,
            )
            .unwrap();
        let socket = root.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
            stream.read_exact(&mut prefix).unwrap();
            let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut payload).unwrap();
            let request = PlatformV2RequestMessage::from_canonical_bytes(&payload).unwrap();
            assert!(matches!(
                request.request(),
                PlatformV2Request::SubmitMutation(_)
            ));
            let response = PlatformV2ResponseMessage::for_request(
                &request,
                PlatformV2Response::Refused(
                    PlatformV2Refusal::new("fixture_refused", "fixture refusal").unwrap(),
                ),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let response = bridge(root.path(), socket, "tenant-test", "actor-test")
            .exchange_mobile_local(PlatformV2Lane::V2, &submit_bytes)
            .unwrap();
        PlatformV2ResponseMessage::from_canonical_bytes(&response, &submit).unwrap();
        server.join().unwrap();

        // Simulate process loss after daemon dispatch but before lease release.
        drop(lease);
        drop(authority);
        let mut restarted = MobileCredentialAuthority::open_scoped(
            &database,
            "ops.example.test",
            "tenant-test",
            "actor-test",
        )
        .unwrap();
        restarted
            .authorize_platform_v2_receipt_custody(
                &authorization,
                &project,
                idempotency_key,
                1_002 + crate::mobile_auth::MOBILE_V2_DISPATCH_LEASE_MILLIS + 1,
            )
            .expect("committed custody survives crash and expired lease cleanup");
    }

    #[test]
    fn missing_or_mismatched_binding_returns_correlated_typed_refusals() {
        let root = tempfile::tempdir().unwrap();
        let request = negotiation_request();
        let unavailable = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-test",
            "actor-test",
        )
        .exchange(
            PlatformV2Lane::Negotiation,
            &request.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let response =
            PlatformNegotiationResponseMessage::from_canonical_bytes(&unavailable, &request)
                .unwrap();
        assert!(matches!(
            response.response(),
            PlatformNegotiationResponse::Refused(value)
                if value.category().as_str() == "platform_v2_web_binding_unavailable"
        ));

        write_policy(
            root.path(),
            nix::unistd::geteuid().as_raw(),
            "tenant-policy",
            "actor-policy",
        );
        let request = v2_request();
        let mismatch = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-web",
            "actor-web",
        )
        .exchange(PlatformV2Lane::V2, &request.to_canonical_bytes().unwrap())
        .unwrap();
        let response =
            PlatformV2ResponseMessage::from_canonical_bytes(&mismatch, &request).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value)
                if value.category().as_str() == "platform_v2_web_binding_mismatch"
        ));
    }

    #[test]
    fn exact_binding_relays_only_validated_correlated_envelopes() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        write_policy(root.path(), uid, "tenant-test", "actor-test");
        let socket = root.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
            stream.read_exact(&mut prefix).unwrap();
            let length = u32::from_be_bytes(prefix) as usize;
            assert!(length <= MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES);
            let mut payload = vec![0_u8; length];
            stream.read_exact(&mut payload).unwrap();
            let request = PlatformV2RequestMessage::from_canonical_bytes(&payload).unwrap();
            let response = PlatformV2ResponseMessage::for_request(
                &request,
                PlatformV2Response::Refused(
                    PlatformV2Refusal::new("fixture_refused", "fixture refusal").unwrap(),
                ),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });

        let request = v2_request();
        let response = bridge(root.path(), socket, "tenant-test", "actor-test")
            .exchange(PlatformV2Lane::V2, &request.to_canonical_bytes().unwrap())
            .unwrap();
        let response =
            PlatformV2ResponseMessage::from_canonical_bytes(&response, &request).unwrap();
        assert!(matches!(
            response.response(),
            PlatformV2Response::Refused(value) if value.category().as_str() == "fixture_refused"
        ));
        server.join().unwrap();
    }

    #[test]
    fn malformed_and_oversized_inputs_never_reach_the_socket() {
        let root = tempfile::tempdir().unwrap();
        write_policy(
            root.path(),
            nix::unistd::geteuid().as_raw(),
            "tenant-test",
            "actor-test",
        );
        let bridge = bridge(
            root.path(),
            root.path().join("absent.sock"),
            "tenant-test",
            "actor-test",
        );
        assert_eq!(
            bridge.exchange(PlatformV2Lane::V2, br#"{"not":"an envelope"}"#),
            Err("platform_v2_request_invalid")
        );
        assert_eq!(
            bridge.exchange(
                PlatformV2Lane::Negotiation,
                &vec![b'x'; MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES + 1],
            ),
            Err("platform_v2_request_invalid")
        );
    }

    #[test]
    fn mismatched_or_oversized_daemon_responses_are_never_forwarded() {
        for oversized in [false, true] {
            let root = tempfile::tempdir().unwrap();
            write_policy(
                root.path(),
                nix::unistd::geteuid().as_raw(),
                "tenant-test",
                "actor-test",
            );
            let socket = root.path().join("admin.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
                stream.read_exact(&mut prefix).unwrap();
                let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
                stream.read_exact(&mut payload).unwrap();
                if oversized {
                    stream
                        .write_all(
                            &u32::try_from(MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES + 1)
                                .unwrap()
                                .to_be_bytes(),
                        )
                        .unwrap();
                    return;
                }
                let wrong_request = PlatformV2RequestMessage::new(
                    RequestId::new("different-correlation").unwrap(),
                    PlatformV2Request::GetWorkContext(WorkContextIdentity::Project(
                        ProjectId::new("project-test").unwrap(),
                    )),
                );
                let response = PlatformV2ResponseMessage::for_request(
                    &wrong_request,
                    PlatformV2Response::Refused(
                        PlatformV2Refusal::new("fixture_refused", "fixture refusal").unwrap(),
                    ),
                )
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
                stream
                    .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            });

            let request = v2_request();
            let error = bridge(root.path(), socket, "tenant-test", "actor-test")
                .exchange(PlatformV2Lane::V2, &request.to_canonical_bytes().unwrap())
                .unwrap_err();
            assert_eq!(
                error,
                if oversized {
                    "platform_v2_response_too_large"
                } else {
                    "platform_v2_response_invalid"
                }
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn bounded_request_uses_one_wall_clock_deadline_against_trickled_responses() {
        let root = tempfile::tempdir().unwrap();
        write_policy(
            root.path(),
            nix::unistd::geteuid().as_raw(),
            "tenant-test",
            "actor-test",
        );
        let socket = root.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
            stream.read_exact(&mut prefix).unwrap();
            let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut payload).unwrap();
            let request = PlatformV2RequestMessage::from_canonical_bytes(&payload).unwrap();
            let response = PlatformV2ResponseMessage::for_request(
                &request,
                PlatformV2Response::Refused(
                    PlatformV2Refusal::new("fixture_refused", "fixture refusal").unwrap(),
                ),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
            stream
                .write_all(&u32::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            for byte in response {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });

        let started = Instant::now();
        let result = bridge(root.path(), socket, "tenant-test", "actor-test")
            .request_with_timeout(v2_request().request().clone(), Duration::from_millis(100));
        let elapsed = started.elapsed();
        assert_eq!(result, Err("platform_v2_bridge_unavailable"));
        assert!(elapsed >= Duration::from_millis(70), "elapsed {elapsed:?}");
        assert!(elapsed < Duration::from_millis(500), "elapsed {elapsed:?}");
        server.join().unwrap();
    }
}
