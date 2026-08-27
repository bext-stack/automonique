// SPDX-License-Identifier: Elastic-2.0

//! Authenticated HTTP-to-local Platform v2 bridge.
//!
//! HTTP credentials never cross the local socket. The caller first proves the
//! request came from the web entry's one configured Basic principal; this
//! module then rechecks that the server-owned tenant and actor are the sole
//! Platform v2 principal mapped to the web process uid. The public request
//! carries no actor, tenant, grant, or review-authority assertion.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, encode_frame_with_limit};
use automonique_protocol::platform_v2_transport::{
    MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES, MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES, PlatformNegotiationRequestMessage,
    PlatformNegotiationResponse, PlatformNegotiationResponseMessage, PlatformV2Refusal,
    PlatformV2RequestMessage, PlatformV2Response, PlatformV2ResponseMessage,
};

pub(crate) const PLATFORM_NEGOTIATION_CONTENT_TYPE: &str =
    "application/vnd.automonique.platform.negotiation.v1+json";
pub(crate) const PLATFORM_V2_CONTENT_TYPE: &str = "application/vnd.automonique.platform.v2+json";

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
        }
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
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + request.len());
        encode_frame_with_limit(request, &mut frame, lane.request_limit())
            .map_err(|_| "platform_v2_request_invalid")?;
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|_| "platform_v2_bridge_unavailable")?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        stream
            .write_all(&frame)
            .and_then(|()| stream.flush())
            .map_err(|_| "platform_v2_bridge_unavailable")?;

        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        stream
            .read_exact(&mut prefix)
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| "platform_v2_response_invalid")?;
        if length == 0 || length > lane.response_limit() {
            return Err("platform_v2_response_too_large");
        }
        let mut response = vec![0_u8; length];
        stream
            .read_exact(&mut response)
            .map_err(|_| "platform_v2_bridge_unavailable")?;
        Ok(response)
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

    use automonique_protocol::codec::RequestId;
    use automonique_protocol::platform_v2::{PlatformVersionOffer, ProjectId, WorkContextIdentity};
    use automonique_protocol::platform_v2_transport::{
        PlatformNegotiationRequest, PlatformV2Request,
    };

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
}
