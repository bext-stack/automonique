// SPDX-License-Identifier: Elastic-2.0

//! Authenticated HTTP-to-local Platform v2 bridge.
//!
//! HTTP credentials never cross the local socket. The caller first proves the
//! request came from the web entry's one configured Basic principal; this
//! module then rechecks that the server-owned tenant and actor are the sole
//! Platform v2 principal mapped to the web process uid. The public request
//! carries no actor, tenant, grant, or review-authority assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, encode_frame_with_limit};
use automonique_protocol::platform_v2::ProjectId;
use automonique_protocol::platform_v2_transport::{
    MAX_PLATFORM_NEGOTIATION_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_NEGOTIATION_RESPONSE_CANONICAL_BYTES, MAX_PLATFORM_V2_REQUEST_CANONICAL_BYTES,
    MAX_PLATFORM_V2_RESPONSE_CANONICAL_BYTES, PlatformNegotiationRequestMessage,
    PlatformNegotiationResponse, PlatformNegotiationResponseMessage, PlatformV2Refusal,
    PlatformV2RequestMessage, PlatformV2Response, PlatformV2ResponseMessage, ReceiptLookupKey,
};

use crate::mobile_auth::{
    MobileCredentialAuthority, MobilePlatformV2Action, MobilePlatformV2Authorization,
};

pub(crate) const PLATFORM_NEGOTIATION_CONTENT_TYPE: &str =
    "application/vnd.automonique.platform.negotiation.v1+json";
pub(crate) const PLATFORM_V2_CONTENT_TYPE: &str = "application/vnd.automonique.platform.v2+json";
const MAX_MOBILE_PREVIEW_SCOPES: usize = 128;

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
    preview_scopes: Mutex<BTreeMap<String, (ProjectId, String, i64, String, u64)>>,
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
                if let automonique_protocol::platform_v2_transport::PlatformV2Request::GetMutationReceipt(
                    lookup,
                ) = request.request()
                {
                    let ReceiptLookupKey::IdempotencyKey(idempotency_key) = lookup.key() else {
                        return typed_v2_refusal(
                            &request,
                            "platform_v2_mobile_receipt_custody_required",
                        );
                    };
                    if authority
                        .authorize_platform_v2_receipt_custody(
                            authorization,
                            &project,
                            idempotency_key.as_str(),
                            now_ms,
                        )
                        .is_err()
                    {
                        return typed_v2_refusal(
                            &request,
                            "platform_v2_mobile_receipt_custody_denied",
                        );
                    }
                }
                if let Some(idempotency_key) = submit_idempotency_key
                    && authority
                        .bind_platform_v2_receipt_custody(
                            authorization,
                            &project,
                            &idempotency_key,
                            now_ms,
                        )
                        .is_err()
                {
                    return typed_v2_refusal(&request, "platform_v2_mobile_receipt_custody_denied");
                }
                let response = self.exchange_local(
                    lane,
                    &request
                        .to_canonical_bytes()
                        .map_err(|_| "platform_v2_request_invalid")?,
                )?;
                let response = PlatformV2ResponseMessage::from_canonical_bytes(&response, &request)
                    .map_err(|_| "platform_v2_response_invalid")?;
                if let PlatformV2Response::MutationPreview(preview) = response.response() {
                    let mut scopes = self
                        .preview_scopes
                        .lock()
                        .map_err(|_| "platform_v2_bridge_unavailable")?;
                    scopes.retain(|_, (_, _, expiry, _, _)| *expiry > now_ms);
                    if scopes.len() >= MAX_MOBILE_PREVIEW_SCOPES
                        && !scopes.contains_key(preview.preview().id().as_str())
                    {
                        return typed_v2_refusal(&request, "platform_v2_mobile_preview_limit");
                    }
                    scopes.insert(
                        preview.preview().id().as_str().to_owned(),
                        (
                            project,
                            preview.proposal().idempotency_key().as_str().to_owned(),
                            preview.expires_at().as_millis(),
                            authorization.credential_id.clone(),
                            authorization.principal_generation,
                        ),
                    );
                }
                response
                    .to_canonical_bytes()
                    .map_err(|_| "platform_v2_response_invalid")
            }
        }
    }

    pub(crate) fn refuse(
        &self,
        lane: PlatformV2Lane,
        request: &[u8],
        category: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        match lane {
            PlatformV2Lane::Negotiation => {
                let request = PlatformNegotiationRequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                typed_negotiation_refusal(&request, category)
            }
            PlatformV2Lane::V2 => {
                let request = PlatformV2RequestMessage::from_canonical_bytes(request)
                    .map_err(|_| "platform_v2_request_invalid")?;
                typed_v2_refusal(&request, category)
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
        scopes.retain(|_, (_, _, expiry, _, _)| *expiry > now_ms);
        scopes
            .get(preview_id)
            .filter(|(_, _, _, credential_id, generation)| {
                credential_id == &authorization.credential_id
                    && *generation == authorization.principal_generation
            })
            .map(|(project, idempotency_key, _, _, _)| (project.clone(), idempotency_key.clone()))
            .ok_or("platform_v2_mobile_preview_scope_required")
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

    use crate::mobile_auth::{
        MobileAction, MobileLimits, MobileOperatorProvisionRequest, MobilePlatformV2GrantRequest,
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

    fn mobile(
        actions: Vec<MobilePlatformV2Action>,
        roots: Vec<&str>,
    ) -> MobilePlatformV2Authorization {
        MobilePlatformV2Authorization {
            actions,
            actor_id: "actor-test".to_owned(),
            authorization_revision: 1,
            credential_id: format!("mc_{}", "A".repeat(43)),
            credential_revision: 1,
            delegation_id: format!("md_{}", "B".repeat(43)),
            expires_at_ms: 2_000,
            issued_at_ms: 1,
            principal_generation: 1,
            project_roots: roots.into_iter().map(str::to_owned).collect(),
            schema: crate::mobile_auth::MOBILE_PLATFORM_V2_AUTH_SCHEMA,
            server_identity: format!("sha256:{}", "c".repeat(64)),
            tenant_id: "tenant-test".to_owned(),
        }
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
        let wrong_action = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &request.to_canonical_bytes().unwrap(),
                &mobile(
                    vec![MobilePlatformV2Action::GetLineage],
                    vec!["project-test"],
                ),
                &mut authority,
                1_000,
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
        let wrong_root = bridge
            .exchange_mobile(
                PlatformV2Lane::V2,
                &query.to_canonical_bytes().unwrap(),
                &mobile(
                    vec![MobilePlatformV2Action::QueryWorkContexts],
                    vec!["project-other"],
                ),
                &mut authority,
                1_000,
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
            (
                ProjectId::new("project-test").unwrap(),
                idempotency_key.to_owned(),
                2_000,
                authorization.credential_id.clone(),
                authorization.principal_generation,
            ),
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
