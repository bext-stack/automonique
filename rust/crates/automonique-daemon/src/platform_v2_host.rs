// SPDX-License-Identifier: Elastic-2.0

//! Server-owned Platform v2 policy and durable host composition.
//!
//! The local transport authenticates a Unix peer before this module is called.
//! This module turns only that kernel supplied uid into an actor and scope. No
//! actor, tenant, grant, or review authority is accepted from a request body.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use automonique_protocol::identity::Actor;
use automonique_protocol::platform::ResourceAuthority;
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PlatformVersionOffer, ProjectId, UserWorkspaceId, WorkContextIdentity,
    WorkContextQueryResult, WorkContextTargetKind, negotiate_platform_version,
};
use automonique_protocol::platform_v2_lifecycle::{
    AuthorityGrantId, MutationApprovalId, MutationApprovalRequirement, MutationExplanation,
    MutationRefusal, MutationRefusalCategory, WorkContextAuthority, WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lineage::{WorkspaceIntent, WorkspaceIntentOutcome};
use automonique_protocol::platform_v2_review::{
    ReviewActionRequest, ReviewActorId, ReviewAuthentication, ReviewAuthority, ReviewAuthorityId,
    ReviewAuthorityKind,
};
use automonique_protocol::platform_v2_transport::{
    PlatformV2Refusal, PlatformV2Request, PlatformV2Response, RawMutationApprovalDocument,
    ReceiptLookupKey,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_store::lineage_index::{IntentAuthorizationScope, LineageIndex};
use automonique_store::review_store::{
    ApprovalPolicy, ReviewActionAdmission, ReviewStore, ReviewStoreError,
};
use automonique_store::work_context_store::{
    ApprovalPolicyDecision, MutationPolicyDecision, PreviewAdmission, ReceiptLookup,
    WorkContextApprovalAuthority, WorkContextNonceSource, WorkContextStore,
};
use serde::Deserialize;

pub const POLICY_FILE_NAME: &str = "platform-v2-policy.json";
pub const WORK_CONTEXT_STORE_NAME: &str = "platform-v2-work-context.sqlite3";
pub const LINEAGE_STORE_NAME: &str = "platform-v2-lineage.sqlite3";
pub const REVIEW_STORE_NAME: &str = "platform-v2-review.sqlite3";

const PREVIEW_LIFETIME_MS: i64 = 5 * 60 * 1_000;
const APPROVAL_LIFETIME_MS: i64 = 60 * 1_000;
const MAX_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Debug)]
pub enum PlatformV2Host {
    Disabled(&'static str),
    Enabled(Box<PlatformV2Runtime>),
}

#[derive(Debug)]
pub struct PlatformV2Runtime {
    principals: BTreeMap<u32, PrincipalPolicy>,
    work_contexts: WorkContextStore,
    lineage: LineageIndex,
    reviews: ReviewStore,
    nonces: HostNonces,
}

#[derive(Clone, Debug)]
struct PrincipalPolicy {
    actor: Actor,
    serving_authority: ResourceAuthority,
    projects: BTreeSet<ProjectId>,
    workspaces: BTreeMap<WorkContextIdentity, ProjectId>,
    authority: WorkContextAuthority,
    review_authorities: BTreeMap<ReviewAuthorityKind, ReviewAuthority>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    version: u8,
    principals: Vec<PrincipalDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDocument {
    uid: u32,
    tenant: String,
    actor: String,
    serving_authority: String,
    projects: Vec<String>,
    workspaces: Vec<WorkspaceDocument>,
    authority: AuthorityDocument,
    review_authorities: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceDocument {
    project: String,
    kind: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityDocument {
    filesystem: Vec<String>,
    credentials: Vec<String>,
    network: Vec<String>,
    tools: Vec<String>,
    providers: Vec<String>,
    models: Vec<String>,
}

impl PlatformV2Host {
    pub fn open(
        policy_path: &Path,
        work_context_path: &Path,
        lineage_path: &Path,
        review_path: &Path,
        expected_uid: u32,
    ) -> Self {
        match PlatformV2Runtime::open(
            policy_path,
            work_context_path,
            lineage_path,
            review_path,
            expected_uid,
        ) {
            Ok(Some(runtime)) => Self::Enabled(Box::new(runtime)),
            Ok(None) => Self::Disabled("platform_v2_unavailable"),
            Err(category) => Self::Disabled(category),
        }
    }

    pub fn available_for(&self, uid: u32) -> bool {
        matches!(self, Self::Enabled(runtime) if runtime.principals.contains_key(&uid))
    }

    pub const fn refusal_category(&self) -> &'static str {
        match self {
            Self::Disabled(category) => category,
            Self::Enabled(_) => "platform_v2_principal_unmapped",
        }
    }

    pub fn handle(
        &mut self,
        uid: u32,
        request: &PlatformV2Request,
        now_ms: i64,
    ) -> PlatformV2Response {
        match self {
            Self::Enabled(runtime) => runtime.handle(uid, request, now_ms).unwrap_or_else(refused),
            Self::Disabled(category) => refused(category),
        }
    }
}

impl PlatformV2Runtime {
    fn open(
        policy_path: &Path,
        work_context_path: &Path,
        lineage_path: &Path,
        review_path: &Path,
        expected_uid: u32,
    ) -> Result<Option<Self>, &'static str> {
        if !policy_path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(policy_path).map_err(|_| "platform_v2_policy_io")?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() > MAX_POLICY_BYTES
        {
            return Err("platform_v2_policy_insecure");
        }
        let bytes = fs::read(policy_path).map_err(|_| "platform_v2_policy_io")?;
        let document: PolicyDocument =
            serde_json::from_slice(&bytes).map_err(|_| "platform_v2_policy_invalid")?;
        let principals = parse_policy(document)?;
        if principals.len() != 1 || !principals.contains_key(&expected_uid) {
            // The admin socket currently admits only this daemon's effective
            // uid. Refuse dead or cross-tenant policy entries instead of
            // keeping authority that no authenticated peer can exercise.
            return Err("platform_v2_policy_invalid");
        }
        let work_contexts = WorkContextStore::open(work_context_path)
            .map_err(|_| "platform_v2_store_unavailable")?;
        let lineage =
            LineageIndex::open(lineage_path).map_err(|_| "platform_v2_store_unavailable")?;
        let tenant = principals
            .get(&expected_uid)
            .ok_or("platform_v2_policy_invalid")?
            .actor
            .tenant();
        let mut reviews = ReviewStore::open_scoped(review_path, tenant)
            .map_err(|_| "platform_v2_store_unavailable")?;
        // Grants are copied from the server-owned policy into the store. The
        // exact same grant is an idempotent replay on restart.
        for principal in principals.values() {
            let actor = ReviewActorId::new(principal.actor.id().to_owned())
                .map_err(|_| "platform_v2_policy_invalid")?;
            for workspace in principal.workspaces.keys() {
                if !matches!(
                    workspace.kind(),
                    WorkContextTargetKind::UserWorkspace
                        | WorkContextTargetKind::AttemptWorkspace
                        | WorkContextTargetKind::Session
                ) {
                    continue;
                }
                for authority in principal.review_authorities.values() {
                    reviews
                        .grant_authority(
                            workspace,
                            &actor,
                            ReviewAuthentication::UserSession,
                            authority,
                            0,
                        )
                        .map_err(|_| "platform_v2_store_unavailable")?;
                }
            }
        }
        Ok(Some(Self {
            principals,
            work_contexts,
            lineage,
            reviews,
            nonces: HostNonces::new()?,
        }))
    }

    fn handle(
        &mut self,
        uid: u32,
        request: &PlatformV2Request,
        now_ms: i64,
    ) -> Result<PlatformV2Response, &'static str> {
        let principal = self
            .principals
            .get(&uid)
            .cloned()
            .ok_or("platform_v2_principal_unmapped")?;
        match request {
            PlatformV2Request::QueryWorkContexts(query) => {
                if query
                    .project()
                    .is_some_and(|project| !principal.projects.contains(project))
                    || query
                        .parent()
                        .is_some_and(|parent| !principal.workspaces.contains_key(parent))
                {
                    return Err("platform_v2_scope_denied");
                }
                match self
                    .work_contexts
                    .inventory(
                        &principal.actor,
                        query,
                        &principal.workspaces.keys().cloned().collect(),
                        now_ms,
                    )
                    .map_err(|_| "platform_v2_store_refused")?
                {
                    WorkContextQueryResult::Page(page) => {
                        Ok(PlatformV2Response::WorkContextPage(page))
                    }
                    WorkContextQueryResult::Resync(value) => {
                        Ok(PlatformV2Response::WorkContextResync(value))
                    }
                }
            }
            PlatformV2Request::GetWorkContext(identity) => {
                let project = principal
                    .workspaces
                    .get(identity)
                    .ok_or("platform_v2_scope_denied")?;
                let policy = principal.read_policy(Some(project.clone()), identity.clone());
                self.work_contexts
                    .record(&policy, identity)
                    .map_err(|_| "platform_v2_store_refused")?
                    .map(PlatformV2Response::WorkContextRecord)
                    .ok_or("platform_v2_not_found")
            }
            PlatformV2Request::PrepareMutation(value) => {
                let proposal = WorkContextMutationProposal::new(
                    principal.actor.clone(),
                    principal.serving_authority,
                    principal.authority.clone(),
                    value.idempotency_key().clone(),
                    value.intent().clone(),
                )
                .map_err(|_| "platform_v2_request_invalid")?;
                let project = project_for_intent(value.intent(), &principal)?;
                let policy = principal.mutation_policy(
                    project,
                    proposal.request_digest(),
                    MutationApprovalRequirement::Required,
                );
                let expires = now_ms
                    .checked_add(PREVIEW_LIFETIME_MS)
                    .ok_or("platform_v2_clock_invalid")?;
                match self
                    .work_contexts
                    .prepare_mutation(&proposal, &policy, now_ms, expires, &mut self.nonces)
                    .map_err(|_| "platform_v2_mutation_refused")?
                {
                    PreviewAdmission::New(preview) | PreviewAdmission::Replay(preview) => {
                        Ok(PlatformV2Response::MutationPreview(preview))
                    }
                }
            }
            PlatformV2Request::DecideMutation(value) => {
                let expiry = now_ms
                    .checked_add(APPROVAL_LIFETIME_MS)
                    .ok_or("platform_v2_clock_invalid")?;
                let id = MutationApprovalId::new(format!("approval_{}", self.nonces.token()))
                    .map_err(|_| "platform_v2_nonce_invalid")?;
                let policy = ApprovalPolicyDecision::new(
                    principal.actor.clone(),
                    principal.serving_authority,
                    WorkContextApprovalAuthority::LifecycleMutation,
                    value.preview().clone(),
                    value.preview_digest(),
                    EpochMillis::from_millis(expiry),
                );
                let approval = self
                    .work_contexts
                    .record_approval(value.preview(), id, value.decision(), &policy, now_ms)
                    .map_err(|_| "platform_v2_decision_refused")?;
                Ok(PlatformV2Response::MutationApproval(
                    RawMutationApprovalDocument::from_approval(&approval)
                        .map_err(|_| "platform_v2_response_invalid")?,
                ))
            }
            PlatformV2Request::SubmitMutation(_) => {
                // The durable store has typed outbox reservation APIs, but no
                // host adapter is wired in this slice. Refuse before admission
                // instead of claiming an external filesystem effect occurred.
                Ok(PlatformV2Response::MutationRefused(MutationRefusal::new(
                    MutationRefusalCategory::Unavailable,
                    None,
                    MutationExplanation::new(
                        "no Platform v2 lifecycle effect adapter is configured",
                    )
                    .map_err(|_| "platform_v2_response_invalid")?,
                )))
            }
            PlatformV2Request::GetMutationReceipt(value) => {
                if !principal.projects.contains(value.project()) {
                    return Err("platform_v2_scope_denied");
                }
                let targets: BTreeSet<WorkContextIdentity> =
                    principal.workspaces.keys().cloned().collect();
                let found = match value.key() {
                    ReceiptLookupKey::ReceiptId(id) => self.work_contexts.receipt_by_id_authorized(
                        &principal.actor,
                        principal.serving_authority,
                        &principal.authority,
                        value.project(),
                        &targets,
                        id,
                    ),
                    ReceiptLookupKey::IdempotencyKey(key) => {
                        self.work_contexts.receipt_by_idempotency_key_authorized(
                            &principal.actor,
                            principal.serving_authority,
                            &principal.authority,
                            value.project(),
                            &targets,
                            key,
                        )
                    }
                }
                .map_err(|_| "platform_v2_receipt_refused")?;
                match found {
                    ReceiptLookup::Found(receipt) => Ok(PlatformV2Response::MutationReceipt(
                        automonique_protocol::platform_v2_transport::RawMutationReceiptDocument::from_receipt(&receipt)
                            .map_err(|_| "platform_v2_response_invalid")?,
                    )),
                    ReceiptLookup::Unknown => Err("platform_v2_not_found"),
                }
            }
            PlatformV2Request::GetLineage(value) => {
                authorize_workspace(&principal, value.project(), value.workspace())?;
                let scope = IntentAuthorizationScope::new(
                    principal.actor.tenant().to_owned(),
                    value.project().clone(),
                    value.workspace().clone(),
                )
                .map_err(|_| "platform_v2_scope_denied")?;
                let projection = self
                    .lineage
                    .projection_authorized(&negotiated_v2()?, &scope, |_| true)
                    .map_err(|_| "platform_v2_store_refused")?;
                Ok(PlatformV2Response::LineageResult(projection))
            }
            PlatformV2Request::SubmitWorkspaceIntent(value) => {
                if !principal.projects.contains(value.project()) {
                    return Err("platform_v2_scope_denied");
                }
                let outcome = match value.intent() {
                    WorkspaceIntent::Create(_) => return Err("platform_v2_create_adapter_pending"),
                    WorkspaceIntent::Resume(intent) => {
                        authorize_workspace(&principal, value.project(), intent.workspace())?;
                        WorkspaceIntentOutcome::Accepted
                    }
                    WorkspaceIntent::Cancel(intent) => {
                        authorize_workspace(&principal, value.project(), intent.workspace())?;
                        WorkspaceIntentOutcome::Cancelled(intent.target_intent_id().clone())
                    }
                };
                self.lineage
                    .record_intent(principal.actor.tenant(), value.intent(), &outcome)
                    .map_err(|_| "platform_v2_intent_refused")?;
                Ok(PlatformV2Response::WorkspaceIntentResult(outcome))
            }
            PlatformV2Request::GetWorkspaceIntent(value) => {
                if !principal.projects.contains(value.project()) {
                    return Err("platform_v2_scope_denied");
                }
                // Intent ids are deliberately not global lookup keys. Search
                // only the caller's explicitly visible workspaces.
                for (workspace, project) in &principal.workspaces {
                    if project != value.project() {
                        continue;
                    }
                    let WorkContextIdentity::UserWorkspace(workspace) = workspace else {
                        continue;
                    };
                    let scope = IntentAuthorizationScope::new(
                        principal.actor.tenant().to_owned(),
                        project.clone(),
                        workspace.clone(),
                    )
                    .map_err(|_| "platform_v2_scope_denied")?;
                    if let Some(stored) = self
                        .lineage
                        .intent_authorized(&negotiated_v2()?, &scope, value.intent_id(), |_| true)
                        .map_err(|_| "platform_v2_store_refused")?
                    {
                        return Ok(PlatformV2Response::WorkspaceIntentResult(stored.outcome));
                    }
                }
                Err("platform_v2_not_found")
            }
            PlatformV2Request::GetReview(value) => {
                authorize_identity(&principal, value.project(), value.workspace())?;
                self.reviews
                    .snapshot(value.workspace())
                    .map_err(|_| "platform_v2_store_refused")?
                    .map(PlatformV2Response::ReviewResult)
                    .ok_or("platform_v2_not_found")
            }
            PlatformV2Request::ExecuteReviewAction(value) => {
                let project = principal
                    .workspaces
                    .get(value.workspace())
                    .ok_or("platform_v2_scope_denied")?;
                if !principal.projects.contains(project) {
                    return Err("platform_v2_scope_denied");
                }
                let authority = principal
                    .review_authorities
                    .get(&value.action().required_authority())
                    .cloned()
                    .ok_or("platform_v2_review_role_denied")?;
                let request = ReviewActionRequest::new(
                    value.workspace().clone(),
                    value.expected_revision(),
                    ReviewActorId::new(principal.actor.id().to_owned())
                        .map_err(|_| "platform_v2_policy_invalid")?,
                    ReviewAuthentication::UserSession,
                    authority,
                    value.idempotency_key().clone(),
                    value.action().clone(),
                )
                .map_err(|_| "platform_v2_request_invalid")?;
                let admission = self
                    .reviews
                    .prepare_action(&request, ApprovalPolicy::Required, now_ms)
                    .map_err(|_| "platform_v2_review_refused")?;
                let stored = match admission {
                    ReviewActionAdmission::New(value) | ReviewActionAdmission::Replay(value) => {
                        value
                    }
                };
                // Preparation is custody, not evidence that git/CI/PR ran.
                Ok(PlatformV2Response::ReviewReceipt(stored.receipt))
            }
            PlatformV2Request::GetReviewReceipt(value) => {
                authorize_identity(&principal, value.project(), value.workspace())?;
                let actor = ReviewActorId::new(principal.actor.id().to_owned())
                    .map_err(|_| "platform_v2_policy_invalid")?;
                for authority in principal.review_authorities.values() {
                    let receipt = self.reviews.receipt(
                        value.workspace(),
                        &actor,
                        ReviewAuthentication::UserSession,
                        authority,
                        value.idempotency_key(),
                        now_ms,
                    );
                    match receipt {
                        Ok(Some(receipt)) => {
                            return Ok(PlatformV2Response::ReviewReceipt(receipt));
                        }
                        Ok(None) | Err(ReviewStoreError::Unauthorized) => {}
                        Err(_) => return Err("platform_v2_receipt_refused"),
                    }
                }
                Err("platform_v2_not_found")
            }
        }
    }
}

impl PrincipalPolicy {
    fn read_policy(
        &self,
        project: Option<ProjectId>,
        identity: WorkContextIdentity,
    ) -> MutationPolicyDecision {
        MutationPolicyDecision::for_read(
            self.actor.clone(),
            self.serving_authority,
            project,
            BTreeSet::from([identity]),
        )
    }

    fn mutation_policy(
        &self,
        project: Option<ProjectId>,
        digest: automonique_protocol::platform_v2_lifecycle::WorkContextRequestDigest,
        approval: MutationApprovalRequirement,
    ) -> MutationPolicyDecision {
        MutationPolicyDecision::new(
            self.actor.clone(),
            self.serving_authority,
            self.authority.clone(),
            self.authority.clone(),
            project,
            self.workspaces.keys().cloned().collect(),
            digest,
            approval,
        )
    }
}

fn parse_policy(document: PolicyDocument) -> Result<BTreeMap<u32, PrincipalPolicy>, &'static str> {
    if document.version != 1 || document.principals.is_empty() || document.principals.len() > 64 {
        return Err("platform_v2_policy_invalid");
    }
    let mut result = BTreeMap::new();
    for raw in document.principals {
        let actor =
            Actor::new(&raw.tenant, &raw.actor).map_err(|_| "platform_v2_policy_invalid")?;
        let serving_authority = ResourceAuthority::parse(&raw.serving_authority)
            .map_err(|_| "platform_v2_policy_invalid")?;
        let projects: BTreeSet<ProjectId> = raw
            .projects
            .into_iter()
            .map(|value| ProjectId::new(value).map_err(|_| "platform_v2_policy_invalid"))
            .collect::<Result<_, _>>()?;
        if projects.is_empty() || projects.len() > 128 {
            return Err("platform_v2_policy_invalid");
        }
        let mut workspaces = BTreeMap::new();
        for raw_workspace in raw.workspaces {
            let project =
                ProjectId::new(raw_workspace.project).map_err(|_| "platform_v2_policy_invalid")?;
            if !projects.contains(&project) {
                return Err("platform_v2_policy_invalid");
            }
            let kind = WorkContextTargetKind::parse(&raw_workspace.kind)
                .map_err(|_| "platform_v2_policy_invalid")?;
            let identity = WorkContextIdentity::parse_local(kind, &raw_workspace.id)
                .map_err(|_| "platform_v2_policy_invalid")?;
            if workspaces.insert(identity, project).is_some() || workspaces.len() > 1024 {
                return Err("platform_v2_policy_invalid");
            }
        }
        let authority = WorkContextAuthority::new(
            grants(raw.authority.filesystem)?,
            grants(raw.authority.credentials)?,
            grants(raw.authority.network)?,
            grants(raw.authority.tools)?,
            grants(raw.authority.providers)?,
            grants(raw.authority.models)?,
        )
        .map_err(|_| "platform_v2_policy_invalid")?;
        let mut review_authorities = BTreeMap::new();
        for (kind, id) in raw.review_authorities {
            let kind =
                ReviewAuthorityKind::parse(&kind).map_err(|_| "platform_v2_policy_invalid")?;
            let authority = ReviewAuthority::new(
                kind,
                ReviewAuthorityId::new(id).map_err(|_| "platform_v2_policy_invalid")?,
            );
            if review_authorities.insert(kind, authority).is_some() {
                return Err("platform_v2_policy_invalid");
            }
        }
        if result
            .insert(
                raw.uid,
                PrincipalPolicy {
                    actor,
                    serving_authority,
                    projects,
                    workspaces,
                    authority,
                    review_authorities,
                },
            )
            .is_some()
        {
            return Err("platform_v2_policy_invalid");
        }
    }
    Ok(result)
}

fn grants(values: Vec<String>) -> Result<Vec<AuthorityGrantId>, &'static str> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("platform_v2_policy_invalid");
    }
    values
        .into_iter()
        .map(|value| AuthorityGrantId::new(value).map_err(|_| "platform_v2_policy_invalid"))
        .collect()
}

fn authorize_identity(
    principal: &PrincipalPolicy,
    project: &ProjectId,
    identity: &WorkContextIdentity,
) -> Result<(), &'static str> {
    if principal.projects.contains(project)
        && principal
            .workspaces
            .get(identity)
            .is_some_and(|owner| owner == project)
    {
        Ok(())
    } else {
        Err("platform_v2_scope_denied")
    }
}

fn authorize_workspace(
    principal: &PrincipalPolicy,
    project: &ProjectId,
    workspace: &UserWorkspaceId,
) -> Result<(), &'static str> {
    authorize_identity(
        principal,
        project,
        &WorkContextIdentity::UserWorkspace(workspace.clone()),
    )
}

fn project_for_intent(
    intent: &automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent,
    principal: &PrincipalPolicy,
) -> Result<Option<ProjectId>, &'static str> {
    use automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent;
    let identity = match intent {
        WorkContextMutationIntent::CreateProject(_) => return Ok(None),
        WorkContextMutationIntent::CreateHostSetup(value) => value.project().identity(),
        WorkContextMutationIntent::CreateCheckout(value) => value.project().identity(),
        WorkContextMutationIntent::CreateUserWorkspace(value) => value.project().identity(),
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => {
            value.user_workspace().identity()
        }
        WorkContextMutationIntent::ResumeAttemptWorkspace(value) => value.target().identity(),
        WorkContextMutationIntent::ResumeSession(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveProject(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveHostSetup(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveCheckout(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveUserWorkspace(value) => value.target().identity(),
    };
    match identity {
        WorkContextIdentity::Project(project) if principal.projects.contains(project) => {
            Ok(Some(project.clone()))
        }
        identity => principal
            .workspaces
            .get(identity)
            .cloned()
            .map(Some)
            .ok_or("platform_v2_scope_denied"),
    }
}

fn negotiated_v2() -> Result<NegotiatedPlatform, &'static str> {
    let offer = PlatformVersionOffer::new(vec![2]).map_err(|_| "platform_v2_negotiation")?;
    negotiate_platform_version(&offer, &offer).map_err(|_| "platform_v2_negotiation")
}

fn refused(category: &str) -> PlatformV2Response {
    let category = if category.len() > 128 {
        "platform_v2_refused"
    } else {
        category
    };
    PlatformV2Response::Refused(
        PlatformV2Refusal::new(category, "the server refused this Platform v2 request")
            .expect("static refusal fields are valid"),
    )
}

#[derive(Debug)]
struct HostNonces {
    counter: u64,
    seed: [u8; 16],
}

impl HostNonces {
    fn new() -> Result<Self, &'static str> {
        let mut seed = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut seed))
            .map_err(|_| "platform_v2_nonce_unavailable")?;
        Ok(Self { counter: 0, seed })
    }

    fn token(&mut self) -> String {
        let nonce = self.nonce();
        nonce.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl WorkContextNonceSource for HostNonces {
    fn nonce(&mut self) -> [u8; 16] {
        self.counter = self.counter.wrapping_add(1);
        let mut material = Vec::with_capacity(24);
        material.extend_from_slice(&self.seed);
        material.extend_from_slice(&self.counter.to_be_bytes());
        let digest = automonique_protocol::digest::Sha256::digest(&material);
        let mut nonce = [0_u8; 16];
        nonce.copy_from_slice(&digest.as_bytes()[..16]);
        nonce
    }
}
