// SPDX-License-Identifier: Elastic-2.0

//! Server-owned Platform v2 policy and durable host composition.
//!
//! The local transport authenticates a Unix peer before this module is called.
//! This module turns only that kernel supplied uid into an actor and scope. No
//! actor, tenant, grant, or review authority is accepted from a request body.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{ReceiptId, ResourceAuthority};
use automonique_protocol::platform_v2::{
    NegotiatedPlatform, PlatformVersionOffer, ProjectId, UserWorkspaceId, WorkContextIdentity,
    WorkContextQueryResult, WorkContextTargetKind, negotiate_platform_version,
};
use automonique_protocol::platform_v2_lifecycle::{
    AuthorityGrantId, MutationApprovalId, MutationApprovalRequirement, MutationExplanation,
    MutationRefusal, MutationRefusalCategory, WorkContextAuthority, WorkContextMutationIntent,
    WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lineage::{WorkspaceIntent, WorkspaceIntentOutcome};
use automonique_protocol::platform_v2_review::{
    ReviewActionRequest, ReviewActorId, ReviewAuthentication, ReviewAuthority, ReviewAuthorityId,
    ReviewAuthorityKind,
};
use automonique_protocol::platform_v2_transport::{
    LIFECYCLE_CAPABILITY_EFFECT_KINDS, LifecycleCapabilities, LifecycleOperationCapability,
    PlatformV2Refusal, PlatformV2Request, PlatformV2Response, RawMutationApprovalDocument,
    RawMutationReceiptDocument, ReceiptLookupKey,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_store::lineage_index::WorkspaceIntentExecutionReceipt;
use automonique_store::lineage_index::{IntentAuthorizationScope, LineageIndex};
use automonique_store::review_store::{ReviewStore, ReviewStoreError};
use automonique_store::work_context_store::{
    ApprovalPolicyDecision, ExternalEffectCompletionPolicy, ExternalEffectExecutorPolicy,
    ExternalEffectReconciliation, ExternalEffectReconciliationOutcome,
    ExternalEffectRecoveryPolicy, MutationPolicyDecision, PreviewAdmission, ProviderEffectEvidence,
    ReceiptAdmission, ReceiptLookup, WorkContextApprovalAuthority, WorkContextNonceSource,
    WorkContextStore, WorkContextStoreError,
};
use serde::Deserialize;

use crate::platform_v2_review_adapter::{ProductionReviewEffectAdapter, ReviewEffectPlan};

pub const POLICY_FILE_NAME: &str = "platform-v2-policy.json";
pub const WORK_CONTEXT_STORE_NAME: &str = "platform-v2-work-context.sqlite3";
pub const LINEAGE_STORE_NAME: &str = "platform-v2-lineage.sqlite3";
pub const REVIEW_STORE_NAME: &str = "platform-v2-review.sqlite3";

const PREVIEW_LIFETIME_MS: i64 = 5 * 60 * 1_000;
const APPROVAL_LIFETIME_MS: i64 = 60 * 1_000;
const EFFECT_LEASE_LIFETIME_MS: i64 = 30 * 1_000;
const MAX_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Debug)]
pub enum PlatformV2Host {
    Disabled(&'static str),
    Enabled(Box<PlatformV2Runtime>),
}

pub struct PlatformV2Runtime {
    policy_fence: PolicyFence,
    principals: BTreeMap<u32, PrincipalPolicy>,
    work_contexts: WorkContextStore,
    lineage: LineageIndex,
    reviews: ReviewStore,
    review_effects: ProductionReviewEffectAdapter,
    nonces: HostNonces,
    lifecycle_effects: Box<dyn PlatformV2LifecycleEffectAdapter>,
    clock: Box<dyn PlatformV2Clock>,
}

impl std::fmt::Debug for PlatformV2Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlatformV2Runtime")
            .field("policy_fence", &self.policy_fence)
            .field("principals", &self.principals)
            .field("work_contexts", &self.work_contexts)
            .field("lineage", &self.lineage)
            .field("reviews", &self.reviews)
            .field("review_effects", &self.review_effects)
            .field("nonces", &self.nonces)
            .field("lifecycle_effects", &"typed adapter")
            .field("clock", &"trusted clock")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformV2EffectExecution {
    Completed,
    NotStarted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformV2EffectReconciliation {
    VerifiedNotStarted(Vec<u8>),
    Completed(Vec<u8>),
    Unknown(Vec<u8>),
}

/// Typed external-effect boundary. It receives only the closed lifecycle
/// intent and server-issued identities; paths and commands are never accepted.
pub trait PlatformV2LifecycleEffectAdapter: Send {
    fn supported_effect_kinds(&self) -> BTreeSet<String>;

    fn capability_for_project(
        &self,
        _project: &ProjectId,
        effect_kind: &str,
    ) -> Result<(), &'static str> {
        if self.supported_effect_kinds().contains(effect_kind) {
            Ok(())
        } else {
            Err("platform_v2_lifecycle_adapter_pending")
        }
    }

    fn preflight(&self, _intent: &WorkContextMutationIntent) -> Result<(), &'static str> {
        Ok(())
    }

    fn preflight_submission(
        &self,
        intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        self.preflight(intent)
    }

    fn verify_generation(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn workspace_intents_supported(&self) -> bool {
        false
    }

    fn preflight_workspace_intent(
        &self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
    ) -> Result<(), &'static str> {
        Err("platform_v2_workspace_executor_unavailable")
    }

    fn execute_workspace_intent(
        &mut self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
    ) -> Result<WorkspaceIntentOutcome, &'static str> {
        Err("platform_v2_workspace_executor_unavailable")
    }

    fn execute(
        &mut self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
        idempotency_key: &automonique_protocol::platform::IdempotencyKey,
    ) -> PlatformV2EffectExecution;

    fn reconcile(
        &mut self,
        intent: &WorkContextMutationIntent,
        resulting_identity: &WorkContextIdentity,
        idempotency_key: &automonique_protocol::platform::IdempotencyKey,
    ) -> PlatformV2EffectReconciliation;
}

pub trait PlatformV2Clock: Send {
    fn now_ms(&mut self) -> Result<i64, &'static str>;
}

struct SystemPlatformV2Clock;

impl PlatformV2Clock for SystemPlatformV2Clock {
    fn now_ms(&mut self) -> Result<i64, &'static str> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "platform_v2_clock_invalid")?
            .as_millis();
        i64::try_from(millis).map_err(|_| "platform_v2_clock_invalid")
    }
}

struct UnavailableLifecycleEffectAdapter;

impl PlatformV2LifecycleEffectAdapter for UnavailableLifecycleEffectAdapter {
    fn supported_effect_kinds(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn preflight(&self, _intent: &WorkContextMutationIntent) -> Result<(), &'static str> {
        match _intent {
            WorkContextMutationIntent::CreateHostSetup(_)
            | WorkContextMutationIntent::CreateCheckout(_) => {
                Err("platform_v2_selector_registry_unavailable")
            }
            _ => Ok(()),
        }
    }

    fn capability_for_project(
        &self,
        _project: &ProjectId,
        effect_kind: &str,
    ) -> Result<(), &'static str> {
        match effect_kind {
            "create_host_setup" | "create_checkout" => {
                Err("platform_v2_selector_registry_unavailable")
            }
            _ => Err("platform_v2_lifecycle_adapter_pending"),
        }
    }

    fn execute(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &automonique_protocol::platform::IdempotencyKey,
    ) -> PlatformV2EffectExecution {
        PlatformV2EffectExecution::NotStarted
    }

    fn reconcile(
        &mut self,
        _intent: &WorkContextMutationIntent,
        _resulting_identity: &WorkContextIdentity,
        _idempotency_key: &automonique_protocol::platform::IdempotencyKey,
    ) -> PlatformV2EffectReconciliation {
        PlatformV2EffectReconciliation::Unknown(b"adapter unavailable".to_vec())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyGeneration {
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    length: u64,
    digest: Sha256Digest,
}

impl PolicyGeneration {
    pub(crate) const fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

#[derive(Debug)]
struct PolicySnapshot {
    bytes: Vec<u8>,
    generation: PolicyGeneration,
}

#[derive(Debug)]
struct PolicyFence {
    path: PathBuf,
    expected_uid: u32,
    generation: PolicyGeneration,
}

impl PolicyFence {
    fn verify(&self) -> Result<(), &'static str> {
        let current = read_policy_snapshot(&self.path, self.expected_uid)?
            .ok_or("platform_v2_policy_changed")?;
        if current.generation != self.generation {
            return Err("platform_v2_policy_changed");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PrincipalPolicy {
    actor: Actor,
    serving_authority: ResourceAuthority,
    projects: BTreeSet<ProjectId>,
    workspaces: BTreeMap<WorkContextIdentity, ScopePolicy>,
    authority: WorkContextAuthority,
    review_authorities: BTreeMap<ReviewAuthorityKind, ReviewAuthority>,
}

#[derive(Clone, Debug)]
struct ScopePolicy {
    project: ProjectId,
    inherited_authority: WorkContextAuthority,
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
    inherited_authority: AuthorityDocument,
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
        let Some(state_dir) = policy_path.parent() else {
            return Self::Disabled("platform_v2_state_path_invalid");
        };
        let adapter =
            match crate::platform_v2_lifecycle_adapter::ProductionLifecycleEffectAdapter::open(
                &state_dir.join(crate::platform_v2_lifecycle_adapter::LIFECYCLE_REGISTRY_FILE_NAME),
                &state_dir.join(crate::platform_v2_lifecycle_adapter::LIFECYCLE_JOURNAL_FILE_NAME),
                expected_uid,
            ) {
                Ok(Some(adapter)) => Box::new(adapter) as Box<dyn PlatformV2LifecycleEffectAdapter>,
                Ok(None) => Box::new(UnavailableLifecycleEffectAdapter),
                Err(category) => return Self::Disabled(category),
            };
        Self::open_with_lifecycle_adapter(
            policy_path,
            work_context_path,
            lineage_path,
            review_path,
            expected_uid,
            adapter,
        )
    }

    pub fn open_with_lifecycle_adapter(
        policy_path: &Path,
        work_context_path: &Path,
        lineage_path: &Path,
        review_path: &Path,
        expected_uid: u32,
        lifecycle_effects: Box<dyn PlatformV2LifecycleEffectAdapter>,
    ) -> Self {
        Self::open_with_lifecycle_adapter_and_clock(
            policy_path,
            work_context_path,
            lineage_path,
            review_path,
            expected_uid,
            lifecycle_effects,
            Box::new(SystemPlatformV2Clock),
        )
    }

    pub fn open_with_lifecycle_adapter_and_clock(
        policy_path: &Path,
        work_context_path: &Path,
        lineage_path: &Path,
        review_path: &Path,
        expected_uid: u32,
        lifecycle_effects: Box<dyn PlatformV2LifecycleEffectAdapter>,
        clock: Box<dyn PlatformV2Clock>,
    ) -> Self {
        match PlatformV2Runtime::open(
            policy_path,
            work_context_path,
            lineage_path,
            review_path,
            expected_uid,
            lifecycle_effects,
            clock,
        ) {
            Ok(Some(runtime)) => Self::Enabled(Box::new(runtime)),
            Ok(None) => Self::Disabled("platform_v2_unavailable"),
            Err(category) => Self::Disabled(category),
        }
    }

    pub fn availability(&self, uid: u32) -> Result<(), &'static str> {
        match self {
            Self::Disabled(category) => Err(category),
            Self::Enabled(runtime) => {
                runtime.policy_fence.verify()?;
                if runtime.principals.contains_key(&uid) {
                    Ok(())
                } else {
                    Err("platform_v2_principal_unmapped")
                }
            }
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

/// Verify the one principal a same-uid web bridge is allowed to represent.
///
/// The local admin socket authenticates a Unix uid, not an HTTP identity. A
/// web process may therefore bridge Platform v2 only when its server-owned
/// tenant/actor binding is exactly the sole principal the daemon policy maps
/// to that uid. This helper intentionally returns no grants or policy
/// document to the caller.
pub fn verify_web_principal_binding(
    policy_path: &Path,
    expected_uid: u32,
    tenant: &str,
    actor: &str,
) -> Result<(), &'static str> {
    load_web_principal(policy_path, expected_uid, tenant, actor).map(|_| ())
}

/// Verify that an operator-provisioned mobile project set is a non-empty
/// subset of the current server-owned principal policy.
pub fn verify_web_project_roots(
    policy_path: &Path,
    expected_uid: u32,
    tenant: &str,
    actor: &str,
    roots: &BTreeSet<ProjectId>,
) -> Result<(), &'static str> {
    let principal = load_web_principal(policy_path, expected_uid, tenant, actor)?;
    if roots.is_empty() || !roots.is_subset(&principal.projects) {
        return Err("platform_v2_mobile_project_denied");
    }
    Ok(())
}

/// Resolve only the project coordinate required to authorize one mobile
/// Platform v2 request. No authority grant or unrelated policy entry leaves
/// this boundary.
pub fn resolve_web_mobile_request_project(
    policy_path: &Path,
    expected_uid: u32,
    tenant: &str,
    actor: &str,
    roots: &BTreeSet<ProjectId>,
    request: &PlatformV2Request,
) -> Result<ProjectId, &'static str> {
    let principal = load_web_principal(policy_path, expected_uid, tenant, actor)?;
    let project = match request {
        PlatformV2Request::GetLifecycleCapabilities => {
            return Err("platform_v2_mobile_action_denied");
        }
        PlatformV2Request::QueryWorkContexts(query) => {
            let project = query
                .project()
                .ok_or("platform_v2_mobile_project_required")?;
            if query.parent().is_some_and(|parent| {
                principal
                    .workspaces
                    .get(parent)
                    .is_none_or(|scope| &scope.project != project)
            }) {
                return Err("platform_v2_mobile_project_denied");
            }
            project.clone()
        }
        PlatformV2Request::GetWorkContext(identity) => principal
            .workspaces
            .get(identity)
            .map(|scope| scope.project.clone())
            .ok_or("platform_v2_mobile_project_denied")?,
        PlatformV2Request::PrepareMutation(value) => {
            scope_for_intent(value.intent(), &principal)?.0
        }
        PlatformV2Request::DecideMutation(_) | PlatformV2Request::SubmitMutation(_) => {
            return Err("platform_v2_mobile_preview_scope_required");
        }
        PlatformV2Request::GetMutationReceipt(value) => value.project().clone(),
        PlatformV2Request::GetLineage(value) => {
            let identity = WorkContextIdentity::UserWorkspace(value.workspace().clone());
            if principal
                .workspaces
                .get(&identity)
                .is_none_or(|scope| &scope.project != value.project())
            {
                return Err("platform_v2_mobile_project_denied");
            }
            value.project().clone()
        }
        PlatformV2Request::SubmitWorkspaceIntent(value) => value.project().clone(),
        PlatformV2Request::GetWorkspaceIntent(value) => value.project().clone(),
        PlatformV2Request::GetReview(value) => {
            if principal
                .workspaces
                .get(value.workspace())
                .is_none_or(|scope| &scope.project != value.project())
            {
                return Err("platform_v2_mobile_project_denied");
            }
            value.project().clone()
        }
        PlatformV2Request::ExecuteReviewAction(value) => principal
            .workspaces
            .get(value.workspace())
            .map(|scope| scope.project.clone())
            .ok_or("platform_v2_mobile_project_denied")?,
        PlatformV2Request::GetReviewReceipt(value) => value.project().clone(),
    };
    if !principal.projects.contains(&project) || !roots.contains(&project) {
        return Err("platform_v2_mobile_project_denied");
    }
    Ok(project)
}

fn load_web_principal(
    policy_path: &Path,
    expected_uid: u32,
    tenant: &str,
    actor: &str,
) -> Result<PrincipalPolicy, &'static str> {
    let snapshot = read_policy_snapshot(policy_path, expected_uid)?
        .ok_or("platform_v2_web_binding_unavailable")?;
    let document: PolicyDocument =
        serde_json::from_slice(&snapshot.bytes).map_err(|_| "platform_v2_policy_invalid")?;
    let principals = parse_policy(document)?;
    let principal = if principals.len() == 1 {
        principals.get(&expected_uid)
    } else {
        None
    }
    .ok_or("platform_v2_web_binding_ambiguous")?;
    if principal.actor.tenant() != tenant || principal.actor.id() != actor {
        return Err("platform_v2_web_binding_mismatch");
    }
    Ok(principal.clone())
}

pub(crate) fn verify_bootstrap_policy(
    policy_path: &Path,
    expected_uid: u32,
    tenant: &str,
    projects: &BTreeSet<ProjectId>,
    ownership: &BTreeMap<WorkContextIdentity, ProjectId>,
) -> Result<PolicyGeneration, &'static str> {
    let snapshot = read_policy_snapshot(policy_path, expected_uid)?
        .ok_or("platform_v2_bootstrap_policy_missing")?;
    let document: PolicyDocument =
        serde_json::from_slice(&snapshot.bytes).map_err(|_| "platform_v2_policy_invalid")?;
    let principals = parse_policy(document)?;
    let principal = if principals.len() == 1 {
        principals.get(&expected_uid)
    } else {
        None
    }
    .ok_or("platform_v2_bootstrap_policy_ambiguous")?;
    if principal.actor.tenant() != tenant
        || &principal.projects != projects
        || principal.workspaces.len() != ownership.len()
        || principal
            .workspaces
            .iter()
            .any(|(identity, scope)| ownership.get(identity) != Some(&scope.project))
    {
        return Err("platform_v2_bootstrap_policy_mismatch");
    }
    Ok(snapshot.generation)
}

pub(crate) fn verify_bootstrap_store(
    policy_path: &Path,
    expected_uid: u32,
    store: &WorkContextStore,
) -> Result<PolicyGeneration, &'static str> {
    let snapshot = read_policy_snapshot(policy_path, expected_uid)?
        .ok_or("platform_v2_bootstrap_policy_missing")?;
    let document: PolicyDocument =
        serde_json::from_slice(&snapshot.bytes).map_err(|_| "platform_v2_policy_invalid")?;
    let principals = parse_policy(document)?;
    let principal = if principals.len() == 1 {
        principals.get(&expected_uid)
    } else {
        None
    }
    .ok_or("platform_v2_bootstrap_policy_ambiguous")?;
    validate_principal_mappings(store, principal)?;
    Ok(snapshot.generation)
}

impl PlatformV2Runtime {
    fn open(
        policy_path: &Path,
        work_context_path: &Path,
        lineage_path: &Path,
        review_path: &Path,
        expected_uid: u32,
        lifecycle_effects: Box<dyn PlatformV2LifecycleEffectAdapter>,
        clock: Box<dyn PlatformV2Clock>,
    ) -> Result<Option<Self>, &'static str> {
        let Some(snapshot) = read_policy_snapshot(policy_path, expected_uid)? else {
            return Ok(None);
        };
        let document: PolicyDocument =
            serde_json::from_slice(&snapshot.bytes).map_err(|_| "platform_v2_policy_invalid")?;
        let principals = parse_policy(document)?;
        if principals.len() != 1 || !principals.contains_key(&expected_uid) {
            // The admin socket currently admits only this daemon's effective
            // uid. Refuse dead or cross-tenant policy entries instead of
            // keeping authority that no authenticated peer can exercise.
            return Err("platform_v2_policy_invalid");
        }
        let work_contexts = WorkContextStore::open(work_context_path)
            .map_err(|_| "platform_v2_store_unavailable")?;
        for principal in principals.values() {
            validate_principal_mappings(&work_contexts, principal)?;
        }
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
            policy_fence: PolicyFence {
                path: policy_path.to_path_buf(),
                expected_uid,
                generation: snapshot.generation,
            },
            principals,
            work_contexts,
            lineage,
            reviews,
            review_effects: ProductionReviewEffectAdapter,
            nonces: HostNonces::new()?,
            lifecycle_effects,
            clock,
        }))
    }

    fn handle(
        &mut self,
        uid: u32,
        request: &PlatformV2Request,
        now_ms: i64,
    ) -> Result<PlatformV2Response, &'static str> {
        self.policy_fence.verify()?;
        let principal = self
            .principals
            .get(&uid)
            .cloned()
            .ok_or("platform_v2_principal_unmapped")?;
        // Policy is a live server-owned authorization registry, not a cached
        // substitute for durable identity and ownership truth.
        self.validate_all_policy_mappings(&principal)?;
        self.drive_lifecycle_effects(&principal, now_ms)?;
        match request {
            PlatformV2Request::GetLifecycleCapabilities => {
                self.lifecycle_effects.verify_generation()?;
                let mut operations = Vec::with_capacity(
                    principal.projects.len() * LIFECYCLE_CAPABILITY_EFFECT_KINDS.len(),
                );
                for project in &principal.projects {
                    for effect_kind in LIFECYCLE_CAPABILITY_EFFECT_KINDS {
                        operations.push(
                            match self
                                .lifecycle_effects
                                .capability_for_project(project, effect_kind)
                            {
                                Ok(()) => LifecycleOperationCapability::available(
                                    project.clone(),
                                    effect_kind,
                                ),
                                Err(category) => LifecycleOperationCapability::unavailable(
                                    project.clone(),
                                    effect_kind,
                                    category,
                                ),
                            }
                            .map_err(|_| "platform_v2_response_invalid")?,
                        );
                    }
                }
                Ok(PlatformV2Response::LifecycleCapabilities(
                    LifecycleCapabilities::new(principal.projects.clone(), operations)
                        .map_err(|_| "platform_v2_response_invalid")?,
                ))
            }
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
                self.validate_all_policy_mappings(&principal)?;
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
                let scope = principal
                    .workspaces
                    .get(identity)
                    .ok_or("platform_v2_scope_denied")?;
                self.validate_policy_mapping(&principal, identity)?;
                let policy = principal.read_policy(Some(scope.project.clone()), identity.clone());
                self.work_contexts
                    .record(&policy, identity)
                    .map_err(|_| "platform_v2_store_refused")?
                    .map(PlatformV2Response::WorkContextRecord)
                    .ok_or("platform_v2_not_found")
            }
            PlatformV2Request::PrepareMutation(value) => {
                if matches!(
                    value.intent(),
                    automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent::CreateProject(_)
                ) {
                    return Err("platform_v2_create_project_adapter_pending");
                }
                if lifecycle_effect_kind(value.intent()).is_some() {
                    self.lifecycle_effects.preflight(value.intent())?;
                }
                let proposal = WorkContextMutationProposal::new(
                    principal.actor.clone(),
                    principal.serving_authority,
                    principal.authority.clone(),
                    value.idempotency_key().clone(),
                    value.intent().clone(),
                )
                .map_err(|_| "platform_v2_request_invalid")?;
                let (project, inherited_authority) = scope_for_intent(value.intent(), &principal)?;
                self.validate_intent_scope(&principal, value.intent())?;
                let policy = principal.mutation_policy(
                    Some(project),
                    inherited_authority,
                    value.intent(),
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
                let candidate = self
                    .work_contexts
                    .preview_for_actor(
                        value.preview(),
                        &principal.actor,
                        principal.serving_authority,
                    )
                    .map_err(|_| "platform_v2_decision_refused")?;
                let (project, inherited_authority) =
                    scope_for_intent(candidate.proposal().intent(), &principal)
                        .map_err(|_| "platform_v2_decision_refused")?;
                let current_policy = principal.mutation_policy(
                    Some(project),
                    inherited_authority,
                    candidate.proposal().intent(),
                    candidate.proposal().request_digest(),
                    candidate.approval(),
                );
                let preview = self
                    .work_contexts
                    .authorize_existing_preview(value.preview(), &current_policy)
                    .map_err(|_| "platform_v2_decision_refused")?;
                let requested_expiry = now_ms
                    .checked_add(APPROVAL_LIFETIME_MS)
                    .ok_or("platform_v2_clock_invalid")?;
                let preview_expiry = preview.expires_at().as_millis();
                let expiry = approval_expiry(requested_expiry, preview_expiry);
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
            PlatformV2Request::SubmitMutation(value) => {
                let candidate = self
                    .work_contexts
                    .preview_for_actor(
                        value.preview(),
                        &principal.actor,
                        principal.serving_authority,
                    )
                    .map_err(|_| "platform_v2_submission_refused")?;
                let request_digest = candidate.proposal().request_digest();
                let (project, inherited_authority) =
                    scope_for_intent(candidate.proposal().intent(), &principal)
                        .map_err(|_| "platform_v2_submission_refused")?;
                self.validate_intent_scope(&principal, candidate.proposal().intent())?;
                if lifecycle_effect_kind(candidate.proposal().intent()).is_some() {
                    self.lifecycle_effects.preflight_submission(
                        candidate.proposal().intent(),
                        candidate.resulting().identity(),
                    )?;
                }
                let policy = principal.mutation_policy(
                    Some(project),
                    inherited_authority,
                    candidate.proposal().intent(),
                    request_digest,
                    candidate.approval(),
                );
                if lifecycle_effect_kind(candidate.proposal().intent()).is_some_and(|kind| {
                    !self
                        .lifecycle_effects
                        .supported_effect_kinds()
                        .contains(kind)
                }) {
                    return Ok(PlatformV2Response::MutationRefused(MutationRefusal::new(
                        MutationRefusalCategory::Unavailable,
                        Some(request_digest),
                        MutationExplanation::new(
                            "no configured executor supports this lifecycle effect",
                        )
                        .map_err(|_| "platform_v2_response_invalid")?,
                    )));
                }
                let receipt_id = ReceiptId::new(format!("receipt_{}", self.nonces.token()))
                    .map_err(|_| "platform_v2_nonce_invalid")?;
                match self.work_contexts.submit_approved_mutation(
                    value.preview(),
                    value.preview_digest(),
                    value.approval(),
                    &policy,
                    receipt_id,
                    now_ms,
                ) {
                    Ok(ReceiptAdmission::New(receipt) | ReceiptAdmission::Replay(receipt)) => {
                        Ok(PlatformV2Response::MutationReceipt(
                            RawMutationReceiptDocument::from_receipt(&receipt)
                                .map_err(|_| "platform_v2_response_invalid")?,
                        ))
                    }
                    Err(error) => Ok(PlatformV2Response::MutationRefused(mutation_store_refusal(
                        &error,
                        request_digest,
                    )?)),
                }
            }
            PlatformV2Request::GetMutationReceipt(value) => {
                if !principal.projects.contains(value.project()) {
                    return Err("platform_v2_scope_denied");
                }
                let candidate = match value.key() {
                    ReceiptLookupKey::ReceiptId(id) => {
                        self.work_contexts.receipt_preview_by_id_for_actor(
                            &principal.actor,
                            principal.serving_authority,
                            id,
                        )
                    }
                    ReceiptLookupKey::IdempotencyKey(key) => self
                        .work_contexts
                        .receipt_preview_by_idempotency_key_for_actor(
                            &principal.actor,
                            principal.serving_authority,
                            key,
                        ),
                }
                .map_err(|_| "platform_v2_not_found")?
                .ok_or("platform_v2_not_found")?;
                let (project, inherited_authority) =
                    scope_for_intent(candidate.proposal().intent(), &principal)
                        .map_err(|_| "platform_v2_not_found")?;
                if &project != value.project() {
                    return Err("platform_v2_not_found");
                }
                let policy = principal.mutation_policy(
                    Some(project),
                    inherited_authority,
                    candidate.proposal().intent(),
                    candidate.proposal().request_digest(),
                    candidate.approval(),
                );
                self.work_contexts
                    .authorize_existing_preview(candidate.preview(), &policy)
                    .map_err(|_| "platform_v2_not_found")?;
                let found = match value.key() {
                    ReceiptLookupKey::ReceiptId(id) => {
                        self.work_contexts.receipt_by_id(&policy, id)
                    }
                    ReceiptLookupKey::IdempotencyKey(key) => {
                        self.work_contexts.receipt_by_idempotency_key(&policy, key)
                    }
                }
                .map_err(|_| "platform_v2_not_found")?;
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
                self.validate_policy_mapping(
                    &principal,
                    &WorkContextIdentity::UserWorkspace(value.workspace().clone()),
                )?;
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
                let allowed = user_workspaces_for_project(&principal, value.project());
                let workspace = match value.intent() {
                    WorkspaceIntent::Create(intent) => {
                        let workspace = self
                            .lineage
                            .task_workspace_authorized(
                                principal.actor.tenant(),
                                intent.task(),
                                &allowed,
                            )
                            .map_err(|_| "platform_v2_create_scope_denied")?
                            .ok_or("platform_v2_create_scope_denied")?;
                        authorize_workspace(&principal, value.project(), &workspace)?;
                        self.validate_policy_mapping(
                            &principal,
                            &WorkContextIdentity::UserWorkspace(workspace.clone()),
                        )?;
                        workspace
                    }
                    WorkspaceIntent::Resume(intent) => {
                        authorize_workspace(&principal, value.project(), intent.workspace())?;
                        let task_workspace = self
                            .lineage
                            .task_workspace_authorized(
                                principal.actor.tenant(),
                                intent.task(),
                                &allowed,
                            )
                            .map_err(|_| "platform_v2_resume_scope_denied")?
                            .ok_or("platform_v2_resume_scope_denied")?;
                        if &task_workspace != intent.workspace() {
                            return Err("platform_v2_resume_scope_denied");
                        }
                        self.work_contexts
                            .validate_resumable_user_workspace(
                                principal.actor.tenant(),
                                value.project(),
                                intent.workspace(),
                                intent.expected_revision(),
                            )
                            .map_err(|error| match error.category() {
                                "stale_revision" => "platform_v2_resume_stale_revision",
                                "not_found" => "platform_v2_resume_not_found",
                                "unavailable" => "platform_v2_resume_not_resumable",
                                _ => "platform_v2_resume_refused",
                            })?;
                        intent.workspace().clone()
                    }
                    WorkspaceIntent::Cancel(intent) => {
                        authorize_workspace(&principal, value.project(), intent.workspace())?;
                        let outcome =
                            WorkspaceIntentOutcome::Cancelled(intent.target_intent_id().clone());
                        self.lineage
                            .record_intent(principal.actor.tenant(), value.intent(), &outcome)
                            .map_err(|_| "platform_v2_intent_refused")?;
                        return Ok(PlatformV2Response::WorkspaceIntentResult(outcome));
                    }
                };
                if !self.lifecycle_effects.workspace_intents_supported() {
                    return Err(match value.intent() {
                        WorkspaceIntent::Create(_) => {
                            "platform_v2_create_selector_registry_unavailable"
                        }
                        WorkspaceIntent::Resume(_) => "platform_v2_resume_adapter_pending",
                        WorkspaceIntent::Cancel(_) => unreachable!("handled above"),
                    });
                }
                self.lifecycle_effects.preflight_workspace_intent(
                    value.intent(),
                    value.project(),
                    &workspace,
                )?;
                self.lineage
                    .record_intent(
                        principal.actor.tenant(),
                        value.intent(),
                        &WorkspaceIntentOutcome::Accepted,
                    )
                    .map_err(|_| "platform_v2_intent_refused")?;
                let stored = self
                    .lineage
                    .intent_authorized_in_workspaces(
                        &negotiated_v2()?,
                        principal.actor.tenant(),
                        value.intent().intent_id(),
                        &allowed,
                    )
                    .map_err(|_| "platform_v2_intent_refused")?
                    .ok_or("platform_v2_intent_refused")?;
                if stored.outcome.reconciliation()
                    == automonique_protocol::platform_v2_lineage::WorkspaceIntentReconciliation::Final
                {
                    return Ok(PlatformV2Response::WorkspaceIntentResult(stored.outcome));
                }
                self.policy_fence.verify()?;
                let outcome = self.lifecycle_effects.execute_workspace_intent(
                    value.intent(),
                    value.project(),
                    &workspace,
                )?;
                self.policy_fence.verify()?;
                self.lineage
                    .reconcile_intent(
                        principal.actor.tenant(),
                        &WorkspaceIntentExecutionReceipt {
                            intent_id: value.intent().intent_id().clone(),
                            request_digest: stored.request_digest,
                            outcome: outcome.clone(),
                        },
                    )
                    .map_err(|_| "platform_v2_intent_refused")?;
                let stored = self
                    .lineage
                    .intent_authorized_in_workspaces(
                        &negotiated_v2()?,
                        principal.actor.tenant(),
                        value.intent().intent_id(),
                        &allowed,
                    )
                    .map_err(|_| "platform_v2_intent_refused")?
                    .ok_or("platform_v2_intent_refused")?;
                Ok(PlatformV2Response::WorkspaceIntentResult(stored.outcome))
            }
            PlatformV2Request::GetWorkspaceIntent(value) => {
                if !principal.projects.contains(value.project()) {
                    return Err("platform_v2_scope_denied");
                }
                let allowed = user_workspaces_for_project(&principal, value.project());
                let stored = self
                    .lineage
                    .intent_authorized_in_workspaces(
                        &negotiated_v2()?,
                        principal.actor.tenant(),
                        value.intent_id(),
                        &allowed,
                    )
                    .map_err(|_| "platform_v2_store_refused")?
                    .ok_or("platform_v2_not_found")?;
                if stored.outcome.reconciliation()
                    != automonique_protocol::platform_v2_lineage::WorkspaceIntentReconciliation::Final
                {
                    if !self.lifecycle_effects.workspace_intents_supported() {
                        return Err("platform_v2_workspace_intent_recovery_unavailable");
                    }
                    let workspace = match &stored.intent {
                        WorkspaceIntent::Create(intent) => self
                            .lineage
                            .task_workspace_authorized(
                                principal.actor.tenant(),
                                intent.task(),
                                &allowed,
                            )
                            .map_err(|_| "platform_v2_intent_refused")?
                            .ok_or("platform_v2_intent_refused")?,
                        WorkspaceIntent::Resume(intent) => intent.workspace().clone(),
                        WorkspaceIntent::Cancel(_) => {
                            return Ok(PlatformV2Response::WorkspaceIntentResult(stored.outcome));
                        }
                    };
                    self.lifecycle_effects.preflight_workspace_intent(
                        &stored.intent,
                        value.project(),
                        &workspace,
                    )?;
                    self.policy_fence.verify()?;
                    let outcome = self.lifecycle_effects.execute_workspace_intent(
                        &stored.intent,
                        value.project(),
                        &workspace,
                    )?;
                    self.policy_fence.verify()?;
                    self.lineage
                        .reconcile_intent(
                            principal.actor.tenant(),
                            &WorkspaceIntentExecutionReceipt {
                                intent_id: stored.intent.intent_id().clone(),
                                request_digest: stored.request_digest,
                                outcome,
                            },
                        )
                        .map_err(|_| "platform_v2_intent_refused")?;
                    let refreshed = self
                        .lineage
                        .intent_authorized_in_workspaces(
                            &negotiated_v2()?,
                            principal.actor.tenant(),
                            value.intent_id(),
                            &allowed,
                        )
                        .map_err(|_| "platform_v2_store_refused")?
                        .ok_or("platform_v2_not_found")?;
                    return Ok(PlatformV2Response::WorkspaceIntentResult(refreshed.outcome));
                }
                Ok(PlatformV2Response::WorkspaceIntentResult(stored.outcome))
            }
            PlatformV2Request::GetReview(value) => {
                authorize_identity(&principal, value.project(), value.workspace())?;
                self.validate_policy_mapping(&principal, value.workspace())?;
                self.reviews
                    .snapshot(value.workspace())
                    .map_err(|_| "platform_v2_store_refused")?
                    .map(PlatformV2Response::ReviewResult)
                    .ok_or("platform_v2_not_found")
            }
            PlatformV2Request::ExecuteReviewAction(value) => {
                let scope = principal
                    .workspaces
                    .get(value.workspace())
                    .ok_or("platform_v2_scope_denied")?;
                if !principal.projects.contains(&scope.project) {
                    return Err("platform_v2_scope_denied");
                }
                self.validate_policy_mapping(&principal, value.workspace())?;
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
                match self.review_effects.plan(request.action()) {
                    Ok(ReviewEffectPlan::LocalStore) => {
                        self.policy_fence.verify()?;
                        let receipt = self
                            .reviews
                            .execute_local_action(&request, now_ms)
                            .map_err(review_store_category)?;
                        self.policy_fence.verify()?;
                        Ok(PlatformV2Response::ReviewReceipt(receipt))
                    }
                    Err(category) => {
                        // Resolve the exact grant, revision, freshness and
                        // target before exposing an adapter capability reason.
                        self.reviews
                            .validate_action(&request, now_ms)
                            .map_err(review_store_category)?;
                        Err(category)
                    }
                }
            }
            PlatformV2Request::GetReviewReceipt(value) => {
                authorize_identity(&principal, value.project(), value.workspace())?;
                self.validate_policy_mapping(&principal, value.workspace())?;
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

    fn validate_policy_mapping(
        &self,
        principal: &PrincipalPolicy,
        identity: &WorkContextIdentity,
    ) -> Result<(), &'static str> {
        let scope = principal
            .workspaces
            .get(identity)
            .ok_or("platform_v2_scope_denied")?;
        self.work_contexts
            .validate_policy_mapping(principal.actor.tenant(), &scope.project, identity)
            .map(|_| ())
            .map_err(|_| "platform_v2_policy_incoherent")
    }

    fn validate_all_policy_mappings(
        &self,
        principal: &PrincipalPolicy,
    ) -> Result<(), &'static str> {
        validate_principal_mappings(&self.work_contexts, principal)
    }

    fn validate_intent_scope(
        &self,
        principal: &PrincipalPolicy,
        intent: &automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent,
    ) -> Result<(), &'static str> {
        let identity = primary_identity_for_intent(intent)
            .ok_or("platform_v2_create_project_adapter_pending")?;
        self.validate_policy_mapping(principal, identity)
    }

    fn drive_lifecycle_effects(
        &mut self,
        principal: &PrincipalPolicy,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        let allowed = self.lifecycle_effects.supported_effect_kinds();
        if allowed.is_empty() {
            return Ok(());
        }
        let executor = Actor::new(
            principal.actor.tenant(),
            "platform-v2-lifecycle-effect-worker",
        )
        .map_err(|_| "platform_v2_effect_policy_invalid")?;
        let recovery_policy = ExternalEffectRecoveryPolicy::for_lease_executor(
            executor.clone(),
            principal.serving_authority,
            allowed.clone(),
        );
        if let Some(effect) = self
            .work_contexts
            .recover_next_ambiguous_external_effect_with_policy(
                &recovery_policy,
                now_ms,
                &mut self.nonces,
                |preview| current_mutation_policy(principal, preview),
            )
            .map_err(|_| "platform_v2_effect_recovery_refused")?
        {
            self.authorize_lifecycle_effect(principal, &effect)?;
            self.policy_fence.verify()?;
            let reconciliation = self.lifecycle_effects.reconcile(
                effect.intent(),
                effect.resulting_identity(),
                effect.idempotency_key(),
            );
            self.policy_fence.verify()?;
            self.lifecycle_effects.verify_generation()?;
            self.authorize_lifecycle_effect(principal, &effect)?;
            let reconciliation = match reconciliation {
                PlatformV2EffectReconciliation::VerifiedNotStarted(document) => {
                    ExternalEffectReconciliation::VerifiedNotStarted {
                        evidence: ProviderEffectEvidence::new(
                            effect.idempotency_key().clone(),
                            document,
                        )
                        .map_err(|_| "platform_v2_effect_evidence_invalid")?,
                    }
                }
                PlatformV2EffectReconciliation::Completed(document) => {
                    ExternalEffectReconciliation::Completed {
                        evidence: ProviderEffectEvidence::new(
                            effect.idempotency_key().clone(),
                            document,
                        )
                        .map_err(|_| "platform_v2_effect_evidence_invalid")?,
                    }
                }
                PlatformV2EffectReconciliation::Unknown(document) => {
                    ExternalEffectReconciliation::Unknown {
                        evidence: ProviderEffectEvidence::new(
                            effect.idempotency_key().clone(),
                            document,
                        )
                        .map_err(|_| "platform_v2_effect_evidence_invalid")?,
                    }
                }
            };
            let reconciliation_now = self.clock.now_ms()?.max(now_ms);
            match self
                .work_contexts
                .reconcile_external_effect(&effect, &reconciliation, reconciliation_now)
                .map_err(|_| "platform_v2_effect_recovery_refused")?
            {
                ExternalEffectReconciliationOutcome::Ready
                | ExternalEffectReconciliationOutcome::Completed(_)
                | ExternalEffectReconciliationOutcome::ReconcileRequired => {}
            }
        }
        let executor_policy =
            ExternalEffectExecutorPolicy::new(executor, principal.serving_authority, allowed);
        if let Some(effect) = self
            .work_contexts
            .claim_next_external_effect_with_policy(
                &executor_policy,
                now_ms,
                EFFECT_LEASE_LIFETIME_MS,
                &mut self.nonces,
                |preview| current_mutation_policy(principal, preview),
            )
            .map_err(|_| "platform_v2_effect_claim_refused")?
        {
            self.authorize_lifecycle_effect(principal, &effect)?;
            self.policy_fence.verify()?;
            if self.lifecycle_effects.execute(
                effect.intent(),
                effect.resulting_identity(),
                effect.idempotency_key(),
            ) == PlatformV2EffectExecution::Completed
            {
                self.policy_fence.verify()?;
                self.lifecycle_effects.verify_generation()?;
                self.authorize_lifecycle_effect(principal, &effect)?;
                let completion_now = self.clock.now_ms()?.max(now_ms);
                match self
                    .work_contexts
                    .complete_external_effect(&effect, completion_now)
                {
                    Ok(_) | Err(WorkContextStoreError::ReconcileRequired) => {}
                    Err(_) => return Err("platform_v2_effect_completion_refused"),
                }
            }
        }
        Ok(())
    }

    fn authorize_lifecycle_effect(
        &self,
        principal: &PrincipalPolicy,
        effect: &ExternalEffectCompletionPolicy,
    ) -> Result<(), &'static str> {
        let preview = self
            .work_contexts
            .preview_for_actor(
                effect.preview(),
                &principal.actor,
                principal.serving_authority,
            )
            .map_err(|_| "platform_v2_effect_policy_refused")?;
        let (project, inherited_authority) =
            scope_for_intent(preview.proposal().intent(), principal)
                .map_err(|_| "platform_v2_effect_policy_refused")?;
        let policy = principal.mutation_policy(
            Some(project),
            inherited_authority,
            preview.proposal().intent(),
            preview.proposal().request_digest(),
            preview.approval(),
        );
        self.work_contexts
            .authorize_existing_preview(effect.preview(), &policy)
            .map(|_| ())
            .map_err(|_| "platform_v2_effect_policy_refused")
    }
}

fn current_mutation_policy(
    principal: &PrincipalPolicy,
    preview: &automonique_protocol::platform_v2_lifecycle::MutationPreview,
) -> Option<MutationPolicyDecision> {
    let (project, inherited_authority) =
        scope_for_intent(preview.proposal().intent(), principal).ok()?;
    Some(principal.mutation_policy(
        Some(project),
        inherited_authority,
        preview.proposal().intent(),
        preview.proposal().request_digest(),
        preview.approval(),
    ))
}

fn lifecycle_effect_kind(intent: &WorkContextMutationIntent) -> Option<&'static str> {
    match intent {
        WorkContextMutationIntent::CreateHostSetup(_) => Some("create_host_setup"),
        WorkContextMutationIntent::CreateCheckout(_) => Some("create_checkout"),
        WorkContextMutationIntent::CreateAttemptWorkspace(_) => Some("create_attempt_workspace"),
        WorkContextMutationIntent::ResumeAttemptWorkspace(_) => Some("resume_attempt_workspace"),
        WorkContextMutationIntent::ResumeSession(_) => Some("resume_session"),
        _ => None,
    }
}

fn review_store_category(error: ReviewStoreError) -> &'static str {
    match error {
        ReviewStoreError::StaleRevision { .. } => "platform_v2_review_stale",
        ReviewStoreError::Conflict(_) => "platform_v2_review_conflict",
        ReviewStoreError::Unauthorized => "platform_v2_review_role_denied",
        ReviewStoreError::ApprovalRequired => "platform_v2_review_approval_required",
        ReviewStoreError::NotFound => "platform_v2_not_found",
        ReviewStoreError::InvalidField(_) | ReviewStoreError::Protocol(_) => {
            "platform_v2_review_refused"
        }
        ReviewStoreError::InsecurePath(_)
        | ReviewStoreError::SchemaVersion { .. }
        | ReviewStoreError::Corrupt(_)
        | ReviewStoreError::Io(_)
        | ReviewStoreError::Sqlite(_) => "platform_v2_store_refused",
    }
}

#[cfg(test)]
fn read_policy_file_after_open(
    policy_path: &Path,
    expected_uid: u32,
    after_open: impl FnOnce(),
) -> Result<Option<Vec<u8>>, &'static str> {
    read_policy_snapshot_after_open(policy_path, expected_uid, after_open)
        .map(|snapshot| snapshot.map(|value| value.bytes))
}

fn read_policy_snapshot(
    policy_path: &Path,
    expected_uid: u32,
) -> Result<Option<PolicySnapshot>, &'static str> {
    read_policy_snapshot_after_open(policy_path, expected_uid, || {})
}

fn read_policy_snapshot_after_open(
    policy_path: &Path,
    expected_uid: u32,
    after_open: impl FnOnce(),
) -> Result<Option<PolicySnapshot>, &'static str> {
    let mut policy_file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(policy_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Err("platform_v2_policy_insecure");
        }
        Err(_) => return Err("platform_v2_policy_io"),
    };
    let metadata = policy_file
        .metadata()
        .map_err(|_| "platform_v2_policy_io")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_POLICY_BYTES
    {
        return Err("platform_v2_policy_insecure");
    }
    after_open();
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    policy_file
        .by_ref()
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_policy_io")?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err("platform_v2_policy_insecure");
    }
    Ok(Some(PolicySnapshot {
        generation: PolicyGeneration {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            length: metadata.len(),
            digest: Sha256::digest(&bytes),
        },
        bytes,
    }))
}

fn validate_principal_mappings(
    work_contexts: &WorkContextStore,
    principal: &PrincipalPolicy,
) -> Result<(), &'static str> {
    let mappings = principal
        .workspaces
        .iter()
        .map(|(identity, scope)| (identity.clone(), scope.project.clone()))
        .collect();
    let records = work_contexts
        .validate_policy_mappings(principal.actor.tenant(), &mappings)
        .map_err(|_| "platform_v2_policy_incoherent")?;
    for (identity, scope) in &principal.workspaces {
        let record = records
            .get(identity)
            .ok_or("platform_v2_policy_incoherent")?;
        if let Some(required_parent) = required_policy_parent(identity.kind()) {
            let parent = record
                .relations()
                .iter()
                .find(|relation| relation.target().kind() == required_parent)
                .ok_or("platform_v2_policy_incoherent")?
                .target();
            let parent_scope = principal
                .workspaces
                .get(parent)
                .ok_or("platform_v2_policy_incoherent")?;
            if parent_scope.project != scope.project
                || !scope
                    .inherited_authority
                    .is_subset_of(&parent_scope.inherited_authority)
            {
                return Err("platform_v2_policy_incoherent");
            }
        }
        for relation in record.relations() {
            if let Some(parent_scope) = principal.workspaces.get(relation.target())
                && (parent_scope.project != scope.project
                    || !scope
                        .inherited_authority
                        .is_subset_of(&parent_scope.inherited_authority))
            {
                return Err("platform_v2_policy_incoherent");
            }
        }
    }
    Ok(())
}

fn required_policy_parent(kind: WorkContextTargetKind) -> Option<WorkContextTargetKind> {
    match kind {
        WorkContextTargetKind::HostSetup => Some(WorkContextTargetKind::Project),
        WorkContextTargetKind::Checkout => Some(WorkContextTargetKind::HostSetup),
        WorkContextTargetKind::UserWorkspace => Some(WorkContextTargetKind::Checkout),
        WorkContextTargetKind::AttemptWorkspace => Some(WorkContextTargetKind::UserWorkspace),
        WorkContextTargetKind::Session => Some(WorkContextTargetKind::AttemptWorkspace),
        WorkContextTargetKind::Pane => Some(WorkContextTargetKind::Session),
        WorkContextTargetKind::Project
        | WorkContextTargetKind::Repository
        | WorkContextTargetKind::PlatformSession => None,
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
        inherited_authority: WorkContextAuthority,
        intent: &WorkContextMutationIntent,
        digest: automonique_protocol::platform_v2_lifecycle::WorkContextRequestDigest,
        approval: MutationApprovalRequirement,
    ) -> MutationPolicyDecision {
        let mut targets: BTreeSet<_> = self
            .workspaces
            .iter()
            .filter(|(_, scope)| {
                project
                    .as_ref()
                    .is_some_and(|value| &scope.project == value)
            })
            .map(|(identity, _)| identity.clone())
            .collect();
        // Repositories are external v1 coordinates, so they cannot appear in
        // the durable workspace policy registry. A checkout preview needs its
        // one immutable repository coordinate in the store authorization set;
        // the store still proves that exact coordinate is a repository of the
        // selected durable project and matches its external snapshot.
        if let WorkContextMutationIntent::CreateCheckout(checkout) = intent {
            targets.insert(checkout.repository().identity().clone());
        }
        MutationPolicyDecision::new(
            self.actor.clone(),
            self.serving_authority,
            self.authority.clone(),
            inherited_authority,
            project,
            targets,
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
            let inherited_authority = authority(raw_workspace.inherited_authority)?;
            if workspaces
                .insert(
                    identity,
                    ScopePolicy {
                        project,
                        inherited_authority,
                    },
                )
                .is_some()
                || workspaces.len() > 1024
            {
                return Err("platform_v2_policy_invalid");
            }
        }
        let authority = authority(raw.authority)?;
        if workspaces
            .values()
            .any(|scope| !scope.inherited_authority.is_subset_of(&authority))
            || projects.iter().any(|project| {
                !workspaces.contains_key(&WorkContextIdentity::Project(project.clone()))
            })
        {
            return Err("platform_v2_policy_invalid");
        }
        for (identity, scope) in &workspaces {
            if matches!(identity, WorkContextIdentity::Project(_)) {
                continue;
            }
            let project_scope = workspaces
                .get(&WorkContextIdentity::Project(scope.project.clone()))
                .ok_or("platform_v2_policy_invalid")?;
            if !scope
                .inherited_authority
                .is_subset_of(&project_scope.inherited_authority)
            {
                return Err("platform_v2_policy_invalid");
            }
        }
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

fn authority(raw: AuthorityDocument) -> Result<WorkContextAuthority, &'static str> {
    WorkContextAuthority::new(
        grants(raw.filesystem)?,
        grants(raw.credentials)?,
        grants(raw.network)?,
        grants(raw.tools)?,
        grants(raw.providers)?,
        grants(raw.models)?,
    )
    .map_err(|_| "platform_v2_policy_invalid")
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
            .is_some_and(|scope| &scope.project == project)
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

fn user_workspaces_for_project(
    principal: &PrincipalPolicy,
    project: &ProjectId,
) -> BTreeSet<UserWorkspaceId> {
    principal
        .workspaces
        .iter()
        .filter(|(_, scope)| &scope.project == project)
        .filter_map(|(identity, _)| match identity {
            WorkContextIdentity::UserWorkspace(workspace) => Some(workspace.clone()),
            _ => None,
        })
        .collect()
}

fn primary_identity_for_intent(
    intent: &automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent,
) -> Option<&WorkContextIdentity> {
    use automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent;
    Some(match intent {
        WorkContextMutationIntent::CreateProject(_) => return None,
        WorkContextMutationIntent::CreateHostSetup(value) => value.project().identity(),
        WorkContextMutationIntent::CreateCheckout(value) => value.host_setup().identity(),
        WorkContextMutationIntent::CreateUserWorkspace(value) => value.checkout().identity(),
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => {
            value.user_workspace().identity()
        }
        WorkContextMutationIntent::ResumeAttemptWorkspace(value) => value.target().identity(),
        WorkContextMutationIntent::ResumeSession(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveProject(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveHostSetup(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveCheckout(value) => value.target().identity(),
        WorkContextMutationIntent::ArchiveUserWorkspace(value) => value.target().identity(),
    })
}

fn scope_for_intent(
    intent: &automonique_protocol::platform_v2_lifecycle::WorkContextMutationIntent,
    principal: &PrincipalPolicy,
) -> Result<(ProjectId, WorkContextAuthority), &'static str> {
    let identity =
        primary_identity_for_intent(intent).ok_or("platform_v2_create_project_adapter_pending")?;
    let scope = principal
        .workspaces
        .get(identity)
        .ok_or("platform_v2_scope_denied")?;
    if !principal.projects.contains(&scope.project) {
        return Err("platform_v2_scope_denied");
    }
    Ok((scope.project.clone(), scope.inherited_authority.clone()))
}

fn approval_expiry(requested_expiry: i64, preview_expiry: i64) -> i64 {
    requested_expiry.min(preview_expiry)
}

fn negotiated_v2() -> Result<NegotiatedPlatform, &'static str> {
    let offer = PlatformVersionOffer::new(vec![2]).map_err(|_| "platform_v2_negotiation")?;
    negotiate_platform_version(&offer, &offer).map_err(|_| "platform_v2_negotiation")
}

fn mutation_store_refusal(
    error: &WorkContextStoreError,
    request_digest: automonique_protocol::platform_v2_lifecycle::WorkContextRequestDigest,
) -> Result<MutationRefusal, &'static str> {
    let category = match error {
        WorkContextStoreError::InvalidField(_)
        | WorkContextStoreError::Protocol(_)
        | WorkContextStoreError::Corrupt(_)
        | WorkContextStoreError::InsecurePath(_)
        | WorkContextStoreError::SchemaVersion { .. }
        | WorkContextStoreError::Io(_)
        | WorkContextStoreError::Sqlite(_) => MutationRefusalCategory::InvalidRequest,
        WorkContextStoreError::Unauthorized | WorkContextStoreError::NotFound => {
            MutationRefusalCategory::Unauthorized
        }
        WorkContextStoreError::AuthorityWidening => MutationRefusalCategory::AuthorityWidening,
        WorkContextStoreError::StaleRevision => MutationRefusalCategory::StaleRevision,
        WorkContextStoreError::GraphConflict | WorkContextStoreError::BodyConflict => {
            MutationRefusalCategory::Conflict
        }
        WorkContextStoreError::ApprovalRequired => MutationRefusalCategory::ApprovalRequired,
        WorkContextStoreError::ApprovalMismatch | WorkContextStoreError::ApprovalConsumed => {
            MutationRefusalCategory::ApprovalMismatch
        }
        WorkContextStoreError::ApprovalDenied => MutationRefusalCategory::ApprovalDenied,
        WorkContextStoreError::ApprovalExpired => MutationRefusalCategory::ApprovalExpired,
        WorkContextStoreError::PreviewExpired => MutationRefusalCategory::PreviewExpired,
        WorkContextStoreError::Unavailable => MutationRefusalCategory::Unavailable,
        WorkContextStoreError::ReconcileRequired
        | WorkContextStoreError::BootstrapPartial
        | WorkContextStoreError::BootstrapMismatch
        | WorkContextStoreError::BootstrapDowngrade
        | WorkContextStoreError::BootstrapGuard => MutationRefusalCategory::Unknown,
    };
    Ok(MutationRefusal::new(
        category,
        Some(request_digest),
        MutationExplanation::new(
            "the current server policy or durable mutation state refused submission",
        )
        .map_err(|_| "platform_v2_response_invalid")?,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use automonique_protocol::platform_v2_transport::{LineageReadRequest, ReviewReadRequest};

    fn policy(inherited_tools: serde_json::Value) -> PolicyDocument {
        serde_json::from_value(serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": 7,
                "tenant": "tenant-test",
                "actor": "actor-test",
                "serving_authority": "automonique",
                "projects": ["project-test"],
                "workspaces": [{
                    "project": "project-test",
                    "kind": "project",
                    "id": "project-test",
                    "inherited_authority": {
                        "filesystem": [], "credentials": [], "network": [],
                        "tools": inherited_tools, "providers": [], "models": []
                    }
                }],
                "authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": ["tool.actor"], "providers": [], "models": []
                },
                "review_authorities": {}
            }]
        }))
        .unwrap()
    }

    fn generation_policy(uid: u32, grant: bool) -> serde_json::Value {
        let grants = if grant {
            serde_json::json!(["tool.actor"])
        } else {
            serde_json::json!([])
        };
        serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": "tenant-test",
                "actor": "actor-test",
                "serving_authority": "automonique",
                "projects": ["project-test"],
                "workspaces": [{
                    "project": "project-test", "kind": "project", "id": "project-test",
                    "inherited_authority": {
                        "filesystem": [], "credentials": [], "network": [],
                        "tools": grants, "providers": [], "models": []
                    }
                }],
                "authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": grants, "providers": [], "models": []
                },
                "review_authorities": {}
            }]
        })
    }

    fn write_generation_policy(path: &Path, document: &serde_json::Value) {
        fs::write(path, serde_json::to_vec(document).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn policy_fence(path: &Path, uid: u32) -> PolicyFence {
        PolicyFence {
            path: path.to_path_buf(),
            expected_uid: uid,
            generation: read_policy_snapshot(path, uid).unwrap().unwrap().generation,
        }
    }

    #[test]
    fn inherited_scope_ceiling_is_independent_and_narrower() {
        let parsed = parse_policy(policy(serde_json::json!([]))).unwrap();
        let principal = parsed.get(&7).unwrap();
        let scope = principal
            .workspaces
            .get(&WorkContextIdentity::Project(
                ProjectId::new("project-test").unwrap(),
            ))
            .unwrap();
        assert!(!principal.authority.is_empty());
        assert!(scope.inherited_authority.is_empty());
    }

    #[test]
    fn unavailable_lifecycle_adapter_advertises_no_effects() {
        assert!(
            UnavailableLifecycleEffectAdapter
                .supported_effect_kinds()
                .is_empty()
        );
    }

    #[test]
    fn inherited_scope_ceiling_cannot_exceed_actor_authority() {
        assert!(parse_policy(policy(serde_json::json!(["tool.not-actor"]))).is_err());
    }

    #[test]
    fn child_scope_ceiling_cannot_exceed_project_ceiling() {
        let document: PolicyDocument = serde_json::from_value(serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": 7, "tenant": "tenant-test", "actor": "actor-test",
                "serving_authority": "automonique", "projects": ["project-test"],
                "workspaces": [
                    {"project": "project-test", "kind": "project", "id": "project-test",
                     "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": [], "providers": [], "models": []}},
                    {"project": "project-test", "kind": "user_workspace", "id": "workspace-test",
                     "inherited_authority": {"filesystem": [], "credentials": [], "network": [], "tools": ["tool.actor"], "providers": [], "models": []}}
                ],
                "authority": {"filesystem": [], "credentials": [], "network": [], "tools": ["tool.actor"], "providers": [], "models": []},
                "review_authorities": {}
            }]
        }))
        .unwrap();
        assert!(parse_policy(document).is_err());
    }

    #[test]
    fn last_minute_approval_is_capped_to_preview_expiry() {
        assert_eq!(approval_expiry(10_060, 10_001), 10_001);
        assert_eq!(approval_expiry(10_060, 20_000), 10_060);
    }

    #[test]
    fn policy_path_swap_cannot_replace_the_open_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let opened_inode = directory.path().join("opened-policy.json");
        fs::write(&path, b"opened document").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = read_policy_file_after_open(&path, nix::unistd::geteuid().as_raw(), || {
            fs::rename(&path, &opened_inode).unwrap();
            fs::write(&path, b"replacement document").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        })
        .unwrap()
        .unwrap();
        assert_eq!(bytes, b"opened document");
        assert_eq!(fs::read(path).unwrap(), b"replacement document");
    }
    #[test]
    fn loaded_policy_fence_refuses_in_place_grant_narrowing_until_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let uid = nix::unistd::geteuid().as_raw();
        write_generation_policy(&path, &generation_policy(uid, true));
        let loaded = policy_fence(&path, uid);
        assert_eq!(loaded.verify(), Ok(()));

        write_generation_policy(&path, &generation_policy(uid, false));
        assert_eq!(loaded.verify(), Err("platform_v2_policy_changed"));

        let restarted = policy_fence(&path, uid);
        assert_eq!(restarted.verify(), Ok(()));
        assert_eq!(loaded.verify(), Err("platform_v2_policy_changed"));
    }

    #[test]
    fn loaded_policy_fence_refuses_same_content_replacement_and_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let replacement = directory.path().join("replacement.json");
        let uid = nix::unistd::geteuid().as_raw();
        let document = generation_policy(uid, true);
        write_generation_policy(&path, &document);
        let loaded = policy_fence(&path, uid);

        write_generation_policy(&replacement, &document);
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(loaded.verify(), Err("platform_v2_policy_changed"));

        let restarted = policy_fence(&path, uid);
        assert_eq!(restarted.verify(), Ok(()));
        fs::remove_file(&path).unwrap();
        assert_eq!(restarted.verify(), Err("platform_v2_policy_changed"));
    }

    #[test]
    fn web_bridge_binding_is_exact_and_single_principal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let uid = nix::unistd::geteuid().as_raw();
        let document = serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": "tenant-test",
                "actor": "actor-test",
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
        write_generation_policy(&path, &document);

        assert_eq!(
            verify_web_principal_binding(&path, uid, "tenant-test", "actor-test"),
            Ok(())
        );
        assert_eq!(
            verify_web_principal_binding(&path, uid, "tenant-other", "actor-test"),
            Err("platform_v2_web_binding_mismatch")
        );
        assert_eq!(
            verify_web_principal_binding(&path, uid, "tenant-test", "actor-other"),
            Err("platform_v2_web_binding_mismatch")
        );

        let mut ambiguous = document;
        let second = ambiguous["principals"][0].clone();
        ambiguous["principals"].as_array_mut().unwrap().push(second);
        ambiguous["principals"][1]["uid"] = serde_json::json!(uid.saturating_add(1));
        write_generation_policy(&path, &ambiguous);
        assert_eq!(
            verify_web_principal_binding(&path, uid, "tenant-test", "actor-test"),
            Err("platform_v2_web_binding_ambiguous")
        );
    }

    #[test]
    fn mobile_target_reads_require_workspace_ownership_in_the_declared_project() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let uid = nix::unistd::geteuid().as_raw();
        let empty_authority = serde_json::json!({
            "filesystem": [], "credentials": [], "network": [],
            "tools": [], "providers": [], "models": []
        });
        let document = serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": "tenant-test",
                "actor": "actor-test",
                "serving_authority": "automonique",
                "projects": ["project-a", "project-b"],
                "workspaces": [
                    {"project": "project-a", "kind": "project", "id": "project-a",
                     "inherited_authority": empty_authority},
                    {"project": "project-b", "kind": "project", "id": "project-b",
                     "inherited_authority": empty_authority},
                    {"project": "project-a", "kind": "user_workspace", "id": "workspace-a",
                     "inherited_authority": empty_authority},
                    {"project": "project-b", "kind": "user_workspace", "id": "workspace-b",
                     "inherited_authority": empty_authority}
                ],
                "authority": empty_authority,
                "review_authorities": {}
            }]
        });
        write_generation_policy(&path, &document);
        let roots = [
            ProjectId::new("project-a").unwrap(),
            ProjectId::new("project-b").unwrap(),
        ]
        .into_iter()
        .collect();
        let project_a = ProjectId::new("project-a").unwrap();
        let project_b = ProjectId::new("project-b").unwrap();
        let workspace_a = UserWorkspaceId::new("workspace-a").unwrap();

        let valid_lineage = PlatformV2Request::GetLineage(LineageReadRequest::new(
            project_a.clone(),
            workspace_a.clone(),
        ));
        assert_eq!(
            resolve_web_mobile_request_project(
                &path,
                uid,
                "tenant-test",
                "actor-test",
                &roots,
                &valid_lineage,
            ),
            Ok(project_a.clone())
        );
        let mismatched_lineage = PlatformV2Request::GetLineage(LineageReadRequest::new(
            project_b.clone(),
            workspace_a.clone(),
        ));
        assert_eq!(
            resolve_web_mobile_request_project(
                &path,
                uid,
                "tenant-test",
                "actor-test",
                &roots,
                &mismatched_lineage,
            ),
            Err("platform_v2_mobile_project_denied")
        );

        let mismatched_review = PlatformV2Request::GetReview(
            ReviewReadRequest::new(project_b, WorkContextIdentity::UserWorkspace(workspace_a))
                .unwrap(),
        );
        assert_eq!(
            resolve_web_mobile_request_project(
                &path,
                uid,
                "tenant-test",
                "actor-test",
                &roots,
                &mismatched_review,
            ),
            Err("platform_v2_mobile_project_denied")
        );
    }
}
