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
    CheckoutId, NegotiatedPlatform, PlatformVersionOffer, ProjectId, UserWorkspaceId,
    WorkContextIdentity, WorkContextLifecycle, WorkContextQueryResult, WorkContextRecord,
    WorkContextRelationKind, WorkContextTargetKind, WorkSessionId, negotiate_platform_version,
};
use automonique_protocol::platform_v2_lifecycle::{
    AuthorityGrantId, MutationApprovalId, MutationApprovalRequirement, MutationExplanation,
    MutationRefusal, MutationRefusalCategory, WorkContextAuthority, WorkContextMutationIntent,
    WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lineage::{WorkspaceIntent, WorkspaceIntentOutcome};
use automonique_protocol::platform_v2_review::{
    ReviewAction, ReviewActionReceipt, ReviewActionRequest, ReviewActorId, ReviewAuthentication,
    ReviewAuthority, ReviewAuthorityId, ReviewAuthorityKind, ReviewSnapshot,
};
use automonique_protocol::platform_v2_transport::{
    LIFECYCLE_CAPABILITY_EFFECT_KINDS, LifecycleCapabilities, LifecycleOperationCapability,
    PlatformV2Refusal, PlatformV2Request, PlatformV2Response, RawMutationApprovalDocument,
    RawMutationReceiptDocument, ReceiptLookupKey,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_protocol::wire::JsonValue;
use automonique_store::lineage_index::WorkspaceIntentExecutionReceipt;
use automonique_store::lineage_index::{IntentAuthorizationScope, LineageIndex};
use automonique_store::review_store::{
    ApprovalPolicy, ReviewActionAdmission, ReviewExternalEffectPlan, ReviewStore, ReviewStoreError,
    ReviewWriteAdmission, StoredReviewAction,
};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformV2ReviewDeliveryState {
    NotStarted,
    Pending,
    Completed,
    Refused,
    Ambiguous,
}

/// Immutable execution fence passed to the scheduler with a retained-session
/// delivery. The scheduler must revalidate this complete server-owned lineage
/// immediately before the provider receives `payload`.
pub struct PlatformV2ReviewExecutionFence<'a> {
    tenant: &'a str,
    project: &'a ProjectId,
    review_workspace: &'a WorkContextIdentity,
    expected_registry_generation: [u8; 32],
    work_session_id: &'a WorkSessionId,
    expected_work_session_revision: Revision,
    provider: &'a str,
    provider_session_id: &'a str,
    expected_provider_session_revision: Revision,
}

impl PlatformV2ReviewExecutionFence<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new<'a>(
        tenant: &'a str,
        project: &'a ProjectId,
        review_workspace: &'a WorkContextIdentity,
        expected_registry_generation: [u8; 32],
        work_session_id: &'a WorkSessionId,
        expected_work_session_revision: Revision,
        provider: &'a str,
        provider_session_id: &'a str,
        expected_provider_session_revision: Revision,
    ) -> PlatformV2ReviewExecutionFence<'a> {
        PlatformV2ReviewExecutionFence {
            tenant,
            project,
            review_workspace,
            expected_registry_generation,
            work_session_id,
            expected_work_session_revision,
            provider,
            provider_session_id,
            expected_provider_session_revision,
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> &str {
        self.tenant
    }

    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        self.project
    }

    #[must_use]
    pub const fn review_workspace(&self) -> &WorkContextIdentity {
        self.review_workspace
    }

    #[must_use]
    pub const fn expected_registry_generation(&self) -> [u8; 32] {
        self.expected_registry_generation
    }

    #[must_use]
    pub const fn work_session_id(&self) -> &WorkSessionId {
        self.work_session_id
    }

    #[must_use]
    pub const fn expected_work_session_revision(&self) -> Revision {
        self.expected_work_session_revision
    }

    #[must_use]
    pub const fn provider(&self) -> &str {
        self.provider
    }

    #[must_use]
    pub const fn provider_session_id(&self) -> &str {
        self.provider_session_id
    }

    #[must_use]
    pub const fn expected_provider_session_revision(&self) -> Revision {
        self.expected_provider_session_revision
    }
}

/// Exact durable inbox identity and exact provider bytes. Reconciliation must
/// match every field, not merely the idempotency key.
pub struct PlatformV2ReviewDeliveryCoordinate<'a> {
    fence: PlatformV2ReviewExecutionFence<'a>,
    transport_key: &'a str,
    payload: &'a [u8],
}

impl PlatformV2ReviewDeliveryCoordinate<'_> {
    pub(crate) const fn new<'a>(
        fence: PlatformV2ReviewExecutionFence<'a>,
        transport_key: &'a str,
        payload: &'a [u8],
    ) -> PlatformV2ReviewDeliveryCoordinate<'a> {
        PlatformV2ReviewDeliveryCoordinate {
            fence,
            transport_key,
            payload,
        }
    }

    #[must_use]
    pub const fn fence(&self) -> &PlatformV2ReviewExecutionFence<'_> {
        &self.fence
    }

    #[must_use]
    pub const fn transport_key(&self) -> &str {
        self.transport_key
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// A scheduler failure is either a proof that no external custody started or
/// an ambiguity that forbids blind replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformV2ReviewDeliveryError {
    RefusedNotStarted(&'static str),
    Ambiguous(&'static str),
}

/// Durable scheduler boundary for one retained provider session. The v2 host
/// owns target selection and payload construction; implementations may only
/// inspect or submit those already-closed coordinates.
pub trait PlatformV2ReviewDelivery {
    fn inspect_target(
        &self,
        provider: &str,
        provider_session_id: &str,
    ) -> Result<Revision, &'static str>;

    fn reconcile(
        &mut self,
        coordinate: &PlatformV2ReviewDeliveryCoordinate<'_>,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError>;

    /// Prove that the exact closed coordinate is admissible at the durable
    /// delivery boundary before the review store admits a write. This is a
    /// pre-custody check: deterministic encoding or size refusal must never be
    /// promoted to an ambiguous provider outcome.
    fn preflight(
        &self,
        _coordinate: &PlatformV2ReviewDeliveryCoordinate<'_>,
    ) -> Result<(), PlatformV2ReviewDeliveryError> {
        Ok(())
    }

    fn submit(
        &mut self,
        coordinate: &PlatformV2ReviewDeliveryCoordinate<'_>,
        now_ms: i64,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError>;
}

struct UnavailableReviewDelivery;

impl PlatformV2ReviewDelivery for UnavailableReviewDelivery {
    fn inspect_target(&self, _: &str, _: &str) -> Result<Revision, &'static str> {
        Err("platform_v2_review_agent_adapter_unavailable")
    }

    fn reconcile(
        &mut self,
        _: &PlatformV2ReviewDeliveryCoordinate<'_>,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError> {
        Err(PlatformV2ReviewDeliveryError::RefusedNotStarted(
            "platform_v2_review_agent_adapter_unavailable",
        ))
    }

    fn submit(
        &mut self,
        _: &PlatformV2ReviewDeliveryCoordinate<'_>,
        _: i64,
    ) -> Result<PlatformV2ReviewDeliveryState, PlatformV2ReviewDeliveryError> {
        Err(PlatformV2ReviewDeliveryError::RefusedNotStarted(
            "platform_v2_review_agent_adapter_unavailable",
        ))
    }
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

    /// Whether this adapter can prove that a workspace intent has no durable
    /// effect custody. Cancellation must consult custody even when mutable
    /// registry selectors no longer permit new workspace effects.
    fn workspace_intent_custody_installed(&self) -> bool {
        self.workspace_intents_supported()
    }

    fn preflight_workspace_intent(
        &self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _checkout: &CheckoutId,
        _workspace_revision: Revision,
        _policy_generation: Sha256Digest,
    ) -> Result<(), &'static str> {
        Err("platform_v2_workspace_executor_unavailable")
    }

    /// Replay only a durably completed adapter receipt. This must not consult
    /// mutable selector or filesystem state.
    fn replay_workspace_intent_receipt(
        &self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
    ) -> Result<Option<WorkspaceIntentOutcome>, &'static str> {
        Ok(None)
    }

    fn execute_workspace_intent(
        &mut self,
        _intent: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _checkout: &CheckoutId,
        _workspace_revision: Revision,
        _policy_generation: Sha256Digest,
    ) -> Result<WorkspaceIntentOutcome, &'static str> {
        Err("platform_v2_workspace_executor_unavailable")
    }

    fn cancel_workspace_intent(
        &mut self,
        _target: &WorkspaceIntent,
        _project: &ProjectId,
        _workspace: &UserWorkspaceId,
        _policy_generation: Sha256Digest,
    ) -> Result<(), &'static str> {
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

    fn binding_digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"automonique.platform/v2/policy-file-generation/v1\0");
        hasher.update(&self.device.to_be_bytes());
        hasher.update(&self.inode.to_be_bytes());
        hasher.update(&self.changed_seconds.to_be_bytes());
        hasher.update(&self.changed_nanoseconds.to_be_bytes());
        hasher.update(&self.modified_seconds.to_be_bytes());
        hasher.update(&self.modified_nanoseconds.to_be_bytes());
        hasher.update(&self.length.to_be_bytes());
        hasher.update(self.digest.as_bytes());
        hasher.finish()
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
        self.handle_with_review_delivery(uid, request, now_ms, &mut UnavailableReviewDelivery)
    }

    pub fn handle_with_review_delivery(
        &mut self,
        uid: u32,
        request: &PlatformV2Request,
        now_ms: i64,
        review_delivery: &mut dyn PlatformV2ReviewDelivery,
    ) -> PlatformV2Response {
        match self {
            Self::Enabled(runtime) => runtime
                .handle(uid, request, now_ms, review_delivery)
                .unwrap_or_else(refused),
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
        PlatformV2Request::GetReviewReceipt(value) => {
            if principal
                .workspaces
                .get(value.workspace())
                .is_none_or(|scope| &scope.project != value.project())
            {
                return Err("platform_v2_mobile_project_denied");
            }
            value.project().clone()
        }
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
        // Validate every private adapter registry before opening or updating a
        // durable store. A malformed operator file must disable v2 without
        // leaving partially refreshed grants behind.
        let review_effects = ProductionReviewEffectAdapter::open(
            &policy_path
                .parent()
                .ok_or("platform_v2_state_path_invalid")?
                .join(crate::platform_v2_review_adapter::REVIEW_REGISTRY_FILE_NAME),
            expected_uid,
        )?;
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
            review_effects,
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
        review_delivery: &mut dyn PlatformV2ReviewDelivery,
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
                let (stored, replayed) = if matches!(value.intent(), WorkspaceIntent::Cancel(_)) {
                    (None, None)
                } else {
                    let replayed = self
                        .lifecycle_effects
                        .replay_workspace_intent_receipt(value.intent(), value.project())?;
                    let stored = self
                        .lineage
                        .intent_authorized_in_workspaces(
                            &negotiated_v2()?,
                            principal.actor.tenant(),
                            value.intent().intent_id(),
                            &allowed,
                        )
                        .map_err(|_| "platform_v2_intent_refused")?;
                    (stored, replayed)
                };
                if let Some(stored) = stored.as_ref() {
                    if stored.intent != *value.intent() {
                        return Err("platform_v2_intent_refused");
                    }
                    if stored.outcome.reconciliation()
                        == automonique_protocol::platform_v2_lineage::WorkspaceIntentReconciliation::Final
                    {
                        return Ok(PlatformV2Response::WorkspaceIntentResult(
                            stored.outcome.clone(),
                        ));
                    }
                }
                if let Some(outcome) = replayed {
                    let workspace = completed_workspace_outcome(value.intent(), &outcome)?;
                    authorize_workspace(&principal, value.project(), workspace)?;
                    let stored = stored.as_ref().ok_or("platform_v2_intent_refused")?;
                    if stored.workspace != *workspace {
                        return Err("platform_v2_workspace_effect_binding_mismatch");
                    }
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
                    return Ok(PlatformV2Response::WorkspaceIntentResult(outcome));
                }
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
                        intent.workspace().clone()
                    }
                    WorkspaceIntent::Cancel(intent) => {
                        authorize_workspace(&principal, value.project(), intent.workspace())?;
                        if let Some(existing) = self
                            .lineage
                            .intent_authorized_in_workspaces(
                                &negotiated_v2()?,
                                principal.actor.tenant(),
                                intent.intent_id(),
                                &allowed,
                            )
                            .map_err(|_| "platform_v2_intent_refused")?
                        {
                            if existing.intent != *value.intent() {
                                return Err("platform_v2_intent_refused");
                            }
                            return Ok(PlatformV2Response::WorkspaceIntentResult(existing.outcome));
                        }
                        let target = self
                            .lineage
                            .intent_authorized_in_workspaces(
                                &negotiated_v2()?,
                                principal.actor.tenant(),
                                intent.target_intent_id(),
                                &allowed,
                            )
                            .map_err(|_| "platform_v2_intent_refused")?
                            .ok_or("platform_v2_intent_refused")?;
                        if target.revision != intent.expected_revision()
                            || target.outcome.reconciliation()
                                == automonique_protocol::platform_v2_lineage::WorkspaceIntentReconciliation::Final
                        {
                            return Err("platform_v2_intent_refused");
                        }
                        let target_workspace = match &target.intent {
                            WorkspaceIntent::Create(create) => self
                                .lineage
                                .task_workspace_authorized(
                                    principal.actor.tenant(),
                                    create.task(),
                                    &allowed,
                                )
                                .map_err(|_| "platform_v2_intent_refused")?
                                .ok_or("platform_v2_intent_refused")?,
                            WorkspaceIntent::Resume(resume) => resume.workspace().clone(),
                            WorkspaceIntent::Cancel(_) => {
                                return Err("platform_v2_intent_refused");
                            }
                        };
                        if target_workspace != *intent.workspace() {
                            return Err("platform_v2_intent_refused");
                        }
                        if self.lifecycle_effects.workspace_intent_custody_installed() {
                            self.lifecycle_effects.cancel_workspace_intent(
                                &target.intent,
                                value.project(),
                                intent.workspace(),
                                self.policy_fence.generation.binding_digest(),
                            )?;
                            self.policy_fence.verify()?;
                        }
                        let outcome =
                            WorkspaceIntentOutcome::Cancelled(intent.target_intent_id().clone());
                        self.lineage
                            .record_intent(principal.actor.tenant(), value.intent(), &outcome)
                            .map_err(|_| "platform_v2_intent_refused")?;
                        return Ok(PlatformV2Response::WorkspaceIntentResult(outcome));
                    }
                };
                let workspace_record = self
                    .work_contexts
                    .validate_policy_mapping(
                        principal.actor.tenant(),
                        value.project(),
                        &WorkContextIdentity::UserWorkspace(workspace.clone()),
                    )
                    .map_err(|_| "platform_v2_policy_incoherent")?;
                let (checkout, workspace_revision) = active_workspace_binding(&workspace_record)
                    .map_err(|category| match value.intent() {
                        WorkspaceIntent::Create(_) => category,
                        WorkspaceIntent::Resume(_) => "platform_v2_resume_not_resumable",
                        WorkspaceIntent::Cancel(_) => unreachable!("handled above"),
                    })?;
                if let WorkspaceIntent::Resume(intent) = value.intent()
                    && intent.expected_revision() != workspace_revision
                {
                    return Err("platform_v2_resume_stale_revision");
                }
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
                    &checkout,
                    workspace_revision,
                    self.policy_fence.generation.binding_digest(),
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
                    &checkout,
                    workspace_revision,
                    self.policy_fence.generation.binding_digest(),
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
                    if let Some(outcome) = self
                        .lifecycle_effects
                        .replay_workspace_intent_receipt(&stored.intent, value.project())?
                    {
                        let workspace = completed_workspace_outcome(&stored.intent, &outcome)?;
                        authorize_workspace(&principal, value.project(), workspace)?;
                        if stored.workspace != *workspace {
                            return Err("platform_v2_workspace_effect_binding_mismatch");
                        }
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
                    let workspace_record = self
                        .work_contexts
                        .validate_policy_mapping(
                            principal.actor.tenant(),
                            value.project(),
                            &WorkContextIdentity::UserWorkspace(workspace.clone()),
                        )
                        .map_err(|_| "platform_v2_policy_incoherent")?;
                    let (checkout, workspace_revision) = active_workspace_binding(&workspace_record)
                        .map_err(|category| match &stored.intent {
                            WorkspaceIntent::Create(_) => category,
                            WorkspaceIntent::Resume(_) => "platform_v2_resume_not_resumable",
                            WorkspaceIntent::Cancel(_) => unreachable!("handled above"),
                        })?;
                    if let WorkspaceIntent::Resume(intent) = &stored.intent
                        && intent.expected_revision() != workspace_revision
                    {
                        return Err("platform_v2_resume_stale_revision");
                    }
                    if !self.lifecycle_effects.workspace_intents_supported() {
                        return Err("platform_v2_workspace_intent_recovery_unavailable");
                    }
                    self.lifecycle_effects.preflight_workspace_intent(
                        &stored.intent,
                        value.project(),
                        &workspace,
                        &checkout,
                        workspace_revision,
                        self.policy_fence.generation.binding_digest(),
                    )?;
                    self.policy_fence.verify()?;
                    let outcome = self.lifecycle_effects.execute_workspace_intent(
                        &stored.intent,
                        value.project(),
                        &workspace,
                        &checkout,
                        workspace_revision,
                        self.policy_fence.generation.binding_digest(),
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
                if let Some((existing, plan)) = self
                    .reviews
                    .external_action(
                        request.workspace(),
                        request.actor(),
                        request.authentication(),
                        request.authority(),
                        request.idempotency_key(),
                        now_ms,
                    )
                    .map_err(review_store_category)?
                {
                    let request_digest =
                        ReviewStore::action_request_digest(&request, ApprovalPolicy::NotRequired)
                            .map_err(review_store_category)?;
                    if existing.request_digest != request_digest
                        || existing.request != request
                        || existing.approval_policy != ApprovalPolicy::NotRequired
                    {
                        return Err("platform_v2_review_conflict");
                    }
                    if existing.receipt.outcome()
                        != automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Accepted
                        && existing.receipt.outcome()
                            != automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Unknown
                    {
                        return Ok(PlatformV2Response::ReviewReceipt(existing.receipt));
                    }
                    if existing.write_admitted_at_ms.is_none()
                        && self
                            .validate_retained_review_execution_fence(
                                &principal,
                                &existing,
                                &plan,
                                review_delivery,
                            )
                            .is_err()
                    {
                        let receipt = self
                            .reviews
                            .refuse_external_action_not_started(
                                &existing.preview_id,
                                existing.request_digest,
                                now_ms,
                            )
                            .map_err(review_store_category)?;
                        return Ok(PlatformV2Response::ReviewReceipt(receipt));
                    }
                    let write =
                        match self.start_retained_review_write_or_refuse(&existing, now_ms)? {
                            Ok(write) => write,
                            Err(receipt) => {
                                return Ok(PlatformV2Response::ReviewReceipt(receipt));
                            }
                        };
                    let action = match write {
                        ReviewWriteAdmission::New(action)
                        | ReviewWriteAdmission::Replay(action) => action,
                    };
                    let receipt = self.drive_retained_review_delivery(
                        &principal,
                        &action,
                        &plan,
                        review_delivery,
                        now_ms,
                    )?;
                    return Ok(PlatformV2Response::ReviewReceipt(receipt));
                }
                if let Some(existing) = self
                    .reviews
                    .inspect_action(&request, ApprovalPolicy::NotRequired, now_ms)
                    .map_err(review_store_category)?
                {
                    if existing.receipt.outcome()
                        == automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Accepted
                        || existing.receipt.outcome()
                            == automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Unknown
                    {
                        return Err("platform_v2_review_plan_missing");
                    }
                    return Ok(PlatformV2Response::ReviewReceipt(existing.receipt));
                }
                match self.review_effects.plan(
                    &scope.project,
                    request.workspace(),
                    request.authority(),
                    request.action(),
                ) {
                    Ok(ReviewEffectPlan::LocalStore) => {
                        self.policy_fence.verify()?;
                        let receipt = self
                            .reviews
                            .execute_local_action(&request, now_ms)
                            .map_err(review_store_category)?;
                        self.policy_fence.verify()?;
                        Ok(PlatformV2Response::ReviewReceipt(receipt))
                    }
                    Ok(ReviewEffectPlan::RetainedSession {
                        provider,
                        provider_session_id,
                        work_session_id,
                        registry_generation,
                    }) => {
                        let snapshot = self
                            .reviews
                            .snapshot(request.workspace())
                            .map_err(review_store_category)?
                            .ok_or("platform_v2_not_found")?;
                        let payload = retained_review_payload(&snapshot, request.action())?;
                        let work_session_revision = self
                            .work_contexts
                            .validate_retained_session_lineage(
                                principal.actor.tenant(),
                                &scope.project,
                                request.workspace(),
                                &work_session_id,
                                &provider_session_id,
                            )
                            .map_err(|_| "platform_v2_review_session_lineage_refused")?;
                        let provider_session_revision =
                            review_delivery.inspect_target(&provider, &provider_session_id)?;
                        let request_digest = ReviewStore::action_request_digest(
                            &request,
                            ApprovalPolicy::NotRequired,
                        )
                        .map_err(review_store_category)?;
                        let transport_key = format!(
                            "v2-review-{}",
                            request_digest
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>()
                        );
                        let external_plan = ReviewExternalEffectPlan::retained_session(
                            request_digest,
                            registry_generation,
                            &provider,
                            work_session_id.as_str(),
                            &provider_session_id,
                            work_session_revision,
                            provider_session_revision,
                            &transport_key,
                            payload,
                        )
                        .map_err(review_store_category)?;
                        self.policy_fence.verify()?;
                        self.review_effects.verify_generation()?;
                        let admitted = self
                            .reviews
                            .prepare_external_action(
                                &request,
                                ApprovalPolicy::NotRequired,
                                &external_plan,
                                now_ms,
                            )
                            .map_err(review_store_category)?;
                        let action = match admitted {
                            ReviewActionAdmission::New(action)
                            | ReviewActionAdmission::Replay(action) => action,
                        };
                        self.policy_fence.verify()?;
                        self.review_effects.verify_generation()?;
                        if self
                            .validate_retained_review_execution_fence(
                                &principal,
                                &action,
                                &external_plan,
                                review_delivery,
                            )
                            .is_err()
                        {
                            let receipt = self
                                .reviews
                                .refuse_external_action_not_started(
                                    &action.preview_id,
                                    action.request_digest,
                                    now_ms,
                                )
                                .map_err(review_store_category)?;
                            return Ok(PlatformV2Response::ReviewReceipt(receipt));
                        }
                        let write =
                            match self.start_retained_review_write_or_refuse(&action, now_ms)? {
                                Ok(write) => write,
                                Err(receipt) => {
                                    return Ok(PlatformV2Response::ReviewReceipt(receipt));
                                }
                            };
                        let action = match write {
                            ReviewWriteAdmission::New(action)
                            | ReviewWriteAdmission::Replay(action) => action,
                        };
                        let receipt = self.drive_retained_review_delivery(
                            &principal,
                            &action,
                            &external_plan,
                            review_delivery,
                            now_ms,
                        )?;
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
                    let external = self.reviews.external_action(
                        value.workspace(),
                        &actor,
                        ReviewAuthentication::UserSession,
                        authority,
                        value.idempotency_key(),
                        now_ms,
                    );
                    match external {
                        Ok(Some((action, plan))) => {
                            if action.receipt.outcome()
                                == automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Accepted
                                || action.receipt.outcome()
                                    == automonique_protocol::platform_v2_review::ReviewReceiptOutcome::Unknown
                            {
                                if action.write_admitted_at_ms.is_none()
                                    && self
                                        .validate_retained_review_execution_fence(
                                            &principal,
                                            &action,
                                            &plan,
                                            review_delivery,
                                        )
                                        .is_err()
                                {
                                    let receipt = self
                                        .reviews
                                        .refuse_external_action_not_started(
                                            &action.preview_id,
                                            action.request_digest,
                                            now_ms,
                                        )
                                        .map_err(review_store_category)?;
                                    return Ok(PlatformV2Response::ReviewReceipt(receipt));
                                }
                                let write = match self
                                    .start_retained_review_write_or_refuse(&action, now_ms)?
                                {
                                    Ok(write) => write,
                                    Err(receipt) => {
                                        return Ok(PlatformV2Response::ReviewReceipt(receipt));
                                    }
                                };
                                let action = match write {
                                    ReviewWriteAdmission::New(action)
                                    | ReviewWriteAdmission::Replay(action) => action,
                                };
                                let receipt = self.drive_retained_review_delivery(
                                    &principal,
                                    &action,
                                    &plan,
                                    review_delivery,
                                    now_ms,
                                )?;
                                return Ok(PlatformV2Response::ReviewReceipt(receipt));
                            }
                            return Ok(PlatformV2Response::ReviewReceipt(action.receipt));
                        }
                        Ok(None) | Err(ReviewStoreError::Unauthorized) => {}
                        Err(_) => return Err("platform_v2_receipt_refused"),
                    }
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

    fn start_retained_review_write_or_refuse(
        &mut self,
        action: &StoredReviewAction,
        now_ms: i64,
    ) -> Result<Result<ReviewWriteAdmission, ReviewActionReceipt>, &'static str> {
        match self
            .reviews
            .start_write(&action.preview_id, action.request_digest, now_ms)
        {
            Ok(write) => Ok(Ok(write)),
            Err(error) => {
                let category = review_store_category(error);
                self.reviews
                    .refuse_external_action_not_started(
                        &action.preview_id,
                        action.request_digest,
                        now_ms,
                    )
                    .map(Err)
                    .map_err(|_| category)
            }
        }
    }

    fn drive_retained_review_delivery(
        &mut self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
        delivery: &mut dyn PlatformV2ReviewDelivery,
        now_ms: i64,
    ) -> Result<ReviewActionReceipt, &'static str> {
        let scope = principal
            .workspaces
            .get(action.request.workspace())
            .ok_or("platform_v2_scope_denied")?;
        let work_session_id = WorkSessionId::new(plan.work_session_id().to_owned())
            .map_err(|_| "platform_v2_review_plan_invalid")?;
        let coordinate = PlatformV2ReviewDeliveryCoordinate::new(
            PlatformV2ReviewExecutionFence::new(
                principal.actor.tenant(),
                &scope.project,
                action.request.workspace(),
                plan.registry_generation_digest(),
                &work_session_id,
                plan.work_session_revision(),
                plan.provider(),
                plan.provider_session_id(),
                plan.provider_session_revision(),
            ),
            plan.transport_key(),
            plan.payload(),
        );
        let mut disposition = match delivery.reconcile(&coordinate) {
            Ok(disposition) => disposition,
            Err(error) => {
                return self.settle_review_delivery_error(action, plan, error, now_ms);
            }
        };
        if disposition == PlatformV2ReviewDeliveryState::NotStarted {
            if self
                .validate_retained_review_execution_fence(principal, action, plan, delivery)
                .is_err()
            {
                return self
                    .reviews
                    .complete_retained_session_delivery(
                        &action.preview_id,
                        action.request_digest,
                        plan.transport_key(),
                        false,
                        now_ms,
                    )
                    .map_err(review_store_category);
            }
            disposition = match delivery.submit(&coordinate, now_ms) {
                Ok(disposition) => disposition,
                Err(error) => {
                    return self.settle_review_delivery_error(action, plan, error, now_ms);
                }
            };
        }
        match disposition {
            PlatformV2ReviewDeliveryState::Completed => self
                .reviews
                .complete_retained_session_delivery(
                    &action.preview_id,
                    action.request_digest,
                    plan.transport_key(),
                    true,
                    now_ms,
                )
                .map_err(review_store_category),
            PlatformV2ReviewDeliveryState::NotStarted | PlatformV2ReviewDeliveryState::Refused => {
                self.reviews
                    .complete_retained_session_delivery(
                        &action.preview_id,
                        action.request_digest,
                        plan.transport_key(),
                        false,
                        now_ms,
                    )
                    .map_err(review_store_category)
            }
            PlatformV2ReviewDeliveryState::Pending => Ok(action.receipt.clone()),
            PlatformV2ReviewDeliveryState::Ambiguous => self
                .reviews
                .mark_ambiguous(&action.preview_id, action.request_digest, now_ms)
                .map_err(review_store_category),
        }
    }

    fn settle_review_delivery_error(
        &mut self,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
        error: PlatformV2ReviewDeliveryError,
        now_ms: i64,
    ) -> Result<ReviewActionReceipt, &'static str> {
        match error {
            PlatformV2ReviewDeliveryError::RefusedNotStarted(_) => self
                .reviews
                .complete_retained_session_delivery(
                    &action.preview_id,
                    action.request_digest,
                    plan.transport_key(),
                    false,
                    now_ms,
                )
                .map_err(review_store_category),
            PlatformV2ReviewDeliveryError::Ambiguous(_) => self
                .reviews
                .mark_ambiguous(&action.preview_id, action.request_digest, now_ms)
                .map_err(review_store_category),
        }
    }

    /// Re-open every mutable selector used to create a retained-session plan
    /// and prove it still names the exact durable fence. This runs immediately
    /// before write admission and again after admission, immediately before a
    /// scheduler submission that reconciliation proved has not started.
    fn validate_retained_review_execution_fence(
        &self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
        delivery: &dyn PlatformV2ReviewDelivery,
    ) -> Result<(), &'static str> {
        self.policy_fence.verify()?;
        let scope = principal
            .workspaces
            .get(action.request.workspace())
            .ok_or("platform_v2_scope_denied")?;
        let current = self.review_effects.plan(
            &scope.project,
            action.request.workspace(),
            action.request.authority(),
            action.request.action(),
        )?;
        let ReviewEffectPlan::RetainedSession {
            provider,
            provider_session_id,
            work_session_id,
            registry_generation,
        } = current
        else {
            return Err("platform_v2_review_registry_changed");
        };
        if provider != plan.provider()
            || provider_session_id != plan.provider_session_id()
            || work_session_id.as_str() != plan.work_session_id()
        {
            return Err("platform_v2_review_registry_changed");
        }
        let current_plan = ReviewExternalEffectPlan::retained_session(
            plan.request_digest(),
            registry_generation,
            &provider,
            work_session_id.as_str(),
            &provider_session_id,
            plan.work_session_revision(),
            plan.provider_session_revision(),
            plan.transport_key(),
            plan.payload().to_vec(),
        )
        .map_err(review_store_category)?;
        if current_plan.digest() != plan.digest() {
            return Err("platform_v2_review_registry_changed");
        }
        let work_revision = self
            .work_contexts
            .validate_retained_session_lineage(
                principal.actor.tenant(),
                &scope.project,
                action.request.workspace(),
                &work_session_id,
                &provider_session_id,
            )
            .map_err(|_| "platform_v2_review_session_lineage_refused")?;
        if work_revision != plan.work_session_revision() {
            return Err("platform_v2_review_work_session_changed");
        }
        let provider_revision = delivery.inspect_target(&provider, &provider_session_id)?;
        if provider_revision != plan.provider_session_revision() {
            return Err("platform_v2_review_session_changed");
        }
        let coordinate = PlatformV2ReviewDeliveryCoordinate::new(
            PlatformV2ReviewExecutionFence::new(
                principal.actor.tenant(),
                &scope.project,
                action.request.workspace(),
                plan.registry_generation_digest(),
                &work_session_id,
                plan.work_session_revision(),
                plan.provider(),
                plan.provider_session_id(),
                plan.provider_session_revision(),
            ),
            plan.transport_key(),
            plan.payload(),
        );
        delivery
            .preflight(&coordinate)
            .map_err(|error| match error {
                PlatformV2ReviewDeliveryError::RefusedNotStarted(category)
                | PlatformV2ReviewDeliveryError::Ambiguous(category) => category,
            })?;
        self.policy_fence.verify()?;
        self.review_effects.verify_generation()
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

fn retained_review_payload(
    snapshot: &ReviewSnapshot,
    action: &ReviewAction,
) -> Result<Vec<u8>, &'static str> {
    let targets: Vec<(
        &automonique_protocol::platform_v2_review::ReviewCommentId,
        Revision,
    )> = match action {
        ReviewAction::SendCommentToAgent {
            comment_id,
            expected_comment_revision,
        } => vec![(comment_id, *expected_comment_revision)],
        ReviewAction::BatchSendCommentsToAgent { comments } => comments
            .iter()
            .map(|target| (target.comment_id(), target.expected_revision()))
            .collect(),
        _ => return Err("platform_v2_review_agent_action_invalid"),
    };
    let mut encoded_comments = Vec::with_capacity(targets.len());
    for (comment_id, expected_revision) in targets {
        let comment = snapshot
            .comments()
            .iter()
            .find(|comment| comment.id() == comment_id && comment.revision() == expected_revision)
            .ok_or("platform_v2_review_agent_action_invalid")?;
        encoded_comments.push(JsonValue::Object(vec![
            (
                "actor".to_owned(),
                JsonValue::String(comment.actor().as_str().to_owned()),
            ),
            (
                "anchor".to_owned(),
                JsonValue::Object(vec![
                    (
                        "file_id".to_owned(),
                        JsonValue::String(comment.anchor().file_id().as_str().to_owned()),
                    ),
                    (
                        "hunk_id".to_owned(),
                        JsonValue::String(comment.anchor().hunk_id().as_str().to_owned()),
                    ),
                    (
                        "line".to_owned(),
                        JsonValue::Integer(i64::from(comment.anchor().line())),
                    ),
                    (
                        "side".to_owned(),
                        JsonValue::String(comment.anchor().side().as_str().to_owned()),
                    ),
                ]),
            ),
            (
                "body".to_owned(),
                JsonValue::String(comment.body().as_str().to_owned()),
            ),
            (
                "comment_id".to_owned(),
                JsonValue::String(comment.id().as_str().to_owned()),
            ),
            (
                "comment_revision".to_owned(),
                JsonValue::Integer(
                    i64::try_from(comment.revision().get())
                        .map_err(|_| "platform_v2_review_agent_action_invalid")?,
                ),
            ),
        ]));
    }
    Ok(JsonValue::Object(vec![
        (
            "comments".to_owned(),
            JsonValue::Array(encoded_comments),
        ),
        (
            "instruction".to_owned(),
            JsonValue::String(
                "Address these exact review comments in the named workspace; preserve their IDs in your response."
                    .to_owned(),
            ),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("automonique.platform/review-agent-delivery/v1".to_owned()),
        ),
        (
            "snapshot_revision".to_owned(),
            JsonValue::Integer(
                i64::try_from(snapshot.revision().get())
                    .map_err(|_| "platform_v2_review_agent_action_invalid")?,
            ),
        ),
        (
            "workspace".to_owned(),
            JsonValue::Object(vec![
                (
                    "id".to_owned(),
                    JsonValue::String(snapshot.workspace().id().to_owned()),
                ),
                (
                    "kind".to_owned(),
                    JsonValue::String(snapshot.workspace().kind().as_str().to_owned()),
                ),
            ]),
        ),
    ])
    .to_canonical_bytes())
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

fn active_workspace_binding(
    record: &WorkContextRecord,
) -> Result<(CheckoutId, Revision), &'static str> {
    if record.lifecycle() != WorkContextLifecycle::Active {
        return Err("platform_v2_workspace_not_active");
    }
    let mut checkouts = record.relations().iter().filter_map(|relation| {
        if relation.kind() != WorkContextRelationKind::UserWorkspaceCheckout {
            return None;
        }
        match relation.target() {
            WorkContextIdentity::Checkout(checkout) => Some(checkout.clone()),
            _ => None,
        }
    });
    let checkout = checkouts
        .next()
        .ok_or("platform_v2_workspace_checkout_invalid")?;
    if checkouts.next().is_some() {
        return Err("platform_v2_workspace_checkout_invalid");
    }
    Ok((checkout, record.revision()))
}

fn completed_workspace_outcome<'a>(
    intent: &WorkspaceIntent,
    outcome: &'a WorkspaceIntentOutcome,
) -> Result<&'a UserWorkspaceId, &'static str> {
    match (intent, outcome) {
        (WorkspaceIntent::Create(_), WorkspaceIntentOutcome::Created(workspace))
        | (WorkspaceIntent::Resume(_), WorkspaceIntentOutcome::Resumed(workspace)) => Ok(workspace),
        _ => Err("platform_v2_workspace_effect_binding_mismatch"),
    }
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

    use automonique_protocol::platform::IdempotencyKey;
    use automonique_protocol::platform_v2_transport::{
        LineageReadRequest, ReviewReadRequest, ReviewReceiptLookup,
    };

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
            ReviewReadRequest::new(
                project_b.clone(),
                WorkContextIdentity::UserWorkspace(workspace_a.clone()),
            )
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
        let mismatched_review_receipt = PlatformV2Request::GetReviewReceipt(
            ReviewReceiptLookup::new(
                project_b,
                WorkContextIdentity::UserWorkspace(workspace_a),
                IdempotencyKey::new("mobile:review:mismatched").unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            resolve_web_mobile_request_project(
                &path,
                uid,
                "tenant-test",
                "actor-test",
                &roots,
                &mismatched_review_receipt,
            ),
            Err("platform_v2_mobile_project_denied")
        );
    }
}
