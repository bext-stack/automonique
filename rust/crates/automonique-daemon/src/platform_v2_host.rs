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

use automonique_github_connector::{RepoTarget, WorkflowRunId};
use automonique_protocol::digest::{Sha256, Sha256Digest};
use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{ReceiptId, ResourceAuthority};
use automonique_protocol::platform_v2::{
    CheckoutId, NegotiatedPlatform, PlatformVersionOffer, ProjectId, UserWorkspaceId, V1SessionRef,
    WorkContextIdentity, WorkContextLifecycle, WorkContextQueryResult, WorkContextRecord,
    WorkContextRelationKind, WorkContextTargetKind, WorkSessionId, negotiate_platform_version,
};
use automonique_protocol::platform_v2_attention::{
    AttentionItem, AttentionItemId, AttentionItemReason, AttentionReadRequest, AttentionSourceKind,
    AttentionSourceSnapshot,
};
use automonique_protocol::platform_v2_lifecycle::{
    AuthorityGrantId, MutationApprovalId, MutationApprovalRequirement, MutationExplanation,
    MutationRefusal, MutationRefusalCategory, WorkContextAuthority, WorkContextMutationIntent,
    WorkContextMutationProposal,
};
use automonique_protocol::platform_v2_lineage::{
    LineageStatus, OrchestrationRecord, WorkspaceIntent, WorkspaceIntentOutcome,
};
use automonique_protocol::platform_v2_review::{
    AttentionReason as ReviewAttentionReason, CheckState, ReviewAction, ReviewActionReceipt,
    ReviewActionRequest, ReviewActorId, ReviewAuthentication, ReviewAuthority, ReviewAuthorityId,
    ReviewAuthorityKind, ReviewFreshnessState, ReviewReceiptOutcome, ReviewSnapshot,
};
use automonique_protocol::platform_v2_transport::{
    LIFECYCLE_CAPABILITY_EFFECT_KINDS, LifecycleCapabilities, LifecycleOperationCapability,
    PlatformV2Refusal, PlatformV2Request, PlatformV2Response, RawMutationApprovalDocument,
    RawMutationReceiptDocument, ReceiptLookupKey, ReviewCapabilities, ReviewCheckRerunCapability,
    ReviewConfirmationDigest, ReviewReceiptCorrelationDigest,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_protocol::wire::JsonValue;
use automonique_store::attention_store::AttentionStore;
use automonique_store::lineage_index::WorkspaceIntentExecutionReceipt;
use automonique_store::lineage_index::{IntentAuthorizationScope, LineageIndex};
use automonique_store::review_store::{
    ApprovalPolicy, ReviewActionAdmission, ReviewApprovalDecision, ReviewApprovalDocument,
    ReviewExternalEffectCustody, ReviewExternalEffectPlan, ReviewStore, ReviewStoreError,
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

use crate::platform_v2_attention_registry::AttentionRegistry;
use crate::platform_v2_github_check_adapter::{
    GitHubCheckRerunCustody, GitHubCheckRerunError, GitHubCheckRerunPlan,
    GitHubCheckRerunSubmission,
};
use crate::platform_v2_review_adapter::{ProductionReviewEffectAdapter, ReviewEffectPlan};

pub const POLICY_FILE_NAME: &str = "platform-v2-policy.json";
pub const WORK_CONTEXT_STORE_NAME: &str = "platform-v2-work-context.sqlite3";
pub const LINEAGE_STORE_NAME: &str = "platform-v2-lineage.sqlite3";
pub const REVIEW_STORE_NAME: &str = "platform-v2-review.sqlite3";
pub const ATTENTION_STORE_NAME: &str =
    crate::platform_v2_attention_registry::ATTENTION_STORE_FILE_NAME;
pub const ATTENTION_REGISTRY_NAME: &str =
    crate::platform_v2_attention_registry::ATTENTION_REGISTRY_FILE_NAME;

const PREVIEW_LIFETIME_MS: i64 = 5 * 60 * 1_000;
const APPROVAL_LIFETIME_MS: i64 = 60 * 1_000;
const EFFECT_LEASE_LIFETIME_MS: i64 = 30 * 1_000;
const MAX_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitHubRecoveryPhase {
    NeverStarted,
    ReconcileOnly,
    Terminal,
}

fn github_recovery_phase(
    outcome: ReviewReceiptOutcome,
    write_admitted: bool,
    custody: ReviewExternalEffectCustody,
) -> Result<GitHubRecoveryPhase, &'static str> {
    match (outcome, write_admitted, custody) {
        (ReviewReceiptOutcome::Accepted, false, ReviewExternalEffectCustody::NotStarted) => {
            Ok(GitHubRecoveryPhase::NeverStarted)
        }
        (
            ReviewReceiptOutcome::Accepted,
            true,
            ReviewExternalEffectCustody::CustodyStarted | ReviewExternalEffectCustody::Accepted,
        )
        | (ReviewReceiptOutcome::Unknown, true, ReviewExternalEffectCustody::Ambiguous) => {
            Ok(GitHubRecoveryPhase::ReconcileOnly)
        }
        (ReviewReceiptOutcome::Refused, _, ReviewExternalEffectCustody::Refused)
        | (
            ReviewReceiptOutcome::Completed | ReviewReceiptOutcome::Conflict,
            true,
            ReviewExternalEffectCustody::Completed,
        ) => Ok(GitHubRecoveryPhase::Terminal),
        _ => Err("platform_v2_review_confirmation_corrupt"),
    }
}

fn stored_github_recovery_phase(
    action: &StoredReviewAction,
    plan: &ReviewExternalEffectPlan,
) -> Result<GitHubRecoveryPhase, &'static str> {
    require_native_github_recovery_identity(plan)?;
    github_recovery_phase(
        action.receipt.outcome(),
        action.write_admitted_at_ms.is_some(),
        plan.github_custody()
            .ok_or("platform_v2_review_plan_invalid")?,
    )
}

fn require_native_github_recovery_identity(
    plan: &ReviewExternalEffectPlan,
) -> Result<(Revision, [u8; 32]), &'static str> {
    match (
        plan.github_expected_workspace_revision(),
        plan.github_receipt_correlation_digest(),
    ) {
        (Some(workspace_revision), Some(receipt_correlation)) => {
            Ok((workspace_revision, receipt_correlation))
        }
        _ => Err("platform_v2_review_plan_invalid"),
    }
}

fn github_receipt_correlation_matches(
    stored: Option<[u8; 32]>,
    supplied: Option<&ReviewReceiptCorrelationDigest>,
) -> Result<bool, &'static str> {
    let (Some(stored), Some(supplied)) = (stored, supplied) else {
        return Ok(false);
    };
    Ok(review_receipt_correlation_digest(stored)?.as_str() == supplied.as_str())
}

fn review_confirmation_digest(digest: [u8; 32]) -> Result<ReviewConfirmationDigest, &'static str> {
    let value = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ReviewConfirmationDigest::new(value).map_err(|_| "platform_v2_response_invalid")
}
fn review_receipt_correlation_digest(
    digest: [u8; 32],
) -> Result<ReviewReceiptCorrelationDigest, &'static str> {
    ReviewReceiptCorrelationDigest::new(
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .map_err(|_| "platform_v2_response_invalid")
}

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
    attention: AttentionStore,
    attention_registry: AttentionRegistry,
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
            .field("attention", &self.attention)
            .field("attention_registry", &self.attention_registry)
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
        PlatformV2Request::GetReview(value) | PlatformV2Request::GetReviewCapabilities(value) => {
            if principal
                .workspaces
                .get(value.workspace())
                .is_none_or(|scope| &scope.project != value.project())
            {
                return Err("platform_v2_mobile_project_denied");
            }
            value.project().clone()
        }
        PlatformV2Request::GetAttentionSourceSnapshot(value) => {
            let workspace = WorkContextIdentity::UserWorkspace(value.user_workspace().clone());
            if principal
                .workspaces
                .get(&workspace)
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
        let state_dir = policy_path
            .parent()
            .ok_or("platform_v2_state_path_invalid")?;
        let mut attention =
            AttentionStore::open_scoped(state_dir.join(ATTENTION_STORE_NAME), tenant)
                .map_err(|_| "platform_v2_store_unavailable")?;
        let principal = principals
            .get(&expected_uid)
            .ok_or("platform_v2_policy_invalid")?;
        let attention_registry = AttentionRegistry::open(
            &state_dir.join(ATTENTION_REGISTRY_NAME),
            expected_uid,
            &mut attention,
            |snapshot| runtime_attention_source_reserved(principal, snapshot),
        )?;
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
            attention,
            attention_registry,
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
            PlatformV2Request::GetAttentionSourceSnapshot(value) => {
                let workspace = WorkContextIdentity::UserWorkspace(value.user_workspace().clone());
                authorize_identity(&principal, value.project(), &workspace)?;
                self.validate_policy_mapping(&principal, &workspace)?;
                match self.runtime_attention_snapshot(&principal, value, now_ms)? {
                    Some(snapshot) => Ok(PlatformV2Response::AttentionSourceSnapshot(snapshot)),
                    None => self
                        .attention_registry
                        .snapshot(value, &self.attention)
                        .map(PlatformV2Response::AttentionSourceSnapshot),
                }
            }
            PlatformV2Request::GetReviewCapabilities(value) => {
                authorize_identity(&principal, value.project(), value.workspace())?;
                let scope = principal
                    .workspaces
                    .get(value.workspace())
                    .ok_or("platform_v2_scope_denied")?;
                let workspace_record = self
                    .work_contexts
                    .validate_policy_mapping(
                        principal.actor.tenant(),
                        &scope.project,
                        value.workspace(),
                    )
                    .map_err(|_| "platform_v2_policy_incoherent")?;
                let snapshot = self
                    .reviews
                    .snapshot(value.workspace())
                    .map_err(|_| "platform_v2_store_refused")?
                    .ok_or("platform_v2_not_found")?;
                let Some(authority) = principal
                    .review_authorities
                    .get(&ReviewAuthorityKind::Ci)
                    .cloned()
                else {
                    return Ok(PlatformV2Response::ReviewCapabilities(
                        ReviewCapabilities::new(
                            value.project().clone(),
                            value.workspace().clone(),
                            snapshot.revision(),
                            workspace_record.revision(),
                            Vec::new(),
                        )
                        .map_err(|_| "platform_v2_response_invalid")?,
                    ));
                };
                let mut rerunnable = Vec::new();
                for check in snapshot.checks() {
                    if check.authority() != &authority
                        || check.freshness().state() != ReviewFreshnessState::Fresh
                        || !matches!(
                            check.state(),
                            CheckState::Passed | CheckState::Failed | CheckState::Cancelled
                        )
                    {
                        continue;
                    }
                    let action = ReviewAction::RerunCheck {
                        check_id: check.id().clone(),
                        expected_check_revision: check.freshness().observed_revision(),
                    };
                    let plan = self.review_effects.plan(
                        value.project(),
                        value.workspace(),
                        &authority,
                        &action,
                    );
                    if plan.as_ref().is_ok_and(|plan| {
                        matches!(plan, ReviewEffectPlan::GitHubCheckRerun { .. })
                            && self
                                .review_effects
                                .preflight_github_capability(plan)
                                .is_ok()
                    }) {
                        let plan = plan.map_err(|_| "platform_v2_review_ci_check_unavailable")?;
                        let confirmation = self.review_effects.github_confirmation_digest(
                            &principal.actor,
                            value.project(),
                            value.workspace(),
                            &authority,
                            snapshot.revision(),
                            workspace_record.revision(),
                            &action,
                            &plan,
                        )?;
                        rerunnable.push(
                            ReviewCheckRerunCapability::new(
                                check.id().clone(),
                                check.freshness().observed_revision(),
                                authority.clone(),
                                review_confirmation_digest(confirmation)?,
                                review_receipt_correlation_digest(ProductionReviewEffectAdapter::github_receipt_correlation_digest(confirmation))?,
                            )
                            .map_err(|_| "platform_v2_response_invalid")?,
                        );
                    }
                }
                Ok(PlatformV2Response::ReviewCapabilities(
                    ReviewCapabilities::new(
                        value.project().clone(),
                        value.workspace().clone(),
                        snapshot.revision(),
                        workspace_record.revision(),
                        rerunnable,
                    )
                    .map_err(|_| "platform_v2_response_invalid")?,
                ))
            }
            PlatformV2Request::ExecuteReviewAction(value) => {
                let confirmation_digest = value.confirmation_digest().cloned();
                let expected_workspace_revision = value.expected_workspace_revision();
                let receipt_correlation_digest = value.receipt_correlation_digest().cloned();
                let scope = principal
                    .workspaces
                    .get(value.workspace())
                    .ok_or("platform_v2_scope_denied")?;
                if !principal.projects.contains(&scope.project) {
                    return Err("platform_v2_scope_denied");
                }
                let workspace_record = self
                    .work_contexts
                    .validate_policy_mapping(
                        principal.actor.tenant(),
                        &scope.project,
                        value.workspace(),
                    )
                    .map_err(|_| "platform_v2_policy_incoherent")?;
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
                let approval_policy = if matches!(request.action(), ReviewAction::RerunCheck { .. })
                {
                    if confirmation_digest.is_none() {
                        return Err("platform_v2_review_confirmation_required");
                    }
                    if expected_workspace_revision.is_none() || receipt_correlation_digest.is_none()
                    {
                        return Err("platform_v2_review_confirmation_changed");
                    }
                    ApprovalPolicy::Required
                } else {
                    ApprovalPolicy::NotRequired
                };
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
                        ReviewStore::action_request_digest(&request, approval_policy)
                            .map_err(review_store_category)?;
                    if existing.request_digest != request_digest
                        || existing.request != request
                        || existing.approval_policy != approval_policy
                    {
                        return Err("platform_v2_review_conflict");
                    }
                    if plan.is_github_check_rerun() {
                        let supplied_workspace_revision = expected_workspace_revision
                            .ok_or("platform_v2_review_confirmation_required")?;
                        let planned_workspace_revision = plan
                            .github_expected_workspace_revision()
                            .ok_or("platform_v2_review_confirmation_changed")?;
                        if supplied_workspace_revision != planned_workspace_revision {
                            return Err("platform_v2_review_confirmation_changed");
                        }
                        let supplied = receipt_correlation_digest
                            .as_ref()
                            .ok_or("platform_v2_review_confirmation_required")?;
                        let actual = plan
                            .github_receipt_correlation_digest()
                            .ok_or("platform_v2_review_confirmation_changed")?;
                        if review_receipt_correlation_digest(actual)?.as_str() != supplied.as_str()
                        {
                            return Err("platform_v2_review_confirmation_changed");
                        }
                        if stored_github_recovery_phase(&existing, &plan)?
                            == GitHubRecoveryPhase::Terminal
                        {
                            return Ok(PlatformV2Response::ReviewReceipt(existing.receipt));
                        }
                        let existing = self.approve_prepared_github_confirmation(
                            &principal, &existing, &plan, now_ms,
                        )?;
                        let receipt =
                            self.drive_github_check_rerun(&principal, &existing, &plan, now_ms)?;
                        return Ok(PlatformV2Response::ReviewReceipt(receipt));
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
                    .inspect_action(&request, approval_policy, now_ms)
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
                    Ok(ReviewEffectPlan::GitHubCheckRerun {
                        credential_reference,
                        repository,
                        run_id,
                        head_sha,
                        observed_attempt,
                        expected_check_revision,
                        registry_generation,
                        credential_generation,
                    }) => {
                        if expected_workspace_revision != Some(workspace_record.revision()) {
                            return Err("platform_v2_review_confirmation_changed");
                        }
                        let advertised_plan = ReviewEffectPlan::GitHubCheckRerun {
                            credential_reference: credential_reference.clone(),
                            repository: repository.clone(),
                            run_id,
                            head_sha: head_sha.clone(),
                            observed_attempt,
                            expected_check_revision,
                            registry_generation,
                            credential_generation,
                        };
                        let expected_confirmation =
                            self.review_effects.github_confirmation_digest(
                                &principal.actor,
                                &scope.project,
                                request.workspace(),
                                request.authority(),
                                request.expected_revision(),
                                workspace_record.revision(),
                                request.action(),
                                &advertised_plan,
                            )?;
                        if confirmation_digest.as_ref().map(|value| value.as_str())
                            != Some(review_confirmation_digest(expected_confirmation)?.as_str())
                        {
                            return Err("platform_v2_review_confirmation_changed");
                        }
                        let expected_correlation =
                            ProductionReviewEffectAdapter::github_receipt_correlation_digest(
                                expected_confirmation,
                            );
                        if receipt_correlation_digest.as_ref().map(|v| v.as_str())
                            != Some(
                                review_receipt_correlation_digest(expected_correlation)?.as_str(),
                            )
                        {
                            return Err("platform_v2_review_confirmation_changed");
                        }
                        let request_digest =
                            ReviewStore::action_request_digest(&request, ApprovalPolicy::Required)
                                .map_err(review_store_category)?;
                        let external_plan = ReviewExternalEffectPlan::github_check_rerun(
                            request_digest,
                            registry_generation,
                            credential_generation,
                            &credential_reference,
                            repository.owner().as_str(),
                            repository.repo().as_str(),
                            run_id.get(),
                            &head_sha,
                            observed_attempt,
                            match request.action() {
                                ReviewAction::RerunCheck { check_id, .. } => check_id.clone(),
                                _ => return Err("platform_v2_review_plan_invalid"),
                            },
                            expected_check_revision,
                            workspace_record.revision(),
                            expected_correlation,
                        )
                        .map_err(review_store_category)?;
                        self.policy_fence.verify()?;
                        self.review_effects.verify_generation()?;
                        self.validate_workspace_revision(
                            &principal,
                            request.workspace(),
                            workspace_record.revision(),
                        )?;
                        let admitted = self
                            .reviews
                            .prepare_external_action(
                                &request,
                                ApprovalPolicy::Required,
                                &external_plan,
                                now_ms,
                            )
                            .map_err(review_store_category)?;
                        let action = match admitted {
                            ReviewActionAdmission::New(action)
                            | ReviewActionAdmission::Replay(action) => action,
                        };
                        let action = self.approve_prepared_github_confirmation(
                            &principal,
                            &action,
                            &external_plan,
                            now_ms,
                        )?;
                        let receipt = self.drive_github_check_rerun(
                            &principal,
                            &action,
                            &external_plan,
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
                            if plan.is_github_check_rerun() {
                                let Ok((_, stored_correlation)) =
                                    require_native_github_recovery_identity(&plan)
                                else {
                                    // A migrated or otherwise partial GitHub
                                    // plan has no complete native recovery
                                    // identity. It is deliberately invisible
                                    // and must never fall through to the
                                    // generic receipt index.
                                    continue;
                                };
                                if !github_receipt_correlation_matches(
                                    Some(stored_correlation),
                                    value.receipt_correlation_digest(),
                                )? {
                                    continue;
                                }
                            } else if value.receipt_correlation_digest().is_some() {
                                continue;
                            }
                            if plan.is_github_check_rerun() {
                                if stored_github_recovery_phase(&action, &plan)?
                                    == GitHubRecoveryPhase::Terminal
                                {
                                    return Ok(PlatformV2Response::ReviewReceipt(action.receipt));
                                }
                                let action = self.approve_prepared_github_confirmation(
                                    &principal, &action, &plan, now_ms,
                                )?;
                                let receipt = self
                                    .drive_github_check_rerun(&principal, &action, &plan, now_ms)?;
                                return Ok(PlatformV2Response::ReviewReceipt(receipt));
                            }
                            if action.receipt.outcome() == ReviewReceiptOutcome::Accepted
                                || action.receipt.outcome() == ReviewReceiptOutcome::Unknown
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
                    if value.receipt_correlation_digest().is_some() {
                        continue;
                    }
                    let receipt = self.reviews.non_rerun_receipt(
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

    fn drive_github_check_rerun(
        &mut self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
        now_ms: i64,
    ) -> Result<ReviewActionReceipt, &'static str> {
        require_native_github_recovery_identity(plan)?;
        let scope = principal
            .workspaces
            .get(action.request.workspace())
            .ok_or("platform_v2_scope_denied")?;
        let phase = stored_github_recovery_phase(action, plan)?;
        if phase == GitHubRecoveryPhase::Terminal {
            return Ok(action.receipt.clone());
        }
        let mut may_submit = false;
        let mut refresh_plan = false;
        let action = if phase == GitHubRecoveryPhase::NeverStarted {
            if self
                .validate_github_check_execution_fence(principal, action, plan)
                .is_err()
            {
                return self
                    .reviews
                    .refuse_external_action_not_started(
                        &action.preview_id,
                        action.request_digest,
                        now_ms,
                    )
                    .map_err(review_store_category);
            }
            let write = self
                .reviews
                .start_write(&action.preview_id, action.request_digest, now_ms)
                .map_err(review_store_category)?;
            match write {
                ReviewWriteAdmission::New(action) => {
                    may_submit = true;
                    refresh_plan = true;
                    action
                }
                ReviewWriteAdmission::Replay(action) => {
                    refresh_plan = true;
                    action
                }
            }
        } else {
            action.clone()
        };
        let refreshed_plan;
        let plan = if refresh_plan {
            let (stored, refreshed) = self
                .reviews
                .external_action(
                    action.request.workspace(),
                    action.request.actor(),
                    action.request.authentication(),
                    action.request.authority(),
                    action.request.idempotency_key(),
                    now_ms,
                )
                .map_err(review_store_category)?
                .ok_or("platform_v2_review_plan_missing")?;
            if stored.preview_id != action.preview_id
                || stored.request_digest != action.request_digest
            {
                return Err("platform_v2_review_plan_invalid");
            }
            refreshed_plan = refreshed;
            &refreshed_plan
        } else {
            plan
        };
        if may_submit
            && self
                .validate_github_check_execution_fence(principal, &action, plan)
                .is_err()
        {
            return self
                .reviews
                .settle_github_check_rerun(
                    &action.preview_id,
                    action.request_digest,
                    ReviewExternalEffectCustody::Refused,
                    now_ms,
                )
                .map_err(review_store_category);
        }
        let provider_plan = github_provider_plan(principal, &scope.project, &action.request, plan)?;
        let repository = github_repository(plan)?;
        let credential_reference = plan
            .github_credential_reference()
            .ok_or("platform_v2_review_plan_invalid")?;
        let credential_generation = plan
            .github_credential_generation_digest()
            .ok_or("platform_v2_review_plan_invalid")?;
        let adapter = match self.review_effects.github_adapter(
            credential_reference,
            &repository,
            credential_generation,
        ) {
            Ok(adapter) => adapter,
            Err(category) if may_submit => {
                return self
                    .reviews
                    .settle_github_check_rerun(
                        &action.preview_id,
                        action.request_digest,
                        ReviewExternalEffectCustody::Refused,
                        now_ms,
                    )
                    .map_err(|_| category);
            }
            Err(category) => return Err(category),
        };
        let custody = map_store_github_custody(
            plan.github_custody()
                .ok_or("platform_v2_review_plan_invalid")?,
        );
        let mut submission =
            GitHubCheckRerunSubmission::restore(&provider_plan, provider_plan.digest(), custody)
                .map_err(github_rerun_category)?;
        if let Err(category) = self.policy_fence.verify() {
            if may_submit {
                return self
                    .reviews
                    .settle_github_check_rerun(
                        &action.preview_id,
                        action.request_digest,
                        ReviewExternalEffectCustody::Refused,
                        now_ms,
                    )
                    .map_err(|_| category);
            }
            return Err(category);
        }
        let result = if may_submit {
            adapter.submit(&provider_plan, &mut submission)
        } else {
            adapter.reconcile(&provider_plan, &mut submission)
        };
        self.policy_fence.verify()?;
        let settled = match result {
            Ok(custody) => map_github_store_custody(custody),
            Err(error) => match submission.custody() {
                GitHubCheckRerunCustody::Refused => ReviewExternalEffectCustody::Refused,
                GitHubCheckRerunCustody::Ambiguous
                | GitHubCheckRerunCustody::CustodyStarted
                | GitHubCheckRerunCustody::Accepted => ReviewExternalEffectCustody::Ambiguous,
                GitHubCheckRerunCustody::Completed => ReviewExternalEffectCustody::Completed,
                GitHubCheckRerunCustody::NotStarted => return Err(github_rerun_category(error)),
            },
        };
        self.reviews
            .settle_github_check_rerun(&action.preview_id, action.request_digest, settled, now_ms)
            .map_err(review_store_category)
    }

    fn approve_prepared_github_confirmation(
        &mut self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
        now_ms: i64,
    ) -> Result<StoredReviewAction, &'static str> {
        require_native_github_recovery_identity(plan)?;
        if action.approval_policy != ApprovalPolicy::Required
            || !matches!(action.request.action(), ReviewAction::RerunCheck { .. })
        {
            return Err("platform_v2_review_confirmation_required");
        }
        let phase = stored_github_recovery_phase(action, plan)?;
        if phase == GitHubRecoveryPhase::Terminal {
            return Ok(action.clone());
        }
        if phase == GitHubRecoveryPhase::NeverStarted {
            self.validate_github_workspace_revision(principal, action, plan)?;
        }
        if action.approval.is_some() {
            return Ok(action.clone());
        }
        if phase != GitHubRecoveryPhase::NeverStarted {
            return Err("platform_v2_review_confirmation_corrupt");
        }
        // This prepared row can only be created after the confirmed transport
        // digest has been validated.  Completing the adjacent durable approval
        // is therefore safe after a crash between those two SQLite commits;
        // provider custody still cannot begin until this approval exists.
        let approval_expires_at = now_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or("platform_v2_time_invalid")?;
        let approval = ReviewApprovalDocument::new(
            action.preview_id.clone(),
            action.request.workspace().clone(),
            action.request.actor().clone(),
            action.request.authentication(),
            action.request.authority().clone(),
            action.request_digest,
            action.request.expected_revision(),
            ReviewApprovalDecision::Approved,
            approval_expires_at,
        )
        .map_err(review_store_category)?;
        self.reviews
            .decide_action(&approval, now_ms)
            .map_err(review_store_category)
    }

    fn validate_github_check_execution_fence(
        &self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
    ) -> Result<(), &'static str> {
        self.policy_fence.verify()?;
        let scope = principal
            .workspaces
            .get(action.request.workspace())
            .ok_or("platform_v2_scope_denied")?;
        let workspace_record = self
            .work_contexts
            .validate_policy_mapping(
                principal.actor.tenant(),
                &scope.project,
                action.request.workspace(),
            )
            .map_err(|_| "platform_v2_review_workspace_changed")?;
        let expected_workspace_revision = plan
            .github_expected_workspace_revision()
            .ok_or("platform_v2_review_workspace_changed")?;
        if workspace_record.revision() != expected_workspace_revision {
            return Err("platform_v2_review_workspace_changed");
        }
        let current = self.review_effects.plan(
            &scope.project,
            action.request.workspace(),
            action.request.authority(),
            action.request.action(),
        )?;
        let ReviewEffectPlan::GitHubCheckRerun {
            credential_reference,
            repository,
            run_id,
            head_sha,
            observed_attempt,
            expected_check_revision,
            registry_generation,
            credential_generation,
        } = current
        else {
            return Err("platform_v2_review_registry_changed");
        };
        let reconstructed = ReviewExternalEffectPlan::github_check_rerun(
            plan.request_digest(),
            registry_generation,
            credential_generation,
            &credential_reference,
            repository.owner().as_str(),
            repository.repo().as_str(),
            run_id.get(),
            &head_sha,
            observed_attempt,
            plan.github_check_id()
                .cloned()
                .ok_or("platform_v2_review_plan_invalid")?,
            expected_check_revision,
            expected_workspace_revision,
            plan.github_receipt_correlation_digest()
                .ok_or("platform_v2_review_plan_invalid")?,
        )
        .map_err(review_store_category)?;
        if reconstructed.digest() != plan.digest() {
            return Err("platform_v2_review_registry_changed");
        }
        let provider_plan = github_provider_plan(principal, &scope.project, &action.request, plan)?;
        self.review_effects
            .github_adapter(&credential_reference, &repository, credential_generation)?
            .preflight(&provider_plan)
            .map_err(github_rerun_category)?;
        self.policy_fence.verify()?;
        self.review_effects.verify_generation()
    }

    fn validate_github_workspace_revision(
        &self,
        principal: &PrincipalPolicy,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
    ) -> Result<(), &'static str> {
        let expected = plan
            .github_expected_workspace_revision()
            .ok_or("platform_v2_review_workspace_changed")?;
        self.validate_workspace_revision(principal, action.request.workspace(), expected)
    }

    fn validate_workspace_revision(
        &self,
        principal: &PrincipalPolicy,
        workspace: &WorkContextIdentity,
        expected: Revision,
    ) -> Result<(), &'static str> {
        let scope = principal
            .workspaces
            .get(workspace)
            .ok_or("platform_v2_scope_denied")?;
        let current = self
            .work_contexts
            .validate_policy_mapping(principal.actor.tenant(), &scope.project, workspace)
            .map_err(|_| "platform_v2_review_workspace_changed")?;
        (current.revision() == expected)
            .then_some(())
            .ok_or("platform_v2_review_workspace_changed")
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

    /// Project a source only from durable state already owned by this runtime.
    /// Source discovery is deliberately bounded by the existing authorized
    /// work-context catalogue: review and orchestration use the exact user
    /// workspace id, while provider-session sources use the exact retained
    /// work-session id. Unknown spellings fall through to the private bootstrap
    /// registry; no label, pane, or local presentation coordinate is inferred.
    fn runtime_attention_snapshot(
        &mut self,
        principal: &PrincipalPolicy,
        request: &AttentionReadRequest,
        now_ms: i64,
    ) -> Result<Option<AttentionSourceSnapshot>, &'static str> {
        let observed_at_ms = u64::try_from(now_ms).map_err(|_| "platform_v2_time_invalid")?;
        let source = request.source();
        let workspace = request.user_workspace();
        let desired = match source.kind() {
            AttentionSourceKind::Review if workspace_source_matches(source, workspace) => {
                refuse_registry_runtime_collision(&self.attention_registry, request)?;
                let identity = WorkContextIdentity::UserWorkspace(workspace.clone());
                let review = self
                    .reviews
                    .snapshot(&identity)
                    .map_err(|_| "platform_v2_store_refused")?;
                review_attention_items_from_snapshot(review.as_ref(), observed_at_ms)?
            }
            AttentionSourceKind::Orchestration if workspace_source_matches(source, workspace) => {
                refuse_registry_runtime_collision(&self.attention_registry, request)?;
                let scope = IntentAuthorizationScope::new(
                    principal.actor.tenant().to_owned(),
                    request.project().clone(),
                    workspace.clone(),
                )
                .map_err(|_| "platform_v2_scope_denied")?;
                let projection = self
                    .lineage
                    .projection_authorized(&negotiated_v2()?, &scope, |_| true)
                    .map_err(|_| "platform_v2_attention_source_unavailable")?;
                let current = self
                    .attention
                    .snapshot(source, request.project(), workspace)
                    .map_err(|_| "platform_v2_attention_store_refused")?;
                orchestration_attention_items(projection.orchestration(), current.as_ref())?
            }
            AttentionSourceKind::ProviderSession => {
                let work_session = WorkSessionId::new(source.id().as_str().to_owned())
                    .map_err(|_| "platform_v2_attention_not_found")?;
                let identity = WorkContextIdentity::Session(work_session.clone());
                let Some(scope) = principal.workspaces.get(&identity) else {
                    return Ok(None);
                };
                if &scope.project != request.project() {
                    return Err("platform_v2_scope_denied");
                }
                refuse_registry_runtime_collision(&self.attention_registry, request)?;
                let session = self
                    .work_contexts
                    .validate_policy_mapping(principal.actor.tenant(), request.project(), &identity)
                    .map_err(|_| "platform_v2_policy_incoherent")?;
                let platform_session = session
                    .relations()
                    .iter()
                    .find(|relation| {
                        relation.kind() == WorkContextRelationKind::SessionPlatformSession
                    })
                    .and_then(|relation| match relation.target() {
                        WorkContextIdentity::PlatformSession(value) => Some(value.clone()),
                        _ => None,
                    })
                    .ok_or("platform_v2_attention_source_unavailable")?;
                let session = self
                    .work_contexts
                    .validate_retained_session_attention_lineage(
                        principal.actor.tenant(),
                        request.project(),
                        &WorkContextIdentity::UserWorkspace(workspace.clone()),
                        &work_session,
                        platform_session.coordinate().id.as_str(),
                    )
                    .map_err(|_| "platform_v2_attention_source_unavailable")?;
                let current = self
                    .attention
                    .snapshot(source, request.project(), workspace)
                    .map_err(|_| "platform_v2_attention_store_refused")?;
                retained_session_attention_items(
                    &session,
                    platform_session,
                    observed_at_ms,
                    current.as_ref(),
                )?
            }
            _ => return Ok(None),
        };
        self.persist_runtime_attention(request, desired, observed_at_ms)
            .map(Some)
    }

    fn persist_runtime_attention(
        &mut self,
        request: &AttentionReadRequest,
        desired: Vec<AttentionItem>,
        observed_at_ms: u64,
    ) -> Result<AttentionSourceSnapshot, &'static str> {
        persist_runtime_attention_snapshot(&mut self.attention, request, desired, observed_at_ms)
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

fn persist_runtime_attention_snapshot(
    store: &mut AttentionStore,
    request: &AttentionReadRequest,
    desired: Vec<AttentionItem>,
    observed_at_ms: u64,
) -> Result<AttentionSourceSnapshot, &'static str> {
    let current = store
        .snapshot(
            request.source(),
            request.project(),
            request.user_workspace(),
        )
        .map_err(|_| "platform_v2_attention_store_refused")?;
    let snapshot =
        prepare_runtime_attention_snapshot(request, desired, observed_at_ms, current.as_ref())?;
    if current.as_ref() == Some(&snapshot) {
        return Ok(snapshot);
    }
    store
        .put_snapshot(&snapshot)
        .map_err(|_| "platform_v2_attention_store_refused")?;
    Ok(snapshot)
}

fn prepare_runtime_attention_snapshot(
    request: &AttentionReadRequest,
    mut desired: Vec<AttentionItem>,
    observed_at_ms: u64,
    current: Option<&AttentionSourceSnapshot>,
) -> Result<AttentionSourceSnapshot, &'static str> {
    desired.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    if let Some(current) = current
        && current.items().len() == desired.len()
        && current
            .items()
            .iter()
            .zip(&desired)
            .all(|(old, item)| attention_item_equal_except_revision_and_observed(old, item))
    {
        // Observation is not a source change. Detect replay before allocating
        // a successor so an exact replay remains readable at Revision::MAX.
        return Ok(current.clone());
    }
    let revision = current
        .map_or(Ok(Revision::FIRST), |value| value.revision().checked_next())
        .map_err(|_| "platform_v2_attention_revision_exhausted")?;
    for item in &mut desired {
        let previous =
            current.and_then(|snapshot| snapshot.items().iter().find(|old| old.id() == item.id()));
        let (item_revision, item_observed_at_ms) =
            previous.map_or((revision, item.observed_at_ms()), |old| {
                if attention_item_equal_except_revision_and_observed(old, item) {
                    (old.revision(), old.observed_at_ms())
                } else {
                    (revision, item.observed_at_ms().max(old.observed_at_ms()))
                }
            });
        *item = AttentionItem::new(
            item.id().clone(),
            item_revision,
            item_observed_at_ms,
            item.state(),
            item.reason(),
            item.unread(),
            item.nested_agent_path().to_vec(),
            item.platform_session().cloned(),
        )
        .map_err(|_| "platform_v2_attention_projection_invalid")?;
    }
    let previous_revision = current.map(AttentionSourceSnapshot::revision);
    let snapshot_observed_at_ms = current
        .map_or(observed_at_ms, |value| {
            value.observed_at_ms().max(observed_at_ms)
        })
        .max(
            desired
                .iter()
                .map(AttentionItem::observed_at_ms)
                .max()
                .unwrap_or(0),
        );
    let snapshot = AttentionSourceSnapshot::new(
        request.source().clone(),
        request.project().clone(),
        request.user_workspace().clone(),
        revision,
        previous_revision,
        snapshot_observed_at_ms,
        desired,
    )
    .map_err(|_| "platform_v2_attention_projection_invalid")?;
    Ok(snapshot)
}

fn workspace_source_matches(
    source: &automonique_protocol::platform_v2_attention::AttentionSource,
    workspace: &UserWorkspaceId,
) -> bool {
    source.id().as_str() == workspace.as_str()
}

fn refuse_registry_runtime_collision(
    registry: &AttentionRegistry,
    request: &AttentionReadRequest,
) -> Result<(), &'static str> {
    if registry.contains(request) {
        Err("platform_v2_attention_registry_runtime_collision")
    } else {
        Ok(())
    }
}

fn runtime_attention_source_reserved(
    principal: &PrincipalPolicy,
    snapshot: &AttentionSourceSnapshot,
) -> bool {
    match snapshot.source().kind() {
        AttentionSourceKind::Review | AttentionSourceKind::Orchestration => principal
            .workspaces
            .keys()
            .any(|identity| {
                matches!(identity, WorkContextIdentity::UserWorkspace(workspace) if workspace.as_str() == snapshot.source().id().as_str())
            }),
        AttentionSourceKind::ProviderSession => principal.workspaces.keys().any(|identity| {
            matches!(identity, WorkContextIdentity::Session(session) if session.as_str() == snapshot.source().id().as_str())
        }),
    }
}

fn attention_item_equal_except_revision_and_observed(
    left: &AttentionItem,
    right: &AttentionItem,
) -> bool {
    left.id() == right.id()
        && left.state() == right.state()
        && left.reason() == right.reason()
        && left.unread() == right.unread()
        && left.nested_agent_path() == right.nested_agent_path()
        && left.platform_session() == right.platform_session()
}

fn review_attention_items(
    review: &ReviewSnapshot,
    observed_at_ms: u64,
) -> Result<Vec<AttentionItem>, &'static str> {
    review
        .attention_events()
        .iter()
        .map(|event| {
            let reason = review_attention_reason(event.reason());
            AttentionItem::new(
                AttentionItemId::new(event.id().as_str().to_owned())
                    .map_err(|_| "platform_v2_attention_projection_invalid")?,
                Revision::FIRST,
                observed_at_ms,
                reason.state(),
                reason,
                event.unread() > 0,
                Vec::new(),
                None,
            )
            .map_err(|_| "platform_v2_attention_projection_invalid")
        })
        .collect()
}

fn review_attention_items_from_snapshot(
    review: Option<&ReviewSnapshot>,
    observed_at_ms: u64,
) -> Result<Vec<AttentionItem>, &'static str> {
    review_attention_items(
        review.ok_or("platform_v2_attention_not_found")?,
        observed_at_ms,
    )
}

const fn review_attention_reason(reason: ReviewAttentionReason) -> AttentionItemReason {
    match reason {
        ReviewAttentionReason::ReviewRequested => AttentionItemReason::ReviewRequested,
        ReviewAttentionReason::CommentReply => AttentionItemReason::CommentReply,
        ReviewAttentionReason::ApprovalRequired => AttentionItemReason::ApprovalRequired,
        ReviewAttentionReason::CheckRunning => AttentionItemReason::CheckRunning,
        ReviewAttentionReason::CheckFailed => AttentionItemReason::CheckFailed,
        ReviewAttentionReason::Conflict => AttentionItemReason::Conflict,
        ReviewAttentionReason::DeliveryPending => AttentionItemReason::DeliveryPending,
        ReviewAttentionReason::Complete => AttentionItemReason::Complete,
        ReviewAttentionReason::ExternalBlocker => AttentionItemReason::ExternalBlocker,
    }
}

fn orchestration_attention_items(
    records: &[OrchestrationRecord],
    current: Option<&AttentionSourceSnapshot>,
) -> Result<Vec<AttentionItem>, &'static str> {
    records
        .iter()
        .filter_map(|record| {
            let (reason, unread) = match record.status() {
                LineageStatus::Working => Some((AttentionItemReason::AgentWorking, false)),
                LineageStatus::Blocked(_) => Some((AttentionItemReason::ExternalBlocker, true)),
                // Waiting does not say who or what is awaited. Projecting it
                // as approval-required or externally blocked would invent a
                // stronger condition than the durable lineage record.
                LineageStatus::Waiting(_) => None,
                LineageStatus::Done(_) => Some((AttentionItemReason::Complete, true)),
            }?;
            let prefix = runtime_attention_incarnation_prefix(
                "orchestration",
                &[record.identity().kind().as_str(), record.identity().id()],
            );
            Some(
                runtime_attention_incarnation_id(current, &prefix, record.revision()).and_then(
                    |id| {
                        AttentionItem::new(
                            id,
                            Revision::FIRST,
                            record.freshness().observed_at_ms(),
                            reason.state(),
                            reason,
                            unread,
                            Vec::new(),
                            None,
                        )
                        .map_err(|_| "platform_v2_attention_projection_invalid")
                    },
                ),
            )
        })
        .collect()
}

fn retained_session_attention_items(
    session: &WorkContextRecord,
    platform_session: V1SessionRef,
    observed_at_ms: u64,
    current: Option<&AttentionSourceSnapshot>,
) -> Result<Vec<AttentionItem>, &'static str> {
    let projection = retained_session_attention_projection(session.lifecycle());
    let Some((reason, unread)) = projection else {
        return Ok(Vec::new());
    };
    let prefix =
        runtime_attention_incarnation_prefix("retained-session", &[session.identity().id()]);
    let id = runtime_attention_incarnation_id(current, &prefix, session.revision())?;
    AttentionItem::new(
        id,
        Revision::FIRST,
        observed_at_ms,
        reason.state(),
        reason,
        unread,
        Vec::new(),
        Some(platform_session),
    )
    .map(|item| vec![item])
    .map_err(|_| "platform_v2_attention_projection_invalid")
}

const fn retained_session_attention_projection(
    lifecycle: WorkContextLifecycle,
) -> Option<(AttentionItemReason, bool)> {
    match lifecycle {
        WorkContextLifecycle::Active
        | WorkContextLifecycle::Preparing
        | WorkContextLifecycle::Running => Some((AttentionItemReason::AgentWorking, false)),
        WorkContextLifecycle::Completed => Some((AttentionItemReason::Complete, true)),
        WorkContextLifecycle::Archived
        | WorkContextLifecycle::Cancelled
        | WorkContextLifecycle::Closed => Some((AttentionItemReason::Complete, false)),
        WorkContextLifecycle::Failed => Some((AttentionItemReason::ExternalBlocker, true)),
        WorkContextLifecycle::Hibernated => None,
    }
}

fn runtime_attention_incarnation_prefix(domain: &str, components: &[&str]) -> String {
    let mut material = Vec::new();
    for component in std::iter::once(domain).chain(components.iter().copied()) {
        let bytes = component.as_bytes();
        material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        material.extend_from_slice(bytes);
    }
    format!(
        "runtime-{domain}-{}-i",
        automonique_protocol::digest::Sha256::digest(&material).to_hex()
    )
}

fn runtime_attention_incarnation_id(
    current: Option<&AttentionSourceSnapshot>,
    prefix: &str,
    incarnation: Revision,
) -> Result<AttentionItemId, &'static str> {
    let mut matching = current
        .into_iter()
        .flat_map(AttentionSourceSnapshot::items)
        .filter(|item| item.id().as_str().starts_with(prefix));
    if let Some(existing) = matching.next() {
        if matching.next().is_some() {
            return Err("platform_v2_attention_projection_invalid");
        }
        return Ok(existing.id().clone());
    }
    AttentionItemId::new(format!("{prefix}{incarnation}"))
        .map_err(|_| "platform_v2_attention_projection_invalid")
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

fn github_repository(plan: &ReviewExternalEffectPlan) -> Result<RepoTarget, &'static str> {
    RepoTarget::parse(
        plan.github_repository_owner()
            .ok_or("platform_v2_review_plan_invalid")?,
        plan.github_repository_name()
            .ok_or("platform_v2_review_plan_invalid")?,
    )
    .map_err(|_| "platform_v2_review_plan_invalid")
}

fn github_provider_plan(
    principal: &PrincipalPolicy,
    project: &ProjectId,
    request: &ReviewActionRequest,
    plan: &ReviewExternalEffectPlan,
) -> Result<GitHubCheckRerunPlan, &'static str> {
    GitHubCheckRerunPlan::new(
        plan.registry_generation_digest(),
        plan.github_credential_generation_digest()
            .ok_or("platform_v2_review_plan_invalid")?,
        plan.github_credential_reference()
            .ok_or("platform_v2_review_plan_invalid")?,
        github_repository(plan)?,
        WorkflowRunId::new(
            plan.github_run_id()
                .ok_or("platform_v2_review_plan_invalid")?,
        )
        .map_err(|_| "platform_v2_review_plan_invalid")?,
        plan.github_head_sha()
            .ok_or("platform_v2_review_plan_invalid")?,
        plan.github_observed_attempt()
            .ok_or("platform_v2_review_plan_invalid")?,
        &principal.actor,
        project.clone(),
        request.workspace().clone(),
        request.authority().clone(),
        request.idempotency_key().clone(),
        plan.github_check_id()
            .cloned()
            .ok_or("platform_v2_review_plan_invalid")?,
        request.expected_revision(),
        plan.github_expected_check_revision()
            .ok_or("platform_v2_review_plan_invalid")?,
    )
    .map_err(github_rerun_category)
}

const fn map_store_github_custody(value: ReviewExternalEffectCustody) -> GitHubCheckRerunCustody {
    match value {
        ReviewExternalEffectCustody::NotStarted => GitHubCheckRerunCustody::NotStarted,
        ReviewExternalEffectCustody::CustodyStarted => GitHubCheckRerunCustody::CustodyStarted,
        ReviewExternalEffectCustody::Accepted => GitHubCheckRerunCustody::Accepted,
        ReviewExternalEffectCustody::Ambiguous => GitHubCheckRerunCustody::Ambiguous,
        ReviewExternalEffectCustody::Refused => GitHubCheckRerunCustody::Refused,
        ReviewExternalEffectCustody::Completed => GitHubCheckRerunCustody::Completed,
    }
}

const fn map_github_store_custody(value: GitHubCheckRerunCustody) -> ReviewExternalEffectCustody {
    match value {
        GitHubCheckRerunCustody::NotStarted => ReviewExternalEffectCustody::NotStarted,
        GitHubCheckRerunCustody::CustodyStarted => ReviewExternalEffectCustody::CustodyStarted,
        GitHubCheckRerunCustody::Accepted => ReviewExternalEffectCustody::Accepted,
        GitHubCheckRerunCustody::Ambiguous => ReviewExternalEffectCustody::Ambiguous,
        GitHubCheckRerunCustody::Refused => ReviewExternalEffectCustody::Refused,
        GitHubCheckRerunCustody::Completed => ReviewExternalEffectCustody::Completed,
    }
}

const fn github_rerun_category(error: GitHubCheckRerunError) -> &'static str {
    match error {
        GitHubCheckRerunError::InvalidPlan | GitHubCheckRerunError::SubmissionState => {
            "platform_v2_review_plan_invalid"
        }
        GitHubCheckRerunError::CapabilityMismatch => "platform_v2_review_ci_credential_incoherent",
        GitHubCheckRerunError::ProviderUnavailable => "platform_v2_review_ci_provider_unavailable",
        GitHubCheckRerunError::ProviderRefused => "platform_v2_review_ci_provider_refused",
        GitHubCheckRerunError::ResourceChanged => "platform_v2_review_ci_check_changed",
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
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use automonique_github_connector::{
        GetWorkflowRunRequest, GitHubFailure, GitHubOutcome, GitHubReply, GitHubWorkflowRun,
        RateLimit, RerunWorkflowRequest, WorkflowRunStatus,
    };
    use automonique_protocol::platform::{
        IdempotencyKey, ResourceCoordinate, ResourceId, ResourceKind,
    };
    use automonique_protocol::platform_v2::{
        AttemptWorkspaceId, CheckoutKind, HostSetupKind, V1RepositoryRef, WorkContextAttributes,
        WorkContextLabel, WorkContextRelation,
    };
    use automonique_protocol::platform_v2_attention::{
        AttentionReadRequest, AttentionSource, AttentionSourceId, AttentionSourceKind,
    };
    use automonique_protocol::platform_v2_lifecycle::{
        ExpectedWorkContext, ExternalParentResolution,
    };
    use automonique_protocol::platform_v2_review::{ReviewCheckId, ReviewReceiptOutcome};
    use automonique_protocol::platform_v2_review_api::decode_review_snapshot;
    use automonique_protocol::platform_v2_transport::{
        LineageReadRequest, ReviewReadRequest, ReviewReceiptLookup,
    };
    use automonique_store::review_store::ReviewActionAdmission;
    use rusqlite::params;

    use crate::platform_v2_github_check_adapter::{
        GitHubActionsTransport, SharedGitHubActionsTransport,
    };

    const GITHUB_RECOVERY_REVIEW_SNAPSHOT: &[u8] =
        include_bytes!("../../automonique-protocol/fixtures/platform-v2-review-v2.json");

    #[derive(Default)]
    struct ProviderCallCounts {
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    struct CountingGitHubTransport {
        counts: Arc<ProviderCallCounts>,
        attempt: Arc<AtomicU32>,
    }

    impl GitHubActionsTransport for CountingGitHubTransport {
        fn get_workflow_run(
            &self,
            _: &GetWorkflowRunRequest,
        ) -> Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure> {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            Ok(GitHubReply::new(
                RateLimit::new(None, None, None),
                GitHubOutcome::Accepted(GitHubWorkflowRun {
                    id: WorkflowRunId::new(91).unwrap(),
                    head_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                    run_attempt: self.attempt.load(Ordering::SeqCst),
                    status: WorkflowRunStatus::Completed,
                }),
            ))
        }

        fn rerun_workflow(
            &self,
            _: &RerunWorkflowRequest,
        ) -> Result<GitHubReply<()>, GitHubFailure> {
            self.counts.writes.fetch_add(1, Ordering::SeqCst);
            Ok(GitHubReply::new(
                RateLimit::new(None, None, None),
                GitHubOutcome::Accepted(()),
            ))
        }
    }

    struct GitHubRecoveryFixture {
        _directory: tempfile::TempDir,
        policy_path: PathBuf,
        work_context_path: PathBuf,
        lineage_path: PathBuf,
        review_path: PathBuf,
        uid: u32,
        counts: Arc<ProviderCallCounts>,
        attempt: Arc<AtomicU32>,
        transport: SharedGitHubActionsTransport,
    }

    impl GitHubRecoveryFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let uid = nix::unistd::geteuid().as_raw();
            let policy_path = directory.path().join(POLICY_FILE_NAME);
            let work_context_path = directory.path().join(WORK_CONTEXT_STORE_NAME);
            let lineage_path = directory.path().join(LINEAGE_STORE_NAME);
            let review_path = directory.path().join(REVIEW_STORE_NAME);
            let empty = serde_json::json!({
                "filesystem": [], "credentials": [], "network": [],
                "tools": [], "providers": [], "models": []
            });
            let policy = serde_json::json!({
                "version": 1,
                "principals": [{
                    "uid": uid,
                    "tenant": "tenant-test",
                    "actor": "actor-test",
                    "serving_authority": "automonique",
                    "projects": ["project-test"],
                    "workspaces": [
                        {"project":"project-test","kind":"project","id":"project-test","inherited_authority":empty.clone()},
                        {"project":"project-test","kind":"host_setup","id":"host-test","inherited_authority":empty.clone()},
                        {"project":"project-test","kind":"checkout","id":"checkout-test","inherited_authority":empty.clone()},
                        {"project":"project-test","kind":"user_workspace","id":"wc_user_1","inherited_authority":empty.clone()}
                    ],
                    "authority": empty,
                    "review_authorities": {"ci":"authority-1"}
                }]
            });
            write_generation_policy(&policy_path, &policy);

            let project = WorkContextRecord::new(
                WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
                Revision::FIRST,
                WorkContextLifecycle::Active,
                WorkContextLabel::new("Project test").unwrap(),
                WorkContextAttributes::EMPTY,
                Vec::new(),
            )
            .unwrap();
            let host = WorkContextRecord::new(
                WorkContextIdentity::parse_local(WorkContextTargetKind::HostSetup, "host-test")
                    .unwrap(),
                Revision::FIRST,
                WorkContextLifecycle::Active,
                WorkContextLabel::new("Host test").unwrap(),
                WorkContextAttributes::host_setup(HostSetupKind::Local),
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::HostSetupProject,
                        project.identity().clone(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
            let repository = WorkContextIdentity::Repository(
                V1RepositoryRef::new(ResourceCoordinate::new(
                    ResourceAuthority::GitHub,
                    ResourceKind::Repository,
                    ResourceId::new("repository-test").unwrap(),
                ))
                .unwrap(),
            );
            let checkout = WorkContextRecord::new(
                WorkContextIdentity::parse_local(WorkContextTargetKind::Checkout, "checkout-test")
                    .unwrap(),
                Revision::FIRST,
                WorkContextLifecycle::Active,
                WorkContextLabel::new("Checkout test").unwrap(),
                WorkContextAttributes::checkout(CheckoutKind::AuthorizedFolder),
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::CheckoutProject,
                        project.identity().clone(),
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::CheckoutHostSetup,
                        host.identity().clone(),
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::CheckoutRepository,
                        repository.clone(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
            let workspace = Self::workspace_record(Revision::FIRST, WorkContextLifecycle::Active);
            let mut contexts = WorkContextStore::open(&work_context_path).unwrap();
            contexts
                .put_external_snapshot(
                    "tenant-test",
                    &ExpectedWorkContext::new(repository, Revision::FIRST),
                    ExternalParentResolution::Available,
                    Some(&ProjectId::new("project-test").unwrap()),
                )
                .unwrap();
            for record in [project, host, checkout, workspace] {
                contexts
                    .put_authoritative_record("tenant-test", &record)
                    .unwrap();
            }
            drop(contexts);
            ReviewStore::open_scoped(&review_path, "tenant-test")
                .unwrap()
                .put_snapshot(
                    &decode_review_snapshot(GITHUB_RECOVERY_REVIEW_SNAPSHOT).unwrap(),
                    1,
                )
                .unwrap();

            let registry = serde_json::json!({
                "version":1,"generation":"github-recovery-test",
                "bindings":[{
                    "project":"project-test","workspace_kind":"user_workspace","workspace_id":"wc_user_1",
                    "authority_kind":"ci","authority_id":"authority-1",
                    "target":{"kind":"ci","provider":"github","target":"example-org/example-repo",
                        "credential_reference":"github-actions-mobile","checks":[{
                            "check_id":"check-1","run_id":91,
                            "head_sha":"0123456789abcdef0123456789abcdef01234567",
                            "observed_attempt":3,"observed_check_revision":7
                        }]}
                }]
            });
            let credentials = serde_json::json!({
                "version":1,"generation":"github-credentials-test",
                "credentials":[{"reference":"github-actions-mobile",
                    "repository":"example-org/example-repo","actions_write":true,
                    "token":"github_pat_test_only_not_a_secret"}]
            });
            for (path, document) in [
                (
                    directory
                        .path()
                        .join(crate::platform_v2_review_adapter::REVIEW_REGISTRY_FILE_NAME),
                    registry,
                ),
                (
                    directory.path().join(
                        crate::platform_v2_review_adapter::REVIEW_GITHUB_CREDENTIALS_FILE_NAME,
                    ),
                    credentials,
                ),
            ] {
                fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let counts = Arc::new(ProviderCallCounts::default());
            let attempt = Arc::new(AtomicU32::new(3));
            let transport: SharedGitHubActionsTransport =
                Arc::new(Mutex::new(Box::new(CountingGitHubTransport {
                    counts: Arc::clone(&counts),
                    attempt: Arc::clone(&attempt),
                })));
            Self {
                _directory: directory,
                policy_path,
                work_context_path,
                lineage_path,
                review_path,
                uid,
                counts,
                attempt,
                transport,
            }
        }

        fn workspace_record(
            revision: Revision,
            lifecycle: WorkContextLifecycle,
        ) -> WorkContextRecord {
            WorkContextRecord::new(
                WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("wc_user_1").unwrap()),
                revision,
                lifecycle,
                WorkContextLabel::new("Workspace test").unwrap(),
                WorkContextAttributes::EMPTY,
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::UserWorkspaceProject,
                        WorkContextIdentity::Project(ProjectId::new("project-test").unwrap()),
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::UserWorkspaceCheckout,
                        WorkContextIdentity::parse_local(
                            WorkContextTargetKind::Checkout,
                            "checkout-test",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
        }

        fn open(&self) -> PlatformV2Host {
            let mut host = PlatformV2Host::open(
                &self.policy_path,
                &self.work_context_path,
                &self.lineage_path,
                &self.review_path,
                self.uid,
            );
            let PlatformV2Host::Enabled(runtime) = &mut host else {
                panic!("GitHub recovery fixture host unavailable: {host:?}");
            };
            runtime
                .review_effects
                .set_github_test_transport(Arc::clone(&self.transport));
            host
        }

        fn advance_workspace(&self) {
            WorkContextStore::open(&self.work_context_path)
                .unwrap()
                .put_authoritative_record(
                    "tenant-test",
                    &Self::workspace_record(
                        Revision::new(2).unwrap(),
                        WorkContextLifecycle::Archived,
                    ),
                )
                .unwrap();
        }

        fn reset_counts(&self) {
            self.counts.reads.store(0, Ordering::SeqCst);
            self.counts.writes.store(0, Ordering::SeqCst);
        }

        fn set_attempt(&self, attempt: u32) {
            self.attempt.store(attempt, Ordering::SeqCst);
        }

        fn calls(&self) -> (usize, usize) {
            (
                self.counts.reads.load(Ordering::SeqCst),
                self.counts.writes.load(Ordering::SeqCst),
            )
        }
    }

    fn seed_github_recovery_action(
        host: &mut PlatformV2Host,
        key: &str,
    ) -> (
        StoredReviewAction,
        ReviewExternalEffectPlan,
        ReviewReceiptCorrelationDigest,
    ) {
        let PlatformV2Host::Enabled(runtime) = host else {
            panic!("enabled host required")
        };
        let workspace =
            WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("wc_user_1").unwrap());
        let authority = ReviewAuthority::new(
            ReviewAuthorityKind::Ci,
            ReviewAuthorityId::new("authority-1").unwrap(),
        );
        let action = ReviewAction::RerunCheck {
            check_id: ReviewCheckId::new("check-1").unwrap(),
            expected_check_revision: Revision::new(7).unwrap(),
        };
        let request = ReviewActionRequest::new(
            workspace.clone(),
            Revision::new(9).unwrap(),
            ReviewActorId::new("actor-test").unwrap(),
            ReviewAuthentication::UserSession,
            authority.clone(),
            IdempotencyKey::new(key).unwrap(),
            action.clone(),
        )
        .unwrap();
        let effect = runtime
            .review_effects
            .plan(
                &ProjectId::new("project-test").unwrap(),
                &workspace,
                &authority,
                &action,
            )
            .unwrap();
        let ReviewEffectPlan::GitHubCheckRerun {
            credential_reference,
            repository,
            run_id,
            head_sha,
            observed_attempt,
            expected_check_revision,
            registry_generation,
            credential_generation,
        } = effect
        else {
            panic!("GitHub effect plan required")
        };
        let request_digest =
            ReviewStore::action_request_digest(&request, ApprovalPolicy::Required).unwrap();
        let correlation = [9; 32];
        let plan = ReviewExternalEffectPlan::github_check_rerun(
            request_digest,
            registry_generation,
            credential_generation,
            &credential_reference,
            repository.owner().as_str(),
            repository.repo().as_str(),
            run_id.get(),
            &head_sha,
            observed_attempt,
            ReviewCheckId::new("check-1").unwrap(),
            expected_check_revision,
            Revision::FIRST,
            correlation,
        )
        .unwrap();
        let stored = match runtime
            .reviews
            .prepare_external_action(&request, ApprovalPolicy::Required, &plan, 10)
            .unwrap()
        {
            ReviewActionAdmission::New(action) => action,
            ReviewActionAdmission::Replay(_) => panic!("new action required"),
        };
        (
            stored,
            plan,
            review_receipt_correlation_digest(correlation).unwrap(),
        )
    }

    fn approve_and_start_github_action(
        host: &mut PlatformV2Host,
        action: &StoredReviewAction,
        plan: &ReviewExternalEffectPlan,
    ) -> StoredReviewAction {
        let PlatformV2Host::Enabled(runtime) = host else {
            panic!("enabled host required")
        };
        let principal = runtime
            .principals
            .get(&nix::unistd::geteuid().as_raw())
            .unwrap()
            .clone();
        let approved = runtime
            .approve_prepared_github_confirmation(&principal, action, plan, 11)
            .unwrap();
        match runtime
            .reviews
            .start_write(&approved.preview_id, approved.request_digest, 12)
            .unwrap()
        {
            ReviewWriteAdmission::New(action) | ReviewWriteAdmission::Replay(action) => action,
        }
    }

    fn correlated_lookup(
        key: &str,
        correlation: ReviewReceiptCorrelationDigest,
    ) -> PlatformV2Request {
        PlatformV2Request::GetReviewReceipt(
            ReviewReceiptLookup::new_correlated(
                ProjectId::new("project-test").unwrap(),
                WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("wc_user_1").unwrap()),
                IdempotencyKey::new(key).unwrap(),
                correlation,
            )
            .unwrap(),
        )
    }

    fn seed_runtime_attention_contexts(
        path: &Path,
        tenant: &str,
        session_lifecycle: WorkContextLifecycle,
    ) {
        let mut store = WorkContextStore::open(path).unwrap();
        let project = WorkContextIdentity::Project(ProjectId::new("project-runtime").unwrap());
        let repository = WorkContextIdentity::Repository(
            V1RepositoryRef::new(ResourceCoordinate::new(
                ResourceAuthority::GitHub,
                ResourceKind::Repository,
                ResourceId::new("repository-runtime").unwrap(),
            ))
            .unwrap(),
        );
        store
            .put_external_snapshot(
                tenant,
                &ExpectedWorkContext::new(repository.clone(), Revision::FIRST),
                ExternalParentResolution::Available,
                Some(&ProjectId::new("project-runtime").unwrap()),
            )
            .unwrap();
        let project_record = WorkContextRecord::new(
            project.clone(),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Runtime project").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(WorkContextRelationKind::ProjectRepository, repository)
                    .unwrap(),
            ],
        )
        .unwrap();
        let host = WorkContextRecord::new(
            WorkContextIdentity::parse_local(WorkContextTargetKind::HostSetup, "host-runtime")
                .unwrap(),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Runtime host").unwrap(),
            WorkContextAttributes::host_setup(HostSetupKind::Local),
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::HostSetupProject,
                    project.clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let checkout = WorkContextRecord::new(
            WorkContextIdentity::parse_local(WorkContextTargetKind::Checkout, "checkout-runtime")
                .unwrap(),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Runtime checkout").unwrap(),
            WorkContextAttributes::checkout(CheckoutKind::GitWorktree),
            vec![
                WorkContextRelation::new(WorkContextRelationKind::CheckoutProject, project.clone())
                    .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::CheckoutHostSetup,
                    host.identity().clone(),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::CheckoutRepository,
                    project_record.relations()[0].target().clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let workspace = WorkContextRecord::new(
            WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-runtime").unwrap()),
            Revision::FIRST,
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Runtime workspace").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceProject,
                    project.clone(),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::UserWorkspaceCheckout,
                    checkout.identity().clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let attempt = WorkContextRecord::new(
            WorkContextIdentity::AttemptWorkspace(
                AttemptWorkspaceId::new("attempt-runtime").unwrap(),
            ),
            Revision::FIRST,
            WorkContextLifecycle::Running,
            WorkContextLabel::new("Runtime attempt").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::AttemptUserWorkspace,
                    workspace.identity().clone(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let session = WorkContextRecord::new(
            WorkContextIdentity::Session(WorkSessionId::new("work-session-runtime").unwrap()),
            Revision::FIRST,
            session_lifecycle,
            WorkContextLabel::new("Runtime session").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::SessionAttemptWorkspace,
                    attempt.identity().clone(),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::SessionPlatformSession,
                    WorkContextIdentity::PlatformSession(
                        V1SessionRef::new(ResourceCoordinate::new(
                            ResourceAuthority::Automonique,
                            ResourceKind::Session,
                            ResourceId::new("provider-session-runtime").unwrap(),
                        ))
                        .unwrap(),
                    ),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        for record in [
            &project_record,
            &host,
            &checkout,
            &workspace,
            &attempt,
            &session,
        ] {
            store.put_authoritative_record(tenant, record).unwrap();
        }
    }

    fn write_runtime_attention_policy(path: &Path, uid: u32) {
        let authority = serde_json::json!({
            "filesystem": [], "credentials": [], "network": [],
            "tools": [], "providers": [], "models": []
        });
        write_generation_policy(
            path,
            &serde_json::json!({
                "version": 1,
                "principals": [{
                    "uid": uid,
                    "tenant": "tenant-runtime",
                    "actor": "actor-runtime",
                    "serving_authority": "automonique",
                    "projects": ["project-runtime"],
                    "workspaces": [
                        {"project": "project-runtime", "kind": "project", "id": "project-runtime", "inherited_authority": authority},
                        {"project": "project-runtime", "kind": "host_setup", "id": "host-runtime", "inherited_authority": authority},
                        {"project": "project-runtime", "kind": "checkout", "id": "checkout-runtime", "inherited_authority": authority},
                        {"project": "project-runtime", "kind": "user_workspace", "id": "workspace-runtime", "inherited_authority": authority},
                        {"project": "project-runtime", "kind": "attempt_workspace", "id": "attempt-runtime", "inherited_authority": authority},
                        {"project": "project-runtime", "kind": "session", "id": "work-session-runtime", "inherited_authority": authority}
                    ],
                    "authority": authority,
                    "review_authorities": {}
                }]
            }),
        );
    }

    #[test]
    fn runtime_attention_producers_preserve_authoritative_identities_and_coordinates() {
        use automonique_protocol::platform_v2_lineage::{
            LineageFreshness, LineageFreshnessState, OrchestrationIdentity, OrchestrationWorkerId,
        };
        use automonique_protocol::platform_v2_review_api::decode_review_snapshot;

        let review = decode_review_snapshot(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-review-v2.json"
        ))
        .unwrap();
        let review_items = review_attention_items(&review, 1_800_000_000_001).unwrap();
        assert_eq!(review_items.len(), review.attention_events().len());
        assert!(
            review_items
                .iter()
                .all(|item| item.platform_session().is_none())
        );
        assert_eq!(
            review_items[0].id().as_str(),
            review.attention_events()[0].id().as_str()
        );
        assert!(
            review_items
                .iter()
                .zip(review.attention_events())
                .all(|(item, event)| item.unread() == (event.unread() > 0)),
            "review unread remains the exact durable event count projection"
        );

        let orchestration = OrchestrationRecord::new_with_origin(
            OrchestrationIdentity::Worker(OrchestrationWorkerId::new("worker-1").unwrap()),
            automonique_protocol::platform_v2_lineage::LineageOrigin::workspace_only(
                UserWorkspaceId::new("workspace-1").unwrap(),
            ),
            None,
            Some(
                automonique_protocol::platform_v2_lineage::OrchestrationIdentity::Dispatch(
                    automonique_protocol::platform_v2_lineage::OrchestrationDispatchId::new(
                        "dispatch-1",
                    )
                    .unwrap(),
                ),
            ),
            LineageStatus::Working,
            LineageFreshness::new(1_700, 60_000, LineageFreshnessState::Fresh).unwrap(),
            None,
            Revision::new(9).unwrap(),
        )
        .unwrap();
        let orchestration_items = orchestration_attention_items(&[orchestration], None).unwrap();
        assert!(orchestration_items[0].id().as_str().ends_with("-i9"));
        assert_eq!(
            orchestration_items[0].reason(),
            AttentionItemReason::AgentWorking
        );
        assert!(!orchestration_items[0].unread());
        assert!(orchestration_items[0].nested_agent_path().is_empty());

        let platform_session = V1SessionRef::new(ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Session,
            ResourceId::new("provider-session-1").unwrap(),
        ))
        .unwrap();
        let session = WorkContextRecord::new(
            WorkContextIdentity::Session(WorkSessionId::new("work-session-1").unwrap()),
            Revision::new(4).unwrap(),
            WorkContextLifecycle::Active,
            WorkContextLabel::new("Retained session").unwrap(),
            WorkContextAttributes::EMPTY,
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::SessionAttemptWorkspace,
                    WorkContextIdentity::AttemptWorkspace(
                        AttemptWorkspaceId::new("attempt-1").unwrap(),
                    ),
                )
                .unwrap(),
                WorkContextRelation::new(
                    WorkContextRelationKind::SessionPlatformSession,
                    WorkContextIdentity::PlatformSession(platform_session.clone()),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let session_items =
            retained_session_attention_items(&session, platform_session.clone(), 2_000, None)
                .unwrap();
        assert_eq!(session_items[0].platform_session(), Some(&platform_session));
        assert_eq!(session_items[0].reason(), AttentionItemReason::AgentWorking);
        assert!(!session_items[0].unread());
        assert!(session_items[0].id().as_str().ends_with("-i4"));
        assert_eq!(
            review_attention_items_from_snapshot(None, 2_001),
            Err("platform_v2_attention_not_found"),
            "an absent durable producer must not become an empty source"
        );
        let review_source = AttentionSource::new(
            AttentionSourceKind::Review,
            AttentionSourceId::new("workspace-1").unwrap(),
        );
        assert!(workspace_source_matches(
            &review_source,
            &UserWorkspaceId::new("workspace-1").unwrap()
        ));
        assert!(!workspace_source_matches(
            &review_source,
            &UserWorkspaceId::new("workspace-2").unwrap()
        ));
    }

    #[test]
    fn runtime_attention_unread_policy_is_exhaustive() {
        use automonique_protocol::platform_v2_lineage::{
            LineageFreshness, LineageFreshnessState, LineageMessage, LineageOrigin,
            OrchestrationIdentity, OrchestrationRunId,
        };

        let orchestration_record = |status| {
            OrchestrationRecord::new_with_origin(
                OrchestrationIdentity::Run(OrchestrationRunId::new("run-unread").unwrap()),
                LineageOrigin::workspace_only(UserWorkspaceId::new("workspace-unread").unwrap()),
                None,
                None,
                status,
                LineageFreshness::new(1_000, 60_000, LineageFreshnessState::Fresh).unwrap(),
                None,
                Revision::FIRST,
            )
            .unwrap()
        };
        for (status, expected) in [
            (
                LineageStatus::Working,
                Some((AttentionItemReason::AgentWorking, false)),
            ),
            (
                LineageStatus::Blocked(LineageMessage::new("blocked").unwrap()),
                Some((AttentionItemReason::ExternalBlocker, true)),
            ),
            (
                LineageStatus::Done(LineageMessage::new("done").unwrap()),
                Some((AttentionItemReason::Complete, true)),
            ),
            (
                LineageStatus::Waiting(LineageMessage::new("waiting").unwrap()),
                None,
            ),
        ] {
            let items =
                orchestration_attention_items(&[orchestration_record(status)], None).unwrap();
            match expected {
                Some((reason, unread)) => {
                    assert_eq!(items.len(), 1);
                    assert_eq!(items[0].reason(), reason);
                    assert_eq!(items[0].state(), reason.state());
                    assert_eq!(items[0].unread(), unread);
                }
                None => assert!(items.is_empty()),
            }
        }

        let platform_session = V1SessionRef::new(ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Session,
            ResourceId::new("provider-session-unread").unwrap(),
        ))
        .unwrap();
        let session_record = |lifecycle| {
            WorkContextRecord::new(
                WorkContextIdentity::Session(WorkSessionId::new("work-session-unread").unwrap()),
                Revision::FIRST,
                lifecycle,
                WorkContextLabel::new("Retained session").unwrap(),
                WorkContextAttributes::EMPTY,
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::SessionAttemptWorkspace,
                        WorkContextIdentity::AttemptWorkspace(
                            AttemptWorkspaceId::new("attempt-unread").unwrap(),
                        ),
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::SessionPlatformSession,
                        WorkContextIdentity::PlatformSession(platform_session.clone()),
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
        };
        let lifecycle_policy = [
            (
                WorkContextLifecycle::Active,
                Some((AttentionItemReason::AgentWorking, false)),
            ),
            (
                WorkContextLifecycle::Preparing,
                Some((AttentionItemReason::AgentWorking, false)),
            ),
            (
                WorkContextLifecycle::Running,
                Some((AttentionItemReason::AgentWorking, false)),
            ),
            (
                WorkContextLifecycle::Failed,
                Some((AttentionItemReason::ExternalBlocker, true)),
            ),
            (
                WorkContextLifecycle::Completed,
                Some((AttentionItemReason::Complete, true)),
            ),
            (
                WorkContextLifecycle::Archived,
                Some((AttentionItemReason::Complete, false)),
            ),
            (
                WorkContextLifecycle::Cancelled,
                Some((AttentionItemReason::Complete, false)),
            ),
            (
                WorkContextLifecycle::Closed,
                Some((AttentionItemReason::Complete, false)),
            ),
            (WorkContextLifecycle::Hibernated, None),
        ];
        for (lifecycle, expected) in lifecycle_policy {
            assert_eq!(retained_session_attention_projection(lifecycle), expected);
        }
        for lifecycle in [
            WorkContextLifecycle::Active,
            WorkContextLifecycle::Failed,
            WorkContextLifecycle::Completed,
            WorkContextLifecycle::Cancelled,
            WorkContextLifecycle::Hibernated,
        ] {
            let expected = retained_session_attention_projection(lifecycle);
            let items = retained_session_attention_items(
                &session_record(lifecycle),
                platform_session.clone(),
                1_000,
                None,
            )
            .unwrap();
            match expected {
                Some((reason, unread)) => {
                    assert_eq!(items.len(), 1);
                    assert_eq!(items[0].reason(), reason);
                    assert_eq!(items[0].state(), reason.state());
                    assert_eq!(items[0].unread(), unread);
                }
                None => assert!(items.is_empty()),
            }
        }
    }

    #[test]
    fn terminal_provider_session_attention_uses_read_lineage_without_control_authority() {
        for (lifecycle, reason, unread) in [
            (
                WorkContextLifecycle::Completed,
                AttentionItemReason::Complete,
                true,
            ),
            (
                WorkContextLifecycle::Failed,
                AttentionItemReason::ExternalBlocker,
                true,
            ),
            (
                WorkContextLifecycle::Cancelled,
                AttentionItemReason::Complete,
                false,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let policy_path = directory.path().join("policy.json");
            let contexts_path = directory.path().join("work-context.sqlite3");
            let uid = nix::unistd::geteuid().as_raw();
            seed_runtime_attention_contexts(&contexts_path, "tenant-runtime", lifecycle);
            write_runtime_attention_policy(&policy_path, uid);
            let mut host = PlatformV2Host::open_with_lifecycle_adapter(
                &policy_path,
                &contexts_path,
                &directory.path().join("lineage.sqlite3"),
                &directory.path().join("review.sqlite3"),
                uid,
                Box::new(UnavailableLifecycleEffectAdapter),
            );
            let response = host.handle(
                uid,
                &PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
                    AttentionSource::new(
                        AttentionSourceKind::ProviderSession,
                        AttentionSourceId::new("work-session-runtime").unwrap(),
                    ),
                    ProjectId::new("project-runtime").unwrap(),
                    UserWorkspaceId::new("workspace-runtime").unwrap(),
                )),
                2_000,
            );
            let PlatformV2Response::AttentionSourceSnapshot(snapshot) = response else {
                panic!("terminal provider attention refused for {lifecycle:?}: {response:?}")
            };
            assert_eq!(snapshot.items().len(), 1);
            assert_eq!(snapshot.items()[0].reason(), reason);
            assert_eq!(snapshot.items()[0].unread(), unread);
            assert_eq!(
                snapshot.items()[0]
                    .platform_session()
                    .unwrap()
                    .coordinate()
                    .id
                    .as_str(),
                "provider-session-runtime"
            );
        }
    }

    #[test]
    fn provider_runtime_tuple_collision_refuses_before_import_on_every_restart() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let policy_path = directory.path().join("policy.json");
        let contexts_path = directory.path().join("work-context.sqlite3");
        let uid = nix::unistd::geteuid().as_raw();
        seed_runtime_attention_contexts(
            &contexts_path,
            "tenant-runtime",
            WorkContextLifecycle::Active,
        );
        write_runtime_attention_policy(&policy_path, uid);

        let mut raw: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../automonique-protocol/fixtures/platform-v2-attention-v1.json"
        ))
        .unwrap();
        raw["source"]["id"] = serde_json::json!("work-session-runtime");
        raw["project"] = serde_json::json!("project-runtime");
        raw["user_workspace"] = serde_json::json!("workspace-runtime");
        let registry_path = directory.path().join(ATTENTION_REGISTRY_NAME);
        fs::write(
            &registry_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "generation": "runtime-collision",
                "snapshots": [raw]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&registry_path, fs::Permissions::from_mode(0o600)).unwrap();

        for _restart in 0..2 {
            let host = PlatformV2Host::open_with_lifecycle_adapter(
                &policy_path,
                &contexts_path,
                &directory.path().join("lineage.sqlite3"),
                &directory.path().join("review.sqlite3"),
                uid,
                Box::new(UnavailableLifecycleEffectAdapter),
            );
            assert!(matches!(
                host,
                PlatformV2Host::Disabled("platform_v2_attention_registry_runtime_collision")
            ));
            let attention = AttentionStore::open_scoped(
                directory.path().join(ATTENTION_STORE_NAME),
                "tenant-runtime",
            )
            .unwrap();
            assert!(
                attention
                    .snapshot(
                        &AttentionSource::new(
                            AttentionSourceKind::ProviderSession,
                            AttentionSourceId::new("work-session-runtime").unwrap(),
                        ),
                        &ProjectId::new("project-runtime").unwrap(),
                        &UserWorkspaceId::new("workspace-runtime").unwrap(),
                    )
                    .unwrap()
                    .is_none(),
                "a rejected registry must not import or shadow runtime custody"
            );
        }
    }

    #[test]
    fn runtime_attention_replacement_is_idempotent_monotone_and_lifetime_safe() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = AttentionStore::open_scoped(
            directory.path().join("runtime-attention.sqlite3"),
            "tenant-test",
        )
        .unwrap();
        let source = AttentionSource::new(
            AttentionSourceKind::Review,
            AttentionSourceId::new("workspace-1").unwrap(),
        );
        let project = ProjectId::new("project-1").unwrap();
        let workspace = UserWorkspaceId::new("workspace-1").unwrap();
        let request = AttentionReadRequest::new(source.clone(), project.clone(), workspace.clone());
        let item = |unread, observed_at_ms| {
            AttentionItem::new(
                AttentionItemId::new("review-item-1").unwrap(),
                Revision::FIRST,
                observed_at_ms,
                AttentionItemReason::ReviewRequested.state(),
                AttentionItemReason::ReviewRequested,
                unread,
                Vec::new(),
                None,
            )
            .unwrap()
        };

        let first =
            persist_runtime_attention_snapshot(&mut store, &request, vec![item(true, 10)], 10)
                .unwrap();
        let replay =
            persist_runtime_attention_snapshot(&mut store, &request, vec![item(true, 20)], 20)
                .unwrap();
        assert_eq!(
            replay, first,
            "read-time observation cannot churn a stable source"
        );
        let changed =
            persist_runtime_attention_snapshot(&mut store, &request, vec![item(false, 30)], 30)
                .unwrap();
        assert_eq!(changed.revision(), Revision::new(2).unwrap());
        assert_eq!(changed.previous_revision(), Some(Revision::FIRST));
        assert_eq!(changed.items()[0].revision(), Revision::new(2).unwrap());
        let removed =
            persist_runtime_attention_snapshot(&mut store, &request, Vec::new(), 40).unwrap();
        assert_eq!(removed.previous_revision(), Some(Revision::new(2).unwrap()));
        assert_eq!(
            persist_runtime_attention_snapshot(&mut store, &request, vec![item(false, 50)], 50),
            Err("platform_v2_attention_store_refused"),
            "a removed source-lifetime item id cannot be reused"
        );
        assert!(
            store
                .snapshot(&source, &ProjectId::new("project-2").unwrap(), &workspace,)
                .unwrap()
                .is_none(),
            "cross-project reads do not inherit a source tuple"
        );
        assert!(
            store
                .snapshot(
                    &source,
                    &project,
                    &UserWorkspaceId::new("workspace-2").unwrap(),
                )
                .unwrap()
                .is_none(),
            "cross-workspace reads do not inherit a source tuple"
        );
    }

    fn uncorrelated_lookup(key: &str) -> PlatformV2Request {
        PlatformV2Request::GetReviewReceipt(
            ReviewReceiptLookup::new(
                ProjectId::new("project-test").unwrap(),
                WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("wc_user_1").unwrap()),
                IdempotencyKey::new(key).unwrap(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn github_recovery_phase_gates_only_never_started_custody() {
        assert_eq!(
            github_recovery_phase(
                ReviewReceiptOutcome::Accepted,
                false,
                ReviewExternalEffectCustody::NotStarted,
            ),
            Ok(GitHubRecoveryPhase::NeverStarted)
        );
        for (outcome, custody) in [
            (
                ReviewReceiptOutcome::Accepted,
                ReviewExternalEffectCustody::CustodyStarted,
            ),
            (
                ReviewReceiptOutcome::Accepted,
                ReviewExternalEffectCustody::Accepted,
            ),
            (
                ReviewReceiptOutcome::Unknown,
                ReviewExternalEffectCustody::Ambiguous,
            ),
        ] {
            assert_eq!(
                github_recovery_phase(outcome, true, custody),
                Ok(GitHubRecoveryPhase::ReconcileOnly)
            );
        }
        for (outcome, admitted, custody) in [
            (
                ReviewReceiptOutcome::Refused,
                false,
                ReviewExternalEffectCustody::Refused,
            ),
            (
                ReviewReceiptOutcome::Completed,
                true,
                ReviewExternalEffectCustody::Completed,
            ),
            (
                ReviewReceiptOutcome::Conflict,
                true,
                ReviewExternalEffectCustody::Completed,
            ),
        ] {
            assert_eq!(
                github_recovery_phase(outcome, admitted, custody),
                Ok(GitHubRecoveryPhase::Terminal)
            );
        }
        assert!(
            github_recovery_phase(
                ReviewReceiptOutcome::Accepted,
                false,
                ReviewExternalEffectCustody::Accepted,
            )
            .is_err()
        );
        assert!(
            github_recovery_phase(
                ReviewReceiptOutcome::Unknown,
                false,
                ReviewExternalEffectCustody::Ambiguous,
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_attention_replay_at_max_revision_does_not_require_a_successor() {
        let source = AttentionSource::new(
            AttentionSourceKind::Review,
            AttentionSourceId::new("workspace-1").unwrap(),
        );
        let project = ProjectId::new("project-1").unwrap();
        let workspace = UserWorkspaceId::new("workspace-1").unwrap();
        let request = AttentionReadRequest::new(source.clone(), project.clone(), workspace.clone());
        let maximum = Revision::new(u64::MAX).unwrap();
        let current_item = AttentionItem::new(
            AttentionItemId::new("review-item-1").unwrap(),
            maximum,
            10,
            AttentionItemReason::ReviewRequested.state(),
            AttentionItemReason::ReviewRequested,
            true,
            Vec::new(),
            None,
        )
        .unwrap();
        let current = AttentionSourceSnapshot::new(
            source,
            project,
            workspace,
            maximum,
            Some(Revision::new(u64::MAX - 1).unwrap()),
            10,
            vec![current_item],
        )
        .unwrap();
        let desired = |unread| {
            AttentionItem::new(
                AttentionItemId::new("review-item-1").unwrap(),
                Revision::FIRST,
                20,
                AttentionItemReason::ReviewRequested.state(),
                AttentionItemReason::ReviewRequested,
                unread,
                Vec::new(),
                None,
            )
            .unwrap()
        };

        assert_eq!(
            prepare_runtime_attention_snapshot(&request, vec![desired(true)], 20, Some(&current)),
            Ok(current.clone()),
            "an exact replay remains the exact durable document at Revision::MAX"
        );
        assert_eq!(
            prepare_runtime_attention_snapshot(&request, vec![desired(false)], 20, Some(&current),),
            Err("platform_v2_attention_revision_exhausted"),
            "a real change must still fail closed when no successor exists"
        );
    }

    #[test]
    fn runtime_attention_logical_items_survive_churn_but_not_an_absent_interval() {
        use automonique_protocol::platform_v2_lineage::{
            LineageFreshness, LineageFreshnessState, LineageMessage, LineageOrigin,
            OrchestrationIdentity, OrchestrationRunId,
        };

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let orchestration_store_path = directory.path().join("orchestration-attention.sqlite3");
        let mut store =
            AttentionStore::open_scoped(&orchestration_store_path, "tenant-test").unwrap();
        let request = AttentionReadRequest::new(
            AttentionSource::new(
                AttentionSourceKind::Orchestration,
                AttentionSourceId::new("workspace-1").unwrap(),
            ),
            ProjectId::new("project-1").unwrap(),
            UserWorkspaceId::new("workspace-1").unwrap(),
        );
        let record = |status, revision, observed_at_ms| {
            OrchestrationRecord::new_with_origin(
                OrchestrationIdentity::Run(OrchestrationRunId::new("run-1").unwrap()),
                LineageOrigin::workspace_only(UserWorkspaceId::new("workspace-1").unwrap()),
                None,
                None,
                status,
                LineageFreshness::new(observed_at_ms, 60_000, LineageFreshnessState::Fresh)
                    .unwrap(),
                None,
                Revision::new(revision).unwrap(),
            )
            .unwrap()
        };

        let first_items =
            orchestration_attention_items(&[record(LineageStatus::Working, 7, 700)], None).unwrap();
        let first =
            persist_runtime_attention_snapshot(&mut store, &request, first_items, 700).unwrap();
        let original_id = first.items()[0].id().clone();
        assert!(!first.items()[0].unread());
        let unchanged_items =
            orchestration_attention_items(&[record(LineageStatus::Working, 8, 800)], Some(&first))
                .unwrap();
        let unchanged =
            persist_runtime_attention_snapshot(&mut store, &request, unchanged_items, 800).unwrap();
        assert_eq!(
            unchanged, first,
            "unrelated record revision churn is replay"
        );

        let changed_items = orchestration_attention_items(
            &[record(
                LineageStatus::Blocked(LineageMessage::new("dependency").unwrap()),
                9,
                900,
            )],
            Some(&unchanged),
        )
        .unwrap();
        let changed =
            persist_runtime_attention_snapshot(&mut store, &request, changed_items, 900).unwrap();
        assert_eq!(changed.items()[0].id(), &original_id);
        assert_eq!(changed.items()[0].revision(), Revision::new(2).unwrap());
        assert_eq!(
            changed.items()[0].reason(),
            AttentionItemReason::ExternalBlocker
        );
        assert!(changed.items()[0].unread());

        let done_items = orchestration_attention_items(
            &[record(
                LineageStatus::Done(LineageMessage::new("complete").unwrap()),
                10,
                1_000,
            )],
            Some(&changed),
        )
        .unwrap();
        let done =
            persist_runtime_attention_snapshot(&mut store, &request, done_items, 1_000).unwrap();
        assert_eq!(done.items()[0].id(), &original_id);
        assert_eq!(done.items()[0].revision(), Revision::new(3).unwrap());
        assert_eq!(done.items()[0].reason(), AttentionItemReason::Complete);
        assert!(done.items()[0].unread());

        let absent_items = orchestration_attention_items(
            &[record(
                LineageStatus::Waiting(LineageMessage::new("idle").unwrap()),
                11,
                1_100,
            )],
            Some(&done),
        )
        .unwrap();
        let absent =
            persist_runtime_attention_snapshot(&mut store, &request, absent_items, 1_100).unwrap();
        assert!(absent.items().is_empty());
        drop(store);
        let mut store =
            AttentionStore::open_scoped(&orchestration_store_path, "tenant-test").unwrap();
        let reappeared_items = orchestration_attention_items(
            &[record(LineageStatus::Working, 12, 1_200)],
            Some(&absent),
        )
        .unwrap();
        let reappeared =
            persist_runtime_attention_snapshot(&mut store, &request, reappeared_items, 1_200)
                .unwrap();
        assert_ne!(reappeared.items()[0].id(), &original_id);
        assert!(!reappeared.items()[0].unread());

        let session_store_path = directory.path().join("session-attention.sqlite3");
        let mut session_store =
            AttentionStore::open_scoped(&session_store_path, "tenant-test").unwrap();
        let session_request = AttentionReadRequest::new(
            AttentionSource::new(
                AttentionSourceKind::ProviderSession,
                AttentionSourceId::new("work-session-1").unwrap(),
            ),
            ProjectId::new("project-1").unwrap(),
            UserWorkspaceId::new("workspace-1").unwrap(),
        );
        let platform_session = V1SessionRef::new(ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Session,
            ResourceId::new("provider-session-1").unwrap(),
        ))
        .unwrap();
        let session = |lifecycle, revision| {
            WorkContextRecord::new(
                WorkContextIdentity::Session(WorkSessionId::new("work-session-1").unwrap()),
                Revision::new(revision).unwrap(),
                lifecycle,
                WorkContextLabel::new("Retained session").unwrap(),
                WorkContextAttributes::EMPTY,
                vec![
                    WorkContextRelation::new(
                        WorkContextRelationKind::SessionAttemptWorkspace,
                        WorkContextIdentity::AttemptWorkspace(
                            AttemptWorkspaceId::new("attempt-1").unwrap(),
                        ),
                    )
                    .unwrap(),
                    WorkContextRelation::new(
                        WorkContextRelationKind::SessionPlatformSession,
                        WorkContextIdentity::PlatformSession(platform_session.clone()),
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
        };
        let first_items = retained_session_attention_items(
            &session(WorkContextLifecycle::Active, 3),
            platform_session.clone(),
            300,
            None,
        )
        .unwrap();
        let first = persist_runtime_attention_snapshot(
            &mut session_store,
            &session_request,
            first_items,
            300,
        )
        .unwrap();
        let original_id = first.items()[0].id().clone();
        assert!(!first.items()[0].unread());
        let unchanged_items = retained_session_attention_items(
            &session(WorkContextLifecycle::Active, 4),
            platform_session.clone(),
            400,
            Some(&first),
        )
        .unwrap();
        let unchanged = persist_runtime_attention_snapshot(
            &mut session_store,
            &session_request,
            unchanged_items,
            400,
        )
        .unwrap();
        assert_eq!(unchanged, first);
        let changed_items = retained_session_attention_items(
            &session(WorkContextLifecycle::Completed, 5),
            platform_session.clone(),
            500,
            Some(&unchanged),
        )
        .unwrap();
        let changed = persist_runtime_attention_snapshot(
            &mut session_store,
            &session_request,
            changed_items,
            500,
        )
        .unwrap();
        assert_eq!(changed.items()[0].id(), &original_id);
        assert_eq!(changed.items()[0].reason(), AttentionItemReason::Complete);
        assert!(changed.items()[0].unread());
        let absent_items = retained_session_attention_items(
            &session(WorkContextLifecycle::Hibernated, 6),
            platform_session.clone(),
            600,
            Some(&changed),
        )
        .unwrap();
        let absent = persist_runtime_attention_snapshot(
            &mut session_store,
            &session_request,
            absent_items,
            600,
        )
        .unwrap();
        assert!(absent.items().is_empty());
        drop(session_store);
        let mut session_store =
            AttentionStore::open_scoped(&session_store_path, "tenant-test").unwrap();
        let reappeared_items = retained_session_attention_items(
            &session(WorkContextLifecycle::Active, 7),
            platform_session,
            700,
            Some(&absent),
        )
        .unwrap();
        let reappeared = persist_runtime_attention_snapshot(
            &mut session_store,
            &session_request,
            reappeared_items,
            700,
        )
        .unwrap();
        assert_ne!(reappeared.items()[0].id(), &original_id);
        assert!(!reappeared.items()[0].unread());
    }

    #[test]
    fn github_lookup_requires_the_exact_nonlegacy_correlation() {
        let exact = review_receipt_correlation_digest([7; 32]).unwrap();
        let wrong = review_receipt_correlation_digest([8; 32]).unwrap();
        assert!(github_receipt_correlation_matches(Some([7; 32]), Some(&exact)).unwrap());
        assert!(!github_receipt_correlation_matches(Some([7; 32]), None).unwrap());
        assert!(!github_receipt_correlation_matches(None, Some(&exact)).unwrap());
        assert!(!github_receipt_correlation_matches(None, None).unwrap());
        assert!(!github_receipt_correlation_matches(Some([7; 32]), Some(&wrong)).unwrap());
    }

    #[test]
    fn github_uncorrelated_lookup_never_reads_the_generic_receipt_index() {
        let fixture = GitHubRecoveryFixture::new();
        let mut host = fixture.open();
        seed_github_recovery_action(&mut host, "github-uncorrelated");
        drop(host);

        let mut restarted = fixture.open();
        fixture.reset_counts();
        let response =
            restarted.handle(fixture.uid, &uncorrelated_lookup("github-uncorrelated"), 20);
        assert!(
            matches!(
                response,
                PlatformV2Response::Refused(ref refusal)
                    if refusal.category().as_str() == "platform_v2_not_found"
            ),
            "unexpected uncorrelated response: {response:?}"
        );
        assert_eq!(fixture.calls(), (0, 0));
    }

    #[test]
    fn github_missing_or_legacy_plan_never_falls_back_to_an_uncorrelated_receipt() {
        let missing = GitHubRecoveryFixture::new();
        let mut host = missing.open();
        seed_github_recovery_action(&mut host, "github-missing-plan");
        drop(host);
        let connection = rusqlite::Connection::open(&missing.review_path).unwrap();
        connection
            .execute(
                "DELETE FROM review_github_check_effect_plans
                 WHERE preview_id=(SELECT preview_id FROM review_action_previews
                                   WHERE idempotency_key='github-missing-plan')",
                [],
            )
            .unwrap();
        drop(connection);
        let mut restarted = missing.open();
        missing.reset_counts();
        let response =
            restarted.handle(missing.uid, &uncorrelated_lookup("github-missing-plan"), 20);
        assert!(
            matches!(
                response,
                PlatformV2Response::Refused(ref refusal)
                    if refusal.category().as_str() == "platform_v2_not_found"
            ),
            "unexpected missing-plan response: {response:?}"
        );
        assert_eq!(missing.calls(), (0, 0));

        let legacy = GitHubRecoveryFixture::new();
        let mut host = legacy.open();
        seed_github_recovery_action(&mut host, "github-legacy-plan");
        drop(host);
        let connection = rusqlite::Connection::open(&legacy.review_path).unwrap();
        let document: Vec<u8> = connection
            .query_row(
                "SELECT plan_document FROM review_github_check_effect_plans
                 WHERE preview_id=(SELECT preview_id FROM review_action_previews
                                   WHERE idempotency_key='github-legacy-plan')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&document).unwrap();
        assert!(
            document
                .as_object_mut()
                .unwrap()
                .remove("expected_workspace_revision")
                .is_some()
        );
        let document = crate::agent_harness::canonical_json_bytes(&document);
        let digest = Sha256::digest(&document);
        connection
            .execute(
                "UPDATE review_github_check_effect_plans
                 SET plan_document=?1,plan_digest=?2,expected_workspace_revision=NULL
                 WHERE preview_id=(SELECT preview_id FROM review_action_previews
                                   WHERE idempotency_key='github-legacy-plan')",
                params![document, digest.as_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);
        let mut restarted = legacy.open();
        legacy.reset_counts();
        let response = restarted.handle(legacy.uid, &uncorrelated_lookup("github-legacy-plan"), 20);
        assert!(
            matches!(
                response,
                PlatformV2Response::Refused(ref refusal)
                    if refusal.category().as_str() == "platform_v2_not_found"
            ),
            "unexpected legacy-v5 response: {response:?}"
        );
        assert_eq!(legacy.calls(), (0, 0));
    }

    #[test]
    fn github_never_started_recovery_after_restart_and_workspace_advance_makes_zero_provider_calls()
    {
        let fixture = GitHubRecoveryFixture::new();
        let mut host = fixture.open();
        let (_, _, correlation) = seed_github_recovery_action(&mut host, "github-never-started");
        drop(host);
        fixture.advance_workspace();

        let mut restarted = fixture.open();
        fixture.reset_counts();
        let response = restarted.handle(
            fixture.uid,
            &correlated_lookup("github-never-started", correlation),
            20,
        );
        assert!(matches!(
            response,
            PlatformV2Response::Refused(refusal)
                if refusal.category().as_str() == "platform_v2_review_workspace_changed"
        ));
        assert_eq!(fixture.calls(), (0, 0));
    }

    #[test]
    fn github_legacy_v5_partial_recovery_identity_is_not_found_without_provider_calls() {
        let fixture = GitHubRecoveryFixture::new();
        let mut host = fixture.open();
        let (_, _, correlation) = seed_github_recovery_action(&mut host, "github-legacy-v5");
        drop(host);

        let connection = rusqlite::Connection::open(&fixture.review_path).unwrap();
        let document: Vec<u8> = connection
            .query_row(
                "SELECT plan_document FROM review_github_check_effect_plans WHERE preview_id=(SELECT preview_id FROM review_action_previews WHERE idempotency_key='github-legacy-v5')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&document).unwrap();
        assert!(
            document
                .as_object_mut()
                .unwrap()
                .remove("expected_workspace_revision")
                .is_some()
        );
        let document = crate::agent_harness::canonical_json_bytes(&document);
        let digest = Sha256::digest(&document);
        connection
            .execute(
                "UPDATE review_github_check_effect_plans
                 SET plan_document=?1,plan_digest=?2,expected_workspace_revision=NULL
                 WHERE preview_id=(SELECT preview_id FROM review_action_previews WHERE idempotency_key='github-legacy-v5')",
                params![document, digest.as_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);

        let mut restarted = fixture.open();
        fixture.reset_counts();
        let response = restarted.handle(
            fixture.uid,
            &correlated_lookup("github-legacy-v5", correlation),
            20,
        );
        assert!(
            matches!(
                response,
                PlatformV2Response::Refused(ref refusal)
                    if refusal.category().as_str() == "platform_v2_not_found"
            ),
            "unexpected partial-v5 response: {response:?}"
        );
        assert_eq!(fixture.calls(), (0, 0));
    }

    #[test]
    fn github_started_recovery_after_workspace_advance_reconciles_once_and_never_posts() {
        for (suffix, custody) in [
            ("custody-started", None),
            ("accepted", Some(ReviewExternalEffectCustody::Accepted)),
            ("ambiguous", Some(ReviewExternalEffectCustody::Ambiguous)),
        ] {
            let fixture = GitHubRecoveryFixture::new();
            let key = format!("github-started-{suffix}");
            let mut host = fixture.open();
            let (prepared, plan, correlation) = seed_github_recovery_action(&mut host, &key);
            let started = approve_and_start_github_action(&mut host, &prepared, &plan);
            if let Some(custody) = custody {
                let PlatformV2Host::Enabled(runtime) = &mut host else {
                    panic!("enabled host required")
                };
                runtime
                    .reviews
                    .settle_github_check_rerun(
                        &started.preview_id,
                        started.request_digest,
                        custody,
                        13,
                    )
                    .unwrap();
            }
            drop(host);
            fixture.advance_workspace();

            let mut restarted = fixture.open();
            fixture.reset_counts();
            let response = restarted.handle(fixture.uid, &correlated_lookup(&key, correlation), 20);
            let expected_outcome = if custody == Some(ReviewExternalEffectCustody::Accepted) {
                ReviewReceiptOutcome::Accepted
            } else {
                ReviewReceiptOutcome::Unknown
            };
            assert!(matches!(
                response,
                PlatformV2Response::ReviewReceipt(receipt)
                    if receipt.outcome() == expected_outcome
            ));
            assert_eq!(fixture.calls(), (1, 0), "phase {suffix}");
        }
    }

    #[test]
    fn github_accepted_restart_recovery_preserves_attribution_until_exact_next_attempt() {
        let fixture = GitHubRecoveryFixture::new();
        let key = "github-accepted-baseline-then-next";
        let mut host = fixture.open();
        let (prepared, plan, correlation) = seed_github_recovery_action(&mut host, key);
        let started = approve_and_start_github_action(&mut host, &prepared, &plan);
        let PlatformV2Host::Enabled(runtime) = &mut host else {
            panic!("enabled host required")
        };
        runtime
            .reviews
            .settle_github_check_rerun(
                &started.preview_id,
                started.request_digest,
                ReviewExternalEffectCustody::Accepted,
                13,
            )
            .unwrap();
        drop(host);

        fixture.reset_counts();
        let mut first_restart = fixture.open();
        let first = first_restart.handle(
            fixture.uid,
            &correlated_lookup(key, correlation.clone()),
            20,
        );
        assert!(matches!(
            first,
            PlatformV2Response::ReviewReceipt(receipt)
                if receipt.outcome() == ReviewReceiptOutcome::Accepted
        ));
        assert_eq!(fixture.calls(), (1, 0), "one GET and no POST per poll");
        drop(first_restart);

        let raw = rusqlite::Connection::open(&fixture.review_path).unwrap();
        let custody: String = raw
            .query_row(
                "SELECT custody FROM review_github_check_effect_plans
                 WHERE preview_id=(SELECT preview_id FROM review_action_previews
                                   WHERE idempotency_key=?1)",
                [key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(custody, "accepted", "the baseline poll stays durable");
        drop(raw);

        fixture.set_attempt(4);
        let mut second_restart = fixture.open();
        let second = second_restart.handle(fixture.uid, &correlated_lookup(key, correlation), 21);
        assert!(matches!(
            second,
            PlatformV2Response::ReviewReceipt(receipt)
                if receipt.outcome() == ReviewReceiptOutcome::Completed
        ));
        assert_eq!(
            fixture.calls(),
            (2, 0),
            "each poll performs one GET and restart recovery never posts"
        );
    }

    #[test]
    fn github_terminal_recovery_after_workspace_advance_returns_without_provider_io() {
        let fixture = GitHubRecoveryFixture::new();
        let mut host = fixture.open();
        let (prepared, plan, correlation) =
            seed_github_recovery_action(&mut host, "github-terminal");
        let started = approve_and_start_github_action(&mut host, &prepared, &plan);
        let PlatformV2Host::Enabled(runtime) = &mut host else {
            panic!("enabled host required")
        };
        let terminal = runtime
            .reviews
            .settle_github_check_rerun(
                &started.preview_id,
                started.request_digest,
                ReviewExternalEffectCustody::Completed,
                13,
            )
            .unwrap();
        drop(host);
        fixture.advance_workspace();

        let mut restarted = fixture.open();
        fixture.reset_counts();
        let response = restarted.handle(
            fixture.uid,
            &correlated_lookup("github-terminal", correlation),
            20,
        );
        assert!(matches!(
            response,
            PlatformV2Response::ReviewReceipt(receipt) if receipt == terminal
        ));
        assert_eq!(fixture.calls(), (0, 0));
    }

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
    fn runtime_debug_redacts_private_attention_store_identity() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let policy_path = directory.path().join("policy.json");
        let uid = nix::unistd::geteuid().as_raw();
        let empty_authority = serde_json::json!({
            "filesystem": [], "credentials": [], "network": [],
            "tools": [], "providers": [], "models": []
        });
        write_generation_policy(
            &policy_path,
            &serde_json::json!({
                "version": 1,
                "principals": [{
                    "uid": uid,
                    "tenant": "runtime-tenant",
                    "actor": "runtime-actor",
                    "serving_authority": "automonique",
                    "projects": ["runtime-project"],
                    "workspaces": [{
                        "project": "runtime-project",
                        "kind": "project",
                        "id": "runtime-project",
                        "inherited_authority": empty_authority
                    }],
                    "authority": empty_authority,
                    "review_authorities": {}
                }]
            }),
        );
        let work_context_path = directory.path().join("work-context.sqlite3");
        let mut work_contexts = WorkContextStore::open(&work_context_path).unwrap();
        work_contexts
            .put_authoritative_record(
                "runtime-tenant",
                &WorkContextRecord::new(
                    WorkContextIdentity::Project(ProjectId::new("runtime-project").unwrap()),
                    Revision::FIRST,
                    WorkContextLifecycle::Active,
                    WorkContextLabel::new("Runtime project").unwrap(),
                    WorkContextAttributes::EMPTY,
                    Vec::new(),
                )
                .unwrap(),
            )
            .unwrap();
        drop(work_contexts);
        let host = PlatformV2Host::open_with_lifecycle_adapter(
            &policy_path,
            &work_context_path,
            &directory.path().join("lineage.sqlite3"),
            &directory.path().join("review.sqlite3"),
            uid,
            Box::new(UnavailableLifecycleEffectAdapter),
        );
        let PlatformV2Host::Enabled(mut runtime) = host else {
            panic!("expected enabled Platform v2 runtime, got {host:?}");
        };
        let attention_path = directory
            .path()
            .join("runtime-attention-private-path-sentinel.sqlite3");
        runtime.attention =
            AttentionStore::open_scoped(&attention_path, "runtime-attention-authority-sentinel")
                .unwrap();

        let debug = format!("{runtime:?}");
        assert!(debug.contains("attention: AttentionStore { state: \"open\" }"));
        assert!(!debug.contains(attention_path.to_str().unwrap()));
        assert!(!debug.contains("runtime-attention-private-path-sentinel"));
        assert!(!debug.contains("runtime-attention-authority-sentinel"));
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
        let attention_source = AttentionSource::new(
            AttentionSourceKind::Review,
            AttentionSourceId::new("review-source").unwrap(),
        );
        let mismatched_attention =
            PlatformV2Request::GetAttentionSourceSnapshot(AttentionReadRequest::new(
                attention_source.clone(),
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
                &mismatched_attention,
            ),
            Err("platform_v2_mobile_project_denied")
        );
        let valid_attention = PlatformV2Request::GetAttentionSourceSnapshot(
            AttentionReadRequest::new(attention_source, project_a.clone(), workspace_a.clone()),
        );
        assert_eq!(
            resolve_web_mobile_request_project(
                &path,
                uid,
                "tenant-test",
                "actor-test",
                &roots,
                &valid_attention,
            ),
            Ok(project_a)
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
