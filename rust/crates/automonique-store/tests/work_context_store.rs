// SPDX-License-Identifier: Elastic-2.0

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use automonique_protocol::identity::Actor;
use automonique_protocol::platform::{
    IdempotencyKey, ReceiptId, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_v2::*;
use automonique_protocol::platform_v2_lifecycle::*;
use automonique_protocol::platform_v2_lifecycle_api::{
    encode_work_context_mutation_submission, work_context_mutation_preview_digest,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_store::work_context_store::*;
use rusqlite::Connection;
use tempfile::TempDir;

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}
impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("work-context.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
struct Nonces {
    next: u8,
    calls: usize,
}
impl Nonces {
    fn new() -> Self {
        Self { next: 1, calls: 0 }
    }
}
impl WorkContextNonceSource for Nonces {
    fn nonce(&mut self) -> [u8; 16] {
        self.calls += 1;
        let value = [self.next; 16];
        self.next = self.next.wrapping_add(1);
        value
    }
}

fn revision(value: u64) -> Revision {
    Revision::new(value).unwrap()
}
fn label(value: &str) -> WorkContextLabel {
    WorkContextLabel::new(value).unwrap()
}
fn identity(kind: WorkContextKind, id: &str) -> WorkContextIdentity {
    WorkContextIdentity::parse_local(kind.into(), id).unwrap()
}
fn expected(kind: WorkContextKind, id: &str, rev: u64) -> ExpectedWorkContext {
    ExpectedWorkContext::new(identity(kind, id), revision(rev))
}
fn actor() -> Actor {
    Actor::new("tenant-1", "operator-1").unwrap()
}
fn policy_for(
    proposal: &WorkContextMutationProposal,
    requirement: MutationApprovalRequirement,
) -> MutationPolicyDecision {
    let mut targets = BTreeSet::new();
    let mut project = None;
    let mut add = |expected: &ExpectedWorkContext| {
        targets.insert(expected.identity().clone());
        if let WorkContextIdentity::Project(value) = expected.identity() {
            project = Some(value.clone());
        }
    };
    match proposal.intent() {
        WorkContextMutationIntent::CreateProject(value) => {
            for expected in value.repositories() {
                add(expected);
            }
        }
        WorkContextMutationIntent::CreateHostSetup(value) => add(value.project()),
        WorkContextMutationIntent::CreateCheckout(value) => {
            add(value.project());
            add(value.host_setup());
            add(value.repository());
        }
        WorkContextMutationIntent::CreateUserWorkspace(value) => {
            add(value.project());
            add(value.checkout());
        }
        WorkContextMutationIntent::CreateAttemptWorkspace(value) => {
            add(value.user_workspace());
            project = Some(ProjectId::new("project-1").unwrap());
        }
        WorkContextMutationIntent::ResumeAttemptWorkspace(value) => {
            add(value.target());
            project = Some(ProjectId::new("project-1").unwrap());
        }
        WorkContextMutationIntent::ResumeSession(value) => {
            add(value.target());
            project = Some(ProjectId::new("project-1").unwrap());
        }
        WorkContextMutationIntent::ArchiveProject(value)
        | WorkContextMutationIntent::ArchiveHostSetup(value)
        | WorkContextMutationIntent::ArchiveCheckout(value)
        | WorkContextMutationIntent::ArchiveUserWorkspace(value) => add(value.target()),
    }
    MutationPolicyDecision::new(
        actor(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        project,
        targets,
        requirement,
    )
}
fn approval_policy(preview: &MutationPreview, expires_at_ms: i64) -> ApprovalPolicyDecision {
    ApprovalPolicyDecision::new(
        Actor::new("tenant-1", "approver-1").unwrap(),
        ResourceAuthority::Automonique,
        WorkContextApprovalAuthority::LifecycleMutation,
        preview.preview().clone(),
        work_context_mutation_preview_digest(preview).unwrap(),
        EpochMillis::from_millis(expires_at_ms),
    )
}
fn read_policy(identity: &WorkContextIdentity, project: Option<&str>) -> MutationPolicyDecision {
    MutationPolicyDecision::new(
        actor(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        project.map(|value| ProjectId::new(value).unwrap()),
        BTreeSet::from([identity.clone()]),
        MutationApprovalRequirement::NotRequired,
    )
}
fn proposal(intent: WorkContextMutationIntent, key: &str) -> WorkContextMutationProposal {
    WorkContextMutationProposal::new(
        actor(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        IdempotencyKey::new(key).unwrap(),
        intent,
    )
    .unwrap()
}
fn project(id: &str, rev: u64, lifecycle: WorkContextLifecycle) -> WorkContextRecord {
    WorkContextRecord::new(
        identity(WorkContextKind::Project, id),
        revision(rev),
        lifecycle,
        label(id),
        WorkContextAttributes::EMPTY,
        vec![],
    )
    .unwrap()
}
fn user_workspace(id: &str, project_id: &str, checkout_id: &str, rev: u64) -> WorkContextRecord {
    WorkContextRecord::new(
        identity(WorkContextKind::UserWorkspace, id),
        revision(rev),
        WorkContextLifecycle::Active,
        label(id),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::UserWorkspaceProject,
                identity(WorkContextKind::Project, project_id),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::UserWorkspaceCheckout,
                identity(WorkContextKind::Checkout, checkout_id),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}
fn repository(id: &str) -> WorkContextIdentity {
    WorkContextIdentity::Repository(
        V1RepositoryRef::new(ResourceCoordinate::new(
            ResourceAuthority::GitHub,
            ResourceKind::Repository,
            ResourceId::new(id).unwrap(),
        ))
        .unwrap(),
    )
}
fn unwrap_new(admission: PreviewAdmission) -> MutationPreview {
    match admission {
        PreviewAdmission::New(value) => value,
        PreviewAdmission::Replay(_) => panic!("expected new"),
    }
}

#[test]
fn create_reservation_reopens_replays_and_refuses_same_key_different_body() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let repo = ExpectedWorkContext::new(repository("repo-1"), revision(4));
    store
        .put_external_snapshot("tenant-1", &repo, ExternalParentResolution::Available, None)
        .unwrap();
    let request = proposal(
        WorkContextMutationIntent::CreateProject(
            CreateProjectIntent::new(label("Project"), vec![repo.clone()]).unwrap(),
        ),
        "create-once",
    );
    let mut nonces = Nonces::new();
    let first = unwrap_new(
        store
            .prepare_mutation(
                &request,
                &policy_for(&request, MutationApprovalRequirement::NotRequired),
                100,
                200,
                &mut nonces,
            )
            .unwrap(),
    );
    assert_eq!(nonces.calls, 2);
    drop(store);
    let mut reopened = WorkContextStore::open(private.path()).unwrap();
    let replay = reopened
        .prepare_mutation(
            &request,
            &policy_for(&request, MutationApprovalRequirement::NotRequired),
            150,
            250,
            &mut nonces,
        )
        .unwrap();
    assert_eq!(replay, PreviewAdmission::Replay(first.clone()));
    assert_eq!(nonces.calls, 2, "replay reserves no IDs");
    let changed = proposal(
        WorkContextMutationIntent::CreateProject(
            CreateProjectIntent::new(label("Changed"), vec![repo]).unwrap(),
        ),
        "create-once",
    );
    assert_eq!(
        reopened
            .prepare_mutation(
                &changed,
                &policy_for(&changed, MutationApprovalRequirement::NotRequired),
                150,
                250,
                &mut nonces
            )
            .unwrap_err()
            .category(),
        "conflict"
    );
    assert!(
        first
            .resulting()
            .identity()
            .id()
            .starts_with("wc2_project_")
    );
}

#[test]
fn concurrent_replay_body_conflict_and_approval_consumption_are_serialized() {
    let private = PrivateStore::new();
    let mut seed = WorkContextStore::open(private.path()).unwrap();
    seed.put_authoritative_record(
        "tenant-1",
        &project("project-1", 1, WorkContextLifecycle::Active),
    )
    .unwrap();
    drop(seed);
    let request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "concurrent-archive",
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for next in [10, 20] {
        let path = private.path().to_path_buf();
        let request = request.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let mut store = WorkContextStore::open(path).unwrap();
            let mut nonces = Nonces { next, calls: 0 };
            barrier.wait();
            store
                .prepare_mutation(
                    &request,
                    &policy_for(&request, MutationApprovalRequirement::Required),
                    100,
                    500,
                    &mut nonces,
                )
                .unwrap()
        }));
    }
    let admissions: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        admissions
            .iter()
            .filter(|value| matches!(value, PreviewAdmission::New(_)))
            .count(),
        1
    );
    assert_eq!(
        admissions
            .iter()
            .filter(|value| matches!(value, PreviewAdmission::Replay(_)))
            .count(),
        1
    );
    let preview = match &admissions[0] {
        PreviewAdmission::New(value) | PreviewAdmission::Replay(value) => value.clone(),
    };

    let mut store = WorkContextStore::open(private.path()).unwrap();
    let approval = store
        .record_approval(
            preview.preview(),
            MutationApprovalId::new("approval-race").unwrap(),
            MutationApprovalDecision::Granted,
            &approval_policy(&preview, 400),
            150,
        )
        .unwrap();
    let submission = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(200),
    )
    .unwrap();
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let mut submitters = Vec::new();
    for receipt in ["receipt-race-a", "receipt-race-b"] {
        let path = private.path().to_path_buf();
        let preview_ref = preview.preview().clone();
        let submission = submission.clone();
        let barrier = barrier.clone();
        let request = request.clone();
        submitters.push(thread::spawn(move || {
            let mut store = WorkContextStore::open(path).unwrap();
            barrier.wait();
            store
                .submit_mutation(
                    &preview_ref,
                    &submission,
                    &policy_for(&request, MutationApprovalRequirement::Required),
                    ReceiptId::new(receipt).unwrap(),
                    210,
                )
                .unwrap()
        }));
    }
    let receipts: Vec<_> = submitters
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        receipts
            .iter()
            .filter(|value| matches!(value, ReceiptAdmission::New(_)))
            .count(),
        1
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|value| matches!(value, ReceiptAdmission::Replay(_)))
            .count(),
        1
    );

    let conflicting = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "concurrent-archive",
    );
    let changed = WorkContextMutationProposal::new(
        conflicting.actor().clone(),
        conflicting.authority(),
        conflicting.actor_authority().clone(),
        conflicting.idempotency_key().clone(),
        WorkContextMutationIntent::CreateProject(
            CreateProjectIntent::new(label("different body"), vec![]).unwrap(),
        ),
    )
    .unwrap();
    let mut reopened = WorkContextStore::open(private.path()).unwrap();
    let mut nonces = Nonces::new();
    assert_eq!(
        reopened
            .prepare_mutation(
                &changed,
                &policy_for(&changed, MutationApprovalRequirement::NotRequired),
                300,
                400,
                &mut nonces
            )
            .unwrap_err()
            .category(),
        "conflict"
    );
}

#[test]
fn stale_parent_graph_scope_and_authority_widening_fail_before_reservation() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 2, WorkContextLifecycle::Active),
        )
        .unwrap();
    store
        .bind_private_selector(
            "tenant-1",
            &WorkContextRegistrySelector::new("selector-1").unwrap(),
            b"private path is never returned",
        )
        .unwrap();
    let stale = proposal(
        WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                label("Setup"),
                expected(WorkContextKind::Project, "project-1", 1),
                HostSetupKind::Local,
                WorkContextRegistrySelector::new("selector-1").unwrap(),
            )
            .unwrap(),
        ),
        "stale",
    );
    let mut nonces = Nonces::new();
    assert_eq!(
        store
            .prepare_mutation(
                &stale,
                &policy_for(&stale, MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces
            )
            .unwrap_err()
            .category(),
        "stale_revision"
    );
    assert_eq!(nonces.calls, 0);
    let valid = proposal(
        WorkContextMutationIntent::CreateHostSetup(
            CreateHostSetupIntent::new(
                label("Setup"),
                expected(WorkContextKind::Project, "project-1", 2),
                HostSetupKind::Local,
                WorkContextRegistrySelector::new("selector-1").unwrap(),
            )
            .unwrap(),
        ),
        "wrong-actor",
    );
    let wrong = MutationPolicyDecision::new(
        Actor::new("tenant-1", "other").unwrap(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        Some(ProjectId::new("project-1").unwrap()),
        BTreeSet::from([identity(WorkContextKind::Project, "project-1")]),
        MutationApprovalRequirement::NotRequired,
    );
    assert_eq!(
        store
            .prepare_mutation(&valid, &wrong, 1, 10, &mut nonces)
            .unwrap_err()
            .category(),
        "unauthorized"
    );
    let grant = AuthorityGrantId::new("fs:one").unwrap();
    let requested =
        WorkContextAuthority::new(vec![grant], vec![], vec![], vec![], vec![], vec![]).unwrap();
    let attempt = proposal(
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                label("Attempt"),
                expected(WorkContextKind::UserWorkspace, "workspace-1", 1),
                requested,
            )
            .unwrap(),
        ),
        "wide",
    );
    assert_eq!(
        store
            .prepare_mutation(
                &attempt,
                &policy_for(&attempt, MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces
            )
            .unwrap_err()
            .category(),
        "authority_widening"
    );
}

#[test]
fn checkout_repository_resolution_and_owner_are_rechecked_before_reservation() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let repository = ExpectedWorkContext::new(repository("repo-checkout"), revision(5));
    let project_identity = identity(WorkContextKind::Project, "project-1");
    let WorkContextIdentity::Project(selected_project) = &project_identity else {
        unreachable!()
    };
    let other = match identity(WorkContextKind::Project, "project-2") {
        WorkContextIdentity::Project(value) => value,
        _ => unreachable!(),
    };
    store
        .put_external_snapshot(
            "tenant-1",
            &repository,
            ExternalParentResolution::Unavailable,
            Some(selected_project),
        )
        .unwrap();
    let project = WorkContextRecord::new(
        project_identity.clone(),
        revision(1),
        WorkContextLifecycle::Active,
        label("Project"),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::ProjectRepository,
                repository.identity().clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let host = WorkContextRecord::new(
        identity(WorkContextKind::HostSetup, "host-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("Host"),
        WorkContextAttributes::host_setup(HostSetupKind::Local),
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::HostSetupProject,
                project_identity.clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-1", &project)
        .unwrap();
    store.put_authoritative_record("tenant-1", &host).unwrap();
    let selector = WorkContextRegistrySelector::new("checkout-selector").unwrap();
    store
        .bind_private_selector("tenant-1", &selector, b"private checkout binding")
        .unwrap();
    let request = proposal(
        WorkContextMutationIntent::CreateCheckout(
            CreateCheckoutIntent::new(
                label("Checkout"),
                ExpectedWorkContext::new(project_identity.clone(), revision(1)),
                ExpectedWorkContext::new(host.identity().clone(), revision(1)),
                repository.clone(),
                CheckoutKind::GitWorktree,
                selector.clone(),
            )
            .unwrap(),
        ),
        "checkout-resolution",
    );
    let mut nonces = Nonces::new();
    assert_eq!(
        store
            .prepare_mutation(
                &request,
                &policy_for(&request, MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces,
            )
            .unwrap_err()
            .category(),
        "unavailable"
    );
    let available = ExpectedWorkContext::new(repository.identity().clone(), revision(6));
    store
        .put_external_snapshot(
            "tenant-1",
            &available,
            ExternalParentResolution::Available,
            Some(selected_project),
        )
        .unwrap();
    let available_request = proposal(
        WorkContextMutationIntent::CreateCheckout(
            CreateCheckoutIntent::new(
                label("Checkout"),
                ExpectedWorkContext::new(project_identity.clone(), revision(1)),
                ExpectedWorkContext::new(host.identity().clone(), revision(1)),
                available.clone(),
                CheckoutKind::GitWorktree,
                selector,
            )
            .unwrap(),
        ),
        "checkout-resolution",
    );
    assert!(matches!(
        store
            .prepare_mutation(
                &available_request,
                &policy_for(&available_request, MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces,
            )
            .unwrap(),
        PreviewAdmission::New(_)
    ));
    assert_eq!(nonces.calls, 2);
    let reparented = ExpectedWorkContext::new(repository.identity().clone(), revision(7));
    assert_eq!(
        store
            .put_external_snapshot(
                "tenant-1",
                &reparented,
                ExternalParentResolution::Available,
                Some(&other),
            )
            .unwrap_err()
            .category(),
        "stale_revision"
    );
}

#[test]
fn approval_is_exact_one_time_and_archive_is_one_way_after_restart() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let repo = ExpectedWorkContext::new(repository("repo-1"), revision(1));
    let selected_project = ProjectId::new("project-1").unwrap();
    store
        .put_external_snapshot(
            "tenant-1",
            &repo,
            ExternalParentResolution::Available,
            Some(&selected_project),
        )
        .unwrap();
    let project = WorkContextRecord::new(
        identity(WorkContextKind::Project, "project-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("project-1"),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::ProjectRepository,
                repo.identity().clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-1", &project)
        .unwrap();
    let host = WorkContextRecord::new(
        identity(WorkContextKind::HostSetup, "setup-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("setup-1"),
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
    store.put_authoritative_record("tenant-1", &host).unwrap();
    let request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "archive",
    );
    let mut nonces = Nonces::new();
    let preview = unwrap_new(
        store
            .prepare_mutation(
                &request,
                &policy_for(&request, MutationApprovalRequirement::Required),
                100,
                500,
                &mut nonces,
            )
            .unwrap(),
    );
    let approval = store
        .record_approval(
            preview.preview(),
            MutationApprovalId::new("approval-1").unwrap(),
            MutationApprovalDecision::Granted,
            &approval_policy(&preview, 400),
            150,
        )
        .unwrap();
    let submission = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(200),
    )
    .unwrap();
    let first = store
        .submit_mutation(
            preview.preview(),
            &submission,
            &policy_for(&request, MutationApprovalRequirement::Required),
            ReceiptId::new("receipt-1").unwrap(),
            210,
        )
        .unwrap();
    assert!(matches!(first, ReceiptAdmission::New(_)));
    assert_eq!(
        store
            .submit_mutation(
                preview.preview(),
                &submission,
                &policy_for(&request, MutationApprovalRequirement::Required),
                ReceiptId::new("ignored-replay-id").unwrap(),
                220
            )
            .unwrap(),
        match first {
            ReceiptAdmission::New(value) => ReceiptAdmission::Replay(value),
            _ => unreachable!(),
        }
    );
    drop(store);
    let mut reopened = WorkContextStore::open(private.path()).unwrap();
    assert_eq!(
        reopened
            .record(
                &read_policy(
                    &identity(WorkContextKind::Project, "project-1"),
                    Some("project-1")
                ),
                &identity(WorkContextKind::Project, "project-1"),
            )
            .unwrap()
            .unwrap()
            .lifecycle(),
        WorkContextLifecycle::Archived
    );
    let second = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 2)).unwrap(),
        ),
        "archive-again",
    );
    assert_eq!(
        reopened
            .prepare_mutation(
                &second,
                &policy_for(&request, MutationApprovalRequirement::NotRequired),
                300,
                400,
                &mut nonces
            )
            .unwrap_err()
            .category(),
        "protocol"
    );
}

#[test]
fn external_effect_commits_outbox_then_result_and_completed_receipt_atomically() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let repo = ExpectedWorkContext::new(repository("repo-1"), revision(1));
    let selected_project = ProjectId::new("project-1").unwrap();
    store
        .put_external_snapshot(
            "tenant-1",
            &repo,
            ExternalParentResolution::Available,
            Some(&selected_project),
        )
        .unwrap();
    let project = WorkContextRecord::new(
        identity(WorkContextKind::Project, "project-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("project-1"),
        WorkContextAttributes::EMPTY,
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::ProjectRepository,
                repo.identity().clone(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-1", &project)
        .unwrap();
    let host = WorkContextRecord::new(
        identity(WorkContextKind::HostSetup, "setup-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("setup-1"),
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
    store.put_authoritative_record("tenant-1", &host).unwrap();
    let checkout = WorkContextRecord::new(
        identity(WorkContextKind::Checkout, "checkout-1"),
        revision(1),
        WorkContextLifecycle::Active,
        label("Checkout"),
        WorkContextAttributes::checkout(CheckoutKind::GitWorktree),
        vec![
            WorkContextRelation::new(
                WorkContextRelationKind::CheckoutProject,
                identity(WorkContextKind::Project, "project-1"),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::CheckoutHostSetup,
                identity(WorkContextKind::HostSetup, "setup-1"),
            )
            .unwrap(),
            WorkContextRelation::new(
                WorkContextRelationKind::CheckoutRepository,
                repository("repo-1"),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    store
        .put_authoritative_record("tenant-1", &checkout)
        .unwrap();
    store
        .put_authoritative_record(
            "tenant-1",
            &user_workspace("workspace-1", "project-1", "checkout-1", 1),
        )
        .unwrap();
    let request = proposal(
        WorkContextMutationIntent::CreateAttemptWorkspace(
            CreateAttemptWorkspaceIntent::new(
                label("Attempt"),
                expected(WorkContextKind::UserWorkspace, "workspace-1", 1),
                WorkContextAuthority::EMPTY,
            )
            .unwrap(),
        ),
        "attempt",
    );
    let mut nonces = Nonces::new();
    let preview = unwrap_new(
        store
            .prepare_mutation(
                &request,
                &policy_for(&request, MutationApprovalRequirement::NotRequired),
                10,
                100,
                &mut nonces,
            )
            .unwrap(),
    );
    let submission =
        encode_work_context_mutation_submission(&preview, None, EpochMillis::from_millis(20))
            .unwrap();
    let accepted = store
        .submit_mutation(
            preview.preview(),
            &submission,
            &policy_for(&request, MutationApprovalRequirement::NotRequired),
            ReceiptId::new("receipt-attempt").unwrap(),
            21,
        )
        .unwrap();
    assert!(
        matches!(accepted,ReceiptAdmission::New(ref value) if value.outcome()==automonique_protocol::platform::ReceiptOutcome::Accepted)
    );
    assert_eq!(store.ready_outbox_count().unwrap(), 1);
    let mutation_policy = policy_for(&request, MutationApprovalRequirement::NotRequired);
    assert!(matches!(
        store
            .receipt_by_id(&mutation_policy, &ReceiptId::new("receipt-attempt").unwrap())
            .unwrap(),
        ReceiptLookup::Found(ref receipt)
            if receipt.outcome() == automonique_protocol::platform::ReceiptOutcome::Accepted
    ));
    assert!(matches!(
        store
            .receipt_by_idempotency_key(&mutation_policy, request.idempotency_key())
            .unwrap(),
        ReceiptLookup::Found(_)
    ));
    assert_eq!(
        store
            .receipt_by_id(
                &mutation_policy,
                &ReceiptId::new("receipt-unknown").unwrap()
            )
            .unwrap(),
        ReceiptLookup::Unknown
    );
    let duplicate_request = proposal(request.intent().clone(), "attempt-distinct-key");
    let duplicate_preview = unwrap_new(
        store
            .prepare_mutation(
                &duplicate_request,
                &policy_for(&duplicate_request, MutationApprovalRequirement::NotRequired),
                22,
                100,
                &mut nonces,
            )
            .unwrap(),
    );
    let duplicate_submission = encode_work_context_mutation_submission(
        &duplicate_preview,
        None,
        EpochMillis::from_millis(23),
    )
    .unwrap();
    assert_eq!(
        store
            .submit_mutation(
                duplicate_preview.preview(),
                &duplicate_submission,
                &policy_for(&duplicate_request, MutationApprovalRequirement::NotRequired),
                ReceiptId::new("receipt-duplicate-effect").unwrap(),
                24,
            )
            .unwrap_err()
            .category(),
        "conflict"
    );
    assert!(
        store
            .record(
                &read_policy(preview.resulting().identity(), Some("project-1")),
                preview.resulting().identity(),
            )
            .unwrap()
            .is_none()
    );
    drop(store);
    let mut unauthorized_store = WorkContextStore::open(private.path()).unwrap();
    let mut unauthorized_nonces = Nonces { next: 80, calls: 0 };
    assert_eq!(
        unauthorized_store
            .claim_external_effect(
                preview.preview(),
                &ExternalEffectExecutorPolicy::new(
                    Actor::new("tenant-1", "executor-x").unwrap(),
                    ResourceAuthority::GitHub,
                    BTreeSet::from(["create_attempt_workspace".to_owned()]),
                ),
                25,
                80,
                &mut unauthorized_nonces,
            )
            .unwrap_err()
            .category(),
        "not_found"
    );
    drop(unauthorized_store);
    let barrier = Arc::new(Barrier::new(2));
    let mut claimers = Vec::new();
    for (executor, next) in [("executor-1", 90), ("executor-2", 91)] {
        let path = private.path().to_path_buf();
        let preview_ref = preview.preview().clone();
        let barrier = barrier.clone();
        claimers.push(thread::spawn(move || {
            let mut store = WorkContextStore::open(path).unwrap();
            let mut nonces = Nonces { next, calls: 0 };
            barrier.wait();
            store.claim_external_effect(
                &preview_ref,
                &ExternalEffectExecutorPolicy::new(
                    Actor::new("tenant-1", executor).unwrap(),
                    ResourceAuthority::Automonique,
                    BTreeSet::from(["create_attempt_workspace".to_owned()]),
                ),
                25,
                80,
                &mut nonces,
            )
        }));
    }
    let claims: Vec<_> = claimers
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(claims.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        claims
            .iter()
            .filter_map(|result| result.as_ref().err())
            .next()
            .unwrap()
            .category(),
        "unavailable"
    );
    let claim = claims.into_iter().find_map(Result::ok).unwrap();
    let mut reopened = WorkContextStore::open(private.path()).unwrap();
    let completed = reopened.complete_external_effect(&claim, 30).unwrap();
    assert_eq!(
        completed.outcome(),
        automonique_protocol::platform::ReceiptOutcome::Completed
    );
    assert_eq!(reopened.ready_outbox_count().unwrap(), 0);
    assert_eq!(
        reopened.complete_external_effect(&claim, 31).unwrap(),
        completed
    );
    assert!(matches!(
        reopened
            .receipt_by_id(&mutation_policy, &ReceiptId::new("receipt-attempt").unwrap())
            .unwrap(),
        ReceiptLookup::Found(ref receipt)
            if receipt.outcome() == automonique_protocol::platform::ReceiptOutcome::Completed
    ));
    assert_eq!(
        reopened
            .record(
                &read_policy(preview.resulting().identity(), Some("project-1")),
                preview.resulting().identity(),
            )
            .unwrap()
            .unwrap(),
        *preview.resulting()
    );
}

#[test]
fn authorized_inventory_pages_past_512_with_hidden_interleaving_and_resyncs_on_change() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let mut allowed = BTreeSet::new();
    for index in 0..720 {
        let id = format!("project-{index:04}");
        let record = project(&id, 1, WorkContextLifecycle::Active);
        store.put_authoritative_record("tenant-1", &record).unwrap();
        if index % 9 != 0 {
            allowed.insert(record.identity().clone());
        }
    }
    assert_eq!(allowed.len(), 640);
    let actor = actor();
    let mut after = None;
    let mut seen = 0;
    for _ in 0..5 {
        let query = WorkContextQuery::new(
            vec![WorkContextKind::Project],
            vec![],
            None,
            None,
            after.clone(),
            128,
        )
        .unwrap();
        let WorkContextQueryResult::Page(page) =
            store.inventory(&actor, &query, &allowed, 1).unwrap()
        else {
            panic!("ordinary page")
        };
        seen += page.items().len();
        after = page.next_cursor().cloned();
    }
    assert_eq!(seen, 640);
    assert!(after.is_none());
    let first = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![],
        None,
        None,
        None,
        128,
    )
    .unwrap();
    let WorkContextQueryResult::Page(page) = store.inventory(&actor, &first, &allowed, 2).unwrap()
    else {
        unreachable!()
    };
    let cursor = page.next_cursor().cloned().unwrap();
    let second_actor = Actor::new("tenant-1", "operator-2").unwrap();
    let WorkContextQueryResult::Page(second_page) =
        store.inventory(&second_actor, &first, &allowed, 2).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(second_page.next_cursor(), Some(&cursor));
    let shared_continuation = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![],
        None,
        None,
        Some(cursor.clone()),
        128,
    )
    .unwrap();
    assert!(matches!(
        store
            .inventory(&actor, &shared_continuation, &allowed, 2)
            .unwrap(),
        WorkContextQueryResult::Page(_)
    ));
    assert!(matches!(
        store
            .inventory(&second_actor, &shared_continuation, &allowed, 2)
            .unwrap(),
        WorkContextQueryResult::Page(_)
    ));
    let changed_identity = allowed.iter().next().unwrap().clone();
    store
        .put_authoritative_record(
            "tenant-1",
            &project(changed_identity.id(), 2, WorkContextLifecycle::Archived),
        )
        .unwrap();
    let continued = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![],
        None,
        None,
        Some(cursor),
        128,
    )
    .unwrap();
    assert!(matches!(
        store.inventory(&actor, &continued, &allowed, 3).unwrap(),
        WorkContextQueryResult::Resync(_)
    ));
}

#[test]
fn tenant_scopes_records_targets_and_replay_authorization() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    let target = identity(WorkContextKind::Project, "shared-project-id");
    store
        .put_authoritative_record(
            "tenant-1",
            &project("shared-project-id", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    store
        .put_authoritative_record(
            "tenant-2",
            &project("shared-project-id", 5, WorkContextLifecycle::Active),
        )
        .unwrap();
    let tenant_two = Actor::new("tenant-2", "operator-2").unwrap();
    let tenant_two_policy = MutationPolicyDecision::new(
        tenant_two.clone(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        Some(ProjectId::new("shared-project-id").unwrap()),
        BTreeSet::from([target.clone()]),
        MutationApprovalRequirement::NotRequired,
    );
    assert_eq!(
        store
            .record(&tenant_two_policy, &target)
            .unwrap()
            .unwrap()
            .revision(),
        revision(5)
    );
    assert_eq!(
        store
            .record(&read_policy(&target, Some("shared-project-id")), &target)
            .unwrap()
            .unwrap()
            .revision(),
        revision(1)
    );

    let tenant_one_request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(ExpectedWorkContext::new(target.clone(), revision(1))).unwrap(),
        ),
        "same-key-no-oracle",
    );
    let mut nonces = Nonces::new();
    store
        .prepare_mutation(
            &tenant_one_request,
            &policy_for(
                &tenant_one_request,
                MutationApprovalRequirement::NotRequired,
            ),
            10,
            100,
            &mut nonces,
        )
        .unwrap();
    let absent = identity(WorkContextKind::Project, "tenant-one-only");
    store
        .put_authoritative_record(
            "tenant-1",
            &project("tenant-one-only", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    let tenant_two_request = WorkContextMutationProposal::new(
        tenant_two,
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        IdempotencyKey::new("same-key-no-oracle").unwrap(),
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(ExpectedWorkContext::new(absent.clone(), revision(1))).unwrap(),
        ),
    )
    .unwrap();
    let cross_tenant_policy = MutationPolicyDecision::new(
        tenant_two_request.actor().clone(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        Some(ProjectId::new("tenant-one-only").unwrap()),
        BTreeSet::from([absent]),
        MutationApprovalRequirement::NotRequired,
    );
    assert_eq!(
        store
            .prepare_mutation(
                &tenant_two_request,
                &cross_tenant_policy,
                10,
                100,
                &mut nonces,
            )
            .unwrap_err()
            .category(),
        "stale_revision"
    );
}

#[test]
fn trusted_now_and_checked_approval_authority_fence_expiry() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    let request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "approval-expiry",
    );
    let mut nonces = Nonces::new();
    let preview = unwrap_new(
        store
            .prepare_mutation(
                &request,
                &policy_for(&request, MutationApprovalRequirement::Required),
                100,
                200,
                &mut nonces,
            )
            .unwrap(),
    );
    assert_eq!(
        store
            .record_approval(
                preview.preview(),
                MutationApprovalId::new("backdated-approval").unwrap(),
                MutationApprovalDecision::Granted,
                &approval_policy(&preview, 150),
                150,
            )
            .unwrap_err()
            .category(),
        "unauthorized"
    );
    let approval = store
        .record_approval(
            preview.preview(),
            MutationApprovalId::new("expiring-approval").unwrap(),
            MutationApprovalDecision::Granted,
            &approval_policy(&preview, 180),
            150,
        )
        .unwrap();
    let backdated_submission = encode_work_context_mutation_submission(
        &preview,
        Some(&approval),
        EpochMillis::from_millis(160),
    )
    .unwrap();
    assert_eq!(
        store
            .submit_mutation(
                preview.preview(),
                &backdated_submission,
                &policy_for(&request, MutationApprovalRequirement::Required),
                ReceiptId::new("expired-approval-receipt").unwrap(),
                181,
            )
            .unwrap_err()
            .category(),
        "approval_expired"
    );
    assert_eq!(
        store
            .submit_mutation(
                preview.preview(),
                &backdated_submission,
                &policy_for(&request, MutationApprovalRequirement::Required),
                ReceiptId::new("expired-preview-receipt").unwrap(),
                201,
            )
            .unwrap_err()
            .category(),
        "preview_expired"
    );
}

#[test]
fn authoritative_ingestion_refuses_terminal_rollback_reparent_and_external_regression() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 2, WorkContextLifecycle::Archived),
        )
        .unwrap();
    assert_eq!(
        store
            .put_authoritative_record(
                "tenant-1",
                &project("project-1", 3, WorkContextLifecycle::Active),
            )
            .unwrap_err()
            .category(),
        "conflict"
    );
    store
        .put_authoritative_record(
            "tenant-1",
            &project("project-2", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    let host = |revision_value, project_id: &str| {
        WorkContextRecord::new(
            identity(WorkContextKind::HostSetup, "host-1"),
            revision(revision_value),
            WorkContextLifecycle::Active,
            label("Host"),
            WorkContextAttributes::host_setup(HostSetupKind::Local),
            vec![
                WorkContextRelation::new(
                    WorkContextRelationKind::HostSetupProject,
                    identity(WorkContextKind::Project, project_id),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    };
    store
        .put_authoritative_record("tenant-1", &host(1, "project-2"))
        .unwrap();
    assert_eq!(
        store
            .put_authoritative_record("tenant-1", &host(2, "project-1"))
            .unwrap_err()
            .category(),
        "conflict"
    );
    let external = ExpectedWorkContext::new(repository("external-regression"), revision(5));
    let owner = ProjectId::new("project-2").unwrap();
    store
        .put_external_snapshot(
            "tenant-1",
            &external,
            ExternalParentResolution::Available,
            Some(&owner),
        )
        .unwrap();
    let regressed = ExpectedWorkContext::new(external.identity().clone(), revision(4));
    assert_eq!(
        store
            .put_external_snapshot(
                "tenant-1",
                &regressed,
                ExternalParentResolution::Available,
                Some(&owner),
            )
            .unwrap_err()
            .category(),
        "stale_revision"
    );
    let reparented = ExpectedWorkContext::new(external.identity().clone(), revision(6));
    assert_eq!(
        store
            .put_external_snapshot(
                "tenant-1",
                &reparented,
                ExternalParentResolution::Available,
                Some(&ProjectId::new("project-1").unwrap()),
            )
            .unwrap_err()
            .category(),
        "stale_revision"
    );
}

#[test]
fn durable_readers_reject_record_preview_and_receipt_projection_corruption() {
    let record_private = PrivateStore::new();
    let mut record_store = WorkContextStore::open(record_private.path()).unwrap();
    let record_identity = identity(WorkContextKind::Project, "project-corrupt");
    record_store
        .put_authoritative_record(
            "tenant-1",
            &project("project-corrupt", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    drop(record_store);
    Connection::open(record_private.path())
        .unwrap()
        .execute(
            "UPDATE work_context_records SET identity_id='substituted' WHERE tenant='tenant-1'",
            [],
        )
        .unwrap();
    let record_store = WorkContextStore::open(record_private.path()).unwrap();
    assert_eq!(
        record_store
            .record(
                &read_policy(&record_identity, Some("project-corrupt")),
                &record_identity,
            )
            .unwrap_err()
            .category(),
        "corrupt"
    );

    let preview_private = PrivateStore::new();
    let mut preview_store = WorkContextStore::open(preview_private.path()).unwrap();
    preview_store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    let preview_request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "corrupt-preview",
    );
    let mut nonces = Nonces::new();
    preview_store
        .prepare_mutation(
            &preview_request,
            &policy_for(&preview_request, MutationApprovalRequirement::NotRequired),
            10,
            100,
            &mut nonces,
        )
        .unwrap();
    drop(preview_store);
    Connection::open(preview_private.path())
        .unwrap()
        .execute(
            "UPDATE work_context_previews SET request_digest='0000000000000000000000000000000000000000000000000000000000000000'",
            [],
        )
        .unwrap();
    let mut preview_store = WorkContextStore::open(preview_private.path()).unwrap();
    assert_eq!(
        preview_store
            .prepare_mutation(
                &preview_request,
                &policy_for(&preview_request, MutationApprovalRequirement::NotRequired),
                11,
                101,
                &mut nonces,
            )
            .unwrap_err()
            .category(),
        "corrupt"
    );

    let receipt_private = PrivateStore::new();
    let mut receipt_store = WorkContextStore::open(receipt_private.path()).unwrap();
    receipt_store
        .put_authoritative_record(
            "tenant-1",
            &project("project-1", 1, WorkContextLifecycle::Active),
        )
        .unwrap();
    let receipt_request = proposal(
        WorkContextMutationIntent::ArchiveProject(
            ArchiveIntent::new(expected(WorkContextKind::Project, "project-1", 1)).unwrap(),
        ),
        "corrupt-receipt",
    );
    let receipt_preview = unwrap_new(
        receipt_store
            .prepare_mutation(
                &receipt_request,
                &policy_for(&receipt_request, MutationApprovalRequirement::NotRequired),
                10,
                100,
                &mut nonces,
            )
            .unwrap(),
    );
    let submission = encode_work_context_mutation_submission(
        &receipt_preview,
        None,
        EpochMillis::from_millis(20),
    )
    .unwrap();
    receipt_store
        .submit_mutation(
            receipt_preview.preview(),
            &submission,
            &policy_for(&receipt_request, MutationApprovalRequirement::NotRequired),
            ReceiptId::new("receipt-corrupt").unwrap(),
            21,
        )
        .unwrap();
    drop(receipt_store);
    Connection::open(receipt_private.path())
        .unwrap()
        .execute("UPDATE work_context_receipts SET outcome='accepted'", [])
        .unwrap();
    let receipt_store = WorkContextStore::open(receipt_private.path()).unwrap();
    assert_eq!(
        receipt_store
            .receipt_by_id(
                &policy_for(&receipt_request, MutationApprovalRequirement::NotRequired),
                &ReceiptId::new("receipt-corrupt").unwrap(),
            )
            .unwrap_err()
            .category(),
        "corrupt"
    );
}

#[test]
fn empty_v1_database_migrates_to_tenant_scoped_schema() {
    let private = PrivateStore::new();
    drop(WorkContextStore::open(private.path()).unwrap());
    let connection = Connection::open(private.path()).unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);
    let store = WorkContextStore::open(private.path()).unwrap();
    let connection = Connection::open(store.path()).unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, WORK_CONTEXT_STORE_SCHEMA_VERSION);
    let primary_key_columns: u32 = connection
        .query_row(
            "SELECT count(*) FROM pragma_table_info('work_context_cursor_state') WHERE pk>0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(primary_key_columns, 3);
}
