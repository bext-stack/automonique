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
use automonique_protocol::platform_v2_lifecycle_api::encode_work_context_mutation_submission;
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_store::work_context_store::*;
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
fn empty_policy(requirement: MutationApprovalRequirement) -> MutationPolicyDecision {
    MutationPolicyDecision::new(
        actor(),
        ResourceAuthority::Automonique,
        WorkContextAuthority::EMPTY,
        WorkContextAuthority::EMPTY,
        requirement,
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
        .put_external_snapshot(&repo, ExternalParentResolution::Available, None)
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
            &empty_policy(MutationApprovalRequirement::NotRequired),
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
    seed.put_authoritative_record(&project("project-1", 1, WorkContextLifecycle::Active))
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
                    &empty_policy(MutationApprovalRequirement::Required),
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
            Actor::new("tenant-1", "approver-1").unwrap(),
            150,
            400,
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
        submitters.push(thread::spawn(move || {
            let mut store = WorkContextStore::open(path).unwrap();
            barrier.wait();
            store
                .submit_mutation(
                    &preview_ref,
                    &submission,
                    &empty_policy(MutationApprovalRequirement::Required),
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
        .put_authoritative_record(&project("project-1", 2, WorkContextLifecycle::Active))
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
    store.put_authoritative_record(&project).unwrap();
    store.put_authoritative_record(&host).unwrap();
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
                selector,
            )
            .unwrap(),
        ),
        "checkout-resolution",
    );
    let WorkContextIdentity::Project(selected_project) = &project_identity else {
        unreachable!()
    };
    store
        .put_external_snapshot(&repository, ExternalParentResolution::Unavailable, None)
        .unwrap();
    let mut nonces = Nonces::new();
    assert_eq!(
        store
            .prepare_mutation(
                &request,
                &empty_policy(MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces,
            )
            .unwrap_err()
            .category(),
        "unavailable"
    );
    let other = match identity(WorkContextKind::Project, "project-2") {
        WorkContextIdentity::Project(value) => value,
        _ => unreachable!(),
    };
    store
        .put_external_snapshot(
            &repository,
            ExternalParentResolution::Available,
            Some(&other),
        )
        .unwrap();
    assert_eq!(
        store
            .prepare_mutation(
                &request,
                &empty_policy(MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces,
            )
            .unwrap_err()
            .category(),
        "conflict"
    );
    assert_eq!(nonces.calls, 0);
    store
        .put_external_snapshot(
            &repository,
            ExternalParentResolution::Available,
            Some(selected_project),
        )
        .unwrap();
    assert!(matches!(
        store
            .prepare_mutation(
                &request,
                &empty_policy(MutationApprovalRequirement::NotRequired),
                1,
                10,
                &mut nonces,
            )
            .unwrap(),
        PreviewAdmission::New(_)
    ));
}

#[test]
fn approval_is_exact_one_time_and_archive_is_one_way_after_restart() {
    let private = PrivateStore::new();
    let mut store = WorkContextStore::open(private.path()).unwrap();
    store
        .put_authoritative_record(&project("project-1", 1, WorkContextLifecycle::Active))
        .unwrap();
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
                &empty_policy(MutationApprovalRequirement::Required),
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
            Actor::new("tenant-1", "approver-1").unwrap(),
            150,
            400,
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
            &empty_policy(MutationApprovalRequirement::Required),
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
                &empty_policy(MutationApprovalRequirement::Required),
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
            .record(&identity(WorkContextKind::Project, "project-1"))
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
    store
        .put_authoritative_record(&project("project-1", 1, WorkContextLifecycle::Active))
        .unwrap();
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
    store.put_authoritative_record(&checkout).unwrap();
    store
        .put_authoritative_record(&user_workspace("workspace-1", "project-1", "checkout-1", 1))
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
                &empty_policy(MutationApprovalRequirement::NotRequired),
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
            &empty_policy(MutationApprovalRequirement::NotRequired),
            ReceiptId::new("receipt-attempt").unwrap(),
            21,
        )
        .unwrap();
    assert!(
        matches!(accepted,ReceiptAdmission::New(ref value) if value.outcome()==automonique_protocol::platform::ReceiptOutcome::Accepted)
    );
    assert_eq!(store.ready_outbox_count().unwrap(), 1);
    assert!(
        store
            .record(preview.resulting().identity())
            .unwrap()
            .is_none()
    );
    drop(store);
    let mut reopened = WorkContextStore::open(private.path()).unwrap();
    let completed = reopened
        .complete_external_effect(preview.preview(), 30)
        .unwrap();
    assert_eq!(
        completed.outcome(),
        automonique_protocol::platform::ReceiptOutcome::Completed
    );
    assert_eq!(reopened.ready_outbox_count().unwrap(), 0);
    assert_eq!(
        reopened
            .record(preview.resulting().identity())
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
        store.put_authoritative_record(&record).unwrap();
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
    let changed_identity = allowed.iter().next().unwrap().clone();
    store
        .put_authoritative_record(&project(
            changed_identity.id(),
            2,
            WorkContextLifecycle::Active,
        ))
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
