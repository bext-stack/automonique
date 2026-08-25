// SPDX-License-Identifier: Elastic-2.0

//! Restart, retry, cursor, and controller invariants for platform v1.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use automonique_protocol::platform::{
    ClientId, ExecuteRequest, Freshness, FreshnessState, IdempotencyKey, PlatformAction,
    PlatformCursor, PlatformText, ReceiptOutcome, ResourceAuthority, ResourceCoordinate,
    ResourceId, ResourceKind, ResourceRecord,
};
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_store::platform_store::{ActionAdmission, ControlAdmission, PlatformStore};
use tempfile::TempDir;

struct PrivateStore {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateStore {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("platform.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("nonzero revision")
}

fn coordinate(kind: ResourceKind, id: &str) -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        kind,
        ResourceId::new(id).expect("resource id"),
    )
}

fn run(id: &str) -> ResourceCoordinate {
    coordinate(ResourceKind::Run, id)
}

fn session(id: &str) -> ResourceCoordinate {
    coordinate(ResourceKind::Session, id)
}

fn execute(key: &str, expected: Option<u64>) -> ExecuteRequest {
    ExecuteRequest::new(
        PlatformAction::StopRun,
        run("run-1"),
        IdempotencyKey::new(key).expect("idempotency key"),
        expected.map(revision),
        None,
    )
    .expect("valid execute request")
}

fn record(kind: ResourceKind, id: &str, rev: u64, observed: i64, summary: &str) -> ResourceRecord {
    ResourceRecord {
        resource: coordinate(kind, id),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(observed),
            revision: revision(rev),
        },
        summary: PlatformText::new(summary).expect("summary"),
    }
}

#[test]
fn duplicate_execute_replays_one_durable_receipt() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let request = execute("stop-run-once", Some(7));

    let ActionAdmission::New(accepted) = store
        .prepare_execute(&request, revision(7), 1_000)
        .expect("admit action")
    else {
        panic!("first action must be new");
    };
    let completed = store
        .finalize_execute(
            &request.idempotency_key,
            ReceiptOutcome::Completed,
            None,
            1_001,
        )
        .expect("finalize action");
    assert_eq!(completed.id, accepted.id);

    drop(store);
    let mut reopened = PlatformStore::open(private.path()).expect("reopen store");
    let ActionAdmission::Replay(replayed) = reopened
        .prepare_execute(&request, revision(7), 2_000)
        .expect("replay action")
    else {
        panic!("retry must replay");
    };
    assert_eq!(replayed, completed);
    assert_eq!(
        reopened
            .receipt(None, Some(&request.idempotency_key), None)
            .expect("receipt by key"),
        completed
    );
    assert_eq!(
        reopened
            .receipt(Some(&completed.id), None, None)
            .expect("receipt by id"),
        completed
    );

    let receipts = reopened
        .subscribe(None, "receipts")
        .expect("receipt events");
    assert_eq!(receipts.events.len(), 2, "accepted and completed only");
}

#[test]
fn mobile_receipt_owner_is_bound_atomically_and_lookups_do_not_cross_credentials() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let owner = ClientId::new("credential-1").expect("owner");
    let other = ClientId::new("credential-2").expect("other");
    let request = execute("owned-receipt", Some(7)).with_client(owner.clone());
    store
        .prepare_execute(&request, revision(7), 1_000)
        .expect("admit action");
    let receipt = store
        .finalize_execute(
            &request.idempotency_key,
            ReceiptOutcome::Completed,
            None,
            1_001,
        )
        .expect("finalize");
    assert_eq!(
        store
            .receipt(Some(&receipt.id), None, Some(&owner))
            .unwrap(),
        receipt
    );
    assert_eq!(
        store
            .receipt(Some(&receipt.id), None, Some(&other))
            .unwrap_err()
            .category(),
        "not_found"
    );
}

#[test]
fn session_bound_receipt_replay_requires_the_exact_owner_and_revision_after_restart() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let owner = ClientId::new("credential-1").expect("owner");
    let request = execute("session-owned-receipt", Some(11)).with_client(owner);
    let owning_session = session("session-1");

    let ActionAdmission::New(first) = store
        .prepare_session_execute(&request, revision(11), &owning_session, revision(3), 1_000)
        .expect("admit session action")
    else {
        panic!("first admission must be new");
    };
    drop(store);

    let mut reopened = PlatformStore::open(private.path()).expect("reopen store");
    let ActionAdmission::Replay(replay) = reopened
        .prepare_session_execute(&request, revision(11), &owning_session, revision(3), 2_000)
        .expect("exact replay")
    else {
        panic!("exact retry must replay");
    };
    assert_eq!(replay, first);

    assert_eq!(
        reopened
            .prepare_session_execute(&request, revision(11), &owning_session, revision(4), 2_001,)
            .expect_err("changed session revision conflicts")
            .category(),
        "conflict"
    );
    assert_eq!(
        reopened
            .prepare_session_execute(
                &request,
                revision(11),
                &session("session-2"),
                revision(3),
                2_002,
            )
            .expect_err("changed owner conflicts")
            .category(),
        "conflict"
    );
    assert_eq!(
        reopened
            .prepare_execute(&request, revision(11), 2_003)
            .expect_err("generic replay cannot shed the owner binding")
            .category(),
        "conflict"
    );
}

#[test]
fn concurrent_session_command_retries_admit_one_effect_and_replay_one_receipt() {
    let private = PrivateStore::new();
    let stores = [
        PlatformStore::open(private.path()).expect("open first store"),
        PlatformStore::open(private.path()).expect("open second store"),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let handles = stores.map(|mut store| {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let owner = ClientId::new("credential-1").expect("owner");
            let request = execute("concurrent-session-command", Some(11)).with_client(owner);
            let owning_session = session("session-1");
            barrier.wait();
            store
                .prepare_session_execute(
                    &request,
                    revision(11),
                    &owning_session,
                    revision(3),
                    1_000,
                )
                .expect("concurrent admission")
        })
    });

    barrier.wait();
    let admissions = handles.map(|handle| handle.join().expect("admission thread"));
    assert_eq!(
        admissions
            .iter()
            .filter(|value| matches!(value, ActionAdmission::New(_)))
            .count(),
        1,
        "exactly one retry may own the effect",
    );
    assert_eq!(
        admissions
            .iter()
            .filter(|value| matches!(value, ActionAdmission::Replay(_)))
            .count(),
        1,
        "the losing retry must replay the durable receipt",
    );
    let receipt = match &admissions[0] {
        ActionAdmission::New(value) | ActionAdmission::Replay(value) => value,
    };
    let other = match &admissions[1] {
        ActionAdmission::New(value) | ActionAdmission::Replay(value) => value,
    };
    assert_eq!(receipt, other, "both retries must observe the same receipt");
}

#[test]
fn idempotency_binding_conflict_and_stale_revision_write_nothing() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let request = execute("bound-key", Some(4));
    store
        .prepare_execute(&request, revision(4), 1_000)
        .expect("first request");
    let after_first = store.revision().expect("revision");

    let mut different = execute("bound-key", Some(4));
    different.target = run("run-2");
    assert_eq!(
        store
            .prepare_execute(&different, revision(4), 1_001)
            .expect_err("binding conflict")
            .category(),
        "conflict"
    );
    assert_eq!(store.revision().expect("revision"), after_first);

    let stale = execute("stale-key", Some(3));
    assert_eq!(
        store
            .prepare_execute(&stale, revision(4), 1_002)
            .expect_err("stale revision")
            .category(),
        "stale_revision"
    );
    assert_eq!(store.revision().expect("revision"), after_first);
    assert_eq!(
        store
            .receipt(None, Some(&stale.idempotency_key), None)
            .expect_err("no stale receipt")
            .category(),
        "not_found"
    );
}

#[test]
fn snapshot_cursor_and_subscription_are_ordered_and_topic_scoped() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let (_, empty_cursor) = store.snapshot(&[], "runs").expect("empty snapshot");
    assert_eq!(empty_cursor.sequence.get(), 1);

    store
        .upsert_resource("runs", &record(ResourceKind::Run, "run-1", 1, 10, "queued"))
        .expect("first resource");
    store
        .upsert_resource(
            "sessions",
            &record(ResourceKind::Session, "session-1", 1, 11, "ready"),
        )
        .expect("other topic");
    store
        .upsert_resource(
            "runs",
            &record(ResourceKind::Run, "run-1", 2, 12, "running"),
        )
        .expect("run update");

    let page = store
        .subscribe(Some(&empty_cursor), "runs")
        .expect("run changes");
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].resource.summary.as_str(), "queued");
    assert_eq!(page.events[1].resource.summary.as_str(), "running");
    assert_eq!(
        page.events[1].cursor.sequence.get(),
        page.events[0].cursor.sequence.get() + 1,
        "a topic stream is gap-free even when other topics change"
    );

    let (_, cursor_before_observation_refresh) = store.snapshot(&[], "runs").expect("snapshot");
    store
        .upsert_resource(
            "runs",
            &record(ResourceKind::Run, "run-1", 2, 99, "running"),
        )
        .expect("observation refresh");
    let no_semantic_change = store
        .subscribe(Some(&cursor_before_observation_refresh), "runs")
        .expect("no event");
    assert!(no_semantic_change.events.is_empty());
}

#[test]
fn cursor_from_another_stream_or_the_future_requires_resync() {
    let private = PrivateStore::new();
    let store = PlatformStore::open(private.path()).expect("open store");
    let (_, cursor) = store.snapshot(&[], "runs").expect("snapshot");
    let wrong_topic = PlatformCursor {
        topic: automonique_protocol::platform::CursorTopic::new("sessions").expect("topic"),
        ..cursor.clone()
    };
    assert_eq!(
        store
            .subscribe(Some(&wrong_topic), "runs")
            .expect_err("wrong topic")
            .category(),
        "resync_required"
    );
    let future = PlatformCursor {
        sequence: revision(cursor.sequence.get() + 1),
        ..cursor
    };
    assert_eq!(
        store
            .subscribe(Some(&future), "runs")
            .expect_err("future cursor")
            .category(),
        "resync_required"
    );
}

#[test]
fn attachments_are_observational_and_allow_multiple_clients() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let target = session("session-1");
    let client_a = ClientId::new("client-a").expect("client");
    let client_b = ClientId::new("client-b").expect("client");

    let a = store
        .attach(&target, &client_a, 1_000, "sessions")
        .expect("attach a");
    let b = store
        .attach(&target, &client_b, 1_001, "sessions")
        .expect("attach b");
    assert_eq!(a.session, b.session);
    assert_ne!(a.client, b.client);
    store.detach(&target, &client_a).expect("detach a");
    store.detach(&target, &client_a).expect("idempotent detach");
}

#[test]
fn controller_is_exclusive_retryable_expiring_and_releasable() {
    let private = PrivateStore::new();
    let mut store = PlatformStore::open(private.path()).expect("open store");
    let target = session("session-1");
    let client_a = ClientId::new("client-a").expect("client");
    let client_b = ClientId::new("client-b").expect("client");
    let key_a = IdempotencyKey::new("claim-a").expect("key");

    let ControlAdmission::New(lease_a) = store
        .claim_control(&target, &client_a, &key_a, 1_000)
        .expect("claim a")
    else {
        panic!("first claim must be new");
    };
    let ControlAdmission::Replay(replay_a) = store
        .claim_control(&target, &client_a, &key_a, 1_001)
        .expect("replay claim")
    else {
        panic!("retry must replay");
    };
    assert_eq!(replay_a, lease_a);
    assert_eq!(
        store
            .active_control(&lease_a.id, 1_001)
            .expect("active control"),
        Some(lease_a.clone())
    );
    assert!(
        store
            .active_control(&lease_a.id, lease_a.expires_at.as_millis())
            .expect("expired control")
            .is_none()
    );

    let key_b = IdempotencyKey::new("claim-b").expect("key");
    assert_eq!(
        store
            .claim_control(&target, &client_b, &key_b, 1_002)
            .expect_err("active controller")
            .category(),
        "conflict"
    );
    let ControlAdmission::New(lease_b) = store
        .claim_control(&target, &client_b, &key_b, lease_a.expires_at.as_millis())
        .expect("take over expired lease")
    else {
        panic!("expired takeover must be new");
    };
    assert_ne!(lease_b.id, lease_a.id);

    let release_key = IdempotencyKey::new("release-b").expect("key");
    store
        .release_control(
            &target,
            &client_b,
            &lease_b.id,
            &release_key,
            lease_b.expires_at.as_millis() - 1,
        )
        .expect("release");
    store
        .release_control(
            &target,
            &client_b,
            &lease_b.id,
            &release_key,
            lease_b.expires_at.as_millis(),
        )
        .expect("idempotent release");
    assert!(
        store
            .active_control(&lease_b.id, lease_b.expires_at.as_millis() - 1)
            .expect("released control")
            .is_none()
    );
}
