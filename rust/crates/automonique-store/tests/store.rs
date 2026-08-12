// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::{
    InboxSubmission, LeaseRenewal, LeaseRequest, Store, TerminalRun, TerminalState, WorkClaim,
};
use rusqlite::Connection;
use tempfile::TempDir;

struct PrivateDatabase {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateDatabase {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("product.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn lease(store: &mut Store, holder: &str, now_ms: i64) -> u64 {
    store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: holder,
            now_ms,
            ttl_ms: 100,
        })
        .expect("lease")
        .epoch
}

fn submit(store: &mut Store, key: &str) -> i64 {
    store
        .submit_inbox(InboxSubmission {
            transport: "local-test",
            transport_key: key,
            payload: b"payload",
            received_ms: 1,
        })
        .expect("submit")
        .inbox_id
}

fn claim(store: &mut Store, inbox_id: i64, epoch: u64, key: &str, scope: &str) -> i64 {
    store
        .claim_work(WorkClaim {
            claim_key: key,
            inbox_id,
            scope,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 2,
        })
        .expect("claim")
        .run_id
}

#[test]
fn open_requires_private_owned_paths_and_refuses_unknown_schema() {
    let database = PrivateDatabase::new();
    let store = Store::open(database.path()).expect("open private database");
    assert_eq!(store.path(), database.path());
    drop(store);

    let connection = Connection::open(database.path()).expect("raw reopen");
    connection
        .pragma_update(None, "user_version", 2)
        .expect("change version");
    drop(connection);
    let error = Store::open(database.path()).err().expect("version refusal");
    assert_eq!(error.category(), "schema_version");

    let public = tempfile::tempdir().expect("public temporary directory");
    fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755))
        .expect("public permissions");
    let error = Store::open(public.path().join("db.sqlite3"))
        .err()
        .expect("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn reopen_preserves_wal_foreign_keys_and_durable_rows() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let first_epoch = lease(&mut store, "holder-a", 0);
    let inbox_id = submit(&mut store, "delivery-reopen");
    assert_eq!(first_epoch, 1);
    assert!(inbox_id > 0);
    let events = store.event_count().expect("events");
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen");
    assert_eq!(reopened.event_count().expect("events after reopen"), events);
    let same = reopened
        .submit_inbox(InboxSubmission {
            transport: "local-test",
            transport_key: "delivery-reopen",
            payload: b"payload",
            received_ms: 99,
        })
        .expect("stable retry");
    assert_eq!(same.inbox_id, inbox_id);
    assert!(same.duplicate);

    let raw = Connection::open(database.path()).expect("inspect pragmas");
    let journal: String = raw
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal, "wal");
    // Foreign-key enforcement is connection-local; Store establishes it on every open.
    reopened
        .claim_work(WorkClaim {
            claim_key: "missing-inbox",
            inbox_id: inbox_id + 99,
            scope: "scope-missing",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: first_epoch,
            now_ms: 2,
        })
        .expect_err("missing referenced inbox");
}

#[test]
fn duplicate_submit_is_stable_and_changed_payload_is_refused() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let original = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: "team:event:42",
            payload: b"first",
            received_ms: 10,
        })
        .expect("first submit");
    let retry = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: "team:event:42",
            payload: b"first",
            received_ms: 20,
        })
        .expect("retry");
    assert_eq!(retry.inbox_id, original.inbox_id);
    assert!(retry.duplicate);
    assert_eq!(store.event_count().expect("events"), 1);

    let error = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: "team:event:42",
            payload: b"changed",
            received_ms: 30,
        })
        .expect_err("changed delivery refused");
    assert_eq!(error.category(), "idempotency_conflict");
    assert_eq!(store.event_count().expect("events unchanged"), 1);
}

#[test]
fn competing_connections_are_serialized_by_lease_and_scope() {
    let database = PrivateDatabase::new();
    let mut first = Store::open(database.path()).expect("first connection");
    let mut second = Store::open(database.path()).expect("second connection");
    let epoch = lease(&mut first, "holder-a", 0);
    let error = second
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-b",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect_err("live lease excludes competitor");
    assert_eq!(error.category(), "lease_held");

    let inbox_a = submit(&mut first, "delivery-a");
    let inbox_b = submit(&mut second, "delivery-b");
    let run_id = claim(&mut first, inbox_a, epoch, "claim-a", "tenant:one");
    assert!(run_id > 0);
    let error = second
        .claim_work(WorkClaim {
            claim_key: "claim-b",
            inbox_id: inbox_b,
            scope: "tenant:one",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 3,
        })
        .expect_err("scope excludes competitor");
    assert_eq!(error.category(), "scope_locked");
}

#[test]
fn expired_epoch_cannot_renew_claim_or_finish() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let inbox_id = submit(&mut store, "delivery-stale");
    let run_id = claim(
        &mut store,
        inbox_id,
        old_epoch,
        "claim-stale",
        "tenant:stale",
    );

    let new_epoch = lease(&mut store, "holder-b", 101);
    assert_eq!(new_epoch, old_epoch + 1);
    let renewal = store
        .renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: old_epoch,
            now_ms: 102,
            ttl_ms: 100,
        })
        .expect_err("old renewal refused");
    assert_eq!(renewal.category(), "stale_epoch");
    let finish = store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old_epoch,
            expected_revision: 1,
            now_ms: 102,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"done",
            outbox_intent_key: "notify-stale",
            outbox_kind: "notify",
            outbox_payload: b"message",
        })
        .expect_err("old finish refused");
    assert_eq!(finish.category(), "stale_epoch");
    assert_eq!(store.run_snapshot(run_id).expect("run").state, "running");
}

#[test]
fn renewal_extends_matching_work_locks_transactionally() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let first_inbox = submit(&mut store, "delivery-renewed-lock-first");
    let run_id = claim(
        &mut store,
        first_inbox,
        epoch,
        "claim-renewed-lock-first",
        "scope:renewed",
    );
    store
        .renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch,
            now_ms: 50,
            ttl_ms: 200,
        })
        .expect("renew generation and its work locks");

    let second_inbox = submit(&mut store, "delivery-renewed-lock-second");
    let error = store
        .claim_work(WorkClaim {
            claim_key: "claim-renewed-lock-second",
            inbox_id: second_inbox,
            scope: "scope:renewed",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 101,
        })
        .expect_err("renewed scope lock remains live past its original expiry");
    assert_eq!(error.category(), "scope_locked");
    assert_eq!(
        store.run_snapshot(run_id).expect("original run").state,
        "running"
    );
}

#[test]
fn expired_scope_requires_reconciliation_without_mutation() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let first_inbox = submit(&mut store, "delivery-reconcile-first");
    let old_run = claim(
        &mut store,
        first_inbox,
        old_epoch,
        "claim-reconcile-first",
        "scope:reconcile",
    );
    let events_before = store
        .event_count()
        .expect("events before reconciliation refusal");
    let new_epoch = lease(&mut store, "holder-b", 101);
    let second_inbox = submit(&mut store, "delivery-reconcile-second");
    let events_after_setup = store.event_count().expect("events after setup");
    let error = store
        .claim_work(WorkClaim {
            claim_key: "claim-reconcile-second",
            inbox_id: second_inbox,
            scope: "scope:reconcile",
            generation_id: "generation-a",
            holder_id: "holder-b",
            lease_epoch: new_epoch,
            now_ms: 102,
        })
        .expect_err("expired run cannot be abandoned by a new claim");
    assert_eq!(error.category(), "reconciliation_required");
    assert!(error.to_string().contains(&old_run.to_string()));
    assert_eq!(
        store.run_snapshot(old_run).expect("old run").state,
        "running"
    );
    assert!(
        store
            .scope_is_locked("scope:reconcile")
            .expect("lock retained")
    );
    assert_eq!(
        store.event_count().expect("events after refusal"),
        events_after_setup
    );
    assert!(events_after_setup > events_before);
}

#[test]
fn exact_fenced_release_allows_immediate_new_epoch_without_erasing_work() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let inbox_id = submit(&mut store, "delivery-release");
    let run_id = claim(
        &mut store,
        inbox_id,
        epoch,
        "claim-release",
        "scope:release",
    );
    store
        .release_generation_lease("generation-a", "holder-a", epoch, 10)
        .expect("exact release");

    let stale = store
        .release_generation_lease("generation-a", "holder-a", epoch, 10)
        .expect_err("released epoch is no longer live");
    assert_eq!(stale.category(), "stale_epoch");
    let new_epoch = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-b",
            now_ms: 10,
            ttl_ms: 100,
        })
        .expect("immediate replacement lease")
        .epoch;
    assert_eq!(new_epoch, epoch + 1);
    assert_eq!(
        store.run_snapshot(run_id).expect("run retained").state,
        "running"
    );
    assert!(
        store
            .scope_is_locked("scope:release")
            .expect("lock retained")
    );

    let next_inbox = submit(&mut store, "delivery-release-next");
    let refusal = store
        .claim_work(WorkClaim {
            claim_key: "claim-release-next",
            inbox_id: next_inbox,
            scope: "scope:release",
            generation_id: "generation-a",
            holder_id: "holder-b",
            lease_epoch: new_epoch,
            now_ms: 11,
        })
        .expect_err("released work requires reconciliation");
    assert_eq!(refusal.category(), "reconciliation_required");
}

#[test]
fn terminal_run_event_and_outbox_are_atomic_and_retryable() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let first_inbox = submit(&mut store, "delivery-first");
    let first_run = claim(&mut store, first_inbox, epoch, "claim-first", "scope:first");
    let first = store
        .finish_run(TerminalRun {
            run_id: first_run,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 3,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"result:first",
            outbox_intent_key: "intent-shared",
            outbox_kind: "provider.reply",
            outbox_payload: b"reply:first",
        })
        .expect("terminal commit");
    assert!(!first.duplicate);
    assert_eq!(
        store.run_snapshot(first_run).expect("first run").revision,
        2
    );

    let duplicate = store
        .finish_run(TerminalRun {
            run_id: first_run,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 4,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"result:first",
            outbox_intent_key: "intent-shared",
            outbox_kind: "provider.reply",
            outbox_payload: b"reply:first",
        })
        .expect("terminal retry");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.event_id, first.event_id);
    assert_eq!(duplicate.outbox_id, first.outbox_id);

    let second_inbox = submit(&mut store, "delivery-second");
    let second_run = claim(
        &mut store,
        second_inbox,
        epoch,
        "claim-second",
        "scope:second",
    );
    let events_before = store.event_count().expect("events before conflict");
    let outbox_before = store.outbox_count().expect("outbox before conflict");
    let error = store
        .finish_run(TerminalRun {
            run_id: second_run,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 5,
            state: TerminalState::Failed,
            event_kind: "run.failed",
            event_payload: b"result:second",
            outbox_intent_key: "intent-shared",
            outbox_kind: "provider.reply",
            outbox_payload: b"reply:second",
        })
        .expect_err("duplicate outbox key rolls transaction back");
    assert_eq!(error.category(), "outbox_conflict");
    assert_eq!(
        store.run_snapshot(second_run).expect("second run").state,
        "running"
    );
    assert!(
        store
            .scope_is_locked("scope:second")
            .expect("lock retained")
    );
    assert_eq!(
        store.event_count().expect("events after conflict"),
        events_before
    );
    assert_eq!(
        store.outbox_count().expect("outbox after conflict"),
        outbox_before
    );
}

#[test]
fn status_snapshot_counts_pending_terminal_and_outbox_state() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let claimed_inbox = submit(&mut store, "delivery-status-claimed");
    let run_id = claim(
        &mut store,
        claimed_inbox,
        epoch,
        "claim-status",
        "scope:status",
    );
    submit(&mut store, "delivery-status-pending");

    let running = store
        .status_snapshot("generation-a")
        .expect("running snapshot");
    assert_eq!(running.inbox_pending, 1);
    assert_eq!(running.outbox_pending, 0);
    assert_eq!(running.runs_running, 1);
    assert_eq!(running.generation.expect("generation").lease_epoch, epoch);

    let terminal = store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 3,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"result:status",
            outbox_intent_key: "intent-status",
            outbox_kind: "provider.reply",
            outbox_payload: b"reply:status",
        })
        .expect("terminal transition");
    let finished = store
        .status_snapshot("generation-a")
        .expect("terminal snapshot");
    assert_eq!(finished.inbox_pending, 1);
    assert_eq!(finished.outbox_pending, 1);
    assert_eq!(finished.runs_running, 0);
    assert_eq!(
        finished.event_cursor,
        u64::try_from(terminal.event_id).unwrap()
    );
}
