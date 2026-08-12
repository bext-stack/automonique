// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::{
    InboxSubmission, LeaseRenewal, LeaseRequest, SCHEMA_VERSION, SchedulerClaim, Store,
    TerminalRun, TerminalState, WorkClaim,
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

fn submit(store: &mut Store, key: &str, scope: &str) -> i64 {
    submit_at(store, key, scope, 1)
}

fn submit_at(store: &mut Store, key: &str, scope: &str, received_ms: i64) -> i64 {
    store
        .submit_inbox(InboxSubmission {
            transport: "local-test",
            transport_key: key,
            scope,
            payload: b"payload",
            received_ms,
        })
        .expect("submit")
        .inbox_id
}

fn claim_next(
    store: &mut Store,
    holder: &str,
    epoch: u64,
    now_ms: i64,
) -> Option<automonique_store::ScheduledRun> {
    store
        .claim_next(SchedulerClaim {
            transport: "local-test",
            generation_id: "generation-a",
            holder_id: holder,
            lease_epoch: epoch,
            now_ms,
        })
        .expect("scheduler claim")
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

fn finish_scheduled(store: &mut Store, run_id: i64, epoch: u64, now_ms: i64, suffix: &str) {
    let intent = format!("intent:{suffix}");
    store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: suffix.as_bytes(),
            outbox_intent_key: &intent,
            outbox_kind: "test.effect",
            outbox_payload: suffix.as_bytes(),
        })
        .expect("finish scheduled run");
}

#[test]
fn open_requires_private_owned_paths_and_refuses_unknown_schema() {
    let database = PrivateDatabase::new();
    let store = Store::open(database.path()).expect("open private database");
    assert_eq!(store.path(), database.path());
    drop(store);

    let connection = Connection::open(database.path()).expect("raw reopen");
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
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
    let inbox_id = submit(&mut store, "delivery-reopen", "scope:reopen");
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
            scope: "scope:reopen",
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
            scope: "scope:duplicate",
            payload: b"first",
            received_ms: 10,
        })
        .expect("first submit");
    let retry = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: "team:event:42",
            scope: "scope:duplicate",
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
            scope: "scope:duplicate",
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

    let inbox_a = submit(&mut first, "delivery-a", "tenant:one");
    let inbox_b = submit(&mut second, "delivery-b", "tenant:one");
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
    let inbox_id = submit(&mut store, "delivery-stale", "tenant:stale");
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
    let first_inbox = submit(&mut store, "delivery-renewed-lock-first", "scope:renewed");
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

    let second_inbox = submit(&mut store, "delivery-renewed-lock-second", "scope:renewed");
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
    let first_inbox = submit(&mut store, "delivery-reconcile-first", "scope:reconcile");
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
    let second_inbox = submit(&mut store, "delivery-reconcile-second", "scope:reconcile");
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
    let inbox_id = submit(&mut store, "delivery-release", "scope:release");
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

    let next_inbox = submit(&mut store, "delivery-release-next", "scope:release");
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
    let first_inbox = submit(&mut store, "delivery-first", "scope:first");
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

    let second_inbox = submit(&mut store, "delivery-second", "scope:second");
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
    let claimed_inbox = submit(&mut store, "delivery-status-claimed", "scope:status");
    let run_id = claim(
        &mut store,
        claimed_inbox,
        epoch,
        "claim-status",
        "scope:status",
    );
    submit(&mut store, "delivery-status-pending", "scope:pending");

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

#[test]
fn scheduler_claims_fifo_and_exposes_only_the_claimed_owned_payload() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let later = submit_at(&mut store, "fifo-later", "scope:later", 20);
    let first = submit_at(&mut store, "fifo-first", "scope:first-fifo", 10);
    let tied = submit_at(&mut store, "fifo-tied", "scope:tied", 10);

    let first_claim = claim_next(&mut store, "holder-a", epoch, 21).expect("first FIFO claim");
    assert_eq!(first_claim.inbox_id, first);
    let payload = store
        .claimed_inbox(first_claim.run_id, "generation-a", "holder-a", epoch, 22)
        .expect("claimed payload");
    assert_eq!(payload.payload, b"payload");
    assert_eq!(payload.scope, "scope:first-fifo");
    finish_scheduled(&mut store, first_claim.run_id, epoch, 23, "first");
    let tied_claim = claim_next(&mut store, "holder-a", epoch, 24).expect("tied FIFO claim");
    assert_eq!(tied_claim.inbox_id, tied);
    finish_scheduled(&mut store, tied_claim.run_id, epoch, 25, "tied");
    assert_eq!(
        claim_next(&mut store, "holder-a", epoch, 26)
            .expect("later FIFO claim")
            .inbox_id,
        later
    );
}

#[test]
fn scheduler_transport_filter_never_claims_an_older_foreign_input() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let foreign = store
        .submit_inbox(InboxSubmission {
            transport: "provider.foreign",
            transport_key: "foreign-oldest",
            scope: "scope:foreign",
            payload: b"foreign",
            received_ms: 1,
        })
        .expect("foreign input")
        .inbox_id;
    let synthetic = store
        .submit_inbox(InboxSubmission {
            transport: "local.synthetic",
            transport_key: "synthetic-newer",
            scope: "scope:synthetic",
            payload: b"synthetic",
            received_ms: 2,
        })
        .expect("synthetic input")
        .inbox_id;

    let claim = store
        .claim_next(SchedulerClaim {
            transport: "local.synthetic",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 3,
        })
        .expect("filtered scheduler claim")
        .expect("synthetic pending row");
    assert_eq!(claim.inbox_id, synthetic);
    assert_ne!(claim.inbox_id, foreign);
    assert_eq!(
        store
            .claimed_inbox(claim.run_id, "generation-a", "holder-a", epoch, 4)
            .expect("claimed synthetic payload")
            .transport,
        "local.synthetic"
    );
    assert_eq!(
        store
            .status_snapshot("generation-a")
            .expect("status")
            .inbox_pending,
        1,
        "foreign input remains pending"
    );
    assert!(
        store
            .claim_next(SchedulerClaim {
                transport: "provider.absent",
                generation_id: "generation-a",
                holder_id: "holder-a",
                lease_epoch: epoch,
                now_ms: 5,
            })
            .expect("absent transport query")
            .is_none()
    );
}

#[test]
fn scheduler_is_exactly_once_across_connections_and_stable_retry() {
    let database = PrivateDatabase::new();
    let mut first = Store::open(database.path()).expect("first connection");
    let mut second = Store::open(database.path()).expect("second connection");
    let epoch = lease(&mut first, "holder-a", 0);
    let inbox_id = submit(&mut first, "once", "scope:once");
    let claimed = claim_next(&mut first, "holder-a", epoch, 2).expect("first claim");
    assert_eq!(claimed.inbox_id, inbox_id);
    let retry = claim_next(&mut second, "holder-a", epoch, 3).expect("stable retry");
    assert_eq!(retry.run_id, claimed.run_id);
    assert!(retry.duplicate);
}

#[test]
fn scheduler_serializes_fifo_and_preserves_reconciliation_owned_work() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let oldest = submit_at(&mut store, "shared-first", "scope:shared", 1);
    let blocked = submit_at(&mut store, "shared-second", "scope:shared", 2);
    submit_at(&mut store, "free", "scope:free", 3);
    assert_eq!(
        claim_next(&mut store, "holder-a", old_epoch, 4)
            .expect("oldest")
            .inbox_id,
        oldest
    );
    let replay = claim_next(&mut store, "holder-a", old_epoch, 5).expect("replay oldest");
    assert_eq!(replay.inbox_id, oldest);
    assert!(replay.duplicate);

    let new_epoch = lease(&mut store, "holder-b", 101);
    let error = store
        .claim_next(SchedulerClaim {
            transport: "local-test",
            generation_id: "generation-a",
            holder_id: "holder-b",
            lease_epoch: new_epoch,
            now_ms: 102,
        })
        .expect_err("expired work remains reconciliation-owned");
    assert_eq!(error.category(), "reconciliation_required");
    assert_eq!(
        store
            .status_snapshot("generation-a")
            .expect("status")
            .inbox_pending,
        2
    );
    assert!(blocked > oldest);
}

#[test]
fn scheduler_and_claimed_payload_survive_reopen_and_stale_epochs_refuse() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let inbox_id = submit(&mut store, "restart-pending", "scope:restart");
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen pending");
    let claim = claim_next(&mut reopened, "holder-a", old_epoch, 2).expect("claim after reopen");
    assert_eq!(claim.inbox_id, inbox_id);
    drop(reopened);

    let mut reopened = Store::open(database.path()).expect("reopen claimed");
    assert_eq!(
        reopened
            .claimed_inbox(claim.run_id, "generation-a", "holder-a", old_epoch, 3,)
            .expect("payload after reopen")
            .inbox_id,
        inbox_id
    );
    let new_epoch = lease(&mut reopened, "holder-b", 101);
    let stale = reopened
        .claim_next(SchedulerClaim {
            transport: "local-test",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old_epoch,
            now_ms: 102,
        })
        .expect_err("stale scheduler epoch");
    assert_eq!(stale.category(), "stale_epoch");
    assert_eq!(new_epoch, old_epoch + 1);
}

#[test]
fn scheduler_terminal_retry_never_duplicates_run_event_or_outbox() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    submit(&mut store, "terminal-scheduled", "scope:terminal-scheduled");
    let next_inbox = submit(&mut store, "terminal-next", "scope:terminal-next");
    let claim = claim_next(&mut store, "holder-a", epoch, 2).expect("scheduled run");
    let terminal = || TerminalRun {
        run_id: claim.run_id,
        generation_id: "generation-a",
        holder_id: "holder-a",
        lease_epoch: epoch,
        expected_revision: 1,
        now_ms: 3,
        state: TerminalState::Succeeded,
        event_kind: "run.succeeded",
        event_payload: b"scheduled-result",
        outbox_intent_key: "scheduled-intent",
        outbox_kind: "provider.reply",
        outbox_payload: b"scheduled-reply",
    };
    let first = store.finish_run(terminal()).expect("terminal commit");
    let event_count = store.event_count().expect("event count");
    let outbox_count = store.outbox_count().expect("outbox count");
    let retry = store.finish_run(terminal()).expect("terminal retry");
    assert!(retry.duplicate);
    assert_eq!(retry.event_id, first.event_id);
    assert_eq!(retry.outbox_id, first.outbox_id);
    assert_eq!(store.event_count().expect("events stable"), event_count);
    assert_eq!(store.outbox_count().expect("outbox stable"), outbox_count);
    let recovered = store
        .terminal_receipt(claim.run_id, "scheduled-intent")
        .expect("receipt after ambiguous commit");
    assert_eq!(recovered.event_id, first.event_id);
    assert_eq!(recovered.outbox_id, first.outbox_id);
    assert!(recovered.duplicate);
    assert_eq!(
        claim_next(&mut store, "holder-a", epoch, 4)
            .expect("advance after recovered terminal")
            .inbox_id,
        next_inbox
    );
}
