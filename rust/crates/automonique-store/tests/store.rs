// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::{
    InboxSubmission, LeaseRenewal, LeaseRequest, ReconciliationDecision, ReconciliationInboxState,
    ReconciliationRequest, ReconciliationRunState, SCHEMA_VERSION, SchedulerClaim, Store,
    TelegramBatchIngestion, TelegramStoreDisposition, TelegramStoreUpdate, TerminalRun,
    TerminalState, WorkClaim,
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

fn telegram_update<'a>(
    update_id: u64,
    source_key: &'a str,
    scope: &'a str,
    disposition: TelegramStoreDisposition<'a>,
) -> TelegramStoreUpdate<'a> {
    TelegramStoreUpdate {
        update_id,
        source_key,
        scope,
        disposition,
    }
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

#[test]
fn reconciliation_discovers_old_epoch_and_accepts_live_successor_authority() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    submit(&mut store, "reconcile-evidence", "scope:evidence");
    let claim = claim_next(&mut store, "holder-a", old_epoch, 2).expect("claim");
    let evidence = store
        .inspect_reconciliation(claim.run_id)
        .expect("reconciliation evidence");
    assert_eq!(evidence.run_state, ReconciliationRunState::Running);
    assert_eq!(evidence.inbox_state, ReconciliationInboxState::Claimed);
    assert_eq!(evidence.inbox_revision, 2);
    assert_eq!(evidence.claimed_run_id, Some(claim.run_id));
    assert_eq!(evidence.generation_id, "generation-a");
    assert_eq!(evidence.lease_epoch, old_epoch);
    assert_eq!(evidence.lock_generation_id.as_deref(), Some("generation-a"));
    assert_eq!(evidence.lock_epoch, Some(old_epoch));
    assert_eq!(evidence.lock_expires_ms, Some(100));
    assert!(!evidence.terminal_payload_present);
    assert!(evidence.outbox_intent_key.is_none());
    assert_eq!(evidence.outbox_count, 0);

    let live = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-a",
            authority_lease_epoch: old_epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-live",
            now_ms: 3,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("live work cannot be reconciled");
    assert_eq!(live.category(), "lease_held");

    lease(&mut store, "holder-b", 101);
    let stale_authority = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-a",
            authority_lease_epoch: old_epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-stale-authority",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("stale operator authority refused");
    assert_eq!(stale_authority.category(), "stale_epoch");
    let wrong_authority = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-c",
            authority_lease_epoch: old_epoch + 1,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-wrong-authority",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("wrong current operator refused");
    assert_eq!(wrong_authority.category(), "stale_epoch");
    let other_authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-b",
            holder_id: "holder-b",
            now_ms: 101,
            ttl_ms: 100,
        })
        .expect("independently live other generation");
    let wrong_successor_authority = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-c",
            authority_lease_epoch: other_authority.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-wrong-successor-authority",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("wrong successor holder cannot authorize decision");
    assert_eq!(wrong_successor_authority.category(), "stale_epoch");
    let wrong_epoch = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-b",
            authority_lease_epoch: old_epoch + 1,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch + 1,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-wrong-epoch",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("wrong claimed epoch refused");
    assert_eq!(wrong_epoch.category(), "stale_epoch");
    let stale = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-b",
            authority_lease_epoch: old_epoch + 1,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision + 1,
            decision_key: "reconcile-stale",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("stale revision refused");
    assert_eq!(stale.category(), "idempotency_conflict");
    assert_eq!(
        store
            .inspect_reconciliation(claim.run_id)
            .expect("unchanged")
            .run_state,
        ReconciliationRunState::Running
    );
    let adopted = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: other_authority.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "reconcile-successor-generation",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect("live successor generation reconciles expired predecessor work");
    assert!(!adopted.duplicate);
    assert_eq!(
        store
            .inspect_reconciliation(claim.run_id)
            .expect("reconciled")
            .run_state,
        ReconciliationRunState::Failed
    );
}

#[test]
fn explicit_reconciliation_failure_is_atomic_retryable_and_unique() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    submit(&mut store, "reconcile-fail", "scope:reconcile-fail");
    let claim = claim_next(&mut store, "holder-a", old_epoch, 2).expect("claim");
    lease(&mut store, "holder-b", 101);
    let request = || ReconciliationRequest {
        run_id: claim.run_id,
        authority_generation_id: "generation-a",
        authority_holder_id: "holder-b",
        authority_lease_epoch: old_epoch + 1,
        expected_generation_id: "generation-a",
        expected_lease_epoch: old_epoch,
        expected_revision: 1,
        decision_key: "fake-reconciliation:fail",
        now_ms: 102,
        decision: ReconciliationDecision::Fail {
            reason: "execution_outcome_unknown",
        },
    };
    let events_before = store.event_count().expect("events before");
    let first = store.reconcile_run(request()).expect("explicit failure");
    assert!(!first.duplicate);
    let outbox = store
        .outbox_snapshot(first.outbox_id)
        .expect("outbox receipt");
    assert_eq!(outbox.kind, "fake.reconciliation.receipt");
    assert_eq!(outbox.state, "pending");
    assert!(
        !store
            .scope_is_locked("scope:reconcile-fail")
            .expect("unlock")
    );
    assert_eq!(
        store
            .inspect_reconciliation(claim.run_id)
            .expect("resolved")
            .run_state,
        ReconciliationRunState::Failed
    );
    assert_eq!(store.outbox_count().expect("one receipt"), 1);
    assert_eq!(
        store.event_count().expect("two terminal events"),
        events_before + 2
    );

    let retry = store.reconcile_run(request()).expect("exact retry");
    assert!(retry.duplicate);
    assert_eq!(
        retry,
        automonique_store::ReconciliationReceipt {
            duplicate: true,
            ..first
        }
    );
    assert_eq!(store.outbox_count().expect("still one receipt"), 1);

    let conflict = store
        .reconcile_run(ReconciliationRequest {
            decision: ReconciliationDecision::Fail {
                reason: "different_reason",
            },
            ..request()
        })
        .expect_err("conflicting decision refused");
    assert_eq!(conflict.category(), "already_terminal");
    assert_eq!(store.outbox_count().expect("no duplicate outbox"), 1);
}

#[test]
fn reconciliation_outbox_conflict_rolls_back_run_inbox_events_and_unlock() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);

    submit_at(&mut store, "receipt-owner", "scope:receipt-owner", 1);
    let receipt_owner = claim_next(&mut store, "holder-a", old_epoch, 2).expect("first claim");
    store
        .finish_run(TerminalRun {
            run_id: receipt_owner.run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old_epoch,
            expected_revision: 1,
            now_ms: 3,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"done",
            outbox_intent_key: "fake-reconciliation:collision",
            outbox_kind: "provider.reply",
            outbox_payload: b"reply",
        })
        .expect("occupy intent key");

    submit_at(&mut store, "ambiguous", "scope:ambiguous", 4);
    let ambiguous = claim_next(&mut store, "holder-a", old_epoch, 5).expect("ambiguous claim");
    lease(&mut store, "holder-b", 101);
    let events_before = store.event_count().expect("events before refusal");
    let outbox_before = store.outbox_count().expect("outbox before refusal");
    let error = store
        .reconcile_run(ReconciliationRequest {
            run_id: ambiguous.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-b",
            authority_lease_epoch: old_epoch + 1,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: 1,
            decision_key: "fake-reconciliation:collision",
            now_ms: 102,
            decision: ReconciliationDecision::Fail {
                reason: "execution_outcome_unknown",
            },
        })
        .expect_err("duplicate receipt key refuses atomically");
    assert_eq!(error.category(), "outbox_conflict");
    assert_eq!(
        store.event_count().expect("events rolled back"),
        events_before
    );
    assert_eq!(store.outbox_count().expect("outbox stable"), outbox_before);
    assert_eq!(
        store
            .run_snapshot(ambiguous.run_id)
            .expect("run rolled back")
            .state,
        "running"
    );
    let evidence = store
        .inspect_reconciliation(ambiguous.run_id)
        .expect("inbox and lock rolled back");
    assert_eq!(evidence.run_revision, 1);
    assert_eq!(evidence.inbox_state, ReconciliationInboxState::Claimed);
    assert_eq!(evidence.claimed_run_id, Some(ambiguous.run_id));
    assert_eq!(evidence.lock_epoch, Some(old_epoch));
    assert!(
        store
            .scope_is_locked("scope:ambiguous")
            .expect("lock retained")
    );
}

#[test]
fn failed_reconciliation_survives_restart_and_scheduler_advances_fifo() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let failed_inbox = submit_at(&mut store, "reconcile-first", "scope:first", 1);
    let next_inbox = submit_at(&mut store, "reconcile-second", "scope:second", 2);
    let claim = claim_next(&mut store, "holder-a", old_epoch, 2).expect("claim");
    assert_eq!(claim.inbox_id, failed_inbox);
    let new_epoch = lease(&mut store, "holder-b", 101);
    let request = || ReconciliationRequest {
        run_id: claim.run_id,
        authority_generation_id: "generation-a",
        authority_holder_id: "holder-b",
        authority_lease_epoch: new_epoch,
        expected_generation_id: "generation-a",
        expected_lease_epoch: old_epoch,
        expected_revision: 1,
        decision_key: "fake-reconciliation:restart",
        now_ms: 102,
        decision: ReconciliationDecision::Fail {
            reason: "execution_outcome_unknown",
        },
    };
    let receipt = store.reconcile_run(request()).expect("explicit failure");
    assert!(receipt.outbox_id > 0);
    assert!(!receipt.duplicate);
    assert_eq!(store.outbox_count().expect("one fake receipt"), 1);
    drop(store);

    let mut reopened = Store::open(database.path()).expect("restart");
    let retry = reopened
        .reconcile_run(request())
        .expect("exact failure retry after restart");
    assert!(retry.duplicate);
    assert_eq!(retry.run_event_id, receipt.run_event_id);
    assert_eq!(retry.inbox_event_id, receipt.inbox_event_id);
    assert_eq!(retry.outbox_id, receipt.outbox_id);
    assert_eq!(reopened.outbox_count().expect("still one receipt"), 1);

    let next =
        claim_next(&mut reopened, "holder-b", new_epoch, 103).expect("scheduler forward progress");
    assert_eq!(next.inbox_id, next_inbox);
    assert_ne!(next.run_id, claim.run_id);
    assert!(!next.duplicate);
    assert_eq!(
        reopened
            .claimed_inbox(next.run_id, "generation-a", "holder-b", new_epoch, 104,)
            .expect("next input")
            .inbox_id,
        next_inbox
    );
    assert_eq!(reopened.outbox_count().expect("no duplicate outbox"), 1);
}

#[test]
fn telegram_batch_is_atomic_replayable_and_content_minimizing() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let updates = [
        telegram_update(
            2,
            "telegram:7:update:2",
            "telegram:7:-100",
            TelegramStoreDisposition::Admitted { content: b"hello" },
        ),
        telegram_update(
            4,
            "telegram:7:update:4",
            "telegram:7:-100",
            TelegramStoreDisposition::Denied,
        ),
        telegram_update(
            5,
            "telegram:7:update:5",
            "telegram:7:unsupported",
            TelegramStoreDisposition::IgnoredUnsupported,
        ),
    ];
    let batch = || TelegramBatchIngestion {
        bot_id: 7,
        expected_offset: 0,
        next_offset: 6,
        received_ms: 10,
        updates: &updates,
    };
    let first = store.ingest_telegram_batch(batch()).expect("first batch");
    assert!(!first.duplicate);
    assert_eq!(first.next_offset, 6);
    assert_eq!(first.disposition_count, updates.len());
    assert_eq!(store.telegram_offset(7).expect("offset"), Some(6));
    assert_eq!(
        store.telegram_disposition(7, 2).expect("admitted").content,
        Some(b"hello".to_vec())
    );
    for update_id in [4, 5] {
        assert_eq!(
            store
                .telegram_disposition(7, update_id)
                .expect("content-free disposition")
                .content,
            None
        );
    }

    let retry = store.ingest_telegram_batch(batch()).expect("exact retry");
    assert!(retry.duplicate);
    assert_eq!(retry.next_offset, first.next_offset);
    assert_eq!(retry.disposition_count, first.disposition_count);
    let changed = [
        telegram_update(
            2,
            "telegram:7:update:2",
            "telegram:7:-100",
            TelegramStoreDisposition::Admitted {
                content: b"changed",
            },
        ),
        telegram_update(
            4,
            "telegram:7:update:4",
            "telegram:7:-100",
            TelegramStoreDisposition::Denied,
        ),
        telegram_update(
            5,
            "telegram:7:update:5",
            "telegram:7:unsupported",
            TelegramStoreDisposition::IgnoredUnsupported,
        ),
    ];
    let conflict = store
        .ingest_telegram_batch(TelegramBatchIngestion {
            bot_id: 7,
            expected_offset: 0,
            next_offset: 6,
            received_ms: 10,
            updates: &changed,
        })
        .expect_err("changed retry is not exact");
    assert_eq!(conflict.category(), "idempotency_conflict");
    assert_eq!(store.telegram_offset(7).expect("stable offset"), Some(6));
}

#[test]
fn telegram_batch_failure_rolls_back_every_disposition_and_offset() {
    let database = PrivateDatabase::new();
    drop(Store::open(database.path()).expect("initialize schema"));
    let raw = Connection::open(database.path()).expect("fault-injection connection");
    raw.execute_batch(
        "CREATE TRIGGER fail_second_telegram_disposition
         BEFORE INSERT ON telegram_ingress
         WHEN NEW.bot_id = 2 AND NEW.update_id = X'0000000000000001'
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .expect("install deterministic transaction fault");
    drop(raw);
    let mut store = Store::open(database.path()).expect("open");

    let partial_then_conflict = [
        telegram_update(
            0,
            "telegram:2:update:0",
            "telegram:2:chat",
            TelegramStoreDisposition::Admitted { content: b"first" },
        ),
        telegram_update(
            1,
            "telegram:2:update:1",
            "telegram:2:chat",
            TelegramStoreDisposition::Admitted { content: b"second" },
        ),
    ];
    let error = store
        .ingest_telegram_batch(TelegramBatchIngestion {
            bot_id: 2,
            expected_offset: 0,
            next_offset: 2,
            received_ms: 2,
            updates: &partial_then_conflict,
        })
        .expect_err("second disposition failure rolls back transaction");
    assert_eq!(error.category(), "sqlite");
    assert_eq!(store.telegram_offset(2).expect("no offset advance"), None);
    assert_eq!(
        store
            .telegram_disposition(2, 0)
            .expect_err("first disposition rolled back")
            .category(),
        "not_found"
    );
    drop(store);

    let reopened = Store::open(database.path()).expect("reopen after failed transaction");
    assert_eq!(reopened.telegram_offset(2).expect("still absent"), None);
}

#[test]
fn telegram_commit_and_offset_survive_crash_boundary_and_bot_ids_isolate_updates() {
    let database = PrivateDatabase::new();
    {
        let unopened = Store::open(database.path()).expect("open before simulated crash");
        assert_eq!(unopened.telegram_offset(7).expect("no batch"), None);
    }
    let update_a = [telegram_update(
        9,
        "telegram:7:update:9",
        "telegram:7:chat",
        TelegramStoreDisposition::Admitted { content: b"a" },
    )];
    let update_b = [telegram_update(
        9,
        "telegram:8:update:9",
        "telegram:8:chat",
        TelegramStoreDisposition::Admitted { content: b"b" },
    )];
    let mut store = Store::open(database.path()).expect("reopen before commit");
    for (bot_id, updates) in [(7, update_a.as_slice()), (8, update_b.as_slice())] {
        store
            .ingest_telegram_batch(TelegramBatchIngestion {
                bot_id,
                expected_offset: 0,
                next_offset: 10,
                received_ms: 3,
                updates,
            })
            .expect("bot-scoped batch");
    }
    drop(store);

    let reopened = Store::open(database.path()).expect("reopen after commit");
    assert_eq!(reopened.telegram_offset(7).expect("bot 7"), Some(10));
    assert_eq!(reopened.telegram_offset(8).expect("bot 8"), Some(10));
    assert_eq!(
        reopened
            .telegram_disposition(7, 9)
            .expect("bot 7 update")
            .content,
        Some(b"a".to_vec())
    );
    assert_eq!(
        reopened
            .telegram_disposition(8, 9)
            .expect("bot 8 update")
            .content,
        Some(b"b".to_vec())
    );
}

#[test]
fn telegram_offset_regression_gap_and_unaccounted_advance_refuse() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let initial_gap = store
        .ingest_telegram_batch(TelegramBatchIngestion {
            bot_id: 7,
            expected_offset: 1,
            next_offset: 1,
            received_ms: 1,
            updates: &[],
        })
        .expect_err("initial state starts at zero");
    assert_eq!(initial_gap.category(), "idempotency_conflict");

    let updates = [telegram_update(
        2,
        "telegram:7:update:2",
        "telegram:7:chat",
        TelegramStoreDisposition::Admitted {
            content: b"accepted",
        },
    )];
    store
        .ingest_telegram_batch(TelegramBatchIngestion {
            bot_id: 7,
            expected_offset: 0,
            next_offset: 3,
            received_ms: 2,
            updates: &updates,
        })
        .expect("initial batch with platform ID gap");

    for (expected_offset, next_offset, updates) in
        [(0, 1, updates.as_slice()), (4, 4, &[][..]), (3, 4, &[][..])]
    {
        let error = store
            .ingest_telegram_batch(TelegramBatchIngestion {
                bot_id: 7,
                expected_offset,
                next_offset,
                received_ms: 3,
                updates,
            })
            .expect_err("offset refusal");
        assert!(matches!(
            error.category(),
            "idempotency_conflict" | "invalid_field"
        ));
        assert_eq!(store.telegram_offset(7).expect("unchanged"), Some(3));
    }
}
