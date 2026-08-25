// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use automonique_store::{
    InboxSubmission, IntakePauseRequest, IntakeResumeRequest, LeaseExpiryRequest,
    LeaseOwnerIdentity, LeaseRenewal, LeaseRequest, LeaseTimeSource, LeaseTransferRequest,
    MAX_TRANSPORT_KEY_BYTES, OutboxClaimRequest, OutboxDelivery, OutboxEnqueue, OutboxFailure,
    OutboxFailureDecision, OutboxPayloadRequest, OutboxReconciliationDecision,
    OutboxReconciliationRequest, ReconciliationDecision, ReconciliationInboxState,
    ReconciliationRequest, ReconciliationRunState, SCHEMA_VERSION, SchedulerClaim, Store,
    StoreError, TelegramBatchIngestion, TelegramPollerCommit, TelegramPollerLeaseIdentity,
    TelegramPollerLeaseRenewal, TelegramPollerLeaseRequest, TelegramStoreDisposition,
    TelegramStoreUpdate, TerminalRun, TerminalState, TransportPauseRequest, WorkClaim,
};
use rusqlite::Connection;
use tempfile::TempDir;

const ZOMBIE_HELPER: &str = "AUTOMONIQUE_STORE_ZOMBIE_HELPER";
const ZOMBIE_DATABASE: &str = "AUTOMONIQUE_STORE_ZOMBIE_DATABASE";
const ZOMBIE_READY: &str = "AUTOMONIQUE_STORE_ZOMBIE_READY";
const ZOMBIE_RESULT: &str = "AUTOMONIQUE_STORE_ZOMBIE_RESULT";

struct FixedLeaseClock(AtomicI64);

impl LeaseTimeSource for FixedLeaseClock {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

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

fn add_effect(store: &mut Store, epoch: u64, suffix: &str, received_ms: i64) -> i64 {
    let inbox = submit_at(
        store,
        &format!("effect:{suffix}"),
        &format!("scope:{suffix}"),
        received_ms,
    );
    let run = claim_next(store, "holder-a", epoch, received_ms + 1).expect("effect claim");
    assert_eq!(run.inbox_id, inbox);
    finish_scheduled(store, run.run_id, epoch, received_ms + 2, suffix);
    store.outbox_count().expect("effect count") as i64
}

fn claim_effect(
    store: &mut Store,
    holder: &str,
    epoch: u64,
    now_ms: i64,
) -> automonique_store::OutboxLease {
    store
        .claim_outbox(OutboxClaimRequest {
            transport: "test",
            kind: "test.effect",
            generation_id: "generation-a",
            holder_id: holder,
            lease_epoch: epoch,
            now_ms,
            ttl_ms: 10,
        })
        .expect("outbox claim")
        .expect("ready effect")
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

fn acquire_poller(
    store: &mut Store,
    bot_id: i64,
    generation_id: &str,
    holder_id: &str,
    authority_lease_epoch: u64,
    now_ms: i64,
    ttl_ms: i64,
) -> automonique_store::TelegramPollerLease {
    store
        .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
            bot_id,
            generation_id,
            holder_id,
            authority_lease_epoch,
            now_ms,
            ttl_ms,
        })
        .expect("poller lease")
}

fn poller_identity<'a>(
    lease: &'a automonique_store::TelegramPollerLease,
    now_ms: i64,
) -> TelegramPollerLeaseIdentity<'a> {
    TelegramPollerLeaseIdentity {
        bot_id: lease.bot_id,
        generation_id: &lease.generation_id,
        holder_id: &lease.holder_id,
        poller_epoch: lease.epoch,
        expected_expires_ms: lease.expires_ms,
        now_ms,
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
fn terminal_effect_has_one_connected_causal_chain_back_to_ingress() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("store");
    let epoch = lease(&mut store, "holder-a", 0);
    let inbox_id = submit(&mut store, "causal-delivery", "causal-scope");
    let run_id = claim(&mut store, inbox_id, epoch, "causal-claim", "causal-scope");
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
            event_payload: b"done",
            outbox_intent_key: "causal-intent",
            outbox_kind: "test.effect",
            outbox_payload: b"effect",
        })
        .expect("terminal effect");

    let chain = store
        .causal_chain_for_outbox(terminal.outbox_id)
        .expect("one-query causal chain");
    assert_eq!(chain.inbox_id, inbox_id);
    assert_eq!(chain.inbox_transport, "local-test");
    assert_eq!(chain.inbox_transport_key, "causal-delivery");
    assert_eq!(chain.run_id, run_id);
    assert_eq!(chain.event_id, terminal.event_id);
    assert_eq!(chain.event_kind, "run.succeeded");
    assert_eq!(chain.outbox_id, terminal.outbox_id);
    assert_eq!(chain.outbox_kind, "test.effect");
    assert_eq!(chain.run_causation_id, format!("inbox:{inbox_id}"));
    assert_eq!(chain.event_causation_id, format!("run:{run_id}"));
    assert_eq!(
        chain.outbox_causation_id,
        format!("event:{}", terminal.event_id)
    );

    let duplicate = store
        .submit_inbox(InboxSubmission {
            transport: "local-test",
            transport_key: "causal-delivery",
            scope: "causal-scope",
            payload: b"payload",
            received_ms: 99,
        })
        .expect("duplicate ingress");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.inbox_id, inbox_id);
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
fn a_dead_owner_sweep_is_exact_and_the_old_epoch_cannot_write_after_takeover() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_owner = LeaseOwnerIdentity {
        boot_id: "boot-a",
        pid: 111,
        starttime: 222,
    };
    let old = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-a",
                now_ms: 0,
                ttl_ms: 100,
            },
            old_owner,
        )
        .expect("old lease");
    let inbox_id = submit(&mut store, "delivery-zombie", "scope:zombie");
    let run_id = claim(
        &mut store,
        inbox_id,
        old.epoch,
        "claim-zombie",
        "scope:zombie",
    );

    let wrong_identity = store
        .expire_generation_lease_owner(LeaseExpiryRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: old.epoch,
            owner: LeaseOwnerIdentity {
                starttime: 223,
                ..old_owner
            },
            now_ms: 10,
        })
        .expect_err("PID-reuse identity must not sweep");
    assert_eq!(wrong_identity.category(), "stale_epoch");
    assert_eq!(
        store
            .status_snapshot("generation-a")
            .expect("status")
            .generation()
            .expect("generation")
            .lease_expires_ms(),
        100
    );

    store
        .expire_generation_lease_owner(LeaseExpiryRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: old.epoch,
            owner: old_owner,
            now_ms: 10,
        })
        .expect("exact dead owner sweep");
    let successor = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-new",
                now_ms: 10,
                ttl_ms: 100,
            },
            LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: 333,
                starttime: 444,
            },
        )
        .expect("successor");
    assert!(successor.epoch > old.epoch);

    let stale_write = store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old.epoch,
            expected_revision: 1,
            now_ms: 11,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"zombie-result",
            outbox_intent_key: "intent-zombie",
            outbox_kind: "provider.reply",
            outbox_payload: b"must-not-exist",
        })
        .expect_err("old holder write must be rejected");
    assert_eq!(stale_write.category(), "stale_epoch");
    assert_eq!(
        store.run_snapshot(run_id).expect("run unchanged").state,
        "running"
    );
    assert_eq!(store.outbox_count().expect("no zombie effect"), 0);
}

#[test]
fn external_lease_deadlines_ignore_every_wall_clock_value() {
    let database = PrivateDatabase::new();
    let clock = Arc::new(FixedLeaseClock(AtomicI64::new(1_000)));
    let mut store = Store::open_with_lease_time_source(database.path(), clock.clone())
        .expect("boot-time store");
    let first = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            now_ms: 1_800_000_000_000,
            ttl_ms: 100,
        })
        .expect("first lease");
    assert_eq!(first.expires_ms, 1_100);

    clock.0.store(1_050, Ordering::Release);
    let renewed = store
        .renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: first.epoch,
            now_ms: 1,
            ttl_ms: 200,
        })
        .expect("renewed lease");
    assert_eq!(renewed.expires_ms, 1_250);
    let snapshot = store
        .status_snapshot_at("generation-a", 9_000_000_000_000)
        .expect("status");
    assert_eq!(snapshot.lease_observed_boottime_ms(), 1_050);

    clock.0.store(1_250, Ordering::Release);
    let successor = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-b",
            now_ms: 2,
            ttl_ms: 100,
        })
        .expect("expired lease is replaceable");
    assert!(successor.epoch > first.epoch);
    assert_eq!(successor.expires_ms, 1_350);
}

/// Whether `/proc/<pid>/stat` reports the process as stopped (`T`), the
/// state a self-delivered SIGSTOP leaves it in.
fn process_is_stopped(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // The command field is parenthesised and may contain spaces; the state
    // is the first field after the closing parenthesis.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "T" || state == "t")
}

/// The SQLITE_BUSY (5) and SQLITE_LOCKED (6) families, including their
/// extended forms such as `SQLITE_BUSY_RECOVERY` (261) and
/// `SQLITE_BUSY_SNAPSHOT` (517): a lock another connection still holds for a
/// moment, never a fencing decision.
fn transient_sqlite_lock(code: rusqlite::ffi::Error) -> bool {
    matches!(code.extended_code & 0xff, 5 | 6)
}

#[test]
fn a_sigstopped_old_holder_cannot_commit_after_its_epoch_is_replaced() {
    let database = PrivateDatabase::new();
    let ready = database
        .path()
        .parent()
        .expect("database parent")
        .join("zombie.ready");
    let result = ready.with_extension("result");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("zombie_holder_helper")
        .env(ZOMBIE_HELPER, "1")
        .env(ZOMBIE_DATABASE, database.path())
        .env(ZOMBIE_READY, &ready)
        .env(ZOMBIE_RESULT, &result)
        .spawn()
        .expect("spawn old holder");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "old holder never reached SIGSTOP"
        );
        assert!(
            child.try_wait().expect("child status").is_none(),
            "old holder exited before SIGSTOP"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // The helper publishes readiness only after closing its database handle
    // and then stops itself. Wait until the kernel reports it stopped: from
    // that instant it can neither hold nor take a lock, so everything the
    // successor meets below is either a lock the filesystem is still
    // releasing or the durable fence this test is about.
    let stopped_deadline = Instant::now() + Duration::from_secs(10);
    while !process_is_stopped(child.id()) {
        assert!(
            Instant::now() < stopped_deadline,
            "old holder never entered the stopped state"
        );
        assert!(
            child.try_wait().expect("child status").is_none(),
            "old holder exited before SIGSTOP"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Open the successor now so it cannot retain a pre-takeover WAL snapshot
    // while the old holder performs its final write before SIGSTOP.
    //
    // A loaded CI filesystem can briefly retain SQLite's WAL writer lock after
    // the helper closes its connection, and the open itself (journal-mode
    // pragma, migration check) can meet WAL recovery still in progress
    // (`SQLITE_BUSY_RECOVERY`, extended code 261). Neither lock is authority
    // and the production connection already has a bounded busy timeout, so
    // retry only the SQLITE_BUSY/SQLITE_LOCKED family, here and at the
    // takeover below, while preserving the fencing assertion.
    let takeover_deadline = Instant::now() + Duration::from_secs(10);
    let mut successor_store = loop {
        match Store::open(database.path()) {
            Ok(store) => break store,
            Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                if transient_sqlite_lock(code) =>
            {
                assert!(
                    Instant::now() < takeover_deadline,
                    "successor could not open the store past a transient SQLite lock"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("successor opens store: {error}"),
        }
    };
    let successor = loop {
        match successor_store.acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-successor",
                now_ms: 100,
                ttl_ms: 100,
            },
            LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: std::process::id(),
                starttime: 999,
            },
        ) {
            Ok(successor) => break successor,
            Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                if transient_sqlite_lock(code) =>
            {
                assert!(
                    Instant::now() < takeover_deadline,
                    "successor remained blocked by a transient SQLite writer lock"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("successor takes expired epoch: {error}"),
        }
    };
    assert!(successor.epoch > 1);

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child pid")),
        nix::sys::signal::Signal::SIGCONT,
    )
    .expect("resume old holder");
    assert!(child.wait().expect("old holder status").success());
    assert_eq!(
        fs::read_to_string(&result).expect("stale result"),
        "stale_epoch"
    );
    let run_id = fs::read_to_string(&ready)
        .expect("run identity")
        .parse::<i64>()
        .expect("numeric run identity");
    assert_eq!(
        successor_store
            .run_snapshot(run_id)
            .expect("unchanged run")
            .state,
        "running"
    );
    assert_eq!(successor_store.outbox_count().expect("no zombie outbox"), 0);
}

#[test]
fn cooperative_transfer_adopts_running_work_and_fences_the_source_atomically() {
    let database = PrivateDatabase::new();
    let clock = Arc::new(FixedLeaseClock(AtomicI64::new(10)));
    let mut store = Store::open_with_lease_time_source(database.path(), clock).expect("store");
    let source = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-a",
                now_ms: 1,
                ttl_ms: 100,
            },
            LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: 10,
                starttime: 100,
            },
        )
        .expect("source lease");
    let inbox_id = submit(&mut store, "handoff-run", "handoff-scope");
    let run_id = claim(
        &mut store,
        inbox_id,
        source.epoch,
        "handoff-claim",
        "handoff-scope",
    );
    let transfer_request = LeaseTransferRequest {
        generation_id: "generation-a",
        source_holder_id: "holder-a",
        source_epoch: source.epoch,
        target_holder_id: "holder-b",
        target_owner: LeaseOwnerIdentity {
            boot_id: "boot-a",
            pid: 11,
            starttime: 200,
        },
        now_ms: 3,
        ttl_ms: 100,
    };
    let transferred = store
        .transfer_generation_lease(transfer_request)
        .expect("transfer");
    assert_eq!(transferred.lease.epoch, source.epoch + 1);
    assert_eq!(transferred.adopted_runs, 1);
    assert!(!transferred.duplicate);

    let replay = store
        .transfer_generation_lease(LeaseTransferRequest {
            generation_id: "generation-a",
            source_holder_id: "holder-a",
            source_epoch: source.epoch,
            target_holder_id: "holder-b",
            target_owner: LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: 11,
                starttime: 200,
            },
            now_ms: 4,
            ttl_ms: 100,
        })
        .expect("idempotent replay");
    assert!(replay.duplicate);
    assert_eq!(replay.lease, transferred.lease);

    assert!(matches!(
        store.finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: source.epoch,
            expected_revision: 1,
            now_ms: 5,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"old",
            outbox_intent_key: "handoff-old",
            outbox_kind: "test.effect",
            outbox_payload: b"old",
        }),
        Err(StoreError::StaleEpoch)
    ));
    store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-b",
            lease_epoch: transferred.lease.epoch,
            expected_revision: 1,
            now_ms: 6,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"new",
            outbox_intent_key: "handoff-new",
            outbox_kind: "test.effect",
            outbox_payload: b"new",
        })
        .expect("successor finishes adopted run");

    let returned = store
        .transfer_generation_lease(LeaseTransferRequest {
            generation_id: "generation-a",
            source_holder_id: "holder-b",
            source_epoch: transferred.lease.epoch,
            target_holder_id: "holder-a",
            target_owner: LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: 10,
                starttime: 100,
            },
            now_ms: 7,
            ttl_ms: 100,
        })
        .expect("return authority");
    assert_eq!(returned.lease.epoch, transferred.lease.epoch + 1);
    assert_eq!(returned.adopted_runs, 0);
    store
        .renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: returned.lease.epoch,
            now_ms: 8,
            ttl_ms: 100,
        })
        .expect("returned source renews authority");
    assert!(matches!(
        store.renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-b",
            epoch: transferred.lease.epoch,
            now_ms: 8,
            ttl_ms: 100,
        }),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn cooperative_transfer_refuses_live_transport_or_effect_ownership() {
    let database = PrivateDatabase::new();
    let clock = Arc::new(FixedLeaseClock(AtomicI64::new(10)));
    let mut store = Store::open_with_lease_time_source(database.path(), clock).expect("store");
    let source = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-a",
                now_ms: 1,
                ttl_ms: 100,
            },
            LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: 10,
                starttime: 100,
            },
        )
        .expect("source lease");
    let poller = acquire_poller(
        &mut store,
        7,
        "generation-a",
        "holder-a",
        source.epoch,
        2,
        50,
    );
    let transfer = || LeaseTransferRequest {
        generation_id: "generation-a",
        source_holder_id: "holder-a",
        source_epoch: source.epoch,
        target_holder_id: "holder-b",
        target_owner: LeaseOwnerIdentity {
            boot_id: "boot-a",
            pid: 11,
            starttime: 200,
        },
        now_ms: 3,
        ttl_ms: 100,
    };
    assert!(matches!(
        store
            .transfer_generation_lease(transfer())
            .expect_err("live poller blocks"),
        StoreError::HandoffBlocked("telegram_poller_live")
    ));

    store
        .release_telegram_poller_lease(poller_identity(&poller, 3))
        .expect("release poller");
    let effect_id = add_effect(&mut store, source.epoch, "handoff", 4);
    assert!(effect_id > 0);
    claim_effect(&mut store, "holder-a", source.epoch, 7);
    assert!(matches!(
        store
            .transfer_generation_lease(transfer())
            .expect_err("in-flight effect blocks"),
        StoreError::HandoffBlocked("outbox_in_flight")
    ));
    store
        .renew_generation_lease(LeaseRenewal {
            generation_id: "generation-a",
            holder_id: "holder-a",
            epoch: source.epoch,
            now_ms: 8,
            ttl_ms: 100,
        })
        .expect("blocked transfer changed no authority");
}

#[test]
fn zombie_holder_helper() {
    if std::env::var_os(ZOMBIE_HELPER).is_none() {
        return;
    }
    let database = PathBuf::from(std::env::var_os(ZOMBIE_DATABASE).expect("database path"));
    let ready = PathBuf::from(std::env::var_os(ZOMBIE_READY).expect("ready path"));
    let result = PathBuf::from(std::env::var_os(ZOMBIE_RESULT).expect("result path"));
    let mut store = Store::open(&database).expect("old holder store");
    let lease = store
        .acquire_generation_lease_owned(
            LeaseRequest {
                generation_id: "generation-a",
                holder_id: "holder-a",
                now_ms: 0,
                ttl_ms: 100,
            },
            LeaseOwnerIdentity {
                boot_id: "boot-a",
                pid: std::process::id(),
                starttime: 111,
            },
        )
        .expect("old holder lease");
    let inbox_id = submit(&mut store, "delivery-sigstop", "scope:sigstop");
    let run_id = claim(
        &mut store,
        inbox_id,
        lease.epoch,
        "claim-sigstop",
        "scope:sigstop",
    );
    // The process is the lease holder; an idle SQLite connection is not part
    // of that authority. Close it before publishing readiness so the parent
    // never races a transient WAL writer lock while proving epoch takeover.
    // Reopening after SIGCONT also exercises the durable fence rather than an
    // in-memory connection artifact.
    drop(store);
    fs::write(&ready, run_id.to_string()).expect("publish ready");
    nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGSTOP)
        .expect("self stop");
    let mut store = Store::open(&database).expect("old holder reopens store");
    let category = store
        .finish_run(TerminalRun {
            run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: lease.epoch,
            expected_revision: 1,
            now_ms: 3,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"old-holder",
            outbox_intent_key: "intent-sigstop",
            outbox_kind: "provider.reply",
            outbox_payload: b"must-not-exist",
        })
        .expect_err("stale old holder")
        .category();
    fs::write(result, category).expect("publish result");
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
    assert_eq!(running.inbox_pending(), 1);
    assert_eq!(running.outbox_pending(), 0);
    assert_eq!(running.runs_running(), 1);
    assert_eq!(
        running.generation().expect("generation").lease_epoch(),
        epoch
    );

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
    assert_eq!(finished.inbox_pending(), 1);
    assert_eq!(finished.outbox_pending(), 1);
    assert_eq!(finished.runs_running(), 0);
    assert_eq!(
        finished.event_cursor(),
        u64::try_from(terminal.event_id).unwrap()
    );
}

#[test]
fn status_snapshot_at_classifies_every_outbox_and_poller_state_at_time_boundary() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);

    let delayed_id = add_effect(&mut store, epoch, "status-delayed", 1);
    let delayed = claim_effect(&mut store, "holder-a", epoch, 4);
    assert_eq!(delayed.outbox_id, delayed_id);
    store
        .fail_outbox(OutboxFailure {
            outbox_id: delayed_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &delayed.lease_token,
            expected_attempt: delayed.attempt,
            now_ms: 5,
            decision: OutboxFailureDecision::Retry {
                reason: "later",
                retry_after_ms: 95,
            },
        })
        .expect("delayed");

    submit_at(&mut store, "effect:status-live", "scope:status-live", 6);
    let live_run = claim_next(&mut store, "holder-a", epoch, 7).expect("live run");
    let live_id = store
        .finish_run(TerminalRun {
            run_id: live_run.run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 8,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"status-live",
            outbox_intent_key: "intent:status-live",
            outbox_kind: "test.live",
            outbox_payload: b"status-live",
        })
        .expect("live terminal")
        .outbox_id;
    let live = store
        .claim_outbox(OutboxClaimRequest {
            transport: "test",
            kind: "test.live",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 9,
            ttl_ms: 60,
        })
        .expect("live claim")
        .expect("live effect");
    assert_eq!(live.outbox_id, live_id);
    submit_at(
        &mut store,
        "effect:status-ambiguous",
        "scope:status-ambiguous",
        10,
    );
    let ambiguous_run = claim_next(&mut store, "holder-a", epoch, 11).expect("ambiguous run");
    let ambiguous_terminal = store
        .finish_run(TerminalRun {
            run_id: ambiguous_run.run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 12,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"status-ambiguous",
            outbox_intent_key: "intent:status-ambiguous",
            outbox_kind: "test.ambiguous",
            outbox_payload: b"status-ambiguous",
        })
        .expect("ambiguous terminal");
    let ambiguous_id = ambiguous_terminal.outbox_id;
    let ambiguous = store
        .claim_outbox(OutboxClaimRequest {
            transport: "test",
            kind: "test.ambiguous",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 13,
            ttl_ms: 7,
        })
        .expect("ambiguous claim")
        .expect("ambiguous effect");
    assert_eq!(ambiguous.outbox_id, ambiguous_id);

    let delivered_id = add_effect(&mut store, epoch, "status-delivered", 14);
    let delivered = claim_effect(&mut store, "holder-a", epoch, 17);
    assert_eq!(delivered.outbox_id, delivered_id);
    store
        .deliver_outbox(OutboxDelivery {
            outbox_id: delivered_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &delivered.lease_token,
            expected_attempt: delivered.attempt,
            receipt_key: "status-delivered-receipt",
            now_ms: 18,
        })
        .expect("delivered");

    let dead_id = add_effect(&mut store, epoch, "status-dead", 19);
    let dead = claim_effect(&mut store, "holder-a", epoch, 22);
    assert_eq!(dead.outbox_id, dead_id);
    store
        .fail_outbox(OutboxFailure {
            outbox_id: dead_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &dead.lease_token,
            expected_attempt: dead.attempt,
            now_ms: 23,
            decision: OutboxFailureDecision::DeadLetter { reason: "closed" },
        })
        .expect("dead-lettered");
    add_effect(&mut store, epoch, "status-ready", 24);

    acquire_poller(&mut store, 7, "generation-a", "holder-a", epoch, 1, 60);
    acquire_poller(&mut store, 8, "generation-a", "holder-a", epoch, 1, 19);
    let other_authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-b",
            holder_id: "holder-b",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("other generation");
    acquire_poller(
        &mut store,
        9,
        "generation-b",
        "holder-b",
        other_authority.epoch,
        2,
        80,
    );
    acquire_poller(
        &mut store,
        10,
        "generation-b",
        "holder-b",
        other_authority.epoch,
        2,
        10,
    );
    let snapshot = store
        .status_snapshot_at("generation-a", 50)
        .expect("boundary snapshot");
    assert_eq!(snapshot.observed_ms(), 50);
    assert_eq!(snapshot.outbox_pending(), 2);
    assert_eq!(snapshot.outbox_pending_ready(), 1);
    assert_eq!(snapshot.outbox_pending_delayed(), 1);
    assert_eq!(snapshot.outbox_in_flight_live(), 1);
    assert_eq!(snapshot.outbox_in_flight_ambiguous(), 1);
    assert_eq!(snapshot.outbox_delivered(), 1);
    assert_eq!(snapshot.outbox_dead_lettered(), 1);
    assert_eq!(snapshot.outbox_oldest_ready_age_ms(), 24);
    assert_eq!(snapshot.telegram_pollers_live(), 1);
    assert_eq!(snapshot.telegram_pollers_expired(), 1);
    let other_snapshot = store
        .status_snapshot_at("generation-b", 50)
        .expect("other generation snapshot");
    assert_eq!(other_snapshot.telegram_pollers_live(), 1);
    assert_eq!(other_snapshot.telegram_pollers_expired(), 1);
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen");
    assert_eq!(
        reopened
            .status_snapshot_at("generation-a", 50)
            .expect("same snapshot after restart"),
        snapshot
    );
    let before_boundary = reopened
        .status_snapshot_at("generation-a", 19)
        .expect("before boundary");
    assert_eq!(before_boundary.outbox_in_flight_live(), 2);
    assert_eq!(before_boundary.outbox_in_flight_ambiguous(), 0);
    assert_eq!(before_boundary.telegram_pollers_live(), 2);
    assert_eq!(before_boundary.telegram_pollers_expired(), 0);
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
            .inbox_pending(),
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
            .inbox_pending(),
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
    assert_eq!(stale_authority.category(), "authority_lost");
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
    assert_eq!(wrong_authority.category(), "authority_lost");
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
    assert_eq!(wrong_successor_authority.category(), "authority_lost");
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
fn reconciliation_can_commit_independently_proven_success_and_custom_receipt() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    submit(&mut store, "reconcile-complete", "scope:complete");
    let claim = claim_next(&mut store, "holder-a", old_epoch, 2).expect("claim");
    let evidence = store
        .inspect_reconciliation(claim.run_id)
        .expect("evidence");
    let successor = lease(&mut store, "holder-b", 101);
    let payload = br#"{"outcome":"completed"}"#;
    let receipt = store
        .reconcile_run(ReconciliationRequest {
            run_id: claim.run_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_revision: evidence.run_revision,
            decision_key: "platform-reconcile-complete",
            now_ms: 102,
            decision: ReconciliationDecision::Complete {
                event_kind: "run.managed_completed",
                event_payload: payload,
                outbox_kind: "platform.managed_receipt",
                outbox_payload: payload,
            },
        })
        .expect("proven completion");
    assert!(!receipt.duplicate);
    let recovered = store
        .terminal_receipt(claim.run_id, "platform-reconcile-complete")
        .expect("terminal receipt");
    assert_eq!(recovered.event_id, receipt.run_event_id);
    assert_eq!(recovered.outbox_id, receipt.outbox_id);
    let snapshot = store
        .status_snapshot_at("generation-a", 103)
        .expect("snapshot");
    assert_eq!(snapshot.runs_running(), 0);
    assert_eq!(snapshot.runs_reconciliation_pending(), 0);
    assert_eq!(snapshot.inbox_pending(), 0);
    assert_eq!(snapshot.outbox_pending(), 1);
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
fn outbox_claim_is_filtered_fifo_and_payload_requires_exact_live_lease() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let first = add_effect(&mut store, epoch, "fifo-first", 1);
    let second = add_effect(&mut store, epoch, "fifo-second", 10);
    assert!(second > first);
    assert!(
        store
            .claim_outbox(OutboxClaimRequest {
                transport: "other",
                kind: "test.effect",
                generation_id: "generation-a",
                holder_id: "holder-a",
                lease_epoch: epoch,
                now_ms: 20,
                ttl_ms: 10,
            })
            .expect("filter")
            .is_none()
    );
    let claimed = claim_effect(&mut store, "holder-a", epoch, 20);
    assert_eq!(claimed.outbox_id, first);
    assert_eq!(claimed.attempt, 1);
    assert!(!claimed.duplicate);
    assert_eq!(claimed.retry_after_ms, 30);

    let wrong = store
        .leased_outbox_payload(OutboxPayloadRequest {
            outbox_id: claimed.outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch + 1,
            lease_token: &claimed.lease_token,
            now_ms: 21,
        })
        .expect_err("wrong epoch cannot read payload");
    assert_eq!(wrong.category(), "stale_epoch");
    let payload = store
        .leased_outbox_payload(OutboxPayloadRequest {
            outbox_id: claimed.outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &claimed.lease_token,
            now_ms: 21,
        })
        .expect("exact leased payload");
    assert_eq!(payload.payload, b"fifo-first");
    assert_eq!(
        store
            .inspect_outbox_reconciliation(second)
            .expect("second untouched")
            .state,
        "pending"
    );
}

#[test]
fn independent_outbox_enqueue_is_fenced_idempotent_and_claimable() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let enqueue = || OutboxEnqueue {
        intent_key: "telegram:42:update:7:reply",
        kind: "telegram.send_message",
        payload: br#"{"chat_id":9,"text":"hello"}"#,
        generation_id: "generation-a",
        holder_id: "holder-a",
        lease_epoch: epoch,
        now_ms: 1,
    };
    let first = store.enqueue_outbox(enqueue()).expect("enqueue");
    assert!(!first.duplicate);
    let duplicate = store.enqueue_outbox(enqueue()).expect("exact retry");
    assert!(duplicate.duplicate);
    assert_eq!(
        duplicate,
        automonique_store::OutboxEnqueueReceipt {
            duplicate: true,
            ..first
        }
    );
    let conflict = store
        .enqueue_outbox(OutboxEnqueue {
            payload: br#"{"chat_id":9,"text":"different"}"#,
            ..enqueue()
        })
        .expect_err("same key cannot change payload");
    assert_eq!(conflict.category(), "outbox_conflict");

    let claim = store
        .claim_outbox(OutboxClaimRequest {
            transport: "telegram",
            kind: "telegram.send_message",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 2,
            ttl_ms: 10,
        })
        .expect("claim")
        .expect("queued effect");
    assert_eq!(claim.outbox_id, first.outbox_id);
    let payload = store
        .leased_outbox_payload(OutboxPayloadRequest {
            outbox_id: claim.outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &claim.lease_token,
            now_ms: 3,
        })
        .expect("leased payload");
    assert_eq!(payload.payload, enqueue().payload);
}

#[test]
fn outbox_claim_survives_restart_and_two_connections_never_double_claim() {
    let database = PrivateDatabase::new();
    let mut first_store = Store::open(database.path()).expect("open first");
    let epoch = lease(&mut first_store, "holder-a", 0);
    let outbox_id = add_effect(&mut first_store, epoch, "crash-after-claim", 1);
    let first = claim_effect(&mut first_store, "holder-a", epoch, 5);
    assert_eq!(first.outbox_id, outbox_id);
    drop(first_store);

    let mut reopened = Store::open(database.path()).expect("reopen");
    let replay = claim_effect(&mut reopened, "holder-a", epoch, 6);
    assert!(replay.duplicate);
    assert_eq!(replay.outbox_id, first.outbox_id);
    assert_eq!(replay.lease_token, first.lease_token);
    assert_eq!(replay.attempt, first.attempt);

    let mut competing = Store::open(database.path()).expect("competing connection");
    let concurrent = claim_effect(&mut competing, "holder-a", epoch, 7);
    assert!(concurrent.duplicate);
    assert_eq!(concurrent.outbox_id, first.outbox_id);
    assert_eq!(concurrent.lease_token, first.lease_token);
    assert_eq!(
        competing
            .inspect_outbox_reconciliation(outbox_id)
            .expect("single durable claim")
            .attempt,
        1
    );
}

#[test]
fn delivery_receipt_is_exact_idempotent_and_survives_reopen() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let outbox_id = add_effect(&mut store, epoch, "delivered", 1);
    let claimed = claim_effect(&mut store, "holder-a", epoch, 5);
    let delivery = || OutboxDelivery {
        outbox_id,
        generation_id: "generation-a",
        holder_id: "holder-a",
        lease_epoch: epoch,
        lease_token: &claimed.lease_token,
        expected_attempt: claimed.attempt,
        receipt_key: "provider-receipt:delivered",
        now_ms: 6,
    };
    let first = store.deliver_outbox(delivery()).expect("delivery receipt");
    assert!(!first.duplicate);
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen after receipt");
    let duplicate = reopened
        .deliver_outbox(OutboxDelivery {
            now_ms: 7,
            ..delivery()
        })
        .expect("exact receipt retry");
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.receipt_key, first.receipt_key);
    assert_eq!(duplicate.revision, first.revision);
    let altered_receipt = reopened
        .deliver_outbox(OutboxDelivery {
            receipt_key: "provider-receipt:altered",
            now_ms: 7,
            ..delivery()
        })
        .expect_err("terminal receipt cannot be replaced");
    assert_eq!(altered_receipt.category(), "already_terminal");
    let altered_attempt = reopened
        .deliver_outbox(OutboxDelivery {
            expected_attempt: claimed.attempt + 1,
            now_ms: 7,
            ..delivery()
        })
        .expect_err("terminal receipt cannot replay with another attempt");
    assert_eq!(altered_attempt.category(), "already_terminal");
    let altered_fence = reopened
        .deliver_outbox(OutboxDelivery {
            lease_epoch: epoch + 1,
            now_ms: 7,
            ..delivery()
        })
        .expect_err("terminal receipt cannot replay through another fence");
    assert_eq!(altered_fence.category(), "stale_epoch");
    let evidence = reopened
        .inspect_outbox_reconciliation(outbox_id)
        .expect("delivered evidence");
    assert_eq!(evidence.state, "delivered");
    assert_eq!(
        evidence.delivery_receipt_key.as_deref(),
        Some("provider-receipt:delivered")
    );
    assert!(
        reopened
            .claim_outbox(OutboxClaimRequest {
                transport: "test",
                kind: "test.effect",
                generation_id: "generation-a",
                holder_id: "holder-a",
                lease_epoch: epoch,
                now_ms: 8,
                ttl_ms: 10,
            })
            .expect("delivered excluded")
            .is_none()
    );

    let second_id = add_effect(&mut reopened, epoch, "receipt-collision", 20);
    let second_claim = claim_effect(&mut reopened, "holder-a", epoch, 24);
    assert_eq!(second_claim.outbox_id, second_id);
    let collision = reopened
        .deliver_outbox(OutboxDelivery {
            outbox_id: second_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &second_claim.lease_token,
            expected_attempt: second_claim.attempt,
            receipt_key: "provider-receipt:delivered",
            now_ms: 25,
        })
        .expect_err("one provider receipt cannot belong to two intents");
    assert_eq!(collision.category(), "outbox_conflict");
    assert_eq!(
        reopened
            .outbox_snapshot(second_id)
            .expect("second intent")
            .state,
        "in_flight"
    );
}

#[test]
fn expired_effect_is_ambiguous_until_explicit_reconciliation() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let outbox_id = add_effect(&mut store, old_epoch, "ambiguous", 1);
    let claimed = claim_effect(&mut store, "holder-a", old_epoch, 5);
    drop(store);

    let mut reopened = Store::open(database.path()).expect("crash after external delivery");
    let refusal = reopened
        .claim_outbox(OutboxClaimRequest {
            transport: "test",
            kind: "test.effect",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old_epoch,
            now_ms: 16,
            ttl_ms: 10,
        })
        .expect_err("expired delivery is never silently redelivered");
    assert_eq!(refusal.category(), "outbox_reconciliation_required");
    let evidence = reopened
        .inspect_outbox_reconciliation(outbox_id)
        .expect("ambiguous evidence");
    assert_eq!(evidence.state, "in_flight");
    assert_eq!(evidence.attempt, 1);
    assert_eq!(
        evidence.lease_token.as_deref(),
        Some(claimed.lease_token.as_str())
    );

    let stale_authority = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-a",
            authority_holder_id: "holder-a",
            authority_lease_epoch: old_epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 102,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect_err("expired old authority cannot reconcile");
    assert_eq!(stale_authority.category(), "authority_lost");
    let successor = reopened
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-b",
            holder_id: "holder-b",
            now_ms: 101,
            ttl_ms: 100,
        })
        .expect("live successor generation");
    let wrong_authority = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-c",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 102,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect_err("wrong successor holder cannot reconcile");
    assert_eq!(wrong_authority.category(), "authority_lost");
    let resolved = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 102,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect("explicit delivered reconciliation");
    assert_eq!(resolved.state, "delivered");
    assert!(!resolved.duplicate);
    let retry = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 103,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect("exact reconciliation retry");
    assert!(retry.duplicate);
    assert_eq!(retry.revision, resolved.revision);
    let wrong_expected_generation = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-c",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 103,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect_err("altered expected generation cannot replay reconciliation");
    assert_eq!(wrong_expected_generation.category(), "already_terminal");
    let wrong_expected_epoch = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch + 1,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 103,
            decision: OutboxReconciliationDecision::Delivered {
                receipt_key: "operator-confirmed:ambiguous",
            },
        })
        .expect_err("altered expected epoch cannot replay reconciliation");
    assert_eq!(wrong_expected_epoch.category(), "already_terminal");
    let conflict = reopened
        .reconcile_outbox(OutboxReconciliationRequest {
            outbox_id,
            authority_generation_id: "generation-b",
            authority_holder_id: "holder-b",
            authority_lease_epoch: successor.epoch,
            expected_generation_id: "generation-a",
            expected_lease_epoch: old_epoch,
            expected_lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            expected_revision: claimed.revision,
            now_ms: 104,
            decision: OutboxReconciliationDecision::DeadLetter {
                reason: "conflicting_operator_decision",
            },
        })
        .expect_err("conflicting closed reconciliation refused");
    assert_eq!(conflict.category(), "already_terminal");
    assert_eq!(
        reopened
            .inspect_outbox_reconciliation(outbox_id)
            .expect("delivered state unchanged")
            .delivery_receipt_key
            .as_deref(),
        Some("operator-confirmed:ambiguous")
    );
}

#[test]
fn explicit_failure_can_retry_or_dead_letter_but_expiry_cannot() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let outbox_id = add_effect(&mut store, epoch, "retry-dead", 1);
    let first = claim_effect(&mut store, "holder-a", epoch, 5);
    let retry = store
        .fail_outbox(OutboxFailure {
            outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &first.lease_token,
            expected_attempt: first.attempt,
            now_ms: 6,
            decision: OutboxFailureDecision::Retry {
                reason: "provider_unavailable",
                retry_after_ms: 20,
            },
        })
        .expect("explicit safe retry");
    assert_eq!(retry.state, "pending");
    drop(store);
    let mut store = Store::open(database.path()).expect("reopen after retry acknowledgement loss");
    let retry_evidence = store
        .inspect_outbox_reconciliation(outbox_id)
        .expect("exact persisted retry evidence");
    assert_eq!(retry_evidence.available_ms, 20);
    assert_eq!(
        retry_evidence.last_error.as_deref(),
        Some("provider_unavailable")
    );
    assert!(
        store
            .claim_outbox(OutboxClaimRequest {
                transport: "test",
                kind: "test.effect",
                generation_id: "generation-a",
                holder_id: "holder-a",
                lease_epoch: epoch,
                now_ms: 19,
                ttl_ms: 10,
            })
            .expect("retry delay")
            .is_none()
    );
    let second = claim_effect(&mut store, "holder-a", epoch, 20);
    assert_eq!(second.attempt, 2);
    assert_ne!(second.lease_token, first.lease_token);
    let dead = store
        .fail_outbox(OutboxFailure {
            outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &second.lease_token,
            expected_attempt: second.attempt,
            now_ms: 21,
            decision: OutboxFailureDecision::DeadLetter {
                reason: "permanent_refusal",
            },
        })
        .expect("closed dead letter");
    assert_eq!(dead.state, "dead_lettered");
    drop(store);
    let store =
        Store::open(database.path()).expect("reopen after dead-letter acknowledgement loss");
    assert_eq!(
        store
            .inspect_outbox_reconciliation(outbox_id)
            .expect("dead evidence")
            .state,
        "dead_lettered"
    );
    assert_eq!(
        store
            .inspect_outbox_reconciliation(outbox_id)
            .expect("dead-letter reason")
            .last_error
            .as_deref(),
        Some("permanent_refusal")
    );
}

#[test]
fn a_delayed_retry_does_not_block_a_later_ready_effect() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let delayed_id = add_effect(&mut store, epoch, "delayed-first", 1);
    let delayed = claim_effect(&mut store, "holder-a", epoch, 5);
    store
        .fail_outbox(OutboxFailure {
            outbox_id: delayed_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            lease_token: &delayed.lease_token,
            expected_attempt: delayed.attempt,
            now_ms: 6,
            decision: OutboxFailureDecision::Retry {
                reason: "provider_backoff",
                retry_after_ms: 50,
            },
        })
        .expect("schedule delayed retry");
    let ready_id = add_effect(&mut store, epoch, "ready-second", 10);
    let ready = claim_effect(&mut store, "holder-a", epoch, 14);
    assert_eq!(ready.outbox_id, ready_id);
    assert_ne!(ready.outbox_id, delayed_id);
    assert_eq!(ready.attempt, 1);
}

#[test]
fn stale_outbox_fences_refuse_without_mutation() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let old_epoch = lease(&mut store, "holder-a", 0);
    let outbox_id = add_effect(&mut store, old_epoch, "stale-fence", 1);
    let claimed = claim_effect(&mut store, "holder-a", old_epoch, 5);
    let before = store
        .inspect_outbox_reconciliation(outbox_id)
        .expect("before stale calls");
    let wrong_holder = store
        .deliver_outbox(OutboxDelivery {
            outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-b",
            lease_epoch: old_epoch,
            lease_token: &claimed.lease_token,
            expected_attempt: claimed.attempt,
            receipt_key: "must-not-commit",
            now_ms: 6,
        })
        .expect_err("wrong holder refused");
    assert_eq!(wrong_holder.category(), "stale_epoch");
    let wrong_token = store
        .fail_outbox(OutboxFailure {
            outbox_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: old_epoch,
            lease_token: "wrong-token",
            expected_attempt: claimed.attempt,
            now_ms: 6,
            decision: OutboxFailureDecision::DeadLetter { reason: "wrong" },
        })
        .expect_err("wrong lease token refused");
    assert_eq!(wrong_token.category(), "stale_epoch");
    assert_eq!(
        store
            .inspect_outbox_reconciliation(outbox_id)
            .expect("unchanged after stale calls"),
        before
    );
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

#[test]
fn telegram_poller_lease_is_fenced_across_connections_restart_and_authority_epochs() {
    let database = PrivateDatabase::new();
    let mut owner = Store::open(database.path()).expect("owner open");
    let authority = lease(&mut owner, "holder-a", 0);
    let first = acquire_poller(&mut owner, 7, "generation-a", "holder-a", authority, 1, 50);
    let stable = acquire_poller(&mut owner, 7, "generation-a", "holder-a", authority, 2, 50);
    assert_eq!(stable, first);

    let mut competitor = Store::open(database.path()).expect("competitor open");
    let competitor_authority = competitor
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-b",
            holder_id: "holder-b",
            now_ms: 2,
            ttl_ms: 100,
        })
        .expect("independent live generation authority");
    let held = competitor
        .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
            bot_id: 7,
            generation_id: "generation-b",
            holder_id: "holder-b",
            authority_lease_epoch: competitor_authority.epoch,
            now_ms: 3,
            ttl_ms: 20,
        })
        .expect_err("two live connections cannot own one bot");
    assert_eq!(held.category(), "lease_held");

    let renewed = owner
        .renew_telegram_poller_lease(TelegramPollerLeaseRenewal {
            bot_id: 7,
            generation_id: "generation-a",
            holder_id: "holder-a",
            authority_lease_epoch: authority,
            poller_epoch: first.epoch,
            expected_expires_ms: first.expires_ms,
            now_ms: 4,
            ttl_ms: 70,
        })
        .expect("exact renew");
    assert_eq!(renewed.epoch, first.epoch);
    assert_eq!(renewed.expires_ms, 74);
    drop(owner);

    let mut reopened = Store::open(database.path()).expect("restart open");
    assert_eq!(
        reopened
            .read_telegram_offset(poller_identity(&renewed, 5))
            .expect("durable lease read")
            .next_offset,
        0
    );
    reopened
        .release_telegram_poller_lease(poller_identity(&renewed, 6))
        .expect("exact release");
    assert_eq!(
        reopened
            .read_telegram_offset(poller_identity(&renewed, 7))
            .expect_err("released lease refuses")
            .category(),
        "stale_epoch"
    );

    reopened
        .release_generation_lease("generation-a", "holder-a", authority, 8)
        .expect("release authority");
    let next_authority = reopened
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-a",
            now_ms: 8,
            ttl_ms: 100,
        })
        .expect("same identity new authority epoch");
    assert!(next_authority.epoch > authority);
    let successor = acquire_poller(
        &mut reopened,
        7,
        "generation-a",
        "holder-a",
        next_authority.epoch,
        9,
        30,
    );
    assert!(successor.epoch > renewed.epoch);
    assert_eq!(
        reopened
            .read_telegram_offset(poller_identity(&renewed, 10))
            .expect_err("old poller epoch remains fenced")
            .category(),
        "stale_epoch"
    );
}

#[test]
fn telegram_poller_commit_is_atomic_exact_and_deadline_fenced() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let authority = lease(&mut store, "holder-a", 0);
    let poller = acquire_poller(&mut store, 7, "generation-a", "holder-a", authority, 1, 50);
    let updates = [telegram_update(
        2,
        "telegram:7:update:2",
        "telegram:7:chat",
        TelegramStoreDisposition::Admitted {
            content: b"accepted",
        },
    )];
    let commit = |digest| TelegramPollerCommit {
        lease: poller_identity(&poller, 10),
        commit_before_ms: poller.expires_ms,
        batch_digest: digest,
        batch: TelegramBatchIngestion {
            bot_id: 7,
            expected_offset: 0,
            next_offset: 3,
            received_ms: 9,
            updates: &updates,
        },
    };
    let first = store
        .commit_telegram_batch(commit([1; 32]))
        .expect("atomic fenced commit");
    assert!(!first.duplicate);
    assert_eq!(first.next_offset, 3);
    assert_eq!(first.batch_digest, [1; 32]);
    let replay = store
        .commit_telegram_batch(commit([1; 32]))
        .expect("exact retry");
    assert!(replay.duplicate);
    assert_eq!(
        store
            .commit_telegram_batch(commit([2; 32]))
            .expect_err("changed digest refuses")
            .category(),
        "idempotency_conflict"
    );
    drop(store);
    let mut reopened = Store::open(database.path()).expect("reopen");
    assert_eq!(
        reopened.telegram_offset(7).expect("durable offset"),
        Some(3)
    );
    assert_eq!(
        reopened
            .telegram_disposition(7, 2)
            .expect("durable disposition")
            .content,
        Some(b"accepted".to_vec())
    );
    let recovered = reopened
        .commit_telegram_batch(TelegramPollerCommit {
            lease: poller_identity(&poller, poller.expires_ms + 1),
            commit_before_ms: poller.expires_ms,
            batch_digest: [1; 32],
            batch: TelegramBatchIngestion {
                bot_id: 7,
                expected_offset: 0,
                next_offset: 3,
                received_ms: 9,
                updates: &updates,
            },
        })
        .expect("crash-lost exact receipt remains recoverable after expiry");
    assert!(recovered.duplicate);

    let expired_updates = [telegram_update(
        3,
        "telegram:7:update:3",
        "telegram:7:chat",
        TelegramStoreDisposition::Denied,
    )];
    let expired = reopened
        .commit_telegram_batch(TelegramPollerCommit {
            lease: TelegramPollerLeaseIdentity {
                now_ms: poller.expires_ms,
                ..poller_identity(&poller, poller.expires_ms)
            },
            commit_before_ms: poller.expires_ms,
            batch_digest: [3; 32],
            batch: TelegramBatchIngestion {
                bot_id: 7,
                expected_offset: 3,
                next_offset: 4,
                received_ms: 49,
                updates: &expired_updates,
            },
        })
        .expect_err("expired lease cannot mutate");
    assert_eq!(expired.category(), "stale_epoch");
    assert_eq!(
        reopened.telegram_offset(7).expect("offset unchanged"),
        Some(3)
    );
    assert_eq!(
        reopened
            .telegram_disposition(7, 3)
            .expect_err("disposition rolled back")
            .category(),
        "not_found"
    );
}

#[test]
fn telegram_poller_commit_rolls_back_on_mid_batch_failure() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let authority = lease(&mut store, "holder-a", 0);
    let poller = acquire_poller(&mut store, 2, "generation-a", "holder-a", authority, 1, 50);
    drop(store);
    let raw = Connection::open(database.path()).expect("fault connection");
    raw.execute_batch(
        "CREATE TRIGGER fail_fenced_telegram_disposition
         BEFORE INSERT ON telegram_ingress
         WHEN NEW.bot_id = 2 AND NEW.update_id = X'0000000000000001'
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .expect("fault trigger");
    drop(raw);
    let updates = [
        telegram_update(
            0,
            "telegram:2:update:0",
            "telegram:2:chat",
            TelegramStoreDisposition::Denied,
        ),
        telegram_update(
            1,
            "telegram:2:update:1",
            "telegram:2:chat",
            TelegramStoreDisposition::Denied,
        ),
    ];
    let mut reopened = Store::open(database.path()).expect("reopen");
    assert_eq!(
        reopened
            .commit_telegram_batch(TelegramPollerCommit {
                lease: poller_identity(&poller, 5),
                commit_before_ms: poller.expires_ms,
                batch_digest: [4; 32],
                batch: TelegramBatchIngestion {
                    bot_id: 2,
                    expected_offset: 0,
                    next_offset: 2,
                    received_ms: 4,
                    updates: &updates,
                },
            })
            .expect_err("fault rolls back")
            .category(),
        "sqlite"
    );
    assert_eq!(reopened.telegram_offset(2).expect("no cursor"), None);
    assert_eq!(
        reopened
            .telegram_disposition(2, 0)
            .expect_err("first row rolled back")
            .category(),
        "not_found"
    );
}

#[test]
fn telegram_fenced_commit_preserves_u64_max_cursor_across_reopen() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let authority = lease(&mut store, "holder-a", 0);
    let poller = acquire_poller(&mut store, 7, "generation-a", "holder-a", authority, 1, 50);
    let update_id = u64::MAX - 1;
    let source_key = format!("telegram:7:update:{update_id}");
    let updates = [telegram_update(
        update_id,
        &source_key,
        "telegram:7:chat",
        TelegramStoreDisposition::Denied,
    )];
    let receipt = store
        .commit_telegram_batch(TelegramPollerCommit {
            lease: poller_identity(&poller, 5),
            commit_before_ms: poller.expires_ms,
            batch_digest: [u8::MAX; 32],
            batch: TelegramBatchIngestion {
                bot_id: 7,
                expected_offset: 0,
                next_offset: u64::MAX,
                received_ms: 4,
                updates: &updates,
            },
        })
        .expect("maximum cursor commit");
    assert_eq!(receipt.next_offset, u64::MAX);
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen maximum cursor");
    assert_eq!(
        reopened.telegram_offset(7).expect("raw cursor read"),
        Some(u64::MAX)
    );
    let fenced = reopened
        .read_telegram_offset(poller_identity(&poller, 6))
        .expect("fenced cursor read");
    assert_eq!(fenced.next_offset, u64::MAX);
    assert_eq!(
        reopened
            .telegram_disposition(7, update_id)
            .expect("maximum update preserved")
            .source_key,
        source_key
    );
}

fn pause(
    store: &mut Store,
    holder: &str,
    epoch: u64,
    actor: &str,
    reason: &str,
    now_ms: i64,
) -> Result<automonique_store::IntakePauseReceipt, automonique_store::StoreError> {
    store.pause_intake(IntakePauseRequest {
        generation_id: "generation-a",
        holder_id: holder,
        authority_lease_epoch: epoch,
        actor,
        reason,
        now_ms,
    })
}

fn resume(
    store: &mut Store,
    holder: &str,
    epoch: u64,
    actor: &str,
    expected_revision: u64,
    now_ms: i64,
) -> Result<automonique_store::IntakePauseReceipt, automonique_store::StoreError> {
    store.resume_intake(IntakeResumeRequest {
        generation_id: "generation-a",
        holder_id: holder,
        authority_lease_epoch: epoch,
        actor,
        expected_revision,
        now_ms,
    })
}

#[test]
fn intake_pause_is_durable_attributed_and_answers_repeats_by_type() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    assert_eq!(
        store.intake_paused("generation-a", 1).expect("read"),
        None,
        "a fresh generation is not paused"
    );

    let receipt =
        pause(&mut store, "holder-a", epoch, "operator:ada", "hotfix", 5).expect("first pause");
    assert!(receipt.pause_id > 0);
    assert_eq!(receipt.revision, 1);

    let live = store
        .intake_paused("generation-a", 9)
        .expect("read")
        .expect("paused");
    assert_eq!(live.pause_id, receipt.pause_id);
    assert_eq!(live.revision, 1);
    assert_eq!(live.paused_at_ms, 5);
    assert_eq!(live.actor, "operator:ada");
    assert_eq!(live.reason, "hotfix");
    assert_eq!(live.observed_ms, 9, "the record is stamped with the read");

    // Pausing a paused generation is not an accident to swallow: the second
    // operator is told who already holds intake closed and why.
    let error =
        pause(&mut store, "holder-a", epoch, "operator:bo", "again", 6).expect_err("double pause");
    assert_eq!(error.category(), "intake_already_paused");
    let automonique_store::StoreError::AlreadyPaused(carried) = error else {
        panic!("AlreadyPaused must carry the live decision")
    };
    assert_eq!(carried.actor, "operator:ada");
    assert_eq!(carried.reason, "hotfix");
    assert_eq!(carried.pause_id, receipt.pause_id);
    assert_eq!(
        store
            .intake_paused("generation-a", 7)
            .expect("read")
            .expect("still paused")
            .revision,
        1,
        "a refused second pause must not move the live row"
    );

    // A resume the caller did not observe is refused rather than applied to
    // whatever the row happens to say now.
    let stale =
        resume(&mut store, "holder-a", epoch, "operator:bo", 7, 8).expect_err("wrong revision");
    assert_eq!(stale.category(), "idempotency_conflict");

    let resumed = resume(&mut store, "holder-a", epoch, "operator:bo", 1, 10).expect("resume");
    assert_eq!(resumed.pause_id, receipt.pause_id);
    assert_eq!(resumed.revision, 2);
    assert_eq!(store.intake_paused("generation-a", 11).expect("read"), None);

    let again =
        resume(&mut store, "holder-a", epoch, "operator:bo", 2, 12).expect_err("double resume");
    assert_eq!(again.category(), "intake_not_paused");

    // Both attributions survive the resume and a reopen: the pause row is
    // history, not a flag that gets cleared.
    drop(store);
    let reopened = Connection::open(database.path()).expect("raw reopen");
    let row: (String, String, i64, Option<String>, Option<i64>, i64) = reopened
        .query_row(
            "SELECT actor, reason, paused_at_ms, resume_actor, resumed_at_ms, revision
             FROM intake_pauses WHERE pause_id = ?1",
            [receipt.pause_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("durable pause row");
    assert_eq!(
        row,
        (
            "operator:ada".to_owned(),
            "hotfix".to_owned(),
            5,
            Some("operator:bo".to_owned()),
            Some(10),
            2
        )
    );
}

#[test]
fn intake_pause_is_fenced_by_generation_authority_and_scoped_to_its_generation() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let first = lease(&mut store, "holder-a", 0);

    // Wrong holder, wrong epoch, and an expired lease are all stale epochs.
    assert_eq!(
        pause(&mut store, "holder-b", first, "operator:ada", "hotfix", 5)
            .expect_err("foreign holder")
            .category(),
        "stale_epoch"
    );
    assert_eq!(
        pause(
            &mut store,
            "holder-a",
            first + 1,
            "operator:ada",
            "hotfix",
            5
        )
        .expect_err("future epoch")
        .category(),
        "stale_epoch"
    );
    assert_eq!(
        pause(&mut store, "holder-a", first, "operator:ada", "hotfix", 500)
            .expect_err("expired lease")
            .category(),
        "stale_epoch"
    );
    assert_eq!(
        store.intake_paused("generation-a", 5).expect("read"),
        None,
        "no refused pause may leave a durable row"
    );

    let receipt =
        pause(&mut store, "holder-a", first, "operator:ada", "hotfix", 5).expect("live authority");

    // A successor takes the lease at a new epoch. The pause is scoped to the
    // generation identifier, not the epoch that wrote it, so the successor
    // inherits it and resumes under its own epoch.
    let second = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "holder-b",
            now_ms: 200,
            ttl_ms: 100,
        })
        .expect("successor lease");
    assert!(second.epoch > first);
    assert_eq!(
        store
            .intake_paused("generation-a", 201)
            .expect("read")
            .expect("inherited")
            .pause_id,
        receipt.pause_id
    );
    assert_eq!(
        pause(&mut store, "holder-a", first, "operator:ada", "hotfix", 201)
            .expect_err("dead epoch")
            .category(),
        "stale_epoch"
    );
    assert_eq!(
        resume(&mut store, "holder-b", second.epoch, "operator:bo", 1, 202)
            .expect("successor resume")
            .revision,
        2
    );

    // A different generation has its own answer and is unaffected throughout.
    store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-b",
            holder_id: "holder-c",
            now_ms: 200,
            ttl_ms: 100,
        })
        .expect("other generation");
    pause(&mut store, "holder-a", first, "operator:ada", "hotfix", 203).ok();
    assert_eq!(
        store.intake_paused("generation-b", 204).expect("read"),
        None
    );
}

#[test]
fn intake_pause_refuses_unbounded_fields_and_survives_reopen() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let overlong = "a".repeat(257);
    for (actor, reason) in [
        ("", "hotfix"),
        ("operator:ada", ""),
        (overlong.as_str(), "hotfix"),
        ("operator:ada", overlong.as_str()),
        ("operator:\u{7}ada", "hotfix"),
    ] {
        assert_eq!(
            pause(&mut store, "holder-a", epoch, actor, reason, 5)
                .expect_err("unbounded field")
                .category(),
            "invalid_field"
        );
    }
    pause(&mut store, "holder-a", epoch, "operator:ada", "hotfix", 5).expect("bounded pause");
    drop(store);

    let mut reopened = Store::open(database.path()).expect("reopen");
    let version: u32 = Connection::open(database.path())
        .expect("raw reopen")
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version");
    assert_eq!(
        version, SCHEMA_VERSION,
        "reopening a paused database must not migrate it again"
    );
    let live = reopened
        .intake_paused("generation-a", 6)
        .expect("read")
        .expect("pause survived the reopen");
    assert_eq!(live.actor, "operator:ada");
    assert_eq!(live.reason, "hotfix");
}

/// A maximal Slack coordinate is a legitimate delivery, not an abusive one.
///
/// `automonique-transports` builds `slack:{app}:{team}:{channel}:{ts}` from four
/// coordinates of at most 128 bytes, so a long-coordinate workspace produces a
/// 521-byte key. The whole key has to survive submission, deduplication and the
/// claim, because the transport is the only thing that can map it back to the
/// message it came from.
#[test]
fn a_maximal_slack_transport_key_round_trips_through_submit_and_claim() {
    let coordinate = "9".repeat(128);
    let key = format!("slack:{coordinate}:{coordinate}:{coordinate}:{coordinate}");
    assert_eq!(key.len(), 521, "the derivable maximal Slack key");
    assert!(
        key.len() <= MAX_TRANSPORT_KEY_BYTES,
        "the inbox bound must admit the transport's maximal key"
    );
    assert_eq!(
        MAX_TRANSPORT_KEY_BYTES,
        automonique_store::slack_ingress::MAX_SOURCE_KEY_BYTES,
        "the inbox must admit exactly the keys the ingress log records"
    );

    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    let accepted = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &key,
            scope: "scope:slack",
            payload: b"slack-payload",
            received_ms: 1,
        })
        .expect("a maximal Slack key is a legitimate delivery");
    assert!(!accepted.duplicate);
    let accepted_events = store.event_count().expect("events");

    // The same delivery arriving twice is still one row, at this width.
    let retry = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &key,
            scope: "scope:slack",
            payload: b"slack-payload",
            received_ms: 2,
        })
        .expect("stable retry");
    assert_eq!(retry.inbox_id, accepted.inbox_id);
    assert!(retry.duplicate);
    assert_eq!(
        store.event_count().expect("events"),
        accepted_events,
        "a replayed maximal key must append nothing"
    );

    // Two Slack messages differing only in the last byte of their timestamp are
    // two deliveries, so the key is compared whole and not by a prefix.
    let mut neighbour = key.clone();
    neighbour.pop();
    neighbour.push('8');
    let separate = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &neighbour,
            scope: "scope:slack",
            payload: b"slack-payload",
            received_ms: 3,
        })
        .expect("a neighbouring timestamp is a different delivery");
    assert_ne!(separate.inbox_id, accepted.inbox_id);
    assert!(!separate.duplicate);

    // A replay carrying different content is still refused by stable key.
    let conflict = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &key,
            scope: "scope:slack",
            payload: b"rewritten",
            received_ms: 4,
        })
        .expect_err("changed delivery refused");
    assert_eq!(conflict.category(), "idempotency_conflict");

    // The claim hands the whole key back untruncated.
    let claim = store
        .claim_next(SchedulerClaim {
            transport: "slack",
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            now_ms: 5,
        })
        .expect("scheduler claim")
        .expect("pending Slack row");
    assert_eq!(claim.inbox_id, accepted.inbox_id);
    let owned = store
        .claimed_inbox(claim.run_id, "generation-a", "holder-a", epoch, 6)
        .expect("claimed Slack input");
    assert_eq!(owned.transport_key, key);
    assert_eq!(owned.transport_key.len(), 521);
    assert_eq!(owned.payload, b"slack-payload");

    // And it survives a reopen: the width is durable, not connection state.
    drop(store);
    let mut reopened = Store::open(database.path()).expect("reopen");
    let same = reopened
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &key,
            scope: "scope:slack",
            payload: b"slack-payload",
            received_ms: 7,
        })
        .expect("stable retry after reopen");
    assert_eq!(same.inbox_id, accepted.inbox_id);
    assert!(same.duplicate);
}

/// The inbox key is wider; nothing else is.
///
/// The widened bound is a bound, not an opening: it still ends somewhere, still
/// refuses empty and control-bearing keys, and the transport and scope beside it
/// keep the store's ordinary 256-byte identifier width.
#[test]
fn only_the_inbox_transport_key_widened_and_it_still_ends() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let widest = format!("slack:{}", "k".repeat(MAX_TRANSPORT_KEY_BYTES - 6));
    assert_eq!(widest.len(), MAX_TRANSPORT_KEY_BYTES);
    let widest_receipt = store
        .submit_inbox(InboxSubmission {
            transport: "slack",
            transport_key: &widest,
            scope: "scope:widest",
            payload: b"payload",
            received_ms: 1,
        })
        .expect("the exact maximum is accepted");
    assert!(!widest_receipt.duplicate);

    let over = format!("{widest}x");
    let mut control_bearing = widest.clone();
    control_bearing.pop();
    control_bearing.push('\u{7}');
    for (label, key) in [
        ("one byte over the maximum", over.as_str()),
        ("empty", ""),
        ("control-bearing at the maximum", control_bearing.as_str()),
    ] {
        let error = store
            .submit_inbox(InboxSubmission {
                transport: "slack",
                transport_key: key,
                scope: "scope:refused",
                payload: b"payload",
                received_ms: 2,
            })
            .expect_err(label);
        assert_eq!(error.category(), "invalid_field", "{label}");
        assert_eq!(error.to_string(), "invalid field: transport_key", "{label}");
    }

    // The identifiers beside the key did not move with it.
    let ordinary = "t".repeat(256);
    let overlong = "t".repeat(257);
    store
        .submit_inbox(InboxSubmission {
            transport: &ordinary,
            transport_key: "ordinary-width-neighbours",
            scope: &ordinary,
            payload: b"payload",
            received_ms: 3,
        })
        .expect("256-byte transport and scope are still accepted");
    for (field, transport, scope) in [
        ("transport", overlong.as_str(), ordinary.as_str()),
        ("scope", ordinary.as_str(), overlong.as_str()),
    ] {
        let error = store
            .submit_inbox(InboxSubmission {
                transport,
                transport_key: "unrelated-bound",
                scope,
                payload: b"payload",
                received_ms: 4,
            })
            .expect_err(field);
        assert_eq!(error.category(), "invalid_field", "{field}");
        assert_eq!(
            error.to_string(),
            format!("invalid field: {field}"),
            "{field}"
        );
    }

    // The short Telegram-shaped key that worked before still works, unchanged.
    let short = submit(&mut store, "telegram:7:42", "scope:short");
    assert_eq!(submit(&mut store, "telegram:7:42", "scope:short"), short);
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: a NULL must not slip a coupling
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*. A coupling
// written over a nullable column as a bare comparison — `col >= 1` — therefore
// admits the very row it was written to refuse, because `NULL >= 1` is `NULL`
// rather than false. Every coupling below spells `IS NULL` or `IS NOT NULL`
// before it compares anything, and these tests are what stops that spelling
// from being tidied back into a hole. Each drives the constraint through a raw
// connection, the only writer that can present a row this API never would, and
// each pairs its refusals with the legal row the fix must still admit.
// ---------------------------------------------------------------------------

/// Runs one raw statement per case and asserts every one of them is refused.
fn each_refused(raw: &Connection, cases: &[(&str, String)]) {
    for (what, statement) in cases {
        assert!(
            raw.execute(statement, []).is_err(),
            "the database must refuse {what}"
        );
    }
}

/// Runs one raw statement per case and asserts every one of them is admitted.
fn each_admitted(raw: &Connection, cases: &[(&str, String)]) {
    for (what, statement) in cases {
        raw.execute(statement, [])
            .unwrap_or_else(|error| panic!("the database must admit {what}: {error}"));
    }
}

#[test]
fn a_null_never_slips_the_outbox_state_coupling() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 1);
    add_effect(&mut store, epoch, "audit", 10);
    drop(store);

    let raw = Connection::open(database.path()).expect("raw write");
    let event_id: i64 = raw
        .query_row("SELECT event_id FROM domain_events LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("an event to hang an effect on");
    // Everything a row needs but the eight columns the coupling speaks about is
    // fixed, so a refusal can only have come from the coupling under test.
    let effect = |intent: &str, coupled: &str| {
        format!(
            "INSERT INTO outbox
                 (intent_key, event_id, transport, kind, payload, revision,
                  attempts, available_ms, last_error, created_ms,
                  state, lease_token, lease_generation_id, lease_holder,
                  lease_epoch, lease_expires_ms, delivery_receipt_key,
                  delivered_ms)
             VALUES ('{intent}', {event_id}, 'test', 'test.effect', x'00', 1,
                     0, 0, NULL, 0, {coupled})"
        )
    };

    each_refused(
        &raw,
        &[
            (
                "an in-flight effect whose lease has no epoch",
                effect(
                    "audit:no-epoch",
                    "'in_flight', 'lt', 'generation-a', 'holder-a', NULL, 5, NULL, NULL",
                ),
            ),
            (
                "an in-flight effect whose lease never expires",
                effect(
                    "audit:no-expiry",
                    "'in_flight', 'lt', 'generation-a', 'holder-a', 1, NULL, NULL, NULL",
                ),
            ),
            (
                "an in-flight effect leased at epoch zero",
                effect(
                    "audit:epoch-zero",
                    "'in_flight', 'lt', 'generation-a', 'holder-a', 0, 5, NULL, NULL",
                ),
            ),
            (
                "a delivered effect with no delivery instant",
                effect(
                    "audit:no-instant",
                    "'delivered', NULL, NULL, NULL, NULL, NULL, 'receipt:audit', NULL",
                ),
            ),
            (
                "a dead-lettered effect with no delivery instant",
                effect(
                    "audit:no-death",
                    "'dead_lettered', NULL, NULL, NULL, NULL, NULL, NULL, NULL",
                ),
            ),
        ],
    );

    // The coupling is tight, not merely strict: every legal shape still lands.
    each_admitted(
        &raw,
        &[
            (
                "a pending effect carrying no lease at all",
                effect(
                    "audit:pending",
                    "'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL",
                ),
            ),
            (
                "an in-flight effect carrying a whole lease",
                effect(
                    "audit:leased",
                    "'in_flight', 'lt', 'generation-a', 'holder-a', 1, 5, NULL, NULL",
                ),
            ),
            (
                "a delivered effect carrying a receipt and an instant",
                effect(
                    "audit:delivered",
                    "'delivered', NULL, NULL, NULL, NULL, NULL, 'receipt:done', 7",
                ),
            ),
        ],
    );
}

#[test]
fn a_null_never_slips_the_telegram_ingress_content_coupling() {
    let database = PrivateDatabase::new();
    let store = Store::open(database.path()).expect("open");
    drop(store);

    let raw = Connection::open(database.path()).expect("raw write");
    raw.execute(
        "INSERT INTO telegram_offsets (bot_id, next_offset, revision, updated_ms)
         VALUES (77, x'0000000000000000', 1, 0)",
        [],
    )
    .expect("an offset row to hang updates on");
    let update = |update_id: u8, source: &str, coupled: &str| {
        format!(
            "INSERT INTO telegram_ingress
                 (bot_id, update_id, source_key, scope, received_ms,
                  disposition, content)
             VALUES (77, x'00000000000000{update_id:02x}', '{source}', 'scope:a',
                     0, {coupled})"
        )
    };

    each_refused(
        &raw,
        &[
            (
                "an admitted update with no content",
                update(1, "src:1", "'admitted', NULL"),
            ),
            (
                "an admitted update with empty content",
                update(2, "src:2", "'admitted', x''"),
            ),
            (
                "a denied update carrying content anyway",
                update(3, "src:3", "'denied', x'00'"),
            ),
        ],
    );
    each_admitted(
        &raw,
        &[
            (
                "an admitted update with content",
                update(4, "src:4", "'admitted', x'00'"),
            ),
            (
                "a denied update with no content",
                update(5, "src:5", "'denied', NULL"),
            ),
        ],
    );

    // The columns v5 bolted onto `telegram_batches` guard their own NULL, since
    // an ALTER TABLE cannot add a table-level coupling to lean on.
    let batch = |expected: u8, next: u8, coupled: &str| {
        format!(
            "INSERT INTO telegram_batches
                 (bot_id, expected_offset, next_offset, disposition_count,
                  received_ms, poller_generation_id, poller_holder_id,
                  batch_digest, poller_epoch)
             VALUES (77, x'00000000000000{expected:02x}',
                     x'00000000000000{next:02x}', 1, 0, NULL, NULL, {coupled})"
        )
    };
    each_refused(
        &raw,
        &[
            ("a digest of the wrong width", batch(1, 2, "x'00', NULL")),
            ("a poller epoch of zero", batch(3, 4, "NULL, 0")),
        ],
    );
    each_admitted(
        &raw,
        &[
            ("a batch no poller has claimed", batch(5, 6, "NULL, NULL")),
            (
                "a batch a poller claimed at epoch one",
                batch(7, 8, &format!("x'{}', 1", "ab".repeat(32))),
            ),
        ],
    );
}

#[test]
fn a_null_never_slips_the_intake_pause_resume_coupling() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 1);
    pause(
        &mut store,
        "holder-a",
        epoch,
        "operator-a",
        "maintenance",
        5,
    )
    .expect("pause");
    drop(store);

    let raw = Connection::open(database.path()).expect("raw write");
    let resumption = |set: &str| format!("UPDATE intake_pauses SET {set}");

    each_refused(
        &raw,
        &[
            (
                "a resume instant with nobody who decided it",
                resumption("resumed_at_ms = 10"),
            ),
            (
                "a resuming actor with no instant",
                resumption("resume_actor = 'operator-b'"),
            ),
            (
                "a resume before the epoch",
                resumption("resumed_at_ms = -1, resume_actor = 'operator-b'"),
            ),
        ],
    );
    each_admitted(
        &raw,
        &[(
            "a whole resume",
            resumption("resumed_at_ms = 10, resume_actor = 'operator-b'"),
        )],
    );
}

fn pause_transport(
    store: &mut Store,
    epoch: u64,
    now_ms: i64,
    resume_after_ms: i64,
) -> Result<automonique_store::TransportPause, automonique_store::StoreError> {
    store.pause_transport(TransportPauseRequest {
        transport: "telegram",
        scope: "123456",
        generation_id: "generation-a",
        holder_id: "holder-a",
        authority_lease_epoch: epoch,
        reason: "rate_limited",
        now_ms,
        resume_after_ms,
    })
}

/// A 429 is about the bot, so the pause it produces is about the bot: one row,
/// a deadline, and an answer that survives the process that wrote it.
#[test]
fn a_transport_pause_is_durable_extended_only_and_lapses_on_its_own() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);
    assert_eq!(
        store
            .transport_pause("telegram", "123456", 1)
            .expect("read"),
        None,
        "a bot nobody has rate limited is not paused"
    );

    let recorded = pause_transport(&mut store, epoch, 5, 30_005).expect("first pause");
    assert_eq!(recorded.revision, 1);
    assert_eq!(recorded.paused_at_ms, 5);
    assert_eq!(recorded.resume_after_ms, 30_005);
    assert_eq!(recorded.reason, "rate_limited");

    let live = store
        .transport_pause("telegram", "123456", 9)
        .expect("read")
        .expect("paused");
    assert_eq!(live.resume_after_ms, 30_005);
    assert_eq!(live.observed_ms, 9, "the record is stamped with the read");

    // A shorter interval arriving second withdraws nothing: the deadline is the
    // longer of the two, and the pause is one episode rather than two.
    let shortened = pause_transport(&mut store, epoch, 10, 11).expect("second 429");
    assert_eq!(shortened.revision, 2);
    assert_eq!(shortened.resume_after_ms, 30_005);
    assert_eq!(shortened.paused_at_ms, 5, "the episode began at the first");
    let extended = pause_transport(&mut store, epoch, 12, 60_000).expect("third 429");
    assert_eq!(extended.revision, 3);
    assert_eq!(extended.resume_after_ms, 60_000);

    // The pause lapses at its own deadline. Nothing sweeps it.
    assert!(
        store
            .transport_pause("telegram", "123456", 59_999)
            .expect("read")
            .is_some()
    );
    assert_eq!(
        store
            .transport_pause("telegram", "123456", 60_000)
            .expect("read"),
        None
    );

    // A different bot, and a different transport, are different questions.
    assert_eq!(
        store.transport_pause("telegram", "999", 100).expect("read"),
        None
    );
    assert_eq!(
        store.transport_pause("slack", "123456", 100).expect("read"),
        None
    );

    // THE RESTART. The deadline is what the next process reads before it dials.
    drop(store);
    let mut reopened = Store::open(database.path()).expect("reopen");
    let inherited = reopened
        .transport_pause("telegram", "123456", 100)
        .expect("read")
        .expect("a restart honours the pause it inherited");
    assert_eq!(inherited.resume_after_ms, 60_000);
    assert_eq!(inherited.revision, 3);
}

/// The pause is state the next process reads before it dials, so a writer who
/// no longer holds the generation must not be able to install one.
#[test]
fn a_transport_pause_is_fenced_and_refuses_every_malformed_field() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 0);

    assert_eq!(
        pause_transport(&mut store, epoch + 1, 5, 10)
            .expect_err("a stale epoch writes nothing")
            .category(),
        "stale_epoch"
    );
    assert_eq!(
        store
            .pause_transport(TransportPauseRequest {
                transport: "telegram",
                scope: "123456",
                generation_id: "generation-a",
                holder_id: "somebody-else",
                authority_lease_epoch: epoch,
                reason: "rate_limited",
                now_ms: 5,
                resume_after_ms: 10,
            })
            .expect_err("a different holder writes nothing")
            .category(),
        "stale_epoch"
    );
    // A deadline before the instant it was decided is not a pause.
    assert_eq!(
        pause_transport(&mut store, epoch, 10, 9)
            .expect_err("a backwards deadline")
            .category(),
        "invalid_field"
    );
    for (label, request) in [
        (
            "an empty transport",
            TransportPauseRequest {
                transport: "",
                scope: "123456",
                generation_id: "generation-a",
                holder_id: "holder-a",
                authority_lease_epoch: epoch,
                reason: "rate_limited",
                now_ms: 5,
                resume_after_ms: 10,
            },
        ),
        (
            "an empty scope",
            TransportPauseRequest {
                transport: "telegram",
                scope: "",
                generation_id: "generation-a",
                holder_id: "holder-a",
                authority_lease_epoch: epoch,
                reason: "rate_limited",
                now_ms: 5,
                resume_after_ms: 10,
            },
        ),
        (
            "an empty reason",
            TransportPauseRequest {
                transport: "telegram",
                scope: "123456",
                generation_id: "generation-a",
                holder_id: "holder-a",
                authority_lease_epoch: epoch,
                reason: "",
                now_ms: 5,
                resume_after_ms: 10,
            },
        ),
        (
            "a negative instant",
            TransportPauseRequest {
                transport: "telegram",
                scope: "123456",
                generation_id: "generation-a",
                holder_id: "holder-a",
                authority_lease_epoch: epoch,
                reason: "rate_limited",
                now_ms: -1,
                resume_after_ms: 10,
            },
        ),
    ] {
        assert_eq!(
            store
                .pause_transport(request)
                .map(|pause| pause.revision)
                .map_err(|error| error.category()),
            Err("invalid_field"),
            "{label} must refuse"
        );
    }
    assert_eq!(
        store
            .transport_pause("telegram", "123456", 5)
            .expect("read"),
        None,
        "no refusal above wrote a row"
    );
    assert_eq!(
        store
            .transport_pause("", "123456", 5)
            .expect_err("an empty transport is not readable either")
            .category(),
        "invalid_field"
    );
}

/// A delivery is located by the coordinate it was submitted under, and its
/// disposition follows the lane from acceptance to a terminal state — without
/// a second submission, which the key would dedupe, and without a run
/// identity the reader may never have seen.
#[test]
fn an_inbox_disposition_is_read_by_transport_key_across_the_whole_lane() {
    let database = PrivateDatabase::new();
    let mut store = Store::open(database.path()).expect("open");
    let epoch = lease(&mut store, "holder-a", 1);

    assert_eq!(
        store
            .inbox_disposition("local-test", "occurrence:1")
            .expect("read"),
        None,
        "nothing was ever accepted under that key"
    );
    let inbox_id = submit(&mut store, "occurrence:1", "scope:a");
    let pending = store
        .inbox_disposition("local-test", "occurrence:1")
        .expect("read")
        .expect("accepted");
    assert_eq!(pending.inbox_id, inbox_id);
    assert_eq!(pending.state, automonique_store::InboxState::Pending);
    assert_eq!(pending.claimed_run_id, None);
    assert!(!pending.state.is_terminal());
    // The key is per transport: another transport's namespace is empty.
    assert_eq!(
        store
            .inbox_disposition("local-other", "occurrence:1")
            .expect("read"),
        None
    );

    let run = claim_next(&mut store, "holder-a", epoch, 2).expect("claim");
    let claimed = store
        .inbox_disposition("local-test", "occurrence:1")
        .expect("read")
        .expect("still there");
    assert_eq!(claimed.state, automonique_store::InboxState::Claimed);
    assert_eq!(claimed.claimed_run_id, Some(run.run_id));
    assert!(!claimed.state.is_terminal());

    finish_scheduled(&mut store, run.run_id, epoch, 3, "1");
    let completed = store
        .inbox_disposition("local-test", "occurrence:1")
        .expect("read")
        .expect("still there");
    assert_eq!(completed.state, automonique_store::InboxState::Completed);
    assert_eq!(completed.claimed_run_id, Some(run.run_id));
    assert!(completed.state.is_terminal());

    // A failed run is terminal the other way.
    submit(&mut store, "occurrence:2", "scope:b");
    let failing = claim_next(&mut store, "holder-a", epoch, 4).expect("claim");
    store
        .finish_run(TerminalRun {
            run_id: failing.run_id,
            generation_id: "generation-a",
            holder_id: "holder-a",
            lease_epoch: epoch,
            expected_revision: 1,
            now_ms: 5,
            state: TerminalState::Failed,
            event_kind: "run.failed",
            event_payload: b"2",
            outbox_intent_key: "intent:2",
            outbox_kind: "test.effect",
            outbox_payload: b"2",
        })
        .expect("finish as failed");
    let failed = store
        .inbox_disposition("local-test", "occurrence:2")
        .expect("read")
        .expect("still there");
    assert_eq!(failed.state, automonique_store::InboxState::Failed);
    assert!(failed.state.is_terminal());

    // The coordinate is validated like a submission's, so a key the inbox
    // could not hold is refused rather than looked up.
    assert_eq!(
        store
            .inbox_disposition("local-test", "")
            .expect_err("empty key")
            .category(),
        "invalid_field"
    );
    assert_eq!(
        store
            .inbox_disposition("local-test", &"k".repeat(MAX_TRANSPORT_KEY_BYTES + 1))
            .expect_err("over-long key")
            .category(),
        "invalid_field"
    );
}
