// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use automonique_store::{LeaseRequest, LeaseTimeSource, Store, TelegramPollerLeaseRequest};
use automonique_transport_runtime::{
    CancellationToken, Clock, ClockFailure, DurableDisposition, DurableTelegramBatch,
    DurableTelegramUpdate, HttpFailure, OpaqueBotToken, PendingCommit, PollerLease, SinkFailure,
    StoreTelegramDurableSink, TelegramDurableSink, TelegramHostState, TelegramHttpClient,
    TelegramHttpPlan, TelegramHttpResponse, TelegramLeaseCoordinator, TelegramPoller,
};
use automonique_transports::{
    TelegramAccessPolicy, TelegramBotId, TelegramInputKind, TelegramPrincipal,
};

#[derive(Clone, Default)]
struct NoHttp(Arc<AtomicUsize>);

impl TelegramHttpClient for NoHttp {
    fn execute(
        &mut self,
        _plan: &TelegramHttpPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Err(HttpFailure::Unavailable)
    }
}

struct EmptyUpdates {
    calls: Arc<AtomicUsize>,
    completed_ms: i64,
}

impl TelegramHttpClient for EmptyUpdates {
    fn execute(
        &mut self,
        _plan: &TelegramHttpPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(TelegramHttpResponse {
            status: 200,
            body: br#"{"ok":true,"result":[]}"#.to_vec(),
            completed_ms: self.completed_ms,
        })
    }
}

#[test]
fn coordinator_release_and_successor_handoff_fence_the_stale_owner() {
    let (_directory, path, store, initial_lease) = open_fixture();
    let clock = TestClock::new(2);
    let mut coordinator = TelegramLeaseCoordinator::disabled(
        StoreTelegramDurableSink::new(store, clock.clone()),
        1,
        600,
    )
    .expect("disabled coordinator");
    assert_eq!(coordinator.state(), &TelegramHostState::DisabledNoClient);
    let owned = coordinator
        .acquire_no_client(7, "generation-a", "poller-a")
        .expect("idempotent existing lease")
        .clone();
    assert_eq!(owned, initial_lease);
    clock.set(10);
    let renewed = coordinator.renew().expect("renew").clone();
    assert_eq!(renewed.epoch, owned.epoch);
    assert!(renewed.expires_ms > owned.expires_ms);

    let unresolved = PendingCommit::restore(batch(b"pending")).expect("pending commit");
    coordinator
        .restore_pending_commit(unresolved)
        .expect("restore pending");
    assert!(matches!(
        coordinator.release(),
        Err(automonique_transport_runtime::RuntimeError::CommitReconciliationRequired { .. })
    ));
    assert!(matches!(
        coordinator.state(),
        TelegramHostState::LeaseOwnedNoClient(_)
    ));
    coordinator
        .resolve_pending_commit()
        .expect("resolve exact pending commit");
    clock.set(20);
    coordinator.release().expect("resolved shutdown release");
    assert_eq!(coordinator.state(), &TelegramHostState::DisabledNoClient);
    let (mut store, _) = coordinator
        .into_sink()
        .expect("clean sink handoff")
        .into_parts();
    store
        .release_generation_lease("generation-a", "poller-a", 1, 20)
        .expect("release old generation");
    let successor_authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "poller-b",
            now_ms: 21,
            ttl_ms: 1_000,
        })
        .expect("successor generation");
    clock.set(22);
    let mut successor = TelegramLeaseCoordinator::disabled(
        StoreTelegramDurableSink::new(store, clock.clone()),
        successor_authority.epoch,
        600,
    )
    .expect("successor coordinator");
    let next = successor
        .acquire_no_client(7, "generation-a", "poller-b")
        .expect("successor lease")
        .clone();
    assert!(next.epoch > renewed.epoch);
    assert_ne!(next.holder_id, renewed.holder_id);

    successor.release().expect("successor clean release");
    let (store, _) = successor.into_sink().expect("successor sink").into_parts();
    let mut stale = StoreTelegramDurableSink::new(Store::open(&path).expect("stale store"), clock);
    assert_eq!(
        stale
            .read_offset(&renewed, 0)
            .expect_err("stale owner cannot read"),
        SinkFailure::StaleLease
    );
    let stale_batch = DurableTelegramBatch::new(
        7,
        0,
        1,
        22,
        vec![DurableTelegramUpdate {
            update_id: 0,
            source_key: "telegram:7:update:0".to_owned(),
            scope: "telegram:7:chat:-100".to_owned(),
            kind: TelegramInputKind::Message,
            disposition: DurableDisposition::Denied,
        }],
    )
    .expect("stale batch");
    assert_eq!(
        stale
            .commit_batch(&renewed, &stale_batch, renewed.expires_ms)
            .expect_err("stale owner cannot commit"),
        SinkFailure::StaleLease
    );
    assert_eq!(store.telegram_offset(7).expect("no stale advance"), Some(6));
}

#[test]
fn crashed_coordinator_keeps_fence_until_expiry_then_successor_takes_over() {
    let (_directory, path, store, initial_lease) = open_fixture();
    let clock = TestClock::new(2);
    let mut crashed = TelegramLeaseCoordinator::disabled(
        StoreTelegramDurableSink::new(store, clock.clone()),
        1,
        600,
    )
    .expect("disabled coordinator");
    let crashed_lease = crashed
        .acquire_no_client(7, "generation-a", "poller-a")
        .expect("existing lease")
        .clone();
    drop(crashed);

    let mut store = Store::open(&path).expect("restart before expiry");
    assert_eq!(
        store
            .acquire_generation_lease(LeaseRequest {
                generation_id: "generation-a",
                holder_id: "poller-b",
                now_ms: 500,
                ttl_ms: 1_000,
            })
            .expect_err("live crashed authority remains fenced")
            .category(),
        "lease_held"
    );

    let successor_authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "poller-b",
            now_ms: 1_001,
            ttl_ms: 1_000,
        })
        .expect("successor generation after expiry");
    clock.set(1_002);
    let mut successor = TelegramLeaseCoordinator::disabled(
        StoreTelegramDurableSink::new(store, clock.clone()),
        successor_authority.epoch,
        600,
    )
    .expect("successor coordinator");
    let successor_lease = successor
        .acquire_no_client(7, "generation-a", "poller-b")
        .expect("successor poller lease")
        .clone();
    assert!(successor_lease.epoch > crashed_lease.epoch);

    let mut stale = StoreTelegramDurableSink::new(Store::open(&path).expect("stale store"), clock);
    assert_eq!(
        stale
            .read_offset(&initial_lease, 0)
            .expect_err("crashed owner cannot read after takeover"),
        SinkFailure::StaleLease
    );
    assert_eq!(
        stale
            .commit_batch(&initial_lease, &batch(b"stale"), initial_lease.expires_ms)
            .expect_err("crashed owner cannot commit after takeover"),
        SinkFailure::StaleLease
    );

    successor.release().expect("successor release");
    let (store, _) = successor.into_sink().expect("clean successor").into_parts();
    assert_eq!(store.telegram_offset(7).expect("no stale advance"), None);
}

fn policy() -> TelegramAccessPolicy {
    TelegramAccessPolicy::new(
        TelegramBotId::new(7).expect("bot"),
        [TelegramPrincipal::new(-100, 42).expect("principal")],
    )
    .expect("policy")
}

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn new(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::Release);
    }
}

impl Clock for TestClock {
    fn now_ms(&mut self) -> Result<i64, ClockFailure> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

#[derive(Clone)]
struct TestLeaseClock(Arc<AtomicI64>);

impl LeaseTimeSource for TestLeaseClock {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        Ok(self.0.load(Ordering::Acquire))
    }
}

#[test]
fn poller_compares_store_lease_expiry_in_lease_clock_domain() {
    const WALL_NOW_MS: i64 = 1_786_890_000_000;
    const LEASE_NOW_MS: i64 = 100;

    let directory = tempfile::tempdir().expect("private directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private mode");
    let path = directory.path().join("store.sqlite3");
    let lease_clock = TestLeaseClock(Arc::new(AtomicI64::new(LEASE_NOW_MS)));
    let mut store =
        Store::open_with_lease_time_source(&path, Arc::new(lease_clock)).expect("boot-time store");
    let authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "poller-a",
            now_ms: WALL_NOW_MS,
            ttl_ms: 20_000,
        })
        .expect("generation authority");
    let lease = PollerLease::try_from(
        store
            .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
                bot_id: 7,
                generation_id: "generation-a",
                holder_id: "poller-a",
                authority_lease_epoch: authority.epoch,
                now_ms: WALL_NOW_MS,
                ttl_ms: 10_000,
            })
            .expect("poller lease"),
    )
    .expect("runtime lease");
    assert!(
        lease.expires_ms < WALL_NOW_MS,
        "clock domains deliberately diverge"
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let client = EmptyUpdates {
        calls: Arc::clone(&calls),
        completed_ms: WALL_NOW_MS + 1,
    };
    let sink = StoreTelegramDurableSink::new(store, TestClock::new(WALL_NOW_MS));
    let mut poller = TelegramPoller::new(
        client,
        sink,
        policy(),
        OpaqueBotToken::new(b"fixture-token".to_vec()).expect("token"),
        3,
    )
    .expect("poller");

    let outcome = poller
        .poll_once(&lease, WALL_NOW_MS, &CancellationToken::new())
        .expect("wall-time audit and boot-time lease coexist");
    assert_eq!(outcome.next_offset, 0);
    assert_eq!(calls.load(Ordering::Acquire), 1);
}

fn open_fixture() -> (tempfile::TempDir, std::path::PathBuf, Store, PollerLease) {
    let directory = tempfile::tempdir().expect("private directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private mode");
    let path = directory.path().join("store.sqlite3");
    let mut store = Store::open(&path).expect("store");
    let authority = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "generation-a",
            holder_id: "poller-a",
            now_ms: 0,
            ttl_ms: 1_000,
        })
        .expect("generation authority");
    let poller = store
        .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
            bot_id: 7,
            generation_id: "generation-a",
            holder_id: "poller-a",
            authority_lease_epoch: authority.epoch,
            now_ms: 1,
            ttl_ms: 500,
        })
        .expect("poller lease");
    let runtime_lease = PollerLease::try_from(poller).expect("runtime lease");
    (directory, path, store, runtime_lease)
}

fn batch(content: &[u8]) -> DurableTelegramBatch {
    DurableTelegramBatch::new(
        7,
        0,
        6,
        9,
        vec![
            DurableTelegramUpdate {
                update_id: 2,
                source_key: "telegram:7:update:2".to_owned(),
                scope: "telegram:7:chat:-100".to_owned(),
                kind: TelegramInputKind::Message,
                disposition: DurableDisposition::Admitted {
                    content: content.to_vec(),
                },
            },
            DurableTelegramUpdate {
                update_id: 4,
                source_key: "telegram:7:update:4".to_owned(),
                scope: "telegram:7:chat:-100".to_owned(),
                kind: TelegramInputKind::Callback,
                disposition: DurableDisposition::Denied,
            },
            DurableTelegramUpdate {
                update_id: 5,
                source_key: "telegram:7:update:5".to_owned(),
                scope: "telegram:7:unsupported".to_owned(),
                kind: TelegramInputKind::Unsupported,
                disposition: DurableDisposition::IgnoredUnsupported,
            },
        ],
    )
    .expect("canonical batch")
}

#[test]
fn real_store_sink_commits_replays_after_restart_and_refuses_stale_or_changed_input() {
    let (_directory, path, store, lease) = open_fixture();
    let clock = TestClock::new(10);
    let clock_control = clock.clone();
    let mut sink = StoreTelegramDurableSink::new(store, clock);

    let offset = sink
        .read_offset(&lease, -1)
        .expect("trusted clock, not caller time, authorizes read");
    assert_eq!(offset.next_offset, 0);
    let original = batch(b"accepted");
    let first = sink
        .commit_batch(&lease, &original, lease.expires_ms)
        .expect("atomic commit");
    assert!(!first.duplicate);
    assert_eq!(first.next_offset, 6);
    assert_eq!(first.disposition_count, 3);
    assert_eq!(first.batch_digest, original.digest);

    let (store, _) = sink.into_parts();
    let admitted = store
        .telegram_disposition(7, 2)
        .expect("admitted disposition");
    assert_eq!(admitted.disposition, "admitted");
    assert_eq!(admitted.content, Some(b"accepted".to_vec()));
    let denied = store
        .telegram_disposition(7, 4)
        .expect("denied disposition");
    assert_eq!(denied.disposition, "denied");
    assert_eq!(denied.content, None);
    let unsupported = store
        .telegram_disposition(7, 5)
        .expect("unsupported disposition");
    assert_eq!(unsupported.disposition, "ignored_unsupported");
    assert_eq!(unsupported.content, None);
    drop(store);

    let reopened = Store::open(&path).expect("restart");
    let mut sink = StoreTelegramDurableSink::new(reopened, clock_control.clone());
    let next = DurableTelegramBatch::new(
        7,
        6,
        7,
        20,
        vec![DurableTelegramUpdate {
            update_id: 6,
            source_key: "telegram:7:update:6".to_owned(),
            scope: "telegram:7:chat:-100".to_owned(),
            kind: TelegramInputKind::Message,
            disposition: DurableDisposition::Denied,
        }],
    )
    .expect("next batch");
    let stale_epoch = PollerLease {
        epoch: lease.epoch + 1,
        ..lease.clone()
    };
    assert_eq!(
        sink.commit_batch(&stale_epoch, &next, stale_epoch.expires_ms)
            .expect_err("wrong poller epoch refuses"),
        SinkFailure::StaleLease
    );
    let invalid_disposition = DurableTelegramBatch::new(
        7,
        6,
        7,
        20,
        vec![DurableTelegramUpdate {
            update_id: 6,
            source_key: "telegram:7:update:6".to_owned(),
            scope: "telegram:7:unsupported".to_owned(),
            kind: TelegramInputKind::Unsupported,
            disposition: DurableDisposition::Denied,
        }],
    )
    .expect("digest-bound but semantically invalid batch");
    assert_eq!(
        sink.commit_batch(&lease, &invalid_disposition, lease.expires_ms)
            .expect_err("unsupported kind cannot become denied"),
        SinkFailure::Conflict
    );

    clock_control.set(600);
    let replay = sink
        .commit_batch(&lease, &original, lease.expires_ms)
        .expect("exact receipt replay survives lease expiry and restart");
    assert!(replay.duplicate);

    let changed_content = batch(b"changed");
    assert_eq!(
        sink.commit_batch(&lease, &changed_content, lease.expires_ms)
            .expect_err("changed durable content refuses"),
        SinkFailure::Conflict
    );
    let mut changed_digest = original.clone();
    changed_digest.digest[0] ^= 1;
    assert_eq!(
        sink.commit_batch(&lease, &changed_digest, lease.expires_ms)
            .expect_err("fabricated digest refuses before store"),
        SinkFailure::Conflict
    );

    assert_eq!(
        sink.commit_batch(&lease, &next, lease.expires_ms)
            .expect_err("expired lease cannot advance"),
        SinkFailure::StaleLease
    );
    let (store, _) = sink.into_parts();
    assert_eq!(store.telegram_offset(7).expect("unchanged offset"), Some(6));
    assert_eq!(
        store
            .telegram_disposition(7, 6)
            .expect_err("stale disposition absent")
            .category(),
        "not_found"
    );
}

#[test]
fn poller_reconciles_exact_commit_after_expiry_but_cannot_make_a_stale_new_commit() {
    let (_directory, path, store, lease) = open_fixture();
    let original = batch(b"accepted");
    let clock = TestClock::new(10);
    let mut initial = StoreTelegramDurableSink::new(store, clock.clone());
    initial
        .commit_batch(&lease, &original, lease.expires_ms)
        .expect("commit whose acknowledgement will be treated as lost");
    drop(initial);

    clock.set(lease.expires_ms + 1);
    let no_http = NoHttp::default();
    let calls = Arc::clone(&no_http.0);
    let sink = StoreTelegramDurableSink::new(Store::open(&path).expect("restart"), clock.clone());
    let mut restarted = TelegramPoller::new(
        no_http,
        sink,
        policy(),
        OpaqueBotToken::new(b"fixture-token".to_vec()).expect("token"),
        30,
    )
    .expect("poller");
    restarted
        .restore_pending_commit(PendingCommit::restore(original.clone()).expect("pending"))
        .expect("restore ambiguity");
    let recovered = restarted
        .reconcile_commit(&lease, lease.expires_ms + 1)
        .expect("durable exact receipt remains recoverable after expiry");
    assert!(recovered.duplicate);
    assert_eq!(calls.load(Ordering::Acquire), 0);

    let (_other_directory, _other_path, other_store, other_lease) = open_fixture();
    let no_http = NoHttp::default();
    let calls = Arc::clone(&no_http.0);
    let other_clock = TestClock::new(other_lease.expires_ms + 1);
    let other_sink = StoreTelegramDurableSink::new(other_store, other_clock);
    let mut uncommitted = TelegramPoller::new(
        no_http,
        other_sink,
        policy(),
        OpaqueBotToken::new(b"fixture-token".to_vec()).expect("token"),
        30,
    )
    .expect("poller");
    uncommitted
        .restore_pending_commit(PendingCommit::restore(original).expect("pending"))
        .expect("restore ambiguity");
    assert!(matches!(
        uncommitted.reconcile_commit(&other_lease, other_lease.expires_ms + 1),
        Err(automonique_transport_runtime::RuntimeError::Sink(
            SinkFailure::StaleLease
        ))
    ));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    let (_, sink) = uncommitted.into_parts();
    let (store, _) = sink.into_parts();
    assert_eq!(store.telegram_offset(7).expect("offset"), None);
}
