// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use automonique_store::{LeaseRequest, Store, TelegramPollerLeaseRequest};
use automonique_transport_runtime::{
    CancellationToken, Clock, ClockFailure, DurableDisposition, DurableTelegramBatch,
    DurableTelegramUpdate, HttpFailure, OpaqueBotToken, PendingCommit, PollerLease, SinkFailure,
    StoreTelegramDurableSink, TelegramDurableSink, TelegramHttpClient, TelegramHttpPlan,
    TelegramHttpResponse, TelegramPoller,
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
