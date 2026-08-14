// SPDX-License-Identifier: Elastic-2.0

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use automonique_transport_runtime::{
    CancellationToken, DurableCommitReceipt, DurableDisposition, DurableTelegramBatch,
    GetUpdatesBody, HttpFailure, HttpMethod, OffsetReceipt, OpaqueBotToken, PollerLease,
    RuntimeError, SinkFailure, TelegramDurableSink, TelegramHttpClient, TelegramHttpPlan,
    TelegramHttpResponse, TelegramPoller, TelegramTarget,
};
use automonique_transports::{
    MAX_TELEGRAM_UPDATES, TelegramAccessPolicy, TelegramBotId, TelegramDisposition,
    TelegramPrincipal,
};

#[derive(Clone)]
struct FakeClient {
    state: Arc<Mutex<ClientState>>,
    order: Arc<Mutex<Vec<&'static str>>>,
}

struct ClientState {
    behaviors: VecDeque<ClientBehavior>,
    plans: Vec<ObservedPlan>,
}

enum ClientBehavior {
    Response(TelegramHttpResponse),
    Failure(HttpFailure),
    BlockUntilCancelled,
    CancelThenRespond(TelegramHttpResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedPlan {
    method: HttpMethod,
    target: TelegramTarget,
    bot_id: i64,
    body: GetUpdatesBody,
    had_authorization: bool,
    debug: String,
}

impl FakeClient {
    fn new(
        behaviors: impl IntoIterator<Item = ClientBehavior>,
        order: Arc<Mutex<Vec<&'static str>>>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClientState {
                behaviors: behaviors.into_iter().collect(),
                plans: Vec::new(),
            })),
            order,
        }
    }
}

impl TelegramHttpClient for FakeClient {
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        self.order.lock().unwrap().push("http");
        let behavior = {
            let mut state = self.state.lock().unwrap();
            state.plans.push(ObservedPlan {
                method: plan.method,
                target: plan.target,
                bot_id: plan.bot_id,
                body: plan.body,
                had_authorization: plan
                    .authorization()
                    .with_secret(|secret| secret == b"123456:fixture-secret"),
                debug: format!("{plan:?}"),
            });
            state.behaviors.pop_front().expect("fixture response")
        };
        match behavior {
            ClientBehavior::Response(response) => Ok(response),
            ClientBehavior::Failure(error) => Err(error),
            ClientBehavior::BlockUntilCancelled => {
                while !cancellation.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(HttpFailure::Cancelled)
            }
            ClientBehavior::CancelThenRespond(response) => {
                cancellation.cancel();
                Ok(response)
            }
        }
    }
}

#[derive(Clone)]
struct FakeSink {
    state: Arc<Mutex<SinkState>>,
    order: Arc<Mutex<Vec<&'static str>>>,
}

struct SinkState {
    authority: PollerLease,
    offsets: BTreeMap<i64, u64>,
    committed: Vec<DurableTelegramBatch>,
    failure: CommitFailure,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CommitFailure {
    None,
    BeforeOnce,
    AmbiguousAfterOnce,
}

impl FakeSink {
    fn new(authority: PollerLease, order: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(SinkState {
                authority,
                offsets: BTreeMap::new(),
                committed: Vec::new(),
                failure: CommitFailure::None,
            })),
            order,
        }
    }

    fn authorize(state: &SinkState, lease: &PollerLease) -> Result<(), SinkFailure> {
        if state.authority != *lease {
            Err(SinkFailure::StaleLease)
        } else {
            Ok(())
        }
    }
}

impl TelegramDurableSink for FakeSink {
    fn read_offset(
        &mut self,
        lease: &PollerLease,
        now_ms: i64,
    ) -> Result<OffsetReceipt, SinkFailure> {
        self.order.lock().unwrap().push("read");
        let state = self.state.lock().unwrap();
        Self::authorize(&state, lease)?;
        if lease.expires_ms <= now_ms {
            return Err(SinkFailure::StaleLease);
        }
        Ok(OffsetReceipt {
            bot_id: lease.bot_id,
            lease_epoch: lease.epoch,
            next_offset: state.offsets.get(&lease.bot_id).copied().unwrap_or(0),
        })
    }

    fn commit_batch(
        &mut self,
        lease: &PollerLease,
        batch: &DurableTelegramBatch,
        commit_before_ms: i64,
    ) -> Result<DurableCommitReceipt, SinkFailure> {
        self.order.lock().unwrap().push("commit");
        let mut state = self.state.lock().unwrap();
        Self::authorize(&state, lease)?;
        if state.authority.expires_ms != commit_before_ms {
            return Err(SinkFailure::StaleLease);
        }
        if state.failure == CommitFailure::BeforeOnce {
            state.failure = CommitFailure::None;
            return Err(SinkFailure::Unavailable);
        }
        let current = state.offsets.get(&lease.bot_id).copied().unwrap_or(0);
        if current == batch.next_offset {
            return Ok(DurableCommitReceipt {
                bot_id: lease.bot_id,
                lease_epoch: lease.epoch,
                next_offset: current,
                disposition_count: batch.updates.len(),
                batch_digest: batch.digest,
                duplicate: true,
            });
        }
        if current != batch.expected_offset {
            return Err(SinkFailure::Conflict);
        }
        state.offsets.insert(lease.bot_id, batch.next_offset);
        state.committed.push(batch.clone());
        if state.failure == CommitFailure::AmbiguousAfterOnce {
            state.failure = CommitFailure::None;
            return Err(SinkFailure::AmbiguousCommit);
        }
        Ok(DurableCommitReceipt {
            bot_id: lease.bot_id,
            lease_epoch: lease.epoch,
            next_offset: batch.next_offset,
            disposition_count: batch.updates.len(),
            batch_digest: batch.digest,
            duplicate: false,
        })
    }
}

fn policy() -> TelegramAccessPolicy {
    TelegramAccessPolicy::new(
        TelegramBotId::new(7).unwrap(),
        [TelegramPrincipal::new(-100, 42).unwrap()],
    )
    .unwrap()
}

fn lease() -> PollerLease {
    PollerLease::new(7, "generation-a", "holder-a", 3, 100_000).unwrap()
}

fn response(body: impl Into<Vec<u8>>) -> TelegramHttpResponse {
    TelegramHttpResponse {
        status: 200,
        body: body.into(),
        completed_ms: 20,
    }
}

fn response_at(body: impl Into<Vec<u8>>, completed_ms: i64) -> TelegramHttpResponse {
    TelegramHttpResponse {
        status: 200,
        body: body.into(),
        completed_ms,
    }
}

type TestPoller = TelegramPoller<FakeClient, FakeSink>;
type TestRig = (
    TestPoller,
    FakeClient,
    FakeSink,
    Arc<Mutex<Vec<&'static str>>>,
);

fn poller(behaviors: impl IntoIterator<Item = ClientBehavior>) -> TestRig {
    let order = Arc::new(Mutex::new(Vec::new()));
    let client = FakeClient::new(behaviors, order.clone());
    let sink = FakeSink::new(lease(), order.clone());
    let runtime = TelegramPoller::new(
        client.clone(),
        sink.clone(),
        policy(),
        OpaqueBotToken::new(b"123456:fixture-secret".to_vec()).unwrap(),
        30,
    )
    .unwrap();
    (runtime, client, sink, order)
}

#[test]
fn poll_orders_offset_http_parse_and_atomic_commit_with_all_dispositions() {
    let payload = br#"{"ok":true,"result":[{"update_id":0,"message":{"chat":{"id":-100},"from":{"id":42},"text":"allowed"}},{"update_id":1,"message":{"chat":{"id":-100},"from":{"id":99},"text":"denied secret"}},{"update_id":2,"edited_message":{}}]}"#;
    let (mut poller, client, sink, order) = poller([ClientBehavior::Response(response(payload))]);
    let outcome = poller
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect("poll");
    assert_eq!(outcome.previous_offset, 0);
    assert_eq!(outcome.next_offset, 3);
    assert_eq!(outcome.disposition_count, 3);
    assert_eq!(*order.lock().unwrap(), ["read", "http", "commit"]);

    let state = sink.state.lock().unwrap();
    let committed = &state.committed[0];
    assert!(matches!(
        committed.updates[0].disposition,
        DurableDisposition::Admitted { ref content } if content == b"allowed"
    ));
    assert_eq!(committed.updates[1].disposition, DurableDisposition::Denied);
    assert_eq!(
        committed.updates[2].disposition,
        DurableDisposition::IgnoredUnsupported
    );
    assert!(!format!("{committed:?}").contains("denied secret"));
    drop(state);

    let plans = &client.state.lock().unwrap().plans;
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].method, HttpMethod::Post);
    assert_eq!(plans[0].target, TelegramTarget::GetUpdates);
    assert_eq!(plans[0].bot_id, 7);
    assert_eq!(plans[0].body.offset, 0);
    assert_eq!(plans[0].body.limit, MAX_TELEGRAM_UPDATES);
    assert_eq!(plans[0].body.timeout_seconds, 30);
    assert!(plans[0].had_authorization);
    assert!(!plans[0].debug.contains("fixture-secret"));
    assert!(
        !format!(
            "{:?}",
            OpaqueBotToken::new(b"fixture-secret".to_vec()).unwrap()
        )
        .contains("fixture-secret")
    );
}

#[test]
fn failure_before_commit_keeps_offset_and_exact_retry_succeeds() {
    let payload = br#"{"ok":true,"result":[{"update_id":0,"message":{"chat":{"id":-100},"from":{"id":42},"text":"retry"}}]}"#;
    let (mut first_poller, _client, sink, _) = poller([
        ClientBehavior::Response(response(payload)),
        ClientBehavior::Response(response(payload)),
    ]);
    sink.state.lock().unwrap().failure = CommitFailure::BeforeOnce;
    let error = first_poller
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect_err("commit failure");
    assert!(matches!(
        error,
        RuntimeError::Sink(SinkFailure::Unavailable)
    ));
    assert_eq!(sink.state.lock().unwrap().offsets.get(&7), None);

    let outcome = first_poller
        .poll_once(&lease(), 11, &CancellationToken::new())
        .expect("retry");
    assert_eq!(outcome.next_offset, 1);
    assert_eq!(sink.state.lock().unwrap().committed.len(), 1);
}

#[test]
fn ambiguous_commit_and_duplicate_response_do_not_duplicate_dispositions() {
    let payload = br#"{"ok":true,"result":[{"update_id":0,"message":{"chat":{"id":-100},"from":{"id":42},"text":"once"}}]}"#;
    let (mut first_poller, _client, sink, _) = poller([
        ClientBehavior::Response(response(payload)),
        ClientBehavior::Response(response(payload)),
    ]);
    sink.state.lock().unwrap().failure = CommitFailure::AmbiguousAfterOnce;
    let error = first_poller
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect_err("ambiguous acknowledgement");
    assert!(matches!(
        error,
        RuntimeError::CommitReconciliationRequired { next_offset: 1, .. }
    ));
    assert_eq!(sink.state.lock().unwrap().offsets.get(&7), Some(&1));
    let durable_pending = first_poller
        .take_pending_commit()
        .expect("ambiguity state exported for durable host storage");
    assert!(!format!("{durable_pending:?}").contains("once"));
    let persisted_batch = durable_pending.batch().clone();
    let durable_pending = automonique_transport_runtime::PendingCommit::restore(persisted_batch)
        .expect("persisted batch reconstructs exact ambiguity after process restart");
    let (mut restarted, restarted_client, _, _) =
        poller([ClientBehavior::Response(response(payload))]);
    restarted
        .restore_pending_commit(durable_pending)
        .expect("exact ambiguity restored before polling");
    assert!(matches!(
        restarted.poll_once(&lease(), 11, &CancellationToken::new()),
        Err(RuntimeError::CommitReconciliationRequired { next_offset: 1, .. })
    ));
    assert!(restarted_client.state.lock().unwrap().plans.is_empty());

    assert!(matches!(
        restarted.poll_once(&lease(), 11, &CancellationToken::new()),
        Err(RuntimeError::CommitReconciliationRequired { next_offset: 1, .. })
    ));
    assert_eq!(
        restarted.into_parts().0.state.lock().unwrap().plans.len(),
        0,
        "ambiguity must stop another Telegram request"
    );

    let (mut second_poller, _client, sink, _) =
        poller([ClientBehavior::Response(response(payload))]);
    sink.state.lock().unwrap().failure = CommitFailure::AmbiguousAfterOnce;
    second_poller
        .poll_once(&lease(), 11, &CancellationToken::new())
        .expect_err("ambiguous acknowledgement");
    let duplicate = second_poller.reconcile_commit(&lease(), 100_001).expect(
        "exact retained batch resolves after lease expiry through durable duplicate receipt",
    );
    assert_eq!(duplicate.previous_offset, 0);
    assert_eq!(duplicate.next_offset, 1);
    assert!(duplicate.duplicate);
    assert_eq!(sink.state.lock().unwrap().committed.len(), 1);
}

#[test]
fn bot_scope_and_single_poller_lease_mismatches_fail_before_http() {
    let payload = br#"{"ok":true,"result":[]}"#;
    let (mut poller, client, _sink, _) = poller([ClientBehavior::Response(response(payload))]);
    let wrong_bot = PollerLease::new(8, "generation-a", "holder-a", 3, 100_000).unwrap();
    assert!(matches!(
        poller.poll_once(&wrong_bot, 10, &CancellationToken::new()),
        Err(RuntimeError::LeaseMismatch)
    ));
    assert!(client.state.lock().unwrap().plans.is_empty());

    let wrong_holder = PollerLease::new(7, "generation-a", "holder-b", 3, 100_000).unwrap();
    assert!(matches!(
        poller.poll_once(&wrong_holder, 10, &CancellationToken::new()),
        Err(RuntimeError::Sink(SinkFailure::StaleLease))
    ));
    assert!(client.state.lock().unwrap().plans.is_empty());
}

#[test]
fn parser_maximum_batch_commits_and_one_over_refuses_without_commit() {
    fn body(count: usize) -> Vec<u8> {
        let updates = (0..count)
            .map(|id| format!(r#"{{"update_id":{id},"edited_message":{{}}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"ok":true,"result":[{updates}]}}"#).into_bytes()
    }
    let (mut maximum, _, maximum_sink, _) = poller([ClientBehavior::Response(response(body(
        MAX_TELEGRAM_UPDATES,
    )))]);
    let result = maximum
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect("maximum accepted");
    assert_eq!(result.disposition_count, MAX_TELEGRAM_UPDATES);
    assert_eq!(maximum_sink.state.lock().unwrap().committed.len(), 1);

    let (mut oversized, _, oversized_sink, _) = poller([ClientBehavior::Response(response(body(
        MAX_TELEGRAM_UPDATES + 1,
    )))]);
    let error = oversized
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect_err("one over maximum refused");
    assert!(matches!(
        error,
        RuntimeError::Parse(error) if error == automonique_transports::TelegramError::LimitExceeded
    ));
    assert!(oversized_sink.state.lock().unwrap().committed.is_empty());
}

#[test]
fn transient_http_failure_has_no_commit_and_can_retry() {
    let payload = br#"{"ok":true,"result":[]}"#;
    let (mut poller, _, sink, _) = poller([
        ClientBehavior::Failure(HttpFailure::Unavailable),
        ClientBehavior::Response(response(payload)),
    ]);
    assert!(matches!(
        poller.poll_once(&lease(), 10, &CancellationToken::new()),
        Err(RuntimeError::Http(HttpFailure::Unavailable))
    ));
    assert!(sink.state.lock().unwrap().committed.is_empty());
    let retry = poller
        .poll_once(&lease(), 11, &CancellationToken::new())
        .expect("retry");
    assert_eq!(retry.next_offset, 0);
}

#[test]
fn long_poll_cancellation_returns_without_commit_or_offset_advance() {
    let (mut poller, client, sink, _) = poller([ClientBehavior::BlockUntilCancelled]);
    let cancellation = CancellationToken::new();
    let worker_cancel = cancellation.clone();
    let worker = thread::spawn(move || poller.poll_once(&lease(), 10, &worker_cancel));
    let deadline = Instant::now() + Duration::from_secs(2);
    while client.state.lock().unwrap().plans.is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    cancellation.cancel();
    let error = worker.join().unwrap().expect_err("cancelled long poll");
    assert!(matches!(error, RuntimeError::Http(HttpFailure::Cancelled)));
    let sink = sink.state.lock().unwrap();
    assert!(sink.committed.is_empty());
    assert!(sink.offsets.is_empty());
}

#[test]
fn response_arriving_after_cancellation_is_not_parsed_or_committed() {
    let payload = br#"{"ok":true,"result":[{"update_id":0,"message":{"chat":{"id":-100},"from":{"id":42},"text":"late"}}]}"#;
    let (mut poller, _, sink, _) = poller([ClientBehavior::CancelThenRespond(response(payload))]);
    let error = poller
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect_err("late response refused");
    assert!(matches!(error, RuntimeError::Cancelled));
    let sink = sink.state.lock().unwrap();
    assert!(sink.committed.is_empty());
    assert!(sink.offsets.is_empty());
}

#[test]
fn pre_cancelled_and_expired_leases_have_no_external_effect() {
    let payload = br#"{"ok":true,"result":[]}"#;
    let (mut poller, client, sink, _) = poller([ClientBehavior::Response(response(payload))]);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        poller.poll_once(&lease(), 10, &cancellation),
        Err(RuntimeError::Cancelled)
    ));
    let expired = PollerLease::new(7, "generation-a", "holder-a", 3, 30_010).unwrap();
    assert!(matches!(
        poller.poll_once(&expired, 10, &CancellationToken::new()),
        Err(RuntimeError::LeaseExpired)
    ));
    assert!(client.state.lock().unwrap().plans.is_empty());
    assert!(sink.state.lock().unwrap().committed.is_empty());
}

#[test]
fn response_completing_at_or_after_lease_expiry_cannot_commit() {
    let payload = br#"{"ok":true,"result":[]}"#;
    let (mut poller, _, sink, _) =
        poller([ClientBehavior::Response(response_at(payload, 100_000))]);
    assert!(matches!(
        poller.poll_once(&lease(), 10, &CancellationToken::new()),
        Err(RuntimeError::LeaseExpired)
    ));
    assert!(sink.state.lock().unwrap().committed.is_empty());
}

#[test]
fn malformed_sink_receipt_cannot_claim_offset_progress() {
    #[derive(Clone)]
    struct LyingSink;
    impl TelegramDurableSink for LyingSink {
        fn read_offset(
            &mut self,
            lease: &PollerLease,
            _now_ms: i64,
        ) -> Result<OffsetReceipt, SinkFailure> {
            Ok(OffsetReceipt {
                bot_id: lease.bot_id,
                lease_epoch: lease.epoch,
                next_offset: 0,
            })
        }

        fn commit_batch(
            &mut self,
            lease: &PollerLease,
            batch: &DurableTelegramBatch,
            _commit_before_ms: i64,
        ) -> Result<DurableCommitReceipt, SinkFailure> {
            Ok(DurableCommitReceipt {
                bot_id: lease.bot_id,
                lease_epoch: lease.epoch,
                next_offset: batch.next_offset + 1,
                disposition_count: batch.updates.len(),
                batch_digest: [9; 32],
                duplicate: false,
            })
        }
    }
    let order = Arc::new(Mutex::new(Vec::new()));
    let client = FakeClient::new(
        [ClientBehavior::Response(response(
            br#"{"ok":true,"result":[]}"#,
        ))],
        order,
    );
    let mut poller = TelegramPoller::new(
        client,
        LyingSink,
        policy(),
        OpaqueBotToken::new(b"secret".to_vec()).unwrap(),
        30,
    )
    .unwrap();
    assert!(matches!(
        poller.poll_once(&lease(), 10, &CancellationToken::new()),
        Err(RuntimeError::CommitReconciliationRequired { next_offset: 0, .. })
    ));
    assert!(matches!(
        poller.poll_once(&lease(), 11, &CancellationToken::new()),
        Err(RuntimeError::CommitReconciliationRequired { next_offset: 0, .. })
    ));
}

#[test]
fn parser_disposition_contract_remains_closed() {
    assert_ne!(
        TelegramDisposition::Denied,
        TelegramDisposition::IgnoredUnsupported
    );
}

/// The policy a running poller admits work under can be widened in place — a
/// host whose operator list changes at runtime must not have to drop its lease
/// and re-read its offset to add one user — but only in ways that keep the
/// durable stream coherent.
#[test]
fn a_policy_may_be_replaced_in_place_but_never_across_bots_or_an_ambiguous_commit() {
    let first = br#"{"ok":true,"result":[{"update_id":0,"message":{"chat":{"id":-100},"from":{"id":99},"text":"newcomer"}}]}"#;
    let second = br#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":-100},"from":{"id":99},"text":"newcomer again"}}]}"#;
    let (mut poller, _client, sink, _order) = poller([
        ClientBehavior::Response(response(first)),
        ClientBehavior::Response(response(second)),
    ]);

    // Under the configured policy this sender is nobody, and the durable
    // record says so.
    poller
        .poll_once(&lease(), 10, &CancellationToken::new())
        .expect("poll");
    assert!(matches!(
        sink.state.lock().unwrap().committed[0].updates[0].disposition,
        DurableDisposition::Denied
    ));

    // A different bot is refused: the identity is bound into every scope this
    // poller has already committed.
    let other_bot = TelegramAccessPolicy::new(
        TelegramBotId::new(8).unwrap(),
        [TelegramPrincipal::new(-100, 99).unwrap()],
    )
    .unwrap();
    assert!(poller.set_policy(other_bot).is_err());

    // The same bot, one principal wider, is accepted — and the next poll
    // admits the sender the previous one denied.
    let widened = TelegramAccessPolicy::new(
        TelegramBotId::new(7).unwrap(),
        [
            TelegramPrincipal::new(-100, 42).unwrap(),
            TelegramPrincipal::new(-100, 99).unwrap(),
        ],
    )
    .unwrap();
    poller.set_policy(widened).expect("the same bot, widened");
    poller
        .poll_once(&lease(), 20, &CancellationToken::new())
        .expect("poll");
    assert!(matches!(
        sink.state.lock().unwrap().committed[1].updates[0].disposition,
        DurableDisposition::Admitted { .. }
    ));
}
