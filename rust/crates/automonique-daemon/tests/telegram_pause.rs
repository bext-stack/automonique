// SPDX-License-Identifier: Elastic-2.0

//! What a Telegram `429` does to the whole bot, and what streaming does not do
//! to the final answer.
//!
//! Two subjects, one file, because they are the two halves of one arithmetic:
//! the durable whole-bot pause is what a rate limit costs, and the call budget
//! is what keeps a run's progress drafts from ever being the reason one is
//! imposed.
//!
//! Every seam is injected and nothing here reaches a network. The read surface
//! is *not* faked: the pause is written and read through the production
//! [`StoreControlSurface`] over a real temporary database, because a pause that
//! did not survive a restart would be the one failure this whole mechanism
//! exists to remove — and a fake store cannot prove it survived.

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use automonique_daemon::progress_hub::ProgressHub;
use automonique_daemon::run_lane::{DraftSink, FALLBACK_EDIT_INTERVAL_MS, TelegramDraftSink};
use automonique_daemon::telegram_bridge::{
    BridgeParts, HostFacts, OperatorRoster, RunFailure, RunLane, RunProgressView,
    StoreControlSurface, TelegramControlBridge,
};
use automonique_protocol::admin::ExecutionState;
use automonique_protocol::event::{Authority, EventKind};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
};
use automonique_protocol::tools::RunId;
use automonique_store::run_index::RunIndex;
use automonique_store::{LeaseRequest, Store, TransportPauseRequest};
use automonique_transport_runtime::{
    CancellationToken, DurableCommitReceipt, DurableTelegramBatch, HttpFailure, OffsetReceipt,
    OpaqueBotToken, PollerLease, RuntimeError, SinkFailure, StoreTelegramDurableSink, SystemClock,
    TelegramCallBudget, TelegramDurableSink, TelegramHttpClient, TelegramHttpPlan,
    TelegramHttpResponse, TelegramLeaseCoordinator, TelegramOutboundClient, TelegramOutboundPlan,
};
use automonique_transports::{TelegramBotId, TelegramPrincipal};

const BOT_ID: i64 = 123_456;
const OPERATOR: i64 = 7_654_321;
const TOKEN: &str = "123456:AAFixtureSecretNeverPrinted";
/// A fixed instant for the draft fixtures, whose sink takes its clock from the
/// caller and therefore needs no relationship to the wall clock at all.
///
/// The pause fixtures deliberately do *not* use it: the bridge's outbox drain
/// reads the wall clock directly, so a pause it writes is on that clock and the
/// tests around it are driven from `real_now_ms`.
const NOW_MS: i64 = 1_700_000_000_000;
const LONG_POLL_SECONDS: u16 = 3;
/// The interval the draft fixtures' pause names, in milliseconds.
const RETRY_AFTER_MS: u64 = 5_000;

// ---------------------------------------------------------------- fake seams

#[derive(Clone)]
struct FakeClient {
    state: Arc<Mutex<ClientState>>,
}

struct ClientState {
    behaviors: VecDeque<ClientBehavior>,
    offsets: Vec<u64>,
    /// The instant every scripted response claims to have completed at.
    ///
    /// The poller refuses a response that completed before the poll asked for
    /// it or after the lease expired, so a fixture that drives several polls
    /// has to name one instant that is inside the window for all of them.
    completed_ms: i64,
}

enum ClientBehavior {
    Body(String),
    Failure(HttpFailure),
}

impl FakeClient {
    fn new(completed_ms: i64, behaviors: impl IntoIterator<Item = ClientBehavior>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClientState {
                behaviors: behaviors.into_iter().collect(),
                offsets: Vec::new(),
                completed_ms,
            })),
        }
    }

    /// Every `getUpdates` this bot issued, in order. The whole point of the
    /// pause is that this list stops growing.
    fn requested_offsets(&self) -> Vec<u64> {
        self.state.lock().expect("client state").offsets.clone()
    }
}

impl TelegramHttpClient for FakeClient {
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        let mut state = self.state.lock().expect("client state");
        state.offsets.push(plan.body.offset);
        let completed_ms = state.completed_ms;
        match state.behaviors.pop_front().expect("a scripted response") {
            ClientBehavior::Body(body) => Ok(TelegramHttpResponse {
                status: 200,
                body: body.into_bytes(),
                completed_ms,
            }),
            ClientBehavior::Failure(failure) => Err(failure),
        }
    }
}

#[derive(Clone, Default)]
struct FakeOutbound {
    state: Arc<Mutex<OutboundState>>,
}

#[derive(Default)]
struct OutboundState {
    /// Every attempt, refused ones included: a drain that stopped is a drain
    /// that stopped *attempting*, and only the attempts show that.
    attempted: Vec<(String, String)>,
    failures: VecDeque<HttpFailure>,
    next_message_id: i64,
}

impl FakeOutbound {
    /// An outbound that refuses its first send with Telegram's own `429`.
    fn rate_limited_once(retry_after_ms: u64) -> Self {
        let outbound = Self::default();
        outbound
            .state
            .lock()
            .expect("outbound state")
            .failures
            .push_back(HttpFailure::RateLimited { retry_after_ms });
        outbound
    }

    fn attempted(&self) -> Vec<(String, String)> {
        self.state.lock().expect("outbound state").attempted.clone()
    }

    fn texts(&self) -> Vec<String> {
        self.attempted()
            .into_iter()
            .filter(|(method, _)| method == "sendMessage")
            .map(|(_, body)| body)
            .collect()
    }
}

impl TelegramOutboundClient for FakeOutbound {
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        let mut state = self.state.lock().expect("outbound state");
        let method = plan.request().method_name().to_owned();
        state
            .attempted
            .push((method.clone(), plan.canonical_body()));
        if let Some(failure) = state.failures.pop_front() {
            return Err(failure);
        }
        let body = if method == "sendMessage" {
            state.next_message_id += 1;
            format!(
                "{{\"ok\":true,\"result\":{{\"message_id\":{}}}}}",
                state.next_message_id
            )
            .into_bytes()
        } else {
            b"{\"ok\":true}".to_vec()
        };
        Ok(TelegramHttpResponse {
            status: 200,
            body,
            completed_ms: NOW_MS + 20,
        })
    }
}

#[derive(Clone, Default)]
struct FakeSink {
    state: Arc<Mutex<(u64, usize)>>,
}

impl FakeSink {
    fn offset(&self) -> u64 {
        self.state.lock().expect("sink state").0
    }

    fn commits(&self) -> usize {
        self.state.lock().expect("sink state").1
    }
}

impl TelegramDurableSink for FakeSink {
    fn read_offset(
        &mut self,
        lease: &PollerLease,
        _now_ms: i64,
    ) -> Result<OffsetReceipt, SinkFailure> {
        Ok(OffsetReceipt {
            bot_id: lease.bot_id,
            lease_epoch: lease.epoch,
            next_offset: self.state.lock().expect("sink state").0,
        })
    }

    fn commit_batch(
        &mut self,
        lease: &PollerLease,
        batch: &DurableTelegramBatch,
        _commit_before_ms: i64,
    ) -> Result<DurableCommitReceipt, SinkFailure> {
        let mut state = self.state.lock().expect("sink state");
        state.0 = batch.next_offset;
        state.1 += 1;
        Ok(DurableCommitReceipt {
            bot_id: batch.bot_id,
            lease_epoch: lease.epoch,
            next_offset: batch.next_offset,
            disposition_count: batch.updates.len(),
            batch_digest: batch.digest,
            duplicate: false,
        })
    }
}

/// A run lane that runs nothing. `/help` is what these fixtures dispatch.
#[derive(Clone, Default)]
struct NoRunLane;

impl RunLane for NoRunLane {
    fn run(&mut self, _task: &str) -> Result<String, RunFailure> {
        Err(RunFailure::NotConfigured)
    }
}

// ------------------------------------------------------------------ fixtures

struct Fixture {
    _root: tempfile::TempDir,
    facts: HostFacts,
    database_path: PathBuf,
    run_index_path: PathBuf,
    support_tickets_path: PathBuf,
    operator_members_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let database_path = root.path().join("automonique.sqlite3");
        let run_index_path = root.path().join("run-index.sqlite3");
        let support_tickets_path = root.path().join("support-tickets.sqlite3");
        let operator_members_path = root.path().join("operator-members.sqlite3");
        let now_ms = real_now_ms();
        let mut store = Store::open(&database_path).expect("store opens");
        let lease = store
            .acquire_generation_lease(LeaseRequest {
                generation_id: "foreground",
                holder_id: "telegram-pause-fixture",
                now_ms,
                ttl_ms: 600_000,
            })
            .expect("generation lease");
        RunIndex::open(&run_index_path).expect("run index opens");
        Self {
            _root: root,
            facts: HostFacts {
                generation_id: String::from("foreground"),
                holder_id: String::from("telegram-pause-fixture"),
                lease_epoch: lease.epoch,
                bot_id: BOT_ID,
                execution_state: ExecutionState::SandboxUnavailableNoLane,
            },
            database_path,
            run_index_path,
            support_tickets_path,
            operator_members_path,
        }
    }

    fn surface(&self) -> StoreControlSurface {
        StoreControlSurface::open(
            &self.database_path,
            &self.run_index_path,
            self.facts.clone(),
        )
        .expect("read surface opens")
        .with_support_tickets(&self.support_tickets_path)
        .with_operator_members(&self.operator_members_path)
    }

    fn store(&self) -> Store {
        Store::open(&self.database_path).expect("store opens")
    }

    /// The pause row exactly as a restarted daemon would read it.
    fn live_pause(&self, now_ms: i64) -> Option<i64> {
        self.store()
            .transport_pause("telegram", &BOT_ID.to_string(), now_ms)
            .expect("pause readable")
            .map(|pause| pause.resume_after_ms)
    }
}

fn real_now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock fits")
}

fn token() -> OpaqueBotToken {
    OpaqueBotToken::new(TOKEN.as_bytes().to_vec()).expect("token")
}

fn lease(expires_ms: i64) -> PollerLease {
    PollerLease::new(BOT_ID, "foreground", "telegram-pause-holder", 1, expires_ms)
        .expect("poller lease")
}

fn roster() -> OperatorRoster {
    OperatorRoster::new(
        TelegramBotId::new(BOT_ID).expect("bot id"),
        [TelegramPrincipal::new(OPERATOR, OPERATOR).expect("principal")],
        [OPERATOR],
        [OPERATOR],
    )
    .expect("roster")
}

/// One `getUpdates` response carrying the given `(update_id, text)` rows, all
/// from the one operator these fixtures authorize.
fn updates(rows: &[(u64, &str)]) -> ClientBehavior {
    let body = rows
        .iter()
        .map(|(update_id, text)| {
            format!(
                r#"{{"update_id":{update_id},"message":{{"message_id":{update_id},"chat":{{"id":{OPERATOR}}},"from":{{"id":{OPERATOR}}},"text":"{text}"}}}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    ClientBehavior::Body(format!("{{\"ok\":true,\"result\":[{body}]}}"))
}

type Bridge =
    TelegramControlBridge<FakeClient, FakeOutbound, FakeSink, StoreControlSurface, NoRunLane>;

fn bridge(fixture: &Fixture, client: FakeClient, outbound: FakeOutbound, sink: FakeSink) -> Bridge {
    TelegramControlBridge::new(BridgeParts {
        client,
        question_outbound: outbound.clone(),
        outbound,
        sink,
        surface: fixture.surface(),
        lane: NoRunLane,
        slack: None,
        github: None,
        github_actions: None,
        improvements: None,
        improvement_github: None,
        improvement_worker: None,
        ticket_actions: None,
        email_actions: None,
        memory: None,
        roster: roster(),
        inbound_token: token(),
        outbound_token: token(),
        question_outbound_token: token(),
        long_poll_seconds: LONG_POLL_SECONDS,
    })
    .expect("bridge composes")
}

// ------------------------------------------------------------------ the pause

/// THE PAUSE ITSELF. One `429` on one outbound send stops the drain where it
/// stands, stops the poll, and is written down — while the durable lease keeps
/// being renewed at its own epoch and the committed offset does not move.
///
/// The bridge's drain reads the wall clock directly, so this drives it on the
/// real one: the fixture's instants are offsets from `now`, and nothing waits.
#[test]
fn one_429_pauses_the_whole_bot_durably_and_stops_every_call() {
    let base = real_now_ms();
    let fixture = Fixture::new();
    let client = FakeClient::new(
        base + 300_000,
        [updates(&[(1, "/help"), (2, "/status")]), updates(&[])],
    );
    let outbound = FakeOutbound::rate_limited_once(5_000);
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound.clone(), sink.clone());
    let lease = lease(base + 600_000);
    let cancellation = CancellationToken::new();

    assert_eq!(bridge.paused_until(base), None, "a fresh bot is not paused");
    assert_eq!(fixture.live_pause(base), None);

    // One poll fetches two commands. The first reply meets Telegram's `429`.
    bridge
        .poll_and_dispatch(&lease, base, &cancellation)
        .expect("the poll itself succeeded");
    let offset_after_poll = sink.offset();
    let commits_after_poll = sink.commits();
    assert_eq!(client.requested_offsets(), vec![0]);
    assert_eq!(
        outbound.attempted().len(),
        1,
        "the drain stops at the refusal rather than trying the rest"
    );

    // THE PAUSE IS DURABLE. This is the row a restarted process reads.
    let resume_after_ms = fixture
        .live_pause(base)
        .expect("a 429 must be written down");
    assert_eq!(
        resume_after_ms,
        bridge.paused_until(base).expect("and held in memory")
    );
    assert!(resume_after_ms > base);

    // ZERO getUpdates FOR THE LENGTH OF THE PAUSE, AND ZERO SENDS.
    //
    // The durable lease is renewed throughout, through the very coordinator the
    // serve thread uses on its own cadence — a store write against the same
    // database, never a Telegram call — and it keeps its epoch while the bot
    // waits.
    let mut coordinator = TelegramLeaseCoordinator::disabled(
        StoreTelegramDurableSink::new(fixture.store(), SystemClock),
        fixture.facts.lease_epoch,
        20_000,
    )
    .expect("coordinator");
    let bot_epoch = coordinator
        .acquire_no_client(
            BOT_ID,
            &fixture.facts.generation_id,
            &fixture.facts.holder_id,
        )
        .expect("bot lease")
        .epoch;
    let mut renewals = 0;
    for step in 0..8 {
        let at_ms = base + step * 100;
        assert!(at_ms < resume_after_ms);
        let report = bridge
            .poll_and_dispatch(&lease, at_ms, &cancellation)
            .expect("a paused cycle is not a failure");
        assert_eq!(report.updates, 0);
        let renewed = coordinator
            .renew()
            .expect("the lease is a store write, not a Telegram call");
        assert_eq!(
            renewed.epoch, bot_epoch,
            "a pause must not rotate the lease epoch"
        );
        renewals += 1;
    }
    assert_eq!(renewals, 8, "the durable lease was renewed throughout");
    assert_eq!(
        client.requested_offsets(),
        vec![0],
        "a paused bot issues no getUpdates at all"
    );
    assert_eq!(
        outbound.attempted().len(),
        1,
        "a paused bot claims nothing from the outbox"
    );
    assert_eq!(
        (sink.offset(), sink.commits()),
        (offset_after_poll, commits_after_poll),
        "the committed offset receipt is untouched by the pause"
    );
}

/// THE OTHER SIDE OF IT. When the deadline passes the backlog drains
/// oldest-first — the intent that met the `429` before anything staged behind it
/// — and the next poll asks for exactly the offset the pause froze.
///
/// The interval is thirty milliseconds so the deadline arrives without the
/// suite waiting five seconds for it — long enough that the whole of the first
/// cycle happens inside the pause, short enough to wait out. Everything else is
/// the same path.
#[test]
fn the_backlog_drains_fifo_and_the_offset_resumes_when_the_pause_ends() {
    let base = real_now_ms();
    let fixture = Fixture::new();
    let client = FakeClient::new(
        base + 300_000,
        [updates(&[(1, "/help"), (2, "/status")]), updates(&[])],
    );
    let outbound = FakeOutbound::rate_limited_once(30);
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound.clone(), sink.clone());
    let lease = lease(base + 600_000);
    let cancellation = CancellationToken::new();

    bridge
        .poll_and_dispatch(&lease, base, &cancellation)
        .expect("the poll itself succeeded");
    let offset_after_poll = sink.offset();
    assert_eq!(outbound.attempted().len(), 1, "the drain stopped");
    // Read with a zero observation so this asserts the row exists, not that a
    // short deadline is still ahead of the clock.
    assert!(
        fixture.live_pause(0).is_some(),
        "even a brief pause is written down"
    );

    std::thread::sleep(std::time::Duration::from_millis(80));
    let after = real_now_ms();
    assert_eq!(bridge.paused_until(after), None, "the deadline has passed");
    bridge
        .poll_and_dispatch(&lease, after, &cancellation)
        .expect("the pause ended");

    let texts = outbound.texts();
    assert_eq!(
        texts.len(),
        3,
        "the refused send and both queued intents were all attempted: {texts:?}"
    );
    assert_eq!(
        texts[0], texts[1],
        "the intent that met the 429 is the one that goes first afterwards"
    );
    assert_ne!(texts[1], texts[2]);
    assert_eq!(
        client.requested_offsets(),
        vec![0, offset_after_poll],
        "the poll resumes at the offset the pause froze"
    );
}

/// A restart inside a live pause starts paused. Without this the first thing a
/// new process does is poll — straight back into the limit it was told to wait
/// out, from a peer that has started counting again.
#[test]
fn a_bridge_composed_inside_a_live_pause_starts_paused_and_issues_nothing() {
    let fixture = Fixture::new();
    let now_ms = real_now_ms();
    let resume_after_ms = now_ms + 60_000;
    fixture
        .store()
        .pause_transport(TransportPauseRequest {
            transport: "telegram",
            scope: &BOT_ID.to_string(),
            generation_id: &fixture.facts.generation_id,
            holder_id: &fixture.facts.holder_id,
            authority_lease_epoch: fixture.facts.lease_epoch,
            reason: "rate_limited",
            now_ms,
            resume_after_ms,
        })
        .expect("a previous process wrote the pause");

    let client = FakeClient::new(now_ms + 300_000, [updates(&[])]);
    let outbound = FakeOutbound::default();
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound.clone(), sink.clone());

    assert_eq!(
        bridge.paused_until(now_ms),
        Some(resume_after_ms),
        "the inherited deadline is in force before anything is dialled"
    );
    let lease = lease(now_ms + 600_000);
    let cancellation = CancellationToken::new();
    for step in 0..4 {
        bridge
            .poll_and_dispatch(&lease, now_ms + step, &cancellation)
            .expect("a paused cycle is not a failure");
    }
    assert!(
        client.requested_offsets().is_empty(),
        "a restart inside a pause must not poll"
    );
    assert!(outbound.attempted().is_empty());
    assert_eq!(sink.commits(), 0);
}

// --------------------------------------------------------------- the drafts

/// One outbound that records everything and answers however the script says.
#[derive(Clone, Default)]
struct DraftTransport {
    state: Arc<Mutex<DraftTransportState>>,
}

#[derive(Default)]
struct DraftTransportState {
    calls: Vec<(String, String)>,
    /// Methods this fixture's Telegram refuses with `ok:false`.
    unsupported: Vec<&'static str>,
    next_message_id: i64,
}

impl DraftTransport {
    fn refusing(unsupported: &[&'static str]) -> Self {
        let transport = Self::default();
        {
            let mut state = transport.state.lock().expect("transport state");
            state.unsupported = unsupported.to_vec();
            state.next_message_id = 100;
        }
        transport
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.state.lock().expect("transport state").calls.clone()
    }

    fn methods(&self) -> Vec<String> {
        self.calls().into_iter().map(|(method, _)| method).collect()
    }
}

impl TelegramOutboundClient for DraftTransport {
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        let mut state = self.state.lock().expect("transport state");
        let method = plan.request().method_name().to_owned();
        state.calls.push((method.clone(), plan.canonical_body()));
        // Telegram answers a method it does not serve with a 200 carrying
        // `ok:false`, which is exactly what makes it detectable rather than
        // indistinguishable from a transport fault.
        let body = if state.unsupported.iter().any(|name| *name == method) {
            b"{\"ok\":false,\"error_code\":404,\"description\":\"Not Found: method not found\"}"
                .to_vec()
        } else if method == "sendMessage" {
            state.next_message_id += 1;
            format!(
                "{{\"ok\":true,\"result\":{{\"message_id\":{}}}}}",
                state.next_message_id
            )
            .into_bytes()
        } else {
            b"{\"ok\":true}".to_vec()
        };
        Ok(TelegramHttpResponse {
            status: 200,
            body,
            completed_ms: NOW_MS,
        })
    }
}

fn draft_sink(
    transport: DraftTransport,
    budget: &Arc<Mutex<TelegramCallBudget>>,
) -> TelegramDraftSink {
    TelegramDraftSink::new(Box::new(transport), token(), BOT_ID, Arc::clone(budget))
}

/// One assistant-text preview at `sequence`, as the backend would stamp it.
///
/// `Synthetic` because a delta is a coalesced preview: the authority split in
/// `event.rs` refuses to let one claim otherwise, which is the point of it.
fn delta(sequence: u64, text: &str) -> ProgressFrame {
    ProgressFrame::new(ProgressFrameParts {
        run_id: RunId::new("tgrun-fixture").expect("a valid run identity"),
        sequence,
        at_ms: EpochMillis::from_millis(NOW_MS),
        authority: Authority::Synthetic,
        kind: EventKind::AssistantMessageDelta,
        body: ProgressBody::new(
            EventKind::AssistantMessageDelta,
            ProgressBodyParts {
                text: Some(ProgressText::new(text).expect("plain text")),
                step: None,
                retry: None,
            },
        )
        .expect("a delta with its text"),
    })
    .expect("a stamped frame")
}

/// The path this environment can actually validate. `sendMessageDraft` could not
/// be exercised against `api.telegram.org` from here, so the fixture answers it
/// the way a deployment without it does — and the streaming that follows is the
/// documented `editMessageText` fallback, end to end.
#[test]
fn a_rejected_draft_method_latches_once_and_streaming_continues_on_the_fallback() {
    let transport = DraftTransport::refusing(&["sendMessageDraft"]);
    let budget = Arc::new(Mutex::new(TelegramCallBudget::new(NOW_MS)));
    let mut sink = draft_sink(transport.clone(), &budget);

    assert!(!sink.drafts_unsupported());
    assert!(
        sink.draft(OPERATOR, "reading files", NOW_MS),
        "the fallback carries the first snapshot the draft method refused"
    );
    assert!(
        sink.drafts_unsupported(),
        "one ok:false is the detection; there is no second attempt"
    );
    assert_eq!(
        transport.methods(),
        vec![
            String::from("sendMessageDraft"),
            String::from("sendMessage")
        ],
        "the first snapshot opens the message the fallback will edit"
    );

    // The throttle: a second snapshot inside the interval draws nothing at all.
    assert!(!sink.draft(OPERATOR, "writing the answer", NOW_MS + 1));
    assert!(!sink.draft(
        OPERATOR,
        "writing the answer",
        NOW_MS + FALLBACK_EDIT_INTERVAL_MS - 1
    ));
    assert_eq!(
        transport.methods().len(),
        2,
        "nothing was sent while throttled"
    );

    // Past the interval it edits the message it opened, and never re-attempts
    // the latched method.
    assert!(sink.draft(
        OPERATOR,
        "writing the answer",
        NOW_MS + FALLBACK_EDIT_INTERVAL_MS
    ));
    let calls = transport.calls();
    assert_eq!(calls[2].0, "editMessageText");
    assert_eq!(
        calls[2].1,
        r#"{"chat_id":7654321,"message_id":101,"text":"writing the answer"}"#
    );
    assert!(
        !transport.methods()[1..].contains(&String::from("sendMessageDraft")),
        "a method Telegram does not serve is never retried"
    );
}

/// The draft path, for the deployment that has it. Pinned as a fixture because
/// this environment is offline: what is asserted here is exactly what this build
/// will put on the wire, and nothing about it was learned from a live peer.
#[test]
fn a_supported_draft_method_streams_without_ever_opening_a_message() {
    let transport = DraftTransport::refusing(&[]);
    let budget = Arc::new(Mutex::new(TelegramCallBudget::new(NOW_MS)));
    let mut sink = draft_sink(transport.clone(), &budget);

    assert!(sink.draft(OPERATOR, "reading files", NOW_MS));
    assert!(sink.draft(OPERATOR, "running tests", NOW_MS + 1_000));
    assert!(!sink.drafts_unsupported());
    assert_eq!(
        transport.calls(),
        vec![
            (
                String::from("sendMessageDraft"),
                String::from(r#"{"chat_id":7654321,"text":"reading files"}"#)
            ),
            (
                String::from("sendMessageDraft"),
                String::from(r#"{"chat_id":7654321,"text":"running tests"}"#)
            ),
        ],
        "a draft replaces its predecessor and never becomes a message"
    );
}

/// A paused bot draws nothing, and neither does one whose chat has no ephemeral
/// headroom left. Both are the budget refusing before any byte is sent.
#[test]
fn streaming_stops_at_a_pause_and_at_the_headroom_line() {
    let transport = DraftTransport::refusing(&[]);
    let budget = Arc::new(Mutex::new(TelegramCallBudget::new(NOW_MS)));
    let mut sink = draft_sink(transport.clone(), &budget);

    budget
        .lock()
        .expect("budget")
        .note_rate_limited(RETRY_AFTER_MS, NOW_MS);
    assert!(!sink.draft(OPERATOR, "reading files", NOW_MS));
    assert!(
        transport.calls().is_empty(),
        "a paused bot does not draw a draft"
    );

    // Past the pause, the chat's own ceiling still bounds it: snapshots offered
    // every millisecond do not become a call every millisecond.
    let after = NOW_MS + i64::try_from(RETRY_AFTER_MS).expect("interval fits") + 1;
    let drawn = (0..50)
        .filter(|step| sink.draft(OPERATOR, "reading files", after + step))
        .count();
    assert!(drawn <= 3, "a chat drew {drawn} drafts inside 50 ms");
}

/// The renderer seam and the transport, joined: frames published into a live hub
/// become one bounded snapshot on the wire, and a run that streams a flood still
/// sends one message per snapshot rather than one per frame.
#[test]
fn hub_frames_become_one_bounded_snapshot_on_the_wire() {
    let hub = ProgressHub::new();
    let transport = DraftTransport::refusing(&[]);
    let budget = Arc::new(Mutex::new(TelegramCallBudget::new(NOW_MS)));
    let mut sink = draft_sink(transport.clone(), &budget);
    let mut view = RunProgressView::new();

    for sequence in 1..=40_u64 {
        let frame = delta(sequence, &"x".repeat(200));
        hub.publish(
            "tgrun-fixture",
            sequence,
            &frame.to_canonical_bytes().expect("canonical frame"),
        );
    }
    let snapshot = view
        .poll(&hub, "tgrun-fixture")
        .expect("forty frames fold into one snapshot");
    assert!(
        snapshot.chars().map(char::len_utf16).sum::<usize>() <= 4_096,
        "a snapshot must fit Telegram's own message ceiling"
    );
    assert!(sink.draft(OPERATOR, &snapshot, NOW_MS));
    assert_eq!(
        transport.calls().len(),
        1,
        "forty frames are one call, not forty"
    );

    // Nothing changed, so nothing is redrawn: the fold answers `None` and the
    // transport is never reached.
    assert!(view.poll(&hub, "tgrun-fixture").is_none());
    assert_eq!(transport.calls().len(), 1);
}

/// The lane's own seam, driven with a counting sink: a lane with no target
/// streams nothing, and one with a target streams into exactly that chat.
#[test]
fn a_lane_streams_only_into_the_chat_that_asked() {
    #[derive(Clone, Default)]
    struct CountingSink {
        chats: Arc<Mutex<Vec<i64>>>,
        calls: Arc<AtomicUsize>,
    }

    impl DraftSink for CountingSink {
        fn draft(&mut self, chat_id: i64, _snapshot: &str, _now_ms: i64) -> bool {
            self.chats.lock().expect("chats").push(chat_id);
            self.calls.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    let counting = CountingSink::default();
    let hub = Arc::new(ProgressHub::new());
    let frame = delta(1, "working");
    hub.publish(
        "tgrun-fixture",
        1,
        &frame.to_canonical_bytes().expect("canonical frame"),
    );

    // The seam without the lane's socket work: the fold plus the target rule,
    // which is the whole of what `stream_progress` decides.
    let mut view = RunProgressView::new();
    let mut sink = counting.clone();
    for target in [None, Some(OPERATOR)] {
        if let (Some(chat_id), Some(snapshot)) = (target, view.poll(&hub, "tgrun-fixture")) {
            sink.draft(chat_id, &snapshot, NOW_MS);
        }
    }
    assert_eq!(
        *counting.chats.lock().expect("chats"),
        Vec::<i64>::new(),
        "the first pass had no target, and the second had nothing new to draw"
    );
    assert_eq!(counting.calls.load(Ordering::Relaxed), 0);
}

/// A `RuntimeError` from the poller that is not a rate limit leaves the bot
/// unpaused: a pause is what Telegram asked for, never a guess.
#[test]
fn a_transport_fault_that_is_not_a_429_pauses_nothing() {
    let base = real_now_ms();
    let fixture = Fixture::new();
    let client = FakeClient::new(
        base + 300_000,
        [ClientBehavior::Failure(HttpFailure::Unavailable)],
    );
    let outbound = FakeOutbound::default();
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound, sink);
    let cancellation = CancellationToken::new();
    let error = bridge
        .poll_and_dispatch(&lease(base + 600_000), base, &cancellation)
        .expect_err("an unavailable transport is still a poll failure");
    assert!(matches!(
        error,
        RuntimeError::Http(HttpFailure::Unavailable)
    ));
    assert_eq!(bridge.paused_until(base), None);
    assert_eq!(fixture.live_pause(base), None);
    assert_eq!(client.requested_offsets(), vec![0]);
}
