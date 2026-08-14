// SPDX-License-Identifier: Elastic-2.0

//! The Telegram control bridge, driven end to end without a network.
//!
//! Every seam the bridge owns is injected here: a fake `getUpdates` transport
//! feeding canned response bodies, a fake outbound transport capturing exactly
//! what would have been sent, and a fake durable sink standing in for the store's
//! offset ledger. The one thing that is *not* faked is the read surface — these
//! tests build the production [`StoreControlSurface`] over real temporary
//! databases, so the `/status` and `/runs` replies an operator would receive are
//! rendered by the same code a live daemon runs.
//!
//! No test writes an `allow=` line into a daemon fixture, and none may: that is
//! the one configuration that makes a daemon dial `api.telegram.org`, and the
//! gate is proved here and in the daemon's own unit tests instead.

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use automonique_daemon::telegram_bridge::{
    BridgeParts, ControlSurface, DispatchReport, HostFacts, RunFailure, RunLane,
    StoreControlSurface, TelegramControlBridge, Unavailable,
};
use automonique_protocol::admin::ExecutionState;
use automonique_store::run_index::{RunIndex, RunIndexEntry};
use automonique_store::{LeaseRequest, Store};
use automonique_transport_runtime::{
    AllowedUsers, CancellationToken, DurableCommitReceipt, DurableTelegramBatch, HttpFailure,
    OffsetReceipt, OpaqueBotToken, PollerLease, RuntimeError, SinkFailure, TelegramDurableSink,
    TelegramHttpClient, TelegramHttpPlan, TelegramHttpResponse, TelegramOutboundClient,
    TelegramOutboundPlan, command_manifest,
};
use automonique_transports::{TelegramAccessPolicy, TelegramBotId, TelegramPrincipal};

/// The bot every fixture configures.
const BOT_ID: i64 = 123_456;
/// The one operator these fixtures authorize.
const OPERATOR: i64 = 7_654_321;
/// Somebody who is not on any list here.
const OUTSIDER: i64 = 9_999_999;
/// The exact credential, so a test can prove no rendering contains it.
const TOKEN: &str = "123456:AAFixtureSecretNeverPrinted";
/// A fixed poller clock. The read surface uses the real one; the two never meet.
const NOW_MS: i64 = 1_700_000_000_000;
/// Long enough that no fixture poll is refused for lease headroom.
const LEASE_MS: i64 = NOW_MS + 600_000;
/// The long poll a fixture asks for, in seconds.
const LONG_POLL_SECONDS: u16 = 3;

// ---------------------------------------------------------------- fake seams

#[derive(Clone)]
struct FakeClient {
    state: Arc<Mutex<ClientState>>,
}

#[derive(Default)]
struct ClientState {
    behaviors: VecDeque<ClientBehavior>,
    offsets: Vec<u64>,
}

enum ClientBehavior {
    Body(String),
    Failure(HttpFailure),
}

impl FakeClient {
    fn new(behaviors: impl IntoIterator<Item = ClientBehavior>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ClientState {
                behaviors: behaviors.into_iter().collect(),
                ..ClientState::default()
            })),
        }
    }

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
        assert!(
            plan.has_authorization(),
            "an inbound plan must be credentialed"
        );
        assert_eq!(plan.bot_id, BOT_ID);
        assert_eq!(plan.body.timeout_seconds, LONG_POLL_SECONDS);
        let mut state = self.state.lock().expect("client state");
        state.offsets.push(plan.body.offset);
        match state.behaviors.pop_front().expect("a scripted response") {
            ClientBehavior::Body(body) => Ok(TelegramHttpResponse {
                status: 200,
                body: body.into_bytes(),
                completed_ms: NOW_MS + 10,
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
    sent: Vec<SentCall>,
    failures: VecDeque<HttpFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SentCall {
    method: String,
    body: String,
}

impl FakeOutbound {
    fn failing_once() -> Self {
        let outbound = Self::default();
        outbound
            .state
            .lock()
            .expect("outbound state")
            .failures
            .push_back(HttpFailure::Unavailable);
        outbound
    }

    fn sent(&self) -> Vec<SentCall> {
        self.state.lock().expect("outbound state").sent.clone()
    }

    fn messages(&self) -> Vec<String> {
        self.sent()
            .into_iter()
            .filter(|call| call.method == "sendMessage")
            .map(|call| call.body)
            .collect()
    }
}

impl TelegramOutboundClient for FakeOutbound {
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        _cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        assert!(
            plan.has_authorization(),
            "an outbound plan must be credentialed"
        );
        assert_eq!(plan.bot_id(), BOT_ID);
        let mut state = self.state.lock().expect("outbound state");
        if let Some(failure) = state.failures.pop_front() {
            return Err(failure);
        }
        state.sent.push(SentCall {
            method: plan.request().method_name().to_owned(),
            body: plan.canonical_body(),
        });
        Ok(TelegramHttpResponse {
            status: 200,
            body: b"{\"ok\":true}".to_vec(),
            completed_ms: NOW_MS + 20,
        })
    }
}

#[derive(Clone, Default)]
struct FakeSink {
    state: Arc<Mutex<SinkState>>,
}

#[derive(Default)]
struct SinkState {
    offset: u64,
    commits: usize,
    duplicate: bool,
}

impl FakeSink {
    fn duplicating() -> Self {
        let sink = Self::default();
        sink.state.lock().expect("sink state").duplicate = true;
        sink
    }

    fn offset(&self) -> u64 {
        self.state.lock().expect("sink state").offset
    }

    fn commits(&self) -> usize {
        self.state.lock().expect("sink state").commits
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
            next_offset: self.state.lock().expect("sink state").offset,
        })
    }

    fn commit_batch(
        &mut self,
        lease: &PollerLease,
        batch: &DurableTelegramBatch,
        commit_before_ms: i64,
    ) -> Result<DurableCommitReceipt, SinkFailure> {
        assert_eq!(
            commit_before_ms, lease.expires_ms,
            "a commit must be fenced by the exact lease expiry"
        );
        let mut state = self.state.lock().expect("sink state");
        state.commits += 1;
        state.offset = batch.next_offset;
        Ok(DurableCommitReceipt {
            bot_id: batch.bot_id,
            lease_epoch: lease.epoch,
            next_offset: batch.next_offset,
            disposition_count: batch.updates.len(),
            batch_digest: batch.digest,
            duplicate: state.duplicate,
        })
    }
}

// ------------------------------------------------------------------ fixtures

/// A private temporary tree holding a store, a run index, and a live generation.
struct Fixture {
    _root: tempfile::TempDir,
    facts: HostFacts,
    database_path: std::path::PathBuf,
    run_index_path: std::path::PathBuf,
}

impl Fixture {
    /// Build the durable state a status and a runs reply are rendered from.
    fn new(runs: &[(i64, &str)]) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let database_path = root.path().join("automonique.sqlite3");
        let run_index_path = root.path().join("run-index.sqlite3");
        let now_ms = real_now_ms();
        let mut store = Store::open(&database_path).expect("store opens");
        let lease = store
            .acquire_generation_lease(LeaseRequest {
                generation_id: "foreground",
                holder_id: "telegram-fixture-holder",
                now_ms,
                ttl_ms: 600_000,
            })
            .expect("generation lease");
        let mut index = RunIndex::open(&run_index_path).expect("run index opens");
        for (submission_id, run_id) in runs {
            index
                .register(RunIndexEntry {
                    submission_id: *submission_id,
                    run_id,
                    registered_at_ms: now_ms,
                })
                .expect("run registered");
        }
        Self {
            _root: root,
            facts: HostFacts {
                generation_id: String::from("foreground"),
                holder_id: String::from("telegram-fixture-holder"),
                lease_epoch: lease.epoch,
                bot_id: BOT_ID,
                execution_state: ExecutionState::SandboxUnavailableNoLane,
            },
            database_path,
            run_index_path,
        }
    }

    fn surface(&self) -> StoreControlSurface {
        StoreControlSurface::open(
            &self.database_path,
            &self.run_index_path,
            self.facts.clone(),
        )
        .expect("read surface opens")
    }
}

fn real_now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time fits")
}

fn policy() -> TelegramAccessPolicy {
    TelegramAccessPolicy::new(
        TelegramBotId::new(BOT_ID).expect("bot id"),
        [TelegramPrincipal::new(OPERATOR, OPERATOR).expect("principal")],
    )
    .expect("policy")
}

fn token() -> OpaqueBotToken {
    OpaqueBotToken::new(TOKEN.as_bytes().to_vec()).expect("token")
}

fn lease() -> PollerLease {
    PollerLease::new(BOT_ID, "foreground", "telegram-fixture-holder", 1, LEASE_MS)
        .expect("poller lease")
}

/// One `getUpdates` response carrying the given `(update_id, from, text)` rows.
fn updates(rows: &[(u64, i64, &str)]) -> ClientBehavior {
    let body = rows
        .iter()
        .map(|(update_id, from, text)| {
            format!(
                r#"{{"update_id":{update_id},"message":{{"message_id":{update_id},"chat":{{"id":{from}}},"from":{{"id":{from}}},"text":{}}}}}"#,
                serde_json_string(text)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    ClientBehavior::Body(format!("{{\"ok\":true,\"result\":[{body}]}}"))
}

/// Minimal JSON string escaping for fixture text.
fn serde_json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            plain => out.push(plain),
        }
    }
    out.push('"');
    out
}

/// A run lane that runs nothing and records exactly what it was asked.
///
/// The dispatch is what these tests are about, so the lane is a seam here for
/// the same reason the transports are: whether a real run answers is
/// `run_compose`'s question, and it needs a contained host to ask it.
#[derive(Clone, Default)]
struct FakeRunLane {
    state: Arc<Mutex<FakeRunLaneState>>,
}

#[derive(Default)]
struct FakeRunLaneState {
    tasks: Vec<String>,
    answer: Option<String>,
    failure: Option<RunFailure>,
}

impl FakeRunLane {
    fn answering(answer: &str) -> Self {
        let lane = Self::default();
        lane.state.lock().expect("lane state").answer = Some(answer.to_owned());
        lane
    }

    fn failing(failure: RunFailure) -> Self {
        let lane = Self::default();
        lane.state.lock().expect("lane state").failure = Some(failure);
        lane
    }

    fn tasks(&self) -> Vec<String> {
        self.state.lock().expect("lane state").tasks.clone()
    }
}

impl RunLane for FakeRunLane {
    fn run(&mut self, task: &str) -> Result<String, RunFailure> {
        let mut state = self.state.lock().expect("lane state");
        state.tasks.push(task.to_owned());
        match (state.answer.clone(), state.failure) {
            (Some(answer), _) => Ok(answer),
            (None, Some(failure)) => Err(failure),
            (None, None) => Err(RunFailure::NotConfigured),
        }
    }
}

type Bridge =
    TelegramControlBridge<FakeClient, FakeOutbound, FakeSink, StoreControlSurface, FakeRunLane>;

fn bridge(fixture: &Fixture, client: FakeClient, outbound: FakeOutbound, sink: FakeSink) -> Bridge {
    bridge_with_lane(fixture, client, outbound, sink, FakeRunLane::default())
}

fn bridge_with_lane(
    fixture: &Fixture,
    client: FakeClient,
    outbound: FakeOutbound,
    sink: FakeSink,
    lane: FakeRunLane,
) -> Bridge {
    TelegramControlBridge::new(BridgeParts {
        client,
        outbound,
        sink,
        surface: fixture.surface(),
        lane,
        policy: policy(),
        allowed: AllowedUsers::new([OPERATOR]).expect("allowlist"),
        inbound_token: token(),
        outbound_token: token(),
        long_poll_seconds: LONG_POLL_SECONDS,
    })
    .expect("bridge composes")
}

fn poll(bridge: &mut Bridge) -> Result<DispatchReport, RuntimeError> {
    bridge.poll_and_dispatch(&lease(), NOW_MS, &CancellationToken::new())
}

// --------------------------------------------------------------------- tests

/// The three commands this build performs are answered from the real read
/// surfaces, and each answer is the one an operator would receive.
#[test]
fn help_status_and_runs_are_answered_from_the_live_read_surfaces() {
    let fixture = Fixture::new(&[(7, "run-alpha"), (8, "run-beta")]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/help"),
        (2, OPERATOR, "/status"),
        (3, OPERATOR, "/runs"),
    ])]);
    let outbound = FakeOutbound::default();
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound.clone(), sink.clone());

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.updates, 3);
    assert_eq!(report.answered, 3);
    assert_eq!(report.sent, 3);
    assert_eq!(report.refused, 0);
    assert_eq!(sink.commits(), 1, "one batch commits once");
    assert_eq!(sink.offset(), 4, "the offset advances past the last update");

    let messages = outbound.messages();
    assert_eq!(messages.len(), 3);
    // Help is the registry rendered, so every advertised command appears.
    for entry in command_manifest() {
        assert!(
            messages[0].contains(&format!("/{}", entry.name)),
            "help omitted /{}",
            entry.name
        );
    }
    // Status is the durable snapshot, named by the generation it was read under.
    assert!(messages[1].contains("Automonique status"));
    assert!(messages[1].contains("generation foreground epoch"));
    assert!(messages[1].contains("intake paused: no"));
    assert!(messages[1].contains("sandbox_unavailable_no_lane"));
    // Runs is the index, newest first.
    assert!(messages[2].contains("Recent runs (2 of 2)"));
    assert!(messages[2].contains("run-alpha"));
    assert!(messages[2].contains("run-beta"));
    let beta = messages[2].find("run-beta").expect("beta listed");
    let alpha = messages[2].find("run-alpha").expect("alpha listed");
    assert!(beta < alpha, "the newest run is listed first");

    // Every reply was addressed to the chat it came from, and none of them
    // carried the credential.
    for message in &messages {
        assert!(message.contains(&format!("\"chat_id\":{OPERATOR}")));
        assert!(!message.contains("AAFixtureSecretNeverPrinted"));
    }
}

/// An empty index is answered as an empty index, not as an unavailable read.
#[test]
fn an_empty_run_index_answers_that_nothing_is_recorded() {
    let fixture = Fixture::new(&[]);
    let mut surface = fixture.surface();
    assert_eq!(
        surface.runs_text().expect("runs render"),
        "No runs recorded."
    );
}

/// A sender outside the access policy is answered once, with a fixed literal,
/// and their message never reaches a surface — the policy discarded its text
/// before this bridge saw it.
#[test]
fn an_unauthorized_sender_is_refused_and_reaches_nothing() {
    let fixture = Fixture::new(&[(7, "run-alpha")]);
    let client = FakeClient::new([updates(&[(1, OUTSIDER, "/status please and thank you")])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        client.clone(),
        outbound.clone(),
        FakeSink::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.updates, 1);
    assert_eq!(report.denied_senders, 1);
    assert_eq!(report.answered, 0, "no surface was read for an outsider");
    assert_eq!(report.sent, 1);

    let messages = outbound.messages();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("Not authorized."));
    assert!(messages[0].contains(&format!("\"chat_id\":{OUTSIDER}")));
    assert!(
        !messages[0].contains("please and thank you"),
        "a refusal must never echo the sender's text"
    );
    assert!(!messages[0].contains("Automonique status"));
}

/// A message that is not a command in the closed registry is refused with the
/// command layer's own reply.
#[test]
fn unknown_and_malformed_commands_reply_their_refusals() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/nope"),
        (2, OPERATOR, "hello there"),
        (3, OPERATOR, "/status extra"),
        (4, OPERATOR, "/cancel"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        client.clone(),
        outbound.clone(),
        FakeSink::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.refused, 4);
    assert_eq!(report.answered, 0);
    let messages = outbound.messages();
    assert!(messages[0].contains("Unknown command. Try /help."));
    assert!(messages[1].contains("Commands start with a slash."));
    assert!(messages[2].contains("That command takes no argument."));
    assert!(messages[3].contains("That command needs an argument."));
}

/// Every command with no surface behind it says so, and does nothing.
///
/// `/run` is deliberately absent: it has a surface now, and
/// [`a_run_reaches_the_lane_and_its_answer_is_the_reply`] is where it is proved.
#[test]
fn commands_without_a_surface_say_nothing_happened() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[
        (2, OPERATOR, "/cancel run-alpha"),
        (3, OPERATOR, "/approve approval-1"),
        (4, OPERATOR, "/deny approval-1"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        client.clone(),
        outbound.clone(),
        FakeSink::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.unavailable, 3);
    assert_eq!(report.answered, 0);
    assert_eq!(report.sent, 3);

    let messages = outbound.messages();
    assert!(messages[0].contains(Unavailable::CancelVerb.operator_reply()));
    assert!(messages[1].contains(Unavailable::ApprovalWiring.operator_reply()));
    assert!(messages[2].contains(Unavailable::ApprovalWiring.operator_reply()));
    for message in &messages {
        assert!(
            message.contains("Not available yet."),
            "an unavailable command must not read as an accepted one"
        );
    }
    // Nothing was submitted: the run index is still empty.
    let mut surface = fixture.surface();
    assert_eq!(
        surface.runs_text().expect("runs render"),
        "No runs recorded."
    );
}

/// The menu is published exactly once, and it advertises the whole registry.
#[test]
fn the_menu_is_published_once_and_advertises_every_command() {
    let fixture = Fixture::new(&[]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        FakeClient::new([]),
        outbound.clone(),
        FakeSink::default(),
    );

    assert!(bridge.publish_menu(&CancellationToken::new()));
    assert!(
        !bridge.publish_menu(&CancellationToken::new()),
        "a second publication must not be attempted"
    );

    let sent = outbound.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "setMyCommands");
    for entry in command_manifest() {
        assert!(
            sent[0]
                .body
                .contains(&format!("\"command\":\"{}\"", entry.name)),
            "the menu omitted {}",
            entry.name
        );
    }
    assert!(bridge.totals().menu_published);
    assert!(!sent[0].body.contains("AAFixtureSecretNeverPrinted"));
}

/// A poll the transport refuses, a response the parser refuses, and a reply the
/// outbound seam fails to deliver are all survivable: the next poll answers.
#[test]
fn a_failed_poll_a_bad_body_and_a_failed_send_do_not_stop_the_bridge() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([
        ClientBehavior::Failure(HttpFailure::Unavailable),
        ClientBehavior::Body(String::from("{\"ok\":true,\"result\":[{\"nonsense\":1}]}")),
        updates(&[(1, OPERATOR, "/help")]),
        updates(&[(2, OPERATOR, "/help")]),
    ]);
    let outbound = FakeOutbound::failing_once();
    let sink = FakeSink::default();
    let mut bridge = bridge(&fixture, client.clone(), outbound.clone(), sink.clone());

    assert!(
        poll(&mut bridge).is_err(),
        "an unavailable transport refuses"
    );
    assert!(poll(&mut bridge).is_err(), "an unparseable body refuses");
    let third = poll(&mut bridge).expect("a good poll still commits");
    assert_eq!(third.send_failed, 1, "the scripted send failure is counted");
    assert_eq!(third.sent, 0);
    let fourth = poll(&mut bridge).expect("the bridge kept going");
    assert_eq!(fourth.sent, 1);

    assert_eq!(sink.commits(), 2, "only the two good polls committed");
    assert_eq!(
        client.requested_offsets(),
        vec![0, 0, 0, 2],
        "a refused poll must not advance the durable offset"
    );
    let totals = bridge.totals();
    assert_eq!(totals.polls, 2);
    assert_eq!(
        totals.poll_failures, 0,
        "poll failures are counted by `run`"
    );
    assert_eq!(totals.reparse_failures, 0);
    assert_eq!(outbound.messages().len(), 1);
}

/// A batch the sink reports as already committed is not answered again.
#[test]
fn a_duplicate_commit_is_not_dispatched() {
    let fixture = Fixture::new(&[]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/help")])]),
        outbound.clone(),
        FakeSink::duplicating(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert!(report.duplicate);
    assert_eq!(report.answered, 0);
    assert!(
        outbound.sent().is_empty(),
        "a replayed batch must not be answered twice"
    );
}

/// Updates this build has no answer for are stepped over in silence.
#[test]
fn unsupported_updates_are_ignored_without_a_reply() {
    let fixture = Fixture::new(&[]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        // An update with no discriminator, and a message with no text: both are
        // durable for offset progress and create no work.
        FakeClient::new([ClientBehavior::Body(String::from(
            "{\"ok\":true,\"result\":[{\"update_id\":1},{\"update_id\":2,\"message\":{\"chat\":{\"id\":7654321},\"from\":{\"id\":7654321}}}]}",
        ))]),
        outbound.clone(),
        FakeSink::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.updates, 2);
    assert_eq!(report.ignored, 2);
    assert_eq!(report.sent, 0);
    assert!(outbound.sent().is_empty());
}

/// The loop ends when the host asks it to, without a poll in flight.
#[test]
fn the_run_loop_stops_when_the_stop_flag_is_set() {
    let fixture = Fixture::new(&[]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(
        &fixture,
        FakeClient::new([]),
        outbound.clone(),
        FakeSink::default(),
    );
    let stop = AtomicBool::new(true);
    bridge.run(
        &Arc::new(Mutex::new(lease())),
        &stop,
        &CancellationToken::new(),
    );
    assert_eq!(bridge.totals().polls, 0);
    assert!(bridge.terminal().is_none());
    assert!(outbound.sent().is_empty());
}

/// The read surface refuses rather than reporting a generation it does not
/// hold. A daemon whose fence moved beneath it must not answer with the
/// successor's durable state.
#[test]
fn a_moved_generation_makes_the_status_surface_refuse() {
    let fixture = Fixture::new(&[]);
    let mut surface = StoreControlSurface::open(
        &fixture.database_path,
        &fixture.run_index_path,
        HostFacts {
            lease_epoch: fixture.facts.lease_epoch + 1,
            ..fixture.facts.clone()
        },
    )
    .expect("surface opens");
    assert!(surface.status_text().is_err());

    // And the honest reply for that refusal says only that, naming nothing.
    let refusal = surface.status_text().expect_err("refused");
    assert_eq!(refusal.category(), "surface_unavailable");
    assert!(!refusal.operator_reply().contains("foreground"));
}

/// A run identity longer than one reply can carry is truncated visibly.
#[test]
fn an_overlong_run_identity_is_marked_when_it_is_shortened() {
    let long = "r".repeat(200);
    let fixture = Fixture::new(&[(1, long.as_str())]);
    let mut surface = fixture.surface();
    let rendered = surface.runs_text().expect("runs render");
    assert!(rendered.contains('…'), "truncation must be visible");
    assert!(!rendered.contains(&long));
}

/// A path assertion, not a behaviour one: the fixtures above are the only
/// databases these tests touch, and they live in a private temporary tree.
#[test]
fn fixture_state_is_private_and_temporary() {
    let fixture = Fixture::new(&[]);
    assert!(fixture.database_path.starts_with(Path::new("/tmp")));
    let mode = std::fs::metadata(fixture.database_path.parent().expect("fixture root"))
        .expect("fixture metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the fixture tree must be private");
}

/// A `/run` reaches the lane with exactly the operator's task, and the run's
/// own answer is what the operator is sent back.
///
/// The lane is faked, so what is proved here is the *dispatch*: that `/run` is
/// no longer answered from the unavailable table, that the task text arrives
/// unaltered and unquoted, and that the reply is the answer rather than a
/// rendering of it.
#[test]
fn a_run_reaches_the_lane_and_its_answer_is_the_reply() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[(
        1,
        OPERATOR,
        "/run summarise the release notes",
    )])]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("AUTOMONIQUE-ANSWER-OK");
    let mut bridge = bridge_with_lane(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.runs_answered, 1);
    assert_eq!(report.runs_failed, 0);
    assert_eq!(report.answered, 1);
    assert_eq!(report.unavailable, 0, "/run is no longer unavailable");
    assert_eq!(report.sent, 1);

    assert_eq!(
        lane.tasks(),
        vec![String::from("summarise the release notes")],
        "the lane must receive the operator's task, and only the task"
    );
    let messages = outbound.messages();
    assert!(
        messages[0].contains("AUTOMONIQUE-ANSWER-OK"),
        "the reply must be the run's own answer: {messages:?}"
    );
    assert!(
        !messages[0].contains("Not available yet."),
        "an answered run must not read as an unavailable command"
    );
}

/// A lane that cannot run anything answers in one closed word, and the daemon
/// keeps polling.
#[test]
fn a_refused_run_is_a_typed_reply_and_not_a_crash() {
    for (failure, expected) in [
        (RunFailure::NotConfigured, "Not configured."),
        (RunFailure::TimedOut, "deadline"),
        (RunFailure::NoAnswer, "wrote no answer"),
    ] {
        let fixture = Fixture::new(&[]);
        let client = FakeClient::new([updates(&[(1, OPERATOR, "/run anything")])]);
        let outbound = FakeOutbound::default();
        let mut bridge = bridge_with_lane(
            &fixture,
            client,
            outbound.clone(),
            FakeSink::default(),
            FakeRunLane::failing(failure),
        );

        let report = poll(&mut bridge).expect("poll commits");
        assert_eq!(report.runs_failed, 1, "{failure:?}");
        assert_eq!(report.runs_answered, 0, "{failure:?}");
        assert_eq!(report.sent, 1, "{failure:?}");
        let messages = outbound.messages();
        assert!(
            messages[0].contains(expected),
            "{failure:?} must be reported as itself: {messages:?}"
        );
    }
}

/// An answer larger than one Telegram message is cut and marked, never dropped
/// and never sent whole.
#[test]
fn an_oversized_answer_is_truncated_visibly() {
    let fixture = Fixture::new(&[]);
    let huge = "x".repeat(20_000);
    let client = FakeClient::new([updates(&[(1, OPERATOR, "/run anything")])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge_with_lane(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::answering(&huge),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(
        report.sent, 1,
        "an oversized answer must still be delivered"
    );
    assert_eq!(report.send_refused, 0, "the transport must not refuse it");
    let messages = outbound.messages();
    assert!(
        messages[0].contains("truncated"),
        "truncation must be visible: {:?}",
        &messages[0][..messages[0].len().min(120)]
    );
    assert!(
        !messages[0].contains(&huge),
        "the whole answer must not be sent"
    );
}
