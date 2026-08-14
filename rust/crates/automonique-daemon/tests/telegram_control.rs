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
    BridgeParts, ControlSurface, DispatchReport, HostFacts, MemberChange, NO_TICKETS_RECORDED,
    OperatorRoster, RunFailure, RunLane, StoreControlSurface, TICKET_NOT_FOUND, TICKETS_LISTED,
    TICKETS_NOT_ENABLED, TelegramControlBridge, Unavailable,
};
use automonique_protocol::admin::ExecutionState;
use automonique_store::operator_members::OperatorMemberStore;
use automonique_store::run_index::{RunIndex, RunIndexEntry};
use automonique_store::support_tickets::{
    FleetTicket, SupportTicketStore, TicketLifecycle, TicketTransition,
};
use automonique_store::{LeaseRequest, Store};
use automonique_transport_runtime::{
    CancellationToken, CommandTier, DurableCommitReceipt, DurableDisposition, DurableTelegramBatch,
    HttpFailure, OffsetReceipt, OpaqueBotToken, PollerLease, RuntimeError, SinkFailure,
    TelegramDurableSink, TelegramHttpClient, TelegramHttpPlan, TelegramHttpResponse,
    TelegramOutboundClient, TelegramOutboundPlan, command_manifest,
};
use automonique_transports::{TelegramBotId, TelegramPrincipal};

/// The bot every fixture configures.
const BOT_ID: i64 = 123_456;
/// The one operator these fixtures authorize, and an administrator in each of
/// them — `bot.conf` with no `admin=` line makes every allowed user one.
const OPERATOR: i64 = 7_654_321;
/// A non-admin member in the tiered fixtures: allowed by configuration, not an
/// administrator.
const MEMBER: i64 = 5_550_001;
/// Somebody an `/admin add` lets in, who starts on no list at all.
const NEWCOMER: i64 = 4_440_002;
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
    /// The disposition the *poller* committed for each update of each batch.
    ///
    /// Kept because it is the only view of what the transport policy decided at
    /// fetch time. The dispatch that follows re-parses the same bytes, so a
    /// reply alone cannot tell whether the two agreed — and they must, or the
    /// bot answers a sender its own durable record says it denied.
    committed: Vec<Vec<DurableDisposition>>,
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

    /// What the poller durably committed for the most recent batch.
    fn last_committed(&self) -> Vec<DurableDisposition> {
        self.state
            .lock()
            .expect("sink state")
            .committed
            .last()
            .cloned()
            .unwrap_or_default()
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
        state.committed.push(
            batch
                .updates
                .iter()
                .map(|update| update.disposition.clone())
                .collect(),
        );
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

/// The instant every seeded ticket is observed at. The read surface never reads
/// a clock for a ticket, so this is the only one these fixtures need.
const TICKET_OBSERVED_MS: i64 = 1_699_000_000_000;

/// A private temporary tree holding a store, a run index, and a live generation.
struct Fixture {
    _root: tempfile::TempDir,
    facts: HostFacts,
    database_path: std::path::PathBuf,
    run_index_path: std::path::PathBuf,
    support_tickets_path: std::path::PathBuf,
    operator_members_path: std::path::PathBuf,
}

/// One synthetic support ticket a fixture records.
///
/// Every field is invented for this file. No fleet identifier, tenant, site or
/// requester here names anything real, and nothing in this file reads a live
/// board: the store is seeded directly, which is the whole point of the seam.
#[derive(Clone, Copy)]
struct SeedTicket<'a> {
    fleet_issue_id: &'a str,
    title: &'a str,
    tenant_name: &'a str,
    fleet_status: &'a str,
    /// Where this host has taken the ticket, reached one lattice step at a time
    /// from `new`.
    lifecycle: TicketLifecycle,
}

impl<'a> SeedTicket<'a> {
    /// A ticket at `new`, which is what a first sighting always records.
    const fn new(fleet_issue_id: &'a str, title: &'a str) -> Self {
        Self {
            fleet_issue_id,
            title,
            tenant_name: "reserved-tenant",
            fleet_status: "triaging",
            lifecycle: TicketLifecycle::New,
        }
    }

    const fn at(mut self, lifecycle: TicketLifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    const fn for_tenant(mut self, tenant_name: &'a str) -> Self {
        self.tenant_name = tenant_name;
        self
    }
}

impl Fixture {
    /// Build the durable state a status and a runs reply are rendered from.
    fn new(runs: &[(i64, &str)]) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let database_path = root.path().join("automonique.sqlite3");
        let run_index_path = root.path().join("run-index.sqlite3");
        // Named and deliberately not created: a fixture that seeds no ticket is
        // a host whose support intake was never configured.
        let support_tickets_path = root.path().join("support-tickets.sqlite3");
        // Likewise named and not created: a host whose administrators have
        // never added a member has no roster file at all.
        let operator_members_path = root.path().join("operator-members.sqlite3");
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

    /// Record these members in this host's roster, creating it.
    ///
    /// This is what an earlier `/admin add` would have left behind, done
    /// directly so a test can start from a host that already has members.
    fn seed_members(&self, members: &[i64]) {
        let mut store =
            OperatorMemberStore::open(&self.operator_members_path).expect("member roster opens");
        for member in members {
            store
                .add_member(*member, TICKET_OBSERVED_MS)
                .expect("added");
        }
    }

    /// The member ids this host's roster holds, read straight from the file.
    fn stored_members(&self) -> Vec<i64> {
        if !self.operator_members_path.is_file() {
            return Vec::new();
        }
        OperatorMemberStore::open(&self.operator_members_path)
            .expect("member roster opens")
            .member_ids()
            .expect("members")
    }

    /// Record these tickets in this host's ticket store, creating it.
    ///
    /// This is the intake worker's job in production and is done directly here:
    /// no fleet is polled, no credential exists in this tree, and the store is
    /// the only thing the bridge reads. A ticket is recorded at `new` and then
    /// walked one lattice step at a time to whatever lifecycle the seed asks
    /// for, because that is the only way this host is allowed to move one.
    fn seed_tickets(&self, seeds: &[SeedTicket<'_>]) {
        let mut store = SupportTicketStore::open(&self.support_tickets_path)
            .expect("support ticket store opens");
        for seed in seeds {
            let receipt = store
                .record(&FleetTicket {
                    fleet_issue_id: seed.fleet_issue_id,
                    title: seed.title,
                    tenant_name: seed.tenant_name,
                    site_label: Some("reserved-site"),
                    fleet_status: seed.fleet_status,
                    priority: "normal",
                    source: "email",
                    requested_by: "reserved-requester",
                    comment_count: 2,
                    created_at: "2026-01-01T00:00:00Z",
                    updated_at: "2026-01-02T00:00:00Z",
                    observed_at_ms: TICKET_OBSERVED_MS,
                })
                .expect("ticket recorded");
            let mut revision = receipt.revision;
            for step in TicketLifecycle::ALL.into_iter().filter(|lifecycle| {
                lifecycle.rank() > 0 && lifecycle.rank() <= seed.lifecycle.rank()
            }) {
                revision = store
                    .transition(TicketTransition {
                        fleet_issue_id: seed.fleet_issue_id,
                        expected_revision: revision,
                        lifecycle: step,
                        now_ms: TICKET_OBSERVED_MS,
                    })
                    .expect("lifecycle advances")
                    .revision;
            }
        }
    }

    /// Create an empty ticket store, as a configured host that has polled a
    /// board with nothing open on it would have.
    fn seed_empty_ticket_store(&self) {
        SupportTicketStore::open(&self.support_tickets_path).expect("support ticket store opens");
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

/// The configured roster these fixtures compose from.
///
/// `admins` and `allowed` are spliced exactly as `bot.conf`'s `admin=` and
/// `allow=` lines would be: each user is given their private chat, every
/// configured user is allowed, and only the first list is administrative.
fn roster(admins: &[i64], allowed: &[i64]) -> OperatorRoster {
    let configured: Vec<i64> = admins.iter().chain(allowed).copied().collect();
    OperatorRoster::new(
        TelegramBotId::new(BOT_ID).expect("bot id"),
        configured
            .iter()
            .map(|id| TelegramPrincipal::new(*id, *id).expect("principal")),
        configured.iter().copied(),
        admins.iter().copied(),
    )
    .expect("roster")
}

/// The single-tier roster: one operator, who is therefore an administrator.
///
/// This is what a `bot.conf` carrying only `allow=` composes, so every test
/// written before the tiers existed still exercises the configuration those
/// deployments have.
fn single_tier_roster() -> OperatorRoster {
    roster(&[OPERATOR], &[])
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
    bridge_with_roster(fixture, client, outbound, sink, lane, single_tier_roster())
}

fn bridge_with_roster(
    fixture: &Fixture,
    client: FakeClient,
    outbound: FakeOutbound,
    sink: FakeSink,
    lane: FakeRunLane,
    roster: OperatorRoster,
) -> Bridge {
    TelegramControlBridge::new(BridgeParts {
        client,
        outbound,
        sink,
        surface: fixture.surface(),
        lane,
        roster,
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

/// `/tickets` lists what the ticket store holds, newest first, and `/ticket`
/// answers with that exact ticket.
///
/// The store is real and seeded directly; no board is polled anywhere in this
/// file. What is proved is the whole path: the parser produced two new commands,
/// the bridge routed them to the ticket reads rather than to the unavailable
/// table, and the surface rendered the durable rows.
#[test]
fn tickets_are_listed_and_one_ticket_is_answered_from_the_store() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[
        SeedTicket::new("SUP-1001", "Printer offline in the back room")
            .at(TicketLifecycle::Working)
            .for_tenant("reserved-tenant-one"),
        SeedTicket::new("SUP-1002", "Mail relay rejects attachments")
            .for_tenant("reserved-tenant-two"),
    ]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/tickets"),
        (2, OPERATOR, "/ticket SUP-1001"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(&fixture, client, outbound.clone(), FakeSink::default());

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.answered, 2);
    assert_eq!(
        report.unavailable, 0,
        "ticket reads are not an unavailable command"
    );
    assert_eq!(report.refused, 0);
    assert_eq!(report.sent, 2);
    assert_eq!(report.send_refused, 0, "both replies fit one message");

    let messages = outbound.messages();
    // The listing names both tickets, newest first, with both states beside
    // each other: this host's lifecycle and the fleet's own status.
    assert!(messages[0].contains("Recent tickets (2 of 2)"));
    assert!(messages[0].contains("SUP-1001"));
    assert!(messages[0].contains("SUP-1002"));
    assert!(messages[0].contains("working/triaging"));
    assert!(messages[0].contains("new/triaging"));
    assert!(messages[0].contains("reserved-tenant-one"));
    let second = messages[0].find("SUP-1002").expect("second listed");
    let first = messages[0].find("SUP-1001").expect("first listed");
    assert!(second < first, "the newest ticket is listed first");

    // The detail is the row that reference names, and no other.
    assert!(messages[1].contains("Ticket SUP-1001"));
    assert!(messages[1].contains("Printer offline in the back room"));
    assert!(messages[1].contains("lifecycle working"));
    assert!(messages[1].contains("fleet status triaging"));
    assert!(messages[1].contains("tenant reserved-tenant-one"));
    assert!(
        !messages[1].contains("SUP-1002"),
        "a detail must answer about one ticket: {:?}",
        messages[1]
    );
    for message in &messages {
        assert!(message.contains(&format!("\"chat_id\":{OPERATOR}")));
        assert!(!message.contains("AAFixtureSecretNeverPrinted"));
    }
}

/// A reference this host has no ticket for is answered as such, and never as a
/// broken read.
#[test]
fn an_unrecorded_reference_is_answered_as_not_found() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[SeedTicket::new("SUP-2001", "Only ticket recorded here")]);
    // The last of these is longer than the ticket store's own identifier
    // ceiling and shorter than the command layer's, so it is a reference that
    // parses and can name nothing.
    let overlong = "S".repeat(121);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/ticket SUP-9999"),
        (2, OPERATOR, &format!("/ticket {overlong}")),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(&fixture, client, outbound.clone(), FakeSink::default());

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.answered, 2);
    assert_eq!(report.sent, 2);
    let messages = outbound.messages();
    for message in &messages {
        assert!(
            message.contains(TICKET_NOT_FOUND),
            "an unrecorded reference must say so: {message:?}"
        );
        assert!(
            !message.contains("SUP-9999") && !message.contains(&overlong),
            "a not-found reply must not echo the reference"
        );
        assert!(
            !message.contains("SUP-2001"),
            "and must name no other ticket"
        );
    }
}

/// A daemon with no ticket store says ticket tracking is not enabled, and asking
/// does not bring a store into existence.
#[test]
fn a_host_without_a_ticket_store_says_tracking_is_not_enabled() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/tickets"),
        (2, OPERATOR, "/ticket SUP-1001"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(&fixture, client, outbound.clone(), FakeSink::default());

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.answered, 2, "an honest answer is still an answer");
    assert_eq!(report.sent, 2);
    for message in outbound.messages() {
        assert!(
            message.contains("not enabled"),
            "a host with no intake must say so: {message:?}"
        );
        assert!(
            !message.contains("unavailable") && !message.contains("No tickets recorded"),
            "\"not enabled\" is neither a fault nor an empty board: {message:?}"
        );
    }
    assert!(
        !fixture.support_tickets_path.exists(),
        "a read surface must not create the store it reads"
    );
}

/// A store that exists and holds nothing is an empty board, which is a different
/// answer from an unconfigured host.
#[test]
fn an_empty_ticket_store_answers_that_nothing_is_recorded() {
    let fixture = Fixture::new(&[]);
    fixture.seed_empty_ticket_store();
    let mut surface = fixture.surface();
    assert_eq!(
        surface.tickets_text().expect("tickets render"),
        NO_TICKETS_RECORDED
    );
    assert_eq!(
        surface.ticket_text("SUP-1001").expect("ticket renders"),
        TICKET_NOT_FOUND
    );

    // And the same surface on a tree with no store at all says the other thing.
    let unconfigured = Fixture::new(&[]);
    let mut surface = unconfigured.surface();
    assert_eq!(
        surface.tickets_text().expect("tickets render"),
        TICKETS_NOT_ENABLED
    );
    assert_eq!(
        surface.ticket_text("SUP-1001").expect("ticket renders"),
        TICKETS_NOT_ENABLED
    );
}

/// A listing is bounded in rows and in width: the newest page only, and a title
/// too wide for a line is cut where an operator can see it was.
#[test]
fn a_ticket_listing_is_bounded_in_rows_and_in_width() {
    let fixture = Fixture::new(&[]);
    let wide = "w".repeat(200);
    let seeds: Vec<SeedTicket<'_>> = (1..=(TICKETS_LISTED + 2))
        .map(|index| {
            if index == TICKETS_LISTED + 2 {
                SeedTicket::new("SUP-3999", wide.as_str())
            } else {
                SeedTicket::new(SEEDED_IDS[index - 1], "Bounded fixture ticket")
            }
        })
        .collect();
    fixture.seed_tickets(&seeds);

    let mut surface = fixture.surface();
    let rendered = surface.tickets_text().expect("tickets render");
    assert!(
        rendered.contains(&format!(
            "Recent tickets ({TICKETS_LISTED} of {})",
            seeds.len()
        )),
        "only the newest page is listed: {rendered}"
    );
    assert_eq!(
        rendered.lines().count(),
        TICKETS_LISTED + 1,
        "one header and one line per listed ticket"
    );
    assert!(
        !rendered.contains(SEEDED_IDS[0]),
        "the oldest ticket is off the newest page"
    );
    assert!(rendered.contains('…'), "a cut title must be marked");
    assert!(!rendered.contains(&wide), "and must not be sent whole");
}

/// Fixed identifiers for the bounded-listing fixture, so no test invents one at
/// runtime and no identifier here resembles a real board's.
const SEEDED_IDS: [&str; TICKETS_LISTED + 2] = [
    "SUP-3001", "SUP-3002", "SUP-3003", "SUP-3004", "SUP-3005", "SUP-3006", "SUP-3007", "SUP-3008",
    "SUP-3009", "SUP-3010", "SUP-3011", "SUP-3012",
];

/// A sender the access policy denied cannot reach the ticket store, even with a
/// command that would otherwise be answered.
#[test]
fn an_unauthorized_sender_cannot_read_tickets() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[SeedTicket::new("SUP-4001", "Confidential fixture title")]);
    let client = FakeClient::new([updates(&[
        (1, OUTSIDER, "/tickets"),
        (2, OUTSIDER, "/ticket SUP-4001"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge(&fixture, client, outbound.clone(), FakeSink::default());

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.denied_senders, 2);
    assert_eq!(
        report.answered, 0,
        "no ticket read happened for an outsider"
    );
    for message in outbound.messages() {
        assert!(message.contains("Not authorized."));
        assert!(
            !message.contains("SUP-4001") && !message.contains("Confidential fixture title"),
            "a refusal must carry nothing from the store: {message:?}"
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

// ------------------------------------------------------------------- /work

/// THE WHOLE COMMAND, MINUS THE RUN. `/work` reads a ticket, composes an
/// instruction from it, puts that through the run lane, and stores what comes
/// back as the ticket's draft.
///
/// The lane is faked here for the reason it is faked for `/run`: whether a
/// contained provider answers is `ticket_work`'s question and it needs a
/// delegated cgroup scope to ask it. Everything else on this path is the
/// production code — the real ticket store, the real composition, the real
/// draft write, the real lifecycle move.
#[test]
fn work_composes_from_the_ticket_runs_it_and_stores_the_draft() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[
        SeedTicket::new("SUP-1001", "Printer offline in the back room")
            .at(TicketLifecycle::Working)
            .for_tenant("reserved-tenant-one"),
        SeedTicket::new("SUP-1002", "Mail relay rejects attachments"),
    ]);
    let client = FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-1001")])]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("Bonjour, nous avons identifié la panne.");
    let mut bridge = bridge_with_lane(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.tickets_worked, 1);
    assert_eq!(report.ticket_work_failed, 0);
    assert_eq!(report.answered, 1);
    assert_eq!(report.unavailable, 0, "/work is not an unavailable command");
    assert_eq!(report.sent, 1);
    assert_eq!(
        report.runs_answered, 0,
        "a worked ticket is counted as itself, not as a /run"
    );

    // THE INSTRUCTION IS COMPOSED FROM THE TICKET, and it is a work order.
    let tasks = lane.tasks();
    assert_eq!(tasks.len(), 1, "one command is one run");
    let task = &tasks[0];
    assert!(task.contains("Ticket: SUP-1001"), "{task}");
    assert!(task.contains("Subject: Printer offline in the back room"));
    assert!(task.contains("Tenant: reserved-tenant-one"));
    assert!(task.contains("Draft a support answer"));
    assert!(
        task.contains("nothing is sent to the requester"),
        "the instruction must say the draft goes nowhere"
    );
    assert!(
        !task.contains("SUP-1002"),
        "a work order must carry one ticket and no others: {task}"
    );

    // THE DRAFT IS STORED, DURABLY, AND THE LIFECYCLE MOVED.
    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    let draft = store
        .draft("SUP-1001")
        .expect("draft read")
        .expect("a draft was stored");
    assert_eq!(draft.text, "Bonjour, nous avons identifié la panne.");
    assert_eq!(draft.lifecycle, TicketLifecycle::Answered);
    let record = store
        .ticket("SUP-1001")
        .expect("read")
        .expect("present")
        .clone();
    assert_eq!(record.lifecycle, TicketLifecycle::Answered);
    assert_eq!(record.draft_answer_bytes, Some(draft.text.len()));
    // The other ticket was not touched by working this one.
    let untouched = store.ticket("SUP-1002").expect("read").expect("present");
    assert_eq!(untouched.lifecycle, TicketLifecycle::New);
    assert_eq!(untouched.draft_answer_bytes, None);

    // THE REPLY IS A CONFIRMATION, NOT THE DRAFT.
    let messages = outbound.messages();
    assert!(
        messages[0].contains("Worked ticket SUP-1001"),
        "{messages:?}"
    );
    assert!(messages[0].contains("lifecycle -> answered"));
    assert!(
        messages[0].contains(&format!("({} chars)", draft.text.chars().count())),
        "the confirmation must say how much was stored: {messages:?}"
    );
    assert!(
        !messages[0].contains("Bonjour"),
        "the draft itself must not be sent to the chat: {messages:?}"
    );
    assert!(messages[0].contains(&format!("\"chat_id\":{OPERATOR}")));
    assert!(!messages[0].contains("AAFixtureSecretNeverPrinted"));
}

/// A ticket at `new` is worked in one command: the store walks the lattice, and
/// the operator does not have to type three transitions they have no command
/// for.
#[test]
fn a_ticket_at_new_is_walked_all_the_way_to_answered() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[SeedTicket::new("SUP-3001", "Nobody has looked at this yet")]);
    let client = FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-3001")])]);
    let outbound = FakeOutbound::default();
    let mut bridge = bridge_with_lane(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::answering("a draft for a brand new ticket"),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.tickets_worked, 1);
    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    let record = store.ticket("SUP-3001").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Answered);
    assert_eq!(
        record.revision, 2,
        "three lattice steps and a draft are one change"
    );
}

/// THE FALSIFICATION. Every way a `/work` stores nothing is answered as itself,
/// and none of them moves the ticket.
///
/// Without this, the test above would pass just as well against a dispatch that
/// stored a draft for anything anybody typed.
#[test]
fn a_work_that_stores_nothing_says_which_way_it_failed() {
    // A reference this host has no ticket for. No run is spent on it.
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[SeedTicket::new("SUP-5001", "The only ticket here")]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("a draft nobody asked for");
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-9999")])]),
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );
    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.ticket_work_failed, 1);
    assert_eq!(report.tickets_worked, 0);
    assert!(outbound.messages()[0].contains(TICKET_NOT_FOUND));
    assert!(
        lane.tasks().is_empty(),
        "an unrecorded reference must not spend a run"
    );

    // A lane that is not configured: the same word `/run` answers with, and
    // still no draft.
    let outbound = FakeOutbound::default();
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-5001")])]),
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::failing(RunFailure::NotConfigured),
    );
    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.ticket_work_failed, 1);
    assert!(
        outbound.messages()[0].contains("Not configured."),
        "{:?}",
        outbound.messages()
    );
    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    let record = store.ticket("SUP-5001").expect("read").expect("present");
    assert_eq!(
        record.lifecycle,
        TicketLifecycle::New,
        "a refused run must leave the ticket where it was"
    );
    assert_eq!(record.draft_answer_bytes, None);
    drop(store);

    // A run that completed and wrote nothing storable.
    let outbound = FakeOutbound::default();
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-5001")])]),
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::answering("   \n\t  "),
    );
    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.ticket_work_failed, 1);
    assert!(outbound.messages()[0].contains("wrote nothing that could be stored"));
    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    assert_eq!(
        store
            .ticket("SUP-5001")
            .expect("read")
            .expect("present")
            .lifecycle,
        TicketLifecycle::New
    );
}

/// A ticket that has already been answered is not worked twice, and the first
/// draft is not overwritten.
#[test]
fn a_re_work_is_refused_and_the_first_draft_stands() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[
        SeedTicket::new("SUP-6001", "Worked once already").at(TicketLifecycle::Working)
    ]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("the first draft");
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-6001")])]),
        outbound.clone(),
        FakeSink::default(),
        lane,
    );
    assert_eq!(poll(&mut bridge).expect("poll commits").tickets_worked, 1);

    // The second `/work` is refused before a run is started.
    let outbound = FakeOutbound::default();
    let second = FakeRunLane::answering("a second and different draft");
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-6001")])]),
        outbound.clone(),
        FakeSink::default(),
        second.clone(),
    );
    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.ticket_work_failed, 1);
    assert_eq!(report.tickets_worked, 0);
    assert!(
        outbound.messages()[0].contains("already been answered or closed"),
        "{:?}",
        outbound.messages()
    );
    assert!(
        second.tasks().is_empty(),
        "an answered ticket must not spend a second run"
    );

    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    assert_eq!(
        store
            .draft("SUP-6001")
            .expect("read")
            .expect("present")
            .text,
        "the first draft",
        "the first draft must stand"
    );
}

/// A host that tracks no tickets says so, and working one brings no store into
/// existence.
#[test]
fn a_host_without_a_ticket_store_cannot_be_asked_to_work_one() {
    let fixture = Fixture::new(&[]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("a draft that must never be composed");
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OPERATOR, "/work SUP-7001")])]),
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.ticket_work_failed, 1);
    assert!(outbound.messages()[0].contains(TICKETS_NOT_ENABLED));
    assert!(lane.tasks().is_empty(), "no run may be spent");
    assert!(
        !fixture.support_tickets_path.exists(),
        "asking must not create a ticket store"
    );
}

/// A sender the access policy denied cannot work a ticket, which is the whole
/// authorization story for the one durable write on this surface.
#[test]
fn an_unauthorized_sender_cannot_work_a_ticket() {
    let fixture = Fixture::new(&[]);
    fixture.seed_tickets(&[SeedTicket::new("SUP-8001", "Confidential fixture title")]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("a draft an outsider must not cause");
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([updates(&[(1, OUTSIDER, "/work SUP-8001")])]),
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.denied_senders, 1);
    assert_eq!(report.tickets_worked, 0);
    assert!(lane.tasks().is_empty(), "no run for an outsider");
    assert!(outbound.messages()[0].contains("Not authorized."));

    let store =
        SupportTicketStore::open(&fixture.support_tickets_path).expect("ticket store reopens");
    let record = store.ticket("SUP-8001").expect("read").expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::New);
    assert_eq!(record.draft_answer_bytes, None);
}

/// The detail view reports that a draft exists and how big it is, and never the
/// draft itself.
#[test]
fn a_ticket_detail_reports_a_draft_by_size_and_never_by_text() {
    let fixture = Fixture::new(&[]);
    fixture
        .seed_tickets(&[SeedTicket::new("SUP-9001", "Has a draft").at(TicketLifecycle::Working)]);
    let draft = "Bonjour, voici la réponse proposée.";
    let outbound = FakeOutbound::default();
    let mut bridge = bridge_with_lane(
        &fixture,
        FakeClient::new([
            updates(&[(1, OPERATOR, "/ticket SUP-9001")]),
            updates(&[(2, OPERATOR, "/work SUP-9001")]),
            updates(&[(3, OPERATOR, "/ticket SUP-9001")]),
        ]),
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::answering(draft),
    );
    for _ in 0..3 {
        poll(&mut bridge).expect("poll commits");
    }

    let messages = outbound.messages();
    assert!(
        messages[0].contains("draft none"),
        "before the work: {:?}",
        messages[0]
    );
    assert!(
        messages[2].contains(&format!("draft {} bytes", draft.len())),
        "after the work: {:?}",
        messages[2]
    );
    assert!(
        !messages[2].contains("voici la réponse"),
        "a detail view must not carry the draft's text: {:?}",
        messages[2]
    );
}

// ------------------------------------------------------ two operator tiers

/// A tiered bridge: `OPERATOR` is an administrator, `MEMBER` is allowed by
/// configuration and is not.
fn tiered_bridge(
    fixture: &Fixture,
    client: FakeClient,
    outbound: FakeOutbound,
    sink: FakeSink,
    lane: FakeRunLane,
) -> Bridge {
    bridge_with_roster(
        fixture,
        client,
        outbound,
        sink,
        lane,
        roster(&[OPERATOR], &[MEMBER]),
    )
}

/// THE TIER LINE, FROM BOTH SIDES. A member reads everything and spends
/// nothing; an administrator does both. The lane is the proof that matters —
/// a refused `/run` must not have reached it, because reaching it is what
/// costs money.
#[test]
fn a_member_reads_but_cannot_spend_or_manage_users() {
    let fixture = Fixture::new(&[(7, "run-alpha")]);
    let client = FakeClient::new([
        updates(&[
            (1, MEMBER, "/status"),
            (2, MEMBER, "/runs"),
            (3, MEMBER, "/help"),
            (4, MEMBER, "/run summarize the board"),
            (5, MEMBER, "/work SUP-1042"),
            (6, MEMBER, "/admin list"),
            (7, MEMBER, "/admin add 4440002"),
        ]),
        updates(&[(8, OPERATOR, "/run summarize the board")]),
    ]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("the answer");
    let mut bridge = tiered_bridge(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    let member_report = poll(&mut bridge).expect("poll commits");
    assert_eq!(member_report.updates, 7);
    assert_eq!(member_report.answered, 3, "the three reads are answered");
    assert_eq!(member_report.refused, 4, "the four admin commands are not");
    assert_eq!(member_report.runs_answered, 0);
    assert_eq!(member_report.member_mutations, 0);
    assert_eq!(
        lane.tasks(),
        Vec::<String>::new(),
        "a refused /run must never reach the lane; reaching it is the spend"
    );
    assert_eq!(
        fixture.stored_members(),
        Vec::<i64>::new(),
        "a member's /admin add must not write a row"
    );

    let messages = outbound.messages();
    assert!(messages[0].contains("Automonique status"));
    assert!(messages[1].contains("Recent runs"));
    // The refusal is the tier's, and it is the same one every time — it never
    // reports which argument was wrong, because the command was not theirs.
    for message in &messages[3..] {
        assert!(
            message.contains("Not authorized for that."),
            "a member must be told the tier, not the grammar: {message:?}"
        );
        assert!(
            !message.contains("Not available yet"),
            "a refusal must not read as a missing feature: {message:?}"
        );
        assert!(
            !message.contains("needs an argument"),
            "a refusal must not leak the grammar: {message:?}"
        );
    }

    // The same command, from the administrator, is carried out.
    let admin_report = poll(&mut bridge).expect("poll commits");
    assert_eq!(admin_report.runs_answered, 1);
    assert_eq!(lane.tasks(), vec![String::from("summarize the board")]);
}

/// The whole point of the feature: an administrator lets somebody in from a
/// chat, they can immediately use the bot, and a revocation takes it back —
/// with no restart anywhere in the sequence.
#[test]
fn an_admin_add_admits_a_newcomer_and_a_remove_revokes_them() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([
        // The addition, and — in the same batch — a message from the newcomer.
        updates(&[
            (1, OPERATOR, "/admin add 4440002"),
            (2, NEWCOMER, "/status"),
        ]),
        // The next poll is the first one fetched under the widened policy.
        updates(&[(3, NEWCOMER, "/status")]),
        updates(&[(4, OPERATOR, "/admin remove 4440002")]),
        updates(&[(5, NEWCOMER, "/status")]),
    ]);
    let outbound = FakeOutbound::default();
    let sink = FakeSink::default();
    let mut bridge = tiered_bridge(
        &fixture,
        client,
        outbound.clone(),
        sink.clone(),
        FakeRunLane::default(),
    );

    let added = poll(&mut bridge).expect("poll commits");
    assert_eq!(added.member_mutations, 1);
    assert_eq!(fixture.stored_members(), vec![NEWCOMER], "durably recorded");
    assert!(
        bridge.authority().authorize(NEWCOMER),
        "the composed gate widens within the batch, without a restart"
    );
    assert_eq!(
        bridge.authority().tier_of(NEWCOMER),
        Some(CommandTier::Allowed),
        "a member added from a chat is never an administrator"
    );
    assert_eq!(
        added.denied_senders, 1,
        "the newcomer's own message in that batch was fetched under the old \
         policy, and its durable disposition already says denied"
    );

    let answered = poll(&mut bridge).expect("poll commits");
    assert_eq!(answered.answered, 1, "the next poll answers them");
    assert_eq!(answered.denied_senders, 0);
    // THE TWO GATES AGREE. The reply above came from the dispatch's re-parse;
    // this is what the *poller* durably committed for the same bytes. They must
    // match, or the bot has answered a sender its own record says it denied —
    // which is exactly what happens if the refreshed policy is published to the
    // bridge and not to the poller.
    assert!(
        matches!(
            sink.last_committed().as_slice(),
            [DurableDisposition::Admitted { .. }]
        ),
        "the poller committed {:?} for a message it answered",
        sink.last_committed()
    );

    let removed = poll(&mut bridge).expect("poll commits");
    assert_eq!(removed.member_mutations, 1);
    assert_eq!(fixture.stored_members(), Vec::<i64>::new());
    assert!(!bridge.authority().authorize(NEWCOMER));

    let revoked = poll(&mut bridge).expect("poll commits");
    assert_eq!(
        sink.last_committed(),
        vec![DurableDisposition::Denied],
        "a revoked member is denied by the poller itself, not merely unanswered"
    );
    assert_eq!(
        revoked.denied_senders, 1,
        "revocation holds at the transport"
    );
    assert_eq!(revoked.answered, 0);

    let messages = outbound.messages();
    assert!(messages[0].contains(&format!("Added member {NEWCOMER}")));
    assert!(messages[3].contains(&format!("Removed member {NEWCOMER}")));
    assert!(
        messages
            .last()
            .expect("a reply")
            .contains("Not authorized."),
        "a revoked member is a stranger again: {:?}",
        messages.last()
    );
}

/// The one thing a chat may never do. Administrators come from `bot.conf`, so
/// `/admin` refuses to touch one in either direction — and refuses to revoke a
/// configured `allow=` user, who is likewise the owner's to remove.
#[test]
fn configuration_owned_users_cannot_be_added_or_removed_from_a_chat() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/admin add 7654321"),
        (2, OPERATOR, "/admin remove 7654321"),
        (3, OPERATOR, "/admin add 5550001"),
        (4, OPERATOR, "/admin remove 5550001"),
    ])]);
    let outbound = FakeOutbound::default();
    let mut bridge = tiered_bridge(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.answered, 4, "each is answered, and each is a no-op");
    assert_eq!(
        report.member_mutations, 0,
        "not one configuration-owned id may reach the durable roster"
    );
    assert_eq!(fixture.stored_members(), Vec::<i64>::new());
    assert_eq!(
        bridge.authority().admins().as_slice(),
        [OPERATOR],
        "the admin set is the configuration's, before and after"
    );

    // The two guards answer differently on purpose, and the difference is
    // asserted: an administrator must be refused *as an administrator*, not
    // merely as somebody configuration happens to name. They are protected
    // twice over, and a test that could not tell the guards apart would let
    // the inner one be deleted silently.
    let messages = outbound.messages();
    assert!(
        messages[0].contains("is an administrator"),
        "{}",
        messages[0]
    );
    assert!(
        messages[1].contains("is an administrator")
            && messages[1].contains("cannot be removed from a chat"),
        "{}",
        messages[1]
    );
    assert!(
        messages[2].contains("already allowed by this host's bot configuration"),
        "{}",
        messages[2]
    );
    assert!(
        messages[3].contains(
            "allowed by this host's bot configuration and \
             cannot be removed from a chat"
        ),
        "{}",
        messages[3]
    );
    assert!(
        !messages[3].contains("is an administrator"),
        "a configured member is not an administrator: {}",
        messages[3]
    );
}

/// `/admin list` is a read: it names ids and nothing else, and moves nothing.
#[test]
fn the_roster_listing_reports_ids_only_and_changes_nothing() {
    let fixture = Fixture::new(&[]);
    fixture.seed_members(&[NEWCOMER]);
    let client = FakeClient::new([updates(&[(1, OPERATOR, "/admin list")])]);
    let outbound = FakeOutbound::default();
    let mut bridge = tiered_bridge(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        FakeRunLane::default(),
    );

    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.answered, 1);
    assert_eq!(report.member_mutations, 0);
    assert_eq!(fixture.stored_members(), vec![NEWCOMER]);

    let listing = &outbound.messages()[0];
    assert!(
        listing.contains(&format!("administrators: {OPERATOR}")),
        "{listing}"
    );
    assert!(
        listing.contains(&format!("allowed by configuration: {MEMBER}")),
        "{listing}"
    );
    assert!(
        listing.contains(&format!("members added here: {NEWCOMER}")),
        "{listing}"
    );
    // A member seeded before the bridge existed is admitted from the first
    // poll, because the refresh happens before the request.
    assert!(bridge.authority().authorize(NEWCOMER));
}

/// The production surface's own contract: a read never creates the roster
/// file, and the first write does.
#[test]
fn the_surface_creates_the_roster_only_when_a_member_is_recorded() {
    let fixture = Fixture::new(&[]);
    let mut surface = fixture.surface();

    assert_eq!(
        surface.member_ids().expect("no roster is not a fault"),
        Vec::<i64>::new()
    );
    assert_eq!(
        surface.remove_member(NEWCOMER).expect("revocation"),
        MemberChange::NotAMember
    );
    assert!(
        !fixture.operator_members_path.is_file(),
        "reading who the members are must not conjure a database"
    );

    assert_eq!(
        surface.add_member(NEWCOMER).expect("addition"),
        MemberChange::Added
    );
    assert!(fixture.operator_members_path.is_file());
    assert_eq!(
        surface.add_member(NEWCOMER).expect("re-addition"),
        MemberChange::AlreadyMember
    );
    assert_eq!(surface.member_ids().expect("members"), vec![NEWCOMER]);
    assert_eq!(
        surface.remove_member(NEWCOMER).expect("revocation"),
        MemberChange::Removed
    );
    assert_eq!(surface.member_ids().expect("members"), Vec::<i64>::new());
}

/// BACK-COMPAT, AT THE BRIDGE. A single-tier roster — what a `bot.conf` with
/// only `allow=` composes — leaves its one operator able to do everything,
/// including manage members.
#[test]
fn a_single_tier_host_keeps_every_authority_it_had() {
    let fixture = Fixture::new(&[]);
    let client = FakeClient::new([updates(&[
        (1, OPERATOR, "/run summarize the board"),
        (2, OPERATOR, "/admin add 4440002"),
    ])]);
    let outbound = FakeOutbound::default();
    let lane = FakeRunLane::answering("the answer");
    let mut bridge = bridge_with_lane(
        &fixture,
        client,
        outbound.clone(),
        FakeSink::default(),
        lane.clone(),
    );

    assert_eq!(
        bridge.authority().tier_of(OPERATOR),
        Some(CommandTier::Admin),
        "with no admin= line, the allowed user is an administrator"
    );
    let report = poll(&mut bridge).expect("poll commits");
    assert_eq!(report.runs_answered, 1);
    assert_eq!(report.member_mutations, 1);
    assert_eq!(lane.tasks(), vec![String::from("summarize the board")]);
    assert_eq!(fixture.stored_members(), vec![NEWCOMER]);
}
