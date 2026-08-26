// SPDX-License-Identifier: Elastic-2.0

//! `/work` end to end, with no provider, no fleet and no network: a recorded
//! support ticket becomes a contained run, and that run's answer becomes the
//! ticket's stored draft.
//!
//! # The claim, and the proofs under it
//!
//! The claim is that an operator's `/work <ticket>` composes an instruction from
//! a ticket this host already recorded, puts it through the *same* lane a `/run`
//! goes through, and stores what comes back against the ticket while advancing
//! its lifecycle — and that nothing is sent to anybody.
//!
//! 1. [`an_unrecorded_reference_spends_no_run`],
//!    [`an_unconfigured_deployment_works_nothing`] and
//!    [`a_host_with_no_ticket_store_works_nothing`] are the gates. They are pure:
//!    they run everywhere, need no host capability, and start no workload.
//! 2. [`a_contained_work_stores_the_draft_it_ran_for`] is the one that closes the
//!    gap. It drives the **production** [`work_ticket`] over the **production**
//!    [`StoreControlSurface`] and the **production** [`SocketRunLane`] against a
//!    **serving daemon**, so the composition, the prompt slot, the admin socket,
//!    the execute lane, the broker, the containment, the read model, the answer
//!    read, the draft write and the lifecycle move are all the real ones.
//!
//! # Running the contained proof
//!
//! It needs the enforced host every execution proof needs: a delegated cgroup v2
//! domain, the Landlock and seccomp mechanisms, busybox, and the built entry
//! helper.
//!
//! ```sh
//! cd rust
//! cargo build -p automonique-runner --bin automonique-launch-enter
//! cargo test -p automonique-daemon --test ticket_work --no-run
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT=1 \
//!   "$(ls -t target/debug/deps/ticket_work-* | grep -v '\.d$' | head -1)" \
//!   --test-threads=1 --nocapture
//! ```
//!
//! The scope must wrap the **test binary** rather than `cargo test`: cgroup v2
//! forbids enabling `subtree_control` on a cgroup that holds member processes,
//! so wrapping cargo makes every request answer `containment_unavailable`.
//!
//! # Non-vacuity
//!
//! The contained workload copies its own prompt into its answer file, so the
//! stored draft *is* the instruction this daemon composed from this ticket. Two
//! tickets are worked in one test and each draft is asserted to carry its own
//! ticket's identifier and not the other's — a lane that read a fixed path, or a
//! composer that ignored the ticket, fails. Beside them, the second `/work` on
//! an answered ticket is asserted to spend no run at all and to leave the first
//! draft exactly where it was.
//!
//! # What none of this establishes
//!
//! **No provider runs, no fleet is called, and nothing is posted anywhere.** The
//! workload is busybox. The ticket is synthetic and is written into a temporary
//! store by this file. The draft is a row in that store: this build has no
//! surface that posts one to a support thread, and adding one is a later,
//! owner-gated wave.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::compose::{ANSWER_PLACEHOLDER, PROVIDER_CONFIG_NAME};
use automonique_daemon::execute::locate_launch_helper;
use automonique_daemon::run_lane::SocketRunLane;
use automonique_daemon::telegram_bridge::{
    HostFacts, RunFailure, StoreControlSurface, TICKET_NOT_FOUND, TICKETS_NOT_ENABLED, work_ticket,
};
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, ExecutionState};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_runner::ContainmentDomain;

#[path = "support/isolation.rs"]
mod test_isolation;
use automonique_store::support_tickets::{
    FleetTicket, SupportTicketStore, TicketLifecycle, TicketTransition,
};

const BUSYBOX: &str = "/usr/bin/busybox";
const REQUIRE_ENFORCED_ENV: &str = "AUTOMONIQUE_REQUIRE_ENFORCED_CONTAINMENT";
/// What a contained run's answer file is prefixed with, so a stored draft that
/// carries it cannot have come from anywhere but the workload.
const ANSWER_PREFIX: &str = "AUTOMONIQUE-DRAFT:";
/// The generation this fixture's surface reports. Nothing on the `/work` path
/// reads it — only `/status` does — so it is fixed here rather than negotiated.
const GENERATION: &str = "foreground";
const HOLDER: &str = "ticket-work-fixture-holder";
/// The instant every seeded ticket is observed at. Deliberately in the past, so
/// the host clock the draft is recorded under is always later.
const TICKET_OBSERVED_MS: i64 = 1_699_000_000_000;
const WORK_DEADLINE: Duration = Duration::from_secs(150);

// --- fixtures -------------------------------------------------------------

/// A private state tree with the daemon's directories, both policy files, a
/// generation, and a support ticket store this file seeds directly.
///
/// Nothing here polls a board. The connector is not involved, no credential
/// exists in this tree, and every ticket field below is invented for this file:
/// no identifier, tenant, site or requester names anything real.
struct Fixture {
    _root: tempfile::TempDir,
    config: DaemonConfig,
    facts: HostFacts,
}

impl Fixture {
    /// Build the tree. `provider` and `policy` are written only when given, so a
    /// test can prove what an unconfigured deployment does.
    fn new(provider: Option<&str>, policy: Option<&str>) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let runtime = root.path().join("runtime");
        test_isolation::assert_isolated_runtime_root(&runtime);
        let state = root.path().join("state");
        for directory in [&runtime, &state] {
            std::fs::create_dir(directory).expect("root");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let state_dir = state.join("automonique");
        std::fs::create_dir(&state_dir).expect("state directory");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        if let Some(body) = provider {
            write_private(&state_dir.join(PROVIDER_CONFIG_NAME), body);
        }
        if let Some(body) = policy {
            write_private(&state_dir.join("egress-destinations"), body);
        }
        Self {
            _root: root,
            // Facts a `/work` never reads. Only `/status` consults the
            // generation, and this fixture drives neither the bridge nor that
            // reply — so no lease is taken here, which matters: the serving
            // daemon takes the real one, and a fixture holding it first would
            // stop the daemon from opening at all.
            facts: HostFacts {
                generation_id: String::from(GENERATION),
                holder_id: String::from(HOLDER),
                lease_epoch: 1,
                bot_id: 123_456,
                execution_state: ExecutionState::SandboxUnavailableLaneWired,
            },
            config: DaemonConfig {
                runtime_root: runtime,
                state_root: state,
            },
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.config.state_dir()
    }

    /// The provider home every fixture grants, created so a grant on it can be
    /// enforced rather than refused for naming nothing.
    fn provider_home(&self) -> PathBuf {
        let home = self.state_dir().join("provider-home");
        if !home.exists() {
            std::fs::create_dir(&home).expect("provider home");
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("private provider home");
        }
        home
    }

    /// The production read-and-write surface, over this tree's own databases.
    fn surface(&self) -> StoreControlSurface {
        StoreControlSurface::open(
            &self.config.database_path(),
            &self.config.run_index_path(),
            self.facts.clone(),
        )
        .expect("read surface opens")
        .with_support_tickets(&self.config.support_tickets_path())
    }

    fn lane(&self) -> SocketRunLane {
        SocketRunLane::open(
            &self.state_dir(),
            &self.config.admin_socket(),
            &self.config.run_index_path(),
        )
        .expect("the run lane opens")
    }

    /// Record one synthetic ticket and walk it to `lifecycle`, one lattice step
    /// at a time, which is the only way this host is allowed to move one.
    fn seed_ticket(&self, fleet_issue_id: &str, title: &str, lifecycle: TicketLifecycle) {
        let mut store = SupportTicketStore::open(self.config.support_tickets_path())
            .expect("support ticket store opens");
        let receipt = store
            .record(&FleetTicket {
                fleet_issue_id,
                title,
                tenant_name: "reserved-tenant",
                site_label: Some("reserved-site.invalid"),
                fleet_status: "triaging",
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
        for step in TicketLifecycle::ALL
            .into_iter()
            .filter(|step| step.rank() > 0 && step.rank() <= lifecycle.rank())
        {
            revision = store
                .transition(TicketTransition {
                    fleet_issue_id,
                    expected_revision: revision,
                    lifecycle: step,
                    now_ms: TICKET_OBSERVED_MS,
                })
                .expect("lifecycle advances")
                .revision;
        }
    }

    /// This tree's ticket store, opened fresh so a read is a read of the file
    /// rather than of a handle the surface may still be holding.
    fn ticket_store(&self) -> SupportTicketStore {
        SupportTicketStore::open(self.config.support_tickets_path())
            .expect("support ticket store opens")
    }
}

fn write_private(path: &Path, body: &str) {
    std::fs::write(path, body).expect("configuration written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private configuration");
}

/// A provider configuration naming busybox and one invocation.
fn busybox_provider(home: &Path, argv: &[String]) -> String {
    let mut body = format!(
        "binary={BUSYBOX}\nhome={}\nversion=busybox-hermetic\n",
        home.display()
    );
    for argument in argv {
        body.push_str(&format!("arg={argument}\n"));
    }
    body
}

/// The invocation that copies this run's prompt into this run's answer file.
///
/// `cat` with no operand reads the workload's stdin, which is where the launch
/// delivers the prompt — so the stored draft is a function of the *instruction
/// this daemon composed*, and a `/work` that composed from the wrong ticket, or
/// from nothing, produces a draft that does not match.
fn echo_prompt_argv() -> Vec<String> {
    vec![
        String::from("sh"),
        String::from("-c"),
        format!(
            "{{ {BUSYBOX} printf '%s' '{ANSWER_PREFIX}'; {BUSYBOX} cat; }} > {ANSWER_PLACEHOLDER}"
        ),
    ]
}

/// A loopback listener nothing ever dials, so the destination policy names a
/// real port on this host rather than anywhere off it.
fn unused_loopback_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a loopback port");
    listener.local_addr().expect("bound").port()
}

/// A fixture whose provider is busybox running `argv`, with a destination policy
/// pointing at one unused loopback port.
fn contained_fixture(argv: &[String]) -> Fixture {
    let fixture = Fixture::new(
        None,
        Some(&format!("127.0.0.1 {} loopback\n", unused_loopback_port())),
    );
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home, argv),
    );
    fixture
}

// --- the serving daemon ---------------------------------------------------

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

fn serve(config: &DaemonConfig) -> Serving {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        let request = AdminRequest::new(
            RequestId::new("shutdown").expect("request ID"),
            AdminCommand::Shutdown,
        );
        let payload = request
            .to_message()
            .expect("encode request")
            .to_canonical_bytes();
        let response =
            AdminResponse::from_canonical_bytes(&exchange(config, &payload)).expect("response");
        assert!(matches!(response, AdminResponse::ShutdownAccepted { .. }));
        self.thread
            .take()
            .expect("running")
            .join()
            .expect("daemon thread")
            .expect("clean stop");
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            let _ = thread.join();
        }
    }
}

fn exchange(config: &DaemonConfig, payload: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .expect("response body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    payload.to_vec()
}

fn sandbox_enforceable() -> bool {
    automonique_daemon::execute::probe_host()
        .select_mode(&automonique_daemon::execute::ENFORCED_PROPERTIES)
        .is_ok()
}

fn first_failing_gate() -> Option<&'static str> {
    if !Path::new(BUSYBOX).exists() {
        return Some("no static busybox at /usr/bin/busybox");
    }
    if !sandbox_enforceable() {
        return Some("this host cannot enforce the composed sandbox");
    }
    if locate_launch_helper().is_none() {
        return Some("no launch entry helper beside this binary");
    }
    if ContainmentDomain::discover().is_err() {
        return Some("no delegated cgroup v2 domain");
    }
    None
}

fn not_proven(test: &str, reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ENFORCED_ENV).is_none(),
        "{test}: {REQUIRE_ENFORCED_ENV} is set but this host cannot prove it: {reason}"
    );
    eprintln!("[ticket_work] NOT PROVEN: {test}: {reason}");
}

// --- the pure gates -------------------------------------------------------

/// A reference this host has no ticket for is answered as such, and no run is
/// spent finding that out.
#[test]
fn an_unrecorded_reference_spends_no_run() {
    let fixture = Fixture::new(None, None);
    fixture.seed_ticket("SUP-1", "The only ticket here", TicketLifecycle::Working);
    let mut surface = fixture.surface();
    let mut lane = fixture.lane();

    let refusal = work_ticket(&mut surface, &mut lane, "SUP-absent").expect_err("no such ticket");
    assert_eq!(refusal, TICKET_NOT_FOUND);
    // The lane is unconfigured here, so a run that *was* attempted would have
    // answered "not configured" instead — which is how this assertion knows the
    // lookup refused first.
    assert!(
        !refusal.contains("Not configured"),
        "the lookup must refuse before the lane is asked: {refusal}"
    );
    let record = fixture
        .ticket_store()
        .ticket("SUP-1")
        .expect("read")
        .expect("present");
    assert_eq!(record.lifecycle, TicketLifecycle::Working);
    assert_eq!(record.draft_answer_bytes, None);
}

/// A deployment with no provider and no destination policy works nothing, in the
/// same word a `/run` is refused with, and stores nothing.
#[test]
fn an_unconfigured_deployment_works_nothing() {
    let fixture = Fixture::new(None, None);
    fixture.seed_ticket(
        "SUP-1",
        "A ticket on an unconfigured host",
        TicketLifecycle::New,
    );
    let mut surface = fixture.surface();
    let mut lane = fixture.lane();
    assert!(!lane.configured());

    let refusal = work_ticket(&mut surface, &mut lane, "SUP-1").expect_err("unconfigured");
    assert_eq!(refusal, RunFailure::NotConfigured.operator_reply());

    let record = fixture
        .ticket_store()
        .ticket("SUP-1")
        .expect("read")
        .expect("present");
    assert_eq!(
        record.lifecycle,
        TicketLifecycle::New,
        "a refused run must leave the ticket where it was"
    );
    assert_eq!(record.draft_answer_bytes, None);
    assert_eq!(record.revision, 1);
}

/// A host that tracks no tickets says so, and asking does not bring a store into
/// existence.
#[test]
fn a_host_with_no_ticket_store_works_nothing() {
    let fixture = Fixture::new(None, None);
    let mut surface = fixture.surface();
    let mut lane = fixture.lane();

    let refusal = work_ticket(&mut surface, &mut lane, "SUP-1").expect_err("no ticket store");
    assert_eq!(refusal, TICKETS_NOT_ENABLED);
    assert!(
        !fixture.config.support_tickets_path().exists(),
        "a read surface must not conjure a ticket store"
    );
}

// --- the contained proof --------------------------------------------------

/// THE WHOLE FEATURE, MINUS THE PROVIDER.
///
/// Two tickets are worked through the production surface and the production run
/// lane against a serving daemon. Each stored draft is the instruction *that*
/// ticket composed, carried out to a contained workload and back; each ticket
/// reaches `answered`; and a second `/work` on one of them is refused without
/// spending a run.
#[test]
fn a_contained_work_stores_the_draft_it_ran_for() {
    let test = "a_contained_work_stores_the_draft_it_ran_for";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }

    let fixture = contained_fixture(&echo_prompt_argv());
    fixture.seed_ticket(
        "SUP-1001",
        "Printer offline in the back room",
        TicketLifecycle::Working,
    );
    fixture.seed_ticket(
        "SUP-1002",
        "Mail relay rejects attachments",
        TicketLifecycle::New,
    );
    let serving = serve(&fixture.config);
    let mut surface = fixture.surface();
    let mut lane = fixture.lane();
    assert!(
        lane.configured(),
        "a fixture with a provider and a destination policy must be configured"
    );

    // TWO TICKETS, TWO DRAFTS, AND NEITHER IS THE OTHER'S.
    let first = with_deadline(&mut surface, &mut lane, "SUP-1001");
    let second = with_deadline(&mut surface, &mut lane, "SUP-1002");
    assert!(first.contains("Worked ticket SUP-1001"), "{first}");
    assert!(first.contains("lifecycle -> answered"), "{first}");
    assert!(second.contains("Worked ticket SUP-1002"), "{second}");
    // The confirmation is a confirmation: it carries no draft.
    for confirmation in [&first, &second] {
        assert!(
            !confirmation.contains(ANSWER_PREFIX),
            "a confirmation must not carry the draft: {confirmation}"
        );
        assert!(confirmation.contains("Nothing was sent to anyone."));
    }

    let store = fixture.ticket_store();
    let drafted = |fleet_issue_id: &str| {
        store
            .draft(fleet_issue_id)
            .expect("draft read")
            .expect("a draft was stored")
    };
    let one = drafted("SUP-1001");
    let two = drafted("SUP-1002");

    // THE DRAFT IS WHAT THE CONTAINED WORKLOAD WROTE, FROM THIS TICKET'S OWN
    // INSTRUCTION. The workload echoes its prompt, so a draft carrying the
    // prefix and this ticket's composed header cannot have come from anywhere
    // else.
    for (draft, ticket, subject, other) in [
        (
            &one,
            "SUP-1001",
            "Printer offline in the back room",
            "SUP-1002",
        ),
        (
            &two,
            "SUP-1002",
            "Mail relay rejects attachments",
            "SUP-1001",
        ),
    ] {
        assert!(draft.text.starts_with(ANSWER_PREFIX), "{}", draft.text);
        assert!(draft.text.contains(&format!("Ticket: {ticket}")));
        assert!(draft.text.contains(&format!("Subject: {subject}")));
        assert!(draft.text.contains("Draft a support answer"));
        assert!(
            !draft.text.contains(other),
            "each draft must come from its own ticket's instruction: {}",
            draft.text
        );
        assert_eq!(draft.lifecycle, TicketLifecycle::Answered);
        assert!(
            draft.recorded_at_ms > TICKET_OBSERVED_MS,
            "the draft instant is this host's clock, not the observation's"
        );
    }
    assert_ne!(
        one.text, two.text,
        "a lane reading a fixed path would answer both tickets the same"
    );

    // THE LIFECYCLE MOVED, ONCE, FOR EACH.
    for (fleet_issue_id, revisions_before) in [("SUP-1001", 3_u64), ("SUP-1002", 1_u64)] {
        let record = store
            .ticket(fleet_issue_id)
            .expect("read")
            .expect("present");
        assert_eq!(
            record.lifecycle,
            TicketLifecycle::Answered,
            "{fleet_issue_id}"
        );
        assert_eq!(
            record.revision,
            revisions_before + 1,
            "{fleet_issue_id}: one work is one revision"
        );
        assert_eq!(
            record.draft_answer_bytes,
            Some(drafted(fleet_issue_id).text.len())
        );
    }
    drop(store);

    // THE SECOND WORK IS REFUSED, AND THE FIRST DRAFT STANDS.
    let refusal = work_ticket(&mut surface, &mut lane, "SUP-1001").expect_err("already answered");
    assert!(
        refusal.contains("already been answered or closed"),
        "{refusal}"
    );
    let store = fixture.ticket_store();
    assert_eq!(
        store
            .draft("SUP-1001")
            .expect("read")
            .expect("present")
            .text,
        one.text,
        "a refused re-work must not overwrite the draft"
    );
    drop(store);

    // THE PROMPT SLOT DOES NOT OUTLIVE THE RUN.
    let prompts = fixture.state_dir().join("prompts");
    let remaining = std::fs::read_dir(&prompts)
        .map(|entries| entries.count())
        .unwrap_or_default();
    assert_eq!(
        remaining, 0,
        "operator content must not outlive the run that consumed it"
    );

    serving.shutdown(&fixture.config);
}

/// THE FALSIFICATION. A run that writes no answer stores no draft and does not
/// move the ticket.
///
/// Without this the test above would pass just as well against a `/work` that
/// marked a ticket answered whatever the run did.
#[test]
fn a_work_whose_run_writes_nothing_stores_no_draft() {
    let test = "a_work_whose_run_writes_nothing_stores_no_draft";
    if let Some(reason) = first_failing_gate() {
        not_proven(test, reason);
        return;
    }

    // A workload that touches its answer file and writes nothing into it. The
    // argv still names the answer file, so the configuration is admissible.
    let silent = vec![
        String::from("sh"),
        String::from("-c"),
        format!("{BUSYBOX} true > {ANSWER_PLACEHOLDER}"),
    ];
    let fixture = contained_fixture(&silent);
    fixture.seed_ticket(
        "SUP-2001",
        "A ticket whose run says nothing",
        TicketLifecycle::Working,
    );
    let serving = serve(&fixture.config);
    let mut surface = fixture.surface();
    let mut lane = fixture.lane();

    let refusal = work_ticket(&mut surface, &mut lane, "SUP-2001").expect_err("no answer");
    assert_eq!(
        refusal,
        RunFailure::NoAnswer.operator_reply(),
        "an empty answer file must not be stored as a draft"
    );

    let store = fixture.ticket_store();
    let record = store.ticket("SUP-2001").expect("read").expect("present");
    assert_eq!(
        record.lifecycle,
        TicketLifecycle::Working,
        "a run that wrote nothing must not mark a ticket answered"
    );
    assert_eq!(record.draft_answer_bytes, None);
    assert_eq!(store.draft("SUP-2001").expect("read"), None);
    drop(store);

    serving.shutdown(&fixture.config);
}

/// Work one ticket, failing the test rather than hanging if the lane does not
/// answer.
fn with_deadline(
    surface: &mut StoreControlSurface,
    lane: &mut SocketRunLane,
    ticket_ref: &str,
) -> String {
    let started = Instant::now();
    let confirmation = work_ticket(surface, lane, ticket_ref).expect("the work answers");
    assert!(
        started.elapsed() < WORK_DEADLINE,
        "a hermetic work must not take {WORK_DEADLINE:?}"
    );
    confirmation
}
