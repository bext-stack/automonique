// SPDX-License-Identifier: Elastic-2.0

//! The native Automation control surface, live over the real local socket.
//!
//! Nothing here is a unit test of the control types — `automonique-protocol`
//! owns those, and `automonique-store` owns the registry's own invariants. What
//! is proved here is the thing neither can prove alone: an operator decision
//! entered through the socket lands in a durable row, comes back through the
//! same socket unchanged, survives the process that recorded it, and is refused
//! in the operator's own vocabulary when the lattice says no.
//!
//! Every request is encoded by the protocol's own encoder and every answer is
//! decoded by its own decoder. A receipt this file assembled, or a page no
//! decoder admitted, would prove nothing.
//!
//! # What this surface still does not do
//!
//! Nothing here schedules or fires anything, and these tests do not pretend
//! otherwise: [`a_paused_automation_suppresses_nothing_because_nothing_runs`]
//! is the assertion that the daemon's other counters are untouched by a pause,
//! which is the honest shape of "a pause suppresses nothing today".

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, DaemonState};
use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::{
    AutomationContinuation, AutomationCursor, AutomationId, AutomationListPage, AutomationPageSize,
    AutomationRecordView, AutomationRefusal, AutomationRequest, AutomationResponse,
    AutomationStateFilter, ListAutomations, PauseReason, RegisterAutomation, SetEnablement,
};
use automonique_protocol::codec::{
    Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId, decode_frame,
    encode_frame,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunStateFilter, RunsRequest, RunsResponse,
};
use automonique_protocol::wire::{JsonValue, Message};
use automonique_store::automation_store::AutomationStore;

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

/// Send one canonical payload and read one back, or report that the daemon
/// closed the connection without answering.
///
/// Both outcomes are legitimate and they are different: a placed frame earns a
/// typed answer, and a frame no lane will place earns silence. Collapsing them
/// into a panic would make the second untestable, and the second is exactly
/// what a malformed control request must receive.
fn exchange(config: &DaemonConfig, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    if stream.read_exact(&mut prefix).is_err() {
        return None;
    }
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
    Some(payload.to_vec())
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let payload = AdminRequest::new(
        RequestId::new("automation-live-admin").expect("request ID"),
        command,
    )
    .to_message()
    .expect("encode request")
    .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

/// Ask the Automation lane one question over the same socket the other two use.
///
/// The answer must carry the request's own correlation identifier: an answer to
/// somebody else's question would otherwise pass every content assertion below.
fn automation(config: &DaemonConfig, request: &AutomationRequest) -> AutomationResponse {
    let payload = request
        .to_message()
        .expect("encode automation request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the automation lane answered");
    let response =
        AutomationResponse::from_canonical_bytes(&response).expect("admitted automation response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

fn id(value: &str) -> AutomationId {
    AutomationId::new(value).expect("automation identity")
}

fn who(value: &str) -> AutomationActor {
    AutomationActor::new(value).expect("actor")
}

fn why(value: &str) -> PauseReason {
    PauseReason::new(value).expect("cause")
}

fn request_id(label: &str) -> RequestId {
    RequestId::new(label).expect("request ID")
}

/// Register one automation and return the revision and entry it landed at.
fn register(config: &DaemonConfig, label: &str, automation_id: &str, actor: &str) -> (u64, u64) {
    let answer = automation(
        config,
        &AutomationRequest::RegisterAutomation {
            request_id: request_id(label),
            registration: RegisterAutomation::new(id(automation_id), who(actor)),
        },
    );
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted registration, got {answer:?}")
    };
    assert_eq!(receipt.automation_id().as_str(), automation_id);
    assert_eq!(receipt.enablement(), EnablementState::Enabled);
    assert_eq!(receipt.revision(), 1, "registration writes revision one");
    assert!(receipt.updated_at().as_millis() > 0);
    (receipt.entry_id(), receipt.revision())
}

/// Ask for one lattice move and return whatever the daemon answered.
fn move_to(
    config: &DaemonConfig,
    label: &str,
    automation_id: &str,
    expected_revision: u64,
    target: EnablementState,
    actor: &str,
    cause: Option<&str>,
) -> AutomationResponse {
    automation(
        config,
        &AutomationRequest::SetEnablement {
            request_id: request_id(label),
            transition: SetEnablement::new(
                id(automation_id),
                expected_revision,
                target,
                who(actor),
                cause.map(why),
            )
            .expect("a coupled transition"),
        },
    )
}

/// One automation in full, or a panic naming what came back instead.
fn detail(config: &DaemonConfig, label: &str, automation_id: &str) -> AutomationRecordView {
    let answer = automation(
        config,
        &AutomationRequest::AutomationDetail {
            request_id: request_id(label),
            automation_id: id(automation_id),
        },
    );
    match answer {
        AutomationResponse::AutomationDetail { record, .. } => record,
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Every automation the daemon lists, under no filter and the largest page.
fn listed(config: &DaemonConfig, label: &str) -> AutomationListPage {
    page_of(
        config,
        label,
        ListAutomations::new(
            AutomationStateFilter::any(),
            AutomationCursor::START,
            AutomationPageSize::MAX,
        ),
    )
}

fn page_of(config: &DaemonConfig, label: &str, query: ListAutomations) -> AutomationListPage {
    let answer = automation(
        config,
        &AutomationRequest::ListAutomations {
            request_id: request_id(label),
            query,
        },
    );
    match answer {
        AutomationResponse::AutomationList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

fn wait_for_socket(config: &DaemonConfig) {
    // Generous on purpose. Everything before the bind is disk-bound — several
    // SQLite databases opened `synchronous = FULL`, each fsyncing its own WAL —
    // so a short deadline here measures the test host under concurrent load
    // rather than the daemon.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

fn serve(config: &DaemonConfig) -> Serving {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        assert!(matches!(
            call(config, AdminCommand::Shutdown),
            AdminResponse::ShutdownAccepted { .. }
        ));
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

#[test]
fn a_registered_automation_is_listed_and_readable_in_full() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Before anything is registered the listing is empty and says so as a
    // complete page rather than as a refusal.
    let empty = listed(&config, "list-empty");
    assert!(empty.entries().is_empty());
    assert_eq!(empty.continuation(), AutomationContinuation::Complete);

    let (entry_id, revision) = register(&config, "register-1", "nightly-report", "ben");
    assert_eq!(revision, 1);

    let page = listed(&config, "list-one");
    assert_eq!(page.entries().len(), 1);
    assert_eq!(page.continuation(), AutomationContinuation::Complete);
    let record = &page.entries()[0];
    assert_eq!(record.automation_id().as_str(), "nightly-report");
    assert_eq!(record.entry_id(), entry_id);
    assert_eq!(record.revision(), 1);
    assert_eq!(record.enablement(), EnablementState::Enabled);
    assert_eq!(record.actor().as_str(), "ben");
    assert_eq!(record.cause(), None);
    assert!(record.admits_occurrence());
    // Registration is not a resume, so nobody is credited with one.
    assert_eq!(record.resumed_by(), None);
    assert!(record.created_at().as_millis() > 0);
    assert_eq!(record.created_at(), record.updated_at());

    // The detail read answers the same row.
    assert_eq!(&detail(&config, "detail-1", "nightly-report"), record);

    // An identity nobody registered is refused by name rather than answered
    // with an empty record.
    assert_eq!(
        automation(
            &config,
            &AutomationRequest::AutomationDetail {
                request_id: request_id("detail-missing"),
                automation_id: id("never-declared"),
            },
        ),
        AutomationResponse::Refused {
            request_id: request_id("detail-missing"),
            refusal: AutomationRefusal::UnknownAutomation,
        },
    );
    serving.shutdown(&config);
}

#[test]
fn a_second_registration_of_one_identity_is_refused_and_writes_nothing() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (entry_id, _) = register(&config, "register-1", "nightly-report", "ben");

    for label in ["register-again", "register-again-2"] {
        let answer = automation(
            &config,
            &AutomationRequest::RegisterAutomation {
                request_id: request_id(label),
                registration: RegisterAutomation::new(id("nightly-report"), who("dana")),
            },
        );
        assert_eq!(
            answer,
            AutomationResponse::Refused {
                request_id: request_id(label),
                refusal: AutomationRefusal::AlreadyRegistered,
            },
        );
    }

    // Nothing moved: the row still names its original registrant at revision
    // one, and there is still exactly one of it.
    let page = listed(&config, "list-after-duplicate");
    assert_eq!(page.entries().len(), 1);
    assert_eq!(page.entries()[0].entry_id(), entry_id);
    assert_eq!(page.entries()[0].actor().as_str(), "ben");
    assert_eq!(page.entries()[0].revision(), 1);
    serving.shutdown(&config);
}

#[test]
fn a_pause_names_who_and_why_and_a_resume_names_whoever_reopened_it() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");

    let answer = move_to(
        &config,
        "pause-1",
        "nightly-report",
        1,
        EnablementState::Paused,
        "ben",
        Some("provider outage"),
    );
    // A landed write answers `accepted`, not `completed`: the row is committed
    // and the decision it records has nowhere to take effect, because this
    // build has no scheduler to read it.
    assert_eq!(answer.outcome(), ActionOutcome::Accepted);
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted pause, got the answer above")
    };
    assert_eq!(receipt.enablement(), EnablementState::Paused);
    assert_eq!(receipt.revision(), 2, "a transition advances the revision");

    let paused = detail(&config, "detail-paused", "nightly-report");
    assert_eq!(paused.enablement(), EnablementState::Paused);
    assert_eq!(paused.revision(), 2);
    assert_eq!(paused.actor().as_str(), "ben");
    assert_eq!(
        paused.cause().map(PauseReason::as_str),
        Some("provider outage")
    );
    assert!(!paused.admits_occurrence());
    // A paused row is not a resumed one.
    assert_eq!(paused.resumed_by(), None);

    // The resume names a *different* actor. One flat `actor` column has to
    // carry both, and the row must credit the resume to whoever performed it
    // rather than to whoever paused it.
    let answer = move_to(
        &config,
        "resume-1",
        "nightly-report",
        2,
        EnablementState::Enabled,
        "dana",
        None,
    );
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted resume, got {answer:?}")
    };
    assert_eq!(receipt.enablement(), EnablementState::Enabled);
    assert_eq!(receipt.revision(), 3);

    let resumed = detail(&config, "detail-resumed", "nightly-report");
    assert_eq!(resumed.enablement(), EnablementState::Enabled);
    assert_eq!(resumed.actor().as_str(), "dana");
    assert_eq!(resumed.cause(), None, "a resume carries no cause");
    assert_eq!(
        resumed.resumed_by().map(AutomationActor::as_str),
        Some("dana"),
        "the resume was credited to the wrong actor",
    );
    assert!(resumed.admits_occurrence());
    // The registration instant is untouched by either move; only the update
    // instant advances.
    assert_eq!(resumed.created_at(), paused.created_at());
    assert!(resumed.updated_at().as_millis() >= paused.updated_at().as_millis());
    serving.shutdown(&config);
}

#[test]
fn archiving_is_terminal_and_leaving_it_is_refused_by_the_lattice() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");

    let answer = move_to(
        &config,
        "archive-1",
        "nightly-report",
        1,
        EnablementState::Archived,
        "ben",
        Some("superseded by the new report"),
    );
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted archive, got {answer:?}")
    };
    assert_eq!(receipt.enablement(), EnablementState::Archived);
    assert_eq!(receipt.revision(), 2);

    // Every way out of `archived` is refused, including archiving it again.
    for (label, target, cause) in [
        ("leave-enabled", EnablementState::Enabled, None),
        (
            "leave-paused",
            EnablementState::Paused,
            Some("changed my mind"),
        ),
        ("leave-archived", EnablementState::Archived, Some("again")),
    ] {
        let answer = move_to(&config, label, "nightly-report", 2, target, "dana", cause);
        assert_eq!(
            answer,
            AutomationResponse::Refused {
                request_id: request_id(label),
                refusal: AutomationRefusal::IllegalTransition,
            },
            "{label} was not refused by the lattice",
        );
    }

    // And the row is exactly where the archive left it: a refused transition
    // wrote nothing, not even the actor who attempted it.
    let record = detail(&config, "detail-archived", "nightly-report");
    assert_eq!(record.enablement(), EnablementState::Archived);
    assert_eq!(
        record.revision(),
        2,
        "a refused transition advanced a revision"
    );
    assert_eq!(record.actor().as_str(), "ben");
    assert_eq!(
        record.cause().map(PauseReason::as_str),
        Some("superseded by the new report"),
    );

    // A re-registration is not a way out either: it is refused, and the row
    // stays archived rather than resetting to enabled.
    assert_eq!(
        automation(
            &config,
            &AutomationRequest::RegisterAutomation {
                request_id: request_id("re-register"),
                registration: RegisterAutomation::new(id("nightly-report"), who("dana")),
            },
        ),
        AutomationResponse::Refused {
            request_id: request_id("re-register"),
            refusal: AutomationRefusal::AlreadyRegistered,
        },
    );
    assert_eq!(
        detail(&config, "detail-still-archived", "nightly-report").enablement(),
        EnablementState::Archived,
    );
    serving.shutdown(&config);
}

#[test]
fn a_state_that_does_not_follow_the_durable_one_is_refused() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");

    // `enabled -> enabled` would credit a resume to somebody who resumed
    // nothing, and is refused rather than absorbed.
    assert_eq!(
        move_to(
            &config,
            "enable-enabled",
            "nightly-report",
            1,
            EnablementState::Enabled,
            "dana",
            None,
        ),
        AutomationResponse::Refused {
            request_id: request_id("enable-enabled"),
            refusal: AutomationRefusal::IllegalTransition,
        },
    );

    move_to(
        &config,
        "pause-1",
        "nightly-report",
        1,
        EnablementState::Paused,
        "ben",
        Some("outage"),
    );

    // `paused -> paused` would overwrite the cause of the pause an operator
    // still has to resume from.
    assert_eq!(
        move_to(
            &config,
            "pause-paused",
            "nightly-report",
            2,
            EnablementState::Paused,
            "dana",
            Some("a different reason"),
        ),
        AutomationResponse::Refused {
            request_id: request_id("pause-paused"),
            refusal: AutomationRefusal::IllegalTransition,
        },
    );
    let record = detail(&config, "detail-after", "nightly-report");
    assert_eq!(record.cause().map(PauseReason::as_str), Some("outage"));
    assert_eq!(record.actor().as_str(), "ben");
    serving.shutdown(&config);
}

#[test]
fn a_stale_expected_revision_is_a_conflict_and_never_an_overwrite() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");
    move_to(
        &config,
        "pause-1",
        "nightly-report",
        1,
        EnablementState::Paused,
        "ben",
        Some("outage"),
    );

    // The row is at revision two. A caller still holding revision one gets a
    // conflict carrying the durable revision, not a rejection and not a write.
    let answer = move_to(
        &config,
        "stale-resume",
        "nightly-report",
        1,
        EnablementState::Enabled,
        "dana",
        None,
    );
    assert_eq!(
        answer,
        AutomationResponse::Conflict {
            request_id: request_id("stale-resume"),
            expected_revision: 1,
            durable_revision: 2,
        },
    );
    // A conflict is its own outcome. Reporting it as a rejection would tell a
    // client the request was malformed, and it was not.
    assert_eq!(answer.outcome(), ActionOutcome::Conflict);

    // A revision from the future is a conflict too, in the same shape.
    let answer = move_to(
        &config,
        "future-resume",
        "nightly-report",
        9,
        EnablementState::Enabled,
        "dana",
        None,
    );
    assert_eq!(
        answer,
        AutomationResponse::Conflict {
            request_id: request_id("future-resume"),
            expected_revision: 9,
            durable_revision: 2,
        },
    );

    // Nothing moved.
    let record = detail(&config, "detail-after-conflicts", "nightly-report");
    assert_eq!(record.enablement(), EnablementState::Paused);
    assert_eq!(record.revision(), 2);
    assert_eq!(record.actor().as_str(), "ben");

    // And the revision the conflict named is the one that works.
    let answer = move_to(
        &config,
        "correct-resume",
        "nightly-report",
        2,
        EnablementState::Enabled,
        "dana",
        None,
    );
    assert!(matches!(answer, AutomationResponse::Accepted { .. }));
    serving.shutdown(&config);
}

#[test]
fn an_unregistered_automation_cannot_be_moved() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    assert_eq!(
        move_to(
            &config,
            "pause-absent",
            "never-declared",
            1,
            EnablementState::Paused,
            "ben",
            Some("outage"),
        ),
        AutomationResponse::Refused {
            request_id: request_id("pause-absent"),
            refusal: AutomationRefusal::UnknownAutomation,
        },
    );
    assert!(listed(&config, "list-after-absent").entries().is_empty());
    serving.shutdown(&config);
}

/// A request whose cause and state disagree never reaches the daemon at all.
///
/// The protocol's own decoder refuses it, so the socket closes without an
/// answer and no durable state is touched. That silence is the assertion: an
/// *answered* causeless pause would mean the coupling had been dropped from the
/// decoder and was being decided somewhere further in.
#[test]
fn an_incoherent_cause_and_state_pairing_is_refused_before_the_daemon() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");

    for (label, body) in [
        (
            "causeless pause",
            br#"{"actor":"ben","automation_id":"nightly-report","cause":null,"expected_revision":1,"target":"paused"}"#.as_slice(),
        ),
        (
            "causeless archive",
            br#"{"actor":"ben","automation_id":"nightly-report","cause":null,"expected_revision":1,"target":"archived"}"#.as_slice(),
        ),
        (
            "resume that states a cause",
            br#"{"actor":"ben","automation_id":"nightly-report","cause":"why","expected_revision":1,"target":"enabled"}"#.as_slice(),
        ),
    ] {
        let payload = [
            br#"{"body":"#.as_slice(),
            body,
            br#","kind":"set_enablement","protocol":"automonique.automation","request_id":"hand-rolled","version":1}"#.as_slice(),
        ]
        .concat();
        assert!(
            exchange(&config, &payload).is_none(),
            "{label} was answered instead of refused before the daemon",
        );
    }

    // Nothing moved, so the refusals above cost no durable state.
    let record = detail(&config, "detail-untouched", "nightly-report");
    assert_eq!(record.enablement(), EnablementState::Enabled);
    assert_eq!(record.revision(), 1);
    serving.shutdown(&config);
}

#[test]
fn a_listing_pages_and_filters_over_the_durable_registry() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    for (label, automation_id) in [
        ("register-1", "alpha"),
        ("register-2", "beta"),
        ("register-3", "gamma"),
    ] {
        register(&config, label, automation_id, "ben");
    }

    // Two at a time, over three rows.
    let two = AutomationPageSize::new(2).expect("page size");
    let head = page_of(
        &config,
        "page-head",
        ListAutomations::new(AutomationStateFilter::any(), AutomationCursor::START, two),
    );
    assert_eq!(head.entries().len(), 2);
    assert_eq!(head.entries()[0].automation_id().as_str(), "alpha");
    assert_eq!(head.entries()[1].automation_id().as_str(), "beta");
    let AutomationContinuation::More(cursor) = head.continuation() else {
        panic!("a page that left a row behind reported itself complete")
    };
    assert_eq!(
        cursor.position(),
        head.entries()[1].entry_id(),
        "the cursor is the last entry served, resumed after",
    );

    let tail = page_of(
        &config,
        "page-tail",
        ListAutomations::new(AutomationStateFilter::any(), cursor, two),
    );
    assert_eq!(
        tail.entries().len(),
        1,
        "the tail repeated or dropped a row"
    );
    assert_eq!(tail.entries()[0].automation_id().as_str(), "gamma");
    assert_eq!(tail.continuation(), AutomationContinuation::Complete);

    // A cursor at the last recorded entry is caught up: a complete empty page.
    let caught_up = page_of(
        &config,
        "page-caught-up",
        ListAutomations::new(
            AutomationStateFilter::any(),
            AutomationCursor::new(tail.entries()[0].entry_id()),
            two,
        ),
    );
    assert!(caught_up.entries().is_empty());
    assert_eq!(caught_up.continuation(), AutomationContinuation::Complete);

    // Pause exactly one of them, then ask for what is paused.
    move_to(
        &config,
        "pause-beta",
        "beta",
        1,
        EnablementState::Paused,
        "dana",
        Some("flaky provider"),
    );
    let paused = page_of(
        &config,
        "page-paused",
        ListAutomations::new(
            AutomationStateFilter::only([EnablementState::Paused]).expect("filter"),
            AutomationCursor::START,
            AutomationPageSize::MAX,
        ),
    );
    assert_eq!(
        paused.entries().len(),
        1,
        "the filter selected the wrong set"
    );
    assert_eq!(paused.entries()[0].automation_id().as_str(), "beta");
    assert_eq!(
        paused.entries()[0].cause().map(PauseReason::as_str),
        Some("flaky provider"),
    );

    // And the complement, so the filter is selecting rather than truncating.
    let enabled = page_of(
        &config,
        "page-enabled",
        ListAutomations::new(
            AutomationStateFilter::only([EnablementState::Enabled]).expect("filter"),
            AutomationCursor::START,
            AutomationPageSize::MAX,
        ),
    );
    assert_eq!(
        enabled
            .entries()
            .iter()
            .map(|record| record.automation_id().as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "gamma"],
    );
    assert_eq!(listed(&config, "list-all").entries().len(), 3);

    // A cursor above everything recorded is a refusal rather than an empty
    // page, exactly as the store decides it: "your cursor names a row that was
    // never written" and "there is nothing to show" are different answers.
    let answer = automation(
        &config,
        &AutomationRequest::ListAutomations {
            request_id: request_id("page-out-of-range"),
            query: ListAutomations::new(
                AutomationStateFilter::any(),
                AutomationCursor::new(4_096),
                two,
            ),
        },
    );
    assert_eq!(
        answer,
        AutomationResponse::Refused {
            request_id: request_id("page-out-of-range"),
            refusal: AutomationRefusal::CursorOutOfRange,
        },
    );
    serving.shutdown(&config);
}

#[test]
fn an_empty_registry_refuses_a_cursor_it_never_wrote() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    // Position zero is where a listing begins and is always legal.
    assert!(listed(&config, "list-empty").entries().is_empty());
    // Anything above it names a row nothing ever wrote.
    let answer = automation(
        &config,
        &AutomationRequest::ListAutomations {
            request_id: request_id("empty-cursor"),
            query: ListAutomations::new(
                AutomationStateFilter::any(),
                AutomationCursor::new(1),
                AutomationPageSize::MAX,
            ),
        },
    );
    assert_eq!(
        answer,
        AutomationResponse::Refused {
            request_id: request_id("empty-cursor"),
            refusal: AutomationRefusal::CursorOutOfRange,
        },
    );
    serving.shutdown(&config);
}

#[test]
fn operator_decisions_survive_the_process_that_recorded_them() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "alpha", "ben");
    register(&config, "register-2", "beta", "ben");
    move_to(
        &config,
        "pause-beta",
        "beta",
        1,
        EnablementState::Paused,
        "dana",
        Some("provider outage"),
    );
    serving.shutdown(&config);

    // A new generation opens the same registry file and answers from it.
    // Nothing was rebuilt in memory: the process that took these decisions is
    // gone.
    let serving = serve(&config);
    let page = listed(&config, "list-after-restart");
    assert_eq!(page.entries().len(), 2);
    assert_eq!(page.entries()[0].automation_id().as_str(), "alpha");
    assert_eq!(page.entries()[0].enablement(), EnablementState::Enabled);
    let beta = &page.entries()[1];
    assert_eq!(beta.automation_id().as_str(), "beta");
    assert_eq!(beta.enablement(), EnablementState::Paused);
    assert_eq!(beta.revision(), 2);
    assert_eq!(beta.actor().as_str(), "dana");
    assert_eq!(
        beta.cause().map(PauseReason::as_str),
        Some("provider outage"),
    );

    // The pause is still resumable from the revision it survived at, which is
    // the whole point of writing it down.
    let answer = move_to(
        &config,
        "resume-after-restart",
        "beta",
        2,
        EnablementState::Enabled,
        "ben",
        None,
    );
    assert!(matches!(answer, AutomationResponse::Accepted { .. }));
    assert_eq!(
        detail(&config, "detail-after-restart", "beta")
            .resumed_by()
            .map(AutomationActor::as_str),
        Some("ben"),
    );

    // A third automation registered after the restart continues the same order,
    // so the registry resumed rather than restarted.
    register(&config, "register-3", "gamma", "ben");
    let page = listed(&config, "list-after-third");
    assert_eq!(page.entries().len(), 3);
    assert_eq!(page.entries()[2].automation_id().as_str(), "gamma");
    assert!(page.entries()[0].entry_id() < page.entries()[2].entry_id());
    serving.shutdown(&config);

    // And the durable file itself holds three rows, so the page above is not a
    // listing that merely happened to deduplicate.
    let registry = AutomationStore::open(config.automation_registry_path()).expect("open registry");
    assert_eq!(registry.automation_count().expect("count"), 3);
    assert_eq!(
        registry
            .entry("beta")
            .expect("read")
            .expect("beta is registered")
            .enablement,
        automonique_store::automation_store::EnablementState::Enabled,
    );
}

#[test]
fn one_socket_places_each_frame_by_the_protocol_it_declares() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(&config, "register-1", "nightly-report", "ben");

    // A frame naming a protocol this socket does not serve is placed by
    // nobody. It earns no answer at all — not an admin refusal, which would
    // mean the admin lane had read a body it does not own.
    let stranger = Message::new(
        Envelope::new(
            ProtocolName::new("automonique.stranger").expect("protocol name"),
            MajorVersion::new(1).expect("version"),
            RequestId::new("stranger-1").expect("request ID"),
            MessageKind::new("list_automations").expect("kind"),
        ),
        JsonValue::Object(Vec::new()),
    )
    .to_canonical_bytes();
    assert!(
        exchange(&config, &stranger).is_none(),
        "an unplaceable frame was answered",
    );

    // An automation kind spelled inside an *admin* envelope is refused by the
    // admin lane, which owns that envelope's kind set. The three lanes do not
    // fall through to one another.
    for protocol in ["automonique.admin", "automonique.runs"] {
        let misplaced = Message::new(
            Envelope::new(
                ProtocolName::new(protocol).expect("protocol name"),
                MajorVersion::new(1).expect("version"),
                RequestId::new("misplaced-1").expect("request ID"),
                MessageKind::new("register_automation").expect("kind"),
            ),
            JsonValue::Object(Vec::new()),
        )
        .to_canonical_bytes();
        assert!(
            exchange(&config, &misplaced).is_none(),
            "a {protocol} frame naming an automation kind was answered",
        );
    }

    // All three lanes still work, interleaved, on the same live daemon.
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    let runs = RunsRequest::ListRuns {
        request_id: RequestId::new("runs-mixed").expect("request ID"),
        query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
    };
    let payload = runs
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(&config, &payload).expect("the runs lane answered");
    assert!(matches!(
        RunsResponse::from_canonical_bytes(&response).expect("admitted runs response"),
        RunsResponse::RunList { .. }
    ));
    assert_eq!(listed(&config, "list-mixed").entries().len(), 1);
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    serving.shutdown(&config);
}

/// A pause is a durable record and not a suppression.
///
/// There is nothing running to suppress in this build, and this is the honest
/// shape of that claim: the daemon's own counters are exactly as they were
/// before the pause, because pausing an automation neither started nor stopped
/// anything.
#[test]
fn a_paused_automation_suppresses_nothing_because_nothing_runs() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let AdminResponse::Status { status: before, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };

    register(&config, "register-1", "nightly-report", "ben");
    move_to(
        &config,
        "pause-1",
        "nightly-report",
        1,
        EnablementState::Paused,
        "ben",
        Some("provider outage"),
    );

    let AdminResponse::Status { status: after, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(after.state(), DaemonState::Ready);
    assert_eq!(after.state(), before.state());
    assert_eq!(after.running(), 0);
    assert_eq!(after.running(), before.running());
    assert_eq!(after.inbox_pending(), before.inbox_pending());
    assert_eq!(after.outbox_pending(), before.outbox_pending());
    // Most pointedly: an automation pause is not an intake pause. Intake is
    // still open, because these are different switches and this one does not
    // pretend to be the other.
    assert!(after.accepting_intake());
    assert_eq!(after.accepting_intake(), before.accepting_intake());
    serving.shutdown(&config);
}
