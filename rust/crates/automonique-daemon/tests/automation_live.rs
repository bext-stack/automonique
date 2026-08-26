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
//! # What fires, and what does not
//!
//! A registered, enabled automation fires: the daemon's scheduler worker
//! derives an occurrence at its instant, admits it through the scheduler core
//! and submits it on the durable synthetic lane under
//! `automation:<automation_id>:<instant>`, where the serve loop's controller
//! completes it with the lane's own outbox intent.
//! [`a_registered_interval_automation_fires_through_the_durable_run_lane`]
//! watches that happen over the socket and reads the delivery back out of the
//! product store afterwards; the restart tests shut the process down and
//! start another one against the same files. The deterministic half — every
//! step at the instant it is decided, under a fake clock — is
//! `automation_scheduler.rs`.
//!
//! What still does not happen: the occurrence's only effect is the synthetic
//! lane's fixture receipt. No provider runs the prompt, and these tests do
//! not pretend one does.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::automation_scheduler::OCCURRENCE_TRANSPORT;
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{
    AdminCommand, AdminRequest, AdminResponse, DaemonState, IntakePause, IntakeResume,
    OperationalMetric, RESERVED_SYNTHETIC_KEY_CATEGORY, SyntheticSubmission,
};
use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::{
    AutomationContinuation, AutomationCursor, AutomationId, AutomationListPage,
    AutomationOccurrenceKey, AutomationPageSize, AutomationPrompt, AutomationRecordView,
    AutomationRefusal, AutomationRequest, AutomationResponse, AutomationSchedule, AutomationScope,
    AutomationStateFilter, ListAutomations, PauseReason, RegisterAutomation, SetEnablement,
};
use automonique_protocol::codec::{
    Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId, decode_frame,
    encode_frame,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunStateFilter, RunsRequest, RunsResponse,
};
use automonique_protocol::wire::{JsonValue, Message};
use automonique_store::automation_store::AutomationStore;
use automonique_store::{InboxState, Store};

#[path = "support/isolation.rs"]
mod test_isolation;

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    test_isolation::assert_isolated_runtime_root(&runtime);
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

/// A job that will not fire during a test: one occurrence a minute.
fn quiet_job() -> (AutomationSchedule, AutomationScope, AutomationPrompt) {
    (
        AutomationSchedule::every(60_000).expect("interval"),
        AutomationScope::new("workspace:reports").expect("scope"),
        AutomationPrompt::new("summarize the night").expect("prompt"),
    )
}

/// Register one automation with a quiet job and return the revision and entry
/// it landed at.
fn register(config: &DaemonConfig, label: &str, automation_id: &str, actor: &str) -> (u64, u64) {
    let (schedule, scope, prompt) = quiet_job();
    let receipt = register_job(config, label, automation_id, actor, schedule, scope, prompt);
    (receipt.entry_id(), receipt.revision())
}

/// Register one automation with the given job and return its receipt.
fn register_job(
    config: &DaemonConfig,
    label: &str,
    automation_id: &str,
    actor: &str,
    schedule: AutomationSchedule,
    scope: AutomationScope,
    prompt: AutomationPrompt,
) -> automonique_protocol::automation_api::AutomationReceiptView {
    let answer = automation(
        config,
        &AutomationRequest::RegisterAutomation {
            request_id: request_id(label),
            registration: RegisterAutomation::new(
                id(automation_id),
                who(actor),
                schedule,
                scope,
                prompt,
            )
            .expect("a registration within its bounds"),
        },
    );
    let AutomationResponse::Accepted { receipt, .. } = answer else {
        panic!("expected an accepted registration, got {answer:?}")
    };
    assert_eq!(receipt.automation_id().as_str(), automation_id);
    assert_eq!(receipt.enablement(), EnablementState::Enabled);
    assert_eq!(receipt.revision(), 1, "registration writes revision one");
    assert!(receipt.updated_at().as_millis() > 0);
    receipt
}

/// The detail read's record and prompt, or a panic naming what came back.
fn detail_with_prompt(
    config: &DaemonConfig,
    label: &str,
    automation_id: &str,
) -> (AutomationRecordView, Option<AutomationPrompt>) {
    let answer = automation(
        config,
        &AutomationRequest::AutomationDetail {
            request_id: request_id(label),
            automation_id: id(automation_id),
        },
    );
    match answer {
        AutomationResponse::AutomationDetail { record, prompt, .. } => (record, prompt),
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Poll the detail read until the automation reports a firing, or fail.
///
/// Generous on purpose: the worker looks every quarter second and the lane
/// completes on the accept loop, so the bound here measures a loaded host
/// rather than the daemon.
fn wait_for_firing(config: &DaemonConfig, automation_id: &str) -> AutomationRecordView {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut polls = 0;
    loop {
        polls += 1;
        let record = detail(
            config,
            &format!("poll-{automation_id}-{polls}"),
            automation_id,
        );
        if record.last_fired_at().is_some() {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "{automation_id} never fired: {record:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Where the lane says one occurrence has got to, read from the product
/// store after the daemon that ran it has stopped.
fn lane_state(config: &DaemonConfig, automation_id: &str, at: EpochMillis) -> Option<InboxState> {
    let key = AutomationOccurrenceKey::derive(&id(automation_id), at).expect("key");
    Store::open(config.database_path())
        .expect("open the product store")
        .inbox_disposition(OCCURRENCE_TRANSPORT, key.as_str())
        .expect("read the lane")
        .map(|disposition| disposition.state)
}

fn outbox_count(config: &DaemonConfig) -> u64 {
    Store::open(config.database_path())
        .expect("open the product store")
        .outbox_count()
        .expect("count the outbox")
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
    // The job reads back whole, first due one interval after registration,
    // and not yet fired.
    assert_eq!(
        record.schedule().map(AutomationSchedule::render).as_deref(),
        Some("every@60000")
    );
    assert_eq!(
        record.scope().map(AutomationScope::as_str),
        Some("workspace:reports")
    );
    assert_eq!(
        record.next_fire_at(),
        Some(EpochMillis::from_millis(
            record.created_at().as_millis() + 60_000
        ))
    );
    assert_eq!(record.last_fired_at(), None);

    // The detail read answers the same row, and carries the prompt a listing
    // omits.
    let (detailed, prompt) = detail_with_prompt(&config, "detail-1", "nightly-report");
    assert_eq!(&detailed, record);
    assert_eq!(
        prompt.as_ref().map(AutomationPrompt::as_str),
        Some("summarize the night")
    );

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
        let (schedule, scope, prompt) = quiet_job();
        let answer = automation(
            &config,
            &AutomationRequest::RegisterAutomation {
                request_id: request_id(label),
                registration: RegisterAutomation::new(
                    id("nightly-report"),
                    who("dana"),
                    schedule,
                    scope,
                    prompt,
                )
                .expect("a registration within its bounds"),
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
    let (schedule, scope, prompt) = quiet_job();
    assert_eq!(
        automation(
            &config,
            &AutomationRequest::RegisterAutomation {
                request_id: request_id("re-register"),
                registration: RegisterAutomation::new(
                    id("nightly-report"),
                    who("dana"),
                    schedule,
                    scope,
                    prompt,
                )
                .expect("a registration within its bounds"),
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

/// An automation pause is not an intake pause.
///
/// The two are different switches: withdrawing one job from service closes
/// nothing else, and the daemon's own counters are exactly as they were,
/// because a job whose instant has not come neither started nor stopped
/// anything.
#[test]
fn an_automation_pause_is_not_an_intake_pause() {
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
    assert!(after.accepting_intake());
    assert_eq!(after.accepting_intake(), before.accepting_intake());
    serving.shutdown(&config);
}

// ---------------------------------------------------------------------------
// Firing
// ---------------------------------------------------------------------------

/// The whole path, over the socket and then out of the files: a fixed
/// interval registered through the control lane fires on the synthetic lane
/// under its derived key, and the daemon reports the firing.
#[test]
fn a_registered_interval_automation_fires_through_the_durable_run_lane() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let receipt = register_job(
        &config,
        "register-1",
        "heartbeat",
        "ben",
        AutomationSchedule::every(1_000).expect("interval"),
        AutomationScope::new("workspace:heartbeat").expect("scope"),
        AutomationPrompt::new("say hello\non two lines").expect("prompt"),
    );
    let first = EpochMillis::from_millis(receipt.updated_at().as_millis() + 1_000);

    let fired = wait_for_firing(&config, "heartbeat");
    assert_eq!(
        fired.last_fired_at(),
        Some(first),
        "the first firing is keyed by the first scheduled instant, not by when it was noticed"
    );
    let next = fired
        .next_fire_at()
        .expect("an interval always has a successor");
    assert!(next.as_millis() > first.as_millis());
    assert_eq!(
        (next.as_millis() - first.as_millis()) % 1_000,
        0,
        "the successor is on the grid"
    );
    assert_eq!(fired.enablement(), EnablementState::Enabled);
    assert_eq!(fired.revision(), 1, "firing is not a transition");

    // The synthetic lane's own outbox intent is the effect, and the daemon's
    // status counts it like any other run's.
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert!(
        status.outbox_pending() >= 1,
        "no outbox intent was committed"
    );
    serving.shutdown(&config);

    // Out of the files: the delivery under the derived key reached the lane's
    // terminal state, and no delivery exists under an instant the worker did
    // not derive.
    assert_eq!(
        lane_state(&config, "heartbeat", first),
        Some(InboxState::Completed)
    );
    assert_eq!(
        lane_state(
            &config,
            "heartbeat",
            EpochMillis::from_millis(first.as_millis() + 1)
        ),
        None
    );
    assert!(outbox_count(&config) >= 1);
}

/// A one-shot whose instant passes while no daemon is running fires exactly
/// once after restart, and never again.
#[test]
fn a_due_but_unfired_occurrence_fires_once_after_restart() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    let at = EpochMillis::from_millis(now + 3_000);
    register_job(
        &config,
        "register-1",
        "once",
        "ben",
        AutomationSchedule::once(at).expect("instant"),
        AutomationScope::new("workspace:once").expect("scope"),
        AutomationPrompt::new("fire once").expect("prompt"),
    );
    assert_eq!(
        detail(&config, "detail-before", "once").last_fired_at(),
        None
    );
    serving.shutdown(&config);
    assert_eq!(
        lane_state(&config, "once", at),
        None,
        "nothing fired before the instant"
    );

    // The instant passes with no daemon running.
    std::thread::sleep(Duration::from_millis(3_500));

    let serving = serve(&config);
    let fired = wait_for_firing(&config, "once");
    assert_eq!(fired.last_fired_at(), Some(at));
    assert_eq!(fired.next_fire_at(), None, "a fired one-shot is exhausted");
    // Give the worker every chance to fire it twice, which it must not.
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        detail(&config, "detail-after", "once").last_fired_at(),
        Some(at)
    );
    serving.shutdown(&config);
    assert_eq!(lane_state(&config, "once", at), Some(InboxState::Completed));
    assert_eq!(
        outbox_count(&config),
        1,
        "the one-shot fired more than once"
    );

    // A third generation derives nothing for it either.
    let serving = serve(&config);
    std::thread::sleep(Duration::from_millis(1_500));
    serving.shutdown(&config);
    assert_eq!(outbox_count(&config), 1);
}

/// A paused automation fires nothing, stays paused across a restart, and
/// fires again once resumed.
#[test]
fn a_paused_automation_fires_nothing_and_stays_paused_across_restart() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register_job(
        &config,
        "register-1",
        "held",
        "ben",
        AutomationSchedule::every(1_000).expect("interval"),
        AutomationScope::new("workspace:held").expect("scope"),
        AutomationPrompt::new("never while paused").expect("prompt"),
    );
    let answer = move_to(
        &config,
        "pause-1",
        "held",
        1,
        EnablementState::Paused,
        "ben",
        Some("provider outage"),
    );
    assert!(matches!(answer, AutomationResponse::Accepted { .. }));
    std::thread::sleep(Duration::from_millis(2_500));
    let paused = detail(&config, "detail-paused", "held");
    assert_eq!(paused.last_fired_at(), None, "a paused automation fired");
    assert_eq!(paused.enablement(), EnablementState::Paused);
    serving.shutdown(&config);
    assert_eq!(outbox_count(&config), 0);

    let serving = serve(&config);
    std::thread::sleep(Duration::from_millis(2_500));
    let still = detail(&config, "detail-still-paused", "held");
    assert_eq!(still.enablement(), EnablementState::Paused);
    assert_eq!(
        still.last_fired_at(),
        None,
        "a restart resumed a paused automation"
    );

    // Resumed, it fires: the oldest due instant once, then on from there.
    let answer = move_to(
        &config,
        "resume-1",
        "held",
        2,
        EnablementState::Enabled,
        "dana",
        None,
    );
    assert!(matches!(answer, AutomationResponse::Accepted { .. }));
    let fired = wait_for_firing(&config, "held");
    assert_eq!(fired.enablement(), EnablementState::Enabled);
    assert_eq!(fired.revision(), 3);
    serving.shutdown(&config);
    assert!(outbox_count(&config) >= 1);
}

/// A cron schedule is canonical and is refused by the protocol's own decoder
/// before the daemon sees it: the socket closes without an answer and nothing
/// is registered.
#[test]
fn a_cron_registration_is_refused_before_the_daemon() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let payload = br#"{"body":{"actor":"ben","automation_id":"nightly","prompt":"p","schedule":"cron@0 0 * * *@UTC@skip_missing_fire_first","scope":"ws"},"kind":"register_automation","protocol":"automonique.automation","request_id":"cron-1","version":1}"#;
    assert!(
        exchange(&config, payload).is_none(),
        "a cron registration was answered instead of refused before the daemon",
    );
    assert!(listed(&config, "list-after-cron").entries().is_empty());
    serving.shutdown(&config);
}

/// Send one fully formed admin request and decode its answer.
fn admin(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

/// An operator intake pause closes the run lane to automations exactly as it
/// closes it to `automonique submit`: the worker on its real thread derives
/// nothing while the pause stands, the due instant is neither consumed nor
/// duplicated, and it fires once — keyed by that oldest instant — after the
/// resume. The status meanwhile reports the worker alive on its thread.
#[test]
fn an_intake_pause_holds_a_due_occurrence_until_intake_resumes() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    let AdminResponse::IntakePaused { .. } = admin(
        &config,
        AdminRequest::pause_intake(
            request_id("pause-intake-1"),
            IntakePause::new("dana", "maintenance").expect("pause body"),
        ),
    ) else {
        panic!("the pause was not accepted")
    };
    let receipt = register_job(
        &config,
        "register-held",
        "held-by-intake",
        "ben",
        AutomationSchedule::every(1_000).expect("interval"),
        AutomationScope::new("workspace:held").expect("scope"),
        AutomationPrompt::new("wait for intake").expect("prompt"),
    );
    let first = EpochMillis::from_millis(receipt.updated_at().as_millis() + 1_000);

    // Well past the first instant, and past the second: nothing derived,
    // the instant still the first one, the worker still on its thread.
    std::thread::sleep(Duration::from_millis(2_500));
    let held = detail(&config, "detail-held", "held-by-intake");
    assert_eq!(
        held.last_fired_at(),
        None,
        "an occurrence fired under a pause"
    );
    assert_eq!(
        held.next_fire_at(),
        Some(first),
        "the due instant was consumed or advanced under a pause"
    );
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert!(status.intake_paused());
    assert!(!status.accepting_intake());
    assert_eq!(
        status.outbox_pending(),
        0,
        "an intent was committed under a pause"
    );
    assert_eq!(
        status
            .durable_state()
            .expect("durable counts")
            .automation_scheduler_workers(),
        OperationalMetric::Measured(1),
        "the worker is on its thread while it waits"
    );

    // Resumed: the oldest due instant fires once, and the successor is on
    // the grid after the firing tick.
    let AdminResponse::IntakeResumed { .. } = admin(
        &config,
        AdminRequest::resume_intake(
            request_id("resume-intake-1"),
            IntakeResume::new("dana").expect("resume body"),
        ),
    ) else {
        panic!("the resume was not accepted")
    };
    let fired = wait_for_firing(&config, "held-by-intake");
    assert_eq!(
        fired.last_fired_at(),
        Some(first),
        "the firing is keyed by the instant that was held, not by when intake reopened"
    );
    let next = fired.next_fire_at().expect("an interval has a successor");
    assert!(next.as_millis() > first.as_millis());
    assert_eq!((next.as_millis() - first.as_millis()) % 1_000, 0);
    serving.shutdown(&config);

    assert_eq!(
        lane_state(&config, "held-by-intake", first),
        Some(InboxState::Completed)
    );
    assert_eq!(
        lane_state(
            &config,
            "held-by-intake",
            EpochMillis::from_millis(first.as_millis() + 1_000)
        ),
        None,
        "the instant that passed under the pause was skipped, not fired late"
    );
}

/// The `automation:` idempotency-key namespace is the scheduler's: a manual
/// submission under it is refused by name and lands nowhere, so an operator's
/// task can never be absorbed as an occurrence's replay, nor an occurrence as
/// the task's. The CLI refuses the same key before it dials; this is the
/// daemon's own answer to a client that did not.
#[test]
fn a_manual_submission_under_the_occurrence_namespace_is_refused_by_name() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let answer = admin(
        &config,
        AdminRequest::submit(
            request_id("reserved-1"),
            SyntheticSubmission::new(
                "workspace:manual",
                "automation:nightly:1700000000000",
                "a task under the scheduler's namespace",
            )
            .expect("structurally valid"),
        ),
    );
    let AdminResponse::Refused { category, .. } = answer else {
        panic!("a reserved key was accepted: {answer:?}")
    };
    assert_eq!(category.as_str(), RESERVED_SYNTHETIC_KEY_CATEGORY);
    assert_eq!(category.as_str(), "idempotency_key_reserved");

    // The same key one byte outside the namespace is ordinary work.
    let answer = admin(
        &config,
        AdminRequest::submit(
            request_id("unreserved-1"),
            SyntheticSubmission::new(
                "workspace:manual",
                "automations:nightly:1700000000000",
                "a task under a name of the operator's own",
            )
            .expect("structurally valid"),
        ),
    );
    assert!(
        matches!(
            answer,
            AdminResponse::SyntheticAccepted {
                duplicate: false,
                ..
            }
        ),
        "an unreserved key was refused: {answer:?}"
    );
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    serving.shutdown(&config);
    let store = Store::open(config.database_path()).expect("open the product store");
    assert!(
        store
            .inbox_disposition(OCCURRENCE_TRANSPORT, "automation:nightly:1700000000000")
            .expect("read the lane")
            .is_none(),
        "the refused key reached the lane"
    );
    assert!(
        store
            .inbox_disposition(OCCURRENCE_TRANSPORT, "automations:nightly:1700000000000")
            .expect("read the lane")
            .is_some(),
        "the accepted key never reached the lane"
    );
    let _ = status;
}

/// A fixed interval below the registration floor is refused by the
/// protocol's own decoder before the daemon sees it, the way a cron
/// schedule is: the socket closes without an answer and nothing is
/// registered.
#[test]
fn a_sub_second_interval_is_refused_before_the_daemon() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let payload = br#"{"body":{"actor":"ben","automation_id":"too-fast","prompt":"p","schedule":"every@999","scope":"ws"},"kind":"register_automation","protocol":"automonique.automation","request_id":"floor-1","version":1}"#;
    assert!(
        exchange(&config, payload).is_none(),
        "a sub-second registration was answered instead of refused before the daemon",
    );
    let page = listed(&config, "list-after-floor");
    assert!(
        page.entries().is_empty(),
        "a sub-second registration landed: {page:?}"
    );
    serving.shutdown(&config);
}
