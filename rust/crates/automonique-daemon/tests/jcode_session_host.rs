// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use automonique_agents::{JcodeInputRequestMode, JcodeProtocolError};
use automonique_daemon::execute::locate_launch_helper;
use automonique_daemon::jcode_session_host::{JcodeHostError, JcodeSessionHost, JcodeTurnOutcome};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    ContainmentDomain, ContainmentLimits, LaunchPlan, RunContainment, SocketGrant,
};
use automonique_store::provider_journal::{
    ApprovalDecision, BindingKind, BindingRecord, ProcessExit, ProcessSpawn, ProcessState,
    ProcessTermination, ProviderJournal, ProviderJournalError, ReplayVersions, RequestState,
    SessionClosing, SessionClosure, SessionOpening, SessionState, TurnState,
};
use sha2::{Digest as _, Sha256};

#[path = "support/isolation.rs"]
mod test_isolation;

const BUSYBOX: &str = "/usr/bin/busybox";

/// The exact `hello_ok` capability list of the maintained fork build.
const MAINTAINED_CAPABILITIES: &str = concat!(
    "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
    "\"stdin_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",",
    "\"persisted_session_discovery\",\"runtime_info\",\"api_key_provisioning\",",
    "\"session_archive\",\"session_retention\",\"session_files\"]"
);

/// The advertisement of pinned builds that predate the maintained harness
/// exposing stdin requests.
const LEGACY_CAPABILITIES: &str = concat!(
    "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
    "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]"
);

/// A build advertising neither input-request capability.
const UNSUPPORTED_CAPABILITIES: &str = concat!(
    "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
    "\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]"
);

/// A busybox engine that answers hello with `capabilities`, attaches
/// `session_id`, completes one text turn, then idles until EOF.
fn one_turn_engine(server: &str, capabilities: &str, session: &str, text: &str) -> String {
    format!(
        "IFS= read -r request; printf '%s\\n' '\
         {{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"{server}\",{capabilities}}}'; \
         IFS= read -r request; printf '%s\\n' '\
         {{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{{\"session_id\":\"{session}\",\"status\":\"idle\"}}}}'; \
         IFS= read -r request; printf '%s\\n' \
         '{{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"{session}\"}}' \
         '{{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"{session}\",\"text\":\"{text}\"}}' \
         '{{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"{session}\"}}'; \
         while IFS= read -r request; do :; done"
    )
}

fn busybox_plan(script: &str) -> LaunchPlan {
    LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap()
}

fn wait_for_pause_or_terminal(
    host: &mut JcodeSessionHost,
    mut outcome: JcodeTurnOutcome,
    now_ms: i64,
) -> JcodeTurnOutcome {
    while outcome == JcodeTurnOutcome::Pending {
        outcome = host
            .poll_turn(now_ms, Duration::from_secs(5))
            .expect("fixture event");
    }
    outcome
}

fn busybox_sha256() -> String {
    format!("{:x}", Sha256::digest(fs::read(BUSYBOX).unwrap()))
}

fn file_sha256(path: &std::path::Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

#[test]
fn installed_jcode_negotiates_inside_the_production_sandbox_when_configured() {
    let (Some(helper), Ok(domain)) = (locate_launch_helper(), ContainmentDomain::discover()) else {
        eprintln!("[jcode_session_host] NOT PROVEN: helper or delegated cgroup unavailable");
        return;
    };
    let (Some(binary), Some(home), Some(server)) = (
        std::env::var_os("AUTOMONIQUE_TEST_JCODE_BINARY").map(std::path::PathBuf::from),
        std::env::var_os("AUTOMONIQUE_TEST_JCODE_HOME").map(std::path::PathBuf::from),
        std::env::var("AUTOMONIQUE_TEST_JCODE_SERVER").ok(),
    ) else {
        eprintln!("[jcode_session_host] NOT PROVEN: real JCode test inputs not configured");
        return;
    };
    assert!(binary.is_absolute() && binary.is_file());
    assert!(home.is_absolute() && home.is_dir());

    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
    test_isolation::assert_isolated_runtime_root(&runtime);
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-real-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let plan = LaunchPlan::new(&binary, file_sha256(&binary))
        .unwrap()
        .argument("--quiet")
        .unwrap()
        .argument("--no-update")
        .unwrap()
        .argument("--no-selfdev")
        .unwrap()
        .argument("api-stdio")
        .unwrap()
        .environment("JCODE_HOME", home.as_os_str().as_encoded_bytes())
        .unwrap()
        .environment("JCODE_RUNTIME_DIR", runtime.as_os_str().as_encoded_bytes())
        .unwrap()
        .environment("JCODE_NO_TELEMETRY", b"1")
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, &binary)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, &home)
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, root.path())
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, "/usr/lib")
        .unwrap()
        .filesystem_grant(PathIntent::ReadWrite, "/dev/null")
        .unwrap()
        .socket_grant(SocketGrant::Unix)
        .unwrap()
        .socket_grant(SocketGrant::UnixSeqPacket)
        .unwrap();
    let host = JcodeSessionHost::spawn(
        &helper,
        &plan,
        containment,
        &root.path().join("provider-journal.sqlite3"),
        "real-jcode-probe",
        root.path(),
        None,
        None,
        &server,
        100,
        Duration::from_secs(30),
        None,
    )
    .expect("installed JCode negotiates inside enforced containment");
    assert!(!host.provider_session_id().is_empty());
    let negotiated = host.input_request_mode();
    eprintln!(
        "[jcode_session_host] PROVEN: {server} negotiated input-request capability {}",
        negotiated.capability()
    );
    if let Ok(expected) = std::env::var("AUTOMONIQUE_TEST_JCODE_INPUT_CAPABILITY") {
        assert_eq!(
            negotiated.capability(),
            expected,
            "the configured build advertised a different input-request capability"
        );
    }
    host.close(200).expect("installed JCode closes cleanly");
}

#[test]
fn contained_jcode_session_negotiates_input_resumes_and_journals() {
    let (Some(helper), Ok(domain)) = (locate_launch_helper(), ContainmentDomain::discover()) else {
        eprintln!("[jcode_session_host] NOT PROVEN: helper or delegated cgroup unavailable");
        return;
    };
    if !std::path::Path::new(BUSYBOX).is_file() {
        eprintln!("[jcode_session_host] NOT PROVEN: static busybox unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = root.path().join("provider-journal.sqlite3");
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-host-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"stdin_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",",
        "\"persisted_session_discovery\",\"runtime_info\",\"api_key_provisioning\",",
        "\"session_archive\",\"session_retention\",\"session_files\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-session-1\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-session-1\"}' ",
        "'{\"v\":1,\"ev\":\"stdin_request\",\"session_id\":\"jcode-session-1\",\"request_id\":\"stdin-1\",\"prompt\":\"fixture input\",\"is_password\":false,\"tool_call_id\":\"tool-input-1\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":4,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-session-1\",\"text\":\"done\"}' ",
        "'{\"v\":1,\"ev\":\"token_usage\",\"session_id\":\"jcode-session-1\",\"input\":5,\"output\":1,\"cache_read_input\":2}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-session-1\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-session-1\"}' ",
        "'{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-session-1\",\"text\":\"again\"}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-session-1\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-session-1\"}' ",
        "'{\"v\":1,\"ev\":\"tool_start\",\"session_id\":\"jcode-session-1\",\"call_id\":\"tool-1\",\"name\":\"read\"}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"reply_to\":7,\"ev\":\"ok\"}' ",
        "'{\"v\":1,\"ev\":\"turn_done\",\"session_id\":\"jcode-session-1\"}'; ",
        "while IFS= read -r request; do :; done"
    );
    let plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    let mut host = JcodeSessionHost::spawn(
        &helper,
        &plan,
        containment,
        &journal_path,
        "logical-session-1",
        root.path(),
        None,
        Some("fixture-model"),
        "jcode/fixture",
        100,
        Duration::from_secs(5),
        None,
    )
    .expect("host starts");
    let pid = host.operating_system_process_id();
    assert_eq!(host.provider_session_id(), "jcode-session-1");
    assert_eq!(
        host.input_request_mode(),
        JcodeInputRequestMode::StdinRequests
    );

    let first = host
        .begin_turn("turn-1", "first", 200, Duration::from_secs(5))
        .expect("turn starts");
    let input = match wait_for_pause_or_terminal(&mut host, first, 200) {
        JcodeTurnOutcome::InputRequired(input) => input,
        JcodeTurnOutcome::Pending => panic!("fixture event stream paused"),
        JcodeTurnOutcome::Completed(_) => panic!("input was skipped"),
        JcodeTurnOutcome::ApprovalRequired(_) => panic!("unexpected legacy approval"),
        JcodeTurnOutcome::Cancelled => panic!("turn was cancelled"),
        JcodeTurnOutcome::InterruptedUnknown(_) => panic!("turn was interrupted"),
    };
    assert_eq!(input.request_id(), "stdin-1");
    assert_eq!(input.prompt(), "fixture input");
    let decided = host
        .respond_stdin(
            input.request_id(),
            "fixture response",
            "operator",
            300,
            Duration::from_secs(5),
        )
        .expect("approval decision is sent");
    let result = match wait_for_pause_or_terminal(&mut host, decided, 300) {
        JcodeTurnOutcome::Completed(result) => result,
        JcodeTurnOutcome::Pending => panic!("fixture event stream paused"),
        JcodeTurnOutcome::ApprovalRequired(_) => panic!("unexpected second approval"),
        JcodeTurnOutcome::InputRequired(_) => panic!("unexpected second input"),
        JcodeTurnOutcome::Cancelled => panic!("approved turn was cancelled"),
        JcodeTurnOutcome::InterruptedUnknown(_) => panic!("turn was interrupted"),
    };
    assert_eq!(result.text(), "done");
    assert_eq!(result.input_tokens(), 5);
    assert_eq!(result.cache_read_input_tokens(), 2);
    let native = host.take_native_envelopes();
    assert_eq!(
        native
            .iter()
            .map(|envelope| envelope.sequence())
            .collect::<Vec<_>>(),
        (1..=native.len() as u64).collect::<Vec<_>>()
    );
    assert!(native.iter().all(|envelope| {
        envelope.run_id() == "logical-session-1" && envelope.turn_id() == "turn-1"
    }));
    assert!(native.iter().all(|envelope| {
        envelope.identity().executable_sha256() == busybox_sha256()
            && envelope.identity().configuration_sha256().len() == 64
            && envelope.identity().expected_server() == "jcode/fixture"
    }));
    assert!(matches!(
        native.last().map(|envelope| envelope.event()),
        Some(automonique_agents::JcodeNativeEvent::Terminal {
            outcome: automonique_agents::JcodeTerminalOutcome::Completed,
            ..
        })
    ));

    let second = host
        .begin_turn("turn-2", "second", 400, Duration::from_secs(5))
        .expect("second turn");
    let second = wait_for_pause_or_terminal(&mut host, second, 400);
    assert!(matches!(second, JcodeTurnOutcome::Completed(ref result) if result.text() == "again"));
    assert_eq!(host.operating_system_process_id(), pid);
    host.start_turn("turn-3", "cancel this", 450)
        .expect("cancelled turn starts without blocking");
    let cancelled = host
        .cancel(475, Duration::from_secs(5))
        .expect("provider cancellation is sent");
    assert_eq!(
        wait_for_pause_or_terminal(&mut host, cancelled, 475),
        JcodeTurnOutcome::Cancelled
    );
    host.close(500).expect("host closes");

    let mut journal = ProviderJournal::open(&journal_path).unwrap();
    let recovery = journal.recover_attempt("logical-session-1").unwrap();
    let process = recovery.process.unwrap();
    assert_eq!(process.state, ProcessState::Exited);
    assert_eq!(process.prompt_version.as_deref(), Some("provider-turn/v1"));
    assert_eq!(
        process.tool_schema_version.as_deref(),
        Some("jcode-api-stdio/v1")
    );
    assert_eq!(process.model_id.as_deref(), Some("fixture-model"));
    assert_eq!(recovery.session.unwrap().state, SessionState::Closed);
    let turns = journal.session_turns(1).unwrap();
    assert_eq!(turns.len(), 3);
    assert!(
        turns[..2]
            .iter()
            .all(|turn| turn.state == TurnState::Completed)
    );
    assert_eq!(turns[2].state, TurnState::Aborted);
    let first_requests = journal.turn_requests(turns[0].turn_id).unwrap();
    assert_eq!(first_requests.len(), 2);
    assert!(
        first_requests
            .iter()
            .all(|request| request.outcome == RequestState::Answered)
    );
    assert!(
        first_requests
            .iter()
            .all(|request| request.canonical_payload.is_some())
    );
    for turn in &turns[..2] {
        let steps = journal.replay_steps(turn.turn_id).unwrap();
        assert_eq!(steps.len(), 2);
        let command = &steps[0];
        let notification = &steps[1];
        let mut tape = journal
            .offline_replay(
                turn.turn_id,
                ReplayVersions {
                    prompt_version: "provider-turn/v1",
                    tool_schema_version: "jcode-api-stdio/v1",
                    model_id: "fixture-model",
                },
                false,
            )
            .unwrap();
        assert_eq!(
            tape.dispatch(
                &command.step_name,
                command.occurrence_index,
                &command.correlation_id,
                &command.canonical_bytes,
            )
            .unwrap(),
            notification.canonical_bytes
        );
        tape.finish().unwrap();
    }
    let approvals = journal.approvals(1).unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].decision, ApprovalDecision::Granted);
}

#[test]
fn eof_is_unknown_once_and_restart_retires_the_orphan_before_resume() {
    let (Some(helper), Ok(domain)) = (locate_launch_helper(), ContainmentDomain::discover()) else {
        eprintln!("[jcode_session_host] NOT PROVEN: helper or delegated cgroup unavailable");
        return;
    };
    if !std::path::Path::new(BUSYBOX).is_file() {
        eprintln!("[jcode_session_host] NOT PROVEN: static busybox unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = root.path().join("provider-journal.sqlite3");
    let eof_script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/eof-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-eof-session\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-eof-session\"}'; ",
        "printf '%s' '{\"v\":1,\"ev\":\"text_delta\",\"session_id\":\"jcode-eof-session\",\"text\":\"partial'"
    );
    let eof_plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(eof_script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-eof-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let mut first = JcodeSessionHost::spawn(
        &helper,
        &eof_plan,
        containment,
        &journal_path,
        "logical-eof-restart",
        root.path(),
        None,
        None,
        "jcode/eof-fixture",
        100,
        Duration::from_secs(5),
        None,
    )
    .expect("first host starts");
    assert_eq!(
        first.input_request_mode(),
        JcodeInputRequestMode::LegacyPermissionRequests,
        "a pinned build from before the harness change still negotiates"
    );
    first
        .start_turn("turn-eof", "interrupt me", 200)
        .expect("turn starts");
    let outcome = wait_for_pause_or_terminal(&mut first, JcodeTurnOutcome::Pending, 300);
    assert_eq!(
        outcome,
        JcodeTurnOutcome::InterruptedUnknown(
            automonique_agents::JcodeInterruptedReason::IncompleteFrame
        )
    );
    let native = first.take_native_envelopes();
    assert_eq!(
        native
            .iter()
            .filter(|envelope| matches!(
                envelope.event(),
                automonique_agents::JcodeNativeEvent::Terminal { .. }
            ))
            .count(),
        1
    );
    drop(first);

    let resume_script = concat!(
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":1,\"ev\":\"hello_ok\",\"version\":1,\"server\":\"jcode/eof-fixture\",",
        "\"capabilities\":[\"sessions\",\"streaming\",\"cancellation\",\"soft_interrupt\",",
        "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-eof-session\",\"status\":\"idle\"}}'; ",
        "while IFS= read -r request; do :; done"
    );
    let resume_plan = LaunchPlan::new(BUSYBOX, busybox_sha256())
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(resume_script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-resume-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let resumed = JcodeSessionHost::spawn(
        &helper,
        &resume_plan,
        containment,
        &journal_path,
        "logical-eof-restart",
        root.path(),
        Some("jcode-eof-session"),
        None,
        "jcode/eof-fixture",
        400,
        Duration::from_secs(5),
        None,
    )
    .expect("restart resumes exact provider session");
    resumed.close(500).expect("resumed host closes");

    let journal = ProviderJournal::open(&journal_path).unwrap();
    assert_eq!(journal.process(1).unwrap().state, ProcessState::Lost);
    assert_eq!(journal.process(2).unwrap().state, ProcessState::Exited);
    let turns = journal.session_turns(1).unwrap();
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0].state, TurnState::Aborted);
    assert!(
        journal
            .turn_requests(turns[0].turn_id)
            .unwrap()
            .iter()
            .all(|request| request.outcome == RequestState::Failed)
    );
}

/// The no-flag-day cutover: a session opened under a pinned build that
/// advertised only `permission_requests` is resumed exactly by a build that
/// advertises `stdin_requests`. The capability change is recorded, not drift;
/// a build advertising neither is refused before anything is journalled.
#[test]
fn an_exact_resume_across_the_input_request_capability_change_is_compatible() {
    let (Some(helper), Ok(domain)) = (locate_launch_helper(), ContainmentDomain::discover()) else {
        eprintln!("[jcode_session_host] NOT PROVEN: helper or delegated cgroup unavailable");
        return;
    };
    if !std::path::Path::new(BUSYBOX).is_file() {
        eprintln!("[jcode_session_host] NOT PROVEN: static busybox unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = root.path().join("provider-journal.sqlite3");
    let session = "jcode-cutover-session";

    let legacy_plan = busybox_plan(&one_turn_engine(
        "jcode/cutover",
        LEGACY_CAPABILITIES,
        session,
        "before",
    ));
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-cutover-legacy-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let mut legacy = JcodeSessionHost::spawn(
        &helper,
        &legacy_plan,
        containment,
        &journal_path,
        "logical-cutover",
        root.path(),
        None,
        None,
        "jcode/cutover",
        100,
        Duration::from_secs(5),
        None,
    )
    .expect("the legacy advertisement negotiates");
    assert_eq!(
        legacy.input_request_mode(),
        JcodeInputRequestMode::LegacyPermissionRequests
    );
    assert_eq!(legacy.provider_session_id(), session);
    let outcome = legacy
        .begin_turn("turn-before", "first", 200, Duration::from_secs(5))
        .expect("legacy turn starts");
    let outcome = wait_for_pause_or_terminal(&mut legacy, outcome, 200);
    assert!(
        matches!(outcome, JcodeTurnOutcome::Completed(ref result) if result.text() == "before")
    );
    legacy.close(300).expect("legacy host closes");

    // The maintained build resumes the exact session under a different
    // launch configuration and a different capability list.
    let maintained_plan = busybox_plan(&one_turn_engine(
        "jcode/cutover",
        MAINTAINED_CAPABILITIES,
        session,
        "after",
    ));
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-cutover-maintained-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let mut maintained = JcodeSessionHost::spawn(
        &helper,
        &maintained_plan,
        containment,
        &journal_path,
        "logical-cutover",
        root.path(),
        Some(session),
        None,
        "jcode/cutover",
        400,
        Duration::from_secs(5),
        None,
    )
    .expect("the exact resume is compatible across the capability change");
    assert_eq!(
        maintained.input_request_mode(),
        JcodeInputRequestMode::StdinRequests
    );
    assert_eq!(maintained.provider_session_id(), session);
    let outcome = maintained
        .begin_turn("turn-after", "second", 500, Duration::from_secs(5))
        .expect("resumed turn starts");
    let outcome = wait_for_pause_or_terminal(&mut maintained, outcome, 500);
    assert!(matches!(outcome, JcodeTurnOutcome::Completed(ref result) if result.text() == "after"));
    maintained.close(600).expect("maintained host closes");

    // A build advertising neither input-request capability is refused at the
    // hello, before any process, session or binding row exists.
    let unsupported_plan = busybox_plan(&one_turn_engine(
        "jcode/cutover",
        UNSUPPORTED_CAPABILITIES,
        session,
        "never",
    ));
    let containment = RunContainment::create(
        &domain,
        &format!("jcode-cutover-unsupported-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let refused = JcodeSessionHost::spawn(
        &helper,
        &unsupported_plan,
        containment,
        &journal_path,
        "logical-cutover",
        root.path(),
        Some(session),
        None,
        "jcode/cutover",
        700,
        Duration::from_secs(5),
        None,
    );
    assert!(
        matches!(
            refused,
            Err(JcodeHostError::Protocol(
                JcodeProtocolError::MissingCapability
            ))
        ),
        "a hello without any input-request capability must be refused"
    );

    let journal = ProviderJournal::open(&journal_path).unwrap();
    assert_eq!(journal.process(1).unwrap().state, ProcessState::Exited);
    assert_eq!(journal.process(2).unwrap().state, ProcessState::Exited);
    assert!(
        journal.process(3).is_err(),
        "the refused build never reached the journal"
    );
    let capability_binding = |session_id: i64, name: &str| {
        journal
            .bindings(session_id, BindingKind::Capability)
            .unwrap()
            .into_iter()
            .find(|binding| binding.name == name)
            .map(|binding| binding.value_digest)
            .unwrap_or_else(|| panic!("session {session_id} binds {name}"))
    };
    assert_ne!(
        capability_binding(1, "jcode-harness-api"),
        capability_binding(2, "jcode-harness-api"),
        "the capability change is recorded exactly on each session"
    );
    assert_ne!(
        capability_binding(1, "jcode-execution-config"),
        capability_binding(2, "jcode-execution-config"),
        "the launch configuration change is recorded exactly on each session"
    );
    let server_digest = |session_id: i64| {
        journal
            .bindings(session_id, BindingKind::Schema)
            .unwrap()
            .into_iter()
            .find(|binding| binding.name == "jcode-server")
            .map(|binding| binding.value_digest)
            .expect("every session binds the reported server")
    };
    assert_eq!(server_digest(1), server_digest(2));
    for session_id in [1, 2] {
        let turns = journal.session_turns(session_id).unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].state, TurnState::Completed);
        journal
            .offline_replay(
                turns[0].turn_id,
                ReplayVersions {
                    prompt_version: "provider-turn/v1",
                    tool_schema_version: "jcode-api-stdio/v1",
                    model_id: "provider-default",
                },
                false,
            )
            .expect("the drift tuple is unchanged on both sides of the cutover");
    }
}

/// The journal side of the rule above, without a sandbox: a new process for
/// the same attempt may carry a different executable digest and bind a
/// different capability digest on its own session; rebinding within one
/// session stays a conflict, and only the presented tuple is drift.
#[test]
fn the_journal_records_a_capability_change_across_processes_without_calling_it_drift() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = ProviderJournal::open(root.path().join("journal.sqlite3")).unwrap();
    let legacy_digest = format!("{:x}", Sha256::digest(b"permission_requests"));
    let maintained_digest = format!("{:x}", Sha256::digest(b"stdin_requests"));
    fn spawn<'a>(
        spawn_key: &'a str,
        executable: &'a str,
        tool_schema_version: &'a str,
        spawned_ms: i64,
    ) -> ProcessSpawn<'a> {
        ProcessSpawn {
            spawn_key,
            attempt_id: "logical-cutover",
            provider_kind: "jcode",
            executable_digest: executable,
            prompt_version: "provider-turn/v1",
            tool_schema_version,
            model_id: "provider-default",
            force_version_change: false,
            spawned_ms,
        }
    }

    let legacy_executable = "a".repeat(64);
    let first = journal
        .record_process(spawn(
            "logical-cutover:100",
            &legacy_executable,
            "jcode-api-stdio/v1",
            100,
        ))
        .unwrap();
    let first_session = journal
        .open_session(SessionOpening {
            process_id: first.process_id,
            provider_session_key: "jcode-cutover-session",
            opened_ms: 100,
        })
        .unwrap();
    journal
        .bind_capability(BindingRecord {
            session_id: first_session.session_id,
            name: "jcode-harness-api",
            version: "1",
            value_digest: &legacy_digest,
            bound_ms: 100,
        })
        .unwrap();
    assert!(
        matches!(
            journal.bind_capability(BindingRecord {
                session_id: first_session.session_id,
                name: "jcode-harness-api",
                version: "1",
                value_digest: &maintained_digest,
                bound_ms: 150,
            }),
            Err(ProviderJournalError::BindingConflict(_))
        ),
        "one session never changes its advertised capabilities"
    );
    journal
        .close_session(SessionClosing {
            session_id: first_session.session_id,
            expected_revision: first_session.revision,
            now_ms: 200,
            closure: SessionClosure::Closed,
        })
        .unwrap();
    journal
        .finish_process(ProcessExit {
            process_id: first.process_id,
            expected_revision: first.revision,
            now_ms: 200,
            termination: ProcessTermination::Exited,
        })
        .unwrap();

    let maintained_executable = "b".repeat(64);
    let second = journal
        .record_process(spawn(
            "logical-cutover:300",
            &maintained_executable,
            "jcode-api-stdio/v1",
            300,
        ))
        .expect("a new engine build under the same attempt is not version drift");
    let second_session = journal
        .open_session(SessionOpening {
            process_id: second.process_id,
            provider_session_key: "jcode-cutover-session",
            opened_ms: 300,
        })
        .unwrap();
    journal
        .bind_capability(BindingRecord {
            session_id: second_session.session_id,
            name: "jcode-harness-api",
            version: "1",
            value_digest: &maintained_digest,
            bound_ms: 300,
        })
        .expect("the new session binds the new capability list exactly");
    journal
        .close_session(SessionClosing {
            session_id: second_session.session_id,
            expected_revision: second_session.revision,
            now_ms: 400,
            closure: SessionClosure::Closed,
        })
        .unwrap();
    journal
        .finish_process(ProcessExit {
            process_id: second.process_id,
            expected_revision: second.revision,
            now_ms: 400,
            termination: ProcessTermination::Exited,
        })
        .unwrap();

    let drifted_executable = "c".repeat(64);
    let drifted = journal.record_process(spawn(
        "logical-cutover:500",
        &drifted_executable,
        "jcode-api-stdio/v2",
        500,
    ));
    assert!(
        matches!(
            drifted,
            Err(ProviderJournalError::ResumeVersionMismatch(
                "tool_schema_version"
            ))
        ),
        "what Automonique presents to the engine is the drift tuple: {drifted:?}"
    );
}
