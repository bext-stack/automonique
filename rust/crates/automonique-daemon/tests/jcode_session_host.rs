// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use automonique_agents::PermissionDecision;
use automonique_daemon::execute::locate_launch_helper;
use automonique_daemon::jcode_session_host::{JcodeSessionHost, JcodeTurnOutcome};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    ContainmentDomain, ContainmentLimits, LaunchPlan, RunContainment, SocketGrant,
};
use automonique_store::provider_journal::{
    ApprovalDecision, ProcessState, ProviderJournal, RequestState, SessionState, TurnState,
};
use sha2::{Digest as _, Sha256};

const BUSYBOX: &str = "/usr/bin/busybox";

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
    let (Some(binary), Some(home)) = (
        std::env::var_os("AUTOMONIQUE_TEST_JCODE_BINARY").map(std::path::PathBuf::from),
        std::env::var_os("AUTOMONIQUE_TEST_JCODE_HOME").map(std::path::PathBuf::from),
    ) else {
        eprintln!("[jcode_session_host] NOT PROVEN: real JCode test inputs not configured");
        return;
    };
    assert!(binary.is_absolute() && binary.is_file());
    assert!(home.is_absolute() && home.is_dir());

    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = root.path().join("runtime");
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
        100,
        Duration::from_secs(30),
    )
    .expect("installed JCode negotiates inside enforced containment");
    assert!(!host.provider_session_id().is_empty());
    host.close(200).expect("installed JCode closes cleanly");
}

#[test]
fn contained_jcode_session_negotiates_approval_resumes_and_journals() {
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
        "\"permission_requests\",\"history\",\"model_catalog\",\"reasoning_effort\",\"usage\",\"runtime_info\"]}'; ",
        "IFS= read -r request; printf '%s\\n' '",
        "{\"v\":1,\"reply_to\":2,\"ev\":\"attached\",\"session\":{\"session_id\":\"jcode-session-1\",\"status\":\"idle\"}}'; ",
        "IFS= read -r request; printf '%s\\n' ",
        "'{\"v\":1,\"ev\":\"message_accepted\",\"session_id\":\"jcode-session-1\"}' ",
        "'{\"v\":1,\"ev\":\"permission_request\",\"session_id\":\"jcode-session-1\",\"request_id\":\"approval-1\",\"tool_name\":\"write\",\"description\":\"fixture write\"}'; ",
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
        100,
        Duration::from_secs(5),
    )
    .expect("host starts");
    let pid = host.operating_system_process_id();
    assert_eq!(host.provider_session_id(), "jcode-session-1");

    let first = host
        .begin_turn("turn-1", "first", 200, Duration::from_secs(5))
        .expect("turn starts");
    let approval = match wait_for_pause_or_terminal(&mut host, first, 200) {
        JcodeTurnOutcome::ApprovalRequired(approval) => approval,
        JcodeTurnOutcome::Pending => panic!("fixture event stream paused"),
        JcodeTurnOutcome::Completed(_) => panic!("approval was skipped"),
        JcodeTurnOutcome::Cancelled => panic!("turn was cancelled"),
    };
    assert_eq!(approval.request_id(), "approval-1");
    assert_eq!(approval.tool_name(), "write");
    let decided = host
        .decide_permission(
            approval.request_id(),
            PermissionDecision::Allow,
            "operator",
            300,
            Duration::from_secs(5),
        )
        .expect("approval decision is sent");
    let result = match wait_for_pause_or_terminal(&mut host, decided, 300) {
        JcodeTurnOutcome::Completed(result) => result,
        JcodeTurnOutcome::Pending => panic!("fixture event stream paused"),
        JcodeTurnOutcome::ApprovalRequired(_) => panic!("unexpected second approval"),
        JcodeTurnOutcome::Cancelled => panic!("approved turn was cancelled"),
    };
    assert_eq!(result.text(), "done");
    assert_eq!(result.input_tokens(), 5);
    assert_eq!(result.cache_read_input_tokens(), 2);

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
    assert_eq!(recovery.process.unwrap().state, ProcessState::Exited);
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
    let approvals = journal.approvals(1).unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].decision, ApprovalDecision::Granted);
}
