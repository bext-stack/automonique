// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use automonique_agents::{ProviderDisposition, SessionScope};
use automonique_daemon::execute::locate_launch_helper;
use automonique_daemon::provider_session_host::{ProviderSessionHost, retire_orphaned_attempt};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{ContainmentDomain, ContainmentLimits, LaunchPlan, RunContainment};
use automonique_store::provider_journal::{
    ProcessSpawn, ProcessState, ProviderJournal, SessionOpening, SessionState, TurnOpening,
    TurnState,
};

const BUSYBOX: &str = "/usr/bin/busybox";

#[test]
fn restart_recovery_marks_an_orphaned_process_session_and_turn_lost() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("provider-journal.sqlite3");
    let mut journal = ProviderJournal::open(&path).unwrap();
    let digest = "b".repeat(64);
    let process = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn-1",
            attempt_id: "session-recovery",
            provider_kind: "fixture",
            executable_digest: &digest,
            spawned_ms: 1,
        })
        .unwrap();
    let session = journal
        .open_session(SessionOpening {
            process_id: process.process_id,
            provider_session_key: "session-recovery",
            opened_ms: 2,
        })
        .unwrap();
    journal
        .open_turn(TurnOpening {
            session_id: session.session_id,
            ordinal: 1,
            turn_key: "turn-1",
            opened_ms: 3,
        })
        .unwrap();
    drop(journal);

    let mut reopened = ProviderJournal::open(&path).unwrap();
    assert!(retire_orphaned_attempt(&mut reopened, "session-recovery", 4).unwrap());
    let recovery = reopened.recover_attempt("session-recovery").unwrap();
    assert_eq!(recovery.process.unwrap().state, ProcessState::Lost);
    assert_eq!(recovery.session.unwrap().state, SessionState::Lost);
    assert_eq!(recovery.turn.unwrap().state, TurnState::Aborted);
}

#[test]
fn turn_two_reuses_the_live_session_process_and_journals_both_turns() {
    let (Some(helper), Ok(domain)) = (locate_launch_helper(), ContainmentDomain::discover()) else {
        eprintln!("[provider_session_host] NOT PROVEN: helper or delegated cgroup unavailable");
        return;
    };
    if !std::path::Path::new(BUSYBOX).is_file() {
        eprintln!("[provider_session_host] NOT PROVEN: static busybox unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = root.path().join("provider-journal.sqlite3");
    let containment = RunContainment::create(
        &domain,
        &format!("psh-{}", std::process::id()),
        ContainmentLimits::none(),
    )
    .unwrap();
    let script = concat!(
        "n=0; while IFS= read -r request; do n=$((n+1)); ",
        "printf '%s\\n' ",
        "'{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}' ",
        "'{\"type\":\"turn.started\"}' ",
        "'{\"type\":\"item.started\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\"}}' ",
        "'{\"type\":\"item.completed\",\"item\":{\"id\":\"m-1\",\"type\":\"agent_message\",\"text\":\"done\"}}' ",
        "'{\"type\":\"turn.completed\",\"usage\":{\"cached_input_tokens\":0,\"input_tokens\":1,\"output_tokens\":1}}'; ",
        "done"
    );
    let plan = LaunchPlan::new(BUSYBOX)
        .unwrap()
        .argument("sh")
        .unwrap()
        .argument("-c")
        .unwrap()
        .argument(script)
        .unwrap()
        .filesystem_grant(PathIntent::ReadExecute, BUSYBOX)
        .unwrap();
    let scope = SessionScope::new("tenant", "account", "namespace").unwrap();
    let mut host = ProviderSessionHost::spawn(
        &helper,
        &plan,
        containment,
        &journal_path,
        "fixture-session",
        scope,
        "fixture",
        Some("fixture-model"),
        &"a".repeat(64),
        100,
        60_000,
    )
    .expect("host");
    let pid = host.operating_system_process_id();
    let first = host
        .turn("turn-1", "first", 200, Duration::from_secs(5))
        .expect("turn one");
    assert_eq!(first.disposition(), ProviderDisposition::Succeeded);
    let second = host
        .turn("turn-2", "second", 300, Duration::from_secs(5))
        .expect("turn two");
    assert_eq!(second.disposition(), ProviderDisposition::Succeeded);
    assert_eq!(host.operating_system_process_id(), pid);
    host.close(400).expect("close");

    let mut journal = ProviderJournal::open(&journal_path).unwrap();
    let recovered = journal.recover_attempt("fixture-session").unwrap();
    assert_eq!(recovered.process.unwrap().state, ProcessState::Exited);
    let session = recovered.session.unwrap();
    assert_eq!(session.state, SessionState::Closed);
    let turns = journal.session_turns(session.session_id).unwrap();
    assert_eq!(turns.len(), 2);
    assert!(turns.iter().all(|turn| turn.state == TurnState::Completed));
    let totals = journal.usage_totals().unwrap();
    assert_eq!(totals.requests, 2);
    assert_eq!(totals.input_tokens, 2);
    assert_eq!(totals.output_tokens, 2);
    for turn in turns {
        let usage = journal.turn_usage(turn.turn_id).unwrap().unwrap();
        assert_eq!(usage.gen_ai_system, "fixture");
        assert_eq!(usage.request_model.as_deref(), Some("fixture-model"));
        assert_eq!(usage.finish_reason.as_str(), "stop");
    }
}
