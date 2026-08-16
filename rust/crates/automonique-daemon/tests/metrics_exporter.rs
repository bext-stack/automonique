// SPDX-License-Identifier: Elastic-2.0

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_store::provider_journal::{
    FinishReason, ProcessSpawn, ProviderJournal, SessionOpening, TurnCompletion, TurnOpening,
    TurnOutcome, TurnUsage,
};

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

fn wait_for_socket(config: &DaemonConfig) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let request = AdminRequest::new(RequestId::new("metrics-test").unwrap(), command);
    let payload = request.to_message().unwrap().to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).unwrap();
    let mut stream = UnixStream::connect(config.admin_socket()).unwrap();
    stream.write_all(&frame).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut response[4..]).unwrap();
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).unwrap() else {
        panic!("complete response was incomplete")
    };
    AdminResponse::from_canonical_bytes(payload).unwrap()
}

#[test]
fn authenticated_scrape_exports_live_and_durable_gen_ai_metrics() {
    let (_root, config) = fixture();
    std::fs::create_dir(config.state_dir()).expect("product state");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private product state");
    let mut journal = ProviderJournal::open(config.provider_journal_path()).unwrap();
    let process = journal
        .record_process(ProcessSpawn {
            spawn_key: "metrics-process",
            attempt_id: "metrics-attempt",
            provider_kind: "openai",
            executable_digest: &"a".repeat(64),
            spawned_ms: 1,
        })
        .unwrap();
    let session = journal
        .open_session(SessionOpening {
            process_id: process.process_id,
            provider_session_key: "metrics-session",
            opened_ms: 2,
        })
        .unwrap();
    let turn = journal
        .open_turn(TurnOpening {
            session_id: session.session_id,
            ordinal: 1,
            turn_key: "metrics-turn",
            opened_ms: 3,
        })
        .unwrap();
    journal
        .complete_turn(TurnCompletion {
            turn_id: turn.turn_id,
            expected_revision: 1,
            now_ms: 4,
            outcome: TurnOutcome::Completed,
            settlements: &[],
            cursor: None,
            usage: Some(TurnUsage {
                gen_ai_system: "openai",
                request_model: Some("gpt-5"),
                response_model: Some("gpt-5"),
                input_tokens: 21,
                cached_input_tokens: 8,
                output_tokens: 13,
                finish_reason: FinishReason::Stop,
            }),
        })
        .unwrap();
    drop(journal);

    let daemon = Daemon::open(&config).expect("daemon");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(&config);

    let AdminResponse::Metrics { exposition, .. } = call(&config, AdminCommand::Metrics) else {
        panic!("metrics response")
    };
    assert!(exposition.contains("automonique_daemon_ready 1\n"));
    assert!(exposition.contains("automonique_intake_enabled 1\n"));
    assert!(exposition.contains("automonique_gen_ai_client_requests_total 1\n"));
    assert!(exposition.contains("automonique_gen_ai_usage_input_tokens_total 21\n"));
    assert!(exposition.contains("automonique_gen_ai_usage_output_tokens_total 13\n"));
    assert!(exposition.contains("# TYPE automonique_gen_ai_client_requests_total counter\n"));

    assert!(matches!(
        call(&config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("join").expect("clean shutdown");
}
