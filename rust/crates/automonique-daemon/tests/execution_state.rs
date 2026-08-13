// SPDX-License-Identifier: Elastic-2.0

//! The daemon's execution-state report is a measurement, not a hope.
//!
//! The status command's `execution_state` must agree with an independent
//! capability probe taken in the same environment, and neither value may ever
//! claim an execution lane exists — both spellings end in `no_lane` because
//! this release wires none.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, ExecutionState};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_runner::capability::{BoundaryProperty, HostCapabilities};

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

fn status(config: &DaemonConfig) -> automonique_protocol::admin::DaemonStatus {
    let request = AdminRequest::new(
        RequestId::new("execution-state-1").expect("request ID"),
        AdminCommand::Status,
    );
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("frame request");
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
    let AdminResponse::Status { status, .. } =
        AdminResponse::from_canonical_bytes(payload).expect("admitted response")
    else {
        panic!("status response expected")
    };
    status
}

#[test]
fn reported_execution_state_matches_an_independent_measurement() {
    let (_root, config) = fixture();
    let daemon = Daemon::open(&config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    // Generous on purpose, as in every other suite here: everything before the
    // bind is disk-bound, so a short deadline measures the test host under
    // concurrent load rather than the daemon.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }

    // The independent measurement asks for exactly the properties the
    // composed launch path enforces — the same question the daemon asks.
    let independent = HostCapabilities::probe().select_mode(&[
        BoundaryProperty::DescendantContainment,
        BoundaryProperty::FilesystemRestriction,
        BoundaryProperty::TcpDenial,
        BoundaryProperty::SyscallRestriction,
    ]);
    let expected = match independent {
        Ok(_) => ExecutionState::SandboxEnforceableNoLane,
        Err(_) => ExecutionState::SandboxUnavailableNoLane,
    };

    let reported = status(&config).execution_state();
    assert_eq!(
        reported, expected,
        "the daemon's execution state must be the measured one, not a default"
    );
    // Whatever the measurement said, no lane exists in this release, and the
    // wire spelling itself must keep saying so.
    assert!(
        reported.as_str().ends_with("_no_lane"),
        "execution state spelling must not imply an execution lane: {}",
        reported.as_str()
    );

    assert!(matches!(
        {
            let request = AdminRequest::new(
                RequestId::new("execution-state-2").expect("request ID"),
                AdminCommand::Shutdown,
            );
            let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
            let payload = request
                .to_message()
                .expect("encode request")
                .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&payload, &mut frame).expect("frame request");
            stream.write_all(&frame).expect("write request");
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("response prefix");
            let length = u32::from_be_bytes(prefix) as usize;
            let mut response = vec![0_u8; length + 4];
            response[..4].copy_from_slice(&prefix);
            stream
                .read_exact(&mut response[4..])
                .expect("response body");
            let FrameDecode::Frame { payload, .. } =
                decode_frame(&response).expect("response frame")
            else {
                panic!("complete response was incomplete")
            };
            AdminResponse::from_canonical_bytes(payload).expect("admitted response")
        },
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
}
