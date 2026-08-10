// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use automonique_lab::build::BuildBroker;
use automonique_lab::canonical_json::{
    TransportErrorCode, decode_response_for, decode_transport_error, encode_request,
};
use automonique_lab::controller::{ControllerError, LabController};
use automonique_lab::framing::{FrameLimits, decode_frame, encode_frame};
use automonique_lab::protocol::{
    BudgetEnforcement, DeniedResponse, Execution, GitSha1, LabBudget, LabBudgetValues, LabRequest,
    LabResponse, OpaqueId, ProviderPolicy, SelectRequest, SyntheticProviderPolicy, UnitState,
};
use automonique_lab::server::{LabHandler, UnixLabServer, UnixServerConfig};
use automonique_lab::workspace_lease::RepoPath;

const BASE: &str = "3637390b5298744b1404b9f4d0655671c4013752";

fn request() -> LabRequest {
    LabRequest::Select(
        SelectRequest::new(
            OpaqueId::new("socket-request").unwrap(),
            OpaqueId::new("socket-objective").unwrap(),
            GitSha1::new(BASE).unwrap(),
            Execution::Synthetic,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            LabBudget::new(LabBudgetValues {
                max_wall_ms: 1_000,
                max_cpu_ms: 1_000,
                max_disk_bytes: 16_384,
                max_output_bytes: 16_384,
                max_pids: 2,
                max_model_calls: 0,
                max_cost_microunits: 0,
                enforcement: BudgetEnforcement::SyntheticInProcess,
            })
            .unwrap(),
        )
        .unwrap(),
    )
}

fn paths() -> Vec<RepoPath> {
    vec![RepoPath::parse("rust/crates/automonique-lab").unwrap()]
}

fn privatize(directory: &tempfile::TempDir) {
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

fn exchange(socket: &std::path::Path, bytes: &[u8]) -> Vec<u8> {
    let mut client = UnixStream::connect(socket).unwrap();
    client.write_all(bytes).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    response
}

fn exchange_without_request_eof(socket: &std::path::Path, bytes: &[u8]) -> Vec<u8> {
    let mut client = UnixStream::connect(socket).unwrap();
    client.write_all(bytes).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn same_uid_one_frame_round_trip_has_private_socket() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let socket = directory.path().join("private").join("lab.sock");
    let controller = LabController::open(
        directory.path().join("state.sqlite3"),
        GitSha1::new(BASE).unwrap(),
        paths(),
        BuildBroker::open(directory.path().join("build")).unwrap(),
    )
    .unwrap();
    let limits = FrameLimits::new(1024 * 1024).unwrap();
    let mut server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: socket.clone(),
            frame_limits: limits,
            io_timeout: Duration::from_secs(2),
        },
        controller,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let request = request();
    let frame = encode_frame(&encode_request(&request).unwrap(), limits).unwrap();
    let join = std::thread::spawn(move || server.serve_once().unwrap());
    let response = exchange_without_request_eof(&socket, &frame);
    join.join().unwrap();
    let payload = decode_frame(&response, limits).unwrap();
    let response = decode_response_for(payload, &request).unwrap();
    assert_eq!(
        match response {
            LabResponse::Selected(value) => value.unit().state(),
            _ => panic!(),
        },
        UnitState::Paused
    );
    assert!(!socket.exists());
}

#[test]
fn malformed_payload_gets_closed_redacted_transport_error() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let socket = directory.path().join("server").join("lab.sock");
    let controller = LabController::open(
        directory.path().join("state.sqlite3"),
        GitSha1::new(BASE).unwrap(),
        paths(),
        BuildBroker::open(directory.path().join("build")).unwrap(),
    )
    .unwrap();
    let limits = FrameLimits::new(4096).unwrap();
    let mut server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: socket.clone(),
            frame_limits: limits,
            io_timeout: Duration::from_secs(2),
        },
        controller,
    )
    .unwrap();
    let frame = encode_frame(br#"{"z":1,"a":2}"#, limits).unwrap();
    let join = std::thread::spawn(move || server.serve_once().unwrap());
    let response = exchange(&socket, &frame);
    join.join().unwrap();
    let error = decode_transport_error(decode_frame(&response, limits).unwrap()).unwrap();
    assert_eq!(error.code(), TransportErrorCode::NoncanonicalJson);
    assert_eq!(error.reason(), "request payload denied");
}

#[test]
fn symlinked_socket_parent_is_refused_without_removing_target() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let real = directory.path().join("real");
    fs::create_dir(&real).unwrap();
    let linked = directory.path().join("linked");
    symlink(&real, &linked).unwrap();
    let controller = LabController::open(
        directory.path().join("state.sqlite3"),
        GitSha1::new(BASE).unwrap(),
        paths(),
        BuildBroker::open(directory.path().join("build")).unwrap(),
    )
    .unwrap();
    let result = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: linked.join("lab.sock"),
            frame_limits: FrameLimits::new(4096).unwrap(),
            io_timeout: Duration::from_secs(1),
        },
        controller,
    );
    assert!(result.is_err());
    assert!(real.exists());
    assert!(!real.join("lab.sock").exists());
}

#[test]
fn stop_flag_gracefully_closes_listener_and_unlinks_only_its_socket() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let socket = directory.path().join("stop").join("lab.sock");
    let controller = LabController::open(
        directory.path().join("state.sqlite3"),
        GitSha1::new(BASE).unwrap(),
        paths(),
        BuildBroker::open(directory.path().join("build")).unwrap(),
    )
    .unwrap();
    let mut server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: socket.clone(),
            frame_limits: FrameLimits::new(4096).unwrap(),
            io_timeout: Duration::from_secs(1),
        },
        controller,
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let join = std::thread::spawn(move || server.serve_until(&thread_stop).unwrap());
    stop.store(true, Ordering::Release);
    join.join().unwrap();
    assert!(!socket.exists());
}

struct CountingHandler(Arc<AtomicUsize>);

impl LabHandler for CountingHandler {
    fn handle_request(&mut self, request: LabRequest) -> Result<LabResponse, ControllerError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(LabResponse::Denied(
            DeniedResponse::new(
                request.request_id().clone(),
                OpaqueId::new("test_denied").unwrap(),
                "test handler denial",
            )
            .unwrap(),
        ))
    }
}

fn counting_server(
    directory: &tempfile::TempDir,
    limits: FrameLimits,
    timeout: Duration,
) -> (
    std::path::PathBuf,
    UnixLabServer<CountingHandler>,
    Arc<AtomicUsize>,
) {
    let socket = directory.path().join("counting").join("lab.sock");
    let count = Arc::new(AtomicUsize::new(0));
    let server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: socket.clone(),
            frame_limits: limits,
            io_timeout: timeout,
        },
        CountingHandler(Arc::clone(&count)),
    )
    .unwrap();
    (socket, server, count)
}

#[test]
fn partial_oversize_and_read_timeout_never_reach_handler() {
    for (name, bytes, timeout, expected) in [
        (
            "partial",
            [10_u32.to_be_bytes().as_slice(), b"{}"].concat(),
            Duration::from_millis(200),
            TransportErrorCode::InvalidRequest,
        ),
        (
            "oversize",
            4097_u32.to_be_bytes().to_vec(),
            Duration::from_millis(200),
            TransportErrorCode::FrameTooLarge,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        privatize(&directory);
        let limits = FrameLimits::new(4096).unwrap();
        let (socket, mut server, count) = counting_server(&directory, limits, timeout);
        let join = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || server.serve_once().unwrap())
            .unwrap();
        let response = exchange(&socket, &bytes);
        join.join().unwrap();
        let error = decode_transport_error(decode_frame(&response, limits).unwrap()).unwrap();
        assert_eq!(error.code(), expected);
        assert_eq!(count.load(Ordering::Acquire), 0);
    }

    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let limits = FrameLimits::new(4096).unwrap();
    let (socket, mut server, count) =
        counting_server(&directory, limits, Duration::from_millis(50));
    let frame = encode_frame(&encode_request(&request()).unwrap(), limits).unwrap();
    let join = thread::spawn(move || server.serve_once().unwrap());
    let mut client = UnixStream::connect(socket).unwrap();
    client.write_all(&frame[..frame.len() - 1]).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    join.join().unwrap();
    let error = decode_transport_error(decode_frame(&response, limits).unwrap()).unwrap();
    assert_eq!(error.code(), TransportErrorCode::InvalidRequest);
    assert_eq!(count.load(Ordering::Acquire), 0);
}

#[test]
fn immediate_and_delayed_trailing_bytes_are_denied_before_handler_mutation() {
    let complete = {
        let limits = FrameLimits::new(4096).unwrap();
        encode_frame(&encode_request(&request()).unwrap(), limits).unwrap()
    };
    for (name, delay) in [
        ("immediate-trailing", Duration::ZERO),
        ("delayed-trailing", Duration::from_millis(50)),
    ] {
        let directory = tempfile::tempdir().unwrap();
        privatize(&directory);
        let limits = FrameLimits::new(4096).unwrap();
        let (socket, mut server, count) =
            counting_server(&directory, limits, Duration::from_millis(500));
        let join = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || server.serve_once().unwrap())
            .unwrap();
        let mut client = UnixStream::connect(socket).unwrap();
        client.write_all(&complete).unwrap();
        thread::sleep(delay);
        client.write_all(b"x").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        join.join().unwrap();
        let error = decode_transport_error(decode_frame(&response, limits).unwrap()).unwrap();
        assert_eq!(error.code(), TransportErrorCode::ExtraData);
        assert_eq!(count.load(Ordering::Acquire), 0);
    }
}

#[test]
fn a_complete_frame_can_arrive_in_chunks_without_request_eof() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let limits = FrameLimits::new(4096).unwrap();
    let (socket, mut server, count) =
        counting_server(&directory, limits, Duration::from_millis(500));
    let frame = encode_frame(&encode_request(&request()).unwrap(), limits).unwrap();
    let join = thread::spawn(move || server.serve_once().unwrap());
    let mut client = UnixStream::connect(socket).unwrap();
    client.write_all(&frame[..2]).unwrap();
    thread::sleep(Duration::from_millis(10));
    client.write_all(&frame[2..9]).unwrap();
    thread::sleep(Duration::from_millis(10));
    client.write_all(&frame[9..]).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    join.join().unwrap();
    let decoded =
        decode_response_for(decode_frame(&response, limits).unwrap(), &request()).unwrap();
    assert!(matches!(decoded, LabResponse::Denied(_)));
    assert_eq!(count.load(Ordering::Acquire), 1);
}

#[test]
fn one_connection_dispatches_once_and_writes_exactly_one_response() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let limits = FrameLimits::new(4096).unwrap();
    let (socket, mut server, count) =
        counting_server(&directory, limits, Duration::from_millis(500));
    let frame = encode_frame(&encode_request(&request()).unwrap(), limits).unwrap();
    let join = thread::spawn(move || server.serve_once().unwrap());
    let mut client = UnixStream::connect(socket).unwrap();
    client.write_all(&frame).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    join.join().unwrap();
    let decoded =
        decode_response_for(decode_frame(&response, limits).unwrap(), &request()).unwrap();
    assert!(matches!(decoded, LabResponse::Denied(_)));
    assert_eq!(count.load(Ordering::Acquire), 1);
}

#[test]
fn socket_can_restart_after_one_request() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let limits = FrameLimits::new(4096).unwrap();
    let frame = encode_frame(&encode_request(&request()).unwrap(), limits).unwrap();

    for _ in 0..2 {
        let (socket, mut server, count) =
            counting_server(&directory, limits, Duration::from_millis(500));
        let join = thread::spawn(move || server.serve_once().unwrap());
        let response = exchange_without_request_eof(&socket, &frame);
        join.join().unwrap();
        let decoded =
            decode_response_for(decode_frame(&response, limits).unwrap(), &request()).unwrap();
        assert!(matches!(decoded, LabResponse::Denied(_)));
        assert_eq!(count.load(Ordering::Acquire), 1);
        assert!(!socket.exists());
    }
}

#[test]
fn permissive_existing_socket_directory_is_refused_without_chmod() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let socket_parent = directory.path().join("shared");
    fs::create_dir(&socket_parent).unwrap();
    fs::set_permissions(&socket_parent, fs::Permissions::from_mode(0o755)).unwrap();
    let result = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: socket_parent.join("lab.sock"),
            frame_limits: FrameLimits::new(4096).unwrap(),
            io_timeout: Duration::from_secs(1),
        },
        CountingHandler(Arc::new(AtomicUsize::new(0))),
    );
    assert!(result.is_err());
    assert_eq!(
        fs::metadata(socket_parent).unwrap().permissions().mode() & 0o777,
        0o755
    );
}
