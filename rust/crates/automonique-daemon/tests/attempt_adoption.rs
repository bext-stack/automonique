// SPDX-License-Identifier: Elastic-2.0

//! Real-socket proof for source-generation attempt adoption.

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::attempt_adoption::{
    AdoptedSourceAttempts, AttemptAdoptionClient, AttemptAdoptionEndpoint, AttemptAdoptionError,
    AttemptHostRoute, SourceAttemptProbe,
};
use automonique_daemon::attempt_host::DaemonAttemptHost;
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_runner::control::{CancelDelivery, CancelSink, CancelSinkError};
use automonique_runner::dispatch::DispatchOutcome;

struct CountingSink {
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for CountingSink {
    fn deliver(
        &self,
        _attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}

#[test]
fn a_serving_daemon_publishes_its_exact_adoption_route() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    fs::create_dir(&runtime_root).expect("runtime root");
    fs::create_dir(&state_root).expect("state root");
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700))
        .expect("private runtime root");
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .expect("private state root");
    let config = DaemonConfig {
        runtime_root,
        state_root,
    };
    let daemon = Daemon::open(&config).expect("open daemon");
    let route = daemon
        .attempt_adoption_route()
        .expect("opened daemon route");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || daemon.serve(&serve_stop));
    let client =
        AttemptAdoptionClient::new(&route.socket_path, &route.holder_id, route.lease_epoch)
            .expect("route client");
    let deadline = Instant::now() + Duration::from_secs(5);
    let inventory = loop {
        match client.inventory() {
            Ok(inventory) => break inventory,
            Err(AttemptAdoptionError::Io(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("adoption route did not become ready: {error}"),
        }
    };
    assert_eq!(inventory.holder_id, route.holder_id);
    assert_eq!(inventory.lease_epoch, route.lease_epoch);
    assert!(inventory.attempt_ids.is_empty());

    stop.store(true, Ordering::Release);
    worker
        .join()
        .expect("serve thread")
        .expect("clean daemon stop");
    assert!(
        !route.socket_path.exists(),
        "ordered shutdown removes only the source route it created"
    );
}

#[test]
fn a_successor_inventories_and_cancels_the_sources_live_attempt() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let host = Arc::new(
        DaemonAttemptHost::open(root.path().join("cancel.sqlite3")).expect("attempt host"),
    );
    let deliveries = Arc::new(AtomicUsize::new(0));
    let registration = host
        .register(
            "attempt-b",
            Box::new(CountingSink {
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register b");
    let other = host
        .register(
            "attempt-a",
            Box::new(CountingSink {
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register a");
    let socket = root.path().join("source-attempts.sock");
    let mut endpoint =
        AttemptAdoptionEndpoint::bind(&socket, "daemon-source", 7, Arc::clone(&host))
            .expect("bind endpoint");
    endpoint.start().expect("start endpoint");
    let client = AttemptAdoptionClient::new(&socket, "daemon-source", 7).expect("client");

    let inventory = client.inventory().expect("inventory");
    assert_eq!(inventory.holder_id, "daemon-source");
    assert_eq!(inventory.lease_epoch, 7);
    assert_eq!(inventory.attempt_ids, ["attempt-a", "attempt-b"]);
    assert_eq!(
        client
            .cancel("attempt-a", "reload-cancel", 11)
            .expect("cancel"),
        DispatchOutcome::Delivered
    );
    assert_eq!(
        client
            .cancel("attempt-a", "reload-cancel", 11)
            .expect("replay"),
        DispatchOutcome::AlreadyDelivered
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    drop(other);
    assert_eq!(
        client.inventory().expect("updated inventory").attempt_ids,
        ["attempt-b"]
    );
    drop(registration);
    drop(endpoint);
    Arc::try_unwrap(host)
        .expect("endpoint and registrations released host")
        .dispose()
        .expect("dispose host");
}

#[test]
fn the_client_is_pinned_to_the_sources_exact_identity() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let host = Arc::new(
        DaemonAttemptHost::open(root.path().join("cancel.sqlite3")).expect("attempt host"),
    );
    let socket = root.path().join("source-attempts.sock");
    let mut endpoint =
        AttemptAdoptionEndpoint::bind(&socket, "daemon-source", 7, Arc::clone(&host))
            .expect("bind endpoint");
    endpoint.start().expect("start endpoint");

    let wrong = AttemptAdoptionClient::new(&socket, "daemon-source", 8).expect("client");
    assert!(matches!(
        wrong.inventory(),
        Err(AttemptAdoptionError::Protocol)
    ));

    drop(endpoint);
    Arc::try_unwrap(host)
        .expect("endpoint released host")
        .dispose()
        .expect("dispose host");
}

#[test]
fn concurrent_successors_still_reach_one_source_sink_once() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let host = Arc::new(
        DaemonAttemptHost::open(root.path().join("cancel.sqlite3")).expect("attempt host"),
    );
    let deliveries = Arc::new(AtomicUsize::new(0));
    let registration = host
        .register(
            "attempt-race",
            Box::new(CountingSink {
                deliveries: Arc::clone(&deliveries),
            }),
        )
        .expect("register");
    let socket = root.path().join("source-attempts.sock");
    let mut endpoint =
        AttemptAdoptionEndpoint::bind(&socket, "daemon-source", 7, Arc::clone(&host))
            .expect("bind endpoint");
    endpoint.start().expect("start endpoint");

    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            AttemptAdoptionClient::new(&socket, "daemon-source", 7)
                .expect("first client")
                .cancel("attempt-race", "ref-race", 1)
                .expect("first cancel")
        });
        let second = scope.spawn(|| {
            AttemptAdoptionClient::new(&socket, "daemon-source", 7)
                .expect("second client")
                .cancel("attempt-race", "ref-race", 1)
                .expect("second cancel")
        });
        [first.join().expect("first"), second.join().expect("second")]
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == DispatchOutcome::Delivered)
            .count(),
        1
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.is_delivery_evidence())
    );
    assert_eq!(deliveries.load(Ordering::Acquire), 1);

    drop(registration);
    drop(endpoint);
    Arc::try_unwrap(host)
        .expect("endpoint and registration released host")
        .dispose()
        .expect("dispose host");
}

/// A route whose socket was never bound, and one whose listener is gone,
/// are the only two failures that prove the route gone. Every other way the
/// route can fail to answer keeps the snapshot standing.
#[test]
fn only_an_absent_or_refused_socket_proves_the_route_gone() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let socket = root.path().join("source-attempts.sock");
    let adopted = AdoptedSourceAttempts {
        route: AttemptHostRoute {
            socket_path: socket.clone(),
            holder_id: "daemon-source".to_owned(),
            lease_epoch: 7,
        },
        attempt_ids: vec!["attempt-a".to_owned()],
    };

    // Never bound: ENOENT at connect.
    assert!(!socket.exists());
    assert!(matches!(
        adopted.probe("attempt-a"),
        SourceAttemptProbe::Gone
    ));
    assert!(matches!(
        adopted.probe("attempt-z"),
        SourceAttemptProbe::NotAdopted
    ));

    // Bound and abandoned: the file outlives the listener and the kernel
    // refuses the connect.
    drop(UnixListener::bind(&socket).expect("bind then abandon"));
    assert!(socket.exists());
    assert!(matches!(
        adopted.probe("attempt-a"),
        SourceAttemptProbe::Gone
    ));
    assert!(matches!(
        AttemptAdoptionClient::new(&socket, "daemon-source", 7)
            .expect("client")
            .cancel("attempt-a", "ref-gone", 1),
        Err(AttemptAdoptionError::RouteGone)
    ));
    fs::remove_file(&socket).expect("remove abandoned socket");

    // A listener that accepts and never answers: the client's own I/O
    // timeout, which is an `Io` failure and not a retirement.
    let silent = UnixListener::bind(&socket).expect("silent listener");
    let hold = std::thread::spawn(move || {
        let (stream, _) = silent.accept().expect("accept the probe");
        let mut request = String::new();
        let _ = BufReader::new(&stream).read_line(&mut request);
        std::thread::sleep(Duration::from_millis(2_500));
        drop(stream);
    });
    let started = Instant::now();
    let probe = adopted.probe("attempt-a");
    assert!(
        matches!(
            probe,
            SourceAttemptProbe::Unavailable(AttemptAdoptionError::Io(_))
        ),
        "{probe:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "the probe waited for the route's timeout, not for a close"
    );
    hold.join().expect("silent listener");
    fs::remove_file(&socket).expect("remove silent socket");

    // A listener that answers under another identity: a protocol violation.
    let foreign = UnixListener::bind(&socket).expect("foreign listener");
    let answer = std::thread::spawn(move || {
        let (mut stream, _) = foreign.accept().expect("accept the probe");
        let mut request = String::new();
        let _ = BufReader::new(stream.try_clone().expect("clone")).read_line(&mut request);
        stream
            .write_all(
                b"{\"schema\":\"automonique.attempt-adoption/v1\",\"holder_id\":\"someone-else\",\
                  \"lease_epoch\":7,\"answer\":\"inventory\",\"attempt_ids\":[]}\n",
            )
            .expect("foreign answer");
    });
    let probe = adopted.probe("attempt-a");
    assert!(
        matches!(
            probe,
            SourceAttemptProbe::Unavailable(AttemptAdoptionError::Protocol)
        ),
        "{probe:?}"
    );
    answer.join().expect("foreign listener");
    fs::remove_file(&socket).expect("remove foreign socket");

    // A listener that refuses in the source's own identity: the host could
    // not answer, which is not the host being gone.
    let refusing = UnixListener::bind(&socket).expect("refusing listener");
    let refuse = std::thread::spawn(move || {
        let (mut stream, _) = refusing.accept().expect("accept the probe");
        let mut request = String::new();
        let _ = BufReader::new(stream.try_clone().expect("clone")).read_line(&mut request);
        stream
            .write_all(
                b"{\"schema\":\"automonique.attempt-adoption/v1\",\"holder_id\":\"daemon-source\",\
                  \"lease_epoch\":7,\"answer\":\"refused\",\
                  \"category\":\"attempt_adoption_host_unavailable\"}\n",
            )
            .expect("refusal");
    });
    let probe = adopted.probe("attempt-a");
    assert!(
        matches!(
            probe,
            SourceAttemptProbe::Unavailable(AttemptAdoptionError::HostUnavailable)
        ),
        "{probe:?}"
    );
    refuse.join().expect("refusing listener");
    fs::remove_file(&socket).expect("remove refusing socket");

    // The real thing: a source endpoint at the pinned identity hosts it.
    let host = Arc::new(
        DaemonAttemptHost::open(root.path().join("cancel.sqlite3")).expect("attempt host"),
    );
    let mut endpoint =
        AttemptAdoptionEndpoint::bind(&socket, "daemon-source", 7, Arc::clone(&host))
            .expect("bind endpoint");
    endpoint.start().expect("start endpoint");
    assert!(matches!(
        adopted.probe("attempt-a"),
        SourceAttemptProbe::Hosted(_)
    ));
    // Retirement removes the socket, and only then is the route gone.
    drop(endpoint);
    assert!(!socket.exists());
    assert!(matches!(
        adopted.probe("attempt-a"),
        SourceAttemptProbe::Gone
    ));
    let _ = UnixStream::connect(&socket);
    Arc::try_unwrap(host)
        .expect("endpoint released host")
        .dispose()
        .expect("dispose host");
}
