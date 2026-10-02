// SPDX-License-Identifier: Elastic-2.0

//! The run lane negotiates against the daemon's host, not its own process.
//!
//! [`SocketRunLane`] composes a document inside whatever process holds it —
//! the daemon's own Telegram thread, or a separate client such as the hosted
//! dashboard. Only the daemon's execution lane runs the document, so only the
//! daemon's offered host features are the right thing to negotiate against. A
//! client that probed itself would, under a hardened service manager (which
//! places it in a user namespace), measure no enforcement at all and refuse
//! every run.
//!
//! Every test here stands a scripted peer on the lane's admin socket, so what
//! the "daemon" offers is fixed by the test and independent of this host:
//!
//! 1. [`the_lane_composes_against_the_features_the_daemon_reports`] offers a
//!    synthetic feature whose digest no local probe can produce, and asserts
//!    the submitted document requires exactly that feature. Composition
//!    succeeding *and* carrying the daemon's digest is what shows the lane
//!    used the daemon's answer rather than its own measurement.
//! 2. The remaining tests are the fail-closed cases: a daemon that predates
//!    the request (closes without answering), one that refuses it, one that
//!    answers with something else, one that offers nothing, and no daemon at
//!    all. Each must refuse the run before anything is submitted, and each
//!    but the empty offer must name its reason in
//!    [`SocketRunLane::host_features_refusal`].

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_daemon::RUN_INDEX_NAME;
use automonique_daemon::compose::{ANSWER_PLACEHOLDER, PROVIDER_CONFIG_NAME};
use automonique_daemon::run_lane::{HostFeaturesRefusal, SocketRunLane};
use automonique_daemon::telegram_bridge::{RunFailure, RunLane};
use automonique_protocol::admin::{
    AdminCommand, AdminRefusalCategory, AdminRequest, AdminResponse,
};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::sandbox::{HostFeature, ImplementationDigest};

const BUSYBOX: &str = "/usr/bin/busybox";

/// A digest no host probe produces: the probe's digests are SHA-256 over a
/// domain-separated statement, never a run of one repeated digit.
fn daemon_feature() -> HostFeature {
    HostFeature::new(
        "descendant_containment",
        ImplementationDigest::parse(&format!("sha256:{}", "7".repeat(64))).expect("digest"),
    )
    .expect("feature")
}

/// What the scripted daemon does with a `host_features` read.
#[derive(Clone)]
enum Answer {
    /// Answer with exactly this offer.
    Offer(Vec<HostFeature>),
    /// Answer with a typed refusal, as a daemon with no execution lane does.
    Refuse,
    /// Close without a byte, as a daemon that predates the request does with a
    /// kind it cannot decode.
    CloseSilently,
    /// Answer a different question.
    WrongKind,
    /// Answer with a valid offer correlated to some other request.
    Uncorrelated,
}

/// A private state tree with a provider and a destination policy, so the only
/// thing standing between a task and a composed document is the host offer.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let state_dir = root.path().join("state");
        std::fs::create_dir(&state_dir).expect("state directory");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        let home = state_dir.join("provider-home");
        std::fs::create_dir(&home).expect("provider home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .expect("private provider home");
        write_private(
            &state_dir.join(PROVIDER_CONFIG_NAME),
            &format!(
                "binary={BUSYBOX}\nhome={}\nversion=busybox-hermetic\n\
                 arg=sh\narg=-c\narg=true > {ANSWER_PLACEHOLDER}\n",
                home.display()
            ),
        );
        write_private(
            &state_dir.join("egress-destinations"),
            "127.0.0.1 1 loopback\n",
        );
        Self { root }
    }

    fn state_dir(&self) -> PathBuf {
        self.root.path().join("state")
    }

    fn admin_socket(&self) -> PathBuf {
        self.root.path().join("admin.sock")
    }

    fn lane(&self) -> SocketRunLane {
        SocketRunLane::open(
            &self.state_dir(),
            &self.admin_socket(),
            &self.state_dir().join(RUN_INDEX_NAME),
        )
        .expect("the run lane opens")
    }
}

fn write_private(path: &Path, body: &str) {
    std::fs::write(path, body).expect("configuration written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private configuration");
}

/// Everything the scripted daemon was asked, in order.
#[derive(Default)]
struct Seen {
    kinds: Vec<AdminCommand>,
    documents: Vec<Vec<u8>>,
}

/// A peer on the admin socket that answers by script and records every request.
struct ScriptedDaemon {
    seen: Arc<Mutex<Seen>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ScriptedDaemon {
    fn serve(socket: &Path, answer: Answer) -> Self {
        let listener = UnixListener::bind(socket).expect("bind the scripted admin socket");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let seen = Arc::clone(&seen);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => answer_one(stream, &answer, &seen),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                }
            })
        };
        Self {
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> Seen {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .expect("serving")
            .join()
            .expect("scripted daemon thread");
        std::mem::take(&mut *self.seen.lock().expect("record"))
    }
}

impl Drop for ScriptedDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn answer_one(mut stream: UnixStream, answer: &Answer, seen: &Mutex<Seen>) {
    stream.set_nonblocking(false).expect("blocking stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read deadline");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("request prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).expect("request body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&frame).expect("request frame") else {
        panic!("complete request was incomplete")
    };
    let request = AdminRequest::from_canonical_bytes(payload).expect("an admin request");
    {
        let mut seen = seen.lock().expect("record");
        seen.kinds.push(request.command());
        if let Some(submission) = request.run_submission() {
            seen.documents.push(submission.document().to_vec());
        }
    }
    let request_id = request.request_id().clone();
    let refused = |category: &str| AdminResponse::Refused {
        request_id: request_id.clone(),
        category: AdminRefusalCategory::new(category).expect("a category"),
    };
    let response = match (request.command(), answer) {
        (AdminCommand::HostFeatures, Answer::Offer(features)) => AdminResponse::HostFeatures {
            request_id: request_id.clone(),
            features: features.clone(),
        },
        (AdminCommand::HostFeatures, Answer::Refuse) => refused("execution_unavailable"),
        (AdminCommand::HostFeatures, Answer::CloseSilently) => return,
        (AdminCommand::HostFeatures, Answer::WrongKind) => AdminResponse::ShutdownAccepted {
            request_id: request_id.clone(),
        },
        (AdminCommand::HostFeatures, Answer::Uncorrelated) => AdminResponse::HostFeatures {
            request_id: RequestId::new("someone-else").expect("request ID"),
            features: vec![daemon_feature()],
        },
        // Custody is refused so nothing downstream of composition is needed:
        // reaching this arm at all is the evidence the document was composed.
        (AdminCommand::SubmitRun, _) => refused("intake_paused"),
        _ => refused("unexpected_request"),
    };
    let payload = response
        .to_message()
        .expect("encode response")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("frame response");
    stream.write_all(&frame).expect("write response");
}

#[test]
fn the_lane_composes_against_the_features_the_daemon_reports() {
    let fixture = Fixture::new();
    let daemon = ScriptedDaemon::serve(
        &fixture.admin_socket(),
        Answer::Offer(vec![daemon_feature()]),
    );
    let mut lane = fixture.lane();
    assert!(lane.configured());

    // Refused at custody, which is *after* composition: a lane that had
    // negotiated against an empty local probe would have stopped before
    // submitting anything and answered `Unavailable`.
    assert_eq!(
        lane.run("compose against the daemon"),
        Err(RunFailure::Refused)
    );
    assert_eq!(lane.host_features_refusal(), None);

    let seen = daemon.finish();
    assert_eq!(
        seen.kinds,
        [AdminCommand::HostFeatures, AdminCommand::SubmitRun],
        "the offer is read from the daemon before the document is composed"
    );
    let [document] = seen.documents.as_slice() else {
        panic!("exactly one document was submitted")
    };
    let document = String::from_utf8_lossy(document);
    let digest = daemon_feature().implementation().to_string();
    assert!(
        document.contains(&digest),
        "the composed document must require the implementation the daemon offered"
    );
    for local in automonique_daemon::execute::offered_host_features() {
        assert!(
            !document.contains(&local.implementation().to_string()),
            "the composed document must not carry this process's own measurement"
        );
    }
}

#[test]
fn a_fresh_offer_is_read_for_every_composition() {
    let fixture = Fixture::new();
    let daemon = ScriptedDaemon::serve(
        &fixture.admin_socket(),
        Answer::Offer(vec![daemon_feature()]),
    );
    let mut lane = fixture.lane();
    assert_eq!(lane.run("first"), Err(RunFailure::Refused));
    assert_eq!(lane.run("second"), Err(RunFailure::Refused));
    assert_eq!(
        daemon.finish().kinds,
        [
            AdminCommand::HostFeatures,
            AdminCommand::SubmitRun,
            AdminCommand::HostFeatures,
            AdminCommand::SubmitRun,
        ],
        "no offer is cached across runs, so a restarted daemon is never negotiated \
         against under its predecessor's answer"
    );
}

/// Run one task against a scripted answer and return the lane's verdict, its
/// recorded reason, and every request the daemon saw.
fn refused_run(
    answer: Answer,
) -> (
    Result<String, RunFailure>,
    Option<HostFeaturesRefusal>,
    Seen,
) {
    let fixture = Fixture::new();
    let daemon = ScriptedDaemon::serve(&fixture.admin_socket(), answer);
    let mut lane = fixture.lane();
    let outcome = lane.run("this must not be submitted");
    let refusal = lane.host_features_refusal();
    (outcome, refusal, daemon.finish())
}

/// A daemon built before the request existed closes the connection on a kind
/// it does not define. That is the deployed skew — a new web entry against an
/// older daemon — and it must refuse, never fall back to probing locally.
#[test]
fn a_daemon_that_predates_the_request_fails_closed() {
    let (outcome, refusal, seen) = refused_run(Answer::CloseSilently);
    assert_eq!(outcome, Err(RunFailure::Unavailable));
    assert_eq!(refusal, Some(HostFeaturesRefusal::Unsupported));
    assert_eq!(
        refusal.map(HostFeaturesRefusal::category),
        Some("daemon_host_features_unsupported")
    );
    assert_eq!(seen.kinds, [AdminCommand::HostFeatures]);
    assert!(seen.documents.is_empty(), "nothing may be submitted");
}

#[test]
fn a_daemon_that_refuses_the_read_fails_closed() {
    let (outcome, refusal, seen) = refused_run(Answer::Refuse);
    assert_eq!(outcome, Err(RunFailure::Unavailable));
    assert_eq!(refusal, Some(HostFeaturesRefusal::Refused));
    assert_eq!(seen.kinds, [AdminCommand::HostFeatures]);
}

#[test]
fn an_answer_to_a_different_question_fails_closed() {
    let (outcome, refusal, seen) = refused_run(Answer::WrongKind);
    assert_eq!(outcome, Err(RunFailure::Unavailable));
    assert_eq!(refusal, Some(HostFeaturesRefusal::Malformed));
    assert_eq!(seen.kinds, [AdminCommand::HostFeatures]);
}

/// An empty offer is a truthful answer — a daemon whose host enforces nothing
/// — so the read itself succeeded, and composition refuses it.
#[test]
fn a_daemon_offering_nothing_composes_nothing() {
    let (outcome, refusal, seen) = refused_run(Answer::Offer(Vec::new()));
    assert_eq!(outcome, Err(RunFailure::Unavailable));
    assert_eq!(refusal, None, "the read succeeded; the offer was empty");
    assert_eq!(seen.kinds, [AdminCommand::HostFeatures]);
    assert!(seen.documents.is_empty());
}

#[test]
fn no_daemon_at_all_fails_closed() {
    let fixture = Fixture::new();
    let mut lane = fixture.lane();
    assert_eq!(
        lane.run("nobody is listening"),
        Err(RunFailure::Unavailable)
    );
    assert_eq!(
        lane.host_features_refusal(),
        Some(HostFeaturesRefusal::Unreachable)
    );
}

/// The recorded reason describes the run that just returned, never an earlier
/// one.
#[test]
fn a_recorded_refusal_does_not_outlive_its_run() {
    let fixture = Fixture::new();
    let mut lane = fixture.lane();
    assert_eq!(
        lane.run("first, with no daemon"),
        Err(RunFailure::Unavailable)
    );
    assert!(lane.host_features_refusal().is_some());

    let daemon = ScriptedDaemon::serve(
        &fixture.admin_socket(),
        Answer::Offer(vec![daemon_feature()]),
    );
    assert_eq!(lane.run("second, answered"), Err(RunFailure::Refused));
    assert_eq!(lane.host_features_refusal(), None);
    drop(daemon);
}

/// An offer correlated to some other request is not this lane's answer.
#[test]
fn an_uncorrelated_offer_fails_closed() {
    let (outcome, refusal, seen) = refused_run(Answer::Uncorrelated);
    assert_eq!(outcome, Err(RunFailure::Unavailable));
    assert_eq!(refusal, Some(HostFeaturesRefusal::Malformed));
    assert_eq!(seen.kinds, [AdminCommand::HostFeatures]);
}
