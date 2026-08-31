// SPDX-License-Identifier: Elastic-2.0

//! Where a pinned program's bytes are read, proved against a live daemon.
//!
//! The unit proofs in `automonique_daemon::program_digest` establish what an
//! observation is and when it is reused. What they cannot establish is that
//! this daemon actually asks for one *before* a request needs it — that is
//! wiring, and wiring is only true where it is wired. Both proofs here count
//! reads rather than time them: a timing assertion on a shared host would be a
//! claim about the runner, and the claim being made is about which thread did
//! the work.
//!
//! # Anti-vacuity
//!
//! Each proof is paired with the deployment that must observe *nothing*: a
//! daemon with no provider configured, and the count before the submission is
//! served. A build that observed everything, or nothing, fails one of them.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use automonique_daemon::compose::{
    ANSWER_PLACEHOLDER, CompositionInputs, PROVIDER_CONFIG_NAME, ProviderConfig, compose,
};
use automonique_daemon::execute::{MAX_PROVIDER_BINARY_BYTES, offered_host_features};
use automonique_daemon::program_digest::ProgramDigests;
use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminRequest, AdminResponse, SubmittedRunSpec};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::sandbox::{HostFeature, ImplementationDigest};

#[path = "support/isolation.rs"]
mod test_isolation;

const BUSYBOX: &str = "/usr/bin/busybox";
/// Bound on waiting for the observer thread. Generous, because the assertion is
/// about which thread read the file and not about how quickly it did.
const OBSERVED_DEADLINE: Duration = Duration::from_secs(30);

// --- fixtures -------------------------------------------------------------

struct Fixture {
    _root: tempfile::TempDir,
    config: DaemonConfig,
}

impl Fixture {
    /// A private state tree, with a provider configuration only when asked for.
    fn new(provider: Option<&str>) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let runtime = root.path().join("runtime");
        test_isolation::assert_isolated_runtime_root(&runtime);
        let state = root.path().join("state");
        for directory in [&runtime, &state] {
            std::fs::create_dir(directory).expect("root");
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("private root");
        }
        let state_dir = state.join("automonique");
        std::fs::create_dir(&state_dir).expect("state directory");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        if let Some(body) = provider {
            write_private(&state_dir.join(PROVIDER_CONFIG_NAME), body);
        }
        Self {
            _root: root,
            config: DaemonConfig {
                runtime_root: runtime,
                state_root: state,
            },
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.config.state_dir()
    }

    /// The isolated home every provider configuration names, created so the
    /// configuration describes something that exists.
    fn provider_home(&self) -> PathBuf {
        let home = self.state_dir().join("provider-home");
        if !home.exists() {
            std::fs::create_dir(&home).expect("provider home");
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                .expect("private provider home");
        }
        home
    }
}

fn write_private(path: &Path, body: &str) {
    std::fs::write(path, body).expect("configuration written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("private configuration");
}

/// A provider configuration naming busybox, which every host in this suite has.
///
/// The invocation is spelled out rather than defaulted because the default is
/// `codex exec`, which `load_execution` refuses as retired — and this suite
/// needs a configuration a live daemon will actually load.
fn busybox_provider(home: &Path) -> String {
    format!(
        "binary={BUSYBOX}\nhome={}\nversion=busybox-hermetic\narg=sh\narg=-c\narg={{ {BUSYBOX} cat; }} > {ANSWER_PLACEHOLDER}\n",
        home.display()
    )
}

/// What this host offers, or one synthetic feature on a host that offers
/// nothing — `compose` refuses an empty negotiation, and this suite is not
/// about the negotiation.
fn features() -> Vec<HostFeature> {
    let offered = offered_host_features();
    if offered.is_empty() {
        vec![
            HostFeature::new(
                "descendant_containment",
                ImplementationDigest::parse(&format!("sha256:{}", "3".repeat(64))).expect("digest"),
            )
            .expect("feature"),
        ]
    } else {
        offered
    }
}

/// Wait until the daemon has read and hashed at least `reads` programs.
fn await_reads(programs: &Arc<ProgramDigests>, reads: usize, what: &str) {
    let deadline = Instant::now() + OBSERVED_DEADLINE;
    while programs.reads() < reads {
        assert!(
            Instant::now() < deadline,
            "{what}: {} programs were read, not {reads}",
            programs.reads()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

// --- the proofs -----------------------------------------------------------

/// A deployment's configured provider is observed while the daemon is opening,
/// so the first launch does not read it on the accept thread.
///
/// The paired negative is in the same test: a daemon with no provider
/// configured has nothing to observe and observes nothing, which is what makes
/// the positive a reading of the configuration rather than of a build that
/// hashes something on every start.
#[test]
fn a_configured_provider_is_observed_while_the_daemon_opens() {
    let unconfigured = Fixture::new(None);
    let bare = Daemon::open(&unconfigured.config).expect("a daemon with no provider opens");
    let bare_programs = Arc::clone(bare.program_digests());
    drop(bare);
    assert_eq!(
        bare_programs.reads(),
        0,
        "a deployment that configured no provider read a program anyway"
    );

    let fixture = Fixture::new(None);
    let home = fixture.provider_home();
    write_private(
        &fixture.state_dir().join(PROVIDER_CONFIG_NAME),
        &busybox_provider(&home),
    );
    let daemon = Daemon::open(&fixture.config).expect("a configured daemon opens");
    let programs = Arc::clone(daemon.program_digests());
    await_reads(&programs, 1, "the configured provider");

    // The observation is reusable, which is the whole point of having made it:
    // asking for the same program now costs no read at all.
    let digest = programs
        .digest(Path::new(BUSYBOX), MAX_PROVIDER_BINARY_BYTES)
        .expect("the configured provider was observed");
    assert!(digest.starts_with("sha256:"));
    assert_eq!(
        programs.reads(),
        1,
        "the observation the opener made was not the one a caller gets"
    );
}

/// A submitted document's program is observed when custody accepts it, not
/// when somebody asks for the run to start.
///
/// No provider is configured here on purpose: the count is zero until the
/// submission is served, so the read this asserts can only be the submission's.
#[test]
fn a_submitted_documents_program_is_observed_before_any_start() {
    let fixture = Fixture::new(None);
    let home = fixture.provider_home();
    // Loaded from beside the daemon's own configuration path rather than from
    // it, so `Daemon::open` prefetches nothing and the only read this test can
    // observe is the one the submission asked for.
    let provider_path = fixture.state_dir().join("provider-for-composition");
    write_private(&provider_path, &busybox_provider(&home));
    let provider = ProviderConfig::load(&provider_path)
        .expect("the provider configuration parses")
        .expect("a provider is configured");

    let composition = compose(
        "observe the program this document pins",
        &CompositionInputs {
            state_dir: &fixture.state_dir(),
            run_id: "program-observation-1",
            provider: &provider,
            offered_features: &features(),
            egress_configured: true,
        },
    )
    .expect("the task composes");

    let daemon = Daemon::open(&fixture.config).expect("daemon opens");
    let programs = Arc::clone(daemon.program_digests());
    assert_eq!(
        programs.reads(),
        0,
        "a daemon with no configured provider read a program at open"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let serving = Serving::start(daemon, &fixture.config, &stop);

    let submission = SubmittedRunSpec::sealed(composition.document().to_vec(), "observation-key")
        .expect("bounded submission");
    let response = admin(
        &fixture.config,
        AdminRequest::submit_run(
            RequestId::new("observation-submit").expect("request ID"),
            submission,
        ),
    );
    assert!(
        matches!(response, AdminResponse::RunAccepted { replay: false, .. }),
        "expected acceptance, got {response:?}"
    );

    await_reads(&programs, 1, "the submitted document's program");
    let digest = programs
        .digest(Path::new(BUSYBOX), MAX_PROVIDER_BINARY_BYTES)
        .expect("the submitted program was observed");
    assert!(digest.starts_with("sha256:"));
    assert_eq!(
        programs.reads(),
        1,
        "the submission's observation was not the one a start would reuse"
    );

    drop(serving);
}

// --- serving --------------------------------------------------------------

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

impl Serving {
    fn start(daemon: Daemon, config: &DaemonConfig, stop: &Arc<AtomicBool>) -> Self {
        let thread_stop = Arc::clone(stop);
        let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
        let deadline = Instant::now() + Duration::from_secs(15);
        while !config.admin_socket().exists() {
            assert!(Instant::now() < deadline, "daemon did not bind");
            std::thread::sleep(Duration::from_millis(5));
        }
        Self {
            stop: Arc::clone(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn admin(config: &DaemonConfig, request: AdminRequest) -> AdminResponse {
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("read deadline");
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
    AdminResponse::from_canonical_bytes(payload).expect("admitted response")
}
