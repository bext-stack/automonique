// SPDX-License-Identifier: Elastic-2.0

#![cfg(target_os = "linux")]

//! Direct mechanism checks against the running kernel.
//!
//! Nothing here enforces a policy on the test process itself, and nothing may
//! start doing so. `landlock_restrict_self` is irreversible and thread-local:
//! one in-process call would restrict whichever test thread made it for the
//! rest of the binary's life, quietly changing the meaning of every test that
//! ran afterwards. Enforcement therefore only ever happens inside the
//! `automonique-landlock-net-probe` subprocess, which exits immediately after
//! reporting what the kernel did.
//!
//! The claims these tests are allowed to make are narrow on purpose. Denying
//! TCP `bind` and `connect` is not denying the network, so several tests below
//! exist to record what stays reachable rather than what is taken away.

use automonique_runner::network::{MAX_ALLOWED_PORTS, TcpBindConnectPolicy, TcpPolicyError};
use std::fs;
use std::io::Read as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_automonique-landlock-net-probe"))
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A free ephemeral port, released before it is handed out.
///
/// Nothing stops the kernel from reusing it in the meantime, so every test that
/// depends on a port being closed asserts that fact instead of assuming it: a
/// collision shows up as a failed assertion, never as a test that passed for
/// the wrong reason.
fn free_port() -> u16 {
    let listener = TcpListener::bind(loopback(0)).expect("reserve port");
    listener.local_addr().expect("reserved address").port()
}

/// Live endpoints for one probe run: an open TCP port, a closed one, a free one
/// to bind, and a live `AF_UNIX` listener.
struct Endpoints {
    open: TcpListener,
    open_port: u16,
    closed_port: u16,
    bind_port: u16,
    directory: PathBuf,
    unix_path: PathBuf,
    _unix: UnixListener,
}

impl Endpoints {
    fn new() -> Self {
        let open = TcpListener::bind(loopback(0)).expect("open listener");
        let open_port = open.local_addr().expect("open address").port();
        let directory = std::env::temp_dir().join(format!(
            "automonique-network-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("probe directory");
        let unix_path = directory.join("probe.sock");
        let unix = UnixListener::bind(&unix_path).expect("unix listener");
        Self {
            open,
            open_port,
            closed_port: free_port(),
            bind_port: free_port(),
            directory,
            unix_path,
            _unix: unix,
        }
    }

    /// Run one probe mode against these endpoints and return its stdout.
    fn probe(&self, mode: &str) -> String {
        let output = Command::new(helper())
            .args([
                mode,
                &self.open_port.to_string(),
                &self.closed_port.to_string(),
                &self.bind_port.to_string(),
            ])
            .arg(&self.unix_path)
            .env_clear()
            .output()
            .expect("execute probe helper");
        let stdout = String::from_utf8(output.stdout).expect("utf8 probe report");
        assert!(
            output.status.success(),
            "probe {mode} failed: status {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
    }
}

impl Drop for Endpoints {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.unix_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

/// First value reported for `key`, or a failure naming the whole report.
fn field<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("probe report has no {key}:\n{report}"))
}

fn assert_field(report: &str, key: &str, expected: &str) {
    assert_eq!(
        field(report, key),
        expected,
        "unexpected {key} in report:\n{report}"
    );
}

/// Control run. Every claim about denial below is only meaningful because the
/// same probes, on the same endpoints, without the policy, come back open.
///
/// This also fixes the vocabulary the denial tests depend on: an unreachable
/// port answers `refused_econnrefused`, which is a different fact from
/// `denied_eacces` and must never be accepted in its place.
#[test]
fn without_the_policy_every_probe_reaches_the_network() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("baseline");

    assert_field(&report, "tcp_connect_open", "allowed");
    assert_field(&report, "tcp_connect_closed", "refused_econnrefused");
    assert_field(&report, "tcp_connect_other_address", "refused_econnrefused");
    assert_field(&report, "tcp_bind", "allowed");
    assert_field(&report, "udp_bind", "allowed");
    assert_field(&report, "udp_send", "allowed");
    assert_field(&report, "unix_connect", "allowed");
}

/// The core proof: TCP connect is denied by policy.
///
/// The closed-port probe carries the weight. Without the policy that port
/// answers `refused_econnrefused`; under the policy it answers `denied_eacces`.
/// A test that accepted "the connection did not happen" would have passed on
/// the refusal alone and proved nothing about Landlock.
#[test]
fn deny_all_policy_denies_tcp_connect_including_a_port_that_would_be_refused() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("deny-all");

    assert_field(&report, "tcp_connect_open", "denied_eacces");
    assert_field(&report, "tcp_connect_closed", "denied_eacces");
    assert_field(&report, "tcp_connect_other_address", "denied_eacces");

    let abi: u8 = field(&report, "abi").parse().expect("reported abi");
    assert!(abi >= 4, "TCP rules need ABI 4 or later, got {abi}");
}

#[test]
fn deny_all_policy_denies_tcp_bind() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("deny-all");

    assert_field(&report, "tcp_bind", "denied_eacces");
}

/// The restriction is a property of the process, not of the program that
/// installed it. A trusted helper can enforce and then `execv` the untrusted
/// workload, which is the only launch shape this module is built for.
#[test]
fn deny_all_policy_outlives_execv() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("deny-all-then-exec");

    assert!(
        report.contains("mode=post-exec-probe"),
        "probes did not run in the exec'd image:\n{report}"
    );
    assert_field(&report, "tcp_connect_open", "denied_eacces");
    assert_field(&report, "tcp_connect_closed", "denied_eacces");
    assert_field(&report, "tcp_bind", "denied_eacces");
}

/// The scope limit, recorded as fact rather than as a comment.
///
/// Landlock ABI 4 knows about TCP bind and TCP connect and about nothing else,
/// so a workload under a "deny all" policy still has UDP and `AF_UNIX` in full.
/// If a future change made this test fail by denying more, that would be good
/// news and the module documentation would be the thing to correct.
#[test]
fn uncovered_udp_and_unix_paths_remain_open_under_the_policy() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("deny-all");

    assert_field(&report, "udp_bind", "allowed");
    assert_field(&report, "udp_send", "allowed");
    assert_field(&report, "unix_connect", "allowed");
}

/// The second scope limit: Landlock hooks `connect(2)`, not the data path.
///
/// A connection opened before enforcement keeps working afterwards, and the
/// bytes really arrive. The same holds for a socket inherited across `execv`,
/// which is why descriptor closure is a prerequisite for this module meaning
/// anything against a workload that was handed a live socket.
#[test]
fn a_connection_opened_before_enforcement_keeps_carrying_bytes() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("preexisting");

    assert_field(&report, "preexisting_tcp_connect", "allowed");
    assert_field(&report, "preexisting_tcp_write", "allowed");

    // The helper has already exited, so the connection and its payload are
    // waiting in the accept queue and this cannot block.
    let (mut stream, _) = endpoints.open.accept().expect("accept preexisting");
    let mut delivered = Vec::new();
    stream.read_to_end(&mut delivered).expect("read payload");
    assert_eq!(
        delivered, b"preexisting",
        "the pre-existing connection delivered nothing"
    );
}

/// A port exception is a port, not an endpoint.
///
/// Allowing connect to the open port also allows connecting to that port on a
/// different address: `tcp_connect_other_address` stops answering
/// `denied_eacces` and starts answering `refused_econnrefused`, which means the
/// kernel let the attempt through and the far side declined it. ABI 4 has no
/// address-scoped rule, and this test exists so nobody can believe otherwise.
#[test]
fn an_allowed_connect_port_is_allowed_on_every_address() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("allow-connect");

    assert_field(&report, "tcp_connect_open", "allowed");
    assert_field(&report, "tcp_connect_other_address", "refused_econnrefused");
    // The exception is exact: no other port, and no direction, comes with it.
    assert_field(&report, "tcp_connect_closed", "denied_eacces");
    assert_field(&report, "tcp_bind", "denied_eacces");
}

#[test]
fn an_allowed_bind_port_does_not_widen_connect() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("allow-bind");

    assert_field(&report, "tcp_bind", "allowed");
    assert_field(&report, "tcp_connect_open", "denied_eacces");
    assert_field(&report, "tcp_connect_closed", "denied_eacces");
}

/// The fail-closed path, reached for real.
///
/// This kernel supports everything the module asks for, so the only honest way
/// to reach a refused enforcement is to make the kernel refuse: Landlock caps a
/// thread at 16 stacked domains, and the next `restrict_self` fails. The result
/// must be a typed error. A weaker success — reporting an enforced restriction
/// that the kernel declined to install — is the one outcome this module exists
/// to make impossible.
#[test]
fn refused_enforcement_is_a_typed_error_not_a_weaker_success() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("layer-exhaustion");

    let error = field(&report, "enforce_error");
    assert_ne!(
        error, "none",
        "the kernel never refused a stacked domain:\n{report}"
    );
    assert!(
        error.starts_with("the Landlock ruleset was refused"),
        "refusal was not the typed ruleset error: {error}"
    );
    let applied: u32 = field(&report, "layers_applied")
        .parse()
        .expect("applied layer count");
    assert!(
        applied > 0,
        "no layer was installed before the refusal:\n{report}"
    );
}

#[test]
fn a_multi_threaded_caller_is_refused_rather_than_half_restricted() {
    let endpoints = Endpoints::new();
    let report = endpoints.probe("multiple-threads");

    assert_field(
        &report,
        "enforce_error",
        "the caller has more than one thread; a Landlock policy would cover only one",
    );
}

/// Policy construction refuses in-process, before any kernel call.
///
/// Port 0 is the important one: the kernel reads a bind rule for port 0 as the
/// whole `ip_local_port_range`, so accepting it would grant far more than the
/// caller asked for while looking like a single narrow exception.
#[test]
fn port_exceptions_are_bounded_and_reject_the_ephemeral_wildcard() {
    let ephemeral = TcpBindConnectPolicy::deny_all().allowing_bind_port(0);
    assert!(
        matches!(ephemeral, Err(TcpPolicyError::EphemeralPortRefused)),
        "port 0 was not refused"
    );
    let ephemeral_connect = TcpBindConnectPolicy::deny_all().allowing_connect_port(0);
    assert!(matches!(
        ephemeral_connect,
        Err(TcpPolicyError::EphemeralPortRefused)
    ));

    let duplicate = TcpBindConnectPolicy::deny_all()
        .allowing_connect_port(443)
        .and_then(|policy| policy.allowing_connect_port(443));
    assert!(
        matches!(duplicate, Err(TcpPolicyError::DuplicateAllowedPort(443))),
        "a duplicate port was accepted"
    );

    let mut policy = TcpBindConnectPolicy::deny_all();
    for offset in 0..MAX_ALLOWED_PORTS {
        let port = u16::try_from(1024 + offset).expect("port fits");
        policy = policy.allowing_connect_port(port).expect("within bound");
    }
    assert_eq!(policy.allowed_connect_ports().len(), MAX_ALLOWED_PORTS);
    assert!(!policy.denies_all_tcp());
    assert!(matches!(
        policy.allowing_connect_port(9999),
        Err(TcpPolicyError::TooManyAllowedPorts)
    ));

    assert!(TcpBindConnectPolicy::deny_all().denies_all_tcp());
    assert_eq!(
        TcpBindConnectPolicy::default(),
        TcpBindConnectPolicy::deny_all(),
        "the default policy must be total denial"
    );
}

/// The pre-flight check is read-only.
///
/// A supervisor calls this before forking, so it must not restrict the caller.
/// If it ever did, this test process would be restricted from here on and the
/// rest of the suite would be measuring the wrong thing — so the check is
/// followed by a bind and a connect that must still succeed.
#[test]
fn kernel_support_check_does_not_restrict_the_caller() {
    TcpBindConnectPolicy::check_kernel_support().expect(
        "this host must support Landlock ABI 4 for the rest of this suite to mean anything",
    );

    let listener = TcpListener::bind(loopback(0)).expect("bind after support check");
    let address = listener.local_addr().expect("bound address");
    TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).expect("connect after support check");
}
