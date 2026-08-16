// SPDX-License-Identifier: Elastic-2.0

//! Subprocess probe for `automonique_runner::network`.
//!
//! `landlock_restrict_self` cannot be undone, so a test process must never
//! enforce a policy on itself: one such call would silently change the
//! behaviour of every later test in the same binary. This helper exists so
//! enforcement always happens in a process that is about to exit anyway.
//!
//! It is a test fixture, not product code. It reports what the kernel did in
//! flat `key=value` lines and makes no judgement about whether an outcome is
//! correct; the assertions live in `tests/network.rs`.
//!
//! Usage: `automonique-landlock-net-probe <mode> <open> <closed> <bind> <unix>`
//! where `open` is a TCP port with a live listener, `closed` is one with none,
//! `bind` is a free port, and `unix` is the path of a live `AF_UNIX` listener.

use automonique_runner::network::TcpBindConnectPolicy;
use std::ffi::CString;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

/// Exit code for an argv this helper does not recognise exactly.
const REFUSED: i32 = 64;
/// Exit code for a mode whose enforcement step was expected to succeed.
const ENFORCEMENT_FAILED: i32 = 65;
/// Bound on a connect that should resolve immediately on loopback either way.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on stacked Landlock domains, above the kernel's own layer ceiling.
const MAX_LAYERS: u32 = 64;
/// Payload written over a connection opened before enforcement.
const PREEXISTING_PAYLOAD: &[u8] = b"preexisting";
/// Second loopback address, used to show that a port exception is not scoped
/// to the address the caller had in mind.
const OTHER_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

fn main() {
    std::process::exit(run());
}

enum Mode {
    /// No policy at all: the control for every denial claim.
    Baseline,
    /// Same probes, reached by `execv` from a restricted parent.
    PostExecProbe,
    DenyAll,
    /// Deny-all except `connect` to the open port.
    AllowConnect,
    /// Deny-all except `bind` to the free port.
    AllowBind,
    /// Enforce deny-all, then `execv` this binary in `PostExecProbe`.
    DenyAllThenExec,
    /// Connect first, enforce second, write third.
    Preexisting,
    /// Stack domains until the kernel refuses, to reach the failure path.
    LayerExhaustion,
    /// Keep a sibling thread alive while enforcement is attempted.
    MultipleThreads,
}

impl Mode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "baseline" => Some(Self::Baseline),
            "post-exec-probe" => Some(Self::PostExecProbe),
            "deny-all" => Some(Self::DenyAll),
            "allow-connect" => Some(Self::AllowConnect),
            "allow-bind" => Some(Self::AllowBind),
            "deny-all-then-exec" => Some(Self::DenyAllThenExec),
            "preexisting" => Some(Self::Preexisting),
            "layer-exhaustion" => Some(Self::LayerExhaustion),
            "multiple-threads" => Some(Self::MultipleThreads),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::PostExecProbe => "post-exec-probe",
            Self::DenyAll => "deny-all",
            Self::AllowConnect => "allow-connect",
            Self::AllowBind => "allow-bind",
            Self::DenyAllThenExec => "deny-all-then-exec",
            Self::Preexisting => "preexisting",
            Self::LayerExhaustion => "layer-exhaustion",
            Self::MultipleThreads => "multiple-threads",
        }
    }
}

struct Targets {
    open_port: u16,
    closed_port: u16,
    bind_port: u16,
    unix_path: String,
}

fn run() -> i32 {
    let arguments = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<String>, _>>();
    let Ok(arguments) = arguments else {
        return REFUSED;
    };
    let [mode, open_port, closed_port, bind_port, unix_path] = arguments.as_slice() else {
        return REFUSED;
    };
    let (Some(mode), Ok(open_port), Ok(closed_port), Ok(bind_port)) = (
        Mode::parse(mode),
        open_port.parse::<u16>(),
        closed_port.parse::<u16>(),
        bind_port.parse::<u16>(),
    ) else {
        return REFUSED;
    };
    let targets = Targets {
        open_port,
        closed_port,
        bind_port,
        unix_path: unix_path.clone(),
    };

    println!("mode={}", mode.name());
    match mode {
        Mode::Baseline | Mode::PostExecProbe => {
            probe_all(&targets);
            0
        }
        Mode::DenyAll => enforce_then(TcpBindConnectPolicy::deny_all(), &targets),
        Mode::AllowConnect => {
            match TcpBindConnectPolicy::deny_all().allowing_connect_port(targets.open_port) {
                Ok(policy) => enforce_then(policy, &targets),
                Err(error) => enforcement_failed(&error),
            }
        }
        Mode::AllowBind => {
            match TcpBindConnectPolicy::deny_all().allowing_bind_port(targets.bind_port) {
                Ok(policy) => enforce_then(policy, &targets),
                Err(error) => enforcement_failed(&error),
            }
        }
        Mode::DenyAllThenExec => deny_all_then_exec(&targets),
        Mode::Preexisting => preexisting(&targets),
        Mode::LayerExhaustion => layer_exhaustion(),
        Mode::MultipleThreads => multiple_threads(),
    }
}

/// Prove enforcement refuses before installing a domain when any sibling
/// thread exists.
fn multiple_threads() -> i32 {
    let rendezvous = Arc::new(Barrier::new(2));
    let sibling = {
        let rendezvous = Arc::clone(&rendezvous);
        thread::spawn(move || rendezvous.wait())
    };

    let result = TcpBindConnectPolicy::deny_all().enforce_on_current_thread();
    rendezvous.wait();
    if sibling.join().is_err() {
        return ENFORCEMENT_FAILED;
    }
    match result {
        Err(error) => {
            println!("enforce_error={error}");
            0
        }
        Ok(_) => {
            println!("enforce_error=none");
            ENFORCEMENT_FAILED
        }
    }
}

/// Enforce `policy`, report the restriction, then run every probe under it.
fn enforce_then(policy: TcpBindConnectPolicy, targets: &Targets) -> i32 {
    match policy.enforce_on_current_thread() {
        Ok(enforced) => {
            println!("abi={}", enforced.landlock_abi().effective());
            println!(
                "erratum_tcp_identification_reported_fixed={}",
                enforced.tcp_identification_erratum_reported_fixed()
            );
            probe_all(targets);
            0
        }
        Err(error) => enforcement_failed(&error),
    }
}

fn enforcement_failed(error: &dyn std::fmt::Display) -> i32 {
    println!("enforce_error={error}");
    ENFORCEMENT_FAILED
}

/// Enforce, then replace this image with a plain probe run.
///
/// Whatever the probes report afterwards was decided by a Landlock domain that
/// outlived an `execv`, which is the shape a real workload launch has.
fn deny_all_then_exec(targets: &Targets) -> i32 {
    match TcpBindConnectPolicy::deny_all().enforce_on_current_thread() {
        Ok(enforced) => println!("abi={}", enforced.landlock_abi().effective()),
        Err(error) => return enforcement_failed(&error),
    }
    let (Ok(program), Ok(())) = (std::env::current_exe(), io::stdout().flush()) else {
        return ENFORCEMENT_FAILED;
    };
    let Ok(program) = CString::new(program.into_os_string().into_vec()) else {
        return ENFORCEMENT_FAILED;
    };
    let arguments = [
        program.clone(),
        cstring("post-exec-probe"),
        cstring(&targets.open_port.to_string()),
        cstring(&targets.closed_port.to_string()),
        cstring(&targets.bind_port.to_string()),
        cstring(&targets.unix_path),
    ];
    // Returns only on failure.
    let _ = nix::unistd::execv(&program, &arguments);
    ENFORCEMENT_FAILED
}

/// Open a connection, then enforce, then use the connection.
fn preexisting(targets: &Targets) -> i32 {
    let stream = TcpStream::connect_timeout(&loopback(targets.open_port), CONNECT_TIMEOUT);
    println!("preexisting_tcp_connect={}", outcome(&stream));
    let Ok(mut stream) = stream else {
        return ENFORCEMENT_FAILED;
    };
    match TcpBindConnectPolicy::deny_all().enforce_on_current_thread() {
        Ok(enforced) => println!("abi={}", enforced.landlock_abi().effective()),
        Err(error) => return enforcement_failed(&error),
    }
    let written = stream
        .write_all(PREEXISTING_PAYLOAD)
        .and_then(|()| stream.flush());
    println!("preexisting_tcp_write={}", outcome(&written));
    // Closing the stream lets the reader on the other side see end of file.
    drop(stream);
    0
}

/// Stack deny-all domains until the kernel refuses one.
///
/// This reaches the enforcement failure path on a kernel that supports
/// everything this module asks for, which is the only way to observe that a
/// refused restriction is reported as a typed error rather than as a success
/// with weaker properties.
fn layer_exhaustion() -> i32 {
    for layer in 1..=MAX_LAYERS {
        if let Err(error) = TcpBindConnectPolicy::deny_all().enforce_on_current_thread() {
            println!("layers_applied={}", layer - 1);
            println!("enforce_error={error}");
            return 0;
        }
    }
    println!("layers_applied={MAX_LAYERS}");
    println!("enforce_error=none");
    0
}

fn probe_all(targets: &Targets) {
    println!(
        "tcp_connect_open={}",
        outcome(&TcpStream::connect_timeout(
            &loopback(targets.open_port),
            CONNECT_TIMEOUT
        ))
    );
    println!(
        "tcp_connect_closed={}",
        outcome(&TcpStream::connect_timeout(
            &loopback(targets.closed_port),
            CONNECT_TIMEOUT
        ))
    );
    println!(
        "tcp_connect_other_address={}",
        outcome(&TcpStream::connect_timeout(
            &SocketAddr::from((OTHER_LOOPBACK, targets.open_port)),
            CONNECT_TIMEOUT
        ))
    );
    println!(
        "tcp_bind={}",
        outcome(&TcpListener::bind(loopback(targets.bind_port)))
    );
    let udp = UdpSocket::bind(loopback(0));
    println!("udp_bind={}", outcome(&udp));
    let sent = match &udp {
        Ok(socket) => socket.send_to(b"probe", loopback(targets.closed_port)),
        Err(_) => Err(io::Error::from(io::ErrorKind::NotConnected)),
    };
    println!("udp_send={}", outcome(&sent));
    println!(
        "unix_connect={}",
        outcome(&UnixStream::connect(&targets.unix_path))
    );
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn cstring(value: &str) -> CString {
    // Every caller passes a port number or a path this test fixture created,
    // neither of which can contain an interior NUL.
    CString::new(value).unwrap_or_default()
}

/// Name an outcome precisely enough that a test cannot conflate two of them.
///
/// A denial by policy and a refusal by the peer are different facts about the
/// kernel, and a test that accepted either would prove nothing.
fn outcome<T>(result: &io::Result<T>) -> String {
    match result {
        Ok(_) => "allowed".to_owned(),
        Err(error) => match error.raw_os_error() {
            Some(nix::libc::EACCES) => "denied_eacces".to_owned(),
            Some(nix::libc::EPERM) => "denied_eperm".to_owned(),
            Some(nix::libc::ECONNREFUSED) => "refused_econnrefused".to_owned(),
            Some(nix::libc::EADDRINUSE) => "in_use_eaddrinuse".to_owned(),
            Some(code) => format!("errno_{code}"),
            None => format!("error_{:?}", error.kind()),
        },
    }
}
