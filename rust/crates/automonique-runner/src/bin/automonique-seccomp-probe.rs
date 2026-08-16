// SPDX-License-Identifier: Elastic-2.0

//! Subprocess probe for `automonique_runner::seccomp`.
//!
//! A seccomp filter cannot be removed once installed, so a test process must
//! never apply one to itself: a single such call would silently change the
//! behaviour of every later test in the same binary, and applying also sets
//! `PR_SET_NO_NEW_PRIVS` for good. This helper exists so enforcement always
//! happens in a process that is about to exit anyway.
//!
//! It is a test fixture, not product code. It reports what the kernel did in
//! flat `key=value` lines and makes no judgement about whether an outcome is
//! correct; the assertions live in `tests/seccomp.rs`.
//!
//! Every probe goes through `nix`, not the standard library, because the point
//! is to reach socket families and types — raw, netlink, packet, vsock,
//! seqpacket — that `std::net` has no way to ask for. The `nix` wrappers are
//! safe functions, which matters in a crate that forbids `unsafe_code`.
//!
//! Usage: `automonique-seccomp-probe <mode>`.

use automonique_runner::seccomp::SocketFamilyPolicy;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket, socketpair};
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::ffi::CString;
use std::io::{self, IoSlice, IoSliceMut, Write as _};
use std::os::unix::ffi::OsStringExt as _;

/// Exit code for an argv this helper does not recognise exactly.
const REFUSED: i32 = 64;
/// Exit code for a mode whose filter was expected to install and did not.
const APPLY_FAILED: i32 = 65;

fn main() {
    std::process::exit(run());
}

enum Mode {
    /// No filter at all: the control for every denial claim below.
    Baseline,
    /// The same probes, reached by `execv` from a filtered parent.
    PostExecProbe,
    /// Deny every socket creation.
    DenyAll,
    /// `AF_UNIX` stream and datagram only.
    Unix,
    /// `AF_UNIX` stream, datagram, and seqpacket.
    UnixSeqpacket,
    /// IPv4 and IPv6 TCP only.
    Tcp,
    /// `AF_UNIX` and TCP together.
    UnixAndTcp,
    /// Apply the TCP policy, then `execv` this binary in `PostExecProbe`.
    TcpThenExec,
}

impl Mode {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "baseline" => Some(Self::Baseline),
            "post-exec-probe" => Some(Self::PostExecProbe),
            "deny-all" => Some(Self::DenyAll),
            "unix" => Some(Self::Unix),
            "unix-seqpacket" => Some(Self::UnixSeqpacket),
            "tcp" => Some(Self::Tcp),
            "unix-and-tcp" => Some(Self::UnixAndTcp),
            "tcp-then-exec" => Some(Self::TcpThenExec),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::PostExecProbe => "post-exec-probe",
            Self::DenyAll => "deny-all",
            Self::Unix => "unix",
            Self::UnixSeqpacket => "unix-seqpacket",
            Self::Tcp => "tcp",
            Self::UnixAndTcp => "unix-and-tcp",
            Self::TcpThenExec => "tcp-then-exec",
        }
    }

    /// The policy this mode installs, or `None` for the unfiltered controls.
    fn policy(&self) -> Option<Result<SocketFamilyPolicy, String>> {
        let policy = SocketFamilyPolicy::deny_all();
        Some(match self {
            Self::Baseline | Self::PostExecProbe => return None,
            Self::DenyAll => Ok(policy),
            Self::Unix => policy.allowing_unix_sockets().map_err(|e| e.to_string()),
            Self::UnixSeqpacket => policy
                .allowing_unix_sockets()
                .and_then(SocketFamilyPolicy::allowing_unix_seqpacket_sockets)
                .map_err(|e| e.to_string()),
            Self::Tcp | Self::TcpThenExec => {
                policy.allowing_tcp_sockets().map_err(|e| e.to_string())
            }
            Self::UnixAndTcp => policy
                .allowing_unix_sockets()
                .and_then(SocketFamilyPolicy::allowing_tcp_sockets)
                .map_err(|e| e.to_string()),
        })
    }
}

fn run() -> i32 {
    let arguments = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<String>, _>>();
    let Ok(arguments) = arguments else {
        return REFUSED;
    };
    let [mode] = arguments.as_slice() else {
        return REFUSED;
    };
    let Some(mode) = Mode::parse(mode) else {
        return REFUSED;
    };

    println!("mode={}", mode.name());
    if let Some(policy) = mode.policy() {
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => return refused(&error),
        };
        match policy.apply_to_current_thread() {
            Ok(enforced) => println!("instructions={}", enforced.instruction_count()),
            Err(error) => return refused(&error.to_string()),
        }
        println!("filter=applied");
    }

    if matches!(mode, Mode::TcpThenExec) {
        return exec_post_exec_probe();
    }
    probe_all();
    0
}

fn refused(error: &str) -> i32 {
    println!("apply_error={error}");
    APPLY_FAILED
}

/// Replace this image with an unfiltered probe run.
///
/// Whatever the probes report afterwards was decided by a seccomp filter that
/// outlived an `execv`, which is the shape a real workload launch has: a
/// trusted helper applies the filter and then becomes the untrusted program.
fn exec_post_exec_probe() -> i32 {
    let (Ok(program), Ok(())) = (std::env::current_exe(), io::stdout().flush()) else {
        return APPLY_FAILED;
    };
    let Ok(program) = CString::new(program.into_os_string().into_vec()) else {
        return APPLY_FAILED;
    };
    let arguments = [
        program.clone(),
        CString::new("post-exec-probe").unwrap_or_default(),
    ];
    // Returns only on failure.
    let _ = nix::unistd::execv(&program, &arguments);
    APPLY_FAILED
}

const CLOEXEC: SockFlag = SockFlag::SOCK_CLOEXEC;
const NONBLOCK: SockFlag = SockFlag::SOCK_NONBLOCK;
const PLAIN: SockFlag = SockFlag::empty();

/// Every probe, in one fixed order, whatever mode is running.
///
/// The set is chosen so that a denial can be told apart from an environmental
/// failure. `netlink_raw` and `inet_dgram` succeed unprivileged, so a
/// `denied_eperm` from them is the policy talking. `vsock_stream` and
/// `inet_socketpair` fail unfiltered with a *different* errno, so a change to
/// `denied_eperm` is also the policy talking. `inet_raw` and `packet_raw` need
/// `CAP_NET_RAW` and answer `denied_eperm` either way on an unprivileged host,
/// which is a fact `tests/seccomp.rs` records rather than a claim it makes.
fn probe_all() {
    // AF_UNIX, including the flag combinations a masked type test must survive.
    report(
        "unix_stream",
        AddressFamily::Unix,
        SockType::Stream,
        PLAIN,
        None,
    );
    report(
        "unix_stream_cloexec",
        AddressFamily::Unix,
        SockType::Stream,
        CLOEXEC,
        None,
    );
    report(
        "unix_dgram_cloexec_nonblock",
        AddressFamily::Unix,
        SockType::Datagram,
        CLOEXEC | NONBLOCK,
        None,
    );
    report(
        "unix_seqpacket_cloexec",
        AddressFamily::Unix,
        SockType::SeqPacket,
        CLOEXEC,
        None,
    );

    // AF_INET / AF_INET6.
    report(
        "inet_stream",
        AddressFamily::Inet,
        SockType::Stream,
        PLAIN,
        None,
    );
    report(
        "inet_stream_cloexec_nonblock",
        AddressFamily::Inet,
        SockType::Stream,
        CLOEXEC | NONBLOCK,
        None,
    );
    report(
        "inet_stream_proto_tcp",
        AddressFamily::Inet,
        SockType::Stream,
        CLOEXEC,
        Some(SockProtocol::Tcp),
    );
    report(
        "inet_stream_proto_udp",
        AddressFamily::Inet,
        SockType::Stream,
        CLOEXEC,
        Some(SockProtocol::Udp),
    );
    report(
        "inet_dgram_cloexec",
        AddressFamily::Inet,
        SockType::Datagram,
        CLOEXEC,
        None,
    );
    report(
        "inet_raw",
        AddressFamily::Inet,
        SockType::Raw,
        CLOEXEC,
        Some(SockProtocol::Raw),
    );
    report(
        "inet6_stream_cloexec",
        AddressFamily::Inet6,
        SockType::Stream,
        CLOEXEC,
        None,
    );
    report(
        "inet6_dgram_cloexec",
        AddressFamily::Inet6,
        SockType::Datagram,
        CLOEXEC,
        None,
    );

    // Families no policy in this module can allow at all.
    report(
        "netlink_raw",
        AddressFamily::Netlink,
        SockType::Raw,
        CLOEXEC,
        Some(SockProtocol::NetlinkRoute),
    );
    report(
        "packet_raw",
        AddressFamily::Packet,
        SockType::Raw,
        CLOEXEC,
        None,
    );
    report(
        "vsock_stream",
        AddressFamily::Vsock,
        SockType::Stream,
        CLOEXEC,
        None,
    );

    // socketpair(2), which carries the same domain argument.
    report_pair(
        "unix_socketpair_cloexec",
        AddressFamily::Unix,
        SockType::Stream,
        CLOEXEC,
    );
    report_pair(
        "unix_socketpair_dgram",
        AddressFamily::Unix,
        SockType::Datagram,
        PLAIN,
    );
    report_pair(
        "inet_socketpair",
        AddressFamily::Inet,
        SockType::Stream,
        CLOEXEC,
    );

    probe_process_inspection();
}

/// Exercise the cross-process interfaces against this process itself. The
/// unfiltered control succeeds without privileges, while every installed
/// policy must answer `EPERM` before the kernel examines the arguments.
fn probe_process_inspection() {
    let source = [b'x'];
    let mut read_target = [0_u8];
    let read_remote = [RemoteIoVec {
        base: source.as_ptr() as usize,
        len: source.len(),
    }];
    let mut read_local = [IoSliceMut::new(&mut read_target)];
    report_result(
        "process_vm_readv",
        process_vm_readv(Pid::this(), &mut read_local, &read_remote),
    );

    let mut write_target = [0_u8];
    let write_remote = [RemoteIoVec {
        base: write_target.as_mut_ptr() as usize,
        len: write_target.len(),
    }];
    let write_local = [IoSlice::new(&source)];
    report_result(
        "process_vm_writev",
        process_vm_writev(Pid::this(), &write_local, &write_remote),
    );

    // Last: an allowed PTRACE_TRACEME changes how a later exec would behave.
    // This fixture exits immediately after the probe, so that state is inert.
    report_result("ptrace", ptrace::traceme());
}

fn report_result<T>(label: &str, result: nix::Result<T>) {
    let outcome = match result {
        Ok(_) => "allowed".to_owned(),
        Err(errno) => name(errno),
    };
    println!("{label}={outcome}");
}

fn report(
    label: &str,
    domain: AddressFamily,
    socket_type: SockType,
    flags: SockFlag,
    protocol: Option<SockProtocol>,
) {
    let outcome = match socket(domain, socket_type, flags, protocol) {
        Ok(descriptor) => {
            drop(descriptor);
            "allowed".to_owned()
        }
        Err(errno) => name(errno),
    };
    println!("{label}={outcome}");
}

fn report_pair(label: &str, domain: AddressFamily, socket_type: SockType, flags: SockFlag) {
    let outcome = match socketpair(domain, socket_type, None, flags) {
        Ok(pair) => {
            drop(pair);
            "allowed".to_owned()
        }
        Err(errno) => name(errno),
    };
    println!("{label}={outcome}");
}

/// Name an outcome precisely enough that a test cannot conflate two of them.
///
/// A denial by policy, a refusal for want of a capability, and a family the
/// kernel does not implement are three different facts, and a test that
/// accepted any of them would prove nothing.
fn name(errno: Errno) -> String {
    match errno {
        Errno::EPERM => "denied_eperm".to_owned(),
        Errno::EACCES => "denied_eacces".to_owned(),
        Errno::EAFNOSUPPORT => "unsupported_eafnosupport".to_owned(),
        Errno::EPROTONOSUPPORT => "unsupported_eprotonosupport".to_owned(),
        Errno::EPROTOTYPE => "unsupported_eprototype".to_owned(),
        Errno::EOPNOTSUPP => "unsupported_eopnotsupp".to_owned(),
        Errno::EINVAL => "invalid_einval".to_owned(),
        other => format!("errno_{}", other as i32),
    }
}
