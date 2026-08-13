// SPDX-License-Identifier: Elastic-2.0

#![cfg(target_os = "linux")]

//! Direct mechanism checks against the running kernel.
//!
//! Nothing here installs a filter on the test process itself, and nothing may
//! start doing so. A seccomp filter cannot be removed: one in-process
//! `apply_to_current_thread` would filter whichever test thread made the call
//! for the rest of the binary's life — and would set `no_new_privs` on it —
//! quietly changing the meaning of every test that ran afterwards. Enforcement
//! therefore only ever happens inside the `automonique-seccomp-probe`
//! subprocess, which exits immediately after reporting what the kernel did.
//!
//! The claims these tests are allowed to make are narrow on purpose. Denying
//! socket *creation* is not denying the network, so several tests below exist
//! to record what stays reachable, or what this host cannot distinguish, rather
//! than what is taken away.

use automonique_runner::seccomp::{
    IO_URING_SYSCALLS, MAX_ALLOWED_SHAPES, REQUIRED_TARGET_ARCH, SOCKET_TYPE_MASK, SocketDomain,
    SocketFamilyPolicy, SocketFilterError, SocketKind,
};
use nix::libc;
use std::path::Path;
use std::process::Command;

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_automonique-seccomp-probe"))
}

/// Run one probe mode and return its stdout.
fn probe(mode: &str) -> String {
    let output = Command::new(helper())
        .arg(mode)
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

fn assert_denied(report: &str, keys: &[&str]) {
    for key in keys {
        assert_field(report, key, "denied_eperm");
    }
}

fn assert_allowed(report: &str, keys: &[&str]) {
    for key in keys {
        assert_field(report, key, "allowed");
    }
}

/// One call the probe helper makes, and the arguments it makes it with.
///
/// The table is the same set of calls the helper issues, in the same spelling,
/// so a test can ask [`SocketFamilyPolicy::permits`] what *should* have
/// happened and compare it against what the kernel did.
struct Probe {
    label: &'static str,
    domain: i32,
    socket_type: i32,
    protocol: i32,
    is_pair: bool,
}

const CLOEXEC: i32 = libc::SOCK_CLOEXEC;
const NONBLOCK: i32 = libc::SOCK_NONBLOCK;

fn probe_table() -> Vec<Probe> {
    let call = |label, domain, socket_type, protocol| Probe {
        label,
        domain,
        socket_type,
        protocol,
        is_pair: false,
    };
    let pair = |label, domain, socket_type| Probe {
        label,
        domain,
        socket_type,
        protocol: 0,
        is_pair: true,
    };
    vec![
        call("unix_stream", libc::AF_UNIX, libc::SOCK_STREAM, 0),
        call(
            "unix_stream_cloexec",
            libc::AF_UNIX,
            libc::SOCK_STREAM | CLOEXEC,
            0,
        ),
        call(
            "unix_dgram_cloexec_nonblock",
            libc::AF_UNIX,
            libc::SOCK_DGRAM | CLOEXEC | NONBLOCK,
            0,
        ),
        call(
            "unix_seqpacket_cloexec",
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | CLOEXEC,
            0,
        ),
        call("inet_stream", libc::AF_INET, libc::SOCK_STREAM, 0),
        call(
            "inet_stream_cloexec_nonblock",
            libc::AF_INET,
            libc::SOCK_STREAM | CLOEXEC | NONBLOCK,
            0,
        ),
        call(
            "inet_stream_proto_tcp",
            libc::AF_INET,
            libc::SOCK_STREAM | CLOEXEC,
            libc::IPPROTO_TCP,
        ),
        call(
            "inet_stream_proto_udp",
            libc::AF_INET,
            libc::SOCK_STREAM | CLOEXEC,
            libc::IPPROTO_UDP,
        ),
        call(
            "inet_dgram_cloexec",
            libc::AF_INET,
            libc::SOCK_DGRAM | CLOEXEC,
            0,
        ),
        call(
            "inet_raw",
            libc::AF_INET,
            libc::SOCK_RAW | CLOEXEC,
            libc::IPPROTO_RAW,
        ),
        call(
            "inet6_stream_cloexec",
            libc::AF_INET6,
            libc::SOCK_STREAM | CLOEXEC,
            0,
        ),
        call(
            "inet6_dgram_cloexec",
            libc::AF_INET6,
            libc::SOCK_DGRAM | CLOEXEC,
            0,
        ),
        call(
            "netlink_raw",
            libc::AF_NETLINK,
            libc::SOCK_RAW | CLOEXEC,
            libc::NETLINK_ROUTE,
        ),
        call("packet_raw", libc::AF_PACKET, libc::SOCK_RAW | CLOEXEC, 0),
        call(
            "vsock_stream",
            libc::AF_VSOCK,
            libc::SOCK_STREAM | CLOEXEC,
            0,
        ),
        pair(
            "unix_socketpair_cloexec",
            libc::AF_UNIX,
            libc::SOCK_STREAM | CLOEXEC,
        ),
        pair("unix_socketpair_dgram", libc::AF_UNIX, libc::SOCK_DGRAM),
        pair(
            "inet_socketpair",
            libc::AF_INET,
            libc::SOCK_STREAM | CLOEXEC,
        ),
    ]
}

fn unix_policy() -> SocketFamilyPolicy {
    SocketFamilyPolicy::deny_all()
        .allowing_unix_sockets()
        .expect("unix policy")
}

fn tcp_policy() -> SocketFamilyPolicy {
    SocketFamilyPolicy::deny_all()
        .allowing_tcp_sockets()
        .expect("tcp policy")
}

/// Control run. Every claim about denial below is only meaningful because the
/// same probes, in the same process shape, without a filter, come back open.
///
/// This also fixes the vocabulary the denial tests depend on. Three probes fail
/// here for reasons that have nothing to do with policy, and they answer with
/// three errnos that are each distinct from `denied_eperm`:
/// `unsupported_eprotonosupport` for a stream socket asked to speak UDP,
/// `unsupported_eopnotsupp` for an `AF_INET` `socketpair`. A test that accepted
/// "the socket was not created" would have passed on those alone.
#[test]
fn without_the_filter_every_probe_creates_its_socket() {
    let report = probe("baseline");

    assert_allowed(
        &report,
        &[
            "unix_stream",
            "unix_stream_cloexec",
            "unix_dgram_cloexec_nonblock",
            "unix_seqpacket_cloexec",
            "inet_stream",
            "inet_stream_cloexec_nonblock",
            "inet_stream_proto_tcp",
            "inet_dgram_cloexec",
            "inet6_stream_cloexec",
            "inet6_dgram_cloexec",
            "netlink_raw",
            "unix_socketpair_cloexec",
            "unix_socketpair_dgram",
        ],
    );
    assert_field(
        &report,
        "inet_stream_proto_udp",
        "unsupported_eprotonosupport",
    );
    assert_field(&report, "inet_socketpair", "unsupported_eopnotsupp");
}

/// What this host cannot tell apart, recorded as fact rather than hidden.
///
/// Raw and packet sockets need `CAP_NET_RAW`, which this test process does not
/// have, so the kernel answers `EPERM` with or without a filter. The raw-socket
/// denial is therefore **not** demonstrated by the probe on this host: the
/// filtered runs below assert `denied_eperm` for them, and that assertion would
/// pass even if the filter permitted raw sockets. What carries the raw-socket
/// claim instead is `netlink_raw`, which is a `SOCK_RAW` socket that succeeds
/// unprivileged here, and the exhaustive clause tests in `src/seccomp.rs`.
#[test]
fn raw_socket_probes_are_capability_limited_on_this_host() {
    let report = probe("baseline");

    assert_denied(&report, &["inet_raw", "packet_raw"]);
    // The control that makes the raw-type claim testable at all.
    assert_field(&report, "netlink_raw", "allowed");
}

/// The core proof: with no shape granted, no socket call succeeds.
///
/// `netlink_raw` and `vsock_stream` carry the weight. Both succeed unfiltered
/// on this host, so their answering `denied_eperm` here is the policy talking
/// and not the environment. `inet_socketpair` is the third witness: it changes
/// answer from `unsupported_eopnotsupp` to `denied_eperm`, which means the
/// filter refused the call before the kernel could decline it on its own terms.
#[test]
fn deny_all_denies_every_socket_the_probe_can_ask_for() {
    let report = probe("deny-all");

    for probe in probe_table() {
        assert_field(&report, probe.label, "denied_eperm");
    }
}

/// A grant is a grant of exactly the shapes named, inside the domain as well as
/// across domains.
///
/// `unix_seqpacket_cloexec` is the interesting one: `AF_UNIX` is allowed, and
/// `SOCK_SEQPACKET` is still refused. That is the socket *type* clause working,
/// not the domain clause, and it is what a policy that leaned on the domain
/// alone would get wrong.
#[test]
fn a_unix_grant_covers_two_types_and_no_family_beyond_unix() {
    let report = probe("unix");

    assert_allowed(
        &report,
        &[
            "unix_stream",
            "unix_stream_cloexec",
            "unix_dgram_cloexec_nonblock",
        ],
    );
    assert_denied(&report, &["unix_seqpacket_cloexec"]);
    assert_denied(
        &report,
        &[
            "inet_stream",
            "inet_stream_cloexec_nonblock",
            "inet_dgram_cloexec",
            "inet6_stream_cloexec",
            "netlink_raw",
            "vsock_stream",
        ],
    );

    // Asking for seqpacket as well gets it, and nothing else moves.
    let widened = probe("unix-seqpacket");
    assert_allowed(&widened, &["unix_seqpacket_cloexec"]);
    assert_denied(&widened, &["inet_stream", "netlink_raw"]);
}

/// The masked type comparison, which is the detail a naive filter gets wrong.
///
/// `socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)` passes
/// `0x80801` in the type argument, not `1`. An equality test against
/// `SOCK_STREAM` classifies that as some unknown type and denies it — which
/// would break every Rust program, since the standard library always sets
/// `SOCK_CLOEXEC`. Both spellings must land on the same side of the policy.
#[test]
fn a_tcp_grant_allows_stream_sockets_with_cloexec_and_nonblock_set() {
    let report = probe("tcp");

    assert_allowed(
        &report,
        &[
            "inet_stream",
            "inet_stream_cloexec_nonblock",
            "inet_stream_proto_tcp",
            "inet6_stream_cloexec",
        ],
    );

    // The same masking must not accidentally let a flagged datagram socket
    // through: the flags are ignored, the type underneath them is not.
    assert_denied(&report, &["inet_dgram_cloexec", "inet6_dgram_cloexec"]);

    assert_eq!(
        SOCKET_TYPE_MASK & (libc::SOCK_STREAM | CLOEXEC | NONBLOCK).cast_unsigned(),
        libc::SOCK_STREAM.cast_unsigned(),
        "the published mask does not recover SOCK_STREAM from a flagged type"
    );
}

/// A TCP grant is not a grant of every `SOCK_STREAM` protocol.
///
/// `SOCK_STREAM` also reaches SCTP and MPTCP, which Landlock's TCP access
/// rights do not restrict. The probe cannot ask for those without a kernel
/// module for each, so it asks for the one non-TCP protocol that is always
/// present: `IPPROTO_UDP` on a stream socket. Unfiltered that answers
/// `unsupported_eprotonosupport` — the kernel rejecting a nonsense pairing —
/// and under the policy it answers `denied_eperm`, which is the protocol clause
/// refusing the call first.
#[test]
fn a_tcp_grant_does_not_carry_an_arbitrary_stream_protocol() {
    let report = probe("tcp");

    assert_field(&report, "inet_stream_proto_udp", "denied_eperm");
    assert_field(
        &probe("baseline"),
        "inet_stream_proto_udp",
        "unsupported_eprotonosupport",
    );

    let policy = tcp_policy();
    for protocol in [libc::IPPROTO_SCTP, 262, libc::IPPROTO_UDP] {
        assert!(
            !policy.permits(libc::AF_INET, libc::SOCK_STREAM, protocol),
            "protocol {protocol} came along with the TCP grant"
        );
    }
}

/// UDP stays denied under a TCP grant, which is the point of the module.
///
/// `crate::network`'s Landlock policy cannot reach UDP at all; this is the
/// mechanism that does, and it does it by refusing to create the socket.
#[test]
fn a_tcp_grant_leaves_udp_and_every_other_family_denied() {
    let report = probe("tcp");

    assert_denied(
        &report,
        &[
            "inet_dgram_cloexec",
            "inet6_dgram_cloexec",
            "netlink_raw",
            "vsock_stream",
            "unix_stream",
            "unix_stream_cloexec",
            "unix_dgram_cloexec_nonblock",
        ],
    );
}

/// The filter is a property of the process, not of the program that installed
/// it. A trusted helper can apply it and then `execv` the untrusted workload,
/// which is the only launch shape this module is built for.
///
/// The exec'd image runs the *whole* probe set, so this shows the exact policy
/// survived — not merely that something was still filtered. A filter that had
/// degraded to total denial after `execv` would fail this test on
/// `inet_stream`, and one that had been dropped would fail on `inet_dgram`.
#[test]
fn the_filter_survives_execv() {
    let report = probe("tcp-then-exec");

    assert!(
        report.contains("mode=post-exec-probe"),
        "probes did not run in the exec'd image:\n{report}"
    );
    assert_allowed(
        &report,
        &[
            "inet_stream",
            "inet_stream_cloexec_nonblock",
            "inet6_stream_cloexec",
        ],
    );
    assert_denied(
        &report,
        &[
            "inet_dgram_cloexec",
            "unix_stream",
            "netlink_raw",
            "inet_stream_proto_udp",
        ],
    );
}

/// `socketpair(2)` carries a domain argument and gets the same discipline.
///
/// Under a Unix grant the pair is created; under a TCP grant it is refused,
/// even though the same policy allows `AF_INET` *stream sockets*, because
/// `socketpair` can only ever produce an `AF_UNIX` pair and a policy that let
/// the call through on the strength of an unrelated grant would be describing
/// something other than what it enforces.
#[test]
fn socketpair_follows_the_domain_discipline_of_the_policy() {
    let unix = probe("unix");
    assert_allowed(&unix, &["unix_socketpair_cloexec", "unix_socketpair_dgram"]);
    assert_denied(&unix, &["inet_socketpair"]);

    let tcp = probe("tcp");
    assert_denied(
        &tcp,
        &[
            "unix_socketpair_cloexec",
            "unix_socketpair_dgram",
            "inet_socketpair",
        ],
    );

    assert!(unix_policy().permits_socketpair(libc::AF_UNIX, libc::SOCK_STREAM | CLOEXEC, 0));
    assert!(!tcp_policy().permits_socketpair(libc::AF_INET, libc::SOCK_STREAM | CLOEXEC, 0));
    assert!(
        tcp_policy().permits(libc::AF_INET, libc::SOCK_STREAM | CLOEXEC, 0),
        "the same shape must still be allowed for socket(2)"
    );
}

/// The predicate a supervisor reads before forking agrees with the kernel
/// afterwards.
///
/// [`SocketFamilyPolicy::permits`] exists so a caller can check that a policy
/// admits the sockets its workload needs *without* installing anything. That is
/// only worth having if it answers the same question the installed filter
/// answers, so every probe in every filtered mode is checked both ways.
#[test]
fn the_policy_predicate_agrees_with_the_installed_filter() {
    let modes = [
        ("deny-all", SocketFamilyPolicy::deny_all()),
        ("unix", unix_policy()),
        ("tcp", tcp_policy()),
        (
            "unix-and-tcp",
            unix_policy()
                .allowing_tcp_sockets()
                .expect("unix and tcp policy"),
        ),
    ];
    for (mode, policy) in modes {
        let report = probe(mode);
        for probe in probe_table() {
            let permitted = if probe.is_pair {
                policy.permits_socketpair(probe.domain, probe.socket_type, probe.protocol)
            } else {
                policy.permits(probe.domain, probe.socket_type, probe.protocol)
            };
            let expected = if permitted { "allowed" } else { "denied_eperm" };
            assert_field(&report, probe.label, expected);
        }
    }
}

/// Compilation is read-only.
///
/// A supervisor compiles before it forks, so this must not filter the caller.
/// If it ever did, this test process would be filtered from here on and the
/// rest of the suite would be measuring the wrong thing — so the compile is
/// followed by socket calls that must still succeed, including the UDP one that
/// every policy in this module denies.
#[test]
fn compiling_a_policy_does_not_filter_the_caller() {
    SocketFamilyPolicy::check_build_arch()
        .expect("this build must be x86_64 for the rest of this suite to mean anything");
    assert_eq!(REQUIRED_TARGET_ARCH, std::env::consts::ARCH);

    let compiled = tcp_policy().compile().expect("tcp policy compiles");
    assert!(compiled.instruction_count() > 0);

    std::net::UdpSocket::bind("127.0.0.1:0").expect("udp socket after compiling");
    std::os::unix::net::UnixDatagram::unbound().expect("unix socket after compiling");
}

/// Every policy denies `io_uring`, including ones that allow sockets.
///
/// `IORING_OP_SOCKET` creates a socket without ever issuing `socket(2)`, so a
/// filter that left `io_uring_setup` reachable would be bypassable in one step.
///
/// This is a structural check, not a behavioural one: driving a real
/// `io_uring_setup` needs either `unsafe` or a dependency the crate does not
/// have, so what is asserted here is that the compiled program carries a rule
/// chain for each of those syscall numbers — under both the native and the
/// `x32` spelling — and not that this kernel returned `EPERM` for one.
#[test]
fn every_policy_filters_io_uring_and_both_syscall_abis() {
    let policies = [SocketFamilyPolicy::deny_all(), unix_policy(), tcp_policy()];
    for policy in policies {
        let compiled = policy.compile().expect("policy compiles");
        let filtered = compiled.filtered_syscalls();

        for syscall in IO_URING_SYSCALLS {
            assert!(
                filtered.contains(&syscall),
                "io_uring syscall {syscall} is not filtered: {filtered:?}"
            );
            assert!(
                filtered.contains(&(syscall | 0x4000_0000)),
                "the x32 spelling of {syscall} is not filtered: {filtered:?}"
            );
        }
        for syscall in [libc::SYS_socket, libc::SYS_socketpair] {
            assert!(filtered.contains(&syscall), "{syscall} is not filtered");
            assert!(
                filtered.contains(&(syscall | 0x4000_0000)),
                "the x32 spelling of {syscall} is not filtered"
            );
        }
        // Nothing else is filtered: this is not a syscall allowlist, and a
        // filter that had quietly grown one would change what "unfiltered
        // syscall" means for every other module in this crate.
        assert_eq!(filtered.len(), 2 * (IO_URING_SYSCALLS.len() + 2));
    }
}

/// Grants are bounded, duplicate-free, and refused with a typed error.
#[test]
fn grants_are_bounded_and_duplicates_are_refused() {
    let duplicate = unix_policy().allowing_unix_sockets();
    assert!(
        matches!(
            duplicate,
            Err(SocketFilterError::DuplicateShape(
                SocketDomain::Unix,
                SocketKind::Stream
            ))
        ),
        "a duplicate grant was accepted"
    );

    assert!(SocketFamilyPolicy::deny_all().denies_all_socket_creation());
    assert_eq!(
        SocketFamilyPolicy::default(),
        SocketFamilyPolicy::deny_all(),
        "the default policy must be total denial"
    );
    assert!(!unix_policy().denies_all_socket_creation());
    assert_eq!(unix_policy().allowed_shapes().len(), 2);
    assert!(tcp_policy().allowed_shapes().len() <= MAX_ALLOWED_SHAPES);

    // The grant is readable back exactly as it was made, so a caller can report
    // what a run was given rather than what it asked for.
    let tcp = tcp_policy();
    let shape = &tcp.allowed_shapes()[0];
    assert_eq!(shape.domain(), SocketDomain::Inet);
    assert_eq!(shape.kind(), SocketKind::Stream);
    assert_eq!(shape.protocols(), [0, libc::IPPROTO_TCP.cast_unsigned()]);
}
