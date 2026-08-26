// SPDX-License-Identifier: Elastic-2.0

//! Socket **creation** restriction for an untrusted workload, via a seccomp-bpf
//! filter on the arguments of `socket(2)` and `socketpair(2)`.
//!
//! # This is not network denial, and it is not socket denial
//!
//! A seccomp filter sees syscall numbers and register values, nothing else. It
//! decides whether a *call* is allowed to run; it has no idea what descriptors
//! the caller already holds, and it cannot follow one syscall's effect into the
//! next. A thread restricted by [`SocketFamilyPolicy`] therefore still has every
//! one of the following:
//!
//! - **Every socket it already holds.** A descriptor inherited across `execv`,
//!   or opened before the filter was applied, is untouched: `read`, `write`,
//!   `send`, `recv`, `sendto`, and `connect` on it are not filtered at all.
//!   Closing inherited descriptors is [`crate::descriptors`]' job, and without
//!   it this module protects nothing against a workload that was handed a live
//!   connection.
//! - **`accept(2)` and `accept4(2)`.** Both mint a brand-new connected socket
//!   from a listening one without going anywhere near `socket(2)`. A workload
//!   that inherits a listener can still take connections on it.
//! - **File descriptors passed to it over an allowed `AF_UNIX` socket.** A
//!   cooperating peer can `sendmsg` an already-connected `AF_INET` socket
//!   through `SCM_RIGHTS`, and the receiving `recvmsg` installs it in the
//!   restricted process without any `socket(2)` call. If a policy allows
//!   `AF_UNIX` at all — which the local-IPC-shaped builders here do — then any
//!   daemon the workload can reach over a Unix socket can hand it a working
//!   network socket. This module does not inspect `sendmsg`/`recvmsg` control
//!   messages and must not be read as closing that path.
//! - **Every other thread of the process.** `seccomp(SECCOMP_SET_MODE_FILTER)`
//!   installs on the calling thread. Threads that already exist keep running
//!   unfiltered; only the caller and the descendants it later creates carry the
//!   filter. This module deliberately does not use the thread-sync flag, for
//!   the same reason the Landlock modules do not: the only supported shape is a
//!   freshly forked single-threaded child.
//! - **Type-argument bits above the low byte.** The classification masks
//!   `type & 0xff` (see [`SOCKET_TYPE_MASK`]), so `SOCK_CLOEXEC` and
//!   `SOCK_NONBLOCK` are correctly ignored — and so would be any *future* flag
//!   bit the kernel adds above bit 7. A new flag would pass unexamined rather
//!   than turn an allowed socket into a denied one.
//! - **Anything on a socket the policy does allow.** Allowing `AF_INET`
//!   `SOCK_STREAM` allows creating a TCP socket, not bounding what it connects
//!   to. That is [`crate::network`]'s Landlock policy, and the two are meant to
//!   be installed together.
//!
//! This is also not [`crate::BoundaryRequirement::NetworkDenial`], which is
//! satisfied by an unrouted network namespace. That removes the packet path;
//! this module only removes some outcomes of two syscalls.
//!
//! # What it does establish
//!
//! This module closes the socket-*creation* half of the gap
//! [`crate::network`] names in its own documentation. Landlock ABI 4 governs
//! TCP `bind` and `connect` and nothing else, so under it alone a workload can
//! still open UDP, raw, packet, netlink, and fresh `AF_UNIX` sockets. Under a
//! [`SocketFamilyPolicy`] those calls return `EPERM` before a descriptor
//! exists, so no data path is created for Landlock to have missed. In
//! particular:
//!
//! - **The protocol argument is bounded too.** [`SocketFamilyPolicy::allowing_tcp_sockets`]
//!   allows `SOCK_STREAM` with protocol `0` or `IPPROTO_TCP` only. `SOCK_STREAM`
//!   also reaches SCTP (`132`) and MPTCP (`262`), which are *not* TCP and which
//!   Landlock's TCP access rights do not cover on a kernel that has fixed
//!   Landlock erratum 1 — see
//!   [`crate::network::EnforcedTcpRestriction::tcp_identification_erratum_reported_fixed`].
//!   Without this bound, "grant TCP port 443" would also have granted an
//!   unrestricted SCTP association.
//! - **`io_uring` is refused outright.** `IORING_OP_SOCKET` creates a socket as
//!   a ring operation, which never appears to a syscall filter as `socket(2)`.
//!   A filter that left `io_uring_setup(2)` reachable would be bypassable in
//!   one step, so [`IO_URING_SYSCALLS`] are denied unconditionally by every
//!   policy this module can build, including ones that allow sockets. There is
//!   no opt-out: a workload that needs `io_uring` cannot run under this filter.
//!   `io_uring_enter` and `io_uring_register` are denied as well, so a ring
//!   descriptor *inherited* across `execv` is also unusable.
//! - **Cross-process inspection and descriptor theft are refused outright.**
//!   [`PROCESS_INSPECTION_SYSCALLS`] denies `ptrace`, both `process_vm_*`
//!   calls, and `pidfd_getfd` under every policy. Those interfaces can read or
//!   alter a sibling process, or copy one of its already-open descriptors,
//!   bypassing the workload's own filesystem and socket-creation boundaries.
//! - **Namespace creation is refused outright.** The workload runs inside a
//!   user namespace of its own ([`crate::identity`]) and, on hosts that grant
//!   the launch helper `userns`, it inherits that grant. A nested user
//!   namespace would make the workload root again inside it — with the mount,
//!   network and other namespaces that root can create. So every policy
//!   denies [`NAMESPACE_SYSCALLS`] (`unshare`, `setns`) unconditionally,
//!   denies `clone(2)` whenever its flags name any namespace
//!   ([`CLONE_NAMESPACE_FLAGS`]), and answers `clone3(2)` with `ENOSYS`
//!   rather than `EPERM`: `clone3` takes its flags through a struct the
//!   filter cannot inspect, and `ENOSYS` is the one answer that makes a C
//!   library fall back to `clone`, where the flags are visible. That
//!   answer is a second, tiny program installed after the first, because
//!   one program has one denial errno.
//!
//! # Denial is `EPERM`, not death
//!
//! Matched calls return [`DENIAL_ERRNO`]. A `SIGSYS`-raising or process-killing
//! action would be strictly worse here: `EPERM` is an outcome a program can
//! report, log, and be tested against, and every probe in `tests/seccomp.rs`
//! depends on being able to tell it apart from `EACCES`, `EAFNOSUPPORT`, and
//! `EPROTONOSUPPORT`. A killed process reports nothing, and a supervisor
//! reading only an exit status cannot distinguish "policy denied a socket" from
//! "the workload crashed". Denial is also not silent success: `EPERM` means no
//! descriptor was created.
//!
//! The one lethal path is not this module's choice. `seccompiler` prefixes
//! every program with an architecture check that returns
//! `SECCOMP_RET_KILL_PROCESS` when the running task's audit architecture is not
//! the one the filter was compiled for. A 32-bit (i386) program `execv`d under
//! this filter is therefore killed on its first syscall rather than refused.
//! That is the fail-closed direction — i386 reaches socket creation through
//! `socketcall(2)`, which these rules do not name, so letting it through would
//! be a hole — but it is a real behaviour change for a caller who assumed only
//! `EPERM` could happen, and it cannot be turned off through `seccompiler`'s
//! API.
//!
//! # Enforcement is one-way, thread-local, and sets `no_new_privs`
//!
//! A seccomp filter cannot be removed or relaxed for the life of the thread.
//! [`SocketFamilyPolicy::apply_to_current_thread`] must therefore run in the
//! child of a `fork`, after the fork and immediately before `execv`, never in a
//! supervisor that has other work to do — the same trusted-entry-helper
//! contract as [`crate::network`] and [`crate::containment`].
//!
//! Applying also sets `PR_SET_NO_NEW_PRIVS`, because the kernel refuses
//! `SECCOMP_SET_MODE_FILTER` from an unprivileged thread without it.
//! `no_new_privs` is itself irreversible and is inherited across `fork` and
//! `execv`, so a caller must expect a later `execv` of a setuid binary to gain
//! nothing. Every filesystem and network policy in this crate wants that
//! anyway; it is called out here because applying a *socket* filter is not an
//! obvious place to acquire it.
//!
//! This module deliberately stops at the apply step and offers no
//! apply-then-`execv` helper: seccomp, Landlock, cgroup placement, and
//! descriptor closure all belong in one entry helper in one child, and
//! composing them is the caller's decision.
//!
//! # One architecture, named out loud
//!
//! Syscall numbers and the audit architecture constant are per-architecture,
//! and only `x86_64` is wired here ([`REQUIRED_TARGET_ARCH`]). On any other
//! build architecture [`SocketFamilyPolicy::compile`] returns
//! [`SocketFilterError::UnsupportedArch`] instead of guessing: a filter built
//! for the wrong architecture would be installed successfully and then match
//! nothing, which is the worst possible failure — a policy that reports success
//! and denies nothing.
//!
//! On `x86_64` the `x32` ABI reaches the same kernel with `__X32_SYSCALL_BIT`
//! (`0x4000_0000`) set in the syscall number, which would miss a rule keyed on
//! the plain number. Every syscall this module filters is therefore listed
//! twice, once with the bit and once without. Distributions overwhelmingly ship
//! `x32` disabled, so this costs filter size on a path that usually cannot be
//! taken, and is kept because the alternative is a silent bypass.
//!
//! # Fail closed
//!
//! Every path that cannot build or install the exact requested filter returns a
//! [`SocketFilterError`]. There is no variant meaning "filtered, but less than
//! you asked for", and no code path returns success after installing a weaker
//! filter than the one requested.
//!
//! # A note on what a "denied" workload can no longer do
//!
//! Denying `AF_INET`/`SOCK_DGRAM` denies DNS. `getaddrinfo` resolves over UDP,
//! so a workload granted TCP but not UDP can open a connection to an address
//! and not to a name. That is a deliberate consequence, not an oversight: a
//! policy that allowed UDP so that name resolution keeps working would also
//! have allowed the most convenient exfiltration path on the host.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::fmt;

/// Errno returned for a socket call this policy denies.
pub const DENIAL_ERRNO: i32 = nix::libc::EPERM;

/// Build architecture this module can compile a filter for.
///
/// Compared against [`std::env::consts::ARCH`]; see the module docs for why a
/// mismatch is a refusal rather than a fallback.
pub const REQUIRED_TARGET_ARCH: &str = "x86_64";

/// Mask isolating the socket type from the flag bits `socket(2)` accepts in the
/// same argument.
///
/// `socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)` passes
/// `0x80801`, not `1`, and the Rust standard library always sets `SOCK_CLOEXEC`.
/// An equality test against `SOCK_STREAM` would classify that call as "not a
/// stream socket" and deny it, so every type comparison this module emits is a
/// masked one.
///
/// The kernel's own `SOCK_TYPE_MASK` is `0xf`; this mask is deliberately wider.
/// Bits 4 to 7 are not valid in any socket type and not valid as flags either,
/// so a call setting one is denied here rather than reaching the kernel's
/// `EINVAL`. Denying more than the kernel would is safe; denying less is not.
pub const SOCKET_TYPE_MASK: u32 = 0xff;

/// Upper bound on distinct `(domain, type)` shapes one policy may allow.
///
/// A policy needing more than this is not an exception list.
pub const MAX_ALLOWED_SHAPES: usize = 8;

/// Largest protocol number a shape may name.
///
/// Protocol exceptions are compiled by enumerating the values *below* the
/// largest allowed one, so an unbounded protocol number would mean an unbounded
/// filter. No builder in this module comes close; the bound exists so that
/// adding one cannot quietly produce a filter too large to install.
const MAX_ALLOWED_PROTOCOL: u32 = 255;

/// Bit the `x32` ABI sets in every syscall number.
const X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// `socket(2)`, as this build's architecture numbers it.
const SYS_SOCKET: i64 = nix::libc::SYS_socket & !X32_SYSCALL_BIT;
/// `socketpair(2)`, as this build's architecture numbers it.
const SYS_SOCKETPAIR: i64 = nix::libc::SYS_socketpair & !X32_SYSCALL_BIT;

/// The `io_uring` entry points every policy denies unconditionally.
///
/// `io_uring_setup` is the one that matters — no ring, no `IORING_OP_SOCKET` —
/// and the other two are denied so that a ring descriptor inherited across
/// `execv` cannot be driven either. See the module docs.
pub const IO_URING_SYSCALLS: [i64; 3] = [
    nix::libc::SYS_io_uring_setup & !X32_SYSCALL_BIT,
    nix::libc::SYS_io_uring_enter & !X32_SYSCALL_BIT,
    nix::libc::SYS_io_uring_register & !X32_SYSCALL_BIT,
];

/// Cross-process inspection and descriptor-copying entry points every policy
/// denies unconditionally.
pub const PROCESS_INSPECTION_SYSCALLS: [i64; 4] = [
    nix::libc::SYS_ptrace & !X32_SYSCALL_BIT,
    nix::libc::SYS_process_vm_readv & !X32_SYSCALL_BIT,
    nix::libc::SYS_process_vm_writev & !X32_SYSCALL_BIT,
    nix::libc::SYS_pidfd_getfd & !X32_SYSCALL_BIT,
];

/// Namespace-creation entry points every policy denies unconditionally.
pub const NAMESPACE_SYSCALLS: [i64; 2] = [
    nix::libc::SYS_unshare & !X32_SYSCALL_BIT,
    nix::libc::SYS_setns & !X32_SYSCALL_BIT,
];
/// `clone(2)`, denied when its flags name a namespace.
pub const SYS_CLONE: i64 = nix::libc::SYS_clone & !X32_SYSCALL_BIT;
/// `clone3(2)`, answered `ENOSYS` by the second program.
pub const SYS_CLONE3: i64 = nix::libc::SYS_clone3 & !X32_SYSCALL_BIT;
/// The `clone(2)` flag bits that create a namespace. Any one of them set
/// denies the call; a `clone` without them — threads, `fork` through
/// `clone`, `vfork` — is untouched.
pub const CLONE_NAMESPACE_FLAGS: [u64; 8] = [
    nix::libc::CLONE_NEWNS as u64,
    nix::libc::CLONE_NEWCGROUP as u64,
    nix::libc::CLONE_NEWUTS as u64,
    nix::libc::CLONE_NEWIPC as u64,
    nix::libc::CLONE_NEWUSER as u64,
    nix::libc::CLONE_NEWPID as u64,
    nix::libc::CLONE_NEWNET as u64,
    nix::libc::CLONE_NEWTIME as u64,
];
/// The errno the `clone3` program answers with.
pub const CLONE3_ERRNO: i32 = nix::libc::ENOSYS;
/// Index of the `flags` argument of `clone(2)` on `x86_64`.
const ARG_CLONE_FLAGS: u8 = 0;

/// Index of the `domain` argument of `socket(2)` and `socketpair(2)`.
const ARG_DOMAIN: u8 = 0;
/// Index of the `type` argument.
const ARG_TYPE: u8 = 1;
/// Index of the `protocol` argument.
const ARG_PROTOCOL: u8 = 2;

/// Number of bits [`SOCKET_TYPE_MASK`] covers.
const TYPE_MASK_BITS: u32 = 8;

/// Every combination of the two flags `socket(2)` accepts inside its type
/// argument. A grant has to survive all four to be worth anything: the Rust
/// standard library always sets `SOCK_CLOEXEC`, and never the bare type.
const TYPE_FLAGS: [u32; 4] = [
    0,
    nix::libc::SOCK_CLOEXEC as u32,
    nix::libc::SOCK_NONBLOCK as u32,
    (nix::libc::SOCK_CLOEXEC | nix::libc::SOCK_NONBLOCK) as u32,
];

/// An address family a policy is able to allow.
///
/// The enumeration is closed on purpose. There is no variant for `AF_PACKET`,
/// `AF_NETLINK`, `AF_ALG`, or `AF_VSOCK`, so no builder path — present or
/// future — can allow one without editing this type, which is a code review
/// rather than a configuration change.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SocketDomain {
    /// Local IPC. Reaches any daemon whose socket the workload can name.
    Unix,
    /// IPv4.
    Inet,
    /// IPv6.
    Inet6,
}

impl SocketDomain {
    /// The `AF_*` value this domain is spelled with in `socket(2)`.
    #[must_use]
    pub const fn address_family(self) -> i32 {
        match self {
            Self::Unix => nix::libc::AF_UNIX,
            Self::Inet => nix::libc::AF_INET,
            Self::Inet6 => nix::libc::AF_INET6,
        }
    }

    /// Stable spelling for reports and error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unix => "AF_UNIX",
            Self::Inet => "AF_INET",
            Self::Inet6 => "AF_INET6",
        }
    }

    /// The value as the filter compares it: the low 32 bits of the register.
    const fn argument(self) -> u32 {
        self.address_family() as u32
    }
}

impl fmt::Display for SocketDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A socket type a policy is able to allow.
///
/// Closed for the same reason as [`SocketDomain`]: there is no `SOCK_RAW` and
/// no `SOCK_RDM` variant, so no builder can produce a policy that permits a raw
/// socket.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SocketKind {
    /// Connection-oriented byte stream.
    Stream,
    /// Connectionless datagrams.
    Datagram,
    /// Connection-oriented, message-preserving. `AF_UNIX` only, here.
    SeqPacket,
}

impl SocketKind {
    /// The `SOCK_*` value this kind is spelled with in `socket(2)`.
    #[must_use]
    pub const fn socket_type(self) -> i32 {
        match self {
            Self::Stream => nix::libc::SOCK_STREAM,
            Self::Datagram => nix::libc::SOCK_DGRAM,
            Self::SeqPacket => nix::libc::SOCK_SEQPACKET,
        }
    }

    /// Stable spelling for reports and error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "SOCK_STREAM",
            Self::Datagram => "SOCK_DGRAM",
            Self::SeqPacket => "SOCK_SEQPACKET",
        }
    }

    /// The value as the filter compares it, after masking.
    const fn argument(self) -> u32 {
        self.socket_type() as u32
    }
}

impl fmt::Display for SocketKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One `(domain, type, protocols)` combination a policy permits.
///
/// Nothing outside this module constructs one: they exist only as the record of
/// what a builder granted, so a caller can read back exactly what it asked for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedSocketShape {
    domain: SocketDomain,
    kind: SocketKind,
    protocols: Vec<u32>,
}

impl AllowedSocketShape {
    /// Address family this shape permits.
    #[must_use]
    pub const fn domain(&self) -> SocketDomain {
        self.domain
    }

    /// Socket type this shape permits, compared under [`SOCKET_TYPE_MASK`].
    #[must_use]
    pub const fn kind(&self) -> SocketKind {
        self.kind
    }

    /// Protocol numbers this shape permits, and no others.
    #[must_use]
    pub fn protocols(&self) -> &[u32] {
        &self.protocols
    }

    fn permits(&self, call: SocketCall) -> bool {
        call.domain == self.domain.argument()
            && (call.socket_type & SOCKET_TYPE_MASK) == self.kind.argument()
            && self.protocols.contains(&call.protocol)
    }
}

impl fmt::Display for AllowedSocketShape {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{} protocols[", self.domain, self.kind)?;
        for (index, protocol) in self.protocols.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{protocol}")?;
        }
        formatter.write_str("]")
    }
}

/// Why a socket filter was refused, before or during installation.
///
/// Every variant is a refusal. None of them means "installed, but narrower than
/// you asked for": a filter this module cannot build exactly is not installed.
#[derive(Debug)]
pub enum SocketFilterError {
    /// The build architecture is not [`REQUIRED_TARGET_ARCH`]. Carries
    /// [`std::env::consts::ARCH`] as observed.
    UnsupportedArch(&'static str),
    /// The same `(domain, type)` shape was granted twice. A duplicate means the
    /// caller has lost track of its own exception list.
    DuplicateShape(SocketDomain, SocketKind),
    /// More than [`MAX_ALLOWED_SHAPES`] shapes were granted.
    TooManyShapes,
    /// A shape named a protocol above [`MAX_ALLOWED_PROTOCOL`]. Unreachable
    /// through the builders in this module, and kept as a standing assertion so
    /// that adding one cannot silently produce an oversized filter.
    ProtocolOutOfRange(u32),
    /// The compiled denial clauses would have denied a shape the policy grants,
    /// so the filter contradicts the policy it was built from. Unreachable
    /// while the clause compiler is correct, and kept as a standing assertion:
    /// the alternative is a child that loses a socket it was promised and has
    /// no way left to say so.
    ShapeDeniedByItsOwnFilter(AllowedSocketShape),
    /// `seccompiler` refused to build or assemble the program — an invalid
    /// condition, or a filter over the BPF length limit. The message is carried
    /// for diagnosis only; no caller should branch on its text.
    FilterRefused(String),
    /// The kernel refused to install the assembled program, or refused to set
    /// `no_new_privs` first. Nothing is filtered when this is returned.
    ApplyRefused(String),
}

impl fmt::Display for SocketFilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArch(arch) => write!(
                formatter,
                "socket filters are only wired for {REQUIRED_TARGET_ARCH}, and this build is {arch}"
            ),
            Self::DuplicateShape(domain, kind) => {
                write!(formatter, "{domain}/{kind} sockets were allowed twice")
            }
            Self::TooManyShapes => write!(
                formatter,
                "more than {MAX_ALLOWED_SHAPES} socket shapes were allowed"
            ),
            Self::ProtocolOutOfRange(protocol) => write!(
                formatter,
                "protocol {protocol} is above the {MAX_ALLOWED_PROTOCOL} this module compiles"
            ),
            Self::ShapeDeniedByItsOwnFilter(shape) => write!(
                formatter,
                "the compiled filter would deny {shape}, which this policy allows"
            ),
            Self::FilterRefused(detail) => {
                write!(formatter, "the seccomp filter was refused: {detail}")
            }
            Self::ApplyRefused(detail) => {
                write!(formatter, "the kernel refused the seccomp filter: {detail}")
            }
        }
    }
}

impl std::error::Error for SocketFilterError {}

/// The three arguments of `socket(2)` as the filter sees them.
///
/// The kernel truncates each register to `int` before `socket(2)` reads it, and
/// every condition this module emits is a `Dword` comparison, so only the low
/// 32 bits are ever consulted. Passing a value with rubbish in the high half
/// therefore cannot make an otherwise denied call slip past a `Ne` test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketCall {
    domain: u32,
    socket_type: u32,
    protocol: u32,
}

impl SocketCall {
    const fn new(domain: i32, socket_type: i32, protocol: i32) -> Self {
        Self {
            domain: domain as u32,
            socket_type: socket_type as u32,
            protocol: protocol as u32,
        }
    }

    const fn argument(self, index: u8) -> u32 {
        match index {
            ARG_DOMAIN => self.domain,
            ARG_TYPE => self.socket_type,
            _ => self.protocol,
        }
    }
}

/// One comparison against one syscall argument.
///
/// This mirrors exactly the subset of `seccompiler`'s condition vocabulary the
/// clause compiler uses. It exists as its own type so the denial rules can be
/// evaluated in Rust, against the same policy the BPF program is built from,
/// without a kernel: `tests` below check that the compiled clauses accept and
/// reject precisely what [`SocketFamilyPolicy::permits`] says they should.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArgTest {
    Eq { arg: u8, value: u32 },
    Ne { arg: u8, value: u32 },
    Gt { arg: u8, value: u32 },
    MaskedEq { arg: u8, mask: u32, value: u32 },
}

impl ArgTest {
    fn matches(self, call: SocketCall) -> bool {
        match self {
            Self::Eq { arg, value } => call.argument(arg) == value,
            Self::Ne { arg, value } => call.argument(arg) != value,
            Self::Gt { arg, value } => call.argument(arg) > value,
            Self::MaskedEq { arg, mask, value } => (call.argument(arg) & mask) == value,
        }
    }

    fn condition(self) -> Result<SeccompCondition, SocketFilterError> {
        let (arg, operator, value) = match self {
            Self::Eq { arg, value } => (arg, SeccompCmpOp::Eq, value),
            Self::Ne { arg, value } => (arg, SeccompCmpOp::Ne, value),
            Self::Gt { arg, value } => (arg, SeccompCmpOp::Gt, value),
            Self::MaskedEq { arg, mask, value } => {
                (arg, SeccompCmpOp::MaskedEq(u64::from(mask)), value)
            }
        };
        SeccompCondition::new(arg, SeccompCmpArgLen::Dword, operator, u64::from(value))
            .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))
    }
}

/// A conjunction of [`ArgTest`]s. If all of them match, the call is denied.
///
/// Denial clauses are the *complement* of the allowed set, because a
/// `seccompiler` filter has exactly one mismatch action and it must be `Allow`:
/// a filter whose mismatch action denied would deny every syscall in the
/// process, not merely the ones it names, and the process would die on its
/// first write. So the rules have to spell out what is forbidden.
type DenyClause = Vec<ArgTest>;

/// What a compiled policy denies for one syscall.
///
/// This is an enum rather than a bare clause list because an *empty* clause
/// list is exactly the case where the two readers of one would disagree:
/// `seccompiler` reads an empty rule chain as "match every call of this
/// syscall", while anything evaluating clauses in Rust reads it as "no clause
/// matched, so allow". Both readings are needed — the first is how
/// [`SocketFamilyPolicy::deny_all`] is spelled — so the distinction is carried
/// in the type instead of in a comment.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SocketDenials {
    /// Every call is denied whatever its arguments carry.
    Everything,
    /// A call is denied when any one clause matches it.
    Clauses(Vec<DenyClause>),
}

impl SocketDenials {
    fn denies(&self, call: SocketCall) -> bool {
        match self {
            Self::Everything => true,
            Self::Clauses(clauses) => clauses
                .iter()
                .any(|clause| clause.iter().all(|test| test.matches(call))),
        }
    }
}

/// A policy over which sockets a thread may create, and nothing else.
///
/// The default is total denial: no domain, no type, no protocol. Exceptions are
/// explicit and bounded, and each one names a domain, a type, and the exact
/// protocol numbers permitted with it.
///
/// # Exceptions are shapes, not endpoints
///
/// Allowing `AF_INET`/`SOCK_STREAM` allows creating a TCP socket. It says
/// nothing about what that socket may connect to or bind — see
/// [`crate::network`], which is the module that answers that question, and
/// which cannot answer it for a socket that was never created.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocketFamilyPolicy {
    shapes: Vec<AllowedSocketShape>,
}

impl SocketFamilyPolicy {
    /// Deny the creation of every socket. This is also [`Default`].
    #[must_use]
    pub const fn deny_all() -> Self {
        Self { shapes: Vec::new() }
    }

    /// Permit local `AF_UNIX` stream and datagram sockets, protocol `0` only.
    ///
    /// This is what a workload needs to talk to a daemon over a Unix socket it
    /// can name, and it is also the widest single grant here: see the module
    /// docs on `SCM_RIGHTS`, which is exactly what an allowed `AF_UNIX` socket
    /// makes reachable.
    ///
    /// `SOCK_SEQPACKET` is *not* included; ask for it separately with
    /// [`Self::allowing_unix_seqpacket_sockets`]. The kernel also accepts
    /// protocol `PF_UNIX` (`1`) for these sockets, and this policy does not:
    /// nothing in the standard library passes anything but `0`.
    pub fn allowing_unix_sockets(self) -> Result<Self, SocketFilterError> {
        self.allowing(SocketDomain::Unix, SocketKind::Stream, &[0])?
            .allowing(SocketDomain::Unix, SocketKind::Datagram, &[0])
    }

    /// Permit `AF_UNIX` `SOCK_SEQPACKET` sockets, protocol `0` only.
    pub fn allowing_unix_seqpacket_sockets(self) -> Result<Self, SocketFilterError> {
        self.allowing(SocketDomain::Unix, SocketKind::SeqPacket, &[0])
    }

    /// Permit IPv4 and IPv6 TCP sockets, and nothing else on those families.
    ///
    /// Grants `SOCK_STREAM` with protocol `0` (the family default, TCP) or
    /// `IPPROTO_TCP`. `SOCK_DGRAM`, `SOCK_RAW`, and every other protocol number
    /// on these families stay denied — including SCTP and MPTCP, which are
    /// `SOCK_STREAM` sockets that Landlock's TCP rules do not restrict.
    ///
    /// Pair this with a [`crate::network::TcpBindConnectPolicy`] that names the
    /// ports. On its own it allows a socket to exist, not to reach anything.
    pub fn allowing_tcp_sockets(self) -> Result<Self, SocketFilterError> {
        let tcp: &[u32] = &[0, nix::libc::IPPROTO_TCP as u32];
        self.allowing(SocketDomain::Inet, SocketKind::Stream, tcp)?
            .allowing(SocketDomain::Inet6, SocketKind::Stream, tcp)
    }

    /// Permit IPv4 and IPv6 UDP sockets, and nothing else on those families.
    ///
    /// Grants `SOCK_DGRAM` with protocol `0` (the family default, UDP) or
    /// `IPPROTO_UDP`. Every other protocol number on these families — including
    /// `SOCK_RAW` — stays denied.
    ///
    /// This is the DNS-resolution grant, and it is deliberately kept separate
    /// from [`Self::allowing_tcp_sockets`] because it is a wider hole than TCP:
    /// [`crate::network::TcpBindConnectPolicy`] governs only `bind`/`connect` on
    /// TCP sockets, so it cannot bound where a UDP socket sends. A workload that
    /// resolves names itself opens these sockets to its nameservers on port 53,
    /// and nothing in this crate confines that destination. The product's design
    /// closes this hole by resolving names in the egress broker rather than in
    /// the workload; this grant exists only for the pre-broker provider-launch
    /// path, where a provider CLI does its own DNS, and it should be paired only
    /// with a workload whose network egress is being deliberately relaxed.
    pub fn allowing_inet_datagram_sockets(self) -> Result<Self, SocketFilterError> {
        let udp: &[u32] = &[0, nix::libc::IPPROTO_UDP as u32];
        self.allowing(SocketDomain::Inet, SocketKind::Datagram, udp)?
            .allowing(SocketDomain::Inet6, SocketKind::Datagram, udp)
    }

    fn allowing(
        mut self,
        domain: SocketDomain,
        kind: SocketKind,
        protocols: &[u32],
    ) -> Result<Self, SocketFilterError> {
        if self
            .shapes
            .iter()
            .any(|shape| shape.domain == domain && shape.kind == kind)
        {
            return Err(SocketFilterError::DuplicateShape(domain, kind));
        }
        if self.shapes.len() >= MAX_ALLOWED_SHAPES {
            return Err(SocketFilterError::TooManyShapes);
        }
        if let Some(&protocol) = protocols
            .iter()
            .find(|&&protocol| protocol > MAX_ALLOWED_PROTOCOL)
        {
            return Err(SocketFilterError::ProtocolOutOfRange(protocol));
        }
        self.shapes.push(AllowedSocketShape {
            domain,
            kind,
            protocols: protocols.to_vec(),
        });
        Ok(self)
    }

    /// The shapes this policy permits, in the order they were granted.
    #[must_use]
    pub fn allowed_shapes(&self) -> &[AllowedSocketShape] {
        &self.shapes
    }

    /// Whether this policy permits no socket creation at all.
    #[must_use]
    pub fn denies_all_socket_creation(&self) -> bool {
        self.shapes.is_empty()
    }

    /// Whether `socket(domain, socket_type, protocol)` is permitted.
    ///
    /// The arguments are the raw `int`s the workload would pass. `socket_type`
    /// may carry `SOCK_CLOEXEC` and `SOCK_NONBLOCK`; they are masked off by
    /// [`SOCKET_TYPE_MASK`] before classification, exactly as the installed
    /// filter does.
    ///
    /// This is side-effect free and answers the same question the BPF program
    /// answers, so a supervisor can check before forking that a policy actually
    /// permits the sockets its workload needs.
    #[must_use]
    pub fn permits(&self, domain: i32, socket_type: i32, protocol: i32) -> bool {
        self.permits_call(SocketCall::new(domain, socket_type, protocol))
    }

    /// Whether `socketpair(domain, socket_type, protocol, …)` is permitted.
    ///
    /// `socketpair(2)` can only ever produce an `AF_UNIX` pair — every other
    /// family answers `EOPNOTSUPP` — but the syscall still takes a domain
    /// argument, so it gets the same discipline with the non-`AF_UNIX` shapes
    /// removed. A policy that allows TCP sockets does not thereby allow
    /// `socketpair(AF_INET, …)`: that call is denied by policy before the
    /// kernel can decline it on its own terms.
    #[must_use]
    pub fn permits_socketpair(&self, domain: i32, socket_type: i32, protocol: i32) -> bool {
        let call = SocketCall::new(domain, socket_type, protocol);
        Self::socketpair_shapes(&self.shapes)
            .iter()
            .any(|shape| shape.permits(call))
    }

    fn permits_call(&self, call: SocketCall) -> bool {
        self.shapes.iter().any(|shape| shape.permits(call))
    }

    /// The subset of `shapes` that `socketpair(2)` may reach.
    fn socketpair_shapes(shapes: &[AllowedSocketShape]) -> Vec<AllowedSocketShape> {
        shapes
            .iter()
            .filter(|shape| shape.domain == SocketDomain::Unix)
            .cloned()
            .collect()
    }

    /// Whether this build can compile a filter at all.
    ///
    /// Read-only and side-effect free, so a supervisor can call it before
    /// forking and refuse the run without filtering itself.
    pub fn check_build_arch() -> Result<(), SocketFilterError> {
        if std::env::consts::ARCH == REQUIRED_TARGET_ARCH {
            Ok(())
        } else {
            Err(SocketFilterError::UnsupportedArch(std::env::consts::ARCH))
        }
    }

    /// Assemble the BPF program for this policy without installing anything.
    ///
    /// Nothing here touches the calling thread, so this is the safe half of
    /// enforcement: a supervisor can compile before it forks, and refuse the
    /// run on a [`SocketFilterError`] rather than discover the problem in a
    /// child that has already given up its ability to report.
    pub fn compile(&self) -> Result<CompiledSocketFilter, SocketFilterError> {
        Self::check_build_arch()?;

        let socket_rules = compile_rules(&self.shapes)?;
        let socketpair_rules = compile_rules(&Self::socketpair_shapes(&self.shapes))?;

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for number in both_abis(SYS_SOCKET) {
            rules.insert(number, socket_rules.clone());
        }
        for number in both_abis(SYS_SOCKETPAIR) {
            rules.insert(number, socketpair_rules.clone());
        }
        for syscall in IO_URING_SYSCALLS
            .into_iter()
            .chain(PROCESS_INSPECTION_SYSCALLS)
            .chain(NAMESPACE_SYSCALLS)
        {
            for number in both_abis(syscall) {
                // An empty rule chain matches the syscall whatever its
                // arguments are, which is how `seccompiler` spells an
                // unconditional denial.
                rules.insert(number, Vec::new());
            }
        }
        let clone_rules = clone_namespace_rules()?;
        for number in both_abis(SYS_CLONE) {
            rules.insert(number, clone_rules.clone());
        }

        let mut filtered_syscalls: Vec<i64> = rules.keys().copied().collect();
        let filter = SeccompFilter::new(
            rules,
            // Every syscall this filter does not name runs untouched. It has to
            // be this way round; see `DenyClause`.
            SeccompAction::Allow,
            SeccompAction::Errno(DENIAL_ERRNO as u32),
            TargetArch::x86_64,
        )
        .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))?;
        let program: BpfProgram =
            filter
                .try_into()
                .map_err(|error: seccompiler::BackendError| {
                    SocketFilterError::FilterRefused(error.to_string())
                })?;

        // The second program: `clone3` answers `ENOSYS`, so a C library
        // falls back to `clone`, which the first program inspects.
        let mut clone3_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for number in both_abis(SYS_CLONE3) {
            clone3_rules.insert(number, Vec::new());
            filtered_syscalls.push(number);
        }
        filtered_syscalls.sort_unstable();
        let clone3_filter = SeccompFilter::new(
            clone3_rules,
            SeccompAction::Allow,
            SeccompAction::Errno(CLONE3_ERRNO as u32),
            TargetArch::x86_64,
        )
        .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))?;
        let clone3_program: BpfProgram =
            clone3_filter
                .try_into()
                .map_err(|error: seccompiler::BackendError| {
                    SocketFilterError::FilterRefused(error.to_string())
                })?;

        Ok(CompiledSocketFilter {
            program,
            clone3_program,
            filtered_syscalls,
        })
    }

    /// Compile and install this policy on the calling thread, irreversibly.
    ///
    /// Run this in a freshly forked child immediately before `execv`. See the
    /// module docs for why it cannot be undone, why it reaches only the calling
    /// thread, and why it also sets `no_new_privs`.
    pub fn apply_to_current_thread(&self) -> Result<EnforcedSocketFilter, SocketFilterError> {
        self.compile()?.apply_to_current_thread()
    }
}

/// One denial rule per namespace flag: `clone(2)` is refused when any of
/// [`CLONE_NAMESPACE_FLAGS`] is set in its flags argument.
///
/// `seccompiler` has no masked inequality, so "any of these bits" is spelled
/// as one masked-equality rule per bit; rules for one syscall are a
/// disjunction, which is exactly the meaning wanted.
fn clone_namespace_rules() -> Result<Vec<SeccompRule>, SocketFilterError> {
    CLONE_NAMESPACE_FLAGS
        .into_iter()
        .map(|flag| {
            let condition = SeccompCondition::new(
                ARG_CLONE_FLAGS,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))?;
            SeccompRule::new(vec![condition])
                .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))
        })
        .collect()
}

/// Both spellings of one syscall number on `x86_64`: native and `x32`.
const fn both_abis(number: i64) -> [i64; 2] {
    [number, number | X32_SYSCALL_BIT]
}

/// Build the denial rule chain for one set of allowed shapes.
///
/// An empty result is not "allow everything": for `seccompiler` an empty rule
/// chain against a syscall number is an unconditional match, so it denies every
/// call of that syscall. That is exactly what a policy with no allowed shape
/// means, and [`SocketFamilyPolicy::deny_all`] relies on it.
fn compile_rules(shapes: &[AllowedSocketShape]) -> Result<Vec<SeccompRule>, SocketFilterError> {
    let denials = deny_clauses(shapes);
    check_clauses_permit_granted_shapes(shapes, &denials)?;
    let clauses = match denials {
        // `seccompiler` spells an unconditional denial as an empty rule chain.
        SocketDenials::Everything => return Ok(Vec::new()),
        SocketDenials::Clauses(clauses) => clauses,
    };
    clauses
        .into_iter()
        .map(|clause| {
            let conditions = clause
                .into_iter()
                .map(ArgTest::condition)
                .collect::<Result<Vec<_>, _>>()?;
            SeccompRule::new(conditions)
                .map_err(|error| SocketFilterError::FilterRefused(error.to_string()))
        })
        .collect()
}

/// Refuse a clause set that would deny a socket the policy promised.
///
/// Cheap and bounded: it walks the granted shapes, not the argument space. So
/// it proves one direction only — that the compiled filter cannot refuse a
/// socket the caller was told it would get, which is the failure a workload
/// would hit at runtime in a child that can no longer explain itself. The other
/// direction, that the clauses deny everything *outside* the granted set, is
/// not cheap to check and is an exhaustive unit test over an argument matrix
/// instead.
fn check_clauses_permit_granted_shapes(
    shapes: &[AllowedSocketShape],
    denials: &SocketDenials,
) -> Result<(), SocketFilterError> {
    for shape in shapes {
        for &protocol in &shape.protocols {
            for flags in TYPE_FLAGS {
                let call = SocketCall {
                    domain: shape.domain.argument(),
                    socket_type: shape.kind.argument() | flags,
                    protocol,
                };
                if denials.denies(call) {
                    return Err(SocketFilterError::ShapeDeniedByItsOwnFilter(shape.clone()));
                }
            }
        }
    }
    Ok(())
}

/// The complement of the allowed set, as a disjunction of conjunctions.
///
/// A call is denied when any one clause matches, and a clause matches when all
/// of its tests do — which is precisely `seccompiler`'s rule-chain semantics.
/// The complement is built in three layers:
///
/// 1. one clause for a domain no shape names,
/// 2. per allowed domain, the clauses covering every socket type that domain
///    does not allow,
/// 3. per allowed `(domain, type)`, the clauses covering every protocol that
///    shape does not allow.
///
/// Together these cover every `(domain, type, protocol)` triple outside the
/// allowed set and none inside it. That claim is not left to reading: the unit
/// tests evaluate these clauses against [`SocketFamilyPolicy::permits`] over a
/// wide argument matrix.
fn deny_clauses(shapes: &[AllowedSocketShape]) -> SocketDenials {
    let mut domains: Vec<SocketDomain> = Vec::new();
    for shape in shapes {
        if !domains.contains(&shape.domain) {
            domains.push(shape.domain);
        }
    }
    if domains.is_empty() {
        return SocketDenials::Everything;
    }
    let mut clauses: Vec<DenyClause> = Vec::new();

    // Layer 1: the domain is not one this policy names at all.
    clauses.push(
        domains
            .iter()
            .map(|domain| ArgTest::Ne {
                arg: ARG_DOMAIN,
                value: domain.argument(),
            })
            .collect(),
    );

    for domain in domains {
        let is_here = ArgTest::Eq {
            arg: ARG_DOMAIN,
            value: domain.argument(),
        };
        let types: Vec<u32> = shapes
            .iter()
            .filter(|shape| shape.domain == domain)
            .map(|shape| shape.kind.argument())
            .collect();

        // Layer 2: the domain is allowed, but not with this socket type.
        for test in unallowed_type_tests(&types) {
            clauses.push(vec![is_here, test]);
        }

        // Layer 3: the domain and type are allowed, but not this protocol.
        for shape in shapes.iter().filter(|shape| shape.domain == domain) {
            let is_this_type = ArgTest::MaskedEq {
                arg: ARG_TYPE,
                mask: SOCKET_TYPE_MASK,
                value: shape.kind.argument(),
            };
            for test in unallowed_protocol_tests(&shape.protocols) {
                clauses.push(vec![is_here, is_this_type, test]);
            }
        }
    }
    SocketDenials::Clauses(clauses)
}

/// Tests matching exactly the socket types outside `allowed`.
///
/// The type argument cannot be compared for inequality under a mask —
/// `seccompiler` has `MaskedEq` and no masked `Ne` — so the complement is built
/// out of masked equalities instead. Let `k` be the number of bits the largest
/// allowed type needs. Then a masked type is *not* allowed exactly when either
///
/// - one of the bits from `k` up to the top of [`SOCKET_TYPE_MASK`] is set, or
/// - the low `k` bits hold one of the values `allowed` does not contain.
///
/// Both halves are single masked equalities, and both ignore everything above
/// bit 7 — which is what makes `SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK`
/// classify as a stream socket instead of as an unknown type.
fn unallowed_type_tests(allowed: &[u32]) -> Vec<ArgTest> {
    // Bounded by [`SocketKind`], whose largest value is `SOCK_SEQPACKET`, so
    // `bits` is never more than 3. The clamp is a standing assertion: a wider
    // value would make the enumeration below unbounded rather than wrong.
    let bits = allowed
        .iter()
        .map(|value| u32::BITS - value.leading_zeros())
        .max()
        .unwrap_or(0)
        .min(TYPE_MASK_BITS);
    let mut tests = Vec::new();
    for bit in bits..TYPE_MASK_BITS {
        tests.push(ArgTest::MaskedEq {
            arg: ARG_TYPE,
            mask: 1 << bit,
            value: 1 << bit,
        });
    }
    let low_mask = (1u32 << bits) - 1;
    for value in 0..=low_mask {
        if !allowed.contains(&value) {
            tests.push(ArgTest::MaskedEq {
                arg: ARG_TYPE,
                mask: low_mask,
                value,
            });
        }
    }
    tests
}

/// Tests matching exactly the protocol numbers outside `allowed`.
///
/// Bounded by construction: everything above the largest allowed protocol is
/// one `Gt`, and the values below it are enumerated. [`MAX_ALLOWED_PROTOCOL`]
/// keeps that enumeration short. A negative protocol argument arrives as a very
/// large unsigned value and is caught by the `Gt`.
fn unallowed_protocol_tests(allowed: &[u32]) -> Vec<ArgTest> {
    let highest = allowed.iter().copied().max().unwrap_or(0);
    let mut tests = vec![ArgTest::Gt {
        arg: ARG_PROTOCOL,
        value: highest,
    }];
    for value in 0..=highest {
        if !allowed.contains(&value) {
            tests.push(ArgTest::Eq {
                arg: ARG_PROTOCOL,
                value,
            });
        }
    }
    tests
}

/// An assembled BPF program for a [`SocketFamilyPolicy`], not yet installed.
///
/// Holding one means the policy compiled: the architecture is supported, every
/// condition was accepted, and the program is within the kernel's length limit.
/// It means nothing about the calling thread, which is still unfiltered.
#[derive(Clone, Debug)]
pub struct CompiledSocketFilter {
    program: BpfProgram,
    clone3_program: BpfProgram,
    filtered_syscalls: Vec<i64>,
}

impl CompiledSocketFilter {
    /// Number of BPF instructions in the assembled programs, both of them.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.program.len() + self.clone3_program.len()
    }

    /// Syscall numbers the programs have a rule chain for, ascending.
    ///
    /// Every other syscall is passed through untouched. The list includes each
    /// filtered syscall's `x32` spelling as well as its native one, and the
    /// `clone3` numbers the second program answers.
    #[must_use]
    pub fn filtered_syscalls(&self) -> &[i64] {
        &self.filtered_syscalls
    }

    /// Install this program on the calling thread, irreversibly.
    ///
    /// Sets `PR_SET_NO_NEW_PRIVS` first, because the kernel will not accept a
    /// filter from an unprivileged thread without it; a failure there is
    /// reported as [`SocketFilterError::ApplyRefused`] with nothing installed.
    pub fn apply_to_current_thread(&self) -> Result<EnforcedSocketFilter, SocketFilterError> {
        seccompiler::apply_filter(&self.program)
            .map_err(|error| SocketFilterError::ApplyRefused(error.to_string()))?;
        // Filters stack: the kernel runs every installed program and takes
        // the most restrictive answer, so the `clone3` program adds its
        // `ENOSYS` without touching what the first program decided.
        seccompiler::apply_filter(&self.clone3_program)
            .map_err(|error| SocketFilterError::ApplyRefused(error.to_string()))?;
        Ok(EnforcedSocketFilter {
            instruction_count: self.instruction_count(),
        })
    }
}

/// Proof that a socket filter is installed on the calling thread.
///
/// Only constructed after the kernel accepted the program, so holding one means
/// the filter is real. What it is a filter *of* is the narrow thing the module
/// documentation describes: which sockets the thread may create, and nothing
/// about the ones it already holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcedSocketFilter {
    instruction_count: usize,
}

impl EnforcedSocketFilter {
    /// Number of BPF instructions the kernel accepted.
    #[must_use]
    pub const fn instruction_count(self) -> usize {
        self.instruction_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nothing in this module's unit tests may install a filter. A seccomp
    // filter cannot be removed, so one in-process `apply` would silently change
    // every later test in the binary. Kernel behaviour is exercised in
    // `tests/seccomp.rs`, through a subprocess that exits straight after.

    /// Domains worth checking: the allowed three, families a workload might
    /// reach for, and values no family uses.
    const DOMAIN_MATRIX: [i32; 10] = [
        nix::libc::AF_UNSPEC,
        nix::libc::AF_UNIX,
        nix::libc::AF_INET,
        nix::libc::AF_INET6,
        nix::libc::AF_NETLINK,
        nix::libc::AF_PACKET,
        nix::libc::AF_ALG,
        nix::libc::AF_VSOCK,
        250,
        -1,
    ];

    const PROTOCOL_MATRIX: [i32; 10] = [
        0,
        1,
        2,
        5,
        nix::libc::IPPROTO_TCP,
        7,
        nix::libc::IPPROTO_UDP,
        nix::libc::IPPROTO_SCTP,
        255,
        -1,
    ];

    /// Every socket type in the low byte, each with all four combinations of
    /// the two flags `socket(2)` accepts in the same argument.
    fn type_matrix() -> Vec<i32> {
        let mut types = Vec::new();
        for base in 0..=0xff {
            for flags in [
                0,
                nix::libc::SOCK_CLOEXEC,
                nix::libc::SOCK_NONBLOCK,
                nix::libc::SOCK_CLOEXEC | nix::libc::SOCK_NONBLOCK,
            ] {
                types.push(base | flags);
            }
        }
        types
    }

    fn policies() -> Vec<(&'static str, SocketFamilyPolicy)> {
        vec![
            ("deny-all", SocketFamilyPolicy::deny_all()),
            (
                "unix",
                SocketFamilyPolicy::deny_all()
                    .allowing_unix_sockets()
                    .expect("unix policy"),
            ),
            (
                "unix+seqpacket",
                SocketFamilyPolicy::deny_all()
                    .allowing_unix_sockets()
                    .and_then(SocketFamilyPolicy::allowing_unix_seqpacket_sockets)
                    .expect("unix seqpacket policy"),
            ),
            (
                "tcp",
                SocketFamilyPolicy::deny_all()
                    .allowing_tcp_sockets()
                    .expect("tcp policy"),
            ),
            (
                "unix+tcp",
                SocketFamilyPolicy::deny_all()
                    .allowing_unix_sockets()
                    .and_then(SocketFamilyPolicy::allowing_tcp_sockets)
                    .expect("unix and tcp policy"),
            ),
        ]
    }

    /// The load-bearing property: the denial clauses handed to `seccompiler`
    /// are the exact complement of what the policy says it permits.
    ///
    /// The two sides are written independently — one is set membership over the
    /// granted shapes, the other is the masked-bit decomposition the BPF is
    /// built from — so any drift between them shows up here rather than as a
    /// filter that quietly permits or refuses the wrong socket.
    #[test]
    fn denial_clauses_are_the_exact_complement_of_the_permitted_set() {
        let types = type_matrix();
        for (name, policy) in policies() {
            let denials = deny_clauses(policy.allowed_shapes());
            for domain in DOMAIN_MATRIX {
                for &socket_type in &types {
                    for protocol in PROTOCOL_MATRIX {
                        let call = SocketCall::new(domain, socket_type, protocol);
                        assert_eq!(
                            policy.permits(domain, socket_type, protocol),
                            !denials.denies(call),
                            "policy {name} disagrees with its own clauses for \
                             domain={domain} type={socket_type:#x} protocol={protocol}"
                        );
                    }
                }
            }
        }
    }

    /// The same property for `socketpair(2)`, whose clauses are compiled from
    /// the `AF_UNIX` subset of the policy.
    #[test]
    fn socketpair_clauses_are_the_exact_complement_of_its_permitted_set() {
        let types = type_matrix();
        for (name, policy) in policies() {
            let shapes = SocketFamilyPolicy::socketpair_shapes(policy.allowed_shapes());
            assert!(
                shapes
                    .iter()
                    .all(|shape| shape.domain() == SocketDomain::Unix),
                "policy {name} offered socketpair a non-Unix shape"
            );
            let denials = deny_clauses(&shapes);
            for domain in DOMAIN_MATRIX {
                for &socket_type in &types {
                    for protocol in PROTOCOL_MATRIX {
                        let call = SocketCall::new(domain, socket_type, protocol);
                        assert_eq!(
                            policy.permits_socketpair(domain, socket_type, protocol),
                            !denials.denies(call),
                            "policy {name} disagrees with its socketpair clauses for \
                             domain={domain} type={socket_type:#x} protocol={protocol}"
                        );
                    }
                }
            }
        }
    }

    /// The flag bits are masked off, not compared.
    #[test]
    fn flagged_stream_sockets_classify_as_stream_sockets() {
        let policy = SocketFamilyPolicy::deny_all()
            .allowing_tcp_sockets()
            .expect("tcp policy");
        for flags in [
            0,
            nix::libc::SOCK_CLOEXEC,
            nix::libc::SOCK_NONBLOCK,
            nix::libc::SOCK_CLOEXEC | nix::libc::SOCK_NONBLOCK,
        ] {
            assert!(
                policy.permits(nix::libc::AF_INET, nix::libc::SOCK_STREAM | flags, 0),
                "a stream socket with flags {flags:#x} was not classified as one"
            );
            assert!(
                !policy.permits(nix::libc::AF_INET, nix::libc::SOCK_DGRAM | flags, 0),
                "a datagram socket with flags {flags:#x} was classified as a stream"
            );
        }
    }

    /// A policy that names no shape denies every socket call unconditionally,
    /// which `seccompiler` spells as an empty rule chain.
    #[test]
    fn deny_all_compiles_to_an_unconditional_denial() {
        let policy = SocketFamilyPolicy::deny_all();
        assert!(policy.denies_all_socket_creation());
        assert_eq!(policy, SocketFamilyPolicy::default());
        assert_eq!(
            deny_clauses(policy.allowed_shapes()),
            SocketDenials::Everything
        );
        // An empty rule chain is `seccompiler`'s unconditional match, so this
        // empty vector is total denial and not the absence of a policy.
        assert!(
            compile_rules(policy.allowed_shapes())
                .expect("deny-all rules")
                .is_empty()
        );
        assert!(!policy.permits(nix::libc::AF_UNIX, nix::libc::SOCK_STREAM, 0));
    }

    /// Protocol exceptions are exact, which is what keeps a TCP grant from
    /// being an SCTP or MPTCP grant.
    #[test]
    fn a_tcp_grant_is_not_a_grant_of_every_stream_protocol() {
        let policy = SocketFamilyPolicy::deny_all()
            .allowing_tcp_sockets()
            .expect("tcp policy");
        for domain in [nix::libc::AF_INET, nix::libc::AF_INET6] {
            assert!(policy.permits(domain, nix::libc::SOCK_STREAM, 0));
            assert!(policy.permits(domain, nix::libc::SOCK_STREAM, nix::libc::IPPROTO_TCP));
            for protocol in [nix::libc::IPPROTO_SCTP, 262, nix::libc::IPPROTO_UDP, -1] {
                assert!(
                    !policy.permits(domain, nix::libc::SOCK_STREAM, protocol),
                    "protocol {protocol} came along with the TCP grant"
                );
            }
        }
    }

    /// The UDP grant permits inet datagram sockets on both families, at the two
    /// spellings a resolver uses, and nothing wider — not raw, not a foreign
    /// protocol, and not TCP, which is a separate grant.
    #[test]
    fn the_datagram_grant_is_udp_on_the_inet_families_and_nothing_wider() {
        let policy = SocketFamilyPolicy::deny_all()
            .allowing_inet_datagram_sockets()
            .expect("inet datagram policy");
        for domain in [nix::libc::AF_INET, nix::libc::AF_INET6] {
            assert!(policy.permits(domain, nix::libc::SOCK_DGRAM, 0));
            assert!(policy.permits(domain, nix::libc::SOCK_DGRAM, nix::libc::IPPROTO_UDP));
            for protocol in [nix::libc::IPPROTO_ICMP, 262, nix::libc::IPPROTO_TCP, -1] {
                assert!(
                    !policy.permits(domain, nix::libc::SOCK_DGRAM, protocol),
                    "protocol {protocol} came along with the UDP grant"
                );
            }
            // The grant does not widen into raw sockets or TCP on these families.
            assert!(!policy.permits(domain, nix::libc::SOCK_RAW, 0));
            assert!(!policy.permits(domain, nix::libc::SOCK_STREAM, 0));
        }
        // It is confined to the inet families: no AF_UNIX datagram comes with it.
        assert!(!policy.permits(nix::libc::AF_UNIX, nix::libc::SOCK_DGRAM, 0));
    }

    /// Grants are bounded and duplicate-free, and refusals are typed.
    #[test]
    fn grants_are_bounded_and_duplicates_are_refused() {
        let duplicate = SocketFamilyPolicy::deny_all()
            .allowing_unix_sockets()
            .and_then(SocketFamilyPolicy::allowing_unix_sockets);
        assert!(
            matches!(
                duplicate,
                Err(SocketFilterError::DuplicateShape(
                    SocketDomain::Unix,
                    SocketKind::Stream
                ))
            ),
            "a duplicate shape was accepted"
        );

        // The bound itself, reached with distinct shapes.
        let mut bounded = SocketFamilyPolicy::deny_all();
        let shapes = [
            (SocketDomain::Unix, SocketKind::Stream),
            (SocketDomain::Unix, SocketKind::Datagram),
            (SocketDomain::Unix, SocketKind::SeqPacket),
            (SocketDomain::Inet, SocketKind::Stream),
            (SocketDomain::Inet, SocketKind::Datagram),
            (SocketDomain::Inet, SocketKind::SeqPacket),
            (SocketDomain::Inet6, SocketKind::Stream),
            (SocketDomain::Inet6, SocketKind::Datagram),
        ];
        assert_eq!(shapes.len(), MAX_ALLOWED_SHAPES);
        for (domain, kind) in shapes {
            bounded = bounded.allowing(domain, kind, &[0]).expect("within bound");
        }
        assert!(matches!(
            bounded.allowing(SocketDomain::Inet6, SocketKind::SeqPacket, &[0]),
            Err(SocketFilterError::TooManyShapes)
        ));

        assert!(matches!(
            SocketFamilyPolicy::deny_all().allowing(
                SocketDomain::Unix,
                SocketKind::Stream,
                &[MAX_ALLOWED_PROTOCOL + 1]
            ),
            Err(SocketFilterError::ProtocolOutOfRange(_))
        ));
    }

    /// The compiled program names both ABI spellings of every syscall it
    /// filters, and denies every unconditional syscall whatever the policy
    /// allows.
    #[test]
    fn every_policy_filters_both_abis_and_denies_unconditional_syscalls() {
        for (name, policy) in policies() {
            let compiled = policy.compile().expect("compiles on this build");
            let filtered = compiled.filtered_syscalls();
            for syscall in [SYS_SOCKET, SYS_SOCKETPAIR, SYS_CLONE, SYS_CLONE3]
                .into_iter()
                .chain(IO_URING_SYSCALLS)
                .chain(PROCESS_INSPECTION_SYSCALLS)
                .chain(NAMESPACE_SYSCALLS)
            {
                for number in both_abis(syscall) {
                    assert!(
                        filtered.contains(&number),
                        "policy {name} does not filter syscall {number}"
                    );
                }
            }
            assert!(
                compiled.instruction_count() > 0,
                "policy {name} compiled to nothing"
            );
        }
    }
}
