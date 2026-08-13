// SPDX-License-Identifier: Elastic-2.0

//! TCP `bind` and `connect` restriction for an untrusted workload, via Landlock.
//!
//! # This is not network denial
//!
//! Landlock ABI 4 — the first ABI with any network support at all — governs
//! exactly two operations: `bind(2)` and `connect(2)` on TCP sockets. No other
//! part of the kernel's network stack is reachable by a Landlock rule, and this
//! module adds nothing on top of the kernel. A thread restricted by
//! [`TcpBindConnectPolicy`] still has every one of the following:
//!
//! - **UDP.** Binding, sending, and receiving datagrams are untouched. DNS over
//!   UDP, QUIC, and therefore HTTP/3 endpoints remain reachable.
//! - **Raw sockets, packet sockets, and ICMP**, to the extent the workload's
//!   credentials already allowed them.
//! - **`AF_UNIX` sockets**, both filesystem-bound and abstract. A workload can
//!   still reach any local daemon whose socket it can name, and can still ask
//!   an unrestricted peer on the other end to open a connection on its behalf.
//!   Restricting `AF_UNIX` needs filesystem rules (for pathname sockets) or a
//!   scoping ABI this module does not require (for abstract ones).
//! - **Sockets that are already connected.** Landlock hooks `connect(2)`, not
//!   `read`, `write`, `send`, or `recv`. A connection opened before enforcement
//!   — including one inherited across `execv` — keeps carrying traffic.
//!   Closing those is [`crate::descriptors`]' job, not this module's.
//! - **`accept(2)`** on a listening socket bound before enforcement or
//!   inherited from the parent.
//! - **Non-TCP `SOCK_STREAM` protocols** (SMC, MPTCP, SCTP) on kernels carrying
//!   the fix for Landlock erratum 1. Before that fix such sockets were
//!   *over*-restricted by the TCP access rights; after it they are correctly
//!   identified as not-TCP and fall outside this policy.
//!   [`EnforcedTcpRestriction::tcp_identification_erratum_reported_fixed`]
//!   reports what the running kernel says, so a caller never has to guess. This
//!   module never treats the unfixed behaviour as protection.
//! - **Every other thread of the process.** `landlock_restrict_self` restricts
//!   the calling thread and the descendants it later creates. Restricting all
//!   threads of a live process needs `LANDLOCK_RESTRICT_SELF_TSYNC`, which
//!   arrived in ABI 8 (Linux 7.0) and is deliberately not required here.
//!
//! Closing those gaps needs two things this module does not do and must not
//! claim: descriptor closure before `execv` (see [`crate::descriptors`]) and a
//! seccomp filter on the socket family and protocol arguments of `socket(2)`,
//! for which no module exists yet. Until both land, a workload under this
//! policy can still move bytes off the host.
//!
//! This is also not [`crate::BoundaryRequirement::NetworkDenial`]. That
//! requirement is satisfied by an unrouted network namespace, which removes the
//! packet path entirely; this module only takes away two syscall outcomes.
//!
//! # What it does establish
//!
//! Under a default [`TcpBindConnectPolicy::deny_all`] the restricted thread
//! cannot open a TCP connection to any address or port, and cannot bind a TCP
//! port. That covers the ordinary shape of an agent workload phoning home over
//! HTTPS, and it survives `execv`, so a trusted helper can install it and then
//! replace itself with the untrusted program.
//!
//! # Enforcement is one-way and thread-local
//!
//! `landlock_restrict_self` cannot be undone: the calling thread carries the
//! new domain until it exits. So [`TcpBindConnectPolicy::enforce_on_current_thread`]
//! must run in the child of a `fork`, after the fork and immediately before
//! `execv`, never in a supervisor that has other work to do. That is the same
//! trusted-entry-helper shape this crate's cgroup containment uses.
//!
//! This module deliberately stops at the enforcement step and does not offer an
//! enforce-then-`execv` helper: network, filesystem, and descriptor closure all
//! belong in one entry helper in one child, and composing them is the caller's
//! decision, not this module's.
//!
//! # Fail closed
//!
//! Every path that cannot install the full requested restriction returns a
//! [`TcpPolicyError`]. There is no variant meaning "partially restricted", and
//! no code path returns success after a weaker ruleset than the one asked for.

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, Erratum, LandlockStatus, NetPort,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use std::fmt;

/// Landlock ABI this module requires, being the first with TCP access rights.
pub const REQUIRED_LANDLOCK_ABI: u8 = 4;

/// The same value as [`REQUIRED_LANDLOCK_ABI`], in the `landlock` crate's type.
///
/// The handled access rights are pinned to this ABI even on a newer kernel, so
/// a kernel upgrade can never silently change the set of denied operations.
const HANDLED_ABI: ABI = ABI::V4;

/// Upper bound on explicitly allowed ports, per direction.
///
/// A policy needing more than this is not an exception list, and the caller
/// should be reaching for a different mechanism.
pub const MAX_ALLOWED_PORTS: usize = 8;

/// Why a TCP policy was refused, before or during enforcement.
///
/// Every variant is a refusal. None of them means "restricted, but less than
/// you asked for": a restriction this module cannot confirm is not installed.
#[derive(Debug)]
pub enum TcpPolicyError {
    /// The running kernel exposes no usable Landlock, either because it was not
    /// built with it or because it is disabled at boot.
    LandlockUnavailable,
    /// Landlock exists but is older than ABI [`REQUIRED_LANDLOCK_ABI`], which
    /// is the first ABI with any TCP access right. Nothing weaker is accepted.
    TcpRulesUnsupported,
    /// Port 0 was offered as an exception. The kernel reads a bind rule for
    /// port 0 as "the whole range in `/proc/sys/net/ipv4/ip_local_port_range`",
    /// so accepting it would silently widen the policy far past the request.
    EphemeralPortRefused,
    /// The same port was offered twice for one direction. Duplicates mean the
    /// caller has lost track of its own exception list.
    DuplicateAllowedPort(u16),
    /// More than [`MAX_ALLOWED_PORTS`] exceptions were offered for one
    /// direction.
    TooManyAllowedPorts,
    /// The kernel or the `landlock` crate refused to build, populate, or
    /// install the ruleset. The message is carried for diagnosis only; no
    /// caller should branch on its text.
    RulesetRefused(String),
    /// The ruleset installed, but the kernel reported less than full
    /// enforcement of what was requested.
    NotFullyEnforced,
    /// `PR_SET_NO_NEW_PRIVS` is not set on the restricted thread, so a setuid
    /// program reached by a later `execv` could still gain privileges. The
    /// Landlock domain is in place by the time this is reported; refusing to
    /// execute anything is the safe direction.
    NoNewPrivs,
    /// The restriction is in place, but the kernel reported a Landlock ABI this
    /// build cannot name, so it cannot be reported honestly. As with
    /// [`Self::NoNewPrivs`], the thread is already restricted; the caller must
    /// refuse to execute rather than report an ABI it invented.
    UnnamedAbi,
}

impl fmt::Display for TcpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LandlockUnavailable => {
                formatter.write_str("the running kernel exposes no usable Landlock implementation")
            }
            Self::TcpRulesUnsupported => write!(
                formatter,
                "Landlock on this kernel is older than ABI {REQUIRED_LANDLOCK_ABI}, \
                 which is the first ABI with TCP access rights"
            ),
            Self::EphemeralPortRefused => formatter
                .write_str("port 0 is refused: the kernel reads it as the whole local port range"),
            Self::DuplicateAllowedPort(port) => {
                write!(formatter, "TCP port {port} was allowed twice")
            }
            Self::TooManyAllowedPorts => write!(
                formatter,
                "more than {MAX_ALLOWED_PORTS} allowed TCP ports were requested"
            ),
            Self::RulesetRefused(detail) => {
                write!(formatter, "the Landlock ruleset was refused: {detail}")
            }
            Self::NotFullyEnforced => {
                formatter.write_str("the kernel did not fully enforce the requested ruleset")
            }
            Self::NoNewPrivs => {
                formatter.write_str("PR_SET_NO_NEW_PRIVS is not set on the restricted thread")
            }
            Self::UnnamedAbi => {
                formatter.write_str("the kernel reported a Landlock ABI this build cannot name")
            }
        }
    }
}

impl std::error::Error for TcpPolicyError {}

/// The running kernel's Landlock ABI, as observed at enforcement time.
///
/// This is the kernel's own version, not the version of the access rights this
/// module handled. Those are always exactly [`REQUIRED_LANDLOCK_ABI`]'s, so
/// `effective` being higher does not mean anything extra was denied.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LandlockAbi {
    effective: u8,
    kernel_newer_than_known: Option<i32>,
}

impl LandlockAbi {
    /// Highest ABI both the kernel and this build understand.
    #[must_use]
    pub const fn effective(self) -> u8 {
        self.effective
    }

    /// The kernel's own ABI when it is newer than any this build knows.
    ///
    /// `Some` means the kernel offers Landlock features this build does not
    /// request. It never means more was denied than [`Self::effective`] covers.
    #[must_use]
    pub const fn kernel_newer_than_known(self) -> Option<i32> {
        self.kernel_newer_than_known
    }

    fn from_status(status: LandlockStatus) -> Result<Self, TcpPolicyError> {
        match status {
            LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
                Err(TcpPolicyError::LandlockUnavailable)
            }
            LandlockStatus::Available {
                effective_abi,
                kernel_abi,
            } => Ok(Self {
                effective: abi_ordinal(effective_abi).ok_or(TcpPolicyError::UnnamedAbi)?,
                kernel_newer_than_known: kernel_abi,
            }),
        }
    }
}

impl fmt::Display for LandlockAbi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.effective)?;
        if let Some(kernel) = self.kernel_newer_than_known {
            write!(
                formatter,
                " (kernel reports {kernel}, newer than this build)"
            )?;
        }
        Ok(())
    }
}

/// Number of a Landlock ABI this build can name.
///
/// `landlock::ABI` is `#[non_exhaustive]`, so a version this build does not
/// name is representable. Returning `None` rather than guessing a number keeps
/// the reported ABI honest; the caller turns it into a refusal.
fn abi_ordinal(abi: ABI) -> Option<u8> {
    match abi {
        ABI::Unsupported => Some(0),
        ABI::V1 => Some(1),
        ABI::V2 => Some(2),
        ABI::V3 => Some(3),
        ABI::V4 => Some(4),
        ABI::V5 => Some(5),
        ABI::V6 => Some(6),
        ABI::V7 => Some(7),
        ABI::V8 => Some(8),
        ABI::V9 => Some(9),
        _ => None,
    }
}

/// Proof that a TCP restriction is installed on the calling thread.
///
/// Only constructed after the kernel reported full enforcement, so holding one
/// means the restriction is real. What it is a restriction *of* is the narrow
/// thing the module documentation describes, not network denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcedTcpRestriction {
    landlock_abi: LandlockAbi,
    tcp_identification_erratum_reported_fixed: bool,
}

impl EnforcedTcpRestriction {
    /// The running kernel's Landlock ABI.
    #[must_use]
    pub const fn landlock_abi(self) -> LandlockAbi {
        self.landlock_abi
    }

    /// Whether the kernel reported Landlock erratum 1 as fixed.
    ///
    /// `false` does **not** mean the kernel is unfixed: a kernel with no errata
    /// interface at all reports nothing, and is indistinguishable here from one
    /// that reports the erratum outstanding. Either way this module's claims do
    /// not depend on the answer — the erratum only ever made the restriction
    /// wider than documented, by also catching SMC, MPTCP, and SCTP stream
    /// sockets. Treat `true` as "those protocols are definitely *not* covered".
    #[must_use]
    pub const fn tcp_identification_erratum_reported_fixed(self) -> bool {
        self.tcp_identification_erratum_reported_fixed
    }
}

/// A policy over TCP `bind(2)` and `connect(2)`, and nothing else.
///
/// The default is total denial of both. Exceptions are explicit, bounded, and
/// port-scoped.
///
/// # Exceptions are ports, not endpoints
///
/// A Landlock network rule names a port and nothing else. Allowing connect on
/// port 8080 allows connecting to port 8080 on *every* address the workload can
/// route to, not just the loopback service the caller had in mind. There is no
/// ABI-4 way to scope a rule to an address, so a caller that needs one must not
/// pretend this provides it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpBindConnectPolicy {
    allowed_connect_ports: Vec<u16>,
    allowed_bind_ports: Vec<u16>,
}

impl TcpBindConnectPolicy {
    /// Deny every TCP `bind` and `connect`. This is also [`Default`].
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allowed_connect_ports: Vec::new(),
            allowed_bind_ports: Vec::new(),
        }
    }

    /// Permit `connect(2)` to `port` — on any address. See the type docs.
    pub fn allowing_connect_port(mut self, port: u16) -> Result<Self, TcpPolicyError> {
        push_port(&mut self.allowed_connect_ports, port)?;
        Ok(self)
    }

    /// Permit `bind(2)` to `port`.
    pub fn allowing_bind_port(mut self, port: u16) -> Result<Self, TcpPolicyError> {
        push_port(&mut self.allowed_bind_ports, port)?;
        Ok(self)
    }

    /// Ports a restricted thread may still connect to, on any address.
    #[must_use]
    pub fn allowed_connect_ports(&self) -> &[u16] {
        &self.allowed_connect_ports
    }

    /// Ports a restricted thread may still bind.
    #[must_use]
    pub fn allowed_bind_ports(&self) -> &[u16] {
        &self.allowed_bind_ports
    }

    /// Whether this policy grants no TCP exception at all.
    #[must_use]
    pub fn denies_all_tcp(&self) -> bool {
        self.allowed_connect_ports.is_empty() && self.allowed_bind_ports.is_empty()
    }

    /// Whether the running kernel can enforce a policy of this kind.
    ///
    /// Read-only and side-effect free: it builds no ruleset file descriptor and
    /// restricts nothing, so a supervisor can call it *before* forking and
    /// refuse the run without poisoning itself. Both probes ask the `landlock`
    /// crate to hard-require an access set rather than silently degrade, so a
    /// failure is a genuine kernel answer and not a compatibility fallback.
    pub fn check_kernel_support() -> Result<(), TcpPolicyError> {
        // Filesystem rights exist since ABI 1, so failing this means Landlock
        // is absent outright rather than merely old.
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .map_err(|_| TcpPolicyError::LandlockUnavailable)?;
        // Failing only this second probe pins the kernel at ABI 1 to 3.
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(HANDLED_ABI))
            .map_err(|_| TcpPolicyError::TcpRulesUnsupported)?;
        Ok(())
    }

    /// Install this policy on the calling thread, irreversibly.
    ///
    /// Run this in a freshly forked child immediately before `execv`; see the
    /// module docs for why it cannot be undone and why it reaches only the
    /// calling thread.
    ///
    /// The ruleset handles TCP access rights only. It deliberately does not
    /// handle filesystem access: a ruleset that handled `AccessFs` without also
    /// carrying path rules would deny the child the `execv` it exists to
    /// perform. Filesystem restriction is a separate Landlock domain, stacked
    /// by a separate module.
    pub fn enforce_on_current_thread(&self) -> Result<EnforcedTcpRestriction, TcpPolicyError> {
        Self::check_kernel_support()?;
        // Queried before restricting so the reported value describes the kernel
        // rather than anything this call did.
        let erratum_fixed = Erratum::current().contains(Erratum::TcpSocketIdentification);

        // `HardRequirement` propagates from the builder into the created
        // ruleset, so a rule the kernel cannot honour is an error rather than a
        // quietly dropped exception.
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(HANDLED_ABI))
            .map_err(refused)?
            .create()
            .map_err(refused)?;
        for &port in &self.allowed_connect_ports {
            ruleset = ruleset
                .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                .map_err(refused)?;
        }
        for &port in &self.allowed_bind_ports {
            ruleset = ruleset
                .add_rule(NetPort::new(port, AccessNet::BindTcp))
                .map_err(refused)?;
        }
        let status = ruleset.restrict_self().map_err(refused)?;

        // Past this point the thread is restricted. Every remaining check can
        // only turn a real restriction into a refusal, never the reverse.
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(TcpPolicyError::NotFullyEnforced);
        }
        if !status.no_new_privs {
            return Err(TcpPolicyError::NoNewPrivs);
        }
        let landlock_abi = LandlockAbi::from_status(status.landlock)?;
        if landlock_abi.effective() < REQUIRED_LANDLOCK_ABI {
            // Unreachable while the ABI-4 access set is hard-required, and kept
            // as a standing assertion rather than a comment.
            return Err(TcpPolicyError::TcpRulesUnsupported);
        }
        Ok(EnforcedTcpRestriction {
            landlock_abi,
            tcp_identification_erratum_reported_fixed: erratum_fixed,
        })
    }
}

fn push_port(ports: &mut Vec<u16>, port: u16) -> Result<(), TcpPolicyError> {
    if port == 0 {
        return Err(TcpPolicyError::EphemeralPortRefused);
    }
    if ports.contains(&port) {
        return Err(TcpPolicyError::DuplicateAllowedPort(port));
    }
    if ports.len() >= MAX_ALLOWED_PORTS {
        return Err(TcpPolicyError::TooManyAllowedPorts);
    }
    ports.push(port);
    Ok(())
}

fn refused<E: fmt::Display>(error: E) -> TcpPolicyError {
    TcpPolicyError::RulesetRefused(error.to_string())
}
