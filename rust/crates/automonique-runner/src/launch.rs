// SPDX-License-Identifier: Elastic-2.0

//! Composed sandboxed launch: cgroup, descriptors, filesystem, TCP.
//!
//! This module composes the crate's four enforcement mechanisms into one
//! trusted entry helper that runs as the supervisor's direct child and, in
//! order:
//!
//! 1. reads a bounded, typed [`LaunchPlan`] frame from stdin — never argv, so
//!    no plan content appears in process listings;
//! 2. migrates itself into the run's [`RunContainment`] cgroup and confirms
//!    membership from the kernel ([`crate::containment`]);
//! 3. replaces stdin with the prompt descriptor the plan names — an anonymous,
//!    sealed, memory-backed file — or with `/dev/null` when it names none, so
//!    the workload cannot read the plan channel either way;
//! 4. closes every descriptor except the standard streams and verifies the
//!    closure ([`crate::descriptors`]);
//! 5. installs the plan's Landlock filesystem allowlist
//!    ([`crate::filesystem`]);
//! 6. installs the plan's Landlock TCP policy ([`crate::network`]);
//! 7. installs the plan's seccomp socket-family filter ([`crate::seccomp`]),
//!    which denies creating every socket shape the plan does not grant —
//!    including UDP, raw and packet sockets, and non-TCP stream protocols
//!    that Landlock's TCP rules cannot see;
//! 8. `execve`s the workload with exactly the environment the plan names.
//!
//! Any failure at any step exits with [`crate::HELPER_REFUSED_EXIT`] before
//! the workload runs. The workload's very first instruction therefore executes
//! inside the cgroup, behind both Landlock domains and the socket filter, with
//! exactly three open descriptors and exactly the environment the plan spells
//! out — empty unless it spells one, and never anything inherited.
//!
//! # Why this order
//!
//! The cgroup join, the membership read-back, the descriptor enumeration, and
//! the plan parse all need `/proc` and cgroupfs access that the workload's
//! filesystem allowlist must not contain, so every one of them happens before
//! Landlock enforcement. Descriptor closure precedes Landlock because its
//! verification re-reads `/proc/self/fd`, which the Landlock domain denies.
//! The residue this ordering accepts is bounded and named: between closure
//! verification and `execve`, the only descriptors this process creates are
//! the Landlock crate's ruleset and grant-path descriptors, which are opened
//! close-on-exec and dropped before `execve`; they cannot reach the workload.
//!
//! The prompt descriptor occupies the same pre-Landlock window, for three
//! reasons rather than one. Landlock governs path resolution, not descriptors
//! already open — the principle [`crate::network`] relies on for inherited
//! sockets — so a descriptor created before enforcement keeps working after
//! it, and the workload's filesystem allowlist need not mention the prompt at
//! all. But a descriptor is still a descriptor, so it must exist before
//! closure verifies the fd table; it is written, sealed, and `dup2`ed onto
//! fd 0 in exactly the slot `/dev/null` otherwise occupies, and the original
//! is closed immediately. And it is created *after* the cgroup join, so the
//! pages holding the prompt are charged to the run's own memory bound rather
//! than to the supervisor's.
//!
//! # What a composed launch does **not** establish
//!
//! - **It is not complete network denial.** The TCP policy governs TCP
//!   `bind`/`connect` and the socket filter denies creating undeclared socket
//!   shapes, but sockets inherited before enforcement, `SCM_RIGHTS` passing
//!   over a granted `AF_UNIX` socket, and io_uring paths are each only as
//!   closed as [`crate::descriptors`], the plan's grants, and
//!   [`crate::seccomp`]'s io_uring denial make them; see those modules for
//!   the exact residual surface.
//! - **It does not protect against a same-uid attacker.** The plan travels
//!   over a private pipe and the cgroup is delegation-checked, but a process
//!   of the same uid outside the sandbox can already trace the supervisor.
//! - **Environment values are not hidden from the host.** Frame delivery keeps
//!   them out of argv, so no process listing shows them, but from `execve`
//!   until exit any same-uid reader can read `/proc/<pid>/environ`. That is
//!   the same-uid limit named above rather than a new one, and it is the
//!   reason a secret placed in the environment is a secret shared with the
//!   whole host account.
//! - **The prompt is closed to the path namespace, not to the host.** Prompt
//!   bytes live in an anonymous memory-backed file that no directory entry
//!   names, so there is no path to open and no grant that could reach it, and
//!   its seals make the bytes immutable — the workload cannot rewrite its own
//!   prompt and hand a different one to a child. A same-uid reader can still
//!   reach the same bytes through `/proc/<pid>/fd/0`.
//! - **Naming a variable can name a mechanism.** `LD_PRELOAD`,
//!   `LD_LIBRARY_PATH` and their kin change what a dynamically linked program
//!   loads. There is deliberately no denylist here: a denylist would be
//!   hidden policy, the plan is the review point, and what such a variable can
//!   actually reach is bounded by the filesystem allowlist, not by this API.
//! - **It is not attestation.** Nothing here proves to a third party what
//!   was launched; the release-manifest trust chain is a separate concern.
//! - **The supervisor cannot distinguish a helper refusal from a workload
//!   that exits with the same code.** [`crate::HELPER_REFUSED_EXIT`] is
//!   reserved by convention, not enforced by the kernel. A later slice adds a
//!   status channel; until then a launch result is evidence the helper ran,
//!   not proof the workload started.
//!
//! # A plan contains exactly what it names
//!
//! There are no implicit grants, and practical workloads notice. Two examples
//! proven by this crate's tests: a dynamically linked program needs
//! read-execute grants over its loader and libraries, not just itself; and a
//! POSIX shell reopens a background job's stdin from `/dev/null`, so a plan
//! whose workload backgrounds anything must grant `/dev/null` read. Both
//! failures are the sandbox working as specified — the fix belongs in the
//! plan, never in a hidden widening here.
//!
//! # Plan frame
//!
//! The frame is line-oriented ASCII. Paths and argument bytes are lowercase
//! hex encoded, so arbitrary bytes — including newlines — cannot corrupt the
//! framing. The frame ends with an explicit terminator line; a frame without
//! it is treated as truncated and refused, so a supervisor that dies mid-write
//! cannot cause a partial policy to be enforced.
//!
//! An `env=` line carries one variable, as `env=<name-hex>:<value-hex>`. Both
//! halves are hex, so the `:` separator is unambiguous and a value may hold
//! any byte but NUL. Names obey a strict grammar — `[A-Z_][A-Z0-9_]*`, at
//! most [`MAX_LAUNCH_ENV_NAME_BYTES`] — values are at most
//! [`MAX_LAUNCH_ENV_VALUE_BYTES`], there are at most
//! [`MAX_LAUNCH_ENV_ENTRIES`] of them, and a repeated name is refused rather
//! than resolved in either direction.
//!
//! A `prompt_hex=` line appears at most once and carries the bytes the
//! workload reads from its own stdin. Its ceiling is chosen so that one
//! prompt can never crowd the rest of a plan out of the frame: at
//! [`MAX_LAUNCH_PROMPT_BYTES`] = 16 KiB the line costs `11 + 2×16384 + 1 =
//! 32780` bytes of the 65536-byte budget, which alongside the 29-byte header
//! and 26-byte terminator leaves 32701 bytes for the program, argv, grants,
//! ports and environment.
//!
//! Per-item ceilings bound shape; the frame bound is separate and binding.
//! Neither 64 maximal argv entries (`64 × 8197 = 524608`) nor four maximal
//! environment entries beside a maximal prompt (`4 × 8454 = 33816`) fit in
//! 65536 bytes, and [`LaunchPlan::encode`] refuses such a plan with
//! [`LaunchPlanError::FrameTooLarge`] rather than truncating it.

use crate::containment::join_and_confirm_membership;
use crate::descriptors::{DescriptorAllowlist, close_all_except, verify_only_allowlist_open};
use crate::filesystem::{FilesystemPolicy, PathIntent};
use crate::network::TcpBindConnectPolicy;
use crate::seccomp::SocketFamilyPolicy;
use crate::{HELPER_REFUSED_EXIT, RunContainment};
use nix::fcntl::{FcntlArg, SealFlag};
use nix::sys::memfd::MemFdCreateFlag;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Exact first line of every launch plan frame.
pub const FRAME_HEADER: &str = "schema=automonique.launch/v1";
/// Exact final line of every complete launch plan frame.
pub const FRAME_TERMINATOR: &str = "end=automonique.launch/v1";
/// Upper bound on one encoded frame, matching the spool's event bound.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Upper bound on workload argv entries, beyond the program itself.
pub const MAX_LAUNCH_ARGS: usize = 64;
/// Upper bound on one argv entry or path, in raw bytes before encoding.
pub const MAX_LAUNCH_ARG_BYTES: usize = 4096;
/// Upper bound on environment entries one plan may name.
pub const MAX_LAUNCH_ENV_ENTRIES: usize = 32;
/// Upper bound on one environment variable name, in raw bytes.
pub const MAX_LAUNCH_ENV_NAME_BYTES: usize = 128;
/// Upper bound on one environment variable value, in raw bytes.
pub const MAX_LAUNCH_ENV_VALUE_BYTES: usize = 4096;
/// Upper bound on the prompt delivered as the workload's stdin, in raw bytes.
///
/// See the module's frame-grammar section for the budget arithmetic that
/// picks this number.
pub const MAX_LAUNCH_PROMPT_BYTES: usize = 16 * 1024;

/// Why a launch plan is refused, before any child exists.
///
/// Every variant is a refusal; none means "launched with less than asked".
#[derive(Debug)]
pub enum LaunchPlanError {
    /// The workload program path is empty, relative, or oversized.
    ProgramRejected,
    /// An argv entry is oversized, or there are too many.
    ArgumentsRejected,
    /// A path, argument, or port failed policy validation.
    PolicyRejected(String),
    /// An environment entry is malformed, oversized, repeated, or one too
    /// many. The reason names no plan content, because helper refusals reach
    /// stderr and a variable name is plan content.
    EnvironmentRejected(&'static str),
    /// The prompt is empty, repeated, or exceeds [`MAX_LAUNCH_PROMPT_BYTES`].
    PromptRejected,
    /// The encoded frame exceeds [`MAX_FRAME_BYTES`].
    FrameTooLarge,
    /// The frame is malformed, truncated, or carries an unknown key.
    FrameRejected,
}

impl fmt::Display for LaunchPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgramRejected => {
                formatter.write_str("workload program must be a bounded absolute path")
            }
            Self::ArgumentsRejected => {
                formatter.write_str("workload arguments are oversized or too many")
            }
            Self::PolicyRejected(reason) => write!(formatter, "policy rejected: {reason}"),
            Self::EnvironmentRejected(reason) => {
                write!(formatter, "environment entry rejected: {reason}")
            }
            Self::PromptRejected => write!(
                formatter,
                "prompt must be present at most once, non-empty, and at most \
                 {MAX_LAUNCH_PROMPT_BYTES} bytes"
            ),
            Self::FrameTooLarge => write!(
                formatter,
                "encoded launch frame exceeds {MAX_FRAME_BYTES} bytes"
            ),
            Self::FrameRejected => {
                formatter.write_str("launch frame is malformed, truncated, or has unknown keys")
            }
        }
    }
}

impl std::error::Error for LaunchPlanError {}

/// A complete, validated description of one sandboxed workload launch.
///
/// The plan is data: constructing one launches nothing and enforces nothing.
/// Its encoded frame is what the supervisor delivers to the entry helper.
#[derive(Clone, Eq, PartialEq)]
pub struct LaunchPlan {
    program: PathBuf,
    arguments: Vec<Vec<u8>>,
    filesystem: Vec<(PathIntent, PathBuf)>,
    connect_ports: Vec<u16>,
    bind_ports: Vec<u16>,
    socket_grants: Vec<SocketGrant>,
    environment: Vec<(String, Vec<u8>)>,
    prompt: Option<Vec<u8>>,
}

/// Redacting: a derived `Debug` would print environment values and prompt
/// bytes, which are exactly the two things a plan may carry that a log must
/// never hold. Names and lengths are enough to identify a plan.
impl fmt::Debug for LaunchPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchPlan")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .field("filesystem", &self.filesystem)
            .field("connect_ports", &self.connect_ports)
            .field("bind_ports", &self.bind_ports)
            .field("socket_grants", &self.socket_grants)
            .field(
                "environment_names",
                &self.environment_names().collect::<Vec<_>>(),
            )
            .field("prompt_bytes", &self.prompt_len())
            .finish()
    }
}

/// One socket-creation grant a plan may carry, mirroring the closed grant
/// vocabulary of [`SocketFamilyPolicy`]. The default plan carries none, which
/// denies every `socket(2)` and `socketpair(2)` in the workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketGrant {
    /// `AF_UNIX` stream and datagram sockets, protocol 0.
    Unix,
    /// `AF_UNIX` `SOCK_SEQPACKET` sockets, protocol 0.
    UnixSeqPacket,
    /// IPv4/IPv6 `SOCK_STREAM` TCP sockets only.
    Tcp,
    /// IPv4/IPv6 `SOCK_DGRAM` UDP sockets only — the DNS-resolution grant.
    ///
    /// Wider than [`Self::Tcp`]: the TCP `bind`/`connect` policy cannot bound
    /// where a UDP socket sends, so this permits a workload to reach any
    /// nameserver on port 53. It exists for the pre-broker provider-launch
    /// path where a provider does its own DNS; see
    /// [`crate::seccomp::SocketFamilyPolicy::allowing_inet_datagram_sockets`].
    InetDatagram,
}

impl SocketGrant {
    /// Stable frame spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::UnixSeqPacket => "unix-seqpacket",
            Self::Tcp => "tcp",
            Self::InetDatagram => "inet-datagram",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "unix" => Some(Self::Unix),
            "unix-seqpacket" => Some(Self::UnixSeqPacket),
            "tcp" => Some(Self::Tcp),
            "inet-datagram" => Some(Self::InetDatagram),
            _ => None,
        }
    }
}

impl LaunchPlan {
    /// Start a plan for `program`, which must be a bounded absolute path.
    ///
    /// The program is executed by exact path; there is no `PATH` search, and a
    /// fresh plan carries no environment at all. Variables exist only where
    /// [`LaunchPlan::environment`] puts them, never by inheritance.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, LaunchPlanError> {
        let program = program.into();
        if !program.is_absolute()
            || program.as_os_str().is_empty()
            || program.as_os_str().len() > MAX_LAUNCH_ARG_BYTES
        {
            return Err(LaunchPlanError::ProgramRejected);
        }
        Ok(Self {
            program,
            arguments: Vec::new(),
            filesystem: Vec::new(),
            connect_ports: Vec::new(),
            bind_ports: Vec::new(),
            socket_grants: Vec::new(),
            environment: Vec::new(),
            prompt: None,
        })
    }

    /// Permit the workload to create sockets of `grant`'s shape.
    ///
    /// Without any grant, every `socket(2)` and `socketpair(2)` in the
    /// workload fails with `EPERM`. A TCP port exception without
    /// [`SocketGrant::Tcp`] is a contradiction the plan refuses at encode and
    /// decode time rather than resolving silently in either direction.
    pub fn socket_grant(mut self, grant: SocketGrant) -> Result<Self, LaunchPlanError> {
        if self.socket_grants.contains(&grant) {
            return Err(LaunchPlanError::PolicyRejected(format!(
                "duplicate socket grant {}",
                grant.as_str()
            )));
        }
        // Validate against the real policy builder so a plan can never carry
        // a grant set the seccomp module would refuse.
        let mut widened = self.socket_grants.clone();
        widened.push(grant);
        socket_policy_from_grants(&widened)
            .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        self.socket_grants = widened;
        Ok(self)
    }

    /// Append one workload argument (after `argv[0]`, which is the program).
    pub fn argument(mut self, value: impl AsRef<[u8]>) -> Result<Self, LaunchPlanError> {
        let value = value.as_ref();
        if value.len() > MAX_LAUNCH_ARG_BYTES || self.arguments.len() >= MAX_LAUNCH_ARGS {
            return Err(LaunchPlanError::ArgumentsRejected);
        }
        if value.contains(&0) {
            return Err(LaunchPlanError::ArgumentsRejected);
        }
        self.arguments.push(value.to_vec());
        Ok(self)
    }

    /// Grant `intent` beneath `path` in the workload's filesystem allowlist.
    ///
    /// Validation is delegated to [`FilesystemPolicy::grant`] at build time so
    /// a plan can never encode a grant the policy type would refuse.
    pub fn filesystem_grant(
        mut self,
        intent: PathIntent,
        path: impl Into<PathBuf>,
    ) -> Result<Self, LaunchPlanError> {
        let path = path.into();
        // Build the policy incrementally to reuse its exact validation.
        let mut policy = FilesystemPolicy::deny_all();
        for (existing_intent, existing_path) in &self.filesystem {
            policy = policy
                .grant(*existing_intent, existing_path.clone())
                .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        }
        policy
            .grant(intent, path.clone())
            .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        self.filesystem.push((intent, path));
        Ok(self)
    }

    /// Permit TCP `connect` to `port` on any address; see [`crate::network`].
    pub fn allow_connect_port(mut self, port: u16) -> Result<Self, LaunchPlanError> {
        let mut policy = self.tcp_policy()?;
        policy = policy
            .allowing_connect_port(port)
            .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        let _ = policy;
        self.connect_ports.push(port);
        Ok(self)
    }

    /// Permit TCP `bind` to `port`.
    pub fn allow_bind_port(mut self, port: u16) -> Result<Self, LaunchPlanError> {
        let mut policy = self.tcp_policy()?;
        policy = policy
            .allowing_bind_port(port)
            .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        let _ = policy;
        self.bind_ports.push(port);
        Ok(self)
    }

    /// Deliver one variable, and by delivering it name it.
    ///
    /// The helper `execve`s with exactly the entries a plan carries: nothing
    /// is inherited from the supervisor and nothing is synthesized, so a
    /// provider that needs `CODEX_HOME` or `SSL_CERT_FILE` gets it because the
    /// plan said so and gets nothing else because the plan did not.
    ///
    /// `name` obeys `[A-Z_][A-Z0-9_]*` within [`MAX_LAUNCH_ENV_NAME_BYTES`];
    /// `value` is arbitrary bytes without NUL, within
    /// [`MAX_LAUNCH_ENV_VALUE_BYTES`]. A repeated name is refused: two
    /// bindings of one variable have no correct resolution, and picking the
    /// first or the last would be a silent policy decision.
    pub fn environment(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, LaunchPlanError> {
        let name = name.as_ref();
        let value = value.as_ref();
        check_environment_entry(name, value)?;
        if self.environment.len() >= MAX_LAUNCH_ENV_ENTRIES {
            return Err(LaunchPlanError::EnvironmentRejected(
                "too many environment entries",
            ));
        }
        if self
            .environment
            .iter()
            .any(|(existing, _)| existing == name)
        {
            return Err(LaunchPlanError::EnvironmentRejected(
                "one name is bound twice",
            ));
        }
        self.environment.push((name.to_owned(), value.to_vec()));
        Ok(self)
    }

    /// Deliver `bytes` to the workload as its stdin.
    ///
    /// Prompt bytes never appear in argv, so no process listing shows them,
    /// and they never travel as a filesystem path, so no grant is needed to
    /// read them. The helper stages them in an anonymous memory-backed file
    /// and hands the workload that descriptor as fd 0 — which is what a
    /// provider invoked with `-` reads. Without this line stdin is
    /// `/dev/null`, exactly as before.
    ///
    /// An empty prompt is refused rather than encoded: "the workload's stdin
    /// is empty" already has one spelling, which is naming no prompt at all.
    pub fn prompt(mut self, bytes: impl AsRef<[u8]>) -> Result<Self, LaunchPlanError> {
        let bytes = bytes.as_ref();
        if self.prompt.is_some() || bytes.is_empty() || bytes.len() > MAX_LAUNCH_PROMPT_BYTES {
            return Err(LaunchPlanError::PromptRejected);
        }
        self.prompt = Some(bytes.to_vec());
        Ok(self)
    }

    /// Exact workload program path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Names this plan delivers, in frame order.
    ///
    /// Values have no accessor on purpose: a plan is built, encoded, and
    /// enforced. Nothing downstream needs to read a secret back out of one.
    pub fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.environment.iter().map(|(name, _)| name.as_str())
    }

    /// Length of the prompt this plan delivers, or `None` when it names none.
    #[must_use]
    pub fn prompt_len(&self) -> Option<usize> {
        self.prompt.as_ref().map(Vec::len)
    }

    fn tcp_policy(&self) -> Result<TcpBindConnectPolicy, LaunchPlanError> {
        let mut policy = TcpBindConnectPolicy::deny_all();
        for &port in &self.connect_ports {
            policy = policy
                .allowing_connect_port(port)
                .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        }
        for &port in &self.bind_ports {
            policy = policy
                .allowing_bind_port(port)
                .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        }
        Ok(policy)
    }

    fn filesystem_policy(&self) -> Result<FilesystemPolicy, LaunchPlanError> {
        let mut policy = FilesystemPolicy::deny_all();
        for (intent, path) in &self.filesystem {
            policy = policy
                .grant(*intent, path.clone())
                .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))?;
        }
        Ok(policy)
    }

    fn socket_policy(&self) -> Result<SocketFamilyPolicy, LaunchPlanError> {
        socket_policy_from_grants(&self.socket_grants)
            .map_err(|error| LaunchPlanError::PolicyRejected(error.to_string()))
    }

    /// Refuse a plan whose layers contradict each other.
    ///
    /// A TCP port exception says "this connect/bind is permitted", while a
    /// socket policy without [`SocketGrant::Tcp`] makes creating the socket
    /// impossible. Widening the socket policy silently would betray the
    /// seccomp layer; dropping the ports silently would betray the caller.
    ///
    /// The environment and prompt bounds are re-checked here rather than
    /// trusted from construction, so that both frame directions enforce them
    /// at the same place: whatever built the value, it does not encode and
    /// does not decode unless every entry still holds.
    fn check_layer_consistency(&self) -> Result<(), LaunchPlanError> {
        if (!self.connect_ports.is_empty() || !self.bind_ports.is_empty())
            && !self.socket_grants.contains(&SocketGrant::Tcp)
        {
            return Err(LaunchPlanError::PolicyRejected(
                "TCP port exceptions require the tcp socket grant".to_owned(),
            ));
        }
        if self.environment.len() > MAX_LAUNCH_ENV_ENTRIES {
            return Err(LaunchPlanError::EnvironmentRejected(
                "too many environment entries",
            ));
        }
        for (index, (name, value)) in self.environment.iter().enumerate() {
            check_environment_entry(name, value)?;
            if self.environment[..index]
                .iter()
                .any(|(earlier, _)| earlier == name)
            {
                return Err(LaunchPlanError::EnvironmentRejected(
                    "one name is bound twice",
                ));
            }
        }
        if self
            .prompt
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_LAUNCH_PROMPT_BYTES)
        {
            return Err(LaunchPlanError::PromptRejected);
        }
        Ok(())
    }

    /// Encode the complete frame the entry helper consumes.
    pub fn encode(&self) -> Result<Vec<u8>, LaunchPlanError> {
        self.check_layer_consistency()?;
        let mut frame = String::new();
        frame.push_str(FRAME_HEADER);
        frame.push('\n');
        frame.push_str(&format!(
            "program={}\n",
            hex(self.program.as_os_str().as_encoded_bytes())
        ));
        for argument in &self.arguments {
            frame.push_str(&format!("arg={}\n", hex(argument)));
        }
        for (intent, path) in &self.filesystem {
            frame.push_str(&format!(
                "grant={}:{}\n",
                intent.as_str(),
                hex(path.as_os_str().as_encoded_bytes())
            ));
        }
        for &port in &self.connect_ports {
            frame.push_str(&format!("connect_port={port}\n"));
        }
        for &port in &self.bind_ports {
            frame.push_str(&format!("bind_port={port}\n"));
        }
        for grant in &self.socket_grants {
            frame.push_str(&format!("socket={}\n", grant.as_str()));
        }
        for (name, value) in &self.environment {
            frame.push_str(&format!("env={}:{}\n", hex(name.as_bytes()), hex(value)));
        }
        if let Some(prompt) = &self.prompt {
            frame.push_str(&format!("prompt_hex={}\n", hex(prompt)));
        }
        frame.push_str(FRAME_TERMINATOR);
        frame.push('\n');
        if frame.len() > MAX_FRAME_BYTES {
            return Err(LaunchPlanError::FrameTooLarge);
        }
        Ok(frame.into_bytes())
    }

    /// Decode a frame, applying exactly the same validation as construction.
    pub fn decode(frame: &[u8]) -> Result<Self, LaunchPlanError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(LaunchPlanError::FrameTooLarge);
        }
        let text = std::str::from_utf8(frame).map_err(|_| LaunchPlanError::FrameRejected)?;
        let mut lines = text.lines();
        if lines.next() != Some(FRAME_HEADER) {
            return Err(LaunchPlanError::FrameRejected);
        }
        let mut plan: Option<Self> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                // Content after the terminator means the framing is broken.
                return Err(LaunchPlanError::FrameRejected);
            }
            if line == FRAME_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(LaunchPlanError::FrameRejected)?;
            match (key, &mut plan) {
                ("program", None) => {
                    let bytes = unhex(value).ok_or(LaunchPlanError::FrameRejected)?;
                    let path = os_string_from_bytes(bytes)?;
                    plan = Some(Self::new(PathBuf::from(path))?);
                }
                ("program", Some(_)) => return Err(LaunchPlanError::FrameRejected),
                ("arg", Some(current)) => {
                    let bytes = unhex(value).ok_or(LaunchPlanError::FrameRejected)?;
                    *current = current.clone().argument(bytes)?;
                }
                ("grant", Some(current)) => {
                    let (intent, path_hex) = value
                        .split_once(':')
                        .ok_or(LaunchPlanError::FrameRejected)?;
                    let intent = match intent {
                        "read" => PathIntent::Read,
                        "read-write" => PathIntent::ReadWrite,
                        "read-execute" => PathIntent::ReadExecute,
                        _ => return Err(LaunchPlanError::FrameRejected),
                    };
                    let bytes = unhex(path_hex).ok_or(LaunchPlanError::FrameRejected)?;
                    let path = os_string_from_bytes(bytes)?;
                    *current = current
                        .clone()
                        .filesystem_grant(intent, PathBuf::from(path))?;
                }
                ("connect_port", Some(current)) => {
                    let port = value
                        .parse::<u16>()
                        .map_err(|_| LaunchPlanError::FrameRejected)?;
                    *current = current.clone().allow_connect_port(port)?;
                }
                ("bind_port", Some(current)) => {
                    let port = value
                        .parse::<u16>()
                        .map_err(|_| LaunchPlanError::FrameRejected)?;
                    *current = current.clone().allow_bind_port(port)?;
                }
                ("socket", Some(current)) => {
                    let grant = SocketGrant::parse(value).ok_or(LaunchPlanError::FrameRejected)?;
                    *current = current.clone().socket_grant(grant)?;
                }
                ("env", Some(current)) => {
                    let (name_hex, value_hex) = value
                        .split_once(':')
                        .ok_or(LaunchPlanError::FrameRejected)?;
                    let name = unhex(name_hex).ok_or(LaunchPlanError::FrameRejected)?;
                    let name =
                        String::from_utf8(name).map_err(|_| LaunchPlanError::FrameRejected)?;
                    let value = unhex(value_hex).ok_or(LaunchPlanError::FrameRejected)?;
                    *current = current.clone().environment(name, value)?;
                }
                ("prompt_hex", Some(current)) => {
                    let bytes = unhex(value).ok_or(LaunchPlanError::FrameRejected)?;
                    // A second prompt line refuses here: the builder already
                    // holds one, and there is no rule for which would win.
                    *current = current.clone().prompt(bytes)?;
                }
                _ => return Err(LaunchPlanError::FrameRejected),
            }
        }
        if !terminated {
            return Err(LaunchPlanError::FrameRejected);
        }
        let plan = plan.ok_or(LaunchPlanError::FrameRejected)?;
        plan.check_layer_consistency()?;
        Ok(plan)
    }
}

/// Why a supervised launch failed before the workload could exist.
#[derive(Debug)]
pub enum LaunchError {
    Plan(LaunchPlanError),
    Io(std::io::Error),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "launch plan refused: {error}"),
            Self::Io(error) => write!(formatter, "launch I/O failed: {error}"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl From<LaunchPlanError> for LaunchError {
    fn from(value: LaunchPlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<std::io::Error> for LaunchError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// What the supervisor does with the workload's stdout.
///
/// Deliberately a choice rather than a default. A piped stdout that nobody
/// reads fills its kernel buffer and stops the workload mid-write, so the
/// decision to pipe and the obligation to read are the same decision, and this
/// enum is where a caller states it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdoutCapture {
    /// The workload writes to the supervisor's own stdout.
    ///
    /// The historical behaviour, and still the right one for a workload nobody
    /// is normalizing: it costs no pipe, no thread and no buffer.
    Inherit,
    /// The supervisor holds the read end and must drain it.
    Piped,
}

impl StdoutCapture {
    fn stdio(self) -> Stdio {
        match self {
            Self::Inherit => Stdio::inherit(),
            Self::Piped => Stdio::piped(),
        }
    }
}

/// Spawn the entry helper for `plan` inside `containment`.
///
/// The returned [`Child`] is the entry helper, which becomes the workload on
/// success. The caller owns waiting on it and disposing of the containment;
/// dropping the containment kills the whole launched tree.
///
/// `helper` is the path to the `automonique-launch-enter` binary. The caller
/// chooses it deliberately — a production supervisor must pass a
/// release-pinned path, and this function does not guess one.
///
/// The workload's stdout is inherited. To read it instead, see
/// [`spawn_sandboxed_with_stdout`] — and read it, or the workload stops.
pub fn spawn_sandboxed(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
) -> Result<Child, LaunchError> {
    spawn_sandboxed_with_stdout(helper, plan, containment, StdoutCapture::Inherit)
}

/// Spawn the entry helper, choosing what becomes of the workload's stdout.
///
/// Everything else is [`spawn_sandboxed`]: same frame on the same piped stdin,
/// same cleared environment, same single containment variable, and stderr still
/// the supervisor's own — a diagnostic line is a diagnostic line whether or not
/// anyone is normalizing the transcript.
///
/// # Errors
///
/// Returns [`LaunchError::Plan`] for a plan that will not encode and
/// [`LaunchError::Io`] for a spawn or a frame write that fails.
pub fn spawn_sandboxed_with_stdout(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
    stdout: StdoutCapture,
) -> Result<Child, LaunchError> {
    let frame = plan.encode()?;
    let mut child = Command::new(helper)
        .env_clear()
        .env(crate::CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(stdout.stdio())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin was requested piped");
    stdin.write_all(&frame)?;
    drop(stdin);
    Ok(child)
}

/// Entry-helper process body for a composed sandboxed launch.
///
/// See the module documentation for the exact sequence. Every failure exits
/// with [`HELPER_REFUSED_EXIT`] before the workload runs; the reason is
/// written to stderr as a single bounded line containing no plan content.
#[must_use]
pub fn launch_entry_helper_main() -> i32 {
    match enter_enforce_and_exec() {
        Ok(never) => match never {},
        Err(reason) => {
            // One bounded diagnostic line; plan content is deliberately absent.
            eprintln!("automonique-launch-enter: refused: {reason}");
            HELPER_REFUSED_EXIT
        }
    }
}

/// Uninhabited: success is `execve`, which does not return.
enum Never {}

fn enter_enforce_and_exec() -> Result<Never, String> {
    // 1. The plan arrives on stdin, bounded, and must be complete.
    let mut frame = Vec::new();
    std::io::stdin()
        .lock()
        .take(u64::try_from(MAX_FRAME_BYTES + 1).expect("constant fits"))
        .read_to_end(&mut frame)
        .map_err(|_| "plan frame unreadable".to_owned())?;
    let plan = LaunchPlan::decode(&frame).map_err(|error| error.to_string())?;

    // 2. Enter the cgroup before the workload exists; confirm from the kernel.
    let target = std::env::var_os(crate::CGROUP_DIR_ENV)
        .ok_or_else(|| "no containment target".to_owned())?;
    join_and_confirm_membership(Path::new(&target)).map_err(|error| error.to_string())?;

    // 3. The plan channel must not reach the workload: stdin becomes the
    //    plan's prompt descriptor, or /dev/null when it names no prompt.
    //    Either source is opened before descriptor closure, so the closure
    //    verification below still proves exactly the standard streams remain,
    //    and after the dup2 the original is closed immediately.
    let stdin_source = match plan.prompt.as_deref() {
        Some(prompt) => sealed_prompt_descriptor(prompt)?,
        None => File::open("/dev/null").map_err(|_| "/dev/null unavailable".to_owned())?,
    };
    nix::unistd::dup2(stdin_source.as_raw_fd(), 0)
        .map_err(|_| "stdin replacement failed".to_owned())?;
    drop(stdin_source);

    // 4. Close and verify descriptors while /proc is still reachable.
    let allowlist = DescriptorAllowlist::standard_streams();
    close_all_except(&allowlist).map_err(|error| error.to_string())?;
    verify_only_allowlist_open(&allowlist).map_err(|error| error.to_string())?;

    // 5–6. Landlock domains. Anything the crate opens here is close-on-exec
    //      and dropped before execve, so it cannot reach the workload.
    plan.filesystem_policy()
        .map_err(|error| error.to_string())?
        .enforce_on_current_thread()
        .map_err(|error| error.to_string())?;
    plan.tcp_policy()
        .map_err(|error| error.to_string())?
        .enforce_on_current_thread()
        .map_err(|error| error.to_string())?;

    // 7. The seccomp socket-family filter closes what Landlock cannot reach:
    //    UDP, raw and packet sockets, and non-TCP stream protocols. It is
    //    installed last so its own installation needs no carve-outs in the
    //    layers above, and like them it survives execve.
    plan.socket_policy()
        .map_err(|error| error.to_string())?
        .apply_to_current_thread()
        .map_err(|error| error.to_string())?;

    // 8. Exact program, exact argv, exactly the named environment — which is
    //    empty when the plan named none, as every plan did before `env=`
    //    existed.
    let program = CString::new(plan.program.as_os_str().as_encoded_bytes().to_vec())
        .map_err(|_| "program path contains NUL".to_owned())?;
    let mut argv = Vec::with_capacity(plan.arguments.len() + 1);
    argv.push(program.clone());
    for argument in &plan.arguments {
        argv.push(CString::new(argument.clone()).map_err(|_| "argument contains NUL".to_owned())?);
    }
    let mut environment = Vec::with_capacity(plan.environment.len());
    for (name, value) in &plan.environment {
        let mut entry = Vec::with_capacity(name.len() + 1 + value.len());
        entry.extend_from_slice(name.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(value);
        environment
            .push(CString::new(entry).map_err(|_| "environment entry contains NUL".to_owned())?);
    }
    nix::unistd::execve(&program, &argv, &environment)
        .map_err(|error| format!("execve failed: {error}"))?;
    unreachable!("execve returned without an error")
}

/// An anonymous, sealed, memory-backed descriptor holding `prompt`, rewound.
///
/// `memfd_create` rather than an unlinked temporary file, for three reasons.
/// The buffer has no name in any directory — not even for the instant between
/// `open` and `unlink` that a temp file would need — so there is no path a
/// racing same-uid process could open and no window in which one exists. It
/// needs no writable directory, so it does not depend on `/tmp` existing, on
/// `TMPDIR`, or on the plan granting anything: the filesystem allowlist stays
/// exactly what the plan wrote. And it can be sealed, which an ordinary file
/// cannot, so the bytes become immutable before any workload sees them.
///
/// The descriptor is created close-on-exec; the `dup2` onto fd 0 in the caller
/// produces a descriptor that is *not* close-on-exec, which is what carries
/// the prompt across `execve`.
fn sealed_prompt_descriptor(prompt: &[u8]) -> Result<File, String> {
    let name = CString::new("automonique-prompt").expect("literal has no interior NUL");
    let descriptor = nix::sys::memfd::memfd_create(
        &name,
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING,
    )
    .map_err(|error| format!("prompt descriptor unavailable: {error}"))?;
    let mut file = File::from(descriptor);
    file.write_all(prompt)
        .map_err(|_| "prompt could not be staged".to_owned())?;
    // Seal before the workload can reach it: writing, growing and shrinking
    // are all closed, and F_SEAL_SEAL closes the sealing itself, so neither
    // the workload nor a descendant can restore any of them.
    nix::fcntl::fcntl(
        file.as_raw_fd(),
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|error| format!("prompt could not be sealed: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "prompt rewind failed".to_owned())?;
    Ok(file)
}

/// Shape check for one environment entry, shared by construction and decode.
///
/// The reasons deliberately quote nothing: a refusal reaches the supervisor's
/// stderr, and a variable name is plan content.
fn check_environment_entry(name: &str, value: &[u8]) -> Result<(), LaunchPlanError> {
    let name = name.as_bytes();
    if name.is_empty() || name.len() > MAX_LAUNCH_ENV_NAME_BYTES {
        return Err(LaunchPlanError::EnvironmentRejected(
            "environment name is empty or oversized",
        ));
    }
    let shaped = matches!(name[0], b'A'..=b'Z' | b'_')
        && name
            .iter()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
    if !shaped {
        return Err(LaunchPlanError::EnvironmentRejected(
            "environment name is not [A-Z_][A-Z0-9_]*",
        ));
    }
    if value.len() > MAX_LAUNCH_ENV_VALUE_BYTES {
        return Err(LaunchPlanError::EnvironmentRejected(
            "environment value is oversized",
        ));
    }
    if value.contains(&0) {
        return Err(LaunchPlanError::EnvironmentRejected(
            "environment value contains NUL",
        ));
    }
    Ok(())
}

fn socket_policy_from_grants(
    grants: &[SocketGrant],
) -> Result<SocketFamilyPolicy, crate::seccomp::SocketFilterError> {
    let mut policy = SocketFamilyPolicy::deny_all();
    for grant in grants {
        policy = match grant {
            SocketGrant::Unix => policy.allowing_unix_sockets()?,
            SocketGrant::UnixSeqPacket => policy.allowing_unix_seqpacket_sockets()?,
            SocketGrant::Tcp => policy.allowing_tcp_sockets()?,
            SocketGrant::InetDatagram => policy.allowing_inet_datagram_sockets()?,
        };
    }
    Ok(policy)
}

fn os_string_from_bytes(bytes: Vec<u8>) -> Result<std::ffi::OsString, LaunchPlanError> {
    // Paths in this crate are Unix byte strings; refuse interior NUL early so
    // the CString conversion at exec time cannot be the first to notice.
    if bytes.contains(&0) {
        return Err(LaunchPlanError::FrameRejected);
    }
    use std::os::unix::ffi::OsStringExt as _;
    Ok(std::ffi::OsString::from_vec(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
