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
//! 3. replaces stdin with `/dev/null`, so the workload cannot read the plan
//!    channel;
//! 4. closes every descriptor except the standard streams and verifies the
//!    closure ([`crate::descriptors`]);
//! 5. installs the plan's Landlock filesystem allowlist
//!    ([`crate::filesystem`]);
//! 6. installs the plan's Landlock TCP policy ([`crate::network`]);
//! 7. installs the plan's seccomp socket-family filter ([`crate::seccomp`]),
//!    which denies creating every socket shape the plan does not grant —
//!    including UDP, raw and packet sockets, and non-TCP stream protocols
//!    that Landlock's TCP rules cannot see;
//! 8. `execve`s the workload with an empty environment.
//!
//! Any failure at any step exits with [`crate::HELPER_REFUSED_EXIT`] before
//! the workload runs. The workload's very first instruction therefore executes
//! inside the cgroup, behind both Landlock domains and the socket filter,
//! with exactly three open descriptors and no inherited environment.
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

use crate::containment::join_and_confirm_membership;
use crate::descriptors::{DescriptorAllowlist, close_all_except, verify_only_allowlist_open};
use crate::filesystem::{FilesystemPolicy, PathIntent};
use crate::network::TcpBindConnectPolicy;
use crate::seccomp::SocketFamilyPolicy;
use crate::{HELPER_REFUSED_EXIT, RunContainment};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPlan {
    program: PathBuf,
    arguments: Vec<Vec<u8>>,
    filesystem: Vec<(PathIntent, PathBuf)>,
    connect_ports: Vec<u16>,
    bind_ports: Vec<u16>,
    socket_grants: Vec<SocketGrant>,
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
}

impl SocketGrant {
    /// Stable frame spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::UnixSeqPacket => "unix-seqpacket",
            Self::Tcp => "tcp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "unix" => Some(Self::Unix),
            "unix-seqpacket" => Some(Self::UnixSeqPacket),
            "tcp" => Some(Self::Tcp),
            _ => None,
        }
    }
}

impl LaunchPlan {
    /// Start a plan for `program`, which must be a bounded absolute path.
    ///
    /// The program is executed by exact path with an empty environment; there
    /// is no `PATH` search and no inherited variable.
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

    /// Exact workload program path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
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
    fn check_layer_consistency(&self) -> Result<(), LaunchPlanError> {
        if (!self.connect_ports.is_empty() || !self.bind_ports.is_empty())
            && !self.socket_grants.contains(&SocketGrant::Tcp)
        {
            return Err(LaunchPlanError::PolicyRejected(
                "TCP port exceptions require the tcp socket grant".to_owned(),
            ));
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

/// Spawn the entry helper for `plan` inside `containment`.
///
/// The returned [`Child`] is the entry helper, which becomes the workload on
/// success. The caller owns waiting on it and disposing of the containment;
/// dropping the containment kills the whole launched tree.
///
/// `helper` is the path to the `automonique-launch-enter` binary. The caller
/// chooses it deliberately — a production supervisor must pass a
/// release-pinned path, and this function does not guess one.
pub fn spawn_sandboxed(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
) -> Result<Child, LaunchError> {
    let frame = plan.encode()?;
    let mut child = Command::new(helper)
        .env_clear()
        .env(crate::CGROUP_DIR_ENV, containment.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
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

    // 3. The plan channel must not reach the workload: stdin becomes
    //    /dev/null before descriptors are sealed.
    let devnull = File::open("/dev/null").map_err(|_| "/dev/null unavailable".to_owned())?;
    nix::unistd::dup2(devnull.as_raw_fd(), 0).map_err(|_| "stdin replacement failed".to_owned())?;
    drop(devnull);

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

    // 8. Exact program, exact argv, empty environment.
    let program = CString::new(plan.program.as_os_str().as_encoded_bytes().to_vec())
        .map_err(|_| "program path contains NUL".to_owned())?;
    let mut argv = Vec::with_capacity(plan.arguments.len() + 1);
    argv.push(program.clone());
    for argument in &plan.arguments {
        argv.push(CString::new(argument.clone()).map_err(|_| "argument contains NUL".to_owned())?);
    }
    let environment: [CString; 0] = [];
    nix::unistd::execve(&program, &argv, &environment)
        .map_err(|error| format!("execve failed: {error}"))?;
    unreachable!("execve returned without an error")
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
