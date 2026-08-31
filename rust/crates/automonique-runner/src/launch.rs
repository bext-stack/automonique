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
//! 3. opens the workload once, copies the bytes into an anonymous
//!    memory-backed image, seals it, and verifies the digest by reading the
//!    sealed object back — so the digest describes the immutable object
//!    `execveat` will consume, not a buffer that once held its bytes;
//! 4. when the plan carries `identity=subordinate`, gives itself the workload
//!    identity ([`crate::identity`]): an unprivileged user namespace whose
//!    subordinate mapping is written by the host's setuid
//!    `newuidmap`/`newgidmap`, a uid switch inside it to a host uid that is
//!    not the supervisor's, and a capability set reduced to the three
//!    discretionary-access capabilities the workload keeps over the
//!    supervisor's files — every step read back from the kernel. A plan that
//!    does not ask keeps the supervisor's identity, exactly as before. A
//!    private namespaced-temporary-storage launch additionally creates its
//!    mount namespace and mounts the run's FUSE filesystem here, while the
//!    helper is namespace root but before any workload instruction runs;
//! 5. replaces stdin with the prompt descriptor the plan names — an anonymous,
//!    sealed, memory-backed file — or with `/dev/null` when it names none, so
//!    the workload cannot read the plan/control channel either way;
//! 6. closes every descriptor except the sealed program descriptor and the
//!    standard streams and verifies the closure ([`crate::descriptors`]);
//! 7. installs the plan's Landlock filesystem allowlist
//!    ([`crate::filesystem`]);
//! 8. installs the plan's Landlock TCP policy ([`crate::network`]);
//! 9. installs the plan's seccomp filter ([`crate::seccomp`]), which denies
//!    creating every socket shape the plan does not grant — including UDP,
//!    raw and packet sockets, and non-TCP stream protocols that Landlock's
//!    TCP rules cannot see — and denies every namespace-creating syscall, so
//!    the identity of step 4 cannot be nested away;
//! 10. applies the plan's per-process resource limits and verifies their
//!     kernel readback;
//! 11. `execveat`s the sealed descriptor with exactly the environment the plan
//!     names. The path is not resolved again.
//!
//! Any failure at any step exits with [`crate::HELPER_REFUSED_EXIT`] before
//! the workload runs. The workload's very first instruction therefore executes
//! inside the cgroup — under its own host uid when the plan asked for one —
//! behind both Landlock domains and the syscall filter, with exactly three
//! inherited descriptors and exactly the environment the plan spells out —
//! empty unless it spells one, and never anything inherited.
//!
//! The identity switch sits where it does for two reasons. It follows the
//! cgroup join and the program staging because both are done as the
//! supervisor's uid — the run cgroup's interfaces are the supervisor's files,
//! and the program is opened by the same rules as before — and it precedes
//! descriptor closure because the switch spawns and reaps a short-lived
//! mapper process whose pipe must be gone before the descriptor table is
//! verified. The helper itself is still the process that becomes the
//! workload, so the pid the supervisor holds is the pid the switch applies
//! to, and the supervisor's launch protocol is unchanged.
//!
//! # Why this order
//!
//! The cgroup join, the membership read-back, the descriptor enumeration, and
//! the plan parse all need `/proc` and cgroupfs access that the workload's
//! filesystem allowlist must not contain, so every one of them happens before
//! Landlock enforcement. Descriptor closure precedes Landlock because its
//! verification re-reads `/proc/self/fd`, which the Landlock domain denies.
//! The residue this ordering accepts is bounded and named: between closure
//! verification and `execveat`, the only descriptors this process creates are
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
//! - **It does not protect the supervisor from a same-uid attacker.** The
//!   plan travels over a private pipe and the cgroup is delegation-checked,
//!   but a process of the supervisor's uid outside the sandbox can already
//!   trace the supervisor itself. What the identity switch closes — for a
//!   plan that requests it — is the other direction: from `execve` on, the
//!   workload runs as a host uid no supervisor-uid process shares, so
//!   `/proc/<pid>/environ` and `/proc/<pid>/fd/0` — the environment and the
//!   prompt — answer `EACCES` to such a reader, and the workload can neither
//!   signal nor trace a supervisor-uid process. A plan that does not request
//!   it keeps the supervisor's uid and the same-uid exposure that has always
//!   come with it; see [`crate::identity`] for why the request is not yet the
//!   default. The environment is never hidden from the host either way:
//!   root, and the workload's own descendants, can read it.
//! - **Identity separation is not discretionary-access separation.** The
//!   workload keeps `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` and `CAP_FOWNER`
//!   inside its namespace over inodes the supervisor owns, because the
//!   workspace, the provider home and the scratch mount are all such inodes.
//!   The filesystem allowlist is the filesystem boundary, exactly as before;
//!   see [`crate::identity`] for what the capabilities do and do not reach.
//! - **The prompt is closed to the path namespace, not to the host.** Prompt
//!   bytes live in an anonymous memory-backed file that no directory entry
//!   names, so there is no path to open and no grant that could reach it, and
//!   its seals make the bytes immutable — the workload cannot rewrite its own
//!   prompt and hand a different one to a child.
//! - **Naming a variable can name a mechanism.** `LD_PRELOAD`,
//!   `LD_LIBRARY_PATH` and their kin change what a dynamically linked program
//!   loads. There is deliberately no denylist here: a denylist would be
//!   hidden policy, the plan is the review point, and what such a variable can
//!   actually reach is bounded by the filesystem allowlist, not by this API.
//! - **The main executable is pinned, not its dynamic loader or libraries.**
//!   The executable bytes are copied into an anonymous image, sealed, hashed
//!   from that sealed image, and executed from the same descriptor. An ELF
//!   interpreter and shared libraries are still resolved by path under the
//!   plan's Landlock read-execute grants. The executable's own path grant
//!   therefore remains necessary even though `execveat` does not resolve that
//!   path again.
//! - **Landlock does not mediate the program image, and could not.** A
//!   `memfd` lives on an `SB_NOUSER` superblock on an internal mount, which
//!   `landlock_add_rule` rejects with `EBADFD` and which Landlock's own file
//!   checks exempt. The execute rule the staged degradation adds is therefore
//!   an allowance for a named inode, not a restriction the sealed image
//!   evades; and the exemption is a property of the kernel's Landlock, not of
//!   this helper — a workload that runs at all can already build and execute
//!   an anonymous image of its own, on either route, because
//!   [`crate::seccomp`] denies socket shapes and namespace creation rather
//!   than `memfd_create`.
//! - **The image is resident memory, not page cache.** A sealed image is
//!   tmpfs-backed: its pages are reclaimable only to swap, where the staged
//!   copy's were droppable clean page cache over a real file. The bound is
//!   [`MAX_PROGRAM_BYTES`] per live attempt, and the daemon caps concurrent
//!   attempts, so the ceiling is that product — with the provider binaries
//!   this runs today, of the order of a gigabyte, against a host sized in
//!   tens. In exchange the staging path writes nothing to disk at all.
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
//! and 26-byte terminator plus the required 80-byte program-digest line and a
//! maximal 22-byte descriptor-limit line leaves 32599 bytes for the program,
//! argv, grants, ports and environment.
//!
//! Per-item ceilings bound shape; the frame bound is separate and binding.
//! Neither 64 maximal argv entries (`64 × 8197 = 524608`) nor four maximal
//! environment entries beside a maximal prompt (`4 × 8454 = 33816`) fit in
//! 65536 bytes, and [`LaunchPlan::encode`] refuses such a plan with
//! [`LaunchPlanError::FrameTooLarge`] rather than truncating it.
//!
//! The frame version is deliberately not backward compatible. The supervisor
//! and entry helper are release-pinned together; accepting an earlier frame
//! would silently mix releases with different enforcement vocabularies.

use crate::containment::join_and_confirm_membership;
use crate::descriptors::{DescriptorAllowlist, close_all_except, verify_only_allowlist_open};
use crate::filesystem::{FilesystemPolicy, PathIntent};
use crate::network::TcpBindConnectPolicy;
use crate::seccomp::SocketFamilyPolicy;
use crate::tempfs::{
    FusePrerequisites, NamespacedMountError, NamespacedMountedTempfs, NamespacedOutcome,
    receive_namespaced_tempfs,
};
use crate::tempfs_ledger::TemporaryStorageBudget;
use crate::{HELPER_REFUSED_EXIT, RunContainment};
use nix::fcntl::{AtFlags, FcntlArg, OFlag, SealFlag};
use nix::sys::memfd::MemFdCreateFlag;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use sha2::{Digest as _, Sha256};
use std::ffi::CString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::ops::Deref;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

/// Exact first line of every launch plan frame.
pub const FRAME_HEADER: &str = "schema=automonique.launch/v3";
/// Exact final line of every complete launch plan frame.
pub const FRAME_TERMINATOR: &str = "end=automonique.launch/v3";
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
/// Largest executable the helper will copy, verify, seal, and execute.
///
/// Current self-contained provider clients can legitimately exceed 128 MiB.
/// Keep a finite copy/seal budget, with enough headroom for those static
/// bundles, instead of rejecting a verified deployment binary by size alone.
pub const MAX_PROGRAM_BYTES: u64 = 384 * 1024 * 1024;
/// Smallest descriptor ceiling that can retain stdin, stdout and stderr.
pub const MIN_LAUNCH_NOFILE: u64 = 3;
/// Largest descriptor ceiling admitted by the run-spec budget grammar.
pub const MAX_LAUNCH_NOFILE: u64 = 65_536;

const SHA256_HEX_BYTES: usize = 64;

/// Private marker selecting the full-duplex session launch path in the entry
/// helper. It is consumed before `execve`; the workload receives only the
/// environment declared by [`LaunchPlan`].
const SESSION_STREAM_ENV: &str = "AUTOMONIQUE_SESSION_STREAM";
/// A missing or wedged helper must refuse a composed launch rather than hold
/// the supervisor forever before the workload exists.
const NAMESPACED_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Why a launch plan is refused, before any child exists.
///
/// Every variant is a refusal; none means "launched with less than asked".
#[derive(Debug)]
pub enum LaunchPlanError {
    /// The workload program path is empty, relative, or oversized.
    ProgramRejected,
    /// The required workload digest is not 64 lowercase hexadecimal bytes.
    ProgramDigestRejected,
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
    /// The descriptor limit is repeated or outside the closed launch range.
    ResourceLimitRejected,
    /// The private in-namespace temporary-storage request is malformed or
    /// contradicts the launch policy around it.
    NamespacedTemporaryStorageRejected,
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
            Self::ProgramDigestRejected => formatter
                .write_str("workload program digest must be 64 lowercase hexadecimal bytes"),
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
            Self::ResourceLimitRejected => formatter
                .write_str("descriptor limit must be unique and retain the three standard streams"),
            Self::NamespacedTemporaryStorageRejected => formatter.write_str(
                "namespaced temporary storage requires one bounded absolute mountpoint, an exact budget, and identity separation",
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
    program_sha256: String,
    arguments: Vec<Vec<u8>>,
    filesystem: Vec<(PathIntent, PathBuf)>,
    connect_ports: Vec<u16>,
    bind_ports: Vec<u16>,
    socket_grants: Vec<SocketGrant>,
    environment: Vec<(String, Vec<u8>)>,
    prompt: Option<Vec<u8>>,
    rlimit_nofile: Option<u64>,
    separate_identity: bool,
    namespaced_temporary_storage: Option<NamespacedTemporaryStorage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NamespacedTemporaryStorage {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
}

/// Redacting: a derived `Debug` would print environment values and prompt
/// bytes, which are exactly the two things a plan may carry that a log must
/// never hold. Names and lengths are enough to identify a plan.
impl fmt::Debug for LaunchPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchPlan")
            .field("program", &self.program)
            .field("program_sha256", &self.program_sha256)
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
            .field("rlimit_nofile", &self.rlimit_nofile)
            .field("separate_identity", &self.separate_identity)
            .field(
                "namespaced_temporary_storage",
                &self.namespaced_temporary_storage,
            )
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
    /// Start a plan for `program`, bound to its expected SHA-256 digest.
    ///
    /// The helper opens `program` without following its final symlink, copies
    /// and hashes the bytes into a private staging file, compares them with
    /// `program_sha256`, and executes that descriptor. There is no `PATH`
    /// search or second path lookup.
    pub fn new(
        program: impl Into<PathBuf>,
        program_sha256: impl Into<String>,
    ) -> Result<Self, LaunchPlanError> {
        let program = program.into();
        let program_sha256 = program_sha256.into();
        if !program.is_absolute()
            || program.as_os_str().is_empty()
            || program.as_os_str().len() > MAX_LAUNCH_ARG_BYTES
        {
            return Err(LaunchPlanError::ProgramRejected);
        }
        if !valid_sha256(&program_sha256) {
            return Err(LaunchPlanError::ProgramDigestRejected);
        }
        Ok(Self {
            program,
            program_sha256,
            arguments: Vec::new(),
            filesystem: Vec::new(),
            connect_ports: Vec::new(),
            bind_ports: Vec::new(),
            socket_grants: Vec::new(),
            environment: Vec::new(),
            prompt: None,
            rlimit_nofile: None,
            separate_identity: false,
            namespaced_temporary_storage: None,
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

    /// Convert an admitted one-shot plan into an interactive session plan.
    ///
    /// The caller must retain the resolved prompt and deliver it through the
    /// negotiated session protocol. This removes only fd-0 prompt staging; it
    /// preserves the exact executable, argv, environment, grants and limits.
    #[must_use]
    pub fn into_session_plan(mut self) -> Self {
        self.prompt = None;
        self
    }

    /// Bound the workload's open descriptors with `RLIMIT_NOFILE`.
    ///
    /// The limit counts the three standard streams the launch deliberately
    /// retains. A lower value would make the workload begin over budget, so it
    /// is refused rather than silently raised.
    pub fn rlimit_descriptors(mut self, value: u64) -> Result<Self, LaunchPlanError> {
        if self.rlimit_nofile.is_some() || !(MIN_LAUNCH_NOFILE..=MAX_LAUNCH_NOFILE).contains(&value)
        {
            return Err(LaunchPlanError::ResourceLimitRejected);
        }
        self.rlimit_nofile = Some(value);
        Ok(self)
    }

    /// Run the workload as a host uid that is not the supervisor's.
    ///
    /// The entry helper performs the whole switch ([`crate::identity`]) and
    /// refuses the launch when the host cannot: subordinate ranges, the
    /// setuid mappers and — where the host restricts unprivileged user
    /// namespaces — an AppArmor grant are all prerequisites, and every step
    /// is read back from the kernel. Off by default: a plan that does not ask
    /// launches exactly as before, and asking twice is refused like every
    /// other repeated line.
    ///
    /// A plan carrying this cannot attach the enforced temporary-storage
    /// mount: on current kernels FUSE refuses `allow_other` access to a
    /// process in a child user namespace, so the combination is refused
    /// (fail-closed) rather than admitted and broken; see
    /// [`crate::admission`].
    pub fn separate_workload_identity(mut self) -> Result<Self, LaunchPlanError> {
        if self.separate_identity {
            return Err(LaunchPlanError::PolicyRejected(
                "identity separation is requested twice".to_owned(),
            ));
        }
        self.separate_identity = true;
        Ok(self)
    }

    fn namespaced_temporary_storage(
        mut self,
        mountpoint: impl Into<PathBuf>,
        budget: TemporaryStorageBudget,
    ) -> Result<Self, LaunchPlanError> {
        let mountpoint = mountpoint.into();
        if self.namespaced_temporary_storage.is_some()
            || !mountpoint.is_absolute()
            || mountpoint.as_os_str().is_empty()
            || mountpoint.as_os_str().len() > MAX_LAUNCH_ARG_BYTES
        {
            return Err(LaunchPlanError::NamespacedTemporaryStorageRejected);
        }
        self.namespaced_temporary_storage = Some(NamespacedTemporaryStorage { mountpoint, budget });
        Ok(self)
    }

    pub(crate) fn with_namespaced_temporary_storage(
        self,
        mountpoint: impl Into<PathBuf>,
        budget: TemporaryStorageBudget,
    ) -> Result<Self, LaunchPlanError> {
        let mountpoint = mountpoint.into();
        match &self.namespaced_temporary_storage {
            Some(existing) if existing.mountpoint == mountpoint && existing.budget == budget => {
                Ok(self)
            }
            Some(_) => Err(LaunchPlanError::NamespacedTemporaryStorageRejected),
            None => self.namespaced_temporary_storage(mountpoint, budget),
        }
    }

    /// Whether this plan runs its workload under a separated host uid.
    #[must_use]
    pub const fn separates_workload_identity(&self) -> bool {
        self.separate_identity
    }

    /// Exact workload program path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// SHA-256 of the exact bytes the helper must execute.
    #[must_use]
    pub fn program_sha256(&self) -> &str {
        &self.program_sha256
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

    /// Exact `RLIMIT_NOFILE` ceiling, when this plan declares one.
    #[must_use]
    pub const fn descriptor_limit(&self) -> Option<u64> {
        self.rlimit_nofile
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
        if self
            .rlimit_nofile
            .is_some_and(|value| !(MIN_LAUNCH_NOFILE..=MAX_LAUNCH_NOFILE).contains(&value))
        {
            return Err(LaunchPlanError::ResourceLimitRejected);
        }
        if let Some(temporary_storage) = &self.namespaced_temporary_storage {
            let tmpdir = temporary_storage.mountpoint.as_os_str().as_encoded_bytes();
            let exact_environment = self
                .environment
                .iter()
                .any(|(name, value)| name == "TMPDIR" && value == tmpdir);
            let exact_grant = self.filesystem.iter().any(|(intent, path)| {
                *intent == PathIntent::ReadWrite && path == &temporary_storage.mountpoint
            });
            if !self.separate_identity || !exact_environment || !exact_grant {
                return Err(LaunchPlanError::NamespacedTemporaryStorageRejected);
            }
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
        frame.push_str(&format!("program_sha256={}\n", self.program_sha256));
        if let Some(limit) = self.rlimit_nofile {
            frame.push_str(&format!("rlimit_nofile={limit}\n"));
        }
        if self.separate_identity {
            frame.push_str("identity=subordinate\n");
        }
        if let Some(temporary_storage) = &self.namespaced_temporary_storage {
            frame.push_str(&format!(
                "tempfs={}:{}:{}\n",
                hex(temporary_storage.mountpoint.as_os_str().as_encoded_bytes()),
                temporary_storage.budget.bytes(),
                temporary_storage.budget.objects()
            ));
        }
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
        let mut program: Option<PathBuf> = None;
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
                ("program", None) if program.is_none() => {
                    let bytes = unhex(value).ok_or(LaunchPlanError::FrameRejected)?;
                    let path = os_string_from_bytes(bytes)?;
                    program = Some(PathBuf::from(path));
                }
                ("program_sha256", None) => {
                    let path = program.take().ok_or(LaunchPlanError::FrameRejected)?;
                    plan = Some(Self::new(path, value)?);
                }
                ("program", _) | ("program_sha256", _) => {
                    return Err(LaunchPlanError::FrameRejected);
                }
                ("arg", Some(current)) => {
                    let bytes = unhex(value).ok_or(LaunchPlanError::FrameRejected)?;
                    *current = current.clone().argument(bytes)?;
                }
                ("rlimit_nofile", Some(current)) => {
                    let value = value
                        .parse::<u64>()
                        .map_err(|_| LaunchPlanError::FrameRejected)?;
                    *current = current.clone().rlimit_descriptors(value)?;
                }
                ("identity", Some(current)) => {
                    if value != "subordinate" {
                        return Err(LaunchPlanError::FrameRejected);
                    }
                    // A second line refuses in the builder: one request has
                    // one spelling, and a repeat is a broken frame.
                    *current = current.clone().separate_workload_identity()?;
                }
                ("tempfs", Some(current)) => {
                    let mut fields = value.split(':');
                    let path = fields.next().ok_or(LaunchPlanError::FrameRejected)?;
                    let bytes = fields
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(LaunchPlanError::FrameRejected)?;
                    let objects = fields
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(LaunchPlanError::FrameRejected)?;
                    if fields.next().is_some() {
                        return Err(LaunchPlanError::FrameRejected);
                    }
                    let path = unhex(path).ok_or(LaunchPlanError::FrameRejected)?;
                    let path = PathBuf::from(os_string_from_bytes(path)?);
                    let budget = TemporaryStorageBudget::new(bytes, objects)
                        .map_err(|_| LaunchPlanError::FrameRejected)?;
                    *current = current.clone().namespaced_temporary_storage(path, budget)?;
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

/// A launch that owns the supervisor side of a FUSE filesystem mounted only
/// in the workload's user+mount namespace.
pub struct NamespacedSandboxedChild {
    child: Option<Child>,
    temporary_storage: Option<NamespacedMountedTempfs>,
    kill_interface: PathBuf,
}

impl fmt::Debug for NamespacedSandboxedChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamespacedSandboxedChild")
            .field("pid", &self.child.as_ref().map(Child::id))
            .finish_non_exhaustive()
    }
}

impl NamespacedSandboxedChild {
    /// Take the workload's captured stdout, when the launch requested it.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    /// The helper pid, which becomes the workload pid after enforcement.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.as_ref().expect("a live launch has a child").id()
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .expect("a live launch has a child")
            .try_wait()
    }

    pub fn kill(&mut self) -> io::Result<()> {
        let child = self.child.as_mut().expect("a live launch has a child");
        let direct = child.kill();
        match std::fs::write(&self.kill_interface, b"1") {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => direct.or(Ok(())),
            Err(error) => Err(error),
        }
    }

    pub fn wait_process(&mut self) -> io::Result<ExitStatus> {
        self.child
            .as_mut()
            .expect("a live launch has a child")
            .wait()
    }

    /// The first typed quota refusal, when one has already happened.
    #[must_use]
    pub fn temporary_storage_exceedance(&self) -> Option<crate::tempfs_ledger::Exceedance> {
        self.temporary_storage.as_ref()?.first_exceedance()
    }

    /// Persist one exact live-ledger snapshot for restart/reaper readback.
    ///
    /// Production integration calls this on the same cadence as the existing
    /// supervisor-mounted filesystem and immediately on a quota refusal.
    pub fn checkpoint_temporary_storage(&mut self) -> io::Result<()> {
        self.temporary_storage
            .as_mut()
            .expect("a live launch has temporary storage")
            .write_checkpoint(crate::tempfs_checkpoint::Phase::Live, None)
    }

    #[must_use]
    pub fn temporary_storage_readback(&self) -> Option<crate::StatfsReadback> {
        crate::StatfsReadback::from_ledger(&self.temporary_storage.as_ref()?.snapshot()?).ok()
    }

    /// Wait for the workload, then reconcile from the filesystem ledger after
    /// the private mount namespace has ended.
    pub fn wait(mut self) -> Result<(ExitStatus, NamespacedOutcome), NamespacedMountError> {
        let status = self
            .child
            .as_mut()
            .expect("a live launch has a child")
            .wait()
            .map_err(NamespacedMountError::Io)?;
        self.child = None;
        let outcome = self
            .temporary_storage
            .take()
            .expect("a namespaced launch has temporary storage")
            .reconcile()?;
        Ok((status, outcome))
    }
}

impl Drop for NamespacedSandboxedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = std::fs::write(&self.kill_interface, b"1");
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        if let Some(temporary_storage) = self.temporary_storage.take() {
            let _ = temporary_storage.reconcile();
        }
    }
}

/// Spawn a separated workload whose quota filesystem is mounted by the entry
/// helper inside that workload's user+mount namespace and served by the
/// supervisor over an `SCM_RIGHTS`-transferred `/dev/fuse` connection.
///
/// This is a bounded runner primitive, not yet the daemon admission path. The
/// existing identity+temporary-storage conflict remains authoritative until
/// the daemon owns this result and its restart reconciliation end to end.
pub fn spawn_sandboxed_with_namespaced_temporary_storage(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
    mountpoint: &Path,
    budget: TemporaryStorageBudget,
    checkpoint: &Path,
    stdout: StdoutCapture,
) -> Result<NamespacedSandboxedChild, LaunchError> {
    FusePrerequisites::host_default()
        .verify()
        .map_err(|error| LaunchError::Io(io::Error::other(error.to_string())))?;
    let plan = plan
        .clone()
        .with_namespaced_temporary_storage(mountpoint, budget)?;
    let frame = plan.encode()?;
    let (mut supervisor, workload) = UnixStream::pair()?;
    supervisor.set_read_timeout(Some(NAMESPACED_HANDSHAKE_DEADLINE))?;
    supervisor.set_write_timeout(Some(NAMESPACED_HANDSHAKE_DEADLINE))?;
    let workload: OwnedFd = workload.into();
    let mut child = Command::new(helper)
        .env_clear()
        .env(crate::CGROUP_DIR_ENV, containment.path())
        .env(crate::tempfs::NAMESPACED_CONTROL_ENV, "1")
        .stdin(Stdio::from(workload))
        .stdout(stdout.stdio())
        .stderr(Stdio::inherit())
        .spawn()?;
    let setup = (|| -> Result<NamespacedMountedTempfs, LaunchError> {
        supervisor.write_all(&frame)?;
        receive_namespaced_tempfs(
            &mut supervisor,
            containment.path(),
            budget,
            nix::unistd::getuid().as_raw(),
            checkpoint,
        )
        .map_err(|error| LaunchError::Io(io::Error::other(error.to_string())))
    })();
    let temporary_storage = match setup {
        Ok(mounted) => mounted,
        Err(error) => {
            let _ = std::fs::write(containment.path().join("cgroup.kill"), b"1");
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    drop(supervisor);
    Ok(NamespacedSandboxedChild {
        child: Some(child),
        temporary_storage: Some(temporary_storage),
        kill_interface: containment.path().join("cgroup.kill"),
    })
}

/// A sandboxed workload whose stdin and stdout remain connected to its
/// supervisor for multiple serialized turns.
pub struct SandboxedSession {
    child: Child,
    stream: UnixStream,
    /// The run containment's `cgroup.kill`, captured at spawn.
    ///
    /// The workload runs as a host uid the supervisor does not share, so a
    /// signal to its pid is refused with `EPERM`; the cgroup's kill interface
    /// is a supervisor-owned file and reaches the whole tree.
    kill_interface: PathBuf,
    temporary_storage: Option<NamespacedMountedTempfs>,
}

impl fmt::Debug for SandboxedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxedSession")
            .field("pid", &self.child.id())
            .field("temporary_storage", &self.temporary_storage.is_some())
            .finish_non_exhaustive()
    }
}

impl SandboxedSession {
    /// A clone suitable for a dedicated stdout reader thread.
    pub fn try_clone_stream(&self) -> Result<UnixStream, std::io::Error> {
        self.stream.try_clone()
    }

    /// Write already-framed provider input. Callers own the NDJSON grammar.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write_all(bytes)
    }

    /// Observe termination without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    /// Wait for the provider process.
    pub fn wait(&mut self) -> Result<ExitStatus, std::io::Error> {
        self.child.wait()
    }

    /// Terminate the workload tree through its run cgroup.
    ///
    /// The owning containment remains responsible for draining and removing
    /// the cgroup; a cgroup already removed holds nothing left to kill and is
    /// not an error. The direct signal is still sent as a fallback for a
    /// process that was never given the workload identity.
    pub fn kill(&mut self) -> Result<(), std::io::Error> {
        let direct = self.child.kill();
        match std::fs::write(&self.kill_interface, b"1") {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => direct.or(Ok(())),
            Err(error) => Err(error),
        }
    }

    /// Operating-system process identifier, for supervision evidence only.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// First filesystem quota refusal, if the session has private temporary
    /// storage and its exact ledger has recorded one.
    #[must_use]
    pub fn temporary_storage_exceedance(&self) -> Option<crate::tempfs_ledger::Exceedance> {
        self.temporary_storage.as_ref()?.first_exceedance()
    }

    /// Persist the current exact ledger on the production supervision cadence.
    pub fn checkpoint_temporary_storage(&mut self) -> io::Result<()> {
        let Some(storage) = self.temporary_storage.as_mut() else {
            return Ok(());
        };
        storage.write_checkpoint(crate::tempfs_checkpoint::Phase::Live, None)
    }

    /// Statfs-shaped evidence from the exact in-memory filesystem ledger.
    pub fn temporary_storage_readback(&self) -> Option<crate::StatfsReadback> {
        crate::StatfsReadback::from_ledger(&self.temporary_storage.as_ref()?.snapshot()?).ok()
    }

    /// Finish the private FUSE server after the workload namespace has ended.
    pub fn reconcile_temporary_storage(
        &mut self,
    ) -> Result<Option<NamespacedOutcome>, NamespacedMountError> {
        self.temporary_storage
            .take()
            .map(NamespacedMountedTempfs::reconcile)
            .transpose()
    }
}

impl Drop for SandboxedSession {
    fn drop(&mut self) {
        // A session owns a process, not merely its control socket. This is the
        // startup-failure path as well as the caller-forgot-to-close path; in
        // both cases leaving the child behind would outlive its journal owner.
        let _ = self.kill();
        let _ = self.child.wait();
        if let Some(storage) = self.temporary_storage.take() {
            let _ = storage.reconcile();
        }
    }
}

/// Spawn a session-scoped workload under the same entry helper and containment
/// policy as a one-shot launch, while retaining a full-duplex stdin/stdout
/// stream for serialized NDJSON turns.
///
/// A session plan may not contain a one-shot prompt. The helper consumes the
/// launch frame through its exact terminator, leaves fd 0 connected, applies
/// the ordinary descriptor/Landlock/seccomp policy, and then `execve`s.
pub fn spawn_sandboxed_session(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
) -> Result<SandboxedSession, LaunchError> {
    if plan.prompt_len().is_some() {
        return Err(LaunchPlanError::PromptRejected.into());
    }
    let frame = plan.encode()?;
    let (mut supervisor, workload) = UnixStream::pair()?;
    let workload_stdin = workload.try_clone()?;
    let workload_stdin: OwnedFd = workload_stdin.into();
    let workload_stdout: OwnedFd = workload.into();
    let mut child = Command::new(helper)
        .env_clear()
        .env(crate::CGROUP_DIR_ENV, containment.path())
        .env(SESSION_STREAM_ENV, "1")
        .stdin(Stdio::from(workload_stdin))
        .stdout(Stdio::from(workload_stdout))
        .stderr(Stdio::inherit())
        .spawn()?;
    if let Err(error) = supervisor.write_all(&frame) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(LaunchError::Io(error));
    }
    Ok(SandboxedSession {
        child,
        stream: supervisor,
        kill_interface: containment.path().join("cgroup.kill"),
        temporary_storage: None,
    })
}

/// Spawn a full-duplex session with its FUSE filesystem mounted inside the
/// separated workload user+mount namespace.
pub fn spawn_sandboxed_session_with_namespaced_temporary_storage(
    helper: &Path,
    plan: &LaunchPlan,
    containment: &RunContainment,
    mountpoint: &Path,
    budget: TemporaryStorageBudget,
    checkpoint: &Path,
) -> Result<SandboxedSession, LaunchError> {
    if plan.prompt_len().is_some() {
        return Err(LaunchPlanError::PromptRejected.into());
    }
    FusePrerequisites::host_default()
        .verify()
        .map_err(|error| LaunchError::Io(io::Error::other(error.to_string())))?;
    let plan = plan
        .clone()
        .with_namespaced_temporary_storage(mountpoint, budget)?;
    let frame = plan.encode()?;
    let (mut supervisor, workload) = UnixStream::pair()?;
    supervisor.set_read_timeout(Some(NAMESPACED_HANDSHAKE_DEADLINE))?;
    supervisor.set_write_timeout(Some(NAMESPACED_HANDSHAKE_DEADLINE))?;
    let workload_stdin = workload.try_clone()?;
    let workload_stdin: OwnedFd = workload_stdin.into();
    let workload_stdout: OwnedFd = workload.into();
    let mut child = Command::new(helper)
        .env_clear()
        .env(crate::CGROUP_DIR_ENV, containment.path())
        .env(SESSION_STREAM_ENV, "1")
        .env(crate::tempfs::NAMESPACED_CONTROL_ENV, "1")
        .stdin(Stdio::from(workload_stdin))
        .stdout(Stdio::from(workload_stdout))
        .stderr(Stdio::inherit())
        .spawn()?;
    let setup = (|| -> Result<NamespacedMountedTempfs, LaunchError> {
        supervisor.write_all(&frame)?;
        receive_namespaced_tempfs(
            &mut supervisor,
            containment.path(),
            budget,
            nix::unistd::getuid().as_raw(),
            checkpoint,
        )
        .map_err(|error| LaunchError::Io(io::Error::other(error.to_string())))
    })();
    let temporary_storage = match setup {
        Ok(storage) => storage,
        Err(error) => {
            let _ = std::fs::write(containment.path().join("cgroup.kill"), b"1");
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    supervisor.set_read_timeout(None)?;
    supervisor.set_write_timeout(None)?;
    Ok(SandboxedSession {
        child,
        stream: supervisor,
        kill_interface: containment.path().join("cgroup.kill"),
        temporary_storage: Some(temporary_storage),
    })
}

/// Entry-helper process body for a composed sandboxed launch.
///
/// See the module documentation for the exact sequence. Every failure exits
/// with [`HELPER_REFUSED_EXIT`] before the workload runs; the reason is
/// written to stderr as a single bounded line containing no plan content.
#[must_use]
pub fn launch_entry_helper_main() -> i32 {
    // Three auxiliary modes share the binary: the identity mapper, the
    // capability probe's throwaway child, and the separately supervised
    // temporary-storage owner. Each is selected by exactly one argument; a
    // launch takes none, and anything else is refused.
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next()) {
        (None, None) => {}
        (Some(mode), None) if mode == crate::identity::MAP_MODE_FLAG => {
            return crate::identity::map_workload_identity_main();
        }
        (Some(mode), None) if mode == crate::identity::PROBE_MODE_FLAG => {
            return crate::identity::probe_workload_identity_main();
        }
        (Some(mode), None) if mode == crate::tempfs_owner::OWNER_MODE_FLAG => {
            return crate::tempfs_owner::owner_main();
        }
        _ => {
            eprintln!("automonique-launch-enter: refused: unknown argument");
            return HELPER_REFUSED_EXIT;
        }
    }
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
    let session_stream = match std::env::var(SESSION_STREAM_ENV) {
        Ok(value) if value == "1" => true,
        Ok(_) => return Err("session stream marker malformed".to_owned()),
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("session stream marker malformed".to_owned());
        }
    };
    let namespaced_control = match std::env::var(crate::tempfs::NAMESPACED_CONTROL_ENV) {
        Ok(value) if value == "1" => true,
        Ok(_) => return Err("namespaced tempfs control marker malformed".to_owned()),
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("namespaced tempfs control marker malformed".to_owned());
        }
    };
    let frame = if session_stream || namespaced_control {
        read_session_launch_frame()?
    } else {
        let mut frame = Vec::new();
        std::io::stdin()
            .lock()
            .take(u64::try_from(MAX_FRAME_BYTES + 1).expect("constant fits"))
            .read_to_end(&mut frame)
            .map_err(|_| "plan frame unreadable".to_owned())?;
        frame
    };
    let plan = LaunchPlan::decode(&frame).map_err(|error| error.to_string())?;
    if session_stream && plan.prompt.is_some() {
        return Err("session stream cannot carry a one-shot prompt".to_owned());
    }
    if namespaced_control != plan.namespaced_temporary_storage.is_some() {
        return Err("namespaced tempfs control and plan do not match".to_owned());
    }

    // 2. Enter the cgroup before the workload exists; confirm from the kernel.
    let target = std::env::var_os(crate::CGROUP_DIR_ENV)
        .ok_or_else(|| "no containment target".to_owned())?;
    join_and_confirm_membership(Path::new(&target)).map_err(|error| error.to_string())?;

    // 3. Copy the program into an anonymous memory-backed image, seal it, and
    //    verify the digest by reading the sealed object back — all before
    //    filesystem policy is installed. The sealed object has no name, so
    //    there is no path to unlink and none to re-point; the retained
    //    descriptor is the object execveat consumes and the source path is
    //    never resolved again. A kernel without memfd sealing degrades to the
    //    staged copy, whose inode Landlock binds and whose name is removed.
    let program_descriptor = verified_program_image(&plan)?;

    // 4. When the plan asks, become the workload identity: a host uid that is
    //    not the supervisor's, in a user namespace of this process's own,
    //    with the capability set the workload keeps. Every step is read back
    //    from the kernel and any failure refuses the launch. The mapper this
    //    spawns is reaped, and its pipe closed, before the descriptor closure
    //    below. A plan that does not ask launches with the supervisor's
    //    identity, exactly as every plan did before the line existed.
    if plan.separate_identity {
        if let Some(temporary_storage) = &plan.namespaced_temporary_storage {
            let verified = FusePrerequisites::host_default()
                .verify()
                .map_err(|error| format!("namespaced temporary storage refused: {error}"))?;
            let duplicate = rustix::io::dup(std::io::stdin())
                .map_err(|error| format!("namespaced control duplication failed: {error}"))?;
            let mut control = UnixStream::from(duplicate);
            crate::identity::separate_workload_identity_with_namespace_setup(|identity| {
                crate::tempfs::mount_in_workload_namespace(
                    &verified,
                    &temporary_storage.mountpoint,
                    temporary_storage.budget,
                    identity,
                    &mut control,
                )
            })
            .map_err(|error| format!("workload identity refused: {error}"))?;
            drop(control);
        } else {
            crate::identity::separate_workload_identity()
                .map_err(|error| format!("workload identity refused: {error}"))?;
        }
    }

    // 5. The plan/control channel must not reach the workload: stdin becomes
    //    the plan's prompt descriptor, or /dev/null when it names no prompt.
    //    For an in-namespace mount this happens only after the descriptor
    //    handoff and kernel readback have completed on the private socket.
    if !session_stream {
        let stdin_source = match plan.prompt.as_deref() {
            Some(prompt) => sealed_prompt_descriptor(prompt)?,
            None => File::open("/dev/null").map_err(|_| "/dev/null unavailable".to_owned())?,
        };
        nix::unistd::dup2(stdin_source.as_raw_fd(), 0)
            .map_err(|_| "stdin replacement failed".to_owned())?;
        drop(stdin_source);
    }

    // 6. Close everything but the standard streams and the program image.
    let mut allowed = vec![0, 1, 2];
    allowed.extend(program_descriptor.open_descriptors());
    let allowlist = DescriptorAllowlist::new(&allowed).map_err(|error| error.to_string())?;
    close_all_except(&allowlist).map_err(|error| error.to_string())?;
    verify_only_allowlist_open(&allowlist).map_err(|error| error.to_string())?;

    // A Landlock domain and the seccomp filter below apply to the calling
    // thread and its future children. Refuse explicitly unless this entry
    // helper still has exactly one thread, so no sibling can escape them.
    crate::filesystem::require_single_threaded().map_err(|error| match error {
        crate::filesystem::SingleThreadError::Multiple => {
            "entry helper has more than one thread".to_owned()
        }
        crate::filesystem::SingleThreadError::Unknown => {
            "entry helper thread count could not be confirmed".to_owned()
        }
    })?;

    // 7–8. Landlock domains. The TCP policy confirms single-threadedness from
    //      /proc while it is being installed, so it must precede the
    //      filesystem domain that deliberately makes /proc unreadable.
    //      Anything either policy opens is close-on-exec and dropped before
    //      execve, so it cannot reach the workload.
    plan.tcp_policy()
        .map_err(|error| error.to_string())?
        .enforce_on_current_thread()
        .map_err(|error| error.to_string())?;
    let filesystem_policy = plan.filesystem_policy().map_err(|error| error.to_string())?;
    match program_descriptor.landlock_binding() {
        // A staged copy is an ordinary inode: it needs an execute rule, and
        // its name is removed while the rule is being built.
        Some((rule_descriptor, staged_path)) => filesystem_policy
            .enforce_on_current_thread_with_executable(rule_descriptor, staged_path)
            .map_err(|error| error.to_string())?,
        // A sealed anonymous image needs no rule and can carry none; Landlock
        // does not mediate executing one. See `ProgramImage::landlock_binding`.
        None => filesystem_policy
            .enforce_on_current_thread()
            .map_err(|error| error.to_string())?,
    };

    // 9. The seccomp filter closes what Landlock cannot reach: UDP, raw and
    //    packet sockets, non-TCP stream protocols, and every namespace
    //    creation. It is installed last so its own installation needs no
    //    carve-outs in the layers above, and like them it survives execve.
    plan.socket_policy()
        .map_err(|error| error.to_string())?
        .apply_to_current_thread()
        .map_err(|error| error.to_string())?;

    // 10. Apply the workload's process-local descriptor ceiling only after the
    //    helper has finished opening policy and executable descriptors. The
    //    hard limit is lowered with the soft limit so the workload cannot raise
    //    it again; readback makes a silent kernel no-op a refusal.
    apply_resource_limits(&plan)?;

    // 11. Exact program, exact argv, exactly the named environment — which is
    //     empty when the plan named none, as every plan did before `env=`
    //     existed.
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
    let empty_path = CString::new(Vec::new()).expect("empty path contains no NUL");
    nix::unistd::execveat(
        Some(program_descriptor.as_raw_fd()),
        &empty_path,
        &argv,
        &environment,
        AtFlags::AT_EMPTY_PATH,
    )
    .map_err(|error| format!("execveat failed: {error}"))?;
    unreachable!("execveat returned without an error")
}

/// Install and verify the process limits that survive `execveat`.
fn apply_resource_limits(plan: &LaunchPlan) -> Result<(), String> {
    let Some(limit) = plan.rlimit_nofile else {
        return Ok(());
    };
    let limit =
        nix::libc::rlim_t::try_from(limit).map_err(|_| "descriptor limit rejected".to_owned())?;
    setrlimit(Resource::RLIMIT_NOFILE, limit, limit)
        .map_err(|_| "descriptor limit unavailable".to_owned())?;
    let observed =
        getrlimit(Resource::RLIMIT_NOFILE).map_err(|_| "descriptor limit unreadable".to_owned())?;
    if observed != (limit, limit) {
        return Err("descriptor limit unconfirmed".to_owned());
    }
    Ok(())
}

/// Read exactly one launch frame without waiting for EOF or consuming bytes
/// from the first provider turn queued behind it.
fn read_session_launch_frame() -> Result<Vec<u8>, String> {
    let terminator = format!("{FRAME_TERMINATOR}\n");
    let mut frame = Vec::new();
    let mut line = Vec::new();
    while frame.len() <= MAX_FRAME_BYTES {
        let mut byte = [0_u8; 1];
        loop {
            match nix::unistd::read(0, &mut byte) {
                Ok(1) => break,
                Ok(_) => return Err("plan frame unreadable".to_owned()),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return Err("plan frame unreadable".to_owned()),
            }
        }
        frame.push(byte[0]);
        line.push(byte[0]);
        if byte[0] == b'\n' {
            if line == terminator.as_bytes() {
                return Ok(frame);
            }
            line.clear();
        }
    }
    Err("plan frame exceeds bound".to_owned())
}

/// The seal set every anonymous program image carries, and the value
/// `F_GET_SEALS` must read back before the image is trusted.
///
/// `F_SEAL_WRITE` alone is not equivalent to an unlinked staged copy: growth
/// and truncation would both still change what `execveat` maps. `F_SEAL_SEAL`
/// closes the sealing interface itself, so no later holder of the descriptor —
/// the workload included — can lift any of the other three.
const PROGRAM_SEALS: SealFlag = SealFlag::F_SEAL_WRITE
    .union(SealFlag::F_SEAL_GROW)
    .union(SealFlag::F_SEAL_SHRINK)
    .union(SealFlag::F_SEAL_SEAL);

/// Why a sealed anonymous image could not be produced.
///
/// The distinction is load-bearing. A kernel that cannot make one is a
/// capability gap and degrades to the staged copy, which is what this helper
/// did before. A program that fails verification is a refusal, and must never
/// be retried by a second route — otherwise "the digest did not match" would
/// silently become "try again somewhere the check is differently shaped".
enum ImageError {
    Unsupported,
    Refused(String),
}

/// The verified program, as the object `execveat` will consume.
#[derive(Debug)]
enum ProgramImage {
    /// An anonymous, sealed, memory-backed image. No directory entry names it,
    /// so there is no path to reopen and nothing to unlink; the seals make the
    /// bytes immutable for every holder of every descriptor onto the object.
    Sealed(File),
    /// The degradation for a kernel without `memfd` sealing: a copy at an
    /// owner-only random path, whose inode a Landlock execute rule binds and
    /// whose name is removed before restriction.
    Staged {
        file: File,
        rule_descriptor: File,
        path: PathBuf,
    },
}

impl ProgramImage {
    /// The Landlock execute rule this image needs, if it needs one.
    ///
    /// A sealed image needs none and can have none. `landlock_add_rule` rejects
    /// a `memfd` with `EBADFD` — its superblock is `SB_NOUSER` on an internal
    /// mount — and by the same token Landlock does not mediate executing one,
    /// so the rule the staged copy adds is an allowance the sealed image has no
    /// use for rather than a restriction it escapes.
    fn landlock_binding(&self) -> Option<(&File, &Path)> {
        match self {
            Self::Sealed(_) => None,
            Self::Staged {
                rule_descriptor,
                path,
                ..
            } => Some((rule_descriptor, path)),
        }
    }

    /// Every descriptor this image keeps open, for the closure allowlist.
    fn open_descriptors(&self) -> Vec<RawFd> {
        match self {
            Self::Sealed(file) => vec![file.as_raw_fd()],
            Self::Staged {
                file,
                rule_descriptor,
                ..
            } => vec![file.as_raw_fd(), rule_descriptor.as_raw_fd()],
        }
    }
}

impl Deref for ProgramImage {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sealed(file) | Self::Staged { file, .. } => file,
        }
    }
}

impl Drop for ProgramImage {
    fn drop(&mut self) {
        if let Self::Staged { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Open the program and check the metadata both staging routes require.
fn open_and_screen_program(plan: &LaunchPlan) -> Result<(File, u64), String> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(&plan.program)
        .map_err(|_| "program unavailable".to_owned())?;
    let metadata = source
        .metadata()
        .map_err(|_| "program metadata unavailable".to_owned())?;
    if !metadata.is_file()
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_PROGRAM_BYTES
    {
        return Err("program metadata rejected".to_owned());
    }
    Ok((source, metadata.len()))
}

/// Copy `source` into `sink`, bounded, refusing a length that moved underneath.
///
/// `hasher` digests the bytes as they pass when the caller has no better place
/// to take the digest from. The sealed route deliberately passes `None` and
/// hashes the sealed object afterwards instead.
fn copy_program_bytes(
    source: &mut File,
    sink: &mut File,
    expected: u64,
    mut hasher: Option<&mut Sha256>,
) -> Result<(), String> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| "program unreadable".to_owned())?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| "program oversized".to_owned())?)
            .ok_or_else(|| "program oversized".to_owned())?;
        if copied > MAX_PROGRAM_BYTES {
            return Err("program oversized".to_owned());
        }
        if let Some(hasher) = hasher.as_deref_mut() {
            hasher.update(&buffer[..read]);
        }
        sink.write_all(&buffer[..read])
            .map_err(|_| "program could not be staged".to_owned())?;
    }
    if copied != expected {
        return Err("program changed while being staged".to_owned());
    }
    Ok(())
}

/// The SHA-256 of everything `file` yields from its current offset, as hex.
fn digest_to_end(file: &mut File, unreadable: &'static str) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| unreadable.to_owned())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Copy the program into an anonymous image, seal it, and verify the seals and
/// the digest by reading the sealed object back.
///
/// The order is the whole point. The bytes are sealed *before* they are
/// hashed, and the hash reads them back out of the sealed object rather than
/// out of the buffer that produced it, so the digest describes the immutable
/// artefact `execveat` will consume and not a transient copy of it. Nothing
/// between verification and exec can alter the object: `F_SEAL_WRITE` is
/// enforced on the object itself, so it survives a `/proc/self/fd` reopen —
/// which is exactly the substitution a path-named staging file has to defend
/// against by unlinking, and which cannot arise here because the object has
/// never had a name.
fn sealed_program_image(plan: &LaunchPlan) -> Result<ProgramImage, ImageError> {
    let (mut source, expected) = open_and_screen_program(plan).map_err(ImageError::Refused)?;
    let name = CString::new("automonique-program").expect("literal has no interior NUL");
    let descriptor = nix::sys::memfd::memfd_create(
        &name,
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING,
    )
    .map_err(|_| ImageError::Unsupported)?;
    let mut file = File::from(descriptor);
    copy_program_bytes(&mut source, &mut file, expected, None).map_err(ImageError::Refused)?;

    // A kernel that accepted MFD_ALLOW_SEALING and then refuses to seal, or
    // reports back a weaker set than it was given, is refused rather than
    // degraded: an unsealed anonymous image is weaker than the staged copy it
    // would be standing in for, and silently accepting one is the failure this
    // whole change exists to prevent.
    seal_descriptor(&file, "program").map_err(ImageError::Refused)?;
    let observed_seals = nix::fcntl::fcntl(file.as_raw_fd(), FcntlArg::F_GET_SEALS)
        .map_err(|error| ImageError::Refused(format!("program seals unreadable: {error}")))?;
    let observed_seals = SealFlag::from_bits_truncate(observed_seals);
    if !observed_seals.contains(PROGRAM_SEALS) {
        return Err(ImageError::Refused(
            "program seals did not take effect".to_owned(),
        ));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|_| ImageError::Refused("program rewind failed".to_owned()))?;
    let observed =
        digest_to_end(&mut file, "sealed program unreadable").map_err(ImageError::Refused)?;
    if observed != plan.program_sha256 {
        return Err(ImageError::Refused("program digest mismatch".to_owned()));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ImageError::Refused("program rewind failed".to_owned()))?;
    Ok(ProgramImage::Sealed(file))
}

/// Removes a half-built staging path unless the staging succeeded.
///
/// Without it a refusal after the copy — a digest mismatch above all — leaves
/// a full-size copy of the program in `/tmp` that nothing ever collects, since
/// the successful path hands its cleanup to [`ProgramImage`] instead.
struct StagingPathGuard<'a>(Option<&'a Path>);

impl StagingPathGuard<'_> {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StagingPathGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Copy the program from one no-follow open into a verified executable fd.
///
/// The degradation for a kernel that cannot seal an anonymous image. A random
/// owner-only staging path lets Landlock bind an execute rule to the copied
/// inode. The path is unlinked before restriction and `execveat` consumes the
/// independently opened descriptor, so the source path is never resolved a
/// second time and the workload receives no staging pathname.
fn staged_verified_program_descriptor(plan: &LaunchPlan) -> Result<ProgramImage, String> {
    let (mut source, expected) = open_and_screen_program(plan)?;
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut entropy| entropy.read_exact(&mut random))
        .map_err(|_| "program staging entropy unavailable".to_owned())?;
    let staged_path = Path::new("/tmp").join(format!(".automonique-program-{}", hex(&random)));
    let mut staged = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(&staged_path)
        .map_err(|_| "program staging file unavailable".to_owned())?;
    let mut guard = StagingPathGuard(Some(&staged_path));
    let mut hasher = Sha256::new();
    copy_program_bytes(&mut source, &mut staged, expected, Some(&mut hasher))?;
    if hex(&hasher.finalize()) != plan.program_sha256 {
        return Err("program digest mismatch".to_owned());
    }
    staged
        .sync_all()
        .map_err(|_| "program staging sync failed".to_owned())?;
    std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o500))
        .map_err(|_| "program staging permissions failed".to_owned())?;
    drop(staged);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(&staged_path)
        .map_err(|_| "program staging reopen failed".to_owned())?;
    let rule_descriptor = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&staged_path)
        .map_err(|_| "program rule descriptor unavailable".to_owned())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "program rewind failed".to_owned())?;
    // From here the returned image owns the path's removal.
    guard.disarm();
    drop(guard);
    Ok(ProgramImage::Staged {
        file,
        rule_descriptor,
        path: staged_path,
    })
}

/// The verified program image, sealed and anonymous where the kernel allows it.
///
/// Only [`ImageError::Unsupported`] falls back. A refusal — a digest mismatch
/// above all — is final on both routes.
fn verified_program_image(plan: &LaunchPlan) -> Result<ProgramImage, String> {
    match sealed_program_image(plan) {
        Ok(image) => Ok(image),
        Err(ImageError::Refused(reason)) => Err(reason),
        Err(ImageError::Unsupported) => staged_verified_program_descriptor(plan),
    }
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
    seal_descriptor(&file, "prompt")?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "prompt rewind failed".to_owned())?;
    Ok(file)
}

fn seal_descriptor(file: &File, label: &str) -> Result<(), String> {
    nix::fcntl::fcntl(
        file.as_raw_fd(),
        FcntlArg::F_ADD_SEALS(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        ),
    )
    .map_err(|error| format!("{label} could not be sealed: {error}"))?;
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{fcntl, FdFlag};
    use std::fs;
    use std::process::Command;

    const BUSYBOX: &str = "/usr/bin/busybox";
    const EXEC_FD_ENV: &str = "AUTOMONIQUE_TEST_EXEC_FD";

    /// A plan naming a private 0755 copy of BusyBox, and its true digest.
    fn busybox_plan(directory: &Path) -> (PathBuf, LaunchPlan) {
        let program = directory.join("provider");
        fs::copy(BUSYBOX, &program).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        let digest = hex(&Sha256::digest(fs::read(&program).unwrap()));
        let plan = LaunchPlan::new(&program, &digest).unwrap();
        (program, plan)
    }

    /// Every seal the image must carry, asserted against the kernel's readback
    /// rather than against what the code believes it asked for.
    #[test]
    fn the_program_image_carries_every_seal_and_the_kernel_agrees() {
        let temporary = tempfile::tempdir().unwrap();
        let (_, plan) = busybox_plan(temporary.path());
        let image = verified_program_image(&plan).unwrap();
        assert!(
            matches!(image, ProgramImage::Sealed(_)),
            "this host seals; a staged fallback here would hide the property under test"
        );

        let observed =
            SealFlag::from_bits_truncate(fcntl(image.as_raw_fd(), FcntlArg::F_GET_SEALS).unwrap());
        for (seal, name) in [
            (SealFlag::F_SEAL_WRITE, "F_SEAL_WRITE"),
            (SealFlag::F_SEAL_GROW, "F_SEAL_GROW"),
            (SealFlag::F_SEAL_SHRINK, "F_SEAL_SHRINK"),
            (SealFlag::F_SEAL_SEAL, "F_SEAL_SEAL"),
        ] {
            assert!(
                observed.contains(seal),
                "{name} missing from kernel readback {observed:?}: a write-only seal still \
                 lets the image grow or be truncated under the running program"
            );
        }
    }

    /// The property, performed rather than inspected: every route that could
    /// change the bytes is attempted on the descriptor that reaches `execveat`,
    /// and every one of them must fail.
    #[test]
    fn nothing_can_alter_the_sealed_image_after_it_is_verified() {
        let temporary = tempfile::tempdir().unwrap();
        let (_, plan) = busybox_plan(temporary.path());
        let image = verified_program_image(&plan).unwrap();
        let raw = image.as_raw_fd();
        let original_len = image.metadata().unwrap().len();

        // A write through the very descriptor `execveat` will consume. The
        // descriptor is still O_RDWR — memfd_create returns one — so this
        // reaches the kernel's seal check rather than bouncing off O_RDONLY.
        let error = (&*image)
            .write_all(b"tampered")
            .expect_err("a sealed image accepted a write");
        assert_eq!(
            error.raw_os_error(),
            Some(nix::libc::EPERM),
            "write refused for the wrong reason: {error}"
        );

        // Growth and truncation each change what the loader maps even though
        // no existing byte is rewritten, so F_SEAL_WRITE alone is not enough.
        assert_eq!(
            nix::unistd::ftruncate(&*image, i64::try_from(original_len + 4096).unwrap()),
            Err(nix::errno::Errno::EPERM),
            "a sealed image could be grown"
        );
        assert_eq!(
            nix::unistd::ftruncate(&*image, 16),
            Err(nix::errno::Errno::EPERM),
            "a sealed image could be truncated"
        );

        // Sealing is itself sealed, so a later holder cannot lift the rest.
        assert_eq!(
            fcntl(raw, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_WRITE)),
            Err(nix::errno::Errno::EPERM),
            "the seal set could still be changed"
        );

        // A shared writable mapping is the remaining route, and F_SEAL_WRITE
        // is the same kernel check that refused the write above — the crate
        // forbids `unsafe`, so `mmap` is not callable here to assert it twice.

        // The bytes still hash to what was verified.
        let mut reread = image.try_clone().unwrap();
        reread.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            digest_to_end(&mut reread, "unreadable").unwrap(),
            plan.program_sha256()
        );
    }

    /// The seal is on the object, so re-entering it through a *path* — the one
    /// name a caller can always construct for an open descriptor — cannot
    /// substitute bytes. The reopen is allowed to succeed; the write is not.
    #[test]
    fn reopening_the_sealed_image_by_path_cannot_substitute_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let (_, plan) = busybox_plan(temporary.path());
        let image = verified_program_image(&plan).unwrap();

        // The image is anonymous: its only "path" is the kernel's own
        // description of an unnamed object, which resolves to no directory.
        let link = std::fs::read_link(format!("/proc/self/fd/{}", image.as_raw_fd())).unwrap();
        let link = link.to_string_lossy();
        assert!(
            link.starts_with("/memfd:automonique-program"),
            "expected an anonymous image, got {link}"
        );
        assert!(
            !Path::new(&*link).exists(),
            "an anonymous image must not be resolvable as a filesystem path"
        );

        let mut reopened = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", image.as_raw_fd()))
            .expect("the reopen itself is expected to succeed; the write is what must fail");
        let error = reopened
            .write_all(b"tampered")
            .expect_err("a path reopen defeated the seal");
        assert_eq!(error.raw_os_error(), Some(nix::libc::EPERM), "{error}");

        let mut reread = image.try_clone().unwrap();
        reread.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            digest_to_end(&mut reread, "unreadable").unwrap(),
            plan.program_sha256()
        );
    }

    /// A refusal must be final. If a digest mismatch fell through to the
    /// staged route, "these are not the bytes you named" would quietly become
    /// "try the path where the check is shaped differently".
    #[test]
    fn a_digest_mismatch_is_refused_without_staging_anything() {
        let temporary = tempfile::tempdir().unwrap();
        let (program, _) = busybox_plan(temporary.path());
        let plan = LaunchPlan::new(&program, &"b".repeat(64)).unwrap();

        let before = staged_program_files();
        let error = verified_program_image(&plan).expect_err("a wrong digest was accepted");
        assert_eq!(error, "program digest mismatch");
        assert_eq!(
            staged_program_files(),
            before,
            "a refused program was copied to /tmp by a fallback that should not have run"
        );
    }

    /// The staged degradation must not leave its copy behind when it refuses.
    /// A provider binary is of the order of a hundred megabytes and this runs
    /// once per attempt, so a leak here fills /tmp rather than merely littering
    /// it. Exercised directly: the sealed route is what production takes, and
    /// it never reaches this code.
    #[test]
    fn a_refused_staged_copy_removes_its_own_path() {
        let temporary = tempfile::tempdir().unwrap();
        let (program, _) = busybox_plan(temporary.path());
        let plan = LaunchPlan::new(&program, &"c".repeat(64)).unwrap();

        let before = staged_program_files();
        let error = staged_verified_program_descriptor(&plan)
            .err()
            .expect("a wrong digest was accepted");
        assert_eq!(error, "program digest mismatch");
        assert_eq!(
            staged_program_files(),
            before,
            "the refused staging copy was left in /tmp"
        );
    }

    fn staged_program_files() -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir("/tmp")
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".automonique-program-"))
            })
            .collect();
        found.sort();
        found
    }

    #[test]
    fn swapping_the_path_after_verification_cannot_change_the_bytes_executed() {
        let temporary = tempfile::tempdir().unwrap();
        let program = temporary.path().join("provider");
        let replacement = temporary.path().join("replacement");
        fs::copy(BUSYBOX, &program).unwrap();
        fs::copy("/usr/bin/false", &replacement).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();

        let original = fs::read(&program).unwrap();
        let original_sha256 = hex(&Sha256::digest(&original));
        let plan = LaunchPlan::new(&program, &original_sha256).unwrap();
        let descriptor = verified_program_image(&plan).unwrap();

        // This is the old vulnerable window: the pathname now resolves to a
        // different executable after verification and before exec.
        fs::rename(&replacement, &program).unwrap();
        assert_ne!(
            hex(&Sha256::digest(fs::read(&program).unwrap())),
            original_sha256
        );

        let mut staged = descriptor.try_clone().unwrap();
        staged.seek(SeekFrom::Start(0)).unwrap();
        let mut staged_bytes = Vec::new();
        staged.read_to_end(&mut staged_bytes).unwrap();
        assert_eq!(hex(&Sha256::digest(&staged_bytes)), plan.program_sha256());

        // The child test process inherits only this explicitly de-CLOEXEC'd
        // descriptor and replaces itself using the same execveat call as the
        // production helper. The replacement path is /usr/bin/false bytes; an
        // observed line proves the staged BusyBox bytes ran instead.
        nix::fcntl::fcntl(descriptor.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("launch::tests::exec_sealed_descriptor_child")
            .env(EXEC_FD_ENV, descriptor.as_raw_fd().to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            output.stdout.ends_with(b"verified-bytes-ran\n"),
            "{output:?}"
        );
    }

    #[test]
    fn the_identity_line_round_trips_and_a_repeat_is_refused() {
        let digest = "a".repeat(64);
        let plain = LaunchPlan::new("/usr/bin/true", &digest).unwrap();
        let encoded = String::from_utf8(plain.encode().unwrap()).unwrap();
        assert!(
            !encoded.contains("identity="),
            "a plan that does not ask must not carry the line: {encoded}"
        );
        assert!(
            !LaunchPlan::decode(encoded.as_bytes())
                .unwrap()
                .separates_workload_identity()
        );

        let asking = LaunchPlan::new("/usr/bin/true", &digest)
            .unwrap()
            .separate_workload_identity()
            .unwrap();
        assert!(asking.separates_workload_identity());
        let encoded = String::from_utf8(asking.encode().unwrap()).unwrap();
        assert!(encoded.contains("\nidentity=subordinate\n"), "{encoded}");
        let decoded = LaunchPlan::decode(encoded.as_bytes()).unwrap();
        assert!(decoded.separates_workload_identity());
        assert_eq!(decoded, asking);

        assert!(matches!(
            asking.clone().separate_workload_identity(),
            Err(LaunchPlanError::PolicyRejected(_))
        ));
        let repeated = encoded.replace(
            "identity=subordinate\n",
            "identity=subordinate\nidentity=subordinate\n",
        );
        assert!(LaunchPlan::decode(repeated.as_bytes()).is_err());
        let unknown = encoded.replace("identity=subordinate", "identity=root");
        assert!(matches!(
            LaunchPlan::decode(unknown.as_bytes()),
            Err(LaunchPlanError::FrameRejected)
        ));
    }

    #[test]
    fn namespaced_tempfs_frame_requires_exact_identity_tmpdir_and_write_grant() {
        let digest = "a".repeat(64);
        let mountpoint = Path::new("/tmp/automonique-namespaced-frame");
        let budget = TemporaryStorageBudget::from_bytes(2 * 4096).unwrap();
        let base = LaunchPlan::new("/usr/bin/true", &digest).unwrap();
        for incomplete in [
            base.clone()
                .namespaced_temporary_storage(mountpoint, budget)
                .unwrap(),
            base.clone()
                .separate_workload_identity()
                .unwrap()
                .environment("TMPDIR", mountpoint.as_os_str().as_encoded_bytes())
                .unwrap()
                .namespaced_temporary_storage(mountpoint, budget)
                .unwrap(),
        ] {
            assert!(matches!(
                incomplete.encode(),
                Err(LaunchPlanError::NamespacedTemporaryStorageRejected)
            ));
        }
        let complete = base
            .separate_workload_identity()
            .unwrap()
            .filesystem_grant(PathIntent::ReadWrite, mountpoint)
            .unwrap()
            .environment("TMPDIR", mountpoint.as_os_str().as_encoded_bytes())
            .unwrap()
            .namespaced_temporary_storage(mountpoint, budget)
            .unwrap();
        let encoded = String::from_utf8(complete.encode().unwrap()).unwrap();
        assert!(encoded.contains("\ntempfs="), "{encoded}");
        assert_eq!(LaunchPlan::decode(encoded.as_bytes()).unwrap(), complete);
        let malformed = encoded.replace(":8192:2", ":0:2");
        assert!(matches!(
            LaunchPlan::decode(malformed.as_bytes()),
            Err(LaunchPlanError::FrameRejected)
        ));
    }

    #[test]
    fn exec_sealed_descriptor_child() {
        let Some(raw_fd) = std::env::var_os(EXEC_FD_ENV) else {
            return;
        };
        let raw_fd = raw_fd.to_string_lossy().parse::<i32>().unwrap();
        let empty_path = CString::new(Vec::new()).unwrap();
        let argv = [
            CString::new("busybox").unwrap(),
            CString::new("echo").unwrap(),
            CString::new("verified-bytes-ran").unwrap(),
        ];
        let environment: [CString; 0] = [];
        match nix::unistd::execveat(
            Some(raw_fd),
            &empty_path,
            &argv,
            &environment,
            AtFlags::AT_EMPTY_PATH,
        ) {
            Ok(never) => match never {},
            Err(error) => panic!("execveat failed: {error}"),
        }
    }
}
