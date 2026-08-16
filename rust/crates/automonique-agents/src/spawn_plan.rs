// SPDX-License-Identifier: Elastic-2.0

//! Typed provider spawn planning: a plan grants exactly what it names.
//!
//! This module turns typed provider coordinates — kind, pinned executable,
//! workspace, network shape, run identity — into one
//! [`automonique_runner::LaunchPlan`], the frame the runner's entry helper
//! consumes. It is the piece that decides *what a provider process would be
//! allowed to touch*, expressed so that the decision is reviewable before
//! anything runs.
//!
//! # This crate still cannot spawn anything
//!
//! Nothing here starts a process. [`ProviderSpawnRequest::plan`] reads and
//! hashes one file and returns data; execution authority lives entirely in
//! [`automonique_runner::spawn_sandboxed`] and the runner's backend, which own
//! the containment domain, the entry helper, and the process. A plan is an
//! argument to that authority, never a substitute for it. The
//! [`crate::CodexAdapter`] refusals remain exactly as they were: this module
//! does not weaken them, it just makes the plan they would need explicit.
//!
//! Nor is a plan a trust decision about the executable. The digest pin below
//! says "the bytes at this path hashed to this value when the plan was built";
//! it does not say the value is the right one. Deciding *which* digest is
//! legitimate is the job of the reviewed release manifest that does not exist
//! yet, and until it does, the pin's whole value is that it is supplied by the
//! caller and checked, rather than assumed.
//!
//! # The digest pin is TOCTOU-vulnerable, and that is not fixable here
//!
//! [`ProviderSpawnRequest::plan`] opens the executable, hashes it, and compares
//! it to the pin. The runner then `execve`s **the path**, not the bytes that
//! were hashed. Between those two moments anything with write access to the
//! path — including the workload of an earlier run, a package upgrade, or a
//! same-uid process — can replace the file, and the sandbox will faithfully
//! execute the replacement. The check therefore detects a *stale or wrong*
//! binary, which is a real and common failure, and does not detect a
//! *deliberate swap*, which is the one an attacker would attempt.
//!
//! The real closure needs both halves and neither is in this crate: a reviewed
//! release manifest that says which digest is legitimate, and descriptor-based
//! execution — hash an open `O_PATH` descriptor and `execveat` *that same
//! descriptor*, so no path resolution happens in between. Until then, a caller
//! must not read a successful plan as "the provider binary is trustworthy".
//!
//! # A grant list, not a convenience layer
//!
//! Landlock grants name exactly what the plan says, and the runner adds
//! nothing. That has consequences a caller must plan for rather than discover:
//!
//! - a dynamically linked provider needs its loader and library directories
//!   read-execute, not just its own file. This module will not guess them —
//!   guessing means reading the ELF interpreter and `ld.so` search path at plan
//!   time and granting whatever they imply, which turns an audited allowlist
//!   into a derived one. The caller passes [`ProviderSpawnRequest::loader_grants`]
//!   explicitly, and a wrong list fails loudly at `execve` instead of quietly
//!   widening the sandbox.
//! - `/dev/null` gets a read grant because the helper's pre-enforcement `dup2`
//!   covers only the already-open descriptor; a provider that *reopens*
//!   `/dev/null` — every shell does, for background jobs and null redirections
//!   — performs a fresh path resolution the Landlock domain checks.
//!
//! Everything else a real provider might want — `/proc`, a TLS certificate
//! bundle, a cache directory, a temporary directory — has deliberately **no
//! spelling in this API**. Adding one is a security decision that belongs in
//! review, not a parameter a caller can pass in passing.
//!
//! # Network shape is a closed vocabulary
//!
//! [`ProviderNetwork`] is the entire network vocabulary a caller can hand this
//! module. `AF_UNIX` sockets, `SOCK_SEQPACKET`, UDP, raw sockets, and TCP
//! *bind* ports have no spelling here at all, so no caller — and no bug in a
//! caller — can widen a plan to include them. The two shapes that exist map to
//! zero socket grants, or to exactly [`automonique_runner::SocketGrant::Tcp`]
//! plus the named connect ports.
//!
//! # What a plan does **not** carry
//!
//! - **No prompt.** The runner's entry helper replaces the workload's stdin
//!   with `/dev/null` after reading the plan frame, so a provider invoked with
//!   `-` (read the prompt from stdin) receives EOF. This is reported as
//!   [`PromptDelivery::UnresolvedProviderStdin`] rather than hidden: the
//!   delivery path is the runner's protected prompt descriptor work
//!   ([`automonique_runner::PromptDeliveryPlan`]), and putting prompt bytes in
//!   argv instead — where every process listing on the host would show them —
//!   is not an option this module offers.
//! - **No environment.** The helper `execve`s with an empty environment. A
//!   [`crate::RunRequest`] carrying environment entries is therefore refused
//!   with [`SpawnPlanError::EnvironmentNotDeliverable`], because building a
//!   plan that silently dropped `CODEX_HOME` would produce a provider run
//!   pointed at the wrong configuration with nothing to show for it.

use crate::codex::{CodexInvocationPlan, ExecutableInspection};
use crate::types::{AdapterError, RunRequest};
use automonique_runner::filesystem::PathIntent;
use automonique_runner::{LaunchPlan, LaunchPlanError, SocketGrant};
use std::fmt;
use std::path::{Path, PathBuf};

/// Largest number of caller-supplied loader/interpreter grants one plan may
/// carry. A real list is the dynamic loader plus a small number of library
/// directories; a long one means the caller is enumerating the filesystem.
pub const MAX_LOADER_GRANTS: usize = 16;

/// Length of a lowercase-hex SHA-256 digest.
pub const SHA256_HEX_BYTES: usize = 64;

/// The path whose read grant keeps a reopened `/dev/null` working.
const DEV_NULL: &str = "/dev/null";

/// Which provider a plan is for.
///
/// Deliberately one variant. A provider kind is not a label — it is an argv
/// contract plus an event vocabulary, and this crate has established exactly
/// one of each ([`crate::CodexInvocationPlan`], [`crate::normalize_jsonl`]).
/// Adding a kind means adding both, with the fixtures that pin them, not
/// adding a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    /// The Codex CLI, invoked as `exec [resume <session>] --json -`.
    Codex,
}

impl ProviderKind {
    /// Stable short spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
        }
    }
}

/// An absolute executable path bound to the SHA-256 the caller expects.
///
/// Construction validates the shape of both; the file itself is read and
/// hashed later, at plan time, by [`ProviderSpawnRequest::plan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderExecutable {
    path: PathBuf,
    pinned_sha256: String,
}

impl ProviderExecutable {
    /// Bind `path` to `sha256`, in lowercase hex.
    ///
    /// Uppercase hex is refused rather than normalized: one spelling means a
    /// pin can be compared as bytes wherever it travels, and a caller that
    /// meant a different digest finds out here.
    pub fn pinned(
        path: impl Into<PathBuf>,
        sha256: impl Into<String>,
    ) -> Result<Self, SpawnPlanError> {
        let path = path.into();
        let pinned_sha256 = sha256.into();
        if !path.is_absolute() {
            return Err(SpawnPlanError::PathNotAbsolute {
                field: "provider executable",
                path,
            });
        }
        if pinned_sha256.len() != SHA256_HEX_BYTES
            || !pinned_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(SpawnPlanError::DigestMalformed);
        }
        Ok(Self {
            path,
            pinned_sha256,
        })
    }

    /// Exact executable path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Digest the caller pinned, in lowercase hex.
    #[must_use]
    pub fn pinned_sha256(&self) -> &str {
        &self.pinned_sha256
    }
}

/// The complete network vocabulary a caller may request.
///
/// There is no variant that grants `AF_UNIX`, `SOCK_SEQPACKET`, UDP, raw
/// sockets, or a TCP bind port, so a plan built here cannot carry one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderNetwork {
    /// No socket of any family may be created. Every `socket(2)` and
    /// `socketpair(2)` in the provider fails with `EPERM`.
    NoNetwork,
    /// IPv4/IPv6 `SOCK_STREAM` sockets may be created, and `connect(2)` is
    /// permitted to exactly these ports, on any address.
    TcpWithPorts {
        /// Ports the provider may connect to. Never empty; see
        /// [`SpawnPlanError::EmptyTcpGrant`].
        connect_ports: Vec<u16>,
    },
}

/// How the provider's prompt reaches it — which, today, it does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptDelivery {
    /// The provider's argv says "read the prompt from stdin", and the runner's
    /// entry helper gives the workload `/dev/null` on stdin. A plan is
    /// therefore launchable but the turn is not deliverable, and this variant
    /// is the plan saying so out loud instead of a caller discovering it as an
    /// empty provider response.
    UnresolvedProviderStdin {
        /// Prompt size the request carried, for accounting only. The bytes
        /// themselves never enter a plan.
        prompt_bytes: usize,
    },
    /// The process keeps stdin open and receives bounded NDJSON turns from the
    /// session host after the launch frame has been consumed.
    SessionNdjson,
}

/// Everything needed to plan one provider process.
///
/// Fields are public because each is a decision the caller must make
/// explicitly; all validation happens in [`Self::plan`], against the runner's
/// own policy types rather than a copy of their rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSpawnRequest {
    /// Which provider, and therefore which argv contract.
    pub kind: ProviderKind,
    /// The pinned executable to run.
    pub executable: ProviderExecutable,
    /// Additional read-execute grants the executable needs in order to run at
    /// all: the dynamic loader, shared library directories, or a script
    /// interpreter. Never guessed; see the module documentation.
    pub loader_grants: Vec<PathBuf>,
    /// Workspace root, granted read-write. Must be an existing directory and
    /// not a symbolic link.
    pub workspace_root: PathBuf,
    /// The exact network shape, from a closed vocabulary.
    pub network: ProviderNetwork,
}

impl ProviderSpawnRequest {
    /// Verify the executable and build the exact launch plan.
    ///
    /// The filesystem grant order is stable and part of the plan's identity,
    /// because the encoded frame is what a reviewer compares:
    ///
    /// 1. read-execute on the executable;
    /// 2. read-execute on each loader grant, in the caller's order;
    /// 3. read-write on the workspace root;
    /// 4. read on `/dev/null`.
    ///
    /// Every path is checked for existence here so that a plan cannot be
    /// reviewed, approved, and only then fail inside the entry helper where
    /// the failure is a bare refusal exit code. Those checks are subject to
    /// the same TOCTOU caveat as the digest: they describe the filesystem at
    /// plan time.
    pub fn plan(&self, request: &RunRequest) -> Result<ProviderLaunchPlan, SpawnPlanError> {
        // An environment that cannot be delivered is a refusal, never a
        // silently emptier provider run.
        let environment_keys = request
            .environment
            .keys()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !environment_keys.is_empty() {
            return Err(SpawnPlanError::EnvironmentNotDeliverable(environment_keys));
        }

        // Read and hash the candidate. `inspect` also refuses a relative path,
        // a symlinked final component, a non-regular or non-executable file,
        // and one that is group- or world-writable.
        let inspection = ExecutableInspection::inspect(self.executable.path())
            .map_err(SpawnPlanError::ExecutableRejected)?;
        if inspection.sha256() != self.executable.pinned_sha256() {
            return Err(SpawnPlanError::DigestMismatch {
                pinned: self.executable.pinned_sha256().to_owned(),
                observed: inspection.sha256().to_owned(),
            });
        }

        let grants = self.grant_list()?;
        let arguments = CodexInvocationPlan::new(inspection, request)
            .arguments()
            .to_vec();

        let mut launch = LaunchPlan::new(self.executable.path())?;
        for argument in &arguments {
            launch = launch.argument(argument)?;
        }
        for (intent, path) in &grants {
            launch = launch.filesystem_grant(*intent, path.clone())?;
        }
        let (socket_grants, connect_ports) = match &self.network {
            ProviderNetwork::NoNetwork => (Vec::new(), Vec::new()),
            ProviderNetwork::TcpWithPorts { connect_ports } => {
                if connect_ports.is_empty() {
                    return Err(SpawnPlanError::EmptyTcpGrant);
                }
                launch = launch.socket_grant(SocketGrant::Tcp)?;
                for &port in connect_ports {
                    launch = launch.allow_connect_port(port)?;
                }
                (vec![SocketGrant::Tcp], connect_ports.clone())
            }
        };
        // Encoding is what the helper actually consumes, so a plan that cannot
        // be encoded is not a plan; find out now rather than at spawn time.
        launch.encode()?;

        Ok(ProviderLaunchPlan {
            kind: self.kind,
            launch,
            grants,
            socket_grants,
            connect_ports,
            arguments,
            verified_sha256: self.executable.pinned_sha256().to_owned(),
            prompt: PromptDelivery::UnresolvedProviderStdin {
                prompt_bytes: request.prompt.len(),
            },
        })
    }

    /// Plan the long-lived Codex app-server shape used by a session host.
    ///
    /// The executable pin and sandbox grants are identical to [`Self::plan`],
    /// but argv is the second closed provider shape (`app-server`) and no turn
    /// prompt is embedded in the launch plan. Turns travel over the retained
    /// NDJSON stdin stream.
    pub fn plan_session(&self, request: &RunRequest) -> Result<ProviderLaunchPlan, SpawnPlanError> {
        let one_shot = self.plan(request)?;
        let arguments = vec!["app-server".to_owned()];
        let mut launch = LaunchPlan::new(self.executable.path())?;
        launch = launch.argument(&arguments[0])?;
        for (intent, path) in &one_shot.grants {
            launch = launch.filesystem_grant(*intent, path.clone())?;
        }
        for grant in &one_shot.socket_grants {
            launch = launch.socket_grant(*grant)?;
        }
        for port in &one_shot.connect_ports {
            launch = launch.allow_connect_port(*port)?;
        }
        launch.encode()?;
        Ok(ProviderLaunchPlan {
            kind: self.kind,
            launch,
            grants: one_shot.grants,
            socket_grants: one_shot.socket_grants,
            connect_ports: one_shot.connect_ports,
            arguments,
            verified_sha256: one_shot.verified_sha256,
            prompt: PromptDelivery::SessionNdjson,
        })
    }

    fn grant_list(&self) -> Result<Vec<(PathIntent, PathBuf)>, SpawnPlanError> {
        if self.loader_grants.len() > MAX_LOADER_GRANTS {
            return Err(SpawnPlanError::TooManyLoaderGrants(
                self.loader_grants.len(),
            ));
        }
        let mut grants = Vec::with_capacity(self.loader_grants.len() + 3);
        grants.push((PathIntent::ReadExecute, self.executable.path().to_owned()));
        for path in &self.loader_grants {
            require_absolute("loader grant", path)?;
            require_present(path, false)?;
            grants.push((PathIntent::ReadExecute, path.clone()));
        }
        require_absolute("workspace root", &self.workspace_root)?;
        require_present(&self.workspace_root, true)?;
        grants.push((PathIntent::ReadWrite, self.workspace_root.clone()));
        require_present(Path::new(DEV_NULL), false)?;
        grants.push((PathIntent::Read, PathBuf::from(DEV_NULL)));
        Ok(grants)
    }
}

/// One provider process, planned and not started.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderLaunchPlan {
    kind: ProviderKind,
    launch: LaunchPlan,
    grants: Vec<(PathIntent, PathBuf)>,
    socket_grants: Vec<SocketGrant>,
    connect_ports: Vec<u16>,
    arguments: Vec<String>,
    verified_sha256: String,
    prompt: PromptDelivery,
}

impl ProviderLaunchPlan {
    /// Which provider this plan runs.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        self.kind
    }

    /// The runner's plan, ready for [`automonique_runner::spawn_sandboxed`].
    #[must_use]
    pub const fn launch_plan(&self) -> &LaunchPlan {
        &self.launch
    }

    /// Take the runner's plan.
    #[must_use]
    pub fn into_launch_plan(self) -> LaunchPlan {
        self.launch
    }

    /// Exact program path the plan executes.
    #[must_use]
    pub fn program(&self) -> &Path {
        self.launch.program()
    }

    /// Workload arguments after `argv[0]`, which is [`Self::program`].
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// The complete filesystem allowlist, in encoded order.
    #[must_use]
    pub fn grants(&self) -> &[(PathIntent, PathBuf)] {
        &self.grants
    }

    /// Socket-creation grants, which are either none or exactly TCP.
    #[must_use]
    pub fn socket_grants(&self) -> &[SocketGrant] {
        &self.socket_grants
    }

    /// TCP ports the provider may connect to.
    #[must_use]
    pub fn connect_ports(&self) -> &[u16] {
        &self.connect_ports
    }

    /// The digest confirmed on disk at plan time. See the module
    /// documentation: this is not proof of what will be executed.
    #[must_use]
    pub fn verified_sha256(&self) -> &str {
        &self.verified_sha256
    }

    /// What still has to happen for the provider to receive its prompt.
    #[must_use]
    pub const fn prompt_delivery(&self) -> PromptDelivery {
        self.prompt
    }

    /// The exact frame the entry helper would consume.
    pub fn encode_frame(&self) -> Result<Vec<u8>, SpawnPlanError> {
        self.launch.encode().map_err(SpawnPlanError::Plan)
    }
}

/// Why a provider launch plan is refused, before any process exists.
///
/// Every variant is a refusal. None means "planned, with less than asked".
#[derive(Debug)]
pub enum SpawnPlanError {
    /// A path that must be absolute is not. A relative grant would resolve
    /// against whatever directory the helper happens to be in.
    PathNotAbsolute {
        /// Which coordinate carried it.
        field: &'static str,
        /// The offending path.
        path: PathBuf,
    },
    /// The pinned digest is not 64 lowercase hex characters.
    DigestMalformed,
    /// The executable could not be inspected: missing, relative, a symlink, not
    /// a regular executable file, group/world writable, empty, or oversized.
    ExecutableRejected(AdapterError),
    /// The executable's bytes do not hash to the pinned digest.
    DigestMismatch {
        /// What the caller pinned.
        pinned: String,
        /// What the file actually hashed to at plan time.
        observed: String,
    },
    /// A grant path does not exist, or is a symbolic link whose target the
    /// grant would silently open instead.
    GrantPathUnusable(PathBuf),
    /// The workspace root is not an existing directory.
    WorkspaceRootUnusable(PathBuf),
    /// More than [`MAX_LOADER_GRANTS`] loader grants were supplied.
    TooManyLoaderGrants(usize),
    /// [`ProviderNetwork::TcpWithPorts`] with no ports would create sockets
    /// that may connect nowhere. Say [`ProviderNetwork::NoNetwork`] instead.
    EmptyTcpGrant,
    /// The request carries environment entries, which the runner's empty-
    /// environment `execve` cannot deliver.
    EnvironmentNotDeliverable(Vec<String>),
    /// The runner refused the plan itself.
    Plan(LaunchPlanError),
}

impl SpawnPlanError {
    /// Stable short spelling, for assertions and structured logs.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::PathNotAbsolute { .. } => "path_not_absolute",
            Self::DigestMalformed => "digest_malformed",
            Self::ExecutableRejected(_) => "executable_rejected",
            Self::DigestMismatch { .. } => "digest_mismatch",
            Self::GrantPathUnusable(_) => "grant_path_unusable",
            Self::WorkspaceRootUnusable(_) => "workspace_root_unusable",
            Self::TooManyLoaderGrants(_) => "too_many_loader_grants",
            Self::EmptyTcpGrant => "empty_tcp_grant",
            Self::EnvironmentNotDeliverable(_) => "environment_not_deliverable",
            Self::Plan(_) => "plan_rejected",
        }
    }
}

impl fmt::Display for SpawnPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathNotAbsolute { field, path } => write!(
                formatter,
                "{field} must be an absolute path, got {}",
                path.display()
            ),
            Self::DigestMalformed => {
                write!(
                    formatter,
                    "pinned digest must be {SHA256_HEX_BYTES} lowercase hex characters"
                )
            }
            Self::ExecutableRejected(error) => {
                write!(formatter, "provider executable rejected: {error}")
            }
            Self::DigestMismatch { pinned, observed } => write!(
                formatter,
                "provider executable hashed to {observed}, pinned {pinned}"
            ),
            Self::GrantPathUnusable(path) => write!(
                formatter,
                "grant path must be an existing non-symlink: {}",
                path.display()
            ),
            Self::WorkspaceRootUnusable(path) => write!(
                formatter,
                "workspace root must be an existing non-symlink directory: {}",
                path.display()
            ),
            Self::TooManyLoaderGrants(count) => write!(
                formatter,
                "a plan carries at most {MAX_LOADER_GRANTS} loader grants, got {count}"
            ),
            Self::EmptyTcpGrant => formatter
                .write_str("a TCP grant with no connect ports permits no destination at all"),
            Self::EnvironmentNotDeliverable(keys) => write!(
                formatter,
                "the sandboxed launch execs with an empty environment, so these \
                 variables cannot be delivered: {}",
                keys.join(", ")
            ),
            Self::Plan(error) => write!(formatter, "launch plan refused: {error}"),
        }
    }
}

impl std::error::Error for SpawnPlanError {}

impl From<LaunchPlanError> for SpawnPlanError {
    fn from(value: LaunchPlanError) -> Self {
        Self::Plan(value)
    }
}

fn require_absolute(field: &'static str, path: &Path) -> Result<(), SpawnPlanError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(SpawnPlanError::PathNotAbsolute {
            field,
            path: path.to_owned(),
        })
    }
}

/// Confirm a grant path exists as itself, not as a symlink's target.
///
/// `symlink_metadata` deliberately does not follow: the runner's filesystem
/// policy refuses a symlinked grant at enforcement time because the hierarchy
/// it would open is the target, not the written path. Catching it here turns
/// that late, opaque refusal into a named one.
fn require_present(path: &Path, directory: bool) -> Result<(), SpawnPlanError> {
    let unusable = || {
        if directory {
            SpawnPlanError::WorkspaceRootUnusable(path.to_owned())
        } else {
            SpawnPlanError::GrantPathUnusable(path.to_owned())
        }
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|_| unusable())?;
    if metadata.file_type().is_symlink() || (directory && !metadata.is_dir()) {
        return Err(unusable());
    }
    Ok(())
}
