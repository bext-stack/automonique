// SPDX-License-Identifier: Elastic-2.0

//! Admission-only execution specification values.
//!
//! This partial covers typed run coordinates, protected prompt routing and
//! bounded argv/environment/path validation. A valid value is not launch or
//! sandbox authority; [`Runner`](crate::Runner) remains fail-closed.
//!
//! Protocol identities remain distinct:
//!
//! ```compile_fail
//! use automonique_protocol::host::{AttemptId, WorkId};
//! let attempt = AttemptId::new("attempt-1").unwrap();
//! let work: WorkId = attempt;
//! ```
//!
//! ```
//! use automonique_protocol::host::WorkId;
//! let work = WorkId::new("work-1").unwrap();
//! let same_domain: WorkId = work;
//! assert_eq!(same_domain.as_str(), "work-1");
//! ```
//!
//! Protected-reference and backend-session coordinates cannot be mixed:
//!
//! ```compile_fail
//! use automonique_runner::{BackendPromptSession, ProtectedPromptReference};
//! let protected = ProtectedPromptReference::new("prompt-slot-1").unwrap();
//! let backend: BackendPromptSession = protected;
//! ```
//!
//! ```
//! use automonique_runner::{
//!     BackendPromptSession, PromptDeliveryPlan, ProtectedPromptReference,
//! };
//! let protected = ProtectedPromptReference::new("prompt-slot-1").unwrap();
//! let backend = BackendPromptSession::new("session-1").unwrap();
//! let protected_plan = PromptDeliveryPlan::ProtectedReference(protected);
//! let backend_plan = PromptDeliveryPlan::BackendSession(backend);
//! assert!(matches!(protected_plan, PromptDeliveryPlan::ProtectedReference(_)));
//! assert!(matches!(backend_plan, PromptDeliveryPlan::BackendSession(_)));
//! ```

use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::primitives::BoundedString;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{ExecutionBackendId, FilesystemAccess, SandboxSpec};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{IsolationKind, WorkspaceRegistration};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_ARG_COUNT: usize = 64;
pub const MAX_ARG_BYTES: usize = 4_096;
pub const MAX_TOTAL_ARG_BYTES: usize = 32 * 1_024;
pub const MAX_ENV_COUNT: usize = 64;
pub const MAX_TOTAL_ENV_BYTES: usize = 64 * 1_024;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TERM_GRACE: Duration = Duration::from_secs(5);
const MIN_SPOOL_BYTES: u64 = 4_096;
const MAX_SPOOL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunSpecError {
    UnsupportedProtocol(u32),
    FieldInvalid(&'static str),
    PathNotAbsolute(&'static str),
    PathNotCanonical(&'static str),
    TooManyArguments,
    ArgumentTooLarge,
    ArgumentsTooLarge,
    TooManyEnvironmentVariables,
    EnvironmentKeyInvalid,
    DuplicateEnvironmentKey,
    EnvironmentValueTooLarge,
    EnvironmentTooLarge,
    WorkspaceTenantMismatch,
    WorkspaceBaseMismatch,
    WorkspaceIsolationMismatch,
    SandboxTimeoutMismatch,
    SandboxSpoolMismatch,
    TimeoutInvalid,
    TermGraceInvalid,
    SpoolLimitInvalid,
}

impl fmt::Display for RunSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol(version) => {
                write!(formatter, "unsupported runner protocol version {version}")
            }
            Self::FieldInvalid(field) => write!(formatter, "field {field} is invalid"),
            Self::PathNotAbsolute(field) => write!(formatter, "path field {field} is not absolute"),
            Self::PathNotCanonical(field) => {
                write!(formatter, "path field {field} is not lexically canonical")
            }
            Self::TooManyArguments => formatter.write_str("argument count exceeds the limit"),
            Self::ArgumentTooLarge => formatter.write_str("an argument exceeds the byte limit"),
            Self::ArgumentsTooLarge => formatter.write_str("total argument bytes exceed the limit"),
            Self::TooManyEnvironmentVariables => {
                formatter.write_str("environment variable count exceeds the limit")
            }
            Self::EnvironmentKeyInvalid => formatter.write_str("environment key is invalid"),
            Self::DuplicateEnvironmentKey => {
                formatter.write_str("environment contains a duplicate key")
            }
            Self::EnvironmentValueTooLarge => {
                formatter.write_str("environment value exceeds the byte limit")
            }
            Self::EnvironmentTooLarge => {
                formatter.write_str("total environment bytes exceed the limit")
            }
            Self::WorkspaceTenantMismatch => {
                formatter.write_str("workspace tenant differs from sandbox tenant")
            }
            Self::WorkspaceBaseMismatch => {
                formatter.write_str("workspace base revision differs from sandbox base revision")
            }
            Self::WorkspaceIsolationMismatch => {
                formatter.write_str("workspace isolation differs from sandbox filesystem policy")
            }
            Self::SandboxTimeoutMismatch => {
                formatter.write_str("runner timeout differs from sandbox timeout budget")
            }
            Self::SandboxSpoolMismatch => {
                formatter.write_str("runner spool limit differs from sandbox spool budget")
            }
            Self::TimeoutInvalid => formatter.write_str("timeout is outside the supported range"),
            Self::TermGraceInvalid => {
                formatter.write_str("termination grace is outside the supported range")
            }
            Self::SpoolLimitInvalid => {
                formatter.write_str("spool limit is outside the supported range")
            }
        }
    }
}

impl std::error::Error for RunSpecError {}

/// Opaque coordinate for the protected R2-02 prompt handoff.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedPromptReference(BoundedString<MAX_FIELD_BYTES>);

impl ProtectedPromptReference {
    pub fn new(value: impl Into<String>) -> Result<Self, RunSpecError> {
        let value = value.into();
        reject_path_shaped_reference(&value, "protected_prompt_reference")?;
        let value = BoundedString::new(value)
            .map_err(|_| RunSpecError::FieldInvalid("protected_prompt_reference"))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ProtectedPromptReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedPromptReference(<protected>)")
    }
}

/// Opaque provider-session coordinate for daemon-managed prompt delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct BackendPromptSession(BoundedString<MAX_FIELD_BYTES>);

impl BackendPromptSession {
    pub fn new(value: impl Into<String>) -> Result<Self, RunSpecError> {
        let value = value.into();
        reject_path_shaped_reference(&value, "backend_prompt_session")?;
        let value = BoundedString::new(value)
            .map_err(|_| RunSpecError::FieldInvalid("backend_prompt_session"))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for BackendPromptSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendPromptSession(<protected>)")
    }
}

/// Prompt transport metadata only. No variant can contain prompt bytes or a
/// filesystem path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptDeliveryPlan {
    Stdin,
    ProtectedReference(ProtectedPromptReference),
    BackendSession(BackendPromptSession),
}

/// Opaque identity of one registered workspace record. It is deliberately
/// distinct from the workspace's host-resolved token and cannot carry a path.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkspaceRegistryId(BoundedString<MAX_FIELD_BYTES>);

impl WorkspaceRegistryId {
    pub fn new(value: impl Into<String>) -> Result<Self, RunSpecError> {
        let value = value.into();
        reject_path_shaped_reference(&value, "workspace_registry_id")?;
        let value = BoundedString::new(value)
            .map_err(|_| RunSpecError::FieldInvalid("workspace_registry_id"))?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for WorkspaceRegistryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceRegistryId(<opaque>)")
    }
}

/// Canonical, domain-distinct lifecycle coordinates from the protocol crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCoordinates {
    work_id: WorkId,
    run_id: RunId,
    attempt_id: AttemptId,
    host_id: HostId,
    host_lifetime: HostLifetime,
    backend: ExecutionBackendId,
}

impl RunCoordinates {
    #[must_use]
    pub const fn new(
        work_id: WorkId,
        run_id: RunId,
        attempt_id: AttemptId,
        host_id: HostId,
        host_lifetime: HostLifetime,
        backend: ExecutionBackendId,
    ) -> Self {
        Self {
            work_id,
            run_id,
            attempt_id,
            host_id,
            host_lifetime,
            backend,
        }
    }

    #[must_use]
    pub const fn work_id(&self) -> &WorkId {
        &self.work_id
    }
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }
    #[must_use]
    pub const fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    #[must_use]
    pub const fn host_id(&self) -> &HostId {
        &self.host_id
    }
    #[must_use]
    pub const fn host_lifetime(&self) -> HostLifetime {
        self.host_lifetime
    }
    #[must_use]
    pub const fn backend(&self) -> &ExecutionBackendId {
        &self.backend
    }
}

#[derive(Clone)]
pub struct RunSpecParts {
    pub protocol_version: u32,
    pub coordinates: RunCoordinates,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    pub prompt: PromptDeliveryPlan,
    pub workspace_registry_id: WorkspaceRegistryId,
    pub workspace: WorkspaceRegistration,
    pub provider_binary: BinaryProvenance,
    pub sandbox: SandboxSpec,
    pub timeout: Duration,
    pub term_grace: Duration,
    pub spool_directory: PathBuf,
    pub max_spool_bytes: u64,
}

impl fmt::Debug for RunSpecParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunSpecParts")
            .field("protocol_version", &self.protocol_version)
            .field("coordinates", &self.coordinates)
            .field("executable", &self.executable)
            .field(
                "arguments",
                &format_args!("<redacted:{} entries>", self.arguments.len()),
            )
            .field("cwd", &self.cwd)
            .field(
                "environment",
                &format_args!("<redacted:{} entries>", self.environment.len()),
            )
            .field("prompt", &self.prompt)
            .field("workspace_registry_id", &self.workspace_registry_id)
            .field("workspace", &"<registered workspace>")
            .field("provider_binary", &"<pinned provider binary>")
            .field("sandbox", &"<compiled sandbox spec>")
            .field("timeout", &self.timeout)
            .field("term_grace", &self.term_grace)
            .field("spool_directory", &self.spool_directory)
            .field("max_spool_bytes", &self.max_spool_bytes)
            .finish()
    }
}

#[derive(Clone)]
pub struct RunSpec {
    protocol_version: u32,
    coordinates: RunCoordinates,
    executable: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    environment: Vec<(OsString, OsString)>,
    prompt: PromptDeliveryPlan,
    workspace_registry_id: WorkspaceRegistryId,
    workspace: WorkspaceRegistration,
    provider_binary: BinaryProvenance,
    sandbox: SandboxSpec,
    timeout: Duration,
    term_grace: Duration,
    spool_directory: PathBuf,
    max_spool_bytes: u64,
}

impl fmt::Debug for RunSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunSpec")
            .field("protocol_version", &self.protocol_version)
            .field("coordinates", &self.coordinates)
            .field("executable", &self.executable)
            .field(
                "arguments",
                &format_args!("<redacted:{} entries>", self.arguments.len()),
            )
            .field("cwd", &self.cwd)
            .field(
                "environment",
                &format_args!("<redacted:{} entries>", self.environment.len()),
            )
            .field("prompt", &self.prompt)
            .field("workspace_registry_id", &self.workspace_registry_id)
            .field("workspace", &"<registered workspace>")
            .field("provider_binary", &"<pinned provider binary>")
            .field("sandbox", &"<compiled sandbox spec>")
            .field("timeout", &self.timeout)
            .field("term_grace", &self.term_grace)
            .field("spool_directory", &self.spool_directory)
            .field("max_spool_bytes", &self.max_spool_bytes)
            .finish()
    }
}

impl RunSpec {
    pub fn new(parts: RunSpecParts) -> Result<Self, RunSpecError> {
        if parts.protocol_version != 1 {
            return Err(RunSpecError::UnsupportedProtocol(parts.protocol_version));
        }
        validate_absolute_canonical(&parts.executable, "executable")?;
        validate_absolute_canonical(&parts.cwd, "cwd")?;
        validate_absolute_canonical(&parts.spool_directory, "spool_directory")?;
        validate_arguments(&parts.arguments)?;
        validate_environment(&parts.environment)?;
        if parts.timeout.is_zero() || parts.timeout > MAX_TIMEOUT {
            return Err(RunSpecError::TimeoutInvalid);
        }
        if parts.term_grace > MAX_TERM_GRACE {
            return Err(RunSpecError::TermGraceInvalid);
        }
        if !(MIN_SPOOL_BYTES..=MAX_SPOOL_BYTES).contains(&parts.max_spool_bytes) {
            return Err(RunSpecError::SpoolLimitInvalid);
        }
        validate_workspace_sandbox(&parts.workspace, &parts.sandbox)?;
        if parts.timeout != Duration::from_millis(parts.sandbox.budgets().timeout().quantity()) {
            return Err(RunSpecError::SandboxTimeoutMismatch);
        }
        if parts.max_spool_bytes != parts.sandbox.budgets().spool().quantity() {
            return Err(RunSpecError::SandboxSpoolMismatch);
        }
        Ok(Self {
            protocol_version: parts.protocol_version,
            coordinates: parts.coordinates,
            executable: parts.executable,
            arguments: parts.arguments,
            cwd: parts.cwd,
            environment: parts.environment,
            prompt: parts.prompt,
            workspace_registry_id: parts.workspace_registry_id,
            workspace: parts.workspace,
            provider_binary: parts.provider_binary,
            sandbox: parts.sandbox,
            timeout: parts.timeout,
            term_grace: parts.term_grace,
            spool_directory: parts.spool_directory,
            max_spool_bytes: parts.max_spool_bytes,
        })
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
    pub const fn coordinates(&self) -> &RunCoordinates {
        &self.coordinates
    }
    pub const fn work_id(&self) -> &WorkId {
        self.coordinates.work_id()
    }
    pub const fn run_id(&self) -> &RunId {
        self.coordinates.run_id()
    }
    pub const fn attempt_id(&self) -> &AttemptId {
        self.coordinates.attempt_id()
    }
    pub const fn host_id(&self) -> &HostId {
        self.coordinates.host_id()
    }
    pub const fn host_lifetime(&self) -> HostLifetime {
        self.coordinates.host_lifetime()
    }
    pub const fn backend_id(&self) -> &ExecutionBackendId {
        self.coordinates.backend()
    }
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }
    pub const fn prompt_delivery(&self) -> &PromptDeliveryPlan {
        &self.prompt
    }
    pub const fn workspace_registry_id(&self) -> &WorkspaceRegistryId {
        &self.workspace_registry_id
    }
    pub const fn workspace(&self) -> &WorkspaceRegistration {
        &self.workspace
    }
    pub const fn provider_binary(&self) -> &BinaryProvenance {
        &self.provider_binary
    }
    pub const fn sandbox(&self) -> &SandboxSpec {
        &self.sandbox
    }
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
    pub const fn term_grace(&self) -> Duration {
        self.term_grace
    }
    pub fn spool_directory(&self) -> &Path {
        &self.spool_directory
    }
    pub const fn max_spool_bytes(&self) -> u64 {
        self.max_spool_bytes
    }
}

fn validate_absolute_canonical(path: &Path, field: &'static str) -> Result<(), RunSpecError> {
    if !path.is_absolute() {
        return Err(RunSpecError::PathNotAbsolute(field));
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
        return Err(RunSpecError::FieldInvalid(field));
    }
    if bytes != b"/" && (bytes.ends_with(b"/") || bytes.windows(2).any(|window| window == b"//")) {
        return Err(RunSpecError::PathNotCanonical(field));
    }
    if bytes
        .split(|byte| *byte == b'/')
        .any(|component| matches!(component, b"." | b".."))
    {
        return Err(RunSpecError::PathNotCanonical(field));
    }
    Ok(())
}

fn validate_arguments(arguments: &[OsString]) -> Result<(), RunSpecError> {
    if arguments.len() > MAX_ARG_COUNT {
        return Err(RunSpecError::TooManyArguments);
    }
    let mut total = 0usize;
    for argument in arguments {
        let bytes = argument.as_bytes();
        if bytes.len() > MAX_ARG_BYTES || bytes.contains(&0) {
            return Err(RunSpecError::ArgumentTooLarge);
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(RunSpecError::ArgumentsTooLarge)?;
    }
    if total > MAX_TOTAL_ARG_BYTES {
        return Err(RunSpecError::ArgumentsTooLarge);
    }
    Ok(())
}

fn validate_environment(environment: &[(OsString, OsString)]) -> Result<(), RunSpecError> {
    if environment.len() > MAX_ENV_COUNT {
        return Err(RunSpecError::TooManyEnvironmentVariables);
    }
    let mut keys = BTreeSet::new();
    let mut total = 0usize;
    for (key, value) in environment {
        let key = key.as_bytes();
        if key.is_empty()
            || key.len() > MAX_FIELD_BYTES
            || key.contains(&0)
            || key.contains(&b'=')
            || !key[0].is_ascii_alphabetic()
            || !key
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(RunSpecError::EnvironmentKeyInvalid);
        }
        if !keys.insert(key.to_vec()) {
            return Err(RunSpecError::DuplicateEnvironmentKey);
        }
        let value = value.as_os_str().as_bytes();
        if value.len() > MAX_ARG_BYTES || value.contains(&0) {
            return Err(RunSpecError::EnvironmentValueTooLarge);
        }
        total = total
            .checked_add(key.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(RunSpecError::EnvironmentTooLarge)?;
    }
    if total > MAX_TOTAL_ENV_BYTES {
        return Err(RunSpecError::EnvironmentTooLarge);
    }
    Ok(())
}

fn reject_path_shaped_reference(value: &str, field: &'static str) -> Result<(), RunSpecError> {
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains(':')
        || value.starts_with('~')
    {
        return Err(RunSpecError::FieldInvalid(field));
    }
    Ok(())
}

fn validate_workspace_sandbox(
    workspace: &WorkspaceRegistration,
    sandbox: &SandboxSpec,
) -> Result<(), RunSpecError> {
    if workspace.tenant() != sandbox.tenant() {
        return Err(RunSpecError::WorkspaceTenantMismatch);
    }
    if workspace.base_revision() != sandbox.base_revision() {
        return Err(RunSpecError::WorkspaceBaseMismatch);
    }
    let access = sandbox.profile().filesystem();
    let isolation_matches = match workspace.isolation() {
        IsolationKind::ReadOnlySnapshot => access == FilesystemAccess::ReadOnlySnapshot,
        IsolationKind::AttemptCopy | IsolationKind::Overlay => {
            matches!(
                access,
                FilesystemAccess::IsolatedWritable | FilesystemAccess::WritableWithGrants
            )
        }
    };
    if !isolation_matches {
        return Err(RunSpecError::WorkspaceIsolationMismatch);
    }
    Ok(())
}
