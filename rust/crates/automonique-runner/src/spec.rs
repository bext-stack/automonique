// SPDX-License-Identifier: Elastic-2.0

//! Admission-only execution specification values.
//!
//! The immutable document composes typed protocol values, protected prompt
//! routing, bounded platform bytes and the closed canonical RunSpec v1 codec.
//! A valid or decoded value is not launch or sandbox authority;
//! [`Runner`](crate::Runner) remains fail-closed.
//!
//! Whole values cannot be constructed or mutated through their private fields:
//!
//! ```compile_fail
//! use automonique_runner::RunSpec;
//! let _ = RunSpec { protocol_version: 1 };
//! ```
//!
//! ```compile_fail
//! use automonique_runner::RunSpec;
//! fn mutate(spec: &mut RunSpec) {
//!     spec.protocol_version = 2;
//! }
//! ```
//!
//! Typed read-only projection is public:
//!
//! ```
//! use automonique_protocol::host::{AttemptId, HostId, WorkId};
//! use automonique_protocol::tools::RunId;
//! use automonique_runner::RunSpec;
//! fn inspect(spec: &RunSpec) {
//!     let _: &WorkId = spec.work_id();
//!     let _: &RunId = spec.run_id();
//!     let _: &AttemptId = spec.attempt_id();
//!     let _: &HostId = spec.host_id();
//! }
//! ```
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
//!
//! Attempt-workspace registration and working-directory tokens remain distinct:
//!
//! ```compile_fail
//! use automonique_protocol::workspace::AttemptWorkspaceToken;
//! use automonique_runner::CwdToken;
//! let cwd = CwdToken::new("cwd-1").unwrap();
//! let attempt_workspace: AttemptWorkspaceToken = cwd;
//! ```
//!
//! ```compile_fail
//! use automonique_runner::{CwdToken, AttemptWorkspaceRegistryId};
//! let cwd = CwdToken::new("cwd-1").unwrap();
//! let attempt_workspace: AttemptWorkspaceRegistryId = cwd;
//! ```
//!
//! ```
//! use automonique_runner::{CwdToken, AttemptWorkspaceRegistryId};
//! let cwd = CwdToken::new("cwd-1").unwrap();
//! let attempt_workspace = AttemptWorkspaceRegistryId::new("workspace-1").unwrap();
//! assert_eq!(cwd.as_str(), "cwd-1");
//! assert_eq!(attempt_workspace.as_str(), "workspace-1");
//! ```

use crate::AdmissionFields;
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::primitives::BoundedString;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{ExecutionBackendId, FilesystemAccess, SandboxSpec};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{AttemptWorkspaceRegistration, IsolationKind};
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
/// Maximum accepted or emitted canonical RunSpec v1 document length.
///
/// This aliases the protocol frame ceiling used by both codec directions.
pub const MAX_RUN_SPEC_BYTES: usize = automonique_protocol::codec::MAX_FRAME_BYTES;
const _: [(); automonique_protocol::codec::MAX_FRAME_BYTES] = [(); MAX_RUN_SPEC_BYTES];
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
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
    AttemptWorkspaceTenantMismatch,
    AttemptWorkspaceBaseMismatch,
    AttemptWorkspaceIsolationMismatch,
    TimeoutInvalid,
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
            Self::AttemptWorkspaceTenantMismatch => {
                formatter.write_str("attempt workspace tenant differs from sandbox tenant")
            }
            Self::AttemptWorkspaceBaseMismatch => formatter
                .write_str("attempt workspace base revision differs from sandbox base revision"),
            Self::AttemptWorkspaceIsolationMismatch => formatter
                .write_str("attempt workspace isolation differs from sandbox filesystem policy"),
            Self::TimeoutInvalid => {
                formatter.write_str("sandbox timeout is outside the supported range")
            }
            Self::SpoolLimitInvalid => {
                formatter.write_str("sandbox spool limit is outside the supported range")
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

impl PromptDeliveryPlan {
    /// Stable spelling of the prompt-delivery mode.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::ProtectedReference(_) => "protected_reference",
            Self::BackendSession(_) => "backend_session",
        }
    }

    /// Reconstruct a mode from its exact spelling and optional coordinates.
    ///
    /// The payload shape is closed: `stdin` accepts neither coordinate,
    /// `protected_reference` accepts only a protected reference, and
    /// `backend_session` accepts only a backend session. Unknown spellings or
    /// any missing, extra, or transposed coordinate refuse.
    #[must_use]
    pub fn from_spelling(
        value: &str,
        protected_reference: Option<ProtectedPromptReference>,
        backend_session: Option<BackendPromptSession>,
    ) -> Option<Self> {
        match (value, protected_reference, backend_session) {
            ("stdin", None, None) => Some(Self::Stdin),
            ("protected_reference", Some(reference), None) => {
                Some(Self::ProtectedReference(reference))
            }
            ("backend_session", None, Some(session)) => Some(Self::BackendSession(session)),
            _ => None,
        }
    }
}

/// Opaque identity of one registered attempt-workspace record. It is
/// deliberately distinct from the attempt workspace's host-resolved token and
/// cannot carry a path.
#[derive(Clone, Eq, PartialEq)]
pub struct AttemptWorkspaceRegistryId(BoundedString<MAX_FIELD_BYTES>);

impl AttemptWorkspaceRegistryId {
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

impl fmt::Debug for AttemptWorkspaceRegistryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttemptWorkspaceRegistryId(<opaque>)")
    }
}

/// Opaque attempt-workspace-relative working-directory coordinate.
///
/// A token is not a host filesystem path and carries no path-resolution
/// authority. The attempt-workspace registry must resolve it in a later
/// bounded step.
#[derive(Clone, Eq, PartialEq)]
pub struct CwdToken(BoundedString<MAX_FIELD_BYTES>);

impl CwdToken {
    /// Construct a path-free working-directory coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`RunSpecError::FieldInvalid`] for empty, oversized, control,
    /// or path-shaped input.
    pub fn new(value: impl Into<String>) -> Result<Self, RunSpecError> {
        let value = value.into();
        reject_path_shaped_reference(&value, "cwd_token")?;
        let value =
            BoundedString::new(value).map_err(|_| RunSpecError::FieldInvalid("cwd_token"))?;
        Ok(Self(value))
    }

    /// Stable opaque spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for CwdToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CwdToken(<opaque>)")
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
    pub cwd_token: CwdToken,
    pub environment: Vec<(OsString, OsString)>,
    pub prompt: PromptDeliveryPlan,
    pub attempt_workspace_registry_id: AttemptWorkspaceRegistryId,
    pub attempt_workspace: AttemptWorkspaceRegistration,
    pub provider_binary: BinaryProvenance,
    pub sandbox: SandboxSpec,
    pub admission: AdmissionFields,
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
            .field("cwd_token", &self.cwd_token)
            .field(
                "environment",
                &format_args!("<redacted:{} entries>", self.environment.len()),
            )
            .field("prompt", &self.prompt)
            .field(
                "attempt_workspace_registry_id",
                &self.attempt_workspace_registry_id,
            )
            .field("attempt_workspace", &"<registered attempt workspace>")
            .field("provider_binary", &"<pinned provider binary>")
            .field("sandbox", &"<compiled sandbox spec>")
            .field("admission", &self.admission)
            .finish()
    }
}

#[derive(Clone)]
pub struct RunSpec {
    protocol_version: u32,
    coordinates: RunCoordinates,
    executable: PathBuf,
    arguments: Vec<OsString>,
    cwd_token: CwdToken,
    environment: Vec<(OsString, OsString)>,
    prompt: PromptDeliveryPlan,
    attempt_workspace_registry_id: AttemptWorkspaceRegistryId,
    attempt_workspace: AttemptWorkspaceRegistration,
    provider_binary: BinaryProvenance,
    sandbox: SandboxSpec,
    admission: AdmissionFields,
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
            .field("cwd_token", &self.cwd_token)
            .field(
                "environment",
                &format_args!("<redacted:{} entries>", self.environment.len()),
            )
            .field("prompt", &self.prompt)
            .field(
                "attempt_workspace_registry_id",
                &self.attempt_workspace_registry_id,
            )
            .field("attempt_workspace", &"<registered attempt workspace>")
            .field("provider_binary", &"<pinned provider binary>")
            .field("sandbox", &"<compiled sandbox spec>")
            .field("admission", &self.admission)
            .finish()
    }
}

impl RunSpec {
    pub fn new(parts: RunSpecParts) -> Result<Self, RunSpecError> {
        if parts.protocol_version != 1 {
            return Err(RunSpecError::UnsupportedProtocol(parts.protocol_version));
        }
        validate_absolute_canonical(&parts.executable, "executable")?;
        validate_arguments(&parts.arguments)?;
        validate_environment(&parts.environment)?;
        let timeout = Duration::from_millis(parts.sandbox.budgets().timeout().quantity());
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(RunSpecError::TimeoutInvalid);
        }
        if !(MIN_SPOOL_BYTES..=MAX_SPOOL_BYTES)
            .contains(&parts.sandbox.budgets().spool().quantity())
        {
            return Err(RunSpecError::SpoolLimitInvalid);
        }
        validate_attempt_workspace_sandbox(&parts.attempt_workspace, &parts.sandbox)?;
        parts
            .admission
            .validate_against(&parts.coordinates, &parts.prompt, &parts.sandbox)?;
        Ok(Self {
            protocol_version: parts.protocol_version,
            coordinates: parts.coordinates,
            executable: parts.executable,
            arguments: parts.arguments,
            cwd_token: parts.cwd_token,
            environment: parts.environment,
            prompt: parts.prompt,
            attempt_workspace_registry_id: parts.attempt_workspace_registry_id,
            attempt_workspace: parts.attempt_workspace,
            provider_binary: parts.provider_binary,
            sandbox: parts.sandbox,
            admission: parts.admission,
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
    pub const fn cwd_token(&self) -> &CwdToken {
        &self.cwd_token
    }
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }
    pub const fn prompt_delivery(&self) -> &PromptDeliveryPlan {
        &self.prompt
    }
    pub const fn attempt_workspace_registry_id(&self) -> &AttemptWorkspaceRegistryId {
        &self.attempt_workspace_registry_id
    }
    pub const fn attempt_workspace(&self) -> &AttemptWorkspaceRegistration {
        &self.attempt_workspace
    }
    pub const fn provider_binary(&self) -> &BinaryProvenance {
        &self.provider_binary
    }
    pub const fn sandbox(&self) -> &SandboxSpec {
        &self.sandbox
    }
    pub const fn admission(&self) -> &AdmissionFields {
        &self.admission
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.sandbox.budgets().timeout().quantity())
    }
    pub fn spool_budget_bytes(&self) -> u64 {
        self.sandbox.budgets().spool().quantity()
    }

    /// Encode this immutable admission document as canonical RunSpec v1 JSON.
    ///
    /// Encoding is a declarative projection only and grants no execution or
    /// use-time authority.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, crate::RunSpecEncodeError> {
        crate::spec_encode::encode(self)
    }

    /// Compute the domain-separated SHA-256 of the canonical encoding.
    pub fn canonical_digest(&self) -> Result<crate::RunSpecDigest, crate::RunSpecEncodeError> {
        crate::spec_encode::digest(self)
    }

    /// Decode one complete strict canonical RunSpec v1 document.
    ///
    /// Success reconstructs immutable declarative admission data only. It does
    /// not grant execution or use-time authority.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, crate::RunSpecDecodeError> {
        crate::spec_decode::decode(bytes)
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

fn validate_attempt_workspace_sandbox(
    attempt_workspace: &AttemptWorkspaceRegistration,
    sandbox: &SandboxSpec,
) -> Result<(), RunSpecError> {
    if attempt_workspace.tenant() != sandbox.tenant() {
        return Err(RunSpecError::AttemptWorkspaceTenantMismatch);
    }
    if attempt_workspace.base_revision() != sandbox.base_revision() {
        return Err(RunSpecError::AttemptWorkspaceBaseMismatch);
    }
    let access = sandbox.profile().filesystem();
    let isolation_matches = match attempt_workspace.isolation() {
        IsolationKind::ReadOnlySnapshot => access == FilesystemAccess::ReadOnlySnapshot,
        IsolationKind::AttemptCopy | IsolationKind::Overlay => {
            matches!(
                access,
                FilesystemAccess::IsolatedWritable | FilesystemAccess::WritableWithGrants
            )
        }
    };
    if !isolation_matches {
        return Err(RunSpecError::AttemptWorkspaceIsolationMismatch);
    }
    Ok(())
}
