// SPDX-License-Identifier: Elastic-2.0

use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_ARG_COUNT: usize = 64;
pub const MAX_ARG_BYTES: usize = 4_096;
pub const MAX_TOTAL_ARG_BYTES: usize = 32 * 1_024;
pub const MAX_ENV_COUNT: usize = 64;
pub const MAX_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TERM_GRACE: Duration = Duration::from_secs(5);
const MIN_SPOOL_BYTES: u64 = 4_096;
const MAX_SPOOL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunSpecError {
    UnsupportedProtocol(u32),
    FieldInvalid(&'static str),
    PathNotAbsolute(&'static str),
    TooManyArguments,
    ArgumentTooLarge,
    ArgumentsTooLarge,
    TooManyEnvironmentVariables,
    EnvironmentKeyInvalid,
    EnvironmentValueTooLarge,
    PromptTooLarge,
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
            Self::TooManyArguments => formatter.write_str("argument count exceeds the limit"),
            Self::ArgumentTooLarge => formatter.write_str("an argument exceeds the byte limit"),
            Self::ArgumentsTooLarge => formatter.write_str("total argument bytes exceed the limit"),
            Self::TooManyEnvironmentVariables => {
                formatter.write_str("environment variable count exceeds the limit")
            }
            Self::EnvironmentKeyInvalid => formatter.write_str("environment key is invalid"),
            Self::EnvironmentValueTooLarge => {
                formatter.write_str("environment value exceeds the byte limit")
            }
            Self::PromptTooLarge => formatter.write_str("prompt exceeds the byte limit"),
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

/// Prompt material kept outside argv and environment values.
#[derive(Clone, Eq, PartialEq)]
pub enum PromptDelivery {
    /// Bytes written directly to the child process's standard input.
    Stdin(Vec<u8>),
    /// A private, owner-only regular file connected to child standard input.
    PrivateFile(PathBuf),
}

impl PromptDelivery {
    pub fn stdin(bytes: impl Into<Vec<u8>>) -> Result<Self, RunSpecError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_PROMPT_BYTES {
            return Err(RunSpecError::PromptTooLarge);
        }
        Ok(Self::Stdin(bytes))
    }

    pub fn private_file(path: impl Into<PathBuf>) -> Result<Self, RunSpecError> {
        let path = path.into();
        validate_absolute(&path, "prompt_file")?;
        Ok(Self::PrivateFile(path))
    }
}

impl fmt::Debug for PromptDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin(bytes) => formatter
                .debug_struct("Stdin")
                .field("bytes", &format_args!("<redacted:{} bytes>", bytes.len()))
                .finish(),
            Self::PrivateFile(_) => formatter.write_str("PrivateFile(<protected>)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunSpecParts {
    pub protocol_version: u32,
    pub work_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub host_id: String,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    pub prompt: PromptDelivery,
    pub timeout: Duration,
    pub term_grace: Duration,
    pub spool_directory: PathBuf,
    pub max_spool_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct RunSpec {
    protocol_version: u32,
    work_id: String,
    run_id: String,
    attempt_id: String,
    host_id: String,
    executable: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    environment: Vec<(OsString, OsString)>,
    prompt: PromptDelivery,
    timeout: Duration,
    term_grace: Duration,
    spool_directory: PathBuf,
    max_spool_bytes: u64,
}

impl RunSpec {
    pub fn new(parts: RunSpecParts) -> Result<Self, RunSpecError> {
        if parts.protocol_version != 1 {
            return Err(RunSpecError::UnsupportedProtocol(parts.protocol_version));
        }
        validate_field(&parts.work_id, "work_id")?;
        validate_field(&parts.run_id, "run_id")?;
        validate_field(&parts.attempt_id, "attempt_id")?;
        validate_field(&parts.host_id, "host_id")?;
        validate_absolute(&parts.executable, "executable")?;
        validate_absolute(&parts.cwd, "cwd")?;
        validate_absolute(&parts.spool_directory, "spool_directory")?;
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
        Ok(Self {
            protocol_version: parts.protocol_version,
            work_id: parts.work_id,
            run_id: parts.run_id,
            attempt_id: parts.attempt_id,
            host_id: parts.host_id,
            executable: parts.executable,
            arguments: parts.arguments,
            cwd: parts.cwd,
            environment: parts.environment,
            prompt: parts.prompt,
            timeout: parts.timeout,
            term_grace: parts.term_grace,
            spool_directory: parts.spool_directory,
            max_spool_bytes: parts.max_spool_bytes,
        })
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
    pub fn work_id(&self) -> &str {
        &self.work_id
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    pub fn host_id(&self) -> &str {
        &self.host_id
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
    pub const fn prompt_delivery(&self) -> &PromptDelivery {
        &self.prompt
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

fn validate_field(value: &str, field: &'static str) -> Result<(), RunSpecError> {
    if value.is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(RunSpecError::FieldInvalid(field));
    }
    Ok(())
}

fn validate_absolute(path: &Path, field: &'static str) -> Result<(), RunSpecError> {
    if !path.is_absolute() {
        return Err(RunSpecError::PathNotAbsolute(field));
    }
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(RunSpecError::FieldInvalid(field));
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
        total = total.saturating_add(bytes.len());
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
    for (key, value) in environment {
        let key = key.as_bytes();
        if key.is_empty() || key.len() > MAX_FIELD_BYTES || key.contains(&0) || key.contains(&b'=')
        {
            return Err(RunSpecError::EnvironmentKeyInvalid);
        }
        let value = value.as_os_str().as_bytes();
        if value.len() > MAX_ARG_BYTES || value.contains(&0) {
            return Err(RunSpecError::EnvironmentValueTooLarge);
        }
    }
    Ok(())
}
