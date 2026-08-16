// SPDX-License-Identifier: Elastic-2.0

use crate::normalize::{NormalizedRun, Normalizer};
use crate::types::{
    AdapterError, CancellationToken, ExecutionMode, MAX_JSONL_LINE_BYTES, MAX_JSONL_TOTAL_BYTES,
    NormalizedTranscript, RunRequest,
};
use nix::fcntl::OFlag;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

/// Read-only metadata for one executable candidate.
///
/// Inspection hashes bytes from an `O_NOFOLLOW` handle and never executes the
/// file. This value is observation data, not a reviewed pin or permission to
/// start a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableInspection {
    sha256: String,
    size: u64,
    mode: u32,
}

impl ExecutableInspection {
    /// Inspect a bounded absolute regular file without executing it.
    pub fn inspect(path: impl AsRef<Path>) -> Result<Self, AdapterError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(AdapterError::UnsafeExecutable);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
            .open(path)
            .map_err(|_| AdapterError::UnsafeExecutable)?;
        inspect_handle(&mut file)
    }

    /// Observed SHA-256 of the complete candidate file.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Observed byte length.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Observed Unix permission bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

fn inspect_handle(file: &mut File) -> Result<ExecutableInspection, AdapterError> {
    let metadata = file
        .metadata()
        .map_err(|_| AdapterError::UnsafeExecutable)?;
    if !metadata.is_file()
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(AdapterError::UnsafeExecutable);
    }
    let mut hasher = Sha256::new();
    let mut read_total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AdapterError::UnsafeExecutable)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(u64::try_from(read).map_err(|_| AdapterError::UnsafeExecutable)?)
            .ok_or(AdapterError::UnsafeExecutable)?;
        if read_total > MAX_EXECUTABLE_BYTES {
            return Err(AdapterError::UnsafeExecutable);
        }
        hasher.update(&buffer[..read]);
    }
    if read_total != metadata.len() {
        return Err(AdapterError::UnsafeExecutable);
    }
    Ok(ExecutableInspection {
        sha256: hex(&hasher.finalize()),
        size: metadata.len(),
        mode: metadata.mode() & 0o7777,
    })
}

/// Non-executable description of a future Codex invocation.
///
/// The plan contains no executable path, prompt bytes, or environment values.
/// It is suitable for review and durable comparison, but confers no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexInvocationPlan {
    executable: ExecutableInspection,
    arguments: Vec<String>,
    prompt_bytes: usize,
    environment_keys: Vec<String>,
}

impl CodexInvocationPlan {
    /// Bind observed executable metadata to one validated request shape.
    #[must_use]
    pub fn new(executable: ExecutableInspection, request: &RunRequest) -> Self {
        let arguments = match &request.mode {
            ExecutionMode::NewSession => vec!["exec", "--json", "-"],
            ExecutionMode::Resume(binding) => vec![
                "exec",
                "resume",
                binding.provider_session_id(),
                "--json",
                "-",
            ],
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        Self {
            executable,
            arguments,
            prompt_bytes: request.prompt.len(),
            environment_keys: request.environment.keys().map(str::to_owned).collect(),
        }
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableInspection {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub const fn prompt_bytes(&self) -> usize {
        self.prompt_bytes
    }

    #[must_use]
    pub fn environment_keys(&self) -> &[String] {
        &self.environment_keys
    }
}

/// Disabled execution entry point retained to make refusal explicit.
///
/// No value of this type can currently be constructed. A later implementation
/// must require an unforgeable, exact-run OS-enforcement capability and a
/// reviewed executable/configuration pin before changing this behavior.
pub struct CodexAdapter {
    _private: (),
}

impl CodexAdapter {
    /// Refuse adapter construction while enforcement authority is unavailable.
    pub fn open(_plan: &CodexInvocationPlan) -> Result<Self, AdapterError> {
        Err(AdapterError::ExecutionUnavailable)
    }

    /// Refuse process execution while enforcement authority is unavailable.
    pub fn run(
        _plan: &CodexInvocationPlan,
        _request: &RunRequest,
        _cancellation: &CancellationToken,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ExecutionUnavailable)
    }
}

/// Strictly normalize complete JSONL bytes captured by an external fixture.
///
/// This function never opens an executable or starts a process. Provider
/// success/failure is returned as a disposition, not as an authoritative run
/// terminal; only a future execution host can combine it with trusted exit and
/// enforcement evidence.
pub fn normalize_jsonl(
    coordinates: &crate::types::RunCoordinates,
    mode: &ExecutionMode,
    output: &[u8],
) -> Result<NormalizedTranscript, AdapterError> {
    if output.len() > MAX_JSONL_TOTAL_BYTES {
        return Err(AdapterError::OutputTooLarge);
    }
    if output.is_empty() || !output.ends_with(b"\n") {
        return Err(AdapterError::InvalidJson);
    }
    let mut normalizer = Normalizer::new(coordinates, mode);
    for line in output[..output.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(AdapterError::InvalidJson);
        }
        if line.len() > MAX_JSONL_LINE_BYTES {
            return Err(AdapterError::OutputTooLarge);
        }
        let line = std::str::from_utf8(line).map_err(|_| AdapterError::InvalidUtf8)?;
        normalizer.push(line)?;
    }
    let NormalizedRun {
        binding,
        events,
        disposition,
    } = normalizer.finish()?;
    Ok(NormalizedTranscript {
        binding,
        events,
        disposition,
        warning_count: 0,
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}
