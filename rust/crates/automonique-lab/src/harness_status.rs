// SPDX-License-Identifier: Elastic-2.0

//! Bounded, read-only inspection of the bootstrap harness state.

use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{close, read};
use serde_json::{Map, Value, json};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const STATE_SCHEMA: &str = "automonique.harness-loop-state/v1";
const OUTPUT_SCHEMA: &str = "automonique.lab-harness-status/v1";
const STATE_RELATIVE: &str = ".automonique/state/harness-loop.json";
const MAX_STATE_BYTES: usize = 32 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_PATHS: usize = 1_024;
const MAX_REPOSITORY_DEPTH: usize = 64;

const CORE_FIELDS: &[&str] = &[
    "base",
    "branch",
    "driver",
    "failures",
    "iteration",
    "run_id",
    "schema",
    "started_at",
    "status",
    "stop_reason",
    "unchanged_results",
    "updated_at",
    "work_id",
];

const CODEX_FIELDS: &[&str] = &["deadline_at", "packet", "packet_sha256"];

const OPTIONAL_FIELDS: &[&str] = &[
    "candidate_commit",
    "candidate_paths",
    "candidate_ref",
    "candidate_summary",
    "candidate_tree",
    "checked_at",
    "elapsed_seconds",
    "integrated_commit",
    "integration_receipt_sha256",
    "last_exit_code",
    "last_tree_digest",
];

const CODEX_STATUSES: &[&str] = &[
    "claimed",
    "candidate_ready",
    "commit_intent",
    "candidate_committed",
    "integrated_and_pushed",
    "reconciliation_required",
    "stopped",
];

const STOP_REASONS: &[&str] = &[
    "blocked",
    "candidate_committed",
    "candidate_drift",
    "candidate_ready",
    "candidate_reconciliation_required",
    "commit_intent",
    "failure_budget",
    "integrated_and_pushed",
    "integration_reconciliation_required",
    "iteration_budget",
    "runner_error",
    "safety_check_failed",
    "unchanged_evidence",
    "user_cancelled",
    "wall_budget",
    "worker_timeout",
];

/// A read-only status request could not be answered safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessStatusError {
    RepositoryUnavailable,
    StateTooLarge,
    UnsafeState,
    InvalidState,
}

impl fmt::Display for HarnessStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "harness status unavailable: {self:?}")
    }
}

impl Error for HarnessStatusError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadError {
    Missing,
    TooLarge,
    Unsafe,
}

/// Read the fixed state below the current Git repository and return a redacted document.
///
/// This function performs no Git or filesystem mutation. A missing state is the stable
/// `idle` result; an unsafe or malformed state fails closed.
pub fn current_document() -> Result<Value, HarnessStatusError> {
    let repository = git_repository_root()?;
    let state_path = repository.join(STATE_RELATIVE);
    let bytes = match read_bounded_regular(&state_path, MAX_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(ReadError::Missing) => {
            return Ok(json!({
                "schema": OUTPUT_SCHEMA,
                "status": "idle",
            }));
        }
        Err(ReadError::TooLarge) => return Err(HarnessStatusError::StateTooLarge),
        Err(ReadError::Unsafe) => return Err(HarnessStatusError::UnsafeState),
    };
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| HarnessStatusError::InvalidState)?;
    redact_state(&value)
}

fn redact_state(value: &Value) -> Result<Value, HarnessStatusError> {
    let state = value.as_object().ok_or(HarnessStatusError::InvalidState)?;
    let driver = text(state, "driver", 32)?;
    let allowed_driver_fields = match driver {
        "codex_session" => CODEX_FIELDS,
        "local_process" => &[][..],
        _ => return Err(HarnessStatusError::InvalidState),
    };
    if state.keys().any(|field| {
        !CORE_FIELDS.contains(&field.as_str())
            && !allowed_driver_fields.contains(&field.as_str())
            && !OPTIONAL_FIELDS.contains(&field.as_str())
    }) {
        return Err(HarnessStatusError::InvalidState);
    }
    if CORE_FIELDS.iter().any(|field| !state.contains_key(*field))
        || allowed_driver_fields
            .iter()
            .any(|field| !state.contains_key(*field))
    {
        return Err(HarnessStatusError::InvalidState);
    }
    if driver == "local_process" && CODEX_FIELDS.iter().any(|field| state.contains_key(*field)) {
        return Err(HarnessStatusError::InvalidState);
    }
    if text(state, "schema", 64)? != STATE_SCHEMA {
        return Err(HarnessStatusError::InvalidState);
    }

    let status = text(state, "status", 64)?;
    if (driver == "codex_session" && !CODEX_STATUSES.contains(&status))
        || (driver == "local_process" && !matches!(status, "running" | "stopped"))
    {
        return Err(HarnessStatusError::InvalidState);
    }
    let run_id = identifier(text(state, "run_id", 64)?, 64, false)?;
    let work_id = identifier(text(state, "work_id", 80)?, 80, true)?;
    let base = lowercase_hex(text(state, "base", 40)?, 40)?;
    validate_branch(text(state, "branch", 255)?)?;
    let started_at = timestamp(text(state, "started_at", 64)?)?;
    let updated_at = timestamp(text(state, "updated_at", 64)?)?;
    let iteration = bounded_integer(state, "iteration")?;
    let failures = bounded_integer(state, "failures")?;
    let unchanged_results = bounded_integer(state, "unchanged_results")?;
    let stop_reason = stop_reason(state)?;

    validate_optional_fields(state, run_id)?;

    let mut output = Map::new();
    output.insert("base".into(), Value::String(base.to_owned()));
    output.insert("driver".into(), Value::String(driver.to_owned()));
    output.insert("failures".into(), Value::from(failures));
    output.insert("iteration".into(), Value::from(iteration));
    output.insert("runId".into(), Value::String(run_id.to_owned()));
    output.insert("schema".into(), Value::String(OUTPUT_SCHEMA.to_owned()));
    output.insert("startedAt".into(), Value::String(started_at.to_owned()));
    output.insert("status".into(), Value::String(status.to_owned()));
    output.insert(
        "stopReason".into(),
        stop_reason.map_or(Value::Null, |reason| Value::String(reason.to_owned())),
    );
    output.insert("unchangedResults".into(), Value::from(unchanged_results));
    output.insert("updatedAt".into(), Value::String(updated_at.to_owned()));
    output.insert("workId".into(), Value::String(work_id.to_owned()));
    if driver == "codex_session" {
        output.insert(
            "deadlineAt".into(),
            Value::String(timestamp(text(state, "deadline_at", 64)?)?.to_owned()),
        );
        lowercase_hex(text(state, "packet_sha256", 64)?, 64)?;
        validate_packet_path(text(state, "packet", MAX_TEXT_BYTES)?, run_id)?;
    }
    copy_optional_digest(state, &mut output, "candidate_tree", "candidateTree", 40)?;
    copy_optional_digest(
        state,
        &mut output,
        "candidate_commit",
        "candidateCommit",
        40,
    )?;
    copy_optional_digest(
        state,
        &mut output,
        "integrated_commit",
        "integratedCommit",
        40,
    )?;
    copy_optional_digest(
        state,
        &mut output,
        "integration_receipt_sha256",
        "integrationReceiptSha256",
        64,
    )?;
    Ok(Value::Object(output))
}

fn validate_optional_fields(
    state: &Map<String, Value>,
    run_id: &str,
) -> Result<(), HarnessStatusError> {
    for field in ["candidate_commit", "candidate_tree", "integrated_commit"] {
        if let Some(value) = state.get(field) {
            lowercase_hex(value.as_str().ok_or(HarnessStatusError::InvalidState)?, 40)?;
        }
    }
    for field in ["integration_receipt_sha256", "last_tree_digest"] {
        if let Some(value) = state.get(field) {
            lowercase_hex(value.as_str().ok_or(HarnessStatusError::InvalidState)?, 64)?;
        }
    }
    for field in ["candidate_summary", "checked_at"] {
        if let Some(value) = state.get(field) {
            printable(value.as_str().ok_or(HarnessStatusError::InvalidState)?)?;
        }
    }
    if state
        .get("candidate_summary")
        .and_then(Value::as_str)
        .is_some_and(|value| value.is_empty() || value.len() > 100)
    {
        return Err(HarnessStatusError::InvalidState);
    }
    if let Some(value) = state.get("candidate_ref") {
        let expected = format!("refs/automonique/candidates/{run_id}");
        if value.as_str() != Some(expected.as_str()) {
            return Err(HarnessStatusError::InvalidState);
        }
    }
    if let Some(value) = state.get("candidate_paths") {
        let paths = value.as_array().ok_or(HarnessStatusError::InvalidState)?;
        if paths.is_empty() || paths.len() > MAX_PATHS {
            return Err(HarnessStatusError::InvalidState);
        }
        for path in paths {
            validate_repo_path(path.as_str().ok_or(HarnessStatusError::InvalidState)?)?;
        }
    }
    if let Some(value) = state.get("last_exit_code")
        && !value.is_null()
    {
        let code = value.as_i64().ok_or(HarnessStatusError::InvalidState)?;
        if !(-255..=255).contains(&code) {
            return Err(HarnessStatusError::InvalidState);
        }
    }
    if let Some(value) = state.get("elapsed_seconds") {
        let seconds = value.as_f64().ok_or(HarnessStatusError::InvalidState)?;
        if !seconds.is_finite() || !(0.0..=86_400.0).contains(&seconds) {
            return Err(HarnessStatusError::InvalidState);
        }
    }
    Ok(())
}

fn copy_optional_digest(
    state: &Map<String, Value>,
    output: &mut Map<String, Value>,
    input_name: &str,
    output_name: &str,
    length: usize,
) -> Result<(), HarnessStatusError> {
    if let Some(value) = state.get(input_name) {
        let digest = lowercase_hex(
            value.as_str().ok_or(HarnessStatusError::InvalidState)?,
            length,
        )?;
        output.insert(output_name.to_owned(), Value::String(digest.to_owned()));
    }
    Ok(())
}

fn text<'a>(
    state: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a str, HarnessStatusError> {
    let value = state
        .get(field)
        .and_then(Value::as_str)
        .ok_or(HarnessStatusError::InvalidState)?;
    if value.is_empty() || value.len() > maximum {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn nullable_text<'a>(
    state: &'a Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<Option<&'a str>, HarnessStatusError> {
    match state.get(field).ok_or(HarnessStatusError::InvalidState)? {
        Value::Null => Ok(None),
        Value::String(value) if !value.is_empty() && value.len() <= maximum => {
            Ok(Some(printable(value)?))
        }
        _ => Err(HarnessStatusError::InvalidState),
    }
}

fn stop_reason(state: &Map<String, Value>) -> Result<Option<&str>, HarnessStatusError> {
    let value = nullable_text(state, "stop_reason", 64)?;
    if value.is_some_and(|reason| !STOP_REASONS.contains(&reason)) {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn timestamp(value: &str) -> Result<&str, HarnessStatusError> {
    let bytes = value.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'+'),
        (22, b':'),
    ];
    if bytes.len() != 25
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn validate_branch(value: &str) -> Result<(), HarnessStatusError> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with(['/', '.', '-'])
        || value.ends_with(['/', '.'])
        || value.contains("..")
        || value.contains("//")
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        })
    {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(())
}

fn bounded_integer(state: &Map<String, Value>, field: &str) -> Result<u64, HarnessStatusError> {
    let value = state
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(HarnessStatusError::InvalidState)?;
    if value > 1_000_000 {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn lowercase_hex(value: &str, length: usize) -> Result<&str, HarnessStatusError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn printable(value: &str) -> Result<&str, HarnessStatusError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn identifier(value: &str, maximum: usize, allow_dot: bool) -> Result<&str, HarnessStatusError> {
    if value.is_empty() || value.len() > maximum {
        return Err(HarnessStatusError::InvalidState);
    }
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-')
                || (allow_dot && byte == b'.')
        })
    {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(value)
}

fn validate_packet_path(value: &str, run_id: &str) -> Result<(), HarnessStatusError> {
    if value != format!(".automonique/state/runs/{run_id}/packet.json") {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(())
}

fn validate_repo_path(value: &str) -> Result<(), HarnessStatusError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.starts_with('/')
        || value.contains(['\0', '\n', '\r', '\\'])
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(HarnessStatusError::InvalidState);
    }
    Ok(())
}

fn git_repository_root() -> Result<PathBuf, HarnessStatusError> {
    let current = std::env::current_dir()
        .map_err(|_| HarnessStatusError::RepositoryUnavailable)?
        .canonicalize()
        .map_err(|_| HarnessStatusError::RepositoryUnavailable)?;
    for candidate in current.ancestors().take(MAX_REPOSITORY_DEPTH) {
        let metadata = match std::fs::symlink_metadata(candidate.join(".git")) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(HarnessStatusError::RepositoryUnavailable),
        };
        if metadata.file_type().is_dir() {
            return Ok(candidate.to_path_buf());
        }
        return Err(HarnessStatusError::RepositoryUnavailable);
    }
    Err(HarnessStatusError::RepositoryUnavailable)
}

fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, ReadError> {
    if !path.is_absolute() {
        return Err(ReadError::Unsafe);
    }
    let descriptor = open_without_symlinks(path)?;
    let result = read_descriptor(descriptor, limit);
    let closed = close(descriptor);
    match (result, closed) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(ReadError::Unsafe),
    }
}

#[cfg(target_os = "linux")]
fn open_without_symlinks(path: &Path) -> Result<i32, ReadError> {
    openat2(
        nix::libc::AT_FDCWD,
        path,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
            .mode(Mode::empty())
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| match error {
        Errno::ENOENT => ReadError::Missing,
        _ => ReadError::Unsafe,
    })
}

#[cfg(not(target_os = "linux"))]
fn open_without_symlinks(_path: &Path) -> Result<i32, ReadError> {
    Err(ReadError::Unsafe)
}

fn read_descriptor(descriptor: i32, limit: usize) -> Result<Vec<u8>, ReadError> {
    let metadata = fstat(descriptor).map_err(|_| ReadError::Unsafe)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(ReadError::Unsafe);
    }
    let mut bytes = vec![0; limit + 1];
    let mut length = 0;
    loop {
        match read(descriptor, &mut bytes[length..]) {
            Ok(0) => {
                bytes.truncate(length);
                return Ok(bytes);
            }
            Ok(count) => {
                length += count;
                if length > limit {
                    return Err(ReadError::TooLarge);
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return Err(ReadError::Unsafe),
        }
    }
}
