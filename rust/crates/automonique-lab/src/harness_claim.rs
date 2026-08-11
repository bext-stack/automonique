// SPDX-License-Identifier: Elastic-2.0

//! Durable core for a Rust-owned bootstrap claim transaction.
//!
//! Repository discovery, Git inspection, and fixed safety-check execution are
//! deliberately composition-root responsibilities. This module accepts their
//! already-verified immutable coordinates, selects from bounded generated
//! documents, and publishes the packet before the active state pointer.

use nix::fcntl::{Flock, FlockArg};
use nix::libc;
use nix::unistd::Uid;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const PROGRAM_SCHEMA: &str = "automonique.dev-program/v1";
const OBJECTIVES_SCHEMA: &str = "automonique.dev-objectives/v1";
const LOOP_SCHEMA: &str = "automonique.dev-loop/v1";
const PACKET_SCHEMA: &str = "automonique.harness-objective-packet/v1";
/// What a candidate *session* may do with the work it is handed. Stamped into
/// every objective packet, and required by [`crate::program`] when one is read
/// back.
///
/// This is a different question from [`REPOSITORY_INTEGRATION_CEILING`] and has
/// a different answer. Both were once spelled `integration_ceiling`, and
/// `tools/harness_loop.py` consequently stamped the repository answer into the
/// packet field that asks the session question — so every packet the loop wrote
/// was refused by `program.rs`. The suite did not notice, because every fixture
/// hard-coded the same literal as the validator it was checking. Two names, and
/// the loop config below is checked against them, so the two halves can no
/// longer disagree quietly.
pub const SESSION_INTEGRATION_CEILING: &str = "proposal_only";
/// What the loop may do to the *repository* once a candidate is verified. Under
/// `autonomous-protected-integration` that reaches `origin/main` by non-force
/// fast-forward without owner sign-off. Release signing, package publication and
/// production deployment stay outside it.
pub const REPOSITORY_INTEGRATION_CEILING: &str = "verified_fast_forward_main";
const STATE_SCHEMA: &str = "automonique.harness-loop-state/v1";
const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 1_024;
const MAX_PACKET_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024;
const MAX_PROGRAM_BYTES: usize = 512 * 1024;
const MAX_OBJECTIVES_BYTES: usize = 128 * 1024;
const MAX_GUIDES_BYTES: usize = 128 * 1024;
const MAX_LOOP_BYTES: usize = 32 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const GIT_WALL_LIMIT: Duration = Duration::from_secs(10);
const CHECK_WALL_LIMIT: Duration = Duration::from_secs(30);
const GIT_OUTPUT_LIMIT: usize = 4 * 1024;
const CHECK_OUTPUT_LIMIT: usize = 256 * 1024;
const PROGRAM_RELATIVE: &str = ".automonique/dev/program.yaml";
const OBJECTIVES_RELATIVE: &str = ".automonique/dev/objectives.json";
const GUIDES_RELATIVE: &str = ".automonique/dev/guides/manifest.json";
const LOOP_RELATIVE: &str = ".automonique/dev/loop.json";
const STATE_RELATIVE: &str = ".automonique/state";
static CLAIM_NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const EXISTING_STATE_FIELDS: &[&str] = &[
    "base",
    "branch",
    "candidate_commit",
    "candidate_paths",
    "candidate_ref",
    "candidate_summary",
    "candidate_tree",
    "checked_at",
    "deadline_at",
    "driver",
    "elapsed_seconds",
    "failures",
    "integrated_commit",
    "integration_receipt_sha256",
    "iteration",
    "last_exit_code",
    "last_tree_digest",
    "packet",
    "packet_sha256",
    "run_id",
    "schema",
    "started_at",
    "status",
    "stop_reason",
    "unchanged_results",
    "updated_at",
    "work_id",
];
const REQUIRED_EXISTING_STATE_FIELDS: &[&str] = &[
    "base",
    "branch",
    "deadline_at",
    "driver",
    "failures",
    "iteration",
    "packet",
    "packet_sha256",
    "run_id",
    "schema",
    "started_at",
    "status",
    "stop_reason",
    "unchanged_results",
    "updated_at",
    "work_id",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSnapshot {
    pub(crate) head: String,
    pub(crate) branch: String,
    pub(crate) clean: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCoordinates {
    pub(crate) started_at: String,
    pub(crate) deadline_at: String,
    pub(crate) nonce: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimFault {
    AfterPacketDurable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimReceipt {
    pub run_id: String,
    pub work_id: String,
    pub packet_relative: String,
    pub packet_sha256: String,
    /// Read back out of the packet that was just written, not re-stated from a
    /// literal. A receipt that names the ceiling independently of the packet is
    /// a receipt that can be wrong about it.
    pub integration_ceiling: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    UnsafeStateRoot,
    LockBusy,
    ActiveClaim,
    InvalidExistingState,
    InvalidInput,
    IneligibleItem,
    Collision,
    Io,
    InjectedFault,
}

/// Closed failure classes for the fixed operational claim composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalClaimError {
    RepositoryUnavailable,
    GitUnavailable,
    DirtyWorktree,
    UnsafeInput,
    InputChanged,
    PlanCheckFailed,
    ProgramCheckFailed,
    GuidesCheckFailed,
    CheckTimeout,
    CheckOutputLimit,
    StateUnavailable,
    ClockUnavailable,
    Claim(ClaimError),
}

impl fmt::Display for OperationalClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "operational claim denied: {self:?}")
    }
}

impl Error for OperationalClaimError {}

impl fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "claim denied: {self:?}")
    }
}

impl Error for ClaimError {}

pub struct ClaimDocuments<'a> {
    pub(crate) program: &'a [u8],
    pub(crate) objectives: &'a [u8],
    pub(crate) guide_manifest: &'a [u8],
    pub(crate) loop_config: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedClaimDocuments {
    program: Vec<u8>,
    objectives: Vec<u8>,
    guide_manifest: Vec<u8>,
    loop_config: Vec<u8>,
}

impl OwnedClaimDocuments {
    fn borrowed(&self) -> ClaimDocuments<'_> {
        ClaimDocuments {
            program: &self.program,
            objectives: &self.objectives,
            guide_manifest: &self.guide_manifest,
            loop_config: &self.loop_config,
        }
    }
}

#[derive(Clone, Copy)]
enum SafetyCheck {
    Plan,
    Program,
    Guides,
}

impl SafetyCheck {
    const ALL: [Self; 3] = [Self::Plan, Self::Program, Self::Guides];

    const fn arguments(self) -> [&'static str; 2] {
        match self {
            Self::Plan => ["plan/check.py", "--verify"],
            Self::Program => ["tools/program.py", "--verify"],
            Self::Guides => ["tools/guides.py", "--verify"],
        }
    }

    const fn failure(self) -> OperationalClaimError {
        match self {
            Self::Plan => OperationalClaimError::PlanCheckFailed,
            Self::Program => OperationalClaimError::ProgramCheckFailed,
            Self::Guides => OperationalClaimError::GuidesCheckFailed,
        }
    }
}

#[derive(Debug)]
struct ProcessResult {
    status: ExitStatus,
    stdout: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessError {
    Unavailable,
    Timeout,
    OutputLimit,
}

/// Claim one score-eligible item using only repository-fixed inputs and checks.
///
/// This is an operational Rust alternative to the bootstrap claim command. It
/// does not alter the configured authority mode or replace the existing driver.
/// The only caller-selected value is an optional work identifier; paths,
/// checks, process limits, and the selected objective's budget are sealed here.
pub fn publish_current_claim(
    requested_item: Option<&str>,
) -> Result<ClaimReceipt, OperationalClaimError> {
    let repository = discover_repository()?;
    verify_state_is_ignored(&repository)?;
    let initial_snapshot = inspect_git(&repository)?;
    if !initial_snapshot.clean {
        return Err(OperationalClaimError::DirtyWorktree);
    }
    let initial_documents = read_operational_documents(&repository)?;
    let max_wall_seconds = operational_budget(&initial_documents, requested_item)?;

    for check in SafetyCheck::ALL {
        run_safety_check(&repository, check)?;
    }

    let final_documents = read_operational_documents(&repository)?;
    let final_snapshot = inspect_git(&repository)?;
    if !final_snapshot.clean {
        return Err(OperationalClaimError::DirtyWorktree);
    }
    if final_snapshot != initial_snapshot || final_documents != initial_documents {
        return Err(OperationalClaimError::InputChanged);
    }
    if operational_budget(&final_documents, requested_item)? != max_wall_seconds {
        return Err(OperationalClaimError::InputChanged);
    }

    let state_root = ensure_private_state_root(&repository)?;
    let coordinates = current_coordinates(max_wall_seconds)?;
    publish_claim(
        &state_root,
        final_documents.borrowed(),
        requested_item,
        &final_snapshot,
        &coordinates,
        None,
    )
    .map_err(OperationalClaimError::Claim)
}

fn discover_repository() -> Result<PathBuf, OperationalClaimError> {
    let current =
        std::env::current_dir().map_err(|_| OperationalClaimError::RepositoryUnavailable)?;
    let output = fixed_git(&current, &["rev-parse", "--show-toplevel"])?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| OperationalClaimError::RepositoryUnavailable)?;
    let untrusted = text.trim_end_matches(['\r', '\n']);
    if untrusted.is_empty() || untrusted.as_bytes().contains(&0) {
        return Err(OperationalClaimError::RepositoryUnavailable);
    }
    let repository = PathBuf::from(untrusted)
        .canonicalize()
        .map_err(|_| OperationalClaimError::RepositoryUnavailable)?;
    if !repository.is_absolute() {
        return Err(OperationalClaimError::RepositoryUnavailable);
    }
    reject_symlink_components(&repository)
        .map_err(|_| OperationalClaimError::RepositoryUnavailable)?;
    Ok(repository)
}

fn inspect_git(repository: &Path) -> Result<GitSnapshot, OperationalClaimError> {
    let head = git_line(repository, &["rev-parse", "--verify", "HEAD"])?;
    let branch = git_line(repository, &["branch", "--show-current"])?;
    let status = fixed_git(
        repository,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
        ],
    )?;
    let snapshot = GitSnapshot {
        head,
        branch,
        clean: status.stdout.is_empty(),
    };
    validate_snapshot(&snapshot).map_err(|_| OperationalClaimError::GitUnavailable)?;
    Ok(snapshot)
}

fn git_line(repository: &Path, arguments: &[&str]) -> Result<String, OperationalClaimError> {
    let output = fixed_git(repository, arguments)?;
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| OperationalClaimError::GitUnavailable)?;
    let line = text.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.contains(['\r', '\n', '\0']) {
        return Err(OperationalClaimError::GitUnavailable);
    }
    Ok(line.to_owned())
}

fn verify_state_is_ignored(repository: &Path) -> Result<(), OperationalClaimError> {
    let result = fixed_git_allow_failure(
        repository,
        &["check-ignore", "-q", ".automonique/state/harness-loop.json"],
    )?;
    if result.status.success() && result.stdout.is_empty() {
        Ok(())
    } else {
        Err(OperationalClaimError::StateUnavailable)
    }
}

fn fixed_git(
    repository: &Path,
    arguments: &[&str],
) -> Result<ProcessResult, OperationalClaimError> {
    let result = fixed_git_allow_failure(repository, arguments)?;
    if result.status.success() {
        Ok(result)
    } else {
        Err(OperationalClaimError::GitUnavailable)
    }
}

fn fixed_git_allow_failure(
    repository: &Path,
    arguments: &[&str],
) -> Result<ProcessResult, OperationalClaimError> {
    let mut command = Command::new("/usr/bin/git");
    command
        .current_dir(repository)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(arguments);
    run_bounded(&mut command, GIT_WALL_LIMIT, GIT_OUTPUT_LIMIT).map_err(|error| match error {
        ProcessError::Unavailable | ProcessError::Timeout | ProcessError::OutputLimit => {
            OperationalClaimError::GitUnavailable
        }
    })
}

fn read_operational_documents(
    repository: &Path,
) -> Result<OwnedClaimDocuments, OperationalClaimError> {
    Ok(OwnedClaimDocuments {
        program: read_fixed_input(repository, PROGRAM_RELATIVE, MAX_PROGRAM_BYTES)?,
        objectives: read_fixed_input(repository, OBJECTIVES_RELATIVE, MAX_OBJECTIVES_BYTES)?,
        guide_manifest: read_fixed_input(repository, GUIDES_RELATIVE, MAX_GUIDES_BYTES)?,
        loop_config: read_fixed_input(repository, LOOP_RELATIVE, MAX_LOOP_BYTES)?,
    })
}

fn read_fixed_input(
    repository: &Path,
    relative: &str,
    maximum: usize,
) -> Result<Vec<u8>, OperationalClaimError> {
    let path = repository.join(relative);
    reject_symlink_components(&path).map_err(|_| OperationalClaimError::UnsafeInput)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| OperationalClaimError::UnsafeInput)?;
    let metadata = file
        .metadata()
        .map_err(|_| OperationalClaimError::UnsafeInput)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(OperationalClaimError::UnsafeInput);
    }
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| OperationalClaimError::UnsafeInput)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(OperationalClaimError::UnsafeInput);
    }
    Ok(bytes)
}

fn operational_budget(
    documents: &OwnedClaimDocuments,
    requested_item: Option<&str>,
) -> Result<u64, OperationalClaimError> {
    let program =
        parse_document(&documents.program).map_err(|_| OperationalClaimError::UnsafeInput)?;
    let objectives =
        parse_document(&documents.objectives).map_err(|_| OperationalClaimError::UnsafeInput)?;
    let loop_config =
        parse_document(&documents.loop_config).map_err(|_| OperationalClaimError::UnsafeInput)?;
    validate_operational_config(&loop_config)?;
    let (_, _, _, max_wall_seconds) = select(&program, &objectives, &loop_config, requested_item)
        .map_err(|_| OperationalClaimError::UnsafeInput)?;
    Ok(max_wall_seconds)
}

fn validate_operational_config(value: &Value) -> Result<(), OperationalClaimError> {
    let object = value
        .as_object()
        .ok_or(OperationalClaimError::UnsafeInput)?;
    if object.get("state_path").and_then(Value::as_str)
        != Some(".automonique/state/harness-loop.json")
        || object.get("max_workers").and_then(Value::as_u64) != Some(1)
        || object.get("safety_checks")
            != Some(&json!([
                ["python3", "plan/check.py", "--verify"],
                ["python3", "tools/program.py", "--verify"],
                ["python3", "tools/guides.py", "--verify"]
            ]))
    {
        return Err(OperationalClaimError::UnsafeInput);
    }
    Ok(())
}

fn run_safety_check(repository: &Path, check: SafetyCheck) -> Result<(), OperationalClaimError> {
    let mut command = Command::new("/usr/bin/python3");
    command
        .current_dir(repository)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONHASHSEED", "0")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .args(check.arguments());
    let result = run_bounded(&mut command, CHECK_WALL_LIMIT, CHECK_OUTPUT_LIMIT).map_err(
        |error| match error {
            ProcessError::Unavailable => check.failure(),
            ProcessError::Timeout => OperationalClaimError::CheckTimeout,
            ProcessError::OutputLimit => OperationalClaimError::CheckOutputLimit,
        },
    )?;
    if result.status.success() {
        Ok(())
    } else {
        Err(check.failure())
    }
}

fn run_bounded(
    command: &mut Command,
    wall_limit: Duration,
    output_limit: usize,
) -> Result<ProcessResult, ProcessError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| ProcessError::Unavailable)?;
    let group = Pid::from_raw(i32::try_from(child.id()).map_err(|_| ProcessError::Unavailable)?);
    let stdout = child.stdout.take().ok_or(ProcessError::Unavailable)?;
    let stderr = child.stderr.take().ok_or(ProcessError::Unavailable)?;
    let captured = Arc::new(AtomicUsize::new(0));
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader = bounded_capture(
        stdout,
        output_limit,
        Arc::clone(&captured),
        Arc::clone(&exceeded),
    );
    let stderr_reader = bounded_capture(stderr, output_limit, captured, Arc::clone(&exceeded));
    let deadline = Instant::now() + wall_limit;
    let mut forced = None;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            forced = Some(ProcessError::OutputLimit);
            break terminate_process(&mut child, group)?;
        }
        if Instant::now() >= deadline {
            forced = Some(ProcessError::Timeout);
            break terminate_process(&mut child, group)?;
        }
        if let Some(status) = child.try_wait().map_err(|_| ProcessError::Unavailable)? {
            cleanup_process_group(group);
            break status;
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ProcessError::Unavailable)??;
    stderr_reader
        .join()
        .map_err(|_| ProcessError::Unavailable)??;
    if let Some(error) = forced {
        return Err(error);
    }
    Ok(ProcessResult { status, stdout })
}

fn bounded_capture(
    mut input: impl Read + Send + 'static,
    maximum: usize,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, ProcessError>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8_192];
        loop {
            let read = input
                .read(&mut chunk)
                .map_err(|_| ProcessError::Unavailable)?;
            if read == 0 {
                return Ok(bytes);
            }
            let start = captured.fetch_add(read, Ordering::AcqRel);
            let remaining = maximum.saturating_sub(start);
            bytes.extend_from_slice(&chunk[..read.min(remaining)]);
            if read > remaining {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn terminate_process(
    child: &mut std::process::Child,
    group: Pid,
) -> Result<ExitStatus, ProcessError> {
    let _ = killpg(group, Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(|_| ProcessError::Unavailable)? {
            cleanup_process_group(group);
            return Ok(status);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
    let _ = killpg(group, Signal::SIGKILL);
    let status = child.wait().map_err(|_| ProcessError::Unavailable)?;
    cleanup_process_group(group);
    Ok(status)
}

fn cleanup_process_group(group: Pid) {
    let _ = killpg(group, Signal::SIGKILL);
}

fn ensure_private_state_root(repository: &Path) -> Result<PathBuf, OperationalClaimError> {
    let automonique = repository.join(".automonique");
    let metadata =
        fs::symlink_metadata(&automonique).map_err(|_| OperationalClaimError::StateUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OperationalClaimError::StateUnavailable);
    }
    let state = repository.join(STATE_RELATIVE);
    match fs::DirBuilder::new().mode(0o700).create(&state) {
        Ok(()) => {
            sync_directory(&automonique).map_err(|_| OperationalClaimError::StateUnavailable)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(OperationalClaimError::StateUnavailable),
    }
    require_private_directory(&state).map_err(|_| OperationalClaimError::StateUnavailable)?;
    reject_symlink_components(&state).map_err(|_| OperationalClaimError::StateUnavailable)?;
    Ok(state)
}

fn current_coordinates(max_wall_seconds: u64) -> Result<ClaimCoordinates, OperationalClaimError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperationalClaimError::ClockUnavailable)?;
    let started_seconds =
        i64::try_from(duration.as_secs()).map_err(|_| OperationalClaimError::ClockUnavailable)?;
    let wall_seconds =
        i64::try_from(max_wall_seconds).map_err(|_| OperationalClaimError::ClockUnavailable)?;
    let deadline_seconds = started_seconds
        .checked_add(wall_seconds)
        .ok_or(OperationalClaimError::ClockUnavailable)?;
    let sequence = CLAIM_NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce_input = Vec::with_capacity(36);
    nonce_input.extend_from_slice(&duration.as_nanos().to_le_bytes());
    nonce_input.extend_from_slice(&std::process::id().to_le_bytes());
    nonce_input.extend_from_slice(&sequence.to_le_bytes());
    let nonce_digest = hex::encode(Sha256::digest(&nonce_input));
    Ok(ClaimCoordinates {
        started_at: format_utc_timestamp(started_seconds)
            .ok_or(OperationalClaimError::ClockUnavailable)?,
        deadline_at: format_utc_timestamp(deadline_seconds)
            .ok_or(OperationalClaimError::ClockUnavailable)?,
        nonce: nonce_digest[..8].to_owned(),
    })
}

fn format_utc_timestamp(epoch_seconds: i64) -> Option<String> {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds = epoch_seconds.rem_euclid(86_400);
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(1..=9_999).contains(&year) {
        return None;
    }
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00"
    ))
}

/// Publish a claim from coordinates sealed inside this crate's trusted
/// composition root. External callers cannot construct the input capabilities.
pub fn publish_claim(
    state_root: &Path,
    documents: ClaimDocuments<'_>,
    requested_item: Option<&str>,
    snapshot: &GitSnapshot,
    coordinates: &ClaimCoordinates,
    fault: Option<ClaimFault>,
) -> Result<ClaimReceipt, ClaimError> {
    reject_symlink_components(state_root)?;
    require_private_directory(state_root)?;
    let lock = open_private_lock(&state_root.join("harness-loop.json.lock"))?;
    let _lock =
        Flock::lock(lock, FlockArg::LockExclusiveNonblock).map_err(|_| ClaimError::LockBusy)?;

    let state_path = state_root.join("harness-loop.json");
    let prior = read_existing_state(&state_path)?;
    validate_snapshot(snapshot)?;
    validate_coordinates(coordinates)?;

    let program = parse_document(documents.program)?;
    let objectives = parse_document(documents.objectives)?;
    let loop_config = parse_document(documents.loop_config)?;
    if documents.guide_manifest.is_empty() || documents.guide_manifest.len() > MAX_DOCUMENT_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    let (item, objective, max_agents, max_wall_seconds) =
        select(&program, &objectives, &loop_config, requested_item)?;
    validate_deadline(coordinates, max_wall_seconds)?;
    let work_id = string(item.as_object().ok_or(ClaimError::InvalidInput)?, "id")?;
    crate::program::validate_claim_documents(documents.program, documents.objectives, work_id)
        .map_err(|_| ClaimError::InvalidInput)?;
    let run_id = run_id(&coordinates.started_at, &coordinates.nonce)?;

    let program_sha = sha256(documents.program);
    let objectives_sha = sha256(documents.objectives);
    let guides_sha = sha256(documents.guide_manifest);
    let packet = json!({
        "attempt_baseline": {
            "admission_safety_checks": "pass",
            "git_head": snapshot.head,
            "guides_sha256": guides_sha,
            "objectives_sha256": objectives_sha,
            "program_sha256": program_sha,
            "worktree_clean": true
        },
        "driver": "codex_session",
        "guides_sha256": guides_sha,
        "immutable_base": snapshot.head,
        "integration_ceiling": SESSION_INTEGRATION_CEILING,
        "iteration": 1,
        "objective": objective,
        "objectives_sha256": objectives_sha,
        "prior_iteration": null,
        "program_sha256": program_sha,
        "run_id": run_id,
        "schema": PACKET_SCHEMA,
        "session_coordination": {
            "concurrent_writes": "disjoint_paths_only",
            "integration_owner": "primary_session",
            "max_concurrent_subagents": max_agents,
            "native_subagents": true,
            "primary_role": "coordinate, integrate, verify, and report",
            "recursive_agent_trees": false,
            "subagent_prompt_fields": [
                "bounded objective",
                "allowed paths",
                "required checks",
                "return evidence"
            ]
        },
        "work_item": item
    });
    let mut packet_bytes =
        serde_json::to_vec_pretty(&packet).map_err(|_| ClaimError::InvalidInput)?;
    packet_bytes.push(b'\n');
    if packet_bytes.len() > MAX_PACKET_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    crate::program::validate_claim_packet(&packet_bytes).map_err(|_| ClaimError::InvalidInput)?;
    let run_dir = state_root.join("runs").join(&run_id);
    create_private_run_directory(state_root, &run_dir)?;
    let packet_path = run_dir.join("packet.json");
    write_create_new(&packet_path, &packet_bytes)?;
    sync_directory(&run_dir)?;
    if fault == Some(ClaimFault::AfterPacketDurable) {
        return Err(ClaimError::InjectedFault);
    }

    let packet_relative = format!(".automonique/state/runs/{run_id}/packet.json");
    let packet_sha = sha256(&packet_bytes);
    let state = json!({
        "base": snapshot.head,
        "branch": snapshot.branch,
        "deadline_at": coordinates.deadline_at,
        "driver": "codex_session",
        "failures": 0,
        "iteration": 1,
        "packet": packet_relative,
        "packet_sha256": packet_sha,
        "run_id": run_id,
        "schema": STATE_SCHEMA,
        "started_at": coordinates.started_at,
        "status": "claimed",
        "stop_reason": null,
        "unchanged_results": 0,
        "updated_at": coordinates.started_at,
        "work_id": work_id
    });
    crate::harness_status::validate_state_document(&state).map_err(|_| ClaimError::InvalidInput)?;
    let mut state_bytes =
        serde_json::to_vec_pretty(&state).map_err(|_| ClaimError::InvalidInput)?;
    state_bytes.push(b'\n');
    if let Some(prior) = &prior {
        verify_prior_unchanged(&state_path, prior)?;
    }
    publish_state(state_root, &state_path, &coordinates.nonce, &state_bytes)?;
    // Read back out of the bytes that were validated and made durable above.
    // Re-stating the constant here would let the receipt and the packet disagree,
    // which is the failure this whole rename exists to prevent.
    let integration_ceiling = serde_json::from_slice::<Value>(&packet_bytes)
        .ok()
        .and_then(|document| {
            document
                .get("integration_ceiling")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .ok_or(ClaimError::InvalidInput)?;
    Ok(ClaimReceipt {
        run_id,
        work_id: work_id.to_owned(),
        packet_relative,
        packet_sha256: packet_sha,
        integration_ceiling,
    })
}

fn select<'a>(
    program: &'a Value,
    objectives: &'a Value,
    loop_config: &Value,
    requested: Option<&str>,
) -> Result<(&'a Value, &'a Value, u64, u64), ClaimError> {
    let program = exact_object(program, &["items", "schema", "source"])?;
    if string(program, "schema")? != PROGRAM_SCHEMA {
        return Err(ClaimError::InvalidInput);
    }
    let objectives = exact_object(objectives, &["objectives", "schema"])?;
    if string(objectives, "schema")? != OBJECTIVES_SCHEMA {
        return Err(ClaimError::InvalidInput);
    }
    let loop_config = loop_config.as_object().ok_or(ClaimError::InvalidInput)?;
    // Both ceilings are checked against the constants above rather than merely
    // read. That is what closes the loop: `tools/harness_loop.py` stamps the
    // packet from `session_integration_ceiling`, this refuses a config whose
    // value is not the one `program.rs` will demand, so the Python producer and
    // the Rust validator cannot drift apart without the claim failing loudly.
    if string(loop_config, "schema")? != LOOP_SCHEMA
        || string(loop_config, "repository_integration_ceiling")? != REPOSITORY_INTEGRATION_CEILING
        || string(loop_config, "session_integration_ceiling")? != SESSION_INTEGRATION_CEILING
        || string(loop_config, "default_driver")? != "codex_session"
    {
        return Err(ClaimError::InvalidInput);
    }
    let threshold = integer(loop_config, "hill_climbability_threshold")?;
    let drivers = object(loop_config, "drivers")?;
    let session = object(drivers, "codex_session")?;
    let max_agents = integer(session, "max_concurrent_subagents")?;
    if max_agents == 0
        || max_agents > 3
        || session.get("native_subagents").and_then(Value::as_bool) != Some(true)
        || session
            .get("recursive_agent_trees")
            .and_then(Value::as_bool)
            != Some(false)
        || string(session, "concurrent_writes")? != "disjoint_paths_only"
        || string(session, "integration_owner")? != "primary_session"
    {
        return Err(ClaimError::InvalidInput);
    }
    let items = array(program, "items")?;
    let objective_values = array(objectives, "objectives")?;
    if items.is_empty() || items.len() > MAX_ITEMS || objective_values.len() > MAX_ITEMS {
        return Err(ClaimError::InvalidInput);
    }
    if requested.is_some_and(|value| !identifier(value, 80)) {
        return Err(ClaimError::InvalidInput);
    }
    let mut item_ids = HashSet::with_capacity(items.len());
    for item in items {
        let item = item.as_object().ok_or(ClaimError::InvalidInput)?;
        let id = string(item, "id")?;
        if !identifier(id, 80) || !item_ids.insert(id) {
            return Err(ClaimError::InvalidInput);
        }
    }
    let mut objective_ids = HashSet::with_capacity(objective_values.len());
    for objective in objective_values {
        let objective = objective.as_object().ok_or(ClaimError::InvalidInput)?;
        let work_id = string(objective, "work_id")?;
        if !identifier(work_id, 80) || !objective_ids.insert(work_id) {
            return Err(ClaimError::InvalidInput);
        }
    }
    let mut selected = None;
    for item in items {
        let item_object = item.as_object().ok_or(ClaimError::InvalidInput)?;
        let id = string(item_object, "id")?;
        if requested.is_some_and(|wanted| wanted != id) {
            continue;
        }
        let objective = objective_values.iter().find(|candidate| {
            candidate
                .as_object()
                .and_then(|value| value.get("work_id"))
                .and_then(Value::as_str)
                == Some(id)
        });
        let Some(objective) = objective else {
            if requested.is_some() {
                return Err(ClaimError::IneligibleItem);
            }
            continue;
        };
        let objective_object = objective.as_object().ok_or(ClaimError::InvalidInput)?;
        let runnable = item_object
            .get("runnable")
            .and_then(Value::as_bool)
            .ok_or(ClaimError::InvalidInput)?;
        let eligible = objective_object
            .get("autonomous_eligible")
            .and_then(Value::as_bool)
            .ok_or(ClaimError::InvalidInput)?;
        let score = integer(objective_object, "hill_climbability")?;
        if eligible != (score >= threshold) {
            return Err(ClaimError::InvalidInput);
        }
        if runnable && eligible {
            validate_pair(item_object, objective_object)?;
            selected = Some((item, objective));
            break;
        }
        if requested.is_some() {
            return Err(ClaimError::IneligibleItem);
        }
    }
    let (item, objective) = selected.ok_or(ClaimError::IneligibleItem)?;
    let objective_object = objective.as_object().ok_or(ClaimError::InvalidInput)?;
    let max_wall_seconds =
        positive_integer(object(objective_object, "budget")?, "max_wall_seconds")?;
    Ok((item, objective, max_agents, max_wall_seconds))
}

fn validate_pair(
    item: &Map<String, Value>,
    objective: &Map<String, Value>,
) -> Result<(), ClaimError> {
    if string(objective, "id")? != format!("objective:{}", string(item, "id")?)
        || item.get("allowed_paths") != objective.get("allowed_paths")
        || item.get("licence") != objective.get("licence")
        || item.get("contract").is_none_or(Value::is_null)
    {
        return Err(ClaimError::InvalidInput);
    }
    let budget = object(objective, "budget")?;
    let iterations = positive_integer(budget, "max_iterations")?;
    let wall = positive_integer(budget, "max_wall_seconds")?;
    let worker = positive_integer(budget, "max_worker_seconds")?;
    let unchanged = positive_integer(budget, "max_unchanged_results")?;
    let failures = positive_integer(budget, "max_failures")?;
    if worker > wall || unchanged > iterations || failures > iterations {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

#[derive(Clone)]
struct PriorState {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
}

fn read_existing_state(path: &Path) -> Result<Option<PriorState>, ClaimError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ClaimError::InvalidExistingState),
    };
    let metadata = file
        .metadata()
        .map_err(|_| ClaimError::InvalidExistingState)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::InvalidExistingState);
    }
    let mut bytes = Vec::new();
    file.take((MAX_STATE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClaimError::InvalidExistingState)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ClaimError::InvalidExistingState);
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| ClaimError::InvalidExistingState)?;
    crate::harness_status::validate_state_document(&value)
        .map_err(|_| ClaimError::InvalidExistingState)?;
    let object = value.as_object().ok_or(ClaimError::InvalidExistingState)?;
    if object
        .keys()
        .any(|field| !EXISTING_STATE_FIELDS.contains(&field.as_str()))
        || REQUIRED_EXISTING_STATE_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(ClaimError::InvalidExistingState);
    }
    if string(object, "schema").map_err(|_| ClaimError::InvalidExistingState)? != STATE_SCHEMA {
        return Err(ClaimError::InvalidExistingState);
    }
    validate_existing_state_coordinates(object)?;
    let status = string(object, "status").map_err(|_| ClaimError::InvalidExistingState)?;
    if !matches!(status, "stopped" | "integrated_and_pushed") {
        return Err(ClaimError::ActiveClaim);
    }
    let reason = object.get("stop_reason").and_then(Value::as_str);
    if (status == "integrated_and_pushed" && reason != Some("integrated_and_pushed"))
        || (status == "stopped" && reason.is_none())
    {
        return Err(ClaimError::InvalidExistingState);
    }
    Ok(Some(PriorState {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn verify_prior_unchanged(path: &Path, prior: &PriorState) -> Result<(), ClaimError> {
    let current = read_file_no_follow(path, MAX_STATE_BYTES)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ClaimError::Io)?;
    if current != prior.bytes || metadata.dev() != prior.device || metadata.ino() != prior.inode {
        return Err(ClaimError::InvalidExistingState);
    }
    Ok(())
}

fn publish_state(
    root: &Path,
    destination: &Path,
    nonce: &str,
    bytes: &[u8],
) -> Result<(), ClaimError> {
    let temporary = root.join(format!(".harness-loop.{nonce}.tmp"));
    write_create_new(&temporary, bytes)?;
    fs::rename(&temporary, destination).map_err(|_| ClaimError::Io)?;
    sync_directory(root)
}

fn create_private_run_directory(state_root: &Path, run_dir: &Path) -> Result<(), ClaimError> {
    let runs = state_root.join("runs");
    if !runs.exists() {
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&runs)
            .map_err(|_| ClaimError::Io)?;
        sync_directory(state_root)?;
    }
    require_private_directory(&runs)?;
    match fs::DirBuilder::new().mode(0o700).create(run_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ClaimError::Collision);
        }
        Err(_) => return Err(ClaimError::Io),
    }
    sync_directory(&runs)
}

fn require_private_directory(path: &Path) -> Result<(), ClaimError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ClaimError::UnsafeStateRoot)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ClaimError::UnsafeStateRoot);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), ClaimError> {
    if !path.is_absolute() {
        return Err(ClaimError::UnsafeStateRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            _ => return Err(ClaimError::UnsafeStateRoot),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| ClaimError::UnsafeStateRoot)?;
        if metadata.file_type().is_symlink() {
            return Err(ClaimError::UnsafeStateRoot);
        }
    }
    Ok(())
}

fn open_private_lock(path: &Path) -> Result<File, ClaimError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::UnsafeStateRoot)?;
    let metadata = file.metadata().map_err(|_| ClaimError::UnsafeStateRoot)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::UnsafeStateRoot);
    }
    Ok(file)
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), ClaimError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ClaimError::Io)?;
    file.write_all(bytes).map_err(|_| ClaimError::Io)?;
    file.sync_all().map_err(|_| ClaimError::Io)?;
    let metadata = file.metadata().map_err(|_| ClaimError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::Io);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ClaimError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ClaimError::Io)
}

fn read_file_no_follow(path: &Path, maximum: usize) -> Result<Vec<u8>, ClaimError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::Io)?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClaimError::Io)?;
    if bytes.len() > maximum {
        return Err(ClaimError::Io);
    }
    Ok(bytes)
}

fn parse_document(bytes: &[u8]) -> Result<Value, ClaimError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    let start = bytes
        .iter()
        .position(|byte| *byte == b'{')
        .ok_or(ClaimError::InvalidInput)?;
    serde_json::from_slice(&bytes[start..]).map_err(|_| ClaimError::InvalidInput)
}

fn validate_snapshot(snapshot: &GitSnapshot) -> Result<(), ClaimError> {
    if !snapshot.clean || !lower_hex(&snapshot.head, 40) || !identifier(&snapshot.branch, 255) {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn validate_coordinates(value: &ClaimCoordinates) -> Result<(), ClaimError> {
    if !timestamp(&value.started_at)
        || !timestamp(&value.deadline_at)
        || !lower_hex(&value.nonce, 8)
        || value.deadline_at <= value.started_at
    {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn validate_deadline(value: &ClaimCoordinates, max_wall_seconds: u64) -> Result<(), ClaimError> {
    let started = timestamp_seconds(&value.started_at).ok_or(ClaimError::InvalidInput)?;
    let deadline = timestamp_seconds(&value.deadline_at).ok_or(ClaimError::InvalidInput)?;
    if deadline.checked_sub(started) != i64::try_from(max_wall_seconds).ok() {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn run_id(timestamp: &str, nonce: &str) -> Result<String, ClaimError> {
    let compact = timestamp
        .strip_suffix("+00:00")
        .ok_or(ClaimError::InvalidInput)?
        .replace(['-', ':'], "");
    Ok(format!("session_{compact}Z_{nonce}"))
}

fn timestamp(value: &str) -> bool {
    timestamp_seconds(value).is_some()
}

fn timestamp_seconds(value: &str) -> Option<i64> {
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
        || !value.ends_with("+00:00")
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        return None;
    }
    let number = |start: usize, end: usize| value.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year == 0
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)
}

fn validate_existing_state_coordinates(object: &Map<String, Value>) -> Result<(), ClaimError> {
    if string(object, "driver")? != "codex_session"
        || !lower_hex(string(object, "base")?, 40)
        || !lower_hex(string(object, "packet_sha256")?, 64)
        || !identifier(string(object, "branch")?, 255)
        || !identifier(string(object, "run_id")?, 64)
        || !identifier(string(object, "work_id")?, 80)
        || !timestamp(string(object, "started_at")?)
        || !timestamp(string(object, "updated_at")?)
        || !timestamp(string(object, "deadline_at")?)
        || integer(object, "iteration").is_err()
        || integer(object, "failures").is_err()
        || integer(object, "unchanged_results").is_err()
    {
        return Err(ClaimError::InvalidExistingState);
    }
    let run_id = string(object, "run_id")?;
    if string(object, "packet")? != format!(".automonique/state/runs/{run_id}/packet.json") {
        return Err(ClaimError::InvalidExistingState);
    }
    match object.get("stop_reason") {
        Some(Value::Null) => Ok(()),
        Some(Value::String(reason))
            if !reason.is_empty()
                && reason.len() <= 64
                && reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_') =>
        {
            Ok(())
        }
        _ => Err(ClaimError::InvalidExistingState),
    }
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ClaimError> {
    let object = value.as_object().ok_or(ClaimError::InvalidInput)?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(ClaimError::InvalidInput);
    }
    Ok(object)
}

fn object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(ClaimError::InvalidInput)
}

fn array<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], ClaimError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ClaimError::InvalidInput)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or(ClaimError::InvalidInput)
}

fn integer(object: &Map<String, Value>, field: &str) -> Result<u64, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or(ClaimError::InvalidInput)
}

fn positive_integer(object: &Map<String, Value>, field: &str) -> Result<u64, ClaimError> {
    integer(object, field).and_then(|value| {
        if value == 0 {
            Err(ClaimError::InvalidInput)
        } else {
            Ok(value)
        }
    })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};

    struct Fixture {
        _temp: tempfile::TempDir,
        state: PathBuf,
        program: Vec<u8>,
        objectives: Vec<u8>,
        loop_config: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let state = temp.path().join("state");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&state)
                .expect("state root");
            let item = |id: &str| {
                json!({
                    "allowed_paths": ["rust/crates/automonique-lab/"],
                    "blocked_by_gates": [], "closes_gate": null,
                    "contract": format!("plan/contracts/{id}.md"), "depends_on": [],
                    "epic": "R0", "id": id, "licence": "Elastic-2.0",
                    "runnable": true, "status": "blocked",
                    "summary": "bounded synthetic claim fixture",
                    "title": "Synthetic claim fixture", "track": "core"
                })
            };
            let objective = |id: &str, score: u64| {
                json!({
                    "allowed_paths": ["rust/crates/automonique-lab/"],
                    "autonomous_eligible": score >= 70,
                    "baseline": {"reason": "synthetic", "value": null},
                    "budget": {"max_failures": 2, "max_iterations": 3,
                        "max_unchanged_results": 1, "max_wall_seconds": 1800,
                        "max_worker_seconds": 1200},
                    "hill_climbability": score, "id": format!("objective:{id}"),
                    "licence": "Elastic-2.0", "metric": {"name": "fixture", "target": 1,
                        "anti_regression": "no weakened fixture checks"},
                    "objective": "Exercise the bounded claim transaction.",
                    "sources": ["plan/contracts/R0-19.md"],
                    "stop_conditions": ["Stop on mismatch."], "tests": ["Harness claim"],
                    "work_id": id
                })
            };
            let mut program = b"# SPDX-License-Identifier: Elastic-2.0\n".to_vec();
            program.extend(
                serde_json::to_vec(&json!({
                    "items": [item("BOOT-003"), item("R0-19")],
                    "schema": PROGRAM_SCHEMA, "source": {"graph": "plan/work-graph.toml",
                        "graph_sha256": "2".repeat(64), "item_count": 2}
                }))
                .expect("program"),
            );
            let objectives = serde_json::to_vec(&json!({
                "objectives": [objective("BOOT-003", 80), objective("R0-19", 78)],
                "schema": OBJECTIVES_SCHEMA
            }))
            .expect("objectives");
            let loop_config = serde_json::to_vec(&json!({
                "default_driver": "codex_session",
                "drivers": {"codex_session": {"concurrent_writes": "disjoint_paths_only",
                    "integration_owner": "primary_session", "max_concurrent_subagents": 3,
                    "native_subagents": true, "recursive_agent_trees": false}},
                "hill_climbability_threshold": 70,
                "repository_integration_ceiling": REPOSITORY_INTEGRATION_CEILING,
                "schema": LOOP_SCHEMA,
                "session_integration_ceiling": SESSION_INTEGRATION_CEILING
            }))
            .expect("loop config");
            Self {
                _temp: temp,
                state,
                program,
                objectives,
                loop_config,
            }
        }

        fn documents(&self) -> ClaimDocuments<'_> {
            ClaimDocuments {
                program: &self.program,
                objectives: &self.objectives,
                guide_manifest: b"synthetic-guide-manifest",
                loop_config: &self.loop_config,
            }
        }
    }

    fn snapshot() -> GitSnapshot {
        GitSnapshot {
            head: "1".repeat(40),
            branch: "main".into(),
            clean: true,
        }
    }

    fn coordinates(nonce: &str) -> ClaimCoordinates {
        ClaimCoordinates {
            started_at: "2026-08-10T10:00:00+00:00".into(),
            deadline_at: "2026-08-10T10:30:00+00:00".into(),
            nonce: nonce.into(),
        }
    }

    #[test]
    fn packet_is_consumer_valid_and_published_before_state() {
        let fixture = Fixture::new();
        let receipt = publish_claim(
            &fixture.state,
            fixture.documents(),
            Some("R0-19"),
            &snapshot(),
            &coordinates("1234abcd"),
            None,
        )
        .expect("claim");
        let packet = fs::read(
            fixture
                .state
                .join("runs")
                .join(&receipt.run_id)
                .join("packet.json"),
        )
        .expect("packet");
        crate::program::validate_claim_packet(&packet).expect("consumer-valid packet");
        assert_eq!(receipt.work_id, "R0-19");
        assert_eq!(sha256(&packet), receipt.packet_sha256);
        assert_eq!(
            fs::metadata(fixture.state.join("harness-loop.json"))
                .expect("state")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn deadline_and_generated_identity_must_be_coherent() {
        let fixture = Fixture::new();
        let mut bad_time = coordinates("2234abcd");
        bad_time.deadline_at = "2026-08-10T10:29:59+00:00".into();
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                None,
                &snapshot(),
                &bad_time,
                None
            ),
            Err(ClaimError::InvalidInput)
        );

        let fixture = Fixture::new();
        let mut program = parse_document(&fixture.program).expect("program");
        program["items"][1]["id"] = json!("BOOT-003");
        let mut bytes = b"# SPDX-License-Identifier: Elastic-2.0\n".to_vec();
        bytes.extend(serde_json::to_vec(&program).expect("duplicate program"));
        let documents = ClaimDocuments {
            program: &bytes,
            ..fixture.documents()
        };
        assert_eq!(
            publish_claim(
                &fixture.state,
                documents,
                None,
                &snapshot(),
                &coordinates("3234abcd"),
                None
            ),
            Err(ClaimError::InvalidInput)
        );
    }

    #[test]
    fn forged_terminal_state_and_unsafe_components_fail_closed() {
        let fixture = Fixture::new();
        fs::write(
            fixture.state.join("harness-loop.json"),
            br#"{"schema":"automonique.harness-loop-state/v1","status":"stopped"}"#,
        )
        .expect("state");
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                None,
                &snapshot(),
                &coordinates("4234abcd"),
                None
            ),
            Err(ClaimError::InvalidExistingState)
        );

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .expect("target");
        let parent = temp.path().join("linked");
        symlink(&target, &parent).expect("symlink");
        assert_eq!(
            publish_claim(
                &parent,
                fixture.documents(),
                None,
                &snapshot(),
                &coordinates("5234abcd"),
                None
            ),
            Err(ClaimError::UnsafeStateRoot)
        );
    }

    #[test]
    fn packet_fault_is_inert_and_retry_uses_new_run() {
        let fixture = Fixture::new();
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                Some("R0-19"),
                &snapshot(),
                &coordinates("6234abcd"),
                Some(ClaimFault::AfterPacketDurable)
            ),
            Err(ClaimError::InjectedFault)
        );
        assert!(!fixture.state.join("harness-loop.json").exists());
        let receipt = publish_claim(
            &fixture.state,
            fixture.documents(),
            Some("R0-19"),
            &snapshot(),
            &coordinates("7234abcd"),
            None,
        )
        .expect("retry");
        assert_eq!(receipt.run_id, "session_20260810T100000Z_7234abcd");
    }

    #[test]
    fn concurrent_claims_publish_exactly_one_pointer() {
        let fixture = Fixture::new();
        let state = Arc::new(fixture.state.clone());
        let barrier = Arc::new(Barrier::new(3));
        let handles = ["8234abcd", "9234abcd"].map(|nonce| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let fixture = Fixture::new();
                barrier.wait();
                publish_claim(
                    &state,
                    fixture.documents(),
                    None,
                    &snapshot(),
                    &coordinates(nonce),
                    None,
                )
            })
        });
        barrier.wait();
        let results = handles.map(|handle| handle.join().expect("thread"));
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| matches!(
                    result,
                    Err(ClaimError::LockBusy | ClaimError::ActiveClaim)
                ))
        );
    }
}
