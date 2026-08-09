// SPDX-License-Identifier: Elastic-2.0

//! Fixed-recipe, budgeted synthetic build execution.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, Uid};
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

const DATABASE_NAME: &str = "build-state.sqlite3";
const WORK_DIRECTORY: &str = "work";
const MAX_CAPTURE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WALL_MS: u64 = 30_000;
const MAX_CPU_SECONDS: u64 = 10;
const MAX_PIDS: u32 = 64;
const MAX_OPEN_FILES: u64 = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS build_actions (
  action_id TEXT PRIMARY KEY,
  recipe TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('prepared', 'running', 'complete')),
  outcome TEXT,
  exit_code INTEGER,
  signal INTEGER,
  wall_ms INTEGER,
  stdout BLOB,
  stderr BLOB,
  CHECK (
    (state IN ('prepared', 'running') AND outcome IS NULL AND wall_ms IS NULL AND stdout IS NULL AND stderr IS NULL)
    OR (state = 'complete' AND outcome IS NOT NULL AND wall_ms IS NOT NULL AND stdout IS NOT NULL AND stderr IS NOT NULL)
  )
) STRICT;
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recipe {
    Success,
    Sleep,
    CpuHog,
    OutputFlood,
    DiskFlood,
    PidBurst,
    Descendant,
    OpenFiles,
}

impl Recipe {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Sleep => "sleep",
            Self::CpuHog => "cpu_hog",
            Self::OutputFlood => "output_flood",
            Self::DiskFlood => "disk_flood",
            Self::PidBurst => "pid_burst",
            Self::Descendant => "descendant",
            Self::OpenFiles => "open_files",
        }
    }

    const fn required_pids(self) -> u32 {
        match self {
            Self::PidBurst => 4,
            Self::Descendant => 2,
            _ => 1,
        }
    }

    const fn maximum_files(self) -> u64 {
        match self {
            Self::OpenFiles => 1_024,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub wall_ms: u64,
    pub term_grace_ms: u64,
    pub cpu_seconds: u64,
    pub output_bytes: u64,
    pub file_bytes: u64,
    pub max_pids: u32,
    pub max_open_files: u64,
}

impl BuildLimits {
    pub fn validate(self) -> Result<Self, BuildError> {
        if !(10..=MAX_WALL_MS).contains(&self.wall_ms)
            || !(1..=1_000).contains(&self.term_grace_ms)
            || !(1..=MAX_CPU_SECONDS).contains(&self.cpu_seconds)
            || !(1..=MAX_CAPTURE_BYTES).contains(&self.output_bytes)
            || !(1..=MAX_FILE_BYTES).contains(&self.file_bytes)
            || !(1..=MAX_PIDS).contains(&self.max_pids)
            || !(8..=MAX_OPEN_FILES).contains(&self.max_open_files)
        {
            return Err(BuildError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildRequest {
    pub action_id: String,
    pub recipe: Recipe,
    pub limits: BuildLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildOutcome {
    Success,
    WallLimit,
    CpuLimit,
    OutputLimit,
    DiskLimit,
    PidLimit,
    FileCountLimit,
    Failed,
}

impl BuildOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::WallLimit => "wall_limit",
            Self::CpuLimit => "cpu_limit",
            Self::OutputLimit => "output_limit",
            Self::DiskLimit => "disk_limit",
            Self::PidLimit => "pid_limit",
            Self::FileCountLimit => "file_count_limit",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, BuildError> {
        match value {
            "success" => Ok(Self::Success),
            "wall_limit" => Ok(Self::WallLimit),
            "cpu_limit" => Ok(Self::CpuLimit),
            "output_limit" => Ok(Self::OutputLimit),
            "disk_limit" => Ok(Self::DiskLimit),
            "pid_limit" => Ok(Self::PidLimit),
            "file_count_limit" => Ok(Self::FileCountLimit),
            "failed" => Ok(Self::Failed),
            _ => Err(BuildError::Corrupt("unknown build outcome")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildReceipt {
    pub action_id: String,
    pub recipe: Recipe,
    pub outcome: BuildOutcome,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub wall_ms: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildMutation {
    Applied(BuildReceipt),
    Replayed(BuildReceipt),
}

impl BuildMutation {
    pub fn receipt(&self) -> &BuildReceipt {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    UnsafePath(&'static str),
    InvalidActionId,
    InvalidLimits,
    IdempotencyConflict,
    InterruptedIntent,
    HostCapabilityMissing,
    CleanupFailed,
    Busy,
    Spawn(io::Error),
    Database(rusqlite::Error),
    Corrupt(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(reason) => write!(formatter, "unsafe build path: {reason}"),
            Self::InvalidActionId => formatter.write_str("invalid build action ID"),
            Self::InvalidLimits => formatter.write_str("build limits are outside the closed range"),
            Self::IdempotencyConflict => formatter.write_str("build action ID was reused"),
            Self::InterruptedIntent => {
                formatter.write_str("build has an unresolved durable intent")
            }
            Self::HostCapabilityMissing => {
                formatter.write_str("required build host capability is unavailable")
            }
            Self::CleanupFailed => formatter.write_str("build process group cleanup failed"),
            Self::Busy => formatter.write_str("build state is busy"),
            Self::Spawn(error) => write!(formatter, "build process error: {error}"),
            Self::Database(error) => write!(formatter, "build database error: {error}"),
            Self::Corrupt(reason) => write!(formatter, "build state is corrupt: {reason}"),
        }
    }
}

impl Error for BuildError {}

pub struct BuildBroker {
    connection: Connection,
    root: PathBuf,
    fixture: PathBuf,
}

impl BuildBroker {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BuildError> {
        let root = secure_root(root.as_ref())?;
        let work = root.join(WORK_DIRECTORY);
        secure_directory(&work, true)?;
        let database = root.join(DATABASE_NAME);
        reject_symlink_if_present(&database)?;
        if database.exists() {
            private_file(&database)?;
        } else {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&database)
                .map_err(BuildError::Spawn)?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(&database, flags).map_err(classify_db)?;
        connection
            .busy_timeout(Duration::from_millis(100))
            .map_err(classify_db)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(classify_db)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(classify_db)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify_db)?;
        tx.execute_batch(SCHEMA).map_err(classify_db)?;
        tx.commit().map_err(classify_db)?;
        private_file(&database)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = append_suffix(&database, suffix);
            if sidecar.exists() {
                private_file(&sidecar)?;
            }
        }
        let fixture = fixture_executable()?;
        Ok(Self {
            connection,
            root,
            fixture,
        })
    }

    pub fn run(&mut self, request: BuildRequest) -> Result<BuildMutation, BuildError> {
        let request = validate_request(request)?;
        let digest = request_digest(&request);
        if let Some(stored) = load_action(&self.connection, &request.action_id)? {
            if stored.matches(&request, &digest) && stored.state == "prepared" {
                self.activate_prepared(&request, &digest)?;
                return self.execute_intent(request, digest);
            }
            return stored.reconcile(&request, &digest);
        }
        self.persist_intent(&request, &digest, "running")?;
        self.execute_intent(request, digest)
    }

    /// Persist intent without executing, for crash-safe two-phase controller orchestration.
    pub fn prepare(&mut self, request: BuildRequest) -> Result<(), BuildError> {
        let request = validate_request(request)?;
        let digest = request_digest(&request);
        if let Some(stored) = load_action(&self.connection, &request.action_id)? {
            if stored.matches(&request, &digest) && stored.state == "prepared" {
                return Ok(());
            }
            return match stored.reconcile(&request, &digest) {
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
        }
        self.persist_intent(&request, &digest, "prepared")
    }

    fn persist_intent(
        &mut self,
        request: &BuildRequest,
        digest: &str,
        state: &str,
    ) -> Result<(), BuildError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify_db)?;
        tx.execute(
            "INSERT INTO build_actions(action_id, recipe, request_digest, state) VALUES (?1, ?2, ?3, ?4)",
            params![request.action_id, request.recipe.as_str(), digest, state],
        )
        .map_err(classify_db)?;
        tx.commit().map_err(classify_db)
    }

    fn activate_prepared(
        &mut self,
        request: &BuildRequest,
        digest: &str,
    ) -> Result<(), BuildError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify_db)?;
        let changed = tx
            .execute(
                "UPDATE build_actions SET state = 'running' WHERE action_id = ?1 AND request_digest = ?2 AND state = 'prepared'",
                params![request.action_id, digest],
            )
            .map_err(classify_db)?;
        if changed != 1 {
            return Err(BuildError::InterruptedIntent);
        }
        tx.commit().map_err(classify_db)
    }

    fn execute_intent(
        &mut self,
        request: BuildRequest,
        digest: String,
    ) -> Result<BuildMutation, BuildError> {
        let work = self.root.join(WORK_DIRECTORY).join(&request.action_id);
        secure_directory(&work, true)?;
        let receipt = if request.recipe.required_pids() > request.limits.max_pids {
            BuildReceipt {
                action_id: request.action_id.clone(),
                recipe: request.recipe,
                outcome: BuildOutcome::PidLimit,
                exit_code: None,
                signal: None,
                wall_ms: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        } else {
            execute_fixture(&self.fixture, &work, &request)?
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify_db)?;
        let changed = tx
            .execute(
                "UPDATE build_actions SET state = 'complete', outcome = ?3, exit_code = ?4, signal = ?5, wall_ms = ?6, stdout = ?7, stderr = ?8 WHERE action_id = ?1 AND request_digest = ?2 AND state = 'running'",
                params![request.action_id, digest, receipt.outcome.as_str(), receipt.exit_code, receipt.signal, i64::try_from(receipt.wall_ms).map_err(|_| BuildError::Corrupt("wall time overflow"))?, receipt.stdout, receipt.stderr],
            )
            .map_err(classify_db)?;
        if changed != 1 {
            return Err(BuildError::Corrupt(
                "durable intent changed during execution",
            ));
        }
        tx.commit().map_err(classify_db)?;
        Ok(BuildMutation::Applied(receipt))
    }
}

fn validate_request(mut request: BuildRequest) -> Result<BuildRequest, BuildError> {
    if request.action_id.is_empty()
        || request.action_id.len() > 128
        || !request.action_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err(BuildError::InvalidActionId);
    }
    request.limits = request.limits.validate()?;
    if request.limits.cpu_seconds / u64::from(request.recipe.required_pids()) == 0
        || request.limits.file_bytes / request.recipe.maximum_files() == 0
    {
        return Err(BuildError::InvalidLimits);
    }
    Ok(request)
}

fn request_digest(request: &BuildRequest) -> String {
    let limits = request.limits;
    let value = format!(
        "v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        request.recipe.as_str(),
        limits.wall_ms,
        limits.term_grace_ms,
        limits.cpu_seconds,
        limits.output_bytes,
        limits.file_bytes,
        limits.max_pids,
        limits.max_open_files
    );
    hex::encode(Sha256::digest(value.as_bytes()))
}

struct StoredAction {
    recipe: String,
    digest: String,
    state: String,
    outcome: Option<String>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    wall_ms: Option<i64>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

impl StoredAction {
    fn matches(&self, request: &BuildRequest, digest: &str) -> bool {
        self.recipe == request.recipe.as_str() && self.digest == digest
    }

    fn reconcile(self, request: &BuildRequest, digest: &str) -> Result<BuildMutation, BuildError> {
        if !self.matches(request, digest) {
            return Err(BuildError::IdempotencyConflict);
        }
        if matches!(self.state.as_str(), "prepared" | "running") {
            return Err(BuildError::InterruptedIntent);
        }
        if self.state != "complete" {
            return Err(BuildError::Corrupt("unknown action state"));
        }
        Ok(BuildMutation::Replayed(BuildReceipt {
            action_id: request.action_id.clone(),
            recipe: request.recipe,
            outcome: BuildOutcome::parse(
                self.outcome
                    .as_deref()
                    .ok_or(BuildError::Corrupt("result has no outcome"))?,
            )?,
            exit_code: self.exit_code,
            signal: self.signal,
            wall_ms: u64::try_from(
                self.wall_ms
                    .ok_or(BuildError::Corrupt("result has no wall time"))?,
            )
            .map_err(|_| BuildError::Corrupt("negative wall time"))?,
            stdout: self
                .stdout
                .ok_or(BuildError::Corrupt("result has no stdout"))?,
            stderr: self
                .stderr
                .ok_or(BuildError::Corrupt("result has no stderr"))?,
        }))
    }
}

fn load_action(
    connection: &Connection,
    action_id: &str,
) -> Result<Option<StoredAction>, BuildError> {
    connection
        .query_row(
            "SELECT recipe, request_digest, state, outcome, exit_code, signal, wall_ms, stdout, stderr FROM build_actions WHERE action_id = ?1",
            [action_id],
            |row| {
                Ok(StoredAction {
                    recipe: row.get(0)?,
                    digest: row.get(1)?,
                    state: row.get(2)?,
                    outcome: row.get(3)?,
                    exit_code: row.get(4)?,
                    signal: row.get(5)?,
                    wall_ms: row.get(6)?,
                    stdout: row.get(7)?,
                    stderr: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(classify_db)
}

fn execute_fixture(
    fixture: &Path,
    work: &Path,
    request: &BuildRequest,
) -> Result<BuildReceipt, BuildError> {
    let limits = request.limits;
    verify_proc_capability()?;
    let per_process_cpu = limits.cpu_seconds / u64::from(request.recipe.required_pids());
    let per_file_bytes = limits.file_bytes / request.recipe.maximum_files();
    if per_process_cpu == 0 || per_file_bytes == 0 {
        return Err(BuildError::InvalidLimits);
    }
    let mut command = Command::new(fixture);
    command
        .arg(request.recipe.as_str())
        .current_dir(work)
        .env_clear()
        .env("AUTOMONIQUE_CPU_SECONDS", per_process_cpu.to_string())
        .env("AUTOMONIQUE_FILE_BYTES", per_file_bytes.to_string())
        .env("AUTOMONIQUE_OPEN_FILES", limits.max_open_files.to_string())
        .env("AUTOMONIQUE_WALL_MS", limits.wall_ms.to_string())
        .env(
            "AUTOMONIQUE_TERM_GRACE_MS",
            limits.term_grace_ms.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().map_err(BuildError::Spawn)?;
    let group = Pid::from_raw(
        i32::try_from(child.id())
            .map_err(|_| BuildError::Spawn(io::Error::other("child PID is outside i32")))?,
    );
    let exceeded = Arc::new(AtomicBool::new(false));
    let captured = Arc::new(AtomicUsize::new(0));
    let maximum = usize::try_from(limits.output_bytes).map_err(|_| BuildError::InvalidLimits)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BuildError::Spawn(io::Error::other("stdout pipe missing")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BuildError::Spawn(io::Error::other("stderr pipe missing")))?;
    let stdout_reader = capture(
        stdout,
        maximum,
        Arc::clone(&captured),
        Arc::clone(&exceeded),
    );
    let stderr_reader = capture(
        stderr,
        maximum,
        Arc::clone(&captured),
        Arc::clone(&exceeded),
    );

    let wall = Duration::from_millis(limits.wall_ms);
    let grace = Duration::from_millis(limits.term_grace_ms);
    let (status, forced) = loop {
        let members = match process_group_members(group) {
            Ok(value) => value,
            Err(error) => {
                terminate(&mut child, group, grace)?;
                return Err(error);
            }
        };
        if members > limits.max_pids {
            break (
                terminate(&mut child, group, grace)?,
                Some(BuildOutcome::PidLimit),
            );
        }
        if exceeded.load(Ordering::Acquire) {
            break (
                terminate(&mut child, group, grace)?,
                Some(BuildOutcome::OutputLimit),
            );
        }
        if started.elapsed() >= wall {
            break (
                terminate(&mut child, group, grace)?,
                Some(BuildOutcome::WallLimit),
            );
        }
        if let Some(status) = child.try_wait().map_err(BuildError::Spawn)? {
            cleanup_group(group)?;
            break (status, None);
        }
        thread::sleep(POLL_INTERVAL);
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| BuildError::Spawn(io::Error::other("stdout reader panicked")))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| BuildError::Spawn(io::Error::other("stderr reader panicked")))??;
    let signal = status.signal();
    let outcome = forced.unwrap_or_else(|| classify_status(request.recipe, status));
    Ok(BuildReceipt {
        action_id: request.action_id.clone(),
        recipe: request.recipe,
        outcome,
        exit_code: status.code(),
        signal,
        wall_ms: u64::try_from(started.elapsed().as_millis())
            .map_err(|_| BuildError::Corrupt("wall time overflow"))?,
        stdout,
        stderr,
    })
}

fn capture(
    mut input: impl Read + Send + 'static,
    maximum: usize,
    captured: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, BuildError>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        let mut chunk = [0_u8; 8_192];
        loop {
            let read = input.read(&mut chunk).map_err(BuildError::Spawn)?;
            if read == 0 {
                return Ok(result);
            }
            let start = captured
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_add(read))
                })
                .unwrap_or(usize::MAX);
            let remaining = maximum.saturating_sub(start);
            result.extend_from_slice(&chunk[..read.min(remaining)]);
            if read > remaining {
                exceeded.store(true, Ordering::Release);
            }
        }
    })
}

fn terminate(
    child: &mut std::process::Child,
    group: Pid,
    grace: Duration,
) -> Result<ExitStatus, BuildError> {
    signal_group(group, Signal::SIGTERM)?;
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(BuildError::Spawn)? {
            cleanup_group(group)?;
            return Ok(status);
        }
        thread::sleep(POLL_INTERVAL);
    }
    signal_group(group, Signal::SIGKILL)?;
    let status = child.wait().map_err(BuildError::Spawn)?;
    verify_group_empty(group)?;
    Ok(status)
}

fn cleanup_group(group: Pid) -> Result<(), BuildError> {
    if process_group_members(group)? == 0 {
        return Ok(());
    }
    signal_group(group, Signal::SIGTERM)?;
    thread::sleep(Duration::from_millis(10));
    if process_group_members(group)? != 0 {
        signal_group(group, Signal::SIGKILL)?;
    }
    verify_group_empty(group)
}

fn signal_group(group: Pid, signal: Signal) -> Result<(), BuildError> {
    match killpg(group, signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(_) => Err(BuildError::CleanupFailed),
    }
}

fn verify_group_empty(group: Pid) -> Result<(), BuildError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if process_group_members(group)? == 0 {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(BuildError::CleanupFailed)
}

fn verify_proc_capability() -> Result<(), BuildError> {
    process_group_from_stat(
        &fs::read_to_string("/proc/self/stat").map_err(|_| BuildError::HostCapabilityMissing)?,
    )
    .map(|_| ())
}

fn process_group_members(group: Pid) -> Result<u32, BuildError> {
    let entries = fs::read_dir("/proc").map_err(|_| BuildError::HostCapabilityMissing)?;
    let mut count = 0_u32;
    for entry in entries {
        let entry = entry.map_err(|_| BuildError::HostCapabilityMissing)?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(BuildError::HostCapabilityMissing),
        };
        if process_group_from_stat(&stat)? == group.as_raw() {
            count = count
                .checked_add(1)
                .ok_or(BuildError::HostCapabilityMissing)?;
        }
    }
    Ok(count)
}

fn process_group_from_stat(stat: &str) -> Result<i32, BuildError> {
    let after_name = stat
        .rfind(") ")
        .and_then(|index| stat.get(index + 2..))
        .ok_or(BuildError::HostCapabilityMissing)?;
    after_name
        .split_ascii_whitespace()
        .nth(2)
        .ok_or(BuildError::HostCapabilityMissing)?
        .parse()
        .map_err(|_| BuildError::HostCapabilityMissing)
}

fn classify_status(recipe: Recipe, status: ExitStatus) -> BuildOutcome {
    match status.signal() {
        Some(value) if value == Signal::SIGXCPU as i32 => BuildOutcome::CpuLimit,
        Some(value) if value == Signal::SIGXFSZ as i32 => BuildOutcome::DiskLimit,
        _ if recipe == Recipe::OpenFiles && status.code() == Some(75) => {
            BuildOutcome::FileCountLimit
        }
        _ if status.success() => BuildOutcome::Success,
        _ => BuildOutcome::Failed,
    }
}

fn fixture_executable() -> Result<PathBuf, BuildError> {
    let current = std::env::current_exe().map_err(BuildError::Spawn)?;
    let directory = current
        .parent()
        .and_then(|parent| {
            if parent.file_name().is_some_and(|name| name == "deps") {
                parent.parent()
            } else {
                Some(parent)
            }
        })
        .ok_or(BuildError::UnsafePath(
            "executable directory is unavailable",
        ))?;
    let mut name = OsString::from("automonique-lab-fixture");
    name.push(std::env::consts::EXE_SUFFIX);
    let fixture = directory.join(name);
    let metadata = fs::symlink_metadata(&fixture)
        .map_err(|_| BuildError::UnsafePath("fixed fixture executable is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BuildError::UnsafePath("fixed fixture executable is unsafe"));
    }
    Ok(fixture)
}

fn secure_root(path: &Path) -> Result<PathBuf, BuildError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(BuildError::UnsafePath(
            "root must be a dedicated absolute directory",
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            _ => return Err(BuildError::UnsafePath("root has a non-normal component")),
        }
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            return Err(BuildError::UnsafePath("root contains a symlink"));
        }
    }
    if path.exists() {
        secure_directory(path, false)?;
    } else {
        let parent = path
            .parent()
            .ok_or(BuildError::UnsafePath("root has no parent"))?;
        secure_directory(parent, false)?;
        secure_directory(path, true)?;
    }
    Ok(path.to_path_buf())
}

fn secure_directory(path: &Path, create: bool) -> Result<(), BuildError> {
    if create && !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(BuildError::Spawn)?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| BuildError::UnsafePath("directory cannot be inspected"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
    {
        return Err(BuildError::UnsafePath("directory owner or type is unsafe"));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(BuildError::UnsafePath("directory is not private"));
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), BuildError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(BuildError::UnsafePath("database is a symlink"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BuildError::UnsafePath("database cannot be inspected")),
    }
}

fn private_file(path: &Path) -> Result<(), BuildError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| BuildError::UnsafePath("private file cannot be inspected"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != Uid::effective().as_raw()
    {
        return Err(BuildError::UnsafePath(
            "private file owner or type is unsafe",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(BuildError::Spawn)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(BuildError::Spawn)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn classify_db(error: rusqlite::Error) -> BuildError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error
        && matches!(
            code.code,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
        )
    {
        return BuildError::Busy;
    }
    BuildError::Database(error)
}
