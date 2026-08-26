// SPDX-License-Identifier: Elastic-2.0

//! Typed direct-process execution backend: one sandboxed workload, supervised
//! to completion, with every lifecycle transition durably recorded.
//!
//! This is the first thing in the crate that actually runs a workload. It
//! composes pieces that each already prove their own boundary — the composed
//! sandboxed launch ([`crate::spawn_sandboxed`]), the kernel containment domain
//! ([`crate::RunContainment`]), and the hash-chained event log
//! ([`crate::Spool`]) — into one supervised attempt:
//!
//! 1. [`DirectProcessBackend::prepare`] validates the plan and the spool,
//!    creates the run's exclusive cgroup, and takes ownership of both;
//! 2. [`PreparedRun::execute`] spawns the entry helper into that cgroup,
//!    records [`EventKind::Started`] carrying the pid it actually observed, and
//!    waits under a cancellation token and a wall-clock deadline;
//! 3. every path out of `execute` — success, cancellation, deadline, refusal,
//!    supervisor error, panic — kills and drains the process tree, appends
//!    exactly one [`EventKind::Terminal`] event, and removes the cgroup.
//!
//! # One attempt, enforced by construction
//!
//! One attempt is one [`Spool`], one [`RunContainment`], and at most one
//! workload process. [`DirectProcessBackend::prepare`] consumes the spool and
//! creates the containment itself; [`PreparedRun::execute`] consumes the
//! prepared run. There is no way to spell "run this attempt twice", and a spool
//! that already carries events is refused rather than continued.
//!
//! # Fail closed, or not at all
//!
//! This backend requires the full composition. Without a delegated cgroup v2
//! domain there is no [`RunContainment`], so `prepare` propagates the typed
//! [`ContainmentError`] and no workload runs. There is deliberately no degraded
//! no-sandbox path: a backend that ran a workload with less would be a
//! different, deliberately named type, in the spirit of
//! [`crate::capability::EnforcementMode`] — a mode is never credited with a
//! guarantee its mechanisms do not deliver.
//!
//! # Normalized progress, when the caller asks for it
//!
//! An attempt may be given a [`ProgressCapture`]. When it is, stdout becomes a
//! pipe rather than the supervisor's own, one reader thread drains it, and the
//! [`ProgressMapper`] the caller supplied turns those bytes into frames that
//! this supervisor appends as [`EventKind::AdapterEvent`]. Three properties are
//! the point:
//!
//! - **The spool stays single-writer.** The reader thread parses; only the
//!   supervision loop appends, and it already holds the spool's exclusive lock.
//! - **This module owns no vocabulary.** `automonique-agents` holds the
//!   provider grammar and depends on *this* crate, so a normalizer implemented
//!   here would be a dependency cycle. [`ProgressMapper`] is the seam: bytes in,
//!   frames out, and the runner's whole contribution is a durable position.
//! - **A run never fails because it streamed too much.** Every progress append
//!   is best-effort. A refused one — an exhausted budget, an oversized frame,
//!   an unencodable body — stops progress and records one warning; it never
//!   becomes the attempt's outcome. See [`PROGRESS_PREVIEW_RESERVE_BYTES`].
//!
//! # What this backend does **not** establish
//!
//! - **It is not provider execution.** Nothing here speaks a provider protocol,
//!   negotiates a session, or understands a prompt. It runs a program.
//! - **Captured output is not interpreted.** With no [`ProgressCapture`] the
//!   workload still writes to the supervisor's own stdout and this module reads
//!   nothing. With one, it reads bytes and hands them straight to the caller's
//!   mapper; it does not parse them, and the answer a run produces still travels
//!   the file the document names rather than this stream.
//! - **It is not attestation.** Nothing here proves to a third party what ran.
//! - **There is no restart, retry, or backoff policy.** An attempt runs once
//!   and reaches one terminal state. Deciding whether to attempt again belongs
//!   to a scheduler that does not exist yet.
//! - **The spool records the terminal *class*, not the exit code.** The four
//!   terminal payloads are byte-exact so that
//!   [`crate::RunState`] recovery from the log stays total; the exit code and
//!   signal live in the returned [`ExecutionOutcome`] only. A durable status
//!   channel that carries them is a later slice.
//! - **It does not distinguish a helper refusal from a workload that exits with
//!   the same code.** See [`ExecutionOutcome::LaunchRefused`].
//!
//! # Threads
//!
//! Everything here is synchronous and blocking. The caller owns threads: to
//! cancel a run, clone the [`CancellationToken`] and flip it from another
//! thread while `execute` blocks.
//!
//! The one thread this module starts is the progress reader, and only when a
//! [`ProgressCapture`] was supplied: exactly one per attempt, joined on every
//! path out of [`PreparedRun::execute`], and bounded by the pipe it reads —
//! after the tree is killed the write end is gone, the read returns zero, and
//! the thread ends. Its queue to the supervisor is bounded too
//! ([`PROGRESS_QUEUE_BATCHES`]), so a provider that outruns the spool is slowed
//! by its own pipe rather than by growing a buffer in this process.

use crate::containment::{ContainmentDomain, ContainmentError, ContainmentLimits, RunContainment};
use crate::launch::{LaunchError, LaunchPlan, StdoutCapture, spawn_sandboxed_with_stdout};
use crate::runner::CancellationToken;
use crate::spool::{Authority, EventKind, Spool, SpoolError, Status};
use crate::tempfs_fs::ExceedanceChannel;
use crate::tempfs_ledger::Exceedance;
use automonique_protocol::event::{
    Authority as FrameAuthority, EventKind as FrameKind, RetryCategory, RetryContext,
};
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
};
use automonique_protocol::tools::RunId;
use nix::unistd::Pid;
use std::fmt;
use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Terminal spool payload for a workload that exited zero.
pub const TERMINAL_COMPLETED: &[u8] = b"completed";
/// Terminal spool payload for every non-success that is not cancellation or a
/// deadline: a nonzero exit, a fatal signal, a launch refusal, or a supervisor
/// error.
pub const TERMINAL_FAILED: &[u8] = b"failed";
/// Terminal spool payload for a run stopped by its [`CancellationToken`].
pub const TERMINAL_CANCELLED: &[u8] = b"cancelled";
/// Terminal spool payload for a run stopped by its deadline.
pub const TERMINAL_TIMED_OUT: &[u8] = b"timed_out";

/// Exact prefix of the [`EventKind::Started`] payload; the remainder is the
/// decimal pid of the process this supervisor spawned.
pub const STARTED_PAYLOAD_PREFIX: &str = "direct-process pid=";

/// How often the supervisor re-checks a running workload, the cancellation
/// token, and the deadline.
///
/// A bounded poll rather than a signal wait: it costs one `waitpid` per
/// interval and needs no signal handler, no `pidfd`, and no thread beyond the
/// caller's own.
pub const SUPERVISION_POLL: Duration = Duration::from_millis(5);

/// Bound on how long disposal waits for the killed tree to leave the cgroup.
///
/// Draining is not instantaneous — a killed process leaves a cgroup only once
/// it is reaped — so this is a deadline, not an expectation.
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// How much of the workload's stdout one read may take.
pub const PROGRESS_READ_CHUNK_BYTES: usize = 8 * 1024;

/// How many mapped batches may wait between the reader and the supervisor.
///
/// The queue is bounded and the reader blocks on a full one, which pushes the
/// backpressure into the pipe and from there onto the provider. An unbounded
/// queue would instead let a provider that writes faster than the spool can
/// absorb grow this process's memory without limit, which is the failure this
/// module least wants to add to a supervisor.
pub const PROGRESS_QUEUE_BATCHES: usize = 64;

/// How many queued batches one supervision poll absorbs.
///
/// The loop that drains progress is the loop that checks the cancellation token
/// and the deadline, so it may not become a drain loop: a run has to stay
/// cancellable while it is talking.
pub const PROGRESS_BATCHES_PER_POLL: usize = 8;

/// Budget below which a preview frame is no longer persisted.
///
/// Progress spends the run's own admitted spool budget, and a preview is the
/// part of it nobody promised: it is a thing that was *shown*. When the
/// remaining budget falls here, previews stop, authoritative frames continue,
/// and exactly one warning is recorded saying so — so a reader of the log can
/// tell a stream that went quiet from a stream that was cut off.
pub const PROGRESS_PREVIEW_RESERVE_BYTES: u64 = 16 * 1024;

/// Budget below which nothing optional is persisted at all.
///
/// The terminal event is not optional, and this is the room kept for it. A run
/// that streamed enough to crowd out its own terminal record would be a run
/// that failed for having been watched, which is the one outcome progress
/// capture must never produce.
pub const PROGRESS_TERMINAL_RESERVE_BYTES: u64 = 2 * 1024;

const _: () = assert!(
    PROGRESS_PREVIEW_RESERVE_BYTES > PROGRESS_TERMINAL_RESERVE_BYTES,
    "previews must stop before the terminal event's room is touched"
);

/// The text of the one warning an exhausted progress budget records.
pub const PROGRESS_BUDGET_WARNING: &str =
    "progress capture stopped: the run's spool budget is spent";

/// One frame a [`ProgressMapper`] produced, before the spool places it.
///
/// It carries no sequence, because it has none yet: a frame's sequence is the
/// position of the event that will hold it, and only the writer holding the
/// spool's lock knows what that will be. See
/// `automonique_protocol::progress_api`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFrame {
    /// How much this frame may be relied upon.
    pub authority: FrameAuthority,
    /// What happened.
    pub kind: FrameKind,
    /// What it says beyond its kind.
    pub body: ProgressBody,
}

/// Turns workload stdout bytes into progress frames.
///
/// The seam that keeps the provider grammar out of this crate. `push` is called
/// with whatever the pipe returned — chunks split anywhere, including mid
/// multi-byte character — and returns whatever that completed; `finish` is
/// called once, after end of file, and returns whatever coalescing held back.
///
/// Neither may block, and neither may panic: both run on the reader thread this
/// module owns, and a panic there would leave an attempt with a live process
/// tree and a supervisor waiting on a thread that will never send again.
pub trait ProgressMapper: Send {
    /// Map the next chunk of stdout. An empty answer is normal.
    fn push(&mut self, chunk: &[u8]) -> Vec<CapturedFrame>;

    /// Flush what coalescing was holding. Called once, at end of file.
    fn finish(&mut self) -> Vec<CapturedFrame>;
}

/// Where an appended frame is republished for a live reader.
///
/// The spool holds an exclusive lock for the whole attempt, so nothing can read
/// it while it is being written; this is how a daemon feeds an in-memory replay
/// buffer without a second writer or a second copy of the truth. It is called
/// on the supervision thread, immediately after the durable append, with the
/// sequence the spool assigned.
///
/// An implementation must not block: it is between two polls of a live process
/// tree. Dropping a frame it cannot take is the correct behaviour — the durable
/// record already has it.
pub trait ProgressPublisher: Send {
    /// Publish one appended frame's canonical bytes at its durable sequence.
    fn publish(&self, sequence: u64, payload: &[u8]);
}

/// One attempt's progress capture: what maps its output, and who sees it.
pub struct ProgressCapture {
    mapper: Box<dyn ProgressMapper>,
    publisher: Option<Box<dyn ProgressPublisher>>,
}

impl fmt::Debug for ProgressCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProgressCapture")
            .field("publishing", &self.publisher.is_some())
            .finish()
    }
}

impl ProgressCapture {
    /// Capture stdout and map it with `mapper`, persisting only.
    #[must_use]
    pub fn new(mapper: Box<dyn ProgressMapper>) -> Self {
        Self {
            mapper,
            publisher: None,
        }
    }

    /// Also republish every appended frame to a live reader.
    #[must_use]
    pub fn publishing_to(mut self, publisher: Box<dyn ProgressPublisher>) -> Self {
        self.publisher = Some(publisher);
        self
    }
}

/// The last spool sequence one attempt has appended, readable while it runs.
///
/// The spool itself is behind an exclusive lock and inside the supervisor, so a
/// caller that needs the attempt's position — to report a state at the sequence
/// the log actually reached rather than at a guessed one — reads it here.
/// Monotonic, and zero until the first event is recorded.
#[derive(Clone, Debug, Default)]
pub struct ObservedSequence(Arc<AtomicU64>);

impl ObservedSequence {
    /// The highest sequence appended so far.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// Advance the observed durable position for a supervisor implemented by
    /// another crate over the same spool contract.
    pub fn observe(&self, sequence: u64) {
        self.0.store(sequence, Ordering::Release);
    }
}

/// How one supervised attempt ended.
///
/// Every variant is a fact this supervisor observed about a process it owned.
/// There is no "unknown" variant: a run that cannot be classified is an error,
/// not an outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    /// The workload exited zero.
    Completed,
    /// The workload exited nonzero with this code.
    Failed {
        /// Exact `wait` status exit code.
        exit_code: i32,
    },
    /// The workload was terminated by this signal and never chose an exit code.
    FailedBySignal {
        /// Exact signal number from the `wait` status.
        signal: i32,
    },
    /// The sandbox refused **before the workload ran**.
    ///
    /// The entry helper exits [`crate::HELPER_REFUSED_EXIT`] when any step of
    /// the composed launch fails — plan frame truncated, cgroup membership
    /// unconfirmed, descriptor closure unverified, a Landlock domain
    /// unenforceable, or `execve` denied by the very policy just installed. It
    /// is emphatically not a workload failure: no workload instruction ran.
    ///
    /// The caveat that comes with it, stated exactly as
    /// [`crate::spawn_sandboxed`]'s own documentation states it: the supervisor
    /// cannot distinguish a helper refusal from a workload that exits with the
    /// same code. [`crate::HELPER_REFUSED_EXIT`] is reserved by convention, not
    /// enforced by the kernel. A later slice adds a status channel; until then
    /// this outcome is evidence the helper ran, not proof the workload did not
    /// start and then choose that code itself.
    LaunchRefused,
    /// The [`CancellationToken`] was set, so the tree was killed.
    Cancelled,
    /// The deadline elapsed, so the tree was killed.
    TimedOut,
    /// The workload crossed its temporary-storage budget. The FUSE filesystem
    /// refused the write or the object at the syscall that asked (`ENOSPC` /
    /// `EDQUOT`), the supervisor read the first refusal from the mount's
    /// exceedance channel, and the tree was killed. The exceedance names the
    /// ceiling that tripped, exactly as the filesystem observed it; the
    /// `statfs` readback that corroborates it is on the reconcile's own
    /// [`crate::Outcome`], which the caller holds beside this report.
    TemporaryStorageExceeded {
        /// The first refusal the filesystem's ledger recorded.
        exceedance: Exceedance,
    },
}

impl ExecutionOutcome {
    /// The byte-exact terminal payload this outcome records in the spool.
    ///
    /// These four spellings are the ones the spool's own state recovery
    /// understands, so an outcome and a replayed [`crate::RunState`] can never
    /// disagree.
    #[must_use]
    pub const fn terminal_payload(self) -> &'static [u8] {
        match self {
            Self::Completed => TERMINAL_COMPLETED,
            Self::Failed { .. }
            | Self::FailedBySignal { .. }
            | Self::LaunchRefused
            | Self::TemporaryStorageExceeded { .. } => TERMINAL_FAILED,
            Self::Cancelled => TERMINAL_CANCELLED,
            Self::TimedOut => TERMINAL_TIMED_OUT,
        }
    }

    /// Whether the workload ran and chose to succeed.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl fmt::Display for ExecutionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed => formatter.write_str("workload exited zero"),
            Self::Failed { exit_code } => {
                write!(formatter, "workload exited with code {exit_code}")
            }
            Self::FailedBySignal { signal } => {
                write!(formatter, "workload was terminated by signal {signal}")
            }
            Self::LaunchRefused => {
                formatter.write_str("the sandbox refused the launch before the workload ran")
            }
            Self::Cancelled => formatter.write_str("the run was cancelled and the tree killed"),
            Self::TimedOut => formatter.write_str("the run exceeded its deadline and was killed"),
            Self::TemporaryStorageExceeded { exceedance } => write!(
                formatter,
                "the run crossed its temporary-storage budget and was killed: {exceedance}"
            ),
        }
    }
}

/// Why a supervised attempt could not be prepared or could not be supervised.
///
/// Every variant is a supervisor-side failure. A workload that ran and failed
/// is an [`ExecutionOutcome`], never an error: the two are deliberately
/// different types so a caller cannot confuse "the thing you asked for said no"
/// with "I could not run the thing you asked for".
#[derive(Debug)]
pub enum BackendError {
    /// The entry-helper path is not absolute. A production supervisor passes a
    /// release-pinned absolute path; this backend performs no `PATH` search and
    /// refuses to guess one.
    HelperRejected,
    /// The spool belongs to a different run than the one being prepared.
    SpoolRunIdMismatch,
    /// The spool already carries events. Runs are never resumed or reused: one
    /// attempt is one spool.
    SpoolNotFresh,
    /// Containment could not be created, applied, drained, or removed.
    Containment(ContainmentError),
    /// The plan was refused, or the entry helper could not be spawned.
    Launch(LaunchError),
    /// A lifecycle event could not be durably recorded.
    Spool(SpoolError),
    /// Waiting on the supervised child failed.
    Wait(std::io::Error),
    /// The spawned child's pid does not fit the kernel's `pid_t`, so the
    /// supervisor cannot name the process it just created.
    PidUnrepresentable,
    /// Stdout was piped for a [`ProgressCapture`] and no reader could take it.
    ///
    /// A failure rather than a quietly disabled feature. The pipe exists by the
    /// time this is decided, and an unread pipe stops the workload as soon as
    /// its kernel buffer fills — so an attempt that could not start its reader
    /// is an attempt that must not run.
    ProgressUnreadable,
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelperRejected => {
                formatter.write_str("entry helper must be a deliberate absolute path")
            }
            Self::SpoolRunIdMismatch => {
                formatter.write_str("the spool records a different run identifier")
            }
            Self::SpoolNotFresh => {
                formatter.write_str("the spool already carries events; runs are never reused")
            }
            Self::Containment(error) => write!(formatter, "backend containment failed: {error}"),
            Self::Launch(error) => write!(formatter, "backend launch failed: {error}"),
            Self::Spool(error) => write!(formatter, "backend record failed: {error}"),
            Self::Wait(error) => write!(formatter, "backend wait failed: {error}"),
            Self::PidUnrepresentable => {
                formatter.write_str("the spawned child's pid is not representable")
            }
            Self::ProgressUnreadable => {
                formatter.write_str("the workload's stdout was piped and no reader could take it")
            }
        }
    }
}

impl std::error::Error for BackendError {}

impl From<ContainmentError> for BackendError {
    fn from(value: ContainmentError) -> Self {
        Self::Containment(value)
    }
}

impl From<LaunchError> for BackendError {
    fn from(value: LaunchError) -> Self {
        Self::Launch(value)
    }
}

impl From<SpoolError> for BackendError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

/// What one finished attempt is known to have done.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    outcome: ExecutionOutcome,
    supervised_pid: Option<Pid>,
    status: Status,
}

impl ExecutionReport {
    /// How the attempt ended.
    #[must_use]
    pub const fn outcome(&self) -> ExecutionOutcome {
        self.outcome
    }

    /// The pid of the process this supervisor spawned, if one was ever created.
    ///
    /// `None` means no process existed: the run was already cancelled when
    /// `execute` was called. The pid names the entry helper, which *becomes*
    /// the workload through `execve`, so it is the workload's pid too — and it
    /// is the pid the [`EventKind::Started`] payload carries.
    #[must_use]
    pub const fn supervised_pid(&self) -> Option<Pid> {
        self.supervised_pid
    }

    /// The spool's status after the terminal event was recorded.
    #[must_use]
    pub const fn status(&self) -> &Status {
        &self.status
    }
}

/// A backend that runs one workload per attempt as a direct child.
///
/// "Direct process" names exactly what it is: the supervised process is this
/// process's own child, waited on with `waitpid`. No daemon, no double fork, no
/// process group games — descendant containment comes from the cgroup, which a
/// process group could never provide.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectProcessBackend {
    helper: PathBuf,
}

impl DirectProcessBackend {
    /// Bind a backend to an exact entry-helper binary.
    ///
    /// The path must be absolute and is not otherwise checked here: whether it
    /// exists and is executable is settled at spawn time by the kernel, and any
    /// check performed now would be a lie by the time it mattered.
    pub fn new(helper: impl Into<PathBuf>) -> Result<Self, BackendError> {
        let helper = helper.into();
        if !helper.is_absolute() {
            return Err(BackendError::HelperRejected);
        }
        Ok(Self { helper })
    }

    /// Exact entry-helper binary this backend spawns.
    #[must_use]
    pub fn helper(&self) -> &Path {
        &self.helper
    }

    /// Create the run's containment and take ownership of its spool.
    ///
    /// Ordering is deliberate: everything that can be refused without touching
    /// the kernel is refused first, so a rejected preparation leaves no cgroup
    /// behind. A refused preparation also drops `spool` without appending
    /// anything — nothing ran, so there is nothing to record, and the durable
    /// file is byte-identical and re-openable.
    pub fn prepare(
        &self,
        domain: &ContainmentDomain,
        run_id: &str,
        limits: ContainmentLimits,
        plan: LaunchPlan,
        spool: Spool,
    ) -> Result<PreparedRun, BackendError> {
        let status = spool.status();
        if status.run_id() != run_id {
            return Err(BackendError::SpoolRunIdMismatch);
        }
        if status.last_sequence() != 0 || spool.is_terminal() {
            return Err(BackendError::SpoolNotFresh);
        }
        // Encoding now means an oversized frame is refused before any kernel
        // state exists; `spawn_sandboxed` encodes again at launch time.
        plan.encode().map_err(LaunchError::Plan)?;
        // A progress frame names its run, so a run identity the frame grammar
        // will refuse is discovered here — before a cgroup exists — rather than
        // silently disabling capture halfway through an attempt.
        let frame_run_id = RunId::new(run_id).map_err(|_| BackendError::SpoolRunIdMismatch)?;
        let containment = RunContainment::create(domain, run_id, limits)?;
        Ok(PreparedRun {
            helper: self.helper.clone(),
            run_id: run_id.to_owned(),
            frame_run_id,
            plan,
            containment,
            spool,
            capture: None,
            observed: ObservedSequence::default(),
            temporary_storage: None,
        })
    }
}

/// One attempt, ready to run exactly once.
///
/// Holding this value means the cgroup exists, the ceilings are applied, and
/// the spool is empty and exclusively locked. [`Self::execute`] consumes it, so
/// a prepared attempt cannot be run twice; dropping it instead kills and
/// removes the containment through [`RunContainment`]'s own `Drop` and leaves
/// the spool empty — an attempt that never started records nothing.
pub struct PreparedRun {
    helper: PathBuf,
    run_id: String,
    frame_run_id: RunId,
    plan: LaunchPlan,
    containment: RunContainment,
    spool: Spool,
    capture: Option<ProgressCapture>,
    observed: ObservedSequence,
    /// The mount's exceedance channel, when this run has a temporary-storage
    /// mount. Polled in the supervision loop so a workload that crosses its
    /// scratch budget is contained the first time the ledger refuses it.
    temporary_storage: Option<Arc<ExceedanceChannel>>,
}

impl fmt::Debug for PreparedRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Spool` holds a locked file and is deliberately not `Debug`; the
        // useful facts are the identity of the attempt.
        formatter
            .debug_struct("PreparedRun")
            .field("run_id", &self.run_id)
            .field("helper", &self.helper)
            .field("program", &self.plan.program())
            .field("containment", &self.containment.path())
            .finish()
    }
}

impl PreparedRun {
    /// Run identifier shared by the cgroup, the spool, and every event.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Exact cgroup directory this attempt's tree will live in.
    #[must_use]
    pub fn containment_path(&self) -> &Path {
        self.containment.path()
    }

    /// Exact workload program that will be executed.
    #[must_use]
    pub fn program(&self) -> &Path {
        self.plan.program()
    }

    /// Read this attempt's stdout and record what `capture` maps it to.
    ///
    /// Without this call stdout is inherited and nothing is read, which is the
    /// behaviour every existing caller keeps.
    #[must_use]
    pub fn with_progress(mut self, capture: ProgressCapture) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Poll `channel` in the supervision loop and contain the run the first
    /// time its temporary-storage ledger refuses a write or an object.
    ///
    /// Without this call the ceiling still holds — the FUSE filesystem refuses
    /// the syscall regardless — but the run continues past its first `ENOSPC`
    /// until it exits or its deadline elapses. With it, the first refusal ends
    /// the run with [`ExecutionOutcome::TemporaryStorageExceeded`].
    #[must_use]
    pub fn with_temporary_storage_channel(mut self, channel: Arc<ExceedanceChannel>) -> Self {
        self.temporary_storage = Some(channel);
        self
    }

    /// A handle on the sequence this attempt's spool has reached.
    ///
    /// Cloned before [`Self::execute`] consumes the attempt, because the point
    /// of it is to be readable *after* a supervision failure has taken the
    /// report away: the spool still holds its terminal event at whatever
    /// position it reached, and a reader that assumed a position instead would
    /// publish a sequence no event has.
    #[must_use]
    pub fn observed_sequence(&self) -> ObservedSequence {
        self.observed.clone()
    }

    /// Run the workload to a terminal state.
    ///
    /// Blocks until the workload exits, `cancellation` is set, or `deadline`
    /// elapses — whichever happens first. `deadline` is a wall-clock budget
    /// measured from the moment the child was spawned.
    ///
    /// On every return path, including every error, the process tree has been
    /// killed and drained, the cgroup has been removed, and the spool holds
    /// exactly one terminal event. An error means the *supervisor* failed; the
    /// spool still says `failed` rather than staying open forever.
    pub fn execute(
        self,
        cancellation: &CancellationToken,
        deadline: Duration,
    ) -> Result<ExecutionReport, BackendError> {
        let Self {
            helper,
            frame_run_id,
            plan,
            containment,
            spool,
            capture,
            observed,
            temporary_storage,
            ..
        } = self;
        let mut supervised = SupervisedRun {
            spool: Some(spool),
            containment: Some(containment),
            child: None,
            reader: None,
            publisher: None,
            progress_stopped: false,
            capture,
            frame_run_id,
            observed,
            temporary_storage,
        };

        // No `?` between here and `finish`: a supervision failure must not be
        // allowed to skip the terminal record. The error is carried, not thrown.
        let (supervised_pid, outcome, failure) =
            match supervised.supervise(&helper, &plan, cancellation, deadline) {
                Ok((pid, outcome)) => (pid, Some(outcome), None),
                Err((pid, error)) => (pid, None, Some(error)),
            };
        let payload = outcome.map_or(TERMINAL_FAILED, ExecutionOutcome::terminal_payload);
        let finished = supervised.finish(payload, DRAIN_DEADLINE);

        // A supervisor failure is the more truthful thing to report, so it wins
        // over any disposal error that followed it.
        if let Some(error) = failure {
            return Err(error);
        }
        let status = finished?;
        Ok(ExecutionReport {
            outcome: outcome.expect("a run without a failure produced an outcome"),
            supervised_pid,
            status,
        })
    }
}

/// The pid of a spawned child, or the supervisor error that ended the attempt.
type Supervision = Result<(Option<Pid>, ExecutionOutcome), (Option<Pid>, BackendError)>;

/// The three things one attempt owns while it runs.
///
/// This exists so that no code path can hold a live process tree without also
/// holding the obligation to record its end. `finish` is the ordinary path and
/// reports what disposal said; `Drop` is the last-resort backstop for a
/// panicking supervisor, not the plan.
struct SupervisedRun {
    spool: Option<Spool>,
    containment: Option<RunContainment>,
    child: Option<Child>,
    /// The live reader, once stdout has been piped to one.
    reader: Option<ProgressReader>,
    /// Where appended frames are republished, for as long as anyone is reading.
    publisher: Option<Box<dyn ProgressPublisher>>,
    /// Set once progress has stopped, for whatever reason, so the warning that
    /// says so is recorded exactly once and nothing is attempted after it.
    progress_stopped: bool,
    /// What will map this attempt's stdout, until the reader takes it.
    capture: Option<ProgressCapture>,
    frame_run_id: RunId,
    observed: ObservedSequence,
    /// The temporary-storage mount's exceedance channel, when the run has a
    /// mount. Polled every supervision interval so the first refusal contains
    /// the run.
    temporary_storage: Option<Arc<ExceedanceChannel>>,
}

/// The reader thread and the queue it fills.
///
/// Held apart from the publisher and the latch so that draining — which takes
/// the reader — does not also take the state the drain needs.
struct ProgressReader {
    batches: Receiver<Vec<CapturedFrame>>,
    handle: JoinHandle<()>,
}

impl SupervisedRun {
    /// Persist one batch of mapped frames, best effort.
    ///
    /// Every refusal here is swallowed. That is the whole guarantee: an
    /// exhausted budget, a body this build cannot encode, an oversized frame or
    /// a spool that will not take another line all stop progress and are
    /// recorded once as a warning, and none of them becomes the attempt's
    /// outcome.
    fn persist_progress(&mut self, frames: Vec<CapturedFrame>) {
        for frame in frames {
            if self.progress_stopped {
                return;
            }
            let Some(spool) = self.spool.as_ref() else {
                return;
            };
            let remaining = spool.remaining_bytes();
            if remaining <= PROGRESS_TERMINAL_RESERVE_BYTES {
                self.stop_progress();
                return;
            }
            // A preview is the part of the stream nobody promised, so it is the
            // part that yields first. An authoritative frame keeps going: it is
            // a thing the provider decided, and the log is where decisions live.
            if matches!(frame.authority, FrameAuthority::Synthetic)
                && remaining <= PROGRESS_PREVIEW_RESERVE_BYTES
            {
                self.stop_progress();
                return;
            }
            if self.append_frame(&frame).is_err() {
                self.stop_progress();
                return;
            }
        }
    }

    /// Encode one frame at the sequence the spool is about to give it, append
    /// it, and republish it.
    ///
    /// The sequence is computed from the spool's own position rather than
    /// counted here, so the number inside the payload and the number the event
    /// is stored at are one fact rather than two that agree.
    fn append_frame(&mut self, frame: &CapturedFrame) -> Result<(), ()> {
        let spool = self.spool.as_mut().ok_or(())?;
        let sequence = spool.status().last_sequence().checked_add(1).ok_or(())?;
        let at_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ())?
                .as_millis(),
        )
        .map_err(|_| ())?;
        let payload = ProgressFrame::new(ProgressFrameParts {
            run_id: self.frame_run_id.clone(),
            sequence,
            at_ms: EpochMillis::from_millis(at_ms),
            authority: frame.authority,
            kind: frame.kind,
            body: frame.body.clone(),
        })
        .and_then(|frame| frame.to_canonical_bytes())
        .map_err(|_| ())?;
        let appended = spool
            .append(
                EventKind::AdapterEvent,
                spool_authority(frame.authority),
                &payload,
            )
            .map_err(|_| ())?;
        self.observed.observe(appended.sequence());
        if let Some(publisher) = self.publisher.as_ref() {
            publisher.publish(appended.sequence(), &payload);
        }
        Ok(())
    }

    /// Latch progress off and record the one warning that explains the silence.
    ///
    /// The warning is appended without consulting the preview reserve — it is
    /// the reason the reserve exists — but still under the terminal reserve, so
    /// the attempt's own last word is never the thing that gets crowded out.
    fn stop_progress(&mut self) {
        if self.progress_stopped {
            return;
        }
        self.progress_stopped = true;
        let Ok(body) = budget_warning_body() else {
            return;
        };
        let frame = CapturedFrame {
            authority: FrameAuthority::Synthetic,
            kind: FrameKind::ProviderWarning,
            body,
        };
        if self
            .spool
            .as_ref()
            .is_some_and(|spool| spool.remaining_bytes() > PROGRESS_TERMINAL_RESERVE_BYTES)
        {
            // The latch is already set, so `append_frame` is called directly:
            // going back through `persist_progress` would find `stopped` and
            // drop the very frame that explains it.
            let _ = self.append_frame(&frame);
        }
    }

    /// Take everything the reader still has, then join it.
    ///
    /// Called after the tree is killed, so the pipe's write end is gone and the
    /// reader reaches end of file rather than waiting on a live process. The
    /// drain blocks until the sender is dropped, which is what makes the
    /// transcript complete rather than merely current.
    /// Take everything the reader still has, then let it go.
    ///
    /// Called after the tree is killed, so the pipe's write end is normally
    /// gone and the reader reaches end of file rather than waiting on a live
    /// process. **Normally**, and that word is why this is bounded: a cgroup
    /// that would not drain is an error path this supervisor already reports,
    /// and on it something may still hold the write end. A drain that waited
    /// for that would hang the supervisor and lose the terminal event, so it
    /// waits `deadline` and then leaves.
    ///
    /// A reader that reached end of file is joined; one that timed out is
    /// deliberately *detached*, because there is no way to interrupt a blocking
    /// read and a leaked thread on an already-failing path is the smaller harm.
    fn drain_progress(&mut self, deadline: Duration) {
        let Some(ProgressReader { batches, handle }) = self.reader.take() else {
            return;
        };
        let until = Instant::now() + deadline;
        let finished = loop {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break false;
            }
            match batches.recv_timeout(remaining) {
                Ok(frames) => self.persist_progress(frames),
                // The sender is the reader's alone, so a disconnect is the
                // reader having ended: the transcript is complete.
                Err(RecvTimeoutError::Disconnected) => break true,
                Err(RecvTimeoutError::Timeout) => break false,
            }
        };
        drop(batches);
        if finished {
            // The reader owns no durable state, so a panicking one is not a
            // reason to fail an attempt that already reached its outcome.
            let _ = handle.join();
        }
    }

    /// Take what the reader has ready, without waiting for more.
    ///
    /// Bounded per poll so the supervision loop keeps checking the cancellation
    /// token and the deadline at its own interval: a run must stay cancellable
    /// while it is talking.
    fn poll_progress(&mut self) {
        for _ in 0..PROGRESS_BATCHES_PER_POLL {
            let Some(frames) = self
                .reader
                .as_ref()
                .and_then(|reader| reader.batches.try_recv().ok())
            else {
                return;
            };
            self.persist_progress(frames);
        }
    }
}

/// Translate a frame's authority into the spool's own two words.
///
/// Two enums with the same two members, kept apart because they are two
/// vocabularies: the spool's is what its durable format spells, and the frame's
/// is the normalized event stream's. This is the one place they meet.
const fn spool_authority(authority: FrameAuthority) -> Authority {
    match authority {
        FrameAuthority::Authoritative => Authority::Authoritative,
        FrameAuthority::Synthetic => Authority::Synthetic,
    }
}

/// The body of the one warning an exhausted progress budget records.
fn budget_warning_body() -> Result<ProgressBody, ()> {
    ProgressBody::new(
        FrameKind::ProviderWarning,
        ProgressBodyParts {
            text: ProgressText::new(PROGRESS_BUDGET_WARNING).ok(),
            step: None,
            // Not retryable, and no wait: the budget is the document's, and
            // nothing this attempt does will get more of it.
            retry: RetryContext::new(RetryCategory::Internal, false, None, 1).ok(),
        },
    )
    .map_err(|_| ())
}

/// The reader thread's whole body: read, map, hand over.
///
/// It parses and never appends, so the spool keeps exactly one writer. A send
/// that fails means the supervisor has stopped listening, which is a reason to
/// stop reading rather than an error to report — the attempt already has its
/// outcome by then.
fn read_progress(
    mut stdout: ChildStdout,
    mut mapper: Box<dyn ProgressMapper>,
    batches: SyncSender<Vec<CapturedFrame>>,
) {
    let mut buffer = [0_u8; PROGRESS_READ_CHUNK_BYTES];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let frames = mapper.push(buffer.get(..read).unwrap_or_default());
                if !frames.is_empty() && batches.send(frames).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            // A read that failed is a pipe this thread cannot use again. The
            // mapper's held bytes are deliberately not flushed: an incomplete
            // transcript is what the refusal-first normalizer refuses.
            Err(_) => return,
        }
    }
    let frames = mapper.finish();
    if !frames.is_empty() {
        let _ = batches.send(frames);
    }
}

impl SupervisedRun {
    /// Spawn, record, and wait. Returns a classification for every path that
    /// reached a decision, and an error only when the supervisor itself failed.
    fn supervise(
        &mut self,
        helper: &Path,
        plan: &LaunchPlan,
        cancellation: &CancellationToken,
        deadline: Duration,
    ) -> Supervision {
        // A run already cancelled never gets a process. Spawning one only to
        // kill it would be a fabricated lifecycle.
        if cancellation.is_cancelled() {
            return Ok((None, ExecutionOutcome::Cancelled));
        }

        let containment = self
            .containment
            .as_ref()
            .expect("a supervised run holds its containment");
        // Piping stdout and reading it are the same decision, and this is where
        // both are made: the capture the caller supplied is what turns the
        // inherited descriptor into a pipe, and the reader below is what keeps
        // that pipe from filling and stopping the workload mid-write.
        let capture = self.capture.take();
        let stdout = if capture.is_some() {
            StdoutCapture::Piped
        } else {
            StdoutCapture::Inherit
        };
        let child = spawn_sandboxed_with_stdout(helper, plan, containment, stdout)
            .map_err(|error| (None, BackendError::Launch(error)))?;
        let raw = i32::try_from(child.id()).map_err(|_| (None, BackendError::PidUnrepresentable));
        self.child = Some(child);
        let pid = Pid::from_raw(raw?);
        self.start_reader(capture)
            .map_err(|error| (Some(pid), error))?;

        // The pid is the first fact this supervisor observed, so it is what the
        // Started event carries. It is recorded before the wait begins: a
        // supervisor that dies in the next instant still leaves evidence that a
        // process was created, and the cgroup that names it.
        let started = format!("{STARTED_PAYLOAD_PREFIX}{}", pid.as_raw());
        let recorded = self
            .spool
            .as_mut()
            .expect("a supervised run holds its spool")
            .append(
                EventKind::Started,
                Authority::Authoritative,
                started.as_bytes(),
            )
            .map_err(|error| (Some(pid), BackendError::Spool(error)))?;
        // Published from the append rather than assumed, so a reader that has
        // to report a position after a supervision failure reports the one the
        // log actually holds.
        self.observed.observe(recorded.sequence());

        let deadline_from = Instant::now();
        loop {
            let child = self.child.as_mut().expect("the child was just adopted");
            match child.try_wait() {
                Ok(Some(status)) => return Ok((Some(pid), outcome_from_status(&status))),
                Ok(None) => {}
                Err(error) => return Err((Some(pid), BackendError::Wait(error))),
            }
            // The loop the supervisor already runs is where progress is
            // absorbed, because it is the one place that holds the spool.
            self.poll_progress();
            // A temporary-storage refusal contains the run the first time the
            // ledger records one. The ceiling has already held — the workload
            // saw its own `ENOSPC`/`EDQUOT` — and this is the policy the ticket
            // names on top of it: the run does not continue past its first
            // budget refusal.
            if let Some(exceedance) = self
                .temporary_storage
                .as_ref()
                .and_then(|channel| channel.first())
            {
                return Ok((
                    Some(pid),
                    ExecutionOutcome::TemporaryStorageExceeded { exceedance },
                ));
            }
            if cancellation.is_cancelled() {
                return Ok((Some(pid), ExecutionOutcome::Cancelled));
            }
            if deadline_from.elapsed() >= deadline {
                return Ok((Some(pid), ExecutionOutcome::TimedOut));
            }
            std::thread::sleep(SUPERVISION_POLL);
        }
    }

    /// Start the one reader thread this attempt may have.
    ///
    /// A capture that cannot get a thread is a supervisor failure rather than a
    /// silently disabled feature: the pipe is already open and unread, and an
    /// unread pipe stops the workload at the first buffer's worth of output.
    fn start_reader(&mut self, capture: Option<ProgressCapture>) -> Result<(), BackendError> {
        let Some(ProgressCapture { mapper, publisher }) = capture else {
            return Ok(());
        };
        let stdout = self
            .child
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or(BackendError::ProgressUnreadable)?;
        let (sender, batches) = sync_channel(PROGRESS_QUEUE_BATCHES);
        let handle = std::thread::Builder::new()
            .name("automonique-progress-reader".to_owned())
            .spawn(move || read_progress(stdout, mapper, sender))
            .map_err(|_| BackendError::ProgressUnreadable)?;
        self.publisher = publisher;
        self.reader = Some(ProgressReader { batches, handle });
        Ok(())
    }

    /// Kill the tree, reap the direct child, and wait for the cgroup to drain.
    ///
    /// Run on every path, not only cancellation: a workload that exited zero
    /// may have left descendants behind, and an attempt ends when the
    /// supervisor says it ends. The kill precedes the reap because the reap is
    /// what lets the kernel drain the cgroup, and the drain is bounded because
    /// an unbounded wait on a dying tree is how supervisors hang.
    fn terminate_tree(&mut self, drain: Duration) -> Result<(), ContainmentError> {
        if let Some(containment) = self.containment.as_ref() {
            containment.kill()?;
        }
        if let Some(child) = self.child.as_mut() {
            // Already-reaped children return their remembered status here.
            let _ = child.wait();
        }
        if let Some(containment) = self.containment.as_ref() {
            containment.kill_and_drain(drain)?;
        }
        Ok(())
    }

    /// Kill, record the terminal event, and dispose of the containment.
    ///
    /// Every step runs even if an earlier one failed, because each is a
    /// separate obligation: the tree must die, the log must close, and the
    /// kernel must be left with no residue. The errors are reported in that
    /// order of seriousness once all three have been attempted.
    fn finish(mut self, payload: &[u8], drain: Duration) -> Result<Status, BackendError> {
        let drained = self.terminate_tree(drain);
        // Only now: the tree is dead, so the pipe's last writer is gone and the
        // reader reaches end of file instead of waiting on a live process. What
        // it still holds is part of this attempt's record and is appended before
        // the terminal event, because nothing may follow that one. Bounded by
        // the same deadline the cgroup drain gets, so a tree that would not die
        // costs this attempt its progress rather than its terminal record.
        self.drain_progress(drain);

        let mut spool = self.spool.take().expect("a supervised run holds its spool");
        let recorded = spool.append(EventKind::Terminal, Authority::Authoritative, payload);
        let status = spool.status();
        self.observed.observe(status.last_sequence());
        // Dropping the spool releases its exclusive lock; the record is already
        // durable, so a reader may re-open and re-verify it immediately.
        drop(spool);

        let containment = self
            .containment
            .take()
            .expect("a supervised run holds its containment");
        let disposed = containment.dispose(drain);

        recorded?;
        drained?;
        disposed?;
        Ok(status)
    }
}

impl Drop for SupervisedRun {
    fn drop(&mut self) {
        // Reached only when `finish` did not run — a panic, or an early return
        // this module does not have. Best effort, in the order that matters:
        // stop the tree, reap so it can drain, then close the log.
        if let Some(containment) = self.containment.as_ref() {
            let _ = containment.kill();
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        // The receiver is dropped so a reader blocked on a full queue is freed
        // and can end; the handle is dropped without joining, because a `Drop`
        // that waits on a thread reading a pipe is a `Drop` that can hang. A
        // backstop closes the log, it does not complete a transcript.
        if let Some(ProgressReader { batches, handle }) = self.reader.take() {
            drop(batches);
            drop(handle);
        }
        if let Some(spool) = self.spool.as_mut()
            && !spool.is_terminal()
        {
            let sequence = spool.status().last_sequence();
            let _ = spool.append(
                EventKind::Terminal,
                Authority::Authoritative,
                TERMINAL_FAILED,
            );
            self.observed.observe(sequence.saturating_add(1));
        }
        // `RunContainment`'s own `Drop` drains and removes the cgroup.
    }
}

/// Classify a reaped `wait` status.
///
/// [`crate::HELPER_REFUSED_EXIT`] is checked before the general nonzero case
/// precisely because the two are indistinguishable at the kernel level: this
/// backend reports the reserved meaning and says so in
/// [`ExecutionOutcome::LaunchRefused`] rather than silently calling a refused
/// launch a workload failure.
fn outcome_from_status(status: &ExitStatus) -> ExecutionOutcome {
    match status.code() {
        Some(crate::HELPER_REFUSED_EXIT) => ExecutionOutcome::LaunchRefused,
        Some(0) => ExecutionOutcome::Completed,
        Some(exit_code) => ExecutionOutcome::Failed { exit_code },
        // No exit code means a signal terminated the process. A reaped child
        // always has one or the other; the fallback records zero rather than
        // inventing an exit code that was never chosen.
        None => ExecutionOutcome::FailedBySignal {
            signal: status.signal().unwrap_or(0),
        },
    }
}
