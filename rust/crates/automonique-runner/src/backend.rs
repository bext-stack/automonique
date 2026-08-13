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
//! # What this backend does **not** establish
//!
//! - **It is not provider execution.** Nothing here speaks a provider protocol,
//!   negotiates a session, or understands a prompt. It runs a program.
//! - **It captures no output.** [`crate::spawn_sandboxed`] hands the workload
//!   the supervisor's stdout and stderr; this module never reads a byte the
//!   workload wrote. Output capture is a separate slice.
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

use crate::containment::{ContainmentDomain, ContainmentError, ContainmentLimits, RunContainment};
use crate::launch::{LaunchError, LaunchPlan, spawn_sandboxed};
use crate::runner::CancellationToken;
use crate::spool::{Authority, EventKind, Spool, SpoolError, Status};
use nix::unistd::Pid;
use std::fmt;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
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
            Self::Failed { .. } | Self::FailedBySignal { .. } | Self::LaunchRefused => {
                TERMINAL_FAILED
            }
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
        let containment = RunContainment::create(domain, run_id, limits)?;
        Ok(PreparedRun {
            helper: self.helper.clone(),
            run_id: run_id.to_owned(),
            plan,
            containment,
            spool,
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
    plan: LaunchPlan,
    containment: RunContainment,
    spool: Spool,
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
            plan,
            containment,
            spool,
            ..
        } = self;
        let mut supervised = SupervisedRun {
            spool: Some(spool),
            containment: Some(containment),
            child: None,
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
        let child = spawn_sandboxed(helper, plan, containment)
            .map_err(|error| (None, BackendError::Launch(error)))?;
        let raw = i32::try_from(child.id()).map_err(|_| (None, BackendError::PidUnrepresentable));
        self.child = Some(child);
        let pid = Pid::from_raw(raw?);

        // The pid is the first fact this supervisor observed, so it is what the
        // Started event carries. It is recorded before the wait begins: a
        // supervisor that dies in the next instant still leaves evidence that a
        // process was created, and the cgroup that names it.
        let started = format!("{STARTED_PAYLOAD_PREFIX}{}", pid.as_raw());
        self.spool
            .as_mut()
            .expect("a supervised run holds its spool")
            .append(
                EventKind::Started,
                Authority::Authoritative,
                started.as_bytes(),
            )
            .map_err(|error| (Some(pid), BackendError::Spool(error)))?;

        let deadline_from = Instant::now();
        loop {
            let child = self.child.as_mut().expect("the child was just adopted");
            match child.try_wait() {
                Ok(Some(status)) => return Ok((Some(pid), outcome_from_status(&status))),
                Ok(None) => {}
                Err(error) => return Err((Some(pid), BackendError::Wait(error))),
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

        let mut spool = self.spool.take().expect("a supervised run holds its spool");
        let recorded = spool.append(EventKind::Terminal, Authority::Authoritative, payload);
        let status = spool.status();
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
        if let Some(spool) = self.spool.as_mut()
            && !spool.is_terminal()
        {
            let _ = spool.append(
                EventKind::Terminal,
                Authority::Authoritative,
                TERMINAL_FAILED,
            );
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
