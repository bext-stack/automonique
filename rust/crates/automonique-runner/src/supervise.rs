// SPDX-License-Identifier: Elastic-2.0

//! Supervised execution: one sandboxed attempt, controllable while it runs.
//!
//! [`crate::backend`] runs one workload to a terminal state but exposes no way
//! to reach a live run; [`crate::control`] answers `inspect`, `subscribe`,
//! `heartbeat` and `cancel` over an authenticated Unix socket but holds no
//! process and terminates nothing. This module is the composition, and nothing
//! more: it owns no policy, no protocol and no kernel mechanism of its own.
//!
//! One [`AttemptSupervisor::run`] call:
//!
//! 1. opens the attempt's **view spool** and records that supervision is live;
//! 2. registers the attempt on the caller's [`ControlServer`] with a
//!    [`CancelSink`] over the run's [`CancellationToken`];
//! 3. prepares the attempt through [`DirectProcessBackend::prepare`], which
//!    creates the run cgroup;
//! 4. runs [`PreparedRun::execute`](crate::backend::PreparedRun::execute) on a
//!    worker thread while serving control requests on the caller's thread;
//! 5. releases the binding, closes the view record, and re-opens the run's
//!    durable spool — which re-verifies its hash chain — for the caller.
//!
//! # The threading model, and the ownership problem it solves
//!
//! A [`Spool`] holds an **exclusive** `flock` on its event file for as long as
//! it exists, and `flock` denies a second lock even to the same process. The
//! backend must own the run's spool for the whole run (it appends `Started` and
//! the terminal event), and [`ControlServer::register`] must own *a* spool to
//! answer `inspect` and `subscribe`. Those two requirements cannot be satisfied
//! by the same spool at the same time, and there is no read-only observer
//! constructor to satisfy them with two. So this module does not try:
//!
//! - **No flock bypass and no second writer.** The run's spool is opened once,
//!   handed to the backend, and not touched again until the backend has dropped
//!   it.
//! - **A live binding is served from a separate view spool.** The view spool is
//!   this supervisor's own bounded record of the *supervision*, in a directory
//!   the caller names and which must not be the run's spool directory. It
//!   carries exactly two [`Authority::Synthetic`] events: `Started` with
//!   [`VIEW_LIVE_PAYLOAD`] before the binding goes live, and `Terminal` with
//!   the payload of the outcome the backend reported. It is therefore
//!   `running` for exactly as long as a workload is under supervision, and
//!   afterwards it names the same terminal class the run reached.
//! - **The authoritative record is served after the run.** `run` returns the
//!   re-opened run spool in [`SupervisedAttempt`]; registering *that* on the
//!   same server makes `inspect` and `subscribe` byte-exact projections of the
//!   durable, hash-chained lifecycle. The server's cancel ledger is not
//!   disturbed by the intervening unregister, so a replayed request reference
//!   still answers `already_delivered`.
//!
//! Only one thread is created per attempt, it is always joined, and it is the
//! one that blocks: `execute` is a blocking poll loop and cannot be
//! interleaved with `serve_once` on one thread without reimplementing the
//! backend's own supervision. The caller's thread keeps the control server,
//! which is what lets the server stay single-threaded and keeps the socket's
//! lifetime tied to the caller's.
//!
//! # What a supervised attempt does **not** establish
//!
//! - **It is still not provider execution.** Nothing here speaks a provider
//!   protocol or understands a prompt; the workload is a program.
//! - **A `cancel` answer is delivery evidence, never exit evidence.**
//!   `delivered` means the request reached this supervisor's sink and the
//!   token was set. That a process tree died is a separate observation, and the
//!   only authority for it is the terminal event the backend recorded.
//! - **Live `subscribe` output is not the run's event log.** During the run it
//!   is the synthetic view record described above; a client that needs the
//!   authoritative chain reads the durable spool, or subscribes after the run.
//! - **Cancel idempotency belongs to the supplied custody.** This module does
//!   not open or choose storage; production composes the daemon's durable
//!   host-wide ledger into the [`ControlServer`].
//! - **A broken control socket does not cancel a run.** If serving fails
//!   mid-run the attempt keeps running to its own terminal state under its
//!   deadline, and the listener failure is reported afterwards. Silently
//!   killing a healthy run because its endpoint broke would be a policy this
//!   module has no standing to choose.

use crate::backend::{BackendError, DirectProcessBackend, ExecutionReport, TERMINAL_FAILED};
use crate::control::{
    CancelDelivery, CancelSink, CancelSinkError, ControlError, ControlServer, Served,
};
use crate::{
    Authority, CancellationToken, ContainmentDomain, ContainmentLimits, EventKind, LaunchPlan,
    Spool, SpoolError,
};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Payload of the view spool's `Started` event, recorded before the attempt's
/// control binding goes live.
///
/// It deliberately carries no pid: at this point no process exists, and the
/// pid the supervisor actually spawned is recorded — authoritatively — by the
/// backend in the run's own spool.
pub const VIEW_LIVE_PAYLOAD: &[u8] = b"supervision live";

/// How long one `serve_once` call waits for a peer before the supervisor
/// re-checks whether the attempt has finished.
///
/// This bounds how late a finished attempt is noticed, not how long a request
/// may take: an accepted connection is served under the control server's own
/// per-connection deadline.
pub const CONTROL_POLL_SLICE: Duration = Duration::from_millis(20);

/// Name given to the worker thread that runs the backend's blocking execution.
pub const WORKER_THREAD_NAME: &str = "automonique-attempt";

/// Why an attempt could not be supervised.
///
/// Every variant is a supervisor-side failure. A workload that ran and failed
/// is an [`ExecutionReport`], never an error.
#[derive(Debug)]
pub enum SuperviseError {
    /// A spool root is not an absolute path. Supervision records durable
    /// evidence, so it never resolves a root against a working directory that
    /// may change between calls.
    RootNotAbsolute,
    /// The view root is the run's spool root. Sharing them would put a second
    /// writer on the run's own event file, or deadlock on its exclusive lock.
    ViewRootConflict,
    /// A durable record could not be opened or appended to.
    Spool(SpoolError),
    /// The attempt could not be bound to, or released from, the control server.
    Control(ControlError),
    /// The attempt could not be prepared, or its supervision failed.
    Backend(BackendError),
    /// The worker thread could not be created, so no workload ran.
    WorkerUnavailable(std::io::Error),
    /// The worker thread panicked. Its containment and spool were disposed of
    /// by the backend's own drop path; the outcome is unknown, so none is
    /// reported.
    WorkerLost,
}

impl fmt::Display for SuperviseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotAbsolute => {
                formatter.write_str("supervision roots must be deliberate absolute paths")
            }
            Self::ViewRootConflict => {
                formatter.write_str("the view root must not be the run's own spool root")
            }
            Self::Spool(error) => write!(formatter, "supervision record failed: {error}"),
            Self::Control(error) => write!(formatter, "supervision binding failed: {error}"),
            Self::Backend(error) => write!(formatter, "supervised execution failed: {error}"),
            Self::WorkerUnavailable(error) => {
                write!(formatter, "supervision worker unavailable: {error}")
            }
            Self::WorkerLost => formatter.write_str("the supervision worker panicked"),
        }
    }
}

impl std::error::Error for SuperviseError {}

impl From<SpoolError> for SuperviseError {
    fn from(value: SpoolError) -> Self {
        Self::Spool(value)
    }
}

impl From<ControlError> for SuperviseError {
    fn from(value: ControlError) -> Self {
        Self::Control(value)
    }
}

impl From<BackendError> for SuperviseError {
    fn from(value: BackendError) -> Self {
        Self::Backend(value)
    }
}

/// What one supervised attempt is known to have done.
pub struct SupervisedAttempt {
    execution: ExecutionReport,
    cancel_deliveries: usize,
    spool: Spool,
}

impl SupervisedAttempt {
    /// The backend's report: outcome, supervised pid, and final spool status.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionReport {
        &self.execution
    }

    /// How many distinct cancellation requests reached this attempt's sink.
    ///
    /// A count above zero means the token was set before the count was
    /// incremented, so it is evidence that cancellation was *delivered*. It is
    /// not evidence that cancellation is what ended the run — the outcome in
    /// [`Self::execution`] is the only authority for that, and a request that
    /// arrives after a workload has already exited changes nothing.
    #[must_use]
    pub const fn cancel_deliveries(&self) -> usize {
        self.cancel_deliveries
    }

    /// The run's durable spool, re-opened after the backend released it.
    ///
    /// Re-opening re-parses and re-verifies the hash chain, so holding this
    /// value means the durable record was intact after the run.
    #[must_use]
    pub const fn spool(&self) -> &Spool {
        &self.spool
    }

    /// Take the run's spool, typically to register it for a records-phase
    /// binding whose `inspect` and `subscribe` answers are authoritative.
    #[must_use]
    pub fn into_spool(self) -> Spool {
        self.spool
    }
}

impl fmt::Debug for SupervisedAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Spool` holds a locked file and is deliberately not `Debug`.
        formatter
            .debug_struct("SupervisedAttempt")
            .field("execution", &self.execution)
            .field("cancel_deliveries", &self.cancel_deliveries)
            .finish_non_exhaustive()
    }
}

/// One attempt's supervisor: backend, identity, and durable record locations.
///
/// A supervisor runs exactly one attempt: [`Self::run`] consumes it, so "run
/// this attempt twice" is unspellable. A second supervisor for an attempt
/// identifier that is already bound is refused by the control server rather
/// than allowed to replace a live binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSupervisor {
    backend: DirectProcessBackend,
    attempt_id: String,
    run_id: String,
    spool_root: PathBuf,
    view_root: PathBuf,
    max_spool_bytes: u64,
}

impl AttemptSupervisor {
    /// Bind a supervisor to one attempt, one run, and two record locations.
    ///
    /// # Errors
    ///
    /// Returns [`SuperviseError::RootNotAbsolute`] for a relative root and
    /// [`SuperviseError::ViewRootConflict`] when the two roots are the same
    /// directory. Identifier grammar is not re-checked here: the control
    /// server's own bounded grammar is the authority, and `run` reports its
    /// refusal unchanged rather than duplicating the rule.
    pub fn new(
        backend: DirectProcessBackend,
        attempt_id: &str,
        run_id: &str,
        spool_root: impl Into<PathBuf>,
        view_root: impl Into<PathBuf>,
        max_spool_bytes: u64,
    ) -> Result<Self, SuperviseError> {
        let spool_root = spool_root.into();
        let view_root = view_root.into();
        if !spool_root.is_absolute() || !view_root.is_absolute() {
            return Err(SuperviseError::RootNotAbsolute);
        }
        if spool_root == view_root {
            return Err(SuperviseError::ViewRootConflict);
        }
        Ok(Self {
            backend,
            attempt_id: attempt_id.to_owned(),
            run_id: run_id.to_owned(),
            spool_root,
            view_root,
            max_spool_bytes,
        })
    }

    /// Attempt identifier this supervisor binds on the control server.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Run identifier shared by the cgroup, both spools, and every event.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Directory holding the run's authoritative spool.
    #[must_use]
    pub fn spool_root(&self) -> &Path {
        &self.spool_root
    }

    /// Directory holding this supervisor's view record.
    #[must_use]
    pub fn view_root(&self) -> &Path {
        &self.view_root
    }

    /// Run one attempt while `control` answers requests about it.
    ///
    /// Blocks until the workload reaches a terminal state, so a caller that
    /// wants to do anything else meanwhile owns that thread itself. Control
    /// requests are served on this thread for the whole run: a peer can
    /// `heartbeat`, `inspect` and `cancel` while the workload is live, and a
    /// `cancel` sets the very token the backend polls, so the kill and the
    /// terminal record come from the backend's own disposal path.
    ///
    /// On every return path, including every error, the control binding has
    /// been released, the view record has been closed with a terminal event,
    /// and the run cgroup has been disposed of by the backend. A supervisor
    /// error never leaves a live binding or a live containment behind.
    ///
    /// # Errors
    ///
    /// Returns [`SuperviseError::Control`] when the attempt cannot be bound —
    /// including [`ControlError::DuplicateAttempt`] for an identifier already
    /// bound — [`SuperviseError::Backend`] when preparation or supervision
    /// fails, and [`SuperviseError::Spool`] when a durable record cannot be
    /// opened or appended to. An execution failure is reported in preference
    /// to a failure that happened while releasing the binding, because it is
    /// the more truthful thing to say about the attempt.
    pub fn run(
        self,
        control: &mut ControlServer,
        domain: &ContainmentDomain,
        limits: ContainmentLimits,
        plan: LaunchPlan,
        deadline: Duration,
    ) -> Result<SupervisedAttempt, SuperviseError> {
        // The view spool is opened before the run's spool, so two roots that
        // alias despite the constructor's check fail closed on the run spool's
        // own exclusive lock instead of producing a second writer.
        let mut view = Spool::open(&self.view_root, &self.run_id, self.max_spool_bytes)?;
        view.append(EventKind::Started, Authority::Synthetic, VIEW_LIVE_PAYLOAD)?;

        let cancellation = CancellationToken::new();
        let deliveries = Arc::new(AtomicUsize::new(0));
        let sink = TokenCancelSink {
            attempt_id: self.attempt_id.clone(),
            cancellation: cancellation.clone(),
            deliveries: Arc::clone(&deliveries),
        };

        // Binding precedes preparation, so a refused binding creates no cgroup.
        let mut bound =
            match BoundAttempt::register(control, self.attempt_id.clone(), view, Box::new(sink)) {
                Ok(bound) => bound,
                Err(error) => {
                    self.close_lost_view();
                    return Err(SuperviseError::Control(error));
                }
            };

        let supervised = self.supervise(&mut bound, domain, limits, plan, &cancellation, deadline);
        // The view record names the same terminal class the backend reported;
        // an attempt whose supervision failed is closed as failed, exactly as
        // the backend closes the run's own spool.
        let payload = supervised.as_ref().map_or(TERMINAL_FAILED, |report| {
            report.outcome().terminal_payload()
        });
        let released = bound.release(payload);

        let execution = supervised?;
        released?;
        let spool = Spool::open(&self.spool_root, &self.run_id, self.max_spool_bytes)?;
        Ok(SupervisedAttempt {
            execution,
            cancel_deliveries: deliveries.load(Ordering::Acquire),
            spool,
        })
    }

    /// Prepare the attempt, run it on a worker thread, and serve control
    /// requests until it finishes.
    fn supervise(
        &self,
        bound: &mut BoundAttempt<'_>,
        domain: &ContainmentDomain,
        limits: ContainmentLimits,
        plan: LaunchPlan,
        cancellation: &CancellationToken,
        deadline: Duration,
    ) -> Result<ExecutionReport, SuperviseError> {
        let spool = Spool::open(&self.spool_root, &self.run_id, self.max_spool_bytes)?;
        let prepared = self
            .backend
            .prepare(domain, &self.run_id, limits, plan, spool)?;

        let worker_cancellation = cancellation.clone();
        // A failed spawn drops `prepared`, whose own drop removes the cgroup it
        // created and leaves the run's spool empty: nothing ran, nothing is
        // recorded.
        let worker = std::thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || prepared.execute(&worker_cancellation, deadline))
            .map_err(SuperviseError::WorkerUnavailable)?;

        let mut listener_failure = None;
        while !worker.is_finished() {
            // A per-peer failure is a `Served` value, not an error; only a
            // listener-level failure ends the loop, and even then the worker is
            // joined rather than abandoned.
            if let Err(error) = bound.serve_once(CONTROL_POLL_SLICE) {
                listener_failure = Some(error);
                break;
            }
        }
        let joined = worker.join().map_err(|_| SuperviseError::WorkerLost)?;
        let execution = joined?;
        if let Some(error) = listener_failure {
            return Err(SuperviseError::Control(error));
        }
        Ok(execution)
    }

    /// Close a view record whose spool was consumed by a refused registration.
    ///
    /// [`ControlServer::register`] takes the spool by value on every path,
    /// including its refusals, so the handle is gone. Re-opening is sound
    /// precisely because no binding holds it, and it leaves no view record
    /// stuck at `running` for an attempt that never started.
    fn close_lost_view(&self) {
        if let Ok(mut view) = Spool::open(&self.view_root, &self.run_id, self.max_spool_bytes) {
            let _ = view.append(EventKind::Terminal, Authority::Synthetic, TERMINAL_FAILED);
        }
    }
}

/// One attempt's live control binding, released on every path.
///
/// The guard exists so that no code path between registration and the end of
/// the run can return, `?`, or panic without unregistering the attempt and
/// closing its view record. [`Self::release`] is the ordinary path and reports
/// what it did; `Drop` is the backstop for an unwinding supervisor.
struct BoundAttempt<'server> {
    server: &'server mut ControlServer,
    attempt_id: String,
    released: bool,
}

impl<'server> BoundAttempt<'server> {
    fn register(
        server: &'server mut ControlServer,
        attempt_id: String,
        view: Spool,
        cancel: Box<dyn CancelSink>,
    ) -> Result<Self, ControlError> {
        server.register(&attempt_id, view, cancel)?;
        Ok(Self {
            server,
            attempt_id,
            released: false,
        })
    }

    fn serve_once(&mut self, timeout: Duration) -> Result<Served, ControlError> {
        self.server.serve_once(timeout)
    }

    /// Release the binding and close the view record with `payload`.
    fn release(mut self, payload: &[u8]) -> Result<(), SuperviseError> {
        // Marked before the work: a release that fails must not be retried by
        // `Drop` against a registry it may have already left.
        self.released = true;
        let mut view = self.server.unregister(&self.attempt_id)?;
        view.append(EventKind::Terminal, Authority::Synthetic, payload)?;
        Ok(())
    }
}

impl Drop for BoundAttempt<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // Reached only when `release` did not run — a panic. Best effort, and
        // deliberately the same shape: the binding goes, and the view record is
        // closed rather than left claiming a live attempt.
        if let Ok(mut view) = self.server.unregister(&self.attempt_id) {
            let _ = view.append(EventKind::Terminal, Authority::Synthetic, TERMINAL_FAILED);
        }
    }
}

/// The composition's cancellation destination: the run's own token.
///
/// Setting the token is the whole delivery. The backend polls it, kills the
/// cgroup tree, drains it, and records the terminal event — so the kill and its
/// classification stay in the module that owns them, and this sink never
/// touches a containment handle or a spool.
struct TokenCancelSink {
    attempt_id: String,
    cancellation: CancellationToken,
    deliveries: Arc<AtomicUsize>,
}

impl CancelSink for TokenCancelSink {
    fn deliver(
        &self,
        attempt_id: &str,
        _request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        // The server only calls the sink its own binding holds, so a mismatch
        // is unreachable; refusing rather than cancelling keeps it that way if
        // that ever stops being true.
        if attempt_id != self.attempt_id {
            return Err(CancelSinkError::Unavailable);
        }
        // Set before counting: an observer that sees a nonzero count has, by
        // release/acquire ordering, also seen the token set.
        self.cancellation.cancel();
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(CancelDelivery::Accepted)
    }
}
