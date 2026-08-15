// SPDX-License-Identifier: Elastic-2.0

//! `/run`, end to end: one task string becomes one contained provider run, and
//! its answer comes back.
//!
//! [`SocketRunLane`] is the production [`RunLane`](crate::telegram_bridge::RunLane)
//! — the seam the Telegram bridge calls when an authorized operator types
//! `/run <task>`. It owns the whole sequence and nothing else:
//!
//! 1. [`crate::compose`] turns the task into a document, a prompt and an answer
//!    path;
//! 2. the prompt is written to this daemon's protected slot directory, because
//!    the document routes its prompt through a slot and carries no bytes;
//! 3. the document is submitted to durable custody over this daemon's own admin
//!    socket, and then started over the execute lane on the same socket;
//! 4. the run's read-model row is watched until it is terminal;
//! 5. on a completion the answer file is read out of the run's workspace, and
//!    on anything else a typed refusal is returned.
//!
//! # Why a socket, when the daemon is right there
//!
//! The execution lane lives on the serve thread and is not shared. This lane
//! runs on the Telegram poller's thread, which is the same discipline
//! [`crate::telegram_bridge::StoreControlSurface`] and [`crate::execute`]'s
//! workers already follow: a thread that borrowed the serve loop's handles would
//! either need a lock around every admin request or would race one.
//!
//! So `/run` is a *client* of this daemon, over the same local socket an
//! operator's CLI uses, under the same peer check. Two consequences worth
//! stating: a `/run` is admitted by exactly the gates a CLI submission is
//! admitted by — intake pause, generation health, custody, the execute lane's
//! own eight — and there is no second path into execution that a reviewer would
//! have to audit separately.
//!
//! The wait in step 4 deliberately does **not** use the socket. It reads the run
//! index directly, on this lane's own connection, so a run that takes minutes
//! does not spend those minutes issuing requests at a single-threaded serve
//! loop.
//!
//! # What this costs, named rather than hidden
//!
//! [`RunLane::run`](crate::telegram_bridge::RunLane::run) is **synchronous**:
//! the poller thread is inside it from the moment the operator's `/run` is
//! dispatched until the run is terminal or [`RUN_DEADLINE`] elapses. For that
//! window this bot answers nothing else — not `/status`, not `/help`. Nothing is
//! lost, because the poll offset was committed before dispatch and Telegram
//! redelivers nothing, but an operator who sends `/status` during a long run
//! waits for the run.
//!
//! That is a real cost and the honest one for this slice: the alternative is a
//! reply keyed to a run identity and delivered from a worker, which needs an
//! outbound path that outlives the dispatch that created it. Until that exists,
//! a `/run` is one command that takes as long as it takes.
//!
//! # What this lane does **not** establish
//!
//! - **It does not run a provider.** It runs the program the composed document
//!   names. Whether a real provider honours `HTTPS_PROXY`, writes its final
//!   message where it was told, and completes a model round trip under this
//!   containment is an owner-run, paid, networked proof.
//! - **It does not retry.** One task is one document is one attempt. A refusal
//!   is reported, never re-attempted under a different shape.
//! - **It holds no run.** After a terminal state the lane keeps nothing: the
//!   durable record is the run's own spool and index row, and the answer is a
//!   file in the run's workspace that outlives this call.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use automonique_protocol::admin::{AdminRequest, AdminResponse, SubmittedRunSpec};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_protocol::execute_api::{ExecuteRequest, ExecuteResponse};
use automonique_protocol::tools::RunId;
use automonique_store::run_index::{RunIndex, RunSpoolState};

use crate::compose::{
    ComposeRefusal, Composition, CompositionInputs, ProviderConfig, compose, read_answer,
};
use crate::telegram_bridge::{RunFailure, RunLane};

/// How long one `/run` waits for its run to reach a terminal state.
///
/// Deliberately above the composed document's own timeout, which the backend
/// enforces by killing the tree: a run that hits its own deadline reaches
/// `timed_out` and is reported as such, and this bound exists only for the case
/// where the row never moves at all — a worker that died between the answer and
/// the advance. Reaching *this* deadline is therefore a statement about the
/// daemon, not about the run, and it is answered as [`RunFailure::Unavailable`].
pub const RUN_DEADLINE: Duration = Duration::from_secs(360);

/// How often the run's read-model row is re-read while waiting.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Read deadline on one admin exchange.
///
/// The two requests this lane issues are both bounded work on the serve thread
/// — a durable insert and the execute lane's gates — so a socket that has gone
/// quiet for this long is a daemon that is not answering rather than one that is
/// thinking.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Prefix of every run identity this lane composes.
pub const RUN_ID_PREFIX: &str = "tgrun";

/// The one thing that stops a `/run` lane from opening.
///
/// One variant, because there is one input this lane cannot answer without: a
/// lane that could not observe a run's read-model row would report every run as
/// unavailable, which is worse than not existing. Everything else a deployment
/// might not have configured is a refusal *per request*, not a lane that
/// refuses to exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunIndexUnavailable;

impl core::fmt::Display for RunIndexUnavailable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the run read model could not be opened")
    }
}

impl std::error::Error for RunIndexUnavailable {}

/// The production `/run` lane.
///
/// Everything it needs is resolved once, at [`SocketRunLane::open`], and never
/// re-read: the provider configuration and whether any brokered destination is
/// configured. That matches [`crate::execute::ExecutionLane::open`]'s own
/// discipline — what a run is admitted against is the policy this daemon
/// started with, not whatever a file said at the instant a message arrived — and
/// it means an owner who edits either file gets the new answer by restarting the
/// daemon, which is the same instant every other policy here takes effect.
pub struct SocketRunLane {
    state_dir: PathBuf,
    admin_socket: PathBuf,
    /// This lane's own read-model connection. Opened here, used only here.
    run_index: RunIndex,
    /// The configured provider, or `None` for a deployment that has not been
    /// configured for `/run` at all.
    provider: Option<ProviderConfig>,
    /// Whether this deployment resolves any brokered destination. A composed
    /// document declares `brokered_named`, so without one it cannot be admitted.
    egress_configured: bool,
    /// What this host offers a document's enforcement negotiation, measured
    /// once, exactly as the execution lane measures it.
    offered: Vec<automonique_protocol::sandbox::HostFeature>,
    /// Distinguishes two runs composed inside one millisecond.
    sequence: u64,
}

impl SocketRunLane {
    /// Open one lane over this daemon's own state directory and admin socket.
    ///
    /// A deployment with no provider configuration, an unreadable one, or no
    /// destination policy opens successfully and refuses every `/run` with
    /// [`RunFailure::NotConfigured`]. That is deliberate: a bot that fails to
    /// start because `/run` is unconfigured would take `/status` and `/runs`
    /// down with it.
    ///
    /// # Errors
    ///
    /// Returns [`RunIndexUnavailable`] when the run index could not be opened.
    pub fn open(
        state_dir: &Path,
        admin_socket: &Path,
        run_index_path: &Path,
    ) -> Result<Self, RunIndexUnavailable> {
        let run_index = RunIndex::open(run_index_path).map_err(|_| RunIndexUnavailable)?;
        // Both policies fail closed: an unreadable file is the same answer as
        // an absent one, which is that `/run` is not configured here.
        let provider = ProviderConfig::load(&state_dir.join(crate::compose::PROVIDER_CONFIG_NAME))
            .unwrap_or_default();
        let egress_configured =
            !crate::egress::load_destinations(&state_dir.join(crate::EGRESS_DESTINATIONS_NAME))
                .unwrap_or_default()
                .is_empty();
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            admin_socket: admin_socket.to_path_buf(),
            run_index,
            provider,
            egress_configured,
            offered: crate::execute::offered_host_features(),
            sequence: 0,
        })
    }

    /// Whether this lane could compose anything at all.
    #[must_use]
    pub const fn configured(&self) -> bool {
        self.provider.is_some() && self.egress_configured
    }

    /// A fresh run identity.
    ///
    /// Wall-clock milliseconds plus a per-lane counter, so two runs composed
    /// inside one millisecond still differ and a run started after a restart
    /// cannot collide with one started before it. The identity names a cgroup, a
    /// directory and a prompt slot, so it carries only the bytes those accept.
    fn next_run_id(&mut self) -> Result<String, RunFailure> {
        let now_ms = crate::unix_millis().map_err(|_| RunFailure::Unavailable)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(format!(
            "{RUN_ID_PREFIX}-{}-{}",
            now_ms.unsigned_abs(),
            self.sequence
        ))
    }

    /// Place the composed prompt in this daemon's protected slot directory.
    ///
    /// "Protected" is exactly what the surrounding state directory protects:
    /// private mode, owned by this user, never echoed. The file is written
    /// `0o600` under a directory this creates `0o700` when it is absent, and it
    /// is removed again once the run is terminal — operator content does not
    /// outlive the run that consumed it.
    fn place_prompt(&self, composition: &Composition) -> Result<PathBuf, RunFailure> {
        let directory = self.state_dir.join(crate::execute::PROMPTS_DIRECTORY);
        match fs::create_dir(&directory) {
            Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| RunFailure::Unavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RunFailure::Unavailable),
        }
        let path = directory.join(composition.prompt_slot());
        fs::write(&path, composition.prompt()).map_err(|_| RunFailure::Unavailable)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RunFailure::Unavailable)?;
        Ok(path)
    }

    /// Submit the composed document to durable custody.
    ///
    /// The idempotency key is the run identity, which this lane just minted and
    /// which no other submission can hold — so a `replay` receipt here would
    /// mean the identity was not fresh, and is treated as this daemon's own
    /// failure rather than as an accepted run.
    fn submit(&self, composition: &Composition) -> Result<u64, RunFailure> {
        let submission =
            SubmittedRunSpec::sealed(composition.document().to_vec(), composition.run_id())
                .map_err(|_| RunFailure::Unavailable)?;
        let request = AdminRequest::submit_run(
            RequestId::new(composition.run_id()).map_err(|_| RunFailure::Unavailable)?,
            submission,
        );
        let payload = request
            .to_message()
            .map_err(|_| RunFailure::Unavailable)?
            .to_canonical_bytes();
        let response = AdminResponse::from_canonical_bytes(&self.exchange(&payload)?)
            .map_err(|_| RunFailure::Unavailable)?;
        match response {
            AdminResponse::RunAccepted {
                submission_id,
                replay: false,
                ..
            } => Ok(submission_id),
            // Every other answer is a refusal of the submission itself: intake
            // paused, a degraded generation, a document custody would not hold.
            // None of them is something this lane can act on, and all of them
            // mean nothing was started.
            _ => Err(RunFailure::Refused),
        }
    }

    /// Start the submitted run through the execute lane.
    fn start(&self, composition: &Composition) -> Result<(), RunFailure> {
        let request = ExecuteRequest::ExecuteRun {
            request_id: RequestId::new(composition.run_id())
                .map_err(|_| RunFailure::Unavailable)?,
            run_id: RunId::new(composition.run_id()).map_err(|_| RunFailure::Unavailable)?,
        };
        let payload = request
            .to_message()
            .map_err(|_| RunFailure::Unavailable)?
            .to_canonical_bytes();
        let response = ExecuteResponse::from_canonical_bytes(&self.exchange(&payload)?)
            .map_err(|_| RunFailure::Unavailable)?;
        match response {
            ExecuteResponse::Accepted { .. } => Ok(()),
            // The execute lane's refusals are typed and every one of them means
            // no attempt exists and nothing was recorded. They are collapsed to
            // one word here for the same reason `SurfaceRefusal` has one
            // variant: a chat reply that distinguished "this host cannot enforce
            // the sandbox" from "the lane is saturated" would be telling an
            // operator something the admin socket answers properly.
            ExecuteResponse::Refused { .. } => Err(RunFailure::Refused),
        }
    }

    /// Watch one run's read-model row until it is terminal.
    ///
    /// The row is this lane's evidence and the only thing it waits on. A row
    /// that never moves is [`RunFailure::Unavailable`] rather than a failure of
    /// the run: the attempt may well have finished, and saying it failed would
    /// be inventing an outcome.
    fn await_terminal(&self, submission_id: u64) -> Result<RunSpoolState, RunFailure> {
        let submission_id = i64::try_from(submission_id).map_err(|_| RunFailure::Unavailable)?;
        let deadline = Instant::now() + RUN_DEADLINE;
        loop {
            let record = self
                .run_index
                .entry(submission_id)
                .map_err(|_| RunFailure::Unavailable)?
                .ok_or(RunFailure::Unavailable)?;
            if record.spool_state.is_terminal() {
                return Ok(record.spool_state);
            }
            if Instant::now() >= deadline {
                return Err(RunFailure::Unavailable);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Issue one bounded request on this daemon's admin socket.
    fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, RunFailure> {
        let mut stream = UnixStream::connect(&self.admin_socket).map_err(unavailable)?;
        stream
            .set_read_timeout(Some(EXCHANGE_TIMEOUT))
            .map_err(unavailable)?;
        stream
            .set_write_timeout(Some(EXCHANGE_TIMEOUT))
            .map_err(unavailable)?;
        let mut frame = Vec::new();
        encode_frame(payload, &mut frame).map_err(unavailable)?;
        stream.write_all(&frame).map_err(unavailable)?;

        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).map_err(unavailable)?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(unavailable)?;
        if length > crate::MAX_ADMIN_PAYLOAD_BYTES {
            return Err(RunFailure::Unavailable);
        }
        let mut response = vec![0_u8; length + 4];
        response[..4].copy_from_slice(&prefix);
        stream.read_exact(&mut response[4..]).map_err(unavailable)?;
        let FrameDecode::Frame { payload, .. } = decode_frame(&response).map_err(unavailable)?
        else {
            return Err(RunFailure::Unavailable);
        };
        Ok(payload.to_vec())
    }
}

/// Every failure on the way to a run is the same word.
///
/// A socket that would not connect, a frame that would not encode, a response
/// that would not decode: none of them says anything about whether a run is
/// live, which is exactly what [`RunFailure::Unavailable`] means.
fn unavailable<E>(_error: E) -> RunFailure {
    RunFailure::Unavailable
}

impl RunLane for SocketRunLane {
    fn run(&mut self, task: &str) -> Result<String, RunFailure> {
        let Some(provider) = self.provider.clone() else {
            return Err(RunFailure::NotConfigured);
        };
        let run_id = self.next_run_id()?;
        let task = match crate::skill_runtime::load_active(&self.state_dir) {
            Ok(Some(skills)) => format!(
                "[approved_skills manifest={}]{}\n[/approved_skills]\n\n[user_task]\n{}\n[/user_task]",
                skills.manifest_digest, skills.instructions, task
            ),
            Ok(None) => task.to_owned(),
            Err(_) => return Err(RunFailure::Unavailable),
        };
        let composition = compose(
            &task,
            &CompositionInputs {
                state_dir: &self.state_dir,
                run_id: &run_id,
                provider: &provider,
                offered_features: &self.offered,
                egress_configured: self.egress_configured,
            },
        )
        .map_err(RunFailure::from_compose)?;

        // The slot exists before the document that names it is submitted, so
        // there is no window in which a started run resolves an absent prompt.
        let slot = self.place_prompt(&composition)?;
        let outcome = self.execute(&composition);
        // The prompt is operator content and the run that consumed it has
        // ended. Removing it is best effort: a slot this lane could not remove
        // is a file in a private directory, not a leak of anything the run did
        // not already carry.
        let _ = fs::remove_file(&slot);
        outcome
    }
}

impl SocketRunLane {
    /// Everything after the prompt is durable: submit, start, wait, read.
    ///
    /// Split out so [`RunLane::run`] has exactly one place that removes the
    /// slot, on every path including a refusal.
    fn execute(&self, composition: &Composition) -> Result<String, RunFailure> {
        let submission_id = self.submit(composition)?;
        self.start(composition)?;
        match self.await_terminal(submission_id)? {
            RunSpoolState::Completed => {
                read_answer(composition.answer_path()).ok_or(RunFailure::NoAnswer)
            }
            RunSpoolState::TimedOut => Err(RunFailure::TimedOut),
            RunSpoolState::Cancelled => Err(RunFailure::Cancelled),
            // `Failed` is the workload's own nonzero exit, a fatal signal, a
            // refused launch, or a supervisor failure — the backend records one
            // word for all four and this lane has no more than that word.
            RunSpoolState::Failed => Err(RunFailure::Failed),
            // Not terminal, so `await_terminal` cannot have returned it.
            RunSpoolState::Ready | RunSpoolState::Running => Err(RunFailure::Unavailable),
        }
    }
}

impl RunFailure {
    /// Map one composition refusal onto the word an operator receives.
    ///
    /// Only the two an operator can act on are distinguished. Everything else —
    /// a provider binary that cannot be hashed, a host that enforces nothing, a
    /// document this build composed and cannot submit — is the deployment's
    /// problem rather than the sender's, and is reported as unavailable rather
    /// than as advice they cannot use.
    #[must_use]
    pub const fn from_compose(refusal: ComposeRefusal) -> Self {
        match refusal {
            ComposeRefusal::NotConfigured => Self::NotConfigured,
            ComposeRefusal::TaskRejected => Self::TaskRejected,
            ComposeRefusal::ProviderUnreadable
            | ComposeRefusal::HostUnenforceable
            | ComposeRefusal::IdentityRejected
            | ComposeRefusal::DocumentRejected => Self::Unavailable,
        }
    }
}
