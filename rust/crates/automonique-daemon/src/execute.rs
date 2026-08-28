// SPDX-License-Identifier: Elastic-2.0

//! The daemon's execution lane: one custodied RunSpec, run once, contained.
//!
//! Every other lane on this socket ends at a durable row. This one starts a
//! process. That difference is the whole reason this module is written the way
//! it is, and the three properties below are what it is written *for*.
//!
//! # 1. Fail closed, or not at all
//!
//! There is no degraded path and no partial execution. Before a single byte of
//! kernel state exists, [`ExecutionLane::start`] passes every one of these
//! gates, in order, and answers a typed [`ExecuteRefusal`] at the first one
//! that says no:
//!
//! 0. the generation is healthy, intake is open, the run is in custody, and its
//!    read-model row is still `ready` — the daemon's own gates, applied by
//!    `Daemon::start_run` before this lane is reached;
//! 1. the host can enforce the composed sandbox — the same probe
//!    `Daemon::measure_execution_state` reports in the status, over the same
//!    [`ENFORCED_PROPERTIES`];
//! 2. the launch entry helper was located as a deliberate absolute path;
//! 3. a delegated cgroup v2 domain exists and can distribute the `pids` and
//!    `memory` controllers, so the document's ceilings are real ceilings;
//! 4. no attempt for the run is already live, and the lane is below its ceiling;
//! 5. the document's prompt resolves, and the program it pins hashes to the
//!    digest it pins;
//! 6. [`admit`] maps the whole document onto one launch, refusing every field
//!    this build cannot honour exactly;
//! 7. a document that asked for brokered egress gets its own broker, bound to a
//!    loopback ephemeral port over its own allowlist, and the plan is completed
//!    with that port — a broker that cannot bind refuses the request rather
//!    than running the workload without one;
//! 8. the attempt registers on the cancellation host, its spool opens, and its
//!    run cgroup is created with the document's ceilings applied.
//!
//! A refusal at any gate has created no cgroup, no spool, no thread and no
//! directory, and has written nothing — the directory tree is created *after*
//! admission precisely so a refused document leaves nothing that looks like a
//! run, and a refusal at gate 8 drops the half-built attempt, whose own guards
//! release the registration, stop the broker and remove the cgroup.
//!
//! Gate 8 is on this list rather than on the worker for a reason worth stating:
//! a caller answered `accepted` has been told an attempt started, so everything
//! that could still say "actually, no" must happen before the answer is
//! written. A worker that discovered a duplicate registration afterwards would
//! leave that caller holding a receipt for a run that never began.
//!
//! # 2. The serve loop keeps serving
//!
//! [`crate::Daemon::serve`] is single-threaded and answers every lane on it, so
//! nothing here may block it for the length of a run. The split is:
//!
//! - **On the serve thread:** the gates above, which are reads and one pure
//!   mapping. They are bounded, and the two that touch bytes are bounded
//!   explicitly — the prompt at [`MAX_PROMPT_BYTES`] and the pinned program at
//!   [`MAX_PROVIDER_BINARY_BYTES`]. This is a deliberate trade, and the cost is
//!   stated rather than hidden: hashing a maximal program stalls the accept
//!   loop for as long as reading that many bytes takes. It buys a *synchronous
//!   typed refusal* for a program whose digest does not match its pin, which is
//!   a release-trust answer a caller can act on, instead of an acknowledgement
//!   followed by a failure they have to go and read.
//! - **On a worker thread:** the containment, the process, the wait, the
//!   terminal record and the read-model advance. One thread per attempt,
//!   bounded by [`MAX_LIVE_ATTEMPTS`], every one of them joined before the
//!   daemon releases its generation.
//!
//! # 3. Cancellation reaches the process
//!
//! The attempt is registered on the daemon's one [`DaemonAttemptHost`] before
//! it is prepared, with a sink over the very [`CancellationToken`] the backend
//! polls. So [`DaemonAttemptHost::cancel`] — the host-wide dispatcher over the
//! durable cancel ledger — sets that token, the backend's own disposal path
//! kills the cgroup tree and records the terminal event, and the answer stays
//! what that dispatcher documents: delivery evidence, never exit evidence.
//! The [`RegistrationHandle`] owns the registration, so every path out of the
//! worker — including a panic — releases it.
//!
//! This is the first thing in this build to put an attempt in that registry;
//! [`crate::attempt_host`] says plainly that until now "a live daemon's
//! registry is empty by construction".
//!
//! ## Why not [`AttemptSupervisor`](automonique_runner::supervise::AttemptSupervisor)
//!
//! That type composes the same backend with a live control socket, and it is
//! the right composition for a caller that wants one. It cannot be the
//! composition *here*, for a reason that is structural rather than a
//! preference: it creates the run's [`CancellationToken`] internally and
//! registers its own sink over it on a [`ControlServer`](automonique_runner::control::ControlServer),
//! and it exposes neither. A daemon holding it therefore has nothing to
//! register on its own dispatcher, so the only route from
//! [`DaemonAttemptHost::cancel`] to the process would be a sink that opens the
//! attempt's control socket and speaks to it — a network round trip inside the
//! dispatcher's serialized section, which
//! [`automonique_runner::dispatch`]'s sink contract forbids in as many words.
//! Driving [`DirectProcessBackend`] directly is what lets the daemon own the
//! token, and owning the token is what makes host-wide cancellation true.
//!
//! What that costs, named rather than implied: there is no per-attempt control
//! socket, so no peer can `inspect` or `subscribe` to a live attempt, and no
//! synthetic view spool is written. The authoritative record — `Started` with
//! the observed pid, and exactly one terminal event — is the run's own durable
//! spool, written by the backend, and it is unaffected.
//!
//! # What this lane does **not** establish
//!
//! - **It is not provider execution.** It runs the program the document names.
//!   Nothing here speaks a provider protocol. A document asking for
//!   `brokered_named` egress gets exactly that — one loopback `CONNECT` broker
//!   of its own, an allowlist, a TCP socket and a `connect` to that broker's
//!   port — and a document asking for anything else is refused by [`admit`]
//!   rather than approximated. Where those destinations come from, and why the
//!   deployment rather than the document supplies them, is [`crate::egress`].
//! - **It is not a scheduler.** One request starts one attempt. There is no
//!   queue, no retry, no backoff and no fairness; [`ExecuteRefusal::LaneSaturated`]
//!   is a refusal, not a wait.
//! - **It is not a user-workspace registry.** See
//!   [`DAEMON_ATTEMPT_WORKSPACE_REGISTRY`]: this daemon resolves one attempt
//!   workspace — a private empty directory it creates for the run — and refuses
//!   every document that names a registry it cannot resolve.
//! - **It is not release trust.** The program's digest is checked against the
//!   document's pin, which establishes that the bytes on disk are the bytes the
//!   document named. Who signed those bytes, and whether that party may be
//!   trusted, is [`automonique_protocol::release_trust_root`]'s question and
//!   nothing here answers it.
//! - **It is not attestation.** It publishes a host feature per property it
//!   enforces, identified by a digest over *how* it enforces it, and nothing
//!   signs that statement. See [`offered_host_features`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use automonique_egress_broker::{
    BrokerConfig, EgressBroker, RefusedDestinationCursor, RefusedDestinationObserver,
    RefusedDestinationWindow,
};
use automonique_protocol::digest::{ALGORITHM, Sha256};
use automonique_protocol::event::{Authority as FrameAuthority, RetryCategory, RetryContext};
use automonique_protocol::execute_api::ExecuteRefusal;
use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::progress_api::{
    ProgressBody, ProgressBodyParts, ProgressFrame, ProgressFrameParts, ProgressText,
};
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    Digest, ExecutionBackendId, HostFeature, ImplementationDigest,
};
use automonique_protocol::tools::RunId as FrameRunId;
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmissionRefusal, AdmittedLaunch, BrokeredDestination,
    PromptSource, ProviderIdentityPolicy, ResolvedPrompt, TemporaryStorageEnforcement,
    UnenforcedBudget, admit,
};
use automonique_runner::backend::{
    CapturedFrame, DirectProcessBackend, ObservedSequence, PROGRESS_BUDGET_WARNING,
    PROGRESS_PREVIEW_RESERVE_BYTES, PROGRESS_TERMINAL_RESERVE_BYTES, PreparedRun, ProgressCapture,
    ProgressPublisher, STARTED_PAYLOAD_PREFIX, TERMINAL_CANCELLED, TERMINAL_COMPLETED,
    TERMINAL_FAILED, TERMINAL_TIMED_OUT, temporary_storage_exceeded_frame,
};
use automonique_runner::capability::{BoundaryProperty, HostCapabilities};
use automonique_runner::control::{CancelDelivery, CancelSink, CancelSinkError};
use automonique_runner::dispatch::RegistrationHandle;
use automonique_runner::tempfs::{
    CHECKPOINT_LEAF, DEFAULT_READBACK_DEADLINE, FusePrerequisites, MOUNT_LEAF, reap_stale_mounts,
};
use automonique_runner::{
    AttemptWorkspaceRegistryId, Authority as SpoolAuthority, CancellationToken, ContainmentDomain,
    Controller, EventKind as SpoolEventKind, Exceedance, LaunchPlan, NamespacedOutcome,
    PromptDeliveryPlan, RunContainment, RunSpec, Spool, StatfsReadback, TemporaryStorageBudget,
};
use automonique_store::approval_requests::{
    ApprovalContext, ApprovalProposal, ApprovalRequests, ApprovalState, MAX_APPROVAL_REQUEST_PAGE,
    REQUEST_KEY_HEX_BYTES, REQUEST_KEY_PREFIX,
};
use automonique_store::run_index::{RunIndex, RunSpoolState, StateAdvance};
use nix::libc;
use sha2::Digest as _;

use crate::attempt_host::DaemonAttemptHost;
use crate::jcode_session_host::{
    HOST_CLOSED_REASON, JcodeHostError, JcodeInputRequest, JcodeSessionHost, JcodeTurnOutcome,
};
use crate::progress::{JcodeProgressMapper, ProviderProgressMapper};
use crate::progress_hub::ProgressHub;

/// Environment variable naming the launch entry helper binary.
///
/// Read once, at [`ExecutionLane::open`]. A value that is not an absolute path
/// is discarded rather than resolved against a working directory that says
/// nothing about which binary was meant.
pub const LAUNCH_HELPER_ENV: &str = "AUTOMONIQUE_LAUNCH_HELPER";

/// Filename of the launch entry helper.
///
/// The helper is the process that installs the sandbox and then *becomes* the
/// workload, so which binary it is matters as much as the workload does. It is
/// therefore located two ways and no others, in order:
///
/// 1. [`LAUNCH_HELPER_ENV`], as an absolute path;
/// 2. a sibling of this process's own executable, or a sibling of that
///    executable's directory.
///
/// The second is a *release-layout convention*, not a search: the helper ships
/// beside the daemon that spawns it, and the second candidate exists because
/// the same layout puts a test binary one directory deeper. There is
/// deliberately no `PATH` lookup and no working-directory resolution — either
/// would let something outside the release decide which binary installs this
/// daemon's enforcement. When neither candidate is an existing regular file the
/// lane has no helper, and every request answers
/// [`ExecuteRefusal::LaunchHelperUnavailable`].
pub const LAUNCH_HELPER_NAME: &str = "automonique-launch-enter";

/// The one attempt-workspace registry identity this daemon can resolve.
///
/// A [`RunSpec`]'s working directory is an opaque `cwd_token` that an
/// attempt-workspace registry is supposed to resolve against a registered
/// attempt workspace. This build has no general registry, so it has exactly one
/// honest option and takes it:
/// it declares an identity of its own, resolves it to a **private empty
/// directory created for the run**, and refuses every document naming any other
/// registry with [`ExecuteRefusal::AdmissionRefused`].
///
/// Stated plainly, because it is the difference between a check and a
/// ceremony: a document that names this identity gets a fresh empty attempt
/// workspace, not the user workspace it was written against. What the check
/// buys is that a document written against a *real* registry cannot be silently
/// run against the wrong tree — it is refused instead.
pub const DAEMON_ATTEMPT_WORKSPACE_REGISTRY: &str = "automonique-daemon-scratch";

/// The one execution backend this daemon is.
///
/// [`admit`] compares it against the document's own `backend_id`, so a
/// document written for another backend is refused here rather than run by the
/// wrong one.
pub const DAEMON_BACKEND_ID: &str = "local-direct";
const MAX_RECOVERED_TEMPFS_CHECKPOINTS: usize = 4096;

/// The boundary properties this build's launch path enforces, and the exact
/// set a host is measured against.
///
/// One array, read by the daemon's startup measurement *and* by
/// [`offered_host_features`], so what the status reports and what a document
/// negotiates against cannot drift apart.
pub const ENFORCED_PROPERTIES: [BoundaryProperty; 5] = [
    BoundaryProperty::DescendantContainment,
    BoundaryProperty::FilesystemRestriction,
    BoundaryProperty::TcpDenial,
    BoundaryProperty::SyscallRestriction,
    BoundaryProperty::UidSeparation,
];

/// Domain separator for the implementation digest this daemon publishes.
pub const HOST_FEATURE_DOMAIN: &str = "automonique.host-feature.v1";

/// Host enforcement features this daemon offers to a document's negotiation.
///
/// A sandbox spec must require at least one feature — `RequiredFeatures`
/// refuses an empty set, because "a spec requiring no enforcement would admit
/// on a host that enforces nothing" — so a host that offers none can run
/// nothing. This daemon therefore offers one feature per property in
/// [`ENFORCED_PROPERTIES`] that the capability probe says this host really
/// enforces, named by that property's own stable spelling.
///
/// # What the implementation digest is, and what it is not
///
/// It is the SHA-256 of a domain-separated statement of *how* this host
/// enforces that property:
///
/// ```text
/// automonique.host-feature.v1
/// mode=<enforcement mode>
/// property=<boundary property>
/// mechanism=<kernel mechanism>
/// ```
///
/// So the digest is a **content identity of the enforcement composition**: it
/// changes when the mode changes, when the mechanism changes, or when this
/// build's model of either changes, and a document that pinned the composition
/// it was reviewed against is refused on a host that would enforce it
/// differently. That is a real check, and it is the check the field is for.
///
/// It is **not an attestation**. Nothing signs this statement, nothing proves
/// to a third party that the mechanisms named are the mechanisms installed, and
/// a host that lies about its own probe produces a digest that matches its lie.
/// Anyone reading a matching digest learns that this daemon and the document
/// agree about the composition — not that the composition is what either says.
/// A signed measurement is [`automonique_protocol::release_trust_root`]'s
/// business and this lane does not pretend to it.
#[must_use]
pub fn offered_host_features() -> Vec<HostFeature> {
    let helper = locate_launch_helper();
    let Ok(selection) = HostCapabilities::probe_with_launch_helper(helper.as_deref())
        .select_mode(&ENFORCED_PROPERTIES)
    else {
        // A host with no enforceable mode offers nothing, which is the same
        // answer `sandbox_enforceable` gives and refuses on first.
        return Vec::new();
    };
    let mode = selection.mode();
    ENFORCED_PROPERTIES
        .into_iter()
        .filter_map(|property| {
            let mechanism = mode.mechanism_for(property)?;
            let statement = format!(
                "{HOST_FEATURE_DOMAIN}\nmode={}\nproperty={}\nmechanism={}\n",
                mode.as_str(),
                property.as_str(),
                mechanism.as_str()
            );
            let digest = ImplementationDigest::parse(&format!(
                "{ALGORITHM}:{}",
                Sha256::digest(statement.as_bytes()).to_hex()
            ))
            .ok()?;
            HostFeature::new(property.as_str(), digest).ok()
        })
        .collect()
}

/// Attempts this daemon runs at once.
///
/// One thread per attempt, so this is a thread ceiling as much as a work
/// ceiling. It is far below the attempt host's own registration bound, because
/// exhausting that bound would make cancellation registration fail for an
/// attempt that is already running.
pub const MAX_LIVE_ATTEMPTS: usize = 8;

/// Largest prompt this daemon will read out of its protected slot directory.
///
/// Matches the launch surface's own prompt ceiling, so a slot this reads is a
/// slot a plan can carry.
pub const MAX_PROMPT_BYTES: usize = automonique_runner::MAX_LAUNCH_PROMPT_BYTES;

/// Largest pinned program this daemon will hash on the serve thread.
///
/// The bound exists because the hash happens on the accept loop; see the
/// module's threading note for what that trade buys and costs. A larger program
/// is not run under a weaker check — it is refused with
/// [`ExecuteRefusal::ProviderBinaryUnverified`].
pub const MAX_PROVIDER_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Whether one observed byte count fits within a finite read ceiling.
///
/// Kept as one predicate so the metadata check and the post-read growth check
/// agree exactly at the boundary.
pub(crate) const fn is_within_byte_limit(bytes: u64, limit: u64) -> bool {
    bytes <= limit
}

/// Hash provider-file bytes through the optimized large-input implementation.
///
/// Protocol messages retain the dependency-free implementation in
/// `automonique-protocol`; provider executables can be hundreds of MiB and are
/// verified twice on a live request, so using that small-message transform here
/// would turn a security check into tens of seconds of control-loop latency.
pub(crate) fn provider_binary_digest(bytes: &[u8]) -> String {
    format!("{ALGORITHM}:{:x}", sha2::Sha256::digest(bytes))
}

/// The two digests an approval binds that are not in the document itself.
///
/// A RunSpec carries the *path* of its program and the *name* of its prompt
/// slot; the bytes behind both are host state that can change after an operator
/// approves and before the launch happens. Hashing them here is what lets the
/// approval bind them.
///
/// Both are computed exactly the way the admission path computes them — the
/// same reads, the same ceilings, the same `read_bounded` — so an approval
/// binds the values the launch will later be checked against rather than a
/// second opinion about them. The prefix `provider_binary_digest` carries is
/// stripped, because these are stored as bare hexadecimal beside the run's
/// canonical spec digest and a mixed alphabet in one row would be a trap for
/// the comparison.
///
/// `None` means one of them could not be observed at all: an unreadable
/// program, an unresolvable prompt, or a prompt this build cannot address. A
/// caller must treat that as a refusal, never as an empty binding.
pub(crate) fn approval_context_digests(
    state_dir: &Path,
    spec: &RunSpec,
) -> Option<(String, String)> {
    let program = read_bounded(spec.executable(), MAX_PROVIDER_BINARY_BYTES)?;
    let program_sha256 = provider_binary_digest(&program)
        .strip_prefix(&format!("{ALGORITHM}:"))?
        .to_owned();

    let slot = match spec.prompt_delivery() {
        PromptDeliveryPlan::ProtectedReference(reference) => reference.as_str().to_owned(),
        PromptDeliveryPlan::Stdin | PromptDeliveryPlan::BackendSession(_) => return None,
    };
    if !is_safe_segment(&slot) {
        return None;
    }
    let limit = u64::try_from(MAX_PROMPT_BYTES).ok()?;
    let prompt = read_bounded(&state_dir.join(PROMPTS_DIRECTORY).join(&slot), limit)?;
    if prompt.is_empty() {
        return None;
    }
    Some((program_sha256, Sha256::digest(&prompt).to_hex()))
}

/// Directory under the state root holding one subtree per executed run.
pub const RUNS_DIRECTORY: &str = "runs";

/// Directory under the state root holding protected prompt slots.
///
/// One file per slot, named by the document's own
/// [`ProtectedPromptReference`](automonique_runner::ProtectedPromptReference).
/// "Protected" here means exactly what the surrounding state directory
/// protects: private mode, owned by this user, and never echoed into a refusal,
/// a log or an event. It is not encryption, not a broker, and not a secret
/// store, and this lane makes no claim that it is.
pub const PROMPTS_DIRECTORY: &str = "prompts";

/// One run's private subtree beneath [`RUNS_DIRECTORY`].
///
/// The workspace is a *sibling* of the spool rather than its parent, and that
/// is load-bearing: the admitted plan grants the workload read-write access to
/// the workspace directory, so a spool inside it would be a durable lifecycle
/// record the workload could rewrite.
const ATTEMPT_WORKSPACE_LEAF: &str = "workspace";
const PROVIDER_APPROVAL_KEY_DOMAIN: &[u8] = b"automonique.provider-approval/v1/key\0";
const PROVIDER_APPROVAL_PROPOSER: &str = "automonique.jcode";
/// The run's authoritative spool directory, outside every grant.
const SPOOL_LEAF: &str = "spool";

#[must_use]
pub fn run_spool_root(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join(RUNS_DIRECTORY).join(run_id).join(SPOOL_LEAF)
}

/// Where this daemon resolves one run's `cwd_token` to, as a pure function of
/// the state directory and the run identity.
///
/// # Why this is public, and why it is a function rather than a convention
///
/// [`DAEMON_ATTEMPT_WORKSPACE_REGISTRY`] says this daemon resolves exactly one
/// attempt workspace: a private empty directory it creates for the run. Everything
/// downstream of that — a document whose argv has to name an absolute path
/// inside the workspace, and a reader that has to find a file the workload left
/// there — needs the *same* answer this lane will compute, and needs it before
/// the run exists.
///
/// Exporting the resolution as one function is what keeps those callers from
/// re-deriving it. A composer that rebuilt the path from constants would be a
/// second owner of this directory tree, and the two would drift silently: the
/// document would name a path the lane never granted, the workload would be
/// denied by Landlock, and the failure would look like a provider fault.
///
/// The answer is a path, not a promise. The directory is created at admission
/// time and only for a document that was admitted; a run that was refused, or
/// that never executed, has nothing here.
#[must_use]
pub fn run_attempt_workspace(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir
        .join(RUNS_DIRECTORY)
        .join(run_id)
        .join(ATTEMPT_WORKSPACE_LEAF)
}

/// Everything the execution lane needs, or the reason it has nothing.
///
/// Not [`Clone`]: it owns the daemon's worker threads and lends the attempt
/// host by [`Arc`], which is the one thing a worker legitimately shares.
#[derive(Debug)]
pub struct ExecutionLane {
    /// This daemon's one host-wide cancellation dispatcher.
    attempt_host: Arc<DaemonAttemptHost>,
    /// Private state directory, parent of [`RUNS_DIRECTORY`] and
    /// [`PROMPTS_DIRECTORY`].
    state_dir: PathBuf,
    /// The read model a worker advances, opened again per worker on its own
    /// connection. See [`advance`].
    run_index_path: PathBuf,
    /// Durable normalized provider-session bindings written by run workers.
    managed_sessions_path: PathBuf,
    /// The entry helper, when one is configured as an absolute path.
    helper: Option<PathBuf>,
    /// Whether the startup probe said this host can enforce the composed
    /// sandbox. Measured once, exactly like the status reports it.
    sandbox_enforceable: bool,
    /// What this host offers a document's enforcement negotiation, measured
    /// once at open beside the sandbox measurement it is derived from.
    offered: Vec<HostFeature>,
    /// The destinations this deployment resolves `brokered_named` egress to,
    /// read once at open. Empty is the ordinary case and refuses every document
    /// that asks for egress; see [`crate::egress`].
    egress_destinations: Vec<BrokeredDestination>,
    /// The delegated domain, discovered and prepared at most once.
    ///
    /// `None` until the first request, because [`ContainmentDomain::prepare`]
    /// *moves this process* into a supervisor leaf so the domain can distribute
    /// controllers to its children. A daemon that never executes anything must
    /// not have its own cgroup placement changed, and the discovery must happen
    /// before the move — afterwards `discover` would find the supervisor leaf,
    /// which holds this process and so can hold no bounded children.
    domain: Option<ContainmentDomain>,
    /// Runs with a live attempt. The serve thread inserts, a worker removes.
    live: Arc<Mutex<BTreeSet<String>>>,
    /// One handle per live worker, joined before the generation is released.
    workers: Vec<JoinHandle<()>>,
    /// Live replay for attempts whose spool nobody else can read yet.
    ///
    /// Shared with the backend's supervision thread, which publishes into it,
    /// and with whatever renders progress, which polls it. See
    /// [`crate::progress_hub`].
    progress: Arc<ProgressHub>,
    /// Lease-authorized input queues for currently attached JCode sessions.
    jcode_controls: Arc<JcodeControlRegistry>,
    /// Set once, by [`ExecutionLane::begin_shutdown`], and read by every
    /// worker that is waiting on an operator rather than on its workload.
    ///
    /// A running turn drains to its own document deadline, and that is the
    /// contract [`ExecutionLane::shutdown`] states. A turn paused on a provider
    /// request is different: nothing is executing, and the wait is for a
    /// person who may not answer before the deadline. A daemon that blocked its
    /// own stop on that wait would hold its generation, its cgroup tree and its
    /// listener for as long as the document allows, so a worker that sees this
    /// flag abandons the wait instead — leaving the request durably unanswered
    /// for the record, never answering it on the operator's behalf.
    draining: Arc<AtomicBool>,
}

const MAX_PENDING_JCODE_STEERS: usize = 16;
const JCODE_STEER_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// The journal's reason for a request left pending because this daemon was
/// draining while the turn waited on an operator.
///
/// Public so a successor — or a test standing in for one — can tell a wait the
/// daemon abandoned from one the provider ended, which is the whole point of
/// recording the reason rather than only the outcome.
pub const DAEMON_DRAINING_REASON: &str = "daemon_draining";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SteerRefusal {
    SessionNotLive,
    QueueFull,
    ProviderRefused,
    Unavailable,
}

impl SteerRefusal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionNotLive => "session_not_live",
            Self::QueueFull => "steering_queue_full",
            Self::ProviderRefused => "provider_steering_refused",
            Self::Unavailable => "steering_unavailable",
        }
    }
}

#[derive(Debug, Default)]
struct JcodeControlRegistry {
    live: Mutex<BTreeMap<String, LiveJcodeControl>>,
}

#[derive(Debug)]
struct LiveJcodeControl {
    run_id: String,
    sender: SyncSender<JcodeSteerCommand>,
}

#[derive(Debug)]
struct JcodeSteerCommand {
    content: String,
    urgent: bool,
    response: SyncSender<Result<(), SteerRefusal>>,
}

struct JcodeControlRegistration {
    registry: Arc<JcodeControlRegistry>,
    session_id: String,
    run_id: String,
    receiver: Receiver<JcodeSteerCommand>,
}

impl JcodeControlRegistry {
    fn register(
        self: &Arc<Self>,
        session_id: &str,
        run_id: &str,
    ) -> Result<JcodeControlRegistration, SteerRefusal> {
        let (sender, receiver) = sync_channel(MAX_PENDING_JCODE_STEERS);
        let mut live = self.live.lock().map_err(|_| SteerRefusal::Unavailable)?;
        if live.contains_key(session_id) {
            return Err(SteerRefusal::Unavailable);
        }
        live.insert(
            session_id.to_owned(),
            LiveJcodeControl {
                run_id: run_id.to_owned(),
                sender,
            },
        );
        Ok(JcodeControlRegistration {
            registry: Arc::clone(self),
            session_id: session_id.to_owned(),
            run_id: run_id.to_owned(),
            receiver,
        })
    }

    fn steer(&self, session_id: &str, content: &str) -> Result<(), SteerRefusal> {
        if content.is_empty() {
            return Err(SteerRefusal::ProviderRefused);
        }
        let sender = self
            .live
            .lock()
            .map_err(|_| SteerRefusal::Unavailable)?
            .get(session_id)
            .map(|control| control.sender.clone())
            .ok_or(SteerRefusal::SessionNotLive)?;
        let (response, received) = sync_channel(1);
        match sender.try_send(JcodeSteerCommand {
            content: content.to_owned(),
            urgent: false,
            response,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(SteerRefusal::QueueFull),
            Err(TrySendError::Disconnected(_)) => return Err(SteerRefusal::SessionNotLive),
        }
        received
            .recv_timeout(JCODE_STEER_ACK_TIMEOUT)
            .map_err(|_| SteerRefusal::Unavailable)?
    }
}

impl Drop for JcodeControlRegistration {
    fn drop(&mut self) {
        if let Ok(mut live) = self.registry.live.lock()
            && live
                .get(&self.session_id)
                .is_some_and(|control| control.run_id == self.run_id)
        {
            live.remove(&self.session_id);
        }
    }
}

impl ExecutionLane {
    /// Bind a lane to one daemon's attempt host and durable locations.
    ///
    /// Nothing is probed, created or moved here. A lane opens on every host,
    /// including one that can never execute anything, because the refusal a
    /// caller gets must be a typed answer on the wire rather than a daemon that
    /// failed to start.
    ///
    /// The destination policy is read here, once, from
    /// [`DaemonConfig::egress_destinations_path`](crate::DaemonConfig::egress_destinations_path)
    /// — so what a run is admitted against is the policy this daemon started
    /// with, not whatever the file said at the instant a request arrived. A file
    /// this daemon cannot read exactly leaves the policy empty, which refuses
    /// every document that asks for egress: the failure direction is closed, and
    /// the operator's evidence is that their brokered runs are refused rather
    /// than quietly permitted against a half-read list.
    #[must_use]
    pub fn open(
        attempt_host: Arc<DaemonAttemptHost>,
        state_dir: PathBuf,
        run_index_path: PathBuf,
        sandbox_enforceable: bool,
    ) -> Self {
        let helper = locate_launch_helper();
        let egress_destinations =
            crate::egress::load_destinations(&state_dir.join(crate::EGRESS_DESTINATIONS_NAME))
                .unwrap_or_default();
        // Detach any temporary-storage mount a crashed predecessor left stale
        // under this daemon's runs directory. Only disconnected mounts this uid
        // owns are detached; a live one belongs to a still-running supervisor
        // during generation handoff and is left alone. Each stale one's last
        // ledger checkpoint stays on disk for reconciliation, and each one is
        // reported to the native journal with whether the detach cleared the
        // mount table and whether a checkpoint was found. Best effort: a host
        // without FUSE has nothing to reap and refuses every run anyway.
        if let Ok(verified) = FusePrerequisites::host_default().verify()
            && let Ok(reaped) = reap_stale_mounts(
                &verified,
                &state_dir.join(RUNS_DIRECTORY),
                DEFAULT_READBACK_DEADLINE,
            )
        {
            for mount in &reaped {
                let _ = crate::structured_log::emit_temporary_storage_reaped(
                    &mount.run_id,
                    mount.detached,
                    mount.checkpoint.is_some(),
                );
            }
        }
        recover_private_temporary_storage_checkpoints(&state_dir.join(RUNS_DIRECTORY));
        Self {
            attempt_host,
            managed_sessions_path: state_dir.join(crate::MANAGED_SESSIONS_NAME),
            state_dir,
            run_index_path,
            helper,
            sandbox_enforceable,
            offered: offered_host_features(),
            egress_destinations,
            domain: None,
            live: Arc::new(Mutex::new(BTreeSet::new())),
            workers: Vec::new(),
            progress: Arc::new(ProgressHub::new()),
            jcode_controls: Arc::new(JcodeControlRegistry::default()),
            draining: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Deliver one lease-authorized input to a currently active JCode turn.
    pub fn steer_session(&self, session_id: &str, content: &str) -> Result<(), SteerRefusal> {
        self.jcode_controls.steer(session_id, content)
    }

    /// Live progress replay for the attempts this lane is running.
    ///
    /// A renderer holds this, polls it with a cursor while an attempt is live,
    /// and re-opens the durable spool once it is not. See
    /// [`crate::progress_hub`] for why those are two different things.
    #[must_use]
    pub fn progress(&self) -> Arc<ProgressHub> {
        Arc::clone(&self.progress)
    }

    /// The brokered destinations this lane was opened with.
    ///
    /// Empty means no document asking for egress can run here.
    #[must_use]
    pub fn egress_destinations(&self) -> &[BrokeredDestination] {
        &self.egress_destinations
    }

    /// Whether the configured provider's own selected route is fully present
    /// in the destination policy this generation admitted at startup.
    ///
    /// This never rereads `egress-destinations`, so status cannot report a
    /// policy edit as effective before the daemon reload that actually admits
    /// it.
    #[must_use]
    pub(crate) fn provider_route_admitted(
        &self,
        provider: &crate::compose::ProviderConfig,
    ) -> bool {
        crate::provider_route::is_admitted(provider, &self.egress_destinations)
    }

    /// The entry helper this lane would spawn, when one is configured.
    #[must_use]
    pub fn helper(&self) -> Option<&Path> {
        self.helper.as_deref()
    }

    /// Where one run's authoritative spool lives.
    ///
    /// The layout is this lane's, so the Runs read lane asks it rather than
    /// rebuilding the path from constants — one owner for one directory tree.
    /// The answer is a path, not a promise: a run that never executed has no
    /// directory there, and the caller's `Spool::open` is what discovers that.
    #[must_use]
    pub fn spool_root(&self, run_id: &str) -> PathBuf {
        run_spool_root(&self.state_dir, run_id)
    }

    /// Where one run's attempt workspace resolves, through this lane's own
    /// state directory. See [`run_attempt_workspace`].
    #[must_use]
    pub fn attempt_workspace_root(&self, run_id: &str) -> PathBuf {
        run_attempt_workspace(&self.state_dir, run_id)
    }

    /// Runs with a live attempt right now.
    ///
    /// `None` when the live set was poisoned by a panicking worker, which is
    /// the one state in which this lane cannot say what it is running.
    #[must_use]
    pub fn live_attempts(&self) -> Option<usize> {
        self.live.lock().ok().map(|live| live.len())
    }

    /// Start one attempt for a custodied document, or refuse without starting.
    ///
    /// `document` is the exact bytes custody holds, and `submission_id` and
    /// `revision` are the read-model row this attempt will advance.
    ///
    /// A refusal starts no workload and records nothing. The last two gates do
    /// build real state — a directory tree, a registration, a spool and a run
    /// cgroup — and every one of those is owned by a value whose drop undoes
    /// it, so a refusal after them leaves an empty directory tree and nothing
    /// else: no registration, no cgroup, and a spool with no events.
    ///
    /// # Errors
    ///
    /// Never. Every failure is an [`ExecuteRefusal`], because a caller asking
    /// this daemon to run something is owed a word about why it will not,
    /// including when the reason is the daemon's own.
    pub fn start(
        &mut self,
        document: &[u8],
        submission_id: i64,
        revision: u64,
    ) -> Result<(), ExecuteRefusal> {
        self.reap();

        if !self.sandbox_enforceable {
            return Err(ExecuteRefusal::SandboxUnenforceable);
        }
        let helper = self
            .helper
            .clone()
            .ok_or(ExecuteRefusal::LaunchHelperUnavailable)?;
        let backend = DirectProcessBackend::new(helper)
            .map_err(|_| ExecuteRefusal::LaunchHelperUnavailable)?;
        let domain = self.domain()?.clone();

        // The document decoded once already, on the way into custody. It is
        // decoded again rather than cached: custody is the source of truth, and
        // a lane that ran a value it had been holding in memory would be
        // running something nobody can point at on disk.
        //
        // A refusal here is therefore not the caller's: these exact bytes were
        // admitted by this decoder at submission time, so a second refusal says
        // this daemon's own custody has changed underneath it.
        let spec = RunSpec::from_canonical_bytes(document)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let run_id = spec.run_id().as_str().to_owned();
        // The containment module's own cgroup-name rule, applied before this
        // identifier names a directory. `admit` re-applies it; the point of
        // doing it first is that nothing creates a path from an identifier
        // whose grammar has not been checked.
        if !is_containment_run_id(&run_id) {
            return Err(ExecuteRefusal::AdmissionRefused);
        }

        // Claim the run before any of the expensive gates, so two requests
        // racing for one run cannot both reach admission.
        self.claim(&run_id)?;
        // Everything below this point must release the claim on failure, which
        // is the whole reason it is one call: on success the worker's own guard
        // owns the claim, and on failure this is the single place that gives it
        // back.
        let started =
            self.prepare_and_spawn(&spec, &run_id, backend, domain, submission_id, revision);
        if started.is_err() {
            self.release(&run_id);
        }
        started
    }

    /// Build the launch, then hand it to a worker.
    ///
    /// Split out so [`Self::start`] has exactly one place that releases the
    /// claim it took.
    fn prepare_and_spawn(
        &mut self,
        spec: &RunSpec,
        run_id: &str,
        backend: DirectProcessBackend,
        domain: ContainmentDomain,
        submission_id: i64,
        revision: u64,
    ) -> Result<(), ExecuteRefusal> {
        // The paths are computed now and *created* below, after admission.
        // Admission validates a context path lexically and opens nothing, so
        // nothing here needs them to exist yet — and a refused document must
        // leave no trace, including an empty directory tree that would make a
        // refused run look like one that started and vanished.
        let run_root = self.state_dir.join(RUNS_DIRECTORY).join(run_id);
        // One owner for this path: a composer that has to write it into a
        // document computes the same value through the same function.
        let attempt_workspace_root = self.attempt_workspace_root(run_id);
        let spool_root = run_root.join(SPOOL_LEAF);

        let (prompt, prompt_bytes) = self.resolve_prompt(spec)?;
        let observed = self.observe_provider_binary(spec)?;
        let provider_program_sha256 = observed
            .digest()
            .strip_prefix("sha256:")
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?
            .to_owned();

        // Verify the FUSE stack now, once, so the answer the context carries
        // and the proof used to mount are the same fresh check. A host that
        // cannot open `/dev/fuse` or lacks a setuid `fusermount3` makes the
        // temporary-storage budget unenforceable, and admission refuses the
        // document rather than admitting it with the budget acknowledged.
        let verified_fuse = FusePrerequisites::host_default().verify();
        let temporary_storage = match (
            &verified_fuse,
            automonique_runner::tempfs_owner::verify_available(),
        ) {
            (Ok(_), Ok(())) => TemporaryStorageEnforcement::Available,
            (Err(error), _) => TemporaryStorageEnforcement::Unavailable(error.to_string()),
            (Ok(_), Err(error)) => TemporaryStorageEnforcement::Unavailable(error.to_string()),
        };

        let context = AdmissionContext::new(AdmissionContextParts {
            backend: ExecutionBackendId::new(DAEMON_BACKEND_ID)
                .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?,
            attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new(
                DAEMON_ATTEMPT_WORKSPACE_REGISTRY,
            )
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?,
            // The attempt-workspace root and the working directory are the same
            // directory: this daemon resolves one, and a `cwd_token` naming a
            // sub-path of a workspace it did not register would be a resolution
            // it cannot perform.
            attempt_workspace_root: attempt_workspace_root.clone(),
            working_directory: attempt_workspace_root.clone(),
            observed_provider_binary: observed,
            host_features: self.offered.clone(),
            prompt: Some(prompt),
            // Naming a budget is not waiving it: `admission` requires each
            // unenforced budget to be acknowledged in advance, and republishes
            // the acknowledgement on the admitted launch. This daemon
            // acknowledges the one remaining gap: no artifact accounting.
            // CPU, descriptor and temporary-storage limits are now applied — by
            // the cgroup, the launch helper, and a per-run FUSE mount.
            unenforced_budgets: UnenforcedBudget::ALL.to_vec(),
            // The destinations this deployment resolves brokered egress to.
            // A document that denies egress is refused if this is non-empty and
            // one that asks for it is refused if this is empty, so the policy
            // can neither widen a denied document nor be defaulted into one.
            brokered_destinations: self.egress_destinations.clone(),
            // Off, and no deployment surface turns it on yet. Identity-bound
            // egress needs two things this lane does not have: a supervisor-held
            // provider credential — every credential here is a file below the
            // provider's own home, never a value the daemon holds — and a
            // provider engine that honours a base-URL variable, which the
            // pinned JCode engine does not on its OAuth route. Until both
            // exist, the mechanism is built, tested and disabled, and
            // production composes exactly the plan it composed before.
            // See `docs/operations/identity-bound-egress.md`.
            provider_identity: ProviderIdentityPolicy::Disabled,
            temporary_storage,
        })
        .map_err(|_| ExecuteRefusal::AdmissionRefused)?;

        let admitted = admit(spec, &context).map_err(|refusal| admission_refusal(&refusal))?;
        // One broker, this run's, bound before the plan is finished — because
        // the port the plan grants is the port this broker just bound, and it
        // does not exist until it is. A run whose document denies egress takes
        // the other branch and gets no broker, no socket grant and no proxy
        // variable at all.
        let (admitted, broker) = self.start_broker(admitted)?;
        let refused_destination = broker
            .as_ref()
            .map(EgressBroker::refused_destination_observer);

        // Admitted, so the run may now have a place on disk. The attempt
        // workspace is created empty and the spool root beside it, never inside
        // it: the admitted plan grants the workload read-write access to the
        // attempt workspace, and a spool under that grant would be a durable
        // lifecycle record the workload could rewrite.
        private_directory(&self.state_dir.join(RUNS_DIRECTORY))
            .and_then(|()| private_directory(&run_root))
            .and_then(|()| private_directory(&attempt_workspace_root))
            .and_then(|()| private_directory(&spool_root))
            .map_err(|()| ExecuteRefusal::ExecutionUnavailable)?;

        // EVERYTHING THAT CAN STILL REFUSE HAPPENS BEFORE THE ANSWER.
        //
        // Registration, the spool and the run cgroup are all created here, on
        // the serve thread, rather than on the worker. The reason is what the
        // answer means: a caller told `accepted` was told an attempt started,
        // and a worker that discovered a duplicate registration or an
        // unopenable spool *after* the answer would leave that caller holding a
        // receipt for a run that never began and never appeared anywhere. Each
        // of these is a bounded local operation — one row, one file, one
        // directory and two ceilings — and each maps onto the refusal that
        // names it.
        //
        // Registration precedes preparation, so no cgroup can exist for an
        // attempt cancellation cannot reach.
        let cancellation = CancellationToken::new();
        let deliveries = Arc::new(AtomicUsize::new(0));
        let attempt_id = spec.attempt_id().as_str().to_owned();
        let registration = self
            .attempt_host
            .register(
                &attempt_id,
                Box::new(TokenCancelSink {
                    attempt_id: attempt_id.clone(),
                    cancellation: cancellation.clone(),
                    deliveries,
                }),
            )
            .map_err(registration_refusal)?;

        // The scratch directory is an ordinary empty supervisor-owned
        // directory here. The entry helper mounts the admitted filesystem over
        // it only after entering the workload user+mount namespace; no
        // supervisor-visible mount exists and no workload instruction runs
        // before the exact FUSE handshake succeeds.
        verified_fuse.map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;
        let mountpoint = run_root.join(MOUNT_LEAF);
        private_directory(&mountpoint).map_err(|()| ExecuteRefusal::ExecutionUnavailable)?;
        let temporary_storage_budget = admitted.temporary_storage_budget();
        let temporary_storage_checkpoint = run_root.join(CHECKPOINT_LEAF);
        let admitted = admitted
            .with_namespaced_temporary_storage(&mountpoint)
            .map_err(|_| ExecuteRefusal::AdmissionRefused)?;

        let spool = Spool::open(&spool_root, run_id, admitted.spool_budget_bytes())
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let session_capture = Arc::new(Mutex::new(None));
        let prepared = if jcode_session_mode(spec)? {
            let containment = RunContainment::create(&domain, run_id, admitted.limits())
                .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;
            let prompt_sha256 = Sha256::digest(&prompt_bytes).to_hex();
            let prompt =
                String::from_utf8(prompt_bytes).map_err(|_| ExecuteRefusal::PromptUnresolvable)?;
            PreparedAttempt::Jcode(Box::new(
                JcodePreparedRun::new(JcodePreparedParts {
                    helper: backend.helper().to_path_buf(),
                    run_id,
                    plan: admitted.plan().clone().into_session_plan(),
                    containment,
                    spool,
                    prompt,
                    resume_session_id: jcode_resume_session(spec)?,
                    expected_server: spec.provider_binary().version().to_owned(),
                    journal_path: self.state_dir.join(crate::PROVIDER_JOURNAL_NAME),
                    answer_path: attempt_workspace_root.join(crate::compose::ANSWER_LEAF),
                    publisher: self.progress.publisher(run_id),
                    session_capture: Arc::clone(&session_capture),
                    managed_sessions_path: self.managed_sessions_path.clone(),
                    controls: Arc::clone(&self.jcode_controls),
                    temporary_storage: Some(NamespacedTemporaryStorage {
                        mountpoint: mountpoint.clone(),
                        budget: temporary_storage_budget,
                        checkpoint: temporary_storage_checkpoint.clone(),
                    }),
                    refused_destination,
                    approval: ProviderApprovalContext {
                        store_path: self.state_dir.join(crate::APPROVAL_REQUESTS_NAME),
                        spec_digest: admitted
                            .spec_digest()
                            .as_str()
                            .strip_prefix("sha256:")
                            .ok_or(ExecuteRefusal::AdmissionRefused)?
                            .to_owned(),
                        program_path: spec
                            .executable()
                            .to_str()
                            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?
                            .to_owned(),
                        program_sha256: provider_program_sha256,
                        prompt_sha256,
                        cwd_token: spec.cwd_token().as_str().to_owned(),
                        expires_after_ms:
                            crate::approval_policy::ApprovalPolicyConfig::lifetime_or_default(
                                &self.state_dir,
                            )
                            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?
                            .ttl_ms(),
                    },
                })
                .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?,
            ))
        } else {
            // `prepare` creates the run cgroup and applies the document's
            // ceilings before any workload can enter it. Dropping the result
            // removes that cgroup and leaves the spool empty.
            let prepared = backend
                .prepare(
                    &domain,
                    run_id,
                    admitted.limits(),
                    admitted.plan().clone(),
                    spool,
                )
                .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?
                // The first temporary-storage refusal contains the run: the
                // supervision loop polls this watch and ends the workload on
                // its first `ENOSPC`/`EDQUOT` with a typed budget outcome, and
                // the spool records the refusal and the mount's readback.
                .with_namespaced_temporary_storage(
                    &mountpoint,
                    temporary_storage_budget,
                    &temporary_storage_checkpoint,
                );
            // Capture only a stdout grammar the document explicitly selected.
            let prepared = if emits_normalized_stream(spec) {
                match progress_capture(spec, run_id, &self.progress, Arc::clone(&session_capture)) {
                    Some(capture) => prepared.with_progress(capture),
                    None => prepared,
                }
            } else {
                prepared
            };
            PreparedAttempt::Direct(Box::new(prepared))
        };
        let observed = prepared.observed_sequence();

        self.spawn(Attempt {
            run_id: run_id.to_owned(),
            attempt_id,
            submission_id,
            revision,
            timeout: admitted.timeout(),
            cancellation,
            registration,
            prepared,
            observed,
            progress: Arc::clone(&self.progress),
            attempt_host: Arc::clone(&self.attempt_host),
            broker,
            session_capture,
            managed_sessions_path: self.managed_sessions_path.clone(),
            approval_requests_path: self.state_dir.join(crate::APPROVAL_REQUESTS_NAME),
            draining: Arc::clone(&self.draining),
        })
    }

    /// Start this run's own broker, or answer that it needs none.
    ///
    /// # One broker per run, never a shared one
    ///
    /// The broker is started here, per run, and its port is part of the
    /// security model rather than an implementation detail: the launch grants
    /// `connect` to a *port*, because a Landlock network rule names nothing
    /// else, and what keeps that from being a grant to some other service is
    /// that the port is a kernel-assigned ephemeral one on `127.0.0.1`. A broker
    /// shared between runs would be a predictable port shared between
    /// allowlists — one run's grant would reach another run's destinations —
    /// so there is no sharing and no reuse, and the ephemeral port is never
    /// pinned.
    ///
    /// The allowlist is rebuilt from the *admitted* destinations rather than
    /// from this lane's own copy of the policy, so the broker a run gets permits
    /// exactly what that run was admitted against.
    fn start_broker(
        &self,
        admitted: AdmittedLaunch,
    ) -> Result<(AdmittedLaunch, Option<EgressBroker>), ExecuteRefusal> {
        let Some(requirement) = admitted.broker_requirement() else {
            return Ok((admitted, None));
        };
        let allowlist = crate::egress::allowlist_for(requirement.destinations())
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        // Unreachable — admission refuses an empty destination set — and
        // checked anyway, because a broker permitting nothing would be a
        // workload holding a socket grant it can do nothing with, which is a
        // grant with no purpose rather than a refusal.
        if allowlist.denies_everything() {
            return Err(ExecuteRefusal::ExecutionUnavailable);
        }
        // A broker that cannot bind its loopback listener is this daemon's own
        // resource failure, not the caller's document.
        let broker = EgressBroker::start(BrokerConfig::new(allowlist))
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        // Everything from here to the worker either succeeds or drops this
        // value, and dropping it stops the listener and tears down every
        // in-flight tunnel.
        let admitted = admitted
            .with_broker(broker.local_addr())
            .map_err(|_| ExecuteRefusal::AdmissionRefused)?;
        Ok((admitted, Some(broker)))
    }

    /// Discover and prepare this process's delegated domain, once.
    ///
    /// The controllers are required rather than optional: the admitted limits
    /// carry memory, process and CPU ceilings, and a domain that cannot
    /// distribute those controllers cannot apply them. Running anyway would
    /// be running *outside the document's declared budget*, which is the exact
    /// silent downgrade this build refuses everywhere else.
    fn domain(&mut self) -> Result<&ContainmentDomain, ExecuteRefusal> {
        if self.domain.is_none() {
            let domain = ContainmentDomain::discover()
                .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;
            domain
                .prepare(&[Controller::Pids, Controller::Memory, Controller::Cpu])
                .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;
            self.domain = Some(domain);
        }
        self.domain
            .as_ref()
            .ok_or(ExecuteRefusal::ContainmentUnavailable)
    }

    /// Resolve the document's prompt transport to bytes this daemon holds.
    ///
    /// A protected reference names a file in [`PROMPTS_DIRECTORY`]. Stdin
    /// delivery and a backend session are both refused: this lane has no
    /// caller stream to forward and no provider session to deliver over, and
    /// substituting empty bytes for either would run a prompt-shaped hole.
    ///
    /// The digest handed to [`ResolvedPrompt`] is computed here, over the bytes
    /// as read, so `admit`'s re-check is a self-check rather than a check of a
    /// resolving store's honesty. That is a weaker statement than the one
    /// `admission` is built to make, and it is weaker for a stated reason: the
    /// slot directory asserts no digest of its own. When a store that does
    /// lands, its assertion is what belongs here.
    fn resolve_prompt(&self, spec: &RunSpec) -> Result<(ResolvedPrompt, Vec<u8>), ExecuteRefusal> {
        let slot = match spec.prompt_delivery() {
            PromptDeliveryPlan::ProtectedReference(reference) => reference.as_str().to_owned(),
            PromptDeliveryPlan::Stdin | PromptDeliveryPlan::BackendSession(_) => {
                return Err(ExecuteRefusal::PromptUnresolvable);
            }
        };
        if !is_safe_segment(&slot) {
            return Err(ExecuteRefusal::PromptUnresolvable);
        }
        let path = self.state_dir.join(PROMPTS_DIRECTORY).join(&slot);
        let limit =
            u64::try_from(MAX_PROMPT_BYTES).map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let bytes = read_bounded(&path, limit).ok_or(ExecuteRefusal::PromptUnresolvable)?;
        if bytes.is_empty() {
            return Err(ExecuteRefusal::PromptUnresolvable);
        }
        let declared = Digest::parse(&format!("{ALGORITHM}:{}", Sha256::digest(&bytes).to_hex()))
            .map_err(|_| ExecuteRefusal::PromptUnresolvable)?;
        let resolved = ResolvedPrompt::new(
            PromptSource::ProtectedReference(
                automonique_runner::ProtectedPromptReference::new(slot)
                    .map_err(|_| ExecuteRefusal::PromptUnresolvable)?,
            ),
            bytes.clone(),
            declared,
        )
        .map_err(|_| ExecuteRefusal::PromptUnresolvable)?;
        Ok((resolved, bytes))
    }

    /// Hash the program the document pins, and report it as observed
    /// provenance.
    ///
    /// The version travels from the document because it is informational —
    /// [`BinaryProvenance::matches`] compares digests, not versions — and the
    /// schema digest must be absent at admission: no process has been started,
    /// so the daemon cannot yet observe a provider handshake, and copying the
    /// document's own claim into the observation would turn that half of the
    /// comparison into a mirror. The contained JCode host binds its negotiated
    /// protocol identity separately after spawn.
    /// A document that pins a schema digest is therefore refused here rather
    /// than admitted on a check nobody performed.
    fn observe_provider_binary(&self, spec: &RunSpec) -> Result<BinaryProvenance, ExecuteRefusal> {
        let pinned = spec.provider_binary();
        if pinned.schema_digest().is_some() {
            return Err(ExecuteRefusal::ProviderBinaryUnverified);
        }
        let bytes = read_bounded(spec.executable(), MAX_PROVIDER_BINARY_BYTES)
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?;
        let observed = provider_binary_digest(&bytes);
        BinaryProvenance::new(pinned.version(), &observed, None)
            .map_err(|_| ExecuteRefusal::ProviderBinaryUnverified)
    }

    /// Take the live claim for one run, refusing a duplicate or a full lane.
    fn claim(&self, run_id: &str) -> Result<(), ExecuteRefusal> {
        let mut live = self
            .live
            .lock()
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        if live.contains(run_id) {
            return Err(ExecuteRefusal::AlreadyExecuting);
        }
        if live.len() >= MAX_LIVE_ATTEMPTS {
            return Err(ExecuteRefusal::LaneSaturated);
        }
        live.insert(run_id.to_owned());
        Ok(())
    }

    /// Release one live claim. Best effort: a poisoned set is already reported
    /// by [`Self::live_attempts`], and failing to release cannot start a run.
    fn release(&self, run_id: &str) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(run_id);
        }
    }

    /// Move one prepared attempt onto its own thread.
    ///
    /// A failed spawn drops the attempt, whose registration handle releases the
    /// cancellation registration and whose prepared run removes the cgroup it
    /// created and leaves the spool empty. Nothing ran, and nothing is recorded.
    fn spawn(&mut self, attempt: Attempt) -> Result<(), ExecuteRefusal> {
        let live = Arc::clone(&self.live);
        let index_path = self.run_index_path.clone();
        let run_id = attempt.run_id.clone();
        let worker = std::thread::Builder::new()
            .name(format!("automonique-run-{run_id}"))
            .spawn(move || {
                // The claim is released on every path out of the attempt,
                // including a panic inside it, because this guard is dropped by
                // the unwinding thread.
                let _claim = LiveClaim {
                    live,
                    run_id: run_id.clone(),
                };
                attempt.run(&index_path);
            })
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        self.workers.push(worker);
        Ok(())
    }

    /// Drop the handles of workers that have already finished.
    ///
    /// Called on the serve thread before each start, so the handle vector is
    /// bounded by the number of *live* attempts rather than by the number this
    /// daemon has ever run.
    fn reap(&mut self) {
        let mut remaining = Vec::with_capacity(self.workers.len());
        for worker in self.workers.drain(..) {
            if worker.is_finished() {
                // A panicking worker already recorded its terminal event
                // through the backend's own drop path, and released its
                // registration and its claim through theirs. The join result is
                // dropped because there is nothing further this lane can
                // truthfully say about it.
                let _ = worker.join();
            } else {
                remaining.push(worker);
            }
        }
        self.workers = remaining;
    }

    /// Join every live worker, then release this lane's own reference to the
    /// attempt host.
    ///
    /// Consuming, and both halves matter to [`crate::Daemon::serve`]:
    ///
    /// - **Joining** happens while the generation lease is still held, because
    ///   a worker holds a registration on the attempt host and writes to the
    ///   read model this generation owns. Returning while an attempt is live
    ///   would also leave a contained process tree owned by a process that has
    ///   stopped answering for it.
    /// - **Releasing** is what lets the daemon unwrap the `Arc` and dispose of
    ///   the host exactly once. A lane that merely joined would still hold a
    ///   clone, and the disposal would report a host that is still shared —
    ///   truthfully, and uselessly.
    ///
    /// This blocks for as long as the longest live attempt still has to run,
    /// bounded by each document's own timeout, which the backend enforces. No
    /// deadline is added here: abandoning a live attempt to meet one would
    /// leave exactly the orphaned tree the containment exists to prevent.
    pub fn shutdown(self) {
        for worker in self.begin_shutdown() {
            let _ = worker.join();
        }
    }

    /// Return every live worker to an external drainer.
    ///
    /// Moving the handles out consumes the lane and releases its own attempt
    /// host reference. Each worker retains its registration until it finishes,
    /// so the daemon can keep the generation lease live while polling these
    /// handles without weakening containment or cancellation custody.
    pub(crate) fn begin_shutdown(mut self) -> Vec<JoinHandle<()>> {
        // Raised before the handles move, so no worker can be handed to a
        // drainer while still believing an operator's answer is worth waiting
        // for. A running turn ignores this; see the field.
        self.draining.store(true, Ordering::Release);
        self.workers.drain(..).collect()
    }
}

fn recover_private_temporary_storage_checkpoints(runs: &Path) {
    let Ok(entries) = fs::read_dir(runs) else {
        return;
    };
    for entry in entries.take(MAX_RECOVERED_TEMPFS_CHECKPOINTS).flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(run_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_containment_run_id(&run_id) {
            continue;
        }
        let Ok(checkpoint) =
            automonique_runner::Checkpoint::read(&entry.path().join(CHECKPOINT_LEAF))
        else {
            continue;
        };
        if checkpoint.phase == automonique_runner::CheckpointPhase::Live
            && checkpoint
                .mount_evidence
                .starts_with("automonique.namespaced-tempfs/v1 ")
            && let Ok(adopted) = automonique_runner::tempfs_owner::adopt_run(&entry.path())
        {
            let _ = crate::structured_log::emit_temporary_storage_checkpoint_recovered(
                &run_id, &adopted,
            );
        }
    }
}

/// A live claim, released when the worker thread's frame is dropped.
struct LiveClaim {
    live: Arc<Mutex<BTreeSet<String>>>,
    run_id: String,
}

enum PreparedAttempt {
    Direct(Box<PreparedRun>),
    Jcode(Box<JcodePreparedRun>),
}

impl PreparedAttempt {
    fn observed_sequence(&self) -> ObservedSequence {
        match self {
            Self::Direct(prepared) => prepared.observed_sequence(),
            Self::Jcode(prepared) => prepared.observed.clone(),
        }
    }

    /// Run to a terminal state.
    ///
    /// `draining` is read only by a JCode attempt paused on a provider request;
    /// a direct workload has no operator wait to abandon and drains to its own
    /// deadline, as [`ExecutionLane::shutdown`] states.
    fn execute(
        self,
        cancellation: &CancellationToken,
        timeout: Duration,
        draining: &AtomicBool,
    ) -> AttemptExecution {
        match self {
            Self::Direct(prepared) => match (*prepared).execute(cancellation, timeout) {
                Ok(report) => AttemptExecution {
                    state: spool_state(report.status().state()),
                    last_sequence: report.status().last_sequence(),
                    temporary_storage: report.namespaced_temporary_storage().cloned(),
                },
                Err(_) => AttemptExecution {
                    state: RunSpoolState::Failed,
                    last_sequence: 0,
                    temporary_storage: None,
                },
            },
            Self::Jcode(prepared) => prepared.execute(cancellation, timeout, draining),
        }
    }
}

struct AttemptExecution {
    state: RunSpoolState,
    last_sequence: u64,
    temporary_storage: Option<NamespacedOutcome>,
}

#[derive(Clone, Debug)]
struct NamespacedTemporaryStorage {
    mountpoint: PathBuf,
    budget: TemporaryStorageBudget,
    checkpoint: PathBuf,
}

struct JcodePreparedParts<'a> {
    helper: PathBuf,
    run_id: &'a str,
    plan: LaunchPlan,
    containment: RunContainment,
    spool: Spool,
    prompt: String,
    resume_session_id: Option<String>,
    expected_server: String,
    journal_path: PathBuf,
    answer_path: PathBuf,
    publisher: Box<dyn ProgressPublisher>,
    session_capture: Arc<Mutex<Option<String>>>,
    /// Where the managed-session binding lives, so this run can name itself as
    /// its session's active run before the turn starts.
    managed_sessions_path: PathBuf,
    controls: Arc<JcodeControlRegistry>,
    /// Private in-namespace scratch launch, absent only in protocol-only tests.
    temporary_storage: Option<NamespacedTemporaryStorage>,
    /// The bounded target most recently refused by this run's own broker.
    refused_destination: Option<RefusedDestinationObserver>,
    approval: ProviderApprovalContext,
}

struct ProviderApprovalContext {
    store_path: PathBuf,
    spec_digest: String,
    program_path: String,
    program_sha256: String,
    prompt_sha256: String,
    cwd_token: String,
    expires_after_ms: i64,
}

impl ProviderApprovalContext {
    fn propose(
        &self,
        run_id: &str,
        request: &crate::jcode_session_host::JcodeApprovalRequest,
        now_ms: i64,
    ) -> Result<(ApprovalRequests, String), ()> {
        let mut material = Vec::from(PROVIDER_APPROVAL_KEY_DOMAIN);
        for coordinate in [run_id, request.request_id()] {
            material.extend_from_slice(coordinate.as_bytes());
            material.push(0);
        }
        let digest = Sha256::digest(&material).to_hex();
        let request_key = format!("{REQUEST_KEY_PREFIX}{}", &digest[..REQUEST_KEY_HEX_BYTES]);
        let subject = format!("provider-permission:{}", &digest[..REQUEST_KEY_HEX_BYTES]);
        let mut approvals = ApprovalRequests::open(&self.store_path).map_err(|_| ())?;
        approvals
            .propose(ApprovalProposal {
                request_key: &request_key,
                subject: &subject,
                run_id,
                context: ApprovalContext {
                    spec_digest: &self.spec_digest,
                    program_path: &self.program_path,
                    program_sha256: &self.program_sha256,
                    prompt_sha256: &self.prompt_sha256,
                    cwd_token: &self.cwd_token,
                },
                requested_by: PROVIDER_APPROVAL_PROPOSER,
                requested_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(self.expires_after_ms),
            })
            .map_err(|_| ())?;
        Ok((approvals, request_key))
    }
}

struct JcodePreparedRun {
    helper: PathBuf,
    run_id: String,
    frame_run_id: FrameRunId,
    plan: LaunchPlan,
    containment: RunContainment,
    spool: Spool,
    prompt: String,
    resume_session_id: Option<String>,
    expected_server: String,
    journal_path: PathBuf,
    answer_path: PathBuf,
    publisher: Box<dyn ProgressPublisher>,
    session_capture: Arc<Mutex<Option<String>>>,
    managed_sessions_path: PathBuf,
    controls: Arc<JcodeControlRegistry>,
    temporary_storage: Option<NamespacedTemporaryStorage>,
    refused_destination: Option<RefusedDestinationObserver>,
    approval: ProviderApprovalContext,
    observed: ObservedSequence,
}

impl JcodePreparedRun {
    fn new(parts: JcodePreparedParts<'_>) -> Result<Self, ()> {
        let status = parts.spool.status();
        if status.run_id() != parts.run_id
            || status.last_sequence() != 0
            || parts.spool.is_terminal()
            || parts.prompt.is_empty()
        {
            return Err(());
        }
        parts.plan.encode().map_err(|_| ())?;
        let frame_run_id = FrameRunId::new(parts.run_id).map_err(|_| ())?;
        Ok(Self {
            helper: parts.helper,
            run_id: parts.run_id.to_owned(),
            frame_run_id,
            plan: parts.plan,
            containment: parts.containment,
            spool: parts.spool,
            prompt: parts.prompt,
            resume_session_id: parts.resume_session_id,
            expected_server: parts.expected_server,
            journal_path: parts.journal_path,
            answer_path: parts.answer_path,
            publisher: parts.publisher,
            session_capture: parts.session_capture,
            managed_sessions_path: parts.managed_sessions_path,
            controls: parts.controls,
            temporary_storage: parts.temporary_storage,
            refused_destination: parts.refused_destination,
            approval: parts.approval,
            observed: ObservedSequence::default(),
        })
    }

    fn execute(
        self,
        cancellation: &CancellationToken,
        timeout: Duration,
        draining: &AtomicBool,
    ) -> AttemptExecution {
        let Self {
            helper,
            run_id,
            frame_run_id,
            plan,
            containment,
            spool,
            prompt,
            resume_session_id,
            expected_server,
            journal_path,
            answer_path,
            publisher,
            session_capture,
            managed_sessions_path,
            controls,
            temporary_storage,
            refused_destination,
            approval,
            observed,
        } = self;
        // Why the host was closed, as the journal will record it against any
        // request still pending. Only the drain path changes it: every other
        // exit either answered the request or lost the provider.
        let mut close_reason = HOST_CLOSED_REASON;
        let mut writer = JcodeSpoolWriter {
            spool,
            frame_run_id,
            publisher,
            observed: observed.clone(),
            progress_stopped: false,
            refused_destination,
            refused_destination_cursor: None,
        };
        if cancellation.is_cancelled() {
            return writer.finish(RunSpoolState::Cancelled);
        }
        let started_at = Instant::now();
        let now_ms = crate::unix_millis().unwrap_or(0);
        let logical_key = format!("{run_id}-attempt");
        let working_directory = answer_path.parent().unwrap_or_else(|| Path::new("/"));
        let spawned = match temporary_storage {
            Some(storage) => JcodeSessionHost::spawn_with_namespaced_temporary_storage(
                &helper,
                &plan,
                containment,
                &journal_path,
                &logical_key,
                working_directory,
                resume_session_id.as_deref(),
                None,
                &expected_server,
                now_ms,
                Duration::from_secs(30),
                &storage.mountpoint,
                storage.budget,
                &storage.checkpoint,
            ),
            None => JcodeSessionHost::spawn(
                &helper,
                &plan,
                containment,
                &journal_path,
                &logical_key,
                working_directory,
                resume_session_id.as_deref(),
                None,
                &expected_server,
                now_ms,
                Duration::from_secs(30),
            ),
        };
        let mut host = match spawned {
            Ok(host) => host,
            Err(JcodeHostError::TemporaryStorageExceeded {
                exceedance,
                readback,
            }) => {
                writer.temporary_storage_exceeded(exceedance, readback);
                return writer.finish(RunSpoolState::Failed);
            }
            Err(_) => return writer.finish(RunSpoolState::Failed),
        };
        if writer.started(host.operating_system_process_id()).is_err() {
            return finish_failed_jcode_host(host, writer, now_ms);
        }
        if let Ok(mut captured) = session_capture.lock() {
            *captured = Some(host.provider_session_id().to_owned());
        }
        // THE SESSION NAMES THE RUN IT IS RUNNING.
        //
        // Written here, before the turn is started, because everything this
        // turn raises is raised against this run: a provider permission request
        // arrives mid-turn and belongs to the run that asked for it. A binding
        // advanced only at completion names the previous, already-terminal run,
        // so a session-scoped surface cannot own the live approval it is being
        // asked to decide, nor name the run it is being asked to stop.
        //
        // Best-effort, exactly like the settlement at the other end of the
        // turn: the binding is a projection of what the run is doing, and a
        // projection that could not be written is not a reason to refuse to
        // run. The independent connection is opened and dropped here rather
        // than held across the turn so nothing this worker owns keeps a write
        // lock while the provider thinks.
        if let Ok(bound_at) = crate::unix_millis()
            && let Ok(mut sessions) =
                crate::managed_sessions::ManagedSessionStore::open(&managed_sessions_path)
        {
            let _ = sessions.observe_active(host.provider_session_id(), &run_id, bound_at);
        }
        let control = match controls.register(host.provider_session_id(), &run_id) {
            Ok(control) => control,
            Err(_) => {
                return finish_failed_jcode_host(host, writer, now_ms);
            }
        };
        let mut pending_steers: BTreeMap<u64, SyncSender<Result<(), SteerRefusal>>> =
            BTreeMap::new();
        let mut mapper = JcodeProgressMapper::new(resume_session_id.is_some());
        writer.project(&mut mapper, host.take_events());
        let mut last_temporary_storage_checkpoint = Instant::now();
        // This forced observation is the custody boundary before the prompt:
        // startup may have touched TMPDIR, but a refusal there must never be
        // followed by a turn request. It also refreshes the checkpoint clock
        // from the exact instant the caller takes over startup supervision.
        match poll_jcode_temporary_storage(&mut host, &mut last_temporary_storage_checkpoint, true)
        {
            Ok(Some((exceedance, readback))) => {
                writer.temporary_storage_exceeded(exceedance, readback);
                return finish_failed_jcode_host(host, writer, now_ms);
            }
            Ok(None) => {}
            Err(()) => return finish_failed_jcode_host(host, writer, now_ms),
        }
        writer.begin_provider_request();
        if host
            .start_turn(&format!("{run_id}-turn"), &prompt, now_ms)
            .is_err()
        {
            return finish_failed_jcode_host(host, writer, now_ms);
        }
        // `start_turn` writes to the provider and can therefore block while
        // the provider is already using its scratch filesystem. Re-observe
        // before any provider outcome or control state can be selected.
        match poll_jcode_temporary_storage(&mut host, &mut last_temporary_storage_checkpoint, true)
        {
            Ok(Some((exceedance, readback))) => {
                writer.temporary_storage_exceeded(exceedance, readback);
                return finish_failed_jcode_host(host, writer, now_ms);
            }
            Ok(None) => {}
            Err(()) => return finish_failed_jcode_host(host, writer, now_ms),
        }

        let mut cancellation_sent = false;
        let final_state = 'run: loop {
            loop {
                match control.receiver.try_recv() {
                    Ok(command) => {
                        let request_id = host.soft_interrupt(
                            &command.content,
                            command.urgent,
                            crate::unix_millis().unwrap_or(now_ms),
                        );
                        match request_id {
                            Ok(request_id) => {
                                pending_steers.insert(request_id, command.response);
                            }
                            Err(_) => {
                                let _ = command.response.send(Err(SteerRefusal::ProviderRefused));
                            }
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            let elapsed = started_at.elapsed();
            let temporary_storage = match poll_jcode_temporary_storage(
                &mut host,
                &mut last_temporary_storage_checkpoint,
                false,
            ) {
                Ok(storage) => storage,
                Err(()) => break RunSpoolState::Failed,
            };
            // This refusal has already been checkpointed. It is therefore the
            // first durable terminal fact and must win over a cancellation or
            // deadline observed later in this same supervision iteration.
            if let Some((exceedance, readback)) = temporary_storage {
                let _ = host.cancel(
                    crate::unix_millis().unwrap_or(now_ms),
                    Duration::from_millis(100),
                );
                writer.project(&mut mapper, host.take_events());
                writer.temporary_storage_exceeded(exceedance, readback);
                break RunSpoolState::Failed;
            }
            if cancellation.is_cancelled() && !cancellation_sent {
                cancellation_sent = true;
                let cancelled = host.cancel(
                    crate::unix_millis().unwrap_or(now_ms),
                    Duration::from_millis(100),
                );
                let events = host.take_events();
                match poll_jcode_temporary_storage(
                    &mut host,
                    &mut last_temporary_storage_checkpoint,
                    true,
                ) {
                    Ok(Some((exceedance, readback))) => {
                        writer.project(&mut mapper, events);
                        writer.temporary_storage_exceeded(exceedance, readback);
                        break RunSpoolState::Failed;
                    }
                    Ok(None) => writer.project_turn_outcome(&mut mapper, events, &cancelled),
                    Err(()) => break RunSpoolState::Failed,
                }
                match cancelled {
                    Ok(JcodeTurnOutcome::Cancelled | JcodeTurnOutcome::Completed(_)) => {
                        break RunSpoolState::Cancelled;
                    }
                    Ok(
                        JcodeTurnOutcome::Pending
                        | JcodeTurnOutcome::ApprovalRequired(_)
                        | JcodeTurnOutcome::InputRequired(_),
                    ) => {}
                    Ok(JcodeTurnOutcome::InterruptedUnknown(_)) => break RunSpoolState::Failed,
                    Err(_) => break RunSpoolState::Failed,
                }
            }
            if elapsed >= timeout {
                break RunSpoolState::TimedOut;
            }
            let outcome = host.poll_turn(
                crate::unix_millis().unwrap_or(now_ms),
                Duration::from_millis(100),
            );
            let events = host.take_events();
            for event in &events {
                match event {
                    automonique_agents::JcodeEvent::Ok { reply_to } => {
                        if let Some(response) = pending_steers.remove(reply_to) {
                            let _ = response.send(Ok(()));
                            writer.steered();
                        }
                    }
                    automonique_agents::JcodeEvent::Error {
                        reply_to: Some(reply_to),
                        ..
                    } => {
                        if let Some(response) = pending_steers.remove(reply_to) {
                            let _ = response.send(Err(SteerRefusal::ProviderRefused));
                        }
                    }
                    _ => {}
                }
            }
            // `poll_turn` may have blocked while the provider handled ENOSPC
            // and then emitted a terminal frame. Observe the ledger again
            // before selecting that terminal outcome so quota refusal wins
            // independently of provider/socket scheduling, like the direct
            // backend's post-`try_wait` arbitration.
            match poll_jcode_temporary_storage(
                &mut host,
                &mut last_temporary_storage_checkpoint,
                false,
            ) {
                Ok(Some((exceedance, readback))) => {
                    // Quota custody decides the final state, but it does not
                    // erase an independently exact attribution for the
                    // provider fault that preceded it. Correlate that one
                    // fault to this request's refusal window, then append the
                    // quota warning as the terminal-authoritative reason.
                    writer.project_turn_outcome(&mut mapper, events, &outcome);
                    let _ = host.cancel(
                        crate::unix_millis().unwrap_or(now_ms),
                        Duration::from_millis(100),
                    );
                    writer.project(&mut mapper, host.take_events());
                    writer.temporary_storage_exceeded(exceedance, readback);
                    break 'run RunSpoolState::Failed;
                }
                Ok(None) => writer.project_turn_outcome(&mut mapper, events, &outcome),
                Err(()) => break 'run RunSpoolState::Failed,
            }
            match outcome {
                Ok(JcodeTurnOutcome::Pending) => {}
                Ok(JcodeTurnOutcome::Completed(result)) => {
                    if write_jcode_answer(&answer_path, result.text()).is_err() {
                        break RunSpoolState::Failed;
                    }
                    break if cancellation_sent {
                        RunSpoolState::Cancelled
                    } else {
                        RunSpoolState::Completed
                    };
                }
                Ok(JcodeTurnOutcome::Cancelled) => break RunSpoolState::Cancelled,
                Ok(JcodeTurnOutcome::InterruptedUnknown(_)) => break RunSpoolState::Failed,
                Ok(JcodeTurnOutcome::InputRequired(mut request)) => 'input: loop {
                    writer.input_waiting(&request);
                    if request.is_password() {
                        // Platform action parameters are not a secret-input
                        // channel. Never route a password through durable
                        // control receipts; a dedicated secret broker is a
                        // separate acceptance gate.
                        break 'run RunSpoolState::Failed;
                    }
                    loop {
                        match poll_jcode_temporary_storage(
                            &mut host,
                            &mut last_temporary_storage_checkpoint,
                            false,
                        ) {
                            Ok(Some((exceedance, readback))) => {
                                writer.temporary_storage_exceeded(exceedance, readback);
                                break 'run RunSpoolState::Failed;
                            }
                            Ok(None) => {}
                            Err(()) => break 'run RunSpoolState::Failed,
                        }
                        if draining.load(Ordering::Acquire) {
                            // The daemon is stopping and nobody is executing:
                            // this turn is waiting for a person. The request
                            // is not answered on their behalf — an empty line
                            // is an answer, and a fabricated one — and it is
                            // not cancelled either, which the host refuses
                            // while a request is pending. It is left exactly
                            // as it was, and the close below records why.
                            close_reason = DAEMON_DRAINING_REASON;
                            break 'run RunSpoolState::Cancelled;
                        }
                        let forced_state = if cancellation.is_cancelled() {
                            Some(RunSpoolState::Cancelled)
                        } else if started_at.elapsed() >= timeout {
                            Some(RunSpoolState::TimedOut)
                        } else {
                            None
                        };
                        if let Some(state) = forced_state {
                            let _ = host.respond_stdin(
                                request.request_id(),
                                "",
                                "automonique-control-stop",
                                crate::unix_millis().unwrap_or(now_ms),
                                Duration::from_millis(100),
                            );
                            writer.project(&mut mapper, host.take_events());
                            match poll_jcode_temporary_storage(
                                &mut host,
                                &mut last_temporary_storage_checkpoint,
                                true,
                            ) {
                                Ok(Some((exceedance, readback))) => {
                                    writer.temporary_storage_exceeded(exceedance, readback);
                                    break 'run RunSpoolState::Failed;
                                }
                                Ok(None) => {}
                                Err(()) => break 'run RunSpoolState::Failed,
                            }
                            break 'run state;
                        }
                        match control.receiver.try_recv() {
                            Ok(command) => {
                                let response = host.respond_stdin(
                                    request.request_id(),
                                    &command.content,
                                    "automonique-control-lease",
                                    crate::unix_millis().unwrap_or(now_ms),
                                    Duration::from_millis(100),
                                );
                                let events = host.take_events();
                                match poll_jcode_temporary_storage(
                                    &mut host,
                                    &mut last_temporary_storage_checkpoint,
                                    false,
                                ) {
                                    Ok(Some((exceedance, readback))) => {
                                        writer.project(&mut mapper, events);
                                        writer.temporary_storage_exceeded(exceedance, readback);
                                        let _ = command
                                            .response
                                            .send(Err(SteerRefusal::ProviderRefused));
                                        break 'run RunSpoolState::Failed;
                                    }
                                    Ok(None) => {
                                        writer.project_turn_outcome(&mut mapper, events, &response)
                                    }
                                    Err(()) => {
                                        let _ = command
                                            .response
                                            .send(Err(SteerRefusal::ProviderRefused));
                                        break 'run RunSpoolState::Failed;
                                    }
                                }
                                match response {
                                    Ok(JcodeTurnOutcome::Pending) => {
                                        let _ = command.response.send(Ok(()));
                                        continue 'run;
                                    }
                                    Ok(JcodeTurnOutcome::InputRequired(next)) => {
                                        let _ = command.response.send(Ok(()));
                                        request = next;
                                        continue 'input;
                                    }
                                    Ok(JcodeTurnOutcome::Completed(result)) => {
                                        let _ = command.response.send(Ok(()));
                                        if write_jcode_answer(&answer_path, result.text()).is_err()
                                        {
                                            break 'run RunSpoolState::Failed;
                                        }
                                        break 'run RunSpoolState::Completed;
                                    }
                                    Ok(JcodeTurnOutcome::Cancelled) => {
                                        let _ = command.response.send(Ok(()));
                                        break 'run RunSpoolState::Cancelled;
                                    }
                                    Ok(
                                        JcodeTurnOutcome::ApprovalRequired(_)
                                        | JcodeTurnOutcome::InterruptedUnknown(_),
                                    )
                                    | Err(_) => {
                                        let _ = command
                                            .response
                                            .send(Err(SteerRefusal::ProviderRefused));
                                        break 'run RunSpoolState::Failed;
                                    }
                                }
                            }
                            Err(TryRecvError::Empty) => {
                                std::thread::sleep(Duration::from_millis(100));
                            }
                            Err(TryRecvError::Disconnected) => {
                                break 'run RunSpoolState::Failed;
                            }
                        }
                    }
                },
                Ok(JcodeTurnOutcome::ApprovalRequired(request)) => {
                    let requested_at = crate::unix_millis().unwrap_or(now_ms);
                    let (approvals, approval_key) =
                        match approval.propose(&run_id, &request, requested_at) {
                            Ok(proposal) => proposal,
                            Err(()) => break RunSpoolState::Failed,
                        };
                    writer.approval_waiting(
                        &approval_key,
                        request.tool_name(),
                        request.description(),
                    );
                    let (decision, forced_state) = loop {
                        match poll_jcode_temporary_storage(
                            &mut host,
                            &mut last_temporary_storage_checkpoint,
                            false,
                        ) {
                            Ok(Some((exceedance, readback))) => {
                                writer.temporary_storage_exceeded(exceedance, readback);
                                break 'run RunSpoolState::Failed;
                            }
                            Ok(None) => {}
                            Err(()) => break 'run RunSpoolState::Failed,
                        }
                        while let Ok(command) = control.receiver.try_recv() {
                            // Provider permission is a serialized protocol pause.
                            // Refuse concurrent steering immediately instead of
                            // leaving the lease holder to time out ambiguously.
                            let _ = command.response.send(Err(SteerRefusal::ProviderRefused));
                        }
                        if draining.load(Ordering::Acquire) {
                            // Same rule as the input wait: a stopping daemon
                            // decides nothing for the operator. The durable
                            // approval stays pending in its store, where it
                            // was proposed, and the journal records that this
                            // host abandoned the wait.
                            close_reason = DAEMON_DRAINING_REASON;
                            break 'run RunSpoolState::Cancelled;
                        }
                        if cancellation.is_cancelled() {
                            break (
                                automonique_agents::PermissionDecision::Deny,
                                Some(RunSpoolState::Cancelled),
                            );
                        }
                        if started_at.elapsed() >= timeout {
                            break (
                                automonique_agents::PermissionDecision::Deny,
                                Some(RunSpoolState::TimedOut),
                            );
                        }
                        let record = match approvals.entry(&approval_key) {
                            Ok(Some(record)) => record,
                            Ok(None) | Err(_) => break 'run RunSpoolState::Failed,
                        };
                        match record.state {
                            ApprovalState::Granted => {
                                break (automonique_agents::PermissionDecision::Allow, None);
                            }
                            ApprovalState::Denied | ApprovalState::Expired => {
                                break (automonique_agents::PermissionDecision::Deny, None);
                            }
                            ApprovalState::Pending => {
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                    };
                    let decided = host.decide_permission(
                        request.request_id(),
                        decision,
                        "automonique-approval",
                        crate::unix_millis().unwrap_or(now_ms),
                        Duration::from_millis(100),
                    );
                    let events = host.take_events();
                    match poll_jcode_temporary_storage(
                        &mut host,
                        &mut last_temporary_storage_checkpoint,
                        false,
                    ) {
                        Ok(Some((exceedance, readback))) => {
                            writer.project(&mut mapper, events);
                            writer.temporary_storage_exceeded(exceedance, readback);
                            break 'run RunSpoolState::Failed;
                        }
                        Ok(None) if forced_state.is_none() => {
                            writer.project_turn_outcome(&mut mapper, events, &decided);
                        }
                        Ok(None) => writer.project(&mut mapper, events),
                        Err(()) => break 'run RunSpoolState::Failed,
                    }
                    if let Some(state) = forced_state {
                        if state == RunSpoolState::Cancelled
                            && matches!(decided, Ok(JcodeTurnOutcome::Pending))
                        {
                            let _ = host.cancel(
                                crate::unix_millis().unwrap_or(now_ms),
                                Duration::from_millis(100),
                            );
                            writer.project(&mut mapper, host.take_events());
                            match poll_jcode_temporary_storage(
                                &mut host,
                                &mut last_temporary_storage_checkpoint,
                                true,
                            ) {
                                Ok(Some((exceedance, readback))) => {
                                    writer.temporary_storage_exceeded(exceedance, readback);
                                    break 'run RunSpoolState::Failed;
                                }
                                Ok(None) => {}
                                Err(()) => break 'run RunSpoolState::Failed,
                            }
                        }
                        break state;
                    }
                    match decided {
                        Ok(JcodeTurnOutcome::Completed(result)) => {
                            if write_jcode_answer(&answer_path, result.text()).is_err() {
                                break RunSpoolState::Failed;
                            }
                            break RunSpoolState::Completed;
                        }
                        Ok(JcodeTurnOutcome::Cancelled) => break RunSpoolState::Cancelled,
                        Ok(
                            JcodeTurnOutcome::Pending
                            | JcodeTurnOutcome::ApprovalRequired(_)
                            | JcodeTurnOutcome::InputRequired(_),
                        ) => {}
                        Ok(JcodeTurnOutcome::InterruptedUnknown(_)) => {
                            break RunSpoolState::Failed;
                        }
                        Err(_) => break RunSpoolState::Failed,
                    }
                }
                Err(_) => break RunSpoolState::Failed,
            }
        };
        for (_, response) in pending_steers {
            let _ = response.send(Err(SteerRefusal::SessionNotLive));
        }
        drop(control);
        let (mut final_state, temporary_storage) = match host
            .close_with_reason_and_temporary_storage(
                crate::unix_millis().unwrap_or(now_ms),
                close_reason,
            ) {
            Ok(outcome) => (final_state, outcome),
            Err(_) => (RunSpoolState::Failed, None),
        };
        // Reconciliation is the last observer. If the provider crossed the
        // ceiling while closing, retain the typed refusal and do not let the
        // earlier provider/control outcome overwrite it.
        if let Some(outcome) = temporary_storage.as_ref()
            && let Some(exceedance) = outcome.ledger.first_exceedance()
        {
            writer.temporary_storage_exceeded(exceedance, Some(outcome.statfs_from_ledger));
            final_state = RunSpoolState::Failed;
        }
        writer.finish_with_temporary_storage(final_state, temporary_storage)
    }
}

fn finish_failed_jcode_host(
    host: JcodeSessionHost,
    writer: JcodeSpoolWriter,
    fallback_now_ms: i64,
) -> AttemptExecution {
    match host.close_with_reason_and_temporary_storage(
        crate::unix_millis().unwrap_or(fallback_now_ms),
        HOST_CLOSED_REASON,
    ) {
        Ok(temporary_storage) => {
            writer.finish_with_temporary_storage(RunSpoolState::Failed, temporary_storage)
        }
        Err(_) => writer.finish(RunSpoolState::Failed),
    }
}

trait JcodeTemporaryStorageHost {
    fn checkpoint_temporary_storage(&mut self) -> Result<(), ()>;
    fn temporary_storage_exceedance(&self) -> Option<Exceedance>;
    fn temporary_storage_readback(&self) -> Option<StatfsReadback>;
}

impl JcodeTemporaryStorageHost for JcodeSessionHost {
    fn checkpoint_temporary_storage(&mut self) -> Result<(), ()> {
        JcodeSessionHost::checkpoint_temporary_storage(self).map_err(|_| ())
    }

    fn temporary_storage_exceedance(&self) -> Option<Exceedance> {
        JcodeSessionHost::temporary_storage_exceedance(self)
    }

    fn temporary_storage_readback(&self) -> Option<StatfsReadback> {
        JcodeSessionHost::temporary_storage_readback(self)
    }
}

fn poll_jcode_temporary_storage<H: JcodeTemporaryStorageHost>(
    host: &mut H,
    last_checkpoint: &mut Instant,
    force_checkpoint: bool,
) -> Result<Option<(Exceedance, Option<StatfsReadback>)>, ()> {
    if let Some(exceedance) = host.temporary_storage_exceedance() {
        host.checkpoint_temporary_storage()?;
        *last_checkpoint = Instant::now();
        return Ok(Some((exceedance, host.temporary_storage_readback())));
    }
    if force_checkpoint
        || last_checkpoint.elapsed()
            >= automonique_runner::backend::TEMPORARY_STORAGE_CHECKPOINT_INTERVAL
    {
        host.checkpoint_temporary_storage()?;
        *last_checkpoint = Instant::now();
    }
    Ok(None)
}

struct JcodeSpoolWriter {
    spool: Spool,
    frame_run_id: FrameRunId,
    publisher: Box<dyn ProgressPublisher>,
    observed: ObservedSequence,
    progress_stopped: bool,
    refused_destination: Option<RefusedDestinationObserver>,
    refused_destination_cursor: Option<RefusedDestinationCursor>,
}

impl JcodeSpoolWriter {
    fn started(&mut self, pid: u32) -> Result<(), ()> {
        let recorded = self
            .spool
            .append(
                SpoolEventKind::Started,
                SpoolAuthority::Authoritative,
                format!("{STARTED_PAYLOAD_PREFIX}{pid}").as_bytes(),
            )
            .map_err(|_| ())?;
        self.observed.observe(recorded.sequence());
        Ok(())
    }

    /// Surface a durable provider approval as the pause frame its kind admits.
    ///
    /// The label leads with the approval key, because the key is what a
    /// consumer acts on — the ACP bridge and the AG-UI adapter both read it
    /// from this exact prefix and then resolve the approval through the
    /// approval lane, never from the frame alone. The tool and its description
    /// are provider-originated and travel only as the bounded, sanitized label
    /// every other kind's text is.
    fn approval_waiting(&mut self, key: &str, tool: &str, description: &str) {
        let text = ProgressText::sanitized(&format!("approval {key}: {tool} — {description}"));
        self.pause_frame(
            automonique_protocol::event::EventKind::ApprovalRequested,
            text,
        );
    }

    /// Surface the provider input request now blocking the turn.
    ///
    /// The prompt is the label, sanitized and bounded like any other. A masked
    /// request carries no label at all: the protocol admits the absence, and a
    /// placeholder would be a second thing a renderer had to know not to show.
    /// No identifier travels either — the lease holder's next input answers
    /// the request the lane is waiting on, and the journal holds the request
    /// key for anyone reconstructing the wait.
    fn input_waiting(&mut self, request: &JcodeInputRequest) {
        let text = if request.is_password() {
            None
        } else {
            ProgressText::sanitized(request.prompt())
        };
        self.pause_frame(automonique_protocol::event::EventKind::InputRequested, text);
    }

    /// Append one authoritative pause frame, with or without its label.
    ///
    /// Unlike a projected provider event, a wait the lane cannot surface is a
    /// wait the operator never learns about, so the body is built the way the
    /// kind declares rather than guessed: a label the kind refuses is dropped
    /// and the bare frame still goes out.
    fn pause_frame(
        &mut self,
        kind: automonique_protocol::event::EventKind,
        text: Option<ProgressText>,
    ) {
        let body = ProgressBody::new(
            kind,
            ProgressBodyParts {
                text,
                step: None,
                retry: None,
            },
        )
        .or_else(|_| ProgressBody::empty(kind));
        let Ok(body) = body else {
            return;
        };
        if self
            .append_frame(&CapturedFrame {
                authority: FrameAuthority::Authoritative,
                kind,
                body,
            })
            .is_err()
        {
            self.stop_progress();
        }
    }

    fn steered(&mut self) {
        let Ok(body) = ProgressBody::new(
            automonique_protocol::event::EventKind::TurnSteered,
            ProgressBodyParts {
                text: None,
                step: None,
                retry: None,
            },
        ) else {
            return;
        };
        if self
            .append_frame(&CapturedFrame {
                authority: FrameAuthority::Authoritative,
                kind: automonique_protocol::event::EventKind::TurnSteered,
                body,
            })
            .is_err()
        {
            self.stop_progress();
        }
    }

    fn project(
        &mut self,
        mapper: &mut JcodeProgressMapper,
        events: Vec<automonique_agents::JcodeEvent>,
    ) {
        self.project_events(mapper, events, false);
    }

    fn project_turn_outcome(
        &mut self,
        mapper: &mut JcodeProgressMapper,
        events: Vec<automonique_agents::JcodeEvent>,
        outcome: &Result<JcodeTurnOutcome, JcodeHostError>,
    ) {
        self.project_events(
            mapper,
            events,
            matches!(outcome, Err(JcodeHostError::ProviderRefused)),
        );
    }

    fn project_events(
        &mut self,
        mapper: &mut JcodeProgressMapper,
        events: Vec<automonique_agents::JcodeEvent>,
        terminal_provider_refusal: bool,
    ) {
        let correlated_faults = events
            .iter()
            .filter(|event| matches!(event, automonique_agents::JcodeEvent::Error { .. }))
            .count();
        for event in events {
            let correlated_terminal_fault = terminal_provider_refusal
                && correlated_faults == 1
                && matches!(event, automonique_agents::JcodeEvent::Error { .. });
            if let Some(frame) = mapper
                .project_event(event)
                .map(|frame| self.with_refused_destination(frame, correlated_terminal_fault))
                && self.append_frame(&frame).is_err()
            {
                self.stop_progress();
            }
        }
    }

    fn begin_provider_request(&mut self) {
        self.refused_destination_cursor = self
            .refused_destination
            .as_ref()
            .and_then(RefusedDestinationObserver::cursor);
    }

    /// Replace a generic provider fault with the exact bounded destination
    /// this run's own broker refused. The observation contains only the parsed
    /// CONNECT authority; no provider text, header, credential, address, or
    /// payload crosses this boundary.
    fn with_refused_destination(
        &mut self,
        frame: CapturedFrame,
        correlated_terminal_fault: bool,
    ) -> CapturedFrame {
        describe_refused_destination(
            frame,
            self.refused_destination.as_ref(),
            self.refused_destination_cursor.as_mut(),
            correlated_terminal_fault,
        )
    }

    fn stop_progress(&mut self) {
        if self.progress_stopped {
            return;
        }
        let body = ProgressBody::new(
            automonique_protocol::event::EventKind::ProviderWarning,
            ProgressBodyParts {
                text: ProgressText::new(PROGRESS_BUDGET_WARNING).ok(),
                step: None,
                retry: RetryContext::new(RetryCategory::Internal, false, None, 1).ok(),
            },
        );
        if self.spool.remaining_bytes() > PROGRESS_TERMINAL_RESERVE_BYTES
            && let Ok(body) = body
        {
            let _ = self.append_frame(&CapturedFrame {
                authority: FrameAuthority::Synthetic,
                kind: automonique_protocol::event::EventKind::ProviderWarning,
                body,
            });
        }
        self.progress_stopped = true;
    }

    /// Record the one warning a temporary-storage exceedance leaves: the
    /// refusal as the ledger spelled it and the mount's bounded `statvfs`, as
    /// the last word before the `failed` terminal event. Recorded past the
    /// progress latch, because this frame is not progress but the reason the
    /// run has no more of it; still under the spool's reserves, so the
    /// terminal event is never crowded out.
    fn temporary_storage_exceeded(
        &mut self,
        exceedance: Exceedance,
        readback: Option<automonique_runner::StatfsReadback>,
    ) {
        let readback = readback.ok_or(automonique_runner::ReadbackError::ThreadUnavailable);
        if let Some(frame) = temporary_storage_exceeded_frame(exceedance, &readback) {
            let _ = self.append_frame_past_latch(&frame);
        }
    }

    fn append_frame(&mut self, frame: &CapturedFrame) -> Result<(), ()> {
        if self.progress_stopped {
            return Err(());
        }
        self.append_frame_past_latch(frame)
    }

    fn append_frame_past_latch(&mut self, frame: &CapturedFrame) -> Result<(), ()> {
        let remaining = self.spool.remaining_bytes();
        if remaining <= PROGRESS_TERMINAL_RESERVE_BYTES
            || (frame.authority == FrameAuthority::Synthetic
                && remaining <= PROGRESS_PREVIEW_RESERVE_BYTES)
        {
            return Err(());
        }
        let sequence = self
            .spool
            .status()
            .last_sequence()
            .checked_add(1)
            .ok_or(())?;
        let at_ms = crate::unix_millis().map_err(|_| ())?;
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
        let recorded = self
            .spool
            .append(
                SpoolEventKind::AdapterEvent,
                match frame.authority {
                    FrameAuthority::Authoritative => SpoolAuthority::Authoritative,
                    FrameAuthority::Synthetic => SpoolAuthority::Synthetic,
                },
                &payload,
            )
            .map_err(|_| ())?;
        self.observed.observe(recorded.sequence());
        self.publisher.publish(recorded.sequence(), &payload);
        Ok(())
    }

    fn finish(self, state: RunSpoolState) -> AttemptExecution {
        self.finish_with_temporary_storage(state, None)
    }

    fn finish_with_temporary_storage(
        mut self,
        state: RunSpoolState,
        temporary_storage: Option<NamespacedOutcome>,
    ) -> AttemptExecution {
        let payload = match state {
            RunSpoolState::Completed => TERMINAL_COMPLETED,
            RunSpoolState::Cancelled => TERMINAL_CANCELLED,
            RunSpoolState::TimedOut => TERMINAL_TIMED_OUT,
            RunSpoolState::Failed | RunSpoolState::Ready | RunSpoolState::Running => {
                TERMINAL_FAILED
            }
        };
        if self
            .spool
            .append(
                SpoolEventKind::Terminal,
                SpoolAuthority::Authoritative,
                payload,
            )
            .is_err()
        {
            return AttemptExecution {
                state: RunSpoolState::Failed,
                last_sequence: self.observed.get(),
                temporary_storage,
            };
        }
        let status = self.spool.status();
        self.observed.observe(status.last_sequence());
        AttemptExecution {
            state,
            last_sequence: status.last_sequence(),
            temporary_storage,
        }
    }
}

fn describe_refused_destination(
    frame: CapturedFrame,
    observer: Option<&RefusedDestinationObserver>,
    cursor: Option<&mut RefusedDestinationCursor>,
    correlated_terminal_fault: bool,
) -> CapturedFrame {
    if frame.kind != automonique_protocol::event::EventKind::ProviderFault
        || !correlated_terminal_fault
    {
        return frame;
    }
    let Some((observer, cursor)) = observer.zip(cursor) else {
        return frame;
    };
    let RefusedDestinationWindow::Unambiguous(refused) = observer.take_since(cursor) else {
        return frame;
    };
    let Some(text) = ProgressText::new(format!(
        "provider route refused destination {}:{}",
        refused.host(),
        refused.port()
    ))
    .ok() else {
        return frame;
    };
    let Ok(body) = ProgressBody::new(
        frame.kind,
        ProgressBodyParts {
            text: Some(text),
            step: frame.body.step(),
            retry: frame.body.retry(),
        },
    ) else {
        return frame;
    };
    CapturedFrame {
        authority: frame.authority,
        kind: frame.kind,
        body,
    }
}

fn write_jcode_answer(path: &Path, text: &str) -> Result<(), ()> {
    if text.is_empty()
        || u64::try_from(text.len())
            .map_or(true, |length| length > crate::compose::MAX_ANSWER_BYTES)
    {
        return Err(());
    }
    let mut options = fs::OpenOptions::new();
    options
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| ())?;
    file.write_all(text.as_bytes()).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}

impl Drop for LiveClaim {
    fn drop(&mut self) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(&self.run_id);
        }
    }
}

/// One attempt that already exists, and everything its worker thread owns.
///
/// Holding this value means the cancellation registration is live, the run
/// cgroup exists with the document's ceilings applied, and the spool is empty
/// and exclusively locked. All three were established on the serve thread
/// before the caller was answered, so a worker holding one has nothing left to
/// refuse — it runs, and it records.
struct Attempt {
    run_id: String,
    attempt_id: String,
    submission_id: i64,
    revision: u64,
    timeout: Duration,
    cancellation: CancellationToken,
    /// Owns the cancellation registration. Dropping it — on any path out,
    /// including a panic — releases the attempt from the host's registry.
    registration: RegistrationHandle,
    prepared: PreparedAttempt,
    /// The spool position this attempt has actually reached, readable after a
    /// supervision failure has taken the report away.
    observed: ObservedSequence,
    /// Where live frames are retained while the spool is locked, and which is
    /// told to forget this attempt once it is not.
    progress: Arc<ProgressHub>,
    /// Host whose durable cancellation rows are retired after terminality.
    attempt_host: Arc<DaemonAttemptHost>,
    /// This run's own broker, when its document asked for egress. Owning it
    /// here is what bounds its lifetime to the run: every path out of this
    /// worker drops it, including a panic, and its drop stops the listener and
    /// tears down every tunnel still open.
    broker: Option<EgressBroker>,
    /// Exact provider session observed by the normalized stream.
    session_capture: Arc<Mutex<Option<String>>>,
    /// Where the session binding lives.  An independent durable connection is
    /// opened against it once the run becomes terminal, to settle the binding
    /// this run's own worker advanced at turn start.
    managed_sessions_path: PathBuf,
    /// Where this run's provider-permission proposals live, so the ones it
    /// leaves unanswered can be closed when it becomes terminal.
    approval_requests_path: PathBuf,
    /// The lane's drain flag; see [`ExecutionLane::begin_shutdown`].
    draining: Arc<AtomicBool>,
}

impl Attempt {
    /// Run to a terminal state, then report it to the read model.
    ///
    /// Nothing here returns a result. The worker's whole output is durable: the
    /// run's spool holds what happened, and the read model holds what a writer
    /// observed. A failure this function cannot record is a failure nobody
    /// could have read anyway.
    fn run(self, index_path: &Path) {
        let Self {
            run_id,
            attempt_id,
            submission_id,
            revision,
            timeout,
            cancellation,
            registration,
            prepared,
            observed,
            progress,
            attempt_host,
            broker,
            session_capture,
            managed_sessions_path,
            approval_requests_path,
            draining,
        } = self;

        let report = prepared.execute(&cancellation, timeout, &draining);
        if let Some(outcome) = report.temporary_storage.as_ref() {
            let _ = crate::structured_log::emit_temporary_storage_reconciled(
                &run_id,
                &crate::structured_log::TemporaryStorageReconciliation::from_namespaced(outcome),
            );
        }
        // The spool's lock is free from here, so the durable record is readable
        // and strictly better than the window this hub was holding: complete,
        // hash-chain verified, and not subject to eviction.
        progress.retire(&run_id);
        // THE BROKER OUTLIVES NO RUN.
        //
        // Torn down here, explicitly, on the one path every terminal state
        // reaches: a completion, a failure, a timeout and a cancellation all
        // return from `execute` before this line. A panic before it drops the
        // same value through the unwinding frame, and a worker this daemon
        // never spawned drops it on the serve thread — so there is no path on
        // which the listener outlives the workload it was bound for. The
        // teardown is bounded: it stops the accept loop, shuts down both ends
        // of every in-flight tunnel, and joins the threads it started.
        drop(broker);
        // The registration is released before the read model is advanced: an
        // attempt whose row says it ended must not still be cancellable.
        drop(registration);

        // The spool was dropped inside `execute`, so its exclusive lock is
        // free by the time the row moves. That ordering is what lets the Runs
        // lane read the lifecycle of a run its listing calls terminal.
        let state = report.state;
        let last_sequence = if report.last_sequence == 0 {
            observed.get()
        } else {
            report.last_sequence
        };
        // THE RUN'S PERMISSIONS DO NOT OUTLIVE THE RUN.
        //
        // A provider permission is proposed by this worker so that *this* run's
        // paused turn can continue, and it is answerable only while the run is
        // there to act on the answer. Once the run is terminal — stopped by an
        // operator, timed out, or failed — a row still `pending` is a live
        // question about a dead run: the session's command state goes on
        // projecting it, and an operator can still be asked to answer something
        // that can no longer have an effect.
        //
        // It is closed as an EXPIRY rather than a decision, and that is the
        // store's own distinction rather than a shortcut:
        // `ApprovalRequests::decide` demands the ledger key of whoever decided,
        // and nobody did — the run ended. An expiry is the absence of an
        // answer, which is exactly what happened, and it is the state
        // `pending_for_run` and `is_answerable_at` already exclude.
        //
        // A DRAINING daemon is the one exception, and it is the same rule the
        // approval wait itself keeps a few frames up: a stopping daemon decides
        // nothing for the operator, so the proposal stays pending where it was
        // written, for the next generation to answer.
        if !draining.load(Ordering::Acquire) {
            expire_unanswered_approvals(&approval_requests_path, &run_id);
        }
        // The turn is over, whichever way it ended. Settling every terminal
        // state, not only a completion, is what keeps the binding honest after
        // turn-start binding: a run bound in flight that then failed, timed out
        // or was cancelled would otherwise leave its session permanently
        // claiming a live run. The run named does not change here — this worker
        // bound it at turn start — so a failure settles exactly where a
        // completion does, and a run whose provider session was never observed
        // still writes nothing at all.
        if let Ok(captured) = session_capture.lock()
            && let Some(provider_session_id) = captured.as_deref()
            && let Ok(now_ms) = crate::unix_millis()
            && let Ok(mut sessions) =
                crate::managed_sessions::ManagedSessionStore::open(&managed_sessions_path)
        {
            let _ = sessions.observe_terminal(provider_session_id, &run_id, now_ms);
        }
        advance(index_path, submission_id, revision, state, last_sequence);
        // The process and spool are terminal and the registration is already
        // gone, so no caller can reach this attempt again. Failure is safe: it
        // retains replay evidence and only costs bounded-ledger capacity.
        let _ = attempt_host.prune_terminal_attempt(&attempt_id);
    }
}

/// The argument that makes a workload's stdout the normalized event grammar.
///
/// The provider writes prose by default and one JSON object per line when this
/// is present. Which of the two it is deciding is not something this daemon can
/// discover from a document any other way: the event dialect a RunSpec declares
/// has one member and says nothing about stdout, and the program is an opaque
/// pinned path.
pub const PROVIDER_JSON_STREAM_ARG: &str = "--json";
pub const JCODE_API_STDIO_ARG: &str = "api-stdio";
pub const JCODE_INTEGRATION_MODE: &str = "jcode-api-stdio-v1";
pub const JCODE_RESUME_ENV: &str = "AUTOMONIQUE_JCODE_SESSION_ID";

fn jcode_session_mode(spec: &RunSpec) -> Result<bool, ExecuteRefusal> {
    let declared = spec.admission().integration_mode().as_str() == JCODE_INTEGRATION_MODE;
    let invoked = spec
        .arguments()
        .iter()
        .any(|argument| argument == JCODE_API_STDIO_ARG);
    if declared != invoked {
        return Err(ExecuteRefusal::AdmissionRefused);
    }
    Ok(declared)
}

fn jcode_resume_session(spec: &RunSpec) -> Result<Option<String>, ExecuteRefusal> {
    let Some((_, value)) = spec
        .environment()
        .iter()
        .find(|(name, _)| name == JCODE_RESUME_ENV)
    else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .filter(|value| !value.is_empty())
        .ok_or(ExecuteRefusal::AdmissionRefused)?;
    automonique_protocol::platform::ResourceId::new(value)
        .map_err(|_| ExecuteRefusal::AdmissionRefused)?;
    Ok(Some(value.to_owned()))
}

/// Whether this document's workload writes a stream this daemon can normalize.
///
/// A conservative gate, and deliberately so. Capturing stdout from a workload
/// that writes prose would pipe a descriptor that was previously the
/// supervisor's own, hand the bytes to a refusal-first parser that rejects the
/// first line, and produce one warning frame per run — all cost, no stream. The
/// document has to ask.
#[must_use]
pub fn emits_normalized_stream(spec: &RunSpec) -> bool {
    spec.arguments()
        .iter()
        .any(|argument| argument == PROVIDER_JSON_STREAM_ARG)
}

/// Build the capture one document's attempt gets, or answer that it gets none.
///
/// `None` for a run whose identity or scope the adapter's own coordinate
/// grammar refuses. That is a reason to run without progress rather than a
/// reason not to run: the coordinates are a rendering detail, and a document
/// that admission accepted is a document this daemon executes.
fn progress_capture(
    spec: &RunSpec,
    run_id: &str,
    hub: &Arc<ProgressHub>,
    session_capture: Arc<Mutex<Option<String>>>,
) -> Option<ProgressCapture> {
    // The scope is this daemon's own deployment identity rather than anything
    // the document supplies: it names where the events came from, and a
    // document-supplied value would be a caller choosing how its own output is
    // labelled.
    let scope = automonique_agents::SessionScope::new(
        PROGRESS_SCOPE_TENANT,
        PROGRESS_SCOPE_ACCOUNT,
        PROGRESS_SCOPE_NAMESPACE,
    )
    .ok()?;
    let coordinates =
        automonique_agents::RunCoordinates::new(run_id, spec.attempt_id().as_str(), scope).ok()?;
    // Every run this lane starts is a fresh provider session: the composed
    // invocation carries no resume binding, and claiming one would make the
    // normalizer demand a session identity the provider will not report.
    let mode = automonique_agents::ExecutionMode::NewSession;
    Some(
        ProgressCapture::new(Box::new(
            ProviderProgressMapper::new(&coordinates, &mode).with_session_capture(session_capture),
        ))
        .publishing_to(hub.publisher(run_id)),
    )
}

/// The deployment identity progress events are labelled with.
///
/// Fixed rather than configured: it exists so the adapter's coordinate grammar
/// has something well-formed to hold, and nothing downstream routes on it.
const PROGRESS_SCOPE_TENANT: &str = "automonique";
const PROGRESS_SCOPE_ACCOUNT: &str = "daemon";
const PROGRESS_SCOPE_NAMESPACE: &str = "run-lane";

/// Translate one registration failure into the refusal that names it.
///
/// Every arm is a real distinction a caller acts on differently: a duplicate is
/// an attempt already live, the limit is a full host, and an identifier the
/// registry cannot hold is a document this daemon will not run — because a run
/// it cannot register is a run it cannot cancel, and starting one would be the
/// silent downgrade this lane exists to refuse.
const fn registration_refusal(error: crate::attempt_host::AttemptHostError) -> ExecuteRefusal {
    use crate::attempt_host::AttemptHostError;
    match error {
        AttemptHostError::DuplicateAttempt => ExecuteRefusal::AlreadyExecuting,
        AttemptHostError::RegistrationLimit => ExecuteRefusal::LaneSaturated,
        AttemptHostError::InvalidAttemptId => ExecuteRefusal::AdmissionRefused,
        AttemptHostError::LedgerUnavailable(_)
        | AttemptHostError::UnknownAttempt
        | AttemptHostError::Poisoned => ExecuteRefusal::ExecutionUnavailable,
    }
}

/// Translate one admission refusal into the refusal that names it.
///
/// Admission judges the document against this host, and nearly everything it
/// refuses is the document's to fix, so the lane reports it as
/// `admission_refused`. One arm is the host's instead: a temporary-storage
/// budget the host cannot enforce — no `/dev/fuse`, no setuid `fusermount3` —
/// refuses every document this daemon is asked to run, and an operator staring
/// at that host needs the host-wide word, `sandbox_unenforceable`, not one that
/// sends them back to re-read a document that was fine. The prerequisite
/// failure the runner quotes stops here: the wire refusal carries no reason.
const fn admission_refusal(refusal: &AdmissionRefusal) -> ExecuteRefusal {
    match refusal {
        AdmissionRefusal::TemporaryStorageUnenforceable(_) => ExecuteRefusal::SandboxUnenforceable,
        _ => ExecuteRefusal::AdmissionRefused,
    }
}

/// Move one read-model row from `ready` to its terminal state.
///
/// # Why two advances
///
/// `run_index`'s lattice is `ready -> running -> terminal`, and it refuses a
/// jump. That is not an obstacle to work around, it is the model being honest:
/// a row that went straight from `ready` to `completed` would claim a run with
/// no `Started` event, which is a shape the spool cannot produce.
///
/// So the row is walked. `running` is reported at sequence one, which is the
/// `Started` event the backend appended before it waited, and the terminal
/// state at whatever sequence the spool actually reached. Both are things this
/// writer observed; neither is invented.
///
/// # Why a second connection
///
/// The serve thread holds the daemon's own [`RunIndex`], and this runs on a
/// worker. Rather than share it behind a lock — which would put a worker in a
/// position to stall the accept loop — the worker opens the same file again.
/// SQLite serialises the two writers, and every advance is compare-and-set on
/// the durable revision, so the worst a race can do is refuse an advance, never
/// silently overwrite one.
///
/// # Why failure is silent
///
/// The run already happened and its spool already says so. A read model that
/// could not be extended is a *listing* that is behind, which
/// `automonique_store::run_index` describes as rebuildable from custody. There
/// is nobody left to answer: the requester was acknowledged before the attempt
/// started.
fn advance(
    index_path: &Path,
    submission_id: i64,
    revision: u64,
    state: RunSpoolState,
    last_sequence: u64,
) {
    let Ok(now_ms) = crate::unix_millis() else {
        return;
    };
    let Ok(mut index) = RunIndex::open(index_path) else {
        return;
    };
    let running = index.advance_state(StateAdvance {
        submission_id,
        expected_revision: revision,
        new_state: RunSpoolState::Running,
        last_sequence: 1,
        now_ms,
    });
    let Ok(running) = running else {
        return;
    };
    // A terminal spool state is reported at the sequence the spool reached; a
    // run somehow still `running` is left where the first advance put it.
    if !state.is_terminal() {
        return;
    }
    let _ = index.advance_state(StateAdvance {
        submission_id,
        expected_revision: running.revision,
        new_state: state,
        last_sequence: last_sequence.max(running.last_sequence.saturating_add(1)),
        now_ms,
    });
}

/// Close every provider permission this terminated run left unanswered.
///
/// Scoped to the proposals this run's own worker wrote
/// ([`PROVIDER_APPROVAL_PROPOSER`]). An approval raised by another stage of the
/// run's life — the launch gate, which asks whether the run may start at all —
/// is answerable without an executing attempt and is none of this worker's
/// business to close.
///
/// Each row is fenced on the revision it was read at, so an approval an
/// operator decided in the same instant keeps exactly the decision they made,
/// and a second pass over an already-closed row changes nothing. One page is
/// the whole set: a turn pauses on one permission at a time and does not
/// propose the next until that one is answered.
///
/// Best-effort, like every other durable write on this path. The run is over
/// either way, and an expiry that could not be written is still bounded by the
/// deadline the proposal already carries.
fn expire_unanswered_approvals(store_path: &Path, run_id: &str) {
    let Ok(now_ms) = crate::unix_millis() else {
        return;
    };
    let Ok(mut approvals) = ApprovalRequests::open(store_path) else {
        return;
    };
    let Ok(pending) = approvals.pending_for_run(run_id, now_ms, MAX_APPROVAL_REQUEST_PAGE) else {
        return;
    };
    for record in pending {
        if record.requested_by != PROVIDER_APPROVAL_PROPOSER {
            continue;
        }
        let _ = approvals.expire(&record.request_key, record.revision, now_ms);
    }
}

/// The cancellation destination: the very token the backend polls.
///
/// Setting the token is the whole delivery, exactly as the runner's own
/// supervisor does it. The kill, the drain and the terminal record all stay in
/// the backend's disposal path, so this sink touches no containment handle and
/// no spool — which is also what keeps it inside the dispatcher's bounded-time
/// sink contract.
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
        // The dispatcher only calls the sink its own registration holds, so a
        // mismatch is unreachable; refusing rather than cancelling keeps it
        // that way if that ever stops being true.
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

/// Translate the runner's spool state into the store's, variant by variant.
///
/// Exhaustive on purpose: a state either crate grows is a compile failure here
/// rather than a row that silently records the wrong thing.
const fn spool_state(state: automonique_runner::RunState) -> RunSpoolState {
    match state {
        automonique_runner::RunState::Ready => RunSpoolState::Ready,
        automonique_runner::RunState::Running => RunSpoolState::Running,
        automonique_runner::RunState::Completed => RunSpoolState::Completed,
        automonique_runner::RunState::Failed => RunSpoolState::Failed,
        automonique_runner::RunState::Cancelled => RunSpoolState::Cancelled,
        automonique_runner::RunState::TimedOut => RunSpoolState::TimedOut,
    }
}

/// Create a directory this user owns and nobody else may enter, or accept an
/// existing one that already is.
fn private_directory(path: &Path) -> Result<(), ()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(());
            }
            Ok(())
        }
        Err(_) => Err(()),
    }
}

/// Read a whole regular file, or nothing, refusing above `limit` bytes.
///
/// The size is taken from the opened file's own metadata rather than from a
/// `stat` of the path, so the bound is applied to the file that was actually
/// opened. A symlink, a directory, a device and anything above the limit are
/// all the same answer: no bytes.
fn read_bounded(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || !is_within_byte_limit(metadata.len(), limit) {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    // Bounded by one byte over the limit, so a file that grew between the
    // metadata read and the read itself is refused rather than read whole.
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if !is_within_byte_limit(u64::try_from(bytes.len()).ok()?, limit) {
        return None;
    }
    Some(bytes)
}

/// Find the entry helper by the two routes [`LAUNCH_HELPER_NAME`] documents.
///
/// A candidate is accepted only when it is an absolute path to an existing
/// regular file, so a lane that reports a helper reports one that was there
/// when it looked. Whether it is still there, and whether it is executable, is
/// settled by the kernel at spawn time — any check performed now would be a
/// claim about a later instant.
#[must_use]
pub fn locate_launch_helper() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(LAUNCH_HELPER_ENV).map(PathBuf::from) {
        return explicit
            .is_absolute()
            .then(|| is_regular_file(&explicit).then_some(explicit))
            .flatten();
    }
    let executable = std::env::current_exe().ok()?;
    let beside = executable.parent()?;
    [Some(beside), beside.parent()]
        .into_iter()
        .flatten()
        .map(|directory| directory.join(LAUNCH_HELPER_NAME))
        .find(|candidate| candidate.is_absolute() && is_regular_file(candidate))
}

/// Whether a path names an existing regular file that is not a symlink.
fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// The bounded safe-name rule shared by every identifier this module turns into
/// a filesystem path.
fn is_safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The containment module's own cgroup-name rule, applied before an identifier
/// becomes a directory.
fn is_containment_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= automonique_runner::MAX_RUN_ID_BYTES
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{
        JcodeSpoolWriter, JcodeTemporaryStorageHost, MAX_PROVIDER_BINARY_BYTES, ObservedSequence,
        PROVIDER_APPROVAL_PROPOSER, ProgressFrame, ProgressPublisher, TokenCancelSink,
        admission_refusal, advance, describe_refused_destination, expire_unanswered_approvals,
        is_containment_run_id, is_safe_segment, is_within_byte_limit, poll_jcode_temporary_storage,
        provider_binary_digest, spool_state,
    };
    use crate::attempt_host::DaemonAttemptHost;
    use crate::jcode_session_host::{JcodeHostError, JcodeTurnOutcome};
    use crate::progress::JcodeProgressMapper;
    use automonique_agents::JcodeEvent;
    use automonique_egress_broker::{BrokerConfig, EgressBroker};
    use automonique_protocol::execute_api::ExecuteRefusal;
    use automonique_runner::admission::AdmissionRefusal;
    use automonique_runner::dispatch::DispatchOutcome;
    use automonique_runner::{
        Authority, CancellationToken, EventKind, Exceedance, Spool, StatfsReadback,
        TemporaryStorageResource,
    };
    use automonique_store::approval_requests::{
        ApprovalContext, ApprovalOutcome, ApprovalProposal, ApprovalRequests, ApprovalState,
    };
    use automonique_store::run_index::{RunIndex, RunIndexEntry, RunSpoolState};
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const FAR_FUTURE_MS: i64 = 9_000_000_000_000;

    #[derive(Default)]
    struct FakeJcodeTemporaryStorage {
        exceedance: Option<Exceedance>,
        checkpoint_count: usize,
        refuse_checkpoint: bool,
    }

    struct NoopPublisher;

    impl ProgressPublisher for NoopPublisher {
        fn publish(&self, _sequence: u64, _payload: &[u8]) {}
    }

    impl JcodeTemporaryStorageHost for FakeJcodeTemporaryStorage {
        fn checkpoint_temporary_storage(&mut self) -> Result<(), ()> {
            self.checkpoint_count += 1;
            if self.refuse_checkpoint {
                Err(())
            } else {
                Ok(())
            }
        }

        fn temporary_storage_exceedance(&self) -> Option<Exceedance> {
            self.exceedance
        }

        fn temporary_storage_readback(&self) -> Option<StatfsReadback> {
            None
        }
    }

    fn byte_exceedance() -> Exceedance {
        Exceedance {
            resource: TemporaryStorageResource::Bytes,
            requested: 2,
            used: 4,
            ceiling: 5,
        }
    }

    #[test]
    fn a_quota_refusal_arriving_with_provider_completion_wins_terminal_arbitration() {
        let mut host = FakeJcodeTemporaryStorage::default();
        let mut checkpoint = Instant::now();

        // This is the pre-poll observation. The provider then returns a
        // completion while its last write is refused by the filesystem.
        assert_eq!(
            poll_jcode_temporary_storage(&mut host, &mut checkpoint, false),
            Ok(None)
        );
        host.exceedance = Some(byte_exceedance());

        // The production loop performs this second observation before it
        // selects the provider outcome, so the refusal is durable and wins.
        assert_eq!(
            poll_jcode_temporary_storage(&mut host, &mut checkpoint, false),
            Ok(Some((byte_exceedance(), None)))
        );
        assert_eq!(host.checkpoint_count, 1);
    }

    #[test]
    fn cancellation_observation_checkpoints_a_concurrent_quota_refusal_immediately() {
        let mut host = FakeJcodeTemporaryStorage {
            exceedance: Some(byte_exceedance()),
            ..FakeJcodeTemporaryStorage::default()
        };
        let mut checkpoint = Instant::now() - Duration::from_millis(1);

        assert_eq!(
            poll_jcode_temporary_storage(&mut host, &mut checkpoint, true),
            Ok(Some((byte_exceedance(), None)))
        );
        // `force_checkpoint` and quota observation share one write: no
        // cancellation boundary can acknowledge the refusal without custody.
        assert_eq!(host.checkpoint_count, 1);
    }

    #[test]
    fn checkpoint_failure_is_fail_closed_before_provider_progress_is_selected() {
        let mut host = FakeJcodeTemporaryStorage {
            refuse_checkpoint: true,
            ..FakeJcodeTemporaryStorage::default()
        };
        let mut checkpoint = Instant::now();

        assert_eq!(
            poll_jcode_temporary_storage(&mut host, &mut checkpoint, true),
            Err(())
        );
        assert_eq!(host.checkpoint_count, 1);
    }

    #[test]
    fn a_failed_reconciliation_spool_reopens_and_advances_the_read_index_exactly() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let spool_root = root.path().join("spool");
        fs::create_dir(&spool_root).unwrap();
        fs::set_permissions(&spool_root, fs::Permissions::from_mode(0o700)).unwrap();
        let index_path = root.path().join("run-index.sqlite3");
        let run_id = "reconcile-fault-run";

        let mut spool = Spool::open(&spool_root, run_id, 64 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Authoritative, b"pid=1")
            .unwrap();
        // This is the canonical terminal selected by the backend when its
        // final checkpoint/reconciliation returns an error.
        spool
            .append(EventKind::Terminal, Authority::Authoritative, b"failed")
            .unwrap();
        drop(spool);
        let reopened = Spool::open(&spool_root, run_id, 64 * 1024).unwrap();
        let status = reopened.status();
        assert_eq!(status.last_sequence(), 2);

        let mut index = RunIndex::open(&index_path).unwrap();
        let registered = index
            .register(RunIndexEntry {
                submission_id: 1,
                run_id,
                registered_at_ms: 1,
            })
            .unwrap();
        drop(index);
        advance(
            &index_path,
            1,
            registered.revision,
            spool_state(status.state()),
            status.last_sequence(),
        );

        let reopened_index = RunIndex::open(&index_path).unwrap();
        let record = reopened_index.entry(1).unwrap().unwrap();
        assert_eq!(record.spool_state, RunSpoolState::Failed);
        assert_eq!(record.last_sequence, status.last_sequence());
        assert_eq!(record.revision, 3);
    }

    fn approval_store(root: &Path) -> ApprovalRequests {
        ApprovalRequests::open(root.join("approval-requests.sqlite3")).expect("approval requests")
    }

    fn propose(store: &mut ApprovalRequests, key: &str, run_id: &str, requested_by: &str) {
        store
            .propose(ApprovalProposal {
                request_key: key,
                subject: &format!("provider-permission:{key}"),
                run_id,
                context: ApprovalContext {
                    spec_digest: &"1".repeat(64),
                    program_path: "/usr/bin/expiry-test",
                    program_sha256: &"2".repeat(64),
                    prompt_sha256: &"3".repeat(64),
                    cwd_token: "expiry-test-cwd",
                },
                requested_by,
                requested_at_ms: 1,
                expires_at_ms: FAR_FUTURE_MS,
            })
            .expect("proposal");
    }

    fn state_of(store: &ApprovalRequests, key: &str) -> ApprovalState {
        store.entry(key).expect("read").expect("row").state
    }

    /// A run that ends leaves no live question behind it.
    ///
    /// The permission this run's worker proposed is answerable only while the
    /// run is there to act on the answer, so a terminal run closes it. The
    /// assertion that matters to the session surface is the last one:
    /// `pending_for_run` is the exact query
    /// `Daemon::platform_session_command_state` projects its pending approvals
    /// from, so an empty answer here is an empty projection there.
    #[test]
    fn a_terminated_runs_unanswered_permission_is_expired_and_leaves_the_projection_empty() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-requests.sqlite3");
        let mine = "apr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let theirs = "apr-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        {
            let mut store = approval_store(root.path());
            propose(&mut store, mine, "run-stopped", PROVIDER_APPROVAL_PROPOSER);
            propose(
                &mut store,
                theirs,
                "run-elsewhere",
                PROVIDER_APPROVAL_PROPOSER,
            );
        }

        expire_unanswered_approvals(&path, "run-stopped");

        let store = approval_store(root.path());
        assert_eq!(state_of(&store, mine), ApprovalState::Expired);
        assert!(
            !store
                .entry(mine)
                .expect("read")
                .expect("row")
                .is_answerable_at(2),
            "a closed permission is no longer answerable"
        );
        assert_eq!(
            store.entry(mine).expect("read").expect("row").approval_key,
            None,
            "nobody decided it, so no decider is named"
        );
        assert!(
            store
                .pending_for_run("run-stopped", 2, 16)
                .expect("projection")
                .is_empty(),
            "the session command state projects nothing for a terminated run"
        );
        assert_eq!(
            state_of(&store, theirs),
            ApprovalState::Pending,
            "another run's permission is not this run's to close"
        );
    }

    /// An answer already given is never overwritten, and a second pass is a
    /// no-op — the sweep is fenced on the revision it read.
    #[test]
    fn expiry_leaves_a_decided_permission_alone_and_is_idempotent_under_replay() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-requests.sqlite3");
        let granted = "apr-cccccccccccccccccccccccccccccccc";
        let unanswered = "apr-dddddddddddddddddddddddddddddddd";
        {
            let mut store = approval_store(root.path());
            propose(&mut store, granted, "run-mixed", PROVIDER_APPROVAL_PROPOSER);
            propose(
                &mut store,
                unanswered,
                "run-mixed",
                PROVIDER_APPROVAL_PROPOSER,
            );
            store
                .decide(granted, 1, ApprovalOutcome::Granted, "apv-operator-1", 5)
                .expect("operator decision");
        }

        expire_unanswered_approvals(&path, "run-mixed");
        let after_first = {
            let store = approval_store(root.path());
            (
                store.entry(granted).expect("read").expect("row"),
                store.entry(unanswered).expect("read").expect("row"),
            )
        };
        assert_eq!(after_first.0.state, ApprovalState::Granted);
        assert_eq!(
            after_first.0.approval_key.as_deref(),
            Some("apv-operator-1")
        );
        assert_eq!(after_first.1.state, ApprovalState::Expired);

        expire_unanswered_approvals(&path, "run-mixed");
        let store = approval_store(root.path());
        assert_eq!(
            store.entry(granted).expect("read").expect("row"),
            after_first.0,
            "a decided permission is byte-identical after a replayed sweep"
        );
        assert_eq!(
            store.entry(unanswered).expect("read").expect("row"),
            after_first.1,
            "an already-closed permission is not closed twice"
        );
    }

    /// The sweep speaks only for the proposals this run's own worker wrote. A
    /// launch-gate approval asks whether the run may start at all and is
    /// answerable without an executing attempt.
    #[test]
    fn expiry_does_not_close_an_approval_this_worker_did_not_propose() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-requests.sqlite3");
        let gate = "apr-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        {
            let mut store = approval_store(root.path());
            propose(&mut store, gate, "run-gated", "automonique.launch-gate");
        }

        expire_unanswered_approvals(&path, "run-gated");

        let store = approval_store(root.path());
        assert_eq!(state_of(&store, gate), ApprovalState::Pending);
    }

    #[test]
    fn provider_binary_limit_accepts_the_boundary_and_refuses_the_next_byte() {
        assert_eq!(MAX_PROVIDER_BINARY_BYTES, 512 * 1024 * 1024);
        assert!(is_within_byte_limit(
            MAX_PROVIDER_BINARY_BYTES,
            MAX_PROVIDER_BINARY_BYTES
        ));
        assert!(!is_within_byte_limit(
            MAX_PROVIDER_BINARY_BYTES + 1,
            MAX_PROVIDER_BINARY_BYTES
        ));
    }

    #[test]
    fn optimized_provider_digest_is_the_canonical_sha256_spelling() {
        assert_eq!(
            provider_binary_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The one admission refusal that is about the host rather than the
    /// document crosses to the wire as the host-wide word, and every other one
    /// keeps the document's.
    #[test]
    fn a_host_without_a_fuse_stack_is_refused_as_sandbox_unenforceable() {
        let host_wide = admission_refusal(&AdmissionRefusal::TemporaryStorageUnenforceable(
            "/dev/fuse is not a character device".to_owned(),
        ));
        assert_eq!(host_wide, ExecuteRefusal::SandboxUnenforceable);
        assert!(
            host_wide.is_host_wide(),
            "a host that cannot mount the budget refuses every document"
        );

        for about_the_document in [
            AdmissionRefusal::RunIdUnusable,
            AdmissionRefusal::TemporaryStorageTmpdirConflict,
            AdmissionRefusal::TemporaryStorageAlreadyAttached,
            AdmissionRefusal::QuotaRejected("sandbox.budgets.temporary_storage"),
        ] {
            assert_eq!(
                admission_refusal(&about_the_document),
                ExecuteRefusal::AdmissionRefused,
                "{about_the_document}"
            );
        }
    }

    /// The seam between the daemon's host-wide dispatcher and a live attempt.
    ///
    /// This is the whole of what makes a running attempt cancellable, and no
    /// integration test can reach it: the wire has no cancel verb, and the
    /// daemon's host is moved into its serve thread. So it is proved here,
    /// against a **real** [`DaemonAttemptHost`] over a real durable ledger,
    /// with the same sink the worker registers.
    ///
    /// What is proved is exactly the property [`super::Attempt::run`] depends
    /// on: a cancellation delivered through the dispatcher sets the very token
    /// the backend polls. That the backend then kills the tree is the runner's
    /// own proof, and it is not restated here.
    #[test]
    fn a_host_wide_cancel_sets_the_token_the_backend_polls() {
        let root = tempfile::tempdir().expect("temporary root");
        // The ledger refuses a parent that is not private and owned, which is
        // the same guard the daemon's own state directory satisfies.
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let host = DaemonAttemptHost::open(root.path().join("cancel-ledger.sqlite3"))
            .expect("attempt host opens");

        let cancellation = CancellationToken::new();
        let deliveries = Arc::new(AtomicUsize::new(0));
        let registration = host
            .register(
                "attempt-1",
                Box::new(TokenCancelSink {
                    attempt_id: "attempt-1".to_owned(),
                    cancellation: cancellation.clone(),
                    deliveries: Arc::clone(&deliveries),
                }),
            )
            .expect("the attempt registers");

        assert!(
            !cancellation.is_cancelled(),
            "registering must not cancel anything"
        );
        assert_eq!(
            host.cancel("attempt-1", "request-1", 1),
            DispatchOutcome::Delivered
        );
        assert!(
            cancellation.is_cancelled(),
            "a delivered cancellation must set the token the backend polls"
        );
        assert_eq!(deliveries.load(Ordering::Acquire), 1);

        // The ledger is durable custody, so the same reference is answered as a
        // replay rather than delivered a second time.
        assert_eq!(
            host.cancel("attempt-1", "request-1", 1),
            DispatchOutcome::AlreadyDelivered
        );
        assert_eq!(deliveries.load(Ordering::Acquire), 1);

        // Releasing is what the worker's guard does on every path out, and a
        // released attempt is no longer reachable.
        drop(registration);
        assert_eq!(
            host.cancel("attempt-1", "request-2", 2),
            DispatchOutcome::UnknownAttempt
        );
    }

    /// The two name rules that stand between a wire identifier and a path.
    ///
    /// Asserted here rather than through the socket because the interesting
    /// inputs — a traversal, a separator, a NUL — are ones a bounded protocol
    /// identifier may legitimately carry and this module must still refuse.
    #[test]
    fn no_identifier_that_could_leave_its_directory_is_accepted() {
        for hostile in [
            "..",
            ".",
            "a/b",
            "../escape",
            "run id",
            "run.id",
            "run\0id",
            "",
        ] {
            assert!(!is_safe_segment(hostile), "{hostile} must be refused");
            assert!(
                !is_containment_run_id(hostile),
                "{hostile} must be refused as a cgroup name"
            );
        }
        for ordinary in ["run-1", "run_1", "R1", "0"] {
            assert!(is_safe_segment(ordinary), "{ordinary} must be accepted");
            assert!(is_containment_run_id(ordinary));
        }
    }

    fn generic_provider_fault(reply_to: u64) -> automonique_runner::backend::CapturedFrame {
        JcodeProgressMapper::new(false)
            .project_event(JcodeEvent::Error {
                reply_to: Some(reply_to),
                code: "rejected".to_owned(),
            })
            .expect("provider fault frame")
    }

    fn refuse_destination(broker: &EgressBroker, host: &str, port: u16) {
        let mut client = TcpStream::connect(broker.local_addr()).expect("connect to broker");
        write!(client, "CONNECT {host}:{port} HTTP/1.1\r\n\r\n").expect("write CONNECT");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read refusal");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn a_terminal_provider_fault_names_one_retried_destination_and_consumes_its_window() {
        let broker = EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts");
        let observer = broker.refused_destination_observer();
        let mut cursor = observer.cursor().expect("request baseline");
        refuse_destination(&broker, "Missing.Example", 443);
        refuse_destination(&broker, "missing.example", 443);

        let generic = generic_provider_fault(3);
        assert!(generic.body.text().is_none());
        let expected_retry = generic.body.retry();
        let described =
            describe_refused_destination(generic, Some(&observer), Some(&mut cursor), true);

        assert_eq!(
            described.body.text().map(|text| text.as_str()),
            Some("provider route refused destination missing.example:443")
        );
        assert_eq!(described.body.retry(), expected_retry);
        assert!(!format!("{observer:?}").contains("missing.example"));

        let after_consumption = describe_refused_destination(
            generic_provider_fault(3),
            Some(&observer),
            Some(&mut cursor),
            true,
        );
        assert!(after_consumption.body.text().is_none());
    }

    #[test]
    fn quota_keeps_correlated_provider_destination_while_remaining_terminal_authoritative() {
        let broker = EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts");
        let observer = broker.refused_destination_observer();
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run_id = "quota-provider-correlation";
        let mut writer = JcodeSpoolWriter {
            spool: Spool::open(directory.path(), run_id, 64 * 1024).unwrap(),
            frame_run_id: automonique_protocol::tools::RunId::new(run_id).unwrap(),
            publisher: Box::new(NoopPublisher),
            observed: ObservedSequence::default(),
            progress_stopped: false,
            refused_destination: Some(observer),
            refused_destination_cursor: None,
        };
        writer.started(1).unwrap();
        writer.begin_provider_request();
        refuse_destination(&broker, "Quota.Example", 443);
        let outcome: Result<JcodeTurnOutcome, JcodeHostError> =
            Err(JcodeHostError::ProviderRefused);
        writer.project_turn_outcome(
            &mut JcodeProgressMapper::new(false),
            vec![JcodeEvent::Error {
                reply_to: Some(3),
                code: "rejected".to_owned(),
            }],
            &outcome,
        );
        writer.temporary_storage_exceeded(byte_exceedance(), None);
        let finished = writer.finish(RunSpoolState::Failed);
        assert_eq!(finished.state, RunSpoolState::Failed);

        let reopened = Spool::open(directory.path(), run_id, 64 * 1024).unwrap();
        let events = reopened.events_after(0).unwrap();
        let frames: Vec<_> = events
            .iter()
            .filter(|event| event.kind() == EventKind::AdapterEvent)
            .filter_map(|event| ProgressFrame::from_canonical_bytes(event.payload()).ok())
            .collect();
        assert_eq!(
            frames[0].body().text().map(|text| text.as_str()),
            Some("provider route refused destination quota.example:443")
        );
        assert!(
            frames[1]
                .body()
                .text()
                .is_some_and(|text| text.as_str().contains("temporary-storage budget exceeded"))
        );
        assert_eq!(
            events.last().map(|event| event.payload()),
            Some(b"failed".as_ref())
        );
    }

    #[test]
    fn stale_and_ambiguous_refusals_never_replace_an_authoritative_fault() {
        let broker = EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts");
        let observer = broker.refused_destination_observer();
        refuse_destination(&broker, "stale.example", 443);
        let mut cursor = observer.cursor().expect("baseline excludes stale refusal");
        let stale = describe_refused_destination(
            generic_provider_fault(3),
            Some(&observer),
            Some(&mut cursor),
            true,
        );
        assert!(stale.body.text().is_none());

        refuse_destination(&broker, "first.example", 443);
        refuse_destination(&broker, "second.example", 443);
        let ambiguous = describe_refused_destination(
            generic_provider_fault(3),
            Some(&observer),
            Some(&mut cursor),
            true,
        );
        assert!(ambiguous.body.text().is_none());
    }

    #[test]
    fn a_steering_error_cannot_consume_the_turns_refusal_window() {
        let broker = EgressBroker::start(BrokerConfig::default()).expect("deny-all broker starts");
        let observer = broker.refused_destination_observer();
        let mut cursor = observer.cursor().expect("request baseline");
        refuse_destination(&broker, "turn.example", 443);

        let steering = describe_refused_destination(
            generic_provider_fault(4),
            Some(&observer),
            Some(&mut cursor),
            false,
        );
        assert!(steering.body.text().is_none());

        let terminal = describe_refused_destination(
            generic_provider_fault(3),
            Some(&observer),
            Some(&mut cursor),
            true,
        );
        assert_eq!(
            terminal.body.text().map(|text| text.as_str()),
            Some("provider route refused destination turn.example:443")
        );
    }
}
