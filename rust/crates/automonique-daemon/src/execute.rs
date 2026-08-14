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
//! - **It is not a workspace registry.** See [`DAEMON_WORKSPACE_REGISTRY`]: this
//!   daemon resolves one workspace — a private empty directory it creates for
//!   the run — and refuses every document that names a registry it cannot
//!   resolve.
//! - **It is not release trust.** The program's digest is checked against the
//!   document's pin, which establishes that the bytes on disk are the bytes the
//!   document named. Who signed those bytes, and whether that party may be
//!   trusted, is [`automonique_protocol::release_trust_root`]'s question and
//!   nothing here answers it.
//! - **It is not attestation.** It publishes a host feature per property it
//!   enforces, identified by a digest over *how* it enforces it, and nothing
//!   signs that statement. See [`offered_host_features`].

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_egress_broker::{BrokerConfig, EgressBroker};
use automonique_protocol::digest::{ALGORITHM, Sha256};
use automonique_protocol::execute_api::ExecuteRefusal;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    Digest, ExecutionBackendId, HostFeature, ImplementationDigest,
};
use automonique_runner::admission::{
    AdmissionContext, AdmissionContextParts, AdmittedLaunch, BrokeredDestination, PromptSource,
    ResolvedPrompt, UnenforcedBudget, admit,
};
use automonique_runner::backend::{DirectProcessBackend, PreparedRun};
use automonique_runner::capability::{BoundaryProperty, HostCapabilities};
use automonique_runner::control::{CancelSink, CancelUnavailable};
use automonique_runner::dispatch::RegistrationHandle;
use automonique_runner::{
    CancellationToken, ContainmentDomain, Controller, PromptDeliveryPlan, RunSpec, Spool,
    WorkspaceRegistryId,
};
use automonique_store::run_index::{RunIndex, RunSpoolState, StateAdvance};

use crate::attempt_host::DaemonAttemptHost;

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

/// The one workspace registry identity this daemon can resolve.
///
/// A [`RunSpec`]'s working directory is an opaque `cwd_token` that a workspace
/// registry is supposed to resolve against a registered workspace. This build
/// has no workspace registry, so it has exactly one honest option and takes it:
/// it declares an identity of its own, resolves it to a **private empty
/// directory created for the run**, and refuses every document naming any other
/// registry with [`ExecuteRefusal::AdmissionRefused`].
///
/// Stated plainly, because it is the difference between a check and a
/// ceremony: a document that names this identity gets a fresh empty workspace,
/// not the workspace it was written against. What the check buys is that a
/// document written against a *real* registry cannot be silently run against
/// the wrong tree — it is refused instead.
pub const DAEMON_WORKSPACE_REGISTRY: &str = "automonique-daemon-scratch";

/// The one execution backend this daemon is.
///
/// [`admit`] compares it against the document's own `backend_id`, so a
/// document written for another backend is refused here rather than run by the
/// wrong one.
pub const DAEMON_BACKEND_ID: &str = "local-direct";

/// The boundary properties this build's launch path enforces, and the exact
/// set a host is measured against.
///
/// One array, read by the daemon's startup measurement *and* by
/// [`offered_host_features`], so what the status reports and what a document
/// negotiates against cannot drift apart.
pub const ENFORCED_PROPERTIES: [BoundaryProperty; 4] = [
    BoundaryProperty::DescendantContainment,
    BoundaryProperty::FilesystemRestriction,
    BoundaryProperty::TcpDenial,
    BoundaryProperty::SyscallRestriction,
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
    let Ok(selection) = HostCapabilities::probe().select_mode(&ENFORCED_PROPERTIES) else {
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
pub const MAX_PROVIDER_BINARY_BYTES: u64 = 64 * 1024 * 1024;

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
const WORKSPACE_LEAF: &str = "workspace";
/// The run's authoritative spool directory, outside every grant.
const SPOOL_LEAF: &str = "spool";

/// Where this daemon resolves one run's `cwd_token` to, as a pure function of
/// the state directory and the run identity.
///
/// # Why this is public, and why it is a function rather than a convention
///
/// [`DAEMON_WORKSPACE_REGISTRY`] says this daemon resolves exactly one
/// workspace: a private empty directory it creates for the run. Everything
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
pub fn run_workspace(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir
        .join(RUNS_DIRECTORY)
        .join(run_id)
        .join(WORKSPACE_LEAF)
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
        Self {
            attempt_host,
            state_dir,
            run_index_path,
            helper,
            sandbox_enforceable,
            offered: offered_host_features(),
            egress_destinations,
            domain: None,
            live: Arc::new(Mutex::new(BTreeSet::new())),
            workers: Vec::new(),
        }
    }

    /// The brokered destinations this lane was opened with.
    ///
    /// Empty means no document asking for egress can run here.
    #[must_use]
    pub fn egress_destinations(&self) -> &[BrokeredDestination] {
        &self.egress_destinations
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
        self.state_dir
            .join(RUNS_DIRECTORY)
            .join(run_id)
            .join(SPOOL_LEAF)
    }

    /// Where one run's workspace resolves, through this lane's own state
    /// directory. See [`run_workspace`].
    #[must_use]
    pub fn workspace_root(&self, run_id: &str) -> PathBuf {
        run_workspace(&self.state_dir, run_id)
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
        let workspace = self.workspace_root(run_id);
        let spool_root = run_root.join(SPOOL_LEAF);

        let prompt = self.resolve_prompt(spec)?;
        let observed = self.observe_provider_binary(spec)?;

        let context = AdmissionContext::new(AdmissionContextParts {
            backend: ExecutionBackendId::new(DAEMON_BACKEND_ID)
                .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?,
            workspace_registry_id: WorkspaceRegistryId::new(DAEMON_WORKSPACE_REGISTRY)
                .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?,
            // The workspace root and the working directory are the same
            // directory: this daemon resolves one, and a `cwd_token` naming a
            // sub-path of a workspace it did not register would be a resolution
            // it cannot perform.
            workspace_root: workspace.clone(),
            working_directory: workspace.clone(),
            observed_provider_binary: observed,
            host_features: self.offered.clone(),
            prompt: Some(prompt),
            // Naming a budget is not waiving it: `admission` requires each
            // unenforced budget to be acknowledged in advance, and republishes
            // the acknowledgement on the admitted launch. This daemon
            // acknowledges all four because it installs no CPU ceiling, no
            // `RLIMIT_NOFILE`, no temporary filesystem quota and no artifact
            // accounting, and saying so is the only alternative to pretending
            // otherwise.
            unenforced_budgets: UnenforcedBudget::ALL.to_vec(),
            // The destinations this deployment resolves brokered egress to.
            // A document that denies egress is refused if this is non-empty and
            // one that asks for it is refused if this is empty, so the policy
            // can neither widen a denied document nor be defaulted into one.
            brokered_destinations: self.egress_destinations.clone(),
        })
        .map_err(|_| ExecuteRefusal::AdmissionRefused)?;

        let admitted = admit(spec, &context).map_err(|_| ExecuteRefusal::AdmissionRefused)?;
        // One broker, this run's, bound before the plan is finished — because
        // the port the plan grants is the port this broker just bound, and it
        // does not exist until it is. A run whose document denies egress takes
        // the other branch and gets no broker, no socket grant and no proxy
        // variable at all.
        let (admitted, broker) = self.start_broker(admitted)?;

        // Admitted, so the run may now have a place on disk. The workspace is
        // created empty and the spool root beside it, never inside it: the
        // admitted plan grants the workload read-write access to the workspace,
        // and a spool under that grant would be a durable lifecycle record the
        // workload could rewrite.
        private_directory(&self.state_dir.join(RUNS_DIRECTORY))
            .and_then(|()| private_directory(&run_root))
            .and_then(|()| private_directory(&workspace))
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

        let spool = Spool::open(&spool_root, run_id, admitted.spool_budget_bytes())
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        // `prepare` creates the run cgroup and applies the document's ceilings
        // before any workload can enter it. Dropping the result — which the
        // error path and a failed spawn both do — removes that cgroup and
        // leaves the spool empty, so a refusal here records nothing.
        let prepared = backend
            .prepare(
                &domain,
                run_id,
                admitted.limits(),
                admitted.plan().clone(),
                spool,
            )
            .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;

        self.spawn(Attempt {
            run_id: run_id.to_owned(),
            submission_id,
            revision,
            timeout: admitted.timeout(),
            cancellation,
            registration,
            prepared,
            broker,
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
    /// carry a memory ceiling and a process ceiling, and a domain that cannot
    /// distribute those controllers cannot apply them. Running anyway would be
    /// running *outside the document's declared budget*, which is the exact
    /// silent downgrade this build refuses everywhere else.
    fn domain(&mut self) -> Result<&ContainmentDomain, ExecuteRefusal> {
        if self.domain.is_none() {
            let domain = ContainmentDomain::discover()
                .map_err(|_| ExecuteRefusal::ContainmentUnavailable)?;
            domain
                .prepare(&[Controller::Pids, Controller::Memory])
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
    fn resolve_prompt(&self, spec: &RunSpec) -> Result<ResolvedPrompt, ExecuteRefusal> {
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
        ResolvedPrompt::new(
            PromptSource::ProtectedReference(
                automonique_runner::ProtectedPromptReference::new(slot)
                    .map_err(|_| ExecuteRefusal::PromptUnresolvable)?,
            ),
            bytes,
            declared,
        )
        .map_err(|_| ExecuteRefusal::PromptUnresolvable)
    }

    /// Hash the program the document pins, and report it as observed
    /// provenance.
    ///
    /// The version travels from the document because it is informational —
    /// [`BinaryProvenance::matches`] compares digests, not versions — and the
    /// schema digest must be absent: this daemon speaks no provider protocol,
    /// so it can observe no schema, and copying the document's own claim into
    /// the observation would turn that half of the comparison into a mirror.
    /// A document that pins a schema digest is therefore refused here rather
    /// than admitted on a check nobody performed.
    fn observe_provider_binary(&self, spec: &RunSpec) -> Result<BinaryProvenance, ExecuteRefusal> {
        let pinned = spec.provider_binary();
        if pinned.schema_digest().is_some() {
            return Err(ExecuteRefusal::ProviderBinaryUnverified);
        }
        let bytes = read_bounded(spec.executable(), MAX_PROVIDER_BINARY_BYTES)
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?;
        let observed = format!("{ALGORITHM}:{}", Sha256::digest(&bytes).to_hex());
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
    pub fn shutdown(mut self) {
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// A live claim, released when the worker thread's frame is dropped.
struct LiveClaim {
    live: Arc<Mutex<BTreeSet<String>>>,
    run_id: String,
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
    submission_id: i64,
    revision: u64,
    timeout: Duration,
    cancellation: CancellationToken,
    /// Owns the cancellation registration. Dropping it — on any path out,
    /// including a panic — releases the attempt from the host's registry.
    registration: RegistrationHandle,
    prepared: PreparedRun,
    /// This run's own broker, when its document asked for egress. Owning it
    /// here is what bounds its lifetime to the run: every path out of this
    /// worker drops it, including a panic, and its drop stops the listener and
    /// tears down every tunnel still open.
    broker: Option<EgressBroker>,
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
            submission_id,
            revision,
            timeout,
            cancellation,
            registration,
            prepared,
            broker,
            ..
        } = self;

        let report = prepared.execute(&cancellation, timeout);
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
        let (state, last_sequence) = match &report {
            Ok(report) => (
                spool_state(report.status().state()),
                report.status().last_sequence(),
            ),
            // A supervisor failure still left exactly one terminal event in the
            // spool — `execute` guarantees it on every path — and that event is
            // `failed`. The row says the same rather than staying open.
            Err(_) => (RunSpoolState::Failed, 2),
        };
        advance(index_path, submission_id, revision, state, last_sequence);
    }
}

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
    fn deliver(&self, attempt_id: &str, _request_ref: &str) -> Result<(), CancelUnavailable> {
        // The dispatcher only calls the sink its own registration holds, so a
        // mismatch is unreachable; refusing rather than cancelling keeps it
        // that way if that ever stops being true.
        if attempt_id != self.attempt_id {
            return Err(CancelUnavailable);
        }
        // Set before counting: an observer that sees a nonzero count has, by
        // release/acquire ordering, also seen the token set.
        self.cancellation.cancel();
        self.deliveries.fetch_add(1, Ordering::Release);
        Ok(())
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
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    // Bounded by one byte over the limit, so a file that grew between the
    // metadata read and the read itself is refused rather than read whole.
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).ok()? > limit {
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
    use super::{TokenCancelSink, is_containment_run_id, is_safe_segment};
    use crate::attempt_host::DaemonAttemptHost;
    use automonique_runner::CancellationToken;
    use automonique_runner::dispatch::DispatchOutcome;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
