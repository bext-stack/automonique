// SPDX-License-Identifier: Elastic-2.0

//! Foreground Automonique control-plane process.
//!
//! This first daemon slice owns a private runtime directory, a durable SQLite
//! store, one fenced process generation, and a peer-authenticated Unix admin
//! socket. It deliberately performs no external effects yet.
//!
//! That includes the run submission lane: a submitted RunSpec document is
//! verified and durably held, and then nothing happens to it. The `SubmitRun`
//! handler arm records what execution would still require and why none of it
//! exists here.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_observability::{MetricName, MetricValue, StoreProjection};
use automonique_protocol::admin::{
    AdminInstanceId, AdminOutboxEvidence, AdminOutboxEvidenceParts, AdminReconciliationEvidence,
    AdminRefusalCategory, AdminRequest, AdminResponse, DaemonState, DaemonStatus, LocalRequest,
    MAX_ADMIN_CANONICAL_BYTES, OperationalMetric, OperationalStatus, OperationalStatusParts,
    OutboxReconciliationDecision,
};
use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::{
    AutomationContinuation, AutomationCursor, AutomationId, AutomationListPage,
    AutomationReceiptView, AutomationRecordParts, AutomationRecordView, AutomationRefusal,
    AutomationRequest, AutomationResponse, ListAutomations, PauseReason, RegisterAutomation,
    SetEnablement,
};
use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::{ALGORITHM, Sha256, Sha256Digest};
use automonique_protocol::journal::{CursorResume, RetainedRange};
use automonique_protocol::runs_api::{
    Continuation, LifecycleCoverage, ListRuns, RunCursor, RunDetailView, RunListPage, RunState,
    RunSummary, RunsRefusal, RunsRequest, RunsResponse, SubmissionState,
};
use automonique_protocol::tools::RunId;
use automonique_runner::{RunSpec, RunSpecDecodeError};
use automonique_store::automation_store::{
    AutomationRecord, AutomationRegistration, AutomationStore, AutomationStoreError,
    EnablementState as StoreEnablementState, EnablementTransition,
};
use automonique_store::run_index::{
    RunIndex, RunIndexEntry, RunIndexError, RunIndexRecord, RunSpoolState,
};
use automonique_store::run_submissions::{
    RunSubmission, RunSubmissionError, RunSubmissionLog, RunSubmissionState,
};
use automonique_store::{
    InboxSubmission, IntakePauseRequest, IntakeResumeRequest, LeaseRenewal, LeaseRequest,
    OutboxReconciliationDecision as StoreOutboxDecision, OutboxReconciliationRequest,
    ReconciliationDecision, ReconciliationRequest, StatusSnapshot, Store, StoreError,
};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

pub mod attempt_host;
pub mod cancel_custody;
mod synthetic;
mod telegram;

use attempt_host::DaemonAttemptHost;

/// Socket filename inside the private product runtime directory.
pub const ADMIN_SOCKET_NAME: &str = concat!("admin", ".sock");

/// Database filename inside the private product state directory.
pub const DATABASE_NAME: &str = concat!("automonique", ".sqlite3");

/// Run submission custody database, a sibling of [`DATABASE_NAME`].
///
/// Separate, like every other sibling log in `automonique-store`: its schema
/// versions independently of the scheduler's, and a submission is not scheduler
/// state. What the separation costs is stated in that module's documentation.
pub const RUN_SUBMISSIONS_NAME: &str = concat!("run-submissions", ".sqlite3");

/// Durable run index, a sibling of [`DATABASE_NAME`].
///
/// The derived read model behind the Runs API listing: one row per accepted
/// submission, binding it to its run and to the last state a writer reported.
/// Separate from [`RUN_SUBMISSIONS_NAME`] for the reason every sibling log is
/// separate — its schema versions independently — and because custody and a
/// read model are different things: the first is the source of truth, the
/// second is rebuildable from it.
pub const RUN_INDEX_NAME: &str = concat!("run-index", ".sqlite3");

/// Durable automation enablement registry, a sibling of [`DATABASE_NAME`].
///
/// One row per automation, recording whether an operator has it in service and
/// who withdrew it. Separate for the reason every sibling log is separate — its
/// schema versions independently — and because an enablement decision is not
/// scheduler state.
///
/// WHAT THIS FILE DOES NOT DO. It holds no schedule, no trigger and no action,
/// and nothing in this build reads it to decide whether to run anything: there
/// is no scheduler and no executor. A `paused` row therefore suppresses nothing
/// today. It is written now so that the scheduler, when it lands, reads its
/// enablement out of a durable record rather than inventing one.
pub const AUTOMATION_REGISTRY_NAME: &str = concat!("automations", ".sqlite3");

/// Durable host-wide cancellation ledger, a sibling of [`DATABASE_NAME`].
///
/// Separate for the same reason every sibling log is: its schema versions
/// independently, and a cancellation request is not scheduler state. Being a
/// sibling *of this state directory* is also what makes the daemon's
/// single-dispatcher argument work — one state directory admits one daemon, so
/// one ledger file has one owner. See [`attempt_host`].
pub const RUN_CANCEL_LEDGER_NAME: &str = concat!("run-cancel-ledger", ".sqlite3");

/// Maximum administration payload accepted by the daemon.
pub const MAX_ADMIN_PAYLOAD_BYTES: usize = MAX_ADMIN_CANONICAL_BYTES;

const GENERATION_ID: &str = "foreground";
const LEASE_TTL_MS: i64 = 30_000;
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
/// Bot-lease TTL, strictly inside the generation TTL: the store refuses a bot
/// lease that would outlive its generation authority, and the bot lease is
/// always acquired or renewed moments after the generation lease.
const TELEGRAM_LEASE_TTL_MS: i64 = 20_000;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(25);

/// Refusal category both intake lanes answer with while an operator pause is
/// live.
///
/// Distinct from `reconciliation_required` on purpose: a submitter that retries
/// on a degraded generation is waiting for a repair, while one that retries
/// through a pause is waiting for a person.
const INTAKE_PAUSED_CATEGORY: &str = "intake_paused";

/// Configuration for one foreground daemon instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    /// Existing private per-user runtime root, normally `$XDG_RUNTIME_DIR`.
    pub runtime_root: PathBuf,
    /// Existing or creatable private per-user state root.
    pub state_root: PathBuf,
}

impl DaemonConfig {
    /// Resolve the standard XDG locations without falling back to a home path.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::EnvironmentMissing`] if either required location
    /// is absent or not valid UTF-8 filesystem data.
    pub fn from_environment() -> Result<Self, DaemonError> {
        let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or(DaemonError::EnvironmentMissing("XDG_RUNTIME_DIR"))?;
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .ok_or(DaemonError::EnvironmentMissing("XDG_STATE_HOME"))?;
        Ok(Self {
            runtime_root,
            state_root,
        })
    }

    /// Product-owned runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        self.runtime_root.join("automonique")
    }

    /// Product-owned state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.state_root.join("automonique")
    }

    /// Local administration endpoint.
    #[must_use]
    pub fn admin_socket(&self) -> PathBuf {
        self.runtime_dir().join(ADMIN_SOCKET_NAME)
    }

    /// Durable database path.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.state_dir().join(DATABASE_NAME)
    }

    /// Durable run submission custody path.
    #[must_use]
    pub fn run_submissions_path(&self) -> PathBuf {
        self.state_dir().join(RUN_SUBMISSIONS_NAME)
    }

    /// Durable host-wide cancellation ledger path.
    #[must_use]
    pub fn run_cancel_ledger_path(&self) -> PathBuf {
        self.state_dir().join(RUN_CANCEL_LEDGER_NAME)
    }

    /// Durable run index path.
    #[must_use]
    pub fn run_index_path(&self) -> PathBuf {
        self.state_dir().join(RUN_INDEX_NAME)
    }

    /// Durable automation enablement registry path.
    #[must_use]
    pub fn automation_registry_path(&self) -> PathBuf {
        self.state_dir().join(AUTOMATION_REGISTRY_NAME)
    }
}

/// A daemon lifecycle or local-control refusal.
#[derive(Debug)]
pub enum DaemonError {
    /// A required environment variable was absent.
    EnvironmentMissing(&'static str),
    /// A configured filesystem path is not absolute, private, owned, or safe.
    InsecurePath(&'static str),
    /// Another daemon is accepting connections at the configured endpoint.
    AlreadyRunning,
    /// The connecting Unix peer is not the daemon's effective user.
    PeerDenied,
    /// The admin frame was incomplete, too large, or not admitted.
    ProtocolRefused(&'static str),
    /// Filesystem or local socket operation failed.
    Io(std::io::Error),
    /// Durable state operation failed.
    Store(StoreError),
    /// A previously claimed synthetic run has no durable terminal outcome.
    ReconciliationRequired,
    /// Host signal setup failed.
    Signal(nix::Error),
    /// The Telegram configuration or bot-lease lifecycle was refused. The
    /// payload is the stable category from the telegram module.
    TelegramRefused(&'static str),
    /// The durable run submission log failed in a way no client caused. The
    /// payload is the stable category from that module.
    RunSubmissionFailed(&'static str),
    /// The durable run index failed in a way no client caused. The payload is
    /// the stable category from that module, or one of this crate's own for a
    /// disagreement between the index and the custody it derives from.
    ///
    /// A submission is durable before its index row is written, so this never
    /// reports a lost document: it reports a read model that could not be
    /// extended or could not be believed.
    RunIndexFailed(&'static str),
    /// The host-wide cancellation host could not be opened or could not be
    /// disposed cleanly. The payload is the stable category from
    /// [`attempt_host`].
    AttemptHostFailed(&'static str),
    /// The durable automation registry failed in a way no client caused. The
    /// payload is the stable category from that module.
    ///
    /// Deliberately separate from the refusals an operator earns: a malformed
    /// field, an illegal transition and a stale revision are answered to the
    /// client, while corruption, a schema mismatch and storage failure say the
    /// daemon's own durable state is unsound and must not be presented as an
    /// operator error. [`automation_refusal`] is where the line is drawn.
    AutomationStoreFailed(&'static str),
}

impl DaemonError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::EnvironmentMissing(_) => "environment_missing",
            Self::InsecurePath(_) => "insecure_path",
            Self::AlreadyRunning => "already_running",
            Self::PeerDenied => "peer_denied",
            Self::ProtocolRefused(_) => "protocol_refused",
            Self::Io(_) => "io",
            Self::Store(error) => error.category(),
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Signal(_) => "signal",
            Self::TelegramRefused(category) => category,
            Self::RunSubmissionFailed(category) => category,
            Self::RunIndexFailed(category) => category,
            Self::AttemptHostFailed(category) => category,
            Self::AutomationStoreFailed(category) => category,
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvironmentMissing(name) => {
                write!(formatter, "required environment {name} is absent")
            }
            Self::InsecurePath(kind) => write!(formatter, "{kind} path is not private and owned"),
            Self::AlreadyRunning => formatter.write_str("another Automonique daemon is running"),
            Self::PeerDenied => formatter.write_str("local administration peer was denied"),
            Self::ProtocolRefused(category) => {
                write!(
                    formatter,
                    "local administration protocol refused: {category}"
                )
            }
            Self::Io(error) => write!(formatter, "daemon I/O failed: {error}"),
            Self::Store(error) => write!(formatter, "daemon store failed: {error}"),
            Self::ReconciliationRequired => {
                formatter.write_str("synthetic scheduler requires reconciliation")
            }
            Self::Signal(error) => write!(formatter, "daemon signal setup failed: {error}"),
            Self::TelegramRefused(category) => {
                write!(formatter, "telegram host refused: {category}")
            }
            Self::RunSubmissionFailed(category) => {
                write!(formatter, "run submission log failed: {category}")
            }
            Self::RunIndexFailed(category) => {
                write!(formatter, "run index failed: {category}")
            }
            Self::AttemptHostFailed(category) => {
                write!(formatter, "attempt host refused: {category}")
            }
            Self::AutomationStoreFailed(category) => {
                write!(formatter, "automation registry failed: {category}")
            }
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Signal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DaemonError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StoreError> for DaemonError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// An opened daemon whose runtime and store are ready.
pub struct Daemon {
    listener: UnixListener,
    socket_path: PathBuf,
    store: Store,
    instance_id: AdminInstanceId,
    lease_epoch: u64,
    lease_expires_ms: i64,
    socket_identity: (u64, u64),
    controller: automonique_core::Controller,
    reconciliation_run_id: Option<i64>,
    telegram: telegram::TelegramHost,
    run_submissions: RunSubmissionLog,
    /// The listing read model derived from `run_submissions`.
    ///
    /// A plain field rather than an `Option`, because unlike
    /// [`Daemon::attempt_host`] this handle owns no dispatcher and needs no
    /// ordered disposal: it is a database, and dropping it closes it. It is
    /// opened beneath the same fence and before the socket guard is disarmed,
    /// for the reason custody storage is — a daemon that cannot record what it
    /// accepted must not publish an endpoint that accepts.
    run_index: RunIndex,
    /// The durable record of which automations an operator has in service.
    ///
    /// A plain field for the same reason [`Daemon::run_index`] is: it owns no
    /// dispatcher and needs no ordered disposal. Nothing in this daemon *reads*
    /// it to decide anything — no scheduler consults it, because there is no
    /// scheduler — so its whole role in this build is to answer the automation
    /// control lane truthfully across restarts.
    automations: AutomationStore,
    /// This host's one cancellation dispatcher over its one durable ledger.
    ///
    /// `Option` only so [`Daemon::serve`] can dispose of it explicitly while
    /// the generation fence is still held — this type has a `Drop` impl, so a
    /// field cannot otherwise be moved out. It is `Some` for the whole life of
    /// a daemon a caller can observe.
    attempt_host: Option<DaemonAttemptHost>,
    execution_state: automonique_protocol::admin::ExecutionState,
}

struct SocketCleanup {
    path: PathBuf,
    identity: (u64, u64),
    armed: bool,
}

impl SocketCleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if self.armed {
            remove_socket_if_identity(&self.path, self.identity);
        }
    }
}

impl Daemon {
    /// Establish private directories, durable state, the fenced generation,
    /// and the local administration endpoint.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, an active endpoint, or store initialization failure.
    pub fn open(config: &DaemonConfig) -> Result<Self, DaemonError> {
        validate_root(&config.runtime_root, "runtime root")?;
        ensure_private_dir(&config.state_root, "state root")?;
        let runtime_dir = config.runtime_dir();
        let state_dir = config.state_dir();
        ensure_private_dir(&runtime_dir, "runtime directory")?;
        ensure_private_dir(&state_dir, "state directory")?;
        let mut store = Store::open(config.database_path())?;

        let socket_path = config.admin_socket();
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let socket_metadata = fs::symlink_metadata(&socket_path)?;
        if !socket_metadata.file_type().is_socket()
            || socket_metadata.uid() != geteuid().as_raw()
            || socket_metadata.mode() & 0o7777 != 0o600
        {
            return Err(DaemonError::InsecurePath("admin socket"));
        }
        listener.set_nonblocking(true)?;
        let socket_identity = (socket_metadata.dev(), socket_metadata.ino());
        let mut socket_cleanup = SocketCleanup {
            path: socket_path.clone(),
            identity: socket_identity,
            armed: true,
        };

        // Establish endpoint exclusion before changing durable ownership. A
        // failed competing bind cannot leave a phantom generation lease.
        let now_ms = unix_millis()?;
        let instance = format!("daemon-{}-{now_ms}", std::process::id());
        let instance_id = AdminInstanceId::new(instance)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        let lease = match store.acquire_generation_lease(LeaseRequest {
            generation_id: GENERATION_ID,
            holder_id: instance_id.as_str(),
            now_ms,
            ttl_ms: LEASE_TTL_MS,
        }) {
            Ok(lease) => lease,
            Err(error) => return Err(DaemonError::Store(error)),
        };

        // The Telegram host loads its explicit configuration and, when one
        // exists, acquires the durable bot lease beneath the generation fence
        // established above. An absent configuration is the disabled state; a
        // present-but-refused one fails startup rather than being ignored.
        let telegram = telegram::TelegramHost::open(
            &state_dir,
            &config.database_path(),
            GENERATION_ID,
            instance_id.as_str(),
            lease.epoch,
            TELEGRAM_LEASE_TTL_MS,
        )
        .map_err(|error| DaemonError::TelegramRefused(error.category()))?;

        // Custody storage opens beneath the same fence and before the socket
        // guard is disarmed: a daemon that cannot hold documents must not
        // publish an endpoint that accepts them.
        let run_submissions = RunSubmissionLog::open(config.run_submissions_path())
            .map_err(|error| DaemonError::RunSubmissionFailed(error.category()))?;

        // The listing read model opens beside custody and under the same
        // fence. It is opened even though nothing has to read it: an index
        // that only appears once someone lists would be an index whose first
        // write races its first read, and a submission accepted while it was
        // absent would never be listed at all.
        let run_index = RunIndex::open(config.run_index_path())
            .map_err(|error| DaemonError::RunIndexFailed(error.category()))?;

        // The automation registry opens under the same fence and before the
        // socket guard is disarmed, for the reason custody storage does: a
        // daemon that cannot durably record an operator's decision to pause an
        // automation must not publish an endpoint that accepts one. An
        // in-memory pause that a restart forgets is exactly the failure this
        // registry exists to remove, and serving the lane from a registry that
        // failed to open would reintroduce it silently.
        let automations = AutomationStore::open(config.automation_registry_path())
            .map_err(|error| DaemonError::AutomationStoreFailed(error.category()))?;

        // The host's one cancellation dispatcher and its durable custody open
        // beneath the same fence and before the socket guard is disarmed, for
        // the same reason custody storage does: a daemon that cannot remember
        // which cancellations it delivered must not publish an endpoint at all.
        // This is also the moment the dispatcher's single-instance requirement
        // is satisfied — one bound endpoint and one generation lease per state
        // directory means one dispatcher per ledger file, with no new lock.
        let attempt_host = DaemonAttemptHost::open(config.run_cancel_ledger_path())
            .map_err(|error| DaemonError::AttemptHostFailed(error.category()))?;
        socket_cleanup.disarm();

        Ok(Self {
            listener,
            socket_path,
            store,
            instance_id,
            lease_epoch: lease.epoch,
            lease_expires_ms: lease.expires_ms,
            socket_identity,
            controller: automonique_core::Controller::new(),
            reconciliation_run_id: None,
            telegram,
            run_submissions,
            run_index,
            automations,
            attempt_host: Some(attempt_host),
            execution_state: Self::measure_execution_state(),
        })
    }

    /// Bound local endpoint.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// This daemon's single host-wide cancellation dispatcher.
    ///
    /// Lent by reference and never by value: a second owner over the same
    /// ledger file is exactly the composition
    /// [`attempt_host`](crate::attempt_host) exists to prevent. `None` only
    /// after [`Daemon::serve`] disposed of it, which no caller can observe
    /// because `serve` consumes the daemon.
    ///
    /// Nothing in this build registers an attempt against it: no administration
    /// command routes a cancel, so a running daemon's registry stays empty.
    #[must_use]
    pub fn attempt_host(&self) -> Option<&DaemonAttemptHost> {
        self.attempt_host.as_ref()
    }

    /// Serve until the supplied stop flag is set or an authenticated shutdown
    /// request is accepted.
    ///
    /// # Errors
    ///
    /// Returns an I/O or durable-state failure. Individual hostile clients are
    /// closed and do not stop the daemon.
    pub fn serve(mut self, stop: &AtomicBool) -> Result<(), DaemonError> {
        let mut next_renewal = std::time::Instant::now() + LEASE_RENEW_INTERVAL;
        let result = loop {
            if stop.load(Ordering::Acquire) {
                break Ok(());
            }
            if std::time::Instant::now() >= next_renewal {
                if let Err(error) = self.renew_lease() {
                    break Err(error);
                }
                // The bot lease renews on the same cadence and beneath the
                // just-renewed generation authority; losing it is fencing
                // evidence, not a condition to poll through.
                if let Err(error) = self.telegram.renew() {
                    break Err(DaemonError::TelegramRefused(error.category()));
                }
                next_renewal = std::time::Instant::now() + LEASE_RENEW_INTERVAL;
            }
            if self.reconciliation_run_id.is_none()
                && let Err(error) = self.tick_synthetic()
            {
                break Err(error);
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    // The timed renewal and each store mutation validate the
                    // durable epoch. Read-only status additionally compares a
                    // consistent lease snapshot, so client polling must not
                    // turn into an fsync/lease-write storm.
                    match self.handle_stream(&mut stream, stop) {
                        Ok(()) => {}
                        Err(DaemonError::Store(store_error)) => {
                            if fatal_store_error(&store_error) {
                                break Err(DaemonError::Store(store_error));
                            }
                        }
                        Err(_) => {
                            // A hostile or incomplete peer is isolated to this
                            // connection. Refusal details never contain bytes.
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(error) => break Err(DaemonError::Io(error)),
            }
        };
        // Cancellation dispatch ends first, beneath the still-held generation
        // fence. The lease is what makes "one daemon is one dispatcher" true,
        // so this process stops owning the ledger before it stops owning the
        // generation: no successor can hold the generation while our dispatcher
        // is still live over the same file. Disposal reports exactly one state
        // — a host a panicking sink poisoned, whose last delivery is unknown —
        // and reporting it is why shutdown does not simply drop the field.
        let attempt_host_disposal = self
            .attempt_host
            .take()
            .map_or(Ok(()), DaemonAttemptHost::dispose)
            .map_err(|error| DaemonError::AttemptHostFailed(error.category()));
        // The bot lease releases before the generation lease so its release
        // still runs under a live generation authority; both results defer to
        // any primary serve failure.
        let telegram_release = self
            .telegram
            .release()
            .map_err(|error| DaemonError::TelegramRefused(error.category()));
        let release = unix_millis().and_then(|now_ms| {
            self.store
                .release_generation_lease(
                    GENERATION_ID,
                    self.instance_id.as_str(),
                    self.lease_epoch,
                    now_ms,
                )
                .map_err(DaemonError::Store)
        });
        match result {
            Err(primary) => {
                let _ = attempt_host_disposal;
                let _ = telegram_release;
                let _ = release;
                Err(primary)
            }
            Ok(()) => attempt_host_disposal.and(telegram_release).and(release),
        }
    }

    /// Measure whether this host could enforce the composed sandbox.
    ///
    /// The measurement is the capability module's read-only probe asking for
    /// exactly the properties the composed launch path enforces: containment,
    /// filesystem restriction, TCP denial, and syscall restriction. It runs
    /// once at startup: delegation is a property of the daemon's own cgroup
    /// placement, which does not change while the process lives. The answer
    /// says nothing about executing work — this release wires no lane — and a
    /// refusal is the expected truthful state on an undelegated host.
    fn measure_execution_state() -> automonique_protocol::admin::ExecutionState {
        use automonique_protocol::admin::ExecutionState;
        use automonique_runner::capability::{BoundaryProperty, HostCapabilities};

        let selection = HostCapabilities::probe().select_mode(&[
            BoundaryProperty::DescendantContainment,
            BoundaryProperty::FilesystemRestriction,
            BoundaryProperty::TcpDenial,
            BoundaryProperty::SyscallRestriction,
        ]);
        match selection {
            Ok(_) => ExecutionState::SandboxEnforceableNoLane,
            Err(_) => ExecutionState::SandboxUnavailableNoLane,
        }
    }

    fn renew_lease(&mut self) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let lease = self.store.renew_generation_lease(LeaseRenewal {
            generation_id: GENERATION_ID,
            holder_id: self.instance_id.as_str(),
            epoch: self.lease_epoch,
            now_ms,
            ttl_ms: LEASE_TTL_MS,
        })?;
        self.lease_expires_ms = lease.expires_ms;
        Ok(())
    }

    fn tick_synthetic(&mut self) -> Result<(), DaemonError> {
        use automonique_core::{SchedulerFence, TickOutcome};

        let now_ms = unix_millis()?;
        let fence = SchedulerFence::new(GENERATION_ID, self.instance_id.as_str(), self.lease_epoch)
            .map_err(|_| DaemonError::ProtocolRefused("scheduler_fence"))?;
        let mut durable = synthetic::StoreScheduler::new(
            &mut self.store,
            now_ms,
            LEASE_TTL_MS,
            &mut self.lease_expires_ms,
        );
        match self
            .controller
            .tick(&mut durable, &fence)
            .map_err(|_| DaemonError::ProtocolRefused("scheduler_invariant"))?
        {
            TickOutcome::FenceRejected { .. } => Err(DaemonError::Store(StoreError::StaleEpoch)),
            TickOutcome::Idle
            | TickOutcome::Completed(_)
            | TickOutcome::Replayed(_)
            | TickOutcome::RetryRequired { .. } => Ok(()),
            TickOutcome::ReconciliationRequired(reconciliation) => {
                let run_id = reconciliation
                    .work_id()
                    .parse::<i64>()
                    .map_err(|_| DaemonError::ProtocolRefused("reconciliation_run_id"))?;
                self.reconciliation_run_id = Some(run_id);
                Ok(())
            }
        }
    }

    /// Authenticate the peer, read one bounded frame, and hand it to the lane
    /// its envelope names.
    ///
    /// The socket serves three protocols. Which one a frame belongs to is read
    /// off its declared protocol name by
    /// [`LocalRequest::from_canonical_bytes`], never guessed and never tried in
    /// sequence, so an administration client, a Runs client and an Automation
    /// client receive their own lane's refusals rather than each other's.
    fn handle_stream(
        &mut self,
        stream: &mut UnixStream,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        authenticate_peer(stream)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let payload = read_payload(stream)?;
        match LocalRequest::from_canonical_bytes(&payload)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
        {
            LocalRequest::Admin(request) => self.handle_admin(stream, &request, stop),
            LocalRequest::Runs(request) => self.handle_runs(stream, &request),
            LocalRequest::Automation(request) => self.handle_automation(stream, &request),
        }
    }

    fn handle_admin(
        &mut self,
        stream: &mut UnixStream,
        request: &AdminRequest,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        let response = match request.command() {
            automonique_protocol::admin::AdminCommand::Status => {
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
                if generation.holder_id() != self.instance_id.as_str()
                    || generation.lease_epoch() != self.lease_epoch
                    || generation.lease_expires_ms() != self.lease_expires_ms
                    || generation.lease_expires_ms() <= now_ms
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let degraded = self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot);
                // Read at the snapshot's own instant. A pause and a degraded
                // generation are different reasons for the same closed intake,
                // and the status reports both so an operator can tell which
                // one they are looking at.
                let paused = self.store.intake_paused(GENERATION_ID, now_ms)?.is_some();
                let projection = StoreProjection::from_status(&snapshot)
                    .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?;
                let operational = operational_status(&projection)?;
                let (telegram_state, telegram_poller_epoch) = self.telegram.status();
                let status = DaemonStatus::new(
                    self.instance_id.clone(),
                    if degraded {
                        DaemonState::Failed
                    } else {
                        DaemonState::Ready
                    },
                    self.lease_epoch,
                    snapshot.event_cursor(),
                    snapshot.inbox_pending(),
                    snapshot.outbox_pending(),
                    snapshot.runs_running(),
                    !degraded && !paused,
                )
                .and_then(|status| status.with_intake_pause(paused))
                .and_then(|status| status.with_telegram(telegram_state, telegram_poller_epoch))
                .map(|status| status.with_execution(self.execution_state))
                .and_then(|status| status.with_operational(operational))
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                AdminResponse::Status {
                    request_id: request.request_id().clone(),
                    status,
                }
            }
            automonique_protocol::admin::AdminCommand::SubmitSynthetic => {
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot)
                {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        DaemonError::ReconciliationRequired.category(),
                    );
                }
                // An operator pause closes this lane with its own category, so
                // a client can tell "an operator stopped intake" from "this
                // generation is damaged" without reading the status.
                if self.store.intake_paused(GENERATION_ID, now_ms)?.is_some() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        INTAKE_PAUSED_CATEGORY,
                    );
                }
                let submission = request
                    .submission()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let receipt = self.store.submit_inbox(InboxSubmission {
                    transport: "local.synthetic",
                    transport_key: submission.idempotency_key(),
                    scope: submission.scope(),
                    payload: submission.task().as_bytes(),
                    received_ms: unix_millis()?,
                })?;
                AdminResponse::SyntheticAccepted {
                    request_id: request.request_id().clone(),
                    inbox_id: u64::try_from(receipt.inbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::SubmitRun => {
                // THIS LANE STOPS AT CUSTODY.
                //
                // What follows verifies a document and writes it down. It does
                // not admit the run, build a launch plan, reserve a workspace,
                // compose a sandbox, or start a supervisor — and it must not
                // acquire the habit of doing so quietly. Executing a submitted
                // document would require two things this build does not have:
                // a release trust chain that establishes the provider binary
                // and policy the document names are the ones on this host, and
                // an operator-enabled execution lane that a host can be
                // measured against and refused fail-closed. `execution_state`
                // in the status snapshot reports the second as absent on every
                // host, by construction. Accepting a document therefore
                // establishes custody of it and no authority over anything.
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot)
                {
                    // A degraded generation is not accepting intake, and a
                    // submission is intake even though it schedules nothing.
                    // The reported `accepting_intake` must keep meaning what
                    // the arms actually do.
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        DaemonError::ReconciliationRequired.category(),
                    );
                }
                // A pause closes intake, and custody of a document is intake
                // even though it schedules nothing — the same reasoning that
                // makes a degraded generation refuse here. Gating both lanes is
                // what keeps `accepting_intake == false` a true statement
                // rather than a description of one of the two arms.
                if self.store.intake_paused(GENERATION_ID, now_ms)?.is_some() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        INTAKE_PAUSED_CATEGORY,
                    );
                }
                // The fence is checked here and the row lands in a different
                // database, so this is a check-then-write across two files
                // rather than one transaction. `automonique_store`'s
                // run_submissions module states that race and the specific
                // ground on which a custody row may accept it.
                let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
                if generation.holder_id() != self.instance_id.as_str()
                    || generation.lease_epoch() != self.lease_epoch
                    || generation.lease_expires_ms() != self.lease_expires_ms
                    || generation.lease_expires_ms() <= now_ms
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let submission = request
                    .run_submission()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;

                // 1. The declared digest must name the bytes as received. This
                //    runs before anything parses them, so a document whose
                //    name and contents disagree is refused without ever being
                //    interpreted.
                let spec_digest = Sha256::digest(submission.document());
                if &spec_digest != submission.spec_digest() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "run_spec_digest_mismatch",
                    );
                }
                // 2. Strict decode by the runner's own decoder. The refusal
                //    carries its class and never a byte of the document.
                let spec = match RunSpec::from_canonical_bytes(submission.document()) {
                    Ok(spec) => spec,
                    Err(error) => {
                        return self.write_refusal(
                            stream,
                            request.request_id(),
                            run_spec_decode_category(error),
                        );
                    }
                };
                // 3. Re-encode what the decoder read and require the same
                //    digest, so the digest about to be stored is bound to the
                //    typed value the decoder actually produced.
                //
                //    Stated plainly: while the runner's decoder keeps its own
                //    `NonCanonicalRoundTrip` guard, this cannot fail, and no
                //    test here can distinguish a build with it from one
                //    without. It is kept because that guard is another crate's
                //    private decode step rather than a contract this lane can
                //    hold anyone to, and because the cost is one hash of at
                //    most a few tens of kilobytes. The `not_encodable` arm is
                //    unreachable for the same reason: a document that decoded
                //    from an admin frame cannot re-encode past the runner's
                //    8 MiB ceiling. Both are fail-closed, and neither is
                //    presented here as evidence of anything.
                let reencoded = match spec.to_canonical_bytes() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.write_refusal(
                            stream,
                            request.request_id(),
                            "run_spec_not_encodable",
                        );
                    }
                };
                if Sha256::digest(&reencoded) != spec_digest {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "run_spec_not_canonical",
                    );
                }
                let digest_hex = spec_digest.to_hex();
                let receipt = match self.run_submissions.record(RunSubmission {
                    idempotency_key: submission.idempotency_key(),
                    run_id: spec.run_id().as_str(),
                    spec_digest: &digest_hex,
                    document: submission.document(),
                    accepted_at_ms: now_ms,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if run_submission_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::RunSubmissionFailed(error.category())),
                };
                // CUSTODY FIRST, READ MODEL SECOND — and the order is the
                // whole of the guarantee.
                //
                // The document is durable above. The index row below is a
                // derived read model of it: it holds nothing the submission
                // log does not, and a rebuild from custody could reconstruct
                // every row it contains. Writing it second means a crash
                // between the two loses a listing entry and never a document.
                // The reverse order would let an index name a submission
                // nobody accepted, which `automonique_store::run_index`
                // describes as a broken listing — the failure this ordering
                // buys, in exchange for never presenting a lost document as an
                // absent one.
                //
                // There is no transaction across the two databases and there
                // cannot be one; they are separate files. So a failed
                // registration is a typed daemon error rather than a client
                // refusal: the submitter's document is held, their receipt
                // would be true, and the thing that failed is ours.
                //
                // A replay registers nothing. The store would refuse it with
                // `AlreadyRegistered` anyway — the refusal is tolerated below
                // rather than relied upon — but the deeper reason is ordering:
                // rows are registered in submission order, which is what makes
                // a page ordered by `index_id` also ordered by
                // `submission_id`, and that is the order `RunListPage`
                // requires. Back-filling a submission whose registration
                // failed would insert a row whose submission identity is below
                // its predecessors', and every later listing would be refused
                // as out of order. Such a submission stays unlisted, and a
                // reconcile that rebuilds the read model in order is where it
                // would come back.
                if !receipt.disposition.is_replay() {
                    match self.run_index.register(RunIndexEntry {
                        submission_id: receipt.submission_id,
                        run_id: spec.run_id().as_str(),
                        registered_at_ms: now_ms,
                    }) {
                        Ok(_) | Err(RunIndexError::AlreadyRegistered { .. }) => {}
                        Err(error) => return Err(DaemonError::RunIndexFailed(error.category())),
                    }
                }
                AdminResponse::RunAccepted {
                    request_id: request.request_id().clone(),
                    run_id: spec.run_id().clone(),
                    spec_digest,
                    submission_id: u64::try_from(receipt.submission_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    replay: receipt.disposition.is_replay(),
                }
            }
            automonique_protocol::admin::AdminCommand::InspectReconciliation => {
                let run_id = request
                    .reconciliation_run_id()
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let evidence = match self.store.inspect_reconciliation(run_id) {
                    Ok(evidence) => evidence,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::ReconciliationInspected {
                    request_id: request.request_id().clone(),
                    evidence: AdminReconciliationEvidence::new(
                        u64::try_from(evidence.run_id)
                            .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                        evidence.scope,
                        evidence.generation_id,
                        evidence.lease_epoch,
                        evidence.run_revision,
                        evidence.terminal_payload_present,
                        evidence.outbox_count,
                    )
                    .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
                }
            }
            automonique_protocol::admin::AdminCommand::FailReconciliation => {
                let failure = request
                    .reconciliation_failure()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let run_id = i64::try_from(failure.run_id())
                    .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?;
                let receipt = match self.store.reconcile_run(ReconciliationRequest {
                    run_id,
                    authority_generation_id: GENERATION_ID,
                    authority_holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    expected_generation_id: failure.expected_generation_id(),
                    expected_lease_epoch: failure.expected_lease_epoch(),
                    expected_revision: failure.expected_revision(),
                    decision_key: failure.decision_key(),
                    now_ms: unix_millis()?,
                    decision: ReconciliationDecision::Fail {
                        reason: failure.reason(),
                    },
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                if self.reconciliation_run_id == Some(run_id) {
                    self.reconciliation_run_id = None;
                }
                AdminResponse::ReconciliationFailed {
                    request_id: request.request_id().clone(),
                    run_event_id: u64::try_from(receipt.run_event_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    inbox_event_id: u64::try_from(receipt.inbox_event_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    outbox_id: u64::try_from(receipt.outbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::InspectOutbox => {
                let outbox_id = request
                    .outbox_id()
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let evidence = match self.store.inspect_outbox_reconciliation(outbox_id) {
                    Ok(evidence) => evidence,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::OutboxInspected {
                    request_id: request.request_id().clone(),
                    evidence: AdminOutboxEvidence::new(AdminOutboxEvidenceParts {
                        outbox_id: u64::try_from(evidence.outbox_id)
                            .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                        intent_key: evidence.intent_key,
                        transport: evidence.transport,
                        kind: evidence.kind,
                        state: evidence.state,
                        revision: evidence.revision,
                        attempt: evidence.attempt,
                        lease_token: evidence.lease_token,
                        lease_generation_id: evidence.lease_generation_id,
                        lease_holder: evidence.lease_holder,
                        lease_epoch: evidence.lease_epoch,
                        lease_expires_ms: evidence
                            .lease_expires_ms
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                        delivery_receipt_key: evidence.delivery_receipt_key,
                    })
                    .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
                }
            }
            automonique_protocol::admin::AdminCommand::ReconcileOutbox => {
                let reconciliation = request
                    .outbox_reconciliation()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let outbox_id = i64::try_from(reconciliation.outbox_id())
                    .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?;
                let decision = match reconciliation.decision() {
                    OutboxReconciliationDecision::Delivered { receipt_key } => {
                        StoreOutboxDecision::Delivered { receipt_key }
                    }
                    OutboxReconciliationDecision::DeadLetter { reason } => {
                        StoreOutboxDecision::DeadLetter { reason }
                    }
                };
                let receipt = match self.store.reconcile_outbox(OutboxReconciliationRequest {
                    outbox_id,
                    authority_generation_id: GENERATION_ID,
                    authority_holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    expected_generation_id: reconciliation.expected_generation_id(),
                    expected_lease_epoch: reconciliation.expected_lease_epoch(),
                    expected_lease_token: reconciliation.expected_lease_token(),
                    expected_attempt: reconciliation.expected_attempt(),
                    expected_revision: reconciliation.expected_revision(),
                    now_ms: unix_millis()?,
                    decision,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::OutboxReconciled {
                    request_id: request.request_id().clone(),
                    outbox_id: u64::try_from(receipt.outbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    state: receipt.state,
                    revision: receipt.revision,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::PauseIntake => {
                // WHAT A PAUSE IS SCOPED TO, AND WHAT THAT COSTS.
                //
                // The durable row names `GENERATION_ID` — the identifier, not
                // the lease epoch that wrote it. Two consequences follow, and
                // only one of them is obvious:
                //
                // - A restart keeps the pause. This daemon always takes the
                //   same named generation, so a successor process reads the
                //   same row and comes back with intake closed. That is the
                //   point: an operator who paused before a crash should not
                //   have their decision quietly undone by the recovery.
                // - A *different* generation does not see it. Its intake is
                //   open on the first tick, and its operator must pause it
                //   themselves. Nothing here warns them.
                //
                // A global pause — one row gating every generation — is the
                // other reasonable policy, and it is a policy choice rather
                // than a correctness fix. It is deliberately not implemented:
                // it would let one operator close intake for a control plane
                // they may not own, which is a decision for whoever owns this
                // product to make, not for this handler to assume.
                let pause = request
                    .intake_pause()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let receipt = match self.store.pause_intake(IntakePauseRequest {
                    generation_id: GENERATION_ID,
                    holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    actor: pause.actor(),
                    reason: pause.reason(),
                    now_ms: unix_millis()?,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if intake_pause_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::IntakePaused {
                    request_id: request.request_id().clone(),
                    pause_id: u64::try_from(receipt.pause_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    revision: receipt.revision,
                }
            }
            automonique_protocol::admin::AdminCommand::ResumeIntake => {
                let resume = request
                    .intake_resume()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let now_ms = unix_millis()?;
                // The revision the resume presents is read here rather than
                // supplied by the client: a resume closes whichever pause is
                // live, and asking an operator to quote a revision they cannot
                // see would make the command unusable. The store still
                // compare-and-sets on it inside its own transaction, so a
                // concurrent writer between this read and that write is
                // refused rather than overwritten.
                let Some(live) = self.store.intake_paused(GENERATION_ID, now_ms)? else {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        StoreError::NotPaused.category(),
                    );
                };
                let receipt = match self.store.resume_intake(IntakeResumeRequest {
                    generation_id: GENERATION_ID,
                    holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    actor: resume.actor(),
                    expected_revision: live.revision,
                    now_ms,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if intake_pause_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::IntakeResumed {
                    request_id: request.request_id().clone(),
                    pause_id: u64::try_from(receipt.pause_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    revision: receipt.revision,
                }
            }
            automonique_protocol::admin::AdminCommand::Shutdown => {
                AdminResponse::ShutdownAccepted {
                    request_id: request.request_id().clone(),
                }
            }
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        if matches!(
            request.command(),
            automonique_protocol::admin::AdminCommand::Shutdown
        ) {
            stop.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Answer one read on the native Runs API.
    ///
    /// Fenced like every other arm: a daemon that has lost its generation
    /// answers nothing, because a read served from a database another
    /// generation now owns is a read of somebody else's state.
    ///
    /// Unlike the intake arms, this is *not* closed by a pause or by a
    /// degraded generation. A pause stops the daemon taking custody of new
    /// work; it does not make what is already held unreadable, and an operator
    /// diagnosing a degraded generation is precisely the person who needs to
    /// list what it holds.
    fn handle_runs(
        &mut self,
        stream: &mut UnixStream,
        request: &RunsRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= now_ms
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            RunsRequest::ListRuns { request_id, query } => self.list_runs(request_id, query)?,
            RunsRequest::RunDetail { request_id, run_id } => self.run_detail(request_id, run_id)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// One bounded page of runs, or the resync a lost cursor earns.
    ///
    /// Every answer is built by [`RunsResponse::listing`] from the decision
    /// [`ListRuns::resume_within`] made, so a page that contradicts its own
    /// retention decision is refused here rather than served. This handler
    /// supplies the two things that module deliberately does not have — the
    /// real retained window and the rows — and nothing else.
    fn list_runs(
        &self,
        request_id: &RequestId,
        query: &ListRuns,
    ) -> Result<RunsResponse, DaemonError> {
        let Some(retained) = self.retained_runs()? else {
            // AN EMPTY INDEX RETAINS NOTHING AND HAS LOST NOTHING.
            //
            // There is no window to judge a cursor against, and inventing one
            // would mean answering `resync_required` — "positions you wanted
            // are gone" — about a log from which nothing has ever been
            // removed. Nothing here deletes, so a cursor ahead of an empty
            // index is caught up rather than lost, and the truthful answer is
            // an empty page that says it is complete.
            let from = query.since().map_or(1, RunCursor::position);
            let page =
                RunListPage::new(Vec::new(), Continuation::Complete).map_err(runs_refused)?;
            return RunsResponse::listing(
                request_id.clone(),
                query,
                CursorResume::Live { from },
                Some(page),
            )
            .map_err(runs_refused);
        };
        let decision = query.resume_within(retained.window);
        let CursorResume::Live { from } = decision else {
            return RunsResponse::listing(request_id.clone(), query, decision, None)
                .map_err(runs_refused);
        };
        let cursor = self.index_cursor_below(from, &retained)?;
        let limit = query.page_size().get();
        let page = match query.states().states() {
            // The filter is translated variant by variant, so a state this
            // build cannot name is a compile failure rather than a row the
            // listing silently drops.
            Some(states) => {
                let states: Vec<RunSpoolState> = states.iter().copied().map(spool_state).collect();
                self.run_index.page_in_states(cursor, limit, &states)
            }
            None => self.run_index.page(cursor, limit),
        }
        .map_err(index_failed)?;
        let mut runs = Vec::with_capacity(page.entries.len());
        for record in &page.entries {
            runs.push(self.summary(record)?);
        }
        // `next_cursor` is set only when the store saw a further *matching*
        // row, so a page shortened by the state filter still reports itself
        // complete only when nothing matching remains. The cursor is one past
        // the last submission served, which is the next identity a caller
        // receives — the coordinate a `RunCursor` names.
        let continuation = match (page.next_cursor, runs.last()) {
            (Some(_), Some(last)) => Continuation::More(RunCursor::new(
                last.submission_id()
                    .checked_add(1)
                    .ok_or(DaemonError::ProtocolRefused("counter_out_of_range"))?,
            )),
            _ => Continuation::Complete,
        };
        let page = RunListPage::new(runs, continuation).map_err(runs_refused)?;
        RunsResponse::listing(request_id.clone(), query, decision, Some(page)).map_err(runs_refused)
    }

    /// One run in full, or [`RunsRefusal::UnknownRun`].
    ///
    /// A run identity is not unique — `run_submissions` admits two submissions
    /// naming one run, and so does the index — so this answers with the most
    /// recently registered of them. The summary carries the exact
    /// `submission_id` it was built from, so the answer says which one it is
    /// rather than leaving a caller to assume there was only ever one.
    fn run_detail(
        &self,
        request_id: &RequestId,
        run_id: &RunId,
    ) -> Result<RunsResponse, DaemonError> {
        let records = self
            .run_index
            .by_run_id(run_id.as_str())
            .map_err(index_failed)?;
        let Some(record) = records.last() else {
            return Ok(RunsResponse::Refused {
                request_id: request_id.clone(),
                refusal: RunsRefusal::UnknownRun,
            });
        };
        // THE LIFECYCLE IS THE SUBSCRIBE LANE'S, NOT THIS HANDLER'S.
        //
        // The index holds a state and a last sequence. It does not hold the
        // events themselves — those live in the runner's durable spool, one
        // directory per run, served by that endpoint's `subscribe`. So a view
        // built here carries no lifecycle at all, and `LifecycleCoverage`
        // makes that a statement rather than an omission: `complete` with an
        // empty lifecycle is only coherent for a `ready` run at sequence zero,
        // which is exactly what a run whose events do not exist is.
        //
        // A row that has moved cannot be served from here at all. `truncated`
        // requires at least one carried event, so this handler would have to
        // invent one or misdeclare coverage, and it will do neither. Nothing
        // in this build advances an index row — no execution lane writes a
        // spool — so this is unreachable today; when that lane lands, this
        // arm reads the spool rather than growing a synthetic event.
        if record.spool_state != RunSpoolState::Ready || record.last_sequence != 0 {
            return Err(DaemonError::ProtocolRefused("run_lifecycle_unavailable"));
        }
        let view = RunDetailView::new(
            self.summary(record)?,
            record.last_sequence,
            Vec::new(),
            LifecycleCoverage::Complete,
        )
        .map_err(runs_refused)?;
        Ok(RunsResponse::RunDetail {
            request_id: request_id.clone(),
            view,
        })
    }

    /// Join one index row against the custody it derives from.
    ///
    /// The index knows the run's state; the submission log knows the digest
    /// the daemon verified and the instant it accepted. A summary is the pair,
    /// and this is the join `runs_api` names as the seam it left open.
    ///
    /// An index row whose submission is absent is refused rather than skipped.
    /// Skipping would shorten a page without saying so, which is the silent
    /// drop the whole retention rule exists to prevent; refusing makes a
    /// broken read model visible on the first read instead of on none.
    fn summary(&self, record: &RunIndexRecord) -> Result<RunSummary, DaemonError> {
        let entry = self
            .run_submissions
            .run_submissions(&record.run_id)
            .map_err(|error| DaemonError::RunSubmissionFailed(error.category()))?
            .into_iter()
            .find(|entry| entry.submission_id == record.submission_id)
            .ok_or(DaemonError::RunIndexFailed("run_index_dangling_row"))?;
        // The digest is the column the daemon wrote after verifying it against
        // the document bytes at acceptance. It is re-parsed, not re-computed:
        // re-hashing every stored document on every page would make a listing
        // a custody audit, which is a different operation with a different
        // cost, and this read does not claim to have performed one.
        let spec_digest: Sha256Digest = format!("{ALGORITHM}:{}", entry.spec_digest)
            .parse()
            .map_err(|_| DaemonError::RunSubmissionFailed("corrupt"))?;
        RunSummary::new(
            RunId::new(&record.run_id)
                .map_err(|_| DaemonError::RunIndexFailed("run_index_run_id_ungrammatical"))?,
            checked_row_id(record.submission_id)?,
            spec_digest,
            run_state(record.spool_state),
            submission_state(entry.state),
            automonique_protocol::primitives::EpochMillis::from_millis(entry.accepted_at_ms),
        )
        .map_err(runs_refused)
    }

    /// The window of submission identities the index still holds, and the
    /// highest index position it holds them at.
    ///
    /// Both bounds are read from the index rather than assumed: nothing
    /// deletes today, so the floor is the first row ever registered, but a
    /// later retention policy would move it and this keeps saying something
    /// true when it does.
    ///
    /// `None` when the index is empty, which is a different answer than a
    /// window and is treated as one by the caller.
    fn retained_runs(&self) -> Result<Option<RetainedRuns>, DaemonError> {
        let Some(window) = self.run_index.retained_range().map_err(index_failed)? else {
            return Ok(None);
        };
        let first = self.submission_after(window.first.saturating_sub(1))?;
        let last = self.submission_after(window.last.saturating_sub(1))?;
        Ok(Some(RetainedRuns {
            window: RetainedRange::new(first, last)
                .map_err(|_| DaemonError::RunIndexFailed("run_index_inverted_window"))?,
            last_index: window.last,
        }))
    }

    /// The submission identity of the first row above an exclusive index
    /// cursor.
    fn submission_after(&self, cursor: u64) -> Result<u64, DaemonError> {
        let page = self.run_index.page(cursor, 1).map_err(index_failed)?;
        let record = page
            .entries
            .first()
            .ok_or(DaemonError::RunIndexFailed("run_index_row_missing"))?;
        checked_row_id(record.submission_id)
    }

    /// The exclusive index cursor a page beginning at submission `from` starts
    /// after.
    ///
    /// The listing's cursor is a *submission* identity, because that is what a
    /// `RunCursor` names and what `RunListPage` orders by. The store pages by
    /// `index_id`. The two agree in order — rows are registered in submission
    /// order, and nothing back-fills — but they are not the same number, so
    /// one has to be translated into the other.
    ///
    /// The translation is a binary search over index positions, which costs at
    /// most sixteen single-row reads against a full 65 536-row index and none
    /// at all in the common case of a listing that starts at the floor. A scan
    /// would also be correct and would cost the whole table; a
    /// submission-keyed page query in the store would cost nothing and is
    /// where this belongs when that store grows one.
    fn index_cursor_below(&self, from: u64, retained: &RetainedRuns) -> Result<u64, DaemonError> {
        if from <= retained.window.first() {
            return Ok(0);
        }
        // Invariant: every row at or below `low` carries a submission below
        // `from`, and the row above `high` — if any — carries one at or above
        // it. `high` starts at the last index position, where the invariant
        // holds because there is no row above it.
        let mut low = 0;
        let mut high = retained.last_index;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.submission_after(middle)? >= from {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        Ok(low)
    }

    /// Answer one operation on the native Automation control API.
    ///
    /// # What an accepted write here does, and what it does not
    ///
    /// It commits one row to the durable registry saying that somebody
    /// claiming to be `actor` decided this automation is, or is no longer, in
    /// service. **Nothing else happens.** This daemon has no scheduler, no
    /// trigger evaluator and no executor, so:
    ///
    /// - registering an automation starts nothing;
    /// - pausing one suppresses nothing, because nothing was running; and
    /// - resuming one resumes nothing.
    ///
    /// That is why an accepted write answers `accepted` rather than
    /// `completed`: the row is committed, and the decision the row records has
    /// not taken effect anywhere, because there is nowhere for it to take
    /// effect yet.
    ///
    /// # Fencing
    ///
    /// Fenced exactly as [`Daemon::handle_runs`] is, and for a stronger reason:
    /// this lane *writes*. A daemon that has lost its generation must not
    /// record an operator's decision into a database another generation now
    /// owns, and must not serve one out of it either.
    ///
    /// Unlike the intake arms, this is *not* closed by an operator pause or by
    /// a degraded generation. An intake pause stops the daemon taking custody
    /// of new work; withdrawing an automation from service is the opposite of
    /// taking on work, and an operator repairing a degraded generation is
    /// precisely the person who needs to pause the automations on it.
    fn handle_automation(
        &mut self,
        stream: &mut UnixStream,
        request: &AutomationRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= now_ms
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            AutomationRequest::RegisterAutomation {
                request_id,
                registration,
            } => self.register_automation(request_id, registration, now_ms)?,
            AutomationRequest::SetEnablement {
                request_id,
                transition,
            } => self.set_enablement(request_id, transition, now_ms)?,
            AutomationRequest::ListAutomations { request_id, query } => {
                self.list_automations(request_id, query)?
            }
            AutomationRequest::AutomationDetail {
                request_id,
                automation_id,
            } => self.automation_detail(request_id, automation_id)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// Record one new automation, enabled, at revision one.
    fn register_automation(
        &mut self,
        request_id: &RequestId,
        registration: &RegisterAutomation,
        now_ms: i64,
    ) -> Result<AutomationResponse, DaemonError> {
        let receipt = match self.automations.register(AutomationRegistration {
            automation_id: registration.automation_id().as_str(),
            actor: registration.actor().as_str(),
            now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::Accepted {
            request_id: request_id.clone(),
            receipt: AutomationReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                registration.automation_id().clone(),
                enablement_state(receipt.enablement),
                receipt.revision,
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.updated_at_ms),
            )
            .map_err(automation_refused)?,
        })
    }

    /// Move one automation along the enablement lattice.
    ///
    /// The cause coupling was already decided by the protocol's own decoder —
    /// a causeless pause never reaches this function — and the store decides it
    /// again. Neither check is redundant: the first refuses a malformed request
    /// before it touches durable state, and the second refuses a malformed row
    /// without trusting us.
    fn set_enablement(
        &mut self,
        request_id: &RequestId,
        transition: &SetEnablement,
        now_ms: i64,
    ) -> Result<AutomationResponse, DaemonError> {
        let receipt = match self.automations.transition(EnablementTransition {
            automation_id: transition.automation_id().as_str(),
            expected_revision: transition.expected_revision(),
            new_enablement: store_enablement_state(transition.target()),
            actor: transition.actor().as_str(),
            cause: transition.cause().map(PauseReason::as_str),
            now_ms,
        }) {
            Ok(receipt) => receipt,
            // A stale expected revision is a `conflict`, not a `rejected`: the
            // caller's request was well-formed and the row simply moved, and
            // the two are retried differently. The durable revision travels
            // with the answer so a retry does not need a second round trip.
            Err(AutomationStoreError::RevisionMismatch { expected, durable }) => {
                return AutomationResponse::conflict(request_id.clone(), expected, durable)
                    .map_err(automation_refused);
            }
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::Accepted {
            request_id: request_id.clone(),
            receipt: AutomationReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                transition.automation_id().clone(),
                enablement_state(receipt.enablement),
                receipt.revision,
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.updated_at_ms),
            )
            .map_err(automation_refused)?,
        })
    }

    /// One bounded page of automations.
    ///
    /// The wire cursor is the store's own exclusive `entry_id` position, so
    /// nothing is translated between the two coordinate spaces and there is no
    /// off-by-one to re-derive — the failure the run listing had to work around
    /// because it pages by a different key than it is cursored on.
    fn list_automations(
        &self,
        request_id: &RequestId,
        query: &ListAutomations,
    ) -> Result<AutomationResponse, DaemonError> {
        let cursor = query.since().position();
        let limit = query.page_size().get();
        let page = match query.states().states() {
            // Translated variant by variant, so a state this build cannot name
            // is a compile failure rather than a row the listing silently
            // drops.
            Some(states) => {
                let states: Vec<StoreEnablementState> =
                    states.iter().copied().map(store_enablement_state).collect();
                self.automations.page_in_states(cursor, limit, &states)
            }
            None => self.automations.page(cursor, limit),
        };
        let page = match page {
            Ok(page) => page,
            Err(error) => return refuse_automation(request_id, &error),
        };
        let mut entries = Vec::with_capacity(page.entries.len());
        for record in &page.entries {
            entries.push(automation_record(record)?);
        }
        // `next_cursor` is set only when the store saw a further *matching*
        // row, so a page shortened by the state filter still reports itself
        // complete only when nothing matching remains.
        let continuation = match page.next_cursor {
            Some(next) => AutomationContinuation::More(AutomationCursor::new(next)),
            None => AutomationContinuation::Complete,
        };
        let page = AutomationListPage::new(entries, continuation).map_err(automation_refused)?;
        AutomationResponse::listing(request_id.clone(), query, page).map_err(automation_refused)
    }

    /// One automation in full, or [`AutomationRefusal::UnknownAutomation`].
    fn automation_detail(
        &self,
        request_id: &RequestId,
        automation_id: &AutomationId,
    ) -> Result<AutomationResponse, DaemonError> {
        let record = match self.automations.entry(automation_id.as_str()) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Ok(AutomationResponse::Refused {
                    request_id: request_id.clone(),
                    refusal: AutomationRefusal::UnknownAutomation,
                });
            }
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::AutomationDetail {
            request_id: request_id.clone(),
            record: automation_record(&record)?,
        })
    }

    fn write_refusal(
        &self,
        stream: &mut UnixStream,
        request_id: &automonique_protocol::codec::RequestId,
        category: &str,
    ) -> Result<(), DaemonError> {
        let response = AdminResponse::Refused {
            request_id: request_id.clone(),
            category: AdminRefusalCategory::new(category)
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        }
        .to_message()
        .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
        .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }
}

/// What the run index retains, in the two coordinate spaces a listing needs.
struct RetainedRuns {
    /// Submission identities still listable, which is what a cursor names.
    window: RetainedRange,
    /// Highest `index_id` recorded, which is what the store pages by.
    last_index: u64,
}

/// Translate the index's state vocabulary into the wire's.
///
/// Two closed six-word enums that mirror one another and one exhaustive match
/// between them. Deliberately not a spelling comparison: a variant added or
/// renamed on either side fails to compile here, where a lookup by word would
/// have failed at runtime on the first row that carried it.
const fn run_state(state: RunSpoolState) -> RunState {
    match state {
        RunSpoolState::Ready => RunState::Ready,
        RunSpoolState::Running => RunState::Running,
        RunSpoolState::Completed => RunState::Completed,
        RunSpoolState::Failed => RunState::Failed,
        RunSpoolState::Cancelled => RunState::Cancelled,
        RunSpoolState::TimedOut => RunState::TimedOut,
    }
}

/// Translate a wire state filter into the index's vocabulary.
const fn spool_state(state: RunState) -> RunSpoolState {
    match state {
        RunState::Ready => RunSpoolState::Ready,
        RunState::Running => RunSpoolState::Running,
        RunState::Completed => RunSpoolState::Completed,
        RunState::Failed => RunSpoolState::Failed,
        RunState::Cancelled => RunSpoolState::Cancelled,
        RunState::TimedOut => RunSpoolState::TimedOut,
    }
}

/// Translate the custody vocabulary into the wire's.
///
/// One variant each, because the store's `CHECK (state IN ('accepted'))` admits
/// one value. The match grows when that constraint does, and not before.
const fn submission_state(state: RunSubmissionState) -> SubmissionState {
    match state {
        RunSubmissionState::Accepted => SubmissionState::Accepted,
    }
}

/// A durable row identity, refused rather than wrapped when it is not one.
///
/// SQLite rowids are signed and the protocol's are not. A negative identity is
/// a row this build could not have written, so it is refused here instead of
/// becoming an enormous unsigned coordinate further down.
fn checked_row_id(value: i64) -> Result<u64, DaemonError> {
    u64::try_from(value).map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))
}

fn runs_refused(error: automonique_protocol::runs_api::RunsApiError) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

fn automation_refused(
    error: automonique_protocol::automation_api::AutomationApiError,
) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

/// Translate the registry's enablement vocabulary into the wire's.
///
/// Two closed three-word enums that mirror one another and one exhaustive match
/// between them. Deliberately not a spelling comparison: a variant added or
/// renamed on either side fails to compile here, where a lookup by word would
/// have failed at runtime on the first row that carried it.
const fn enablement_state(state: StoreEnablementState) -> EnablementState {
    match state {
        StoreEnablementState::Enabled => EnablementState::Enabled,
        StoreEnablementState::Paused => EnablementState::Paused,
        StoreEnablementState::Archived => EnablementState::Archived,
    }
}

/// Translate the wire's enablement vocabulary into the registry's.
const fn store_enablement_state(state: EnablementState) -> StoreEnablementState {
    match state {
        EnablementState::Enabled => StoreEnablementState::Enabled,
        EnablementState::Paused => StoreEnablementState::Paused,
        EnablementState::Archived => StoreEnablementState::Archived,
    }
}

/// Project one validated registry row onto the wire.
///
/// Every field is re-validated by the protocol's own constructor rather than
/// trusted through: the store validated it against its grammar, and this
/// validates it against the wire's, which is the one a client will decode
/// under. A row the wire cannot carry is a typed daemon failure rather than a
/// row silently omitted from a page — the same rule the run listing follows for
/// a dangling index row.
fn automation_record(record: &AutomationRecord) -> Result<AutomationRecordView, DaemonError> {
    use automonique_protocol::primitives::EpochMillis;

    AutomationRecordView::new(AutomationRecordParts {
        entry_id: checked_row_id(record.entry_id)?,
        automation_id: AutomationId::new(&record.automation_id)
            .map_err(|_| DaemonError::AutomationStoreFailed("automation_id_ungrammatical"))?,
        revision: record.revision,
        enablement: enablement_state(record.enablement),
        actor: AutomationActor::new(&record.actor)
            .map_err(|_| DaemonError::AutomationStoreFailed("actor_ungrammatical"))?,
        cause: record
            .cause
            .as_deref()
            .map(PauseReason::new)
            .transpose()
            .map_err(|_| DaemonError::AutomationStoreFailed("cause_ungrammatical"))?,
        created_at: EpochMillis::from_millis(record.created_at_ms),
        updated_at: EpochMillis::from_millis(record.updated_at_ms),
    })
    .map_err(automation_refused)
}

/// Answer one automation-registry failure to the client, or report it as ours.
///
/// The split is the same one the submission log gets: a malformed field, a
/// duplicate registration, an illegal move, an incoherent cause, a lost cursor
/// and a full registry are the operator's to fix and are answered with one
/// closed word carrying no echo of what they sent. Corruption, a schema
/// mismatch, an unsafe path and storage failure are *ours* — they say the
/// daemon's own durable state is unsound — and presenting them as a refusal
/// would blame an operator for our broken database.
///
/// [`AutomationStoreError::RevisionMismatch`] never reaches here: it is the
/// `conflict` answer, handled at the call site before this function is asked.
fn refuse_automation(
    request_id: &RequestId,
    error: &AutomationStoreError,
) -> Result<AutomationResponse, DaemonError> {
    let refusal = match error {
        AutomationStoreError::InvalidField(_) => AutomationRefusal::InvalidField,
        AutomationStoreError::AlreadyRegistered { .. } => AutomationRefusal::AlreadyRegistered,
        AutomationStoreError::NotFound(_) => AutomationRefusal::UnknownAutomation,
        AutomationStoreError::IllegalTransition { .. } => AutomationRefusal::IllegalTransition,
        AutomationStoreError::CauseRequired { .. } => AutomationRefusal::CauseRequired,
        AutomationStoreError::CauseForbidden { .. } => AutomationRefusal::CauseForbidden,
        AutomationStoreError::CursorOutOfRange { .. } => AutomationRefusal::CursorOutOfRange,
        AutomationStoreError::RegistryFull { .. } => AutomationRefusal::RegistryFull,
        AutomationStoreError::RevisionMismatch { .. }
        | AutomationStoreError::InsecurePath(_)
        | AutomationStoreError::SchemaVersion { .. }
        | AutomationStoreError::Corrupt(_)
        | AutomationStoreError::Io(_)
        | AutomationStoreError::Sqlite(_) => {
            return Err(DaemonError::AutomationStoreFailed(error.category()));
        }
    };
    Ok(AutomationResponse::Refused {
        request_id: request_id.clone(),
        refusal,
    })
}

fn index_failed(error: RunIndexError) -> DaemonError {
    DaemonError::RunIndexFailed(error.category())
}

fn snapshot_requires_reconciliation(snapshot: &StatusSnapshot) -> bool {
    snapshot.runs_reconciliation_pending() > 0 || snapshot.outbox_in_flight_ambiguous() > 0
}

fn operational_status(projection: &StoreProjection) -> Result<OperationalStatus, DaemonError> {
    let metrics = projection.metrics();
    let measured = |name| match metrics.value(name) {
        MetricValue::Measured(value) => Ok(value),
        MetricValue::Unavailable(_) => Err(DaemonError::ProtocolRefused("operational_projection")),
    };
    let projected = |name| match metrics.value(name) {
        MetricValue::Measured(value) => OperationalMetric::measured(value),
        MetricValue::Unavailable(_) => Ok(OperationalMetric::Unavailable),
    };
    OperationalStatus::new(OperationalStatusParts {
        observed_ms: metrics.observed_ms(),
        reconciliation_pending: measured(MetricName::ReconciliationPending)?,
        outbox_pending_ready: measured(MetricName::OutboxPendingReady)?,
        outbox_pending_delayed: measured(MetricName::OutboxPendingDelayed)?,
        outbox_in_flight_live: measured(MetricName::OutboxInFlightLive)?,
        outbox_in_flight_ambiguous: measured(MetricName::OutboxInFlightAmbiguous)?,
        outbox_delivered: measured(MetricName::OutboxDelivered)?,
        outbox_dead_lettered: measured(MetricName::OutboxDeadLettered)?,
        outbox_oldest_ready_age_ms: measured(MetricName::OutboxOldestAgeMs)?,
        telegram_pollers_live: measured(MetricName::TelegramPollersLive)?,
        telegram_pollers_expired: measured(MetricName::TelegramPollersExpired)?,
        telegram_offset_lag: projected(MetricName::TelegramOffsetLag)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        provider_available: projected(MetricName::ProviderAvailable)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        sandbox_launch_refusals: projected(MetricName::SandboxLaunchRefusals)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
    })
    .map_err(|error| DaemonError::ProtocolRefused(error.category()))
}

impl Drop for Daemon {
    fn drop(&mut self) {
        remove_socket_if_identity(&self.socket_path, self.socket_identity);
    }
}

fn remove_socket_if_identity(path: &Path, identity: (u64, u64)) {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_socket()
        && metadata.uid() == geteuid().as_raw()
        && (metadata.dev(), metadata.ino()) == identity
    {
        let _ = fs::remove_file(path);
    }
}

/// Run the daemon with SIGINT/SIGTERM translated into the same orderly stop
/// path as the local shutdown command.
///
/// # Errors
///
/// Returns setup, signal, store, or serving failures.
pub fn run_foreground(config: &DaemonConfig) -> Result<(), DaemonError> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    let mut old_signals = SigSet::empty();
    pthread_sigmask(
        SigmaskHow::SIG_BLOCK,
        Some(&signals),
        Some(&mut old_signals),
    )
    .map_err(DaemonError::Signal)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    let signal_fd = match SignalFd::with_flags(&signals, SfdFlags::SFD_NONBLOCK) {
        Ok(signal_fd) => signal_fd,
        Err(error) => {
            let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&old_signals), None);
            return Err(DaemonError::Signal(error));
        }
    };
    let signal_thread = std::thread::spawn(move || {
        while !signal_stop.load(Ordering::Acquire) {
            match signal_fd.read_signal() {
                Ok(Some(_)) => signal_stop.store(true, Ordering::Release),
                Ok(None) => std::thread::sleep(ACCEPT_POLL),
                Err(_) => signal_stop.store(true, Ordering::Release),
            }
        }
    });
    let result = Daemon::open(config).and_then(|daemon| daemon.serve(&stop));
    if !stop.load(Ordering::Acquire) {
        stop.store(true, Ordering::Release);
    }
    let joined = signal_thread
        .join()
        .map_err(|_| DaemonError::Signal(nix::errno::Errno::EIO));
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&old_signals), None)
        .map_err(DaemonError::Signal);
    result.and(joined).and(restored)
}

fn read_payload(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut prefix)?;
    let declared = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| DaemonError::ProtocolRefused("frame_too_large"))?;
    if declared == 0 || declared > MAX_ADMIN_PAYLOAD_BYTES {
        return Err(DaemonError::ProtocolRefused("frame_size"));
    }
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + declared);
    framed.extend_from_slice(&prefix);
    framed.resize(LENGTH_PREFIX_BYTES + declared, 0);
    stream.read_exact(&mut framed[LENGTH_PREFIX_BYTES..])?;
    match decode_frame(&framed).map_err(|error| DaemonError::ProtocolRefused(error.category()))? {
        automonique_protocol::codec::FrameDecode::Frame { payload, consumed }
            if consumed == framed.len() =>
        {
            Ok(payload.to_vec())
        }
        _ => Err(DaemonError::ProtocolRefused("incomplete_frame")),
    }
}

fn authenticate_peer(stream: &UnixStream) -> Result<(), DaemonError> {
    let credentials =
        getsockopt(stream, sockopt::PeerCredentials).map_err(|_| DaemonError::PeerDenied)?;
    if credentials.uid() != geteuid().as_raw() || credentials.pid() <= 0 {
        return Err(DaemonError::PeerDenied);
    }
    Ok(())
}

fn prepare_socket_path(path: &Path) -> Result<(), DaemonError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
        return Err(DaemonError::InsecurePath("admin socket"));
    }
    let identity = (metadata.dev(), metadata.ino());
    match UnixStream::connect(path) {
        Ok(_) => Err(DaemonError::AlreadyRunning),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.uid() != geteuid().as_raw()
                || (current.dev(), current.ino()) != identity
            {
                return Err(DaemonError::InsecurePath("admin socket"));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) => Err(DaemonError::Io(error)),
    }
}

fn validate_root(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(DaemonError::InsecurePath(kind));
    }
    validate_components(path, kind)?;
    let metadata = fs::symlink_metadata(path).map_err(DaemonError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(DaemonError::InsecurePath(kind));
    }
    Ok(())
}

fn validate_components(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current).map_err(DaemonError::Io)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(DaemonError::InsecurePath(kind));
                }
            }
            _ => return Err(DaemonError::InsecurePath(kind)),
        }
    }
    Ok(())
}

fn ensure_private_dir(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(DaemonError::InsecurePath(kind));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => validate_root(path, kind),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(DaemonError::InsecurePath(kind))?;
            validate_root(parent, kind)?;
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_root(path, kind)
        }
        Err(error) => Err(DaemonError::Io(error)),
    }
}

fn unix_millis() -> Result<i64, DaemonError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DaemonError::ProtocolRefused("clock_before_epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| DaemonError::ProtocolRefused("clock_out_of_range"))
}

fn fatal_store_error(error: &StoreError) -> bool {
    !matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::ScopeLocked
            | StoreError::AlreadyTerminal
            | StoreError::OutboxConflict
            | StoreError::NotFound(_)
    )
}

/// Stable, document-free class of one strict RunSpec decode refusal.
///
/// The decoder's own variants name a field or an object, which is our own
/// static vocabulary rather than submitter data. They are collapsed to a fixed
/// set here anyway: a refusal category is a metric label, and one that can take
/// a few dozen values is a worse label than one that takes six.
const fn run_spec_decode_category(error: RunSpecDecodeError) -> &'static str {
    match error {
        RunSpecDecodeError::DocumentTooLarge => "run_spec_document_too_large",
        RunSpecDecodeError::InvalidCanonicalJson => "run_spec_invalid_canonical_json",
        RunSpecDecodeError::ObjectShape(_) => "run_spec_object_shape",
        RunSpecDecodeError::Field(_) => "run_spec_field_invalid",
        RunSpecDecodeError::Domain(_) => "run_spec_domain_invariant",
        RunSpecDecodeError::NonCanonicalRoundTrip => "run_spec_non_canonical_round_trip",
    }
}

/// Whether a submission-log failure is the submitter's to fix.
///
/// A malformed field, a reused key and a full log are answered to the client.
/// Corruption, a schema mismatch and storage failure are not: they say the
/// daemon's own custody is unsound, and a correlated refusal would present that
/// as a client error.
const fn run_submission_refusal(error: &RunSubmissionError) -> bool {
    matches!(
        error,
        RunSubmissionError::InvalidField(_)
            | RunSubmissionError::Conflict { .. }
            | RunSubmissionError::LogFull { .. }
    )
}

/// Whether an intake pause or resume failure is the operator's to act on.
///
/// A lost fence, an idempotent repeat and a malformed field are answered to the
/// client. Storage failure is not: it says the daemon's own durable state is
/// unsound, and a correlated refusal would present that as an operator error.
fn intake_pause_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::StaleEpoch
            | StoreError::AlreadyPaused(_)
            | StoreError::NotPaused
    )
}

fn reconciliation_command_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::StaleEpoch
            | StoreError::LeaseHeld
            | StoreError::ScopeLocked
            | StoreError::AlreadyTerminal
            | StoreError::OutboxConflict
            | StoreError::NotFound(_)
    )
}
