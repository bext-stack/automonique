// SPDX-License-Identifier: Elastic-2.0

//! Foreground Automonique control-plane process.
//!
//! This first daemon slice owns a private runtime directory, a durable SQLite
//! store, one fenced process generation, and a peer-authenticated Unix admin
//! socket. It deliberately performs no external effects yet.

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
    AdminRefusalCategory, AdminRequest, AdminResponse, DaemonState, DaemonStatus,
    MAX_ADMIN_CANONICAL_BYTES, OperationalMetric, OperationalStatus, OperationalStatusParts,
    OutboxReconciliationDecision,
};
use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, decode_frame, encode_frame};
use automonique_store::{
    InboxSubmission, LeaseRenewal, LeaseRequest,
    OutboxReconciliationDecision as StoreOutboxDecision, OutboxReconciliationRequest,
    ReconciliationDecision, ReconciliationRequest, StatusSnapshot, Store, StoreError,
};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

mod synthetic;
mod telegram;

/// Socket filename inside the private product runtime directory.
pub const ADMIN_SOCKET_NAME: &str = concat!("admin", ".sock");

/// Database filename inside the private product state directory.
pub const DATABASE_NAME: &str = concat!("automonique", ".sqlite3");

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
        })
    }

    /// Bound local endpoint.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
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
                let _ = telegram_release;
                let _ = release;
                Err(primary)
            }
            Ok(()) => telegram_release.and(release),
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

    fn handle_stream(
        &mut self,
        stream: &mut UnixStream,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        authenticate_peer(stream)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let payload = read_payload(stream)?;
        let request = AdminRequest::from_canonical_bytes(&payload)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
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
                    !degraded,
                )
                .and_then(|status| status.with_telegram(telegram_state, telegram_poller_epoch))
                .and_then(|status| status.with_operational(operational))
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                AdminResponse::Status {
                    request_id: request.request_id().clone(),
                    status,
                }
            }
            automonique_protocol::admin::AdminCommand::SubmitSynthetic => {
                let snapshot = self
                    .store
                    .status_snapshot_at(GENERATION_ID, unix_millis()?)?;
                if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot)
                {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        DaemonError::ReconciliationRequired.category(),
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
