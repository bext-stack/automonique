// SPDX-License-Identifier: Elastic-2.0

//! Fleet support-board intake: one worker that reads the board on a cadence and
//! records what it saw.
//!
//! `automonique-support-connector` can read one page of the Support fleet
//! board, and `automonique_store::support_tickets` can remember one. This module
//! is the loop between them, and nothing else: it polls, it upserts, it records
//! the one lifecycle fact the fleet is authoritative about, and it stops when
//! the daemon does.
//!
//! ```text
//! FleetClient::support_issues  ->  SupportIssue  ->  SupportTicketStore::record
//!                                              \->  ::transition(Closed)
//! ```
//!
//! # The enablement gate
//!
//! Exactly the shape [`crate::telegram`] uses, and for the same reason. An
//! absent `<state>/automonique/support/fleet.conf` means the fleet is
//! deliberately not configured: no credential is read, no client is
//! constructed, no thread is started, and this daemon cannot reach the support
//! API at all. A present-but-invalid or present-but-insecure file refuses daemon
//! startup rather than being ignored, because ignoring it would hide an operator
//! error behind an honest-looking disabled state.
//!
//! So live polling is not something this daemon can drift into. Turning it on
//! takes an operator writing down an origin, an instance identity and a token,
//! in a private file, by hand.
//!
//! # What this worker does not have
//!
//! **No cursor, and therefore no lease.** The Telegram poller owns a durable
//! per-bot offset and holds a fenced lease over it, because advancing a cursor
//! twice loses updates. This worker has no cursor: it re-reads the open board
//! every cadence and upserts by fleet issue id, so a second poller would write
//! the same rows to the same keys and lose nothing. What keeps it single is the
//! same thing that keeps the execution lane single — one state directory admits
//! one daemon, because one generation lease fences it — and inventing a second
//! lease here would be ceremony that proves nothing.
//!
//! **No paging.** One poll reads one page of at most
//! [`MAX_SUPPORT_ISSUES`](automonique_support_connector::MAX_SUPPORT_ISSUES)
//! rows, which is the whole page size the fleet action offers. A board with more
//! open tickets than that is not fully recorded by one poll, and this module
//! does not pretend otherwise: the connector has no cursor to follow, so the
//! honest bound is the one the API gives.
//!
//! **No reply, no note, no email.** The connector can send all three. Nothing
//! here calls any of them. This wave is intake — reading and remembering — and
//! an externally visible effect belongs on a confirmed-action path, not on a
//! timer.
//!
//! # Fail-closed, and what that means for each kind of failure
//!
//! A poll is the network; the network fails. Every failure the *fleet* can
//! produce is survivable and retried on the next cadence:
//!
//! - a transport failure or a contract break is [`PollOutcome::Unavailable`];
//! - the fleet's own `ok: false` refusal is [`PollOutcome::Refused`];
//! - one row this store will not accept is counted in [`PollReport::refused`]
//!   and skipped, so a single malformed ticket does not cost the page.
//!
//! None of those ends the worker. What does end it is [`IntakeHalt`]: the
//! durable store said something that means writing again would be wrong — it is
//! full, it is corrupt, its schema is foreign, or SQLite failed. Continuing past
//! any of those would spin producing the same refusal forever, so the worker
//! stops and remembers why, and [`IntakeMetrics::halt`] is where an operator
//! reads it.
//!
//! This crate has no logger — it takes no `log` dependency, and neither does the
//! daemon around it — so the counters on [`IntakeMetrics`] *are* the record. They
//! are atomics rather than a returned value because the worker runs on its own
//! thread and the thing that wants to read them is the serve loop.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use automonique_store::support_tickets::{
    FleetTicket, SupportTicketError, SupportTicketStore, TicketLifecycle, TicketTransition,
};
use automonique_support_connector::{
    FleetBase, FleetClient, FleetFailure, FleetInstanceId, FleetOutcome, FleetToken,
    MAX_SUPPORT_ISSUES, ServerMessage, SupportIssue, SupportIssues, SupportIssuesRequest,
};

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "support/fleet.conf";
/// Exact first line of a fleet configuration.
const CONFIG_HEADER: &str = "schema=automonique.support-fleet/v1";
/// Exact final line of a complete fleet configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.support-fleet/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;

/// Cadence used when a configuration names none.
pub const DEFAULT_POLL_SECONDS: u64 = 300;
/// Fastest cadence an operator may configure.
///
/// The support board is a human queue measured in minutes, so a poll every few
/// seconds would spend the fleet's rate budget to learn nothing. Thirty seconds
/// is the floor rather than one, because a shorter one is always a mistake.
pub const MIN_POLL_SECONDS: u64 = 30;
/// Slowest cadence an operator may configure.
pub const MAX_POLL_SECONDS: u64 = 3_600;

/// How often a sleeping worker wakes to check whether it was asked to stop.
///
/// Shutdown latency, not poll latency. A cadence is minutes; a join must not be.
const STOP_POLL: Duration = Duration::from_millis(100);

/// One source of support board pages.
///
/// The seam the hermetic tests use. [`FleetClient`] is the production
/// implementation and the only one that opens a socket; a test supplies canned
/// pages and this module cannot tell the difference, which is what keeps every
/// test in this crate free of the network.
pub trait SupportBoard: Send {
    /// Read one page of at most `limit` open support issues.
    ///
    /// # Errors
    ///
    /// Returns the connector's closed [`FleetFailure`] vocabulary for a
    /// transport problem or a response that is not the action's contract. The
    /// fleet's *own* refusal is an `Ok` outcome, not an error, because it is a
    /// parsed answer.
    fn support_issues(&self, limit: usize) -> Result<FleetOutcome<SupportIssues>, FleetFailure>;
}

impl SupportBoard for FleetClient {
    fn support_issues(&self, limit: usize) -> Result<FleetOutcome<SupportIssues>, FleetFailure> {
        // A limit outside the connector's own bound is this module's mistake,
        // not the fleet's, and there is nothing to ask about it: report it as
        // the contract break it would have been.
        let request =
            SupportIssuesRequest::new(limit).map_err(|_| FleetFailure::InvalidResponse)?;
        Self::support_issues(self, &request)
    }
}

/// Why a present fleet configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`FleetConfig::load`].
#[derive(Debug)]
pub enum FleetConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// `base` is absent or is not an origin the connector may address.
    BaseInvalid,
    /// `instance` is absent, over-long, or not an opaque identifier.
    InstanceInvalid,
    /// `token` is absent, empty, over-long, or outside the credential charset.
    TokenInvalid,
    /// `poll_seconds` is not an integer inside [`MIN_POLL_SECONDS`] to
    /// [`MAX_POLL_SECONDS`].
    CadenceInvalid,
}

impl fmt::Display for FleetConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => formatter
                .write_str("support fleet configuration is not a private owner-only regular file"),
            Self::Unreadable => formatter.write_str("support fleet configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("support fleet configuration frame is malformed or truncated")
            }
            Self::BaseInvalid => formatter.write_str("support fleet configuration base is invalid"),
            Self::InstanceInvalid => {
                formatter.write_str("support fleet configuration instance is invalid")
            }
            Self::TokenInvalid => {
                formatter.write_str("support fleet configuration token is invalid")
            }
            Self::CadenceInvalid => {
                formatter.write_str("support fleet configuration poll_seconds is invalid")
            }
        }
    }
}

impl std::error::Error for FleetConfigError {}

impl FleetConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "support_config_insecure",
            Self::Unreadable => "support_config_unreadable",
            Self::Malformed => "support_config_malformed",
            Self::BaseInvalid => "support_config_base",
            Self::InstanceInvalid => "support_config_instance",
            Self::TokenInvalid => "support_config_token",
            Self::CadenceInvalid => "support_config_cadence",
        }
    }
}

/// A validated fleet configuration.
///
/// Holding one means the operator authorized live support polling. It carries
/// the credential, so it is `Debug`-redacted the way [`FleetToken`] is, and it
/// is consumed into a [`FleetClient`] rather than kept around.
pub struct FleetConfig {
    base: FleetBase,
    instance: FleetInstanceId,
    token: FleetToken,
    cadence: Duration,
    page_limit: usize,
}

impl fmt::Debug for FleetConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FleetConfig")
            .field("base", &self.base.origin())
            .field("instance", &self.instance)
            .field("token", &"<redacted>")
            .field("cadence", &self.cadence)
            .field("page_limit", &self.page_limit)
            .finish()
    }
}

impl FleetConfig {
    /// Configuration file location beneath `state_dir`.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// The cadence between polls.
    #[must_use]
    pub const fn cadence(&self) -> Duration {
        self.cadence
    }

    /// How many issues one poll asks for.
    #[must_use]
    pub const fn page_limit(&self) -> usize {
        self.page_limit
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`FleetConfigError`] naming which part of a present file was
    /// refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, FleetConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(FleetConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(FleetConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| FleetConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| FleetConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, FleetConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(FleetConfigError::Malformed);
        }
        let mut base: Option<FleetBase> = None;
        let mut instance: Option<FleetInstanceId> = None;
        let mut token: Option<FleetToken> = None;
        let mut cadence: Option<u64> = None;
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(FleetConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(FleetConfigError::Malformed)?;
            match key {
                "base" if base.is_none() => {
                    base = Some(FleetBase::new(value).map_err(|_| FleetConfigError::BaseInvalid)?);
                }
                "instance" if instance.is_none() => {
                    instance = Some(
                        FleetInstanceId::new(value)
                            .map_err(|_| FleetConfigError::InstanceInvalid)?,
                    );
                }
                "token" if token.is_none() => {
                    token = Some(
                        FleetToken::new(value.as_bytes().to_vec())
                            .map_err(|_| FleetConfigError::TokenInvalid)?,
                    );
                }
                "poll_seconds" if cadence.is_none() => {
                    let seconds = value
                        .parse::<u64>()
                        .map_err(|_| FleetConfigError::CadenceInvalid)?;
                    if !(MIN_POLL_SECONDS..=MAX_POLL_SECONDS).contains(&seconds) {
                        return Err(FleetConfigError::CadenceInvalid);
                    }
                    cadence = Some(seconds);
                }
                _ => return Err(FleetConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(FleetConfigError::Malformed);
        }
        Ok(Some(Self {
            base: base.ok_or(FleetConfigError::BaseInvalid)?,
            instance: instance.ok_or(FleetConfigError::InstanceInvalid)?,
            token: token.ok_or(FleetConfigError::TokenInvalid)?,
            cadence: Duration::from_secs(cadence.unwrap_or(DEFAULT_POLL_SECONDS)),
            page_limit: MAX_SUPPORT_ISSUES,
        }))
    }

    /// Build the live client this configuration authorizes.
    ///
    /// Constructing a client dials nothing. [`TicketIntakeHost::start`] is what
    /// puts one on a thread, which is why a daemon that was opened and never
    /// served has issued no request to the fleet.
    #[must_use]
    fn into_client(self) -> (FleetClient, Duration, usize) {
        let cadence = self.cadence;
        let page_limit = self.page_limit;
        (
            FleetClient::new(self.base, self.instance, self.token),
            cadence,
            page_limit,
        )
    }
}

/// The durable failure that ends a worker.
///
/// Every one of these means writing again would be wrong, so the worker stops
/// rather than spinning. Contrast [`PollOutcome`], every variant of which is
/// survivable and retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntakeHalt {
    /// The ticket store holds its capacity. Nothing evicts, so every further
    /// first sighting would be refused identically.
    StoreFull,
    /// A stored row is not one the store's API could have written.
    StoreCorrupt,
    /// The store's schema is foreign to this build.
    SchemaVersion,
    /// The store's path stopped being private and owned.
    InsecurePath,
    /// SQLite or the filesystem failed underneath the store.
    StoreUnavailable,
}

impl IntakeHalt {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::StoreFull => "ticket_store_full",
            Self::StoreCorrupt => "ticket_store_corrupt",
            Self::SchemaVersion => "ticket_store_schema_version",
            Self::InsecurePath => "ticket_store_insecure_path",
            Self::StoreUnavailable => "ticket_store_unavailable",
        }
    }

    /// Classify one store refusal as fatal to the worker, or not.
    ///
    /// `None` means the refusal is about *this row* — a field outside its
    /// grammar, a lifecycle that does not follow, a revision that moved — and
    /// the next row is still worth trying. `Some` means the store itself is in
    /// a state that makes every further write pointless or unsafe.
    fn classify(error: &SupportTicketError) -> Option<Self> {
        match error {
            SupportTicketError::StoreFull { .. } => Some(Self::StoreFull),
            SupportTicketError::Corrupt(_) => Some(Self::StoreCorrupt),
            SupportTicketError::SchemaVersion { .. } => Some(Self::SchemaVersion),
            SupportTicketError::InsecurePath(_) => Some(Self::InsecurePath),
            SupportTicketError::Io(_) | SupportTicketError::Sqlite(_) => {
                Some(Self::StoreUnavailable)
            }
            SupportTicketError::InvalidField(_)
            | SupportTicketError::NotFound(_)
            | SupportTicketError::IllegalTransition { .. }
            | SupportTicketError::RevisionMismatch { .. }
            | SupportTicketError::CursorOutOfRange { .. } => None,
        }
    }
}

impl fmt::Display for IntakeHalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ticket intake halted: {}", self.category())
    }
}

impl std::error::Error for IntakeHalt {}

/// What one poll recorded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollReport {
    /// Fleet issues seen for the first time, and therefore inserted.
    pub recorded: usize,
    /// Rows already held whose fleet-owned fields moved.
    pub updated: usize,
    /// Rows already held that said exactly what they said last time.
    pub unchanged: usize,
    /// Lifecycles advanced, which in this wave means closed.
    pub transitioned: usize,
    /// Rows the store would not accept, skipped rather than fatal.
    pub refused: usize,
}

impl PollReport {
    /// Rows this poll looked at.
    #[must_use]
    pub const fn seen(&self) -> usize {
        self.recorded + self.updated + self.unchanged + self.refused
    }
}

/// The outcome of one poll, all three of which are survivable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    /// The fleet answered with a page, and this is what it did to the store.
    Recorded(PollReport),
    /// The fleet answered `ok: false` with a bounded reason. Nothing was
    /// written; the next cadence tries again.
    Refused(ServerMessage),
    /// The call did not produce a contract answer. Nothing was written; the next
    /// cadence tries again.
    Unavailable(FleetFailure),
}

/// Counters a worker publishes for whoever wants to know how it is doing.
///
/// Atomics because the worker runs on its own thread. This crate has no logger,
/// so these are the record rather than a convenience over one.
#[derive(Debug, Default)]
pub struct IntakeMetrics {
    polls: AtomicU64,
    tickets_recorded: AtomicU64,
    tickets_updated: AtomicU64,
    transitions: AtomicU64,
    rows_refused: AtomicU64,
    fleet_failures: AtomicU64,
    fleet_refusals: AtomicU64,
    /// The reason the worker stopped, if it stopped for a reason.
    halt: Mutex<Option<IntakeHalt>>,
}

impl IntakeMetrics {
    /// Polls completed, of every outcome.
    #[must_use]
    pub fn polls(&self) -> u64 {
        self.polls.load(Ordering::Relaxed)
    }
    /// Fleet issues recorded here for the first time.
    #[must_use]
    pub fn tickets_recorded(&self) -> u64 {
        self.tickets_recorded.load(Ordering::Relaxed)
    }
    /// Sightings that moved a field the fleet owns.
    #[must_use]
    pub fn tickets_updated(&self) -> u64 {
        self.tickets_updated.load(Ordering::Relaxed)
    }
    /// Lifecycles advanced.
    #[must_use]
    pub fn transitions(&self) -> u64 {
        self.transitions.load(Ordering::Relaxed)
    }
    /// Rows the store refused, skipped rather than fatal.
    #[must_use]
    pub fn rows_refused(&self) -> u64 {
        self.rows_refused.load(Ordering::Relaxed)
    }
    /// Polls that did not reach a contract answer.
    #[must_use]
    pub fn fleet_failures(&self) -> u64 {
        self.fleet_failures.load(Ordering::Relaxed)
    }
    /// Polls the fleet itself refused.
    #[must_use]
    pub fn fleet_refusals(&self) -> u64 {
        self.fleet_refusals.load(Ordering::Relaxed)
    }

    /// Why the worker stopped, or `None` while it is healthy.
    ///
    /// A poisoned lock is reported as `None` rather than a panic: the only
    /// writer is the worker, and a worker that panicked while recording its halt
    /// has already ended, which is the fact a reader was asking about.
    #[must_use]
    pub fn halt(&self) -> Option<IntakeHalt> {
        self.halt.lock().map(|halt| *halt).unwrap_or_default()
    }

    fn observe(&self, report: PollReport) {
        add(&self.tickets_recorded, report.recorded);
        add(&self.tickets_updated, report.updated);
        add(&self.transitions, report.transitioned);
        add(&self.rows_refused, report.refused);
    }

    fn record_halt(&self, halt: IntakeHalt) {
        if let Ok(mut slot) = self.halt.lock() {
            *slot = Some(halt);
        }
    }
}

fn add(counter: &AtomicU64, delta: usize) {
    counter.fetch_add(delta as u64, Ordering::Relaxed);
}

/// Which fleet statuses mean the ticket is finished.
///
/// The only fleet fact this module reads rather than stores verbatim, and the
/// list is short on purpose: `done` and `closed` are the two spellings the
/// support board uses for an ended request. Every other status — `open`,
/// `triaging`, `in_progress`, `blocked` — describes work the *fleet* is doing,
/// which says nothing about what Automonique has done, so none of them maps onto
/// a local lifecycle. Comparison is ASCII-case-insensitive because the board's
/// status is free text this module does not control.
const CLOSED_FLEET_STATUSES: [&str; 2] = ["done", "closed"];

/// Whether the fleet's own status means the ticket has ended.
#[must_use]
pub fn fleet_status_is_closed(status: &str) -> bool {
    CLOSED_FLEET_STATUSES
        .iter()
        .any(|closed| status.eq_ignore_ascii_case(closed))
}

/// One issue as the connector decoded it, presented for recording.
fn as_fleet_ticket<'a>(issue: &'a SupportIssue, observed_at_ms: i64) -> FleetTicket<'a> {
    FleetTicket {
        fleet_issue_id: &issue.id,
        title: &issue.title,
        tenant_name: &issue.tenant_name,
        site_label: issue.site_label.as_deref(),
        fleet_status: &issue.status,
        priority: &issue.priority,
        source: &issue.source,
        requested_by: &issue.requested_by,
        comment_count: issue.comment_count,
        created_at: &issue.created_at,
        updated_at: &issue.updated_at,
        observed_at_ms,
    }
}

/// The poll-and-record loop, over one board and one store.
///
/// Deliberately split so [`TicketIntake::poll_once`] is a *pure step* a test can
/// drive at an exact instant with no clock and no sleeping, and
/// [`TicketIntake::run`] is only the loop around it.
pub struct TicketIntake<B: SupportBoard> {
    board: B,
    store: SupportTicketStore,
    page_limit: usize,
    metrics: Arc<IntakeMetrics>,
}

impl<B: SupportBoard> TicketIntake<B> {
    /// Bind one board to one store.
    ///
    /// The store connection is this worker's own. A worker that borrowed the
    /// serve loop's handle would either need a lock around every admin request
    /// or would race one — the same reason [`crate::execute`]'s workers and the
    /// Telegram poller open theirs.
    ///
    /// `page_limit` is clamped to
    /// [`MAX_SUPPORT_ISSUES`](automonique_support_connector::MAX_SUPPORT_ISSUES),
    /// which is the largest page the fleet action offers; a zero is read as that
    /// ceiling rather than as "ask for nothing".
    #[must_use]
    pub fn new(board: B, store: SupportTicketStore, page_limit: usize) -> Self {
        let page_limit = if page_limit == 0 {
            MAX_SUPPORT_ISSUES
        } else {
            page_limit.min(MAX_SUPPORT_ISSUES)
        };
        Self {
            board,
            store,
            page_limit,
            metrics: Arc::new(IntakeMetrics::default()),
        }
    }

    /// The counters this worker publishes.
    #[must_use]
    pub fn metrics(&self) -> Arc<IntakeMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Read one page and record it, at exactly `now_ms`.
    ///
    /// One row at a time, and one row's refusal costs only that row. The two
    /// writes per issue are deliberately separate calls rather than one: the
    /// upsert is the *fleet's* writer and touches no lifecycle, and the
    /// transition is this host's and touches nothing the fleet owns. They are
    /// not atomic together, and they do not need to be — a crash between them
    /// leaves a recorded ticket whose closure the next poll notices again,
    /// because the fleet keeps saying it is closed.
    ///
    /// # Errors
    ///
    /// Returns [`IntakeHalt`] when the durable store says something that makes
    /// every further write pointless or unsafe. A *fleet* failure is never an
    /// error here; it is [`PollOutcome::Unavailable`].
    pub fn poll_once(&mut self, now_ms: i64) -> Result<PollOutcome, IntakeHalt> {
        self.metrics.polls.fetch_add(1, Ordering::Relaxed);
        let page = match self.board.support_issues(self.page_limit) {
            Ok(FleetOutcome::Accepted(page)) => page,
            Ok(FleetOutcome::Rejected(message)) => {
                self.metrics.fleet_refusals.fetch_add(1, Ordering::Relaxed);
                return Ok(PollOutcome::Refused(message));
            }
            Err(failure) => {
                self.metrics.fleet_failures.fetch_add(1, Ordering::Relaxed);
                return Ok(PollOutcome::Unavailable(failure));
            }
        };

        let mut report = PollReport::default();
        for issue in &page.issues {
            let receipt = match self.store.record(&as_fleet_ticket(issue, now_ms)) {
                Ok(receipt) => receipt,
                Err(error) => {
                    if let Some(halt) = IntakeHalt::classify(&error) {
                        self.metrics.observe(report);
                        self.metrics.record_halt(halt);
                        return Err(halt);
                    }
                    report.refused += 1;
                    continue;
                }
            };
            if receipt.inserted {
                report.recorded += 1;
            } else if receipt.changed {
                report.updated += 1;
            } else {
                report.unchanged += 1;
            }

            // THE ONE LIFECYCLE FACT THE FLEET OWNS. A board that says an issue
            // is done is authoritative about that and about nothing else here.
            if !fleet_status_is_closed(&issue.status) || receipt.lifecycle.is_terminal() {
                continue;
            }
            match self.store.transition(TicketTransition {
                fleet_issue_id: &issue.id,
                expected_revision: receipt.revision,
                lifecycle: TicketLifecycle::Closed,
                now_ms,
            }) {
                Ok(_) => report.transitioned += 1,
                Err(error) => {
                    if let Some(halt) = IntakeHalt::classify(&error) {
                        self.metrics.observe(report);
                        self.metrics.record_halt(halt);
                        return Err(halt);
                    }
                    report.refused += 1;
                }
            }
        }
        self.metrics.observe(report);
        Ok(PollOutcome::Recorded(report))
    }

    /// Poll on `cadence` until `stop` is set or the store halts the worker.
    ///
    /// `now` is the clock, supplied rather than taken, so this loop is the same
    /// code in a test as in the daemon. A clock that fails is treated as a
    /// survivable condition and skipped, not as a reason to stop recording
    /// support tickets forever.
    ///
    /// Returns the halt that ended it, or `None` when `stop` did.
    pub fn run(
        &mut self,
        stop: &AtomicBool,
        cadence: Duration,
        now: &dyn Fn() -> Option<i64>,
    ) -> Option<IntakeHalt> {
        loop {
            if stop.load(Ordering::Acquire) {
                return None;
            }
            if let Some(now_ms) = now()
                && let Err(halt) = self.poll_once(now_ms)
            {
                return Some(halt);
            }
            // Slept in short steps so a join waits on shutdown latency rather
            // than on the cadence, which is minutes.
            let mut remaining = cadence;
            while !remaining.is_zero() {
                if stop.load(Ordering::Acquire) {
                    return None;
                }
                let step = remaining.min(STOP_POLL);
                std::thread::sleep(step);
                remaining -= step;
            }
        }
    }
}

/// Ticket intake capability state.
///
/// The same two-state shape [`crate::telegram`] has, minus its third: there is
/// no "configured but nobody authorized" here, because a fleet configuration is
/// itself the authorization — it names the origin, the instance and the
/// credential, and there is nothing further to enable.
pub enum TicketIntakeHost {
    /// No configuration file exists. Nothing was constructed and no thread can
    /// start; this daemon cannot reach the support API.
    Disabled,
    /// A configuration exists, so a client and a store connection are composed
    /// and parked. [`TicketIntakeHost::start`] is what puts them on a thread.
    Configured {
        intake: Option<Box<TicketIntake<FleetClient>>>,
        metrics: Arc<IntakeMetrics>,
        cadence: Duration,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    },
}

/// The host holds a credential inside its composed client, so `Debug` renders
/// the gate's state and the cadence and nothing that could carry one out.
impl fmt::Debug for TicketIntakeHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("TicketIntakeHost::Disabled"),
            Self::Configured {
                cadence,
                intake,
                worker,
                ..
            } => formatter
                .debug_struct("TicketIntakeHost::Configured")
                .field("cadence", cadence)
                .field("composed", &intake.is_some())
                .field("started", &worker.is_some())
                .field("client", &"<redacted>")
                .finish(),
        }
    }
}

/// Everything [`TicketIntakeHost::open`] needs, as one value.
pub struct TicketIntakeParams<'a> {
    /// Private state directory holding the fleet configuration.
    pub state_dir: &'a Path,
    /// This host's ticket store, a sibling of the daemon's main database.
    pub ticket_store_path: &'a Path,
}

/// Why the ticket intake host could not reach its configured state.
#[derive(Debug)]
pub enum TicketIntakeError {
    /// The configuration file is present but refused.
    Config(FleetConfigError),
    /// The ticket store could not be opened.
    StoreUnavailable(&'static str),
    /// The worker thread could not be started.
    WorkerUnavailable,
}

impl fmt::Display for TicketIntakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => {
                write!(formatter, "support fleet configuration refused: {error}")
            }
            Self::StoreUnavailable(category) => {
                write!(formatter, "support ticket store unavailable: {category}")
            }
            Self::WorkerUnavailable => {
                formatter.write_str("support ticket intake worker thread unavailable")
            }
        }
    }
}

impl std::error::Error for TicketIntakeError {}

impl TicketIntakeError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Config(error) => error.category(),
            Self::StoreUnavailable(category) => category,
            Self::WorkerUnavailable => "support_intake_worker_unavailable",
        }
    }
}

impl TicketIntakeHost {
    /// Load the configuration and, when one exists, compose the worker.
    ///
    /// Nothing is dialled here. A configured host is *composed* and then parked;
    /// [`Self::start`] is what puts it on a thread, which is why a daemon that
    /// was opened and never served has issued no request to the fleet.
    ///
    /// The ticket store is opened even for a configured-but-never-started host,
    /// so a startup that cannot hold tickets refuses now rather than discovering
    /// it one cadence later on a thread nobody is watching.
    ///
    /// # Errors
    ///
    /// Returns [`TicketIntakeError::Config`] for a present-but-refused
    /// configuration and [`TicketIntakeError::StoreUnavailable`] when the ticket
    /// store will not open. An absent configuration is [`Self::Disabled`], not
    /// an error.
    pub fn open(params: &TicketIntakeParams<'_>) -> Result<Self, TicketIntakeError> {
        let Some(config) =
            FleetConfig::load(params.state_dir).map_err(TicketIntakeError::Config)?
        else {
            return Ok(Self::Disabled);
        };
        let store = SupportTicketStore::open(params.ticket_store_path)
            .map_err(|error| TicketIntakeError::StoreUnavailable(error.category()))?;
        let (client, cadence, page_limit) = config.into_client();
        let intake = TicketIntake::new(client, store, page_limit);
        let metrics = intake.metrics();
        Ok(Self::Configured {
            intake: Some(Box::new(intake)),
            metrics,
            cadence,
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
        })
    }

    /// Whether this host will poll the support fleet.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        matches!(self, Self::Configured { .. })
    }

    /// The counters the worker publishes, or `None` when disabled.
    #[must_use]
    pub fn metrics(&self) -> Option<&Arc<IntakeMetrics>> {
        match self {
            Self::Disabled => None,
            Self::Configured { metrics, .. } => Some(metrics),
        }
    }

    /// Put a composed worker on its own thread. Idempotent, and a no-op unless
    /// this host is configured.
    ///
    /// A thread that cannot be spawned is a startup refusal rather than a
    /// silently degraded host: the operator asked for intake by writing down a
    /// fleet, and a daemon that quietly recorded nothing would be the dishonest
    /// state this gate exists to avoid.
    ///
    /// # Errors
    ///
    /// Returns [`TicketIntakeError::WorkerUnavailable`] when the thread cannot
    /// be spawned.
    pub fn start(&mut self) -> Result<(), TicketIntakeError> {
        let Self::Configured {
            intake,
            cadence,
            stop,
            worker,
            ..
        } = self
        else {
            return Ok(());
        };
        let Some(mut composed) = intake.take() else {
            return Ok(());
        };
        let cadence = *cadence;
        let stop = Arc::clone(stop);
        let spawned = std::thread::Builder::new()
            .name(String::from("automonique-ticket-intake"))
            .spawn(move || {
                composed.run(&stop, cadence, &|| crate::unix_millis().ok());
            })
            .map_err(|_| TicketIntakeError::WorkerUnavailable)?;
        *worker = Some(spawned);
        Ok(())
    }

    /// Ask the worker to stop, then join it.
    ///
    /// Called on the daemon's shutdown path before the generation lease is
    /// released, for the reason the execution lane and the Telegram poller are:
    /// this thread writes to durable state this generation owns, and returning
    /// while it still polls would leave a writer running under authority nobody
    /// holds. Bounded by [`STOP_POLL`] plus one in-flight request budget.
    pub fn shutdown(&mut self) {
        let Self::Configured {
            intake,
            stop,
            worker,
            ..
        } = self
        else {
            return;
        };
        stop.store(true, Ordering::Release);
        *intake = None;
        if let Some(worker) = worker.take() {
            let _ = worker.join();
        }
    }
}

/// Last-resort custody, for a host dropped without being shut down.
///
/// [`TicketIntakeHost::shutdown`] is the ordered path; this exists so a process
/// unwinding out of `serve` cannot leave a thread polling and writing under a
/// generation nobody is holding any more.
impl Drop for TicketIntakeHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(lines: &[&str]) -> String {
        let mut text = vec![String::from(CONFIG_HEADER)];
        text.extend(lines.iter().map(|line| (*line).to_owned()));
        text.push(String::from(CONFIG_TERMINATOR));
        text.push(String::new());
        text.join("\n")
    }

    fn complete() -> Vec<&'static str> {
        vec![
            "base=https://manage.example.com",
            "instance=sd-instance-01",
            "token=sd_fixture-secret-never-print",
        ]
    }

    /// THE GATE, CLOSED. No configuration means nothing to parse and nothing to
    /// start.
    #[test]
    fn an_absent_configuration_is_not_an_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert!(
            FleetConfig::load(directory.path())
                .expect("an absent file is deliberate")
                .is_none()
        );
    }

    /// The other side of the gate: a complete file authorizes live polling.
    #[test]
    fn a_complete_configuration_carries_the_whole_target_lock() {
        let parsed = FleetConfig::parse(&config(&complete()))
            .expect("valid configuration")
            .expect("present configuration");
        assert_eq!(parsed.base.origin(), "https://manage.example.com");
        assert_eq!(parsed.instance.as_str(), "sd-instance-01");
        assert_eq!(parsed.cadence(), Duration::from_secs(DEFAULT_POLL_SECONDS));
        assert_eq!(parsed.page_limit(), MAX_SUPPORT_ISSUES);
    }

    #[test]
    fn the_credential_never_reaches_a_rendering_of_the_configuration() {
        const SECRET: &str = "sd_fixture-secret-never-print";
        let parsed = FleetConfig::parse(&config(&complete()))
            .expect("valid configuration")
            .expect("present configuration");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("sd_fixture"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn every_incomplete_or_malformed_frame_is_refused() {
        // A missing required key names itself.
        for (dropped, expected) in [
            ("base=", "support_config_base"),
            ("instance=", "support_config_instance"),
            ("token=", "support_config_token"),
        ] {
            let kept: Vec<&str> = complete()
                .into_iter()
                .filter(|line| !line.starts_with(dropped))
                .collect();
            let error = FleetConfig::parse(&config(&kept)).expect_err("incomplete frame");
            assert_eq!(error.category(), expected);
        }

        // A malformed value names the field it was for.
        for (line, expected) in [
            ("base=not a url", "support_config_base"),
            ("base=ftp://manage.example.com", "support_config_base"),
            ("instance=", "support_config_instance"),
            ("token=", "support_config_token"),
            ("poll_seconds=zero", "support_config_cadence"),
            ("poll_seconds=1", "support_config_cadence"),
            ("poll_seconds=100000", "support_config_cadence"),
        ] {
            let mut lines = complete();
            lines.retain(|kept| {
                !kept.starts_with(line.split_once('=').expect("key").0)
                    || line.starts_with("poll_seconds")
            });
            lines.push(line);
            let error = FleetConfig::parse(&config(&lines)).expect_err("malformed value");
            assert_eq!(error.category(), expected, "{line}");
        }

        // Frame damage is refused before any field is believed.
        let complete_frame = config(&complete());
        for (what, text) in [
            (
                "a missing header",
                complete_frame.replacen(CONFIG_HEADER, "", 1),
            ),
            (
                "a missing terminator",
                complete_frame.replacen(CONFIG_TERMINATOR, "", 1),
            ),
            (
                "content after the terminator",
                format!("{complete_frame}base=https://other.example.com\n"),
            ),
            (
                "a duplicate key",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("base=https://other.example.com\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
            (
                "an unknown key",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("action=support-email\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
            (
                "a keyless line",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("nonsense\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
        ] {
            assert_eq!(
                FleetConfig::parse(&text).expect_err(what).category(),
                "support_config_malformed",
                "{what} must be refused"
            );
        }
    }

    #[test]
    fn a_configured_cadence_is_taken_and_bounded_at_both_ends() {
        for seconds in [MIN_POLL_SECONDS, 600, MAX_POLL_SECONDS] {
            let mut lines = complete();
            let line = format!("poll_seconds={seconds}");
            lines.push(&line);
            let parsed = FleetConfig::parse(&config(&lines))
                .expect("valid cadence")
                .expect("present configuration");
            assert_eq!(parsed.cadence(), Duration::from_secs(seconds));
        }
        for seconds in [MIN_POLL_SECONDS - 1, MAX_POLL_SECONDS + 1] {
            let mut lines = complete();
            let line = format!("poll_seconds={seconds}");
            lines.push(&line);
            assert_eq!(
                FleetConfig::parse(&config(&lines))
                    .expect_err("cadence refusal")
                    .category(),
                "support_config_cadence"
            );
        }
    }

    /// THE GATE, AS THE HOST SEES IT. No configuration means no worker, and
    /// starting one is a no-op rather than an error.
    #[test]
    fn a_host_without_a_configuration_starts_nothing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut host = TicketIntakeHost::open(&TicketIntakeParams {
            state_dir: directory.path(),
            ticket_store_path: &directory.path().join("support-tickets.sqlite3"),
        })
        .expect("host opens");
        assert!(matches!(host, TicketIntakeHost::Disabled));
        assert!(!host.is_configured());
        assert!(host.metrics().is_none());
        host.start().expect("starting a disabled host is a no-op");
        assert!(matches!(host, TicketIntakeHost::Disabled));
        host.shutdown();
        // And no ticket store was created, because nothing wanted one.
        assert!(!directory.path().join("support-tickets.sqlite3").exists());
    }

    /// Only the two spellings the board uses for an ended request map onto the
    /// local terminal state.
    #[test]
    fn only_a_finished_fleet_status_maps_onto_closed() {
        for closed in ["done", "closed", "DONE", "Closed"] {
            assert!(fleet_status_is_closed(closed), "{closed}");
        }
        for live in ["open", "triaging", "in_progress", "blocked", "", "close"] {
            assert!(!fleet_status_is_closed(live), "{live}");
        }
    }

    /// A page limit is clamped to the connector's own page ceiling in both
    /// directions, so a caller cannot ask the fleet for more than it offers.
    #[test]
    fn the_page_limit_is_clamped_to_the_connectors_ceiling() {
        struct Silent;
        impl SupportBoard for Silent {
            fn support_issues(
                &self,
                _limit: usize,
            ) -> Result<FleetOutcome<SupportIssues>, FleetFailure> {
                Err(FleetFailure::Unavailable)
            }
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private directory");
        let opened = |limit| {
            let store =
                SupportTicketStore::open(directory.path().join(format!("tickets-{limit}.sqlite3")))
                    .expect("store opens");
            TicketIntake::new(Silent, store, limit).page_limit
        };
        assert_eq!(opened(0), MAX_SUPPORT_ISSUES);
        assert_eq!(opened(5), 5);
        assert_eq!(opened(MAX_SUPPORT_ISSUES + 1), MAX_SUPPORT_ISSUES);
    }
}
