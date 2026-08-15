// SPDX-License-Identifier: Elastic-2.0

//! The daemon's single host-wide owner of cancellation dispatch.
//!
//! [`CancelDispatcher`] serialises `classify -> deliver -> record` for every
//! caller it owns, and states plainly the one thing it cannot establish by
//! itself:
//!
//! > **Host-wide means one dispatcher instance.** Two dispatchers over one
//! > durable ledger file still interleave exactly as two bare servers did: this
//! > type serialises the callers it owns, not the file. Closing that needs one
//! > process to own custody for the host — composition policy the daemon
//! > decides, not a property this type can carry.
//!
//! This module is that composition policy. [`DaemonAttemptHost`] owns exactly
//! one [`CancelDispatcher`], constructed over exactly one
//! [`StoreCancelCustody`] on exactly one [`CancelLedger`] file, and the daemon
//! holds exactly one of these. Nothing here adds a lock or a protocol: the two
//! halves already existed and were never joined.
//!
//! # What the composition establishes
//!
//! - **Idempotency is durable.** Custody is the store-backed ledger, so a
//!   reference delivered before a restart is answered `already_delivered`
//!   afterwards, by a new process over the same file. The in-memory default the
//!   runner ships dies with its process; this does not.
//! - **Idempotency is host-wide within this process.** Every caller — a direct
//!   [`DaemonAttemptHost::cancel`], and every
//!   [`ControlServer`](automonique_runner::control::ControlServer) seated
//!   through [`DaemonAttemptHost::seat`] — runs the whole sequence under the one
//!   dispatcher's lock, so one reference reaches one sink once however many
//!   callers race for it.
//!
//! One daemon is one process is one dispatcher, so "host-wide within this
//! process" and "host-wide" coincide exactly as far as the exclusion below
//! holds.
//!
//! # Why "one daemon" is true: the lease fence, not a new lock
//!
//! The dispatcher's single-instance requirement is satisfied by exclusion this
//! daemon already enforces, so nothing here takes a lock of its own.
//! [`Daemon::open`](crate::Daemon::open) refuses to start a second daemon over
//! one state directory twice over:
//!
//! 1. The admin socket is bound before any durable ownership changes, and a
//!    live listener at that path is [`DaemonError::AlreadyRunning`](crate::DaemonError::AlreadyRunning).
//! 2. The named generation lease is then acquired in the store. A live lease
//!    held by another instance refuses startup rather than being seized;
//!    take-over happens only through expiry.
//!
//! The cancel ledger path is derived from that same state directory, so "one
//! daemon over this state directory" and "one dispatcher over this ledger file"
//! are the same statement. Two daemons cannot be the two dispatchers the
//! dispatcher module warns about.
//!
//! What that argument does **not** cover, stated rather than implied: nothing
//! on the filesystem stops some other program from opening the same SQLite file
//! and writing to it. SQLite will serialise the transactions, but a foreign
//! writer is outside this product's composition, and against one the dispatcher
//! degrades to exactly what it documents — a `record` that returns
//! [`DispatchOutcome::Conflict`] after a delivery that did happen.
//!
//! # Who reaches this host
//!
//! - **The execution lane registers every attempt it starts**, before it opens
//!   the spool and before it creates the run cgroup, so no containment can
//!   exist for an attempt cancellation cannot reach. A live daemon's registry
//!   is non-empty exactly when it is running something.
//! - **`Daemon::cancel_run` is the one caller that delivers**, and every
//!   operator surface routes through it: the Execute lane's `cancel_run` verb,
//!   the CLI's `cancel`, and the Telegram bridge's `/cancel`. One function, one
//!   fence, one ledger — which is what makes those three equal in authority
//!   rather than three implementations that agree today.
//!
//! # What this does not do
//!
//! - **It does not resolve a run to an attempt.** This host keys on
//!   `attempt_id`, and an operator names a run; the walk between them is the
//!   daemon's, through the run index and custody to the document's own declared
//!   identity.
//! - **It is not exit evidence, and it is not authorization.** Both limits are
//!   the dispatcher's and are unchanged by owning one: a delivery says a
//!   request reached a sink once, and anyone holding the host may cancel any
//!   attempt registered on it.

use std::fmt;
use std::path::{Path, PathBuf};

use automonique_runner::control::CancelSink;
use automonique_runner::dispatch::{
    CancelDispatcher, ControlSeat, DispatchError, DispatchOutcome, MAX_REGISTRATIONS,
    RegistrationHandle,
};
use automonique_store::cancel_ledger::{CancelLedger, CancelLedgerError};

use crate::cancel_custody::StoreCancelCustody;

/// Attempts one daemon may hold cancellation registrations for at once.
///
/// The dispatcher's own bound, restated so a caller reads it from the type it
/// actually holds. It is deliberately not widened here: the daemon composes the
/// dispatcher, it does not get to enlarge it.
pub const MAX_ATTEMPT_REGISTRATIONS: usize = MAX_REGISTRATIONS;

/// Why the attempt host could not be opened, registered against, or disposed.
///
/// Cancellation itself never returns one of these: a cancel always has a
/// [`DispatchOutcome`], including for the failures named here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptHostError {
    /// The durable cancel ledger could not be opened. The payload is the stable
    /// category, derived from the ledger's own.
    LedgerUnavailable(&'static str),
    /// The attempt identifier is outside the control endpoint's bounded
    /// grammar.
    InvalidAttemptId,
    /// A registration already holds this attempt. Registration never replaces a
    /// live one.
    DuplicateAttempt,
    /// No registration holds this attempt, or the handle's registration was
    /// already replaced.
    UnknownAttempt,
    /// The host already holds [`MAX_ATTEMPT_REGISTRATIONS`] registrations.
    RegistrationLimit,
    /// A cancel sink panicked inside the dispatcher's serialized section. The
    /// host can no longer say whether that delivery happened, so it answers
    /// nothing else.
    Poisoned,
}

impl AttemptHostError {
    /// Stable machine-readable category, on the daemon's category discipline.
    ///
    /// Every spelling is a fixed string with no caller bytes in it, so it is
    /// usable as a metric label and as a refusal category without leaking an
    /// attempt identifier or a path.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::LedgerUnavailable(category) => category,
            Self::InvalidAttemptId => "attempt_host_invalid_attempt_id",
            Self::DuplicateAttempt => "attempt_host_duplicate_attempt",
            Self::UnknownAttempt => "attempt_host_unknown_attempt",
            Self::RegistrationLimit => "attempt_host_registration_limit",
            Self::Poisoned => "attempt_host_poisoned",
        }
    }
}

impl fmt::Display for AttemptHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerUnavailable(category) => {
                write!(formatter, "cancel ledger unavailable: {category}")
            }
            Self::InvalidAttemptId => formatter.write_str("attempt id is not a bounded identifier"),
            Self::DuplicateAttempt => {
                formatter.write_str("a registration already holds this attempt")
            }
            Self::UnknownAttempt => formatter.write_str("no registration holds this attempt"),
            Self::RegistrationLimit => write!(
                formatter,
                "attempt host already holds {MAX_ATTEMPT_REGISTRATIONS} registrations"
            ),
            Self::Poisoned => {
                formatter.write_str("attempt host was poisoned by a panicking cancel sink")
            }
        }
    }
}

impl std::error::Error for AttemptHostError {}

impl From<DispatchError> for AttemptHostError {
    fn from(value: DispatchError) -> Self {
        match value {
            DispatchError::InvalidIdentifier => Self::InvalidAttemptId,
            DispatchError::DuplicateAttempt => Self::DuplicateAttempt,
            DispatchError::UnknownAttempt => Self::UnknownAttempt,
            DispatchError::RegistrationLimit => Self::RegistrationLimit,
            DispatchError::Poisoned => Self::Poisoned,
        }
    }
}

/// One daemon's single owner of cancellation dispatch and its durable custody.
///
/// Not [`Clone`] and never handed out by value: the daemon holds one and lends
/// it by reference, because a second value over the same ledger file would be
/// the second dispatcher the dispatcher module refuses to be responsible for.
#[derive(Debug)]
pub struct DaemonAttemptHost {
    dispatcher: CancelDispatcher,
    ledger_path: PathBuf,
}

impl DaemonAttemptHost {
    /// Open the durable cancel ledger and take ownership of the one dispatcher
    /// over it.
    ///
    /// The ledger is opened here rather than passed in, so the process that
    /// decides where durable state lives is the process that owns the
    /// dispatcher over it. Fail-closed by construction: a daemon that cannot
    /// remember which cancellations it delivered has no host to be, so this
    /// returns an error instead of falling back to process-local custody. That
    /// fallback would be worse than the failure — it answers `delivered` twice
    /// across a restart while looking exactly like the durable path.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptHostError::LedgerUnavailable`] when the ledger path is
    /// not private and owned, holds an unsupported schema, or cannot be opened.
    pub fn open(ledger_path: impl Into<PathBuf>) -> Result<Self, AttemptHostError> {
        let ledger_path = ledger_path.into();
        let ledger = CancelLedger::open(&ledger_path)
            .map_err(|error| AttemptHostError::LedgerUnavailable(ledger_category(&error)))?;
        Ok(Self {
            // One dispatcher, one custody, one file — the whole composition is
            // this line, and the type system holds it: `CancelDispatcher` is
            // neither `Clone` nor reconstructible from a `&self` method here.
            dispatcher: CancelDispatcher::new(Box::new(StoreCancelCustody::new(ledger))),
            ledger_path,
        })
    }

    /// Durable ledger file this host's custody is bound to.
    #[must_use]
    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    /// Registrations this host may hold at once.
    #[must_use]
    pub fn registration_capacity(&self) -> usize {
        self.dispatcher.capacity()
    }

    /// Live registrations.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptHostError::Poisoned`] when a sink panicked inside the
    /// dispatcher's serialized section.
    pub fn registration_count(&self) -> Result<usize, AttemptHostError> {
        self.dispatcher
            .registration_count()
            .map_err(AttemptHostError::from)
    }

    /// Couple one attempt identifier to the sink that cancels it.
    ///
    /// The returned handle owns the registration: dropping it releases the
    /// attempt, so an unwinding caller cannot leave a sink reachable for an
    /// attempt that is gone.
    ///
    /// The sink contract is the dispatcher's and is not softened here: it runs
    /// inside the host's one serialized section, so it must deliver in bounded
    /// time and must not wait on anything this host has to make progress on. A
    /// sink whose real work is unbounded hands off to a bounded queue.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptHostError::InvalidAttemptId`],
    /// [`AttemptHostError::DuplicateAttempt`],
    /// [`AttemptHostError::RegistrationLimit`] at
    /// [`MAX_ATTEMPT_REGISTRATIONS`], or [`AttemptHostError::Poisoned`].
    pub fn register(
        &self,
        attempt_id: &str,
        sink: Box<dyn CancelSink>,
    ) -> Result<RegistrationHandle, AttemptHostError> {
        self.dispatcher
            .register(attempt_id, sink)
            .map_err(AttemptHostError::from)
    }

    /// A seat for exactly one [`ControlServer`](automonique_runner::control::ControlServer).
    ///
    /// The seat routes that server's `cancel` through this host's one
    /// dispatcher, so a request arriving over a control socket and a request
    /// made directly through [`DaemonAttemptHost::cancel`] are serialized
    /// against each other rather than merely against their own kind. One seat
    /// per server: the seat carries a server's in-flight claim between its
    /// classify and its deliver.
    #[must_use]
    pub fn seat(&self) -> ControlSeat {
        self.dispatcher.seat()
    }

    /// Classify, deliver and record one cancellation request as one unit.
    ///
    /// The answer is delivery evidence, never exit evidence: it says a request
    /// reached a sink exactly once. Whether a process exited and whether the run
    /// reached a terminal state are separate observations through the spool.
    #[must_use]
    pub fn cancel(
        &self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: u64,
    ) -> DispatchOutcome {
        self.dispatcher
            .cancel(attempt_id, request_ref, observed_sequence)
    }

    /// End dispatch for this host and close its durable custody.
    ///
    /// Dropping the dispatcher is what ends dispatch: outstanding registration
    /// handles and seat adapters hold the interior weakly, so every one of them
    /// fails closed rather than reaching a half-dead registry. The ledger's
    /// SQLite connection closes with the custody it was owned by.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptHostError::Poisoned`] when a sink panicked inside the
    /// serialized section at some point in this host's life. Disposal still
    /// happens — the state is reported, not repaired — because a poisoned host
    /// is the one state in which this daemon cannot say whether its last
    /// cancellation was delivered, and a shutdown that returned `Ok` would be
    /// claiming it can.
    pub fn dispose(self) -> Result<(), AttemptHostError> {
        // Reading the registry is the probe: what matters is not the count but
        // whether the lock can be taken at all.
        self.registration_count().map(|_| ())
    }
}

/// Stable category for one ledger-open failure.
///
/// [`CancelLedgerError::Conflict`] and [`CancelLedgerError::LedgerFull`] are
/// unreachable from [`CancelLedger::open`], which records nothing; they are
/// mapped rather than panicked on, because an unreachable arm is not a licence
/// to abort a daemon.
const fn ledger_category(error: &CancelLedgerError) -> &'static str {
    match error {
        CancelLedgerError::InsecurePath(_) => "attempt_host_ledger_insecure_path",
        CancelLedgerError::SchemaVersion { .. } => "attempt_host_ledger_schema_version",
        CancelLedgerError::InvalidField(_) => "attempt_host_ledger_invalid_field",
        CancelLedgerError::Corrupt(_) => "attempt_host_ledger_corrupt",
        CancelLedgerError::Io(_) => "attempt_host_ledger_io",
        CancelLedgerError::Sqlite(_) => "attempt_host_ledger_sqlite",
        CancelLedgerError::Conflict { .. } | CancelLedgerError::LedgerFull { .. } => {
            "attempt_host_ledger_unavailable"
        }
    }
}
