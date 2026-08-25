// SPDX-License-Identifier: Elastic-2.0

//! Host cancellation dispatcher: one owner for classify, deliver and record.
//!
//! [`crate::control`] holds the two halves of a cancellation apart. Custody
//! decides *whether* a request is new; a per-binding [`CancelSink`] performs the
//! delivery; the server sequences them and states the gap it leaves open. This
//! module closes that gap inside one process by owning both halves in one
//! non-cloneable value, so the whole `classify -> deliver -> record` sequence is
//! one serialized section.
//!
//! # The race this closes
//!
//! Two control servers over one durable custody can interleave:
//!
//! ```text
//! server A: classify(ref) -> Fresh
//! server B: classify(ref) -> Fresh          <- B has not seen A's record yet
//! server A: sink.deliver(ref)               <- first delivery
//! server B: sink.deliver(ref)               <- second delivery, same reference
//! server A: record(ref)   -> Fresh
//! server B: record(ref)   -> Replay
//! ```
//!
//! Idempotency was claimed and not held: one reference reached a sink twice.
//! [`CancelDispatcher::cancel`] makes that interleaving unspellable inside one
//! dispatcher. Exactly one caller is told [`DispatchOutcome::Delivered`]; every
//! later caller of that reference is told
//! [`DispatchOutcome::AlreadyDelivered`], and the sink fires once. A custody
//! implementation that durably reserves during `classify` extends sink
//! exclusion across dispatcher processes; an overlapping caller may fail
//! closed as [`DispatchOutcome::CustodyUnavailable`] while the winner is still
//! in flight, then observe `AlreadyDelivered` after completion.
//!
//! # Lock discipline
//!
//! One coarse [`Mutex`] guards custody and the sink registry together, and
//! **delivery happens inside it**. Three reasons the coarse lock is the right
//! shape here rather than a per-reference lock map:
//!
//! - [`CancelCustody::record`] takes `&mut self`, so custody is a single
//!   exclusive resource whatever else is done. A per-reference map would still
//!   funnel every request through that one object.
//! - Custody capacity is global, not per reference. With per-reference locks a
//!   claim could classify `Fresh` and then hit [`CustodyFailure::Full`] at
//!   record time because an unrelated reference took the last slot — a delivery
//!   that happened and could not be remembered. The coarse lock removes that
//!   window entirely.
//! - The critical section is bounded by construction: one hash lookup, one
//!   `classify`, one `deliver`, one `record`.
//!
//! Delivering inside the lock is what buys atomicity, and it imposes a contract
//! on the sink rather than an assumption about it:
//!
//! > A [`CancelSink`] registered here must deliver in bounded time and must not
//! > wait on anything this host has to make progress on. Flipping a
//! > [`CancellationToken`](crate::CancellationToken), signalling a process
//! > group, or pushing onto a bounded queue all qualify. Joining a process,
//! > performing a network round trip, or taking a lock another cancelling
//! > thread may hold do not.
//!
//! This module states that contract; it cannot enforce it. A slow sink does not
//! corrupt anything — the sequence stays correct — but it stalls every other
//! attempt's cancellation on this host for as long as it blocks, because there
//! is one lock for the host. A caller whose real cancellation work is unbounded
//! registers a sink that hands off to a bounded queue and does the slow work on
//! its own thread. A sink that *panics* inside the section poisons the lock, and
//! this module then fails closed: every later `cancel` answers
//! [`DispatchOutcome::CustodyUnavailable`] and every later registration answers
//! [`DispatchError::Poisoned`], because after a panic between delivery and
//! recording nobody can say whether the delivery happened.
//!
//! # Composing with [`ControlServer`](crate::control::ControlServer)
//!
//! The server calls `custody.classify`, then its own `sink.deliver`, then
//! `custody.record` — three separate calls it drives itself. A dispatcher-backed
//! custody cannot simply take the lock in `classify` and release it in `record`:
//! the server returns early — and never calls `record` — on a replay, on a
//! conflict and on an unavailable sink, so the lock would leak on three of five
//! paths and deadlock the host.
//!
//! So the atomicity lives in the *sink* instead. A [`ControlSeat`] hands one
//! server a custody adapter and one sink adapter per attempt:
//!
//! - the custody adapter remembers a syntactically valid claim but deliberately
//!   defers authoritative classification to the sink adapter, avoiding a second
//!   reservation of the same reference;
//! - the sink adapter runs the entire serialized sequence — re-classify,
//!   deliver, record — so a request that lost the race between the server's
//!   classify and its deliver is not delivered a second time;
//! - the sink returns the dispatcher's completed outcome, so the server skips
//!   its ordinary trailing `record` and answers with the winner's exact result.
//!
//! The seat exists because [`CancelSink::deliver`] carries no observed sequence
//! and the claim needs one. The seat remembers the claim its custody adapter
//! last classified, pinned to the classifying thread, and the sink adapter
//! refuses to invent one: a delivery whose seat holds no matching claim from
//! this thread fails closed rather than recording a sequence it guessed.
//!
//! The server's own invariant is preserved rather than weakened: an unavailable
//! sink records nothing. The dispatcher records only after the registered sink
//! returned `Ok`, in the same critical section, so there is no window in which a
//! refused delivery is remembered as one.
//!
//! # What this does **not** establish
//!
//! - **Cross-process exclusion belongs to custody.** This type serialises the
//!   callers it owns. Two dispatchers are safe only when their shared durable
//!   custody reserves a fresh claim before either sink is touched; a purely
//!   in-memory custody remains process-local.
//! - **It is not exit evidence.** [`DispatchOutcome::Delivered`] says a request
//!   reached a sink once. Whether a process exited, whether descendants were
//!   reaped and whether the run reached a terminal state remain separate
//!   observations through the spool.
//! - **It is not durability.** Idempotency survives exactly as long as the
//!   explicit custody it was constructed with.
//! - **It is not authorization.** Anyone holding the dispatcher can cancel any
//!   attempt registered on it. Deciding who may ask is the caller's policy.

use crate::control::{
    CancelClaim, CancelCustody, CancelDelivery, CancelSink, CancelSinkError, CustodyFailure,
    CustodyVerdict, MAX_BINDINGS, MAX_IDENTIFIER_BYTES, Refusal,
};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::ThreadId;

/// Most attempts one dispatcher registers at once.
///
/// Deliberately [`MAX_BINDINGS`]: a registration exists to serve a control
/// binding, so a dispatcher that outgrew the server it feeds would be holding
/// sinks nothing can reach. Reusing the number keeps the two bounds from
/// drifting into a state where a binding is admissible and its dispatch
/// registration is not.
pub const MAX_REGISTRATIONS: usize = MAX_BINDINGS;

/// What one dispatch decided.
///
/// The vocabulary is the control wire's, so a caller placing this on that wire
/// makes no judgement of its own — see [`DispatchOutcome::refusal`], which is
/// the whole mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    /// The registered sink accepted this reference, and custody now holds it.
    /// Delivery evidence only: nothing here claims a process exited.
    Delivered,
    /// Custody already held this exact reference. The sink was not called.
    AlreadyDelivered,
    /// Custody binds this reference to a different attempt or a different
    /// observed sequence. The sink was not called and nothing was written.
    Conflict,
    /// No registration holds this attempt, so there was nothing to deliver to.
    /// Custody was not consulted and cannot be minted by an unknown attempt.
    UnknownAttempt,
    /// The registered sink accepted no signal. Nothing was recorded, so a retry
    /// with the same reference is a real second attempt.
    SinkUnavailable,
    /// Custody holds its full capacity.
    CustodyFull,
    /// Custody could not be consulted, or this dispatcher was poisoned by a
    /// panicking sink.
    CustodyUnavailable,
    /// An identifier is outside the bounded grammar. The direct API is reachable
    /// by callers that never parsed a wire line, so spelling is checked here
    /// rather than trusted.
    FieldInvalid,
}

impl DispatchOutcome {
    /// Stable spelling for logs and assertions. It carries no caller bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::AlreadyDelivered => "already_delivered",
            Self::Conflict => "conflict",
            Self::UnknownAttempt => "unknown_attempt",
            Self::SinkUnavailable => "sink_unavailable",
            Self::CustodyFull => "custody_full",
            Self::CustodyUnavailable => "custody_unavailable",
            Self::FieldInvalid => "field_invalid",
        }
    }

    /// The control wire's refusal category, or `None` for the two outcomes that
    /// answer `cancel_result` instead of `refused`.
    ///
    /// This is the only place the two vocabularies are joined, so a new outcome
    /// cannot reach the wire without a deliberate category for it.
    #[must_use]
    pub const fn refusal(self) -> Option<Refusal> {
        match self {
            Self::Delivered | Self::AlreadyDelivered => None,
            Self::Conflict => Some(Refusal::CancelConflict),
            Self::UnknownAttempt => Some(Refusal::TargetUnknown),
            Self::SinkUnavailable => Some(Refusal::CancelUnavailable),
            Self::CustodyFull => Some(Refusal::LedgerFull),
            Self::CustodyUnavailable => Some(Refusal::Internal),
            Self::FieldInvalid => Some(Refusal::FieldInvalid),
        }
    }

    /// Whether this outcome says the request reached the sink exactly once.
    ///
    /// True for both delivery answers: the distinction between them is which
    /// caller delivered, not whether a delivery happened.
    #[must_use]
    pub const fn is_delivery_evidence(self) -> bool {
        matches!(self, Self::Delivered | Self::AlreadyDelivered)
    }
}

impl fmt::Display for DispatchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why a registration could not be made or released.
///
/// Dispatch itself never returns one of these: a cancellation always has a
/// [`DispatchOutcome`], including for the failures these name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// The attempt identifier is outside the bounded grammar.
    InvalidIdentifier,
    /// A registration already holds this attempt. Registration never replaces a
    /// live one, mirroring [`ControlServer::register`](crate::control::ControlServer::register).
    DuplicateAttempt,
    /// No registration holds this attempt, or the handle's registration was
    /// already replaced.
    UnknownAttempt,
    /// The dispatcher already holds [`MAX_REGISTRATIONS`] registrations.
    RegistrationLimit,
    /// A sink panicked inside the serialized section. The dispatcher is dead:
    /// it can no longer say whether that delivery happened, so it answers
    /// nothing else.
    Poisoned,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => {
                formatter.write_str("dispatch attempt id is not a bounded identifier")
            }
            Self::DuplicateAttempt => {
                formatter.write_str("dispatch registration already exists for this attempt")
            }
            Self::UnknownAttempt => {
                formatter.write_str("no dispatch registration holds this attempt")
            }
            Self::RegistrationLimit => write!(
                formatter,
                "dispatcher already holds {MAX_REGISTRATIONS} registrations"
            ),
            Self::Poisoned => {
                formatter.write_str("dispatcher was poisoned by a panicking cancel sink")
            }
        }
    }
}

impl std::error::Error for DispatchError {}

/// One attempt's sink, and the registration epoch that owns it.
struct Registration {
    /// Monotonic epoch. A handle or sink adapter from an earlier registration
    /// of the same attempt identifier carries an older epoch and is refused, so
    /// a late drop cannot release a live registration and a stale adapter cannot
    /// cross-route into it.
    epoch: u64,
    sink: Box<dyn CancelSink>,
}

/// Everything the coarse lock guards, in one place.
struct DispatchState {
    custody: Box<dyn CancelCustody>,
    registrations: HashMap<String, Registration>,
    next_epoch: u64,
}

/// The shared interior. Handles and adapters hold this weakly, so dropping the
/// [`CancelDispatcher`] really does end dispatch rather than keeping a detached
/// half of it alive through an outstanding adapter.
struct DispatchCore {
    state: Mutex<DispatchState>,
    capacity: usize,
}

impl DispatchCore {
    fn locked(&self) -> Result<MutexGuard<'_, DispatchState>, DispatchError> {
        self.state.lock().map_err(|_| DispatchError::Poisoned)
    }

    /// The whole sequence, under one lock, for one claim.
    ///
    /// `pinned_epoch` is `Some` only for a sink adapter, which must reach the
    /// exact registration it was minted for.
    fn dispatch(
        &self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: u64,
        pinned_epoch: Option<u64>,
    ) -> DispatchOutcome {
        if !is_identifier(attempt_id) || !is_identifier(request_ref) {
            return DispatchOutcome::FieldInvalid;
        }
        let Ok(mut guard) = self.state.lock() else {
            return DispatchOutcome::CustodyUnavailable;
        };
        // Split the borrow so custody can be mutated while the sink is held.
        let DispatchState {
            custody,
            registrations,
            ..
        } = &mut *guard;

        // Existence first, exactly as the control server orders it: an attempt
        // nothing is registered for must not be able to mint a custody entry.
        let Some(registration) = registrations.get(attempt_id) else {
            return DispatchOutcome::UnknownAttempt;
        };
        if pinned_epoch.is_some_and(|epoch| epoch != registration.epoch) {
            return DispatchOutcome::UnknownAttempt;
        }

        let claim = CancelClaim {
            attempt_id,
            request_ref,
            observed_sequence,
        };
        match custody.classify(claim) {
            Ok(CustodyVerdict::Fresh) => {}
            Ok(CustodyVerdict::Replay) => return DispatchOutcome::AlreadyDelivered,
            Ok(CustodyVerdict::Conflict) => return DispatchOutcome::Conflict,
            Err(failure) => return custody_outcome(failure),
        }
        if registration.sink.deliver(attempt_id, request_ref).is_err() {
            // Nothing recorded: a delivery that was refused must never be
            // remembered as one, or the retry becomes a false replay.
            return match custody.abandon(claim) {
                Ok(()) => DispatchOutcome::SinkUnavailable,
                Err(failure) => custody_outcome(failure),
            };
        }
        match custody.record(claim) {
            Ok(CustodyVerdict::Fresh | CustodyVerdict::Replay) => DispatchOutcome::Delivered,
            // Only reachable when custody is shared with a writer outside this
            // dispatcher — another process over one durable ledger. Reported the
            // way the control server reports it, after a delivery that did
            // happen.
            Ok(CustodyVerdict::Conflict) => DispatchOutcome::Conflict,
            Err(failure) => custody_outcome(failure),
        }
    }

    /// Release `attempt_id` only while `epoch` still owns it.
    fn release(&self, attempt_id: &str, epoch: u64) -> Result<Box<dyn CancelSink>, DispatchError> {
        let mut guard = self.locked()?;
        match guard.registrations.get(attempt_id) {
            Some(registration) if registration.epoch == epoch => {}
            _ => return Err(DispatchError::UnknownAttempt),
        }
        guard
            .registrations
            .remove(attempt_id)
            .map(|registration| registration.sink)
            .ok_or(DispatchError::UnknownAttempt)
    }
}

/// One host's owner of the cancellation sequence.
///
/// Deliberately **not** [`Clone`]: a second dispatcher over the same custody
/// would reintroduce the interleaving this type exists to remove, so the type
/// system refuses to spell it. Sharing is by reference — the value is [`Sync`],
/// and every operation takes `&self`.
///
/// Dropping it ends dispatch: outstanding adapters hold the interior weakly, so
/// a sink adapter still bound on a control server fails closed rather than
/// reaching a half-dead registry.
pub struct CancelDispatcher {
    core: Arc<DispatchCore>,
}

impl CancelDispatcher {
    /// Take ownership of one custody for this host.
    ///
    /// Whatever durability, capacity and clock the custody has are the
    /// dispatcher's: this type adds serialization, never storage.
    #[must_use]
    pub fn new(custody: Box<dyn CancelCustody>) -> Self {
        Self::with_capacity(custody, MAX_REGISTRATIONS)
    }

    /// As [`CancelDispatcher::new`], bounded at `capacity` registrations.
    ///
    /// A capacity above [`MAX_REGISTRATIONS`] is clamped down to it, so no
    /// caller can widen this process's footprint past the module's stated bound.
    #[must_use]
    pub fn with_capacity(custody: Box<dyn CancelCustody>, capacity: usize) -> Self {
        Self {
            core: Arc::new(DispatchCore {
                state: Mutex::new(DispatchState {
                    custody,
                    registrations: HashMap::new(),
                    next_epoch: 0,
                }),
                capacity: capacity.min(MAX_REGISTRATIONS),
            }),
        }
    }

    /// Registrations this dispatcher may hold at once.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.core.capacity
    }

    /// Live registrations.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::Poisoned`] when a sink panicked inside the
    /// serialized section.
    pub fn registration_count(&self) -> Result<usize, DispatchError> {
        Ok(self.core.locked()?.registrations.len())
    }

    /// Couple one attempt identifier to the sink that cancels it.
    ///
    /// The returned handle owns the registration: dropping it releases the
    /// attempt, so an unwinding caller cannot leave a sink reachable for an
    /// attempt that is gone. That is the same guard discipline
    /// [`crate::supervise`] uses for a control binding, for the same reason.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::InvalidIdentifier`] for a spelling outside the
    /// bounded grammar, [`DispatchError::DuplicateAttempt`] when the attempt is
    /// already registered — registration never replaces a live one —
    /// [`DispatchError::RegistrationLimit`] at [`CancelDispatcher::capacity`],
    /// and [`DispatchError::Poisoned`] for a dead dispatcher.
    pub fn register(
        &self,
        attempt_id: &str,
        sink: Box<dyn CancelSink>,
    ) -> Result<RegistrationHandle, DispatchError> {
        if !is_identifier(attempt_id) {
            return Err(DispatchError::InvalidIdentifier);
        }
        let mut guard = self.core.locked()?;
        if guard.registrations.contains_key(attempt_id) {
            return Err(DispatchError::DuplicateAttempt);
        }
        if guard.registrations.len() >= self.core.capacity {
            return Err(DispatchError::RegistrationLimit);
        }
        let epoch = guard.next_epoch;
        guard.next_epoch += 1;
        guard
            .registrations
            .insert(attempt_id.to_owned(), Registration { epoch, sink });
        drop(guard);
        Ok(RegistrationHandle {
            core: Arc::downgrade(&self.core),
            attempt_id: attempt_id.to_owned(),
            epoch,
            released: false,
        })
    }

    /// Classify, deliver and record one cancellation request as one unit.
    ///
    /// This is the operation the whole module exists for. Every step runs under
    /// one lock, so no other caller of this dispatcher can observe the
    /// half-state between them and deliver the same reference again.
    ///
    /// The answer is delivery evidence, never exit evidence.
    pub fn cancel(
        &self,
        attempt_id: &str,
        request_ref: &str,
        observed_sequence: u64,
    ) -> DispatchOutcome {
        self.core
            .dispatch(attempt_id, request_ref, observed_sequence, None)
    }

    /// A seat for exactly one [`ControlServer`](crate::control::ControlServer).
    ///
    /// One seat per server, always: the seat carries the in-flight claim between
    /// that server's `classify` and its `deliver`, and a server is
    /// single-threaded by construction, so a seat holds at most one claim at a
    /// time. A seat shared by two servers on two threads does not corrupt
    /// anything — the claim is pinned to the thread that classified it, and a
    /// delivery from any other thread fails closed.
    #[must_use]
    pub fn seat(&self) -> ControlSeat {
        ControlSeat {
            core: Arc::downgrade(&self.core),
            claim: Arc::new(Mutex::new(None)),
        }
    }
}

impl fmt::Debug for CancelDispatcher {
    /// Deliberately narrow: no attempt identifiers, no request references and
    /// no custody contents reach a debug rendering. A poisoned dispatcher says
    /// so rather than pretending to a count it cannot read.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let registrations = self.registration_count().ok();
        formatter
            .debug_struct("CancelDispatcher")
            .field("registrations", &registrations)
            .field("capacity", &self.core.capacity)
            .finish_non_exhaustive()
    }
}

/// One live registration, released on every path including a panic.
///
/// The handle is the registration's owner. It is not [`Clone`], so there is
/// exactly one releaser per registration, and it carries the registration epoch,
/// so a handle dropped after its attempt was re-registered releases nothing.
pub struct RegistrationHandle {
    core: Weak<DispatchCore>,
    attempt_id: String,
    epoch: u64,
    released: bool,
}

impl RegistrationHandle {
    /// Attempt identifier this registration holds.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Release the registration and hand the sink back.
    ///
    /// The ordinary path. `Drop` is the backstop for an unwinding caller and
    /// does the same thing without reporting it.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::UnknownAttempt`] when the registration is
    /// already gone, when a later registration replaced it, or when the
    /// dispatcher itself has been dropped — there is no registry left to leave.
    /// Returns [`DispatchError::Poisoned`] for a dispatcher a panicking sink
    /// killed.
    pub fn release(mut self) -> Result<Box<dyn CancelSink>, DispatchError> {
        // Marked before the work, so a release that fails is not retried by
        // `Drop` against a registry it may already have left.
        self.released = true;
        let core = self.core.upgrade().ok_or(DispatchError::UnknownAttempt)?;
        core.release(&self.attempt_id, self.epoch)
    }
}

impl Drop for RegistrationHandle {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // Best effort and deliberately the same shape as `release`. A poisoned
        // dispatcher cannot be mutated at all; that leaks at most
        // `MAX_REGISTRATIONS` sinks in a process whose dispatcher already
        // refuses every operation.
        if let Some(core) = self.core.upgrade() {
            let _ = core.release(&self.attempt_id, self.epoch);
        }
    }
}

impl fmt::Debug for RegistrationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationHandle")
            .field("attempt_id", &self.attempt_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// The claim a seat's custody adapter last classified.
///
/// `thread` is part of the identity, not a diagnostic: it is what makes a sink
/// adapter refuse to deliver on behalf of a classify some other thread did.
struct SeatClaim {
    thread: ThreadId,
    attempt_id: String,
    request_ref: String,
    observed_sequence: u64,
}

/// One [`ControlServer`](crate::control::ControlServer)'s connection to a
/// dispatcher.
///
/// Not [`Clone`]: one seat per server. See the module documentation for what
/// this composition establishes.
///
/// # Lock ordering
///
/// A seat holds two locks — the dispatcher's state lock and its own claim cell —
/// and never holds one while taking the other. Every adapter method acquires
/// them strictly one at a time, so no ordering between them exists to invert.
pub struct ControlSeat {
    core: Weak<DispatchCore>,
    claim: Arc<Mutex<Option<SeatClaim>>>,
}

impl ControlSeat {
    /// Custody for [`ControlServer::bind`](crate::control::ControlServer::bind).
    ///
    /// It remembers the claim so this seat's sink can run authoritative
    /// classification and delivery through the dispatcher in one serialized
    /// operation. Bind exactly one server with it.
    #[must_use]
    pub fn custody(&self) -> Box<dyn CancelCustody> {
        Box::new(SeatCustody {
            core: Weak::clone(&self.core),
            claim: Arc::clone(&self.claim),
        })
    }

    /// A sink for [`ControlServer::register`](crate::control::ControlServer::register)
    /// that routes the whole sequence through the dispatcher.
    ///
    /// Pinned to `handle`'s exact registration: once that handle is dropped or
    /// the attempt is re-registered, this sink reaches nothing, so a stale
    /// binding can never cross-route into a newer registration.
    #[must_use]
    pub fn sink(&self, handle: &RegistrationHandle) -> Box<dyn CancelSink> {
        Box::new(SeatSink {
            core: Weak::clone(&self.core),
            claim: Arc::clone(&self.claim),
            attempt_id: handle.attempt_id.clone(),
            epoch: handle.epoch,
        })
    }
}

impl fmt::Debug for ControlSeat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlSeat")
            .finish_non_exhaustive()
    }
}

/// A seat's custody adapter.
struct SeatCustody {
    core: Weak<DispatchCore>,
    claim: Arc<Mutex<Option<SeatClaim>>>,
}

impl SeatCustody {
    /// Remember a claim the server is about to deliver, or forget the last one.
    ///
    /// A verdict other than `Fresh` means the server answers without delivering,
    /// so the claim is dropped rather than left behind for a sink to complete.
    fn remember(&self, claim: Option<&CancelClaim<'_>>) {
        let Ok(mut slot) = self.claim.lock() else {
            return;
        };
        *slot = claim.map(|claim| SeatClaim {
            thread: std::thread::current().id(),
            attempt_id: claim.attempt_id.to_owned(),
            request_ref: claim.request_ref.to_owned(),
            observed_sequence: claim.observed_sequence,
        });
    }
}

impl CancelCustody for SeatCustody {
    fn classify(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        self.core.upgrade().ok_or(CustodyFailure::Unavailable)?;
        // The sink adapter performs the authoritative classification inside
        // the dispatcher's serialized section. Remembering the claim here
        // supplies its observed sequence without reserving it twice.
        self.remember(Some(&claim));
        Ok(CustodyVerdict::Fresh)
    }

    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        let core = self.core.upgrade().ok_or(CustodyFailure::Unavailable)?;
        // The sequence is over either way, so the claim is forgotten before the
        // answer: a sink must never be able to complete a claim twice.
        self.remember(None);
        let mut guard = core.state.lock().map_err(|_| CustodyFailure::Unavailable)?;
        guard.custody.record(claim)
    }

    fn abandon(&mut self, _claim: CancelClaim<'_>) -> Result<(), CustodyFailure> {
        self.remember(None);
        Ok(())
    }
}

/// A seat's sink adapter: where the serialized sequence actually runs.
struct SeatSink {
    core: Weak<DispatchCore>,
    claim: Arc<Mutex<Option<SeatClaim>>>,
    attempt_id: String,
    epoch: u64,
}

impl SeatSink {
    /// Consume the observed sequence this seat classified for exactly this
    /// request, on this thread.
    ///
    /// `None` means the seat holds no matching claim: the sink was reached
    /// without its own custody's classify, from another thread, or twice for one
    /// claim. There is no sequence to guess, so the caller fails closed. Taking
    /// rather than reading is what makes one classify complete at most one
    /// delivery even on the paths where the server never calls `record`.
    fn take_observed_sequence(&self, attempt_id: &str, request_ref: &str) -> Option<u64> {
        let mut slot = self.claim.lock().ok()?;
        let matches = slot.as_ref().is_some_and(|claim| {
            claim.thread == std::thread::current().id()
                && claim.attempt_id == attempt_id
                && claim.request_ref == request_ref
        });
        if !matches {
            return None;
        }
        slot.take().map(|claim| claim.observed_sequence)
    }
}

impl CancelSink for SeatSink {
    fn deliver(
        &self,
        attempt_id: &str,
        request_ref: &str,
    ) -> Result<CancelDelivery, CancelSinkError> {
        // The server only calls the sink its own binding holds, so a mismatch is
        // unreachable; refusing rather than dispatching keeps it that way if
        // that ever stops being true.
        if attempt_id != self.attempt_id {
            return Err(CancelSinkError::Unavailable);
        }
        let observed_sequence = self
            .take_observed_sequence(attempt_id, request_ref)
            .ok_or(CancelSinkError::Unavailable)?;
        let core = self.core.upgrade().ok_or(CancelSinkError::Unavailable)?;
        let outcome = core.dispatch(attempt_id, request_ref, observed_sequence, Some(self.epoch));
        match outcome {
            DispatchOutcome::Delivered => Ok(CancelDelivery::Delivered),
            DispatchOutcome::AlreadyDelivered => Ok(CancelDelivery::AlreadyDelivered),
            DispatchOutcome::Conflict => Err(CancelSinkError::Conflict),
            DispatchOutcome::CustodyFull => Err(CancelSinkError::LedgerFull),
            DispatchOutcome::CustodyUnavailable => Err(CancelSinkError::Internal),
            DispatchOutcome::UnknownAttempt
            | DispatchOutcome::SinkUnavailable
            | DispatchOutcome::FieldInvalid => Err(CancelSinkError::Unavailable),
        }
    }
}

/// Map a custody failure onto the outcome that carries the same wire category.
const fn custody_outcome(failure: CustodyFailure) -> DispatchOutcome {
    match failure {
        CustodyFailure::Full => DispatchOutcome::CustodyFull,
        CustodyFailure::Unavailable => DispatchOutcome::CustodyUnavailable,
    }
}

/// The control endpoint's bounded identifier grammar, restated.
///
/// `control`'s own predicate is private to that module, so this is a copy rather
/// than a call. It is deliberately the *same* rule: an identifier this
/// dispatcher accepts but the wire refuses would be a registration nothing could
/// ever reach, and one the wire accepts but this refuses would be a binding that
/// could never be cancelled. The exercised tests pin both directions against a
/// real server.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}
