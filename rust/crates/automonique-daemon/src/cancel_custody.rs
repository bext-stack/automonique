// SPDX-License-Identifier: Elastic-2.0

//! Durable cancel idempotency for the runner control endpoint.
//!
//! `automonique-runner`'s control socket answers `cancel` from a
//! [`CancelCustody`] implementation and holds no idempotency state of its own.
//! Its default custody is a process-local map: correct while the server lives,
//! gone the moment it restarts, and never shared with a second server. That is
//! stated as a divergence in the runner rather than pretended away.
//!
//! This module closes it. [`StoreCancelCustody`] is a newtype over
//! [`CancelLedger`], the durable host-wide ledger in `automonique-store`, and
//! it is the reason the seam is a trait at all: the runner must not depend on
//! the store — the dependency runs the other way, and a SQLite handle inside a
//! runner would put durable host state in the wrong process — so the trait
//! lives in the runner and the only implementation that survives a restart
//! lives here.
//!
//! # What this establishes, and what it does not
//!
//! - A `record` that returns [`CustodyVerdict::Fresh`] means the binding
//!   `request_ref -> (attempt_id, observed_sequence)` is durable: committed in
//!   one immediate transaction, visible to any later reader of that file,
//!   including a different process.
//! - It does **not** establish that anything was cancelled. The verdict is
//!   about custody's memory, never about a process exiting or a run reaching a
//!   terminal state. The control server delivers to its own sink; this ledger
//!   only remembers that it did.
//! - Idempotency holds for exactly as long as the row is live. The ledger's own
//!   `prune` forgets rows, and a forgotten reference is answered `Fresh` a
//!   second time.
//!
//! # Failure classification
//!
//! A reused reference is the client's bug and is answered
//! [`CustodyVerdict::Conflict`]. Everything else — corruption, a schema
//! mismatch, an unreachable database, a clock before the epoch — is this host's
//! custody being unsound, and is reported as [`CustodyFailure::Unavailable`] so
//! the endpoint answers `internal` rather than blaming the caller. This mirrors
//! the split the run-submission lane already makes between what a submitter can
//! fix and what it cannot; collapsing the two would present broken storage as a
//! misbehaving client.
//!
//! The one exception is capacity: a full ledger is a real bound a caller can
//! observe and retry against, so it keeps its own
//! [`CustodyFailure::Full`] category and reaches the wire as `ledger_full`.

use std::time::{SystemTime, UNIX_EPOCH};

use automonique_runner::control::{
    CancelClaim, CancelCustody, CustodyFailure, CustodyVerdict, MAX_IDENTIFIER_BYTES,
};
use automonique_store::cancel_ledger::{
    CancelDisposition, CancelLedger, CancelLedgerError, CancelRequest,
    MAX_IDENTIFIER_BYTES as LEDGER_MAX_IDENTIFIER_BYTES,
};

// The control endpoint validates every identifier against its own stricter
// grammar before custody is consulted, so a well-formed claim can never trip
// the ledger's length bound. If that stops holding, this assertion fails at
// compile time rather than turning a routing bug into a runtime `internal`.
const _: () = assert!(MAX_IDENTIFIER_BYTES <= LEDGER_MAX_IDENTIFIER_BYTES);

/// Durable, host-wide cancel custody backed by [`CancelLedger`].
///
/// Two control servers over one ledger file deduplicate against each other, and
/// a server that restarts over the same file answers `already_delivered` for
/// every reference its predecessor recorded.
#[derive(Debug)]
pub struct StoreCancelCustody {
    ledger: CancelLedger,
}

impl StoreCancelCustody {
    /// Take custody of an already-opened ledger.
    ///
    /// The ledger is opened by the caller rather than here, so the process that
    /// decides where durable state lives is the process that owns it. The
    /// handle's capacity is whatever it was opened with; this type never
    /// widens it.
    #[must_use]
    pub const fn new(ledger: CancelLedger) -> Self {
        Self { ledger }
    }

    /// Recover the owned ledger for controlled shutdown, pruning or tests.
    #[must_use]
    pub fn into_ledger(self) -> CancelLedger {
        self.ledger
    }

    /// Read-only view of the ledger under custody.
    #[must_use]
    pub const fn ledger(&self) -> &CancelLedger {
        &self.ledger
    }

    /// Decide one claim against a row the ledger already holds.
    ///
    /// The comparison is the ledger's own binding rule, restated here because
    /// `classify` must not write: `attempt_id` and `observed_sequence` both
    /// bind, and `requested_at_ms` does not — a retry naturally carries a later
    /// clock and is still an exact replay.
    fn verdict_for_recorded(
        recorded_attempt_id: &str,
        recorded_observed_sequence: u64,
        claim: CancelClaim<'_>,
    ) -> CustodyVerdict {
        if recorded_attempt_id == claim.attempt_id
            && recorded_observed_sequence == claim.observed_sequence
        {
            CustodyVerdict::Replay
        } else {
            CustodyVerdict::Conflict
        }
    }
}

impl CancelCustody for StoreCancelCustody {
    fn classify(&self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        if let Some(entry) = self
            .ledger
            .entry(claim.request_ref)
            .map_err(|error| custody_failure(&error))?
        {
            return Ok(Self::verdict_for_recorded(
                &entry.attempt_id,
                entry.observed_sequence,
                claim,
            ));
        }
        // Lookup precedes the capacity check, exactly as the ledger's own
        // recording does: a replay writes nothing and must never degrade into a
        // refusal because the ledger happens to be full.
        let live = self
            .ledger
            .entry_count()
            .map_err(|error| custody_failure(&error))?;
        if live >= self.ledger.capacity() {
            return Err(CustodyFailure::Full);
        }
        Ok(CustodyVerdict::Fresh)
    }

    fn record(&mut self, claim: CancelClaim<'_>) -> Result<CustodyVerdict, CustodyFailure> {
        // The clock is ours, never the wire's: a client cannot backdate a
        // durable row by sending a timestamp, because there is no field for one.
        let requested_at_ms = now_ms()?;
        let request = CancelRequest {
            request_ref: claim.request_ref,
            attempt_id: claim.attempt_id,
            observed_sequence: claim.observed_sequence,
            requested_at_ms,
        };
        match self.ledger.record(request) {
            Ok(receipt) => Ok(match receipt.disposition {
                CancelDisposition::Delivered => CustodyVerdict::Fresh,
                CancelDisposition::AlreadyDelivered => CustodyVerdict::Replay,
            }),
            Err(CancelLedgerError::Conflict { .. }) => Ok(CustodyVerdict::Conflict),
            Err(error) => Err(custody_failure(&error)),
        }
    }
}

/// Split a ledger failure into the seam's two typed custody failures.
///
/// [`CancelLedgerError::Conflict`] never reaches here: a conflict is an answer
/// about the claim, not a failure of custody, and both trait methods map it to
/// [`CustodyVerdict::Conflict`] before this function is called.
///
/// `InvalidField` is deliberately *not* treated as a client-fixable refusal.
/// The control endpoint's identifier grammar is strictly narrower than the
/// ledger's, so a field the ledger rejects means our own routing handed custody
/// something it had already validated — our invariant, not the caller's.
const fn custody_failure(error: &CancelLedgerError) -> CustodyFailure {
    match error {
        CancelLedgerError::LedgerFull { .. } => CustodyFailure::Full,
        CancelLedgerError::Conflict { .. }
        | CancelLedgerError::InvalidField(_)
        | CancelLedgerError::InsecurePath(_)
        | CancelLedgerError::SchemaVersion { .. }
        | CancelLedgerError::Corrupt(_)
        | CancelLedgerError::Io(_)
        | CancelLedgerError::Sqlite(_) => CustodyFailure::Unavailable,
    }
}

/// Host wall clock in milliseconds, on the same discipline as the transport
/// runtime's `SystemClock`: one `SystemTime` reading, and any clock this side
/// of the epoch or past `i64` is a failure rather than a clamped value.
fn now_ms() -> Result<i64, CustodyFailure> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyFailure::Unavailable)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| CustodyFailure::Unavailable)
}
