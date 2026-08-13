// SPDX-License-Identifier: Elastic-2.0

//! Concrete durable-sink adapter for the product SQLite store.

use std::time::{SystemTime, UNIX_EPOCH};

use automonique_store::{
    Store, StoreError, TelegramBatchIngestion, TelegramPollerCommit,
    TelegramPollerLease as StorePollerLease, TelegramPollerLeaseIdentity,
    TelegramPollerLeaseRenewal, TelegramPollerLeaseRequest, TelegramStoreDisposition,
    TelegramStoreUpdate,
};

use super::{
    DurableCommitReceipt, DurableDisposition, DurableTelegramBatch, OffsetReceipt, PollerLease,
    RuntimeError, SinkFailure, TelegramDurableSink, TelegramInputKind, telegram_batch_digest,
};

impl TryFrom<StorePollerLease> for PollerLease {
    type Error = RuntimeError;

    fn try_from(lease: StorePollerLease) -> Result<Self, Self::Error> {
        Self::new(
            lease.bot_id,
            lease.generation_id,
            lease.holder_id,
            lease.epoch,
            lease.expires_ms,
        )
    }
}

/// Trusted wall-clock failure. It carries no host detail into runtime errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockFailure {
    Unavailable,
}

/// Injected trusted wall-clock observation used at the durable boundary.
pub trait Clock {
    fn now_ms(&mut self) -> Result<i64, ClockFailure>;
}

/// Host wall clock for production composition.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&mut self) -> Result<i64, ClockFailure> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockFailure::Unavailable)?;
        i64::try_from(elapsed.as_millis()).map_err(|_| ClockFailure::Unavailable)
    }
}

/// Concrete adapter from the transport runtime seam to the private SQLite store.
pub struct StoreTelegramDurableSink<C> {
    store: Store,
    clock: C,
}

impl<C> StoreTelegramDurableSink<C>
where
    C: Clock,
{
    #[must_use]
    pub const fn new(store: Store, clock: C) -> Self {
        Self { store, clock }
    }

    /// Recover the owned store and clock for controlled host shutdown or tests.
    #[must_use]
    pub fn into_parts(self) -> (Store, C) {
        (self.store, self.clock)
    }

    fn observed_now(&mut self) -> Result<i64, SinkFailure> {
        self.clock
            .now_ms()
            .map_err(|_| SinkFailure::Unavailable)
            .and_then(|now_ms| {
                if now_ms < 0 {
                    Err(SinkFailure::Unavailable)
                } else {
                    Ok(now_ms)
                }
            })
    }

    /// Acquire one exact bot lease beneath an already-live generation fence.
    pub fn acquire_poller_lease(
        &mut self,
        bot_id: i64,
        generation_id: &str,
        holder_id: &str,
        authority_lease_epoch: u64,
        ttl_ms: i64,
    ) -> Result<PollerLease, SinkFailure> {
        let now_ms = self.observed_now()?;
        let lease = self
            .store
            .acquire_telegram_poller_lease(TelegramPollerLeaseRequest {
                bot_id,
                generation_id,
                holder_id,
                authority_lease_epoch,
                now_ms,
                ttl_ms,
            })
            .map_err(map_lifecycle_error)?;
        PollerLease::try_from(lease).map_err(|_| SinkFailure::Conflict)
    }

    /// Renew the exact bot lease without changing its epoch or owner.
    pub fn renew_poller_lease(
        &mut self,
        lease: &PollerLease,
        authority_lease_epoch: u64,
        ttl_ms: i64,
    ) -> Result<PollerLease, SinkFailure> {
        let now_ms = self.observed_now()?;
        let renewed = self
            .store
            .renew_telegram_poller_lease(TelegramPollerLeaseRenewal {
                bot_id: lease.bot_id,
                generation_id: &lease.generation_id,
                holder_id: &lease.holder_id,
                authority_lease_epoch,
                poller_epoch: lease.epoch,
                expected_expires_ms: lease.expires_ms,
                now_ms,
                ttl_ms,
            })
            .map_err(map_lifecycle_error)?;
        PollerLease::try_from(renewed).map_err(|_| SinkFailure::Conflict)
    }

    /// Release the exact bot lease while preserving its fencing epoch.
    pub fn release_poller_lease(&mut self, lease: &PollerLease) -> Result<(), SinkFailure> {
        let now_ms = self.observed_now()?;
        self.store
            .release_telegram_poller_lease(store_lease(lease, now_ms))
            .map_err(map_lifecycle_error)
    }
}

impl<C> TelegramDurableSink for StoreTelegramDurableSink<C>
where
    C: Clock,
{
    fn read_offset(
        &mut self,
        lease: &PollerLease,
        _caller_now_ms: i64,
    ) -> Result<OffsetReceipt, SinkFailure> {
        let observed_now = self.observed_now()?;
        let receipt = self
            .store
            .read_telegram_offset(store_lease(lease, observed_now))
            .map_err(map_read_error)?;
        Ok(OffsetReceipt {
            bot_id: receipt.bot_id,
            lease_epoch: receipt.lease_epoch,
            next_offset: receipt.next_offset,
        })
    }

    fn commit_batch(
        &mut self,
        lease: &PollerLease,
        batch: &DurableTelegramBatch,
        commit_before_ms: i64,
    ) -> Result<DurableCommitReceipt, SinkFailure> {
        if batch.bot_id != lease.bot_id
            || commit_before_ms != lease.expires_ms
            || telegram_batch_digest(batch) != batch.digest
        {
            return Err(SinkFailure::Conflict);
        }
        let observed_now = self.observed_now()?;
        let updates = batch
            .updates
            .iter()
            .map(store_update)
            .collect::<Result<Vec<_>, _>>()?;
        let receipt = self
            .store
            .commit_telegram_batch(TelegramPollerCommit {
                lease: store_lease(lease, observed_now),
                commit_before_ms,
                batch_digest: batch.digest,
                batch: TelegramBatchIngestion {
                    bot_id: batch.bot_id,
                    expected_offset: batch.expected_offset,
                    next_offset: batch.next_offset,
                    received_ms: batch.received_ms,
                    updates: &updates,
                },
            })
            .map_err(map_commit_error)?;
        Ok(DurableCommitReceipt {
            bot_id: receipt.bot_id,
            lease_epoch: receipt.lease_epoch,
            next_offset: receipt.next_offset,
            disposition_count: receipt.disposition_count,
            batch_digest: receipt.batch_digest,
            duplicate: receipt.duplicate,
        })
    }
}

fn store_lease(lease: &PollerLease, now_ms: i64) -> TelegramPollerLeaseIdentity<'_> {
    TelegramPollerLeaseIdentity {
        bot_id: lease.bot_id,
        generation_id: &lease.generation_id,
        holder_id: &lease.holder_id,
        poller_epoch: lease.epoch,
        expected_expires_ms: lease.expires_ms,
        now_ms,
    }
}

fn store_update(
    update: &super::DurableTelegramUpdate,
) -> Result<TelegramStoreUpdate<'_>, SinkFailure> {
    let disposition = match (&update.kind, &update.disposition) {
        (
            TelegramInputKind::Message | TelegramInputKind::Callback,
            DurableDisposition::Admitted { content },
        ) if !content.is_empty() => TelegramStoreDisposition::Admitted { content },
        (TelegramInputKind::Message | TelegramInputKind::Callback, DurableDisposition::Denied) => {
            TelegramStoreDisposition::Denied
        }
        (TelegramInputKind::Unsupported, DurableDisposition::IgnoredUnsupported) => {
            TelegramStoreDisposition::IgnoredUnsupported
        }
        _ => return Err(SinkFailure::Conflict),
    };
    Ok(TelegramStoreUpdate {
        update_id: update.update_id,
        source_key: &update.source_key,
        scope: &update.scope,
        disposition,
    })
}

fn map_read_error(error: StoreError) -> SinkFailure {
    match error {
        StoreError::AuthorityLost | StoreError::StaleEpoch | StoreError::LeaseHeld => {
            SinkFailure::StaleLease
        }
        StoreError::InvalidField(_)
        | StoreError::IdempotencyConflict(_)
        | StoreError::ScopeLocked
        | StoreError::ReconciliationRequired { .. }
        | StoreError::OutboxReconciliationRequired { .. }
        | StoreError::NotFound(_)
        | StoreError::AlreadyTerminal
        | StoreError::OutboxConflict
        | StoreError::AlreadyPaused(_)
        | StoreError::NotPaused => SinkFailure::Conflict,
        StoreError::InsecurePath(_)
        | StoreError::SchemaVersion { .. }
        | StoreError::MigrationInvariant(_)
        | StoreError::Io(_)
        | StoreError::Sqlite(_) => SinkFailure::Unavailable,
    }
}

fn map_lifecycle_error(error: StoreError) -> SinkFailure {
    match error {
        StoreError::AuthorityLost | StoreError::StaleEpoch | StoreError::LeaseHeld => {
            SinkFailure::StaleLease
        }
        StoreError::InvalidField(_)
        | StoreError::IdempotencyConflict(_)
        | StoreError::ScopeLocked
        | StoreError::ReconciliationRequired { .. }
        | StoreError::OutboxReconciliationRequired { .. }
        | StoreError::NotFound(_)
        | StoreError::AlreadyTerminal
        | StoreError::OutboxConflict
        | StoreError::AlreadyPaused(_)
        | StoreError::NotPaused => SinkFailure::Conflict,
        StoreError::InsecurePath(_)
        | StoreError::SchemaVersion { .. }
        | StoreError::MigrationInvariant(_)
        | StoreError::Io(_)
        | StoreError::Sqlite(_) => SinkFailure::Unavailable,
    }
}

fn map_commit_error(error: StoreError) -> SinkFailure {
    match error {
        StoreError::AuthorityLost | StoreError::StaleEpoch | StoreError::LeaseHeld => {
            SinkFailure::StaleLease
        }
        StoreError::InvalidField(_)
        | StoreError::IdempotencyConflict(_)
        | StoreError::ScopeLocked
        | StoreError::ReconciliationRequired { .. }
        | StoreError::OutboxReconciliationRequired { .. }
        | StoreError::NotFound(_)
        | StoreError::AlreadyTerminal
        | StoreError::OutboxConflict
        | StoreError::AlreadyPaused(_)
        | StoreError::NotPaused => SinkFailure::Conflict,
        StoreError::Io(_) | StoreError::Sqlite(_) => SinkFailure::AmbiguousCommit,
        StoreError::InsecurePath(_)
        | StoreError::SchemaVersion { .. }
        | StoreError::MigrationInvariant(_) => SinkFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_refusal_classes_are_contextual_and_closed() {
        assert_eq!(
            map_read_error(StoreError::AuthorityLost),
            SinkFailure::StaleLease
        );
        assert_eq!(
            map_commit_error(StoreError::AuthorityLost),
            SinkFailure::StaleLease
        );
        assert_eq!(
            map_commit_error(StoreError::IdempotencyConflict("fixture")),
            SinkFailure::Conflict
        );
        assert_eq!(
            map_read_error(StoreError::MigrationInvariant("fixture")),
            SinkFailure::Unavailable
        );
    }
}
