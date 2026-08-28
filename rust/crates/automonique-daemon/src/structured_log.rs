// SPDX-License-Identifier: Elastic-2.0

//! Bounded native-journal lifecycle events for operator diagnostics.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

pub(crate) const READY_MESSAGE_ID: &str = "e8b42f1b07f64ccfae8bb73f1dd7cf37";
pub(crate) const READY_SCHEMA: &str = "automonique.structured-log/v1";
pub(crate) const READY_EVENT: &str = "daemon_ready";
pub(crate) const DRAIN_MESSAGE_ID: &str = "c64c8c969f2d43bb8baef5569fb69f96";
pub(crate) const DRAIN_EVENT: &str = "shutdown_worker_drain";
pub(crate) const WORKER_FAULT_MESSAGE_ID: &str = "5d3f0b7a9c1e4e0b8a6f2d9c4b1e7a35";
pub(crate) const WORKER_FAULT_EVENT: &str = "worker_fault";
pub(crate) const RENEWAL_DEFERRED_MESSAGE_ID: &str = "0b1c7d5e2a9f4b6c8d3e1f7a5c9b2d40";
pub(crate) const RENEWAL_DEFERRED_EVENT: &str = "lease_renewal_deferred";
pub(crate) const TEMPFS_RECONCILED_MESSAGE_ID: &str = "db1313b593ad4bbe907a22f790c6b8f6";
pub(crate) const TEMPFS_RECONCILED_EVENT: &str = "temporary_storage_reconciled";
#[cfg(test)]
const TEMPFS_UNRECONCILED_MESSAGE_ID: &str = "d6ed31785c3e441b934c73311da99a03";
#[cfg(test)]
const TEMPFS_UNRECONCILED_EVENT: &str = "temporary_storage_unreconciled";
pub(crate) const TEMPFS_REAPED_MESSAGE_ID: &str = "37b70f59343543d4a52a9c6b2015c0f6";
pub(crate) const TEMPFS_REAPED_EVENT: &str = "temporary_storage_mount_reaped";
pub(crate) const TEMPFS_RECOVERED_MESSAGE_ID: &str = "3a576f63c0964a31947c4d7b9cc57261";
pub(crate) const TEMPFS_RECOVERED_EVENT: &str = "temporary_storage_checkpoint_recovered";
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
const MAX_EVENT_BYTES: usize = 1_024;
const MAX_CATEGORY_BYTES: usize = 64;

/// A worker thread stopped on its own, on a failure a later tick could not
/// have retried.
///
/// Emitted once by the thread that stops, at warning priority: the daemon
/// keeps serving, but a worker group it started is no longer acting, and the
/// status projection can say only that it stopped — the category, which is
/// the only diagnostic the worker has, lands here. Both fields are stable
/// machine vocabularies; nothing a user typed can reach a journal field.
pub(crate) fn emit_worker_fault(worker_group: &str, category: &str) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_worker_fault_to(Path::new(JOURNAL_SOCKET), worker_group, category)
}

fn emit_worker_fault_to(socket_path: &Path, worker_group: &str, category: &str) -> io::Result<()> {
    if !stable_vocabulary(worker_group) || !stable_vocabulary(category) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid worker fault observation",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique worker stopped on a fault\n\
         MESSAGE_ID={WORKER_FAULT_MESSAGE_ID}\n\
         PRIORITY=4\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={WORKER_FAULT_EVENT}\n\
         AUTOMONIQUE_WORKER_GROUP={worker_group}\n\
         AUTOMONIQUE_FAULT_CATEGORY={category}\n"
    );
    emit_to(socket_path, &event)
}

/// A lease renewal failed on a store that would not answer while the lease
/// is still ours by its TTL: the daemon backs off and retries instead of
/// exiting. `lease` names which lease, `category` the store's refusal, and
/// `remaining_ms` how long the lease stays valid without a renewal.
pub(crate) fn emit_lease_renewal_deferred(
    lease: &str,
    category: &str,
    remaining_ms: i64,
) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_lease_renewal_deferred_to(Path::new(JOURNAL_SOCKET), lease, category, remaining_ms)
}

fn emit_lease_renewal_deferred_to(
    socket_path: &Path,
    lease: &str,
    category: &str,
    remaining_ms: i64,
) -> io::Result<()> {
    if !stable_vocabulary(lease) || !stable_vocabulary(category) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid renewal observation",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique deferred a lease renewal on a transient store failure\n\
         MESSAGE_ID={RENEWAL_DEFERRED_MESSAGE_ID}\n\
         PRIORITY=4\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={RENEWAL_DEFERRED_EVENT}\n\
         AUTOMONIQUE_LEASE={lease}\n\
         AUTOMONIQUE_FAULT_CATEGORY={category}\n\
         AUTOMONIQUE_LEASE_REMAINING_MS={remaining_ms}\n"
    );
    emit_to(socket_path, &event)
}

/// What one run's temporary-storage mount was found to hold when its owner
/// reconciled it: the ledger's ceilings, peaks and refusals, the kernel's
/// `statvfs` right before unmount when the server answered, and whether the
/// readback had to be aborted and the unmount was confirmed from the mount
/// table. Numbers and booleans only, so nothing a workload wrote can reach a
/// journal field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TemporaryStorageReconciliation {
    pub(crate) ceiling_bytes: u64,
    pub(crate) ceiling_objects: u64,
    pub(crate) peak_bytes: u64,
    pub(crate) peak_objects: u64,
    pub(crate) refused_bytes: u64,
    pub(crate) refused_objects: u64,
    /// Bytes in use per the kernel's `statvfs` before unmount; `None` when
    /// the server had gone or the readback was aborted.
    pub(crate) statfs_used_bytes: Option<u64>,
    pub(crate) readback_aborted: bool,
    pub(crate) unmount_confirmed: bool,
}

impl TemporaryStorageReconciliation {
    pub(crate) fn from_namespaced(outcome: &automonique_runner::NamespacedOutcome) -> Self {
        Self {
            ceiling_bytes: outcome.ledger.budget.bytes(),
            ceiling_objects: outcome.ledger.budget.objects(),
            peak_bytes: outcome.ledger.peak_bytes,
            peak_objects: outcome.ledger.peak_objects,
            refused_bytes: outcome.ledger.refused_bytes,
            refused_objects: outcome.ledger.refused_objects,
            statfs_used_bytes: Some(outcome.statfs_from_ledger.used_bytes()),
            readback_aborted: false,
            unmount_confirmed: outcome.unmount_confirmed,
        }
    }

    /// Whether the operator should see this at warning priority: a ceiling
    /// refused something, the server had to be aborted, or the mount table
    /// still showed the mount.
    const fn is_notable(&self) -> bool {
        self.refused_bytes > 0
            || self.refused_objects > 0
            || self.readback_aborted
            || !self.unmount_confirmed
    }
}

/// A run's temporary-storage mount was reconciled after the run: the final
/// ledger and readback are recorded against the run id, so the consumed
/// scratch budget and whether the ceiling refused anything are visible without
/// opening the run's checkpoint.
pub(crate) fn emit_temporary_storage_reconciled(
    run_id: &str,
    reconciliation: &TemporaryStorageReconciliation,
) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_temporary_storage_reconciled_to(Path::new(JOURNAL_SOCKET), run_id, reconciliation)
}

/// A new daemon generation recovered exact usage from a live private-mount
/// checkpoint left by a predecessor that did not write a final record.
pub(crate) fn emit_temporary_storage_checkpoint_recovered(
    run_id: &str,
    checkpoint: &automonique_runner::Checkpoint,
) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_temporary_storage_checkpoint_recovered_to(Path::new(JOURNAL_SOCKET), run_id, checkpoint)
}

fn emit_temporary_storage_checkpoint_recovered_to(
    socket_path: &Path,
    run_id: &str,
    checkpoint: &automonique_runner::Checkpoint,
) -> io::Result<()> {
    if !stable_identifier(run_id)
        || checkpoint.phase != automonique_runner::CheckpointPhase::Live
        || !checkpoint
            .mount_evidence
            .starts_with("automonique.namespaced-tempfs/v1 ")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private temporary-storage recovery",
        ));
    }
    automonique_runner::StatfsReadback::from_ledger(&checkpoint.snapshot)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let event = format!(
        "MESSAGE=Automonique recovered a live private temporary-storage checkpoint\n\
         MESSAGE_ID={TEMPFS_RECOVERED_MESSAGE_ID}\n\
         PRIORITY=4\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={TEMPFS_RECOVERED_EVENT}\n\
         AUTOMONIQUE_RUN_ID={run_id}\n\
         AUTOMONIQUE_TEMPFS_CHECKPOINT_SEQUENCE={}\n\
         AUTOMONIQUE_TEMPFS_CEILING_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_USED_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_USED_OBJECTS={}\n\
         AUTOMONIQUE_TEMPFS_PEAK_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_PEAK_OBJECTS={}\n\
         AUTOMONIQUE_TEMPFS_REFUSED_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_REFUSED_OBJECTS={}\n",
        checkpoint.sequence,
        checkpoint.snapshot.budget.bytes(),
        checkpoint.snapshot.used_bytes,
        checkpoint.snapshot.used_objects,
        checkpoint.snapshot.peak_bytes,
        checkpoint.snapshot.peak_objects,
        checkpoint.snapshot.refused_bytes,
        checkpoint.snapshot.refused_objects,
    );
    emit_to(socket_path, &event)
}

fn emit_temporary_storage_reconciled_to(
    socket_path: &Path,
    run_id: &str,
    reconciliation: &TemporaryStorageReconciliation,
) -> io::Result<()> {
    if !stable_identifier(run_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid run identifier",
        ));
    }
    let priority = if reconciliation.is_notable() { 4 } else { 6 };
    let statfs_used_bytes = reconciliation
        .statfs_used_bytes
        .map_or_else(|| "absent".to_owned(), |bytes| bytes.to_string());
    let event = format!(
        "MESSAGE=Automonique reconciled a run's temporary-storage mount\n\
         MESSAGE_ID={TEMPFS_RECONCILED_MESSAGE_ID}\n\
         PRIORITY={priority}\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={TEMPFS_RECONCILED_EVENT}\n\
         AUTOMONIQUE_RUN_ID={run_id}\n\
         AUTOMONIQUE_TEMPFS_CEILING_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_CEILING_OBJECTS={}\n\
         AUTOMONIQUE_TEMPFS_PEAK_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_PEAK_OBJECTS={}\n\
         AUTOMONIQUE_TEMPFS_REFUSED_BYTES={}\n\
         AUTOMONIQUE_TEMPFS_REFUSED_OBJECTS={}\n\
         AUTOMONIQUE_TEMPFS_STATFS_USED_BYTES={statfs_used_bytes}\n\
         AUTOMONIQUE_TEMPFS_READBACK_ABORTED={}\n\
         AUTOMONIQUE_TEMPFS_UNMOUNT_CONFIRMED={}\n",
        reconciliation.ceiling_bytes,
        reconciliation.ceiling_objects,
        reconciliation.peak_bytes,
        reconciliation.peak_objects,
        reconciliation.refused_bytes,
        reconciliation.refused_objects,
        reconciliation.readback_aborted,
        reconciliation.unmount_confirmed,
    );
    emit_to(socket_path, &event)
}

/// A run's temporary-storage mount could not be unmounted, or the unmount
/// could not be confirmed, at reconcile. The mount's `Drop` still detaches it
/// lazily; the category names what refused.
#[cfg(test)]
fn emit_temporary_storage_unreconciled_to(
    socket_path: &Path,
    run_id: &str,
    category: &str,
) -> io::Result<()> {
    if !stable_identifier(run_id) || !stable_vocabulary(category) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid reconcile observation",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique could not reconcile a run's temporary-storage mount\n\
         MESSAGE_ID={TEMPFS_UNRECONCILED_MESSAGE_ID}\n\
         PRIORITY=4\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={TEMPFS_UNRECONCILED_EVENT}\n\
         AUTOMONIQUE_RUN_ID={run_id}\n\
         AUTOMONIQUE_FAULT_CATEGORY={category}\n"
    );
    emit_to(socket_path, &event)
}

/// A stale temporary-storage mount left by a dead supervisor was found under
/// the runs directory when the execution lane opened, and detached. Whether
/// the detach cleared the mount table and whether the dead owner's last ledger
/// checkpoint was found beside it are both recorded.
pub(crate) fn emit_temporary_storage_reaped(
    run_id: &str,
    detached: bool,
    checkpoint_found: bool,
) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_temporary_storage_reaped_to(
        Path::new(JOURNAL_SOCKET),
        run_id,
        detached,
        checkpoint_found,
    )
}

fn emit_temporary_storage_reaped_to(
    socket_path: &Path,
    run_id: &str,
    detached: bool,
    checkpoint_found: bool,
) -> io::Result<()> {
    if !stable_identifier(run_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid run identifier",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique detached a stale temporary-storage mount\n\
         MESSAGE_ID={TEMPFS_REAPED_MESSAGE_ID}\n\
         PRIORITY=4\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={TEMPFS_REAPED_EVENT}\n\
         AUTOMONIQUE_RUN_ID={run_id}\n\
         AUTOMONIQUE_TEMPFS_DETACHED={detached}\n\
         AUTOMONIQUE_TEMPFS_CHECKPOINT_FOUND={checkpoint_found}\n"
    );
    emit_to(socket_path, &event)
}

/// A stable identifier spelling, as generation and run identifiers are:
/// ASCII alphanumerics, `_`, `-` and `.`, bounded. Anything else could carry a
/// newline into a second journal field.
fn stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A stable category or worker-group spelling: lowercase ASCII, digits and
/// underscores, bounded. Anything else could carry a newline into a second
/// journal field.
fn stable_vocabulary(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CATEGORY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) fn emit_readiness(generation_id: &str, lease_epoch: u64) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_readiness_to(Path::new(JOURNAL_SOCKET), generation_id, lease_epoch)
}

fn emit_readiness_to(socket_path: &Path, generation_id: &str, lease_epoch: u64) -> io::Result<()> {
    if generation_id.is_empty()
        || generation_id.len() > 128
        || !generation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid generation identifier",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique daemon readiness fields landed\n\
         MESSAGE_ID={READY_MESSAGE_ID}\n\
         PRIORITY=6\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={READY_EVENT}\n\
         AUTOMONIQUE_GENERATION_ID={generation_id}\n\
         AUTOMONIQUE_LEASE_EPOCH={lease_epoch}\n"
    );
    emit_to(socket_path, &event)
}

pub(crate) fn emit_shutdown_worker_drain(
    worker_group: &str,
    worker_ordinal: usize,
    phase: &str,
    elapsed_ms: u64,
    budget_ms: u64,
) -> io::Result<()> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Ok(());
    }
    emit_shutdown_worker_drain_to(
        Path::new(JOURNAL_SOCKET),
        worker_group,
        worker_ordinal,
        phase,
        elapsed_ms,
        budget_ms,
    )
}

fn emit_shutdown_worker_drain_to(
    socket_path: &Path,
    worker_group: &str,
    worker_ordinal: usize,
    phase: &str,
    elapsed_ms: u64,
    budget_ms: u64,
) -> io::Result<()> {
    if worker_group.is_empty()
        || worker_group.len() > 64
        || !worker_group
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || !matches!(phase, "started" | "completed" | "over_budget")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid shutdown worker observation",
        ));
    }
    let event = format!(
        "MESSAGE=Automonique shutdown worker drain observation\n\
         MESSAGE_ID={DRAIN_MESSAGE_ID}\n\
         PRIORITY=6\n\
         SYSLOG_IDENTIFIER=automonique\n\
         AUTOMONIQUE_SCHEMA={READY_SCHEMA}\n\
         AUTOMONIQUE_EVENT={DRAIN_EVENT}\n\
         AUTOMONIQUE_WORKER_GROUP={worker_group}\n\
         AUTOMONIQUE_WORKER_ORDINAL={worker_ordinal}\n\
         AUTOMONIQUE_DRAIN_PHASE={phase}\n\
         AUTOMONIQUE_DRAIN_ELAPSED_MS={elapsed_ms}\n\
         AUTOMONIQUE_DRAIN_BUDGET_MS={budget_ms}\n"
    );
    emit_to(socket_path, &event)
}

fn emit_to(socket_path: &Path, event: &str) -> io::Result<()> {
    if event.len() > MAX_EVENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "structured event is overlong",
        ));
    }
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_millis(250)))?;
    socket.connect(socket_path)?;
    let sent = socket.send(event.as_bytes())?;
    if sent != event.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "structured event was truncated",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_namespaced_checkpoint() -> automonique_runner::Checkpoint {
        use automonique_runner::{
            Checkpoint, CheckpointPhase, Ledger, STATFS_BLOCK_BYTES, StatfsReadback,
            TemporaryStorageBudget,
        };

        let mut ledger = Ledger::new(
            TemporaryStorageBudget::new(2 * STATFS_BLOCK_BYTES, 8).expect("valid budget"),
        );
        ledger.reserve_object().expect("object within budget");
        ledger.reserve_bytes(17).expect("bytes within budget");
        Checkpoint {
            sequence: 9,
            at_millis: 1_700_000_000_000,
            phase: CheckpointPhase::Live,
            snapshot: ledger.snapshot(),
            mount_evidence: "automonique.namespaced-tempfs/v1 pid=321 uid=1234".to_owned(),
            statfs_at_mount: StatfsReadback {
                block_size: STATFS_BLOCK_BYTES,
                fragment_size: STATFS_BLOCK_BYTES,
                blocks: 2,
                blocks_free: 2,
                blocks_available: 2,
                files: 8,
                files_free: 8,
                name_max: 255,
            },
            final_record: None,
        }
    }

    #[test]
    fn readiness_event_is_bounded_and_names_every_documented_field() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        emit_readiness_to(&path, "foreground", 42).expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");

        assert!(count <= MAX_EVENT_BYTES);
        for field in [
            "MESSAGE=Automonique daemon readiness fields landed",
            "MESSAGE_ID=e8b42f1b07f64ccfae8bb73f1dd7cf37",
            "SYSLOG_IDENTIFIER=automonique",
            "AUTOMONIQUE_SCHEMA=automonique.structured-log/v1",
            "AUTOMONIQUE_EVENT=daemon_ready",
            "AUTOMONIQUE_GENERATION_ID=foreground",
            "AUTOMONIQUE_LEASE_EPOCH=42",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
    }

    #[test]
    fn malformed_generation_cannot_add_a_journal_field() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert_eq!(
            emit_readiness_to(&directory.path().join("absent"), "bad\nFIELD=value", 1)
                .expect_err("generation must be refused")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn shutdown_worker_event_is_bounded_content_free_and_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        emit_shutdown_worker_drain_to(&path, "ticket_intake", 2, "completed", 15_025, 20_000)
            .expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");

        assert!(count <= MAX_EVENT_BYTES);
        for field in [
            "MESSAGE=Automonique shutdown worker drain observation",
            "MESSAGE_ID=c64c8c969f2d43bb8baef5569fb69f96",
            "AUTOMONIQUE_SCHEMA=automonique.structured-log/v1",
            "AUTOMONIQUE_EVENT=shutdown_worker_drain",
            "AUTOMONIQUE_WORKER_GROUP=ticket_intake",
            "AUTOMONIQUE_WORKER_ORDINAL=2",
            "AUTOMONIQUE_DRAIN_PHASE=completed",
            "AUTOMONIQUE_DRAIN_ELAPSED_MS=15025",
            "AUTOMONIQUE_DRAIN_BUDGET_MS=20000",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
        assert!(!event.contains("CONTENT="));
        assert!(!event.contains("TOKEN="));
    }

    #[test]
    fn worker_fault_event_is_bounded_content_free_and_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        emit_worker_fault_to(&path, "automation_scheduler", "stale_fence")
            .expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");

        assert!(count <= MAX_EVENT_BYTES);
        for field in [
            "MESSAGE=Automonique worker stopped on a fault",
            "MESSAGE_ID=5d3f0b7a9c1e4e0b8a6f2d9c4b1e7a35",
            "PRIORITY=4",
            "AUTOMONIQUE_SCHEMA=automonique.structured-log/v1",
            "AUTOMONIQUE_EVENT=worker_fault",
            "AUTOMONIQUE_WORKER_GROUP=automation_scheduler",
            "AUTOMONIQUE_FAULT_CATEGORY=stale_fence",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
        assert!(!event.contains("CONTENT="));
        assert!(!event.contains("TOKEN="));
    }

    #[test]
    fn worker_fault_fields_cannot_inject_journal_fields() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (group, category) in [
            ("automation_scheduler\nTOKEN=secret", "stale_fence"),
            ("automation-scheduler", "stale_fence"),
            ("automation_scheduler", "stale_fence\nTOKEN=secret"),
            ("automation_scheduler", ""),
            ("automation_scheduler", "Stale Fence"),
        ] {
            assert_eq!(
                emit_worker_fault_to(&directory.path().join("absent"), group, category)
                    .expect_err("invalid field must be refused")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn shutdown_worker_fields_cannot_inject_journal_fields() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (group, phase) in [
            ("ticket_intake\nTOKEN=secret", "completed"),
            ("ticket-intake", "completed"),
            ("ticket_intake", "completed\nTOKEN=secret"),
        ] {
            assert_eq!(
                emit_shutdown_worker_drain_to(
                    &directory.path().join("absent"),
                    group,
                    0,
                    phase,
                    1,
                    20_000,
                )
                .expect_err("invalid field must be refused")
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    fn reconciliation() -> TemporaryStorageReconciliation {
        TemporaryStorageReconciliation {
            ceiling_bytes: 32_768,
            ceiling_objects: 8,
            peak_bytes: 32_768,
            peak_objects: 1,
            refused_bytes: 1,
            refused_objects: 0,
            statfs_used_bytes: Some(32_768),
            readback_aborted: false,
            unmount_confirmed: true,
        }
    }

    #[test]
    fn temporary_storage_reconcile_event_is_bounded_numeric_and_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        emit_temporary_storage_reconciled_to(&path, "run-7_a.1", &reconciliation())
            .expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");

        assert!(count <= MAX_EVENT_BYTES);
        for field in [
            "MESSAGE=Automonique reconciled a run's temporary-storage mount",
            "MESSAGE_ID=db1313b593ad4bbe907a22f790c6b8f6",
            // A refusal was recorded, so the operator sees it as a warning.
            "PRIORITY=4",
            "AUTOMONIQUE_SCHEMA=automonique.structured-log/v1",
            "AUTOMONIQUE_EVENT=temporary_storage_reconciled",
            "AUTOMONIQUE_RUN_ID=run-7_a.1",
            "AUTOMONIQUE_TEMPFS_CEILING_BYTES=32768",
            "AUTOMONIQUE_TEMPFS_CEILING_OBJECTS=8",
            "AUTOMONIQUE_TEMPFS_PEAK_BYTES=32768",
            "AUTOMONIQUE_TEMPFS_PEAK_OBJECTS=1",
            "AUTOMONIQUE_TEMPFS_REFUSED_BYTES=1",
            "AUTOMONIQUE_TEMPFS_REFUSED_OBJECTS=0",
            "AUTOMONIQUE_TEMPFS_STATFS_USED_BYTES=32768",
            "AUTOMONIQUE_TEMPFS_READBACK_ABORTED=false",
            "AUTOMONIQUE_TEMPFS_UNMOUNT_CONFIRMED=true",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
        assert!(!event.contains("CONTENT="));
        assert!(!event.contains("TOKEN="));
    }

    #[test]
    fn recovered_private_checkpoint_event_is_bounded_numeric_and_exact() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        emit_temporary_storage_checkpoint_recovered_to(
            &path,
            "run-7_a.1",
            &live_namespaced_checkpoint(),
        )
        .expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");

        assert!(count <= MAX_EVENT_BYTES);
        for field in [
            "MESSAGE_ID=3a576f63c0964a31947c4d7b9cc57261",
            "PRIORITY=4",
            "AUTOMONIQUE_EVENT=temporary_storage_checkpoint_recovered",
            "AUTOMONIQUE_RUN_ID=run-7_a.1",
            "AUTOMONIQUE_TEMPFS_CHECKPOINT_SEQUENCE=9",
            "AUTOMONIQUE_TEMPFS_CEILING_BYTES=8192",
            "AUTOMONIQUE_TEMPFS_USED_BYTES=17",
            "AUTOMONIQUE_TEMPFS_USED_OBJECTS=1",
            "AUTOMONIQUE_TEMPFS_PEAK_BYTES=17",
            "AUTOMONIQUE_TEMPFS_PEAK_OBJECTS=1",
            "AUTOMONIQUE_TEMPFS_REFUSED_BYTES=0",
            "AUTOMONIQUE_TEMPFS_REFUSED_OBJECTS=0",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
        assert!(!event.contains("CONTENT="));
        assert!(!event.contains("TOKEN="));
    }

    #[test]
    fn recovered_checkpoint_refuses_non_live_or_non_namespaced_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let absent = directory.path().join("absent");
        let mut checkpoint = live_namespaced_checkpoint();
        checkpoint.phase = automonique_runner::CheckpointPhase::Final;
        assert_eq!(
            emit_temporary_storage_checkpoint_recovered_to(&absent, "run-7", &checkpoint)
                .expect_err("final checkpoint cannot be recovered as live")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        checkpoint.phase = automonique_runner::CheckpointPhase::Live;
        checkpoint.mount_evidence = "fstype=fuse.automonique-tempfs".to_owned();
        assert_eq!(
            emit_temporary_storage_checkpoint_recovered_to(&absent, "run-7", &checkpoint)
                .expect_err("legacy mount evidence cannot claim a private namespace")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_clean_reconcile_is_informational_and_an_absent_readback_is_spelled() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");

        let clean = TemporaryStorageReconciliation {
            refused_bytes: 0,
            statfs_used_bytes: None,
            ..reconciliation()
        };
        emit_temporary_storage_reconciled_to(&path, "run-8", &clean).expect("structured event");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");
        for field in ["PRIORITY=6", "AUTOMONIQUE_TEMPFS_STATFS_USED_BYTES=absent"] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }

        // An aborted readback is notable even with nothing refused.
        let aborted = TemporaryStorageReconciliation {
            refused_bytes: 0,
            readback_aborted: true,
            ..reconciliation()
        };
        emit_temporary_storage_reconciled_to(&path, "run-9", &aborted).expect("structured event");
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");
        assert!(event.lines().any(|line| line == "PRIORITY=4"));
    }

    #[test]
    fn temporary_storage_unreconciled_and_reaped_events_are_complete() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("journal receiver");
        let mut bytes = [0_u8; MAX_EVENT_BYTES + 1];

        emit_temporary_storage_unreconciled_to(&path, "run-10", "still_mounted")
            .expect("structured event");
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");
        for field in [
            "MESSAGE_ID=d6ed31785c3e441b934c73311da99a03",
            "PRIORITY=4",
            "AUTOMONIQUE_EVENT=temporary_storage_unreconciled",
            "AUTOMONIQUE_RUN_ID=run-10",
            "AUTOMONIQUE_FAULT_CATEGORY=still_mounted",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }

        emit_temporary_storage_reaped_to(&path, "run-11", true, false).expect("structured event");
        let count = receiver.recv(&mut bytes).expect("event datagram");
        let event = std::str::from_utf8(&bytes[..count]).expect("UTF-8 event");
        for field in [
            "MESSAGE_ID=37b70f59343543d4a52a9c6b2015c0f6",
            "PRIORITY=4",
            "AUTOMONIQUE_EVENT=temporary_storage_mount_reaped",
            "AUTOMONIQUE_RUN_ID=run-11",
            "AUTOMONIQUE_TEMPFS_DETACHED=true",
            "AUTOMONIQUE_TEMPFS_CHECKPOINT_FOUND=false",
        ] {
            assert!(event.lines().any(|line| line == field), "missing {field}");
        }
    }

    #[test]
    fn temporary_storage_run_ids_cannot_inject_journal_fields() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let absent = directory.path().join("absent");
        for run_id in ["run\nTOKEN=secret", "", "run id", "run/../id"] {
            assert_eq!(
                emit_temporary_storage_reconciled_to(&absent, run_id, &reconciliation())
                    .expect_err("invalid run id must be refused")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                emit_temporary_storage_unreconciled_to(&absent, run_id, "still_mounted")
                    .expect_err("invalid run id must be refused")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                emit_temporary_storage_reaped_to(&absent, run_id, true, true)
                    .expect_err("invalid run id must be refused")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            emit_temporary_storage_unreconciled_to(&absent, "run-12", "Still Mounted\nX=y")
                .expect_err("invalid category must be refused")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
