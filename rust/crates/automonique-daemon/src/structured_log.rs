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
}
