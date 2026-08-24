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
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
const MAX_EVENT_BYTES: usize = 1_024;

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
