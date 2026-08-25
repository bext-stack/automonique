// SPDX-License-Identifier: Elastic-2.0

//! Bounded read-only host and local-control diagnostics.

use crate::admin_client::{self, Operation};
use automonique_protocol::admin::{AdminResponse, DaemonStatus, OperationalMetric};
use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const MAX_RUNTIME_PATH_BYTES: usize = 4_096;
const MAX_RUNTIME_COMPONENTS: usize = 256;

// Linux statfs magic values for filesystems whose locking and shared-memory
// semantics are supplied by a remote server. SQLite WAL explicitly requires
// every participant to share one host, so a healthy local mount check cannot
// be inferred merely because opening a database succeeded once.
const NETWORK_FILESYSTEM_TYPES: [u64; 8] = [
    0x0000_564c, // NCP
    0x0000_6969, // NFS
    0x0000_517b, // SMB
    0x0102_1997, // 9P
    0x00c3_6400, // Ceph
    0x5346_414f, // AFS
    0x7375_7245, // Coda
    0xff53_4d42, // CIFS
];

/// Check the admin socket's filesystem boundary without connecting to it.
pub fn inspect_admin_socket(runtime: Option<&OsStr>) -> DoctorCheck {
    let Some(runtime) = runtime else {
        return unavailable(
            "admin.runtime-unavailable",
            "Admin socket cannot be inspected without a runtime directory",
        );
    };
    let runtime = Path::new(runtime);
    if !valid_absolute_path(runtime) {
        return finding(
            "admin.runtime-invalid",
            "Admin socket runtime location is invalid",
        );
    }
    let socket = runtime.join("automonique/admin.sock");
    match inspect_socket_path(&socket) {
        SocketResult::Healthy => healthy("admin.socket-metadata"),
        SocketResult::Missing => unavailable(
            "admin.socket-missing",
            "Admin socket is not currently available",
        ),
        SocketResult::Symlink => finding(
            "admin.socket-symlink",
            "Admin socket path contains a symbolic link",
        ),
        SocketResult::WrongType => {
            finding("admin.socket-type", "Admin endpoint is not a Unix socket")
        }
        SocketResult::WrongOwner => {
            finding("admin.socket-owner", "Admin socket has the wrong owner")
        }
        SocketResult::WrongMode => finding(
            "admin.socket-mode",
            "Admin socket permissions are not private",
        ),
        SocketResult::Unavailable => unavailable(
            "admin.socket-metadata-unavailable",
            "Admin socket metadata is unavailable",
        ),
    }
}

/// Check the foreground process-control primitives used by this process.
pub fn inspect_process_control() -> DoctorCheck {
    #[cfg(target_os = "linux")]
    {
        let process = nix::unistd::getpid().as_raw();
        let group = nix::unistd::getpgrp().as_raw();
        if process > 0 && group > 0 {
            return healthy("host.process-control");
        }
        unavailable_for(
            "host.process-control",
            "host.process-control-unavailable",
            "Foreground process control is unavailable",
        )
    }
    #[cfg(not(target_os = "linux"))]
    unavailable_for(
        "host.process-control",
        "host.platform-unsupported",
        "Host process-control evidence is unavailable on this platform",
    )
}

/// Verify that the durable state path is not on a known network filesystem.
///
/// The product directory is preferred when it exists because it may itself be
/// a mount point. Before first start, checking its existing state-home parent
/// still gives a useful answer without creating anything. This diagnostic is
/// read-only and reports an unavailable observation rather than guessing when
/// the path cannot be inspected.
pub fn inspect_state_filesystem(state: Option<&OsStr>) -> DoctorCheck {
    let Some(state) = state else {
        return unavailable_for(
            "state.filesystem",
            "state.environment-missing",
            "State filesystem cannot be inspected without XDG_STATE_HOME",
        );
    };
    let state = Path::new(state);
    if !valid_absolute_path(state) {
        return non_healthy(
            "state.filesystem",
            CheckStatus::Finding,
            "state.path-invalid",
            "State filesystem location is invalid",
        );
    }
    let product = state.join("automonique");
    let target = if product.exists() {
        product.as_path()
    } else {
        state
    };
    match nix::sys::statfs::statfs(target) {
        Ok(stat) => state_filesystem_type(stat.filesystem_type().0 as u64),
        Err(_) => unavailable_for(
            "state.filesystem",
            "state.filesystem-unavailable",
            "State filesystem type could not be read",
        ),
    }
}

fn state_filesystem_type(filesystem_type: u64) -> DoctorCheck {
    if NETWORK_FILESYSTEM_TYPES.contains(&filesystem_type) {
        non_healthy(
            "state.filesystem",
            CheckStatus::Finding,
            "state.filesystem-network",
            "State is on a network filesystem that cannot safely host SQLite WAL",
        )
    } else {
        healthy("state.filesystem")
    }
}

/// Read database and generation health from one authenticated status snapshot.
///
/// The two checks deliberately share one request. Two status calls could
/// straddle a generation change and make the doctor combine facts that were
/// never true together. The local client also re-checks the socket owner and
/// mode before connecting, so a healthy metadata check is a prerequisite, not
/// a substitute for peer authentication.
pub fn inspect_control_plane(
    runtime: Option<&OsStr>,
    admin_socket: &DoctorCheck,
) -> [DoctorCheck; 2] {
    if admin_socket.status() != CheckStatus::Healthy {
        return control_plane_unavailable(
            "database.control-plane-unavailable",
            "Database health is unavailable without the control plane",
            "foreground.admin-endpoint-unavailable",
            "Foreground generation identity is unavailable without the admin endpoint",
        );
    }

    match admin_client::request(runtime, Operation::Status) {
        Ok(AdminResponse::Status { status, .. }) => status_checks(&status),
        Ok(_) => control_plane_unavailable(
            "database.status-response-mismatch",
            "Database health is unavailable because the admin endpoint returned the wrong response",
            "foreground.status-response-mismatch",
            "Foreground generation identity is unavailable because the admin endpoint returned the wrong response",
        ),
        Err(_) => control_plane_unavailable(
            "database.status-rpc-unavailable",
            "Database health is unavailable because the status RPC could not be completed",
            "foreground.status-rpc-unavailable",
            "Foreground generation identity is unavailable because the status RPC could not be completed",
        ),
    }
}

fn status_checks(status: &DaemonStatus) -> [DoctorCheck; 2] {
    let database = match (status.operational(), status.durable_state()) {
        (Some(_), Some(durable)) => {
            let complete = [
                durable.approvals_recorded(),
                durable.automations_registered(),
                durable.open_tenure_epoch(),
                durable.open_tenures(),
                durable.runs_registered(),
                durable.tenures_recorded(),
            ]
            .into_iter()
            .all(|metric| metric.value().is_some());
            let tenure_matches = matches!(
                (durable.open_tenures(), durable.open_tenure_epoch()),
                (
                    OperationalMetric::Measured(1),
                    OperationalMetric::Measured(epoch)
                ) if epoch == status.generation()
            );
            if complete && tenure_matches {
                healthy("control-plane.database-health")
            } else {
                non_healthy(
                    "control-plane.database-health",
                    CheckStatus::Finding,
                    "database.status-incomplete",
                    "One or more durable stores could not be read from the live status snapshot",
                )
            }
        }
        _ => unavailable_for(
            "control-plane.database-health",
            "database.status-projection-unavailable",
            "The live daemon did not provide the database status projection",
        ),
    };

    let generation = if status.generation() == 0 {
        non_healthy(
            "runtime.foreground-generation",
            CheckStatus::Finding,
            "foreground.generation-invalid",
            "The live daemon reported an invalid zero generation",
        )
    } else {
        healthy("runtime.foreground-generation")
    };
    [database, generation]
}

fn control_plane_unavailable(
    database_code: &str,
    database_message: &str,
    generation_code: &str,
    generation_message: &str,
) -> [DoctorCheck; 2] {
    [
        unavailable_for(
            "control-plane.database-health",
            database_code,
            database_message,
        ),
        unavailable_for(
            "runtime.foreground-generation",
            generation_code,
            generation_message,
        ),
    ]
}

fn valid_absolute_path(path: &Path) -> bool {
    #[cfg(unix)]
    if path.as_os_str().as_bytes().len() > MAX_RUNTIME_PATH_BYTES {
        return false;
    }
    if !path.is_absolute() || path == Path::new("/") {
        return false;
    }
    let mut count = 0usize;
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return false;
        }
        count += 1;
        if count > MAX_RUNTIME_COMPONENTS {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
enum SocketResult {
    Healthy,
    Missing,
    Symlink,
    WrongType,
    WrongOwner,
    WrongMode,
    Unavailable,
}

fn inspect_socket_path(socket: &Path) -> SocketResult {
    let mut current = PathBuf::new();
    for component in socket.components() {
        current.push(component.as_os_str());
        if component == Component::RootDir {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return SocketResult::Missing;
            }
            Err(_) => return SocketResult::Unavailable,
        };
        if metadata.file_type().is_symlink() {
            return SocketResult::Symlink;
        }
        if current != socket && !metadata.is_dir() {
            return SocketResult::WrongType;
        }
        if current == socket {
            #[cfg(unix)]
            {
                if !metadata.file_type().is_socket() {
                    return SocketResult::WrongType;
                }
                if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
                    return SocketResult::WrongOwner;
                }
                if metadata.mode() & 0o7777 != 0o600 {
                    return SocketResult::WrongMode;
                }
            }
        }
    }
    SocketResult::Healthy
}

fn healthy(code: &str) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(code).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn finding(code: &str, message: &str) -> DoctorCheck {
    non_healthy("admin.socket-metadata", CheckStatus::Finding, code, message)
}

fn unavailable(code: &str, message: &str) -> DoctorCheck {
    unavailable_for("admin.socket-metadata", code, message)
}

fn unavailable_for(check_code: &str, reason_code: &str, message: &str) -> DoctorCheck {
    non_healthy(check_code, CheckStatus::Unavailable, reason_code, message)
}

fn non_healthy(
    check_code: &str,
    status: CheckStatus,
    reason_code: &str,
    message: &str,
) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(check_code).expect("constant check code is valid"),
        status,
        Some(DoctorReason::new(
            FindingCode::new(reason_code).expect("constant reason code is valid"),
            FindingMessage::new(message).expect("constant reason message is valid"),
        )),
    )
    .expect("constant non-healthy check is coherent")
}

#[cfg(test)]
mod tests {
    use super::{inspect_state_filesystem, state_filesystem_type, status_checks};
    use automonique_protocol::CheckStatus;
    use automonique_protocol::admin::{
        AdminInstanceId, DaemonState, DaemonStatus, DurableStateCounts, DurableStateCountsParts,
        OperationalMetric, OperationalStatus, OperationalStatusParts,
    };

    fn status(runs: OperationalMetric) -> DaemonStatus {
        let operational = OperationalStatus::new(OperationalStatusParts {
            observed_ms: 1,
            reconciliation_pending: 0,
            outbox_pending_ready: 0,
            outbox_pending_delayed: 0,
            outbox_in_flight_live: 0,
            outbox_in_flight_ambiguous: 0,
            outbox_delivered: 0,
            outbox_dead_lettered: 0,
            outbox_oldest_ready_age_ms: 0,
            telegram_pollers_live: 0,
            telegram_pollers_expired: 0,
            telegram_offset_lag: OperationalMetric::Unavailable,
            provider_available: OperationalMetric::Unavailable,
            sandbox_launch_refusals: OperationalMetric::Unavailable,
        })
        .expect("operational status");
        let durable = DurableStateCounts::new(DurableStateCountsParts {
            approvals_recorded: OperationalMetric::Measured(2),
            automation_scheduler_workers: OperationalMetric::Measured(1),
            automations_registered: OperationalMetric::Measured(3),
            open_tenure_epoch: OperationalMetric::Measured(7),
            open_tenures: OperationalMetric::Measured(1),
            runs_registered: runs,
            tenures_recorded: OperationalMetric::Measured(4),
        })
        .expect("durable status");
        DaemonStatus::new(
            AdminInstanceId::new("doctor-fixture").expect("instance"),
            DaemonState::Ready,
            7,
            0,
            0,
            0,
            0,
            true,
        )
        .and_then(|status| status.with_operational(operational))
        .and_then(|status| status.with_durable_state(durable))
        .expect("complete status")
    }

    #[test]
    fn a_complete_live_snapshot_makes_both_control_plane_checks_healthy() {
        let [database, generation] = status_checks(&status(OperationalMetric::Measured(9)));
        assert_eq!(database.status(), CheckStatus::Healthy);
        assert_eq!(generation.status(), CheckStatus::Healthy);
    }

    #[test]
    fn an_unreadable_store_is_a_finding_without_erasing_generation_identity() {
        let [database, generation] = status_checks(&status(OperationalMetric::Unavailable));
        assert_eq!(database.status(), CheckStatus::Finding);
        assert_eq!(
            database.reason().expect("reason").code().as_str(),
            "database.status-incomplete"
        );
        assert_eq!(generation.status(), CheckStatus::Healthy);
    }

    #[test]
    fn every_known_network_filesystem_refuses_sqlite_wal_state() {
        for filesystem_type in super::NETWORK_FILESYSTEM_TYPES {
            let check = state_filesystem_type(filesystem_type);
            assert_eq!(check.status(), CheckStatus::Finding);
            assert_eq!(
                check
                    .reason()
                    .expect("network filesystem reason")
                    .code()
                    .as_str(),
                "state.filesystem-network"
            );
        }
    }

    #[test]
    fn a_local_filesystem_type_is_healthy() {
        // EXT4_SUPER_MAGIC. The classifier deliberately accepts local types it
        // does not otherwise need to name; only known remote semantics are a
        // finding.
        assert_eq!(
            state_filesystem_type(0x0000_ef53).status(),
            CheckStatus::Healthy
        );
    }

    #[test]
    fn the_state_filesystem_probe_is_read_only_and_truthful_about_missing_input() {
        let missing = inspect_state_filesystem(None);
        assert_eq!(missing.status(), CheckStatus::Unavailable);
        assert_eq!(
            missing
                .reason()
                .expect("missing state reason")
                .code()
                .as_str(),
            "state.environment-missing"
        );

        let directory = tempfile::tempdir().expect("temporary state directory");
        let observed = inspect_state_filesystem(Some(directory.path().as_os_str()));
        assert!(matches!(
            observed.status(),
            CheckStatus::Healthy | CheckStatus::Finding
        ));
        assert!(
            directory
                .path()
                .read_dir()
                .expect("read state directory")
                .next()
                .is_none()
        );
    }
}
