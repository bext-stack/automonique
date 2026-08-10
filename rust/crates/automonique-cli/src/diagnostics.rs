// SPDX-License-Identifier: Elastic-2.0

//! Bounded read-only host and local-control diagnostics.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const MAX_RUNTIME_PATH_BYTES: usize = 4_096;
const MAX_RUNTIME_COMPONENTS: usize = 256;

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

/// Report database health as unavailable until the authenticated admin RPC exists.
pub fn inspect_database_health(admin_socket: &DoctorCheck) -> DoctorCheck {
    if admin_socket.status() == CheckStatus::Healthy {
        unavailable_for(
            "control-plane.database-health",
            "database.health-rpc-unavailable",
            "Database health RPC is not available in this release",
        )
    } else {
        unavailable_for(
            "control-plane.database-health",
            "database.control-plane-unavailable",
            "Database health is unavailable without the control plane",
        )
    }
}

/// Report foreground generation identity as unavailable until the admin RPC exists.
pub fn inspect_foreground_generation(admin_socket: &DoctorCheck) -> DoctorCheck {
    if admin_socket.status() == CheckStatus::Healthy {
        unavailable_for(
            "runtime.foreground-generation",
            "foreground.identity-rpc-unavailable",
            "Foreground generation identity RPC is not available in this release",
        )
    } else {
        unavailable_for(
            "runtime.foreground-generation",
            "foreground.admin-endpoint-unavailable",
            "Foreground generation identity is unavailable without the admin endpoint",
        )
    }
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
