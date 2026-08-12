// SPDX-License-Identifier: Elastic-2.0

//! Closed, read-only product command dispatch.

use automonique_protocol::{
    CheckStatus, DoctorCheck, DoctorReason, DoctorReportError, DoctorReportV1, FindingCode,
    FindingMessage,
};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

mod admin_client;
mod diagnostics;
mod kernel;
mod release;
mod supervisor;

pub use diagnostics::{
    inspect_admin_socket, inspect_database_health, inspect_foreground_generation,
    inspect_process_control,
};
pub use kernel::{inspect_cgroup_v2_controllers, inspect_max_user_namespaces};
pub use release::{
    InspectedRelease, InspectedVersionRange, MAX_RELEASE_MANIFEST_BYTES, ReleaseInspection,
    ReleaseInspectionStatus, ReleaseIssue, inspect_release_manifest_structure,
};
pub use supervisor::inspect_supervisor_adapter;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const MAX_RUNTIME_PATH_BYTES: usize = 4_096;
const MAX_RUNTIME_COMPONENTS: usize = 256;
const USAGE: &str = "usage: automonique doctor [--json]\n       automonique status [--json]\n       automonique shutdown\n";

#[derive(Clone, Copy)]
enum Command {
    Doctor { json: bool },
    Status { json: bool },
    Shutdown,
}

/// Execute one closed product command. Arguments exclude the program name.
pub fn run<I, S, W, E>(arguments: I, mut stdout: W, mut stderr: E) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
    E: Write,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let command = arguments.next();
    let flag = arguments.next();
    let extra = arguments.next();
    let command = match (command.as_deref(), flag.as_deref(), extra) {
        (Some(command), None, None) if command == "doctor" => Command::Doctor { json: false },
        (Some(command), Some(flag), None) if command == "doctor" && flag == "--json" => {
            Command::Doctor { json: true }
        }
        (Some(command), None, None) if command == "status" => Command::Status { json: false },
        (Some(command), Some(flag), None) if command == "status" && flag == "--json" => {
            Command::Status { json: true }
        }
        (Some(command), None, None) if command == "shutdown" => Command::Shutdown,
        _ => {
            let _ = stderr.write_all(USAGE.as_bytes());
            return 2;
        }
    };

    let runtime = std::env::var_os("XDG_RUNTIME_DIR");
    if let Command::Status { json } = command {
        return admin_status(runtime.as_deref(), json, &mut stdout, &mut stderr);
    }
    if matches!(command, Command::Shutdown) {
        return admin_shutdown(runtime.as_deref(), &mut stdout, &mut stderr);
    }
    let Command::Doctor { json } = command else {
        unreachable!("status and shutdown returned above")
    };
    let report = match inspect_doctor(runtime.as_deref()) {
        Ok(report) => report,
        Err(_) => {
            let _ = stderr.write_all(b"automonique doctor could not construct its report\n");
            return 1;
        }
    };
    let rendered = if json {
        render_json(&report)
    } else {
        render_human(&report)
    };
    if stdout.write_all(rendered.as_bytes()).is_err() {
        return 1;
    }
    if report.status() == automonique_protocol::ReportStatus::Healthy {
        0
    } else {
        1
    }
}

fn admin_status<W: Write, E: Write>(
    runtime: Option<&OsStr>,
    json: bool,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let response = match admin_client::request(runtime, admin_client::Operation::Status) {
        Ok(response) => response,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "automonique status unavailable: {}",
                error.category()
            );
            return 1;
        }
    };
    let automonique_protocol::admin::AdminResponse::Status { status, .. } = response else {
        let _ = stderr.write_all(b"automonique status unavailable: response_mismatch\n");
        return 1;
    };
    let rendered = if json {
        serde_json::json!({
            "accepting_intake": status.accepting_intake(),
            "event_cursor": status.event_cursor(),
            "generation": status.generation(),
            "inbox_pending": status.inbox_pending(),
            "instance_id": status.instance_id().as_str(),
            "outbox_pending": status.outbox_pending(),
            "running": status.running(),
            "state": status.state().as_str(),
        })
        .to_string()
            + "\n"
    } else {
        format!(
            "Automonique daemon: {}\ninstance: {}\ngeneration: {}\nevent cursor: {}\ninbox pending: {}\noutbox pending: {}\nrunning: {}\naccepting intake: {}\n",
            status.state().as_str(),
            status.instance_id().as_str(),
            status.generation(),
            status.event_cursor(),
            status.inbox_pending(),
            status.outbox_pending(),
            status.running(),
            status.accepting_intake(),
        )
    };
    if stdout.write_all(rendered.as_bytes()).is_err() {
        return 1;
    }
    0
}

fn admin_shutdown<W: Write, E: Write>(
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    match admin_client::request(runtime, admin_client::Operation::Shutdown) {
        Ok(automonique_protocol::admin::AdminResponse::ShutdownAccepted { .. }) => {
            if stdout
                .write_all(b"Automonique daemon shutdown accepted\n")
                .is_ok()
            {
                0
            } else {
                1
            }
        }
        Ok(_) => {
            let _ = stderr.write_all(b"automonique shutdown refused: response_mismatch\n");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique shutdown refused: {}", error.category());
            1
        }
    }
}

fn inspect_doctor(runtime: Option<&OsStr>) -> Result<DoctorReportV1, DoctorReportError> {
    let admin_socket = inspect_admin_socket(runtime);
    DoctorReportV1::new([
        runtime_check(runtime),
        admin_socket.clone(),
        inspect_process_control(),
        inspect_database_health(&admin_socket),
        inspect_foreground_generation(&admin_socket),
        inspect_cgroup_v2_controllers(Path::new("/sys/fs/cgroup/cgroup.controllers")),
        inspect_max_user_namespaces(Path::new("/proc/sys/user/max_user_namespaces")),
        inspect_local_release(),
        inspect_supervisor_adapter(),
    ])
}

fn inspect_local_release() -> DoctorCheck {
    let Some(path) = std::env::current_exe().ok().and_then(|executable| {
        executable
            .parent()?
            .parent()
            .map(|root| root.join("manifest.json"))
    }) else {
        return typed_check(
            "release.manifest-structure",
            CheckStatus::Unavailable,
            "release.location-unavailable",
            "Release manifest location is unavailable",
        );
    };
    match inspect_release_manifest_structure(&path) {
        ReleaseInspection::Structured(_) => DoctorCheck::new(
            FindingCode::new("release.manifest-structure").expect("constant check code is valid"),
            CheckStatus::Healthy,
            None,
        )
        .expect("constant healthy check is coherent"),
        ReleaseInspection::Finding(issue) => typed_check(
            "release.manifest-structure",
            CheckStatus::Finding,
            issue.code(),
            issue.message(),
        ),
        ReleaseInspection::Unavailable(issue) => typed_check(
            "release.manifest-structure",
            CheckStatus::Unavailable,
            issue.code(),
            issue.message(),
        ),
    }
}

fn typed_check(
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

/// Inspect only `$XDG_RUNTIME_DIR/automonique` without following links or mutating it.
pub fn inspect_runtime(runtime: Option<&OsStr>) -> Result<DoctorReportV1, DoctorReportError> {
    let check = runtime_check(runtime);
    DoctorReportV1::new([check])
}

fn runtime_check(runtime: Option<&OsStr>) -> DoctorCheck {
    let Some(runtime) = runtime else {
        return unavailable(
            "runtime.environment-missing",
            "XDG runtime directory is unavailable",
        );
    };
    let path = Path::new(runtime);
    if !valid_runtime_path(path) {
        return finding(
            "runtime.environment-invalid",
            "XDG runtime directory is invalid",
        );
    }
    let product = path.join("automonique");
    match inspect_path(path, &product) {
        PathResult::Healthy => healthy(),
        PathResult::Missing => unavailable(
            "runtime.directory-missing",
            "Automonique runtime directory is unavailable",
        ),
        PathResult::Symlink => finding(
            "runtime.symlink-forbidden",
            "Runtime directory path contains a symbolic link",
        ),
        PathResult::WrongType => finding(
            "runtime.directory-type",
            "Automonique runtime path is not a directory",
        ),
        PathResult::WrongOwner => finding(
            "runtime.directory-owner",
            "Automonique runtime directory has the wrong owner",
        ),
        PathResult::WrongMode => finding(
            "runtime.directory-mode",
            "Automonique runtime directory is not private",
        ),
        PathResult::Unavailable => unavailable(
            "runtime.metadata-unavailable",
            "Runtime directory metadata is unavailable",
        ),
    }
}

fn valid_runtime_path(path: &Path) -> bool {
    #[cfg(unix)]
    if path.as_os_str().as_bytes().len() > MAX_RUNTIME_PATH_BYTES {
        return false;
    }
    if !path.is_absolute() || path == Path::new("/") {
        return false;
    }
    let mut count = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return false,
        }
        count += 1;
        if count > MAX_RUNTIME_COMPONENTS {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
enum PathResult {
    Healthy,
    Missing,
    Symlink,
    WrongType,
    WrongOwner,
    WrongMode,
    Unavailable,
}

fn inspect_path(runtime: &Path, product: &Path) -> PathResult {
    let mut current = PathBuf::new();
    for component in product.components() {
        current.push(component.as_os_str());
        if component == Component::RootDir {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return PathResult::Missing;
            }
            Err(_) => return PathResult::Unavailable,
        };
        if metadata.file_type().is_symlink() {
            return PathResult::Symlink;
        }
        if current != runtime && current != product && !metadata.is_dir() {
            return PathResult::WrongType;
        }
        if current == runtime || current == product {
            if !metadata.is_dir() {
                return PathResult::WrongType;
            }
            #[cfg(unix)]
            {
                if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
                    return PathResult::WrongOwner;
                }
                if metadata.mode() & 0o7777 != 0o700 {
                    return PathResult::WrongMode;
                }
            }
        }
    }
    PathResult::Healthy
}

fn healthy() -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new("runtime.directory").expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn finding(code: &str, message: &str) -> DoctorCheck {
    non_healthy(CheckStatus::Finding, code, message)
}

fn unavailable(code: &str, message: &str) -> DoctorCheck {
    non_healthy(CheckStatus::Unavailable, code, message)
}

fn non_healthy(status: CheckStatus, code: &str, message: &str) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new("runtime.directory").expect("constant check code is valid"),
        status,
        Some(DoctorReason::new(
            FindingCode::new(code).expect("constant reason code is valid"),
            FindingMessage::new(message).expect("constant reason message is valid"),
        )),
    )
    .expect("constant non-healthy check is coherent")
}

fn render_json(report: &DoctorReportV1) -> String {
    let checks = report
        .checks()
        .iter()
        .map(|check| {
            let reason = check.reason().map(|reason| {
                serde_json::json!({
                    "code": reason.code().as_str(),
                    "message": reason.message().as_str(),
                })
            });
            serde_json::json!({
                "id": check.code().as_str(),
                "status": check.status().as_str(),
                "reason": reason,
            })
        })
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "schema": report.schema(),
        "status": report.status().as_str(),
        "checks": checks,
    });
    format!("{document}\n")
}

fn render_human(report: &DoctorReportV1) -> String {
    let mut output = format!("Automonique doctor: {}\n", report.status().as_str());
    for check in report.checks() {
        output.push_str("- ");
        output.push_str(check.code().as_str());
        output.push_str(": ");
        output.push_str(check.status().as_str());
        if let Some(reason) = check.reason() {
            output.push_str(" (");
            output.push_str(reason.code().as_str());
            output.push_str(": ");
            output.push_str(reason.message().as_str());
            output.push(')');
        }
        output.push('\n');
    }
    output
}
