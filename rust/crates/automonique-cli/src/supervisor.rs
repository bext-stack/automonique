// SPDX-License-Identifier: Elastic-2.0

//! Bounded supervisor declaration and effective-state diagnostics.
//!
//! Socket activation means Unix peer credentials identify the process that
//! created the listener, not the service that accepts it. This adapter maps the
//! exact active admin socket to its triggered service, reads that service's
//! effective properties, and checks its main process against the matching
//! kernel cgroup. All four views must agree before the line is healthy.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use nix::unistd::geteuid;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHECK_CODE: &str = "supervisor.adapter";
const MAX_CGROUP_BYTES: usize = 4_096;
const MAX_SOCKET_UNITS: usize = 64;
const MAX_SYSTEMCTL_OUTPUT_BYTES: usize = 16 * 1_024;
const MAX_UNIT_BYTES: usize = 256;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];
const MANAGER_PROPERTIES: [&str; 12] = [
    "ActiveState",
    "ControlGroup",
    "Delegate",
    "Id",
    "MainPID",
    "NotifyAccess",
    "Restart",
    "StatusText",
    "SubState",
    "Type",
    "WatchdogTimestampMonotonic",
    "WatchdogUSec",
];
const SOCKET_PROPERTIES: [&str; 5] = ["ActiveState", "Id", "Listen", "SubState", "Triggers"];

/// Inspect the supervisor instance reached through the active admin socket.
#[must_use]
pub fn inspect_supervisor_adapter(runtime: Option<&OsStr>) -> DoctorCheck {
    let unit = match locate_service(runtime) {
        Ok(unit) => unit,
        Err(SocketLocateError::Unavailable) => {
            return unavailable("supervisor.socket-readback-unavailable");
        }
        Err(SocketLocateError::Mismatch) => {
            return finding(
                "supervisor.socket-service-mismatch",
                "The active admin socket does not map to exactly one supervised service",
            );
        }
    };
    let manager = match query_manager(runtime, &unit) {
        Ok(manager) => manager,
        Err(()) => return unavailable("supervisor.manager-readback-unavailable"),
    };
    if manager.main_pid == 0 {
        return enforcement_mismatch();
    }
    let process_cgroup = match process_service_cgroup(manager.main_pid) {
        Ok(cgroup) => cgroup,
        Err(()) => return unavailable("supervisor.process-cgroup-unavailable"),
    };
    let kernel_delegated = kernel_delegation_matches(&process_cgroup, manager.main_pid);
    match assess(
        &manager,
        &unit,
        &process_cgroup,
        manager.main_pid,
        kernel_delegated,
    ) {
        SupervisorAssessment::Healthy => healthy(),
        SupervisorAssessment::DeclarationMismatch => finding(
            "supervisor.declaration-mismatch",
            "The active daemon unit does not declare the required supervision contract",
        ),
        SupervisorAssessment::EnforcementMismatch => enforcement_mismatch(),
    }
}

fn enforcement_mismatch() -> DoctorCheck {
    finding(
        "supervisor.enforcement-mismatch",
        "The active daemon process does not match the supervisor or kernel readback",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketLocateError {
    Unavailable,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SocketReadback {
    active_state: String,
    id: String,
    listen: String,
    sub_state: String,
    triggers: String,
}

fn locate_service(runtime: Option<&OsStr>) -> Result<String, SocketLocateError> {
    let runtime = runtime.ok_or(SocketLocateError::Unavailable)?;
    let admin_socket = Path::new(runtime).join("automonique/admin.sock");
    let admin_socket = admin_socket
        .to_str()
        .ok_or(SocketLocateError::Unavailable)?;
    let expected_listen = format!("{admin_socket} (Stream)");
    let units = active_socket_units(runtime).map_err(|()| SocketLocateError::Unavailable)?;
    let mut matched_service = None;
    for unit in units {
        let socket = query_socket(runtime, &unit).map_err(|()| SocketLocateError::Unavailable)?;
        if socket.id != unit
            || socket.active_state != "active"
            || socket.sub_state != "running"
            || socket.listen != expected_listen
        {
            continue;
        }
        let mut triggers = socket.triggers.split_ascii_whitespace();
        let service = triggers
            .next()
            .filter(|name| valid_unit_name(name, ".service"));
        if triggers.next().is_some() || service.is_none() || matched_service.is_some() {
            return Err(SocketLocateError::Mismatch);
        }
        matched_service = service.map(str::to_owned);
    }
    matched_service.ok_or(SocketLocateError::Mismatch)
}

fn active_socket_units(runtime: &OsStr) -> Result<Vec<String>, ()> {
    let output = systemctl_output(
        runtime,
        &[
            OsStr::new("--user"),
            OsStr::new("list-units"),
            OsStr::new("--type=socket"),
            OsStr::new("--state=active"),
            OsStr::new("--no-legend"),
            OsStr::new("--plain"),
            OsStr::new("--no-pager"),
        ],
    )?;
    parse_active_socket_units(&output)
}

fn parse_active_socket_units(output: &[u8]) -> Result<Vec<String>, ()> {
    let text = std::str::from_utf8(output).map_err(|_| ())?;
    let mut units = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let unit = line.split_ascii_whitespace().next().ok_or(())?;
        if !valid_unit_name(unit, ".socket")
            || units.iter().any(|known| known == unit)
            || units.len() >= MAX_SOCKET_UNITS
        {
            return Err(());
        }
        units.push(unit.to_owned());
    }
    Ok(units)
}

fn query_socket(runtime: &OsStr, unit: &str) -> Result<SocketReadback, ()> {
    if !valid_unit_name(unit, ".socket") {
        return Err(());
    }
    let mut arguments = vec![OsStr::new("--user"), OsStr::new("show")];
    for property in SOCKET_PROPERTIES {
        arguments.push(OsStr::new("--property"));
        arguments.push(OsStr::new(property));
    }
    arguments.push(OsStr::new("--"));
    arguments.push(OsStr::new(unit));
    parse_socket_readback(&systemctl_output(runtime, &arguments)?)
}

fn parse_socket_readback(output: &[u8]) -> Result<SocketReadback, ()> {
    let values = parse_properties(output, &SOCKET_PROPERTIES)?;
    let value = |key| values.get(key).copied().ok_or(());
    Ok(SocketReadback {
        active_state: value("ActiveState")?.to_owned(),
        id: value("Id")?.to_owned(),
        listen: value("Listen")?.to_owned(),
        sub_state: value("SubState")?.to_owned(),
        triggers: value("Triggers")?.to_owned(),
    })
}

fn process_service_cgroup(pid: u32) -> Result<String, ()> {
    let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
    let bytes = read_bounded(&path, MAX_CGROUP_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    let mut found = None;
    for line in text.lines() {
        let Some(cgroup) = line.strip_prefix("0::") else {
            continue;
        };
        if found.is_some() || !valid_control_group(cgroup) {
            return Err(());
        }
        found = Some(cgroup.to_owned());
    }
    found.ok_or(())
}

fn valid_unit_name(unit: &str, suffix: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAX_UNIT_BYTES
        && !unit.starts_with('-')
        && unit.ends_with(suffix)
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@' | b'\\')
        })
}

fn valid_control_group(control_group: &str) -> bool {
    if control_group.len() > MAX_CGROUP_BYTES || !control_group.starts_with('/') {
        return false;
    }
    let mut components = 0usize;
    for component in Path::new(control_group).components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return false;
        }
        components += 1;
        if components > 256 {
            return false;
        }
    }
    components > 1
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagerReadback {
    active_state: String,
    control_group: String,
    delegate: String,
    id: String,
    main_pid: u32,
    notify_access: String,
    restart: String,
    status_text: String,
    sub_state: String,
    service_type: String,
    watchdog_timestamp: u64,
    watchdog_usec: String,
}

fn query_manager(runtime: Option<&OsStr>, unit: &str) -> Result<ManagerReadback, ()> {
    let runtime = runtime.ok_or(())?;
    if !valid_unit_name(unit, ".service") {
        return Err(());
    }
    let mut arguments = vec![OsStr::new("--user"), OsStr::new("show")];
    for property in MANAGER_PROPERTIES {
        arguments.push(OsStr::new("--property"));
        arguments.push(OsStr::new(property));
    }
    arguments.push(OsStr::new("--"));
    arguments.push(OsStr::new(unit));
    parse_manager_readback(&systemctl_output(runtime, &arguments)?)
}

pub(crate) fn active_service_identity(runtime: Option<&OsStr>) -> Result<(String, u32), ()> {
    let unit = locate_service(runtime).map_err(|_| ())?;
    let manager = query_manager(runtime, &unit)?;
    if manager.active_state != "active" || manager.sub_state != "running" || manager.main_pid == 0 {
        return Err(());
    }
    Ok((unit, manager.main_pid))
}

fn systemctl_output(runtime: &OsStr, arguments: &[&OsStr]) -> Result<Vec<u8>, ()> {
    let mut child = Command::new(SYSTEMCTL)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let stdout = child.stdout.take().ok_or(())?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take((MAX_SYSTEMCTL_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut output)
            .map(|_| output)
            .map_err(|_| ())
    });
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(());
            }
        }
    };
    let output = reader.join().map_err(|_| ())??;
    if !status.success() || output.len() > MAX_SYSTEMCTL_OUTPUT_BYTES {
        return Err(());
    }
    Ok(output)
}

fn parse_manager_readback(output: &[u8]) -> Result<ManagerReadback, ()> {
    let values = parse_properties(output, &MANAGER_PROPERTIES)?;
    let value = |key| values.get(key).copied().ok_or(());
    Ok(ManagerReadback {
        active_state: value("ActiveState")?.to_owned(),
        control_group: value("ControlGroup")?.to_owned(),
        delegate: value("Delegate")?.to_owned(),
        id: value("Id")?.to_owned(),
        main_pid: value("MainPID")?.parse().map_err(|_| ())?,
        notify_access: value("NotifyAccess")?.to_owned(),
        restart: value("Restart")?.to_owned(),
        status_text: value("StatusText")?.to_owned(),
        sub_state: value("SubState")?.to_owned(),
        service_type: value("Type")?.to_owned(),
        watchdog_timestamp: value("WatchdogTimestampMonotonic")?
            .parse()
            .map_err(|_| ())?,
        watchdog_usec: value("WatchdogUSec")?.to_owned(),
    })
}

fn parse_properties<'a>(
    output: &'a [u8],
    properties: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, ()> {
    let text = std::str::from_utf8(output).map_err(|_| ())?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(())?;
        if !properties.contains(&key) || values.insert(key, value).is_some() {
            return Err(());
        }
    }
    if values.len() != properties.len() {
        return Err(());
    }
    Ok(values)
}

fn kernel_delegation_matches(control_group: &str, main_pid: u32) -> bool {
    if !valid_control_group(control_group) {
        return false;
    }
    let Some(relative) = control_group.strip_prefix('/') else {
        return false;
    };
    let directory = Path::new("/sys/fs/cgroup").join(relative);
    let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
        return false;
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o200 == 0
    {
        return false;
    }
    let controllers = match read_bounded(&directory.join("cgroup.controllers"), MAX_CGROUP_BYTES) {
        Ok(bytes) => bytes,
        Err(()) => return false,
    };
    let Ok(controllers) = std::str::from_utf8(&controllers) else {
        return false;
    };
    let controllers = controllers.split_ascii_whitespace().collect::<Vec<_>>();
    if !REQUIRED_CONTROLLERS
        .iter()
        .all(|required| controllers.contains(required))
    {
        return false;
    }
    let processes = match read_bounded(&directory.join("cgroup.procs"), MAX_CGROUP_BYTES) {
        Ok(bytes) => bytes,
        Err(()) => return false,
    };
    let Ok(processes) = std::str::from_utf8(&processes) else {
        return false;
    };
    if !processes
        .lines()
        .filter_map(|line| line.parse::<u32>().ok())
        .any(|pid| pid == main_pid)
    {
        return false;
    }
    let Ok(kill) = std::fs::symlink_metadata(directory.join("cgroup.kill")) else {
        return false;
    };
    kill.is_file()
        && !kill.file_type().is_symlink()
        && kill.uid() == geteuid().as_raw()
        && kill.mode() & 0o200 != 0
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ()> {
    let mut file = std::fs::File::open(path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > limit {
        return Err(());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisorAssessment {
    Healthy,
    DeclarationMismatch,
    EnforcementMismatch,
}

fn assess(
    manager: &ManagerReadback,
    unit: &str,
    process_cgroup: &str,
    main_pid: u32,
    kernel_delegated: bool,
) -> SupervisorAssessment {
    if manager.service_type != "notify-reload"
        || manager.notify_access != "main"
        || manager.delegate != "yes"
        || manager.restart != "on-failure"
        || manager.watchdog_usec == "0"
        || manager.watchdog_usec == "0us"
        || manager.watchdog_usec == "infinity"
    {
        return SupervisorAssessment::DeclarationMismatch;
    }
    if manager.id != unit
        || manager.active_state != "active"
        || manager.sub_state != "running"
        || manager.status_text != "Ready"
        || manager.main_pid != main_pid
        || manager.control_group != process_cgroup
        || manager.watchdog_timestamp == 0
        || !kernel_delegated
    {
        return SupervisorAssessment::EnforcementMismatch;
    }
    SupervisorAssessment::Healthy
}

fn healthy() -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(CHECK_CODE).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn unavailable(code: &str) -> DoctorCheck {
    non_healthy(
        CheckStatus::Unavailable,
        code,
        "Supervisor readback is unavailable for the active admin socket",
    )
}

fn finding(code: &str, message: &str) -> DoctorCheck {
    non_healthy(CheckStatus::Finding, code, message)
}

fn non_healthy(status: CheckStatus, code: &str, message: &str) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(CHECK_CODE).expect("constant check code is valid"),
        status,
        Some(DoctorReason::new(
            FindingCode::new(code).expect("constant reason code is valid"),
            FindingMessage::new(message).expect("constant reason message is valid"),
        )),
    )
    .expect("constant non-healthy check is coherent")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> ManagerReadback {
        ManagerReadback {
            active_state: "active".into(),
            control_group: "/app.slice/automonique.service".into(),
            delegate: "yes".into(),
            id: "automonique.service".into(),
            main_pid: 42,
            notify_access: "main".into(),
            restart: "on-failure".into(),
            status_text: "Ready".into(),
            sub_state: "running".into(),
            service_type: "notify-reload".into(),
            watchdog_timestamp: 7,
            watchdog_usec: "30s".into(),
        }
    }

    #[test]
    fn declaration_manager_process_and_kernel_must_all_agree() {
        let baseline = manager();
        assert_eq!(
            assess(
                &baseline,
                "automonique.service",
                "/app.slice/automonique.service",
                42,
                true
            ),
            SupervisorAssessment::Healthy
        );
        for mutate in [
            |value: &mut ManagerReadback| value.delegate = "no".into(),
            |value: &mut ManagerReadback| value.service_type = "notify".into(),
            |value: &mut ManagerReadback| value.watchdog_usec = "0".into(),
        ] {
            let mut value = baseline.clone();
            mutate(&mut value);
            assert_eq!(
                assess(
                    &value,
                    "automonique.service",
                    "/app.slice/automonique.service",
                    42,
                    true
                ),
                SupervisorAssessment::DeclarationMismatch
            );
        }
        assert_eq!(
            assess(
                &baseline,
                "automonique.service",
                "/app.slice/automonique.service",
                42,
                false
            ),
            SupervisorAssessment::EnforcementMismatch
        );
        assert_eq!(
            assess(
                &baseline,
                "automonique.service",
                "/app.slice/automonique.service",
                43,
                true
            ),
            SupervisorAssessment::EnforcementMismatch
        );
    }

    #[test]
    fn manager_output_is_closed_complete_and_typed() {
        let fixture = b"Type=notify-reload\nRestart=on-failure\nNotifyAccess=main\nWatchdogUSec=30s\nWatchdogTimestampMonotonic=7\nMainPID=42\nStatusText=Ready\nControlGroup=/app.slice/automonique.service\nDelegate=yes\nId=automonique.service\nActiveState=active\nSubState=running\n";
        assert_eq!(parse_manager_readback(fixture), Ok(manager()));
        assert!(parse_manager_readback(b"Id=automonique.service\n").is_err());
        let mut extended = fixture.to_vec();
        extended.extend_from_slice(b"Unknown=value\n");
        assert!(parse_manager_readback(&extended).is_err());
    }

    #[test]
    fn socket_output_is_closed_complete_and_typed() {
        let fixture = b"ActiveState=active\nId=automonique.socket\nListen=/run/user/1000/automonique/admin.sock (Stream)\nSubState=running\nTriggers=automonique.service\n";
        assert_eq!(
            parse_socket_readback(fixture),
            Ok(SocketReadback {
                active_state: "active".into(),
                id: "automonique.socket".into(),
                listen: "/run/user/1000/automonique/admin.sock (Stream)".into(),
                sub_state: "running".into(),
                triggers: "automonique.service".into(),
            })
        );
        assert!(parse_socket_readback(b"Id=automonique.socket\n").is_err());
    }

    #[test]
    fn active_socket_listing_yields_only_bounded_unit_arguments() {
        let fixture = b"dbus.socket loaded active running D-Bus User Message Bus Socket\nautomonique.socket loaded active running Automonique\n";
        assert_eq!(
            parse_active_socket_units(fixture),
            Ok(vec!["dbus.socket".into(), "automonique.socket".into()])
        );
        for refused in [
            b"--help.socket loaded active running x\n".as_slice(),
            b"name with space.socket loaded active running x\n".as_slice(),
            b"name.service loaded active running x\n".as_slice(),
            b"name.socket loaded active running x\nname.socket loaded active running x\n"
                .as_slice(),
        ] {
            assert!(parse_active_socket_units(refused).is_err());
        }
        assert!(valid_unit_name("automonique.service", ".service"));
        assert!(!valid_unit_name("--help.service", ".service"));
    }
}
