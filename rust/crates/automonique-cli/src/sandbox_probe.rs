// SPDX-License-Identifier: Elastic-2.0

//! Disposable effective-enforcement probe for `automonique doctor`.
//!
//! Capability discovery cannot prove that a restriction actually landed on a
//! workload. The parent therefore executes the current product binary under a
//! private command. That child installs the runner's real Landlock and seccomp
//! policies, reads its own kernel status after installation, exercises one
//! denied path and one denied socket syscall, emits one bounded fixed frame,
//! and exits. Every restriction is irreversible, so none is ever installed in
//! the long-lived doctor process.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use automonique_runner::filesystem::{FilesystemPolicy, PathIntent};
use automonique_runner::seccomp::SocketFamilyPolicy;
use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHECK_CODE: &str = "sandbox.enforced";
const PROBE_COMMAND: &str = "__doctor-sandbox-probe";
const FRAME_HEADER: &str = "AUTOMONIQUE_SANDBOX_PROBE_V1";
const FRAME_TERMINATOR: &str = "END";
const MAX_PROBE_OUTPUT_BYTES: usize = 4_096;
const MAX_STATUS_BYTES: u64 = 64 * 1_024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Execute one disposable child and require effective kernel denials.
#[must_use]
pub fn inspect_sandbox_enforcement() -> DoctorCheck {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return unavailable("sandbox.probe-executable-unavailable"),
    };
    let mut child = match Command::new(executable)
        .arg(PROBE_COMMAND)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return unavailable("sandbox.probe-spawn-unavailable"),
    };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return unavailable("sandbox.probe-timeout");
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return unavailable("sandbox.probe-wait-unavailable");
            }
        }
    };
    let mut output = Vec::new();
    let Some(mut stdout) = child.stdout.take() else {
        return unavailable("sandbox.probe-output-unavailable");
    };
    if stdout
        .by_ref()
        .take((MAX_PROBE_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .is_err()
        || output.len() > MAX_PROBE_OUTPUT_BYTES
    {
        return unavailable("sandbox.probe-output-unavailable");
    }
    if !status.success() {
        return finding(
            "sandbox.probe-refused",
            "The disposable sandbox child could not install every required restriction",
        );
    }
    if probe_frame_is_enforced(&output) {
        healthy()
    } else {
        finding(
            "sandbox.enforcement-mismatch",
            "The disposable sandbox child did not observe every required restriction",
        )
    }
}

/// Install irreversible restrictions in the private probe process and report.
///
/// This is public only so the top-level product binary can dispatch the hidden
/// child command before entering the ordinary CLI parser.
pub fn sandbox_probe_child<W: Write>(mut output: W) -> u8 {
    if run_probe_child(&mut output).is_ok() {
        0
    } else {
        let _ = writeln!(
            output,
            "{FRAME_HEADER}\nrefused=enforcement\n{FRAME_TERMINATOR}"
        );
        3
    }
}

fn run_probe_child<W: Write>(output: &mut W) -> Result<(), ()> {
    let filesystem = FilesystemPolicy::deny_all()
        .grant(PathIntent::Read, "/proc")
        .map_err(|_| ())?;
    let isolation = filesystem.enforce_on_current_thread().map_err(|_| ())?;
    SocketFamilyPolicy::deny_all()
        .apply_to_current_thread()
        .map_err(|_| ())?;

    let mut status = Vec::new();
    std::fs::File::open("/proc/self/status")
        .map_err(|_| ())?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut status)
        .map_err(|_| ())?;
    if status.len() > MAX_STATUS_BYTES as usize {
        return Err(());
    }
    let status = std::str::from_utf8(&status).map_err(|_| ())?;
    let no_new_privs = status_value(status, "NoNewPrivs:").ok_or(())?;
    let seccomp = status_value(status, "Seccomp:").ok_or(())?;
    let seccomp_filters = status_value(status, "Seccomp_filters:")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 1)
        .ok_or(())?;
    if no_new_privs != "1" || seccomp != "2" {
        return Err(());
    }

    let denied_path = matches!(
        std::fs::read("/etc/hostname"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    );
    let denied_socket = matches!(
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        ),
        Err(Errno::EPERM)
    );
    if !denied_path || !denied_socket {
        return Err(());
    }

    writeln!(output, "{FRAME_HEADER}").map_err(|_| ())?;
    writeln!(output, "landlock=full").map_err(|_| ())?;
    writeln!(output, "landlock_abi={}", isolation.kernel_abi()).map_err(|_| ())?;
    writeln!(output, "no_new_privs={no_new_privs}").map_err(|_| ())?;
    writeln!(output, "seccomp={seccomp}").map_err(|_| ())?;
    writeln!(output, "seccomp_filters={seccomp_filters}").map_err(|_| ())?;
    writeln!(output, "denied_path=permission_denied").map_err(|_| ())?;
    writeln!(output, "denied_socket=eperm").map_err(|_| ())?;
    writeln!(output, "{FRAME_TERMINATOR}").map_err(|_| ())?;
    Ok(())
}

fn status_value<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn probe_frame_is_enforced(output: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(output) else {
        return false;
    };
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 9
        || lines[0] != FRAME_HEADER
        || lines[1] != "landlock=full"
        || lines[3] != "no_new_privs=1"
        || lines[4] != "seccomp=2"
        || lines[6] != "denied_path=permission_denied"
        || lines[7] != "denied_socket=eperm"
        || lines[8] != FRAME_TERMINATOR
    {
        return false;
    }
    let landlock_abi = lines[2]
        .strip_prefix("landlock_abi=")
        .and_then(|value| value.parse::<u8>().ok());
    let filters = lines[5]
        .strip_prefix("seccomp_filters=")
        .and_then(|value| value.parse::<u32>().ok());
    matches!(landlock_abi, Some(abi) if abi >= 3) && matches!(filters, Some(count) if count >= 1)
}

fn healthy() -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(CHECK_CODE).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn finding(code: &str, message: &str) -> DoctorCheck {
    non_healthy(CheckStatus::Finding, code, message)
}

fn unavailable(code: &str) -> DoctorCheck {
    non_healthy(
        CheckStatus::Unavailable,
        code,
        "The disposable sandbox enforcement probe is unavailable",
    )
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

    #[test]
    fn only_a_complete_effective_enforcement_frame_is_healthy() {
        let complete = b"AUTOMONIQUE_SANDBOX_PROBE_V1\nlandlock=full\nlandlock_abi=4\nno_new_privs=1\nseccomp=2\nseccomp_filters=2\ndenied_path=permission_denied\ndenied_socket=eperm\nEND\n";
        assert!(probe_frame_is_enforced(complete));

        for replacement in [
            "no_new_privs=0",
            "seccomp=0",
            "seccomp_filters=0",
            "denied_path=allowed",
            "denied_socket=allowed",
        ] {
            let damaged = std::str::from_utf8(complete)
                .expect("fixture is UTF-8")
                .lines()
                .map(|line| {
                    if line.starts_with(replacement.split('=').next().expect("field")) {
                        replacement
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!probe_frame_is_enforced(damaged.as_bytes()));
        }
    }

    #[test]
    fn malformed_or_extended_frames_are_refused() {
        assert!(!probe_frame_is_enforced(b"not a frame"));
        assert!(!probe_frame_is_enforced(
            b"AUTOMONIQUE_SANDBOX_PROBE_V1\nlandlock=full\nlandlock_abi=4\nno_new_privs=1\nseccomp=2\nseccomp_filters=1\ndenied_path=permission_denied\ndenied_socket=eperm\nextra=value\nEND\n"
        ));
    }
}
