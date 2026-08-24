// SPDX-License-Identifier: Elastic-2.0

//! Read back the daemon readiness event from journald itself.

use crate::supervisor;
use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use serde_json::Value;
use std::ffi::OsStr;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHECK_CODE: &str = "journal.structured-fields";
const JOURNALCTL: &str = "/usr/bin/journalctl";
const MAX_OUTPUT_BYTES: usize = 64 * 1_024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const READY_MESSAGE_ID: &str = "e8b42f1b07f64ccfae8bb73f1dd7cf37";
const READY_SCHEMA: &str = "automonique.structured-log/v1";

/// Require one current-daemon readiness record with every documented field.
#[must_use]
pub fn inspect_structured_journal(runtime: Option<&OsStr>) -> DoctorCheck {
    let runtime = match runtime {
        Some(runtime) => runtime,
        None => return unavailable(),
    };
    let (unit, main_pid) = match supervisor::active_service_identity(Some(runtime)) {
        Ok(identity) => identity,
        Err(()) => return unavailable(),
    };
    let output = match query_journal(runtime, &unit, main_pid) {
        Ok(output) => output,
        Err(()) => return unavailable(),
    };
    match assess(&output, main_pid) {
        Ok(JournalAssessment::Healthy) => healthy(),
        Ok(JournalAssessment::Missing) => finding(
            "journal.readiness-event-missing",
            "The active daemon has no structured readiness event in journald",
        ),
        Ok(JournalAssessment::FieldsMismatch) => finding(
            "journal.fields-mismatch",
            "The active daemon readiness event is missing or changed structured fields",
        ),
        Err(()) => unavailable(),
    }
}

fn query_journal(runtime: &OsStr, unit: &str, main_pid: u32) -> Result<Vec<u8>, ()> {
    let message_match = format!("MESSAGE_ID={READY_MESSAGE_ID}");
    let pid_match = format!("_PID={main_pid}");
    let mut child = Command::new(JOURNALCTL)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime)
        .arg("--user")
        .arg("--boot")
        .arg("--unit")
        .arg(unit)
        .arg("--output=json")
        .arg("--no-pager")
        .arg("--quiet")
        .arg("--all")
        .arg("--reverse")
        .arg("--lines=16")
        .arg("--")
        .arg(message_match)
        .arg(pid_match)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let stdout = child.stdout.take().ok_or(())?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take((MAX_OUTPUT_BYTES + 1) as u64)
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
    if !status.success() || output.len() > MAX_OUTPUT_BYTES {
        return Err(());
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalAssessment {
    Healthy,
    Missing,
    FieldsMismatch,
}

fn assess(output: &[u8], main_pid: u32) -> Result<JournalAssessment, ()> {
    let text = std::str::from_utf8(output).map_err(|_| ())?;
    let lines = text
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Ok(JournalAssessment::Missing);
    }
    if lines.len() != 1 {
        return Ok(JournalAssessment::FieldsMismatch);
    }
    let entry: Value = serde_json::from_str(lines[0]).map_err(|_| ())?;
    let object = entry.as_object().ok_or(())?;
    let field = |name| object.get(name).and_then(Value::as_str);
    let lease_epoch = field("AUTOMONIQUE_LEASE_EPOCH")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let expected_pid = main_pid.to_string();
    if field("MESSAGE") != Some("Automonique daemon readiness fields landed")
        || field("MESSAGE_ID") != Some(READY_MESSAGE_ID)
        || field("SYSLOG_IDENTIFIER") != Some("automonique")
        || field("AUTOMONIQUE_SCHEMA") != Some(READY_SCHEMA)
        || field("AUTOMONIQUE_EVENT") != Some("daemon_ready")
        || field("AUTOMONIQUE_GENERATION_ID") != Some("foreground")
        || field("_PID") != Some(expected_pid.as_str())
        || lease_epoch.is_none()
    {
        return Ok(JournalAssessment::FieldsMismatch);
    }
    Ok(JournalAssessment::Healthy)
}

fn healthy() -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(CHECK_CODE).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn unavailable() -> DoctorCheck {
    non_healthy(
        CheckStatus::Unavailable,
        "journal.readback-unavailable",
        "Structured journal readback is unavailable for the active daemon",
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

    fn record(overrides: &[(&str, &str)]) -> Vec<u8> {
        let mut value = serde_json::json!({
            "MESSAGE": "Automonique daemon readiness fields landed",
            "MESSAGE_ID": READY_MESSAGE_ID,
            "SYSLOG_IDENTIFIER": "automonique",
            "AUTOMONIQUE_SCHEMA": READY_SCHEMA,
            "AUTOMONIQUE_EVENT": "daemon_ready",
            "AUTOMONIQUE_GENERATION_ID": "foreground",
            "AUTOMONIQUE_LEASE_EPOCH": "42",
            "_PID": "7",
        });
        for (field, replacement) in overrides {
            value[field] = Value::String((*replacement).to_owned());
        }
        serde_json::to_vec(&value).expect("fixture")
    }

    #[test]
    fn every_landed_field_and_current_pid_are_required() {
        assert_eq!(assess(&record(&[]), 7), Ok(JournalAssessment::Healthy));
        for field in [
            "MESSAGE",
            "MESSAGE_ID",
            "SYSLOG_IDENTIFIER",
            "AUTOMONIQUE_SCHEMA",
            "AUTOMONIQUE_EVENT",
            "AUTOMONIQUE_GENERATION_ID",
            "AUTOMONIQUE_LEASE_EPOCH",
            "_PID",
        ] {
            assert_eq!(
                assess(&record(&[(field, "changed")]), 7),
                Ok(JournalAssessment::FieldsMismatch),
                "{field}"
            );
        }
        let mut missing: Value = serde_json::from_slice(&record(&[])).expect("fixture");
        missing
            .as_object_mut()
            .expect("object")
            .remove("AUTOMONIQUE_EVENT");
        assert_eq!(
            assess(&serde_json::to_vec(&missing).expect("fixture"), 7),
            Ok(JournalAssessment::FieldsMismatch)
        );
    }

    #[test]
    fn absence_duplication_and_malformed_json_are_distinct() {
        assert_eq!(assess(b"", 7), Ok(JournalAssessment::Missing));
        let mut duplicate = record(&[]);
        duplicate.push(b'\n');
        duplicate.extend_from_slice(&record(&[]));
        assert_eq!(assess(&duplicate, 7), Ok(JournalAssessment::FieldsMismatch));
        assert_eq!(assess(b"not-json", 7), Err(()));
    }

    #[test]
    fn unavailable_result_is_typed_and_redacted() {
        let check = inspect_structured_journal(None);
        let reason = check.reason().expect("unavailable reason");
        assert_eq!(check.status(), CheckStatus::Unavailable);
        assert_eq!(reason.code().as_str(), "journal.readback-unavailable");
        assert_eq!(
            reason.message().as_str(),
            "Structured journal readback is unavailable for the active daemon"
        );
    }
}
