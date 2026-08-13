// SPDX-License-Identifier: Elastic-2.0

//! Closed product command dispatch and bounded local synthetic intake.

use automonique_protocol::{
    CheckStatus, DoctorCheck, DoctorReason, DoctorReportError, DoctorReportV1, FindingCode,
    FindingMessage,
};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

mod admin_client;
mod approval;
mod attempt;
mod automation;
mod batch;
mod diagnostics;
mod kernel;
mod release;
mod run_submit;
mod runs;
mod supervisor;

pub use diagnostics::{
    inspect_admin_socket, inspect_database_health, inspect_foreground_generation,
    inspect_process_control,
};
pub use kernel::{
    inspect_cgroup_v2_controllers, inspect_cgroup_v2_delegation, inspect_landlock_support,
    inspect_max_user_namespaces,
};
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
const USAGE: &str = "usage: automonique doctor [--json]\n       automonique status [--json]\n       automonique submit <scope> <idempotency-key> < task.txt\n       automonique reconcile inspect <run-id>\n       automonique reconcile fail <run-id> <generation-id> <epoch> <revision> <decision-key>\n       automonique outbox inspect <outbox-id>\n       automonique outbox reconcile <delivered|dead-letter> <outbox-id> <generation-id> <epoch> <attempt> <revision> < receipt-or-reason.txt\n       automonique run submit <idempotency-key> < run-spec.bin\n       automonique runs list [--state <state>]... [--cursor <submission-id>] [--page <size>]\n       automonique runs detail <run-id>\n       automonique automation register <automation-id> <actor>\n       automonique automation pause <automation-id> <revision> <actor> <cause>\n       automonique automation resume <automation-id> <revision> <actor>\n       automonique automation archive <automation-id> <revision> <actor> <cause>\n       automonique automation list [--state <state>]... [--cursor <entry-id>] [--page <size>]\n       automonique automation detail <automation-id>\n       automonique approval record <approval-key> <subject> <granted|denied> <decider>\n       automonique approval list [--cursor <entry-id>] [--page <size>]\n       automonique approval detail <approval-key>\n       automonique approval by-subject <subject> [--cursor <entry-id>] [--page <size>]\n       automonique batch register <batch-id> [--label <label>] [--sequential | --parallel <ceiling>] <member-key>...\n       automonique batch advance <batch-id> <member-key> <revision> <state> <last-sequence>\n       automonique batch list [--cursor <entry-id>] [--page <size>]\n       automonique batch detail <batch-id>\n       automonique attempt heartbeat <socket-path>\n       automonique attempt inspect <socket-path> <attempt-id>\n       automonique attempt events <socket-path> <attempt-id> [cursor]\n       automonique attempt cancel <socket-path> <attempt-id> <request-ref>\n       automonique shutdown\n";

#[derive(Clone)]
enum Command {
    Doctor {
        json: bool,
    },
    Status {
        json: bool,
    },
    Submit {
        scope: OsString,
        idempotency_key: OsString,
    },
    ReconcileInspect {
        run_id: OsString,
    },
    ReconcileFail {
        run_id: OsString,
        generation_id: OsString,
        epoch: OsString,
        revision: OsString,
        decision_key: OsString,
    },
    OutboxInspect {
        outbox_id: OsString,
    },
    OutboxReconcile {
        decision: OsString,
        outbox_id: OsString,
        generation_id: OsString,
        epoch: OsString,
        attempt: OsString,
        revision: OsString,
    },
    RunSubmit {
        idempotency_key: OsString,
    },
    Shutdown,
    Attempt(attempt::Operation),
    Runs(runs::Operation),
    Automation(automation::Operation),
    Approval(approval::Operation),
    Batch(batch::Operation),
}

/// Execute one closed product command. Arguments exclude the program name.
pub fn run<I, S, W, E>(arguments: I, mut stdout: W, mut stderr: E) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    W: Write,
    E: Write,
{
    run_with_input(arguments, std::io::stdin().lock(), &mut stdout, &mut stderr)
}

/// Execute one closed product command with an explicit input stream.
///
/// `submit`, `outbox reconcile`, and `run submit` consume input. Keeping task
/// content, receipts, and documents out of argv prevents them from appearing
/// in process listings and makes each protocol size limit enforceable before
/// any request is sent.
pub fn run_with_input<I, S, R, W, E>(arguments: I, mut input: R, mut stdout: W, mut stderr: E) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    R: Read,
    W: Write,
    E: Write,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let command = arguments.next();
    let first = arguments.next();
    let second = arguments.next();
    let third = arguments.next();
    let command = match (command.as_deref(), first, second, third) {
        (Some(command), None, None, None) if command == "doctor" => Command::Doctor { json: false },
        (Some(command), Some(flag), None, None) if command == "doctor" && flag == "--json" => {
            Command::Doctor { json: true }
        }
        (Some(command), None, None, None) if command == "status" => Command::Status { json: false },
        (Some(command), Some(flag), None, None) if command == "status" && flag == "--json" => {
            Command::Status { json: true }
        }
        (Some(command), Some(scope), Some(idempotency_key), None) if command == "submit" => {
            Command::Submit {
                scope,
                idempotency_key,
            }
        }
        (Some(command), Some(action), Some(run_id), None)
            if command == "reconcile" && action == "inspect" =>
        {
            Command::ReconcileInspect { run_id }
        }
        (Some(command), Some(action), Some(run_id), Some(generation_id))
            if command == "reconcile" && action == "fail" =>
        {
            let epoch = arguments.next();
            let revision = arguments.next();
            let decision_key = arguments.next();
            let extra = arguments.next();
            match (epoch, revision, decision_key, extra) {
                (Some(epoch), Some(revision), Some(decision_key), None) => Command::ReconcileFail {
                    run_id,
                    generation_id,
                    epoch,
                    revision,
                    decision_key,
                },
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        (Some(command), Some(action), Some(outbox_id), None)
            if command == "outbox" && action == "inspect" =>
        {
            Command::OutboxInspect { outbox_id }
        }
        (Some(command), Some(action), Some(decision), Some(outbox_id))
            if command == "outbox" && action == "reconcile" =>
        {
            let generation_id = arguments.next();
            let epoch = arguments.next();
            let attempt = arguments.next();
            let revision = arguments.next();
            let extra = arguments.next();
            match (generation_id, epoch, attempt, revision, extra) {
                (Some(generation_id), Some(epoch), Some(attempt), Some(revision), None) => {
                    Command::OutboxReconcile {
                        decision,
                        outbox_id,
                        generation_id,
                        epoch,
                        attempt,
                        revision,
                    }
                }
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        (Some(command), Some(action), Some(idempotency_key), None)
            if command == "run" && action == "submit" =>
        {
            Command::RunSubmit { idempotency_key }
        }
        // `runs` is variadic where the rest of this CLI is positional: a state
        // filter repeats and the two paging flags are optional. The remaining
        // argument words are collected here and judged by the verb itself, so
        // an unknown flag is refused by name rather than silently dropped by a
        // positional match that happened to bind.
        (Some(command), Some(action), second, third) if command == "runs" => {
            let flags: Vec<OsString> = second
                .into_iter()
                .chain(third)
                .chain(arguments.by_ref())
                .collect();
            match (action.to_str(), flags.as_slice()) {
                (Some("list"), _) => Command::Runs(runs::Operation::List { flags }),
                (Some("detail"), [run_id]) => Command::Runs(runs::Operation::Detail {
                    run_id: run_id.clone(),
                }),
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        // `automation` is variadic for the same reason `runs` is: `list`
        // takes repeating flags while the lifecycle verbs are positional with
        // three different arities. The remaining words are collected here and
        // matched by the verb they belong to, so a wrong arity is a usage
        // refusal rather than a positional match that happened to bind.
        (Some(command), Some(action), second, third) if command == "automation" => {
            let words: Vec<OsString> = second
                .into_iter()
                .chain(third)
                .chain(arguments.by_ref())
                .collect();
            match (action.to_str(), words.as_slice()) {
                (Some("list"), _) => {
                    Command::Automation(automation::Operation::List { flags: words })
                }
                (Some("detail"), [automation_id]) => {
                    Command::Automation(automation::Operation::Detail {
                        automation_id: automation_id.clone(),
                    })
                }
                (Some("register"), [automation_id, actor]) => {
                    Command::Automation(automation::Operation::Register {
                        automation_id: automation_id.clone(),
                        actor: actor.clone(),
                    })
                }
                (Some("pause"), [automation_id, revision, actor, cause]) => {
                    Command::Automation(automation::Operation::Pause {
                        automation_id: automation_id.clone(),
                        revision: revision.clone(),
                        actor: actor.clone(),
                        cause: cause.clone(),
                    })
                }
                (Some("resume"), [automation_id, revision, actor]) => {
                    Command::Automation(automation::Operation::Resume {
                        automation_id: automation_id.clone(),
                        revision: revision.clone(),
                        actor: actor.clone(),
                    })
                }
                (Some("archive"), [automation_id, revision, actor, cause]) => {
                    Command::Automation(automation::Operation::Archive {
                        automation_id: automation_id.clone(),
                        revision: revision.clone(),
                        actor: actor.clone(),
                        cause: cause.clone(),
                    })
                }
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        // `approval` is variadic for the reason `runs` and `automation` are:
        // both listings take optional paging flags while `record` and `detail`
        // are positional with different arities. The remaining words are
        // collected here and matched by the verb they belong to, so a wrong
        // arity is a usage refusal rather than a positional match that happened
        // to bind.
        (Some(command), Some(action), second, third) if command == "approval" => {
            let words: Vec<OsString> = second
                .into_iter()
                .chain(third)
                .chain(arguments.by_ref())
                .collect();
            match (action.to_str(), words.as_slice()) {
                (Some("list"), _) => Command::Approval(approval::Operation::List { flags: words }),
                (Some("detail"), [approval_key]) => {
                    Command::Approval(approval::Operation::Detail {
                        approval_key: approval_key.clone(),
                    })
                }
                (Some("by-subject"), [subject, flags @ ..]) => {
                    Command::Approval(approval::Operation::BySubject {
                        subject: subject.clone(),
                        flags: flags.to_vec(),
                    })
                }
                (Some("record"), [approval_key, subject, decision, decider]) => {
                    Command::Approval(approval::Operation::Record {
                        approval_key: approval_key.clone(),
                        subject: subject.clone(),
                        decision: decision.clone(),
                        decider: decider.clone(),
                    })
                }
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        // `batch` is variadic for the reason `approval` is, and one degree more:
        // `register` takes optional flags *and* a whole membership after them,
        // so its arity is unbounded below one member. The remaining words are
        // collected here and matched by the verb they belong to; `register`
        // hands its own words on for the flag-and-membership split, which is
        // that verb's grammar rather than this dispatch's.
        (Some(command), Some(action), second, third) if command == "batch" => {
            let words: Vec<OsString> = second
                .into_iter()
                .chain(third)
                .chain(arguments.by_ref())
                .collect();
            match (action.to_str(), words.as_slice()) {
                (Some("list"), _) => Command::Batch(batch::Operation::List { flags: words }),
                (Some("detail"), [batch_id]) => Command::Batch(batch::Operation::Detail {
                    batch_id: batch_id.clone(),
                }),
                (Some("register"), [batch_id, rest @ ..]) => {
                    Command::Batch(batch::Operation::Register {
                        batch_id: batch_id.clone(),
                        words: rest.to_vec(),
                    })
                }
                (Some("advance"), [batch_id, member_key, revision, state, last_sequence]) => {
                    Command::Batch(batch::Operation::Advance {
                        batch_id: batch_id.clone(),
                        member_key: member_key.clone(),
                        revision: revision.clone(),
                        state: state.clone(),
                        last_sequence: last_sequence.clone(),
                    })
                }
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        (Some(command), Some(operation), Some(socket_path), None)
            if command == "attempt" && operation == "heartbeat" =>
        {
            Command::Attempt(attempt::Operation::Heartbeat { socket_path })
        }
        (Some(command), Some(operation), Some(socket_path), Some(attempt_id))
            if command == "attempt" =>
        {
            let trailing = arguments.next();
            let extra = arguments.next();
            match (operation.to_str(), trailing, extra) {
                (Some("inspect"), None, None) => Command::Attempt(attempt::Operation::Inspect {
                    socket_path,
                    attempt_id,
                }),
                (Some("events"), cursor, None) => Command::Attempt(attempt::Operation::Events {
                    socket_path,
                    attempt_id,
                    cursor,
                }),
                (Some("cancel"), Some(request_ref), None) => {
                    Command::Attempt(attempt::Operation::Cancel {
                        socket_path,
                        attempt_id,
                        request_ref,
                    })
                }
                _ => {
                    let _ = stderr.write_all(USAGE.as_bytes());
                    return 2;
                }
            }
        }
        (Some(command), None, None, None) if command == "shutdown" => Command::Shutdown,
        _ => {
            let _ = stderr.write_all(USAGE.as_bytes());
            return 2;
        }
    };

    let runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let json = match command {
        Command::Status { json } => {
            return admin_status(runtime.as_deref(), json, &mut stdout, &mut stderr);
        }
        Command::Submit {
            scope,
            idempotency_key,
        } => {
            return admin_submit(
                runtime.as_deref(),
                scope,
                idempotency_key,
                &mut input,
                &mut stdout,
                &mut stderr,
            );
        }
        Command::ReconcileInspect { run_id } => {
            return admin_reconcile_inspect(runtime.as_deref(), run_id, &mut stdout, &mut stderr);
        }
        Command::ReconcileFail {
            run_id,
            generation_id,
            epoch,
            revision,
            decision_key,
        } => {
            return admin_reconcile_fail(
                runtime.as_deref(),
                run_id,
                generation_id,
                epoch,
                revision,
                decision_key,
                &mut stdout,
                &mut stderr,
            );
        }
        Command::OutboxInspect { outbox_id } => {
            return admin_outbox_inspect(runtime.as_deref(), outbox_id, &mut stdout, &mut stderr);
        }
        Command::OutboxReconcile {
            decision,
            outbox_id,
            generation_id,
            epoch,
            attempt,
            revision,
        } => {
            return admin_outbox_reconcile(
                runtime.as_deref(),
                OutboxCliCoordinates {
                    decision,
                    outbox_id,
                    generation_id,
                    epoch,
                    attempt,
                    revision,
                },
                &mut input,
                &mut stdout,
                &mut stderr,
            );
        }
        Command::RunSubmit { idempotency_key } => {
            return run_submit::run(
                runtime.as_deref(),
                idempotency_key,
                &mut input,
                &mut stdout,
                &mut stderr,
            );
        }
        Command::Runs(operation) => {
            return runs::run(&operation, runtime.as_deref(), &mut stdout, &mut stderr);
        }
        Command::Automation(operation) => {
            return automation::run(&operation, runtime.as_deref(), &mut stdout, &mut stderr);
        }
        Command::Approval(operation) => {
            return approval::run(&operation, runtime.as_deref(), &mut stdout, &mut stderr);
        }
        Command::Batch(operation) => {
            return batch::run(&operation, runtime.as_deref(), &mut stdout, &mut stderr);
        }
        Command::Shutdown => {
            return admin_shutdown(runtime.as_deref(), &mut stdout, &mut stderr);
        }
        Command::Attempt(operation) => {
            return attempt::run(operation, &mut stdout, &mut stderr);
        }
        Command::Doctor { json } => json,
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

fn admin_outbox_inspect<W: Write, E: Write>(
    runtime: Option<&OsStr>,
    outbox_id: OsString,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let outbox_id = match parse_u64_coordinate(outbox_id, "outbox_id") {
        Ok(value) => value,
        Err(category) => {
            let _ = writeln!(stderr, "automonique outbox refused: {category}");
            return 2;
        }
    };
    match admin_client::request(runtime, admin_client::Operation::InspectOutbox(outbox_id)) {
        Ok(automonique_protocol::admin::AdminResponse::OutboxInspected { evidence, .. }) => {
            if writeln!(
                stdout,
                "Automonique outbox: outbox_id={} intent_key={} transport={} kind={} state={} revision={} attempt={} lease_generation={} lease_holder={} lease_epoch={} lease_expires_ms={} lease_token_present={} delivery_receipt_present={}",
                evidence.outbox_id(), evidence.intent_key(), evidence.transport(), evidence.kind(), evidence.state(), evidence.revision(), evidence.attempt(),
                evidence.lease_generation_id().unwrap_or("-"), evidence.lease_holder().unwrap_or("-"),
                evidence.lease_epoch().map_or_else(|| "-".to_owned(), |value| value.to_string()),
                evidence.lease_expires_ms().map_or_else(|| "-".to_owned(), |value| value.to_string()),
                evidence.lease_token().is_some(), evidence.delivery_receipt_key().is_some(),
            ).is_ok() { 0 } else { 1 }
        }
        Ok(_) => { let _ = stderr.write_all(b"automonique outbox refused: response_mismatch\n"); 1 }
        Err(error) => { let _ = writeln!(stderr, "automonique outbox refused: {}", error.category()); 1 }
    }
}

struct OutboxCliCoordinates {
    decision: OsString,
    outbox_id: OsString,
    generation_id: OsString,
    epoch: OsString,
    attempt: OsString,
    revision: OsString,
}

fn admin_outbox_reconcile<R: Read, W: Write, E: Write>(
    runtime: Option<&OsStr>,
    coordinates: OutboxCliCoordinates,
    input: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let mut secret_input = Vec::new();
    if input
        .take((automonique_protocol::admin::MAX_RECONCILIATION_FIELD_BYTES + 2) as u64)
        .read_to_end(&mut secret_input)
        .is_err()
        || secret_input.len() > automonique_protocol::admin::MAX_RECONCILIATION_FIELD_BYTES + 1
    {
        let _ = stderr.write_all(b"automonique outbox refused: invalid_private_input\n");
        return 2;
    }
    let Ok(secret_input) = std::str::from_utf8(&secret_input) else {
        let _ = stderr.write_all(b"automonique outbox refused: invalid_private_input\n");
        return 2;
    };
    let mut private_fields = secret_input.lines();
    let (Some(value), None) = (private_fields.next(), private_fields.next()) else {
        let _ = stderr.write_all(b"automonique outbox refused: invalid_private_input\n");
        return 2;
    };
    let parsed = (
        parse_u64_coordinate(coordinates.outbox_id, "outbox_id"),
        parse_u64_coordinate(coordinates.epoch, "epoch"),
        parse_u64_coordinate(coordinates.attempt, "attempt"),
        parse_u64_coordinate(coordinates.revision, "revision"),
        coordinates.decision.into_string(),
        coordinates.generation_id.into_string(),
    );
    let (Ok(outbox_id), Ok(epoch), Ok(attempt), Ok(revision), Ok(decision), Ok(generation_id)) =
        parsed
    else {
        let _ = stderr.write_all(b"automonique outbox refused: invalid_coordinates\n");
        return 2;
    };
    let decision = match decision.as_str() {
        "delivered" => automonique_protocol::admin::OutboxReconciliationDecision::Delivered {
            receipt_key: value.to_owned(),
        },
        "dead-letter" => automonique_protocol::admin::OutboxReconciliationDecision::DeadLetter {
            reason: value.to_owned(),
        },
        _ => {
            let _ = stderr.write_all(b"automonique outbox refused: invalid_decision\n");
            return 2;
        }
    };
    let lease_token =
        match admin_client::request(runtime, admin_client::Operation::InspectOutbox(outbox_id)) {
            Ok(automonique_protocol::admin::AdminResponse::OutboxInspected {
                evidence, ..
            }) if evidence.lease_generation_id() == Some(generation_id.as_str())
                && evidence.lease_epoch() == Some(epoch)
                && evidence.attempt() == attempt
                && (evidence.revision() == revision
                    || (matches!(evidence.state(), "delivered" | "dead_lettered")
                        && revision.checked_add(1) == Some(evidence.revision()))) =>
            {
                match evidence.lease_token() {
                    Some(token) => token.to_owned(),
                    None => {
                        let _ = stderr.write_all(b"automonique outbox refused: stale_evidence\n");
                        return 1;
                    }
                }
            }
            Ok(automonique_protocol::admin::AdminResponse::OutboxInspected { .. }) => {
                let _ = stderr.write_all(b"automonique outbox refused: stale_evidence\n");
                return 1;
            }
            Ok(_) => {
                let _ = stderr.write_all(b"automonique outbox refused: response_mismatch\n");
                return 1;
            }
            Err(error) => {
                let _ = writeln!(stderr, "automonique outbox refused: {}", error.category());
                return 1;
            }
        };
    let reconciliation = match automonique_protocol::admin::OutboxReconciliation::new(
        automonique_protocol::admin::OutboxReconciliationParts {
            outbox_id,
            expected_generation_id: generation_id,
            expected_lease_epoch: epoch,
            expected_lease_token: lease_token,
            expected_attempt: attempt,
            expected_revision: revision,
            decision,
        },
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(stderr, "automonique outbox refused: {}", error.category());
            return 2;
        }
    };
    match admin_client::request(runtime, admin_client::Operation::ReconcileOutbox(reconciliation)) {
        Ok(automonique_protocol::admin::AdminResponse::OutboxReconciled { outbox_id, state, revision, duplicate, .. }) => {
            if writeln!(stdout, "Automonique outbox reconciled: outbox_id={outbox_id} state={state} revision={revision} duplicate={duplicate}").is_ok() { 0 } else { 1 }
        }
        Ok(_) => { let _ = stderr.write_all(b"automonique outbox refused: response_mismatch\n"); 1 }
        Err(error) => { let _ = writeln!(stderr, "automonique outbox refused: {}", error.category()); 1 }
    }
}

fn parse_u64_coordinate(value: OsString, field: &str) -> Result<u64, String> {
    value
        .into_string()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("invalid_{field}"))
}

fn admin_reconcile_inspect<W: Write, E: Write>(
    runtime: Option<&OsStr>,
    run_id: OsString,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let run_id = match parse_u64_coordinate(run_id, "run_id") {
        Ok(value) => value,
        Err(category) => {
            let _ = writeln!(stderr, "automonique reconcile refused: {category}");
            return 2;
        }
    };
    match admin_client::request(runtime, admin_client::Operation::InspectReconciliation(run_id)) {
        Ok(automonique_protocol::admin::AdminResponse::ReconciliationInspected { evidence, .. }) => {
            if writeln!(
                stdout,
                "Automonique reconciliation: run_id={} scope={} generation={} epoch={} revision={} terminal_payload={} outbox_count={}",
                evidence.run_id(),
                evidence.scope(),
                evidence.generation_id(),
                evidence.lease_epoch(),
                evidence.run_revision(),
                evidence.terminal_payload_present(),
                evidence.outbox_count(),
            ).is_ok() { 0 } else { 1 }
        }
        Ok(_) => {
            let _ = stderr.write_all(b"automonique reconcile refused: response_mismatch\n");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique reconcile refused: {}", error.category());
            1
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn admin_reconcile_fail<W: Write, E: Write>(
    runtime: Option<&OsStr>,
    run_id: OsString,
    generation_id: OsString,
    epoch: OsString,
    revision: OsString,
    decision_key: OsString,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let parsed = (
        parse_u64_coordinate(run_id, "run_id"),
        parse_u64_coordinate(epoch, "epoch"),
        parse_u64_coordinate(revision, "revision"),
        generation_id.into_string(),
        decision_key.into_string(),
    );
    let (Ok(run_id), Ok(epoch), Ok(revision), Ok(generation_id), Ok(decision_key)) = parsed else {
        let _ = stderr.write_all(b"automonique reconcile refused: invalid_coordinates\n");
        return 2;
    };
    let failure = match automonique_protocol::admin::ReconciliationFailure::new(
        run_id,
        generation_id,
        epoch,
        revision,
        decision_key,
        "execution_outcome_unknown",
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "automonique reconcile refused: {}",
                error.category()
            );
            return 2;
        }
    };
    match admin_client::request(runtime, admin_client::Operation::FailReconciliation(failure)) {
        Ok(automonique_protocol::admin::AdminResponse::ReconciliationFailed {
            run_event_id,
            inbox_event_id,
            outbox_id,
            duplicate,
            ..
        }) => {
            if writeln!(
                stdout,
                "Automonique reconciliation failed: run_event_id={run_event_id} inbox_event_id={inbox_event_id} outbox_id={outbox_id} duplicate={duplicate}"
            ).is_ok() { 0 } else { 1 }
        }
        Ok(_) => {
            let _ = stderr.write_all(b"automonique reconcile refused: response_mismatch\n");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique reconcile refused: {}", error.category());
            1
        }
    }
}

fn admin_submit<R: Read, W: Write, E: Write>(
    runtime: Option<&OsStr>,
    scope: OsString,
    idempotency_key: OsString,
    input: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let Ok(scope) = scope.into_string() else {
        let _ = stderr.write_all(b"automonique submit refused: invalid_scope\n");
        return 2;
    };
    let Ok(idempotency_key) = idempotency_key.into_string() else {
        let _ = stderr.write_all(b"automonique submit refused: invalid_idempotency_key\n");
        return 2;
    };
    let mut task = Vec::new();
    let limit = u64::try_from(automonique_protocol::admin::MAX_SYNTHETIC_TASK_BYTES)
        .expect("protocol task bound fits u64")
        + 1;
    if input.take(limit).read_to_end(&mut task).is_err() {
        let _ = stderr.write_all(b"automonique submit refused: stdin_io\n");
        return 1;
    }
    if task.len() > automonique_protocol::admin::MAX_SYNTHETIC_TASK_BYTES {
        let _ = stderr.write_all(b"automonique submit refused: task_too_large\n");
        return 2;
    }
    let Ok(task) = String::from_utf8(task) else {
        let _ = stderr.write_all(b"automonique submit refused: task_not_utf8\n");
        return 2;
    };
    let submission =
        match automonique_protocol::admin::SyntheticSubmission::new(scope, idempotency_key, task) {
            Ok(submission) => submission,
            Err(error) => {
                let _ = writeln!(stderr, "automonique submit refused: {}", error.category());
                return 2;
            }
        };
    match admin_client::request(runtime, admin_client::Operation::Submit(submission)) {
        Ok(automonique_protocol::admin::AdminResponse::SyntheticAccepted {
            inbox_id,
            duplicate,
            ..
        }) => {
            if writeln!(
                stdout,
                "Automonique synthetic task accepted: inbox_id={inbox_id} duplicate={duplicate}"
            )
            .is_ok()
            {
                0
            } else {
                1
            }
        }
        Ok(_) => {
            let _ = stderr.write_all(b"automonique submit refused: response_mismatch\n");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique submit refused: {}", error.category());
            1
        }
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
    let Some(operational) = status.operational() else {
        let _ = stderr.write_all(b"automonique status unavailable: response_mismatch\n");
        return 1;
    };
    let Some(durable) = status.durable_state() else {
        let _ = stderr.write_all(b"automonique status unavailable: response_mismatch\n");
        return 1;
    };
    let metric_json = |metric: automonique_protocol::admin::OperationalMetric| {
        serde_json::json!({
            "state": metric.state(),
            "value": metric.value(),
        })
    };
    // A count nobody could read prints as a dash, not as zero: the human
    // rendering owes the reader the same distinction the wire keeps.
    let metric_text = |metric: automonique_protocol::admin::OperationalMetric| {
        metric
            .value()
            .map_or_else(|| metric.state().to_owned(), |value| value.to_string())
    };
    let rendered = if json {
        serde_json::json!({
            "accepting_intake": status.accepting_intake(),
            "durable_state": {
                "approvals_recorded": metric_json(durable.approvals_recorded()),
                "automations_registered": metric_json(durable.automations_registered()),
                "open_tenure_epoch": metric_json(durable.open_tenure_epoch()),
                "open_tenures": metric_json(durable.open_tenures()),
                "runs_registered": metric_json(durable.runs_registered()),
                "tenures_recorded": metric_json(durable.tenures_recorded()),
            },
            "event_cursor": status.event_cursor(),
            "execution_state": status.execution_state().as_str(),
            "generation": status.generation(),
            "inbox_pending": status.inbox_pending(),
            "instance_id": status.instance_id().as_str(),
            "intake_paused": status.intake_paused(),
            "outbox_pending": status.outbox_pending(),
            "operational": {
                "observed_ms": operational.observed_ms(),
                "outbox_dead_lettered": operational.outbox_dead_lettered(),
                "outbox_delivered": operational.outbox_delivered(),
                "outbox_in_flight_ambiguous": operational.outbox_in_flight_ambiguous(),
                "outbox_in_flight_live": operational.outbox_in_flight_live(),
                "outbox_oldest_ready_age_ms": operational.outbox_oldest_ready_age_ms(),
                "outbox_pending_delayed": operational.outbox_pending_delayed(),
                "outbox_pending_ready": operational.outbox_pending_ready(),
                "provider_available": metric_json(operational.provider_available()),
                "reconciliation_pending": operational.reconciliation_pending(),
                "sandbox_launch_refusals": metric_json(operational.sandbox_launch_refusals()),
                "telegram_offset_lag": metric_json(operational.telegram_offset_lag()),
                "telegram_pollers_expired": operational.telegram_pollers_expired(),
                "telegram_pollers_live": operational.telegram_pollers_live(),
            },
            "running": status.running(),
            "state": status.state().as_str(),
            "telegram_poller_epoch": status.telegram_poller_epoch(),
            "telegram_state": status.telegram_state().as_str(),
        })
        .to_string()
            + "\n"
    } else {
        format!(
            "Automonique daemon: {}\ninstance: {}\ngeneration: {}\nevent cursor: {}\ninbox pending: {}\noutbox pending: {}\nrunning: {}\naccepting intake: {}\nintake paused: {}\nexecution: {}\ntelegram: {}\ntelegram poller epoch: {}\nobserved ms: {}\nreconciliation pending: {}\noutbox ready: {}\noutbox delayed: {}\noutbox live: {}\noutbox ambiguous: {}\noutbox delivered: {}\noutbox dead-lettered: {}\noutbox oldest ready age ms: {}\ntelegram pollers live: {}\ntelegram pollers expired: {}\ntelegram offset lag: {}\nprovider available: {}\nsandbox launch refusals: {}\nruns registered: {}\nautomations registered: {}\napprovals recorded: {}\ntenures recorded: {}\nopen tenures: {}\nopen tenure epoch: {}\n",
            status.state().as_str(),
            status.instance_id().as_str(),
            status.generation(),
            status.event_cursor(),
            status.inbox_pending(),
            status.outbox_pending(),
            status.running(),
            status.accepting_intake(),
            status.intake_paused(),
            status.execution_state().as_str(),
            status.telegram_state().as_str(),
            status
                .telegram_poller_epoch()
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            operational.observed_ms(),
            operational.reconciliation_pending(),
            operational.outbox_pending_ready(),
            operational.outbox_pending_delayed(),
            operational.outbox_in_flight_live(),
            operational.outbox_in_flight_ambiguous(),
            operational.outbox_delivered(),
            operational.outbox_dead_lettered(),
            operational.outbox_oldest_ready_age_ms(),
            operational.telegram_pollers_live(),
            operational.telegram_pollers_expired(),
            operational.telegram_offset_lag().state(),
            operational.provider_available().state(),
            operational.sandbox_launch_refusals().state(),
            metric_text(durable.runs_registered()),
            metric_text(durable.automations_registered()),
            metric_text(durable.approvals_recorded()),
            metric_text(durable.tenures_recorded()),
            metric_text(durable.open_tenures()),
            metric_text(durable.open_tenure_epoch()),
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
        // The controller list above is the hierarchy's, not this process's.
        // Delegation is asked separately so a host with a complete controller
        // list and an undelegated cgroup cannot read as able to bound a run.
        inspect_cgroup_v2_delegation(),
        inspect_landlock_support(),
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use automonique_protocol::admin::{
        AdminInstanceId, AdminRequest, AdminResponse, DaemonState, DaemonStatus,
        DurableStateCounts, DurableStateCountsParts, OperationalMetric, OperationalStatus,
        OperationalStatusParts,
    };
    use automonique_protocol::codec::encode_frame;

    /// One fake daemon that answers a single status request with `counts`.
    ///
    /// The daemon crate proves what the real counts are; this proves the CLI
    /// renders whatever it was handed, including a count no store could answer.
    fn rendered(counts: DurableStateCounts, json: bool) -> String {
        let runtime = tempfile::tempdir().expect("runtime");
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let product = runtime.path().join("automonique");
        std::fs::create_dir(&product).expect("product runtime");
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
            .expect("product mode");
        let socket = product.join("admin.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request = AdminRequest::from_canonical_bytes(&body).expect("typed request");
            let status = DaemonStatus::new(
                AdminInstanceId::new("render-daemon").expect("instance"),
                DaemonState::Ready,
                3,
                1,
                0,
                0,
                0,
                true,
            )
            .and_then(|status| {
                status.with_operational(
                    OperationalStatus::new(OperationalStatusParts {
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
                    .expect("operational"),
                )
            })
            .and_then(|status| status.with_durable_state(counts))
            .expect("status");
            let response = AdminResponse::Status {
                request_id: request.request_id().clone(),
                status,
            }
            .to_message()
            .expect("response")
            .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            stream.write_all(&frame).expect("write");
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = super::admin_status(
            Some(runtime.path().as_os_str()),
            json,
            &mut stdout,
            &mut stderr,
        );
        server.join().expect("server");
        assert_eq!(
            code,
            0,
            "status failed: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty(), "status wrote to stderr");
        String::from_utf8(stdout).expect("UTF-8 rendering")
    }

    fn counts(runs: OperationalMetric) -> DurableStateCounts {
        DurableStateCounts::new(DurableStateCountsParts {
            approvals_recorded: OperationalMetric::Measured(5),
            automations_registered: OperationalMetric::Measured(0),
            open_tenure_epoch: OperationalMetric::Measured(3),
            open_tenures: OperationalMetric::Measured(1),
            runs_registered: runs,
            tenures_recorded: OperationalMetric::Measured(2),
        })
        .expect("coherent counts")
    }

    #[test]
    fn status_json_carries_every_durable_count_with_its_state() {
        let rendered = rendered(counts(OperationalMetric::Measured(4)), true);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("status --json is JSON");
        let durable = parsed
            .get("durable_state")
            .expect("durable counts are reported");
        for (field, value) in [
            ("approvals_recorded", 5),
            ("automations_registered", 0),
            ("open_tenure_epoch", 3),
            ("open_tenures", 1),
            ("runs_registered", 4),
            ("tenures_recorded", 2),
        ] {
            let metric = durable.get(field).unwrap_or_else(|| panic!("{field}"));
            assert_eq!(metric["state"], "measured", "{field}");
            assert_eq!(metric["value"], value, "{field}");
        }
    }

    /// The distinction the wire keeps must survive both renderings.
    ///
    /// A count nobody could read prints as `unavailable` and carries a null
    /// value, where a store holding nothing prints `0`. Collapsing the two in
    /// the rendering would undo the whole point of carrying them apart.
    #[test]
    fn an_unavailable_count_never_renders_as_zero() {
        let json = rendered(counts(OperationalMetric::Unavailable), true);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("status --json is JSON");
        let runs = &parsed["durable_state"]["runs_registered"];
        assert_eq!(runs["state"], "unavailable");
        assert!(runs["value"].is_null(), "an unread count has no value");
        // The empty store beside it still reports its zero.
        assert_eq!(
            parsed["durable_state"]["automations_registered"]["value"],
            0
        );

        let human = rendered(counts(OperationalMetric::Unavailable), false);
        assert!(
            human.contains("runs registered: unavailable\n"),
            "human status hid an unreadable store:\n{human}"
        );
        assert!(
            human.contains("automations registered: 0\n"),
            "human status lost a measured zero:\n{human}"
        );
    }

    #[test]
    fn human_status_shows_every_durable_count() {
        let human = rendered(counts(OperationalMetric::Measured(4)), false);
        for line in [
            "runs registered: 4\n",
            "automations registered: 0\n",
            "approvals recorded: 5\n",
            "tenures recorded: 2\n",
            "open tenures: 1\n",
            "open tenure epoch: 3\n",
        ] {
            assert!(human.contains(line), "missing {line:?} in:\n{human}");
        }
    }
}
