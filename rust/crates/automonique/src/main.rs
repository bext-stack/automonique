// SPDX-License-Identifier: Elastic-2.0

use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next();
    if command.as_deref() == Some(std::ffi::OsStr::new("improvement-activate")) {
        let values = arguments.collect::<Vec<_>>();
        if values.len() != 8
            || values[0] != "--state-dir"
            || values[2] != "--improvement-id"
            || values[4] != "--revision"
            || values[6] != "--manifest"
        {
            return ExitCode::from(2);
        }
        let Some(state_dir) = values[1].to_str().map(std::path::Path::new) else {
            return ExitCode::from(2);
        };
        let Some(improvement_id) = values[3].to_str().and_then(|value| value.parse().ok()) else {
            return ExitCode::from(2);
        };
        let Some(revision) = values[5].to_str().and_then(|value| value.parse().ok()) else {
            return ExitCode::from(2);
        };
        let Some(manifest) = values[7].to_str() else {
            return ExitCode::from(2);
        };
        return match automonique_daemon::improvement_worker::run_scheduled_activation(
            state_dir,
            improvement_id,
            revision,
            manifest,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("daemon")) {
        let values = arguments.collect::<Vec<_>>();
        let disconnected = values.as_slice()
            == [
                std::ffi::OsString::from("--foreground"),
                std::ffi::OsString::from("--disconnected-recovery"),
            ];
        if values.as_slice() != [std::ffi::OsString::from("--foreground")] && !disconnected {
            eprintln!("usage: automonique daemon --foreground [--disconnected-recovery]");
            return ExitCode::from(2);
        }
        let result = automonique_daemon::DaemonConfig::from_environment().and_then(|config| {
            if disconnected {
                automonique_daemon::run_disconnected_recovery(&config)
            } else {
                automonique_daemon::run_foreground(&config)
            }
        });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("automonique daemon refused: {}", error.category());
                ExitCode::FAILURE
            }
        };
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("work-brief")) {
        return work_brief_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("ask")) {
        return ask_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("shot")) {
        return shot_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("backup")) {
        return backup_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("restore")) {
        return restore_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("tui")) {
        return tui_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("platform-job")) {
        return platform_job_command(arguments.collect());
    }
    ExitCode::from(automonique_cli::run(
        std::env::args_os().skip(1),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ))
}

struct PlatformJobArguments {
    socket: std::path::PathBuf,
    idempotency_key: String,
    timeout: Duration,
}

/// Submit one federated AI Operations assignment through Automonique's local
/// platform authority and wait for its durable terminal receipt. The prompt is
/// accepted only on stdin, and the command line remains a closed typed shape.
fn platform_job_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    let arguments = match platform_job_arguments(&values) {
        Ok(arguments) => arguments,
        Err(()) => {
            eprintln!(
                "usage: automonique platform-job --socket PATH --idempotency-key KEY --timeout-seconds SECONDS < prompt"
            );
            return ExitCode::from(2);
        }
    };
    let mut prompt = Vec::new();
    {
        use std::io::Read as _;
        if std::io::stdin()
            .lock()
            .take(257)
            .read_to_end(&mut prompt)
            .is_err()
            || prompt.is_empty()
            || prompt.len() > 256
        {
            eprintln!("automonique platform-job refused: prompt");
            return ExitCode::from(2);
        }
    }
    let Ok(prompt) = String::from_utf8(prompt) else {
        eprintln!("automonique platform-job refused: prompt");
        return ExitCode::from(2);
    };
    match run_platform_job(&arguments, &prompt) {
        Ok((outcome, explanation)) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema": "automonique.platform-job/v1",
                    "outcome": outcome.as_str(),
                    "explanation": explanation,
                })
            );
            if outcome == automonique_protocol::platform::ReceiptOutcome::Completed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(category) => {
            eprintln!("automonique platform-job refused: {category}");
            ExitCode::FAILURE
        }
    }
}

fn platform_job_arguments(values: &[std::ffi::OsString]) -> Result<PlatformJobArguments, ()> {
    if values.len() != 6
        || values[0] != "--socket"
        || values[2] != "--idempotency-key"
        || values[4] != "--timeout-seconds"
    {
        return Err(());
    }
    let socket = std::path::PathBuf::from(&values[1]);
    let idempotency_key = values[3].to_str().ok_or(())?.to_owned();
    let timeout_seconds = values[5]
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=21_600).contains(value))
        .ok_or(())?;
    if !socket.is_absolute()
        || automonique_protocol::platform::IdempotencyKey::new(&idempotency_key).is_err()
    {
        return Err(());
    }
    Ok(PlatformJobArguments {
        socket,
        idempotency_key,
        timeout: Duration::from_secs(timeout_seconds),
    })
}

fn run_platform_job(
    arguments: &PlatformJobArguments,
    prompt: &str,
) -> Result<
    (
        automonique_protocol::platform::ReceiptOutcome,
        Option<String>,
    ),
    &'static str,
> {
    use automonique_platform_client::{ActionResult, PlatformClient, UnixTransport};
    use automonique_protocol::platform::{
        ExecuteRequest, FreshnessState, GetReceiptRequest, IdempotencyKey, PlatformAction,
        PlatformText, ReceiptOutcome, ResourceAuthority, ResourceKind,
    };

    let mut client = PlatformClient::new(UnixTransport::new(&arguments.socket));
    let snapshot = client.snapshot(Vec::new()).map_err(|_| "snapshot")?;
    let mut nodes = snapshot.resources.into_iter().filter(|record| {
        record.resource.authority == ResourceAuthority::Automonique
            && record.resource.kind == ResourceKind::Node
            && record.freshness.state == FreshnessState::Fresh
            && record.summary.as_str() == "daemon ready"
    });
    let node = nodes.next().ok_or("active_node")?;
    if nodes.next().is_some() {
        return Err("active_node_ambiguous");
    }
    let key = IdempotencyKey::new(&arguments.idempotency_key).map_err(|_| "idempotency_key")?;
    let request = ExecuteRequest::new(
        PlatformAction::SubmitRequest,
        node.resource,
        key.clone(),
        Some(node.freshness.revision),
        Some(PlatformText::new(prompt.trim_end()).map_err(|_| "prompt")?),
    )
    .map_err(|_| "request")?;
    let receipt = match client.execute_outcome(request).map_err(|_| "execute")? {
        ActionResult::Receipt(receipt) => receipt,
        ActionResult::Refused {
            outcome,
            explanation,
        } => return Ok((outcome, Some(explanation.as_str().to_owned()))),
    };
    if receipt.outcome != ReceiptOutcome::Accepted {
        return Ok((
            receipt.outcome,
            receipt.explanation.map(|value| value.as_str().to_owned()),
        ));
    }

    let deadline = Instant::now() + arguments.timeout;
    loop {
        if Instant::now() >= deadline {
            return Ok((
                ReceiptOutcome::Unknown,
                Some("local_receipt_timeout".to_owned()),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
        let receipt = client
            .get_receipt(GetReceiptRequest::by_idempotency_key(key.clone()))
            .map_err(|_| "receipt")?;
        if receipt.outcome != ReceiptOutcome::Accepted {
            return Ok((
                receipt.outcome,
                receipt.explanation.map(|value| value.as_str().to_owned()),
            ));
        }
    }
}

/// Launch the maintained JCode-derived operator client over Automonique's
/// authenticated platform socket. The wrapper accepts only the two platform
/// client options it owns and forwards them as an explicit argument vector;
/// no request or model-produced text is ever interpreted as a command line.
fn tui_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    let arguments = match tui_arguments(&values) {
        Ok(arguments) => arguments,
        Err(()) => {
            eprintln!("usage: automonique tui [--json] [--socket PATH]");
            return ExitCode::from(2);
        }
    };
    let binary = std::env::var_os("AUTOMONIQUE_TUI_BINARY")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| std::ffi::OsString::from("jcode"));
    match std::process::Command::new(binary)
        .arg("platform")
        .args(arguments)
        .status()
    {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from),
        Err(_) => {
            eprintln!(
                "automonique tui unavailable: install the maintained jcode client or set AUTOMONIQUE_TUI_BINARY"
            );
            ExitCode::FAILURE
        }
    }
}

fn tui_arguments(values: &[std::ffi::OsString]) -> Result<Vec<std::ffi::OsString>, ()> {
    let mut output = Vec::new();
    let mut index = 0;
    let mut json = false;
    let mut socket = false;
    while index < values.len() {
        if values[index] == "--json" && !json {
            json = true;
            output.push(values[index].clone());
            index += 1;
        } else if values[index] == "--socket" && !socket {
            let Some(path) = values.get(index + 1).filter(|value| !value.is_empty()) else {
                return Err(());
            };
            socket = true;
            output.push(values[index].clone());
            output.push(path.clone());
            index += 2;
        } else {
            return Err(());
        }
    }
    Ok(output)
}

/// `automonique work-brief --state-dir D --job-id J --issue-url U` prints the
/// local context block for one approved job. The ranking hint (the job's
/// prompt head) arrives on stdin, never as an argument: it is model- and
/// console-produced text and must not become part of a command line.
fn work_brief_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    const MAX_HINT_BYTES: usize = 8 * 1024;
    if values.len() != 6
        || values[0] != "--state-dir"
        || values[2] != "--job-id"
        || values[4] != "--issue-url"
    {
        eprintln!(
            "usage: automonique work-brief --state-dir DIR --job-id ID --issue-url URL < hint"
        );
        return ExitCode::from(2);
    }
    let Some(state_dir) = values[1].to_str().map(std::path::Path::new) else {
        return ExitCode::from(2);
    };
    let (Some(job_id), Some(issue_url)) = (values[3].to_str(), values[5].to_str()) else {
        return ExitCode::from(2);
    };
    let mut hint = Vec::new();
    {
        use std::io::Read as _;
        let stdin = std::io::stdin();
        let mut handle = stdin.lock().take(MAX_HINT_BYTES as u64);
        if handle.read_to_end(&mut hint).is_err() {
            hint.clear();
        }
    }
    let hint = String::from_utf8_lossy(&hint).into_owned();
    let brief = automonique_daemon::work_brief::render(
        state_dir,
        &automonique_daemon::work_brief::WorkBriefRequest {
            job_id: job_id.to_owned(),
            issue_url: issue_url.to_owned(),
            hint,
        },
    );
    // The method is operator policy and travels outside the untrusted
    // local-context block; the screenshot verb is named by this binary's
    // own absolute path so the agent can call it from any working directory.
    let binary =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("automonique"));
    let method = automonique_daemon::work_method::render(state_dir, &binary);
    println!("{method}\n\n{brief}");
    ExitCode::SUCCESS
}

/// `automonique ask [--approve] [--context TEXT]` reads one question from
/// stdin and prints what the conversational surfaces would reply, against
/// this host's live state and the running daemon. Nothing is sent anywhere
/// and nothing is remembered. `--approve` follows an escalation the router
/// asks for, as an approved card would; `--context` stands in for the recent
/// conversation. The question arrives on stdin so it never becomes part of a
/// command line.
fn ask_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    const MAX_QUESTION_BYTES: usize = 8 * 1024;
    const MAX_CONTEXT_BYTES: usize = 16 * 1024;
    let mut approve = false;
    let mut context = String::new();
    let mut values = values.into_iter();
    while let Some(value) = values.next() {
        if value == "--approve" {
            approve = true;
        } else if value == "--context" {
            match values.next().and_then(|text| text.into_string().ok()) {
                Some(text) if text.len() <= MAX_CONTEXT_BYTES => context = text,
                _ => return ask_usage(),
            }
        } else {
            return ask_usage();
        }
    }
    let mut question = Vec::new();
    {
        use std::io::Read as _;
        let stdin = std::io::stdin();
        let mut handle = stdin.lock().take(MAX_QUESTION_BYTES as u64);
        if handle.read_to_end(&mut question).is_err() {
            question.clear();
        }
    }
    let question = String::from_utf8_lossy(&question).trim().to_owned();
    if question.is_empty() {
        return ask_usage();
    }
    let config = match automonique_daemon::DaemonConfig::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("automonique ask refused: {}", error.category());
            return ExitCode::FAILURE;
        }
    };
    let mut host = match automonique_daemon::ask::AskHost::open(&config) {
        Ok(host) => host,
        Err(reason) => {
            eprintln!("automonique ask refused: {reason}");
            return ExitCode::FAILURE;
        }
    };
    if question == "--probe-lane" {
        match host.probe_lane() {
            Ok(answer) => println!("lane ok: {answer}"),
            Err(failure) => println!("lane failure: {failure}"),
        }
        return ExitCode::SUCCESS;
    }
    let outcome = host.ask(&question, &context);
    println!("{}", outcome.answer);
    if let Some(selected) = outcome.selected {
        println!("\n[selected] {selected}");
        if approve && let Some(answer) = host.approve_escalation() {
            println!("\n[approved escalation answer]\n{answer}");
        }
    }
    ExitCode::SUCCESS
}

/// `automonique shot <url> [--out PNG] [--host VHOST] [--width N] [--height N] [--full] [--timeout S]`
/// captures one rendered page with the host's headless Chromium and prints
/// `MONIQUE_SHOT_OK: <png>` + `title: …`, or one `MONIQUE_SHOT_FAIL: <reason>`
/// line. It never hangs past its deadline and never prints a stack trace.
fn shot_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    use automonique_daemon::shot::{FAIL_MARKER, OK_MARKER, capture, find_browser, parse};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let default_out = std::env::temp_dir().join(format!("monique-shot-{stamp}.png"));
    let request = match parse(&values, default_out) {
        Ok(request) => request,
        Err(reason) => {
            println!("{FAIL_MARKER} {reason}");
            eprintln!(
                "usage: automonique shot <url> [--out PNG] [--host VHOST] [--width N] [--height N] [--full] [--timeout S]"
            );
            return ExitCode::from(2);
        }
    };
    let Some(browser) = find_browser() else {
        println!(
            "{FAIL_MARKER} no headless Chromium found (set {} to a browser binary)",
            automonique_daemon::shot::BROWSER_ENV
        );
        return ExitCode::FAILURE;
    };
    match capture(&request, &browser) {
        Ok(outcome) => {
            println!("{OK_MARKER} {}", outcome.png.display());
            println!("title: {}", outcome.title);
            println!("bytes: {}", outcome.bytes);
            ExitCode::SUCCESS
        }
        Err(reason) => {
            println!("{FAIL_MARKER} {reason}");
            ExitCode::FAILURE
        }
    }
}

fn ask_usage() -> ExitCode {
    eprintln!("usage: automonique ask [--approve] [--context TEXT] < question");
    ExitCode::from(2)
}

fn backup_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    let result = match values.as_slice() {
        [verb, root] if verb == "create" => state_dir().and_then(|state| {
            automonique_backup::create(&state, std::path::Path::new(root))
                .map(|path| println!("{}", path.display()))
                .map_err(|error| error.category())
        }),
        [verb, recovery_set] if verb == "verify" => {
            automonique_backup::verify(std::path::Path::new(recovery_set))
                .map(|manifest| println!("verified {} databases", manifest.database_count))
                .map_err(|error| error.category())
        }
        _ => {
            eprintln!(
                "usage: automonique backup create <backup-root> | backup verify <recovery-set>"
            );
            return ExitCode::from(2);
        }
    };
    command_result("backup", result)
}

fn restore_command(values: Vec<std::ffi::OsString>) -> ExitCode {
    let result = match values.as_slice() {
        [from_flag, source, into_flag, target]
            if from_flag == "--from" && into_flag == "--into" =>
        {
            automonique_backup::restore(std::path::Path::new(source), std::path::Path::new(target))
                .map(|manifest| println!("restored {} databases", manifest.database_count))
                .map_err(|error| error.category())
        }
        [
            drill,
            scope_flag,
            scope,
            from_flag,
            source,
            into_flag,
            target,
        ] if drill == "drill"
            && scope_flag == "--scope"
            && from_flag == "--from"
            && into_flag == "--into"
            && (scope == "clean-host" || scope == "local-fixture") =>
        {
            run_restore_drill(
                scope,
                std::path::Path::new(source),
                std::path::Path::new(target),
            )
        }
        _ => {
            eprintln!(
                "usage: automonique restore --from <recovery-set> --into <empty-target> | restore drill --scope clean-host|local-fixture --from <recovery-set> --into <empty-target>"
            );
            return ExitCode::from(2);
        }
    };
    command_result("restore", result)
}

fn run_restore_drill(
    scope: &std::ffi::OsStr,
    source: &std::path::Path,
    target: &std::path::Path,
) -> Result<(), &'static str> {
    if scope == "clean-host"
        && std::env::var_os("AUTOMONIQUE_CLEAN_HOST").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return Err("clean_host_attestation_missing");
    }
    let started = Instant::now();
    let manifest = automonique_backup::restore(source, target).map_err(|error| error.category())?;
    prove_disconnected_start(target, started)?;
    let rto_ms =
        u64::try_from(started.elapsed().as_millis()).map_err(|_| "system_clock_invalid")?;
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_millis(),
    )
    .map_err(|_| "system_clock_invalid")?;
    let rpo_ms = now_ms.saturating_sub(manifest.snapshot_completed_unix_ms);
    let objective = scope == "clean-host";
    if objective
        && (rpo_ms > automonique_backup::RPO_MILLIS || rto_ms > automonique_backup::RTO_MILLIS)
    {
        return Err("recovery_objective_missed");
    }
    println!(
        "scope={} databases={} rpo_ms={} rto_ms={} objective_met={}",
        scope.to_string_lossy(),
        manifest.database_count,
        rpo_ms,
        rto_ms,
        if objective { "true" } else { "not_applicable" }
    );
    Ok(())
}

fn prove_disconnected_start(
    target: &std::path::Path,
    started: Instant,
) -> Result<(), &'static str> {
    if state_dir()?.as_path() != target {
        return Err("restore_target_is_not_active_state");
    }
    let executable = std::env::current_exe().map_err(|_| "recovery_runtime_unavailable")?;
    let mut daemon = std::process::Command::new(&executable)
        .args(["daemon", "--foreground", "--disconnected-recovery"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "disconnected_start_failed")?;
    let ready = loop {
        if daemon
            .try_wait()
            .map_err(|_| "disconnected_start_failed")?
            .is_some()
        {
            break false;
        }
        if std::process::Command::new(&executable)
            .args(["status", "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            break true;
        }
        if started.elapsed().as_millis() > u128::from(automonique_backup::RTO_MILLIS) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !ready {
        let _ = daemon.kill();
        let _ = daemon.wait();
        return Err("disconnected_start_failed");
    }
    let shutdown = std::process::Command::new(&executable)
        .arg("shutdown")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let Ok(shutdown) = shutdown else {
        let _ = daemon.kill();
        let _ = daemon.wait();
        return Err("disconnected_shutdown_failed");
    };
    if !shutdown.success()
        || !daemon
            .wait()
            .map_err(|_| "disconnected_shutdown_failed")?
            .success()
    {
        return Err("disconnected_shutdown_failed");
    }
    Ok(())
}

fn state_dir() -> Result<std::path::PathBuf, &'static str> {
    std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("automonique"))
        .ok_or("xdg_state_home_missing")
}

fn command_result(command: &str, result: Result<(), &'static str>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(category) => {
            eprintln!("automonique {command} refused: {category}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tui_tests {
    use super::{platform_job_arguments, tui_arguments};
    use std::ffi::OsString;
    use std::time::Duration;

    #[test]
    fn tui_wrapper_forwards_only_typed_platform_options() {
        assert_eq!(
            tui_arguments(&[
                OsString::from("--socket"),
                OsString::from("/run/user/1/operator.sock"),
                OsString::from("--json"),
            ])
            .expect("arguments"),
            vec![
                OsString::from("--socket"),
                OsString::from("/run/user/1/operator.sock"),
                OsString::from("--json"),
            ]
        );
    }

    #[test]
    fn tui_wrapper_rejects_unknown_duplicate_or_missing_values() {
        assert!(tui_arguments(&[OsString::from("--provider")]).is_err());
        assert!(tui_arguments(&[OsString::from("--socket")]).is_err());
        assert!(tui_arguments(&[OsString::from("--json"), OsString::from("--json")]).is_err());
    }

    #[test]
    fn platform_job_arguments_are_closed_and_bounded() {
        let parsed = platform_job_arguments(&[
            OsString::from("--socket"),
            OsString::from("/run/user/1000/automonique/admin.sock"),
            OsString::from("--idempotency-key"),
            OsString::from("cmd_12345678"),
            OsString::from("--timeout-seconds"),
            OsString::from("60"),
        ])
        .expect("valid platform job");
        assert!(parsed.socket.is_absolute());
        assert_eq!(parsed.idempotency_key, "cmd_12345678");
        assert_eq!(parsed.timeout, Duration::from_secs(60));

        assert!(
            platform_job_arguments(&[
                OsString::from("--socket"),
                OsString::from("relative.sock"),
                OsString::from("--idempotency-key"),
                OsString::from("cmd_12345678"),
                OsString::from("--timeout-seconds"),
                OsString::from("60"),
            ])
            .is_err()
        );
        assert!(
            platform_job_arguments(&[
                OsString::from("--socket"),
                OsString::from("/run/automonique.sock"),
                OsString::from("--idempotency-key"),
                OsString::from("cmd_12345678"),
                OsString::from("--timeout-seconds"),
                OsString::from("21601"),
            ])
            .is_err()
        );
    }
}
