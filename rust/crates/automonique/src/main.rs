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
    if command.as_deref() == Some(std::ffi::OsStr::new("backup")) {
        return backup_command(arguments.collect());
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("restore")) {
        return restore_command(arguments.collect());
    }
    ExitCode::from(automonique_cli::run(
        std::env::args_os().skip(1),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ))
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
