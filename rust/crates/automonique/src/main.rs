// SPDX-License-Identifier: Elastic-2.0

use std::process::ExitCode;

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
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--foreground"))
            || arguments.next().is_some()
        {
            eprintln!("usage: automonique daemon --foreground");
            return ExitCode::from(2);
        }
        let result = automonique_daemon::DaemonConfig::from_environment()
            .and_then(|config| automonique_daemon::run_foreground(&config));
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("automonique daemon refused: {}", error.category());
                ExitCode::FAILURE
            }
        };
    }
    ExitCode::from(automonique_cli::run(
        std::env::args_os().skip(1),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ))
}
