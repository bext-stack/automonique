// SPDX-License-Identifier: Elastic-2.0

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("daemon")) {
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
