// SPDX-License-Identifier: Elastic-2.0

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next();
    if command.as_deref() == Some(std::ffi::OsStr::new("__doctor-sandbox-probe")) {
        if arguments.next().is_some() {
            return ExitCode::from(2);
        }
        return ExitCode::from(automonique_cli::sandbox_probe_child(
            std::io::stdout().lock(),
        ));
    }
    ExitCode::from(automonique_cli::run(
        std::env::args_os().skip(1),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ))
}
