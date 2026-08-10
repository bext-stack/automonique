// SPDX-License-Identifier: Elastic-2.0

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(automonique_cli::run(
        std::env::args_os().skip(1),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    ))
}
