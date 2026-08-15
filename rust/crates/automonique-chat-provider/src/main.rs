// SPDX-License-Identifier: Elastic-2.0

use std::process::ExitCode;

fn main() -> ExitCode {
    match automonique_chat_provider::run(std::env::args().skip(1), std::io::stdin().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automonique chat provider refused: {}", error.category());
            ExitCode::FAILURE
        }
    }
}
