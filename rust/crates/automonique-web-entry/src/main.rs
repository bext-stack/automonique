// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automonique web entry refused: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut bind = IpAddr::from([127, 0, 0, 1]);
    let mut port = 18_082_u16;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bind" => bind = arguments.next().ok_or("--bind requires a value")?.parse()?,
            "--port" => port = arguments.next().ok_or("--port requires a value")?.parse()?,
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    if !bind.is_loopback() {
        return Err("non-loopback bind".into());
    }
    if port == 0 {
        return Err("port zero".into());
    }
    let listener = TcpListener::bind(SocketAddr::new(bind, port))?;
    automonique_web_entry::serve(listener)?;
    Ok(())
}
