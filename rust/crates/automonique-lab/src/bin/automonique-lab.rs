// SPDX-License-Identifier: Elastic-2.0

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use automonique_lab::build::BuildBroker;
use automonique_lab::controller::LabController;
use automonique_lab::framing::FrameLimits;
use automonique_lab::protocol::GitSha1;
use automonique_lab::server::{UnixLabServer, UnixServerConfig};
use automonique_lab::workspace_lease::RepoPath;

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("automonique-lab: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<std::ffi::OsString>) -> Result<(), &'static str> {
    if arguments.len() != 11
        || arguments[0] != "serve-once"
        || arguments[1] != "--socket"
        || arguments[3] != "--state"
        || arguments[5] != "--build-root"
        || arguments[7] != "--base"
        || arguments[9] != "--lease-path"
    {
        return Err(
            "usage: automonique-lab serve-once --socket PATH --state PATH --build-root PATH --base SHA1 --lease-path REPO_PATH",
        );
    }
    let socket_path = PathBuf::from(&arguments[2]);
    let state_path = PathBuf::from(&arguments[4]);
    let build_root = PathBuf::from(&arguments[6]);
    let base = arguments[8].to_str().ok_or("base must be UTF-8")?;
    let base = GitSha1::new(base).map_err(|_| "base must be a full SHA-1")?;
    let lease_path = arguments[10].to_str().ok_or("lease path must be UTF-8")?;
    let lease_path = RepoPath::parse(lease_path).map_err(|_| "lease path must be canonical")?;
    let broker =
        BuildBroker::open(build_root).map_err(|_| "could not open synthetic build broker")?;
    let controller = LabController::open(state_path, base, vec![lease_path], broker)
        .map_err(|_| "could not open durable controller")?;
    let mut server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path,
            frame_limits: FrameLimits::new(1024 * 1024).map_err(|_| "invalid frame bound")?,
            io_timeout: Duration::from_secs(5),
        },
        controller,
    )
    .map_err(|_| "could not bind local server")?;
    server.serve_once().map_err(|_| "request failed")
}
