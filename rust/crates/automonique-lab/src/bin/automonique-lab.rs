// SPDX-License-Identifier: Elastic-2.0

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use automonique_lab::build::BuildBroker;
use automonique_lab::controller::LabController;
use automonique_lab::framing::FrameLimits;
use automonique_lab::program::select_admitted;
use automonique_lab::protocol::GitSha1;
use automonique_lab::server::{UnixLabServer, UnixServerConfig};
use automonique_lab::workspace_lease::RepoPath;

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("automonique-lab: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I, W>(arguments: I, mut output: W) -> Result<(), &'static str>
where
    I: IntoIterator<Item = OsString>,
    W: Write,
{
    let arguments = bounded_arguments(arguments)?;
    if arguments
        .first()
        .is_some_and(|value| value == "program-select")
    {
        return run_program_select(&arguments, &mut output);
    }
    run_serve_once(&arguments)
}

fn bounded_arguments<I>(arguments: I) -> Result<Vec<OsString>, &'static str>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iterator = arguments.into_iter();
    let mut bounded = Vec::with_capacity(13);
    for _ in 0..14 {
        let Some(argument) = iterator.next() else {
            return Ok(bounded);
        };
        if bounded.len() == 13 {
            return Err("too many arguments");
        }
        bounded.push(argument);
    }
    unreachable!("the bounded parser returns on its fourteenth argument")
}

fn run_serve_once(arguments: &[OsString]) -> Result<(), &'static str> {
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

fn run_program_select<W: Write>(
    arguments: &[OsString],
    output: &mut W,
) -> Result<(), &'static str> {
    if arguments.len() != 1 || arguments[0] != "program-select" {
        return Err("usage: automonique-lab program-select");
    }
    let proposal = select_admitted().map_err(|_| "program selection denied")?;
    if !proposal.autonomous_eligible() {
        return Err("program selection is not autonomous-eligible");
    }
    let budget = proposal.budget();
    let document = serde_json::json!({
        "schema": "automonique.lab-proposal/v1",
        "immutableBase": proposal.immutable_base().as_str(),
        "runId": proposal.run_id().as_str(),
        "packetPath": proposal.packet_path().as_str(),
        "packetSha256": proposal.packet_digest().as_str(),
        "workId": proposal.work_id().as_str(),
        "objectiveId": proposal.objective_id().as_str(),
        "objective": proposal.objective(),
        "graphSha256": proposal.graph_digest().as_str(),
        "programSha256": proposal.program_digest().as_str(),
        "objectivesSha256": proposal.objectives_digest().as_str(),
        "guidesSha256": proposal.guides_digest().as_str(),
        "dependencies": proposal.dependencies().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "allowedPaths": proposal.allowed_paths().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "budget": {
            "maxIterations": budget.max_iterations(),
            "maxWallSeconds": budget.max_wall_seconds(),
            "maxWorkerSeconds": budget.max_worker_seconds(),
            "maxUnchangedResults": budget.max_unchanged_results(),
            "maxFailures": budget.max_failures(),
        },
        "licence": proposal.licence(),
        "autonomousEligible": proposal.autonomous_eligible(),
    });
    serde_json::to_writer(&mut *output, &document).map_err(|_| "could not encode proposal")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write proposal")
}

#[cfg(test)]
mod tests {
    use super::bounded_arguments;
    use std::cell::Cell;
    use std::ffi::OsString;

    #[test]
    fn argument_parsing_stops_after_one_bounded_extra_sentinel() {
        let polls = Cell::new(0usize);
        let iterator = std::iter::from_fn(|| {
            let next = polls.get() + 1;
            polls.set(next);
            assert!(next <= 14, "bounded parser polled too many arguments");
            Some(OsString::from("extra"))
        });
        assert!(bounded_arguments(iterator).is_err());
        assert_eq!(polls.get(), 14);
    }
}
