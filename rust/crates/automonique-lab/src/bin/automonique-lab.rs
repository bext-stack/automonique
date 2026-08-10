// SPDX-License-Identifier: Elastic-2.0

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use automonique_lab::build::BuildBroker;
use automonique_lab::controller::{LabController, UnavailableBuildBroker};
use automonique_lab::framing::FrameLimits;
use automonique_lab::program::select_admitted;
use automonique_lab::protocol::GitSha1;
use automonique_lab::server::{UnixLabServer, UnixServerConfig};
use automonique_lab::state::AttemptState;
use automonique_lab::workspace_lease::RepoPath;
use automonique_lab::worktree::{Reconciliation, WorktreeState};
use nix::unistd::Uid;
use sha2::{Digest, Sha256};

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
    if arguments
        .first()
        .is_some_and(|value| value == "admit-worktree")
    {
        return run_admit_worktree(&arguments, &mut output);
    }
    if arguments
        .first()
        .is_some_and(|value| value == "serve-admitted-once")
    {
        return run_serve_admitted_once(&arguments);
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

fn run_admit_worktree<W: Write>(
    arguments: &[OsString],
    output: &mut W,
) -> Result<(), &'static str> {
    if arguments.len() != 1 || arguments[0] != "admit-worktree" {
        return Err("usage: automonique-lab admit-worktree");
    }
    let proposal = select_admitted().map_err(|_| "program selection denied")?;
    let expected_base =
        GitSha1::new(proposal.immutable_base().as_str()).map_err(|_| "admitted base is invalid")?;
    let paths = proposal
        .allowed_paths()
        .iter()
        .map(|path| RepoPath::parse(path.as_str().trim_end_matches('/')))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "admitted path set is invalid")?;
    let repository = std::env::current_dir().map_err(|_| "repository is unavailable")?;
    let runtime = admitted_runtime_paths(&repository)?;
    let mut controller =
        LabController::open(&runtime.state, expected_base, paths, UnavailableBuildBroker)
            .map_err(|_| "could not open durable controller")?;
    let selection = controller
        .select_admitted_worktree(&repository, &runtime.worktrees)
        .map_err(|_| "admitted worktree allocation denied")?;
    let attempt = selection.attempt();
    let worktree = selection.worktree();
    let document = serde_json::json!({
        "schema": "automonique.lab-admission/v1",
        "runId": selection.proposal().run_id().as_str(),
        "workId": selection.proposal().work_id().as_str(),
        "immutableBase": selection.proposal().immutable_base().as_str(),
        "attempt": {
            "state": attempt_state(attempt.state()),
            "revision": attempt.revision().get(),
            "lastSequence": attempt.last_sequence(),
        },
        "worktree": {
            "state": worktree_state(worktree.state()),
            "reconciliation": reconciliation(worktree.reconciliation()),
            "requestDigest": worktree.request_digest(),
            "materializedBytes": worktree.materialized_bytes(),
        },
    });
    serde_json::to_writer(&mut *output, &document)
        .map_err(|_| "could not encode admission receipt")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write admission receipt")
}

fn run_serve_admitted_once(arguments: &[OsString]) -> Result<(), &'static str> {
    if arguments.len() != 1 || arguments[0] != "serve-admitted-once" {
        return Err("usage: automonique-lab serve-admitted-once");
    }
    let proposal = select_admitted().map_err(|_| "program selection denied")?;
    let expected_base =
        GitSha1::new(proposal.immutable_base().as_str()).map_err(|_| "admitted base is invalid")?;
    let paths = proposal
        .allowed_paths()
        .iter()
        .map(|path| RepoPath::parse(path.as_str().trim_end_matches('/')))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "admitted path set is invalid")?;
    let repository = std::env::current_dir().map_err(|_| "repository is unavailable")?;
    let runtime = admitted_runtime_paths(&repository)?;
    let mut controller =
        LabController::open(&runtime.state, expected_base, paths, UnavailableBuildBroker)
            .map_err(|_| "could not open durable controller")?;
    controller
        .select_admitted_worktree(&repository, &runtime.worktrees)
        .map_err(|_| "admitted worktree allocation denied")?;
    let mut server = UnixLabServer::bind(
        UnixServerConfig {
            socket_path: runtime.socket,
            frame_limits: FrameLimits::new(1024 * 1024).map_err(|_| "invalid frame bound")?,
            io_timeout: Duration::from_secs(5),
        },
        controller,
    )
    .map_err(|_| "could not bind admitted local server")?;
    server.serve_once().map_err(|_| "request failed")
}

struct AdmittedRuntimePaths {
    state: PathBuf,
    worktrees: PathBuf,
    socket: PathBuf,
}

fn admitted_runtime_paths(repository: &Path) -> Result<AdmittedRuntimePaths, &'static str> {
    let repository = repository
        .canonicalize()
        .map_err(|_| "repository is unavailable")?;
    let uid = Uid::effective().as_raw();
    let user_runtime = PathBuf::from("/run/user").join(uid.to_string());
    verify_private_runtime_directory(&user_runtime)?;
    let automonique = private_runtime_child(&user_runtime, "automonique")?;
    let lab = private_runtime_child(&automonique, "l")?;
    let repository_id = hex::encode(Sha256::digest(repository.as_os_str().as_bytes()));
    let root = private_runtime_child(&lab, &repository_id)?;
    Ok(AdmittedRuntimePaths {
        state: root.join("state.sqlite3"),
        worktrees: root.join("worktrees"),
        socket: root.join("s"),
    })
}

fn private_runtime_child(parent: &Path, name: &str) -> Result<PathBuf, &'static str> {
    let path = parent.join(name);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("private runtime directory could not be created"),
    }
    verify_private_runtime_directory(&path)?;
    Ok(path)
}

fn verify_private_runtime_directory(path: &Path) -> Result<(), &'static str> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "private runtime directory is unavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("private runtime directory is unsafe");
    }
    Ok(())
}

const fn attempt_state(value: AttemptState) -> &'static str {
    match value {
        AttemptState::Queued => "queued",
        AttemptState::Running => "running",
        AttemptState::Paused => "paused",
        AttemptState::Succeeded => "succeeded",
        AttemptState::Failed => "failed",
        AttemptState::Blocked => "blocked",
        AttemptState::Cancelled => "cancelled",
    }
}

const fn worktree_state(value: WorktreeState) -> &'static str {
    match value {
        WorktreeState::Allocated => "allocated",
        WorktreeState::Released => "released",
    }
}

const fn reconciliation(value: Reconciliation) -> &'static str {
    match value {
        Reconciliation::Applied => "applied",
        Reconciliation::Replayed => "replayed",
        Reconciliation::Recovered => "recovered",
    }
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
