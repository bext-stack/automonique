// SPDX-License-Identifier: Elastic-2.0

//! Bounded execution of an owner-approved self-improvement plan.
//!
//! GitHub credentials and integration authority deliberately do not enter this
//! module. It creates a detached worktree at the approved source revision,
//! lets the pinned App Server edit only that worktree, runs host-selected
//! checks, and creates a local candidate commit. A separate host broker may
//! publish that exact commit and ask for the release approval.

use std::error::Error;
use std::fmt;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

use crate::codex_app_server::{
    CodexAppServer, CodexAppServerConfig, CodexAppServerError, CodexTurnResult,
};

const MAX_PLAN_BYTES: usize = 128 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const CANDIDATE_NAME: &str = "Automonique Candidate";
const CANDIDATE_EMAIL: &str = "candidate@automonique.invalid";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexRuntimePin {
    pub binary: PathBuf,
    pub binary_sha256: String,
    pub codex_home: PathBuf,
    pub cargo_home: PathBuf,
    pub rustup_home: PathBuf,
    pub model: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementExecutionRequest {
    pub public_id: String,
    pub revision: u64,
    pub source_base_sha: String,
    pub plan_digest: String,
    pub plan_markdown: String,
}

impl ImprovementExecutionRequest {
    pub fn validate(&self) -> Result<(), ImprovementExecutionError> {
        validate_public_id(&self.public_id)?;
        if self.revision == 0 {
            return Err(ImprovementExecutionError::InvalidInput("revision"));
        }
        validate_object_id(&self.source_base_sha)?;
        let approved_digest = self
            .plan_digest
            .strip_prefix("sha256:")
            .unwrap_or(&self.plan_digest);
        validate_digest(approved_digest, "plan digest")?;
        if self.plan_markdown.trim().is_empty()
            || self.plan_markdown.len() > MAX_PLAN_BYTES
            || self.plan_markdown.contains('\0')
        {
            return Err(ImprovementExecutionError::InvalidInput("plan markdown"));
        }
        let actual = hex::encode(Sha256::digest(self.plan_markdown.as_bytes()));
        if actual != approved_digest {
            return Err(ImprovementExecutionError::PlanDigestMismatch);
        }
        Ok(())
    }
}

/// Where a verification recipe runs, relative to the candidate worktree. The
/// Cargo gates run in `rust/`; the repository-wide checkers read paths from the
/// worktree root and refuse to run anywhere else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipeDir {
    RustWorkspace,
    RepositoryRoot,
}

/// One verification gate, spelled exactly as the required CI job spells it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recipe {
    pub label: &'static str,
    pub program: &'static str,
    pub args: &'static [&'static str],
    pub dir: RecipeDir,
}

/// The check-run names the required CI jobs publish. A gate that is renamed,
/// deleted or never triggered has to be visible on both sides of the pipeline:
/// here it scopes which workflow jobs the drift test reads, and the release
/// gate treats a name missing from a commit's check runs as a refusal rather
/// than as a pass.
pub const REQUIRED_CI_CHECKS: &[&str] = &["workspace", "licence-boundary", "development-scrub"];

/// The gates a candidate must pass locally, in the order and spelling the
/// required CI jobs use. `tests::recipes_match_the_required_ci_jobs` fails when
/// this table and those jobs disagree in either direction, so a gate added to
/// CI cannot silently stop applying to candidates and vice versa.
pub const CI_VERIFICATION_RECIPES: &[Recipe] = &[
    Recipe {
        label: "cargo fmt --all -- --check",
        program: "cargo",
        args: &["fmt", "--all", "--", "--check"],
        dir: RecipeDir::RustWorkspace,
    },
    Recipe {
        label: "cargo check --workspace --all-targets --offline --locked",
        program: "cargo",
        args: &[
            "check",
            "--workspace",
            "--all-targets",
            "--offline",
            "--locked",
        ],
        dir: RecipeDir::RustWorkspace,
    },
    Recipe {
        label: "cargo test --workspace --all-targets --offline --locked",
        program: "cargo",
        args: &[
            "test",
            "--workspace",
            "--all-targets",
            "--offline",
            "--locked",
        ],
        dir: RecipeDir::RustWorkspace,
    },
    Recipe {
        label: "cargo clippy --workspace --all-targets --offline --locked -- -D warnings",
        program: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--offline",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        dir: RecipeDir::RustWorkspace,
    },
    Recipe {
        label: "python3 tools/check_licenses.py",
        program: "python3",
        args: &["tools/check_licenses.py"],
        dir: RecipeDir::RepositoryRoot,
    },
    Recipe {
        label: "python3 tools/scrub/scan.py",
        program: "python3",
        args: &["tools/scrub/scan.py"],
        dir: RecipeDir::RepositoryRoot,
    },
    Recipe {
        label: "python3 plan/check.py --identifiers",
        program: "python3",
        args: &["plan/check.py", "--identifiers"],
        dir: RecipeDir::RepositoryRoot,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationProfile {
    /// The full required-CI gate set, `CI_VERIFICATION_RECIPES`.
    RustWorkspace,
    /// Exactly these recipes. Tests use it to observe what state a recipe is
    /// handed; the daemon always selects `RustWorkspace`.
    Recipes(&'static [Recipe]),
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckReceipt {
    pub command: &'static str,
    pub succeeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementExecutionReceipt {
    pub public_id: String,
    pub revision: u64,
    pub source_base_sha: String,
    pub plan_digest: String,
    pub candidate_sha: String,
    pub candidate_tree: String,
    pub changed_paths: Vec<String>,
    pub checks: Vec<CheckReceipt>,
    pub thread_id: String,
    pub turn_id: String,
    pub worktree: PathBuf,
}

pub trait ImprovementAgent {
    fn implement(
        &mut self,
        worktree: &Path,
        developer_instructions: &str,
        plan_prompt: &str,
    ) -> Result<CodexTurnResult, ImprovementExecutionError>;
}

#[derive(Clone, Debug)]
pub struct PinnedCodexAgent {
    pin: CodexRuntimePin,
}

impl PinnedCodexAgent {
    #[must_use]
    pub const fn new(pin: CodexRuntimePin) -> Self {
        Self { pin }
    }
}

impl ImprovementAgent for PinnedCodexAgent {
    fn implement(
        &mut self,
        worktree: &Path,
        developer_instructions: &str,
        plan_prompt: &str,
    ) -> Result<CodexTurnResult, ImprovementExecutionError> {
        let config = CodexAppServerConfig::verify(
            &self.pin.binary,
            &self.pin.binary_sha256,
            worktree,
            &self.pin.codex_home,
            &self.pin.cargo_home,
            &self.pin.rustup_home,
            &self.pin.model,
        )?;
        let mut server = CodexAppServer::spawn(&config)?;
        let thread = server.start_thread(developer_instructions)?;
        server.run_turn(&thread, plan_prompt).map_err(Into::into)
    }
}

#[derive(Debug)]
pub struct ImprovementExecutor<A> {
    repository: PathBuf,
    worktree_root: PathBuf,
    verification: VerificationProfile,
    agent: A,
}

impl<A: ImprovementAgent> ImprovementExecutor<A> {
    pub fn open(
        repository: impl AsRef<Path>,
        worktree_root: impl AsRef<Path>,
        verification: VerificationProfile,
        agent: A,
    ) -> Result<Self, ImprovementExecutionError> {
        let repository = canonical_git_repository(repository.as_ref())?;
        let worktree_root = private_directory(worktree_root.as_ref())?;
        if worktree_root.starts_with(&repository) || repository.starts_with(&worktree_root) {
            return Err(ImprovementExecutionError::UnsafePath("worktree overlap"));
        }
        Ok(Self {
            repository,
            worktree_root,
            verification,
            agent,
        })
    }

    pub fn execute(
        &mut self,
        request: &ImprovementExecutionRequest,
    ) -> Result<ImprovementExecutionReceipt, ImprovementExecutionError> {
        request.validate()?;
        verify_object(&self.repository, &request.source_base_sha)?;
        let plan_component = request
            .plan_digest
            .strip_prefix("sha256:")
            .unwrap_or(&request.plan_digest);
        let worktree = self.worktree_root.join(format!(
            "{}-r{}-{}",
            request.public_id.to_ascii_lowercase(),
            request.revision,
            &plan_component[..16]
        ));
        if worktree.exists() {
            return Err(ImprovementExecutionError::AttemptExists);
        }
        run_checked(
            Command::new("git")
                .arg("-C")
                .arg(&self.repository)
                .args(["worktree", "add", "--detach"])
                .arg(&worktree)
                .arg(&request.source_base_sha),
            "git worktree add",
        )?;
        let actual_base = git_text(&worktree, &["rev-parse", "HEAD"])?;
        if actual_base != request.source_base_sha {
            return Err(ImprovementExecutionError::BaseMoved);
        }

        let developer_instructions = concat!(
            "Implement only the approved Automonique plan supplied by the user. ",
            "Treat repository AGENTS.md files as binding. This is a clean-room repository: ",
            "use only checked-in files, owner-authorized structural references, public standards, ",
            "and permitted dependencies. Do not access credentials, GitHub, deployment systems, ",
            "production infrastructure, or files outside the mounted worktree. Do not commit or ",
            "push. Make the smallest coherent change and run useful local checks; the host will ",
            "independently verify and commit the candidate."
        );
        let prompt = format!(
            "Approved improvement: {}\nApproved source base: {}\nApproved plan SHA-256: {}\n\n{}",
            request.public_id, request.source_base_sha, request.plan_digest, request.plan_markdown
        );
        let turn = self
            .agent
            .implement(&worktree, developer_instructions, &prompt)?;

        ensure_no_commit(&worktree, &request.source_base_sha)?;
        if changed_paths(&worktree)?.is_empty() {
            return Err(ImprovementExecutionError::NoChanges);
        }
        // Stage before verifying. `tools/scrub/scan.py` reads content through
        // the index, so a scan run against an unstaged worktree would inspect
        // the approved base and pass without ever seeing the candidate's edits.
        // Staging first is safe: `ensure_no_commit` above already refused a
        // candidate that created a commit, and the `status_is_clean` assertion
        // after the commit still catches anything a check left behind.
        run_checked(
            Command::new("git")
                .arg("-C")
                .arg(&worktree)
                .args(["add", "--all"]),
            "git add",
        )?;
        let checks = run_checks(&worktree, self.verification)?;
        run_checked(
            Command::new("git")
                .arg("-C")
                .arg(&worktree)
                .args(["-c", &format!("user.name={CANDIDATE_NAME}")])
                .args(["-c", &format!("user.email={CANDIDATE_EMAIL}")])
                .args(["commit", "--no-gpg-sign", "-m"])
                .arg(format!(
                    "Implement {} approved improvement",
                    request.public_id
                )),
            "git commit",
        )?;
        let candidate_sha = git_text(&worktree, &["rev-parse", "HEAD"])?;
        let candidate_tree = git_text(&worktree, &["rev-parse", "HEAD^{tree}"])?;
        let changed_paths = committed_paths(&worktree, &request.source_base_sha, &candidate_sha)?;
        validate_object_id(&candidate_sha)?;
        validate_object_id(&candidate_tree)?;
        if candidate_sha == request.source_base_sha || !status_is_clean(&worktree)? {
            return Err(ImprovementExecutionError::CandidateMismatch);
        }
        Ok(ImprovementExecutionReceipt {
            public_id: request.public_id.clone(),
            revision: request.revision,
            source_base_sha: request.source_base_sha.clone(),
            plan_digest: request.plan_digest.clone(),
            candidate_sha,
            candidate_tree,
            changed_paths,
            checks,
            thread_id: turn.thread_id,
            turn_id: turn.turn_id,
            worktree,
        })
    }
}

fn run_checks(
    worktree: &Path,
    profile: VerificationProfile,
) -> Result<Vec<CheckReceipt>, ImprovementExecutionError> {
    let recipes = match profile {
        VerificationProfile::None => return Ok(Vec::new()),
        VerificationProfile::RustWorkspace => CI_VERIFICATION_RECIPES,
        VerificationProfile::Recipes(recipes) => recipes,
    };
    let rust = worktree.join("rust");
    if recipes
        .iter()
        .any(|recipe| recipe.dir == RecipeDir::RustWorkspace)
        && !rust.join("Cargo.toml").is_file()
    {
        return Err(ImprovementExecutionError::CheckFailed(
            "rust workspace missing",
        ));
    }
    let mut receipts = Vec::with_capacity(recipes.len());
    for recipe in recipes {
        let directory = match recipe.dir {
            RecipeDir::RustWorkspace => rust.as_path(),
            RecipeDir::RepositoryRoot => worktree,
        };
        let succeeded = bounded_output(
            Command::new(recipe.program)
                .current_dir(directory)
                .args(recipe.args)
                .stdin(Stdio::null()),
        )?
        .status
        .success();
        receipts.push(CheckReceipt {
            command: recipe.label,
            succeeded,
        });
        if !succeeded {
            return Err(ImprovementExecutionError::CheckFailed(recipe.label));
        }
    }
    Ok(receipts)
}

fn canonical_git_repository(path: &Path) -> Result<PathBuf, ImprovementExecutionError> {
    let path = fs::canonicalize(path).map_err(ImprovementExecutionError::Io)?;
    if !path.is_dir() || !path.join(".git").exists() {
        return Err(ImprovementExecutionError::UnsafePath("repository"));
    }
    Ok(path)
}

fn private_directory(path: &Path) -> Result<PathBuf, ImprovementExecutionError> {
    if !path.is_absolute() {
        return Err(ImprovementExecutionError::UnsafePath("worktree root"));
    }
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(ImprovementExecutionError::Io)?;
    }
    let path = fs::canonicalize(path).map_err(ImprovementExecutionError::Io)?;
    let metadata = fs::metadata(&path).map_err(ImprovementExecutionError::Io)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ImprovementExecutionError::UnsafePath("worktree root"));
    }
    Ok(path)
}

fn verify_object(repository: &Path, object: &str) -> Result<(), ImprovementExecutionError> {
    let expression = format!("{object}^{{commit}}");
    let actual = git_text(repository, &["rev-parse", "--verify", &expression])?;
    if actual != object {
        return Err(ImprovementExecutionError::BaseMoved);
    }
    Ok(())
}

fn ensure_no_commit(worktree: &Path, base: &str) -> Result<(), ImprovementExecutionError> {
    if git_text(worktree, &["rev-parse", "HEAD"])? != base {
        return Err(ImprovementExecutionError::CandidateCommitted);
    }
    Ok(())
}

fn changed_paths(worktree: &Path) -> Result<Vec<String>, ImprovementExecutionError> {
    let output = bounded_output(Command::new("git").arg("-C").arg(worktree).args([
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ]))?;
    if !output.status.success() {
        return Err(ImprovementExecutionError::CommandFailed("git status"));
    }
    let mut paths = Vec::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|v| !v.is_empty())
    {
        if entry.len() < 4 || entry[2] != b' ' {
            return Err(ImprovementExecutionError::CandidateMismatch);
        }
        let path = std::str::from_utf8(&entry[3..])
            .map_err(|_| ImprovementExecutionError::CandidateMismatch)?;
        validate_repo_path(path)?;
        paths.push(path.to_owned());
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn status_is_clean(worktree: &Path) -> Result<bool, ImprovementExecutionError> {
    let output = bounded_output(
        Command::new("git")
            .arg("-C")
            .arg(worktree)
            .args(["status", "--porcelain=v1"]),
    )?;
    Ok(output.status.success() && output.stdout.is_empty())
}

fn committed_paths(
    worktree: &Path,
    base: &str,
    candidate: &str,
) -> Result<Vec<String>, ImprovementExecutionError> {
    let output = bounded_output(Command::new("git").arg("-C").arg(worktree).args([
        "diff",
        "--name-only",
        "-z",
        base,
        candidate,
    ]))?;
    if !output.status.success() {
        return Err(ImprovementExecutionError::CommandFailed("git diff"));
    }
    let mut paths = Vec::new();
    for path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|v| !v.is_empty())
    {
        let path =
            std::str::from_utf8(path).map_err(|_| ImprovementExecutionError::CandidateMismatch)?;
        validate_repo_path(path)?;
        paths.push(path.to_owned());
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(ImprovementExecutionError::NoChanges);
    }
    Ok(paths)
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, ImprovementExecutionError> {
    let output = bounded_output(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments),
    )?;
    if !output.status.success() {
        return Err(ImprovementExecutionError::CommandFailed("git query"));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ImprovementExecutionError::CommandFailed("git output"))?
        .trim();
    if text.is_empty() {
        return Err(ImprovementExecutionError::CommandFailed("git output"));
    }
    Ok(text.to_owned())
}

fn run_checked(
    command: &mut Command,
    label: &'static str,
) -> Result<(), ImprovementExecutionError> {
    if !bounded_output(command)?.status.success() {
        return Err(ImprovementExecutionError::CommandFailed(label));
    }
    Ok(())
}

fn bounded_output(command: &mut Command) -> Result<Output, ImprovementExecutionError> {
    let output = command.output().map_err(ImprovementExecutionError::Io)?;
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_GIT_OUTPUT_BYTES {
        return Err(ImprovementExecutionError::CommandOutputExceeded);
    }
    Ok(output)
}

fn validate_public_id(value: &str) -> Result<(), ImprovementExecutionError> {
    if value.len() != 10
        || !value.starts_with("IMP-")
        || !value[4..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ImprovementExecutionError::InvalidInput("public id"));
    }
    Ok(())
}

fn validate_object_id(value: &str) -> Result<(), ImprovementExecutionError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ImprovementExecutionError::InvalidInput("git object id"));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ImprovementExecutionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ImprovementExecutionError::InvalidInput(field));
    }
    Ok(())
}

fn validate_repo_path(value: &str) -> Result<(), ImprovementExecutionError> {
    if value.is_empty()
        || value.len() > 4_096
        || value.starts_with('/')
        || value.contains('\0')
        || value.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(ImprovementExecutionError::CandidateMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub enum ImprovementExecutionError {
    InvalidInput(&'static str),
    UnsafePath(&'static str),
    PlanDigestMismatch,
    AttemptExists,
    BaseMoved,
    CandidateCommitted,
    NoChanges,
    CandidateMismatch,
    CommandFailed(&'static str),
    CommandOutputExceeded,
    CheckFailed(&'static str),
    Io(std::io::Error),
    AppServer(CodexAppServerError),
}

impl fmt::Display for ImprovementExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid improvement input: {field}"),
            Self::UnsafePath(field) => write!(formatter, "unsafe improvement path: {field}"),
            Self::PlanDigestMismatch => formatter.write_str("approved plan digest mismatch"),
            Self::AttemptExists => formatter.write_str("improvement attempt already exists"),
            Self::BaseMoved => formatter.write_str("approved source base is unavailable or moved"),
            Self::CandidateCommitted => {
                formatter.write_str("candidate attempted to create a commit")
            }
            Self::NoChanges => formatter.write_str("candidate produced no changes"),
            Self::CandidateMismatch => {
                formatter.write_str("candidate worktree failed verification")
            }
            Self::CommandFailed(command) => {
                write!(formatter, "improvement command failed: {command}")
            }
            Self::CommandOutputExceeded => {
                formatter.write_str("improvement command output exceeded limit")
            }
            Self::CheckFailed(command) => write!(formatter, "candidate check failed: {command}"),
            Self::Io(error) => write!(formatter, "improvement I/O failed: {error}"),
            Self::AppServer(error) => write!(formatter, "improvement App Server failed: {error}"),
        }
    }
}

impl Error for ImprovementExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::AppServer(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodexAppServerError> for ImprovementExecutionError {
    fn from(value: CodexAppServerError) -> Self {
        Self::AppServer(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    /// The workflow file each required check run is defined by. The job key is
    /// also the check-run name GitHub publishes, which is why one constant can
    /// serve both the drift test and the release gate's required-check set.
    const REQUIRED_JOBS: &[(&str, &str)] = &[
        ("rust.yml", "workspace"),
        ("plan.yml", "licence-boundary"),
        ("scrub.yml", "development-scrub"),
    ];

    /// Command lines inside the required jobs that are deliberately not
    /// candidate gates. Every entry has to say why, and every entry has to
    /// still appear in the workflow — an allowlist nobody can see rotting is
    /// how the drift test would quietly stop meaning anything.
    const CI_ONLY: &[(&str, &str)] = &[
        (
            "cargo fetch --locked",
            "populates the offline cache the gates below then use; a prerequisite, not a gate",
        ),
        (
            "cargo metadata --no-deps --offline --locked --format-version 1 >/dev/null",
            "manifest parse only, wholly subsumed by the `cargo check` gate beside it",
        ),
        (
            "cargo generate-lockfile --offline",
            "the lockfile-reproducibility probe; it rewrites Cargo.lock, so it needs the scratch copy CI takes outside the tree and must not run against a candidate worktree",
        ),
        (
            "python3 -m unittest -v tools.test_check_licenses",
            "negative controls for the licence checker itself, not a property of the candidate's tree",
        ),
        (
            "python3 -m unittest discover -s tools/scrub -p 'test_*.py'",
            "negative controls for the scrub scanner itself, as above",
        ),
    ];

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("repository root above rust/crates/<crate>")
            .to_path_buf()
    }

    /// Every `cargo …` and `python3 …` line inside one workflow job. A job ends
    /// at the next key indented by exactly two spaces, which is how these three
    /// workflows separate jobs.
    fn job_commands(workflow: &str, job: &str) -> Vec<String> {
        let path = repository_root().join(".github/workflows").join(workflow);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("required workflow {}: {error}", path.display()));
        let mut lines = text.lines();
        lines
            .by_ref()
            .find(|line| line.trim_end() == format!("  {job}:"))
            .unwrap_or_else(|| panic!("workflow {workflow} no longer defines job {job}"));
        let mut commands = Vec::new();
        for line in lines {
            let is_next_job = line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim().starts_with('-');
            if is_next_job {
                break;
            }
            // A step spells its command either inline (`run: cargo …`) or as a
            // block scalar whose body lines carry no key.
            let trimmed = line.trim();
            let command = trimmed.strip_prefix("run:").map_or(trimmed, str::trim);
            if command.starts_with("cargo ") || command.starts_with("python3 ") {
                commands.push(command.to_owned());
            }
        }
        commands
    }

    #[test]
    fn recipe_labels_spell_the_command_they_run() {
        for recipe in CI_VERIFICATION_RECIPES {
            let spelled = std::iter::once(recipe.program)
                .chain(recipe.args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(recipe.label, spelled, "recipe label is not what it runs");
        }
    }

    #[test]
    fn recipes_match_the_required_ci_jobs() {
        let jobs = REQUIRED_JOBS
            .iter()
            .map(|(_, job)| *job)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            jobs,
            REQUIRED_CI_CHECKS.iter().copied().collect::<BTreeSet<_>>(),
            "the required-check set and the jobs this test reads disagree"
        );

        let mut workflow_gates = BTreeSet::new();
        for (workflow, job) in REQUIRED_JOBS {
            workflow_gates.extend(job_commands(workflow, job));
        }
        for (line, why) in CI_ONLY {
            assert!(
                workflow_gates.remove(*line),
                "allowlisted line is no longer in any required job, so its reason has expired: {line} ({why})"
            );
        }

        let recipes = CI_VERIFICATION_RECIPES
            .iter()
            .map(|recipe| recipe.label.to_owned())
            .collect::<BTreeSet<_>>();
        let missing_from_recipes = workflow_gates.difference(&recipes).collect::<Vec<_>>();
        let missing_from_ci = recipes.difference(&workflow_gates).collect::<Vec<_>>();
        assert!(
            missing_from_recipes.is_empty(),
            "CI gates the candidate never runs: {missing_from_recipes:?}"
        );
        assert!(
            missing_from_ci.is_empty(),
            "candidate gates no required CI job runs: {missing_from_ci:?}"
        );
    }

    #[derive(Debug)]
    struct FakeAgent {
        path: String,
        contents: String,
        commit: bool,
    }

    impl ImprovementAgent for FakeAgent {
        fn implement(
            &mut self,
            worktree: &Path,
            _developer_instructions: &str,
            _plan_prompt: &str,
        ) -> Result<CodexTurnResult, ImprovementExecutionError> {
            fs::write(worktree.join(&self.path), &self.contents)
                .map_err(ImprovementExecutionError::Io)?;
            if self.commit {
                run_checked(
                    Command::new("git")
                        .arg("-C")
                        .arg(worktree)
                        .args(["add", "--all"]),
                    "fake add",
                )?;
                run_checked(
                    Command::new("git")
                        .arg("-C")
                        .arg(worktree)
                        .args(["-c", "user.name=fake", "-c", "user.email=fake.invalid"])
                        .args(["commit", "-m", "forbidden"]),
                    "fake commit",
                )?;
            }
            Ok(CodexTurnResult {
                thread_id: "thread-1".to_owned(),
                turn_id: "turn-1".to_owned(),
                final_message: "done".to_owned(),
            })
        }
    }

    fn fixture(agent: FakeAgent) -> (TempDir, ImprovementExecutor<FakeAgent>, String) {
        fixture_with(agent, VerificationProfile::None)
    }

    fn fixture_with(
        agent: FakeAgent,
        verification: VerificationProfile,
    ) -> (TempDir, ImprovementExecutor<FakeAgent>, String) {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let repository = root.path().join("repository");
        fs::create_dir(&repository).expect("repository");
        run_checked(Command::new("git").arg("init").arg(&repository), "init").expect("init");
        fs::write(repository.join("README.md"), "base\n").expect("base");
        run_checked(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["add", "--all"]),
            "add",
        )
        .expect("add");
        run_checked(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["-c", "user.name=base", "-c", "user.email=base.invalid"])
                .args(["commit", "-m", "base"]),
            "commit",
        )
        .expect("commit");
        let base = git_text(&repository, &["rev-parse", "HEAD"]).expect("base sha");
        let worktrees = root.path().join("worktrees");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&worktrees)
            .expect("worktrees");
        let executor = ImprovementExecutor::open(&repository, &worktrees, verification, agent)
            .expect("executor");
        (root, executor, base)
    }

    fn request(base: String) -> ImprovementExecutionRequest {
        let plan = "# Approved plan\n\nChange README.\n".to_owned();
        ImprovementExecutionRequest {
            public_id: "IMP-000001".to_owned(),
            revision: 1,
            source_base_sha: base,
            plan_digest: format!("sha256:{}", hex::encode(Sha256::digest(plan.as_bytes()))),
            plan_markdown: plan,
        }
    }

    #[test]
    fn creates_a_verified_local_candidate_without_publishing_it() {
        let (_root, mut executor, base) = fixture(FakeAgent {
            path: "README.md".to_owned(),
            contents: "improved\n".to_owned(),
            commit: false,
        });
        let receipt = executor.execute(&request(base.clone())).expect("execute");
        assert_eq!(receipt.revision, 1);
        assert_eq!(receipt.source_base_sha, base);
        assert_ne!(receipt.candidate_sha, receipt.source_base_sha);
        assert_eq!(receipt.changed_paths, vec!["README.md"]);
        assert!(status_is_clean(&receipt.worktree).expect("status"));
        assert!(git_text(&receipt.worktree, &["remote"]).is_err());
        let identity =
            git_text(&receipt.worktree, &["show", "-s", "--format=%an <%ae>"]).expect("identity");
        assert_eq!(
            identity,
            "Automonique Candidate <candidate@automonique.invalid>"
        );
    }

    #[test]
    fn rejects_a_plan_whose_bytes_do_not_match_the_approval() {
        let (_root, mut executor, base) = fixture(FakeAgent {
            path: "README.md".to_owned(),
            contents: "improved\n".to_owned(),
            commit: false,
        });
        let mut request = request(base);
        request.plan_markdown.push_str("different");
        assert!(matches!(
            executor.execute(&request),
            Err(ImprovementExecutionError::PlanDigestMismatch)
        ));
    }

    /// The gates must see the candidate's bytes, not the approved base. This
    /// recipe exits non-zero exactly when the index differs from `HEAD`, so it
    /// fails only if staging happened first — which is the ordering the scrub
    /// gate depends on, since `tools/scrub/scan.py` reads through the index.
    const STAGED_PROBE: &[Recipe] = &[Recipe {
        label: "git diff --cached --quiet",
        program: "git",
        args: &["diff", "--cached", "--quiet"],
        dir: RecipeDir::RepositoryRoot,
    }];

    #[test]
    fn verification_recipes_run_against_the_staged_candidate() {
        let (_root, mut executor, base) = fixture_with(
            FakeAgent {
                path: "README.md".to_owned(),
                contents: "improved\n".to_owned(),
                commit: false,
            },
            VerificationProfile::Recipes(STAGED_PROBE),
        );
        assert!(matches!(
            executor.execute(&request(base)),
            Err(ImprovementExecutionError::CheckFailed(
                "git diff --cached --quiet"
            ))
        ));
    }

    #[test]
    fn refuses_a_candidate_that_commits_inside_the_sandbox() {
        let (_root, mut executor, base) = fixture(FakeAgent {
            path: "README.md".to_owned(),
            contents: "improved\n".to_owned(),
            commit: true,
        });
        assert!(matches!(
            executor.execute(&request(base)),
            Err(ImprovementExecutionError::CandidateCommitted)
        ));
    }
}
