// SPDX-License-Identifier: Elastic-2.0

//! Bounded loading and exact selection from the generated development program.

use crate::protocol::{BoundedText, GitSha1, JsUInt, OpaqueId, Sha256Digest};
use crate::workspace_lease::RepoPath;
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{close, read};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PROGRAM_SCHEMA: &str = "automonique.dev-program/v1";
const OBJECTIVES_SCHEMA: &str = "automonique.dev-objectives/v1";
const PROGRAM_HEADER: &[u8] = b"# SPDX-License-Identifier: Elastic-2.0\n";
const MAX_PROGRAM_BYTES: usize = 512 * 1024;
const MAX_OBJECTIVES_BYTES: usize = 128 * 1024;
const MAX_PACKET_BYTES: usize = 64 * 1024;
const MAX_GRAPH_BYTES: usize = 512 * 1024;
const MAX_GUIDES_BYTES: usize = 128 * 1024;
const MAX_LOOP_STATE_BYTES: usize = 32 * 1024;
const MAX_ITEMS: usize = 1_024;
const MAX_COLLECTION: usize = 1_024;
const MAX_TEXT: usize = 8_192;

/// A validated proposal budget from the generated objective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalBudget {
    max_iterations: u64,
    max_wall_seconds: u64,
    max_worker_seconds: u64,
    max_unchanged_results: u64,
    max_failures: u64,
}

impl ProposalBudget {
    #[must_use]
    pub const fn max_iterations(self) -> u64 {
        self.max_iterations
    }
    #[must_use]
    pub const fn max_wall_seconds(self) -> u64 {
        self.max_wall_seconds
    }
    #[must_use]
    pub const fn max_worker_seconds(self) -> u64 {
        self.max_worker_seconds
    }
    #[must_use]
    pub const fn max_unchanged_results(self) -> u64 {
        self.max_unchanged_results
    }
    #[must_use]
    pub const fn max_failures(self) -> u64 {
        self.max_failures
    }
}

/// An exact, validated path lease token.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProposalPath(String);

impl ProposalPath {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed data that can later be handed to the controller for a proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnableProposal {
    immutable_base: GitSha1,
    run_id: OpaqueId,
    packet_path: ProposalPath,
    packet_digest: Sha256Digest,
    work_id: OpaqueId,
    objective_id: OpaqueId,
    objective: BoundedText,
    graph_digest: Sha256Digest,
    program_digest: Sha256Digest,
    objectives_digest: Sha256Digest,
    guides_digest: Sha256Digest,
    dependencies: Vec<OpaqueId>,
    allowed_paths: Vec<ProposalPath>,
    budget: ProposalBudget,
    licence: String,
    autonomous_eligible: bool,
}

impl RunnableProposal {
    #[must_use]
    pub fn immutable_base(&self) -> &GitSha1 {
        &self.immutable_base
    }
    #[must_use]
    pub fn run_id(&self) -> &OpaqueId {
        &self.run_id
    }
    #[must_use]
    pub fn packet_path(&self) -> &ProposalPath {
        &self.packet_path
    }
    #[must_use]
    pub fn packet_digest(&self) -> &Sha256Digest {
        &self.packet_digest
    }
    #[must_use]
    pub fn work_id(&self) -> &OpaqueId {
        &self.work_id
    }
    #[must_use]
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    #[must_use]
    pub fn objective(&self) -> &str {
        self.objective.as_str()
    }
    #[must_use]
    pub fn graph_digest(&self) -> &Sha256Digest {
        &self.graph_digest
    }
    #[must_use]
    pub fn program_digest(&self) -> &Sha256Digest {
        &self.program_digest
    }
    #[must_use]
    pub fn objectives_digest(&self) -> &Sha256Digest {
        &self.objectives_digest
    }
    #[must_use]
    pub fn guides_digest(&self) -> &Sha256Digest {
        &self.guides_digest
    }
    #[must_use]
    pub fn dependencies(&self) -> &[OpaqueId] {
        &self.dependencies
    }
    #[must_use]
    pub fn allowed_paths(&self) -> &[ProposalPath] {
        &self.allowed_paths
    }
    #[must_use]
    pub const fn budget(&self) -> ProposalBudget {
        self.budget
    }
    #[must_use]
    pub fn licence(&self) -> &str {
        &self.licence
    }
    #[must_use]
    pub const fn autonomous_eligible(&self) -> bool {
        self.autonomous_eligible
    }
}

/// Closed failure classes for loading or selecting generated proposal data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramError {
    MissingInput,
    UnsafeInput,
    InputTooLarge,
    InvalidJson,
    InvalidPacket(&'static str),
    InvalidProgram(&'static str),
    InvalidObjectives(&'static str),
    GraphDigestMismatch,
    PacketDigestMismatch,
    GuidesDigestMismatch,
    ProgramDigestMismatch,
    ObjectivesDigestMismatch,
    UnknownWork,
    NotRunnable,
    ObjectiveMissing,
}

impl fmt::Display for ProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "development program error: {self:?}")
    }
}

impl Error for ProgramError {}

/// Verify the current repository's fixed harness claim and select its exact objective.
pub fn select_admitted() -> Result<RunnableProposal, ProgramError> {
    let repository_root = git_repository_root()?;
    let state_path = repository_root.join(".automonique/state/harness-loop.json");
    let state_bytes = read_bounded_regular(&state_path, MAX_LOOP_STATE_BYTES)?;
    let state_value = parse_json(&state_bytes)?;
    let state = parse_harness_state(&state_value)?;
    verify_git_state(&repository_root, &state.immutable_base)?;
    let expected_packet_path = format!(
        ".automonique/state/runs/{}/packet.json",
        state.run_id.as_str()
    );
    if state.packet_path.as_str() != expected_packet_path {
        return Err(ProgramError::InvalidPacket("state packet path"));
    }
    let packet_path = repository_root.join(state.packet_path.as_str());
    let expected_packet_digest = &state.packet_digest;
    let packet_bytes = read_bounded_regular(&packet_path, MAX_PACKET_BYTES)?;
    let packet_digest = digest_bytes(&packet_bytes)?;
    if &packet_digest != expected_packet_digest {
        return Err(ProgramError::PacketDigestMismatch);
    }
    let packet_value = parse_json(&packet_bytes)?;
    let packet = parse_packet(&packet_value)?;
    if packet.immutable_base != state.immutable_base
        || packet.run_id != state.run_id
        || packet.work_id != state.work_id
    {
        return Err(ProgramError::InvalidPacket("state binding"));
    }
    let packet_repo_path = state.packet_path;
    let graph_path = repository_root.join("plan/work-graph.toml");
    let program_path = repository_root.join(".automonique/dev/program.yaml");
    let objectives_path = repository_root.join(".automonique/dev/objectives.json");
    let guides_path = repository_root.join(".automonique/dev/guides/manifest.json");

    let graph_bytes = read_bounded_regular(&graph_path, MAX_GRAPH_BYTES)?;
    let program_bytes = read_bounded_regular(&program_path, MAX_PROGRAM_BYTES)?;
    let objectives_bytes = read_bounded_regular(&objectives_path, MAX_OBJECTIVES_BYTES)?;
    let guides_bytes = read_bounded_regular(&guides_path, MAX_GUIDES_BYTES)?;
    let program_digest = digest_bytes(&program_bytes)?;
    if program_digest != packet.program_digest {
        return Err(ProgramError::ProgramDigestMismatch);
    }
    let objectives_digest = digest_bytes(&objectives_bytes)?;
    if objectives_digest != packet.objectives_digest {
        return Err(ProgramError::ObjectivesDigestMismatch);
    }
    let guides_digest = digest_bytes(&guides_bytes)?;
    if guides_digest != packet.guides_digest {
        return Err(ProgramError::GuidesDigestMismatch);
    }
    let body = program_bytes
        .strip_prefix(PROGRAM_HEADER)
        .ok_or(ProgramError::InvalidProgram("SPDX header"))?;
    let program = parse_json(body)?;
    let objectives = parse_json(&objectives_bytes)?;
    if selected_document(&program, "items", "id", packet.work_id.as_str())? != &packet.work_document
        || selected_document(
            &objectives,
            "objectives",
            "work_id",
            packet.work_id.as_str(),
        )? != &packet.objective_document
    {
        return Err(ProgramError::InvalidPacket("exact document binding"));
    }
    let (nodes, graph_digest) = parse_program(&program)?;
    if graph_digest != digest_bytes(&graph_bytes)? {
        return Err(ProgramError::GraphDigestMismatch);
    }
    let node = nodes
        .get(packet.work_id.as_str())
        .ok_or(ProgramError::UnknownWork)?;
    if !node.runnable {
        return Err(ProgramError::NotRunnable);
    }
    let objectives = parse_objectives(&objectives, &nodes)?;
    let objective = objectives
        .get(packet.work_id.as_str())
        .ok_or(ProgramError::ObjectiveMissing)?;
    if node.dependencies != packet.dependencies
        || node.allowed_paths != packet.allowed_paths
        || node.licence != packet.licence
        || objective.id != packet.objective_id
        || objective.text != packet.objective
        || objective.budget != packet.budget
        || objective.autonomous_eligible != packet.autonomous_eligible
    {
        return Err(ProgramError::InvalidPacket("document binding"));
    }
    Ok(RunnableProposal {
        immutable_base: packet.immutable_base,
        run_id: packet.run_id,
        packet_path: packet_repo_path,
        packet_digest,
        work_id: packet.work_id,
        objective_id: objective.id.clone(),
        objective: objective.text.clone(),
        graph_digest,
        program_digest,
        objectives_digest,
        guides_digest,
        dependencies: node.dependencies.clone(),
        allowed_paths: node.allowed_paths.clone(),
        budget: objective.budget,
        licence: node.licence.clone(),
        autonomous_eligible: objective.autonomous_eligible,
    })
}

struct HarnessState {
    immutable_base: GitSha1,
    run_id: OpaqueId,
    work_id: OpaqueId,
    packet_path: ProposalPath,
    packet_digest: Sha256Digest,
}

fn parse_harness_state(value: &Value) -> Result<HarnessState, ProgramError> {
    let root = packet_object(
        value,
        &[
            "base",
            "branch",
            "deadline_at",
            "driver",
            "failures",
            "iteration",
            "packet",
            "packet_sha256",
            "run_id",
            "schema",
            "started_at",
            "status",
            "stop_reason",
            "unchanged_results",
            "updated_at",
            "work_id",
        ],
    )?;
    if packet_string(root, "schema")? != "automonique.harness-loop-state/v1"
        || packet_string(root, "driver")? != "codex_session"
        || !matches!(
            packet_string(root, "status")?,
            "claimed" | "candidate_ready"
        )
    {
        return Err(ProgramError::InvalidPacket("harness state"));
    }
    let immutable_base = GitSha1::new(packet_string(root, "base")?)
        .map_err(|_| ProgramError::InvalidPacket("state base"))?;
    let run_id = packet_id(root, "run_id")?;
    let work_id = packet_id(root, "work_id")?;
    let packet_path = proposal_path(packet_string(root, "packet")?, false)
        .map_err(|_| ProgramError::InvalidPacket("state packet"))?;
    let packet_digest = packet_digest(root, "packet_sha256")?;
    Ok(HarnessState {
        immutable_base,
        run_id,
        work_id,
        packet_path,
        packet_digest,
    })
}

fn git_repository_root() -> Result<PathBuf, ProgramError> {
    let output = fixed_git(&["rev-parse", "--show-toplevel"])?;
    let text = std::str::from_utf8(&output).map_err(|_| ProgramError::UnsafeInput)?;
    let root = PathBuf::from(text.trim_end_matches(['\r', '\n']));
    if !root.is_absolute() || output.len() > 4096 {
        return Err(ProgramError::UnsafeInput);
    }
    Ok(root)
}

fn verify_git_state(root: &Path, expected: &GitSha1) -> Result<(), ProgramError> {
    let head = fixed_git_in(root, &["rev-parse", "--verify", "HEAD"])?;
    if std::str::from_utf8(&head)
        .map_err(|_| ProgramError::UnsafeInput)?
        .trim()
        != expected.as_str()
    {
        return Err(ProgramError::InvalidPacket("Git base"));
    }
    let status = fixed_git_in(
        root,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
        ],
    )?;
    if !status.is_empty() {
        return Err(ProgramError::InvalidPacket("dirty worktree"));
    }
    Ok(())
}

fn fixed_git(arguments: &[&str]) -> Result<Vec<u8>, ProgramError> {
    let root = std::env::current_dir().map_err(|_| ProgramError::UnsafeInput)?;
    fixed_git_in(&root, arguments)
}
fn fixed_git_in(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, ProgramError> {
    let mut child = git_command(root, arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ProgramError::UnsafeInput)?;
    let mut stdout = child.stdout.take().ok_or(ProgramError::UnsafeInput)?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| ProgramError::UnsafeInput)?;
    let status = child.wait().map_err(|_| ProgramError::UnsafeInput)?;
    if !status.success() || bytes.len() > 4096 {
        return Err(ProgramError::UnsafeInput);
    }
    Ok(bytes)
}
fn git_command(root: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(arguments);
    command
}

struct AdmissionPacket {
    immutable_base: GitSha1,
    run_id: OpaqueId,
    work_id: OpaqueId,
    objective_id: OpaqueId,
    objective: BoundedText,
    program_digest: Sha256Digest,
    objectives_digest: Sha256Digest,
    guides_digest: Sha256Digest,
    dependencies: Vec<OpaqueId>,
    allowed_paths: Vec<ProposalPath>,
    budget: ProposalBudget,
    licence: String,
    autonomous_eligible: bool,
    work_document: Value,
    objective_document: Value,
}

fn parse_packet(value: &Value) -> Result<AdmissionPacket, ProgramError> {
    let root = packet_object(
        value,
        &[
            "attempt_baseline",
            "driver",
            "guides_sha256",
            "immutable_base",
            "integration_ceiling",
            "iteration",
            "objective",
            "objectives_sha256",
            "prior_iteration",
            "program_sha256",
            "run_id",
            "schema",
            "session_coordination",
            "work_item",
        ],
    )?;
    if packet_string(root, "schema")? != "automonique.harness-objective-packet/v1"
        || packet_string(root, "driver")? != "codex_session"
        || packet_string(root, "integration_ceiling")? != "proposal_only"
        || packet_uint(root, "iteration")? == 0
    {
        return Err(ProgramError::InvalidPacket("header"));
    }
    let immutable_base = GitSha1::new(packet_string(root, "immutable_base")?)
        .map_err(|_| ProgramError::InvalidPacket("base"))?;
    let run_id = OpaqueId::new(packet_string(root, "run_id")?)
        .map_err(|_| ProgramError::InvalidPacket("run"))?;
    let program_digest = packet_digest(root, "program_sha256")?;
    let objectives_digest = packet_digest(root, "objectives_sha256")?;
    let guides_digest = packet_digest(root, "guides_sha256")?;
    let baseline = packet_object(
        packet_field(root, "attempt_baseline")?,
        &[
            "admission_safety_checks",
            "git_head",
            "guides_sha256",
            "objectives_sha256",
            "program_sha256",
            "worktree_clean",
        ],
    )?;
    if packet_string(baseline, "admission_safety_checks")? != "pass"
        || packet_string(baseline, "git_head")? != immutable_base.as_str()
        || packet_digest(baseline, "program_sha256")? != program_digest
        || packet_digest(baseline, "objectives_sha256")? != objectives_digest
        || packet_digest(baseline, "guides_sha256")? != guides_digest
        || packet_field(baseline, "worktree_clean")?.as_bool() != Some(true)
    {
        return Err(ProgramError::InvalidPacket("baseline"));
    }
    let work = packet_object(
        packet_field(root, "work_item")?,
        &[
            "allowed_paths",
            "blocked_by_gates",
            "closes_gate",
            "contract",
            "depends_on",
            "epic",
            "id",
            "licence",
            "runnable",
            "status",
            "summary",
            "title",
            "track",
        ],
    )?;
    let objective = packet_object(
        packet_field(root, "objective")?,
        &[
            "allowed_paths",
            "autonomous_eligible",
            "baseline",
            "budget",
            "hill_climbability",
            "id",
            "licence",
            "metric",
            "objective",
            "sources",
            "stop_conditions",
            "tests",
            "work_id",
        ],
    )?;
    let work_id = packet_id(work, "id")?;
    if packet_string(objective, "work_id")? != work_id.as_str()
        || packet_string(work, "status")? != "blocked"
        || packet_field(work, "runnable")?.as_bool() != Some(true)
    {
        return Err(ProgramError::InvalidPacket("work"));
    }
    let objective_id = packet_id(objective, "id")?;
    if objective_id.as_str() != format!("objective:{}", work_id.as_str()) {
        return Err(ProgramError::InvalidPacket("objective ID"));
    }
    let allowed_paths = packet_paths(work, "allowed_paths")?;
    if packet_paths(objective, "allowed_paths")? != allowed_paths {
        return Err(ProgramError::InvalidPacket("paths"));
    }
    let licence = licence(packet_string(work, "licence")?, false)?.to_owned();
    if packet_string(objective, "licence")? != licence {
        return Err(ProgramError::InvalidPacket("licence"));
    }
    let budget = parse_budget(packet_field(objective, "budget")?)
        .map_err(|_| ProgramError::InvalidPacket("budget"))?;
    let objective_text = BoundedText::new(
        packet_string(objective, "objective")?,
        MAX_TEXT,
        "objective",
    )
    .map_err(|_| ProgramError::InvalidPacket("objective"))?;
    let dependencies = packet_ids(work, "depends_on")?;
    let autonomous_eligible = packet_field(objective, "autonomous_eligible")?
        .as_bool()
        .ok_or(ProgramError::InvalidPacket("autonomous"))?;
    Ok(AdmissionPacket {
        immutable_base,
        run_id,
        work_id,
        objective_id,
        objective: objective_text,
        program_digest,
        objectives_digest,
        guides_digest,
        dependencies,
        allowed_paths,
        budget,
        licence,
        autonomous_eligible,
        work_document: Value::Object(work.clone()),
        objective_document: Value::Object(objective.clone()),
    })
}

/// Validate bytes produced by the crate-internal claim transaction against the
/// same closed packet schema consumed by [`select_admitted`].
pub(crate) fn validate_claim_packet(bytes: &[u8]) -> Result<(), ProgramError> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
        return Err(ProgramError::InputTooLarge);
    }
    let value = parse_json(bytes)?;
    parse_packet(&value).map(|_| ())
}

/// Validate the complete generated documents selected by the claim core using
/// the same parsers later used by [`select_admitted`].
pub(crate) fn validate_claim_documents(
    program_bytes: &[u8],
    objectives_bytes: &[u8],
    work_id: &str,
) -> Result<(), ProgramError> {
    if program_bytes.len() > MAX_PROGRAM_BYTES || objectives_bytes.len() > MAX_OBJECTIVES_BYTES {
        return Err(ProgramError::InputTooLarge);
    }
    let program_body = program_bytes
        .strip_prefix(PROGRAM_HEADER)
        .ok_or(ProgramError::InvalidProgram("SPDX header"))?;
    let program_value = parse_json(program_body)?;
    let objectives_value = parse_json(objectives_bytes)?;
    let (nodes, _) = parse_program(&program_value)?;
    let objectives = parse_objectives(&objectives_value, &nodes)?;
    let node = nodes.get(work_id).ok_or(ProgramError::UnknownWork)?;
    let objective = objectives
        .get(work_id)
        .ok_or(ProgramError::ObjectiveMissing)?;
    if !node.runnable || !objective.autonomous_eligible {
        return Err(ProgramError::NotRunnable);
    }
    Ok(())
}

fn selected_document<'a>(
    root: &'a Value,
    collection: &str,
    identity: &str,
    expected: &str,
) -> Result<&'a Value, ProgramError> {
    root.as_object()
        .and_then(|object| object.get(collection))
        .and_then(Value::as_array)
        .and_then(|values| {
            values.iter().find(|value| {
                value
                    .as_object()
                    .and_then(|object| object.get(identity))
                    .and_then(Value::as_str)
                    == Some(expected)
            })
        })
        .ok_or(ProgramError::InvalidPacket("selected document"))
}

fn packet_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ProgramError> {
    let object = value
        .as_object()
        .ok_or(ProgramError::InvalidPacket("object"))?;
    if object.len() != fields.len() || fields.iter().any(|name| !object.contains_key(*name)) {
        return Err(ProgramError::InvalidPacket("fields"));
    }
    Ok(object)
}
fn packet_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ProgramError> {
    object.get(name).ok_or(ProgramError::InvalidPacket("field"))
}
fn packet_string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProgramError> {
    packet_field(object, name)?
        .as_str()
        .ok_or(ProgramError::InvalidPacket("string"))
}
fn packet_uint(object: &Map<String, Value>, name: &str) -> Result<u64, ProgramError> {
    packet_field(object, name)?
        .as_u64()
        .ok_or(ProgramError::InvalidPacket("integer"))
}
fn packet_digest(object: &Map<String, Value>, name: &str) -> Result<Sha256Digest, ProgramError> {
    Sha256Digest::new(packet_string(object, name)?)
        .map_err(|_| ProgramError::InvalidPacket("digest"))
}
fn packet_id(object: &Map<String, Value>, name: &str) -> Result<OpaqueId, ProgramError> {
    OpaqueId::new(packet_string(object, name)?)
        .map_err(|_| ProgramError::InvalidPacket("identifier"))
}
fn packet_ids(object: &Map<String, Value>, name: &str) -> Result<Vec<OpaqueId>, ProgramError> {
    let values = packet_field(object, name)?
        .as_array()
        .ok_or(ProgramError::InvalidPacket("identifiers"))?;
    if values.len() > MAX_COLLECTION {
        return Err(ProgramError::InvalidPacket("collection"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ProgramError::InvalidPacket("identifier"))
                .and_then(|value| {
                    OpaqueId::new(value).map_err(|_| ProgramError::InvalidPacket("identifier"))
                })
        })
        .collect()
}
fn packet_paths(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Vec<ProposalPath>, ProgramError> {
    let values = packet_field(object, name)?
        .as_array()
        .ok_or(ProgramError::InvalidPacket("paths"))?;
    if values.is_empty() || values.len() > MAX_COLLECTION {
        return Err(ProgramError::InvalidPacket("paths"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ProgramError::InvalidPacket("path"))
                .and_then(|value| {
                    proposal_path(value, false).map_err(|_| ProgramError::InvalidPacket("path"))
                })
        })
        .collect()
}

fn digest_bytes(bytes: &[u8]) -> Result<Sha256Digest, ProgramError> {
    Sha256Digest::new(hex::encode(Sha256::digest(bytes)))
        .map_err(|_| ProgramError::InvalidProgram("digest"))
}

#[derive(Clone)]
struct ProgramNode {
    dependencies: Vec<OpaqueId>,
    gates: Vec<OpaqueId>,
    closes_gate: Option<OpaqueId>,
    contract: bool,
    done: bool,
    runnable: bool,
    allowed_paths: Vec<ProposalPath>,
    licence: String,
}

fn parse_program(
    value: &Value,
) -> Result<(BTreeMap<String, ProgramNode>, Sha256Digest), ProgramError> {
    let root = exact_object(value, &["schema", "source", "items"], false)?;
    if string(root, "schema", false)? != PROGRAM_SCHEMA {
        return Err(ProgramError::InvalidProgram("schema"));
    }
    let source = exact_object(
        field(root, "source", false)?,
        &["graph", "graph_sha256", "item_count"],
        false,
    )?;
    if string(source, "graph", false)? != "plan/work-graph.toml" {
        return Err(ProgramError::InvalidProgram("graph"));
    }
    let digest = Sha256Digest::new(string(source, "graph_sha256", false)?)
        .map_err(|_| ProgramError::InvalidProgram("graph digest"))?;
    let items = array(root, "items", false)?;
    if items.is_empty()
        || items.len() > MAX_ITEMS
        || uint(source, "item_count", false)? as usize != items.len()
    {
        return Err(ProgramError::InvalidProgram("item count"));
    }
    let mut nodes = BTreeMap::new();
    for item in items {
        let object = exact_object(
            item,
            &[
                "id",
                "epic",
                "track",
                "title",
                "summary",
                "depends_on",
                "blocked_by_gates",
                "licence",
                "allowed_paths",
                "closes_gate",
                "status",
                "contract",
                "runnable",
            ],
            false,
        )?;
        let id = identifier(object, "id", false)?;
        bounded_string(object, "epic", 128, false)?;
        bounded_string(object, "track", 128, false)?;
        bounded_string(object, "title", MAX_TEXT, false)?;
        nullable_bounded(object, "summary", MAX_TEXT, false)?;
        let dependencies = identifiers(object, "depends_on", false)?;
        let gates = identifiers(object, "blocked_by_gates", false)?;
        let licence = licence(string(object, "licence", false)?, false)?.to_owned();
        let allowed_paths = proposal_paths(object, "allowed_paths", false)?;
        let closes_gate = nullable_identifier(object, "closes_gate", false)?;
        let contract = nullable_path(object, "contract", false)?.is_some();
        let done = match string(object, "status", false)? {
            "done" => true,
            "blocked" => false,
            _ => return Err(ProgramError::InvalidProgram("status")),
        };
        let runnable = boolean(object, "runnable", false)?;
        if nodes
            .insert(
                id.as_str().to_owned(),
                ProgramNode {
                    dependencies,
                    gates,
                    closes_gate,
                    contract,
                    done,
                    runnable,
                    allowed_paths,
                    licence,
                },
            )
            .is_some()
        {
            return Err(ProgramError::InvalidProgram("duplicate work ID"));
        }
    }
    let closed_gates: BTreeSet<_> = nodes
        .values()
        .filter(|node| node.done)
        .filter_map(|node| node.closes_gate.as_ref().map(|gate| gate.as_str()))
        .collect();
    for node in nodes.values() {
        let mut unique = BTreeSet::new();
        if node.dependencies.iter().any(|dependency| {
            !unique.insert(dependency.as_str()) || !nodes.contains_key(dependency.as_str())
        }) {
            return Err(ProgramError::InvalidProgram("dependencies"));
        }
        let derived = !node.done
            && node.contract
            && node
                .dependencies
                .iter()
                .all(|dependency| nodes[dependency.as_str()].done)
            && node
                .gates
                .iter()
                .all(|gate| closed_gates.contains(gate.as_str()));
        if node.runnable != derived {
            return Err(ProgramError::InvalidProgram("runnable status"));
        }
        if node.done
            && node
                .dependencies
                .iter()
                .any(|dependency| !nodes[dependency.as_str()].done)
        {
            return Err(ProgramError::InvalidProgram("dependency status"));
        }
    }
    let mut remaining: BTreeMap<_, _> = nodes
        .iter()
        .map(|(id, node)| (id.as_str(), node.dependencies.len()))
        .collect();
    let mut ready: Vec<_> = remaining
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0usize;
    while let Some(completed) = ready.pop() {
        visited += 1;
        for (id, node) in &nodes {
            if node
                .dependencies
                .iter()
                .any(|dependency| dependency.as_str() == completed)
            {
                let count = remaining
                    .get_mut(id.as_str())
                    .ok_or(ProgramError::InvalidProgram("dependencies"))?;
                *count -= 1;
                if *count == 0 {
                    ready.push(id);
                }
            }
        }
    }
    if visited != nodes.len() {
        return Err(ProgramError::InvalidProgram("dependency cycle"));
    }
    Ok((nodes, digest))
}

#[derive(Clone)]
struct Objective {
    id: OpaqueId,
    text: BoundedText,
    budget: ProposalBudget,
    autonomous_eligible: bool,
}

fn parse_objectives(
    value: &Value,
    nodes: &BTreeMap<String, ProgramNode>,
) -> Result<BTreeMap<String, Objective>, ProgramError> {
    let root = exact_object(value, &["schema", "objectives"], true)?;
    if string(root, "schema", true)? != OBJECTIVES_SCHEMA {
        return Err(ProgramError::InvalidObjectives("schema"));
    }
    let values = array(root, "objectives", true)?;
    if values.is_empty() || values.len() > MAX_ITEMS {
        return Err(ProgramError::InvalidObjectives("objective count"));
    }
    let mut objectives = BTreeMap::new();
    for value in values {
        let object = exact_object(
            value,
            &[
                "id",
                "work_id",
                "objective",
                "metric",
                "baseline",
                "budget",
                "tests",
                "stop_conditions",
                "hill_climbability",
                "autonomous_eligible",
                "allowed_paths",
                "licence",
                "sources",
            ],
            true,
        )?;
        let work_id = identifier(object, "work_id", true)?;
        let id = identifier(object, "id", true)?;
        if id.as_str() != format!("objective:{}", work_id.as_str()) {
            return Err(ProgramError::InvalidObjectives("objective ID"));
        }
        let node = nodes
            .get(work_id.as_str())
            .ok_or(ProgramError::InvalidObjectives("unknown work ID"))?;
        let text = BoundedText::new(string(object, "objective", true)?, MAX_TEXT, "objective")
            .map_err(|_| ProgramError::InvalidObjectives("objective text"))?;
        validate_metric(field(object, "metric", true)?)?;
        validate_baseline(field(object, "baseline", true)?)?;
        let budget = parse_budget(field(object, "budget", true)?)?;
        nonempty_strings(object, "tests", true)?;
        nonempty_strings(object, "stop_conditions", true)?;
        if uint(object, "hill_climbability", true)? > 100 {
            return Err(ProgramError::InvalidObjectives("hill climbability"));
        }
        let autonomous_eligible = boolean(object, "autonomous_eligible", true)?;
        let paths = proposal_paths(object, "allowed_paths", true)?;
        if paths != node.allowed_paths
            || licence(string(object, "licence", true)?, true)? != node.licence
        {
            return Err(ProgramError::InvalidObjectives("program binding"));
        }
        nonempty_strings(object, "sources", true)?;
        if objectives
            .insert(
                work_id.as_str().to_owned(),
                Objective {
                    id,
                    text,
                    budget,
                    autonomous_eligible,
                },
            )
            .is_some()
        {
            return Err(ProgramError::InvalidObjectives("duplicate work ID"));
        }
    }
    Ok(objectives)
}

fn validate_metric(value: &Value) -> Result<(), ProgramError> {
    let object = exact_object(value, &["name", "target", "anti_regression"], true)?;
    bounded_string(object, "name", 256, true)?;
    if uint(object, "target", true)? == 0 {
        return Err(ProgramError::InvalidObjectives("metric target"));
    }
    bounded_string(object, "anti_regression", MAX_TEXT, true)?;
    Ok(())
}

fn validate_baseline(value: &Value) -> Result<(), ProgramError> {
    let object = exact_object(value, &["value", "reason"], true)?;
    if !field(object, "value", true)?.is_null() {
        return Err(ProgramError::InvalidObjectives("baseline"));
    }
    bounded_string(object, "reason", MAX_TEXT, true)?;
    Ok(())
}

fn parse_budget(value: &Value) -> Result<ProposalBudget, ProgramError> {
    let object = exact_object(
        value,
        &[
            "max_iterations",
            "max_wall_seconds",
            "max_worker_seconds",
            "max_unchanged_results",
            "max_failures",
        ],
        true,
    )?;
    let positive = |field_name| {
        uint(object, field_name, true).and_then(|value| {
            JsUInt::positive(value, "budget")
                .map(JsUInt::get)
                .map_err(|_| ProgramError::InvalidObjectives("budget"))
        })
    };
    let budget = ProposalBudget {
        max_iterations: positive("max_iterations")?,
        max_wall_seconds: positive("max_wall_seconds")?,
        max_worker_seconds: positive("max_worker_seconds")?,
        max_unchanged_results: positive("max_unchanged_results")?,
        max_failures: positive("max_failures")?,
    };
    if budget.max_worker_seconds > budget.max_wall_seconds
        || budget.max_unchanged_results > budget.max_iterations
        || budget.max_failures > budget.max_iterations
    {
        return Err(ProgramError::InvalidObjectives("budget coherence"));
    }
    Ok(budget)
}

fn parse_json(bytes: &[u8]) -> Result<Value, ProgramError> {
    std::str::from_utf8(bytes).map_err(|_| ProgramError::InvalidJson)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ProgramError::InvalidJson)?;
    validate_value(&value, 0)?;
    if !value.is_object() {
        return Err(ProgramError::InvalidJson);
    }
    Ok(value)
}

fn validate_value(value: &Value, depth: usize) -> Result<(), ProgramError> {
    if depth > 16 {
        return Err(ProgramError::InvalidJson);
    }
    match value {
        Value::Number(number) if number.as_u64().is_none() && number.as_i64().is_none() => {
            Err(ProgramError::InvalidJson)
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_value(value, depth + 1)),
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_value(value, depth + 1)),
        _ => Ok(()),
    }
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    objectives: bool,
) -> Result<&'a Map<String, Value>, ProgramError> {
    let error = || {
        if objectives {
            ProgramError::InvalidObjectives("object fields")
        } else {
            ProgramError::InvalidProgram("object fields")
        }
    };
    let object = value.as_object().ok_or_else(error)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(error());
    }
    Ok(object)
}

fn field<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<&'a Value, ProgramError> {
    object.get(name).ok_or(if objectives {
        ProgramError::InvalidObjectives("missing field")
    } else {
        ProgramError::InvalidProgram("missing field")
    })
}
fn string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<&'a str, ProgramError> {
    field(object, name, objectives)?
        .as_str()
        .ok_or(if objectives {
            ProgramError::InvalidObjectives("string")
        } else {
            ProgramError::InvalidProgram("string")
        })
}
fn uint(object: &Map<String, Value>, name: &str, objectives: bool) -> Result<u64, ProgramError> {
    field(object, name, objectives)?
        .as_u64()
        .ok_or(if objectives {
            ProgramError::InvalidObjectives("integer")
        } else {
            ProgramError::InvalidProgram("integer")
        })
}
fn boolean(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<bool, ProgramError> {
    field(object, name, objectives)?
        .as_bool()
        .ok_or(if objectives {
            ProgramError::InvalidObjectives("boolean")
        } else {
            ProgramError::InvalidProgram("boolean")
        })
}
fn array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<&'a [Value], ProgramError> {
    field(object, name, objectives)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(if objectives {
            ProgramError::InvalidObjectives("array")
        } else {
            ProgramError::InvalidProgram("array")
        })
}
fn bounded_string(
    object: &Map<String, Value>,
    name: &str,
    max: usize,
    objectives: bool,
) -> Result<(), ProgramError> {
    BoundedText::new(string(object, name, objectives)?, max, "program text")
        .map(|_| ())
        .map_err(|_| {
            if objectives {
                ProgramError::InvalidObjectives("bounded text")
            } else {
                ProgramError::InvalidProgram("bounded text")
            }
        })
}
fn nullable_bounded(
    object: &Map<String, Value>,
    name: &str,
    max: usize,
    objectives: bool,
) -> Result<(), ProgramError> {
    let value = field(object, name, objectives)?;
    if value.is_null() {
        Ok(())
    } else {
        value
            .as_str()
            .ok_or(ProgramError::InvalidProgram("nullable text"))
            .and_then(|_| bounded_string(object, name, max, objectives))
    }
}
fn identifier(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<OpaqueId, ProgramError> {
    OpaqueId::new(string(object, name, objectives)?).map_err(|_| {
        if objectives {
            ProgramError::InvalidObjectives("identifier")
        } else {
            ProgramError::InvalidProgram("identifier")
        }
    })
}
fn identifiers(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<Vec<OpaqueId>, ProgramError> {
    let values = array(object, name, objectives)?;
    if values.len() > MAX_COLLECTION {
        return Err(ProgramError::InvalidProgram("collection bound"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(ProgramError::InvalidProgram("identifier array"))
                .and_then(|value| {
                    OpaqueId::new(value)
                        .map_err(|_| ProgramError::InvalidProgram("identifier array"))
                })
        })
        .collect()
}
fn nullable_identifier(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<Option<OpaqueId>, ProgramError> {
    let value = field(object, name, objectives)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_str()
            .ok_or(ProgramError::InvalidProgram("nullable identifier"))
            .and_then(|value| {
                OpaqueId::new(value)
                    .map(Some)
                    .map_err(|_| ProgramError::InvalidProgram("nullable identifier"))
            })
    }
}
fn nullable_path(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<Option<ProposalPath>, ProgramError> {
    let value = field(object, name, objectives)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_str()
            .ok_or(ProgramError::InvalidProgram("contract path"))
            .and_then(|value| proposal_path(value, objectives).map(Some))
    }
}
fn proposal_paths(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<Vec<ProposalPath>, ProgramError> {
    let values = array(object, name, objectives)?;
    if values.is_empty() || values.len() > MAX_COLLECTION {
        return Err(if objectives {
            ProgramError::InvalidObjectives("allowed paths")
        } else {
            ProgramError::InvalidProgram("allowed paths")
        });
    }
    let paths: Vec<_> = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(if objectives {
                    ProgramError::InvalidObjectives("allowed path")
                } else {
                    ProgramError::InvalidProgram("allowed path")
                })
                .and_then(|value| proposal_path(value, objectives))
        })
        .collect::<Result<_, _>>()?;
    let unique: BTreeSet<_> = paths.iter().map(ProposalPath::as_str).collect();
    if unique.len() != paths.len() {
        return Err(if objectives {
            ProgramError::InvalidObjectives("duplicate allowed path")
        } else {
            ProgramError::InvalidProgram("duplicate allowed path")
        });
    }
    Ok(paths)
}
fn proposal_path(value: &str, objectives: bool) -> Result<ProposalPath, ProgramError> {
    let lexical = value.strip_suffix('/').unwrap_or(value);
    if lexical.is_empty() || value.ends_with("//") || RepoPath::parse(lexical.to_owned()).is_err() {
        return Err(if objectives {
            ProgramError::InvalidObjectives("allowed path")
        } else {
            ProgramError::InvalidProgram("allowed path")
        });
    }
    Ok(ProposalPath(value.to_owned()))
}
fn licence(value: &str, objectives: bool) -> Result<&str, ProgramError> {
    if matches!(value, "Elastic-2.0" | "Apache-2.0") {
        Ok(value)
    } else {
        Err(if objectives {
            ProgramError::InvalidObjectives("licence")
        } else {
            ProgramError::InvalidProgram("licence")
        })
    }
}
fn nonempty_strings(
    object: &Map<String, Value>,
    name: &str,
    objectives: bool,
) -> Result<(), ProgramError> {
    let values = array(object, name, objectives)?;
    if values.is_empty() || values.len() > MAX_COLLECTION {
        return Err(ProgramError::InvalidObjectives("string collection"));
    }
    for value in values {
        BoundedText::new(
            value
                .as_str()
                .ok_or(ProgramError::InvalidObjectives("string collection"))?,
            MAX_TEXT,
            "objective list",
        )
        .map_err(|_| ProgramError::InvalidObjectives("string collection"))?;
    }
    Ok(())
}

fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, ProgramError> {
    if !path.is_absolute() {
        return Err(ProgramError::UnsafeInput);
    }
    let descriptor = open_without_symlinks(path)?;
    let result = read_descriptor(descriptor, limit);
    let closed = close(descriptor);
    match (result, closed) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(ProgramError::UnsafeInput),
    }
}

#[cfg(target_os = "linux")]
fn open_without_symlinks(path: &Path) -> Result<i32, ProgramError> {
    openat2(
        nix::libc::AT_FDCWD,
        path,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
            .mode(Mode::empty())
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| {
        if error == Errno::ENOENT {
            ProgramError::MissingInput
        } else {
            ProgramError::UnsafeInput
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn open_without_symlinks(_path: &Path) -> Result<i32, ProgramError> {
    Err(ProgramError::UnsafeInput)
}

fn read_descriptor(descriptor: i32, limit: usize) -> Result<Vec<u8>, ProgramError> {
    let metadata = fstat(descriptor).map_err(|_| ProgramError::UnsafeInput)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(ProgramError::UnsafeInput);
    }
    let mut bytes = vec![0; limit + 1];
    let mut length = 0;
    loop {
        match read(descriptor, &mut bytes[length..]) {
            Ok(0) => {
                bytes.truncate(length);
                return Ok(bytes);
            }
            Ok(count) => {
                length += count;
                if length > limit {
                    return Err(ProgramError::InputTooLarge);
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return Err(ProgramError::UnsafeInput),
        }
    }
}
