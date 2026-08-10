// SPDX-License-Identifier: Elastic-2.0

//! Durable core for a Rust-owned bootstrap claim transaction.
//!
//! Repository discovery, Git inspection, and fixed safety-check execution are
//! deliberately composition-root responsibilities. This module accepts their
//! already-verified immutable coordinates, selects from bounded generated
//! documents, and publishes the packet before the active state pointer.

use nix::fcntl::{Flock, FlockArg};
use nix::libc;
use nix::unistd::Uid;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const PROGRAM_SCHEMA: &str = "automonique.dev-program/v1";
const OBJECTIVES_SCHEMA: &str = "automonique.dev-objectives/v1";
const LOOP_SCHEMA: &str = "automonique.dev-loop/v1";
const PACKET_SCHEMA: &str = "automonique.harness-objective-packet/v1";
const STATE_SCHEMA: &str = "automonique.harness-loop-state/v1";
const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 1_024;
const MAX_PACKET_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 32 * 1024;
const EXISTING_STATE_FIELDS: &[&str] = &[
    "base",
    "branch",
    "candidate_commit",
    "candidate_paths",
    "candidate_ref",
    "candidate_summary",
    "candidate_tree",
    "checked_at",
    "deadline_at",
    "driver",
    "elapsed_seconds",
    "failures",
    "integrated_commit",
    "integration_receipt_sha256",
    "iteration",
    "last_exit_code",
    "last_tree_digest",
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
];
const REQUIRED_EXISTING_STATE_FIELDS: &[&str] = &[
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
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSnapshot {
    pub(crate) head: String,
    pub(crate) branch: String,
    pub(crate) clean: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCoordinates {
    pub(crate) started_at: String,
    pub(crate) deadline_at: String,
    pub(crate) nonce: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimFault {
    AfterPacketDurable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimReceipt {
    pub run_id: String,
    pub work_id: String,
    pub packet_relative: String,
    pub packet_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    UnsafeStateRoot,
    LockBusy,
    ActiveClaim,
    InvalidExistingState,
    InvalidInput,
    IneligibleItem,
    Collision,
    Io,
    InjectedFault,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "claim denied: {self:?}")
    }
}

impl Error for ClaimError {}

pub struct ClaimDocuments<'a> {
    pub(crate) program: &'a [u8],
    pub(crate) objectives: &'a [u8],
    pub(crate) guide_manifest: &'a [u8],
    pub(crate) loop_config: &'a [u8],
}

/// Publish a claim from coordinates sealed inside this crate's trusted
/// composition root. External callers cannot construct the input capabilities.
pub fn publish_claim(
    state_root: &Path,
    documents: ClaimDocuments<'_>,
    requested_item: Option<&str>,
    snapshot: &GitSnapshot,
    coordinates: &ClaimCoordinates,
    fault: Option<ClaimFault>,
) -> Result<ClaimReceipt, ClaimError> {
    reject_symlink_components(state_root)?;
    require_private_directory(state_root)?;
    let lock = open_private_lock(&state_root.join("harness-loop.json.lock"))?;
    let _lock =
        Flock::lock(lock, FlockArg::LockExclusiveNonblock).map_err(|_| ClaimError::LockBusy)?;

    let state_path = state_root.join("harness-loop.json");
    let prior = read_existing_state(&state_path)?;
    validate_snapshot(snapshot)?;
    validate_coordinates(coordinates)?;

    let program = parse_document(documents.program)?;
    let objectives = parse_document(documents.objectives)?;
    let loop_config = parse_document(documents.loop_config)?;
    if documents.guide_manifest.is_empty() || documents.guide_manifest.len() > MAX_DOCUMENT_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    let (item, objective, max_agents, max_wall_seconds) =
        select(&program, &objectives, &loop_config, requested_item)?;
    validate_deadline(coordinates, max_wall_seconds)?;
    let work_id = string(item.as_object().ok_or(ClaimError::InvalidInput)?, "id")?;
    crate::program::validate_claim_documents(documents.program, documents.objectives, work_id)
        .map_err(|_| ClaimError::InvalidInput)?;
    let run_id = run_id(&coordinates.started_at, &coordinates.nonce)?;

    let program_sha = sha256(documents.program);
    let objectives_sha = sha256(documents.objectives);
    let guides_sha = sha256(documents.guide_manifest);
    let packet = json!({
        "attempt_baseline": {
            "admission_safety_checks": "pass",
            "git_head": snapshot.head,
            "guides_sha256": guides_sha,
            "objectives_sha256": objectives_sha,
            "program_sha256": program_sha,
            "worktree_clean": true
        },
        "driver": "codex_session",
        "guides_sha256": guides_sha,
        "immutable_base": snapshot.head,
        "integration_ceiling": "proposal_only",
        "iteration": 1,
        "objective": objective,
        "objectives_sha256": objectives_sha,
        "prior_iteration": null,
        "program_sha256": program_sha,
        "run_id": run_id,
        "schema": PACKET_SCHEMA,
        "session_coordination": {
            "concurrent_writes": "disjoint_paths_only",
            "integration_owner": "primary_session",
            "max_concurrent_subagents": max_agents,
            "native_subagents": true,
            "primary_role": "coordinate, integrate, verify, and report",
            "recursive_agent_trees": false,
            "subagent_prompt_fields": [
                "bounded objective",
                "allowed paths",
                "required checks",
                "return evidence"
            ]
        },
        "work_item": item
    });
    let mut packet_bytes =
        serde_json::to_vec_pretty(&packet).map_err(|_| ClaimError::InvalidInput)?;
    packet_bytes.push(b'\n');
    if packet_bytes.len() > MAX_PACKET_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    crate::program::validate_claim_packet(&packet_bytes).map_err(|_| ClaimError::InvalidInput)?;
    let run_dir = state_root.join("runs").join(&run_id);
    create_private_run_directory(state_root, &run_dir)?;
    let packet_path = run_dir.join("packet.json");
    write_create_new(&packet_path, &packet_bytes)?;
    sync_directory(&run_dir)?;
    if fault == Some(ClaimFault::AfterPacketDurable) {
        return Err(ClaimError::InjectedFault);
    }

    let packet_relative = format!(".automonique/state/runs/{run_id}/packet.json");
    let packet_sha = sha256(&packet_bytes);
    let state = json!({
        "base": snapshot.head,
        "branch": snapshot.branch,
        "deadline_at": coordinates.deadline_at,
        "driver": "codex_session",
        "failures": 0,
        "iteration": 1,
        "packet": packet_relative,
        "packet_sha256": packet_sha,
        "run_id": run_id,
        "schema": STATE_SCHEMA,
        "started_at": coordinates.started_at,
        "status": "claimed",
        "stop_reason": null,
        "unchanged_results": 0,
        "updated_at": coordinates.started_at,
        "work_id": work_id
    });
    crate::harness_status::validate_state_document(&state).map_err(|_| ClaimError::InvalidInput)?;
    let mut state_bytes =
        serde_json::to_vec_pretty(&state).map_err(|_| ClaimError::InvalidInput)?;
    state_bytes.push(b'\n');
    if let Some(prior) = &prior {
        verify_prior_unchanged(&state_path, prior)?;
    }
    publish_state(state_root, &state_path, &coordinates.nonce, &state_bytes)?;
    Ok(ClaimReceipt {
        run_id,
        work_id: work_id.to_owned(),
        packet_relative,
        packet_sha256: packet_sha,
    })
}

fn select<'a>(
    program: &'a Value,
    objectives: &'a Value,
    loop_config: &Value,
    requested: Option<&str>,
) -> Result<(&'a Value, &'a Value, u64, u64), ClaimError> {
    let program = exact_object(program, &["items", "schema", "source"])?;
    if string(program, "schema")? != PROGRAM_SCHEMA {
        return Err(ClaimError::InvalidInput);
    }
    let objectives = exact_object(objectives, &["objectives", "schema"])?;
    if string(objectives, "schema")? != OBJECTIVES_SCHEMA {
        return Err(ClaimError::InvalidInput);
    }
    let loop_config = loop_config.as_object().ok_or(ClaimError::InvalidInput)?;
    if string(loop_config, "schema")? != LOOP_SCHEMA
        || string(loop_config, "integration_ceiling")? != "proposal_only"
        || string(loop_config, "default_driver")? != "codex_session"
    {
        return Err(ClaimError::InvalidInput);
    }
    let threshold = integer(loop_config, "hill_climbability_threshold")?;
    let drivers = object(loop_config, "drivers")?;
    let session = object(drivers, "codex_session")?;
    let max_agents = integer(session, "max_concurrent_subagents")?;
    if max_agents == 0
        || max_agents > 3
        || session.get("native_subagents").and_then(Value::as_bool) != Some(true)
        || session
            .get("recursive_agent_trees")
            .and_then(Value::as_bool)
            != Some(false)
        || string(session, "concurrent_writes")? != "disjoint_paths_only"
        || string(session, "integration_owner")? != "primary_session"
    {
        return Err(ClaimError::InvalidInput);
    }
    let items = array(program, "items")?;
    let objective_values = array(objectives, "objectives")?;
    if items.is_empty() || items.len() > MAX_ITEMS || objective_values.len() > MAX_ITEMS {
        return Err(ClaimError::InvalidInput);
    }
    if requested.is_some_and(|value| !identifier(value, 80)) {
        return Err(ClaimError::InvalidInput);
    }
    let mut item_ids = HashSet::with_capacity(items.len());
    for item in items {
        let item = item.as_object().ok_or(ClaimError::InvalidInput)?;
        let id = string(item, "id")?;
        if !identifier(id, 80) || !item_ids.insert(id) {
            return Err(ClaimError::InvalidInput);
        }
    }
    let mut objective_ids = HashSet::with_capacity(objective_values.len());
    for objective in objective_values {
        let objective = objective.as_object().ok_or(ClaimError::InvalidInput)?;
        let work_id = string(objective, "work_id")?;
        if !identifier(work_id, 80) || !objective_ids.insert(work_id) {
            return Err(ClaimError::InvalidInput);
        }
    }
    let mut selected = None;
    for item in items {
        let item_object = item.as_object().ok_or(ClaimError::InvalidInput)?;
        let id = string(item_object, "id")?;
        if requested.is_some_and(|wanted| wanted != id) {
            continue;
        }
        let objective = objective_values.iter().find(|candidate| {
            candidate
                .as_object()
                .and_then(|value| value.get("work_id"))
                .and_then(Value::as_str)
                == Some(id)
        });
        let Some(objective) = objective else {
            if requested.is_some() {
                return Err(ClaimError::IneligibleItem);
            }
            continue;
        };
        let objective_object = objective.as_object().ok_or(ClaimError::InvalidInput)?;
        let runnable = item_object
            .get("runnable")
            .and_then(Value::as_bool)
            .ok_or(ClaimError::InvalidInput)?;
        let eligible = objective_object
            .get("autonomous_eligible")
            .and_then(Value::as_bool)
            .ok_or(ClaimError::InvalidInput)?;
        let score = integer(objective_object, "hill_climbability")?;
        if eligible != (score >= threshold) {
            return Err(ClaimError::InvalidInput);
        }
        if runnable && eligible {
            validate_pair(item_object, objective_object)?;
            selected = Some((item, objective));
            break;
        }
        if requested.is_some() {
            return Err(ClaimError::IneligibleItem);
        }
    }
    let (item, objective) = selected.ok_or(ClaimError::IneligibleItem)?;
    let objective_object = objective.as_object().ok_or(ClaimError::InvalidInput)?;
    let max_wall_seconds =
        positive_integer(object(objective_object, "budget")?, "max_wall_seconds")?;
    Ok((item, objective, max_agents, max_wall_seconds))
}

fn validate_pair(
    item: &Map<String, Value>,
    objective: &Map<String, Value>,
) -> Result<(), ClaimError> {
    if string(objective, "id")? != format!("objective:{}", string(item, "id")?)
        || item.get("allowed_paths") != objective.get("allowed_paths")
        || item.get("licence") != objective.get("licence")
        || item.get("contract").is_none_or(Value::is_null)
    {
        return Err(ClaimError::InvalidInput);
    }
    let budget = object(objective, "budget")?;
    let iterations = positive_integer(budget, "max_iterations")?;
    let wall = positive_integer(budget, "max_wall_seconds")?;
    let worker = positive_integer(budget, "max_worker_seconds")?;
    let unchanged = positive_integer(budget, "max_unchanged_results")?;
    let failures = positive_integer(budget, "max_failures")?;
    if worker > wall || unchanged > iterations || failures > iterations {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

#[derive(Clone)]
struct PriorState {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
}

fn read_existing_state(path: &Path) -> Result<Option<PriorState>, ClaimError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ClaimError::InvalidExistingState),
    };
    let metadata = file
        .metadata()
        .map_err(|_| ClaimError::InvalidExistingState)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::InvalidExistingState);
    }
    let mut bytes = Vec::new();
    file.take((MAX_STATE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClaimError::InvalidExistingState)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ClaimError::InvalidExistingState);
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| ClaimError::InvalidExistingState)?;
    crate::harness_status::validate_state_document(&value)
        .map_err(|_| ClaimError::InvalidExistingState)?;
    let object = value.as_object().ok_or(ClaimError::InvalidExistingState)?;
    if object
        .keys()
        .any(|field| !EXISTING_STATE_FIELDS.contains(&field.as_str()))
        || REQUIRED_EXISTING_STATE_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(ClaimError::InvalidExistingState);
    }
    if string(object, "schema").map_err(|_| ClaimError::InvalidExistingState)? != STATE_SCHEMA {
        return Err(ClaimError::InvalidExistingState);
    }
    validate_existing_state_coordinates(object)?;
    let status = string(object, "status").map_err(|_| ClaimError::InvalidExistingState)?;
    if !matches!(status, "stopped" | "integrated_and_pushed") {
        return Err(ClaimError::ActiveClaim);
    }
    let reason = object.get("stop_reason").and_then(Value::as_str);
    if (status == "integrated_and_pushed" && reason != Some("integrated_and_pushed"))
        || (status == "stopped" && reason.is_none())
    {
        return Err(ClaimError::InvalidExistingState);
    }
    Ok(Some(PriorState {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
    }))
}

fn verify_prior_unchanged(path: &Path, prior: &PriorState) -> Result<(), ClaimError> {
    let current = read_file_no_follow(path, MAX_STATE_BYTES)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ClaimError::Io)?;
    if current != prior.bytes || metadata.dev() != prior.device || metadata.ino() != prior.inode {
        return Err(ClaimError::InvalidExistingState);
    }
    Ok(())
}

fn publish_state(
    root: &Path,
    destination: &Path,
    nonce: &str,
    bytes: &[u8],
) -> Result<(), ClaimError> {
    let temporary = root.join(format!(".harness-loop.{nonce}.tmp"));
    write_create_new(&temporary, bytes)?;
    fs::rename(&temporary, destination).map_err(|_| ClaimError::Io)?;
    sync_directory(root)
}

fn create_private_run_directory(state_root: &Path, run_dir: &Path) -> Result<(), ClaimError> {
    let runs = state_root.join("runs");
    if !runs.exists() {
        fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&runs)
            .map_err(|_| ClaimError::Io)?;
        sync_directory(state_root)?;
    }
    require_private_directory(&runs)?;
    match fs::DirBuilder::new().mode(0o700).create(run_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ClaimError::Collision);
        }
        Err(_) => return Err(ClaimError::Io),
    }
    sync_directory(&runs)
}

fn require_private_directory(path: &Path) -> Result<(), ClaimError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ClaimError::UnsafeStateRoot)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ClaimError::UnsafeStateRoot);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), ClaimError> {
    if !path.is_absolute() {
        return Err(ClaimError::UnsafeStateRoot);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            _ => return Err(ClaimError::UnsafeStateRoot),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| ClaimError::UnsafeStateRoot)?;
        if metadata.file_type().is_symlink() {
            return Err(ClaimError::UnsafeStateRoot);
        }
    }
    Ok(())
}

fn open_private_lock(path: &Path) -> Result<File, ClaimError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::UnsafeStateRoot)?;
    let metadata = file.metadata().map_err(|_| ClaimError::UnsafeStateRoot)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::UnsafeStateRoot);
    }
    Ok(file)
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), ClaimError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| ClaimError::Io)?;
    file.write_all(bytes).map_err(|_| ClaimError::Io)?;
    file.sync_all().map_err(|_| ClaimError::Io)?;
    let metadata = file.metadata().map_err(|_| ClaimError::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ClaimError::Io);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ClaimError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ClaimError::Io)
}

fn read_file_no_follow(path: &Path, maximum: usize) -> Result<Vec<u8>, ClaimError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ClaimError::Io)?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClaimError::Io)?;
    if bytes.len() > maximum {
        return Err(ClaimError::Io);
    }
    Ok(bytes)
}

fn parse_document(bytes: &[u8]) -> Result<Value, ClaimError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ClaimError::InvalidInput);
    }
    let start = bytes
        .iter()
        .position(|byte| *byte == b'{')
        .ok_or(ClaimError::InvalidInput)?;
    serde_json::from_slice(&bytes[start..]).map_err(|_| ClaimError::InvalidInput)
}

fn validate_snapshot(snapshot: &GitSnapshot) -> Result<(), ClaimError> {
    if !snapshot.clean || !lower_hex(&snapshot.head, 40) || !identifier(&snapshot.branch, 255) {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn validate_coordinates(value: &ClaimCoordinates) -> Result<(), ClaimError> {
    if !timestamp(&value.started_at)
        || !timestamp(&value.deadline_at)
        || !lower_hex(&value.nonce, 8)
        || value.deadline_at <= value.started_at
    {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn validate_deadline(value: &ClaimCoordinates, max_wall_seconds: u64) -> Result<(), ClaimError> {
    let started = timestamp_seconds(&value.started_at).ok_or(ClaimError::InvalidInput)?;
    let deadline = timestamp_seconds(&value.deadline_at).ok_or(ClaimError::InvalidInput)?;
    if deadline.checked_sub(started) != i64::try_from(max_wall_seconds).ok() {
        return Err(ClaimError::InvalidInput);
    }
    Ok(())
}

fn run_id(timestamp: &str, nonce: &str) -> Result<String, ClaimError> {
    let compact = timestamp
        .strip_suffix("+00:00")
        .ok_or(ClaimError::InvalidInput)?
        .replace(['-', ':'], "");
    Ok(format!("session_{compact}Z_{nonce}"))
}

fn timestamp(value: &str) -> bool {
    timestamp_seconds(value).is_some()
}

fn timestamp_seconds(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'+'),
        (22, b':'),
    ];
    if bytes.len() != 25
        || !value.ends_with("+00:00")
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        return None;
    }
    let number = |start: usize, end: usize| value.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year == 0
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days.checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)
}

fn validate_existing_state_coordinates(object: &Map<String, Value>) -> Result<(), ClaimError> {
    if string(object, "driver")? != "codex_session"
        || !lower_hex(string(object, "base")?, 40)
        || !lower_hex(string(object, "packet_sha256")?, 64)
        || !identifier(string(object, "branch")?, 255)
        || !identifier(string(object, "run_id")?, 64)
        || !identifier(string(object, "work_id")?, 80)
        || !timestamp(string(object, "started_at")?)
        || !timestamp(string(object, "updated_at")?)
        || !timestamp(string(object, "deadline_at")?)
        || integer(object, "iteration").is_err()
        || integer(object, "failures").is_err()
        || integer(object, "unchanged_results").is_err()
    {
        return Err(ClaimError::InvalidExistingState);
    }
    let run_id = string(object, "run_id")?;
    if string(object, "packet")? != format!(".automonique/state/runs/{run_id}/packet.json") {
        return Err(ClaimError::InvalidExistingState);
    }
    match object.get("stop_reason") {
        Some(Value::Null) => Ok(()),
        Some(Value::String(reason))
            if !reason.is_empty()
                && reason.len() <= 64
                && reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_') =>
        {
            Ok(())
        }
        _ => Err(ClaimError::InvalidExistingState),
    }
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, ClaimError> {
    let object = value.as_object().ok_or(ClaimError::InvalidInput)?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(ClaimError::InvalidInput);
    }
    Ok(object)
}

fn object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(ClaimError::InvalidInput)
}

fn array<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], ClaimError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(ClaimError::InvalidInput)
}

fn string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .ok_or(ClaimError::InvalidInput)
}

fn integer(object: &Map<String, Value>, field: &str) -> Result<u64, ClaimError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or(ClaimError::InvalidInput)
}

fn positive_integer(object: &Map<String, Value>, field: &str) -> Result<u64, ClaimError> {
    integer(object, field).and_then(|value| {
        if value == 0 {
            Err(ClaimError::InvalidInput)
        } else {
            Ok(value)
        }
    })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};

    struct Fixture {
        _temp: tempfile::TempDir,
        state: PathBuf,
        program: Vec<u8>,
        objectives: Vec<u8>,
        loop_config: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let state = temp.path().join("state");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&state)
                .expect("state root");
            let item = |id: &str| {
                json!({
                    "allowed_paths": ["rust/crates/automonique-lab/"],
                    "blocked_by_gates": [], "closes_gate": null,
                    "contract": format!("plan/contracts/{id}.md"), "depends_on": [],
                    "epic": "R0", "id": id, "licence": "Elastic-2.0",
                    "runnable": true, "status": "blocked",
                    "summary": "bounded synthetic claim fixture",
                    "title": "Synthetic claim fixture", "track": "core"
                })
            };
            let objective = |id: &str, score: u64| {
                json!({
                    "allowed_paths": ["rust/crates/automonique-lab/"],
                    "autonomous_eligible": score >= 70,
                    "baseline": {"reason": "synthetic", "value": null},
                    "budget": {"max_failures": 2, "max_iterations": 3,
                        "max_unchanged_results": 1, "max_wall_seconds": 1800,
                        "max_worker_seconds": 1200},
                    "hill_climbability": score, "id": format!("objective:{id}"),
                    "licence": "Elastic-2.0", "metric": {"name": "fixture", "target": 1,
                        "anti_regression": "no weakened fixture checks"},
                    "objective": "Exercise the bounded claim transaction.",
                    "sources": ["plan/contracts/R0-19.md"],
                    "stop_conditions": ["Stop on mismatch."], "tests": ["Harness claim"],
                    "work_id": id
                })
            };
            let mut program = b"# SPDX-License-Identifier: Elastic-2.0\n".to_vec();
            program.extend(
                serde_json::to_vec(&json!({
                    "items": [item("BOOT-003"), item("R0-19")],
                    "schema": PROGRAM_SCHEMA, "source": {"graph": "plan/work-graph.toml",
                        "graph_sha256": "2".repeat(64), "item_count": 2}
                }))
                .expect("program"),
            );
            let objectives = serde_json::to_vec(&json!({
                "objectives": [objective("BOOT-003", 80), objective("R0-19", 78)],
                "schema": OBJECTIVES_SCHEMA
            }))
            .expect("objectives");
            let loop_config = serde_json::to_vec(&json!({
                "default_driver": "codex_session",
                "drivers": {"codex_session": {"concurrent_writes": "disjoint_paths_only",
                    "integration_owner": "primary_session", "max_concurrent_subagents": 3,
                    "native_subagents": true, "recursive_agent_trees": false}},
                "hill_climbability_threshold": 70, "integration_ceiling": "proposal_only",
                "schema": LOOP_SCHEMA
            }))
            .expect("loop config");
            Self {
                _temp: temp,
                state,
                program,
                objectives,
                loop_config,
            }
        }

        fn documents(&self) -> ClaimDocuments<'_> {
            ClaimDocuments {
                program: &self.program,
                objectives: &self.objectives,
                guide_manifest: b"synthetic-guide-manifest",
                loop_config: &self.loop_config,
            }
        }
    }

    fn snapshot() -> GitSnapshot {
        GitSnapshot {
            head: "1".repeat(40),
            branch: "main".into(),
            clean: true,
        }
    }

    fn coordinates(nonce: &str) -> ClaimCoordinates {
        ClaimCoordinates {
            started_at: "2026-08-10T10:00:00+00:00".into(),
            deadline_at: "2026-08-10T10:30:00+00:00".into(),
            nonce: nonce.into(),
        }
    }

    #[test]
    fn packet_is_consumer_valid_and_published_before_state() {
        let fixture = Fixture::new();
        let receipt = publish_claim(
            &fixture.state,
            fixture.documents(),
            Some("R0-19"),
            &snapshot(),
            &coordinates("1234abcd"),
            None,
        )
        .expect("claim");
        let packet = fs::read(
            fixture
                .state
                .join("runs")
                .join(&receipt.run_id)
                .join("packet.json"),
        )
        .expect("packet");
        crate::program::validate_claim_packet(&packet).expect("consumer-valid packet");
        assert_eq!(receipt.work_id, "R0-19");
        assert_eq!(sha256(&packet), receipt.packet_sha256);
        assert_eq!(
            fs::metadata(fixture.state.join("harness-loop.json"))
                .expect("state")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn deadline_and_generated_identity_must_be_coherent() {
        let fixture = Fixture::new();
        let mut bad_time = coordinates("2234abcd");
        bad_time.deadline_at = "2026-08-10T10:29:59+00:00".into();
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                None,
                &snapshot(),
                &bad_time,
                None
            ),
            Err(ClaimError::InvalidInput)
        );

        let fixture = Fixture::new();
        let mut program = parse_document(&fixture.program).expect("program");
        program["items"][1]["id"] = json!("BOOT-003");
        let mut bytes = b"# SPDX-License-Identifier: Elastic-2.0\n".to_vec();
        bytes.extend(serde_json::to_vec(&program).expect("duplicate program"));
        let documents = ClaimDocuments {
            program: &bytes,
            ..fixture.documents()
        };
        assert_eq!(
            publish_claim(
                &fixture.state,
                documents,
                None,
                &snapshot(),
                &coordinates("3234abcd"),
                None
            ),
            Err(ClaimError::InvalidInput)
        );
    }

    #[test]
    fn forged_terminal_state_and_unsafe_components_fail_closed() {
        let fixture = Fixture::new();
        fs::write(
            fixture.state.join("harness-loop.json"),
            br#"{"schema":"automonique.harness-loop-state/v1","status":"stopped"}"#,
        )
        .expect("state");
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                None,
                &snapshot(),
                &coordinates("4234abcd"),
                None
            ),
            Err(ClaimError::InvalidExistingState)
        );

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .expect("target");
        let parent = temp.path().join("linked");
        symlink(&target, &parent).expect("symlink");
        assert_eq!(
            publish_claim(
                &parent,
                fixture.documents(),
                None,
                &snapshot(),
                &coordinates("5234abcd"),
                None
            ),
            Err(ClaimError::UnsafeStateRoot)
        );
    }

    #[test]
    fn packet_fault_is_inert_and_retry_uses_new_run() {
        let fixture = Fixture::new();
        assert_eq!(
            publish_claim(
                &fixture.state,
                fixture.documents(),
                Some("R0-19"),
                &snapshot(),
                &coordinates("6234abcd"),
                Some(ClaimFault::AfterPacketDurable)
            ),
            Err(ClaimError::InjectedFault)
        );
        assert!(!fixture.state.join("harness-loop.json").exists());
        let receipt = publish_claim(
            &fixture.state,
            fixture.documents(),
            Some("R0-19"),
            &snapshot(),
            &coordinates("7234abcd"),
            None,
        )
        .expect("retry");
        assert_eq!(receipt.run_id, "session_20260810T100000Z_7234abcd");
    }

    #[test]
    fn concurrent_claims_publish_exactly_one_pointer() {
        let fixture = Fixture::new();
        let state = Arc::new(fixture.state.clone());
        let barrier = Arc::new(Barrier::new(3));
        let handles = ["8234abcd", "9234abcd"].map(|nonce| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let fixture = Fixture::new();
                barrier.wait();
                publish_claim(
                    &state,
                    fixture.documents(),
                    None,
                    &snapshot(),
                    &coordinates(nonce),
                    None,
                )
            })
        });
        barrier.wait();
        let results = handles.map(|handle| handle.join().expect("thread"));
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| matches!(
                    result,
                    Err(ClaimError::LockBusy | ClaimError::ActiveClaim)
                ))
        );
    }
}
