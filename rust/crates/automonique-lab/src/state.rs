// SPDX-License-Identifier: Elastic-2.0

//! Durable SQLite state for the proposal-only development harness.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use rusqlite::{
    Connection, ErrorCode, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};

use crate::protocol::{OpaqueId, Sha256Digest};
use crate::workspace_lease::{
    ActionId, AttemptId, BaseRevision, FenceEpoch, LeaseId, Mutation, RepoPath, Revision,
};

const MIGRATION_0001: &str = include_str!("../migrations/0001.sql");
const SCHEMA_VERSION: i64 = 1;
const MAX_LEASE_PATHS: usize = 1_024;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_BUSY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptState {
    Queued,
    Running,
    Paused,
    Succeeded,
    Failed,
    Blocked,
    Cancelled,
}

impl AttemptState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled
        )
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "paused" => Ok(Self::Paused),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "blocked" => Ok(Self::Blocked),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(StateError::Corrupt("attempt state is unknown")),
        }
    }

    const fn may_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (
                Self::Queued,
                Self::Running | Self::Blocked | Self::Cancelled
            ) | (
                Self::Running,
                Self::Paused | Self::Succeeded | Self::Failed | Self::Blocked | Self::Cancelled
            ) | (
                Self::Paused,
                Self::Running | Self::Blocked | Self::Cancelled
            )
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalKind {
    Event,
    Checkpoint,
    Evidence,
}

impl JournalKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Checkpoint => "checkpoint",
            Self::Evidence => "evidence",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "event" => Ok(Self::Event),
            "checkpoint" => Ok(Self::Checkpoint),
            "evidence" => Ok(Self::Evidence),
            _ => Err(StateError::Corrupt("journal kind is unknown")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordAuthority {
    Harness,
    Worker,
    Reviewer,
    Owner,
}

impl RecordAuthority {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Harness => "harness",
            Self::Worker => "worker",
            Self::Reviewer => "reviewer",
            Self::Owner => "owner",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "harness" => Ok(Self::Harness),
            "worker" => Ok(Self::Worker),
            "reviewer" => Ok(Self::Reviewer),
            "owner" => Ok(Self::Owner),
            _ => Err(StateError::Corrupt("record authority is unknown")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    Pending,
    Applied,
    Failed,
    Unknown,
}

impl EffectStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            "unknown" => Ok(Self::Unknown),
            _ => Err(StateError::Corrupt("effect status is unknown")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSnapshot {
    attempt_id: AttemptId,
    objective_id: OpaqueId,
    base_revision: BaseRevision,
    state: AttemptState,
    revision: Revision,
    last_sequence: u64,
}

impl AttemptSnapshot {
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn objective_id(&self) -> &OpaqueId {
        &self.objective_id
    }
    pub fn base_revision(&self) -> &BaseRevision {
        &self.base_revision
    }
    pub const fn state(&self) -> AttemptState {
        self.state
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    attempt_id: AttemptId,
    sequence: u64,
    record_id: ActionId,
    kind: JournalKind,
    attempt_revision: Revision,
    authority: RecordAuthority,
    payload_digest: Sha256Digest,
}

impl JournalRecord {
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn record_id(&self) -> &ActionId {
        &self.record_id
    }
    pub const fn kind(&self) -> JournalKind {
        self.kind
    }
    pub const fn attempt_revision(&self) -> Revision {
        self.attempt_revision
    }
    pub const fn authority(&self) -> RecordAuthority {
        self.authority
    }
    pub fn payload_digest(&self) -> &Sha256Digest {
        &self.payload_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectSnapshot {
    attempt_id: AttemptId,
    idempotency_key: ActionId,
    request_digest: Sha256Digest,
    status: EffectStatus,
    result_digest: Option<Sha256Digest>,
    intent_authority: RecordAuthority,
    result_authority: Option<RecordAuthority>,
    intent_revision: Revision,
    result_revision: Option<Revision>,
}

impl EffectSnapshot {
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn idempotency_key(&self) -> &ActionId {
        &self.idempotency_key
    }
    pub fn request_digest(&self) -> &Sha256Digest {
        &self.request_digest
    }
    pub const fn status(&self) -> EffectStatus {
        self.status
    }
    pub fn result_digest(&self) -> Option<&Sha256Digest> {
        self.result_digest.as_ref()
    }
    pub const fn intent_authority(&self) -> RecordAuthority {
        self.intent_authority
    }
    pub const fn result_authority(&self) -> Option<RecordAuthority> {
        self.result_authority
    }
    pub const fn intent_revision(&self) -> Revision {
        self.intent_revision
    }
    pub const fn result_revision(&self) -> Option<Revision> {
        self.result_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedLease {
    lease_id: LeaseId,
    attempt_id: AttemptId,
    paths: Vec<RepoPath>,
    epoch: FenceEpoch,
    acquired_revision: Revision,
}

impl PersistedLease {
    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn paths(&self) -> &[RepoPath] {
        &self.paths
    }
    pub const fn epoch(&self) -> FenceEpoch {
        self.epoch
    }
    pub const fn acquired_revision(&self) -> Revision {
        self.acquired_revision
    }
}

/// Opaque, instance-issued evidence that an exact durable lease is active.
/// Only [`StateStore::verify_active_lease`] can construct this value.
#[derive(Clone, Debug)]
pub struct VerifiedActiveLease {
    lease_identity: Weak<()>,
    store_binding: String,
    attempt_id: AttemptId,
    lease_id: LeaseId,
    epoch: FenceEpoch,
    base_revision: BaseRevision,
    paths: Vec<RepoPath>,
}

impl VerifiedActiveLease {
    pub(crate) fn lease_identity(&self) -> &Weak<()> {
        &self.lease_identity
    }
    pub(crate) fn store_binding(&self) -> &str {
        &self.store_binding
    }
    pub(crate) fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub(crate) fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }
    pub(crate) const fn epoch(&self) -> FenceEpoch {
        self.epoch
    }
    pub(crate) fn base_revision(&self) -> &BaseRevision {
        &self.base_revision
    }
    pub(crate) fn paths(&self) -> &[RepoPath] {
        &self.paths
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionAttempt {
    pub action_id: ActionId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub target: AttemptState,
    pub event_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionReceipt {
    pub action_id: ActionId,
    pub attempt_id: AttemptId,
    pub state: AttemptState,
    pub revision: Revision,
    pub event_sequence: u64,
    pub released_lease_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendRecord {
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub record_id: ActionId,
    pub kind: JournalKind,
    pub payload_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquirePaths {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub paths: Vec<RepoPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePaths {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub epoch: FenceEpoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseMutationReceipt {
    pub action_id: ActionId,
    pub lease_id: LeaseId,
    pub attempt_id: AttemptId,
    pub epoch: FenceEpoch,
    pub revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectIntent {
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub idempotency_key: ActionId,
    pub request_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectResult {
    pub attempt_id: AttemptId,
    pub base_revision: BaseRevision,
    pub expected_revision: Revision,
    pub idempotency_key: ActionId,
    pub request_digest: Sha256Digest,
    pub status: EffectStatus,
    pub result_digest: Sha256Digest,
}

#[derive(Debug)]
pub enum StateError {
    UnsafePath(&'static str),
    Busy,
    Database(rusqlite::Error),
    SchemaVersion {
        found: i64,
    },
    Corrupt(&'static str),
    NotFound(&'static str),
    AttemptConflict,
    AuthorityDenied,
    ActionConflict,
    RecordConflict,
    EffectConflict,
    RevisionConflict {
        expected: Revision,
        actual: Revision,
    },
    BaseRevisionMismatch,
    TerminalImmutable,
    InvalidTransition {
        from: AttemptState,
        to: AttemptState,
    },
    SequenceOverflow,
    RevisionOverflow,
    EpochOverflow,
    EmptyPathSet,
    TooManyPaths,
    RequestedPathsOverlap,
    LeaseConflict {
        held_path: RepoPath,
    },
    LeaseAlreadyActive,
    LeaseOwnerMismatch,
    LeaseInactive,
    NonterminalReleaseDenied,
    Fenced {
        supplied: FenceEpoch,
        active: FenceEpoch,
    },
    PendingEffectRequired,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(reason) => write!(formatter, "unsafe database path: {reason}"),
            Self::Busy => formatter.write_str("development state is busy"),
            Self::Database(error) => write!(formatter, "SQLite state error: {error}"),
            Self::SchemaVersion { found } => {
                write!(formatter, "unsupported schema version {found}")
            }
            Self::Corrupt(reason) => write!(formatter, "development state is corrupt: {reason}"),
            Self::NotFound(kind) => write!(formatter, "{kind} was not found"),
            Self::AttemptConflict => {
                formatter.write_str("attempt identity conflicts with durable state")
            }
            Self::AuthorityDenied => formatter.write_str("broker authority does not match store"),
            Self::ActionConflict => {
                formatter.write_str("action ID was reused for another mutation")
            }
            Self::RecordConflict => {
                formatter.write_str("journal record ID was reused with different content")
            }
            Self::EffectConflict => {
                formatter.write_str("effect idempotency key has different coordinates")
            }
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "revision conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::BaseRevisionMismatch => formatter.write_str("attempt immutable base differs"),
            Self::TerminalImmutable => formatter.write_str("terminal attempt is immutable"),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid attempt transition {from:?} -> {to:?}")
            }
            Self::SequenceOverflow => formatter.write_str("journal sequence exhausted"),
            Self::RevisionOverflow => formatter.write_str("attempt revision exhausted"),
            Self::EpochOverflow => formatter.write_str("lease epoch exhausted"),
            Self::EmptyPathSet => formatter.write_str("lease path set is empty"),
            Self::TooManyPaths => formatter.write_str("lease path set exceeds its bound"),
            Self::RequestedPathsOverlap => formatter.write_str("requested lease paths overlap"),
            Self::LeaseConflict { held_path } => {
                write!(formatter, "path overlaps active lease at {held_path}")
            }
            Self::LeaseAlreadyActive => formatter.write_str("lease ID is already active"),
            Self::LeaseOwnerMismatch => formatter.write_str("lease belongs to another attempt"),
            Self::LeaseInactive => {
                formatter.write_str("historical lease receipt is no longer active")
            }
            Self::NonterminalReleaseDenied => formatter
                .write_str("only a terminal transition or recovery authority may release a lease"),
            Self::Fenced { supplied, active } => write!(
                formatter,
                "lease epoch {} is fenced by {}",
                supplied.get(),
                active.get()
            ),
            Self::PendingEffectRequired => {
                formatter.write_str("effect result requires a pending intent")
            }
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

pub struct StateStore {
    connection: Connection,
    path: PathBuf,
    authority_identity: Arc<()>,
    active_lease_identities: RefCell<BTreeMap<String, Arc<()>>>,
}

/// An unforgeable capability minted by an opened controller store.
pub struct BrokerAuthority {
    identity: Arc<()>,
}

/// Sealed root capability constructed only by the in-crate trusted controller.
pub struct ControllerRoot {
    pub(crate) seal: (),
}

impl StateStore {
    pub fn open(root: &ControllerRoot, path: impl AsRef<Path>) -> Result<Self, StateError> {
        Self::open_with_timeout(root, path, DEFAULT_BUSY_TIMEOUT)
    }

    pub fn open_with_timeout(
        root: &ControllerRoot,
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, StateError> {
        let () = root.seal;
        if busy_timeout.is_zero() || busy_timeout > MAX_BUSY_TIMEOUT {
            return Err(StateError::UnsafePath("busy timeout is outside 1ns..=60s"));
        }
        let path = validate_database_path(path.as_ref())?;
        let effective_uid = secure_state_paths_before_open(&path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = map_db(Connection::open_with_flags(&path, flags))?;
        secure_owned_file(&path, effective_uid, "database")?;
        map_db(connection.busy_timeout(busy_timeout))?;
        map_db(connection.pragma_update(None, "foreign_keys", true))?;
        map_db(connection.pragma_update(None, "synchronous", "FULL"))?;
        let mode: String =
            map_db(connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0)))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StateError::Corrupt("SQLite refused WAL mode"));
        }
        initialize_schema(&mut connection)?;
        secure_state_files(&path, effective_uid)?;
        verify_connection(&connection)?;
        verify_durable_state(&connection)?;
        Ok(Self {
            connection,
            path,
            authority_identity: Arc::new(()),
            active_lease_identities: RefCell::new(BTreeMap::new()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mint the capability that must accompany trusted durable mutations.
    pub fn broker_authority(&self) -> BrokerAuthority {
        BrokerAuthority {
            identity: Arc::clone(&self.authority_identity),
        }
    }

    fn require_broker(&self, authority: &BrokerAuthority) -> Result<(), StateError> {
        if Arc::ptr_eq(&authority.identity, &self.authority_identity) {
            Ok(())
        } else {
            Err(StateError::AuthorityDenied)
        }
    }

    pub fn schema_version(&self) -> Result<i64, StateError> {
        map_db(self.connection.query_row(
            "SELECT schema_version FROM automonique_lab_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        ))
    }

    pub fn create_attempt(
        &mut self,
        authority: &BrokerAuthority,
        attempt_id: AttemptId,
        objective_id: OpaqueId,
        base_revision: BaseRevision,
    ) -> Result<Mutation<AttemptSnapshot>, StateError> {
        self.require_broker(authority)?;
        let tx = immediate(&mut self.connection)?;
        if let Some(existing) = load_attempt(&tx, &attempt_id)? {
            if existing.objective_id == objective_id && existing.base_revision == base_revision {
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(existing));
            }
            return Err(StateError::AttemptConflict);
        }
        map_db(tx.execute(
            "INSERT INTO attempts(attempt_id, objective_id, base_revision, state, revision, last_sequence) VALUES (?1, ?2, ?3, 'queued', 0, 0)",
            params![attempt_id.as_str(), objective_id.as_str(), base_revision.as_str()],
        ))?;
        let snapshot = AttemptSnapshot {
            attempt_id,
            objective_id,
            base_revision,
            state: AttemptState::Queued,
            revision: Revision::default(),
            last_sequence: 0,
        };
        tx.commit().map_err(classify_db)?;
        Ok(Mutation::Applied(snapshot))
    }

    pub fn attempt(&self, attempt_id: &AttemptId) -> Result<Option<AttemptSnapshot>, StateError> {
        load_attempt(&self.connection, attempt_id)
    }

    pub fn transition(
        &mut self,
        authority: &BrokerAuthority,
        request: TransitionAttempt,
    ) -> Result<Mutation<TransitionReceipt>, StateError> {
        self.require_broker(authority)?;
        let tx = immediate(&mut self.connection)?;
        if let Some(stored) = load_state_action(&tx, &request.action_id)? {
            if stored.matches_transition(&request) {
                let receipt = TransitionReceipt {
                    action_id: request.action_id,
                    attempt_id: request.attempt_id,
                    state: AttemptState::parse(
                        stored
                            .target_state
                            .as_deref()
                            .ok_or(StateError::Corrupt("transition action has no target"))?,
                    )?,
                    revision: revision_from_i64(stored.result_revision)?,
                    event_sequence: u64_from_i64(
                        stored
                            .result_sequence
                            .ok_or(StateError::Corrupt("transition action has no sequence"))?,
                    )?,
                    released_lease_count: u64_from_i64(stored.released_lease_count)?,
                };
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(receipt));
            }
            return Err(StateError::ActionConflict);
        }
        let current = require_attempt(&tx, &request.attempt_id)?;
        validate_attempt_coordinates(&current, &request.base_revision, request.expected_revision)?;
        if current.state.is_terminal() {
            return Err(StateError::TerminalImmutable);
        }
        if !current.state.may_transition_to(request.target) {
            return Err(StateError::InvalidTransition {
                from: current.state,
                to: request.target,
            });
        }
        let revision = increment_revision(current.revision)?;
        let sequence = increment_sequence(current.last_sequence)?;
        let released_lease_ids = if request.target.is_terminal() {
            let mut statement = map_db(tx.prepare(
                "SELECT DISTINCT lease_id FROM path_leases WHERE attempt_id = ?1 ORDER BY lease_id",
            ))?;
            let rows = map_db(
                statement.query_map([request.attempt_id.as_str()], |row| row.get::<_, String>(0)),
            )?;
            let mut lease_ids = Vec::new();
            for row in rows {
                lease_ids.push(map_db(row)?);
            }
            drop(statement);
            map_db(tx.execute(
                "DELETE FROM path_leases WHERE attempt_id = ?1",
                [request.attempt_id.as_str()],
            ))?;
            lease_ids
        } else {
            Vec::new()
        };
        let released = u64::try_from(released_lease_ids.len())
            .map_err(|_| StateError::Corrupt("lease count exceeds u64"))?;
        map_db(tx.execute("UPDATE attempts SET state = ?2, revision = ?3, last_sequence = ?4 WHERE attempt_id = ?1", params![request.attempt_id.as_str(), request.target.as_str(), i64_from_revision(revision)?, i64_from_u64(sequence)?]))?;
        let event = JournalRecord {
            attempt_id: request.attempt_id.clone(),
            sequence,
            record_id: request.action_id.clone(),
            kind: JournalKind::Event,
            attempt_revision: revision,
            authority: RecordAuthority::Harness,
            payload_digest: request.event_digest.clone(),
        };
        insert_journal(&tx, &event)?;
        insert_state_action(
            &tx,
            &StoredAction::transition(&request, revision, sequence, released)?,
        )?;
        let receipt = TransitionReceipt {
            action_id: request.action_id,
            attempt_id: request.attempt_id,
            state: request.target,
            revision,
            event_sequence: sequence,
            released_lease_count: released,
        };
        tx.commit().map_err(classify_db)?;
        if !released_lease_ids.is_empty() {
            let mut identities = self.active_lease_identities.borrow_mut();
            for lease_id in released_lease_ids {
                identities.remove(&lease_id);
            }
        }
        Ok(Mutation::Applied(receipt))
    }

    pub fn append_record(
        &mut self,
        authority: &BrokerAuthority,
        request: AppendRecord,
    ) -> Result<Mutation<JournalRecord>, StateError> {
        self.require_broker(authority)?;
        let tx = immediate(&mut self.connection)?;
        if let Some(existing) = load_record_by_id(&tx, &request.attempt_id, &request.record_id)? {
            let attempt = require_attempt(&tx, &request.attempt_id)?;
            let coordinates_match = attempt.base_revision == request.base_revision
                && increment_revision(request.expected_revision).ok()
                    == Some(existing.attempt_revision);
            if coordinates_match
                && existing.kind == request.kind
                && existing.authority == RecordAuthority::Harness
                && existing.payload_digest == request.payload_digest
            {
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(existing));
            }
            return Err(StateError::RecordConflict);
        }
        let current = require_attempt(&tx, &request.attempt_id)?;
        validate_attempt_coordinates(&current, &request.base_revision, request.expected_revision)?;
        if current.state.is_terminal() && request.kind != JournalKind::Evidence {
            return Err(StateError::TerminalImmutable);
        }
        let revision = increment_revision(current.revision)?;
        let sequence = increment_sequence(current.last_sequence)?;
        map_db(tx.execute(
            "UPDATE attempts SET revision = ?2, last_sequence = ?3 WHERE attempt_id = ?1",
            params![
                request.attempt_id.as_str(),
                i64_from_revision(revision)?,
                i64_from_u64(sequence)?
            ],
        ))?;
        let record = JournalRecord {
            attempt_id: request.attempt_id,
            sequence,
            record_id: request.record_id,
            kind: request.kind,
            attempt_revision: revision,
            authority: RecordAuthority::Harness,
            payload_digest: request.payload_digest,
        };
        insert_journal(&tx, &record)?;
        tx.commit().map_err(classify_db)?;
        Ok(Mutation::Applied(record))
    }

    pub fn journal(&self, attempt_id: &AttemptId) -> Result<Vec<JournalRecord>, StateError> {
        let mut statement = map_db(self.connection.prepare("SELECT sequence, record_id, kind, attempt_revision, authority, payload_digest FROM journal_records WHERE attempt_id = ?1 ORDER BY sequence"))?;
        let rows = map_db(statement.query_map([attempt_id.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        }))?;
        let mut records = Vec::new();
        for row in rows {
            let (sequence, record_id, kind, revision, authority, digest) = map_db(row)?;
            records.push(JournalRecord {
                attempt_id: attempt_id.clone(),
                sequence: u64_from_i64(sequence)?,
                record_id: parse_action_id(record_id)?,
                kind: JournalKind::parse(&kind)?,
                attempt_revision: revision_from_i64(revision)?,
                authority: RecordAuthority::parse(&authority)?,
                payload_digest: parse_sha256(digest)?,
            });
        }
        Ok(records)
    }

    pub fn acquire_paths(
        &mut self,
        authority: &BrokerAuthority,
        mut request: AcquirePaths,
    ) -> Result<Mutation<LeaseMutationReceipt>, StateError> {
        self.require_broker(authority)?;
        request.paths.sort();
        validate_path_set(&request.paths)?;
        let tx = immediate(&mut self.connection)?;
        if let Some(stored) = load_state_action(&tx, &request.action_id)? {
            let paths = load_action_paths(&tx, &request.action_id)?;
            if stored.matches_acquire(&request) && paths == request.paths {
                if !stored_acquire_is_active(&tx, &stored, &paths)? {
                    return Err(StateError::LeaseInactive);
                }
                let receipt = LeaseMutationReceipt {
                    action_id: request.action_id,
                    lease_id: request.lease_id,
                    attempt_id: request.attempt_id,
                    epoch: FenceEpoch::from_u64(u64_from_i64(
                        stored
                            .lease_epoch
                            .ok_or(StateError::Corrupt("lease action has no epoch"))?,
                    )?),
                    revision: revision_from_i64(stored.result_revision)?,
                };
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(receipt));
            }
            return Err(StateError::ActionConflict);
        }
        let current = require_attempt(&tx, &request.attempt_id)?;
        validate_attempt_coordinates(&current, &request.base_revision, request.expected_revision)?;
        if current.state.is_terminal() {
            return Err(StateError::TerminalImmutable);
        }
        let active_id: Option<i64> = map_db(
            tx.query_row(
                "SELECT 1 FROM path_leases WHERE lease_id = ?1 LIMIT 1",
                [request.lease_id.as_str()],
                |row| row.get(0),
            )
            .optional(),
        )?;
        if active_id.is_some() {
            return Err(StateError::LeaseAlreadyActive);
        }
        for LeaseRow(_, _, held_path, _, _) in load_all_lease_rows(&tx)? {
            if request
                .paths
                .iter()
                .any(|candidate| candidate.overlaps(&held_path))
            {
                return Err(StateError::LeaseConflict { held_path });
            }
        }
        let revision = increment_revision(current.revision)?;
        let last_epoch: i64 = map_db(tx.query_row(
            "SELECT last_lease_epoch FROM automonique_lab_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        ))?;
        let epoch = u64_from_i64(last_epoch)?
            .checked_add(1)
            .ok_or(StateError::EpochOverflow)?;
        let epoch_i64 = i64_from_u64(epoch).map_err(|_| StateError::EpochOverflow)?;
        map_db(tx.execute(
            "UPDATE automonique_lab_meta SET last_lease_epoch = ?1 WHERE singleton = 1",
            [epoch_i64],
        ))?;
        map_db(tx.execute(
            "UPDATE attempts SET revision = ?2 WHERE attempt_id = ?1",
            params![request.attempt_id.as_str(), i64_from_revision(revision)?],
        ))?;
        for path in &request.paths {
            map_db(tx.execute("INSERT INTO path_leases(lease_id, attempt_id, path, epoch, acquired_revision) VALUES (?1, ?2, ?3, ?4, ?5)", params![request.lease_id.as_str(), request.attempt_id.as_str(), path.as_str(), epoch_i64, i64_from_revision(revision)?]))?;
        }
        insert_state_action(&tx, &StoredAction::acquire(&request, revision, epoch)?)?;
        insert_action_paths(&tx, &request.action_id, &request.paths)?;
        let receipt = LeaseMutationReceipt {
            action_id: request.action_id,
            lease_id: request.lease_id,
            attempt_id: request.attempt_id,
            epoch: FenceEpoch::from_u64(epoch),
            revision,
        };
        tx.commit().map_err(classify_db)?;
        Ok(Mutation::Applied(receipt))
    }

    pub fn release_paths(
        &mut self,
        authority: &BrokerAuthority,
        _request: ReleasePaths,
    ) -> Result<Mutation<LeaseMutationReceipt>, StateError> {
        self.require_broker(authority)?;
        Err(StateError::NonterminalReleaseDenied)
    }

    pub fn active_leases(&self) -> Result<Vec<PersistedLease>, StateError> {
        let rows = load_all_lease_rows(&self.connection)?;
        let mut grouped: Vec<PersistedLease> = Vec::new();
        for LeaseRow(lease_id, attempt_id, path, epoch, revision) in rows {
            if let Some(last) = grouped
                .last_mut()
                .filter(|lease| lease.lease_id == lease_id)
            {
                if last.attempt_id != attempt_id
                    || last.epoch != epoch
                    || last.acquired_revision != revision
                {
                    return Err(StateError::Corrupt("lease rows disagree"));
                }
                last.paths.push(path);
            } else {
                grouped.push(PersistedLease {
                    lease_id,
                    attempt_id,
                    paths: vec![path],
                    epoch,
                    acquired_revision: revision,
                });
            }
        }
        Ok(grouped)
    }

    /// Mint an opaque Git authority only after an exact active-lease lookup.
    pub fn verify_active_lease(
        &self,
        authority: &BrokerAuthority,
        attempt_id: &AttemptId,
        lease_id: &LeaseId,
        epoch: FenceEpoch,
        base_revision: &BaseRevision,
        mut paths: Vec<RepoPath>,
    ) -> Result<VerifiedActiveLease, StateError> {
        self.require_broker(authority)?;
        paths.sort();
        validate_path_set(&paths)?;
        let attempt = require_attempt(&self.connection, attempt_id)?;
        if &attempt.base_revision != base_revision {
            return Err(StateError::BaseRevisionMismatch);
        }
        let active = self
            .active_leases()?
            .into_iter()
            .find(|lease| lease.lease_id() == lease_id)
            .ok_or(StateError::LeaseInactive)?;
        if active.attempt_id() != attempt_id || active.paths() != paths {
            return Err(StateError::LeaseOwnerMismatch);
        }
        if active.epoch() != epoch {
            return Err(StateError::Fenced {
                supplied: epoch,
                active: active.epoch(),
            });
        }
        let store_binding = hex::encode(Sha256::digest(self.path.as_os_str().as_encoded_bytes()));
        let lease_identity = {
            let mut identities = self.active_lease_identities.borrow_mut();
            Arc::downgrade(
                identities
                    .entry(lease_id.as_str().to_owned())
                    .or_insert_with(|| Arc::new(())),
            )
        };
        Ok(VerifiedActiveLease {
            lease_identity,
            store_binding,
            attempt_id: attempt_id.clone(),
            lease_id: lease_id.clone(),
            epoch,
            base_revision: base_revision.clone(),
            paths,
        })
    }

    pub fn record_effect_intent(
        &mut self,
        authority: &BrokerAuthority,
        request: EffectIntent,
    ) -> Result<Mutation<EffectSnapshot>, StateError> {
        self.require_broker(authority)?;
        let tx = immediate(&mut self.connection)?;
        if let Some(existing) = load_effect(&tx, &request.attempt_id, &request.idempotency_key)? {
            let attempt = require_attempt(&tx, &request.attempt_id)?;
            let coordinates_match = attempt.base_revision == request.base_revision
                && increment_revision(request.expected_revision).ok()
                    == Some(existing.intent_revision);
            if coordinates_match
                && existing.request_digest == request.request_digest
                && existing.intent_authority == RecordAuthority::Harness
            {
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(existing));
            }
            return Err(StateError::EffectConflict);
        }
        let current = require_attempt(&tx, &request.attempt_id)?;
        validate_attempt_coordinates(&current, &request.base_revision, request.expected_revision)?;
        if current.state.is_terminal() {
            return Err(StateError::TerminalImmutable);
        }
        let revision = increment_revision(current.revision)?;
        map_db(tx.execute(
            "UPDATE attempts SET revision = ?2 WHERE attempt_id = ?1",
            params![request.attempt_id.as_str(), i64_from_revision(revision)?],
        ))?;
        map_db(tx.execute("INSERT INTO effects(attempt_id, idempotency_key, request_digest, status, result_digest, intent_authority, result_authority, intent_revision, result_revision) VALUES (?1, ?2, ?3, 'pending', NULL, ?4, NULL, ?5, NULL)", params![request.attempt_id.as_str(), request.idempotency_key.as_str(), request.request_digest.as_str(), RecordAuthority::Harness.as_str(), i64_from_revision(revision)?]))?;
        let snapshot = EffectSnapshot {
            attempt_id: request.attempt_id,
            idempotency_key: request.idempotency_key,
            request_digest: request.request_digest,
            status: EffectStatus::Pending,
            result_digest: None,
            intent_authority: RecordAuthority::Harness,
            result_authority: None,
            intent_revision: revision,
            result_revision: None,
        };
        tx.commit().map_err(classify_db)?;
        Ok(Mutation::Applied(snapshot))
    }

    pub fn record_effect_result(
        &mut self,
        authority: &BrokerAuthority,
        request: EffectResult,
    ) -> Result<Mutation<EffectSnapshot>, StateError> {
        self.require_broker(authority)?;
        if request.status == EffectStatus::Pending {
            return Err(StateError::PendingEffectRequired);
        }
        let tx = immediate(&mut self.connection)?;
        let existing = load_effect(&tx, &request.attempt_id, &request.idempotency_key)?
            .ok_or(StateError::PendingEffectRequired)?;
        if existing.request_digest != request.request_digest {
            return Err(StateError::EffectConflict);
        }
        if existing.status != EffectStatus::Pending {
            let attempt = require_attempt(&tx, &request.attempt_id)?;
            let coordinates_match = attempt.base_revision == request.base_revision
                && increment_revision(request.expected_revision).ok() == existing.result_revision;
            if coordinates_match
                && existing.status == request.status
                && existing.result_digest.as_ref() == Some(&request.result_digest)
                && existing.result_authority == Some(RecordAuthority::Harness)
            {
                tx.commit().map_err(classify_db)?;
                return Ok(Mutation::Replayed(existing));
            }
            return Err(StateError::EffectConflict);
        }
        let current = require_attempt(&tx, &request.attempt_id)?;
        validate_attempt_coordinates(&current, &request.base_revision, request.expected_revision)?;
        let revision = increment_revision(current.revision)?;
        map_db(tx.execute(
            "UPDATE attempts SET revision = ?2 WHERE attempt_id = ?1",
            params![request.attempt_id.as_str(), i64_from_revision(revision)?],
        ))?;
        map_db(tx.execute("UPDATE effects SET status = ?3, result_digest = ?4, result_authority = ?5, result_revision = ?6 WHERE attempt_id = ?1 AND idempotency_key = ?2", params![request.attempt_id.as_str(), request.idempotency_key.as_str(), request.status.as_str(), request.result_digest.as_str(), RecordAuthority::Harness.as_str(), i64_from_revision(revision)?]))?;
        let snapshot = EffectSnapshot {
            attempt_id: request.attempt_id,
            idempotency_key: request.idempotency_key,
            request_digest: request.request_digest,
            status: request.status,
            result_digest: Some(request.result_digest),
            intent_authority: existing.intent_authority,
            result_authority: Some(RecordAuthority::Harness),
            intent_revision: existing.intent_revision,
            result_revision: Some(revision),
        };
        tx.commit().map_err(classify_db)?;
        Ok(Mutation::Applied(snapshot))
    }

    pub fn effect(
        &self,
        attempt_id: &AttemptId,
        key: &ActionId,
    ) -> Result<Option<EffectSnapshot>, StateError> {
        load_effect(&self.connection, attempt_id, key)
    }
}

fn validate_database_path(path: &Path) -> Result<PathBuf, StateError> {
    if !path.is_absolute() {
        return Err(StateError::UnsafePath("path must be absolute"));
    }
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(part) => current.push(part),
            Component::CurDir | Component::ParentDir => {
                return Err(StateError::UnsafePath("dot segments are forbidden"));
            }
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(StateError::UnsafePath("path contains a symlink"));
                }
                if index + 1 < components.len() && !metadata.is_dir() {
                    return Err(StateError::UnsafePath(
                        "parent component is not a directory",
                    ));
                }
                if index + 1 == components.len() && !metadata.is_file() {
                    return Err(StateError::UnsafePath(
                        "database path is not a regular file",
                    ));
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && index + 1 == components.len() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StateError::UnsafePath("database parent does not exist"));
            }
            Err(_) => return Err(StateError::UnsafePath("database path cannot be inspected")),
        }
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "linux")]
fn effective_user_id() -> Result<u32, StateError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| StateError::UnsafePath("effective user cannot be determined"))?;
    let line =
        status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .ok_or(StateError::UnsafePath(
                "effective user cannot be determined",
            ))?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or(StateError::UnsafePath(
            "effective user cannot be determined",
        ))?
        .parse()
        .map_err(|_| StateError::UnsafePath("effective user cannot be determined"))
}

#[cfg(not(target_os = "linux"))]
fn effective_user_id() -> Result<u32, StateError> {
    Err(StateError::UnsafePath(
        "private ownership enforcement requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn enforce_mode(
    path: &Path,
    effective_uid: u32,
    expected_mode: u32,
    kind: &'static str,
    directory: bool,
) -> Result<(), StateError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| StateError::UnsafePath("state path cannot be inspected"))?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(StateError::UnsafePath("state path has an unsafe file type"));
    }
    if metadata.uid() != effective_uid {
        return Err(StateError::UnsafePath(
            "state path is not owned by the effective user",
        ));
    }
    if directory && metadata.mode() & 0o7777 != expected_mode {
        return Err(StateError::UnsafePath(kind));
    }
    if !directory && metadata.mode() & 0o7777 != expected_mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(expected_mode))
            .map_err(|_| StateError::UnsafePath("private state mode cannot be enforced"))?;
    }
    let checked = std::fs::symlink_metadata(path)
        .map_err(|_| StateError::UnsafePath("state path cannot be rechecked"))?;
    if checked.file_type().is_symlink()
        || checked.uid() != effective_uid
        || checked.mode() & 0o7777 != expected_mode
        || (directory && !checked.is_dir())
        || (!directory && !checked.is_file())
    {
        return Err(StateError::UnsafePath(kind));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enforce_mode(
    _path: &Path,
    _effective_uid: u32,
    _expected_mode: u32,
    _kind: &'static str,
    _directory: bool,
) -> Result<(), StateError> {
    Err(StateError::UnsafePath(
        "private mode enforcement requires Linux",
    ))
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn secure_owned_file(
    path: &Path,
    effective_uid: u32,
    kind: &'static str,
) -> Result<(), StateError> {
    enforce_mode(path, effective_uid, 0o600, kind, false)
}

fn secure_existing_file(
    path: &Path,
    effective_uid: u32,
    kind: &'static str,
) -> Result<(), StateError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => secure_owned_file(path, effective_uid, kind),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StateError::UnsafePath("state sidecar cannot be inspected")),
    }
}

fn secure_state_paths_before_open(path: &Path) -> Result<u32, StateError> {
    let effective_uid = effective_user_id()?;
    let parent = path
        .parent()
        .filter(|parent| parent.parent().is_some())
        .ok_or(StateError::UnsafePath(
            "database requires a dedicated parent directory",
        ))?;
    enforce_mode(
        parent,
        effective_uid,
        0o700,
        "state directory is not private",
        true,
    )?;
    secure_existing_file(path, effective_uid, "database is not private")?;
    secure_existing_file(
        &sidecar_path(path, "-wal"),
        effective_uid,
        "WAL is not private",
    )?;
    secure_existing_file(
        &sidecar_path(path, "-shm"),
        effective_uid,
        "shared-memory file is not private",
    )?;
    Ok(effective_uid)
}

fn secure_state_files(path: &Path, effective_uid: u32) -> Result<(), StateError> {
    secure_owned_file(path, effective_uid, "database is not private")?;
    secure_existing_file(
        &sidecar_path(path, "-wal"),
        effective_uid,
        "WAL is not private",
    )?;
    secure_existing_file(
        &sidecar_path(path, "-shm"),
        effective_uid,
        "shared-memory file is not private",
    )
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StateError> {
    let found: i64 = map_db(connection.pragma_query_value(None, "user_version", |row| row.get(0)))?;
    match found {
        0 => {
            let tx = immediate(connection)?;
            map_db(tx.execute_batch(MIGRATION_0001))?;
            map_db(tx.pragma_update(None, "user_version", SCHEMA_VERSION))?;
            tx.commit().map_err(classify_db)
        }
        SCHEMA_VERSION => Ok(()),
        other => Err(StateError::SchemaVersion { found: other }),
    }
}

fn verify_connection(connection: &Connection) -> Result<(), StateError> {
    let foreign_keys: i64 =
        map_db(connection.pragma_query_value(None, "foreign_keys", |row| row.get(0)))?;
    let synchronous: i64 =
        map_db(connection.pragma_query_value(None, "synchronous", |row| row.get(0)))?;
    let version: i64 =
        map_db(connection.pragma_query_value(None, "user_version", |row| row.get(0)))?;
    if foreign_keys != 1 || synchronous != 2 {
        return Err(StateError::Corrupt("required SQLite pragmas are inactive"));
    }
    if version != SCHEMA_VERSION {
        return Err(StateError::SchemaVersion { found: version });
    }
    let schema: i64 = map_db(connection.query_row(
        "SELECT schema_version FROM automonique_lab_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    ))?;
    if schema != SCHEMA_VERSION {
        return Err(StateError::SchemaVersion { found: schema });
    }
    Ok(())
}

type SchemaRow = (String, String, String, String);

fn schema_manifest(connection: &Connection) -> Result<Vec<SchemaRow>, StateError> {
    let mut statement = map_db(connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ))?;
    let rows = map_db(statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    }))?;
    rows.map(map_db).collect()
}

fn pragma_ok(connection: &Connection, pragma: &str) -> Result<bool, StateError> {
    let mut statement = map_db(connection.prepare(pragma))?;
    let rows = map_db(statement.query_map([], |row| row.get::<_, String>(0)))?;
    let values = rows.map(map_db).collect::<Result<Vec<_>, _>>()?;
    Ok(values == ["ok"])
}

fn verify_durable_state(connection: &Connection) -> Result<(), StateError> {
    if !pragma_ok(connection, "PRAGMA quick_check(1)")?
        || !pragma_ok(connection, "PRAGMA integrity_check(1)")?
    {
        return Err(StateError::Corrupt("SQLite integrity check failed"));
    }
    let mut foreign_keys = map_db(connection.prepare("PRAGMA foreign_key_check"))?;
    if map_db(foreign_keys.exists([]))? {
        return Err(StateError::Corrupt("foreign-key check failed"));
    }

    let expected = map_db(Connection::open_in_memory())?;
    map_db(expected.execute_batch(MIGRATION_0001))?;
    if schema_manifest(connection)? != schema_manifest(&expected)? {
        return Err(StateError::Corrupt(
            "schema manifest differs from migration",
        ));
    }

    let bad_attempts: i64 = map_db(connection.query_row(
        "SELECT count(*) FROM attempts AS a WHERE
           a.last_sequence != coalesce((SELECT max(j.sequence) FROM journal_records AS j WHERE j.attempt_id = a.attempt_id), 0)
           OR a.revision != max(
             coalesce((SELECT max(j.attempt_revision) FROM journal_records AS j WHERE j.attempt_id = a.attempt_id), 0),
             coalesce((SELECT max(e.intent_revision) FROM effects AS e WHERE e.attempt_id = a.attempt_id), 0),
             coalesce((SELECT max(e.result_revision) FROM effects AS e WHERE e.attempt_id = a.attempt_id), 0),
             coalesce((SELECT max(l.acquired_revision) FROM path_leases AS l WHERE l.attempt_id = a.attempt_id), 0),
             coalesce((SELECT max(s.result_revision) FROM state_actions AS s WHERE s.attempt_id = a.attempt_id), 0)
           )",
        [],
        |row| row.get(0),
    ))?;
    let bad_journal: i64 = map_db(connection.query_row(
        "SELECT count(*) FROM (
           SELECT attempt_id, count(*) AS records, max(sequence) AS last_sequence,
                  count(DISTINCT attempt_revision) AS revisions
           FROM journal_records GROUP BY attempt_id
         ) WHERE records != last_sequence OR records != revisions",
        [],
        |row| row.get(0),
    ))?;
    let bad_actions: i64 = map_db(connection.query_row(
        "SELECT count(*) FROM state_actions AS s
         WHERE s.operation = 'release_lease'
            OR s.result_revision > (SELECT revision FROM attempts WHERE attempt_id = s.attempt_id)
            OR (s.operation = 'transition' AND (
                s.authority != 'harness' OR NOT EXISTS (
                  SELECT 1 FROM journal_records AS j
                  WHERE j.attempt_id = s.attempt_id AND j.record_id = s.action_id
                    AND j.kind = 'event' AND j.sequence = s.result_sequence
                    AND j.attempt_revision = s.result_revision
                    AND j.payload_digest = s.record_digest AND j.authority = 'harness')))
            OR (s.operation = 'acquire_lease' AND NOT EXISTS (
                SELECT 1 FROM state_action_paths AS p WHERE p.action_id = s.action_id))",
        [],
        |row| row.get(0),
    ))?;
    let bad_authority: i64 = map_db(connection.query_row(
        "SELECT
          (SELECT count(*) FROM journal_records WHERE authority != 'harness')
          + (SELECT count(*) FROM effects WHERE intent_authority != 'harness'
              OR (result_authority IS NOT NULL AND result_authority != 'harness'))
          + (SELECT count(*) FROM path_leases AS l JOIN attempts AS a USING(attempt_id)
              WHERE a.state IN ('succeeded', 'failed', 'blocked', 'cancelled'))
          + (SELECT count(*) FROM path_leases
              WHERE epoch > (SELECT last_lease_epoch FROM automonique_lab_meta WHERE singleton = 1))",
        [],
        |row| row.get(0),
    ))?;
    let orphan_leases: i64 = map_db(connection.query_row(
        "SELECT count(*) FROM path_leases AS l
         WHERE (SELECT count(*)
                FROM state_actions AS s
                JOIN state_action_paths AS p ON p.action_id = s.action_id
                WHERE s.operation = 'acquire_lease'
                  AND s.attempt_id = l.attempt_id
                  AND s.lease_id = l.lease_id
                  AND s.lease_epoch = l.epoch
                  AND s.result_revision = l.acquired_revision
                  AND p.path = l.path) != 1",
        [],
        |row| row.get(0),
    ))?;
    if bad_attempts != 0
        || bad_journal != 0
        || bad_actions != 0
        || bad_authority != 0
        || orphan_leases != 0
    {
        return Err(StateError::Corrupt("durable semantic invariant failed"));
    }

    let mut acquisitions = map_db(connection.prepare(
        "SELECT action_id FROM state_actions WHERE operation = 'acquire_lease' ORDER BY action_id",
    ))?;
    let action_ids = map_db(acquisitions.query_map([], |row| row.get::<_, String>(0)))?
        .map(map_db)
        .collect::<Result<Vec<_>, _>>()?;
    for action_id in action_ids {
        let action_id = parse_action_id(action_id)?;
        let action = load_state_action(connection, &action_id)?
            .ok_or(StateError::Corrupt("acquisition action disappeared"))?;
        let paths = load_action_paths(connection, &action_id)?;
        let _active = stored_acquire_is_active(connection, &action, &paths)?;
    }

    let leases = load_all_lease_rows(connection)?;
    for (index, LeaseRow(_, _, first, _, _)) in leases.iter().enumerate() {
        if leases[index + 1..]
            .iter()
            .any(|LeaseRow(_, _, second, _, _)| first.overlaps(second))
        {
            return Err(StateError::Corrupt("persisted lease paths overlap"));
        }
    }
    Ok(())
}

fn immediate(connection: &mut Connection) -> Result<Transaction<'_>, StateError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(classify_db)
}

fn classify_db(error: rusqlite::Error) -> StateError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error
        && matches!(
            code.code,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
        )
    {
        return StateError::Busy;
    }
    StateError::Database(error)
}

fn map_db<T>(result: rusqlite::Result<T>) -> Result<T, StateError> {
    result.map_err(classify_db)
}

fn i64_from_revision(value: Revision) -> Result<i64, StateError> {
    i64_from_u64(value.get()).map_err(|_| StateError::RevisionOverflow)
}
fn revision_from_i64(value: i64) -> Result<Revision, StateError> {
    Ok(Revision::from_u64(u64_from_i64(value)?))
}
fn i64_from_u64(value: u64) -> Result<i64, StateError> {
    i64::try_from(value).map_err(|_| StateError::Corrupt("integer exceeds SQLite range"))
}
fn u64_from_i64(value: i64) -> Result<u64, StateError> {
    u64::try_from(value).map_err(|_| StateError::Corrupt("negative durable integer"))
}
fn increment_revision(value: Revision) -> Result<Revision, StateError> {
    value
        .get()
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .map(Revision::from_u64)
        .ok_or(StateError::RevisionOverflow)
}
fn increment_sequence(value: u64) -> Result<u64, StateError> {
    value
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(StateError::SequenceOverflow)
}

fn parse_attempt_id(value: String) -> Result<AttemptId, StateError> {
    AttemptId::parse(value).map_err(|_| StateError::Corrupt("attempt ID is invalid"))
}
fn parse_action_id(value: String) -> Result<ActionId, StateError> {
    ActionId::parse(value).map_err(|_| StateError::Corrupt("action ID is invalid"))
}
fn parse_lease_id(value: String) -> Result<LeaseId, StateError> {
    LeaseId::parse(value).map_err(|_| StateError::Corrupt("lease ID is invalid"))
}
fn parse_objective_id(value: String) -> Result<OpaqueId, StateError> {
    OpaqueId::new(value).map_err(|_| StateError::Corrupt("objective ID is invalid"))
}
fn parse_base(value: String) -> Result<BaseRevision, StateError> {
    BaseRevision::parse(value).map_err(|_| StateError::Corrupt("base revision is invalid"))
}
fn parse_sha256(value: String) -> Result<Sha256Digest, StateError> {
    Sha256Digest::new(value).map_err(|_| StateError::Corrupt("SHA-256 is invalid"))
}
fn parse_path(value: String) -> Result<RepoPath, StateError> {
    RepoPath::parse(value).map_err(|_| StateError::Corrupt("lease path is invalid"))
}

type AttemptRow = (String, String, String, i64, i64);

trait SqlRead {
    fn query_attempt(&self, attempt_id: &AttemptId) -> rusqlite::Result<Option<AttemptRow>>;
}
impl SqlRead for Connection {
    fn query_attempt(&self, id: &AttemptId) -> rusqlite::Result<Option<AttemptRow>> {
        self.query_row("SELECT objective_id, base_revision, state, revision, last_sequence FROM attempts WHERE attempt_id = ?1", [id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional()
    }
}
impl SqlRead for Transaction<'_> {
    fn query_attempt(&self, id: &AttemptId) -> rusqlite::Result<Option<AttemptRow>> {
        self.query_row("SELECT objective_id, base_revision, state, revision, last_sequence FROM attempts WHERE attempt_id = ?1", [id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional()
    }
}

fn load_attempt(
    reader: &impl SqlRead,
    attempt_id: &AttemptId,
) -> Result<Option<AttemptSnapshot>, StateError> {
    let row = map_db(reader.query_attempt(attempt_id))?;
    row.map(|(objective, base, state, revision, sequence)| {
        Ok(AttemptSnapshot {
            attempt_id: attempt_id.clone(),
            objective_id: parse_objective_id(objective)?,
            base_revision: parse_base(base)?,
            state: AttemptState::parse(&state)?,
            revision: revision_from_i64(revision)?,
            last_sequence: u64_from_i64(sequence)?,
        })
    })
    .transpose()
}

fn require_attempt(
    reader: &impl SqlRead,
    attempt_id: &AttemptId,
) -> Result<AttemptSnapshot, StateError> {
    load_attempt(reader, attempt_id)?.ok_or(StateError::NotFound("attempt"))
}

fn validate_attempt_coordinates(
    attempt: &AttemptSnapshot,
    base: &BaseRevision,
    expected: Revision,
) -> Result<(), StateError> {
    if &attempt.base_revision != base {
        return Err(StateError::BaseRevisionMismatch);
    }
    if attempt.revision != expected {
        return Err(StateError::RevisionConflict {
            expected,
            actual: attempt.revision,
        });
    }
    Ok(())
}

fn insert_journal(tx: &Transaction<'_>, record: &JournalRecord) -> Result<(), StateError> {
    map_db(tx.execute("INSERT INTO journal_records(attempt_id, sequence, record_id, kind, attempt_revision, authority, payload_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![record.attempt_id.as_str(), i64_from_u64(record.sequence)?, record.record_id.as_str(), record.kind.as_str(), i64_from_revision(record.attempt_revision)?, record.authority.as_str(), record.payload_digest.as_str()]))?;
    Ok(())
}

fn load_record_by_id(
    connection: &Connection,
    attempt_id: &AttemptId,
    record_id: &ActionId,
) -> Result<Option<JournalRecord>, StateError> {
    let row: Option<(i64, String, i64, String, String)> = map_db(connection.query_row("SELECT sequence, kind, attempt_revision, authority, payload_digest FROM journal_records WHERE attempt_id = ?1 AND record_id = ?2", params![attempt_id.as_str(), record_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional())?;
    row.map(|(sequence, kind, revision, authority, digest)| {
        Ok(JournalRecord {
            attempt_id: attempt_id.clone(),
            sequence: u64_from_i64(sequence)?,
            record_id: record_id.clone(),
            kind: JournalKind::parse(&kind)?,
            attempt_revision: revision_from_i64(revision)?,
            authority: RecordAuthority::parse(&authority)?,
            payload_digest: parse_sha256(digest)?,
        })
    })
    .transpose()
}

#[derive(Debug)]
struct StoredAction {
    action_id: String,
    operation: String,
    attempt_id: String,
    base_revision: String,
    expected_revision: i64,
    target_state: Option<String>,
    record_digest: Option<String>,
    authority: Option<String>,
    lease_id: Option<String>,
    lease_epoch: Option<i64>,
    result_revision: i64,
    result_sequence: Option<i64>,
    released_lease_count: i64,
}

impl StoredAction {
    fn transition(
        request: &TransitionAttempt,
        revision: Revision,
        sequence: u64,
        released: u64,
    ) -> Result<Self, StateError> {
        Ok(Self {
            action_id: request.action_id.as_str().into(),
            operation: "transition".into(),
            attempt_id: request.attempt_id.as_str().into(),
            base_revision: request.base_revision.as_str().into(),
            expected_revision: i64_from_revision(request.expected_revision)?,
            target_state: Some(request.target.as_str().into()),
            record_digest: Some(request.event_digest.as_str().into()),
            authority: Some(RecordAuthority::Harness.as_str().into()),
            lease_id: None,
            lease_epoch: None,
            result_revision: i64_from_revision(revision)?,
            result_sequence: Some(i64_from_u64(sequence)?),
            released_lease_count: i64_from_u64(released)?,
        })
    }
    fn acquire(request: &AcquirePaths, revision: Revision, epoch: u64) -> Result<Self, StateError> {
        Ok(Self {
            action_id: request.action_id.as_str().into(),
            operation: "acquire_lease".into(),
            attempt_id: request.attempt_id.as_str().into(),
            base_revision: request.base_revision.as_str().into(),
            expected_revision: i64_from_revision(request.expected_revision)?,
            target_state: None,
            record_digest: None,
            authority: None,
            lease_id: Some(request.lease_id.as_str().into()),
            lease_epoch: Some(i64_from_u64(epoch)?),
            result_revision: i64_from_revision(revision)?,
            result_sequence: None,
            released_lease_count: 0,
        })
    }
    fn matches_transition(&self, request: &TransitionAttempt) -> bool {
        self.operation == "transition"
            && self.attempt_id == request.attempt_id.as_str()
            && self.base_revision == request.base_revision.as_str()
            && Some(self.expected_revision) == i64_from_revision(request.expected_revision).ok()
            && self.target_state.as_deref() == Some(request.target.as_str())
            && self.record_digest.as_deref() == Some(request.event_digest.as_str())
            && self.authority.as_deref() == Some(RecordAuthority::Harness.as_str())
    }
    fn matches_acquire(&self, request: &AcquirePaths) -> bool {
        self.operation == "acquire_lease"
            && self.attempt_id == request.attempt_id.as_str()
            && self.base_revision == request.base_revision.as_str()
            && Some(self.expected_revision) == i64_from_revision(request.expected_revision).ok()
            && self.lease_id.as_deref() == Some(request.lease_id.as_str())
    }
}

fn load_state_action(
    connection: &Connection,
    action_id: &ActionId,
) -> Result<Option<StoredAction>, StateError> {
    map_db(connection.query_row("SELECT operation, attempt_id, base_revision, expected_revision, target_state, record_digest, authority, lease_id, lease_epoch, result_revision, result_sequence, released_lease_count FROM state_actions WHERE action_id = ?1", [action_id.as_str()], |row| Ok(StoredAction { action_id: action_id.as_str().into(), operation: row.get(0)?, attempt_id: row.get(1)?, base_revision: row.get(2)?, expected_revision: row.get(3)?, target_state: row.get(4)?, record_digest: row.get(5)?, authority: row.get(6)?, lease_id: row.get(7)?, lease_epoch: row.get(8)?, result_revision: row.get(9)?, result_sequence: row.get(10)?, released_lease_count: row.get(11)? })).optional())
}

fn insert_state_action(tx: &Transaction<'_>, action: &StoredAction) -> Result<(), StateError> {
    map_db(tx.execute("INSERT INTO state_actions(action_id, operation, attempt_id, base_revision, expected_revision, target_state, record_digest, authority, lease_id, lease_epoch, result_revision, result_sequence, released_lease_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)", params![action.action_id, action.operation, action.attempt_id, action.base_revision, action.expected_revision, action.target_state, action.record_digest, action.authority, action.lease_id, action.lease_epoch, action.result_revision, action.result_sequence, action.released_lease_count]))?;
    Ok(())
}

fn insert_action_paths(
    tx: &Transaction<'_>,
    action_id: &ActionId,
    paths: &[RepoPath],
) -> Result<(), StateError> {
    for (index, path) in paths.iter().enumerate() {
        map_db(tx.execute(
            "INSERT INTO state_action_paths(action_id, ordinal, path) VALUES (?1, ?2, ?3)",
            params![
                action_id.as_str(),
                i64::try_from(index).map_err(|_| StateError::TooManyPaths)?,
                path.as_str()
            ],
        ))?;
    }
    Ok(())
}
fn load_action_paths(
    connection: &Connection,
    action_id: &ActionId,
) -> Result<Vec<RepoPath>, StateError> {
    let mut statement = map_db(
        connection
            .prepare("SELECT path FROM state_action_paths WHERE action_id = ?1 ORDER BY ordinal"),
    )?;
    let rows = map_db(statement.query_map([action_id.as_str()], |row| row.get::<_, String>(0)))?;
    rows.map(|row| parse_path(map_db(row)?)).collect()
}

fn stored_acquire_is_active(
    connection: &Connection,
    action: &StoredAction,
    expected_paths: &[RepoPath],
) -> Result<bool, StateError> {
    if action.operation != "acquire_lease" {
        return Err(StateError::Corrupt("action is not an acquisition"));
    }
    let lease_id = parse_lease_id(
        action
            .lease_id
            .clone()
            .ok_or(StateError::Corrupt("acquisition has no lease ID"))?,
    )?;
    let attempt_id = parse_attempt_id(action.attempt_id.clone())?;
    let epoch = FenceEpoch::from_u64(u64_from_i64(
        action
            .lease_epoch
            .ok_or(StateError::Corrupt("acquisition has no epoch"))?,
    )?);
    let revision = revision_from_i64(action.result_revision)?;
    let active = load_all_lease_rows(connection)?
        .into_iter()
        .filter(|LeaseRow(candidate, _, _, _, _)| candidate == &lease_id)
        .collect::<Vec<_>>();
    let active_paths = active
        .iter()
        .map(|LeaseRow(_, _, path, _, _)| path.clone())
        .collect::<Vec<_>>();
    let exact = active_paths == expected_paths
        && active.iter().all(
            |LeaseRow(_, candidate_attempt, _, candidate_epoch, candidate_revision)| {
                candidate_attempt == &attempt_id
                    && *candidate_epoch == epoch
                    && *candidate_revision == revision
            },
        );
    if exact {
        return Ok(true);
    }
    if require_attempt(connection, &attempt_id)?
        .state
        .is_terminal()
    {
        return Ok(false);
    }
    Err(StateError::Corrupt(
        "active lease differs from its acquisition receipt",
    ))
}

fn validate_path_set(paths: &[RepoPath]) -> Result<(), StateError> {
    if paths.is_empty() {
        return Err(StateError::EmptyPathSet);
    }
    if paths.len() > MAX_LEASE_PATHS {
        return Err(StateError::TooManyPaths);
    }
    for (index, first) in paths.iter().enumerate() {
        if paths[index + 1..]
            .iter()
            .any(|second| first.overlaps(second))
        {
            return Err(StateError::RequestedPathsOverlap);
        }
    }
    Ok(())
}

struct LeaseRow(LeaseId, AttemptId, RepoPath, FenceEpoch, Revision);

fn load_all_lease_rows(connection: &Connection) -> Result<Vec<LeaseRow>, StateError> {
    let mut statement = map_db(connection.prepare("SELECT lease_id, attempt_id, path, epoch, acquired_revision FROM path_leases ORDER BY lease_id, path"))?;
    let rows = map_db(statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    }))?;
    rows.map(|row| {
        let (lease, attempt, path, epoch, revision) = map_db(row)?;
        Ok(LeaseRow(
            parse_lease_id(lease)?,
            parse_attempt_id(attempt)?,
            parse_path(path)?,
            FenceEpoch::from_u64(u64_from_i64(epoch)?),
            revision_from_i64(revision)?,
        ))
    })
    .collect()
}

type EffectRow = (
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    i64,
    Option<i64>,
);

fn load_effect(
    connection: &Connection,
    attempt_id: &AttemptId,
    key: &ActionId,
) -> Result<Option<EffectSnapshot>, StateError> {
    let row: Option<EffectRow> = map_db(connection.query_row("SELECT request_digest, status, result_digest, intent_authority, result_authority, intent_revision, result_revision FROM effects WHERE attempt_id = ?1 AND idempotency_key = ?2", params![attempt_id.as_str(), key.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))).optional())?;
    row.map(
        |(request, status, result, intent_auth, result_auth, intent_rev, result_rev)| {
            Ok(EffectSnapshot {
                attempt_id: attempt_id.clone(),
                idempotency_key: key.clone(),
                request_digest: parse_sha256(request)?,
                status: EffectStatus::parse(&status)?,
                result_digest: result.map(parse_sha256).transpose()?,
                intent_authority: RecordAuthority::parse(&intent_auth)?,
                result_authority: result_auth
                    .map(|value| RecordAuthority::parse(&value))
                    .transpose()?,
                intent_revision: revision_from_i64(intent_rev)?,
                result_revision: result_rev.map(revision_from_i64).transpose()?,
            })
        },
    )
    .transpose()
}
