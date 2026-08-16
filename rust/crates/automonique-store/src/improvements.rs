// SPDX-License-Identifier: Elastic-2.0

//! Durable state for owner-directed Automonique self-improvements.
//!
//! An improvement is deliberately a two-gate workflow. A plan can be revised
//! until an owner approves its exact digest; implementation then produces an
//! exact release manifest which requires a second approval before activation.
//! Approval challenges are single-use, expire, and are bound to the requesting
//! actor, Telegram chat, durable revision, and artifact digest. This store does
//! not authenticate an actor or talk to GitHub/Telegram: it persists the facts
//! an authenticated coordinator has already established.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

pub const IMPROVEMENT_STORE_SCHEMA_VERSION: u32 = 2;
pub const MAX_IMPROVEMENTS: usize = 65_536;
pub const MAX_FIELD_BYTES: usize = 512;
pub const MAX_URL_BYTES: usize = 2_048;
pub const MAX_SUMMARY_BYTES: usize = 8_192;
pub const MAX_CI_EVIDENCE_BYTES: usize = 4_096;

const SCHEMA_V1: &str = r#"
CREATE TABLE improvements (
    entry_id INTEGER PRIMARY KEY,
    request_key TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    summary TEXT NOT NULL,
    source_repo TEXT NOT NULL,
    planning_repo TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'draft', 'plan_review', 'plan_approved', 'implementing',
        'release_review', 'release_approved', 'activating',
        'completed', 'failed', 'rolled_back'
    )),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    plan_digest TEXT,
    plan_head_sha TEXT,
    source_base_sha TEXT,
    issue_number INTEGER CHECK (issue_number IS NULL OR issue_number > 0),
    issue_url TEXT,
    plan_pr_number INTEGER CHECK (plan_pr_number IS NULL OR plan_pr_number > 0),
    plan_pr_url TEXT,
    implementation_head_sha TEXT,
    implementation_tree_sha TEXT,
    release_manifest_digest TEXT,
    implementation_pr_number INTEGER CHECK (
        implementation_pr_number IS NULL OR implementation_pr_number > 0
    ),
    implementation_pr_url TEXT,
    active_release_digest TEXT,
    last_actor TEXT NOT NULL,
    failure_reason TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK ((state IN ('plan_review', 'plan_approved', 'implementing',
                      'release_review', 'release_approved', 'activating',
                      'completed', 'failed', 'rolled_back')) =
           (plan_digest IS NOT NULL)),
    CHECK (state NOT IN ('release_review', 'release_approved', 'activating',
                         'completed', 'rolled_back') OR
           release_manifest_digest IS NOT NULL),
    CHECK (state NOT IN ('draft', 'plan_review', 'plan_approved', 'implementing') OR
           release_manifest_digest IS NULL),
    CHECK ((state = 'completed') = (active_release_digest IS NOT NULL)),
    CHECK ((state = 'failed') = (failure_reason IS NOT NULL))
) STRICT;

CREATE TABLE improvement_events (
    event_id INTEGER PRIMARY KEY,
    improvement_id INTEGER NOT NULL REFERENCES improvements(entry_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    artifact_digest TEXT,
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    UNIQUE (improvement_id, revision)
) STRICT;

CREATE TABLE improvement_plan_drafts (
    improvement_id INTEGER NOT NULL REFERENCES improvements(entry_id),
    based_on_revision INTEGER NOT NULL CHECK (based_on_revision >= 1),
    source_base_sha TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    markdown TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (improvement_id, based_on_revision)
) STRICT;

CREATE TABLE improvement_approval_challenges (
    challenge_key TEXT PRIMARY KEY,
    improvement_id INTEGER NOT NULL REFERENCES improvements(entry_id),
    approval_kind TEXT NOT NULL CHECK (approval_kind IN ('plan', 'release')),
    bound_revision INTEGER NOT NULL CHECK (bound_revision >= 1),
    artifact_digest TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    consumed_at_ms INTEGER CHECK (consumed_at_ms IS NULL OR consumed_at_ms >= 0),
    CHECK (expires_at_ms >= created_at_ms)
) STRICT;

CREATE INDEX improvements_by_state ON improvements(state, entry_id);
CREATE INDEX improvement_events_by_improvement
    ON improvement_events(improvement_id, revision);
CREATE INDEX improvement_challenges_by_improvement
    ON improvement_approval_challenges(improvement_id, approval_kind, bound_revision);
"#;

/// The remote-CI evidence a release must carry before it may activate: the
/// exact commit CI ran on, and one entry per required check naming its run.
///
/// The column is nullable because a V1 database may already hold rows in
/// `activating` or `completed` that predate the gate, and a migration that
/// refused to open such a database would lose the journal it is meant to
/// preserve. Presence is enforced on the write path instead: `transition`
/// requires it to reach `activating`, so no new record can get there without
/// it.
const MIGRATE_V1_TO_V2: &str = r#"
ALTER TABLE improvements ADD COLUMN ci_evidence TEXT;
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImprovementState {
    Draft,
    PlanReview,
    PlanApproved,
    Implementing,
    ReleaseReview,
    ReleaseApproved,
    Activating,
    Completed,
    Failed,
    RolledBack,
}

impl ImprovementState {
    pub const ALL: [Self; 10] = [
        Self::Draft,
        Self::PlanReview,
        Self::PlanApproved,
        Self::Implementing,
        Self::ReleaseReview,
        Self::ReleaseApproved,
        Self::Activating,
        Self::Completed,
        Self::Failed,
        Self::RolledBack,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PlanReview => "plan_review",
            Self::PlanApproved => "plan_approved",
            Self::Implementing => "implementing",
            Self::ReleaseReview => "release_review",
            Self::ReleaseApproved => "release_approved",
            Self::Activating => "activating",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }

    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::RolledBack)
    }
}

impl fmt::Display for ImprovementState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalKind {
    Plan,
    Release,
}

impl ApprovalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Release => "release",
        }
    }

    fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "plan" => Some(Self::Plan),
            "release" => Some(Self::Release),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum ImprovementStoreError {
    InsecurePath(String),
    SchemaVersion {
        found: u32,
        supported: u32,
    },
    InvalidField(&'static str),
    IdempotencyConflict,
    NotFound(&'static str),
    StaleRevision {
        expected: u64,
        actual: u64,
    },
    IllegalTransition {
        from: ImprovementState,
        to: ImprovementState,
    },
    ApprovalRequired(ApprovalKind),
    ChallengeConsumed,
    ChallengeExpired,
    ChallengeMismatch(&'static str),
    Capacity,
    Corrupt(&'static str),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for ImprovementStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "insecure improvement store path: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "unsupported improvement store schema {found}; supported {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid improvement field: {field}"),
            Self::IdempotencyConflict => {
                formatter.write_str("improvement request key reused with different content")
            }
            Self::NotFound(kind) => write!(formatter, "{kind} not found"),
            Self::StaleRevision { expected, actual } => write!(
                formatter,
                "stale improvement revision: expected {expected}, actual {actual}"
            ),
            Self::IllegalTransition { from, to } => write!(
                formatter,
                "illegal improvement transition from {from} to {to}"
            ),
            Self::ApprovalRequired(kind) => write!(
                formatter,
                "{} approval must use a bound challenge",
                kind.as_str()
            ),
            Self::ChallengeConsumed => formatter.write_str("approval challenge already consumed"),
            Self::ChallengeExpired => formatter.write_str("approval challenge expired"),
            Self::ChallengeMismatch(field) => {
                write!(formatter, "approval challenge mismatch: {field}")
            }
            Self::Capacity => formatter.write_str("improvement registry capacity reached"),
            Self::Corrupt(field) => write!(formatter, "corrupt improvement store field: {field}"),
            Self::Io(error) => write!(formatter, "improvement store I/O error: {error}"),
            Self::Sqlite(error) => write!(formatter, "improvement store SQLite error: {error}"),
        }
    }
}

impl Error for ImprovementStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ImprovementStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for ImprovementStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

type Stored<T> = Result<T, ImprovementStoreError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewImprovement<'a> {
    pub request_key: &'a str,
    pub actor_id: &'a str,
    pub chat_id: &'a str,
    pub summary: &'a str,
    pub source_repo: &'a str,
    pub planning_repo: &'a str,
    pub now_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanSubmission<'a> {
    pub improvement_id: i64,
    pub expected_revision: u64,
    pub actor: &'a str,
    pub plan_digest: &'a str,
    pub plan_head_sha: &'a str,
    pub source_base_sha: &'a str,
    pub issue_number: u64,
    pub issue_url: &'a str,
    pub plan_pr_number: u64,
    pub plan_pr_url: &'a str,
    pub now_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseSubmission<'a> {
    pub improvement_id: i64,
    pub expected_revision: u64,
    pub actor: &'a str,
    pub implementation_head_sha: &'a str,
    pub implementation_tree_sha: &'a str,
    pub release_manifest_digest: &'a str,
    pub implementation_pr_number: u64,
    pub implementation_pr_url: &'a str,
    pub now_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateTransition<'a> {
    pub improvement_id: i64,
    pub expected_revision: u64,
    pub actor: &'a str,
    pub to: ImprovementState,
    pub failure_reason: Option<&'a str>,
    pub active_release_digest: Option<&'a str>,
    /// Required to reach `activating` and refused anywhere else. This is what
    /// makes "a release activates only on green remote CI" a property of the
    /// store rather than a convention the caller is trusted to keep.
    pub ci_evidence: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewApprovalChallenge<'a> {
    pub challenge_key: &'a str,
    pub improvement_id: i64,
    pub expected_revision: u64,
    pub kind: ApprovalKind,
    pub actor_id: &'a str,
    pub chat_id: &'a str,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalAttempt<'a> {
    pub challenge_key: &'a str,
    pub actor_id: &'a str,
    pub chat_id: &'a str,
    pub now_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementRecord {
    pub entry_id: i64,
    pub request_key: String,
    pub actor_id: String,
    pub chat_id: String,
    pub summary: String,
    pub source_repo: String,
    pub planning_repo: String,
    pub state: ImprovementState,
    pub revision: u64,
    pub plan_digest: Option<String>,
    pub plan_head_sha: Option<String>,
    pub source_base_sha: Option<String>,
    pub issue_number: Option<u64>,
    pub issue_url: Option<String>,
    pub plan_pr_number: Option<u64>,
    pub plan_pr_url: Option<String>,
    pub implementation_head_sha: Option<String>,
    pub implementation_tree_sha: Option<String>,
    pub release_manifest_digest: Option<String>,
    pub implementation_pr_number: Option<u64>,
    pub implementation_pr_url: Option<String>,
    pub active_release_digest: Option<String>,
    pub last_actor: String,
    pub failure_reason: Option<String>,
    pub ci_evidence: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl ImprovementRecord {
    #[must_use]
    pub fn public_id(&self) -> String {
        format!("IMP-{:06}", self.entry_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementEvent {
    pub event_id: i64,
    pub improvement_id: i64,
    pub revision: u64,
    pub kind: String,
    pub actor: String,
    pub artifact_digest: Option<String>,
    pub occurred_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPlan {
    pub improvement_id: i64,
    pub based_on_revision: u64,
    pub source_base_sha: String,
    pub plan_digest: String,
    pub markdown: String,
    pub created_at_ms: i64,
}

#[derive(Debug)]
pub struct ImprovementStore {
    connection: Connection,
    path: PathBuf,
}

impl ImprovementStore {
    pub fn open(path: impl AsRef<Path>) -> Stored<Self> {
        let path = path.as_ref();
        secure_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        secure_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(ImprovementStoreError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn create(&mut self, input: NewImprovement<'_>) -> Stored<ImprovementRecord> {
        validate_new(&input)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_by_request_key(&transaction, input.request_key)? {
            if existing.actor_id == input.actor_id
                && existing.chat_id == input.chat_id
                && existing.summary == input.summary
                && existing.source_repo == input.source_repo
                && existing.planning_repo == input.planning_repo
            {
                return Ok(existing);
            }
            return Err(ImprovementStoreError::IdempotencyConflict);
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM improvements", [], |row| row.get(0))?;
        if usize::try_from(count).map_err(|_| corrupt("improvement_count"))? >= MAX_IMPROVEMENTS {
            return Err(ImprovementStoreError::Capacity);
        }
        transaction.execute(
            "INSERT INTO improvements (
                request_key, actor_id, chat_id, summary, source_repo, planning_repo,
                state, revision, last_actor, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', 1, ?2, ?7, ?7)",
            params![
                input.request_key,
                input.actor_id,
                input.chat_id,
                input.summary,
                input.source_repo,
                input.planning_repo,
                input.now_ms
            ],
        )?;
        let improvement_id = transaction.last_insert_rowid();
        insert_event(
            &transaction,
            improvement_id,
            1,
            "created",
            input.actor_id,
            None,
            input.now_ms,
        )?;
        let record = read_by_id(&transaction, improvement_id)?
            .ok_or(ImprovementStoreError::NotFound("improvement"))?;
        transaction.commit()?;
        Ok(record)
    }

    pub fn get(&self, improvement_id: i64) -> Stored<Option<ImprovementRecord>> {
        validate_row_id(improvement_id, "improvement_id")?;
        read_by_id(&self.connection, improvement_id)
    }

    /// Add owner guidance to a draft and fence any planner working from the
    /// previous revision. Published/approved work cannot be edited through
    /// this route; it must first return to `draft` through the bound gate.
    pub fn revise_draft(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        summary: &str,
        actor: &str,
        now_ms: i64,
    ) -> Stored<ImprovementRecord> {
        validate_summary(summary)?;
        validate_identifier(actor, "actor")?;
        validate_time(now_ms, "now_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, improvement_id, expected_revision)?;
        if current.state != ImprovementState::Draft {
            return Err(ImprovementStoreError::IllegalTransition {
                from: current.state,
                to: ImprovementState::Draft,
            });
        }
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvements SET summary = ?1, revision = ?2, last_actor = ?3,
                    updated_at_ms = ?4
               WHERE entry_id = ?5 AND revision = ?6",
            params![
                summary,
                to_db_u64(next, "revision")?,
                actor,
                now_ms,
                improvement_id,
                to_db_u64(expected_revision, "expected_revision")?
            ],
        )?;
        insert_event(
            &transaction,
            improvement_id,
            next,
            "draft_revised",
            actor,
            None,
            now_ms,
        )?;
        finish_mutation(transaction, improvement_id)
    }

    pub fn prepare_plan(
        &mut self,
        improvement_id: i64,
        expected_revision: u64,
        source_base_sha: &str,
        plan_digest: &str,
        markdown: &str,
        now_ms: i64,
    ) -> Stored<PreparedPlan> {
        validate_identifier(plan_digest, "plan_digest")?;
        validate_identifier(source_base_sha, "source_base_sha")?;
        if markdown.trim().is_empty() || markdown.len() > 64 * 1024 || markdown.contains('\0') {
            return Err(ImprovementStoreError::InvalidField("plan_markdown"));
        }
        validate_time(now_ms, "now_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, improvement_id, expected_revision)?;
        if current.state != ImprovementState::Draft {
            return Err(ImprovementStoreError::IllegalTransition {
                from: current.state,
                to: ImprovementState::PlanReview,
            });
        }
        let inserted = transaction.execute(
            "INSERT INTO improvement_plan_drafts (
                improvement_id, based_on_revision, source_base_sha, plan_digest, markdown, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(improvement_id, based_on_revision) DO NOTHING",
            params![
                improvement_id,
                to_db_u64(expected_revision, "expected_revision")?,
                source_base_sha,
                plan_digest,
                markdown,
                now_ms
            ],
        )?;
        let prepared = read_prepared_plan(&transaction, improvement_id, expected_revision)?
            .ok_or(ImprovementStoreError::NotFound("prepared plan"))?;
        if inserted == 0
            && (prepared.source_base_sha != source_base_sha
                || prepared.plan_digest != plan_digest
                || prepared.markdown != markdown)
        {
            return Err(ImprovementStoreError::IdempotencyConflict);
        }
        transaction.commit()?;
        Ok(prepared)
    }

    pub fn prepared_plan(
        &self,
        improvement_id: i64,
        based_on_revision: u64,
    ) -> Stored<Option<PreparedPlan>> {
        validate_row_id(improvement_id, "improvement_id")?;
        if based_on_revision == 0 {
            return Err(ImprovementStoreError::InvalidField("based_on_revision"));
        }
        read_prepared_plan(&self.connection, improvement_id, based_on_revision)
    }

    pub fn prepared_plan_for_artifact(
        &self,
        improvement_id: i64,
        source_base_sha: &str,
        plan_digest: &str,
    ) -> Stored<Option<PreparedPlan>> {
        validate_row_id(improvement_id, "improvement_id")?;
        validate_identifier(source_base_sha, "source_base_sha")?;
        validate_identifier(plan_digest, "plan_digest")?;
        let revision = self
            .connection
            .query_row(
                "SELECT based_on_revision
                   FROM improvement_plan_drafts
                  WHERE improvement_id = ?1 AND source_base_sha = ?2 AND plan_digest = ?3
                  ORDER BY based_on_revision DESC LIMIT 1",
                params![improvement_id, source_base_sha, plan_digest],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        revision
            .map(|revision| {
                read_prepared_plan(
                    &self.connection,
                    improvement_id,
                    from_db_u64(revision, "based_on_revision")?,
                )?
                .ok_or(ImprovementStoreError::NotFound("prepared plan"))
            })
            .transpose()
    }

    pub fn submit_plan(&mut self, input: PlanSubmission<'_>) -> Stored<ImprovementRecord> {
        validate_plan(&input)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, input.improvement_id, input.expected_revision)?;
        let prepared =
            read_prepared_plan(&transaction, input.improvement_id, input.expected_revision)?
                .ok_or(ImprovementStoreError::NotFound("prepared plan"))?;
        if prepared.plan_digest != input.plan_digest
            || prepared.source_base_sha != input.source_base_sha
        {
            return Err(ImprovementStoreError::IdempotencyConflict);
        }
        require_transition(current.state, ImprovementState::PlanReview)?;
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvements SET state = 'plan_review', revision = ?1,
                plan_digest = ?2, plan_head_sha = ?3, source_base_sha = ?4,
                issue_number = ?5, issue_url = ?6, plan_pr_number = ?7,
                plan_pr_url = ?8, implementation_head_sha = NULL,
                implementation_tree_sha = NULL, release_manifest_digest = NULL,
                implementation_pr_number = NULL, implementation_pr_url = NULL,
                active_release_digest = NULL, failure_reason = NULL,
                last_actor = ?9, updated_at_ms = ?10
             WHERE entry_id = ?11 AND revision = ?12",
            params![
                to_db_u64(next, "revision")?,
                input.plan_digest,
                input.plan_head_sha,
                input.source_base_sha,
                to_db_u64(input.issue_number, "issue_number")?,
                input.issue_url,
                to_db_u64(input.plan_pr_number, "plan_pr_number")?,
                input.plan_pr_url,
                input.actor,
                input.now_ms,
                input.improvement_id,
                to_db_u64(input.expected_revision, "expected_revision")?
            ],
        )?;
        insert_event(
            &transaction,
            input.improvement_id,
            next,
            "plan_submitted",
            input.actor,
            Some(input.plan_digest),
            input.now_ms,
        )?;
        finish_mutation(transaction, input.improvement_id)
    }

    pub fn submit_release(&mut self, input: ReleaseSubmission<'_>) -> Stored<ImprovementRecord> {
        validate_release(&input)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, input.improvement_id, input.expected_revision)?;
        require_transition(current.state, ImprovementState::ReleaseReview)?;
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvements SET state = 'release_review', revision = ?1,
                implementation_head_sha = ?2, implementation_tree_sha = ?3,
                release_manifest_digest = ?4, implementation_pr_number = ?5,
                implementation_pr_url = ?6, active_release_digest = NULL,
                failure_reason = NULL, last_actor = ?7, updated_at_ms = ?8
             WHERE entry_id = ?9 AND revision = ?10",
            params![
                to_db_u64(next, "revision")?,
                input.implementation_head_sha,
                input.implementation_tree_sha,
                input.release_manifest_digest,
                to_db_u64(input.implementation_pr_number, "implementation_pr_number")?,
                input.implementation_pr_url,
                input.actor,
                input.now_ms,
                input.improvement_id,
                to_db_u64(input.expected_revision, "expected_revision")?
            ],
        )?;
        insert_event(
            &transaction,
            input.improvement_id,
            next,
            "release_submitted",
            input.actor,
            Some(input.release_manifest_digest),
            input.now_ms,
        )?;
        finish_mutation(transaction, input.improvement_id)
    }

    pub fn transition(&mut self, input: StateTransition<'_>) -> Stored<ImprovementRecord> {
        validate_transition(&input)?;
        if input.to == ImprovementState::PlanApproved {
            return Err(ImprovementStoreError::ApprovalRequired(ApprovalKind::Plan));
        }
        if input.to == ImprovementState::ReleaseApproved {
            return Err(ImprovementStoreError::ApprovalRequired(
                ApprovalKind::Release,
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, input.improvement_id, input.expected_revision)?;
        require_transition(current.state, input.to)?;
        if input.to == ImprovementState::Completed
            && input.active_release_digest != current.release_manifest_digest.as_deref()
        {
            return Err(ImprovementStoreError::InvalidField("active_release_digest"));
        }
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvements SET state = ?1, revision = ?2,
                plan_digest = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_digest END,
                plan_head_sha = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_head_sha END,
                source_base_sha = CASE WHEN ?1 = 'draft' THEN NULL ELSE source_base_sha END,
                issue_number = CASE WHEN ?1 = 'draft' THEN NULL ELSE issue_number END,
                issue_url = CASE WHEN ?1 = 'draft' THEN NULL ELSE issue_url END,
                plan_pr_number = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_pr_number END,
                plan_pr_url = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_pr_url END,
                implementation_head_sha = CASE WHEN ?1 = 'implementing' THEN NULL ELSE implementation_head_sha END,
                implementation_tree_sha = CASE WHEN ?1 = 'implementing' THEN NULL ELSE implementation_tree_sha END,
                release_manifest_digest = CASE WHEN ?1 = 'implementing' THEN NULL ELSE release_manifest_digest END,
                implementation_pr_number = CASE WHEN ?1 = 'implementing' THEN NULL ELSE implementation_pr_number END,
                implementation_pr_url = CASE WHEN ?1 = 'implementing' THEN NULL ELSE implementation_pr_url END,
                active_release_digest = ?3, failure_reason = ?4,
                ci_evidence = CASE
                    WHEN ?1 = 'activating' THEN ?9
                    WHEN ?1 IN ('draft', 'implementing') THEN NULL
                    ELSE ci_evidence END,
                last_actor = ?5, updated_at_ms = ?6
             WHERE entry_id = ?7 AND revision = ?8",
            params![
                input.to.as_str(),
                to_db_u64(next, "revision")?,
                input.active_release_digest,
                input.failure_reason,
                input.actor,
                input.now_ms,
                input.improvement_id,
                to_db_u64(input.expected_revision, "expected_revision")?,
                input.ci_evidence
            ],
        )?;
        insert_event(
            &transaction,
            input.improvement_id,
            next,
            transition_event(input.to),
            input.actor,
            input.active_release_digest,
            input.now_ms,
        )?;
        finish_mutation(transaction, input.improvement_id)
    }

    pub fn issue_challenge(&mut self, input: NewApprovalChallenge<'_>) -> Stored<()> {
        validate_challenge(&input)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = require_current(&transaction, input.improvement_id, input.expected_revision)?;
        let (required_state, digest) = match input.kind {
            ApprovalKind::Plan => (ImprovementState::PlanReview, current.plan_digest.as_deref()),
            ApprovalKind::Release => (
                ImprovementState::ReleaseReview,
                current.release_manifest_digest.as_deref(),
            ),
        };
        if current.state != required_state {
            return Err(ImprovementStoreError::IllegalTransition {
                from: current.state,
                to: approval_state(input.kind),
            });
        }
        let digest = digest.ok_or(ImprovementStoreError::Corrupt("approval_artifact"))?;
        let inserted = transaction.execute(
            "INSERT INTO improvement_approval_challenges (
                challenge_key, improvement_id, approval_kind, bound_revision,
                artifact_digest, actor_id, chat_id, expires_at_ms, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(challenge_key) DO NOTHING",
            params![
                input.challenge_key,
                input.improvement_id,
                input.kind.as_str(),
                to_db_u64(input.expected_revision, "expected_revision")?,
                digest,
                input.actor_id,
                input.chat_id,
                input.expires_at_ms,
                input.created_at_ms
            ],
        )?;
        if inserted == 0 {
            let matches: bool = transaction.query_row(
                "SELECT improvement_id = ?2 AND approval_kind = ?3 AND bound_revision = ?4
                        AND artifact_digest = ?5 AND actor_id = ?6 AND chat_id = ?7
                        AND expires_at_ms = ?8 AND created_at_ms = ?9
                   FROM improvement_approval_challenges WHERE challenge_key = ?1",
                params![
                    input.challenge_key,
                    input.improvement_id,
                    input.kind.as_str(),
                    to_db_u64(input.expected_revision, "expected_revision")?,
                    digest,
                    input.actor_id,
                    input.chat_id,
                    input.expires_at_ms,
                    input.created_at_ms
                ],
                |row| row.get(0),
            )?;
            if !matches {
                return Err(ImprovementStoreError::IdempotencyConflict);
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn approve(&mut self, input: ApprovalAttempt<'_>) -> Stored<ImprovementRecord> {
        validate_identifier(input.challenge_key, "challenge_key")?;
        validate_identifier(input.actor_id, "actor_id")?;
        validate_identifier(input.chat_id, "chat_id")?;
        validate_time(input.now_ms, "now_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let challenge = read_challenge(&transaction, input.challenge_key)?
            .ok_or(ImprovementStoreError::NotFound("approval challenge"))?;
        if challenge.consumed_at_ms.is_some() {
            return Err(ImprovementStoreError::ChallengeConsumed);
        }
        if input.now_ms > challenge.expires_at_ms {
            return Err(ImprovementStoreError::ChallengeExpired);
        }
        if input.actor_id != challenge.actor_id {
            return Err(ImprovementStoreError::ChallengeMismatch("actor_id"));
        }
        if input.chat_id != challenge.chat_id {
            return Err(ImprovementStoreError::ChallengeMismatch("chat_id"));
        }
        let current = read_by_id(&transaction, challenge.improvement_id)?
            .ok_or(ImprovementStoreError::NotFound("improvement"))?;
        if current.revision != challenge.bound_revision {
            return Err(ImprovementStoreError::StaleRevision {
                expected: challenge.bound_revision,
                actual: current.revision,
            });
        }
        let (required_state, current_digest) = match challenge.kind {
            ApprovalKind::Plan => (ImprovementState::PlanReview, current.plan_digest.as_deref()),
            ApprovalKind::Release => (
                ImprovementState::ReleaseReview,
                current.release_manifest_digest.as_deref(),
            ),
        };
        if current.state != required_state {
            return Err(ImprovementStoreError::IllegalTransition {
                from: current.state,
                to: approval_state(challenge.kind),
            });
        }
        if current_digest != Some(challenge.artifact_digest.as_str()) {
            return Err(ImprovementStoreError::ChallengeMismatch("artifact_digest"));
        }
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvement_approval_challenges SET consumed_at_ms = ?1
             WHERE challenge_key = ?2 AND consumed_at_ms IS NULL",
            params![input.now_ms, input.challenge_key],
        )?;
        transaction.execute(
            "UPDATE improvements SET state = ?1, revision = ?2, last_actor = ?3,
                updated_at_ms = ?4 WHERE entry_id = ?5 AND revision = ?6",
            params![
                approval_state(challenge.kind).as_str(),
                to_db_u64(next, "revision")?,
                input.actor_id,
                input.now_ms,
                current.entry_id,
                to_db_u64(current.revision, "revision")?
            ],
        )?;
        insert_event(
            &transaction,
            current.entry_id,
            next,
            if challenge.kind == ApprovalKind::Plan {
                "plan_approved"
            } else {
                "release_approved"
            },
            input.actor_id,
            Some(&challenge.artifact_digest),
            input.now_ms,
        )?;
        finish_mutation(transaction, current.entry_id)
    }

    /// Consume a bound challenge by requesting another revision of its exact
    /// artifact. This negative button has the same identity, expiry, revision,
    /// digest, and replay protection as approval.
    pub fn request_changes(&mut self, input: ApprovalAttempt<'_>) -> Stored<ImprovementRecord> {
        validate_identifier(input.challenge_key, "challenge_key")?;
        validate_identifier(input.actor_id, "actor_id")?;
        validate_identifier(input.chat_id, "chat_id")?;
        validate_time(input.now_ms, "now_ms")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let challenge = read_challenge(&transaction, input.challenge_key)?
            .ok_or(ImprovementStoreError::NotFound("approval challenge"))?;
        if challenge.consumed_at_ms.is_some() {
            return Err(ImprovementStoreError::ChallengeConsumed);
        }
        if input.now_ms > challenge.expires_at_ms {
            return Err(ImprovementStoreError::ChallengeExpired);
        }
        if input.actor_id != challenge.actor_id {
            return Err(ImprovementStoreError::ChallengeMismatch("actor_id"));
        }
        if input.chat_id != challenge.chat_id {
            return Err(ImprovementStoreError::ChallengeMismatch("chat_id"));
        }
        let current = read_by_id(&transaction, challenge.improvement_id)?
            .ok_or(ImprovementStoreError::NotFound("improvement"))?;
        if current.revision != challenge.bound_revision {
            return Err(ImprovementStoreError::StaleRevision {
                expected: challenge.bound_revision,
                actual: current.revision,
            });
        }
        let (required_state, current_digest, target, event) = match challenge.kind {
            ApprovalKind::Plan => (
                ImprovementState::PlanReview,
                current.plan_digest.as_deref(),
                ImprovementState::Draft,
                "plan_changes_requested",
            ),
            ApprovalKind::Release => (
                ImprovementState::ReleaseReview,
                current.release_manifest_digest.as_deref(),
                // Implementation feedback changes what the candidate may do.
                // Return to draft so that guidance becomes a new plan and is
                // covered by a fresh plan approval before another lab run.
                ImprovementState::Draft,
                "release_changes_requested",
            ),
        };
        if current.state != required_state {
            return Err(ImprovementStoreError::IllegalTransition {
                from: current.state,
                to: target,
            });
        }
        if current_digest != Some(challenge.artifact_digest.as_str()) {
            return Err(ImprovementStoreError::ChallengeMismatch("artifact_digest"));
        }
        let next = next_revision(current.revision)?;
        transaction.execute(
            "UPDATE improvement_approval_challenges SET consumed_at_ms = ?1
             WHERE challenge_key = ?2 AND consumed_at_ms IS NULL",
            params![input.now_ms, input.challenge_key],
        )?;
        transaction.execute(
            "UPDATE improvements SET state = ?1, revision = ?2,
                plan_digest = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_digest END,
                plan_head_sha = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_head_sha END,
                source_base_sha = CASE WHEN ?1 = 'draft' THEN NULL ELSE source_base_sha END,
                issue_number = CASE WHEN ?1 = 'draft' THEN NULL ELSE issue_number END,
                issue_url = CASE WHEN ?1 = 'draft' THEN NULL ELSE issue_url END,
                plan_pr_number = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_pr_number END,
                plan_pr_url = CASE WHEN ?1 = 'draft' THEN NULL ELSE plan_pr_url END,
                implementation_head_sha = NULL, implementation_tree_sha = NULL,
                release_manifest_digest = NULL, implementation_pr_number = NULL,
                implementation_pr_url = NULL, active_release_digest = NULL,
                ci_evidence = NULL,
                last_actor = ?3, updated_at_ms = ?4
             WHERE entry_id = ?5 AND revision = ?6",
            params![
                target.as_str(),
                to_db_u64(next, "revision")?,
                input.actor_id,
                input.now_ms,
                current.entry_id,
                to_db_u64(current.revision, "revision")?
            ],
        )?;
        insert_event(
            &transaction,
            current.entry_id,
            next,
            event,
            input.actor_id,
            Some(&challenge.artifact_digest),
            input.now_ms,
        )?;
        finish_mutation(transaction, current.entry_id)
    }

    pub fn events(&self, improvement_id: i64) -> Stored<Vec<ImprovementEvent>> {
        validate_row_id(improvement_id, "improvement_id")?;
        let mut statement = self.connection.prepare(
            "SELECT event_id, improvement_id, revision, kind, actor, artifact_digest, occurred_at_ms
             FROM improvement_events WHERE improvement_id = ?1 ORDER BY revision"
        )?;
        let rows = statement.query_map([improvement_id], raw_event)?;
        rows.map(|row| {
            row.map_err(ImprovementStoreError::from)
                .and_then(validate_event)
        })
        .collect()
    }
}

fn require_transition(from: ImprovementState, to: ImprovementState) -> Stored<()> {
    let allowed = matches!(
        (from, to),
        (ImprovementState::Draft, ImprovementState::PlanReview)
            | (ImprovementState::PlanReview, ImprovementState::Draft)
            | (
                ImprovementState::PlanApproved,
                ImprovementState::Implementing
            )
            | (
                ImprovementState::Implementing,
                ImprovementState::ReleaseReview
            )
            | (
                ImprovementState::ReleaseReview,
                ImprovementState::Implementing
            )
            | (ImprovementState::ReleaseReview, ImprovementState::Draft)
            | (
                ImprovementState::ReleaseApproved,
                ImprovementState::Activating
            )
            | (ImprovementState::Activating, ImprovementState::Completed)
            | (ImprovementState::Activating, ImprovementState::Failed)
            | (ImprovementState::Activating, ImprovementState::RolledBack)
            | (ImprovementState::Implementing, ImprovementState::Failed)
            // An approved release whose remote CI is red has nowhere else to
            // go. Before the CI gate, `release_approved` could only ever exit
            // into `activating`, which meant "refuse to activate" had no
            // durable spelling at all.
            | (ImprovementState::ReleaseApproved, ImprovementState::Failed)
    );
    if allowed {
        Ok(())
    } else {
        Err(ImprovementStoreError::IllegalTransition { from, to })
    }
}

fn approval_state(kind: ApprovalKind) -> ImprovementState {
    match kind {
        ApprovalKind::Plan => ImprovementState::PlanApproved,
        ApprovalKind::Release => ImprovementState::ReleaseApproved,
    }
}

fn transition_event(state: ImprovementState) -> &'static str {
    match state {
        ImprovementState::Draft => "plan_revision_requested",
        ImprovementState::Implementing => "implementation_started",
        ImprovementState::Activating => "activation_started",
        ImprovementState::Completed => "activation_completed",
        ImprovementState::Failed => "failed",
        ImprovementState::RolledBack => "rolled_back",
        _ => "state_changed",
    }
}

fn finish_mutation(transaction: Transaction<'_>, improvement_id: i64) -> Stored<ImprovementRecord> {
    let record = read_by_id(&transaction, improvement_id)?
        .ok_or(ImprovementStoreError::NotFound("improvement"))?;
    transaction.commit()?;
    Ok(record)
}

fn require_current(
    connection: &Connection,
    improvement_id: i64,
    expected: u64,
) -> Stored<ImprovementRecord> {
    validate_row_id(improvement_id, "improvement_id")?;
    if expected == 0 {
        return Err(ImprovementStoreError::InvalidField("expected_revision"));
    }
    let current = read_by_id(connection, improvement_id)?
        .ok_or(ImprovementStoreError::NotFound("improvement"))?;
    if current.revision != expected {
        return Err(ImprovementStoreError::StaleRevision {
            expected,
            actual: current.revision,
        });
    }
    Ok(current)
}

fn insert_event(
    connection: &Connection,
    improvement_id: i64,
    revision: u64,
    kind: &str,
    actor: &str,
    digest: Option<&str>,
    now_ms: i64,
) -> Stored<()> {
    connection.execute(
        "INSERT INTO improvement_events (
            improvement_id, revision, kind, actor, artifact_digest, occurred_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            improvement_id,
            to_db_u64(revision, "revision")?,
            kind,
            actor,
            digest,
            now_ms
        ],
    )?;
    Ok(())
}

const RECORD_COLUMNS: &str = "entry_id, request_key, actor_id, chat_id, summary, source_repo,
    planning_repo, state, revision, plan_digest, plan_head_sha, source_base_sha,
    issue_number, issue_url, plan_pr_number, plan_pr_url, implementation_head_sha,
    implementation_tree_sha, release_manifest_digest, implementation_pr_number,
    implementation_pr_url, active_release_digest, last_actor, failure_reason,
    ci_evidence, created_at_ms, updated_at_ms";

fn read_by_id(connection: &Connection, id: i64) -> Stored<Option<ImprovementRecord>> {
    connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM improvements WHERE entry_id = ?1"),
            [id],
            raw_record,
        )
        .optional()?
        .map(validate_record)
        .transpose()
}

fn read_by_request_key(connection: &Connection, key: &str) -> Stored<Option<ImprovementRecord>> {
    connection
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM improvements WHERE request_key = ?1"),
            [key],
            raw_record,
        )
        .optional()?
        .map(validate_record)
        .transpose()
}

fn read_prepared_plan(
    connection: &Connection,
    improvement_id: i64,
    based_on_revision: u64,
) -> Stored<Option<PreparedPlan>> {
    let raw = connection
        .query_row(
            "SELECT improvement_id, based_on_revision, source_base_sha, plan_digest, markdown, created_at_ms
               FROM improvement_plan_drafts
              WHERE improvement_id = ?1 AND based_on_revision = ?2",
            params![
                improvement_id,
                to_db_u64(based_on_revision, "based_on_revision")?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    raw.map(
        |(improvement_id, revision, source_base_sha, plan_digest, markdown, created_at_ms)| {
            validate_row_id(improvement_id, "improvement_id")
                .map_err(|_| corrupt("improvement_id"))?;
            let based_on_revision = from_db_u64(revision, "based_on_revision")?;
            validate_identifier(&source_base_sha, "source_base_sha")
                .map_err(|_| corrupt("source_base_sha"))?;
            validate_identifier(&plan_digest, "plan_digest").map_err(|_| corrupt("plan_digest"))?;
            if markdown.trim().is_empty() || markdown.len() > 64 * 1024 || markdown.contains('\0') {
                return Err(corrupt("plan_markdown"));
            }
            let created_at_ms = checked_time(created_at_ms, "created_at_ms")?;
            Ok(PreparedPlan {
                improvement_id,
                based_on_revision,
                source_base_sha,
                plan_digest,
                markdown,
                created_at_ms,
            })
        },
    )
    .transpose()
}

fn raw_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImprovementRecord> {
    Ok(ImprovementRecord {
        entry_id: row.get(0)?,
        request_key: row.get(1)?,
        actor_id: row.get(2)?,
        chat_id: row.get(3)?,
        summary: row.get(4)?,
        source_repo: row.get(5)?,
        planning_repo: row.get(6)?,
        state: ImprovementState::from_spelling(&row.get::<_, String>(7)?)
            .unwrap_or(ImprovementState::Draft),
        revision: from_db_u64_raw(row.get(8)?),
        plan_digest: row.get(9)?,
        plan_head_sha: row.get(10)?,
        source_base_sha: row.get(11)?,
        issue_number: optional_u64_raw(row.get(12)?),
        issue_url: row.get(13)?,
        plan_pr_number: optional_u64_raw(row.get(14)?),
        plan_pr_url: row.get(15)?,
        implementation_head_sha: row.get(16)?,
        implementation_tree_sha: row.get(17)?,
        release_manifest_digest: row.get(18)?,
        implementation_pr_number: optional_u64_raw(row.get(19)?),
        implementation_pr_url: row.get(20)?,
        active_release_digest: row.get(21)?,
        last_actor: row.get(22)?,
        failure_reason: row.get(23)?,
        ci_evidence: row.get(24)?,
        created_at_ms: row.get(25)?,
        updated_at_ms: row.get(26)?,
    })
}

fn validate_record(record: ImprovementRecord) -> Stored<ImprovementRecord> {
    validate_row_id(record.entry_id, "entry_id").map_err(|_| corrupt("entry_id"))?;
    for (value, field) in [
        (&record.request_key, "request_key"),
        (&record.actor_id, "actor_id"),
        (&record.chat_id, "chat_id"),
        (&record.source_repo, "source_repo"),
        (&record.planning_repo, "planning_repo"),
        (&record.last_actor, "last_actor"),
    ] {
        validate_identifier(value, field).map_err(|_| corrupt(field))?;
    }
    validate_summary(&record.summary).map_err(|_| corrupt("summary"))?;
    if record.revision == 0 {
        return Err(corrupt("revision"));
    }
    validate_time(record.created_at_ms, "created_at_ms").map_err(|_| corrupt("created_at_ms"))?;
    validate_time(record.updated_at_ms, "updated_at_ms").map_err(|_| corrupt("updated_at_ms"))?;
    let has_plan = record.plan_digest.is_some();
    let expects_plan = record.state != ImprovementState::Draft;
    if has_plan != expects_plan {
        return Err(corrupt("plan_digest"));
    }
    let has_release = record.release_manifest_digest.is_some();
    let requires_release = matches!(
        record.state,
        ImprovementState::ReleaseReview
            | ImprovementState::ReleaseApproved
            | ImprovementState::Activating
            | ImprovementState::Completed
            | ImprovementState::RolledBack
    );
    let forbids_release = matches!(
        record.state,
        ImprovementState::Draft
            | ImprovementState::PlanReview
            | ImprovementState::PlanApproved
            | ImprovementState::Implementing
    );
    if (requires_release && !has_release) || (forbids_release && has_release) {
        return Err(corrupt("release_manifest_digest"));
    }
    Ok(record)
}

#[derive(Debug)]
struct StoredChallenge {
    improvement_id: i64,
    kind: ApprovalKind,
    bound_revision: u64,
    artifact_digest: String,
    actor_id: String,
    chat_id: String,
    expires_at_ms: i64,
    consumed_at_ms: Option<i64>,
}

fn read_challenge(connection: &Connection, key: &str) -> Stored<Option<StoredChallenge>> {
    let raw = connection
        .query_row(
            "SELECT improvement_id, approval_kind, bound_revision, artifact_digest,
                actor_id, chat_id, expires_at_ms, consumed_at_ms
           FROM improvement_approval_challenges WHERE challenge_key = ?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()?;
    raw.map(
        |(
            improvement_id,
            kind,
            revision,
            digest,
            actor_id,
            chat_id,
            expires_at_ms,
            consumed_at_ms,
        )| {
            Ok(StoredChallenge {
                improvement_id: checked_row_id(improvement_id, "improvement_id")?,
                kind: ApprovalKind::from_spelling(&kind).ok_or(corrupt("approval_kind"))?,
                bound_revision: from_db_u64(revision, "bound_revision")?,
                artifact_digest: checked_identifier(digest, "artifact_digest")?,
                actor_id: checked_identifier(actor_id, "actor_id")?,
                chat_id: checked_identifier(chat_id, "chat_id")?,
                expires_at_ms: checked_time(expires_at_ms, "expires_at_ms")?,
                consumed_at_ms: consumed_at_ms
                    .map(|value| checked_time(value, "consumed_at_ms"))
                    .transpose()?,
            })
        },
    )
    .transpose()
}

fn raw_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImprovementEvent> {
    Ok(ImprovementEvent {
        event_id: row.get(0)?,
        improvement_id: row.get(1)?,
        revision: from_db_u64_raw(row.get(2)?),
        kind: row.get(3)?,
        actor: row.get(4)?,
        artifact_digest: row.get(5)?,
        occurred_at_ms: row.get(6)?,
    })
}

fn validate_event(event: ImprovementEvent) -> Stored<ImprovementEvent> {
    validate_row_id(event.event_id, "event_id").map_err(|_| corrupt("event_id"))?;
    validate_row_id(event.improvement_id, "improvement_id")
        .map_err(|_| corrupt("improvement_id"))?;
    if event.revision == 0 {
        return Err(corrupt("revision"));
    }
    validate_identifier(&event.kind, "kind").map_err(|_| corrupt("kind"))?;
    validate_identifier(&event.actor, "actor").map_err(|_| corrupt("actor"))?;
    checked_time(event.occurred_at_ms, "occurred_at_ms")?;
    Ok(event)
}

fn validate_new(input: &NewImprovement<'_>) -> Stored<()> {
    validate_identifier(input.request_key, "request_key")?;
    validate_identifier(input.actor_id, "actor_id")?;
    validate_identifier(input.chat_id, "chat_id")?;
    validate_summary(input.summary)?;
    validate_identifier(input.source_repo, "source_repo")?;
    validate_identifier(input.planning_repo, "planning_repo")?;
    validate_time(input.now_ms, "now_ms")
}

fn validate_plan(input: &PlanSubmission<'_>) -> Stored<()> {
    validate_row_id(input.improvement_id, "improvement_id")?;
    validate_identifier(input.actor, "actor")?;
    for (value, field) in [
        (input.plan_digest, "plan_digest"),
        (input.plan_head_sha, "plan_head_sha"),
        (input.source_base_sha, "source_base_sha"),
    ] {
        validate_identifier(value, field)?;
    }
    validate_positive(input.issue_number, "issue_number")?;
    validate_url(input.issue_url, "issue_url")?;
    validate_positive(input.plan_pr_number, "plan_pr_number")?;
    validate_url(input.plan_pr_url, "plan_pr_url")?;
    validate_time(input.now_ms, "now_ms")
}

fn validate_release(input: &ReleaseSubmission<'_>) -> Stored<()> {
    validate_row_id(input.improvement_id, "improvement_id")?;
    validate_identifier(input.actor, "actor")?;
    for (value, field) in [
        (input.implementation_head_sha, "implementation_head_sha"),
        (input.implementation_tree_sha, "implementation_tree_sha"),
        (input.release_manifest_digest, "release_manifest_digest"),
    ] {
        validate_identifier(value, field)?;
    }
    validate_positive(input.implementation_pr_number, "implementation_pr_number")?;
    validate_url(input.implementation_pr_url, "implementation_pr_url")?;
    validate_time(input.now_ms, "now_ms")
}

fn validate_transition(input: &StateTransition<'_>) -> Stored<()> {
    validate_row_id(input.improvement_id, "improvement_id")?;
    validate_identifier(input.actor, "actor")?;
    validate_time(input.now_ms, "now_ms")?;
    if input.to == ImprovementState::Failed {
        validate_identifier(
            input
                .failure_reason
                .ok_or(ImprovementStoreError::InvalidField("failure_reason"))?,
            "failure_reason",
        )?;
    } else if input.failure_reason.is_some() {
        return Err(ImprovementStoreError::InvalidField("failure_reason"));
    }
    if let Some(digest) = input.active_release_digest {
        validate_identifier(digest, "active_release_digest")?;
    }
    if input.to != ImprovementState::Completed && input.active_release_digest.is_some() {
        return Err(ImprovementStoreError::InvalidField("active_release_digest"));
    }
    // `activating` is the state in which the release link is switched, so this
    // is the last point at which "CI was green for exactly this commit" can be
    // required rather than assumed. Any other target carrying evidence is a
    // caller confusion, not a harmless extra.
    if input.to == ImprovementState::Activating {
        validate_ci_evidence(
            input
                .ci_evidence
                .ok_or(ImprovementStoreError::InvalidField("ci_evidence"))?,
        )?;
    } else if input.ci_evidence.is_some() {
        return Err(ImprovementStoreError::InvalidField("ci_evidence"));
    }
    Ok(())
}

fn validate_ci_evidence(value: &str) -> Stored<()> {
    if value.trim().is_empty()
        || value.len() > MAX_CI_EVIDENCE_BYTES
        || value.contains('\0')
        || !value.starts_with('{')
    {
        return Err(ImprovementStoreError::InvalidField("ci_evidence"));
    }
    Ok(())
}

fn validate_challenge(input: &NewApprovalChallenge<'_>) -> Stored<()> {
    validate_identifier(input.challenge_key, "challenge_key")?;
    validate_row_id(input.improvement_id, "improvement_id")?;
    validate_identifier(input.actor_id, "actor_id")?;
    validate_identifier(input.chat_id, "chat_id")?;
    validate_time(input.created_at_ms, "created_at_ms")?;
    validate_time(input.expires_at_ms, "expires_at_ms")?;
    if input.expires_at_ms < input.created_at_ms {
        return Err(ImprovementStoreError::InvalidField("expires_at_ms"));
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Stored<()> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(ImprovementStoreError::InvalidField(field));
    }
    Ok(())
}

fn validate_summary(value: &str) -> Stored<()> {
    if value.trim().is_empty()
        || value.len() > MAX_SUMMARY_BYTES
        || value.chars().any(|c| c == '\0')
    {
        return Err(ImprovementStoreError::InvalidField("summary"));
    }
    Ok(())
}

fn validate_url(value: &str, field: &'static str) -> Stored<()> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.chars().any(char::is_control)
        || !(value.starts_with("https://") || value.starts_with("http://localhost"))
    {
        return Err(ImprovementStoreError::InvalidField(field));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Stored<()> {
    if value < 0 {
        Err(ImprovementStoreError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_positive(value: u64, field: &'static str) -> Stored<()> {
    if value == 0 {
        Err(ImprovementStoreError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_row_id(value: i64, field: &'static str) -> Stored<()> {
    if value <= 0 {
        Err(ImprovementStoreError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn secure_path(path: &Path) -> Stored<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => ImprovementStoreError::Io(io),
        other => ImprovementStoreError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Stored<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == IMPROVEMENT_STORE_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        return migrate_v1_to_v2(connection);
    }
    if version != 0 {
        return Err(ImprovementStoreError::SchemaVersion {
            found: version,
            supported: IMPROVEMENT_STORE_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(ImprovementStoreError::SchemaVersion {
            found: 0,
            supported: IMPROVEMENT_STORE_SCHEMA_VERSION,
        });
    }
    // A fresh database is the base schema plus every migration replayed in
    // order, so the two ways of arriving at the current version cannot drift.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.execute_batch(MIGRATE_V1_TO_V2)?;
    transaction.pragma_update(None, "user_version", IMPROVEMENT_STORE_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v1_to_v2(connection: &mut Connection) -> Stored<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATE_V1_TO_V2)?;
    transaction.pragma_update(None, "user_version", 2)?;
    transaction.commit()?;
    Ok(())
}

fn next_revision(value: u64) -> Stored<u64> {
    value
        .checked_add(1)
        .ok_or(ImprovementStoreError::InvalidField("revision"))
}

fn to_db_u64(value: u64, field: &'static str) -> Stored<i64> {
    i64::try_from(value).map_err(|_| ImprovementStoreError::InvalidField(field))
}

fn from_db_u64(value: i64, field: &'static str) -> Stored<u64> {
    u64::try_from(value).map_err(|_| corrupt(field))
}

fn from_db_u64_raw(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
fn optional_u64_raw(value: Option<i64>) -> Option<u64> {
    value.and_then(|v| u64::try_from(v).ok())
}

fn checked_row_id(value: i64, field: &'static str) -> Stored<i64> {
    if value <= 0 {
        Err(corrupt(field))
    } else {
        Ok(value)
    }
}

fn checked_identifier(value: String, field: &'static str) -> Stored<String> {
    validate_identifier(&value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Stored<i64> {
    validate_time(value, field).map_err(|_| corrupt(field))?;
    Ok(value)
}

const fn corrupt(field: &'static str) -> ImprovementStoreError {
    ImprovementStoreError::Corrupt(field)
}
