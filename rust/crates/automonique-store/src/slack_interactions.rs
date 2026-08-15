// SPDX-License-Identifier: Elastic-2.0

//! Durable, idempotent Slack approval interaction journal.
//!
//! A block action or modal submission is recorded before Socket Mode is
//! acknowledged. The row binds its stable interaction key to the exact Manage
//! job, original ticket source, actor and Slack message coordinates. Replays
//! return the existing row; a different binding under the same key conflicts.

use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

pub const SLACK_INTERACTION_SCHEMA_VERSION: u32 = 1;
pub const MAX_INTERACTION_KEY_BYTES: usize = 640;
pub const MAX_INTERACTION_FIELD_BYTES: usize = 640;

const SCHEMA: &str = r#"
CREATE TABLE slack_ticket_interactions (
    interaction_id INTEGER PRIMARY KEY,
    interaction_key TEXT NOT NULL UNIQUE,
    job_id TEXT NOT NULL,
    ticket_source_key TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('approve', 'reject')),
    channel_id TEXT NOT NULL,
    message_ts TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('recorded', 'applied', 'failed')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    resolved_at_ms INTEGER,
    CHECK ((state = 'recorded' AND resolved_at_ms IS NULL)
        OR (state != 'recorded' AND resolved_at_ms IS NOT NULL))
) STRICT;
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackInteractionAction {
    Approve,
    Reject,
}

impl SlackInteractionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackInteractionState {
    Recorded,
    Applied,
    Failed,
}

impl SlackInteractionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "recorded" => Some(Self::Recorded),
            "applied" => Some(Self::Applied),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackInteractionInput<'a> {
    pub interaction_key: &'a str,
    pub job_id: &'a str,
    pub ticket_source_key: &'a str,
    pub actor_key: &'a str,
    pub action: SlackInteractionAction,
    pub channel_id: &'a str,
    pub message_ts: &'a str,
    pub recorded_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackInteractionRecord {
    pub interaction_id: i64,
    pub interaction_key: String,
    pub job_id: String,
    pub ticket_source_key: String,
    pub actor_key: String,
    pub action: SlackInteractionAction,
    pub channel_id: String,
    pub message_ts: String,
    pub state: SlackInteractionState,
    pub revision: u32,
    pub recorded_at_ms: i64,
    pub resolved_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackInteractionRecordOutcome {
    Recorded,
    Replay,
}

#[derive(Debug)]
pub enum SlackInteractionError {
    InvalidField(&'static str),
    Conflict,
    StaleRevision,
    Store(StoreError),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for SlackInteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid Slack interaction field: {field}"),
            Self::Conflict => f.write_str("Slack interaction key is already bound differently"),
            Self::StaleRevision => f.write_str("Slack interaction revision is stale"),
            Self::Store(error) => write!(f, "Slack interaction store: {error}"),
            Self::Sqlite(error) => write!(f, "Slack interaction sqlite: {error}"),
        }
    }
}

impl std::error::Error for SlackInteractionError {}
impl From<StoreError> for SlackInteractionError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<rusqlite::Error> for SlackInteractionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

#[derive(Debug)]
pub struct SlackInteractionStore {
    connection: Connection,
    path: PathBuf,
}

impl SlackInteractionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SlackInteractionError> {
        let path = path.as_ref();
        validate_database_path(path)?;
        if !path.exists() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(StoreError::Io)?;
        }
        validate_database_path(path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 0 {
            connection.execute_batch(SCHEMA)?;
            connection.pragma_update(None, "user_version", SLACK_INTERACTION_SCHEMA_VERSION)?;
        } else if version != SLACK_INTERACTION_SCHEMA_VERSION {
            return Err(SlackInteractionError::InvalidField("schema_version"));
        }
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(
        &mut self,
        input: &SlackInteractionInput<'_>,
    ) -> Result<(SlackInteractionRecord, SlackInteractionRecordOutcome), SlackInteractionError>
    {
        validate_input(input)?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load(&transaction, input.interaction_key)? {
            if existing.job_id != input.job_id
                || existing.ticket_source_key != input.ticket_source_key
                || existing.actor_key != input.actor_key
                || existing.action != input.action
                || existing.channel_id != input.channel_id
                || existing.message_ts != input.message_ts
            {
                return Err(SlackInteractionError::Conflict);
            }
            transaction.commit()?;
            return Ok((existing, SlackInteractionRecordOutcome::Replay));
        }
        transaction.execute(
            "INSERT INTO slack_ticket_interactions (interaction_key, job_id, ticket_source_key, actor_key, action, channel_id, message_ts, state, revision, recorded_at_ms, resolved_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'recorded', 1, ?8, NULL)",
            params![input.interaction_key, input.job_id, input.ticket_source_key, input.actor_key, input.action.as_str(), input.channel_id, input.message_ts, input.recorded_at_ms],
        )?;
        let record =
            load(&transaction, input.interaction_key)?.ok_or(SlackInteractionError::Conflict)?;
        transaction.commit()?;
        Ok((record, SlackInteractionRecordOutcome::Recorded))
    }

    pub fn resolve(
        &mut self,
        interaction_key: &str,
        expected_revision: u32,
        state: SlackInteractionState,
        resolved_at_ms: i64,
    ) -> Result<SlackInteractionRecord, SlackInteractionError> {
        if state == SlackInteractionState::Recorded || resolved_at_ms < 0 {
            return Err(SlackInteractionError::InvalidField("resolution"));
        }
        let changed = self.connection.execute(
            "UPDATE slack_ticket_interactions SET state=?1, revision=revision+1, resolved_at_ms=?2 WHERE interaction_key=?3 AND revision=?4 AND state='recorded'",
            params![state.as_str(), resolved_at_ms, interaction_key, expected_revision],
        )?;
        if changed != 1 {
            return Err(SlackInteractionError::StaleRevision);
        }
        load(&self.connection, interaction_key)?.ok_or(SlackInteractionError::Conflict)
    }
}

fn validate_input(input: &SlackInteractionInput<'_>) -> Result<(), SlackInteractionError> {
    for (name, value, max) in [
        (
            "interaction_key",
            input.interaction_key,
            MAX_INTERACTION_KEY_BYTES,
        ),
        ("job_id", input.job_id, MAX_INTERACTION_FIELD_BYTES),
        (
            "ticket_source_key",
            input.ticket_source_key,
            MAX_INTERACTION_FIELD_BYTES,
        ),
        ("actor_key", input.actor_key, MAX_INTERACTION_FIELD_BYTES),
        ("channel_id", input.channel_id, MAX_INTERACTION_FIELD_BYTES),
        ("message_ts", input.message_ts, MAX_INTERACTION_FIELD_BYTES),
    ] {
        if value.is_empty()
            || value.len() > max
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(SlackInteractionError::InvalidField(name));
        }
    }
    if input.recorded_at_ms < 0 {
        return Err(SlackInteractionError::InvalidField("recorded_at_ms"));
    }
    Ok(())
}

fn load(
    connection: &Connection,
    key: &str,
) -> Result<Option<SlackInteractionRecord>, SlackInteractionError> {
    connection.query_row(
        "SELECT interaction_id, interaction_key, job_id, ticket_source_key, actor_key, action, channel_id, message_ts, state, revision, recorded_at_ms, resolved_at_ms FROM slack_ticket_interactions WHERE interaction_key=?1",
        [key],
        |row| {
            let action: String = row.get(5)?;
            let state: String = row.get(8)?;
            Ok(SlackInteractionRecord {
                interaction_id: row.get(0)?, interaction_key: row.get(1)?, job_id: row.get(2)?,
                ticket_source_key: row.get(3)?, actor_key: row.get(4)?,
                action: SlackInteractionAction::parse(&action).ok_or(rusqlite::Error::InvalidQuery)?,
                channel_id: row.get(6)?, message_ts: row.get(7)?,
                state: SlackInteractionState::parse(&state).ok_or(rusqlite::Error::InvalidQuery)?,
                revision: row.get(9)?, recorded_at_ms: row.get(10)?, resolved_at_ms: row.get(11)?,
            })
        },
    ).optional().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn record_is_idempotent_conflicting_reuse_refuses_and_resolution_is_fenced() {
        let root = tempfile::tempdir().expect("root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let mut store =
            SlackInteractionStore::open(root.path().join("interactions.sqlite3")).expect("store");
        let input = SlackInteractionInput {
            interaction_key: "slack-action:T1:C1:123.4:U1:approve",
            job_id: "job-1",
            ticket_source_key: "slack:A1:T1:C1:122.1",
            actor_key: "slack:T1:U1",
            action: SlackInteractionAction::Approve,
            channel_id: "C1",
            message_ts: "123.4",
            recorded_at_ms: 10,
        };
        let (record, outcome) = store.record(&input).expect("record");
        assert_eq!(outcome, SlackInteractionRecordOutcome::Recorded);
        let (replay, outcome) = store.record(&input).expect("replay");
        assert_eq!(outcome, SlackInteractionRecordOutcome::Replay);
        assert_eq!(record, replay);

        let conflict = SlackInteractionInput {
            job_id: "job-2",
            ..input.clone()
        };
        assert!(matches!(
            store.record(&conflict),
            Err(SlackInteractionError::Conflict)
        ));

        let applied = store
            .resolve(input.interaction_key, 1, SlackInteractionState::Applied, 20)
            .expect("applied");
        assert_eq!(applied.state, SlackInteractionState::Applied);
        assert_eq!(applied.revision, 2);
        assert!(matches!(
            store.resolve(input.interaction_key, 1, SlackInteractionState::Failed, 21),
            Err(SlackInteractionError::StaleRevision)
        ));
    }
}
