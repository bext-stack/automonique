// SPDX-License-Identifier: Elastic-2.0

//! Durable record of Slack Socket Mode ingress dispositions.
//!
//! Slack acknowledges one Socket Mode envelope at a time and never redelivers
//! an acknowledged one. A transport must therefore make its decision about a
//! frame durable *before* it acknowledges, and must answer a redelivery of the
//! same event with the decision it already made rather than a fresh one. This
//! module is that durable half. It records exactly the binding
//!
//! ```text
//! source_key -> (app_id, disposition, content_digest)
//! ```
//!
//! and answers three ways and only three ways:
//!
//! - the `source_key` is new: the binding is recorded,
//!   [`SlackRecordOutcome::Recorded`];
//! - the `source_key` is present with the *same* app, disposition and digest:
//!   it is an exact replay, [`SlackRecordOutcome::AlreadyRecorded`], and not one
//!   byte of the durable row changes;
//! - the `source_key` is present with a different app, disposition or digest:
//!   [`SlackIngressError::Conflict`], and nothing is written. A redelivery must
//!   not rewrite history.
//!
//! There is no Slack IO here and nothing is parsed: callers supply every
//! identifier, digest and timestamp, so retries stay deterministic and tests do
//! not depend on an ambient clock.
//!
//! # Divergences from the Telegram ingress model
//!
//! * **Per-envelope, not per-batch.** `telegram_ingress` rows are written by
//!   one fenced batch commit that also advances a single monotonic offset, so
//!   the batch is the atomic unit. Slack has no offset and no cursor: one
//!   envelope is one acknowledgement and one row. There is deliberately no
//!   batch entry point here, because there is no commit point for a batch to
//!   share.
//! * **`source_key` is the identity, and it is the only one.** Telegram
//!   deduplicates on `(bot_id, update_id)` and additionally holds `source_key`
//!   unique. Slack mints a fresh `envelope_id` for every delivery attempt of the
//!   same event, so `envelope_id` is an acknowledgement key and never an
//!   identity. `source_key` — `slack:{app}:{team}:{channel}:{ts}` as built by
//!   `automonique-transports` — is the whole of it.
//! * **Per-delivery facts are not part of the binding.** `envelope_id`,
//!   `retry_attempt` and `recorded_at_ms` belong to the delivery that first
//!   recorded the row. A redelivery naturally carries a different
//!   `envelope_id`, a higher `retry_attempt` and a later clock; none of those
//!   makes it a conflict, and none of them is rewritten on replay. The row
//!   therefore states what the *first* delivery looked like, not the last.
//! * **No lease fence.** A Telegram commit is fenced by a poller lease because
//!   two pollers advancing one offset would lose updates. A Slack Socket Mode
//!   connection has no shared cursor to corrupt, so this module takes no lease
//!   and asserts no exclusivity. Two writers presenting the same event race to
//!   the unique index; the loser sees its own binding and replays.
//!
//! # Why a digest and not the content
//!
//! `telegram_ingress` stores the admitted content bytes, because a Telegram
//! commit is the single atomic point that both captures the input and advances
//! the offset past it: content not captured there is unrecoverable. This module
//! stores only a caller-supplied SHA-256 digest of admitted content, and never
//! the bytes. It computes no digest, cannot re-derive one, and cannot verify
//! that a digest names the content the caller claims — a digest here is a stable
//! name a caller chose to record, exactly as in [`crate::provider_journal`].
//!
//! That divergence has a cost and it is stated rather than buried: **a row here
//! cannot reproduce the admitted text.** A caller that records a disposition and
//! acknowledges without having durably placed the admitted content somewhere
//! else has lost the message, because Slack will not redeliver an acknowledged
//! envelope. The ordering duty is the caller's:
//!
//! 1. durably place any work derived from the frame (for example a
//!    [`crate::Store`] inbox row keyed by the same `source_key`);
//! 2. record the disposition here;
//! 3. acknowledge.
//!
//! A crash before step 2 costs a redelivery, which step 1's own idempotency key
//! absorbs. A crash after step 2 and before step 3 also costs a redelivery,
//! which this log answers [`SlackRecordOutcome::AlreadyRecorded`]. This module
//! cannot check that order and does not pretend to.
//!
//! # What a row does not establish
//!
//! - A row proves a disposition was **recorded**, never that an acknowledgement
//!   was sent. Nothing in this module performs or observes an acknowledgement.
//! - It does not establish that admitted work was created, scheduled or run.
//! - `retry_attempt` is what Slack claimed on the delivery that first recorded
//!   the row. Later redeliveries are answered from the row and do not update it,
//!   so this column is not a redelivery counter.
//!
//! # Storage discipline
//!
//! The log owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`], exactly as [`crate::cancel_ledger`] and
//! [`crate::provider_journal`] do. Recording one disposition is one immediate
//! transaction, so a reader after a crash sees the whole row or no row. Every
//! read re-validates the row it loaded rather than trusting the database.
//!
//! Rows are write-once: there is no in-place transition anywhere in this module
//! and therefore no revision column to check. The only mutation of an existing
//! row is [`SlackIngressLog::prune`], which deletes it.
//!
//! # Deletion
//!
//! Ordinary operation never deletes. [`SlackIngressLog::prune`] is the only
//! deletion path, and its cost is stated in that method's documentation: a
//! pruned `source_key` is *forgotten*, so the same event presented again is
//! recorded fresh.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::provenance::{CausationId, CorrelationId, TraceId};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::{StoreError, StoredProvenance, validate_database_path};

/// The only Slack ingress schema this build can read and write.
pub const SLACK_INGRESS_SCHEMA_VERSION: u32 = 2;

/// Largest number of live dispositions any log will hold.
pub const MAX_SLACK_DISPOSITIONS: usize = 65_536;

/// Longest accepted `source_key`, in bytes.
///
/// Deliberately larger than [`crate::Store`]'s 256-byte identifier bound, which
/// a legitimate maximal Slack key would exceed. `automonique-transports` builds
/// `slack:{app}:{team}:{channel}:{ts}` from four coordinates of at most 128
/// bytes each, so the derivable maximum is `9 + 4 * 128 = 521` bytes; this bound
/// clears it with headroom rather than sitting exactly on it.
pub const MAX_SOURCE_KEY_BYTES: usize = 640;

/// Longest accepted `app_id` or `envelope_id`, in bytes.
///
/// Matches the opaque-identifier bound `automonique-transports` admits.
pub const MAX_SLACK_IDENTIFIER_BYTES: usize = 128;

/// Exact character count of a lowercase hex SHA-256 content digest.
pub const CONTENT_DIGEST_CHARS: usize = 64;

/// Largest page [`SlackIngressLog::app_dispositions`] will return.
pub const MAX_DISPOSITION_PAGE: usize = 1_024;

/// Schema v1.
///
/// Uniqueness of `source_key`, the closed disposition vocabulary, the
/// digest-presence rule and the non-negative ranges are database constraints so
/// a second writer cannot introduce a row this API would refuse. The identifier
/// grammar, length bounds and digest alphabet are deliberately *not* database
/// constraints: they are enforced on write and re-checked on every read, so a
/// row written around this API is refused rather than believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE slack_ingress_dispositions (
    entry_id INTEGER PRIMARY KEY,
    source_key TEXT NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (
        disposition IN ('admitted', 'denied', 'ignored_unsupported')
    ),
    content_digest TEXT,
    envelope_id TEXT NOT NULL,
    retry_attempt INTEGER NOT NULL CHECK (retry_attempt >= 0),
    recorded_at_ms INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    CHECK (
        (disposition = 'admitted' AND content_digest IS NOT NULL
         AND length(content_digest) = 64)
        OR
        (disposition != 'admitted' AND content_digest IS NULL)
    )
) STRICT;

CREATE INDEX slack_ingress_by_app
    ON slack_ingress_dispositions(app_id, recorded_at_ms, entry_id);
"#;

const MIGRATE_V1_TO_V2: &str = r#"
ALTER TABLE slack_ingress_dispositions ADD COLUMN trace_id TEXT;
ALTER TABLE slack_ingress_dispositions ADD COLUMN correlation_id TEXT;
ALTER TABLE slack_ingress_dispositions ADD COLUMN causation_id TEXT;
CREATE INDEX slack_ingress_by_trace
    ON slack_ingress_dispositions(trace_id, entry_id);
"#;

/// A Slack ingress log error with stable refusal categories.
#[derive(Debug)]
pub enum SlackIngressError {
    /// The log path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The log schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is empty, over-long, malformed, or out of range.
    InvalidField(&'static str),
    /// A recorded `source_key` was presented with a different binding.
    ///
    /// Nothing was written and the durable row is unchanged. The recorded
    /// binding is reported so a caller can tell a stale redelivery from a
    /// fabricated one without a second read.
    Conflict {
        /// First bound coordinate that differs: `app_id`, `disposition` or
        /// `content_digest`.
        field: &'static str,
        /// App the durable row binds.
        recorded_app_id: String,
        /// Disposition the durable row binds.
        recorded_disposition: SlackDispositionKind,
        /// Content digest the durable row binds, present only for admitted.
        recorded_content_digest: Option<String>,
    },
    /// The log holds its full capacity of live dispositions.
    ///
    /// Recording is refused *before* acknowledgement, because a disposition
    /// this log cannot record would lose deduplication for every redelivery of
    /// the same event.
    LogFull { capacity: usize },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private log.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl SlackIngressError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::Conflict { .. } => "conflict",
            Self::LogFull { .. } => "log_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for SlackIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "slack ingress path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "slack ingress schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::Conflict {
                field,
                recorded_app_id,
                recorded_disposition,
                ..
            } => write!(
                formatter,
                "source_key is already bound to app {recorded_app_id} \
                 with disposition {}; {field} differs",
                recorded_disposition.as_str()
            ),
            Self::LogFull { capacity } => {
                write!(
                    formatter,
                    "slack ingress log holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "slack ingress filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for SlackIngressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SlackIngressError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for SlackIngressError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one Slack ingress log operation.
pub type Logged<T> = Result<T, SlackIngressError>;

/// Closed durable disposition vocabulary.
///
/// The three recordable spellings are exactly the three
/// `automonique-transports` can pair with a `source_key`. The remaining
/// transport dispositions — a refused frame and a `hello`/`disconnect` control
/// frame — carry no `(team, channel, ts)` triple at all, so they have no
/// deduplication identity and cannot be a row in a table keyed by one. They are
/// absent from this vocabulary deliberately rather than mapped onto a
/// neighbouring spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackDispositionKind {
    /// The exact team/channel/user triple was allowlisted.
    Admitted,
    /// The frame was well-formed but outside the exact allowlist.
    Denied,
    /// The frame was well-formed and acknowledgeable but created no work.
    IgnoredUnsupported,
}

impl SlackDispositionKind {
    /// Stable machine-oriented spelling, and the exact stored column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Denied => "denied",
            Self::IgnoredUnsupported => "ignored_unsupported",
        }
    }

    /// Map a stored column value back onto the closed vocabulary.
    ///
    /// An unrecognised spelling is corruption, never an invalid caller field:
    /// this API can only ever have written the three above.
    fn from_stored(value: &str) -> Logged<Self> {
        match value {
            "admitted" => Ok(Self::Admitted),
            "denied" => Ok(Self::Denied),
            "ignored_unsupported" => Ok(Self::IgnoredUnsupported),
            _ => Err(corrupt_field("disposition")),
        }
    }
}

/// Digest-bearing or digest-free disposition presented for recording.
///
/// Denied and unsupported frames cannot carry a digest in this type, so a
/// content binding for a frame that admitted no content cannot cross the API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackStoreDisposition<'a> {
    /// Admitted content, named by its lowercase hex SHA-256 digest.
    Admitted { content_digest: &'a str },
    /// Outside the allowlist. No content was retained.
    Denied,
    /// Understood but creates no work. No content was retained.
    IgnoredUnsupported,
}

impl<'a> SlackStoreDisposition<'a> {
    /// Closed vocabulary member this disposition records as.
    #[must_use]
    pub const fn kind(self) -> SlackDispositionKind {
        match self {
            Self::Admitted { .. } => SlackDispositionKind::Admitted,
            Self::Denied => SlackDispositionKind::Denied,
            Self::IgnoredUnsupported => SlackDispositionKind::IgnoredUnsupported,
        }
    }

    /// Content digest bound by this disposition, if any.
    #[must_use]
    pub const fn content_digest(self) -> Option<&'a str> {
        match self {
            Self::Admitted { content_digest } => Some(content_digest),
            Self::Denied | Self::IgnoredUnsupported => None,
        }
    }
}

/// One Slack disposition presented for durable recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackDispositionRecord<'a> {
    /// Transport deduplication identity. The unique key.
    pub source_key: &'a str,
    /// Slack app this frame was delivered to.
    pub app_id: &'a str,
    /// Acknowledgement key of *this* delivery attempt.
    ///
    /// Not part of the binding: Slack mints a fresh one per attempt, so a
    /// redelivery carries a different value and is still an exact replay. Only
    /// the first delivery's value is stored.
    pub envelope_id: &'a str,
    /// Slack's redelivery counter on *this* delivery attempt.
    ///
    /// Not part of the binding, for the same reason as `envelope_id`.
    pub retry_attempt: u32,
    /// The decision that must be durable before any acknowledgement.
    pub disposition: SlackStoreDisposition<'a>,
    /// When this delivery was decided, in caller-supplied milliseconds.
    ///
    /// Not part of the binding: a redelivery naturally carries a later clock.
    pub recorded_at_ms: i64,
}

/// How the log answered one recording.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackRecordOutcome {
    /// The binding was new and is now durable.
    Recorded,
    /// The exact binding was already durable. Nothing changed.
    AlreadyRecorded,
}

impl SlackRecordOutcome {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }

    /// Whether this answer came from a row that already existed.
    #[must_use]
    pub const fn is_replay(self) -> bool {
        matches!(self, Self::AlreadyRecorded)
    }
}

/// Durable identity of one recorded or replayed disposition.
///
/// Both outcomes prove the same thing — the disposition is durable — which is
/// why an acknowledgement decision must not branch on the outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackIngressReceipt {
    /// Row identity of the durable disposition.
    pub entry_id: i64,
    pub outcome: SlackRecordOutcome,
}

/// Validated `slack_ingress_dispositions` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackDispositionEntry {
    pub entry_id: i64,
    pub source_key: String,
    pub app_id: String,
    pub disposition: SlackDispositionKind,
    /// Lowercase hex SHA-256 of admitted content. Never the content itself.
    pub content_digest: Option<String>,
    /// Acknowledgement key of the *first* delivery that recorded this row.
    pub envelope_id: String,
    /// Redelivery counter of the *first* delivery that recorded this row.
    pub retry_attempt: u32,
    /// When the *first* delivery of this event was recorded.
    pub recorded_at_ms: i64,
    /// Absent only on a disposition written before schema v2.
    pub provenance: Option<StoredProvenance>,
}

/// Bounded retention window for [`SlackIngressLog::prune`].
///
/// Scoped to one app, and to rows recorded strictly before a horizon. There is
/// no "prune everything" spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackRetention<'a> {
    /// Only this app's rows are eligible.
    pub app_id: &'a str,
    /// Rows recorded strictly before this instant are old enough.
    pub older_than_ms: i64,
}

/// What one prune removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlackPruneOutcome {
    /// Rows deleted by this prune.
    pub removed: usize,
    /// Rows still live afterwards, across every app.
    pub remaining: usize,
}

/// Durable log of Slack Socket Mode ingress dispositions.
#[derive(Debug)]
pub struct SlackIngressLog {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl SlackIngressLog {
    /// Open or initialize a log inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. Existing log paths must be regular, owned, non-symlinks.
    /// Capacity is [`MAX_SLACK_DISPOSITIONS`].
    pub fn open(path: impl AsRef<Path>) -> Logged<Self> {
        Self::open_with_capacity(path, MAX_SLACK_DISPOSITIONS)
    }

    /// Open a log with a lowered live-row capacity.
    ///
    /// `capacity` must be between one and [`MAX_SLACK_DISPOSITIONS`]. It is a
    /// property of this handle, not of the database: opening an existing log
    /// under a capacity below its current row count refuses further recordings
    /// with [`SlackIngressError::LogFull`] while exact replays and reads keep
    /// working, because a replay writes nothing.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Logged<Self> {
        if capacity == 0 || capacity > MAX_SLACK_DISPOSITIONS {
            return Err(SlackIngressError::InvalidField("capacity"));
        }
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

        let open_flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, open_flags)?;
        crate::sqlite_policy::configure_authoritative(&connection)?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this log.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Live-row capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one Slack disposition.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row, never half of one.
    ///
    /// Lookup precedes the capacity check, so an exact replay is still answered
    /// [`SlackRecordOutcome::AlreadyRecorded`] in a full log — a replay writes
    /// nothing and must never degrade into a refusal that would leave a
    /// redelivery unacknowledgeable. A conflicting redelivery is likewise a
    /// [`SlackIngressError::Conflict`] rather than
    /// [`SlackIngressError::LogFull`], because the disagreement is a caller bug
    /// regardless of how full the log is.
    ///
    /// The returned receipt proves the disposition is durable. It does not
    /// prove, and cannot prove, that an acknowledgement was sent.
    pub fn record(&mut self, record: SlackDispositionRecord<'_>) -> Logged<SlackIngressReceipt> {
        validate_record(&record)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut live = count_entries(&transaction)?;
        let receipt = record_row(&transaction, &record, self.capacity, &mut live)?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Read the validated row one `source_key` binds, if any.
    pub fn disposition(&self, source_key: &str) -> Logged<Option<SlackDispositionEntry>> {
        validate_source_key(source_key)?;
        read_entry_by_source_key(&self.connection, source_key)
    }

    /// List one app's dispositions recorded at or after an instant.
    ///
    /// This is the recovery view: a socket layer that reconnected asks which
    /// events it has already decided, oldest first. The page is bounded by
    /// `limit`, which must be between one and [`MAX_DISPOSITION_PAGE`]; a caller
    /// that needs more pages advances `since_ms` past the last row it read and
    /// asks again. Ordering is `(recorded_at_ms, entry_id)`, so the pair is a
    /// total order even when a clock repeats.
    ///
    /// An empty answer means nothing was recorded for that window — never that
    /// nothing was delivered.
    pub fn app_dispositions(
        &self,
        app_id: &str,
        since_ms: i64,
        limit: usize,
    ) -> Logged<Vec<SlackDispositionEntry>> {
        validate_identifier(app_id, MAX_SLACK_IDENTIFIER_BYTES, "app_id")?;
        validate_time(since_ms, "since_ms")?;
        if limit == 0 || limit > MAX_DISPOSITION_PAGE {
            return Err(SlackIngressError::InvalidField("limit"));
        }
        read_app_entries(&self.connection, app_id, since_ms, limit)
    }

    /// Count live rows.
    pub fn entry_count(&self) -> Logged<usize> {
        count_entries(&self.connection)
    }

    /// Delete one app's rows recorded before a horizon.
    ///
    /// This is the only deletion in this module, and it costs exactly one
    /// thing, stated here rather than buried: **a pruned `source_key` is
    /// forgotten.** If Slack delivers that event again after its row is pruned,
    /// the log has no memory of it and records it fresh, which can create the
    /// work a second time. A retention horizon must therefore sit well beyond
    /// Slack's redelivery window, and the caller owns that judgement — this
    /// module cannot tell a late redelivery from a new event.
    ///
    /// The whole prune is one transaction. The removed keys are not returned; a
    /// caller that needs them must read [`SlackIngressLog::app_dispositions`]
    /// first, because returning them would make the answer grow with the log.
    pub fn prune(&mut self, retention: SlackRetention<'_>) -> Logged<SlackPruneOutcome> {
        validate_identifier(retention.app_id, MAX_SLACK_IDENTIFIER_BYTES, "app_id")?;
        validate_time(retention.older_than_ms, "older_than_ms")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = transaction.execute(
            "DELETE FROM slack_ingress_dispositions
             WHERE app_id = ?1 AND recorded_at_ms < ?2",
            params![retention.app_id, retention.older_than_ms],
        )?;
        let remaining = count_entries(&transaction)?;
        transaction.commit()?;
        Ok(SlackPruneOutcome { removed, remaining })
    }
}

/// Record one disposition inside an open transaction.
///
/// `live` is the row count as of the start of the transaction, advanced here for
/// every row this transaction inserts. The transaction is immediate, so no other
/// writer can move the count underneath it.
fn record_row(
    transaction: &Transaction<'_>,
    record: &SlackDispositionRecord<'_>,
    capacity: usize,
    live: &mut usize,
) -> Logged<SlackIngressReceipt> {
    if let Some(recorded) = read_entry_by_source_key(transaction, record.source_key)? {
        if recorded.app_id != record.app_id {
            return Err(conflict("app_id", recorded));
        }
        if recorded.disposition != record.disposition.kind() {
            return Err(conflict("disposition", recorded));
        }
        if recorded.content_digest.as_deref() != record.disposition.content_digest() {
            return Err(conflict("content_digest", recorded));
        }
        // Exact replay. `envelope_id`, `retry_attempt` and `recorded_at_ms`
        // stay at the first delivery's values.
        return Ok(SlackIngressReceipt {
            entry_id: recorded.entry_id,
            outcome: SlackRecordOutcome::AlreadyRecorded,
        });
    }
    if *live >= capacity {
        return Err(SlackIngressError::LogFull { capacity });
    }
    transaction.execute(
        "INSERT INTO slack_ingress_dispositions
         (source_key, app_id, disposition, content_digest,
          envelope_id, retry_attempt, recorded_at_ms, trace_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            record.source_key,
            record.app_id,
            record.disposition.kind().as_str(),
            record.disposition.content_digest(),
            record.envelope_id,
            i64::from(record.retry_attempt),
            record.recorded_at_ms,
            TraceId::for_ingress("slack", record.source_key).as_str()
        ],
    )?;
    let entry_id = transaction.last_insert_rowid();
    let trace_id = TraceId::for_ingress("slack", record.source_key);
    let correlation_id = CorrelationId::new(format!("slack:{entry_id}"))
        .map_err(|_| SlackIngressError::InvalidField("correlation_id"))?;
    let causation_id = CausationId::new(format!("ingress:{}", trace_id.as_str()))
        .map_err(|_| SlackIngressError::InvalidField("causation_id"))?;
    transaction.execute(
        "UPDATE slack_ingress_dispositions
         SET correlation_id = ?2, causation_id = ?3 WHERE entry_id = ?1",
        params![entry_id, correlation_id.as_str(), causation_id.as_str()],
    )?;
    *live = live
        .checked_add(1)
        .ok_or(SlackIngressError::InvalidField("source_key"))?;
    Ok(SlackIngressReceipt {
        entry_id,
        outcome: SlackRecordOutcome::Recorded,
    })
}

fn conflict(field: &'static str, recorded: SlackDispositionEntry) -> SlackIngressError {
    SlackIngressError::Conflict {
        field,
        recorded_app_id: recorded.app_id,
        recorded_disposition: recorded.disposition,
        recorded_content_digest: recorded.content_digest,
    }
}

struct RawEntry {
    entry_id: i64,
    source_key: String,
    app_id: String,
    disposition: String,
    content_digest: Option<String>,
    envelope_id: String,
    retry_attempt: i64,
    recorded_at_ms: i64,
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
}

const ENTRY_COLUMNS: &str = "entry_id, source_key, app_id, disposition, \
                             content_digest, envelope_id, retry_attempt, recorded_at_ms, \
                             trace_id, correlation_id, causation_id";

fn raw_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok(RawEntry {
        entry_id: row.get(0)?,
        source_key: row.get(1)?,
        app_id: row.get(2)?,
        disposition: row.get(3)?,
        content_digest: row.get(4)?,
        envelope_id: row.get(5)?,
        retry_attempt: row.get(6)?,
        recorded_at_ms: row.get(7)?,
        trace_id: row.get(8)?,
        correlation_id: row.get(9)?,
        causation_id: row.get(10)?,
    })
}

fn validated_entry(raw: RawEntry) -> Logged<SlackDispositionEntry> {
    let disposition = SlackDispositionKind::from_stored(&raw.disposition)?;
    let content_digest = match (disposition, raw.content_digest) {
        (SlackDispositionKind::Admitted, Some(digest)) => Some(checked_digest(digest)?),
        (SlackDispositionKind::Admitted, None)
        | (SlackDispositionKind::Denied | SlackDispositionKind::IgnoredUnsupported, Some(_)) => {
            return Err(corrupt_field("content_digest"));
        }
        (SlackDispositionKind::Denied | SlackDispositionKind::IgnoredUnsupported, None) => None,
    };
    Ok(SlackDispositionEntry {
        entry_id: checked_row_id(raw.entry_id)?,
        source_key: checked_bounded(raw.source_key, MAX_SOURCE_KEY_BYTES, "source_key")?,
        app_id: checked_bounded(raw.app_id, MAX_SLACK_IDENTIFIER_BYTES, "app_id")?,
        disposition,
        content_digest,
        envelope_id: checked_bounded(raw.envelope_id, MAX_SLACK_IDENTIFIER_BYTES, "envelope_id")?,
        retry_attempt: u32::try_from(raw.retry_attempt)
            .map_err(|_| corrupt_field("retry_attempt"))?,
        recorded_at_ms: checked_time(raw.recorded_at_ms)?,
        provenance: checked_provenance(raw.trace_id, raw.correlation_id, raw.causation_id)?,
    })
}

fn checked_provenance(
    trace_id: Option<String>,
    correlation_id: Option<String>,
    causation_id: Option<String>,
) -> Logged<Option<StoredProvenance>> {
    match (trace_id, correlation_id, causation_id) {
        (None, None, None) => Ok(None),
        (Some(trace_id), Some(correlation_id), Some(causation_id)) => {
            TraceId::new(trace_id.clone()).map_err(|_| corrupt_field("trace_id"))?;
            CorrelationId::new(correlation_id.clone())
                .map_err(|_| corrupt_field("correlation_id"))?;
            CausationId::new(causation_id.clone()).map_err(|_| corrupt_field("causation_id"))?;
            Ok(Some(StoredProvenance {
                trace_id,
                correlation_id,
                causation_id,
            }))
        }
        _ => Err(corrupt_field("partial_provenance")),
    }
}

fn read_entry_by_source_key(
    connection: &Connection,
    source_key: &str,
) -> Logged<Option<SlackDispositionEntry>> {
    let raw = connection
        .query_row(
            &format!(
                "SELECT {ENTRY_COLUMNS} FROM slack_ingress_dispositions WHERE source_key = ?1"
            ),
            [source_key],
            raw_entry,
        )
        .optional()?;
    raw.map(validated_entry).transpose()
}

fn read_app_entries(
    connection: &Connection,
    app_id: &str,
    since_ms: i64,
    limit: usize,
) -> Logged<Vec<SlackDispositionEntry>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {ENTRY_COLUMNS} FROM slack_ingress_dispositions
         WHERE app_id = ?1 AND recorded_at_ms >= ?2
         ORDER BY recorded_at_ms, entry_id
         LIMIT ?3"
    ))?;
    let limit = i64::try_from(limit).map_err(|_| SlackIngressError::InvalidField("limit"))?;
    let rows = statement.query_map(params![app_id, since_ms, limit], raw_entry)?;
    let mut entries = Vec::new();
    for raw in rows {
        entries.push(validated_entry(raw?)?);
    }
    Ok(entries)
}

fn count_entries(connection: &Connection) -> Logged<usize> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM slack_ingress_dispositions",
        [],
        |row| row.get(0),
    )?;
    usize::try_from(count).map_err(|_| corrupt_field("entry_count"))
}

fn secure_path(path: &Path) -> Logged<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => SlackIngressError::Io(io),
        other => SlackIngressError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Logged<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SLACK_INGRESS_SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(MIGRATE_V1_TO_V2)?;
        transaction.pragma_update(None, "user_version", SLACK_INGRESS_SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }
    if version != 0 {
        return Err(SlackIngressError::SchemaVersion {
            found: version,
            supported: SLACK_INGRESS_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(SlackIngressError::SchemaVersion {
            found: 0,
            supported: SLACK_INGRESS_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.execute_batch(MIGRATE_V1_TO_V2)?;
    transaction.pragma_update(None, "user_version", SLACK_INGRESS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_record(record: &SlackDispositionRecord<'_>) -> Logged<()> {
    validate_source_key(record.source_key)?;
    validate_identifier(record.app_id, MAX_SLACK_IDENTIFIER_BYTES, "app_id")?;
    validate_identifier(
        record.envelope_id,
        MAX_SLACK_IDENTIFIER_BYTES,
        "envelope_id",
    )?;
    validate_time(record.recorded_at_ms, "recorded_at_ms")?;
    if let Some(digest) = record.disposition.content_digest() {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_source_key(value: &str) -> Logged<()> {
    validate_identifier(value, MAX_SOURCE_KEY_BYTES, "source_key")
}

/// Admit one bounded identifier under [`crate::Store`]'s grammar.
///
/// Non-empty, at most `limit` bytes, no control characters. Deliberately looser
/// than the transport's ASCII-graphic rule: this log stores what a transport
/// derived and must not refuse a coordinate a future Slack change makes legal,
/// while still refusing the shapes that could break a stored row.
fn validate_identifier(value: &str, limit: usize, field: &'static str) -> Logged<()> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(SlackIngressError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Logged<()> {
    if value.len() != CONTENT_DIGEST_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SlackIngressError::InvalidField("content_digest"));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Logged<()> {
    if value < 0 {
        return Err(SlackIngressError::InvalidField(field));
    }
    Ok(())
}

fn checked_bounded(value: String, limit: usize, field: &'static str) -> Logged<String> {
    validate_identifier(&value, limit, field).map_err(|_| corrupt_field(field))?;
    Ok(value)
}

fn checked_digest(value: String) -> Logged<String> {
    validate_digest(&value).map_err(|_| corrupt_field("content_digest"))?;
    Ok(value)
}

fn checked_time(value: i64) -> Logged<i64> {
    validate_time(value, "recorded_at_ms").map_err(|_| corrupt_field("recorded_at_ms"))?;
    Ok(value)
}

fn checked_row_id(value: i64) -> Logged<i64> {
    if value <= 0 {
        return Err(corrupt_field("entry_id"));
    }
    Ok(value)
}

/// Map a validation field onto its stable corruption invariant name.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
const fn corrupt_field(field: &'static str) -> SlackIngressError {
    SlackIngressError::Corrupt(field)
}
