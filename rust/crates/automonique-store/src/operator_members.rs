// SPDX-License-Identifier: Elastic-2.0

//! Durable roster of operator **members** added at runtime.
//!
//! An operator surface — today the Telegram control bot — has two tiers. The
//! upper one is written down by the owner in a configuration file the daemon
//! reads at startup and this module never sees. The lower one is this file: the
//! non-admin members an administrator added from a chat, which must survive a
//! restart and must be host-wide rather than per-process, because the authority
//! they carry is the authority to command a daemon.
//!
//! The whole record is one binding:
//!
//! ```text
//! user_id -> added_at_ms
//! ```
//!
//! and it answers three ways and only three ways:
//!
//! - the id is new: it is recorded, [`MemberDisposition::Added`];
//! - the id is already present: [`MemberDisposition::AlreadyMember`], and not
//!   one byte of the durable row changes — in particular `added_at_ms` keeps
//!   the *first* addition's instant, so a re-add is not a way to rewrite when
//!   somebody was let in;
//! - removal names an id nobody recorded: [`MemberDisposition::NotAMember`],
//!   and nothing is written.
//!
//! # What a member row does not establish
//!
//! - A row says an administrator asked for this id to be allowed. It does not
//!   say the id names a real person, that Telegram will ever deliver a message
//!   from them, or that any *particular* command is theirs to run. Which
//!   commands a member may issue is the operator surface's own table, decided
//!   above this store.
//! - **A row grants no administrative authority, ever.** Administrators are the
//!   configuration file's alone. This store cannot record one, cannot promote a
//!   member into one, and the caller is expected to refuse an add or a remove
//!   that names a configured administrator before it reaches here — see the
//!   Telegram bridge's `/admin` dispatch, which does exactly that.
//! - The absence of a row is not the absence of authority: a configured
//!   `allow=` user is allowed without ever appearing here.
//!
//! # Deletion
//!
//! [`OperatorMemberStore::remove_member`] is the only deletion in this module
//! and it is exactly what it says: revoking one named member. Nothing here
//! evicts, prunes, ages out, or makes room by forgetting somebody — a roster
//! that quietly dropped its oldest member when it filled would revoke an
//! operator's access as a side effect of adding a different one. A full roster
//! refuses the *addition* instead, with [`OperatorMemberError::RosterFull`].
//!
//! # Storage discipline
//!
//! The store owns its own SQLite database with its own `user_version`, opened
//! under the same privacy, WAL and `synchronous = FULL` rules as
//! [`crate::Store`]. One mutation is one immediate transaction, so a reader
//! after a crash sees the whole row or no row. Every read re-validates the row
//! it loaded rather than trusting the database.

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{BUSY_TIMEOUT, StoreError, validate_database_path};

/// The only operator member schema this build can read and write.
pub const OPERATOR_MEMBERS_SCHEMA_VERSION: u32 = 1;

/// Largest number of members any roster will hold.
///
/// Deliberately the same ceiling the Telegram control gate applies to its whole
/// allowlist. The two are not the same set — the gate admits configured users
/// *and* these members — so a caller composing both must still handle a union
/// that overruns its own bound, and the Telegram bridge does exactly that
/// before it writes. This bound is the one that keeps a runaway `/admin add`
/// loop from growing a database without limit.
pub const MAX_OPERATOR_MEMBERS: usize = 256;

/// Schema v1.
///
/// Uniqueness and positivity of `user_id` are database constraints so a second
/// writer cannot introduce a duplicate or a nonsense id. They are re-checked on
/// every read as well, so a row written around this API is refused rather than
/// believed.
const SCHEMA_V1: &str = r#"
CREATE TABLE operator_members (
    member_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE CHECK (user_id > 0),
    added_at_ms INTEGER NOT NULL CHECK (added_at_ms >= 0)
) STRICT;

CREATE INDEX operator_members_by_user
    ON operator_members(user_id);
"#;

/// An operator member store error with stable refusal categories.
#[derive(Debug)]
pub enum OperatorMemberError {
    /// The store path or its containing directory is not private and owned.
    InsecurePath(String),
    /// The schema is absent from a non-empty database or unsupported.
    SchemaVersion { found: u32, supported: u32 },
    /// A caller-provided field is out of range: an id that is not a positive
    /// Telegram user id, or a negative instant.
    InvalidField(&'static str),
    /// The roster holds its full capacity of members.
    ///
    /// The addition is refused; nothing is evicted to make room. See this
    /// module's note on deletion.
    RosterFull { capacity: usize },
    /// A stored row violates an invariant this API can only have written once.
    Corrupt(&'static str),
    /// Filesystem failure while establishing the private store.
    Io(std::io::Error),
    /// SQLite rejected an operation.
    Sqlite(rusqlite::Error),
}

impl OperatorMemberError {
    /// Stable machine-oriented category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::InsecurePath(_) => "insecure_path",
            Self::SchemaVersion { .. } => "schema_version",
            Self::InvalidField(_) => "invalid_field",
            Self::RosterFull { .. } => "roster_full",
            Self::Corrupt(_) => "corrupt",
            Self::Io(_) => "io",
            Self::Sqlite(_) => "sqlite",
        }
    }
}

impl fmt::Display for OperatorMemberError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsecurePath(reason) => {
                write!(formatter, "member store path is not private: {reason}")
            }
            Self::SchemaVersion { found, supported } => write!(
                formatter,
                "operator member schema {found} is unsupported; expected {supported}"
            ),
            Self::InvalidField(field) => write!(formatter, "invalid field: {field}"),
            Self::RosterFull { capacity } => {
                write!(
                    formatter,
                    "operator roster holds its capacity of {capacity}"
                )
            }
            Self::Corrupt(invariant) => {
                write!(formatter, "stored row violates invariant: {invariant}")
            }
            Self::Io(error) => write!(formatter, "member store filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite error: {error}"),
        }
    }
}

impl Error for OperatorMemberError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for OperatorMemberError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for OperatorMemberError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

/// Result of one member store operation.
pub type Membered<T> = Result<T, OperatorMemberError>;

/// How the roster answered one mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberDisposition {
    /// The id was new and is now a durable member.
    Added,
    /// The id was already a member. Nothing changed.
    AlreadyMember,
    /// The id was a member and no longer is.
    Removed,
    /// The id was not a member. Nothing changed.
    NotAMember,
}

impl MemberDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::AlreadyMember => "already_member",
            Self::Removed => "removed",
            Self::NotAMember => "not_a_member",
        }
    }

    /// Whether this disposition changed a durable row.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Added | Self::Removed)
    }
}

/// One validated `operator_members` row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberRecord {
    /// Row identity, ascending in insertion order.
    pub member_id: i64,
    /// The Telegram user id this row admits.
    pub user_id: i64,
    /// When this member was *first* added, in caller-supplied milliseconds.
    pub added_at_ms: i64,
}

/// Durable roster of runtime-added operator members.
#[derive(Debug)]
pub struct OperatorMemberStore {
    connection: Connection,
    path: PathBuf,
    capacity: usize,
}

impl OperatorMemberStore {
    /// Open or initialize a roster inside an existing private directory.
    ///
    /// The parent must be owned by the effective user and deny all group/other
    /// access. An existing path must be a regular owned non-symlink file.
    /// Capacity is [`MAX_OPERATOR_MEMBERS`].
    pub fn open(path: impl AsRef<Path>) -> Membered<Self> {
        Self::open_with_capacity(path, MAX_OPERATOR_MEMBERS)
    }

    /// Open a roster with a lowered member capacity.
    ///
    /// `capacity` must be between one and [`MAX_OPERATOR_MEMBERS`]. It is a
    /// property of this handle, not of the database: opening an existing roster
    /// under a capacity below its current membership refuses further additions
    /// with [`OperatorMemberError::RosterFull`] while reads, re-adds of an
    /// existing member and *removals* keep working — a lowered ceiling must
    /// never be a reason an operator cannot be revoked.
    pub fn open_with_capacity(path: impl AsRef<Path>, capacity: usize) -> Membered<Self> {
        if capacity == 0 || capacity > MAX_OPERATOR_MEMBERS {
            return Err(OperatorMemberError::InvalidField("capacity"));
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
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(OperatorMemberError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        initialize_or_validate_schema(&mut connection)?;

        Ok(Self {
            connection,
            path: path.to_path_buf(),
            capacity,
        })
    }

    /// Exact path opened by this store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Member capacity of this handle.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one member.
    ///
    /// One immediate transaction: after a crash a reader sees the whole row or
    /// no row. The lookup precedes the capacity check, so re-adding an existing
    /// member is still [`MemberDisposition::AlreadyMember`] in a full roster —
    /// it writes nothing and must never degrade into a refusal.
    ///
    /// # Errors
    ///
    /// [`OperatorMemberError::InvalidField`] for an id that is not a positive
    /// Telegram user id or a negative instant, and
    /// [`OperatorMemberError::RosterFull`] when the roster is at capacity and
    /// the id is new.
    pub fn add_member(&mut self, user_id: i64, added_at_ms: i64) -> Membered<MemberDisposition> {
        validate_user_id(user_id)?;
        validate_time(added_at_ms, "added_at_ms")?;
        let capacity = self.capacity;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_member(&transaction, user_id)?.is_some() {
            // No commit is needed for a read-only transaction, but committing
            // it keeps one exit path and releases the write lock immediately.
            transaction.commit()?;
            return Ok(MemberDisposition::AlreadyMember);
        }
        if count_members(&transaction)? >= capacity {
            return Err(OperatorMemberError::RosterFull { capacity });
        }
        transaction.execute(
            "INSERT INTO operator_members (user_id, added_at_ms) VALUES (?1, ?2)",
            params![user_id, added_at_ms],
        )?;
        transaction.commit()?;
        Ok(MemberDisposition::Added)
    }

    /// Revoke one member.
    ///
    /// Removing an id nobody recorded is [`MemberDisposition::NotAMember`]
    /// rather than an error: the caller asked for that id not to be a member,
    /// and it is not.
    ///
    /// # Errors
    ///
    /// [`OperatorMemberError::InvalidField`] for an id that is not a positive
    /// Telegram user id.
    pub fn remove_member(&mut self, user_id: i64) -> Membered<MemberDisposition> {
        validate_user_id(user_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = transaction.execute(
            "DELETE FROM operator_members WHERE user_id = ?1",
            params![user_id],
        )?;
        transaction.commit()?;
        Ok(if removed == 0 {
            MemberDisposition::NotAMember
        } else {
            MemberDisposition::Removed
        })
    }

    /// Every member, ordered by user id.
    ///
    /// Ordered by the id rather than by insertion, because the answer is a set
    /// an operator reads and compares against a configuration file, not a
    /// history.
    pub fn list_members(&self) -> Membered<Vec<MemberRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT member_id, user_id, added_at_ms FROM operator_members ORDER BY user_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut members = Vec::new();
        for row in rows {
            let (member_id, user_id, added_at_ms) = row?;
            members.push(MemberRecord {
                member_id: checked_row_id(member_id, "member_id")?,
                user_id: checked_user_id(user_id)?,
                added_at_ms: checked_time(added_at_ms, "added_at_ms")?,
            });
        }
        Ok(members)
    }

    /// Just the member ids, ordered and de-duplicated by construction.
    ///
    /// This is what an authorization gate is composed from; it exists so a
    /// caller does not have to carry rows it will throw away.
    pub fn member_ids(&self) -> Membered<Vec<i64>> {
        Ok(self
            .list_members()?
            .into_iter()
            .map(|member| member.user_id)
            .collect())
    }

    /// Whether this id is a recorded member.
    ///
    /// # Errors
    ///
    /// [`OperatorMemberError::InvalidField`] for an id that is not a positive
    /// Telegram user id. A caller holding an unvalidated id should treat that
    /// refusal as "not a member", which is what it means.
    pub fn is_member(&self, user_id: i64) -> Membered<bool> {
        validate_user_id(user_id)?;
        Ok(read_member(&self.connection, user_id)?.is_some())
    }

    /// Count members.
    pub fn member_count(&self) -> Membered<usize> {
        count_members(&self.connection)
    }
}

fn read_member(connection: &Connection, user_id: i64) -> Membered<Option<i64>> {
    let member_id = connection
        .query_row(
            "SELECT member_id FROM operator_members WHERE user_id = ?1",
            params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    member_id
        .map(|id| checked_row_id(id, "member_id"))
        .transpose()
}

fn count_members(connection: &Connection) -> Membered<usize> {
    let count: i64 = connection.query_row("SELECT count(*) FROM operator_members", [], |row| {
        row.get(0)
    })?;
    usize::try_from(count).map_err(|_| OperatorMemberError::Corrupt("member_count"))
}

fn secure_path(path: &Path) -> Membered<()> {
    validate_database_path(path).map_err(|error| match error {
        StoreError::Io(io) => OperatorMemberError::Io(io),
        other => OperatorMemberError::InsecurePath(other.to_string()),
    })
}

fn initialize_or_validate_schema(connection: &mut Connection) -> Membered<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == OPERATOR_MEMBERS_SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(OperatorMemberError::SchemaVersion {
            found: version,
            supported: OPERATOR_MEMBERS_SCHEMA_VERSION,
        });
    }
    let objects: u32 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if objects != 0 {
        return Err(OperatorMemberError::SchemaVersion {
            found: 0,
            supported: OPERATOR_MEMBERS_SCHEMA_VERSION,
        });
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_V1)?;
    transaction.pragma_update(None, "user_version", OPERATOR_MEMBERS_SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn validate_user_id(user_id: i64) -> Membered<()> {
    if user_id <= 0 {
        return Err(OperatorMemberError::InvalidField("user_id"));
    }
    Ok(())
}

fn validate_time(value: i64, field: &'static str) -> Membered<()> {
    if value < 0 {
        return Err(OperatorMemberError::InvalidField(field));
    }
    Ok(())
}

/// Map a validation failure on a *stored* value onto corruption.
///
/// Read paths never reuse `InvalidField`: a bad stored row is corruption the
/// caller cannot have caused, and the two must not be confused.
fn checked_user_id(value: i64) -> Membered<i64> {
    validate_user_id(value).map_err(|_| OperatorMemberError::Corrupt("user_id"))?;
    Ok(value)
}

fn checked_time(value: i64, field: &'static str) -> Membered<i64> {
    validate_time(value, field).map_err(|_| OperatorMemberError::Corrupt(field))?;
    Ok(value)
}

fn checked_row_id(value: i64, field: &'static str) -> Membered<i64> {
    if value <= 0 {
        return Err(OperatorMemberError::Corrupt(field));
    }
    Ok(value)
}
