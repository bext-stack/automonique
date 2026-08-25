// SPDX-License-Identifier: Elastic-2.0

//! One read-back-verified SQLite connection policy for runtime state.
//!
//! Every current runtime database can affect authorization, idempotency,
//! reconciliation, or audit evidence. They therefore share the authoritative
//! class: WAL, foreign keys, trusted-schema refusal, a bounded lock wait, and
//! `synchronous=FULL`. A store must fail to open when SQLite cannot read those
//! settings back exactly. Production has no weakening override; the benchmark
//! harness may compare `NORMAL`, but that comparison is not runtime policy.

use std::time::Duration;

use rusqlite::Connection;

/// Longest a runtime connection may wait for another SQLite writer.
pub const AUTHORITY_BUSY_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Closed runtime database classes.
///
/// There is intentionally no regenerable class yet. Adding one requires a
/// proven reconstruction source and recovery test, not merely a database that
/// looks like a cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseClass {
    Authority,
}

/// Apply and verify the policy for state that participates in authority.
pub fn configure_authoritative(connection: &Connection) -> rusqlite::Result<()> {
    configure(connection, DatabaseClass::Authority)
}

/// Apply and read back the selected runtime policy.
pub fn configure(connection: &Connection, database_class: DatabaseClass) -> rusqlite::Result<()> {
    match database_class {
        DatabaseClass::Authority => {
            connection.busy_timeout(AUTHORITY_BUSY_TIMEOUT)?;
            connection.pragma_update(None, "foreign_keys", true)?;
            connection.pragma_update(None, "trusted_schema", false)?;
            let journal: String =
                connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
            if !journal.eq_ignore_ascii_case("wal") {
                return Err(rusqlite::Error::InvalidQuery);
            }
            verify_authoritative(connection)
        }
    }
}

/// Verify without mutating a connection, for tests and operator diagnostics.
pub fn verify_authoritative(connection: &Connection) -> rusqlite::Result<()> {
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let busy_timeout_ms: u64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;

    let expected_busy_timeout =
        u64::try_from(AUTHORITY_BUSY_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    if foreign_keys != 1
        || trusted_schema != 0
        || !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || busy_timeout_ms != expected_busy_timeout
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_policy_is_applied_and_read_back_exactly() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let connection =
            Connection::open(directory.path().join("state.sqlite3")).expect("database opens");

        configure_authoritative(&connection).expect("policy applies");
        verify_authoritative(&connection).expect("policy reads back");
    }

    #[test]
    fn a_weakened_connection_fails_policy_verification() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let connection =
            Connection::open(directory.path().join("state.sqlite3")).expect("database opens");
        configure_authoritative(&connection).expect("policy applies");

        connection
            .pragma_update(None, "synchronous", "NORMAL")
            .expect("fault injection");
        assert_eq!(
            verify_authoritative(&connection),
            Err(rusqlite::Error::InvalidQuery)
        );
    }
}
