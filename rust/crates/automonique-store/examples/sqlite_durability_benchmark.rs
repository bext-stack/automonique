// SPDX-License-Identifier: Elastic-2.0

//! Reproducible local comparison for the runtime SQLite durability decision.

use std::fs;
use std::time::{Duration, Instant};

use rusqlite::{Connection, TransactionBehavior, params};

const TRANSACTIONS: usize = 500;
const PAYLOAD_BYTES: usize = 1_024;
const MODES: [&str; 2] = ["FULL", "NORMAL"];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "automonique-sqlite-durability-benchmark-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;

    println!("mode,transactions,payload_bytes,elapsed_ms,rows_after_reopen,integrity");
    for mode in MODES {
        let result = run(&root, mode)?;
        println!(
            "{mode},{TRANSACTIONS},{PAYLOAD_BYTES},{},{},{}",
            result.elapsed.as_millis(),
            result.rows,
            result.integrity
        );
    }

    fs::remove_dir_all(&root)?;
    Ok(())
}

struct ResultRow {
    elapsed: Duration,
    rows: usize,
    integrity: String,
}

fn run(root: &std::path::Path, mode: &str) -> rusqlite::Result<ResultRow> {
    let path = root.join(format!("{mode}.sqlite3"));
    let mut connection = Connection::open(&path)?;
    connection.busy_timeout(automonique_store::sqlite_policy::AUTHORITY_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    connection.pragma_update(None, "synchronous", mode)?;
    connection.execute_batch(
        "CREATE TABLE samples (
             sequence INTEGER PRIMARY KEY,
             payload BLOB NOT NULL
         ) STRICT;",
    )?;

    let payload = vec![0x5a_u8; PAYLOAD_BYTES];
    let started = Instant::now();
    for sequence in 0..TRANSACTIONS {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO samples (sequence, payload) VALUES (?1, ?2)",
            params![sequence, payload],
        )?;
        transaction.commit()?;
    }
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let elapsed = started.elapsed();
    drop(connection);

    let reopened = Connection::open(path)?;
    let rows = reopened.query_row("SELECT COUNT(*) FROM samples", [], |row| row.get(0))?;
    let integrity = reopened.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    Ok(ResultRow {
        elapsed,
        rows,
        integrity,
    })
}
